const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const quic = netz.quic;

pub const Task = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server_address: std.Io.net.IpAddress,
    public_key: [65]u8,
    input: []const u8,
    client_index: usize,
    start: std.Io.Event = .unset,
    connected: std.Io.Event = .unset,
    round_trip_done: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    done: std.Io.Event = .unset,
    err: ?anyerror = null,

    pub fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
            self.connected.set(self.io);
            self.round_trip_done.set(self.io);
        };
        self.done.set(self.io);
    }

    fn runFallible(self: *@This()) !void {
        try self.start.wait(self.io);
        var endpoint = try quic.runtime.Endpoint.bind(
            self.allocator,
            self.io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        defer endpoint.deinit();
        const version = model.version(self.input, self.client_index);
        const suite = model.suite(self.input, self.client_index);
        var original_dcid = [_]u8{0x30} ** 8;
        var local_cid = [_]u8{0x40} ** 8;
        original_dcid[0] +%= @intCast(self.client_index);
        local_cid[0] +%= @intCast(self.client_index);
        var random = [_]u8{0x50} ** 32;
        var secret = [_]u8{0x60} ** 32;
        random[0] +%= @intCast(self.client_index);
        secret[0] +%= @intCast(self.client_index);
        var established = try quic.handshake.connectWithTimeout(
            &endpoint,
            self.server_address,
            .{
                .version = version,
                .available_versions = &.{version},
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &local_cid,
                .server_name = "localhost",
                .alpn_protocols = &.{"netz-endpoint-fuzz"},
                .server_auth = .{
                    .pinned_ecdsa_p256_public_key = self.public_key,
                },
                .random = random,
                .x25519_secret_key = secret,
                .key_exchange_groups = &.{.x25519},
                .cipher_suites = &.{suite},
                .local_transport_parameters = .{
                    .initial_max_data = 64,
                    .initial_max_stream_data_bidi_local = 64,
                    .initial_max_stream_data_bidi_remote = 64,
                    .initial_max_streams_bidi = 1,
                },
                .initial_one_rtt_config = .{
                    .enable_pacing = false,
                    .automatic_ecn_policy = .disabled,
                },
                .handshake_recovery = recovery(),
            },
            model.timeout,
        );
        defer established.deinit();
        try std.testing.expectEqual(version, established.connection.config.version);
        try std.testing.expectEqual(suite, established.negotiatedCipherSuite());
        self.connected.set(self.io);

        const payload = model.payload(self.input, self.client_index);
        var committed: usize = 0;
        try established.connection.sendStreamWithTimeout(
            0,
            0,
            &payload,
            true,
            &committed,
            model.timeout,
        );
        try std.testing.expectEqual(payload.len, committed);
        var response: [payload.len]u8 = undefined;
        const received = try established.connection.receiveStreamIdWithTimeout(
            0,
            &response,
            model.timeout,
        );
        const data = switch (received) {
            .data => |value| value,
            .reset => return error.UnexpectedStreamReset,
        };
        try std.testing.expect(data.fin);
        try std.testing.expectEqual(payload.len, data.bytes);
        try std.testing.expectEqualSlices(u8, &payload, &response);
        self.round_trip_done.set(self.io);
        try self.release.wait(self.io);
        try established.connection.sendWithTimeout(
            &.{.{ .ping = {} }},
            model.timeout,
        );
    }
};

fn recovery() @FieldType(quic.handshake.ClientOptions, "handshake_recovery") {
    return .{
        .initial_pto_ms = 20,
        .max_pto_ms = 40,
        .max_retries = 6,
        .max_duration_ms = 2_000,
    };
}

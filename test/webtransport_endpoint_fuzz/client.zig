const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const runtime = netz.webtransport.runtime;

pub const Task = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    public_key: [65]u8,
    input: []const u8,
    client_index: usize,
    ready: std.Io.Event = .unset,
    release: std.Io.Event = .unset,
    err: ?anyerror = null,

    pub fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
            self.ready.set(self.io);
        };
    }

    fn runFallible(self: *@This()) !void {
        const ids = [_]struct {
            original: []const u8,
            local: []const u8,
            path: []const u8,
            random: u8,
            secret: u8,
        }{
            .{
                .original = "wt-fuzz-origin-a",
                .local = "wt-fuzz-client-a",
                .path = "/fuzz/a",
                .random = 0x31,
                .secret = 0x32,
            },
            .{
                .original = "wt-fuzz-origin-b",
                .local = "wt-fuzz-client-b",
                .path = "/fuzz/b",
                .random = 0x41,
                .secret = 0x42,
            },
        };
        const identity = ids[self.client_index];
        var client = try runtime.HandshakeClientSession.connectWithTimeout(
            self.allocator,
            self.io,
            .{ .ip4 = .loopback(0) },
            self.address,
            .{
                .authority = "localhost",
                .path = identity.path,
                .limits = limits(),
                .h3 = .{
                    .handshake = .{
                        .original_destination_connection_id = identity.original,
                        .local_connection_id = identity.local,
                        .server_name = "localhost",
                        .server_auth = .{
                            .pinned_ecdsa_p256_public_key = self.public_key,
                        },
                        .random = .{identity.random} ** 32,
                        .x25519_secret_key = .{identity.secret} ** 32,
                        .handshake_recovery = .{
                            .initial_pto_ms = 20,
                            .max_pto_ms = 40,
                            .max_duration_ms = 2_000,
                        },
                        .initial_one_rtt_config = .{
                            .enable_pacing = false,
                        },
                    },
                    .session = sessionOptions(),
                },
            },
            model.timeout,
        );
        defer client.deinit();
        self.ready.set(self.io);
        try self.release.wait(self.io);

        try datagramRoundTrip(
            self.allocator,
            &client,
            model.Payload.baseline(self.client_index),
        );
        var drained = false;
        for (self.input, 0..) |operation, operation_index| {
            if (model.clientIndex(operation) != self.client_index) continue;
            const payload = model.Payload.operation(
                self.client_index,
                operation_index,
                operation,
            );
            switch (model.kind(operation)) {
                .datagram => try datagramRoundTrip(
                    self.allocator,
                    &client,
                    payload,
                ),
                .stream => try streamRoundTrip(&client, payload),
                .datagram_pair => {
                    const pair = payload.paired();
                    try client.sendDatagramWithTimeout(
                        &payload.bytes,
                        model.timeout,
                    );
                    try client.sendDatagramWithTimeout(
                        &pair.bytes,
                        model.timeout,
                    );
                    try receiveDatagramPair(
                        self.allocator,
                        &client,
                        payload.response(),
                        pair.response(),
                    );
                },
                .drain => if (!drained) {
                    try client.drainWithTimeout(model.timeout);
                    drained = true;
                },
            }
        }
        const reasons = [_][]const u8{ "client-a", "client-b" };
        try client.closeWithTimeout(
            @intCast(70 + self.client_index),
            reasons[self.client_index],
            model.timeout,
        );
    }
};

fn limits() runtime.Limits {
    return .{
        .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .max_session_streams = model.max_operations + 1,
    };
}

fn sessionOptions() netz.http3.runtime.HandshakeSessionOptions {
    return .{
        .local_settings = netz.webtransport.defaultSettings(.{}),
        .max_stream_frame_data = 256,
        .max_frames_per_packet = 8,
    };
}

fn datagramRoundTrip(
    allocator: std.mem.Allocator,
    client: *runtime.HandshakeClientSession,
    payload: model.Payload,
) !void {
    try client.sendDatagramWithTimeout(&payload.bytes, model.timeout);
    try receiveDatagram(allocator, client, payload.response());
}

fn receiveDatagram(
    allocator: std.mem.Allocator,
    client: *runtime.HandshakeClientSession,
    expected: model.Payload,
) !void {
    var datagram = try client.receiveDatagramWithTimeout(model.timeout);
    defer datagram.deinit(allocator);
    try std.testing.expectEqualSlices(
        u8,
        &expected.bytes,
        datagram.datagram.payload,
    );
}

fn receiveDatagramPair(
    allocator: std.mem.Allocator,
    client: *runtime.HandshakeClientSession,
    first_expected: model.Payload,
    second_expected: model.Payload,
) !void {
    var first = try client.receiveDatagramWithTimeout(model.timeout);
    defer first.deinit(allocator);
    var second = try client.receiveDatagramWithTimeout(model.timeout);
    defer second.deinit(allocator);
    const forward = std.mem.eql(
        u8,
        &first_expected.bytes,
        first.datagram.payload,
    ) and std.mem.eql(
        u8,
        &second_expected.bytes,
        second.datagram.payload,
    );
    const reverse = std.mem.eql(
        u8,
        &second_expected.bytes,
        first.datagram.payload,
    ) and std.mem.eql(
        u8,
        &first_expected.bytes,
        second.datagram.payload,
    );
    try std.testing.expect(forward or reverse);
}

fn streamRoundTrip(
    client: *runtime.HandshakeClientSession,
    payload: model.Payload,
) !void {
    const stream_id = try client.openBidirectionalStreamWithTimeout(
        model.timeout,
    );
    var committed: usize = 0;
    try client.sendStreamWithTimeout(
        stream_id,
        &payload.bytes,
        true,
        &committed,
        model.timeout,
    );
    try std.testing.expectEqual(payload.bytes.len, committed);
    var response = try client.receiveStreamWithTimeout(model.timeout);
    defer response.deinit();
    try std.testing.expectEqual(stream_id, response.stream_id);
    try std.testing.expect(response.fin);
    try std.testing.expectEqualSlices(
        u8,
        &payload.response().bytes,
        response.payload,
    );
}

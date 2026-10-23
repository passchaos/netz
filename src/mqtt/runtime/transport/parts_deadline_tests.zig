const std = @import("std");
const mqtt = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const mqtt_tls = @import("../../tls_runtime.zig");
const mqtt_ws = @import("../../websocket_runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const BlockedWrite = @import("../acknowledgement/deadline_tests.zig").BlockedWrite;

const Mode = enum { tcp, tls, native_tls, tls12, websocket };
const Outcome = enum { complete, timeout, network_error };

test "MQTT Session deadline writes preserve complete payload across transports" {
    inline for (std.enums.values(Mode)) |mode| try exercise(mode, .complete);
}

test "MQTT Session deadline writes cancel blocked output across transports" {
    inline for (std.enums.values(Mode)) |mode| try exercise(mode, .timeout);
}

test "MQTT Session deadline write preserves standard TLS network failure" {
    try exercise(.tls, .network_error);
}

fn exercise(comptime mode: Mode, outcome: Outcome) !void {
    const blocked = outcome != .complete;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var observer = BlockedWrite{ .delegate = io, .failure = if (outcome == .network_error) error.NetworkDown else null };
    BlockedWrite.active = &observer;
    defer BlockedWrite.active = null;
    var vtable = io.vtable.*;
    vtable.netWrite = BlockedWrite.netWrite;
    const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const secure = mode == .tls or mode == .native_tls or mode == .tls12;
    var server = if (secure) try mqtt_tls.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .protocol_policy = if (mode == .tls12) .tls12_only else .tls13_only,
    }) else if (mode == .websocket) try mqtt_ws.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}) else try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const payload = try allocator.alloc(u8, 48 * 1024);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index *% 7);
    const Peer = struct {
        server: *@TypeOf(server),
        payload: []const u8,
        blocked: bool,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var accepted = try self.server.accept(.{});
            defer accepted.deinit(self.server.allocator);
            var publish = accepted.connection.readPublish() catch |err| switch (err) {
                error.ConnectionClosed, error.ConnectionResetByPeer, error.SocketUnconnected, error.UnexpectedEof, error.TruncatedRecord => if (self.blocked) return else return err,
                else => return err,
            };
            defer publish.deinit(self.server.allocator);
            if (self.blocked) return error.TestUnexpectedResult;
            try std.testing.expectEqualStrings("deadline/parts", publish.publish.topic);
            try std.testing.expectEqualSlices(u8, self.payload, publish.publish.payload);
            try std.testing.expectEqual(@as(?u16, 17), publish.publish.packet_id);
            try accepted.connection.writePubAck(17, 0);
        }
    };
    var peer = Peer{ .server = &server, .payload = payload, .blocked = blocked };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = if (secure) try mqtt_tls.Client.connectAddress(allocator, observed_io, server.address(), "localhost", .{
        .mqtt = .{ .client_id = "parts-deadline" },
        .tls = .{ .verify_host = false },
        .server_verifier = if (mode == .native_tls or mode == .tls12) .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() } else null,
        .protocol_policy = if (mode == .tls12) .tls12_only else .tls13_only,
    }) else if (mode == .websocket) try mqtt_ws.Client.connect(allocator, observed_io, server.address(), .{ .mqtt = .{ .client_id = "parts-deadline" }, .host = "localhost" }) else try runtime.Client.connect(allocator, observed_io, server.address(), .{ .client_id = "parts-deadline" });
    var open = true;
    defer if (open) client.close();
    observer.armed.store(blocked, .release);
    const result = client.writeClientSessionTransmissionWithDeadline(.{ .publish = .{
        .topic = "deadline/parts",
        .payload = payload,
        .qos = .at_least_once,
        .retain = false,
        .dup = false,
        .packet_id = 17,
        .properties = &.{},
        .message_expiry_interval = null,
    } }, .fromNow(observed_io, .{ .raw = if (blocked) .fromMilliseconds(50) else .fromSeconds(2), .clock = .awake }));
    if (blocked) {
        try std.testing.expectError(if (outcome == .network_error) error.NetworkDown else error.Timeout, result);
        try std.testing.expect(observer.entered.load(.acquire));
        try std.testing.expectEqual(outcome == .timeout, observer.canceled.load(.acquire));
        try std.testing.expect(!client.isUsable());
        client.close();
        open = false;
    } else {
        try result;
        var acknowledgement = try client.readPubAck();
        defer acknowledgement.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 17), acknowledgement.ack.packet_id);
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

//! Late extension traffic stays outside HTTP messages after adapter teardown.
const std = @import("std");
const Backend = @import("../../../runtime.zig").Backend;
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const Pair = @import("../session_control/test_support/handshake_pair.zig").Pair;

fn receiveAll(session: anytype, id: u62, expected: []const u8) !void {
    var output: [32]u8 = undefined;
    var received: usize = 0;
    const until: std.Io.Clock.Timestamp = .fromNow(session.h3.established.connection.endpoint.io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    while (true) {
        const event = try session.readStreamIdWithDeadline(id, output[received..], until);
        try std.testing.expect(event == .data);
        received += event.data.bytes;
        if (event.data.fin) break;
    }
    try std.testing.expectEqualStrings(expected, output[0..received]);
}

test "WebTransport closed extension routing ignores late local bidi after final association teardown" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    for ([_]bool{ false, true }) |reset| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        const id = try pair.server.openBidirectionalStream();
        try pair.server.sendStream(id, "server", true);
        try receiveAll(&pair.client, id, "server");
        try pair.client.sendStream(id, "reply", true);
        try receiveAll(&pair.server, id, "reply");
        _ = try pair.client.flushPendingAck();
        const server = pair.connection(.server);
        const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        while (!server.localStreamClosed(id)) try pair.receiveProgress(.server, until);
        try std.testing.expect(server.sendStreamStats(id) == null and server.recvStreamStats(id) == null);
        try pair.server.h3.closeConnectDatagramAssociation(0);
        try std.testing.expect(!pair.server.h3.connect_datagrams.hasDetachedStreams());

        const client = pair.connection(.client);
        var scratch = http3.runtime.ProtectedSendState.init(std.testing.allocator);
        defer scratch.deinit();
        const frames = [_]quic.Frame{if (reset)
            .{ .reset_stream = .{ .stream_id = id, .application_error_code = 91, .final_size = 5 } }
        else
            .{ .stream = .{ .stream_id = id, .data = "reply", .fin = true } }};
        const keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
        try http3.runtime.sendProtectedFrames(client.endpoint, server.endpoint.address(), keys, client.config.peer_connection_id, &client.next_packet_number, &frames, 8, &scratch);
        const request_id = try pair.client.h3.startRequest(.{ .method = "GET", .scheme = "https", .authority = "localhost", .path = "/after-extension" }, null);
        var event = try pair.server.h3.receiveRequestEventWithTimeout(.fromSeconds(1));
        defer event.deinit(std.testing.allocator);
        try std.testing.expect(event == .message and event.message.stream_id == request_id and event.message.value == .head);
        try std.testing.expect(server.localStreamClosed(id));
        try std.testing.expect(server.sendStreamStats(id) == null and server.recvStreamStats(id) == null);
        try std.testing.expect(!server.closing());
    }
}

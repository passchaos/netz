const std = @import("std");
const http3 = @import("../../../mod.zig");
const RequestBuffer = @import("../request_buffer.zig").Set;
const PeerSet = @import("state.zig").Set;

const net = std.Io.net;

test "HTTP/3 dev streaming adoption preserves partial aggregate request" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(8443) };
    var buffered = RequestBuffer.init(allocator, 4096, 4);
    defer buffered.deinit();
    var peers = PeerSet.init(allocator, 4096, 4);
    defer peers.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const body = "aggregate state survives streaming takeover";
    try (http3.Request{
        .method = "POST",
        .path = "/adopt-partial",
        .authority = "localhost",
        .body = body,
    }).write(&encoded, allocator);
    const split = encoded.items.len - body.len + body.len / 2;

    const partial = try buffered.ensureStream(from, 0);
    try partial.insert(.{
        .stream_id = 0,
        .data = encoded.items[0..split],
    });
    try peers.adoptBufferedRequests(&buffered);
    try std.testing.expect(buffered.isEmpty());
    try std.testing.expectEqual(@as(usize, 1), peers.totalRetained());

    try peers.insert(from, .{
        .stream_id = 0,
        .offset = split,
        .data = encoded.items[split..],
        .fin = true,
    });
    var head_event = (try peers.pollRequestHead()) orelse
        return error.TestUnexpectedResult;
    defer head_event.deinit(allocator);
    try std.testing.expect(head_event == .message);
    try std.testing.expect(head_event.message.value == .head);
    try std.testing.expectEqualStrings(
        "/adopt-partial",
        head_event.message.value.head.request.path,
    );

    var received: [64]u8 = undefined;
    var received_len: usize = 0;
    var finished = false;
    while (!finished) {
        var event = (try peers.pollRequestEventFor(from, 0)) orelse
            return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        switch (event) {
            .reset => return error.TestUnexpectedResult,
            .message => |message| switch (message.value) {
                .data_available => {
                    received_len += try peers.readRequestData(
                        from,
                        0,
                        received[received_len..],
                    );
                },
                .finished => finished = true,
                else => return error.TestUnexpectedResult,
            },
        }
    }
    try std.testing.expectEqualStrings(body, received[0..received_len]);
}

test "HTTP/3 head polling retires only unadmitted resets" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    var peers = PeerSet.init(allocator, 512, 3);
    defer peers.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/admitted",
        .authority = "example.test",
    }).write(&encoded, allocator);
    try peers.insert(from, .{
        .stream_id = 0,
        .data = encoded.items,
    });
    var admitted = (try peers.pollRequestHead()) orelse
        return error.TestUnexpectedResult;
    defer admitted.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), admitted.message.stream_id);

    try peers.recordReset(
        from,
        0,
        http3.ApplicationErrorCode.request_cancelled,
    );
    try peers.insert(from, .{
        .stream_id = 4,
        .data = encoded.items,
    });
    try peers.recordReset(
        from,
        4,
        http3.ApplicationErrorCode.request_cancelled,
    );

    try std.testing.expect((try peers.pollRequestHead()) == null);
    try std.testing.expect(peers.containsRequest(from, 0));
    try std.testing.expect(!peers.containsRequest(from, 4));
    try std.testing.expectEqual(@as(usize, 1), peers.totalRetained());

    const reset = (try peers.pollRequestEventFor(from, 0)) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(@as(u62, 0), reset.reset.stream_id);
    try std.testing.expectEqual(@as(usize, 0), peers.totalRetained());
}

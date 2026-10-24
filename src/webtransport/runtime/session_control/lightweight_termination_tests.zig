const std = @import("std");
const support = @import("test_support/lightweight_pair.zig");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const control_mod = @import("../session_control.zig");

fn resetsSession(role: support.Role) !void {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]u64{ webtransport.ApplicationErrorCode.session_gone, http3.ApplicationErrorCode.request_rejected, webtransport.applicationErrorCodeToHttp3(72) }) |code| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.resetConnect(role, code);
        const event = try pair.receive(role);
        try std.testing.expect(event == .reset);
        try std.testing.expectEqual(@as(u64, code), event.reset.http3_code);
        try std.testing.expectEqual(webtransport.http3ToApplicationErrorCode(code), event.reset.application_code);
        const control = if (role == .client) &pair.client.control.control else &pair.accepted.control.control;
        try std.testing.expect(control.state.closed and control.terminal_reported);
        try std.testing.expectError(error.InvalidSessionState, control.ensureOpen());
        try std.testing.expect(control.resetCapsulePayload(0) == null);
        switch (role) {
            .client => {
                const before = pair.client.h3.next_packet_number;
                try std.testing.expectError(error.InvalidSessionState, pair.client.sendDatagram("late"));
                try std.testing.expectError(error.InvalidSessionState, pair.client.sendSessionData("late", false));
                try std.testing.expectError(error.InvalidSessionState, pair.client.receiveDatagramWithTimeout(.fromMilliseconds(5)));
                try std.testing.expectEqual(before, pair.client.h3.next_packet_number);
            },
            .server => {
                const before = pair.server.h3.next_packet_number;
                try std.testing.expectError(error.InvalidSessionState, pair.accepted.sendDatagram(&pair.server, "late"));
                try std.testing.expectEqual(before, pair.server.h3.next_packet_number);
            },
        }
    }
}

test "WebTransport lightweight CONNECT reset closes the client Session with its exact error" {
    try resetsSession(.client);
}

test "WebTransport lightweight CONNECT reset closes the server Session with its exact error" {
    try resetsSession(.server);
}

test "WebTransport lightweight CONNECT reset aborts an incomplete CLOSE and releases its reason" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        var bytes: [600]u8 = undefined;
        _ = try control_mod.writeCloseInto(&bytes, 77, &([_]u8{'r'} ** 512));
        try pair.sendCapsules(role, bytes[0..20]);
        try std.testing.expectError(error.Timeout, pair.receiveWithTimeout(role, .fromMilliseconds(5)));
        const control = if (role == .client) &pair.client.control.control else &pair.accepted.control.control;
        try std.testing.expect(control.close_reason_heap != null and !control.terminal_reported);
        try pair.resetConnect(role, webtransport.ApplicationErrorCode.session_gone);
        const event = try pair.receive(role);
        try std.testing.expect(event == .reset);
        try std.testing.expect(control.close_reason_heap == null);
        try std.testing.expectEqual(@as(usize, 0), control.close_reason_len);
    }
}

test "WebTransport reset after a decoded CLOSE preserves its borrowed metadata" {
    var control = try control_mod.Control.init(std.testing.allocator, .init(0));
    defer control.deinit();
    var bytes: [600]u8 = undefined;
    const reason = [_]u8{'r'} ** 512;
    const close = try control_mod.writeCloseInto(&bytes, 77, &reason);
    const event = (try control.feedCapsulePayload(close)).event.?;
    try std.testing.expect(event == .closed);
    try std.testing.expect(control.resetCapsulePayload(webtransport.ApplicationErrorCode.session_gone) == null);
    try std.testing.expectEqual(@as(?u32, 77), control.state.close_code);
    try std.testing.expectEqualSlices(u8, &reason, event.closed.reason);
}

test "WebTransport lightweight CONNECT reset preserves ordinary HTTP sibling requests" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    for ([_]support.Role{ .client, .server }) |role| {
        var pair: support.Pair = undefined;
        try pair.init(threaded.io());
        defer pair.deinit();
        try pair.resetConnect(role, webtransport.ApplicationErrorCode.session_gone);
        try std.testing.expect((try pair.receive(role)) == .reset);
        const id = try pair.client.h3.sendRequest(.{ .method = "GET", .authority = "localhost", .path = "/sibling" });
        var request = try pair.server.h3.receiveRequestEventForWithTimeout(id, .fromSeconds(1));
        defer request.deinit(std.testing.allocator);
        try std.testing.expect(request == .message and request.message.value == .head);
        try std.testing.expectEqual(id, request.message.stream_id);
        try pair.server.h3.sendResponse(request.message.from, id, .{ .status = 200, .body = "alive" });
        const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        var output: [16]u8 = undefined;
        var used: usize = 0;
        while (true) {
            var response = (try pair.client.h3.receiveResponseEventWithDeadline(id, deadline)) orelse continue;
            defer response.deinit(std.testing.allocator);
            switch (response) {
                .head => try std.testing.expect(response.head == .response and response.head.response.status == 200),
                .data_available => used += try pair.client.h3.readResponseData(id, output[used..]),
                .finished => break,
                else => return error.TestUnexpectedResult,
            }
        }
        try std.testing.expectEqualStrings("alive", output[0..used]);
    }
}

const std = @import("std");
const http1 = @import("../mod.zig");

test "HTTP/1 owned heads parse framing without body bytes and release folded fields on every allocation failure" {
    const request = "POST / HTTP/1.1\r\nHost: example\r\nContent-Length: invalid\r\nTransfer-Encoding: custom,\r\n chunked\r\nX-Trace: first\r\n second\r\n third\r\n\r\n";
    const response = "HTTP/1.1 200 OK\r\nContent-Length: invalid\r\nTransfer-Encoding: custom,\r\n chunked\r\nX-Trace: first\r\n second\r\n third\r\n\r\n";
    for ([_]bool{ false, true }) |is_request| {
        var succeeded = false;
        for (0..32) |fail_index| {
            var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_index });
            if (is_request) {
                var owned = http1.parseOwnedRequestHead(failing.allocator(), request, .{ .allow_obs_fold = true }) catch |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    continue;
                };
                defer owned.deinit(failing.allocator());
                try std.testing.expect(owned.head.must_close);
                try std.testing.expectEqual(http1.BodyFraming.chunked, owned.head.body_framing);
                try std.testing.expect(owned.head.header("content-length") == null);
                try std.testing.expectEqualStrings("first second third", owned.head.header("x-trace").?);
            } else {
                var owned = http1.parseOwnedResponseHead(failing.allocator(), response, .{ .allow_obs_fold = true }, .{}) catch |err| {
                    try std.testing.expectEqual(error.OutOfMemory, err);
                    continue;
                };
                defer owned.deinit(failing.allocator());
                try std.testing.expect(owned.head.must_close);
                try std.testing.expectEqual(http1.BodyFraming.chunked, owned.head.body_framing);
                try std.testing.expect(owned.head.header("content-length") == null);
                try std.testing.expectEqualStrings("first second third", owned.head.header("x-trace").?);
            }
            succeeded = true;
            break;
        }
        try std.testing.expect(succeeded);
    }
}

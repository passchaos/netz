//! Protocol maintenance cannot spend the budget for the next submission.
const std = @import("std");
const support = @import("../../flow/progress/support.zig");
const Pair = support.Pair;

const ExpireAfterSend = struct {
    delegate: std.Io,
    now_ns: i96,
    sends: usize = 0,

    fn now(userdata: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        return .fromNanoseconds(self.now_ns);
    }

    fn netSend(userdata: ?*anyopaque, handle: std.Io.net.Socket.Handle, messages: []std.Io.net.OutgoingMessage, flags: std.Io.net.SendFlags) struct { ?std.Io.net.Socket.SendError, usize } {
        const self: *@This() = @ptrCast(@alignCast(userdata));
        const result = self.delegate.vtable.netSend(self.delegate.userdata, handle, messages, flags);
        if (result[1] != 0) {
            self.sends += result[1];
            self.now_ns += std.time.ns_per_s;
        }
        return result;
    }
};

test "WebTransport stream send stops before submission when maintenance spends its deadline" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        inline for (.{ false, true }) |fin_only| {
            var pair: Pair = undefined;
            _ = try support.pending(&pair, threaded.io(), role);
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            const id = try session.openUnidirectionalStream();
            connection.pacer.enabled = false;
            try std.testing.expectEqual(@as(?u64, 12), session.streams.flow.?.automaticDataGrant());
            const original = connection.endpoint.io;
            var timed = ExpireAfterSend{ .delegate = original, .now_ns = std.Io.Clock.awake.now(original).nanoseconds };
            var vtable = original.vtable.*;
            vtable.now = ExpireAfterSend.now;
            vtable.netSend = ExpireAfterSend.netSend;
            connection.endpoint.io = .{ .userdata = &timed, .vtable = &vtable };
            defer connection.endpoint.io = original;
            const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(timed.now_ns + std.time.ns_per_ms) };
            var committed: usize = 99;
            const result = if (fin_only) session.finishStreamWithDeadline(id, deadline) else session.sendStreamWithDeadline(id, "late", true, &committed, deadline);
            try std.testing.expectError(error.Timeout, result);
            try std.testing.expectEqual(@as(usize, 1), timed.sends);
            try std.testing.expectEqual(@as(u64, 12), session.streams.flow.?.receive_limit.data);
            try std.testing.expect(!session.streams.get(id).?.prefix_sent);
            try std.testing.expect(!session.streams.get(id).?.local_fin);
            if (!fin_only) try std.testing.expectEqual(@as(usize, 0), committed);
        }
    }
}

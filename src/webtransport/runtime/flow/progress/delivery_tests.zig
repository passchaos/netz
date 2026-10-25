//! Pacing-limited receiver credit cannot hide already available application work.
const std = @import("std");
const control = @import("../../session_control.zig");
const progress = @import("../progress.zig");
const support = @import("support.zig");
const Pair = support.Pair;

test "WebTransport automatic grant pacing wait preserves DRAIN before a ready datagram" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        var pair: Pair = undefined;
        _ = try support.pending(&pair, threaded.io(), role);
        defer pair.deinit();
        const session = if (role == .client) &pair.client else &pair.server;
        var storage: [16]u8 = undefined;
        const drain = try control.writeDrainInto(&storage);
        if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, drain, false) else try pair.client.h3.sendRequestBodyPaced(0, drain, false);
        try pair.connection(if (role == .client) .server else .client).send(&.{.{ .datagram = .{ .data = "\x00after drain" } }});
        const Receiver = struct {
            fn run(target: @TypeOf(session)) !void {
                var storage_value: [16]u8 = undefined;
                const payload = try target.receiveDatagramIntoWithTimeout(&storage_value, .fromMilliseconds(100));
                try std.testing.expectEqualStrings("after drain", payload);
            }
        };
        try support.withinBudget(threaded.io(), Receiver.run, .{session});
        try std.testing.expect(session.control.state.draining and !session.control.state.closed);
        try std.testing.expect((try pair.poll(role)).? == .draining);
        try std.testing.expectEqual(@as(?u64, 12), session.streams.flow.?.automaticDataGrant());
    }
}

test "WebTransport automatic grant pacing wait delivers incremental and whole streams" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |whole| {
            for ([_]bool{ false, true }) |buffered| {
                var pair: Pair = undefined;
                const id = try support.pendingWithCredit(&pair, threaded.io(), role, 12);
                defer pair.deinit();
                const session = if (role == .client) &pair.client else &pair.server;
                const peer = if (role == .client) &pair.server else &pair.client;
                const incoming_id = if (whole) try peer.openUnidirectionalStream() else id;
                try peer.sendStream(incoming_id, "tail", whole);
                if (buffered) {
                    const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
                    try pair.receiveProgress(role, deadline);
                }
                const Receiver = struct {
                    fn run(target: @TypeOf(session), all: bool) !void {
                        if (all) {
                            var stream = try target.receiveStreamWithTimeout(.fromMilliseconds(100));
                            defer stream.deinit();
                            try std.testing.expectEqualStrings("tail", stream.payload);
                        } else {
                            var storage: [16]u8 = undefined;
                            const event = try target.readStreamWithTimeout(&storage, .fromMilliseconds(100));
                            try std.testing.expect(event == .data and event.data.bytes == 4);
                            try std.testing.expectEqualStrings("tail", storage[0..event.data.bytes]);
                        }
                    }
                };
                try support.withinBudget(threaded.io(), Receiver.run, .{ session, whole });
                try std.testing.expectEqual(@as(u64, 10), session.streams.flow.?.consumed_data);
                try std.testing.expectEqual(@as(u64, 12), session.streams.flow.?.receive_limit.data);
                try std.testing.expect(!session.control.state.closed);
            }
        }
    }
}

test "WebTransport automatic grant pacing wait retains queued control during one attempt" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |dispatcher| {
            var pair: Pair = undefined;
            _ = try support.pending(&pair, threaded.io(), role);
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            var storage: [64]u8 = undefined;
            const close = try control.writeCloseInto(&storage, 91, "owner retained");
            if (role == .client) try pair.server.h3.sendResponseBodyPaced(0, close, false) else try pair.client.h3.sendRequestBodyPaced(0, close, false);
            if (dispatcher) session.h3.dispatcher_bound = true;
            var context = progress.Context(@TypeOf(&session.h3)){ .control = &session.control, .h3 = &session.h3, .registry = &session.streams, .one_attempt = !dispatcher };
            try context.progress().maintain(null);
            try std.testing.expect(!session.control.state.closed);
            try std.testing.expectEqual(@as(?u64, 12), session.streams.flow.?.automaticDataGrant());
            // Restore this fixture's direct receive ownership for observation.
            if (dispatcher) session.h3.dispatcher_bound = false;
            pair.connection(role).pacer.enabled = false;
            const deadline: std.Io.Clock.Timestamp = .fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try pair.receiveProgress(role, deadline);
            const event = (try pair.poll(role)).?;
            try std.testing.expect(event == .closed);
            try std.testing.expectEqualStrings("owner retained", event.closed.reason);
        }
    }
}

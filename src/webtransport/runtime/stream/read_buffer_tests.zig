//! Invalid receive storage cannot claim a reader or consume terminal events.
const std = @import("std");
const Backend = @import("../../../runtime.zig").Backend;
const support = @import("../session_control/test_support/handshake_pair.zig");
const Pair = support.Pair;
const buffered = @import("../session_control/test_support/buffered_stream.zig");
const incremental = @import("../stream_incremental.zig");

const Poll = enum { ordinary, once, shared };
const Facade = enum { poll, read, timeout, deadline, targeted, targeted_timeout, targeted_deadline };

fn poll(pair: *Pair, comptime role: support.Role, kind: Poll, output: []u8) !void {
    const session = if (role == .client) &pair.client else &pair.server;
    const Lookup = struct {
        fn contains(_: *const anyopaque, _: u64, id: u62) bool {
            return id == 0;
        }
    };
    switch (kind) {
        .ordinary => _ = try incremental.poll(pair.connection(role), &session.streams, session.session_id, output),
        .once => _ = try incremental.pollOnce(pair.connection(role), &session.streams, session.session_id, output),
        .shared => _ = try incremental.pollOnceShared(pair.connection(role), &session.streams, session.session_id, output, .{ .context = pair, .scope = 0, .containsFn = Lookup.contains }),
    }
}

fn callFacade(session: anytype, kind: Facade, output: []u8, until: std.Io.Clock.Timestamp) !void {
    switch (kind) {
        .poll => _ = try session.pollStream(output),
        .read => _ = try session.readStream(output),
        .timeout => _ = try session.readStreamWithTimeout(output, .fromSeconds(1)),
        .deadline => _ = try session.readStreamWithDeadline(output, until),
        .targeted => _ = try session.readStreamId(100, output),
        .targeted_timeout => _ = try session.readStreamIdWithTimeout(100, output, .fromSeconds(1)),
        .targeted_deadline => _ = try session.readStreamIdWithDeadline(100, output, until),
    }
}

test "WebTransport stream read buffer admission preserves whole reader after empty poll" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Poll)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const id = try buffered.ready(&pair, role, "unclaimed", true);
            const session = if (role == .client) &pair.client else &pair.server;
            const before = pair.connection(role).recvStreamStats(id).?.bytes_read;
            const registered = session.streams.registered().len;
            var empty: [0]u8 = .{};
            try std.testing.expectError(error.BufferTooShort, poll(&pair, role, kind, &empty));
            try std.testing.expectEqual(before, pair.connection(role).recvStreamStats(id).?.bytes_read);
            try std.testing.expectEqual(registered, session.streams.registered().len);
            var stream = (try session.pollCompleteStream()).?;
            defer stream.deinit();
            try std.testing.expectEqual(id, stream.stream_id);
            try std.testing.expectEqualStrings("unclaimed", stream.payload);
        }
    }
}

test "WebTransport stream read buffer admission precedes facade lifecycle rejection" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Facade)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            session.streams.flow_violation = true;
            const packet_number = pair.connection(role).next_packet_number;
            var empty: [0]u8 = .{};
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.BufferTooShort, callFacade(session, kind, &empty, until));
            try std.testing.expect(!session.control.flow_violation and !session.control.state.closed);
            try std.testing.expectEqual(packet_number, pair.connection(role).next_packet_number);
        }
    }
}

test "WebTransport stream read buffer admission preserves RESET and zero byte FIN events" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Poll)) |kind| {
            for ([_]bool{ false, true }) |reset| {
                var pair: Pair = undefined;
                try pair.init(backend.io());
                defer pair.deinit();
                const id = try buffered.ready(&pair, role, "prefix", false);
                const session = if (role == .client) &pair.client else &pair.server;
                const peer = if (role == .client) &pair.server else &pair.client;
                var output: [32]u8 = undefined;
                const prefix = (try session.pollStream(&output)).?;
                try std.testing.expect(prefix == .data and !prefix.data.fin);
                try std.testing.expectEqualStrings("prefix", output[0..prefix.data.bytes]);
                if (reset) try peer.resetStream(id, 91) else try peer.finishStream(id);
                const connection = pair.connection(role);
                const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
                while (true) {
                    if (connection.recvStreamStats(id)) |stats| {
                        if ((reset and stats.reset != null) or (!reset and stats.final_size != null)) break;
                    }
                    try pair.receiveProgress(role, until);
                }
                var empty: [0]u8 = .{};
                try std.testing.expectError(error.BufferTooShort, poll(&pair, role, kind, &empty));
                try std.testing.expect(!session.streams.get(id).?.reset_reported and !session.streams.get(id).?.peer_fin);
                const event = (try session.pollStream(&output)).?;
                if (reset) {
                    try std.testing.expect(event == .reset);
                    try std.testing.expectEqual(@as(?u32, 91), event.reset.error_info.application_code);
                } else {
                    try std.testing.expect(event == .data and event.data.fin);
                    try std.testing.expectEqual(@as(usize, 0), event.data.bytes);
                }
                try std.testing.expectEqual(id, if (reset) event.reset.stream_id else event.data.stream_id);
            }
        }
    }
}

test "WebTransport stream read buffer admission retains callback owner precedence" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    for (std.enums.values(Facade)) |kind| {
        var pair: Pair = undefined;
        try pair.init(backend.io());
        defer pair.deinit();
        pair.client.streams.flow_violation = true;
        pair.client.h3.callback_reader_active = true;
        defer pair.client.h3.callback_reader_active = false;
        var empty: [0]u8 = .{};
        const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
        try std.testing.expectError(error.ConcurrentRead, callFacade(&pair.client, kind, &empty, until));
        try std.testing.expect(!pair.client.control.flow_violation and !pair.client.control.state.closed);
    }
}

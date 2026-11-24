//! Stream ownership precedes buffered delivery and Session maintenance.
const std = @import("std");
const Backend = @import("../../../runtime.zig").Backend;
const support = @import("../session_control/test_support/handshake_pair.zig");
const Pair = support.Pair;
const flow_read = @import("../flow/read.zig");
const control = @import("../session_control.zig");

const Incremental = enum { any, timeout, deadline, targeted, targeted_timeout, targeted_deadline };
const Whole = enum { ordinary, timeout, deadline };

fn ready(pair: *Pair, comptime role: support.Role, fin: bool) !u62 {
    return @import("../session_control/test_support/buffered_stream.zig").ready(pair, role, "delivered", fin);
}

fn read(session: anytype, kind: Incremental, id: u62, output: []u8, until: std.Io.Clock.Timestamp) !void {
    switch (kind) {
        .any => _ = try session.readStream(output),
        .timeout => _ = try session.readStreamWithTimeout(output, .fromSeconds(1)),
        .deadline => _ = try session.readStreamWithDeadline(output, until),
        .targeted => _ = try session.readStreamId(id, output),
        .targeted_timeout => _ = try session.readStreamIdWithTimeout(id, output, .fromSeconds(1)),
        .targeted_deadline => _ = try session.readStreamIdWithDeadline(id, output, until),
    }
}

fn receive(session: anytype, kind: Whole, until: std.Io.Clock.Timestamp) !void {
    var stream = switch (kind) {
        .ordinary => try session.receiveStream(),
        .timeout => try session.receiveStreamWithTimeout(.fromSeconds(1)),
        .deadline => try session.receiveStreamWithDeadline(until),
    };
    defer stream.deinit();
}

test "WebTransport stream reader admission rejects dispatcher before buffered incremental delivery" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Incremental)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const id = try ready(&pair, role, false);
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            const before = connection.recvStreamStats(id).?.bytes_read;
            const packet_number = connection.next_packet_number;
            const consumed = session.streams.flow.?.consumed_data;
            const registered = session.streams.registered().len;
            session.h3.dispatcher_bound = true;
            defer session.h3.dispatcher_bound = false;
            var output: [32]u8 = @splat(0xaa);
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.InvalidDispatcherState, read(session, kind, id, &output, until));
            try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
            try std.testing.expectEqual(before, connection.recvStreamStats(id).?.bytes_read);
            try std.testing.expectEqual(consumed, session.streams.flow.?.consumed_data);
            try std.testing.expectEqual(registered, session.streams.registered().len);
            try std.testing.expectEqual(packet_number, connection.next_packet_number);
            const event = (try session.pollStream(&output)).?;
            try std.testing.expect(event == .data and event.data.stream_id == id);
            try std.testing.expectEqualStrings("delivered", output[0..event.data.bytes]);
        }
    }
}

test "WebTransport stream reader admission rejects dispatcher before buffered whole stream delivery" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Whole)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const id = try ready(&pair, role, true);
            const session = if (role == .client) &pair.client else &pair.server;
            const connection = pair.connection(role);
            const before = connection.recvStreamStats(id).?.bytes_read;
            const consumed = session.streams.flow.?.consumed_data;
            const registered = session.streams.registered().len;
            session.h3.dispatcher_bound = true;
            defer session.h3.dispatcher_bound = false;
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.InvalidDispatcherState, receive(session, kind, until));
            try std.testing.expectEqual(before, connection.recvStreamStats(id).?.bytes_read);
            try std.testing.expectEqual(consumed, session.streams.flow.?.consumed_data);
            try std.testing.expectEqual(registered, session.streams.registered().len);
            var stream = (try session.pollCompleteStream()).?;
            defer stream.deinit();
            try std.testing.expectEqual(id, stream.stream_id);
            try std.testing.expectEqualStrings("delivered", stream.payload);
        }
    }
}

test "WebTransport stream reader admission rejects before facade flow cleanup" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for (std.enums.values(Incremental)) |kind| {
            var pair: Pair = undefined;
            try pair.init(backend.io());
            defer pair.deinit();
            const session = if (role == .client) &pair.client else &pair.server;
            session.streams.flow_violation = true;
            session.h3.dispatcher_bound = true;
            defer session.h3.dispatcher_bound = false;
            const packet_number = pair.connection(role).next_packet_number;
            var output: [32]u8 = @splat(0xaa);
            const until: std.Io.Clock.Timestamp = .fromNow(backend.io(), .{ .clock = .awake, .raw = .fromSeconds(1) });
            try std.testing.expectError(error.InvalidDispatcherState, read(session, kind, 100, &output, until));
            try std.testing.expect(!session.control.flow_violation and !session.control.state.closed);
            try std.testing.expectEqual(packet_number, pair.connection(role).next_packet_number);
            try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
        }
    }
}

test "WebTransport stream reader admission guards composable flow readers before buffered CLOSE" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const Kind = enum { incremental, targeted, whole };
    inline for (.{ support.Role.client, support.Role.server }) |role| {
        for ([_]bool{ false, true }) |callback| {
            if (role == .server and callback) continue;
            for (std.enums.values(Kind)) |kind| {
                var pair: Pair = undefined;
                try pair.init(backend.io());
                defer pair.deinit();
                const id = try ready(&pair, role, kind == .whole);
                var capsules: [64]u8 = undefined;
                try pair.sendCapsules(role, try control.writeCloseInto(&capsules, 91, "reader owner"));
                const session = if (role == .client) &pair.client else &pair.server;
                const connection = pair.connection(role);
                const stream_before = connection.recvStreamStats(id).?.bytes_read;
                const control_before = connection.recvStreamStats(0).?.bytes_read;
                if (role == .client and callback) pair.client.h3.callback_reader_active = true else session.h3.dispatcher_bound = true;
                defer {
                    if (role == .client) pair.client.h3.callback_reader_active = false;
                    session.h3.dispatcher_bound = false;
                }
                var output: [32]u8 = @splat(0xaa);
                const Worker = struct {
                    fn run(target: @TypeOf(session), shape: Kind, stream_id: u62, buffer: []u8) !void {
                        switch (shape) {
                            .incremental => _ = try flow_read.read(&target.control, &target.h3, &target.streams, target.session_id, buffer),
                            .targeted => _ = try flow_read.readId(&target.control, &target.h3, &target.streams, target.session_id, stream_id, buffer),
                            .whole => {
                                var stream = try flow_read.receive(&target.control, &target.h3, &target.streams, target.session_id, 1024);
                                defer stream.deinit();
                            },
                        }
                    }
                };
                try std.testing.expectError(if (callback) error.ConcurrentRead else error.InvalidDispatcherState, Worker.run(session, kind, id, &output));
                try std.testing.expectEqual(stream_before, connection.recvStreamStats(id).?.bytes_read);
                try std.testing.expectEqual(control_before, connection.recvStreamStats(0).?.bytes_read);
                try std.testing.expect(!session.control.state.closed);
                try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 32), &output);
                if (role == .client) pair.client.h3.callback_reader_active = false;
                session.h3.dispatcher_bound = false;
                const event = (try pair.poll(role)).?;
                try std.testing.expect(event == .closed);
                try std.testing.expectEqualStrings("reader owner", event.closed.reason);
            }
        }
    }
}

//! One receive owner validates reentry/budgets before queue or protocol access.
//! Buffered inspection remains nonblocking after a payload is fulfilled, so a
//! parsing-time deadline expiry cannot turn consumed input into a lost result.
const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
const datagram = @import("../datagram.zig");
const routing = @import("routing.zig");
const Error = @import("../error.zig").ReceiveTimeoutError;

fn checkDeadline(session: anytype, deadline: ?std.Io.Clock.Timestamp) Error!void {
    if (deadline) |until| _ = try deadline_policy.usableAwake(session.connectionIo(), until);
}

fn validateOwner(session: anytype, stream_id: u62, deadline: ?std.Io.Clock.Timestamp) Error!void {
    const Session = @typeInfo(@TypeOf(session)).pointer.child;
    if (comptime @hasField(Session, "callback_reader_active")) {
        if (session.callback_reader_active) return error.ConcurrentRead;
    }
    if (session.dispatcherBound()) return error.InvalidDispatcherState;
    try checkDeadline(session, deadline);
    try datagram.validateStreamId(stream_id);
    if (!session.connect_datagrams.contains(stream_id)) return error.UnexpectedStream;
    try routing.ensureNegotiated(session.control.settings, session.established.connection, .receive);
}

fn inspectBuffered(progress: anytype) @TypeOf(progress).ErrorSet!void {
    if (comptime @hasDecl(@TypeOf(progress), "inspect")) try progress.inspect(null);
}

pub fn owned(session: anytype, stream_id: u62, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || Error)!datagram.Owned {
    try validateOwner(session, stream_id, deadline);
    while (true) {
        try inspectBuffered(progress);
        if (try session.pollConnectDatagram(stream_id)) |payload| return payload;
        try checkDeadline(session, deadline);
        try progress.maintain(deadline);
        try inspectBuffered(progress);
        if (try session.pollConnectDatagram(stream_id)) |payload| return payload;
        try receivePacket(session, stream_id, deadline, null);
    }
}

pub fn into(session: anytype, stream_id: u62, output: []u8, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || Error)![]u8 {
    try validateOwner(session, stream_id, deadline);
    while (true) {
        try inspectBuffered(progress);
        if (try session.pollConnectDatagramInto(stream_id, output)) |payload| return payload;
        try checkDeadline(session, deadline);
        try progress.maintain(deadline);
        try inspectBuffered(progress);
        if (try session.pollConnectDatagramInto(stream_id, output)) |payload| return payload;
        var target = datagram.ReceiveIntoTarget.init(stream_id, output);
        try receivePacket(session, stream_id, deadline, &target);
        if (try target.finish()) |payload| {
            try inspectBuffered(progress);
            return payload;
        }
    }
}

pub fn many(session: anytype, stream_id: u62, outputs: [][]u8, received: *usize, deadline: ?std.Io.Clock.Timestamp, progress: anytype) (@TypeOf(progress).ErrorSet || Error)!void {
    received.* = 0;
    try validateOwner(session, stream_id, deadline);
    for (outputs) |*output| {
        output.* = try into(session, stream_id, output.*, deadline, progress);
        received.* += 1;
    }
}

fn receivePacket(session: anytype, stream_id: u62, deadline: ?std.Io.Clock.Timestamp, target: ?*datagram.ReceiveIntoTarget) Error!void {
    const Session = @typeInfo(@TypeOf(session)).pointer.child;
    if (!session.connect_datagrams.streamDetached(stream_id)) {
        return session.receiveAttachedConnectDatagramProgress(deadline);
    }
    if (comptime @hasDecl(Session, "receiveDetachedRequestProgress")) {
        if (target) |direct| return session.receiveDetachedRequestProgressInto(stream_id, deadline, direct);
        if (deadline) |until| return session.receiveDetachedRequestProgressWithDeadline(stream_id, until);
        return session.receiveDetachedRequestProgress(stream_id);
    } else {
        if (target) |direct| return session.receiveDetachedResponseProgressInto(stream_id, deadline, direct);
        if (deadline) |until| return session.receiveDetachedResponseProgressWithDeadline(stream_id, until);
        return session.receiveDetachedResponseProgress(stream_id);
    }
}

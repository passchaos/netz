//! Ordered CONNECT progress shared by flow-blocked opens and writes. The
//! callback context lives only for one synchronous owning-session operation.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const quic = @import("../../../quic/mod.zig");
const http3 = @import("../../../http3/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const lifecycle = @import("../connection_lifecycle.zig");
const credits = @import("credits.zig");
const association = @import("../stream_association.zig");

pub const Error = control_mod.Error || quic.runtime.ReceiveTimeoutError;

pub fn buffered(control: *control_mod.Control, connection: *quic.one_rtt.Connection) control_mod.Error!void {
    return bufferedInternal(control, connection, false);
}

pub fn applicationBuffered(control: *control_mod.Control, connection: *quic.one_rtt.Connection) control_mod.Error!void {
    return bufferedInternal(control, connection, true);
}

fn bufferedInternal(control: *control_mod.Control, connection: *quic.one_rtt.Connection, strict: bool) control_mod.Error!void {
    const result = if (strict) control.progressBuffered(connection) else control.progressFlow(connection);
    result catch |err| {
        switch (err) {
            error.InvalidCapsule, error.FlowControlViolation => {
                _ = control.tryRejectInvalidCapsule(connection) catch |rejection_err| switch (rejection_err) {
                    error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => false,
                    else => return rejection_err,
                };
            },
            error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => {},
            else => try http3.runtime.closeConnectionForProtocolError(connection, err),
        }
        return err;
    };
}

pub const Progress = struct {
    pub const ErrorSet = Error;
    context: *anyopaque,
    runFn: *const fn (*anyopaque, ?std.Io.Clock.Timestamp) Error!void,
    maintainFn: *const fn (*anyopaque, ?std.Io.Clock.Timestamp) Error!void,
    // Owning stream reads must drain the same H3 packet cursor used by
    // maintenance, including any retained UDP/GRO batch suffix.
    receiveFn: ?*const fn (*anyopaque, ?std.Io.Clock.Timestamp) Error!void = null,
    waitForPacingFn: ?*const fn (*anyopaque, ?std.Io.Clock.Timestamp) Error!void = null,
    // Ready DATAGRAMs need stream accounting without advancing buffered CLOSE
    // capsules or requiring another socket wait.
    inspectFn: ?*const fn (*anyopaque, ?std.Io.Clock.Timestamp) Error!void = null,

    pub fn run(self: Progress, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return self.runFn(self.context, deadline);
    }

    pub fn maintain(self: Progress, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return self.maintainFn(self.context, deadline);
    }

    pub fn inspect(self: Progress, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.inspectFn) |function| try function(self.context, deadline);
    }

    pub fn receive(self: Progress, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        const function = self.receiveFn orelse return false;
        try function(self.context, deadline);
        return true;
    }

    pub fn pacing(self: Progress, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        const function = self.waitForPacingFn orelse return false;
        try function(self.context, deadline);
        return true;
    }
};

pub fn Context(comptime H3Pointer: type) type {
    return struct {
        control: *control_mod.Control,
        h3: H3Pointer,
        registry: *webtransport.StreamRegistry,
        one_attempt: bool = false,
        // Yield only for input this operation can deliver. A partial whole
        // stream or a ready sibling must not suppress a pending grant timer.
        input: enum { none, datagram, incremental, whole } = .none,
        target: ?u62 = null,

        pub fn progress(self: *@This()) Progress {
            return .{ .context = self, .runFn = run, .maintainFn = maintain, .inspectFn = inspect, .receiveFn = receiveProgress, .waitForPacingFn = pacingProgress };
        }

        fn inspect(context_ptr: *anyopaque, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, absolute);
            try self.inspectBuffered();
        }

        pub fn inspectBuffered(self: *@This()) control_mod.Error!void {
            const connection = &self.h3.established.connection;
            association.discoverBuffered(connection, self.registry) catch |err| {
                _ = lifecycle.observeWithoutCredits(self.control, self.h3, self.registry);
                return err;
            };
            _ = lifecycle.observeWithoutCredits(self.control, self.h3, self.registry);
            if (self.registry.flow_violation) return error.FlowControlViolation;
        }

        fn maintain(context_ptr: *anyopaque, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            while (true) {
                try self.maintainBuffered();
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, absolute);
                credits.sendPending(self.control, self.h3, self.registry) catch |err| switch (err) {
                    error.PacingLimited => {
                        if (self.one_attempt or self.h3.dispatcherBound()) return;
                        if (try self.hasBufferedInput()) return;
                        if (try self.waitForPacing(deadline)) {
                            // Give the caller a turn to deliver newly ready
                            // data after processing control from this packet.
                            try self.maintainBuffered();
                            if (try self.hasBufferedInput()) return;
                        }
                        continue;
                    },
                    error.CongestionLimited, error.FlowControlBlocked => return,
                    else => return err,
                };
                return;
            }
        }

        fn maintainBuffered(self: *@This()) Error!void {
            self.control.bindFlow(self.registry.flow);
            lifecycle.observeGoAway(self.control, self.h3);
            if (self.registry.flow_violation) {
                _ = lifecycle.observeWithoutCredits(self.control, self.h3, self.registry);
                return error.FlowControlViolation;
            }
            try buffered(self.control, &self.h3.established.connection);
            try self.control.ensureOpen();
            try self.inspectBuffered();
            try self.control.ensureOpen();
        }

        fn hasBufferedInput(self: *@This()) Error!bool {
            if (self.input == .none) return false;
            if (self.input == .datagram) return try self.h3.connect_datagrams.queuedCount(self.control.session_id.value) != 0;
            const connection = &self.h3.established.connection;
            for (self.registry.registered()) |stream| {
                if (self.target) |id| if (stream.stream_id != id) continue;
                if (stream.locally_initiated and stream.direction == .unidirectional) continue;
                if (self.input == .whole and stream.receive_mode == .incremental) continue;
                if (self.input == .incremental and stream.receive_mode == .whole) continue;
                if ((stream.receive_reset != null and !stream.reset_reported) or
                    (stream.stopped != null and !stream.stopped_reported)) return true;
                if (stream.stop_sent != null) continue;
                const available = connection.availableReceivedStream(stream.stream_id) orelse &.{};
                const prefix = if (stream.receive_mode == .incremental) 0 else stream.receive_prefix_len;
                if (self.input == .incremental and available.len > prefix) return true;
                const stats = connection.recvStreamStats(stream.stream_id) orelse continue;
                if (!stream.peer_fin and stats.final_size != null and stats.bytes_read + available.len == stats.final_size.?) return true;
            }
            return false;
        }

        /// True when an inbound packet arrived, false at a local pacing wake.
        fn waitForPacing(self: *@This(), deadline: ?std.Io.Clock.Timestamp) Error!bool {
            const connection = &self.h3.established.connection;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
            const wake_ns = connection.pendingPacingDeadline() orelse return error.PacingLimited;
            const wake: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(@intCast(wake_ns)) };
            const until = deadline_policy.earlier(wake, deadline).?;
            if (until.durationFromNow(connection.endpoint.io).raw.nanoseconds <= 0) return false;
            self.receive(until) catch |err| {
                if (err == error.Timeout and (deadline == null or std.Io.Clock.Timestamp.compare(until, .lt, deadline.?))) return false;
                return err;
            };
            return true;
        }

        fn receive(self: *@This(), deadline: ?std.Io.Clock.Timestamp) Error!void {
            const H3 = @typeInfo(H3Pointer).pointer.child;
            if (comptime @hasDecl(H3, "receiveDetachedRequestProgress")) {
                if (deadline) |absolute|
                    try self.h3.receiveDetachedRequestProgressWithDeadline(self.control.session_id.value, absolute)
                else
                    try self.h3.receiveDetachedRequestProgress(self.control.session_id.value);
            } else {
                if (deadline) |absolute|
                    try self.h3.receiveDetachedResponseProgressWithDeadline(self.control.session_id.value, absolute)
                else
                    try self.h3.receiveDetachedResponseProgress(self.control.session_id.value);
            }
        }

        fn receiveProgress(context_ptr: *anyopaque, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            return self.receive(deadline);
        }

        fn pacingProgress(context_ptr: *anyopaque, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            _ = try self.waitForPacing(deadline);
            try self.maintainBuffered();
        }

        fn run(context_ptr: *anyopaque, deadline: ?std.Io.Clock.Timestamp) Error!void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            const connection = &self.h3.established.connection;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(connection.endpoint.io, absolute);
            try maintain(context_ptr, deadline);
            if (self.registry.flow == null or self.registry.flow.?.sendDataAvailable() != 0) return;
            if (self.h3.dispatcherBound()) return error.InvalidDispatcherState;
            try self.receive(deadline);
            try maintain(context_ptr, deadline);
        }
    };
}

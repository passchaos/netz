//! Owning client response events and bounded message delivery.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub const PendingData = struct {
    data: http2.runtime.DuplexData,
    offset: usize = 0,
    end_stream: bool,
};

fn pending(self: anytype, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, max_messages: usize, context: anytype, comptime consume: anytype, comptime Hooks: anytype, comptime deadline_validated: bool) !?Hooks.Event {
    if (max_messages == 0) return error.InvalidStreamState;
    if (self.pending_terminal) |response| {
        self.pending_terminal = null;
        self.receive_state = .terminal_delivered;
        return .{ .terminal = response };
    }
    if (self.receive_state != .active) return error.ConnectionClosed;
    if (self.pending_data != null) {
        if (comptime Hooks.raw) return error.InvalidStreamState;
        if (deadline) |until| {
            if (comptime deadline_validated) {
                std.debug.assert(until.clock == .awake);
            } else _ = deadline_policy.usableAwake(
                self.transport.connection.io,
                until,
            ) catch |err| {
                if (cancel_on_timeout) Hooks.fail(self, .cancel);
                return err;
            };
        }
        return try drain(self, deadline, max_messages, context, consume, Hooks);
    }
    return null;
}

pub fn poll(self: anytype, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, max_messages: usize, context: anytype, comptime consume: anytype, comptime Hooks: anytype) !?Hooks.Event {
    return pollWithConnectionCredit(self, deadline, cancel_on_timeout, max_messages, context, consume, Hooks, .immediate);
}

pub fn pollWithConnectionCredit(self: anytype, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, max_messages: usize, context: anytype, comptime consume: anytype, comptime Hooks: anytype, policy: http2.runtime.ClientDuplexStream.ConnectionCreditPolicy) !?Hooks.Event {
    return pollWithConnectionCreditMode(
        self,
        deadline,
        cancel_on_timeout,
        max_messages,
        context,
        consume,
        Hooks,
        policy,
        false,
    );
}

pub fn pollWithConnectionCreditValidatedDeadline(self: anytype, deadline: std.Io.Clock.Timestamp, cancel_on_timeout: bool, max_messages: usize, context: anytype, comptime consume: anytype, comptime Hooks: anytype, policy: http2.runtime.ClientDuplexStream.ConnectionCreditPolicy) !?Hooks.Event {
    return pollWithConnectionCreditMode(
        self,
        deadline,
        cancel_on_timeout,
        max_messages,
        context,
        consume,
        Hooks,
        policy,
        true,
    );
}

fn pollWithConnectionCreditMode(self: anytype, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, max_messages: usize, context: anytype, comptime consume: anytype, comptime Hooks: anytype, policy: http2.runtime.ClientDuplexStream.ConnectionCreditPolicy, comptime deadline_validated: bool) !?Hooks.Event {
    if (try pending(
        self,
        deadline,
        cancel_on_timeout,
        max_messages,
        context,
        consume,
        Hooks,
        deadline_validated,
    )) |event| return event;
    const event = (if (deadline) |absolute| if (comptime deadline_validated)
        self.transport.pollResponseEventWithCreditPolicyAssumeUsableDeadline(
            policy,
            absolute,
        )
    else
        self.transport.pollResponseEventWithCreditPolicyAndDeadline(
            policy,
            absolute,
        ) else self.transport.pollResponseEventWithCreditPolicy(policy)) catch |err| {
        transportReadFailed(self, err, cancel_on_timeout, Hooks);
        return err;
    };
    return if (event) |ready| try transport(self, ready, deadline, max_messages, context, consume, Hooks) else null;
}

pub fn read(self: anytype, deadline: ?std.Io.Clock.Timestamp, cancel_on_timeout: bool, context: anytype, comptime consume: anytype, comptime Hooks: anytype) !Hooks.Event {
    if (try pending(
        self,
        deadline,
        cancel_on_timeout,
        std.math.maxInt(usize),
        context,
        consume,
        Hooks,
        false,
    )) |event| return event;
    const event = Hooks.readTransport(&self.transport, deadline) catch |err| {
        transportReadFailed(self, err, cancel_on_timeout, Hooks);
        return err;
    };
    return transport(self, event, deadline, std.math.maxInt(usize), context, consume, Hooks);
}

/// HTTP/2 retains its cursor after a local read interruption. Keep the gRPC
/// decoder and stream when that transport remains usable. This only applies
/// to transport reads; callback and decode errors follow their own fail path.
fn transportReadFailed(self: anytype, err: anyerror, cancel_on_timeout: bool, comptime Hooks: anytype) void {
    const terminal = self.transport.connection.aggregate_timeout_unusable or switch (err) {
        error.Timeout => cancel_on_timeout,
        error.Canceled, error.ConcurrencyUnavailable => false,
        else => true,
    };
    if (terminal) Hooks.fail(self, if (err == error.Timeout) .cancel else .internal_error);
}

fn drain(self: anytype, deadline: ?std.Io.Clock.Timestamp, max_messages: usize, context: anytype, comptime consume: anytype, comptime Hooks: anytype) !Hooks.Event {
    const data = &self.pending_data.?;
    var delivered: usize = 0;
    const Counter = Hooks.Counter(@TypeOf(context), consume);
    var counter = Counter{ .context = context, .count = &delivered };
    if (self.parse_response_body) {
        const decoder = if (self.decoder) |*value| value else {
            Hooks.fail(self, .internal_error);
            return error.InvalidStreamState;
        };
        const progress = decoder.feedLimited(data.data.data[data.offset..], max_messages, &counter, Counter.deliver) catch |err| {
            Hooks.fail(self, .internal_error);
            return err;
        };
        data.offset += progress.consumed;
    } else data.offset = data.data.data.len;
    if (data.offset != data.data.data.len) return .{ .messages = .{ .count = delivered, .end_stream = false } };
    const ended = data.end_stream;
    data.data.deinit(self.allocator);
    self.pending_data = null;
    if (ended) {
        Hooks.finishDecoder(self) catch |err| {
            Hooks.fail(self, .internal_error);
            return err;
        };
        Hooks.finished(self, deadline) catch |err| {
            Hooks.fail(self, .internal_error);
            return err;
        };
        const response = Hooks.terminal(self, null) catch |err| {
            Hooks.fail(self, .internal_error);
            return err;
        };
        Hooks.closeRequest(self) catch {};
        if (delivered == 0) {
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        }
        self.pending_terminal = response;
        self.receive_state = .terminal_pending;
    }
    return .{ .messages = .{ .count = delivered, .end_stream = ended } };
}

pub fn transport(
    self: anytype,
    transport_event: http2.runtime.DuplexResponseEvent,
    deadline: ?std.Io.Clock.Timestamp,
    max_messages: usize,
    context: anytype,
    comptime consume: anytype,
    comptime Hooks: anytype,
) !Hooks.Event {
    if (self.pending_terminal != null or self.receive_state != .active) {
        var unused = transport_event;
        unused.deinit(self.allocator);
        return error.ConnectionClosed;
    }
    var event = transport_event;
    switch (event) {
        .informational => |head| {
            event = undefined;
            return .{ .informational = head };
        },
        .head => |head| {
            event = undefined;
            Hooks.begin(self, head) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            if (!self.transport.responseFinished()) {
                const stored = self.response_head.?;
                return .{ .initial_metadata = .{
                    .status = stored.status,
                    .headers = stored.headers,
                    .encoding = self.response_encoding,
                } };
            }
            Hooks.finishDecoder(self) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            Hooks.finished(self, deadline) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            const response = Hooks.terminal(self, null) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            Hooks.closeRequest(self) catch {};
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        },
        .data => |value| {
            event = undefined;
            if (comptime Hooks.raw) {
                var data = value;
                const deliver = self.parse_response_body;
                const ended = self.transport.responseFinished();
                if (!deliver) {
                    const consumed = data.data.len;
                    data.deinit(self.allocator);
                    // Discarding a non-gRPC fallback body consumes its bytes
                    // just as reading them into the application would.
                    if (self.transport.responseStreamCreditDeferred()) {
                        self.transport.releaseResponseStreamCreditWithDeadline(consumed, deadline.?) catch |err| {
                            Hooks.fail(self, if (err == error.Timeout) .cancel else .internal_error);
                            return err;
                        };
                    }
                }
                if (ended) {
                    Hooks.finished(self, deadline) catch |err| {
                        if (deliver) data.deinit(self.allocator);
                        Hooks.fail(self, .internal_error);
                        return err;
                    };
                    const response = Hooks.terminal(self, null) catch |err| {
                        if (deliver) data.deinit(self.allocator);
                        Hooks.fail(self, .internal_error);
                        return err;
                    };
                    Hooks.closeRequest(self) catch {};
                    if (!deliver) {
                        self.receive_state = .terminal_delivered;
                        return .{ .terminal = response };
                    }
                    self.pending_terminal = response;
                    self.receive_state = .terminal_pending;
                }
                return if (deliver) .{ .data = data } else .progress;
            }
            self.pending_data = .{ .data = value, .end_stream = self.transport.responseFinished() };
            return drain(self, deadline, max_messages, context, consume, Hooks);
        },
        .trailers => |trailers| {
            event = undefined;
            var trailers_owned = true;
            errdefer if (trailers_owned) {
                http2.Hpack.freeOwnedFields(self.allocator, trailers);
            };
            Hooks.finishDecoder(self) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            Hooks.finished(self, deadline) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            const response = Hooks.terminal(self, trailers) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            trailers_owned = false;
            Hooks.closeRequest(self) catch {};
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        },
        .finished => {
            event = undefined;
            Hooks.finishDecoder(self) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            const response = Hooks.terminal(self, null) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            Hooks.closeRequest(self) catch {};
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        },
        .reset => |reset_value| {
            event = undefined;
            Hooks.discardPending(self);
            const response = Hooks.resetTerminal(self, reset_value) catch |err| {
                Hooks.fail(self, .internal_error);
                return err;
            };
            self.receive_state = .terminal_delivered;
            return .{ .terminal = response };
        },
    }
}

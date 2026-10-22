//! Session flow-control limits from draft-ietf-webtrans-http3-16 section 5.
//! Runtime callers retain per-stream highest offsets and commit grants only
//! after sending their corresponding Capsule successfully.

const std = @import("std");
const quic = @import("../quic/mod.zig");
const http3 = @import("../http3/mod.zig");
const webtransport = @import("mod.zig");

pub const Error = error{ FlowControlBlocked, FlowControlViolation, IntegerOverflow };
pub const max_streams: u64 = @as(u64, 1) << 60;
pub const prohibited_max_stream_data: u64 = 0x190b4d3e;
pub const prohibited_stream_data_blocked: u64 = 0x190b4d42;
pub const Direction = webtransport.StreamDirection;

pub const StreamCounts = struct {
    bidi: u64 = 0,
    uni: u64 = 0,
};

pub const Limits = struct {
    data: u64 = 0,
    bidi: u64 = 0,
    uni: u64 = 0,

    fn validate(self: Limits) Error!void {
        if (self.data > quic.varint.max_value or self.bidi > max_streams or self.uni > max_streams) {
            return error.FlowControlViolation;
        }
    }

    fn fromSettings(settings: http3.Settings) Limits {
        return .{ .data = settings.webtransport_initial_max_data, .bidi = settings.webtransport_initial_max_streams_bidi, .uni = settings.webtransport_initial_max_streams_uni };
    }
};

pub fn intent(settings: http3.Settings) bool {
    const limits = Limits.fromSettings(settings);
    return limits.data != 0 or limits.bidi != 0 or limits.uni != 0;
}

pub fn negotiated(local: http3.Settings, peer: http3.Settings) bool {
    return intent(local) and intent(peer);
}

pub const State = struct {
    enabled: bool,
    /// Limits the peer advertised for this endpoint's sends.
    send_limit: Limits,
    /// Limits this endpoint advertised for peer sends.
    receive_limit: Limits,
    sent: Limits = .{},
    received: Limits = .{},
    /// Receiver policy window and cumulative body bytes released by the
    /// application, including abandoned/reset bytes. Runtime grants preserve
    /// this window as consumption advances.
    receive_window: u64 = 0,
    consumed_data: u64 = 0,
    receive_stream_window: StreamCounts = .{},
    retired_peer: StreamCounts = .{},
    peer_data_blocked: ?u64 = null,
    peer_bidi_blocked: ?u64 = null,
    peer_uni_blocked: ?u64 = null,

    pub fn init(local: http3.Settings, peer: http3.Settings) Error!State {
        const receive_limit = Limits.fromSettings(local);
        const send_limit = Limits.fromSettings(peer);
        try receive_limit.validate();
        try send_limit.validate();
        return .{
            .enabled = negotiated(local, peer),
            .send_limit = send_limit,
            .receive_limit = receive_limit,
            .receive_window = receive_limit.data,
            .receive_stream_window = .{ .bidi = receive_limit.bidi, .uni = receive_limit.uni },
        };
    }

    pub fn sendDataAvailable(self: State) u64 {
        return if (self.enabled) self.send_limit.data -| self.sent.data else quic.varint.max_value;
    }

    pub fn openLocal(self: *State, direction: Direction) Error!void {
        if (!self.enabled) return;
        const used = streams(&self.sent, direction);
        if (used.* >= streams(&self.send_limit, direction).*) return error.FlowControlBlocked;
        used.* += 1;
    }

    pub fn openPeer(self: *State, direction: Direction) Error!void {
        if (!self.enabled) return;
        const used = streams(&self.received, direction);
        if (used.* >= streams(&self.receive_limit, direction).*) return error.FlowControlViolation;
        used.* += 1;
    }

    /// Charge new highest-offset growth, excluding the association header.
    /// Retransmission and overlapping writes consume no additional credit.
    pub fn accountSent(self: *State, previous: u64, highest: u64, header_len: u64) Error!void {
        if (!self.enabled) return;
        const delta = bodyGrowth(previous, highest, header_len);
        const next = std.math.add(u64, self.sent.data, delta) catch return error.FlowControlBlocked;
        if (next > self.send_limit.data) return error.FlowControlBlocked;
        self.sent.data = next;
    }

    pub fn accountReceived(self: *State, previous: u64, highest: u64, header_len: u64) Error!void {
        if (!self.enabled) return;
        const next = std.math.add(u64, self.received.data, bodyGrowth(previous, highest, header_len)) catch return error.FlowControlViolation;
        if (next > self.receive_limit.data) return error.FlowControlViolation;
        self.received.data = next;
    }

    /// RESET's Final Size charges application data that was lost in flight.
    pub fn accountReset(self: *State, previous: u64, final_size: u64, header_len: u64) Error!void {
        if (!self.enabled) return;
        if (final_size < previous or final_size < header_len) return error.FlowControlViolation;
        try self.accountReceived(previous, final_size, header_len);
    }

    /// Apply peer MAX_* or BLOCKED notifications after negotiation. MAX_*
    /// values must strictly increase because Capsules are delivered in order.
    pub fn receiveCapsule(self: *State, capsule: webtransport.Capsule) Error!bool {
        if (capsule == .unknown) {
            if (capsule.unknown.capsule_type == prohibited_max_stream_data or
                capsule.unknown.capsule_type == prohibited_stream_data_blocked)
            {
                return error.FlowControlViolation;
            }
        }
        if (!self.enabled) return false;
        switch (capsule) {
            .max_data => |value| try increase(&self.send_limit.data, value, quic.varint.max_value),
            .max_streams_bidi => |value| try increase(&self.send_limit.bidi, value, max_streams),
            .max_streams_uni => |value| try increase(&self.send_limit.uni, value, max_streams),
            .data_blocked => |value| {
                if (value > quic.varint.max_value) return error.FlowControlViolation;
                self.peer_data_blocked = value;
            },
            .streams_blocked_bidi => |value| {
                if (value > max_streams) return error.FlowControlViolation;
                self.peer_bidi_blocked = value;
            },
            .streams_blocked_uni => |value| {
                if (value > max_streams) return error.FlowControlViolation;
                self.peer_uni_blocked = value;
            },
            else => return false,
        }
        return true;
    }

    /// Preflight a receiver grant without changing the advertised limit.
    pub fn prepareGrantData(self: *const State, value: u64) Error!webtransport.Capsule {
        try validateIncrease(self.receive_limit.data, value, quic.varint.max_value);
        return .{ .max_data = value };
    }

    pub fn prepareGrantStreams(self: *const State, direction: Direction, value: u64) Error!webtransport.Capsule {
        const previous = switch (direction) {
            .bidirectional => self.receive_limit.bidi,
            .unidirectional => self.receive_limit.uni,
        };
        try validateIncrease(previous, value, max_streams);
        return switch (direction) {
            .bidirectional => .{ .max_streams_bidi = value },
            .unidirectional => .{ .max_streams_uni = value },
        };
    }

    /// Commit the grant only after its serialized Capsule reaches the wire.
    pub fn commitGrant(self: *State, capsule: webtransport.Capsule) Error!void {
        switch (capsule) {
            .max_data => |value| {
                try increase(&self.receive_limit.data, value, quic.varint.max_value);
                self.receive_window = @max(self.receive_window, value -| self.consumed_data);
            },
            .max_streams_bidi => |value| {
                try increase(&self.receive_limit.bidi, value, max_streams);
                self.receive_stream_window.bidi = @max(self.receive_stream_window.bidi, value -| self.retired_peer.bidi);
            },
            .max_streams_uni => |value| {
                try increase(&self.receive_limit.uni, value, max_streams);
                self.receive_stream_window.uni = @max(self.receive_stream_window.uni, value -| self.retired_peer.uni);
            },
            else => return error.FlowControlViolation,
        }
    }

    /// Replenish after half the policy window is consumed. Explicit grants
    /// can enlarge that window; zero credit remains zero until granted.
    pub fn automaticDataGrant(self: *const State) ?u64 {
        if (!self.enabled or self.receive_window == 0) return null;
        if (self.receive_limit.data -| self.consumed_data > self.receive_window / 2) return null;
        const maximum = @min(self.receive_window +| self.consumed_data, quic.varint.max_value);
        return if (maximum > self.receive_limit.data) maximum else null;
    }

    /// The runtime calls this once after retiring an associated peer stream.
    /// Cumulative opening/data accounting remains intact after its record goes.
    pub fn retirePeer(self: *State, direction: Direction) Error!void {
        if (!self.enabled) return;
        const retired = switch (direction) {
            .bidirectional => &self.retired_peer.bidi,
            .unidirectional => &self.retired_peer.uni,
        };
        if (retired.* >= streams(&self.received, direction).*) return error.FlowControlViolation;
        retired.* += 1;
    }

    pub fn automaticStreamGrant(self: *const State, direction: Direction) ?u64 {
        if (!self.enabled) return null;
        const window, const retired, const previous = switch (direction) {
            .bidirectional => .{ self.receive_stream_window.bidi, self.retired_peer.bidi, self.receive_limit.bidi },
            .unidirectional => .{ self.receive_stream_window.uni, self.retired_peer.uni, self.receive_limit.uni },
        };
        if (window == 0) return null;
        const maximum = @min(window +| retired, max_streams);
        return if (maximum > previous) maximum else null;
    }
};

fn streams(limits: *Limits, direction: Direction) *u64 {
    return switch (direction) {
        .bidirectional => &limits.bidi,
        .unidirectional => &limits.uni,
    };
}

fn bodyGrowth(previous: u64, highest: u64, header_len: u64) u64 {
    return (highest -| header_len) -| (previous -| header_len);
}

fn validateIncrease(previous: u64, next: u64, maximum: u64) Error!void {
    if (next <= previous or next > maximum) return error.FlowControlViolation;
}

fn increase(value: *u64, next: u64, maximum: u64) Error!void {
    try validateIncrease(value.*, next, maximum);
    value.* = next;
}

test {
    _ = @import("flow_control/tests.zig");
}

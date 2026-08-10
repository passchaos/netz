//! Adapter that projects netz QUIC codec/state into qlog event views.
//!
//! Keeping frame conversion and event policy here prevents the transport state
//! machine from accumulating a second copy of qlog's schema logic.

const std = @import("std");
const quic = @import("../../mod.zig");
const events = @import("events.zig");
const frame_adapter = @import("frame_adapter.zig");
const encoder = @import("encoder.zig");

pub const max_frames_per_packet: usize = 256;
pub const max_ack_ranges_per_packet: usize = 256;

pub const Error = encoder.Error || frame_adapter.Error || error{
    TooManyFrames,
    TooManyAckRanges,
};

pub const Observer = struct {
    trace: *encoder.Trace,
    frame_views: [max_frames_per_packet]events.Frame = undefined,
    ack_ranges: [max_ack_ranges_per_packet]events.AckRange = undefined,
    failure: ?anyerror = null,

    pub fn init(trace: *encoder.Trace) Observer {
        return .{ .trace = trace };
    }

    /// Return and clear the first observer error. Packet transport never rolls
    /// back on an observability failure because doing so could duplicate
    /// application data; callers can poll this sticky diagnostic separately.
    pub fn takeError(self: *Observer) ?anyerror {
        const failure = self.failure;
        self.failure = null;
        return failure;
    }

    pub fn connectionStarted(self: *Observer, now_ns: u64) void {
        if (self.failure != null) return;
        self.trace.writeEvent(now_ns, .{ .connection_started = .{} }) catch |err| {
            self.failure = err;
        };
    }

    pub fn packetSent(
        self: *Observer,
        now_ns: u64,
        packet_number: u64,
        packet_length: usize,
        frames: []const quic.Frame,
        ack_delay_exponent: u6,
    ) void {
        if (self.failure != null) return;
        self.writePacket(
            now_ns,
            .sent,
            packet_number,
            packet_length,
            frames,
            ack_delay_exponent,
        ) catch |err| {
            self.failure = err;
        };
    }

    pub fn packetReceived(
        self: *Observer,
        now_ns: u64,
        packet_number: u64,
        packet_length: usize,
        frames: []const quic.Frame,
        ack_delay_exponent: u6,
    ) void {
        if (self.failure != null) return;
        self.writePacket(
            now_ns,
            .received,
            packet_number,
            packet_length,
            frames,
            ack_delay_exponent,
        ) catch |err| {
            self.failure = err;
        };
    }

    pub fn metricsUpdated(
        self: *Observer,
        now_ns: u64,
        metrics: events.RecoveryMetrics,
    ) void {
        if (self.failure != null) return;
        self.trace.writeEvent(
            now_ns,
            .{ .metrics_updated = metrics },
        ) catch |err| {
            self.failure = err;
        };
    }

    pub fn packetLost(
        self: *Observer,
        now_ns: u64,
        packet_number: u64,
        trigger: []const u8,
    ) void {
        if (self.failure != null) return;
        self.trace.writeEvent(now_ns, .{ .packet_lost = .{
            .packet_type = .one_rtt,
            .packet_number = packet_number,
            .trigger = trigger,
        } }) catch |err| {
            self.failure = err;
        };
    }

    pub fn connectionClosed(
        self: *Observer,
        now_ns: u64,
        trigger: []const u8,
        owner: ?events.Owner,
        error_space: events.ErrorSpace,
        error_code: u64,
        reason: []const u8,
    ) void {
        if (self.failure != null) return;
        self.trace.writeEvent(now_ns, .{ .connection_closed = .{
            .trigger = trigger,
            .owner = owner,
            .error_space = error_space,
            .error_code = error_code,
            .reason = reason,
        } }) catch |err| {
            self.failure = err;
        };
    }

    pub fn keyUpdated(
        self: *Observer,
        now_ns: u64,
        trigger: []const u8,
        key_type: []const u8,
        generation: u64,
    ) void {
        if (self.failure != null) return;
        self.trace.writeEvent(now_ns, .{ .key_updated = .{
            .trigger = trigger,
            .key_type = key_type,
            .generation = generation,
        } }) catch |err| {
            self.failure = err;
        };
    }

    fn writePacket(
        self: *Observer,
        now_ns: u64,
        direction: enum { sent, received },
        packet_number: u64,
        packet_length: usize,
        frames: []const quic.Frame,
        ack_delay_exponent: u6,
    ) Error!void {
        if (frames.len > self.frame_views.len) return error.TooManyFrames;

        var total_ranges: usize = 0;
        for (frames) |frame| {
            if (frame == .ack) {
                total_ranges = std.math.add(
                    usize,
                    total_ranges,
                    frame.ack.ranges.len,
                ) catch return error.TooManyAckRanges;
            }
        }
        if (total_ranges > self.ack_ranges.len) {
            return error.TooManyAckRanges;
        }

        var range_offset: usize = 0;
        for (frames, self.frame_views[0..frames.len]) |frame, *frame_view| {
            const adapted = try frame_adapter.adapt(
                frame,
                self.ack_ranges[range_offset..total_ranges],
                .{ .ack_delay_exponent = ack_delay_exponent },
            );
            frame_view.* = adapted.frame;
            range_offset += adapted.ack_ranges_used;
        }

        const packet = events.Packet{
            .packet_type = .one_rtt,
            .packet_number = packet_number,
            .length = packet_length,
            .frames = self.frame_views[0..frames.len],
        };
        switch (direction) {
            .sent => try self.trace.writeEvent(
                now_ns,
                .{ .packet_sent = packet },
            ),
            .received => try self.trace.writeEvent(
                now_ns,
                .{ .packet_received = packet },
            ),
        }
    }
};

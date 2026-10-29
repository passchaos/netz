//! Non-blocking gRPC keepalive policy for the shared single-reader channel.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");

fn awakeNow(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .zero, .clock = .awake });
}

/// grpc-core-compatible client keepalive defaults. Null at the containing
/// SharedChannel option disables probes completely.
pub const Options = struct {
    interval: std.Io.Duration = .fromSeconds(2 * 60 * 60),
    timeout: std.Io.Duration = .fromSeconds(20),
    permit_without_calls: bool = false,

    pub fn validate(self: Options) error{InvalidSharedOptions}!void {
        if (self.interval.nanoseconds <= 0 or self.timeout.nanoseconds <= 0) {
            return error.InvalidSharedOptions;
        }
    }
};

pub const Stats = struct {
    probes_sent: u64,
    acknowledgements: u64,
    timeouts: u64,
};

pub const Counters = struct {
    probes_sent: std.atomic.Value(u64) = .init(0),
    acknowledgements: std.atomic.Value(u64) = .init(0),
    timeouts: std.atomic.Value(u64) = .init(0),

    pub fn snapshot(self: *const Counters) Stats {
        // Completion counters publish after probe submission. Read them first,
        // then acquire the sent total so a snapshot cannot report more
        // completions than submitted probes.
        const acknowledgements = self.acknowledgements.load(.acquire);
        const timeouts = self.timeouts.load(.acquire);
        return .{
            .probes_sent = self.probes_sent.load(.acquire),
            .acknowledgements = acknowledgements,
            .timeouts = timeouts,
        };
    }
};

/// Per-endpoint scheduling state. The HTTP/2 connection retains exact ACK
/// matching while this driver owns only policy deadlines and telemetry.
pub const Driver = struct {
    last_peer_activity: ?std.Io.Clock.Timestamp = null,
    probe_deadline: ?std.Io.Clock.Timestamp = null,
    next_sequence: u32 = 0,

    pub fn connected(self: *Driver, io: std.Io) void {
        self.last_peer_activity = awakeNow(io);
        self.probe_deadline = null;
    }

    pub fn disconnected(self: *Driver) void {
        self.last_peer_activity = null;
        self.probe_deadline = null;
    }

    pub fn nextDeadline(
        self: Driver,
        configured: ?Options,
        has_calls: bool,
    ) ?std.Io.Clock.Timestamp {
        if (self.probe_deadline) |deadline| return deadline;
        const options = configured orelse return null;
        if (!has_calls and !options.permit_without_calls) return null;
        const activity = self.last_peer_activity orelse return null;
        return .{
            .raw = activity.raw.addDuration(options.interval),
            .clock = .awake,
        };
    }

    pub fn observePump(
        self: *Driver,
        io: std.Io,
        connection: *http2.runtime.Connection,
        event: http2.runtime.ClientDuplexPumpEvent,
        counters: *Counters,
    ) void {
        switch (event) {
            .wake => {},
            else => self.last_peer_activity = awakeNow(io),
        }
        self.observeAcknowledgement(io, connection, counters);
    }

    pub fn observeAcknowledgement(
        self: *Driver,
        io: std.Io,
        connection: *http2.runtime.Connection,
        counters: *Counters,
    ) void {
        if (!connection.takePingProbeAcknowledged()) return;
        self.probe_deadline = null;
        self.last_peer_activity = awakeNow(io);
        _ = counters.acknowledgements.fetchAdd(1, .release);
    }

    /// Handle the keepalive deadline selected by the endpoint owner. Starting
    /// a probe performs only the bounded PING write; subsequent application
    /// pumping observes the ACK or reaches the independent probe deadline.
    pub fn handleDeadline(
        self: *Driver,
        io: std.Io,
        connection: *http2.runtime.Connection,
        configured: ?Options,
        has_calls: bool,
        output_deadline: std.Io.Clock.Timestamp,
        counters: *Counters,
    ) !void {
        const options = configured orelse return;
        const now = awakeNow(io);
        if (self.probe_deadline) |deadline| {
            if (deadline.durationFromNow(io).raw.nanoseconds > 0) return;
            connection.abandonPingProbe();
            self.probe_deadline = null;
            _ = counters.timeouts.fetchAdd(1, .release);
            return error.Timeout;
        }
        if (!has_calls and !options.permit_without_calls) return;
        const activity = self.last_peer_activity orelse now;
        const due = std.Io.Clock.Timestamp{
            .raw = activity.raw.addDuration(options.interval),
            .clock = .awake,
        };
        if (due.durationFromNow(io).raw.nanoseconds > 0) return;

        var payload: [8]u8 = .{ 'N', 'Z', 'G', 'K', 0, 0, 0, 0 };
        std.mem.writeInt(u32, payload[4..8], self.next_sequence, .big);
        try connection.beginPingProbeWithDeadline(payload, output_deadline);
        self.next_sequence +%= 1;
        self.probe_deadline = .fromNow(io, .{
            .raw = options.timeout,
            .clock = .awake,
        });
        _ = counters.probes_sent.fetchAdd(1, .release);
    }
};

test "gRPC keepalive defaults and validation match grpc-core channel policy" {
    const options: Options = .{};
    try options.validate();
    try std.testing.expectEqual(
        @as(i96, 2 * 60 * 60 * std.time.ns_per_s),
        options.interval.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 20 * std.time.ns_per_s),
        options.timeout.nanoseconds,
    );
    try std.testing.expect(!options.permit_without_calls);
    try std.testing.expectError(
        error.InvalidSharedOptions,
        (Options{ .interval = .zero }).validate(),
    );
    try std.testing.expectError(
        error.InvalidSharedOptions,
        (Options{ .timeout = .zero }).validate(),
    );

    var driver: Driver = .{};
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    driver.connected(threaded.io());
    try std.testing.expect(driver.nextDeadline(null, true) == null);
}

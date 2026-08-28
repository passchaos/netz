//! Mosquitto-compatible exponentially weighted broker rates.
//!
//! Samples are cumulative counters taken on each `$SYS` publication. The
//! update scales the observed delta to a per-minute rate, then applies the
//! standard 1/5/15-minute exponential decays used by Mosquitto's sys tree.

const std = @import("std");

pub const Counters = struct {
    messages_received: u64 = 0,
    messages_sent: u64 = 0,
    publish_messages_dropped: u64 = 0,
    publish_messages_received: u64 = 0,
    publish_messages_sent: u64 = 0,
    bytes_received: u64 = 0,
    bytes_sent: u64 = 0,
};

pub const Rates = struct {
    messages_received: f64 = 0,
    messages_sent: f64 = 0,
    publish_messages_dropped: f64 = 0,
    publish_messages_received: f64 = 0,
    publish_messages_sent: f64 = 0,
    bytes_received: f64 = 0,
    bytes_sent: f64 = 0,
};

pub const Snapshot = struct {
    one_minute: Rates = .{},
    five_minutes: Rates = .{},
    fifteen_minutes: Rates = .{},
};

pub const Tracker = struct {
    last_sample_ns: ?i96 = null,
    previous: Counters = .{},
    snapshot: Snapshot = .{},

    pub fn init(now_ns: i96) Tracker {
        return .{ .last_sample_ns = now_ns };
    }

    /// Advance the EWMA at `now_ns`. Counter reset/wrap is treated as a fresh
    /// interval beginning at zero instead of manufacturing a huge rate.
    pub fn sample(self: *Tracker, now_ns: i96, current: Counters) Snapshot {
        const previous_ns = self.last_sample_ns orelse {
            self.last_sample_ns = now_ns;
            self.previous = current;
            return self.snapshot;
        };
        if (now_ns <= previous_ns) return self.snapshot;

        const elapsed_seconds = @as(f64, @floatFromInt(now_ns - previous_ns)) /
            @as(f64, std.time.ns_per_s);
        updateRates(
            &self.snapshot.one_minute,
            self.previous,
            current,
            elapsed_seconds,
            60.0,
        );
        updateRates(
            &self.snapshot.five_minutes,
            self.previous,
            current,
            elapsed_seconds,
            300.0,
        );
        updateRates(
            &self.snapshot.fifteen_minutes,
            self.previous,
            current,
            elapsed_seconds,
            900.0,
        );
        self.last_sample_ns = now_ns;
        self.previous = current;
        return self.snapshot;
    }
};

fn updateRates(
    rates: *Rates,
    previous: Counters,
    current: Counters,
    elapsed_seconds: f64,
    period_seconds: f64,
) void {
    const exponent = @exp(-elapsed_seconds / period_seconds);
    const per_minute = 60.0 / elapsed_seconds;
    inline for (@typeInfo(Counters).@"struct".fields) |field| {
        const old = @field(previous, field.name);
        const new = @field(current, field.name);
        const delta = if (new >= old) new - old else new;
        const interval_rate = @as(f64, @floatFromInt(delta)) * per_minute;
        const prior_rate = @field(rates, field.name);
        @field(rates, field.name) = interval_rate +
            exponent * (prior_rate - interval_rate);
    }
}

test "MQTT broker load metrics match one five and fifteen minute EWMA" {
    var tracker = Tracker.init(0);
    const snapshot = tracker.sample(60 * std.time.ns_per_s, .{
        .messages_received = 60,
        .messages_sent = 120,
    });
    try std.testing.expectApproxEqAbs(
        60.0 * (1.0 - @exp(-1.0)),
        snapshot.one_minute.messages_received,
        0.000001,
    );
    try std.testing.expectApproxEqAbs(
        120.0 * (1.0 - @exp(-0.2)),
        snapshot.five_minutes.messages_sent,
        0.000001,
    );
    try std.testing.expectApproxEqAbs(
        60.0 * (1.0 - @exp(-1.0 / 15.0)),
        snapshot.fifteen_minutes.messages_received,
        0.000001,
    );
}

test "MQTT broker load metrics tolerate clock stalls and counter reset" {
    var tracker = Tracker.init(10);
    tracker.previous.bytes_received = 100;
    const stalled = tracker.sample(10, .{ .bytes_received = 200 });
    try std.testing.expectEqual(@as(f64, 0), stalled.one_minute.bytes_received);
    const reset = tracker.sample(60 * std.time.ns_per_s + 10, .{
        .bytes_received = 60,
    });
    try std.testing.expectApproxEqAbs(
        60.0 * (1.0 - @exp(-1.0)),
        reset.one_minute.bytes_received,
        0.000001,
    );
}

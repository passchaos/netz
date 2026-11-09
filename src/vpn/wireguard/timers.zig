//! WireGuard peer timer schedule as a pure state machine.
//!
//! No threads or wall clock: the caller supplies monotonic milliseconds and
//! jitter, polls `nextDeadline`, and executes the returned action. This mirrors
//! wireguard-go's timer semantics while remaining deterministic in tests.

const std = @import("std");

pub const rekey_after_time_ms: i64 = 120_000;
pub const rekey_attempt_time_ms: i64 = 90_000;
pub const rekey_timeout_ms: i64 = 5_000;
pub const max_timer_handshakes: u8 = 18;
pub const rekey_timeout_jitter_max_ms: i64 = 334;
pub const reject_after_time_ms: i64 = 180_000;
pub const keepalive_timeout_ms: i64 = 10_000;
pub const cookie_refresh_ms: i64 = 120_000;
pub const handshake_initiation_rate_ms: i64 = 20;
pub const zero_key_material_delay_ms: i64 = reject_after_time_ms * 3;

pub const Action = enum {
    send_handshake_retry,
    send_keepalive,
    send_new_handshake,
    zero_key_material,
};

pub const Timers = struct {
    retransmit_handshake_ms: ?i64 = null,
    send_keepalive_ms: ?i64 = null,
    new_handshake_ms: ?i64 = null,
    zero_key_material_ms: ?i64 = null,
    persistent_keepalive_ms: ?i64 = null,
    handshake_attempts: u8 = 0,
    need_another_keepalive: bool = false,
    sent_last_minute_handshake: bool = false,

    pub fn reset(self: *Timers) void {
        self.* = .{};
    }

    pub fn nextDeadline(self: *const Timers) ?i64 {
        var deadline: ?i64 = null;
        for ([_]?i64{
            self.retransmit_handshake_ms,
            self.send_keepalive_ms,
            self.new_handshake_ms,
            self.zero_key_material_ms,
            self.persistent_keepalive_ms,
        }) |candidate| {
            const value = candidate orelse continue;
            if (deadline == null or value < deadline.?) deadline = value;
        }
        return deadline;
    }

    pub fn handshakeInitiated(self: *Timers, now_ms: i64, jitter_ms: i64) void {
        self.retransmit_handshake_ms = now_ms + rekey_timeout_ms +
            clampJitter(jitter_ms);
    }

    pub fn handshakeComplete(self: *Timers) void {
        self.retransmit_handshake_ms = null;
        self.handshake_attempts = 0;
        self.sent_last_minute_handshake = false;
    }

    pub fn dataSent(self: *Timers, now_ms: i64, jitter_ms: i64) void {
        if (self.new_handshake_ms == null) {
            self.new_handshake_ms = now_ms + keepalive_timeout_ms +
                rekey_timeout_ms + clampJitter(jitter_ms);
        }
    }

    pub fn dataReceived(self: *Timers, now_ms: i64) void {
        if (self.send_keepalive_ms == null) {
            self.send_keepalive_ms = now_ms + keepalive_timeout_ms;
        } else {
            self.need_another_keepalive = true;
        }
    }

    pub fn anyAuthenticatedPacketSent(self: *Timers) void {
        self.send_keepalive_ms = null;
    }

    pub fn anyAuthenticatedPacketReceived(self: *Timers) void {
        self.new_handshake_ms = null;
    }

    pub fn sessionDerived(self: *Timers, now_ms: i64) void {
        self.zero_key_material_ms = now_ms + zero_key_material_delay_ms;
    }

    pub fn persistentKeepaliveTouched(
        self: *Timers,
        now_ms: i64,
        interval_seconds: u16,
    ) void {
        if (interval_seconds == 0) return;
        self.persistent_keepalive_ms = now_ms +
            @as(i64, interval_seconds) * 1000;
    }

    /// Returns the next due action and advances that timer. Call repeatedly
    /// while `nextDeadline` is at or before `now_ms`.
    pub fn expire(self: *Timers, now_ms: i64) ?Action {
        const deadline = self.nextDeadline() orelse return null;
        if (deadline > now_ms) return null;

        if (self.retransmit_handshake_ms) |value| {
            if (value <= now_ms) {
                self.retransmit_handshake_ms = null;
                if (self.handshake_attempts > max_timer_handshakes) {
                    self.send_keepalive_ms = null;
                    if (self.zero_key_material_ms == null) {
                        self.zero_key_material_ms = now_ms +
                            zero_key_material_delay_ms;
                    }
                    return .zero_key_material;
                }
                self.handshake_attempts += 1;
                self.retransmit_handshake_ms = now_ms + rekey_timeout_ms;
                return .send_handshake_retry;
            }
        }

        if (self.send_keepalive_ms) |value| {
            if (value <= now_ms) {
                self.send_keepalive_ms = null;
                if (self.need_another_keepalive) {
                    self.need_another_keepalive = false;
                    self.send_keepalive_ms = now_ms + keepalive_timeout_ms;
                }
                return .send_keepalive;
            }
        }

        if (self.new_handshake_ms) |value| {
            if (value <= now_ms) {
                self.new_handshake_ms = null;
                return .send_new_handshake;
            }
        }

        if (self.zero_key_material_ms) |value| {
            if (value <= now_ms) {
                self.zero_key_material_ms = null;
                return .zero_key_material;
            }
        }

        if (self.persistent_keepalive_ms) |value| {
            if (value <= now_ms) {
                self.persistent_keepalive_ms = null;
                return .send_keepalive;
            }
        }

        return null;
    }
};

fn clampJitter(jitter_ms: i64) i64 {
    if (jitter_ms < 0) return 0;
    if (jitter_ms > rekey_timeout_jitter_max_ms) {
        return rekey_timeout_jitter_max_ms;
    }
    return jitter_ms;
}

test "handshake retransmission and completion" {
    var timers = Timers{};
    timers.handshakeInitiated(0, 100);
    try std.testing.expectEqual(@as(?i64, 5_100), timers.nextDeadline());

    try std.testing.expectEqual(
        @as(?Action, .send_handshake_retry),
        timers.expire(5_100),
    );
    try std.testing.expectEqual(@as(u8, 1), timers.handshake_attempts);
    try std.testing.expectEqual(@as(?i64, 10_100), timers.nextDeadline());

    timers.handshakeComplete();
    try std.testing.expectEqual(@as(?i64, null), timers.nextDeadline());
    try std.testing.expectEqual(@as(u8, 0), timers.handshake_attempts);
}

test "retransmission gives up and schedules key erasure" {
    var timers = Timers{};
    timers.handshakeInitiated(0, 0);
    var now: i64 = 0;
    var attempts: u8 = 0;
    while (true) {
        now = timers.nextDeadline().?;
        const action = timers.expire(now).?;
        if (action == .zero_key_material) break;
        attempts += 1;
    }
    try std.testing.expectEqual(
        max_timer_handshakes + 1,
        attempts,
    );
    try std.testing.expectEqual(
        @as(?i64, now + zero_key_material_delay_ms),
        timers.zero_key_material_ms,
    );
}

test "data traffic schedules keepalive and new-handshake timers" {
    var timers = Timers{};
    timers.dataReceived(0);
    try std.testing.expectEqual(@as(?i64, 10_000), timers.send_keepalive_ms);

    // A second receive before the timer fires requires another keepalive.
    timers.dataReceived(100);
    try std.testing.expect(timers.need_another_keepalive);
    try std.testing.expectEqual(
        @as(?Action, .send_keepalive),
        timers.expire(10_000),
    );
    try std.testing.expectEqual(@as(?i64, 20_000), timers.send_keepalive_ms);
    try std.testing.expect(!timers.need_another_keepalive);

    timers.dataSent(10_000, 0);
    try std.testing.expectEqual(@as(?i64, 25_000), timers.new_handshake_ms);

    timers.anyAuthenticatedPacketReceived();
    try std.testing.expectEqual(@as(?i64, null), timers.new_handshake_ms);

    timers.anyAuthenticatedPacketSent();
    try std.testing.expectEqual(@as(?i64, null), timers.send_keepalive_ms);
}

test "persistent keepalive and key material timers" {
    var timers = Timers{};
    timers.sessionDerived(0);
    try std.testing.expectEqual(@as(?i64, 540_000), timers.zero_key_material_ms);
    try std.testing.expectEqual(
        @as(?Action, .zero_key_material),
        timers.expire(540_000),
    );

    timers.persistentKeepaliveTouched(0, 25);
    try std.testing.expectEqual(@as(?i64, 25_000), timers.persistent_keepalive_ms);
    try std.testing.expectEqual(
        @as(?Action, .send_keepalive),
        timers.expire(25_000),
    );
}

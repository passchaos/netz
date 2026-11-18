const std = @import("std");

/// RFC 9002 section 7.7 packet pacer.
///
/// The bucket permits an initial burst and then replenishes at 1.25*cwnd/RTT,
/// matching the local quicz/quic-zig references. An optional explicit byte
/// rate caps that congestion-derived rate. Common arithmetic stays in u128;
/// only overflowing extreme products fall back to u256 so results remain
/// exact before saturating to the public integer type.
pub const Pacer = struct {
    // Keep optional u64 presence bits together so they share the alignment
    // gap before the word-sized counters instead of growing every connection.
    enabled: bool,
    has_max_pacing_rate: bool,
    has_last_sent_time: bool = false,
    max_datagram_size: usize,
    max_burst_packets: usize,
    max_pacing_rate_bytes_per_second_value: u64,
    budget: usize,
    last_sent_time_ns_value: u64 = 0,

    pub const default_max_burst_packets: usize = 10;
    const Wide = u128;
    const OverflowWide = u256;
    pub const congestion_rate_numerator: Wide = 5;
    pub const congestion_rate_denominator: Wide = 4;
    const nanoseconds_per_second: Wide = std.time.ns_per_s;

    pub fn init(enabled: bool, max_datagram_size: usize, max_burst_packets: usize) Pacer {
        return initWithRateLimit(
            enabled,
            max_datagram_size,
            max_burst_packets,
            null,
        );
    }

    /// Initializes a pacer whose steady-state rate is at most `max_rate`.
    /// `null` preserves the congestion-derived default; zero permits only the
    /// initial/reset burst and never replenishes pacing credit.
    pub fn initWithRateLimit(
        enabled: bool,
        max_datagram_size: usize,
        max_burst_packets: usize,
        max_rate_bytes_per_second: ?u64,
    ) Pacer {
        const burst_packets = @max(max_burst_packets, 1);
        const burst_size = std.math.mul(usize, max_datagram_size, burst_packets) catch std.math.maxInt(usize);
        return .{
            .enabled = enabled,
            .has_max_pacing_rate = max_rate_bytes_per_second != null,
            .max_datagram_size = max_datagram_size,
            .max_burst_packets = burst_packets,
            .max_pacing_rate_bytes_per_second_value = max_rate_bytes_per_second orelse 0,
            .budget = burst_size,
        };
    }

    pub fn maxPacingRateBytesPerSecond(self: Pacer) ?u64 {
        return if (self.has_max_pacing_rate)
            self.max_pacing_rate_bytes_per_second_value
        else
            null;
    }

    /// Returns the finite rate currently governing this pacer, in bytes per
    /// second. Null means pacing is disabled or neither congestion state nor
    /// an explicit ceiling supplies a finite rate.
    pub fn rateBytesPerSecond(
        self: Pacer,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) ?u64 {
        if (!self.enabled) return null;
        const congestion_rate: ?u64 = if (congestion_window == 0 or
            smoothed_rtt_ns == 0)
            null
        else
            std.math.cast(
                u64,
                mulDivFloorSaturating(
                    @as(Wide, congestion_window) *
                        congestion_rate_numerator,
                    nanoseconds_per_second,
                    @as(Wide, smoothed_rtt_ns) *
                        congestion_rate_denominator,
                ),
            ) orelse std.math.maxInt(u64);
        const configured_max = self.maxPacingRateBytesPerSecond();
        if (congestion_rate) |rate| {
            return if (configured_max) |maximum| @min(rate, maximum) else rate;
        }
        return configured_max;
    }

    /// Changes the steady-state ceiling without applying the new rate to time
    /// that elapsed under the old policy. Already earned burst credit remains
    /// available, and a regressed caller timestamp cannot move accounting
    /// behind the last successful send.
    pub fn setMaxPacingRateBytesPerSecondAt(
        self: *Pacer,
        max_rate_bytes_per_second: ?u64,
        now_ns: u64,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) void {
        if (self.maxPacingRateBytesPerSecond() == max_rate_bytes_per_second) {
            return;
        }
        if (self.enabled) {
            if (self.lastSentTimeNs()) |last_sent| {
                const accounted_at = @max(now_ns, last_sent);
                self.budget = self.budgetAt(
                    accounted_at,
                    congestion_window,
                    smoothed_rtt_ns,
                );
                self.setLastSentTimeNs(accounted_at);
            }
        }
        self.has_max_pacing_rate = max_rate_bytes_per_second != null;
        self.max_pacing_rate_bytes_per_second_value =
            max_rate_bytes_per_second orelse 0;
    }

    pub fn lastSentTimeNs(self: Pacer) ?u64 {
        return if (self.has_last_sent_time)
            self.last_sent_time_ns_value
        else
            null;
    }

    pub fn setLastSentTimeNs(self: *Pacer, value: ?u64) void {
        self.has_last_sent_time = value != null;
        self.last_sent_time_ns_value = value orelse 0;
    }

    pub fn maxBurstSize(self: Pacer) usize {
        return std.math.mul(usize, self.max_datagram_size, self.max_burst_packets) catch std.math.maxInt(usize);
    }

    pub fn budgetAt(self: Pacer, now_ns: u64, congestion_window: usize, smoothed_rtt_ns: u64) usize {
        const max_burst = self.maxBurstSize();
        if (!self.enabled) return max_burst;
        const last_sent = self.lastSentTimeNs() orelse return max_burst;
        if (self.budget >= max_burst) return max_burst;
        const elapsed_ns = now_ns -| last_sent;
        if (elapsed_ns == 0) return self.budget;

        const congestion_replenished = if (congestion_window == 0 or
            smoothed_rtt_ns == 0)
            std.math.maxInt(usize)
        else
            bytesForInterval(
                @as(Wide, congestion_window) * congestion_rate_numerator,
                @as(Wide, smoothed_rtt_ns) * congestion_rate_denominator,
                elapsed_ns,
            );
        const rate_limited_replenished = if (self.maxPacingRateBytesPerSecond()) |max_rate|
            bytesForInterval(max_rate, nanoseconds_per_second, elapsed_ns)
        else
            std.math.maxInt(usize);
        const replenished = @min(
            congestion_replenished,
            rate_limited_replenished,
        );
        return @min(max_burst, self.budget +| replenished);
    }

    /// Earliest timestamp at which `packet_size` bytes may be emitted.
    /// `null` means the packet can be sent immediately or pacing is disabled.
    pub fn deadlineAt(
        self: Pacer,
        now_ns: u64,
        packet_size: usize,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) ?u64 {
        if (!self.enabled or packet_size == 0) return null;
        if (packet_size <= self.budget) return null;
        const available = self.budgetAt(now_ns, congestion_window, smoothed_rtt_ns);
        if (packet_size <= available) return null;

        const deficit = packet_size - available;
        var delay_ns_wide: Wide = 0;
        if (congestion_window != 0 and smoothed_rtt_ns != 0) {
            delay_ns_wide = delayForBytes(
                deficit,
                @as(Wide, congestion_window) * congestion_rate_numerator,
                @as(Wide, smoothed_rtt_ns) * congestion_rate_denominator,
            );
        }
        if (self.maxPacingRateBytesPerSecond()) |max_rate| {
            const rate_delay = if (max_rate == 0)
                std.math.maxInt(Wide)
            else
                delayForBytes(deficit, max_rate, nanoseconds_per_second);
            delay_ns_wide = @max(delay_ns_wide, rate_delay);
        }
        // With neither a usable RTT/cwnd pair nor an explicit limit there is
        // no rate constraint to schedule against, preserving the old bypass.
        if (delay_ns_wide == 0) return null;

        const delay_ns = std.math.cast(u64, delay_ns_wide) orelse std.math.maxInt(u64);
        const deadline_base_ns = if (self.lastSentTimeNs()) |last_sent|
            @max(now_ns, last_sent)
        else
            now_ns;
        return std.math.add(u64, deadline_base_ns, delay_ns) catch std.math.maxInt(u64);
    }

    pub fn canSendAt(
        self: Pacer,
        now_ns: u64,
        packet_size: usize,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) bool {
        return self.deadlineAt(now_ns, packet_size, congestion_window, smoothed_rtt_ns) == null;
    }

    /// Commit a successful packet send. Call this only after the UDP write
    /// succeeds so transient socket failures do not consume pacing credit.
    pub fn onPacketSentAt(
        self: *Pacer,
        now_ns: u64,
        packet_size: usize,
        congestion_window: usize,
        smoothed_rtt_ns: u64,
    ) void {
        if (!self.enabled or packet_size == 0) return;
        self.budget = self.budgetAt(now_ns, congestion_window, smoothed_rtt_ns) -| packet_size;
        self.setLastSentTimeNs(now_ns);
    }

    pub fn reset(self: *Pacer) void {
        self.budget = self.maxBurstSize();
        self.setLastSentTimeNs(null);
    }

    /// Retune burst accounting after a validated PMTU change.
    ///
    /// Pacing stores its burst limit in bytes derived from the path datagram
    /// size. Recompute the configured burst and clamp any carried budget so a
    /// PMTU drop cannot leave stale extra credit for oversized bursts.
    pub fn onMtuUpdate(self: *Pacer, new_max_datagram_size: usize) void {
        if (new_max_datagram_size == 0 or new_max_datagram_size == self.max_datagram_size) return;
        self.max_datagram_size = new_max_datagram_size;
        self.budget = @min(self.budget, self.maxBurstSize());
    }

    fn bytesForInterval(
        bytes_per_period: Wide,
        period_ns: Wide,
        elapsed_ns: u64,
    ) usize {
        const bytes = mulDivFloorSaturating(
            bytes_per_period,
            elapsed_ns,
            period_ns,
        );
        return std.math.cast(usize, bytes) orelse std.math.maxInt(usize);
    }

    /// Returns ceil(bytes * period / rate) in nanoseconds. Callers guarantee
    /// a non-zero rate. The widest possible input product needs only 130 bits.
    fn delayForBytes(bytes: usize, bytes_per_period: Wide, period_ns: Wide) Wide {
        return mulDivCeilSaturating(bytes, period_ns, bytes_per_period);
    }

    fn mulDivFloorSaturating(a: Wide, b: Wide, denominator: Wide) Wide {
        const product = std.math.mul(Wide, a, b) catch {
            const overflow_result =
                @as(OverflowWide, a) * @as(OverflowWide, b) /
                @as(OverflowWide, denominator);
            return std.math.cast(Wide, overflow_result) orelse
                std.math.maxInt(Wide);
        };
        return product / denominator;
    }

    fn mulDivCeilSaturating(a: Wide, b: Wide, denominator: Wide) Wide {
        const product = std.math.mul(Wide, a, b) catch {
            const overflow_product =
                @as(OverflowWide, a) * @as(OverflowWide, b);
            const overflow_denominator: OverflowWide = denominator;
            const overflow_result = overflow_product / overflow_denominator +
                @intFromBool(overflow_product % overflow_denominator != 0);
            return std.math.cast(Wide, overflow_result) orelse
                std.math.maxInt(Wide);
        };
        return product / denominator + @intFromBool(product % denominator != 0);
    }
};

test {
    _ = @import("pacing/tests.zig");
}

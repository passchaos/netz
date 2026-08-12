//! Bounded PTO retries for the synchronous integrated QUIC handshake.
//!
//! The full established connection already has RFC 9002 packet recovery. The
//! blocking handshake adapter needs a smaller mechanism before that state
//! exists: wait with exponential backoff and retransmit the exact CRYPTO
//! flight under fresh packet numbers when no response arrives.

const std = @import("std");
const quic = @import("../mod.zig");

const net = std.Io.net;

pub const Config = struct {
    /// RFC 9002 recommends a 333ms initial RTT, yielding an approximately one
    /// second initial PTO before an RTT sample exists.
    initial_pto_ms: u32 = 1000,
    max_pto_ms: u32 = 4000,
    max_retries: u8 = 3,
    /// Optional wall-clock budget for one synchronous handshake transition.
    ///
    /// Event-loop QUIC stacks keep probing until a separate handshake-duration
    /// or idle deadline fires.  When this adapter is configured with a non-zero
    /// budget it mirrors that behavior by continuing capped PTO probes past
    /// `max_retries` until the budget expires.  The default of zero preserves
    /// the older strictly retry-count-bounded behavior for tests and embedded
    /// callers that need deterministic fail-fast handshakes.
    max_duration_ms: u32 = 0,
    /// Optional fault-injection callback. Production callers leave this null;
    /// tests can deterministically drop selected complete flights without
    /// teaching the transport about test-only counters.
    should_drop: ?*const fn (attempt: u8) bool = null,

    pub fn validate(self: Config) error{InvalidHandshakeRecovery}!void {
        if (self.initial_pto_ms == 0 or
            self.max_pto_ms < self.initial_pto_ms)
        {
            return error.InvalidHandshakeRecovery;
        }
    }

    pub fn timeoutMillis(self: Config, retry_count: u8) u64 {
        const shift: u5 = @intCast(@min(retry_count, 31));
        const scaled = std.math.shl(u64, self.initial_pto_ms, shift);
        return @min(scaled, self.max_pto_ms);
    }

    pub fn timeout(self: Config, retry_count: u8) std.Io.Timeout {
        return durationFromMillis(self.timeoutMillis(retry_count));
    }

    pub fn budgetMillis(self: Config) u64 {
        if (self.max_duration_ms != 0) return self.max_duration_ms;

        var total_ms: u64 = 0;
        var retry_count: u16 = 0;
        while (retry_count <= @as(u16, self.max_retries)) : (retry_count += 1) {
            total_ms += self.timeoutMillis(@intCast(retry_count));
        }
        return total_ms;
    }

    /// Timeout budget for passive waits after the peer has already proven
    /// liveness with part of a flight.  Waiting only the first PTO here makes a
    /// split Initial/Handshake response much more fragile than the active
    /// retransmission path above; summing the same bounded PTO windows keeps
    /// the blocking adapter aligned with mature QUIC stacks that separate PTO
    /// probing from the final handshake timeout.
    pub fn passiveTimeout(self: Config) std.Io.Timeout {
        return durationFromMillis(self.budgetMillis());
    }

    fn durationFromMillis(milliseconds: u64) std.Io.Timeout {
        return .{ .duration = clockDurationFromMillis(milliseconds) };
    }

    fn clockDurationFromMillis(milliseconds: u64) std.Io.Clock.Duration {
        return .{
            .raw = .fromMilliseconds(@intCast(@min(
                milliseconds,
                @as(u64, @intCast(std.math.maxInt(i64))),
            ))),
            .clock = .awake,
        };
    }
};

pub const Error = quic.runtime.Error ||
    error{
        HandshakeTimeout,
        InvalidHandshakeRecovery,
        HandshakeSendFailed,
        HandshakeReceiveFailed,
    };

pub const SendFn = *const fn (
    context: *anyopaque,
    retransmission: u8,
) anyerror!void;
pub const AcceptFn = *const fn (datagram: []const u8) bool;
pub const AcceptContextFn = *const fn (
    context: *anyopaque,
    datagram: []const u8,
) bool;

fn acceptAny(_: []const u8) bool {
    return true;
}

/// Send once and wait for a datagram, retransmitting after each PTO.
///
/// `send_fn` receives zero for the original transmission and increasing values
/// for retries. Callers use that index to select fresh packet-number ranges;
/// retransmitting protected bytes verbatim would reuse an AEAD nonce.
pub fn sendAndReceive(
    endpoint: *quic.runtime.Endpoint,
    config: Config,
    context: *anyopaque,
    send_fn: SendFn,
) Error!quic.runtime.OwnedBytes {
    return sendAndReceiveMatching(
        endpoint,
        config,
        context,
        send_fn,
        acceptAny,
    );
}

/// Retransmit on PTO while ignoring valid UDP traffic that does not match the
/// encryption level expected by the current handshake transition.
pub fn sendAndReceiveMatching(
    endpoint: *quic.runtime.Endpoint,
    config: Config,
    context: *anyopaque,
    send_fn: SendFn,
    accept_fn: AcceptFn,
) Error!quic.runtime.OwnedBytes {
    try config.validate();
    var retransmission: u8 = 0;
    var transmitted: u8 = 0;
    const hard_deadline = activeDeadline(config, endpoint.io);
    while (true) {
        const drop = if (config.should_drop) |should_drop|
            should_drop(retransmission)
        else
            false;
        if (!drop) {
            send_fn(context, transmitted) catch
                return error.HandshakeSendFailed;
            transmitted +|= 1;
        }
        const deadline = attemptDeadline(
            config,
            endpoint.io,
            retransmission,
            hard_deadline,
        );
        while (true) {
            var datagram = endpoint.receiveBytesTimeout(deadline) catch |err|
                switch (err) {
                    error.Timeout => {
                        if (retryBudgetExhausted(
                            config,
                            endpoint.io,
                            retransmission,
                            hard_deadline,
                        )) {
                            return error.HandshakeTimeout;
                        }
                        retransmission +|= 1;
                        break;
                    },
                    error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
                    else => |other| return @errorCast(other),
                };
            if (accept_fn(datagram.bytes)) return datagram;
            datagram.deinit(endpoint.allocator);
            if (hardDeadlineExpired(endpoint.io, hard_deadline)) {
                return error.HandshakeTimeout;
            }
        }
    }
}

/// Context-aware counterpart for response classifiers that must validate
/// connection-specific metadata before a datagram can advance the handshake.
///
/// QUIC Retry is the motivating case: integrity validation depends on the
/// original DCID and the packet must be addressed to this attempt's Initial
/// SCID. Invalid Retry datagrams are ignored inside the current PTO window
/// rather than being surfaced as a fatal handshake response.
pub fn sendAndReceiveMatchingContext(
    endpoint: *quic.runtime.Endpoint,
    config: Config,
    context: *anyopaque,
    send_fn: SendFn,
    accept_context: *anyopaque,
    accept_fn: AcceptContextFn,
) Error!quic.runtime.OwnedBytes {
    try config.validate();
    var retransmission: u8 = 0;
    var transmitted: u8 = 0;
    const hard_deadline = activeDeadline(config, endpoint.io);
    while (true) {
        const drop = if (config.should_drop) |should_drop|
            should_drop(retransmission)
        else
            false;
        if (!drop) {
            send_fn(context, transmitted) catch
                return error.HandshakeSendFailed;
            transmitted +|= 1;
        }
        const deadline = attemptDeadline(
            config,
            endpoint.io,
            retransmission,
            hard_deadline,
        );
        while (true) {
            var datagram = endpoint.receiveBytesTimeout(deadline) catch |err|
                switch (err) {
                    error.Timeout => {
                        if (retryBudgetExhausted(
                            config,
                            endpoint.io,
                            retransmission,
                            hard_deadline,
                        )) {
                            return error.HandshakeTimeout;
                        }
                        retransmission +|= 1;
                        break;
                    },
                    error.ConcurrencyUnavailable => return error.HandshakeReceiveFailed,
                    else => |other| return @errorCast(other),
                };
            if (accept_fn(accept_context, datagram.bytes)) return datagram;
            datagram.deinit(endpoint.allocator);
            if (hardDeadlineExpired(endpoint.io, hard_deadline)) {
                return error.HandshakeTimeout;
            }
        }
    }
}

/// Send a flight once when no synchronous response is required.
///
/// Client Finished is acknowledged indirectly by subsequent 1-RTT traffic and
/// HANDSHAKE_DONE; established-connection recovery owns those retries.
pub fn sendWithoutResponse(
    config: Config,
    context: *anyopaque,
    send_fn: SendFn,
) Error!void {
    try config.validate();
    send_fn(context, 0) catch return error.HandshakeSendFailed;
}

fn activeDeadline(config: Config, io: std.Io) ?std.Io.Clock.Timestamp {
    if (config.max_duration_ms == 0) return null;
    return std.Io.Clock.Timestamp.fromNow(
        io,
        Config.clockDurationFromMillis(config.max_duration_ms),
    );
}

fn attemptDeadline(
    config: Config,
    io: std.Io,
    retransmission: u8,
    hard_deadline: ?std.Io.Clock.Timestamp,
) std.Io.Timeout {
    const pto_deadline = config.timeout(retransmission).toDeadline(io);
    const hard = hard_deadline orelse return pto_deadline;
    switch (pto_deadline) {
        .deadline => |deadline| {
            if (std.Io.Clock.Timestamp.compare(hard, .lt, deadline)) {
                return .{ .deadline = hard };
            }
            return pto_deadline;
        },
        .none, .duration => unreachable,
    }
}

fn retryBudgetExhausted(
    config: Config,
    io: std.Io,
    retransmission: u8,
    hard_deadline: ?std.Io.Clock.Timestamp,
) bool {
    // SendFn receives the retransmission number as u8 so flight helpers can
    // derive fresh packet numbers without extra allocation.  Stop before that
    // counter would saturate and risk reusing a QUIC AEAD nonce.
    if (retransmission == std.math.maxInt(u8)) return true;
    if (hard_deadline) |deadline| {
        std.debug.assert(deadline.clock == .awake);
        return std.Io.Clock.awake.now(io).nanoseconds >= deadline.raw.nanoseconds;
    }
    return retransmission == config.max_retries;
}

fn hardDeadlineExpired(
    io: std.Io,
    hard_deadline: ?std.Io.Clock.Timestamp,
) bool {
    const deadline = hard_deadline orelse return false;
    std.debug.assert(deadline.clock == .awake);
    return std.Io.Clock.awake.now(io).nanoseconds >= deadline.raw.nanoseconds;
}

pub const InitialFlight = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: quic.initial_exchange.SendInitialFlightOptions,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *InitialFlight = @ptrCast(@alignCast(context));
        var options = self.options;
        options.initial.packet_number = try retryPacketNumber(
            self.options.initial.packet_number,
            self.options.max_datagrams,
            retransmission,
        );
        _ = try quic.initial_exchange.sendInitialCryptoFlight(
            self.endpoint,
            self.peer,
            self.keys,
            options,
        );
    }
};

pub const InitialHandshakeFlight = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    initial_keys: quic.protection.PacketProtectionKeys,
    initial_options: quic.initial_exchange.SendInitialFlightOptions,
    handshake_keys: quic.protection.PacketProtectionKeys,
    handshake_options: quic.initial_exchange.SendInitialOptions,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *InitialHandshakeFlight = @ptrCast(@alignCast(context));
        var initial_options = self.initial_options;
        initial_options.initial.packet_number = try retryPacketNumber(
            self.initial_options.initial.packet_number,
            self.initial_options.max_datagrams,
            retransmission,
        );
        var handshake_options = self.handshake_options;
        handshake_options.packet_number = try retryPacketNumber(
            self.handshake_options.packet_number,
            1,
            retransmission,
        );
        _ = try quic.initial_exchange.sendInitialThenHandshakeCrypto(
            self.endpoint,
            self.peer,
            self.initial_keys,
            initial_options,
            self.handshake_keys,
            handshake_options,
        );
    }
};

pub const HandshakeFlight = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: quic.initial_exchange.SendInitialOptions,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *HandshakeFlight = @ptrCast(@alignCast(context));
        var options = self.options;
        options.packet_number = try retryPacketNumber(
            self.options.packet_number,
            1,
            retransmission,
        );
        try quic.initial_exchange.sendHandshakeCrypto(
            self.endpoint,
            self.peer,
            self.keys,
            options,
        );
    }
};

fn retryPacketNumber(
    base: u64,
    stride: u64,
    retransmission: u8,
) error{InvalidPacketNumber}!u64 {
    if (stride == 0) return error.InvalidPacketNumber;
    const increment = std.math.mul(
        u64,
        stride,
        retransmission,
    ) catch return error.InvalidPacketNumber;
    const packet_number = std.math.add(
        u64,
        base,
        increment,
    ) catch return error.InvalidPacketNumber;
    if (packet_number > quic.protection.max_packet_number) {
        return error.InvalidPacketNumber;
    }
    return packet_number;
}

test {
    _ = @import("retransmit_tests.zig");
}

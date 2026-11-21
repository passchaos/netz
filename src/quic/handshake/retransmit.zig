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
    /// Optional caller-owned deadline shared across several handshake
    /// transitions. It caps retry-derived budgets instead of being recomputed
    /// whenever a later transition begins.
    deadline: ?std.Io.Clock.Timestamp = null,
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
        if (self.deadline) |deadline| {
            if (deadline.clock != .awake) return error.InvalidHandshakeRecovery;
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

pub const AntiAmplificationBudget = struct {
    validated: bool = false,
    bytes_received: usize = 0,
    bytes_sent: usize = 0,

    pub fn recordReceived(self: *AntiAmplificationBudget, bytes: usize) void {
        if (self.validated) return;
        self.bytes_received = std.math.add(
            usize,
            self.bytes_received,
            bytes,
        ) catch std.math.maxInt(usize);
    }

    pub fn validate(self: *AntiAmplificationBudget) void {
        self.validated = true;
    }

    pub fn remaining(self: AntiAmplificationBudget) ?usize {
        if (self.validated) return null;
        const limit = std.math.mul(
            usize,
            self.bytes_received,
            quic.one_rtt.anti_amplification_multiplier,
        ) catch std.math.maxInt(usize);
        return limit -| self.bytes_sent;
    }

    pub fn reserve(self: *AntiAmplificationBudget, bytes: usize) !void {
        const available = self.remaining() orelse return;
        if (bytes > available) return error.AntiAmplificationLimited;
        self.bytes_sent = std.math.add(
            usize,
            self.bytes_sent,
            bytes,
        ) catch std.math.maxInt(usize);
    }

    pub fn release(self: *AntiAmplificationBudget, bytes: usize) void {
        if (self.validated) return;
        std.debug.assert(bytes <= self.bytes_sent);
        self.bytes_sent -= bytes;
    }
};

pub const SendFn = *const fn (
    context: *anyopaque,
    retransmission: u8,
) anyerror!void;
pub const AcceptFn = *const fn (datagram: []const u8) bool;
pub const ObserveDatagramFn = *const fn (
    context: *anyopaque,
    from: net.IpAddress,
    bytes: usize,
) void;
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
    return sendAndReceiveMatchingFrom(
        endpoint,
        quic.runtime.DatagramSource.fromEndpoint(endpoint),
        config,
        context,
        send_fn,
        accept_fn,
    );
}

pub fn sendAndReceiveMatchingFrom(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    config: Config,
    context: *anyopaque,
    send_fn: SendFn,
    accept_fn: AcceptFn,
) Error!quic.runtime.OwnedBytes {
    return sendAndReceiveMatchingFromObserved(
        endpoint,
        source,
        config,
        context,
        send_fn,
        accept_fn,
        null,
    );
}

/// Source-driven retransmission with an observer that sees every complete UDP
/// datagram before response classification. Server handshakes use this to
/// account all same-path bytes, including packets that are later discarded,
/// toward RFC 9000's anti-amplification allowance.
pub fn sendAndReceiveMatchingFromObserved(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
    config: Config,
    context: *anyopaque,
    send_fn: SendFn,
    accept_fn: AcceptFn,
    observe_fn: ?ObserveDatagramFn,
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
            const sent = blk: {
                send_fn(context, transmitted) catch |err| switch (err) {
                    error.AntiAmplificationLimited => break :blk false,
                    else => return error.HandshakeSendFailed,
                };
                break :blk true;
            };
            if (sent) transmitted +|= 1;
        }
        const deadline = attemptDeadline(
            config,
            endpoint.io,
            retransmission,
            hard_deadline,
        );
        while (true) {
            var datagram = source.receiveTimeout(deadline) catch |err|
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
            if (observe_fn) |observe| {
                observe(context, datagram.from, datagram.bytes.len);
            }
            if (accept_fn(datagram.bytes)) return datagram;
            datagram.deinit(endpoint.allocator);
            if (hardDeadlineExpired(endpoint.io, hard_deadline)) {
                return error.HandshakeTimeout;
            }
        }
    }
}

test "handshake PTO receives from an injected datagram source" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1200 },
    );
    defer endpoint.deinit();
    const peer = std.Io.net.IpAddress{ .ip4 = .loopback(4433) };
    var inbox = try quic.handshake_inbox.Inbox.init(
        allocator,
        io,
        &.{"server"},
        peer,
        1,
    );
    defer inbox.deinit();
    const payload = try allocator.dupe(
        u8,
        &.{ 0xc0, 0, 0, 0, 1, 6, 's', 'e', 'r', 'v', 'e', 'r', 0 },
    );
    try inbox.push(.{ .from = peer, .bytes = payload });

    const Context = struct {
        calls: usize = 0,
        fn send(context: *anyopaque, _: u8) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
        }
        fn accept(_: []const u8) bool {
            return true;
        }
    };
    var context = Context{};
    var datagram = try sendAndReceiveMatchingFrom(
        &endpoint,
        inbox.datagramSource(),
        .{ .initial_pto_ms = 10, .max_pto_ms = 10 },
        &context,
        Context.send,
        Context.accept,
    );
    defer datagram.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), context.calls);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xc0, 0, 0, 0, 1, 6, 's', 'e', 'r', 'v', 'e', 'r', 0 },
        datagram.bytes,
    );
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
    return sendAndReceiveMatchingContextFrom(
        endpoint,
        quic.runtime.DatagramSource.fromEndpoint(endpoint),
        config,
        context,
        send_fn,
        accept_context,
        accept_fn,
    );
}

/// Source-driven form for clients whose endpoint has a single receive owner.
/// The source owns filtering and transfers each accepted datagram to this
/// helper, while retransmissions continue to use the caller's endpoint.
pub fn sendAndReceiveMatchingContextFrom(
    endpoint: *quic.runtime.Endpoint,
    source: quic.runtime.DatagramSource,
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
            var datagram = source.receiveTimeout(deadline) catch |err|
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
    const configured = if (config.max_duration_ms == 0) null else std.Io.Clock.Timestamp.fromNow(
        io,
        Config.clockDurationFromMillis(config.max_duration_ms),
    );
    const caller = config.deadline orelse return configured;
    const local = configured orelse return caller;
    return if (std.Io.Clock.Timestamp.compare(caller, .lt, local))
        caller
    else
        local;
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
    next_packet_number: ?u64 = null,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *InitialFlight = @ptrCast(@alignCast(context));
        var options = self.options;
        options.initial.packet_number = try retryPacketNumber(
            self.options.initial.packet_number,
            self.options.max_datagrams,
            retransmission,
        );
        const progress = try quic.initial_exchange
            .sendInitialCryptoFlightProgress(
            self.endpoint,
            self.peer,
            self.keys,
            options,
        );
        self.next_packet_number = if (progress.last_packet_number < quic.protection.max_packet_number)
            progress.last_packet_number + 1
        else
            null;
        // Once protection has completed, the whole packet-number range is
        // retired. A socket-rejected suffix behaves like packet loss: let the
        // PTO loop wait and retry the CRYPTO data under the next fresh range.
        _ = progress.send_error;
    }
};

pub const InitialHandshakeFlight = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    initial_keys: quic.protection.PacketProtectionKeys,
    initial_options: quic.initial_exchange.SendInitialFlightOptions,
    handshake_keys: quic.protection.PacketProtectionKeys,
    handshake_options: quic.initial_exchange.SendInitialOptions,
    anti_amplification: AntiAmplificationBudget = .{ .validated = true },
    /// First Handshake packet number not consumed by packet protection. A
    /// fatal receive error can use it for CONNECTION_CLOSE without reusing an
    /// AEAD nonce, including after a zero-progress socket failure.
    next_handshake_packet_number: ?u64 = null,
    last_retransmission: u8 = 0,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *InitialHandshakeFlight = @ptrCast(@alignCast(context));
        self.last_retransmission = retransmission;
        var initial_options = self.initial_options;
        initial_options.initial.packet_number = try retryPacketNumber(
            self.initial_options.initial.packet_number,
            self.initial_options.max_datagrams,
            retransmission,
        );
        var handshake_options = self.handshake_options;
        const handshake_flight: quic.initial_exchange.SendInitialFlightOptions = .{
            .initial = handshake_options,
            .max_datagram_size = self.endpoint.limits.max_datagram_size,
        };
        // Stride the retransmission range by the complete flight so a later
        // attempt cannot reuse a packet number from an earlier attempt.
        const handshake_packets = try quic.initial_exchange
            .handshakeCryptoFlightPacketCount(handshake_flight);
        handshake_options.packet_number = try retryPacketNumber(
            self.handshake_options.packet_number,
            handshake_packets,
            retransmission,
        );
        const flight_bytes = try quic.initial_exchange
            .initialThenHandshakeCryptoWireLen(
            initial_options,
            .{
                .initial = handshake_options,
                .max_datagram_size = self.endpoint.limits.max_datagram_size,
            },
        );
        try self.anti_amplification.reserve(flight_bytes);
        var committed_bytes: usize = 0;
        var reservation_active = true;
        errdefer if (reservation_active) {
            self.anti_amplification.release(flight_bytes - committed_bytes);
        };

        const initial_progress = try quic.initial_exchange
            .sendInitialCryptoFlightProgress(
            self.endpoint,
            self.peer,
            self.initial_keys,
            initial_options,
        );
        committed_bytes = initial_progress.sent_bytes;
        if (initial_progress.sent_count < initial_progress.protected_count) {
            self.anti_amplification.release(
                flight_bytes - committed_bytes,
            );
            reservation_active = false;
            return;
        }

        // The Handshake flight was validated by the wire-length calculation
        // above, so a failure here is allocation or socket progress rather
        // than an unsendable certificate flight.
        const handshake_progress = try quic.initial_exchange
            .sendHandshakeCryptoFlightProgress(
            self.endpoint,
            self.peer,
            self.handshake_keys,
            .{
                .initial = handshake_options,
                .max_datagram_size = self.endpoint.limits.max_datagram_size,
            },
        );
        self.next_handshake_packet_number = if (handshake_progress.last_packet_number <
            quic.protection.max_packet_number)
            handshake_progress.last_packet_number + 1
        else
            null;
        committed_bytes = std.math.add(
            usize,
            committed_bytes,
            handshake_progress.sent_bytes,
        ) catch flight_bytes;
        self.anti_amplification.release(flight_bytes - committed_bytes);
        reservation_active = false;
        _ = initial_progress.send_error;
        // The complete Initial flight is already visible. A socket-rejected
        // Handshake suffix is therefore packet loss, not a zero-progress send
        // failure; wait for the PTO loop and retry both levels under fresh
        // packet numbers.
        _ = handshake_progress.send_error;
    }

    pub fn observeReceived(
        context: *anyopaque,
        from: net.IpAddress,
        bytes: usize,
    ) void {
        const self: *InitialHandshakeFlight = @ptrCast(@alignCast(context));
        if (!from.eql(&self.peer)) return;
        self.anti_amplification.recordReceived(bytes);
    }
};

pub const HandshakeFlight = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    options: quic.initial_exchange.SendInitialOptions,
    /// First Handshake packet number not consumed by packet protection. A
    /// fatal error after the flight can use it for CONNECTION_CLOSE without
    /// reusing an AEAD nonce.
    next_packet_number: ?u64 = null,

    pub fn send(context: *anyopaque, retransmission: u8) anyerror!void {
        const self: *HandshakeFlight = @ptrCast(@alignCast(context));
        const flight_options: quic.initial_exchange.SendInitialFlightOptions = .{
            .initial = self.options,
            .max_datagram_size = self.endpoint.limits.max_datagram_size,
        };
        const packet_count = try quic.initial_exchange
            .handshakeCryptoFlightPacketCount(flight_options);
        var options = self.options;
        options.packet_number = try retryPacketNumber(
            self.options.packet_number,
            packet_count,
            retransmission,
        );
        const progress = try quic.initial_exchange
            .sendHandshakeCryptoFlightProgress(
            self.endpoint,
            self.peer,
            self.keys,
            .{
                .initial = options,
                .max_datagram_size = self.endpoint.limits.max_datagram_size,
            },
        );
        self.next_packet_number = if (progress.last_packet_number <
            quic.protection.max_packet_number)
            progress.last_packet_number + 1
        else
            null;
        // This final client flight has no PTO retransmission. A socket error
        // or partially sent batch means the server never receives the complete
        // Finished/Certificate flight, so reporting success would leave the
        // caller with a half-open connection.
        if (progress.send_error) |err| return err;
        if (progress.sent_count != progress.protected_count) {
            return error.HandshakeSendFailed;
        }
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

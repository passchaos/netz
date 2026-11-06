//! gRPC unary call semantics over the netz HTTP/2 runtime.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const path_rewrite = @import("path_rewrite.zig");
pub const RegexRewrite = path_rewrite.RegexRewrite;
const compression_mod = @import("compression.zig");
const metadata_mod = @import("metadata.zig");
const details_mod = @import("status_details.zig");
const response_metadata = @import("response_metadata.zig");
const retry = @import("call/retry.zig");
const wire = @import("wire.zig");
const codec = @import("stream/codec.zig");
const outbound_ownership = @import("stream/duplex/outbound_ownership.zig");

pub const Error = wire.Error || metadata_mod.Error ||
    compression_mod.Error || details_mod.Error ||
    http2.runtime.ResponseTimeoutError || error{
    CompressionNotNegotiated,
    InvalidContentType,
    InvalidGrpcRequest,
    InvalidMetadata,
    InvalidMessageCount,
    InvalidRetryPolicy,
    InvalidStreamState,
};

const Status = wire.Status;
const Message = wire.Message;
const MessageIterator = wire.MessageIterator;
const Timeout = wire.Timeout;
const Algorithm = compression_mod.Algorithm;
const AlgorithmSet = compression_mod.AlgorithmSet;
const writeMessage = wire.writeMessage;
const encodeStatusMessageAlloc = wire.encodeStatusMessageAlloc;
const decodeStatusMessageAlloc = wire.decodeStatusMessageAlloc;
const isContentType = wire.isContentType;

pub const UnaryRequest = struct {
    allocator: std.mem.Allocator,
    stream_id: u31,
    path: []const u8,
    service: []const u8,
    method: []const u8,
    /// The application payload after any per-message decompression.
    message: Message,
    was_compressed: bool,
    timeout: ?Timeout,
    encoding: ?[]const u8,
    accepted_encodings: AlgorithmSet,
    headers: []const http2.Hpack.HeaderField,
    owned_message: ?[]u8,

    pub fn deinit(self: *UnaryRequest) void {
        if (self.owned_message) |owned| self.allocator.free(owned);
        self.* = undefined;
    }
};

/// Validated gRPC request metadata shared by unary and streaming calls.
///
/// Every slice borrows the HTTP/2 request headers/head that was supplied to
/// `parseRequestMetadata`.
pub const RequestMetadata = struct {
    path: []const u8,
    service: []const u8,
    method: []const u8,
    timeout: ?Timeout,
    encoding: ?[]const u8,
    accepted_encodings: AlgorithmSet,
};

pub fn parseRequestMetadata(
    method: []const u8,
    path_value: []const u8,
    headers: []const http2.Hpack.HeaderField,
) Error!RequestMetadata {
    if (!std.mem.eql(u8, method, "POST")) {
        return error.InvalidGrpcRequest;
    }
    const content_type = findHeader(
        headers,
        "content-type",
    ) orelse return error.InvalidContentType;
    if (!isContentType(content_type)) return error.InvalidContentType;
    const te = findHeader(headers, "te") orelse
        return error.InvalidGrpcRequest;
    if (!std.ascii.eqlIgnoreCase(
        std.mem.trim(u8, te, " \t"),
        "trailers",
    )) {
        return error.InvalidGrpcRequest;
    }
    return parseValidatedRequestMetadata(path_value, headers);
}

/// gRPC-Web requests omit the `te: trailers` header that browsers are not
/// allowed to set. The content type is already validated by the web module,
/// so this only validates POST, path, timeout, and compression metadata.
pub fn parseWebRequestMetadata(
    method: []const u8,
    path_value: []const u8,
    headers: []const http2.Hpack.HeaderField,
) Error!RequestMetadata {
    if (!std.mem.eql(u8, method, "POST")) {
        return error.InvalidGrpcRequest;
    }
    return parseValidatedRequestMetadata(path_value, headers);
}

fn parseValidatedRequestMetadata(
    path_value: []const u8,
    headers: []const http2.Hpack.HeaderField,
) Error!RequestMetadata {
    const path = try splitMethodPath(path_value);
    return .{
        .path = path_value,
        .service = path.service,
        .method = path.method,
        .timeout = if (findHeader(headers, "grpc-timeout")) |raw|
            try Timeout.parse(raw)
        else
            null,
        .encoding = findHeader(headers, "grpc-encoding"),
        .accepted_encodings = compression_mod.parseAcceptEncodingFields(headers),
    };
}

pub fn parseUnaryRequest(
    allocator: std.mem.Allocator,
    request: *const http2.runtime.OwnedRequest,
    max_message_size: usize,
) Error!UnaryRequest {
    return parseUnaryRequestParts(
        allocator,
        request.stream_id,
        request.method,
        request.path,
        request.headers,
        request.body,
        max_message_size,
        false,
    );
}

pub fn parseWebUnaryRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    path_value: []const u8,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    max_message_size: usize,
) Error!UnaryRequest {
    return parseUnaryRequestParts(
        allocator,
        // The HTTP/2 stream identifier is transport metadata. Body-level
        // parsing is stream-independent; callers fill it in after parsing.
        0,
        method,
        path_value,
        headers,
        body,
        max_message_size,
        true,
    );
}

fn parseUnaryRequestParts(
    allocator: std.mem.Allocator,
    stream_id: u31,
    method: []const u8,
    path_value: []const u8,
    headers: []const http2.Hpack.HeaderField,
    body: []const u8,
    max_message_size: usize,
    web: bool,
) Error!UnaryRequest {
    const metadata = if (web)
        try parseWebRequestMetadata(method, path_value, headers)
    else
        try parseRequestMetadata(method, path_value, headers);
    var iterator = MessageIterator.init(
        body,
        max_message_size,
    );
    const message = (try iterator.next()) orelse
        return error.InvalidMessageCount;
    if (try iterator.next() != null) {
        return error.InvalidMessageCount;
    }
    try validateMessageEncoding(message, metadata.encoding);
    var decoded = try decodeReceivedMessage(
        allocator,
        message,
        metadata.encoding,
        AlgorithmSet.supported,
        max_message_size,
    );
    errdefer decoded.deinit(allocator);
    return .{
        .allocator = allocator,
        .stream_id = stream_id,
        .path = metadata.path,
        .service = metadata.service,
        .method = metadata.method,
        .message = .{
            .compressed = false,
            .payload = decoded.bytes,
        },
        .was_compressed = message.compressed,
        .timeout = metadata.timeout,
        .encoding = metadata.encoding,
        .accepted_encodings = metadata.accepted_encodings,
        .headers = headers,
        .owned_message = decoded.owned,
    };
}

/// Internal xDS request-header mutation applied while request inputs are
/// copied. It never becomes application metadata on its own.
pub const HeaderMutationAction = enum {
    append,
    add_if_absent,
    overwrite,
    overwrite_if_exists,
};
pub const HeaderMutation = struct {
    name: []const u8,
    value: []const u8,
    action: HeaderMutationAction = .append,
};

/// Internal xDS route path rewrite. It is consumed while request inputs are
/// copied and never becomes application metadata.
pub const PathRewrite = union(enum) {
    /// Replace the complete request path.
    whole: []const u8,
    /// Replace the matched route prefix with `replacement`.
    prefix: struct { matched: usize, replacement: []const u8 },
    /// Apply an RE2-style capture-aware replacement to the complete path.
    regex: struct {
        rewrite: *const RegexRewrite,
        output_len: usize,
    },
    /// Apply a URI-template replacement using the route match variables.
    template: struct {
        rewrite: *const path_rewrite.TemplateRewrite,
        output_len: usize,
    },

    pub fn outputLen(self: PathRewrite, original_len: usize) usize {
        return switch (self) {
            .whole => |value| value.len,
            .prefix => |value| value.replacement.len +
                (original_len - @min(value.matched, original_len)),
            .regex => |value| value.output_len,
            .template => |value| value.output_len,
        };
    }

    pub fn write(
        self: PathRewrite,
        allocator: std.mem.Allocator,
        original: []const u8,
        output: []u8,
    ) std.mem.Allocator.Error![]const u8 {
        return switch (self) {
            .whole => |value| blk: {
                @memcpy(output[0..value.len], value);
                break :blk output[0..value.len];
            },
            .prefix => |value| blk: {
                const matched = @min(value.matched, original.len);
                @memcpy(output[0..value.replacement.len], value.replacement);
                @memcpy(
                    output[value.replacement.len..][0 .. original.len - matched],
                    original[matched..],
                );
                break :blk output[0 .. value.replacement.len + original.len - matched];
            },
            .regex => |value| path_rewrite.apply(
                allocator,
                value.rewrite,
                original,
                output,
            ),
            .template => |value| path_rewrite.templateApply(
                allocator,
                value.rewrite,
                original,
                output,
            ),
        };
    }
};

/// Internal xDS host rewrite. The regex form evaluates the path with query and
/// fragment removed, matching Envoy's `host_rewrite_path_regex`.
pub const HostRewrite = union(enum) {
    regex: struct {
        rewrite: *const RegexRewrite,
        output_len: usize,
    },

    pub fn outputLen(self: HostRewrite) usize {
        return switch (self) {
            .regex => |value| value.output_len,
        };
    }

    pub fn write(
        self: HostRewrite,
        allocator: std.mem.Allocator,
        path: []const u8,
        output: []u8,
    ) std.mem.Allocator.Error![]const u8 {
        return switch (self) {
            .regex => |value| path_rewrite.apply(
                allocator,
                value.rewrite,
                path_rewrite.stripQueryAndFragment(path),
                output,
            ),
        };
    }
};

pub const UnaryCallOptions = struct {
    path: []const u8,
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    message: []const u8,
    /// Requested per-message encoding. Compression is skipped when it cannot
    /// make this particular message smaller.
    compression: Algorithm = .identity,
    compression_level: u4 = 6,
    /// Decoders advertised to the server for response messages.
    accepted_encodings: AlgorithmSet = .supported,
    /// Enforced from one awake-clock deadline captured at call entry. Every
    /// attempt advertises the remaining `grpc-timeout`; null is unbounded.
    timeout: ?Timeout = null,
    /// Explicit channel readiness policy. Null permits a service config to
    /// supply its method policy; direct connected clients do not need to wait.
    wait_for_ready: ?bool = null,
    /// Precomputed grpc-core `RequestHashAttribute` value used by
    /// `ring_hash_experimental` when no requestHashHeader is configured.
    request_hash: ?u64 = null,
    /// RPC-local xDS cluster attribute. It is never serialized as a header.
    xds_cluster: ?[]const u8 = null,
    /// Internal xDS route path rewrite applied when request inputs are copied.
    xds_path_rewrite: ?PathRewrite = null,
    /// Internal xDS host rewrite applied when request inputs are copied.
    xds_host_rewrite: ?HostRewrite = null,
    /// Internal xDS request-header additions applied when request inputs are
    /// copied. The slices remain borrowed from the selector snapshot.
    xds_request_header_mutations: []const HeaderMutation = &.{},
    /// Internal xDS request-header removals applied before additions.
    xds_request_header_removals: []const []const u8 = &.{},
    /// Internal xDS response-header additions applied to received metadata.
    xds_response_header_mutations: []const HeaderMutation = &.{},
    /// Internal xDS response-header removals applied before additions.
    xds_response_header_removals: []const []const u8 = &.{},
    /// Internal xDS `auto_host_rewrite`: use the selected endpoint authority
    /// as the outbound `:authority`.
    xds_auto_host_rewrite: bool = false,
    /// Retry one REFUSED_STREAM before response commitment without charging a
    /// configured retry attempt. Disable for explicit single-attempt probes.
    transparent_retry: bool = true,
    /// ASCII application metadata already suitable for HTTP/2.
    metadata: []const http2.Hpack.HeaderField = &.{},
    /// Raw application bytes encoded as unpadded Base64 `-bin` fields.
    binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    /// Compatibility ceiling used for both directions unless a directional
    /// limit below is stricter.
    max_message_size: usize = 16 * 1024 * 1024,
    max_request_message_size: ?usize = null,
    max_response_message_size: ?usize = null,

    pub fn requestMessageLimit(self: UnaryCallOptions) usize {
        return @min(
            self.max_message_size,
            self.max_request_message_size orelse
                self.max_message_size,
        );
    }

    pub fn responseMessageLimit(self: UnaryCallOptions) usize {
        return @min(
            self.max_message_size,
            self.max_response_message_size orelse
                self.max_message_size,
        );
    }
};

/// Explicit retry policy for replay-safe unary RPCs.
///
/// `max_attempts` includes the original request. Matching status codes are
/// retried only when they arrive in a trailers-only response, before the RPC
/// is committed by response headers or a message. This mirrors gRPC service
/// config retry semantics without assuming that every unary method is safe to
/// replay.
pub const RetryPolicy = struct {
    max_attempts: u8,
    initial_backoff: std.Io.Duration,
    max_backoff: std.Io.Duration,
    backoff_multiplier: f64,
    retryable_status_codes: []const Status,
    /// Optional receive timer for each physical attempt. This is sequential
    /// retry, not concurrent hedging: expiry cancels the current attempt,
    /// applies ordinary retry throttling/backoff, then starts the next one.
    per_attempt_recv_timeout: ?std.Io.Duration = null,
    /// Optional token bucket shared by calls to the same logical backend.
    /// A retryable failure consumes one token before retry eligibility is
    /// decided; an OK response restores `token_ratio` up to the configured
    /// maximum.
    throttler: ?*RetryThrottler = null,

    pub fn validate(self: RetryPolicy) error{InvalidRetryPolicy}!void {
        // gRPC Core clamps service-config retry attempts to five. Rejecting an
        // out-of-range direct API value is less surprising than silently
        // changing application policy.
        if (self.max_attempts < 2 or self.max_attempts > 5 or
            self.initial_backoff.nanoseconds <= 0 or
            self.max_backoff.nanoseconds <= 0 or
            !std.math.isFinite(self.backoff_multiplier) or
            self.backoff_multiplier <= 0 or
            (self.retryable_status_codes.len == 0 and
                self.per_attempt_recv_timeout == null))
        {
            return error.InvalidRetryPolicy;
        }
        if (self.per_attempt_recv_timeout) |timeout| {
            if (timeout.nanoseconds <= 0) return error.InvalidRetryPolicy;
        }
        for (self.retryable_status_codes) |status| {
            if (status == .ok) return error.InvalidRetryPolicy;
        }
    }
};

/// gRFC A6 unary hedging policy. Multiple attempts may execute application
/// logic, so callers must use it only for replay-safe methods.
pub const HedgingPolicy = struct {
    max_attempts: u8,
    hedging_delay: std.Io.Duration = .zero,
    non_fatal_status_codes: []const Status = &.{},
    throttler: ?*RetryThrottler = null,

    pub fn validate(self: HedgingPolicy) error{InvalidRetryPolicy}!void {
        if (self.max_attempts < 2 or self.max_attempts > 5 or
            self.hedging_delay.nanoseconds < 0)
        {
            return error.InvalidRetryPolicy;
        }
        for (self.non_fatal_status_codes, 0..) |status, index| {
            if (status == .ok) return error.InvalidRetryPolicy;
            for (self.non_fatal_status_codes[0..index]) |prior| {
                if (prior == status) return error.InvalidRetryPolicy;
            }
        }
    }

    pub fn isNonFatal(self: HedgingPolicy, status: Status) bool {
        for (self.non_fatal_status_codes) |candidate| {
            if (candidate == status) return true;
        }
        return false;
    }
};

/// Thread-safe channel-level retry throttle using gRPC's milli-token model.
///
/// `max_tokens` starts full. Every configured retryable failure removes one
/// token, and retries remain allowed only while the new balance is above half
/// full. Successful RPCs restore `token_ratio`, capped at the maximum.
pub const RetryThrottler = struct {
    max_milli_tokens: u64,
    milli_token_ratio: u64,
    milli_tokens: std.atomic.Value(u64),

    pub fn init(
        max_tokens: u32,
        token_ratio: f64,
    ) error{InvalidRetryPolicy}!RetryThrottler {
        if (max_tokens == 0 or !std.math.isFinite(token_ratio) or
            token_ratio <= 0)
        {
            return error.InvalidRetryPolicy;
        }
        const scaled_ratio = token_ratio * 1000.0;
        if (!std.math.isFinite(scaled_ratio) or scaled_ratio < 1.0 or
            scaled_ratio > @as(f64, @floatFromInt(std.math.maxInt(u32))))
        {
            return error.InvalidRetryPolicy;
        }
        const max_milli_tokens = @as(u64, max_tokens) * 1000;
        return .{
            .max_milli_tokens = max_milli_tokens,
            .milli_token_ratio = @intFromFloat(@floor(scaled_ratio)),
            .milli_tokens = .init(max_milli_tokens),
        };
    }

    /// Record a retryable failure and return whether another attempt is
    /// permitted by the resulting balance.
    pub fn recordFailure(self: *RetryThrottler) bool {
        var current = self.milli_tokens.load(.monotonic);
        while (true) {
            const next = current -| 1000;
            if (self.milli_tokens.cmpxchgWeak(
                current,
                next,
                .monotonic,
                .monotonic,
            )) |observed| {
                current = observed;
            } else {
                return next > self.max_milli_tokens / 2;
            }
        }
    }

    pub fn recordSuccess(self: *RetryThrottler) void {
        var current = self.milli_tokens.load(.monotonic);
        while (true) {
            const next = @min(
                current +| self.milli_token_ratio,
                self.max_milli_tokens,
            );
            if (self.milli_tokens.cmpxchgWeak(
                current,
                next,
                .monotonic,
                .monotonic,
            )) |observed| {
                current = observed;
            } else {
                return;
            }
        }
    }

    pub fn hedgingAllowed(self: *const RetryThrottler) bool {
        return self.milli_tokens.load(.monotonic) >
            self.max_milli_tokens / 2;
    }

    pub fn milliTokens(self: *const RetryThrottler) u64 {
        return self.milli_tokens.load(.monotonic);
    }
};

pub const UnaryResponse = struct {
    allocator: std.mem.Allocator,
    /// Null when the peer reset the stream before a complete HTTP response.
    transport: ?http2.runtime.OwnedResponse,
    reset: ?http2.ResetStreamPayload = null,
    /// Conservative replay evidence: response heads commit a call, while a
    /// pre-head peer reset can remain eligible for transparent/explicit retry.
    response_committed: bool = true,
    /// Local LB policy rejection; retry and hedging must not launch another attempt.
    was_dropped: bool = false,
    status: Status,
    status_message: []u8,
    status_details: ?details_mod.Owned = null,
    message: ?Message,
    was_compressed: bool,
    encoding: ?[]const u8,
    owned_message: ?[]u8,

    pub fn deinit(self: *UnaryResponse) void {
        if (self.owned_message) |owned| self.allocator.free(owned);
        self.allocator.free(self.status_message);
        if (self.status_details) |*details| details.deinit();
        if (self.transport) |*transport| {
            transport.deinit(self.allocator);
        }
        self.* = undefined;
    }
};

pub fn policyDropResponse(allocator: std.mem.Allocator, category: []const u8) std.mem.Allocator.Error!UnaryResponse {
    return .{ .allocator = allocator, .transport = null, .was_dropped = true, .status = .unavailable, .status_message = try std.fmt.allocPrint(allocator, "EDS-configured drop: {s}", .{category}), .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
}

pub fn circuitBreakerResponse(allocator: std.mem.Allocator) std.mem.Allocator.Error!UnaryResponse {
    return .{ .allocator = allocator, .transport = null, .was_dropped = true, .status = .unavailable, .status_message = try allocator.dupe(u8, "circuit breaker drop"), .message = null, .was_compressed = false, .encoding = null, .owned_message = null };
}

pub fn perAttemptTimeoutResponse(
    allocator: std.mem.Allocator,
) std.mem.Allocator.Error!UnaryResponse {
    return .{
        .allocator = allocator,
        .transport = null,
        .response_committed = true,
        .status = .cancelled,
        .status_message = try allocator.dupe(
            u8,
            "retry perAttemptRecvTimeout exceeded",
        ),
        .message = null,
        .was_compressed = false,
        .encoding = null,
        .owned_message = null,
    };
}

/// One unary RPC, including one transparent refusal recovery before any
/// response head. Every physical attempt retains the original awake deadline.
pub fn unaryCall(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: UnaryCallOptions) Error!UnaryResponse {
    return retry.run(connection, allocator, options, null, retryUnaryCallAttempt);
}

/// Unary call whose absolute deadline was captured by an owning channel before
/// connection readiness. This prevents connection wait from renewing the RPC.
pub fn unaryCallUnderDeadline(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: UnaryCallOptions, deadline: ?std.Io.Clock.Timestamp) Error!UnaryResponse {
    return retry.runWithDeadline(
        connection,
        allocator,
        options,
        null,
        deadline,
        retryUnaryCallAttempt,
    );
}

/// Add explicit replay-safe retries to the transparent transport recovery.
/// Logical attempts, pushback, throttling, and backoff share one RPC deadline.
pub fn unaryCallWithRetry(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: UnaryCallOptions, policy: RetryPolicy) Error!UnaryResponse {
    return retry.run(
        connection,
        allocator,
        options,
        policy,
        retryUnaryCallAttempt,
    );
}

pub fn unaryCallWithRetryUnderDeadline(connection: *http2.runtime.Connection, allocator: std.mem.Allocator, options: UnaryCallOptions, policy: RetryPolicy, deadline: ?std.Io.Clock.Timestamp) Error!UnaryResponse {
    return retry.runWithDeadline(
        connection,
        allocator,
        options,
        policy,
        deadline,
        retryUnaryCallAttempt,
    );
}

fn retryUnaryCallAttempt(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: UnaryCallOptions,
    attempt_deadline: ?std.Io.Clock.Timestamp,
    _: ?std.Io.Clock.Timestamp,
    timeout_header: ?Timeout,
    previous_attempts: ?u8,
) Error!UnaryResponse {
    return unaryCallAttempt(
        connection,
        allocator,
        options,
        attempt_deadline,
        timeout_header,
        previous_attempts,
    );
}

/// Execute one unary attempt under a caller-owned absolute deadline.
///
/// Retry orchestration uses this entry point so every attempt inherits the
/// original RPC budget while advertising its remaining budget and attempt
/// number on the wire. `previous_attempts` is omitted for the first attempt.
pub fn unaryCallAttempt(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    options: UnaryCallOptions,
    deadline: ?std.Io.Clock.Timestamp,
    timeout_header: ?Timeout,
    previous_attempts: ?u8,
) Error!UnaryResponse {
    if ((deadline == null) != (timeout_header == null)) {
        return error.InvalidTimeout;
    }
    if (options.message.len > options.requestMessageLimit()) {
        return error.GrpcMessageTooLarge;
    }
    var encoded = try compression_mod.compressAlloc(
        allocator,
        options.compression,
        options.message,
        options.compression_level,
    );
    defer encoded.deinit(allocator);
    _ = try splitMethodPath(options.path);
    try validateCustomMetadata(options.metadata);
    try validateCustomBinaryMetadata(options.binary_metadata);
    var binary_metadata = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.binary_metadata,
    );
    defer binary_metadata.deinit();

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    try writeMessage(
        &framed,
        allocator,
        encoded.bytes,
        encoded.compressed,
    );

    var header_storage: [16]http2.Hpack.HeaderField = undefined;
    const header_count = std.math.add(
        usize,
        options.metadata.len,
        std.math.add(
            usize,
            binary_metadata.fields.len,
            5 + @as(usize, @intFromBool(previous_attempts != null)),
        ) catch return error.MessageTooLarge,
    ) catch return error.MessageTooLarge;
    const buffer = if (header_count <= header_storage.len)
        header_storage[0..header_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, header_count);
    defer if (buffer.ptr != header_storage[0..].ptr) {
        allocator.free(buffer);
    };
    var headers: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(buffer);
    headers.appendAssumeCapacity(.{
        .name = "content-type",
        .value = "application/grpc+proto",
    });
    headers.appendAssumeCapacity(.{
        .name = "te",
        .value = "trailers",
    });
    var timeout_buffer: [9]u8 = undefined;
    if (timeout_header) |timeout| {
        headers.appendAssumeCapacity(.{
            .name = "grpc-timeout",
            .value = try timeout.formatInto(&timeout_buffer),
        });
    }
    var previous_attempts_buffer: [3]u8 = undefined;
    if (previous_attempts) |attempts| {
        if (attempts == 0) return error.InvalidMetadata;
        headers.appendAssumeCapacity(.{
            .name = "grpc-previous-rpc-attempts",
            .value = std.fmt.bufPrint(
                &previous_attempts_buffer,
                "{d}",
                .{attempts},
            ) catch return error.InvalidMetadata,
        });
    }
    if (options.compression != .identity) {
        headers.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = options.compression.name(),
        });
    }
    var accept_encoding_buffer: [32]u8 = undefined;
    headers.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression_mod.formatAcceptEncodingInto(
            &accept_encoding_buffer,
            options.accepted_encodings,
        ),
    });
    headers.appendSliceAssumeCapacity(options.metadata);
    headers.appendSliceAssumeCapacity(binary_metadata.fields);

    const request_options = http2.runtime.RequestOptions{
        .method = "POST",
        .path = options.path,
        .scheme = options.scheme,
        .authority = options.authority,
        .headers = headers.items,
        .body = framed.items,
    };
    const response = (if (deadline) |absolute|
        connection.requestWithDeadline(request_options, absolute)
    else
        connection.request(request_options)) catch |err| switch (err) {
        error.StreamReset => {
            const info = connection.takeLastPeerResetInfo() orelse return err;
            return resetUnaryResponse(allocator, info);
        },
        else => return err,
    };
    return parseUnaryResponse(
        allocator,
        response,
        options.responseMessageLimit(),
        options.accepted_encodings,
    );
}

/// Prefix-reserved server response storage: allocate through
/// `OwnedResponseMessage.init`, serialize into `payload()`, and submit it here.
/// Identity responses hand the exact allocation to the HTTP/2 writer without
/// another copy; the caller's deferred `deinit` sees a consumed message.
pub const OwnedResponseMessage = outbound_ownership.OwnedMessage;

pub const UnaryResponseOptions = struct {
    status: Status = .ok,
    message: ?[]const u8 = null,
    /// Mutually exclusive with `message`. On success the message's storage is
    /// consumed and transferred to the response writer.
    owned_message: ?*OwnedResponseMessage = null,
    /// Requested response encoding. The message remains uncompressed unless
    /// the request advertised support for this algorithm.
    compression: Algorithm = .identity,
    compression_level: u4 = 6,
    request_accepted_encodings: AlgorithmSet = .{},
    /// Decoders advertised by this server for future request messages.
    accepted_encodings: AlgorithmSet = .supported,
    status_message: ?[]const u8 = null,
    /// Raw google.rpc.Status protobuf, validated against status before I/O.
    status_details: ?[]const u8 = null,
    initial_metadata: []const http2.Hpack.HeaderField = &.{},
    trailing_metadata: []const http2.Hpack.HeaderField = &.{},
    /// Raw initial metadata encoded into HTTP/2 response headers.
    initial_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    /// Raw trailing metadata encoded into gRPC response trailers.
    trailing_binary_metadata: []const metadata_mod.BinaryMetadata = &.{},
    /// Optional server retry push-back in milliseconds. A negative value
    /// tells conforming clients not to retry this response.
    retry_pushback_ms: ?i64 = null,
    trailers_only: bool = false,
};

pub fn writeUnaryResponse(
    connection: *http2.runtime.Connection,
    allocator: std.mem.Allocator,
    stream_id: u31,
    options: UnaryResponseOptions,
) Error!void {
    if (options.status_details) |bytes| _ = try details_mod.validate(options.status, bytes);
    const encoded_details = if (options.status_details) |bytes| try details_mod.encodedAlloc(allocator, options.status, bytes) else null;
    defer if (encoded_details) |bytes| allocator.free(bytes);
    try validateCustomMetadata(options.initial_metadata);
    try validateCustomMetadata(options.trailing_metadata);
    try validateCustomBinaryMetadata(
        options.initial_binary_metadata,
    );
    try validateCustomBinaryMetadata(
        options.trailing_binary_metadata,
    );
    var initial_binary = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.initial_binary_metadata,
    );
    defer initial_binary.deinit();
    var trailing_binary = try metadata_mod.encodeFieldsAlloc(
        allocator,
        options.trailing_binary_metadata,
    );
    defer trailing_binary.deinit();
    if (options.message != null and options.owned_message != null) {
        return error.InvalidMessageCount;
    }
    const has_message = options.message != null or options.owned_message != null;
    if (options.status == .ok and !has_message) {
        return error.InvalidMessageCount;
    }
    if (options.trailers_only and has_message) {
        return error.InvalidMessageCount;
    }

    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    var encoded_message: ?compression_mod.EncodedPayload = null;
    defer if (encoded_message) |*encoded| encoded.deinit(allocator);
    var owned_storage: ?[]u8 = null;
    defer if (owned_storage) |storage| allocator.free(storage);
    var compressed_frame: ?[]u8 = null;
    defer if (compressed_frame) |bytes| allocator.free(bytes);
    var framed_bytes: []const u8 = &.{};
    const response_algorithm: Algorithm =
        if (has_message and
        options.request_accepted_encodings.contains(
            options.compression,
        ))
            options.compression
        else
            .identity;
    if (options.owned_message) |owned| {
        // Take the prefix-reserved storage so an identity response reaches the
        // HTTP/2 writer as the caller's exact allocation, without a staging
        // copy. Compression still falls back to a separate framed buffer.
        const storage = try owned.takeFor(allocator);
        owned_storage = storage;
        const encoder = codec.Encoder{
            .allocator = allocator,
            .algorithm = response_algorithm,
            .compression_level = options.compression_level,
        };
        const encoded = try outbound_ownership.encode(allocator, encoder, storage, .{});
        framed_bytes = encoded.bytes;
        if (!encoded.input_transferred) compressed_frame = encoded.bytes;
    } else if (options.message) |message| {
        // A server must not use a response encoding absent from the client's
        // last grpc-accept-encoding advertisement. Falling back to identity
        // is required even when the application requested compression.
        encoded_message = try compression_mod.compressAlloc(
            allocator,
            response_algorithm,
            message,
            options.compression_level,
        );
        try writeMessage(
            &framed,
            allocator,
            encoded_message.?.bytes,
            encoded_message.?.compressed,
        );
        framed_bytes = framed.items;
    }
    var status_buffer: [2]u8 = undefined;
    const status_value = std.fmt.bufPrint(
        &status_buffer,
        "{d}",
        .{@intFromEnum(options.status)},
    ) catch unreachable;
    const encoded_status_message = if (options.status_message) |message|
        try encodeStatusMessageAlloc(allocator, message)
    else
        try allocator.alloc(u8, 0);
    defer allocator.free(encoded_status_message);

    const trailing_count = std.math.add(
        usize,
        std.math.add(
            usize,
            options.trailing_metadata.len,
            trailing_binary.fields.len,
        ) catch return error.MessageTooLarge,
        @as(usize, 1) +
            @intFromBool(options.status_message != null) +
            @intFromBool(options.retry_pushback_ms != null) +
            @intFromBool(options.status_details != null),
    ) catch return error.MessageTooLarge;
    var initial_storage: [16]http2.Hpack.HeaderField = undefined;
    const initial_base = std.math.add(
        usize,
        2,
        @intFromBool(response_algorithm != .identity),
    ) catch return error.MessageTooLarge;
    const initial_extra = std.math.add(
        usize,
        initial_base,
        if (options.trailers_only) trailing_count else 0,
    ) catch return error.MessageTooLarge;
    const initial_count = std.math.add(
        usize,
        std.math.add(
            usize,
            options.initial_metadata.len,
            initial_binary.fields.len,
        ) catch return error.MessageTooLarge,
        initial_extra,
    ) catch return error.MessageTooLarge;
    const initial_buffer = if (initial_count <= initial_storage.len)
        initial_storage[0..initial_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, initial_count);
    defer if (initial_buffer.ptr != initial_storage[0..].ptr) {
        allocator.free(initial_buffer);
    };
    var initial: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(initial_buffer);
    initial.appendAssumeCapacity(.{
        .name = "content-type",
        .value = "application/grpc+proto",
    });
    if (response_algorithm != .identity) {
        initial.appendAssumeCapacity(.{
            .name = "grpc-encoding",
            .value = response_algorithm.name(),
        });
    }
    var accept_encoding_buffer: [32]u8 = undefined;
    initial.appendAssumeCapacity(.{
        .name = "grpc-accept-encoding",
        .value = try compression_mod.formatAcceptEncodingInto(
            &accept_encoding_buffer,
            options.accepted_encodings,
        ),
    });
    initial.appendSliceAssumeCapacity(options.initial_metadata);
    initial.appendSliceAssumeCapacity(initial_binary.fields);

    var trailing_storage: [16]http2.Hpack.HeaderField = undefined;
    const trailing_buffer = if (trailing_count <= trailing_storage.len)
        trailing_storage[0..trailing_count]
    else
        try allocator.alloc(http2.Hpack.HeaderField, trailing_count);
    defer if (trailing_buffer.ptr != trailing_storage[0..].ptr) {
        allocator.free(trailing_buffer);
    };
    var trailing: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(trailing_buffer);
    trailing.appendAssumeCapacity(.{
        .name = "grpc-status",
        .value = status_value,
    });
    if (options.status_message != null) {
        trailing.appendAssumeCapacity(.{
            .name = "grpc-message",
            .value = encoded_status_message,
        });
    }
    var retry_pushback_buffer: [21]u8 = undefined;
    if (options.retry_pushback_ms) |milliseconds| {
        trailing.appendAssumeCapacity(.{
            .name = "grpc-retry-pushback-ms",
            .value = std.fmt.bufPrint(
                &retry_pushback_buffer,
                "{d}",
                .{milliseconds},
            ) catch unreachable,
        });
    }
    if (encoded_details) |bytes| trailing.appendAssumeCapacity(.{ .name = details_mod.name, .value = bytes, .never_index = true });
    trailing.appendSliceAssumeCapacity(options.trailing_metadata);
    trailing.appendSliceAssumeCapacity(trailing_binary.fields);

    if (options.trailers_only) {
        initial.appendSliceAssumeCapacity(trailing.items);
        return connection.writeResponse(stream_id, .{
            .headers = initial.items,
        });
    }
    return connection.writeResponse(stream_id, .{
        .headers = initial.items,
        .body = framed_bytes,
        .trailers = trailing.items,
    });
}

fn parseUnaryResponse(
    allocator: std.mem.Allocator,
    transport: http2.runtime.OwnedResponse,
    max_message_size: usize,
    accepted_encodings: AlgorithmSet,
) Error!UnaryResponse {
    var owned = transport;
    errdefer owned.deinit(allocator);
    var terminal = try response_metadata.parseTerminal(allocator, owned.status, owned.headers, owned.trailers);
    errdefer terminal.deinit(allocator);
    const status = terminal.status;
    const parse_grpc_body = response_metadata.parseBody(owned.status, owned.headers, owned.trailers);
    const encoding = if (parse_grpc_body) findHeader(owned.headers, "grpc-encoding") else null;
    var message: ?Message = null;
    var owned_message: ?[]u8 = null;
    errdefer if (owned_message) |payload| allocator.free(payload);
    var was_compressed = false;
    if (parse_grpc_body and owned.body.len != 0) {
        var iterator = MessageIterator.init(
            owned.body,
            max_message_size,
        );
        message = (try iterator.next()) orelse unreachable;
        if (try iterator.next() != null) {
            return error.InvalidMessageCount;
        }
        try validateMessageEncoding(message.?, encoding);
        var decoded = try decodeReceivedMessage(
            allocator,
            message.?,
            encoding,
            accepted_encodings,
            max_message_size,
        );
        errdefer decoded.deinit(allocator);
        was_compressed = message.?.compressed;
        owned_message = decoded.owned;
        // From this point UnaryResponse owns the decoded allocation. Clear
        // the temporary guard so a later status-validation error cannot free
        // the same payload through two errdefers.
        decoded.owned = null;
        message = .{
            .compressed = false,
            .payload = decoded.bytes,
        };
    }
    if (status == .ok and message == null) {
        return error.InvalidMessageCount;
    }
    return .{
        .allocator = allocator,
        .transport = owned,
        .reset = null,
        .response_committed = !owned.trailers_only,
        .status = status,
        .status_message = terminal.status_message,
        .status_details = terminal.status_details,
        .message = message,
        .was_compressed = was_compressed,
        .encoding = encoding,
        .owned_message = owned_message,
    };
}

fn resetUnaryResponse(
    allocator: std.mem.Allocator,
    info: http2.runtime.PeerResetInfo,
) Error!UnaryResponse {
    const reset = info.reset;
    return .{
        .allocator = allocator,
        .transport = null,
        .reset = reset,
        .response_committed = info.response_started,
        .status = statusFromHttp2Error(reset.error_code),
        .status_message = try resetStatusMessageAlloc(
            allocator,
            reset.error_code,
        ),
        .message = null,
        .was_compressed = false,
        .encoding = null,
        .owned_message = null,
    };
}

fn decodeReceivedMessage(
    allocator: std.mem.Allocator,
    message: Message,
    encoding: ?[]const u8,
    accepted_encodings: AlgorithmSet,
    max_message_size: usize,
) Error!compression_mod.DecodedPayload {
    if (!message.compressed) {
        return .{ .bytes = message.payload };
    }
    const raw_encoding = encoding orelse
        return error.CompressionNotNegotiated;
    const algorithm = Algorithm.parse(raw_encoding) orelse
        return error.UnsupportedCompression;
    if (algorithm == .identity) return error.CompressionNotNegotiated;
    if (!accepted_encodings.contains(algorithm)) {
        return error.UnsupportedCompression;
    }
    return compression_mod.decompressAlloc(
        allocator,
        algorithm,
        message.payload,
        max_message_size,
    );
}

fn splitMethodPath(
    path: []const u8,
) Error!struct {
    service: []const u8,
    method: []const u8,
} {
    if (path.len < 4 or path[0] != '/') {
        return error.InvalidGrpcRequest;
    }
    const separator = std.mem.indexOfScalar(
        u8,
        path[1..],
        '/',
    ) orelse return error.InvalidGrpcRequest;
    const absolute = separator + 1;
    if (absolute == 1 or absolute + 1 >= path.len or
        std.mem.indexOfScalar(u8, path[absolute + 1 ..], '/') != null)
    {
        return error.InvalidGrpcRequest;
    }
    return .{
        .service = path[1..absolute],
        .method = path[absolute + 1 ..],
    };
}

fn findHeader(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return header.value;
        }
    }
    return null;
}

pub fn validateMessageEncoding(
    message: Message,
    encoding: ?[]const u8,
) Error!void {
    const value = encoding orelse {
        if (message.compressed) return error.CompressionNotNegotiated;
        return;
    };
    const algorithm = Algorithm.parse(value) orelse
        return error.UnsupportedCompression;
    if (message.compressed and algorithm == .identity) {
        return error.CompressionNotNegotiated;
    }
}

pub fn headerValue(
    headers: []const http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    return findHeader(headers, name);
}

/// Apply xDS response-header mutations to an owned HTTP/2 header block. The
/// original block is freed only after every replacement allocation succeeds.
/// The returned slice is owned by `allocator` and can be passed to the normal
/// HTTP/2 response deinitializer.
pub fn rewriteResponseHeaders(
    allocator: std.mem.Allocator,
    headers: []http2.Hpack.HeaderField,
    mutations: []const HeaderMutation,
    removals: []const []const u8,
) std.mem.Allocator.Error![]http2.Hpack.HeaderField {
    if (mutations.len == 0 and removals.len == 0) return headers;
    var staged: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    defer staged.deinit(allocator);
    const capacity = std.math.add(usize, headers.len, mutations.len) catch
        return error.OutOfMemory;
    try staged.ensureTotalCapacity(allocator, capacity);
    for (headers) |field| {
        var removed = false;
        for (removals) |name| {
            if (std.ascii.eqlIgnoreCase(field.name, name)) {
                removed = true;
                break;
            }
        }
        if (!removed) staged.appendAssumeCapacity(field);
    }
    for (mutations) |mutation| {
        const present = findHeader(staged.items, mutation.name) != null;
        switch (mutation.action) {
            .append => {},
            .add_if_absent => if (present) continue,
            .overwrite => removeStagedHeader(&staged, mutation.name),
            .overwrite_if_exists => {
                if (!present) continue;
                removeStagedHeader(&staged, mutation.name);
            },
        }
        staged.appendAssumeCapacity(.{
            .name = mutation.name,
            .value = mutation.value,
            .never_index = false,
        });
    }
    const owned = try allocator.alloc(http2.Hpack.HeaderField, staged.items.len);
    var written: usize = 0;
    errdefer {
        for (owned[0..written]) |field| {
            allocator.free(field.value);
            allocator.free(field.name);
        }
        allocator.free(owned);
    }
    for (staged.items, owned) |field, *out| {
        const name = try allocator.dupe(u8, field.name);
        const value = allocator.dupe(u8, field.value) catch |err| {
            allocator.free(name);
            return err;
        };
        out.* = .{
            .name = name,
            .value = value,
            .never_index = field.never_index,
        };
        written += 1;
    }
    http2.runtime.freeHeaderFields(allocator, headers);
    return owned;
}

fn removeStagedHeader(
    staged: *std.ArrayList(http2.Hpack.HeaderField),
    name: []const u8,
) void {
    var write: usize = 0;
    for (staged.items) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) continue;
        staged.items[write] = field;
        write += 1;
    }
    staged.items.len = write;
}

pub const statusFromHttp = response_metadata.statusFromHttp;

/// Map an HTTP/2 RST_STREAM reason according to gRPC's HTTP/2 transport
/// specification. Unknown extension codes are protocol failures and therefore
/// surface as INTERNAL rather than being mistaken for an application status.
pub fn statusFromHttp2Error(error_code: http2.ErrorCode) Status {
    return switch (error_code) {
        .refused_stream => .unavailable,
        .cancel => .cancelled,
        .enhance_your_calm => .resource_exhausted,
        .inadequate_security => .permission_denied,
        else => .internal,
    };
}

pub fn resetStatusMessageAlloc(
    allocator: std.mem.Allocator,
    error_code: http2.ErrorCode,
) std.mem.Allocator.Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "RST_STREAM received with HTTP/2 error {s} ({d})",
        .{ http2ErrorName(error_code), @intFromEnum(error_code) },
    );
}

fn http2ErrorName(error_code: http2.ErrorCode) []const u8 {
    return switch (error_code) {
        .no_error => "no_error",
        .protocol_error => "protocol_error",
        .internal_error => "internal_error",
        .flow_control_error => "flow_control_error",
        .settings_timeout => "settings_timeout",
        .stream_closed => "stream_closed",
        .frame_size_error => "frame_size_error",
        .refused_stream => "refused_stream",
        .cancel => "cancel",
        .compression_error => "compression_error",
        .connect_error => "connect_error",
        .enhance_your_calm => "enhance_your_calm",
        .inadequate_security => "inadequate_security",
        .http_1_1_required => "http_1_1_required",
        _ => "unknown",
    };
}

pub fn validateCustomMetadata(
    metadata: []const http2.Hpack.HeaderField,
) Error!void {
    for (metadata) |field| {
        if (field.name.len == 0 or field.name[0] == ':' or
            metadata_mod.isBinaryName(field.name) or
            std.ascii.eqlIgnoreCase(field.name, "content-type") or
            std.ascii.eqlIgnoreCase(field.name, "te") or
            std.ascii.startsWithIgnoreCase(field.name, "grpc-"))
        {
            return error.InvalidMetadata;
        }
    }
}

pub fn validateCustomBinaryMetadata(
    metadata: []const metadata_mod.BinaryMetadata,
) Error!void {
    for (metadata) |field| {
        try metadata_mod.validateBinaryName(field.name);
        if (std.ascii.startsWithIgnoreCase(field.name, "grpc-")) {
            return error.InvalidMetadata;
        }
    }
}

//! RFC 9220 WebSocket over an authenticated HTTP/3 Extended CONNECT stream.
//!
//! WebSocket bytes are carried in HTTP/3 DATA frames while QUIC continues to
//! provide loss recovery and flow control. Complete and fragmented messages
//! share the RFC 6455 codec and transactional permessage-deflate engine.

const std = @import("std");
const builtin = @import("builtin");
const websocket = @import("../mod.zig");
const common = @import("common.zig");
const cookie_handshake = @import("cookies.zig");
const compression_scratch = @import("compression_scratch.zig");
const origin_policy = @import("origin_policy.zig");
const handshake_headers = @import("handshake/headers.zig");
const handshake_storage = @import("handshake/storage.zig");
const message_buffer = @import("message/buffer.zig");
const message_state = @import("message/state.zig");
const frame_validation = @import("message/frame_validation.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const http3 = @import("../../http3/mod.zig");
const rejection_drain_timeout: std.Io.Duration = .fromSeconds(5);
const max_payload_read_chunk: usize = 16 * 1024;
const fragmented_write_scratch_len: usize = 16 * 1024;
const max_batched_fragments: usize = 16;
const max_batched_payload_slices: usize = 64;

pub const MessageWriteProgress = common.MessageWriteProgress;
const PendingAutomaticControl = common.PendingAutomaticControl;
const automatic_control = @import("control/automatic.zig");
const ping_control = @import("control/ping.zig");

const PendingMessage = struct {
    const Source = enum { contiguous, slices, fragmented, in_place };

    opcode: websocket.Opcode,
    source: Source = .contiguous,
    original_ptr: usize,
    original_len: usize,
    header: [websocket.max_frame_header_len]u8 = undefined,
    header_len: usize = 0,
    payload_len: usize = 0,
    committed: usize = 0,
    mask_key: ?[4]u8 = null,
    compressed: bool = false,
    fragment_index: usize = 0,
    fragment_start: usize = 0,
    fragmented_payload_total: usize = 0,
    wire_total: usize = 0,

    fn matches(
        self: *const PendingMessage,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) bool {
        return self.source == .contiguous and
            self.opcode == opcode and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    fn matchesParts(
        self: *const PendingMessage,
        parts: []const []const u8,
    ) bool {
        return self.source == .slices and
            self.opcode == .binary and
            self.original_len == parts.len and
            (parts.len == 0 or
                self.original_ptr == @intFromPtr(parts.ptr));
    }

    fn matchesInPlace(
        self: *const PendingMessage,
        payload: []const u8,
    ) bool {
        return self.source == .in_place and
            self.opcode == .binary and
            self.original_len == payload.len and
            (payload.len == 0 or
                self.original_ptr == @intFromPtr(payload.ptr));
    }

    fn matchesFragments(
        self: *const PendingMessage,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) bool {
        return self.source == .fragmented and
            self.opcode == opcode and
            self.original_len == fragments.len and
            (fragments.len == 0 or
                self.original_ptr == @intFromPtr(fragments.ptr));
    }

    fn totalLen(self: *const PendingMessage) usize {
        return if (self.source == .fragmented)
            self.wire_total
        else
            self.header_len + self.payload_len;
    }
};

const PendingControlFrame = common.PendingControlFrame;
const PendingWrite = common.PendingWriteState(PendingMessage);

fn copyMessagePartsAt(
    destination: []u8,
    parts: []const []const u8,
    start_offset: usize,
    mask_key: ?[4]u8,
) websocket.Error!void {
    var skip = start_offset;
    var written: usize = 0;
    for (parts) |part| {
        if (skip >= part.len) {
            skip -= part.len;
            continue;
        }
        const count = @min(
            destination.len - written,
            part.len - skip,
        );
        const source = part[skip..][0..count];
        if (mask_key) |mask| {
            try websocket.applyMaskCopy(
                destination[written..][0..count],
                source,
                mask,
                start_offset + written,
            );
        } else {
            @memcpy(destination[written..][0..count], source);
        }
        written += count;
        skip = 0;
        if (written == destination.len) return;
    }
    std.debug.assert(written == destination.len);
}

fn fragmentedWireLen(
    fragments: []const []const u8,
    compressed_len: ?usize,
    masked: bool,
) websocket.Error!usize {
    var total: usize = 0;
    for (fragments, 0..) |fragment, index| {
        const payload_len = if (compressed_len) |len| blk: {
            const range = compressedFragmentRange(
                len,
                fragments.len,
                index,
            );
            break :blk range.end - range.start;
        } else fragment.len;
        var header: [websocket.max_frame_header_len]u8 = undefined;
        const encoded = try websocket.writeFrameHeaderForLengthInto(
            &header,
            if (index == 0) .binary else .continuation,
            payload_len,
            .{ .mask_key = if (masked) [4]u8{ 0, 0, 0, 0 } else null },
        );
        total = std.math.add(usize, total, encoded.len) catch
            return error.PayloadTooLarge;
        total = std.math.add(usize, total, payload_len) catch
            return error.PayloadTooLarge;
    }
    return total;
}

const IncomingDataKind = frame_validation.DataKind;

fn isAbruptReceiveEnd(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.RequestCancelled,
        error.RequestRejected,
        error.ConnectionResetByPeer,
        => true,
        else => false,
    };
}

const MessageFrameReceiveState = struct {
    header: ?websocket.FrameHeader = null,
    payload_start: usize = 0,
    payload_end: usize = 0,
    payload_written: usize = 0,
    message_kind: IncomingDataKind = .none,

    fn reset(self: *MessageFrameReceiveState) void {
        self.* = .{};
    }
};

pub const PingEvent = common.PingEvent;
pub const CloseHandshakeEvent = common.CloseHandshakeEvent;
pub const Message = common.Message;
pub const CookieHandshakeOptions = cookie_handshake.Options;
pub const AddressResolver = http3.runtime.AddressResolver;

pub const Error = websocket.Error || http3.runtime.Error ||
    cookie_handshake.Error || error{
    ConnectionClosed,
    ConcurrencyUnavailable,
    InvalidResponse,
    InvalidOrigin,
    InvalidSubprotocol,
    MessageTooLarge,
    UnexpectedPong,
    WriteInProgress,
    Timeout,
} || std.Io.RandomSecureError;

pub const ConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    protocols: []const []const u8 = &.{},
    /// Require the peer to select one offered subprotocol. The default accepts
    /// RFC 6455's null selection.
    require_subprotocol: bool = false,
    origin: ?[]const u8 = null,
    extra_headers: []const http3.Qpack.HeaderField = &.{},
    /// Optional single-owner CookieJar adapter. Scope is derived from the
    /// actual HTTPS `:authority` and `:path` values.
    cookies: ?CookieHandshakeOptions = null,
    enable_permessage_deflate: bool = false,
    /// Offer RFC 7692 context takeover on this Extended CONNECT stream.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// Offer a bound for this client's compression history.
    client_max_window_bits: ?u8 = null,
    /// Require the server compressor to use at most this history window.
    server_max_window_bits: ?u8 = null,
    compression_threshold: usize = 32,
    limits: common.Limits = .{},
};

/// URI-based RFC 9220 connection options. Authority, request target, DNS
/// destination, and default TLS server name are derived from the HTTPS URI.
pub const UriConnectOptions = struct {
    protocols: []const []const u8 = &.{},
    /// Require the peer to select one offered subprotocol. The default accepts
    /// RFC 6455's null selection.
    require_subprotocol: bool = false,
    origin: ?[]const u8 = null,
    extra_headers: []const http3.Qpack.HeaderField = &.{},
    /// Optional single-owner CookieJar adapter. Scope is derived from the
    /// parsed URI argument before opening QUIC.
    cookies: ?CookieHandshakeOptions = null,
    enable_permessage_deflate: bool = false,
    /// Offer RFC 7692 context takeover on this Extended CONNECT stream.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// Offer a bound for this client's compression history.
    client_max_window_bits: ?u8 = null,
    /// Require the server compressor to use at most this history window.
    server_max_window_bits: ?u8 = null,
    compression_threshold: usize = 32,
    limits: common.Limits = .{},
    h3_limits: http3.runtime.Limits = .{},
    h3: http3.runtime.HandshakeClientOptions,
    /// Route QUIC through SOCKS5 UDP ASSOCIATE while keeping URI DNS at the
    /// proxy and TLS identity bound to the HTTPS origin.
    socks5_proxy: ?http3.socks5_runtime.Proxy = null,
};

pub const AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    /// Reject the RFC 9220 handshake unless one of `protocols` was selected.
    require_subprotocol: bool = false,
    allowed_origins: []const []const u8 = &.{},
    extra_headers: []const http3.Qpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    /// Permit RFC 7692 context takeover on this Extended CONNECT stream.
    allow_context_takeover: bool = false,
    /// Explicit client/server direction policy overrides allow_context_takeover.
    context_takeover: ?websocket.ContextTakeover = null,
    /// If offered by the client, select at most this receive-history window.
    client_max_window_bits: ?u8 = null,
    /// Select at most this server send-history window.
    server_max_window_bits: ?u8 = null,
    compression_threshold: usize = 32,
    limits: common.Limits = .{},
};

pub const ClientConnection = Connection(.client);
pub const ServerConnection = Connection(.server);

/// Result of an authenticated RFC 9220 attempt before the application chooses
/// whether a non-2xx response should become a typed rejection. Response
/// metadata, bounded body, and trailers remain owned and inspectable until
/// `deinit` or `requireAccepted`.
pub const ConnectAttempt = struct {
    h3: ?http3.runtime.HandshakeClient,
    /// Non-null when the attempt temporarily owns a caller-supplied session.
    /// `deinit` restores it after abandoning only this CONNECT stream.
    restore_to: ?*http3.runtime.HandshakeClient = null,
    stream_id: u62,
    response: http3.DecodedResponseHead,
    response_body: []u8 = &.{},
    response_trailers: []http3.Qpack.HeaderField = &.{},
    stream_complete: bool = false,
    options: ConnectOptions,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.response.status >= 200 and self.response.status < 300;
    }

    pub fn status(self: ConnectAttempt) u16 {
        return self.response.status;
    }

    pub fn responseHeader(
        self: ConnectAttempt,
        name: []const u8,
    ) ?[]const u8 {
        for (self.response.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) {
                return header.value;
            }
        }
        return null;
    }

    pub fn body(self: ConnectAttempt) []const u8 {
        return self.response_body;
    }

    pub fn trailers(
        self: ConnectAttempt,
    ) []const http3.Qpack.HeaderField {
        return self.response_trailers;
    }

    pub fn deinit(self: *ConnectAttempt) void {
        const allocator = self.h3.?.allocator;
        self.response.deinit(allocator);
        allocator.free(self.response_body);
        http3.Qpack.freeDecodedFields(allocator, self.response_trailers);
        if (self.h3) |*client| {
            if (self.restore_to) |destination| {
                if (!self.stream_complete) {
                    client.abandonExtendedConnect(self.stream_id);
                }
                destination.* = client.*;
            } else {
                client.deinit();
            }
        }
        self.* = undefined;
    }

    pub fn requireAccepted(self: *ConnectAttempt) Error!ClientConnection {
        if (!self.accepted()) {
            if (handshake_headers.isUnsupportedVersionResponse(
                self.response.status,
                self.response.headers,
            )) return error.UnsupportedVersion;
            return error.InvalidResponse;
        }
        std.debug.assert(self.response_body.len == 0);
        std.debug.assert(self.response_trailers.len == 0);
        std.debug.assert(!self.stream_complete);
        const selected_protocol = try validateServerHandshake(
            self.h3.?.allocator,
            self.response.headers,
            self.options.protocols,
        );
        errdefer if (selected_protocol) |protocol| {
            self.h3.?.allocator.free(protocol);
        };
        try handshake_headers.enforceSubprotocolRequirement(
            self.options.require_subprotocol,
            selected_protocol,
        );
        const extension_policy: websocket.ExtensionNegotiation.Policy = .{
            .enable_permessage_deflate = self.options.enable_permessage_deflate,
            .allow_context_takeover = self.options.allow_context_takeover,
            .context_takeover = self.options.context_takeover,
        };
        var extension_offer_storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
        const extension_offer = try websocket.ExtensionNegotiation
            .offerValueInto(
            &extension_offer_storage,
            extension_policy,
            self.options.client_max_window_bits,
            self.options.server_max_window_bits,
        );
        const negotiated_extension = try websocket.ExtensionNegotiation
            .validateResponseHeadersForOfferWithPolicy(
            self.response.headers,
            extension_offer,
            extension_policy,
        );
        if (negotiated_extension.permessage_deflate and
            !self.options.enable_permessage_deflate)
        {
            return error.InvalidExtension;
        }
        const connection = ClientConnection.init(
            self.h3.?.allocator,
            self.stream_id,
            self.h3.?,
            self.options.limits,
            selected_protocol,
            negotiated_extension,
            self.options.compression_threshold,
        );
        self.response.deinit(connection.allocator);
        self.* = undefined;
        return connection;
    }
};

pub fn Connection(comptime role: common.Role) type {
    return struct {
        const Self = @This();
        const PingReader = ping_control.Reader(.{ .Error = Error, .receive = receiveFrameInternal, .io = io });

        allocator: std.mem.Allocator,
        stream_id: u62,
        h3: switch (role) {
            .client => http3.runtime.HandshakeClient,
            .server => http3.runtime.HandshakeServerSession,
        },
        limits: common.MessageLimits = .{},
        selected_protocol: ?[]u8 = null,
        inbuf: std.ArrayList(u8) = .empty,
        inbuf_consumed: usize = 0,
        /// Serializes complete WebSocket frame sequences and the reusable
        /// compression encoder. HTTP/3 may split one message across many QUIC
        /// packets, so locking only individual DATA writes would still permit
        /// another sender to splice bytes into the RFC 6455 frame.
        send_mutex: std.Io.Mutex = .init,
        message_assembler: ?websocket.MessageAssembler = null,
        message_into: common.MessageIntoReceiveState = .{},
        /// Owning/frame receives validate uncompressed text while HTTP/3 DATA
        /// chunks arrive, before the complete WebSocket frame exists. The
        /// caller-buffer path keeps equivalent state directly in `message_into`.
        incoming_data_kind: IncomingDataKind = .none,
        incoming_text_utf8: websocket.Utf8Validator = .{},
        incoming_frame_validated: usize = 0,
        message_frame_receive: MessageFrameReceiveState = .{},
        permessage_deflate: bool = false,
        compression_send_context_takeover: bool = false,
        compression_receive_context_takeover: bool = false,
        compression_threshold: usize = 32,
        compression_send_max_window_bits: u8 = 15,
        compression_receive_max_window_bits: u8 = 15,
        compression_send: compression_scratch.SendScratch = .{},
        compression_receive: compression_scratch.Scratch = .{},
        /// Receive progress and public writers may run on separate threads.
        /// The send mutex orders wire writes; atomics make their shared Close
        /// observations race-free without holding that mutex across QUIC reads.
        close_sent: std.atomic.Value(bool) = .init(false),
        close_received: std.atomic.Value(bool) = .init(false),
        /// A protocol failure or abrupt FIN/reset terminates parsing and
        /// releases receive-only storage instead of retaining/reparsing the
        /// incomplete DATA prefix.
        receive_failed: std.atomic.Value(bool) = .init(false),
        /// A retained outbound frame forced the Extended CONNECT stream to be
        /// cancelled instead of appending a Close after a partial frame.
        write_aborted: std.atomic.Value(bool) = .init(false),
        application_write_pending: std.atomic.Value(bool) = .init(false),
        automatic_write_pending: std.atomic.Value(bool) = .init(false),
        /// A bounded application message, Ping, or Close may own the HTTP/3
        /// DATA sequence. These transaction shapes are mutually exclusive.
        pending_write: PendingWrite = .none,
        /// Automatic Pong/Close bytes plus an optional peer control frame that
        /// remains owned until a bounded reply is fully committed.
        pending_auto_control: ?PendingAutomaticControl = null,
        receive_finished: bool = false,

        fn init(
            allocator: std.mem.Allocator,
            stream_id: u62,
            h3: @FieldType(Self, "h3"),
            limits: common.Limits,
            selected_protocol: ?[]u8,
            negotiated_extension: websocket.ExtensionNegotiation,
            compression_threshold: usize,
        ) Self {
            return .{
                .allocator = allocator,
                .stream_id = stream_id,
                .h3 = h3,
                .limits = common.MessageLimits.from(limits),
                .selected_protocol = selected_protocol,
                .permessage_deflate = negotiated_extension.permessage_deflate,
                .compression_send_context_takeover = negotiated_extension.permessage_deflate and switch (role) {
                    .client => !negotiated_extension.client_no_context_takeover,
                    .server => !negotiated_extension.server_no_context_takeover,
                },
                .compression_receive_context_takeover = negotiated_extension.permessage_deflate and switch (role) {
                    .client => !negotiated_extension.server_no_context_takeover,
                    .server => !negotiated_extension.client_no_context_takeover,
                },
                .compression_threshold = compression_threshold,
                .compression_send_max_window_bits = switch (role) {
                    .client => negotiated_extension.client_max_window_bits orelse 15,
                    .server => negotiated_extension.server_max_window_bits orelse 15,
                },
                .compression_receive_max_window_bits = switch (role) {
                    .client => negotiated_extension.server_max_window_bits orelse 15,
                    .server => negotiated_extension.client_max_window_bits orelse 15,
                },
            };
        }

        pub fn deinit(self: *Self) void {
            self.pending_write.clear();
            if (self.pending_auto_control) |*pending| {
                pending.deinit(self.allocator);
            }
            if (self.selected_protocol) |protocol| {
                self.allocator.free(protocol);
            }
            if (self.message_assembler) |*assembler| assembler.deinit();
            self.inbuf.deinit(self.allocator);
            self.compression_send.deinit(self.allocator);
            self.compression_receive.deinit(self.allocator);
            self.h3.deinit();
            self.* = undefined;
        }

        pub fn selectedProtocol(self: *const Self) ?[]const u8 {
            return self.selected_protocol;
        }

        pub fn negotiatedAlpn(self: *const Self) []const u8 {
            return self.h3.negotiatedAlpn();
        }

        pub fn peerCertificates(self: *const Self) ?[]const []const u8 {
            return self.h3.peerCertificates();
        }

        pub fn negotiatedCipherSuite(
            self: *const Self,
        ) @TypeOf(self.h3.negotiatedCipherSuite()) {
            return self.h3.negotiatedCipherSuite();
        }

        pub fn negotiatedTranscriptHash(
            self: *const Self,
        ) @TypeOf(self.h3.negotiatedTranscriptHash()) {
            return self.h3.negotiatedTranscriptHash();
        }

        pub fn exportKeyingMaterial(
            self: *const Self,
            label: []const u8,
            context: []const u8,
            out: []u8,
        ) Error!void {
            try self.h3.exportKeyingMaterial(label, context, out);
        }

        pub fn initiateKeyUpdate(self: *Self) Error!void {
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (!self.pending_write.isNone() or
                self.pending_auto_control != null)
            {
                return error.WriteInProgress;
            }
            try self.h3.initiateKeyUpdate();
        }

        pub fn localKeyUpdateCount(self: *const Self) u64 {
            return self.h3.localKeyUpdateCount();
        }

        pub fn peerKeyUpdateCount(self: *const Self) u64 {
            return self.h3.peerKeyUpdateCount();
        }

        pub fn keyUpdateAwaitingAck(self: *const Self) bool {
            return self.h3.keyUpdateAwaitingAck();
        }

        /// Drive QUIC ACK/loss/PTO processing until all reliable data on this
        /// connection has been acknowledged. Short-lived owners should call
        /// this after the Close handshake and before destroying the connection.
        pub fn waitForRecoveryIdleWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.waitForRecoveryIdleWithDeadline(.fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        pub fn waitForRecoveryIdleWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            try self.h3.waitForRecoveryIdleWithDeadline(deadline);
            // The last peer Close/FIN may have arrived while draining our own
            // reliable bytes. Flush that cumulative ACK within the same
            // caller budget before a short-lived owner releases the socket.
            _ = try self.h3.established.connection
                .flushPendingAckWithDeadline(deadline);
        }

        pub fn sendText(self: *Self, text: []const u8) Error!void {
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try common.validateOutgoingMessage(self.limits, .text, text);
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            try self.sendDataFrameValidatedLocked(.text, text);
        }

        pub fn sendTextWithTimeout(
            self: *Self,
            text: []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendTextWithDeadline(
                text,
                progress,
                .fromNow(self.io(), .{
                    .raw = timeout,
                    .clock = .awake,
                }),
            );
        }

        /// Send one text frame under an absolute deadline. If the deadline
        /// expires after a prefix commits, retry this method with the exact
        /// same slice; its address, length, and contents must remain stable
        /// until `progress.frame_committed` becomes true.
        pub fn sendTextWithDeadline(
            self: *Self,
            text: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try common.validateOutgoingMessage(self.limits, .text, text);
            return self.sendMessageWithDeadlineLocked(
                .text,
                text,
                progress,
                deadline,
            );
        }

        pub fn sendBinary(self: *Self, payload: []const u8) Error!void {
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try common.validateOutgoingMessage(
                self.limits,
                .binary,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            try self.sendDataFrameValidatedLocked(.binary, payload);
        }

        pub fn sendBinaryWithTimeout(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendBinaryWithDeadline(
                payload,
                progress,
                .fromNow(self.io(), .{
                    .raw = timeout,
                    .clock = .awake,
                }),
            );
        }

        /// Binary counterpart to `sendTextWithDeadline`. Progress is
        /// cumulative across retries and counts the complete RFC 6455 frame,
        /// including its header. The caller retains the same immutable payload
        /// slice until the frame commits.
        pub fn sendBinaryWithDeadline(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try common.validateOutgoingMessage(
                self.limits,
                .binary,
                payload,
            );
            return self.sendMessageWithDeadlineLocked(
                .binary,
                payload,
                progress,
                deadline,
            );
        }

        /// Mask a mutable client payload in place and send it without the
        /// bounded copy used by immutable client sends. The payload remains
        /// masked after return, matching websocket.zig's mutable send contract.
        /// Server connections and negotiated compression reject this opt-in
        /// path because neither requires an in-place client mask.
        pub fn sendBinaryInPlace(
            self: *Self,
            payload: []u8,
        ) Error!void {
            try self.validateBinaryInPlace(payload.len);
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (!self.pending_write.isNone()) return error.WriteInProgress;
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }

            var mask_key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io(), &mask_key);
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                .binary,
                payload,
                .{ .mask_key = mask_key },
            );
            websocket.applyMask(payload, mask_key, 0);
            // The QUIC sender encodes the borrowed STREAM view into stable
            // recovery storage before returning, so caller ownership resumes
            // as soon as this synchronous operation completes.
            self.writeParts(&.{ header, payload }, false) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }

        pub fn sendBinaryInPlaceWithTimeout(
            self: *Self,
            payload: []u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendBinaryInPlaceWithDeadline(
                payload,
                progress,
                .fromNow(self.io(), .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendBinaryInPlaceWithDeadline(
            self: *Self,
            payload: []u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try self.validateBinaryInPlace(payload.len);
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.pending_write.isPing() or self.pending_write.isClose()) {
                return error.WriteInProgress;
            }
            if (self.pending_write.messagePtr()) |pending| {
                if (!pending.matchesInPlace(payload)) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return error.WriteInProgress;
                }
            } else {
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                try self.beginPendingInPlaceLocked(payload);
            }
            try self.resumePendingInPlaceLocked(payload, progress, deadline);
        }

        fn beginPendingInPlaceLocked(
            self: *Self,
            payload: []u8,
        ) Error!void {
            var pending = PendingMessage{
                .opcode = .binary,
                .source = .in_place,
                .original_ptr = @intFromPtr(payload.ptr),
                .original_len = payload.len,
                .payload_len = payload.len,
            };
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.io(), &key);
            pending.mask_key = key;
            const header = try websocket.writeFrameHeaderForLengthInto(
                &pending.header,
                .binary,
                payload.len,
                .{ .mask_key = key },
            );
            pending.header_len = header.len;
            websocket.applyMask(payload, key, 0);
            self.pending_write = .{ .message = pending };
            self.application_write_pending.store(true, .release);
        }

        fn resumePendingInPlaceLocked(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            const pending = self.pending_write.messagePtr().?;
            while (pending.committed < pending.totalLen()) {
                const header_offset = @min(
                    pending.committed,
                    pending.header_len,
                );
                const payload_offset = pending.committed - header_offset;
                const bytes = if (header_offset < pending.header_len)
                    pending.header[header_offset..pending.header_len]
                else
                    payload[payload_offset..];
                var body_progress: http3.runtime.BodyWriteProgress = .{};
                const send_result = if (comptime role == .client)
                    self.h3.sendRequestBodyPacedWithDeadline(
                        self.stream_id,
                        bytes,
                        false,
                        &body_progress,
                        deadline,
                    )
                else
                    return error.InvalidFrame;
                send_result catch |err| {
                    pending.committed += body_progress.committed_bytes;
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return err;
                };
                pending.committed += body_progress.committed_bytes;
            }
            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.totalLen(),
                .frame_committed = true,
            };
            self.pending_write = .none;
            self.application_write_pending.store(false, .release);
        }

        /// Test the role/extension/state validation without constructing a
        /// live QUIC session. Kept private to the implementation module's
        /// testing facade below.
        fn validateBinaryInPlace(self: *const Self, payload_len: usize) Error!void {
            if (role != .client or self.permessage_deflate) {
                return error.InvalidFrame;
            }
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try common.validateOutgoingMessageLength(
                self.limits,
                payload_len,
            );
        }

        /// Compatibility wrapper for the two-slice binary-message form.
        pub fn sendBinaryParts(
            self: *Self,
            first: []const u8,
            second: []const u8,
        ) Error!void {
            return self.sendBinarySlices(&.{ first, second });
        }

        /// Send borrowed slices as one FIN-terminated RFC 6455 binary frame.
        /// HTTP/3 DATA boundaries remain invisible to the WebSocket peer.
        pub fn sendBinarySlices(
            self: *Self,
            parts: []const []const u8,
        ) Error!void {
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            const payload_len = try common.validateOutgoingMessageParts(
                self.limits,
                parts,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (!self.pending_write.isNone()) return error.WriteInProgress;
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            if (self.permessage_deflate and
                payload_len >= self.compression_threshold)
            {
                const compressed = try self.compressMessageParts(
                    parts,
                    payload_len,
                );
                if (compressed.len < payload_len) {
                    self.writeFrameExtended(
                        .binary,
                        compressed,
                        true,
                        false,
                        true,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    };
                    self.commitCompressionPreviewLocked();
                    return;
                }
                self.discardCompressionPreviewLocked();
            }
            self.writeBinarySlices(parts, payload_len) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }

        pub fn sendBinarySlicesWithTimeout(
            self: *Self,
            parts: []const []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendBinarySlicesWithDeadline(
                parts,
                progress,
                .fromNow(self.io(), .{
                    .raw = timeout,
                    .clock = .awake,
                }),
            );
        }

        /// Send borrowed slices as one binary frame under an absolute
        /// deadline. Until the frame commits, retries must pass the same slice
        /// descriptor array and keep every referenced payload byte stable.
        pub fn sendBinarySlicesWithDeadline(
            self: *Self,
            parts: []const []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            const payload_len = try common.validateOutgoingMessageParts(
                self.limits,
                parts,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.pending_write.isPing() or self.pending_write.isClose()) {
                return error.WriteInProgress;
            }
            if (self.pending_write.messagePtr()) |pending| {
                if (!pending.matchesParts(parts)) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return error.WriteInProgress;
                }
            } else {
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingMessagePartsLocked(parts, payload_len);
            }
            try self.resumePendingMessagePartsLocked(
                parts,
                progress,
                deadline,
            );
        }

        /// Send one WebSocket message as caller-selected RFC 6455 fragments
        /// while keeping the HTTP/3 request stream open. When compression is
        /// negotiated, the complete logical message is compressed before its
        /// wire framing is selected.
        pub fn sendFragmented(
            self: *Self,
            opcode: websocket.Opcode,
            fragments: []const []const u8,
        ) Error!void {
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            const total = try common.validateOutgoingFragments(
                self.limits,
                opcode,
                fragments,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (!self.pending_write.isNone()) return error.WriteInProgress;
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            if (self.permessage_deflate and
                total >= self.compression_threshold)
            {
                const compressed = try self.compressMessageParts(
                    fragments,
                    total,
                );
                if (compressed.len < total) {
                    self.writeCompressedFragments(
                        opcode,
                        compressed,
                        fragments.len,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    };
                    self.commitCompressionPreviewLocked();
                    return;
                }
                self.discardCompressionPreviewLocked();
            }
            self.writeUncompressedFragments(opcode, fragments) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }

        pub fn sendFragmentedWithTimeout(
            self: *Self,
            opcode: websocket.Opcode,
            fragments: []const []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendFragmentedWithDeadline(
                opcode,
                fragments,
                progress,
                .fromNow(self.io(), .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendFragmentedWithDeadline(
            self: *Self,
            opcode: websocket.Opcode,
            fragments: []const []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            const plain_len = try common.validateOutgoingFragments(
                self.limits,
                opcode,
                fragments,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.pending_write.isPing() or self.pending_write.isClose()) {
                return error.WriteInProgress;
            }
            if (self.pending_write.messagePtr()) |pending| {
                if (!pending.matchesFragments(opcode, fragments)) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return error.WriteInProgress;
                }
            } else {
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingFragmentedLocked(
                    opcode,
                    fragments,
                    plain_len,
                );
            }
            try self.resumePendingFragmentedLocked(
                fragments,
                progress,
                deadline,
            );
        }

        fn beginPendingFragmentedLocked(
            self: *Self,
            opcode: websocket.Opcode,
            fragments: []const []const u8,
            plain_len: usize,
        ) Error!void {
            std.debug.assert(self.pending_write.isNone());
            var pending = PendingMessage{
                .opcode = opcode,
                .source = .fragmented,
                .original_ptr = @intFromPtr(fragments.ptr),
                .original_len = fragments.len,
            };
            errdefer self.discardCompressionPreviewLocked();
            if (self.permessage_deflate and
                plain_len >= self.compression_threshold)
            {
                const compressed = try self.compressMessageParts(
                    fragments,
                    plain_len,
                );
                pending.compressed = compressed.len < plain_len;
                if (pending.compressed) {
                    pending.fragmented_payload_total = compressed.len;
                } else {
                    self.discardCompressionPreviewLocked();
                }
            }
            pending.wire_total = try fragmentedWireLen(
                fragments,
                if (pending.compressed) pending.fragmented_payload_total else null,
                role == .client,
            );
            self.pending_write = .{ .message = pending };
            self.application_write_pending.store(true, .release);
            errdefer {
                self.pending_write = .none;
                self.application_write_pending.store(false, .release);
            }
            try self.preparePendingFragmentLocked(fragments, 0);
        }

        fn preparePendingFragmentLocked(
            self: *Self,
            fragments: []const []const u8,
            index: usize,
        ) Error!void {
            const pending = self.pending_write.messagePtr().?;
            std.debug.assert(pending.source == .fragmented);
            const range: FragmentRange = if (pending.compressed)
                compressedFragmentRange(
                    pending.fragmented_payload_total,
                    fragments.len,
                    index,
                )
            else
                .{ .start = 0, .end = fragments[index].len };
            const mask_key: ?[4]u8 = if (role == .client) blk: {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                break :blk key;
            } else null;
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                if (index == 0) pending.opcode else .continuation,
                range.end - range.start,
                .{
                    .fin = index + 1 == fragments.len,
                    .mask_key = mask_key,
                    .rsv1 = pending.compressed and index == 0,
                },
            );
            @memcpy(pending.header[0..header.len], header);
            pending.fragment_index = index;
            pending.payload_len = range.end - range.start;
            pending.fragment_start = pending.committed;
            pending.mask_key = mask_key;
            pending.header_len = header.len;
        }

        fn resumePendingFragmentedLocked(
            self: *Self,
            fragments: []const []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            var scratch: [fragmented_write_scratch_len]u8 = undefined;
            while (self.pending_write.messagePtr()) |pending| {
                const frame_committed =
                    pending.committed - pending.fragment_start;
                const header_offset = @min(
                    frame_committed,
                    pending.header_len,
                );
                const payload_offset = frame_committed - header_offset;
                var len: usize = 0;
                if (header_offset < pending.header_len) {
                    const header =
                        pending.header[header_offset..pending.header_len];
                    @memcpy(scratch[0..header.len], header);
                    len = header.len;
                }
                const payload = if (pending.compressed) blk: {
                    const range = compressedFragmentRange(
                        self.compression_send.payload.items.len,
                        fragments.len,
                        pending.fragment_index,
                    );
                    break :blk self.compression_send.payload.items[range.start..range.end];
                } else fragments[pending.fragment_index];
                const count = @min(
                    scratch.len - len,
                    payload.len - payload_offset,
                );
                if (pending.mask_key) |mask| {
                    try websocket.applyMaskCopy(
                        scratch[len..][0..count],
                        payload[payload_offset..][0..count],
                        mask,
                        payload_offset,
                    );
                } else {
                    @memcpy(
                        scratch[len..][0..count],
                        payload[payload_offset..][0..count],
                    );
                }
                len += count;
                var body_progress: http3.runtime.BodyWriteProgress = .{};
                const send_result = switch (role) {
                    .client => self.h3.sendRequestBodyPacedWithDeadline(
                        self.stream_id,
                        scratch[0..len],
                        false,
                        &body_progress,
                        deadline,
                    ),
                    .server => self.h3.sendResponseBodyPacedWithDeadline(
                        self.stream_id,
                        scratch[0..len],
                        false,
                        &body_progress,
                        deadline,
                    ),
                };
                send_result catch |err| {
                    pending.committed += body_progress.committed_bytes;
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.wire_total,
                    };
                    return err;
                };
                pending.committed += body_progress.committed_bytes;
                if (pending.committed - pending.fragment_start ==
                    pending.header_len + pending.payload_len)
                {
                    const next_index = pending.fragment_index + 1;
                    if (next_index == fragments.len) {
                        progress.* = .{
                            .committed_bytes = pending.committed,
                            .total_bytes = pending.wire_total,
                            .frame_committed = true,
                        };
                        if (pending.compressed) {
                            self.commitCompressionPreviewLocked();
                        }
                        self.pending_write = .none;
                        self.application_write_pending.store(false, .release);
                        return;
                    }
                    try self.preparePendingFragmentLocked(
                        fragments,
                        next_index,
                    );
                }
            }
        }

        fn sendMessageWithDeadlineLocked(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);

            if (self.pending_write.messagePtr()) |pending| {
                if (!pending.matches(opcode, payload)) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return error.WriteInProgress;
                }
            } else {
                if (!self.pending_write.isNone()) return error.WriteInProgress;
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingMessageLocked(opcode, payload);
            }
            try self.resumePendingMessageLocked(payload, progress, deadline);
        }

        fn beginPendingMessageLocked(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
        ) Error!void {
            std.debug.assert(self.pending_write.isNone());
            var pending = PendingMessage{
                .opcode = opcode,
                .original_ptr = @intFromPtr(payload.ptr),
                .original_len = payload.len,
            };
            var encoded_payload = payload;
            errdefer self.discardCompressionPreviewLocked();
            if (self.permessage_deflate and
                payload.len >= self.compression_threshold)
            {
                const compressed = try self.compressMessage(payload);
                if (compressed.len < payload.len) {
                    encoded_payload = compressed;
                    pending.compressed = true;
                } else {
                    self.discardCompressionPreviewLocked();
                }
            }
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                pending.mask_key = key;
            }
            const header = try websocket.writeFrameHeaderForLengthInto(
                &pending.header,
                opcode,
                encoded_payload.len,
                .{
                    .mask_key = pending.mask_key,
                    .rsv1 = pending.compressed,
                },
            );
            pending.header_len = header.len;
            pending.payload_len = encoded_payload.len;
            self.pending_write = .{ .message = pending };
            self.application_write_pending.store(true, .release);
        }

        fn beginPendingPongLocked(
            self: *Self,
            payload: []const u8,
        ) Error!void {
            std.debug.assert(self.pending_write.isNone());
            var pending = PendingMessage{
                .opcode = .pong,
                .original_ptr = @intFromPtr(payload.ptr),
                .original_len = payload.len,
                .payload_len = payload.len,
            };
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                pending.mask_key = key;
            }
            const header = try websocket.writeFrameHeaderForLengthInto(
                &pending.header,
                .pong,
                payload.len,
                .{ .mask_key = pending.mask_key },
            );
            pending.header_len = header.len;
            self.pending_write = .{ .message = pending };
            self.application_write_pending.store(true, .release);
        }

        fn beginPendingMessagePartsLocked(
            self: *Self,
            parts: []const []const u8,
            payload_len: usize,
        ) Error!void {
            std.debug.assert(self.pending_write.isNone());
            var pending = PendingMessage{
                .opcode = .binary,
                .source = .slices,
                .original_ptr = @intFromPtr(parts.ptr),
                .original_len = parts.len,
            };
            var encoded_len = payload_len;
            errdefer self.discardCompressionPreviewLocked();
            if (self.permessage_deflate and
                payload_len >= self.compression_threshold)
            {
                const compressed = try self.compressMessageParts(
                    parts,
                    payload_len,
                );
                if (compressed.len < payload_len) {
                    encoded_len = compressed.len;
                    pending.compressed = true;
                } else {
                    self.discardCompressionPreviewLocked();
                }
            }
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                pending.mask_key = key;
            }
            const header = try websocket.writeFrameHeaderForLengthInto(
                &pending.header,
                .binary,
                encoded_len,
                .{
                    .mask_key = pending.mask_key,
                    .rsv1 = pending.compressed,
                },
            );
            pending.header_len = header.len;
            pending.payload_len = encoded_len;
            self.pending_write = .{ .message = pending };
            self.application_write_pending.store(true, .release);
        }

        fn resumePendingMessageLocked(
            self: *Self,
            original_payload: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            const pending = self.pending_write.messagePtr().?;
            const encoded_payload = if (pending.compressed)
                self.compression_send.payload.items[0..pending.payload_len]
            else
                original_payload;
            var masked: [16 * 1024]u8 align(64) = undefined;

            while (pending.committed < pending.totalLen()) {
                const header_offset = @min(
                    pending.committed,
                    pending.header_len,
                );
                const payload_offset = pending.committed - header_offset;
                const header = pending.header[header_offset..pending.header_len];
                const remaining_payload = encoded_payload[payload_offset..];
                var parts: [2][]const u8 = undefined;
                var part_count: usize = 0;
                if (header.len != 0) {
                    parts[part_count] = header;
                    part_count += 1;
                }
                if (remaining_payload.len != 0) {
                    if (pending.mask_key) |mask| {
                        const count = @min(masked.len, remaining_payload.len);
                        try websocket.applyMaskCopy(
                            masked[0..count],
                            remaining_payload[0..count],
                            mask,
                            payload_offset,
                        );
                        parts[part_count] = masked[0..count];
                    } else {
                        parts[part_count] = remaining_payload;
                    }
                    part_count += 1;
                }

                var body_progress: http3.runtime.BodyWriteProgress = .{};
                const send_result = switch (role) {
                    .client => self.h3.sendRequestBodyPartsPacedWithDeadline(
                        self.stream_id,
                        parts[0..part_count],
                        false,
                        &body_progress,
                        deadline,
                    ),
                    .server => self.h3.sendResponseBodyPartsPacedWithDeadline(
                        self.stream_id,
                        parts[0..part_count],
                        false,
                        &body_progress,
                        deadline,
                    ),
                };
                send_result catch |err| {
                    pending.committed += body_progress.committed_bytes;
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return err;
                };
                pending.committed += body_progress.committed_bytes;
            }

            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.totalLen(),
                .frame_committed = true,
            };
            if (pending.compressed) self.commitCompressionPreviewLocked();
            self.pending_write = .none;
            self.application_write_pending.store(false, .release);
        }

        fn resumePendingMessagePartsLocked(
            self: *Self,
            parts: []const []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            const pending = self.pending_write.messagePtr().?;
            var scratch: [16 * 1024 + websocket.max_frame_header_len]u8 align(64) = undefined;

            while (pending.committed < pending.totalLen()) {
                const header_offset = @min(
                    pending.committed,
                    pending.header_len,
                );
                const payload_offset = pending.committed - header_offset;
                var wire_len: usize = 0;
                if (header_offset < pending.header_len) {
                    const header = pending.header[header_offset..pending.header_len];
                    @memcpy(scratch[0..header.len], header);
                    wire_len = header.len;
                }
                const payload_capacity = @min(
                    scratch.len - wire_len,
                    pending.payload_len - payload_offset,
                );
                if (payload_capacity != 0) {
                    const destination = scratch[wire_len..][0..payload_capacity];
                    if (pending.compressed) {
                        const source = self.compression_send.payload.items[payload_offset..][0..payload_capacity];
                        if (pending.mask_key) |mask| {
                            try websocket.applyMaskCopy(
                                destination,
                                source,
                                mask,
                                payload_offset,
                            );
                        } else {
                            @memcpy(destination, source);
                        }
                    } else {
                        try copyMessagePartsAt(
                            destination,
                            parts,
                            payload_offset,
                            pending.mask_key,
                        );
                    }
                    wire_len += payload_capacity;
                }

                var body_progress: http3.runtime.BodyWriteProgress = .{};
                const send_result = switch (role) {
                    .client => self.h3.sendRequestBodyPacedWithDeadline(
                        self.stream_id,
                        scratch[0..wire_len],
                        false,
                        &body_progress,
                        deadline,
                    ),
                    .server => self.h3.sendResponseBodyPacedWithDeadline(
                        self.stream_id,
                        scratch[0..wire_len],
                        false,
                        &body_progress,
                        deadline,
                    ),
                };
                send_result catch |err| {
                    pending.committed += body_progress.committed_bytes;
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return err;
                };
                pending.committed += body_progress.committed_bytes;
            }

            progress.* = .{
                .committed_bytes = pending.committed,
                .total_bytes = pending.totalLen(),
                .frame_committed = true,
            };
            if (pending.compressed) self.commitCompressionPreviewLocked();
            self.pending_write = .none;
            self.application_write_pending.store(false, .release);
        }

        pub fn sendPing(self: *Self, payload: []const u8) Error!void {
            try self.sendControlFrame(.ping, payload);
        }

        pub fn sendPingWithTimeout(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendPingWithDeadline(
                payload,
                progress,
                .fromNow(self.io(), .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendPingWithDeadline(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try common.validateOutgoingControlFrame(
                self.limits,
                .ping,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.pending_write.isMessage() or self.pending_write.isClose()) {
                return error.WriteInProgress;
            }
            if (!self.pending_write.isPing()) {
                if (!self.pending_write.isNone() or
                    self.pending_auto_control != null)
                {
                    return error.WriteInProgress;
                }
                if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingPingLocked(payload);
            }
            const total = self.pending_write.pingPtr().?.len;
            self.resumePendingPingLocked(payload, deadline) catch |err| {
                const pending = self.pending_write.pingPtr().?.*;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.len,
                };
                return err;
            };
            progress.* = .{
                .committed_bytes = total,
                .total_bytes = total,
                .frame_committed = true,
            };
        }

        pub fn sendPong(self: *Self, payload: []const u8) Error!void {
            try self.sendControlFrame(.pong, payload);
        }

        pub fn sendPongWithTimeout(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendPongWithDeadline(
                payload,
                progress,
                .fromNow(self.io(), .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendPongWithDeadline(
            self: *Self,
            payload: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try common.validateOutgoingControlFrame(
                self.limits,
                .pong,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.pending_write.isPing() or self.pending_write.isClose()) {
                return error.WriteInProgress;
            }
            if (self.pending_write.messagePtr()) |pending| {
                if (!pending.matches(.pong, payload)) {
                    progress.* = .{
                        .committed_bytes = pending.committed,
                        .total_bytes = pending.totalLen(),
                    };
                    return error.WriteInProgress;
                }
            } else {
                if (self.pending_auto_control != null) {
                    return error.WriteInProgress;
                }
                if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingPongLocked(payload);
            }
            try self.resumePendingMessageLocked(payload, progress, deadline);
        }

        /// Send Ping once and wait for the matching Pong under one relative
        /// budget. Application frames already in flight are returned with
        /// ownership and may be followed with `continuePingWithTimeout`.
        pub fn pingWithTimeout(
            self: *Self,
            payload: []const u8,
            timeout: std.Io.Duration,
        ) Error!PingEvent {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.pingWithDeadline(payload, .fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        /// Send Ping once and advance under the caller's absolute deadline.
        /// Reuse that deadline with `continuePingWithDeadline` when retaining
        /// one total budget across interleaved application frames. The send
        /// lock is released before receive progress so automatic Pong/Close
        /// replies cannot recursively deadlock the connection.
        pub fn pingWithDeadline(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!PingEvent {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try common.validateOutgoingControlFrame(
                self.limits,
                .ping,
                payload,
            );
            if (self.automatic_write_pending.load(.acquire) and
                !self.application_write_pending.load(.acquire))
            {
                _ = try self.pendingAutomaticControlOpcode(.ping_wait);
                return self.readPingEvent(payload, deadline);
            }
            {
                self.send_mutex.lockUncancelable(self.io());
                defer self.send_mutex.unlock(self.io());
                _ = try deadline_policy.usableAwake(self.io(), deadline);
                if (self.pending_write.isMessage() or
                    self.pending_write.isClose())
                {
                    return error.WriteInProgress;
                }
                if (!self.pending_write.isPing()) {
                    if (!self.pending_write.isNone() or
                        self.pending_auto_control != null)
                    {
                        return error.WriteInProgress;
                    }
                    if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                        return error.ConnectionClosed;
                    }
                    try self.beginPendingPingLocked(payload);
                }
                try self.resumePendingPingLocked(payload, deadline);
            }
            return self.readPingEvent(payload, deadline);
        }

        /// Resume an outstanding Ping under a fresh relative budget without
        /// transmitting a second Ping frame.
        pub fn continuePingWithTimeout(
            self: *Self,
            payload: []const u8,
            timeout: std.Io.Duration,
        ) Error!PingEvent {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.continuePingWithDeadline(payload, .fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        /// Resume an outstanding Ping under the original absolute deadline.
        pub fn continuePingWithDeadline(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!PingEvent {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.automatic_write_pending.load(.acquire) and
                !self.application_write_pending.load(.acquire))
            {
                _ = try self.pendingAutomaticControlOpcode(.ping_wait);
                return self.readPingEvent(payload, deadline);
            }
            {
                self.send_mutex.lockUncancelable(self.io());
                defer self.send_mutex.unlock(self.io());
                if (self.pending_write.isMessage() or
                    self.pending_write.isClose())
                {
                    return error.WriteInProgress;
                }
                try self.resumePendingPingLocked(payload, deadline);
            }
            return self.readPingEvent(payload, deadline);
        }

        pub fn sendClose(
            self: *Self,
            code: websocket.CloseCode,
            reason: []const u8,
        ) Error!void {
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            var storage: [125]u8 = undefined;
            const payload = try websocket.writeClosePayloadInto(
                &storage,
                .{ .code = code, .reason = reason },
            );
            try common.validateOutgoingControlFrame(
                self.limits,
                .close,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            try self.sendControlFrameLocked(.close, payload);
        }

        pub fn sendCloseWithTimeout(
            self: *Self,
            code: websocket.CloseCode,
            reason: []const u8,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            return self.sendCloseFrameWithTimeout(
                .{ .code = code, .reason = reason },
                progress,
                timeout,
            );
        }

        pub fn sendCloseWithDeadline(
            self: *Self,
            code: websocket.CloseCode,
            reason: []const u8,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            return self.sendCloseFrameWithDeadline(
                .{ .code = code, .reason = reason },
                progress,
                deadline,
            );
        }

        pub fn sendCloseFrameWithTimeout(
            self: *Self,
            close_frame: ?websocket.CloseFrame,
            progress: *MessageWriteProgress,
            timeout: std.Io.Duration,
        ) Error!void {
            progress.* = .{};
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendCloseFrameWithDeadline(
                close_frame,
                progress,
                .fromNow(self.io(), .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendCloseFrameWithDeadline(
            self: *Self,
            close_frame: ?websocket.CloseFrame,
            progress: *MessageWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            progress.* = .{};
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            var storage: [125]u8 = undefined;
            const payload = try websocket.writeClosePayloadInto(
                &storage,
                close_frame,
            );
            try common.validateOutgoingControlFrame(
                self.limits,
                .close,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_write.isMessage() or self.pending_write.isPing()) {
                return error.WriteInProgress;
            }
            if (self.pending_write.closePtr()) |pending| {
                if (!pending.matches(payload)) return error.WriteInProgress;
            } else {
                if (!self.pending_write.isNone() or
                    self.pending_auto_control != null)
                {
                    return error.WriteInProgress;
                }
                if (self.closeSent()) return error.ConnectionClosed;
                try self.beginPendingCloseLocked(payload);
            }
            const total = self.pending_write.closePtr().?.len;
            self.resumePendingCloseLocked(deadline) catch |err| {
                const pending = self.pending_write.closePtr() orelse {
                    progress.* = .{
                        .committed_bytes = total,
                        .total_bytes = total,
                        .frame_committed = true,
                    };
                    return err;
                };
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.len,
                };
                return err;
            };
            progress.* = .{
                .committed_bytes = total,
                .total_bytes = total,
                .frame_committed = true,
            };
        }

        /// Send a Close frame with optional status metadata. Passing null emits
        /// the RFC 6455 empty Close payload rather than the reserved 1005 code.
        pub fn sendCloseFrame(
            self: *Self,
            close_frame: ?websocket.CloseFrame,
        ) Error!void {
            var storage: [125]u8 = undefined;
            const payload = try websocket.writeClosePayloadInto(
                &storage,
                close_frame,
            );
            try common.validateOutgoingControlFrame(
                self.limits,
                .close,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            try self.sendControlFrameLocked(.close, payload);
        }

        /// Receive and own metadata from the next frame when it is Close.
        /// Like the HTTP/1 and RFC 8441 strict helpers, an intervening data or
        /// control frame is consumed and reported as `InvalidFrame`, not
        /// silently skipped while searching for a later Close.
        pub fn receiveCloseFrame(
            self: *Self,
        ) Error!?websocket.OwnedCloseFrame {
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            var frame = try self.receiveFrame();
            errdefer frame.deinit(self.allocator);
            if (frame.header.opcode != .close) return error.InvalidFrame;
            return frame.takeClose(self.allocator);
        }

        /// Relative-budget counterpart to `receiveCloseFrameWithDeadline`.
        /// Partial HTTP/3 DATA and WebSocket frame bytes remain resumable.
        pub fn receiveCloseFrameWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!?websocket.OwnedCloseFrame {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveCloseFrameWithDeadline(.fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        /// Receive and parse one peer Close under a caller-owned deadline.
        /// Deadline validation occurs before any receive state is changed.
        pub fn receiveCloseFrameWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!?websocket.OwnedCloseFrame {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            var frame = try self.receiveFrameWithDeadline(deadline);
            errdefer frame.deinit(self.allocator);
            if (frame.header.opcode != .close) return error.InvalidFrame;
            return frame.takeClose(self.allocator);
        }

        /// Send Close once and wait for peer-close progress under one relative
        /// budget. In-flight application frames are surfaced, not discarded.
        pub fn closeWithTimeout(
            self: *Self,
            close_frame: ?websocket.CloseFrame,
            timeout: std.Io.Duration,
        ) Error!CloseHandshakeEvent {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.closeWithDeadline(close_frame, .fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        /// Send Close once and advance the handshake under an absolute
        /// deadline. Re-entering after `.application` does not resend Close.
        pub fn closeWithDeadline(
            self: *Self,
            close_frame: ?websocket.CloseFrame,
            deadline: std.Io.Clock.Timestamp,
        ) Error!CloseHandshakeEvent {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.automatic_write_pending.load(.acquire) and
                !self.application_write_pending.load(.acquire))
            {
                _ = try self.pendingAutomaticControlOpcode(.close_wait);
                return self.readCloseHandshakeEvent(deadline);
            }
            if (!self.closeSent() or self.pending_write.isClose()) {
                var storage: [125]u8 = undefined;
                const payload = try websocket.writeClosePayloadInto(
                    &storage,
                    close_frame,
                );
                try common.validateOutgoingControlFrame(
                    self.limits,
                    .close,
                    payload,
                );
                {
                    self.send_mutex.lockUncancelable(self.io());
                    defer self.send_mutex.unlock(self.io());
                    _ = try deadline_policy.usableAwake(self.io(), deadline);
                    if (self.receiveFailed() or self.writeAborted()) {
                        return error.ConnectionClosed;
                    }
                    if (self.pending_write.isMessage() or
                        self.pending_write.isPing())
                    {
                        return error.WriteInProgress;
                    }
                    if (self.pending_write.closePtr()) |pending| {
                        if (!pending.matches(payload)) {
                            return error.WriteInProgress;
                        }
                    } else if (!self.closeSent()) {
                        if (!self.pending_write.isNone() or
                            self.pending_auto_control != null)
                        {
                            return error.WriteInProgress;
                        }
                        try self.beginPendingCloseLocked(payload);
                    }
                    try self.resumePendingCloseLocked(deadline);
                }
            }
            return self.readCloseHandshakeEvent(deadline);
        }

        /// Resume a started Close handshake under a fresh relative budget.
        pub fn continueCloseWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!CloseHandshakeEvent {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.continueCloseWithDeadline(.fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        /// Resume a started Close handshake under the original deadline.
        pub fn continueCloseWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!CloseHandshakeEvent {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.automatic_write_pending.load(.acquire) and
                !self.application_write_pending.load(.acquire))
            {
                _ = try self.pendingAutomaticControlOpcode(.close_wait);
                return self.readCloseHandshakeEvent(deadline);
            }
            {
                self.send_mutex.lockUncancelable(self.io());
                defer self.send_mutex.unlock(self.io());
                if (self.receiveFailed() or self.writeAborted()) {
                    return error.ConnectionClosed;
                }
                if (self.pending_write.isMessage() or
                    self.pending_write.isPing())
                {
                    return error.WriteInProgress;
                }
                if (!self.closeSent() and !self.pending_write.isClose()) {
                    return error.InvalidFrame;
                }
                try self.resumePendingCloseLocked(deadline);
            }
            return self.readCloseHandshakeEvent(deadline);
        }

        /// Receive one complete message, automatically replying to Ping and
        /// Close control frames. Fragmented messages are assembled with the
        /// configured aggregate bound and negotiated compression is decoded.
        pub fn receiveMessage(self: *Self) Error!common.OwnedMessage {
            return self.receiveMessageInternal(null);
        }

        pub fn receiveMessageWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!common.OwnedMessage {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveMessageInternal(.fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        pub fn receiveMessageWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!common.OwnedMessage {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            return self.receiveMessageInternal(deadline);
        }

        const AllocatingMessageReceiver = @import("message/receive.zig").Controller(struct {
            pub const ConnectionType = Self;
            pub const ErrorType = Error;
            pub const receiveFailed = Self.receiveFailed;
            pub const checkWrites = Self.ensureNoPendingWrites;
            pub const pendingControl = Self.pendingAutomaticControlOpcode;
            pub const resumeControl = Self.resumeAutomaticControl;
            pub const beginControl = Self.beginAutomaticControl;
            pub const discard = Self.discardBuffered;
            pub const readFrame = Self.receiveMessageFrameBorrowed;
            pub const afterError = Self.closeAfterReceiveError;
            pub const onClose = Self.flushTerminalReceiveAck;
        });

        fn receiveMessageInternal(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!common.OwnedMessage {
            return AllocatingMessageReceiver.receive(self, deadline);
        }

        fn receiveMessageFrameBorrowed(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!websocket.BorrowedFrame {
            if (self.closeSent() and self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try self.ensureBuffered(2, deadline);
            var available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const second = available[1];
            var header_len: usize = 2;
            const length_code = second & 0x7f;
            if (length_code == 126) {
                header_len += 2;
            } else if (length_code == 127) {
                header_len += 8;
            }
            if ((second & 0x80) != 0) header_len += 4;
            try self.ensureBuffered(header_len, deadline);
            available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const header = try websocket.FrameHeader.parse(available);
            const payload_len = std.math.cast(
                usize,
                header.payload_len,
            ) orelse return error.PayloadTooLarge;
            if (payload_len > self.limits.max_frame_bytes) {
                return error.MessageTooLarge;
            }
            const total_len = try header.wireLen();
            try self.ensureIncomingFrameBuffered(header, total_len, deadline);
            available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const options: websocket.ParseFrameOptions = switch (role) {
                .client => .{
                    .expect_mask = .unmasked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
                .server => .{
                    .expect_mask = .masked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
            };
            return websocket.parseFrameInPlaceWithHeader(
                available[0..total_len],
                header,
                options,
            );
        }

        fn resetMessageIntoAfterError(self: *Self, err: anyerror) void {
            // Timeout is resumable because `inbuf`, the completed-fragment
            // offset, and compressed bytes are connection-owned. Decoder OOM
            // after a complete compressed message also retains owned input,
            // having already released the caller's output reference. Other
            // failures terminate this caller-buffer operation.
            if (err != error.Timeout and !self.message_into.canRetryCompletion(err)) {
                self.message_into.reset();
                self.message_frame_receive.reset();
            }
        }

        /// Receive one complete RFC 9220 message into caller-owned storage.
        /// The output must cover `limits.max_message_bytes`, allowing timeout
        /// recovery to retain only offsets and compressed scratch rather than
        /// allocating an intermediate uncompressed message.
        /// A final compressed decode OOM may be retried with a new output.
        pub fn receiveMessageInto(
            self: *Self,
            out: []u8,
        ) Error!Message {
            return self.receiveMessageIntoInternal(out, null);
        }

        pub fn receiveMessageIntoWithTimeout(
            self: *Self,
            out: []u8,
            timeout: std.Io.Duration,
        ) Error!Message {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveMessageIntoInternal(out, .fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        /// Use the same caller-owned absolute deadline across every HTTP/3
        /// DATA chunk, WebSocket continuation, and interleaved control frame.
        pub fn receiveMessageIntoWithDeadline(
            self: *Self,
            out: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!Message {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            return self.receiveMessageIntoInternal(out, deadline);
        }

        fn receiveMessageIntoInternal(
            self: *Self,
            out: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!Message {
            if (self.receiveFailed()) return error.ConnectionClosed;
            if (self.message_assembler != null) return error.InvalidFrame;
            if (out.len < self.limits.max_message_bytes) {
                return error.BufferTooShort;
            }
            try self.message_into.validateOutput(out);
            errdefer |err| self.resetMessageIntoAfterError(err);
            errdefer |err| self.closeAfterReceiveError(err, deadline);
            if (try self.pendingAutomaticControlOpcode(.message)) |opcode| {
                std.debug.assert(
                    (try self.resumeAutomaticControl(deadline)) == null,
                );
                if (opcode == .close) return error.ConnectionClosed;
            }
            try self.ensureNoPendingWrites();
            if (self.message_into.complete) return @import("message/complete_into.zig").finish(self, out);

            var control_storage: [125]u8 = undefined;
            while (true) {
                const frame = try self.receiveMessageFrameIntoInternal(
                    out,
                    &control_storage,
                    deadline,
                );
                switch (frame.header.opcode) {
                    .ping => {
                        if (!self.closeSent()) {
                            try self.beginAutomaticControl(
                                .pong,
                                frame.payload,
                                .message,
                                null,
                            );
                            std.debug.assert(
                                (try self.resumeAutomaticControl(deadline)) == null,
                            );
                        }
                        continue;
                    },
                    .pong => continue,
                    .close => {
                        if (!self.closeSent()) {
                            try self.beginAutomaticControl(
                                .close,
                                frame.payload,
                                .message,
                                null,
                            );
                            std.debug.assert(
                                (try self.resumeAutomaticControl(deadline)) == null,
                            );
                        }
                        self.flushTerminalReceiveAck();
                        return error.ConnectionClosed;
                    },
                    .text, .binary => {
                        std.debug.assert(self.message_into.active());
                    },
                    .continuation => {
                        std.debug.assert(self.message_into.active());
                    },
                    else => return error.InvalidFrame,
                }

                if (!frame.header.fin) continue;

                self.message_into.markComplete();
                return @import("message/complete_into.zig").finish(self, out);
            }
        }

        fn receiveFrameIntoInternal(
            self: *Self,
            out: []u8,
            control_out: *[125]u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!websocket.BorrowedFrame {
            if (self.closeSent() and self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try self.ensureBuffered(2, deadline);
            var available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const second = available[1];
            var header_len: usize = 2;
            const length_code = second & 0x7f;
            if (length_code == 126) {
                header_len += 2;
            } else if (length_code == 127) {
                header_len += 8;
            }
            if ((second & 0x80) != 0) header_len += 4;
            try self.ensureBuffered(header_len, deadline);
            available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const header = try websocket.FrameHeader.parse(available);
            const payload_len = std.math.cast(
                usize,
                header.payload_len,
            ) orelse return error.PayloadTooLarge;
            if (payload_len > self.limits.max_frame_bytes) {
                return error.MessageTooLarge;
            }
            const payload_out = if (header.opcode.isControl())
                control_out[0..]
            else
                out;
            if (payload_len > payload_out.len) return error.PayloadTooLarge;
            const total_len = try header.wireLen();
            try self.ensureIncomingFrameBuffered(
                header,
                total_len,
                deadline,
            );
            available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const options: websocket.ParseFrameOptions = switch (role) {
                .client => .{
                    .expect_mask = .unmasked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
                .server => .{
                    .expect_mask = .masked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
            };
            const frame = try websocket.parseFrameIntoWithHeader(
                payload_out,
                available[0..total_len],
                header,
                options,
            );
            self.discardBuffered(frame.consumed);
            switch (frame.header.opcode) {
                .ping => {},
                .close => {
                    self.close_received.store(true, .release);
                },
                else => {},
            }
            return frame;
        }

        /// Decode application DATA directly into the caller's message buffer
        /// (or reusable compressed scratch). Only control frames retain the
        /// complete-frame staging path because their destination is stack
        /// storage that cannot survive a timeout.
        fn receiveMessageFrameIntoInternal(
            self: *Self,
            out: []u8,
            control_out: *[125]u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!websocket.BorrowedFrame {
            if (self.message_frame_receive.header == null) {
                if (self.closeSent() and self.closeReceived()) {
                    return error.ConnectionClosed;
                }
                try self.ensureBufferedExact(2, deadline);
                var available = message_buffer.unread(
                    &self.inbuf,
                    self.inbuf_consumed,
                );
                const second = available[1];
                var header_len: usize = 2;
                const length_code = second & 0x7f;
                if (length_code == 126) {
                    header_len += 2;
                } else if (length_code == 127) {
                    header_len += 8;
                }
                if ((second & 0x80) != 0) header_len += 4;
                try self.ensureBufferedExact(header_len, deadline);
                available = message_buffer.unread(
                    &self.inbuf,
                    self.inbuf_consumed,
                );
                const header = try websocket.FrameHeader.parse(available);
                const options: websocket.ParseFrameOptions = switch (role) {
                    .client => .{
                        .expect_mask = .unmasked,
                        .allow_rsv1 = self.permessage_deflate,
                        .validate_utf8 = false,
                    },
                    .server => .{
                        .expect_mask = .masked,
                        .allow_rsv1 = self.permessage_deflate,
                        .validate_utf8 = false,
                    },
                };
                try websocket.validateFrameHeader(header, options);
                const payload_len = std.math.cast(
                    usize,
                    header.payload_len,
                ) orelse return error.PayloadTooLarge;
                if (payload_len > self.limits.max_frame_bytes) {
                    return error.MessageTooLarge;
                }
                if (header.opcode.isControl()) {
                    return self.receiveFrameIntoInternal(
                        out,
                        control_out,
                        deadline,
                    );
                }

                const message_kind: IncomingDataKind = switch (header.opcode) {
                    .text => blk: {
                        if (self.message_into.active()) {
                            return error.InvalidFrame;
                        }
                        self.message_into.begin(
                            out,
                            .text,
                            header.rsv1,
                        );
                        if (header.rsv1) {
                            try self.ensureCompressionReceiveScratch();
                        } else {
                            self.message_into.text_utf8.reset();
                        }
                        break :blk if (header.rsv1)
                            .compressed_text
                        else
                            .text;
                    },
                    .binary => blk: {
                        if (self.message_into.active()) {
                            return error.InvalidFrame;
                        }
                        self.message_into.begin(
                            out,
                            .binary,
                            header.rsv1,
                        );
                        if (header.rsv1) {
                            try self.ensureCompressionReceiveScratch();
                        }
                        break :blk .binary;
                    },
                    .continuation => blk: {
                        if (!self.message_into.active()) {
                            return error.InvalidFrame;
                        }
                        break :blk self.incoming_data_kind;
                    },
                    else => return error.InvalidFrame,
                };
                const next_written = std.math.add(
                    usize,
                    self.message_into.written,
                    payload_len,
                ) catch return error.PayloadTooLarge;
                if (next_written > self.limits.max_message_bytes) {
                    return error.PayloadTooLarge;
                }
                self.discardBuffered(header.header_len);
                self.message_frame_receive = .{
                    .header = header,
                    .payload_start = self.message_into.written,
                    .payload_end = next_written,
                    .message_kind = message_kind,
                };
            }

            const state = &self.message_frame_receive;
            const header = state.header.?;
            const payload_len: usize = @intCast(header.payload_len);
            const destination = if (self.message_into.compressed)
                self.compression_receive.payload.items[state.payload_start..state.payload_end]
            else
                out[state.payload_start..state.payload_end];
            while (state.payload_written < payload_len) {
                const buffered = message_buffer.unread(
                    &self.inbuf,
                    self.inbuf_consumed,
                );
                const count = @min(
                    buffered.len,
                    payload_len - state.payload_written,
                );
                if (count != 0) {
                    try self.decodeMessagePayloadChunk(
                        destination[state.payload_written..][0..count],
                        buffered[0..count],
                        header,
                        state.payload_written,
                        state.message_kind,
                    );
                    self.discardBuffered(count);
                    state.payload_written += count;
                    continue;
                }
                if (self.receive_finished) return error.ConnectionClosed;
                const read = try self.readPayloadChunkInto(
                    destination[state.payload_written..],
                    deadline,
                );
                if (read == 0) continue;
                if (header.mask_key) |mask| {
                    const decoded =
                        destination[state.payload_written..][0..read];
                    if (state.message_kind == .text) {
                        try self.message_into.text_utf8.feedMaskedCopy(
                            decoded,
                            decoded,
                            mask,
                            state.payload_written,
                        );
                    } else {
                        websocket.applyMask(
                            decoded,
                            mask,
                            state.payload_written,
                        );
                    }
                } else if (state.message_kind == .text) {
                    try self.message_into.text_utf8.feed(
                        destination[state.payload_written..][0..read],
                    );
                }
                state.payload_written += read;
            }
            if (state.message_kind == .text and header.fin) {
                try self.message_into.text_utf8.finish();
            }
            self.message_into.written = state.payload_end;
            self.incoming_data_kind =
                if (header.fin) .none else state.message_kind;
            state.reset();
            return .{
                .header = header,
                .payload = destination,
                .consumed = header.header_len + payload_len,
            };
        }

        fn decodeMessagePayloadChunk(
            self: *Self,
            destination: []u8,
            encoded: []const u8,
            header: websocket.FrameHeader,
            payload_offset: usize,
            message_kind: IncomingDataKind,
        ) Error!void {
            if (header.mask_key) |mask| {
                if (message_kind == .text) {
                    return self.message_into.text_utf8.feedMaskedCopy(
                        destination,
                        encoded,
                        mask,
                        payload_offset,
                    );
                }
                try websocket.applyMaskCopy(
                    destination,
                    encoded,
                    mask,
                    payload_offset,
                );
            } else {
                @memcpy(destination, encoded);
            }
            if (message_kind == .text) {
                try self.message_into.text_utf8.feed(destination);
            }
        }

        fn ensureCompressionReceiveScratch(self: *Self) Error!void {
            if (self.compression_receive_context_takeover) {
                try self.compression_receive.prepareContext(
                    self.allocator,
                    self.limits.max_message_bytes,
                );
            } else {
                try self.compression_receive.prepare(
                    self.allocator,
                    self.limits.max_message_bytes,
                );
            }
        }

        pub fn receiveFrame(self: *Self) Error!websocket.Frame {
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            return self.receiveFrameInternal(null, .frame);
        }

        pub fn receiveFrameWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!websocket.Frame {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            return self.receiveFrameInternal(
                .fromNow(
                    self.io(),
                    .{ .raw = timeout, .clock = .awake },
                ),
                .frame,
            );
        }

        pub fn receiveFrameWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!websocket.Frame {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            return self.receiveFrameInternal(deadline, .frame);
        }

        fn readPingEvent(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!PingEvent {
            return PingReader.read(self, payload, deadline);
        }

        fn readCloseHandshakeEvent(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!CloseHandshakeEvent {
            while (true) {
                var frame = try self.receiveFrameInternal(
                    deadline,
                    .close_wait,
                );
                switch (frame.header.opcode) {
                    .ping, .pong => {
                        frame.deinit(self.allocator);
                        continue;
                    },
                    .close => {
                        errdefer frame.deinit(self.allocator);
                        const close = try frame.takeClose(self.allocator);
                        return .{ .closed = close };
                    },
                    .text, .binary, .continuation => {
                        return .{ .application = frame };
                    },
                    else => {
                        frame.deinit(self.allocator);
                        return error.InvalidFrame;
                    },
                }
            }
        }

        fn receiveFrameInternal(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
            delivery: PendingAutomaticControl.Delivery,
        ) Error!websocket.Frame {
            if (self.receiveFailed()) return error.ConnectionClosed;
            if (try self.pendingAutomaticControlOpcode(delivery)) |_| {
                if (try self.resumeAutomaticControl(deadline)) |frame| {
                    return frame;
                }
                return self.receiveFrameInternal(deadline, delivery);
            }
            try self.ensureNoPendingWrites();
            errdefer |err| self.closeAfterReceiveError(err, deadline);
            if (self.closeSent() and self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try self.ensureBuffered(2, deadline);
            var available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const second = available[1];
            var header_len: usize = 2;
            const length_code = second & 0x7f;
            if (length_code == 126) {
                header_len += 2;
            } else if (length_code == 127) {
                header_len += 8;
            }
            if ((second & 0x80) != 0) header_len += 4;
            try self.ensureBuffered(header_len, deadline);
            available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const header = try websocket.FrameHeader.parse(available);
            const payload_len = std.math.cast(
                usize,
                header.payload_len,
            ) orelse return error.PayloadTooLarge;
            if (payload_len > self.limits.max_frame_bytes) {
                return error.MessageTooLarge;
            }
            const total_len = std.math.add(
                usize,
                header.header_len,
                payload_len,
            ) catch return error.PayloadTooLarge;
            const validation = frame_validation.Checkpoint.capture(self);
            try self.ensureIncomingFrameBuffered(
                header,
                total_len,
                deadline,
            );
            available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const options: websocket.ParseFrameOptions = switch (role) {
                .client => .{
                    .expect_mask = .unmasked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
                .server => .{
                    .expect_mask = .masked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
            };
            var frame = try validation.parseOwned(
                self,
                available[0..total_len],
                header,
                options,
            );
            self.discardBuffered(frame.consumed);
            if (self.compression_receive_context_takeover and
                !frame.header.opcode.isControl())
            {
                self.compression_receive.observeFrame(
                    self.allocator,
                    frame.header.opcode != .continuation,
                    frame.header.rsv1,
                    frame.header.opcode == .text,
                    frame.header.fin,
                    frame.payload,
                    self.limits.max_message_bytes,
                    self.compression_receive_max_window_bits,
                ) catch |err| {
                    frame.deinit(self.allocator);
                    return switch (err) {
                        error.PreviewPending => error.InvalidFrame,
                        error.OutOfMemory => blk: {
                            _ = self.failReceive();
                            break :blk error.OutOfMemory;
                        },
                        else => |other| @errorCast(other),
                    };
                };
            }
            switch (frame.header.opcode) {
                .ping => {
                    if (self.closeSent()) return frame;
                    try self.beginAutomaticControl(.pong, frame.payload, delivery, frame);
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                .close => {
                    self.close_received.store(true, .release);
                    if (self.closeSent()) {
                        self.flushTerminalReceiveAck();
                        return frame;
                    }
                    try self.beginAutomaticControl(.close, frame.payload, delivery, frame);
                    const delivered = (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                    self.flushTerminalReceiveAck();
                    return delivered;
                },
                else => {},
            }
            return frame;
        }

        fn closeAfterReceiveError(
            self: *Self,
            err: anyerror,
            deadline: ?std.Io.Clock.Timestamp,
        ) void {
            if (common.closeCodeForReceiveError(err)) |code| {
                // Nested receive helpers can observe the same error. Emit at
                // most one failure Close while preserving the receive error.
                if (!self.failReceive()) return;
                self.finishReceiveFailure(code, deadline);
                return;
            }
            if (!isAbruptReceiveEnd(err) or
                self.close_received.load(.acquire))
            {
                return;
            }
            // QUIC FIN/reset without a WebSocket Close is an abnormal closure.
            // Do not invent a Close frame after the peer ended this direction.
            if (!self.failReceive()) return;
            self.finishAbruptReceiveEnd();
        }

        fn flushTerminalReceiveAck(self: *Self) void {
            // Returning a peer Close is often the application's final receive.
            // Keep it from stranding the peer's reliable-send recovery when no
            // later WebSocket read occurs.
            _ = self.h3.established.connection.tryFlushPendingAck() catch {};
        }

        fn abortStreamAfterReceiveFailureLocked(self: *Self) void {
            self.write_aborted.store(true, .release);
            self.h3.tryCancelRequest(
                self.stream_id,
                http3.ApplicationErrorCode.request_cancelled,
            ) catch {};
            common.clearPendingOutboundLocked(self);
        }

        fn abortAfterUnboundedMessageWriteLocked(self: *Self) void {
            self.discardCompressionPreviewLocked();
            self.abortStreamAfterReceiveFailureLocked();
        }

        fn finishReceiveFailure(
            self: *Self,
            code: websocket.CloseCode,
            deadline: ?std.Io.Clock.Timestamp,
        ) void {
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (!self.pending_write.isNone() or
                self.pending_auto_control != null)
            {
                self.abortStreamAfterReceiveFailureLocked();
                return;
            }
            if (self.closeSent()) return;
            var storage: [125]u8 = undefined;
            const payload = websocket.writeClosePayloadInto(
                &storage,
                .{ .code = code },
            ) catch return;
            if (deadline) |absolute| {
                self.beginPendingCloseLocked(payload) catch return;
                self.resumePendingCloseLocked(absolute) catch {
                    self.abortStreamAfterReceiveFailureLocked();
                };
                return;
            }
            self.writeFrame(.close, payload, true, true) catch {
                self.abortStreamAfterReceiveFailureLocked();
                return;
            };
            self.close_sent.store(true, .release);
        }

        fn finishAbruptReceiveEnd(self: *Self) void {
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            self.abortStreamAfterReceiveFailureLocked();
        }

        fn failReceive(self: *Self) bool {
            if (self.receive_failed.swap(true, .acq_rel)) return false;
            if (self.message_assembler) |*assembler| assembler.deinit();
            self.message_assembler = null;
            self.message_into.reset();
            self.message_frame_receive.reset();
            self.incoming_data_kind = .none;
            self.incoming_text_utf8.reset();
            self.incoming_frame_validated = 0;
            self.inbuf.clearAndFree(self.allocator);
            self.inbuf_consumed = 0;
            self.compression_receive.deinit(self.allocator);
            self.compression_receive = .{};
            return true;
        }

        fn sendDataFrameValidatedLocked(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
        ) Error!void {
            if (!self.pending_write.isNone() or
                self.pending_auto_control != null)
            {
                return error.WriteInProgress;
            }
            if (self.writeAborted() or self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            if (self.permessage_deflate and
                payload.len >= self.compression_threshold)
            {
                const compressed = try self.compressMessage(payload);
                if (compressed.len < payload.len) {
                    self.writeFrameExtended(
                        opcode,
                        compressed,
                        true,
                        false,
                        true,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    };
                    self.commitCompressionPreviewLocked();
                    return;
                }
                self.discardCompressionPreviewLocked();
            }
            self.writeFrame(opcode, payload, true, false) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }

        fn sendControlFrame(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
        ) Error!void {
            try common.validateOutgoingControlFrame(
                self.limits,
                opcode,
                payload,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            try self.sendControlFrameLocked(opcode, payload);
        }

        fn sendControlFrameLocked(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
        ) Error!void {
            if (self.writeAborted()) return error.ConnectionClosed;
            if (!self.pending_write.isNone()) return error.WriteInProgress;
            if (self.pending_auto_control != null) {
                return error.WriteInProgress;
            }
            if (self.receiveFailed() or self.closeSent()) {
                return error.ConnectionClosed;
            }
            self.writeFrame(
                opcode,
                payload,
                true,
                opcode == .close,
            ) catch |err| {
                // Unbounded HTTP/3 sends do not expose how much of a
                // multi-packet frame became visible. No opcode can safely be
                // retried from byte zero, so cancel this request stream.
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            if (opcode == .close) self.close_sent.store(true, .release);
        }

        fn beginAutomaticControl(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            delivery: PendingAutomaticControl.Delivery,
            frame: ?websocket.Frame,
        ) Error!void {
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            return automatic_control.begin(self, self.io(), role, opcode, payload, delivery, frame, false);
        }

        fn resumeAutomaticControl(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!?websocket.Frame {
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            const pending = if (self.pending_auto_control) |*value|
                value
            else
                return null;
            if (!self.pending_write.isNone()) {
                return error.WriteInProgress;
            }
            if (self.closeSent()) pending.writes_reply = false;
            try automatic_control.resumeEncoding(pending, self.io(), role);

            var progress: http3.runtime.BodyWriteProgress = .{};
            const bytes = pending.bytes[pending.committed..pending.len];
            const fin = pending.opcode == .close;
            if (!pending.complete() and deadline != null) {
                const absolute = deadline.?;
                _ = try deadline_policy.usableAwake(self.io(), absolute);
                switch (role) {
                    .client => self.h3.sendRequestBodyPacedWithDeadline(
                        self.stream_id,
                        bytes,
                        fin,
                        &progress,
                        absolute,
                    ) catch |err| {
                        pending.committed += progress.committed_bytes;
                        pending.fin_committed =
                            pending.fin_committed or progress.fin_committed;
                        return err;
                    },
                    .server => self.h3.sendResponseBodyPacedWithDeadline(
                        self.stream_id,
                        bytes,
                        fin,
                        &progress,
                        absolute,
                    ) catch |err| {
                        pending.committed += progress.committed_bytes;
                        pending.fin_committed =
                            pending.fin_committed or progress.fin_committed;
                        return err;
                    },
                }
            } else if (!pending.complete()) {
                switch (role) {
                    .client => self.h3.sendRequestBodyPaced(
                        self.stream_id,
                        bytes,
                        fin,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    },
                    .server => self.h3.sendResponseBodyPaced(
                        self.stream_id,
                        bytes,
                        fin,
                    ) catch |err| {
                        self.abortAfterUnboundedMessageWriteLocked();
                        return err;
                    },
                }
                progress.committed_bytes = bytes.len;
                progress.fin_committed = fin;
            }
            pending.committed += progress.committed_bytes;
            pending.fin_committed =
                pending.fin_committed or progress.fin_committed;
            std.debug.assert(pending.complete());
            if (pending.opcode == .close) {
                self.close_sent.store(true, .release);
            }
            const frame = pending.frame;
            pending.frame = null;
            std.crypto.secureZero(u8, &pending.bytes);
            self.pending_auto_control = null;
            self.automatic_write_pending.store(false, .release);
            return frame;
        }

        fn beginPendingPingLocked(
            self: *Self,
            payload: []const u8,
        ) Error!void {
            std.debug.assert(self.pending_write.isNone());
            var pending: PendingControlFrame = .{};
            @memcpy(pending.payload[0..payload.len], payload);
            pending.payload_len = payload.len;
            var mask_key: ?[4]u8 = null;
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                mask_key = key;
            }
            const encoded = try websocket.writeFrameInto(
                &pending.bytes,
                .ping,
                payload,
                .{ .mask_key = mask_key },
            );
            pending.len = encoded.len;
            self.pending_write = .{ .ping = pending };
            self.application_write_pending.store(true, .release);
        }

        fn resumePendingPingLocked(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            const pending = self.pending_write.pingPtr() orelse return;
            if (!pending.matches(payload)) return error.WriteInProgress;
            var progress: http3.runtime.BodyWriteProgress = .{};
            switch (role) {
                .client => self.h3.sendRequestBodyPacedWithDeadline(
                    self.stream_id,
                    pending.bytes[pending.committed..pending.len],
                    false,
                    &progress,
                    deadline,
                ) catch |err| {
                    pending.committed += progress.committed_bytes;
                    return err;
                },
                .server => self.h3.sendResponseBodyPacedWithDeadline(
                    self.stream_id,
                    pending.bytes[pending.committed..pending.len],
                    false,
                    &progress,
                    deadline,
                ) catch |err| {
                    pending.committed += progress.committed_bytes;
                    return err;
                },
            }
            pending.committed += progress.committed_bytes;
            std.debug.assert(pending.committed == pending.len);
            self.pending_write = .none;
            self.application_write_pending.store(false, .release);
        }

        fn beginPendingCloseLocked(
            self: *Self,
            payload: []const u8,
        ) Error!void {
            std.debug.assert(self.pending_write.isNone());
            var pending: PendingControlFrame = .{};
            @memcpy(pending.payload[0..payload.len], payload);
            pending.payload_len = payload.len;
            var mask_key: ?[4]u8 = null;
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                mask_key = key;
            }
            const encoded = try websocket.writeFrameInto(
                &pending.bytes,
                .close,
                payload,
                .{ .mask_key = mask_key },
            );
            pending.len = encoded.len;
            self.pending_write = .{ .close = pending };
            self.application_write_pending.store(true, .release);
        }

        fn resumePendingCloseLocked(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!void {
            if (self.writeAborted()) return error.ConnectionClosed;
            const pending = self.pending_write.closePtr() orelse return;
            var progress: http3.runtime.BodyWriteProgress = .{};
            switch (role) {
                .client => self.h3.sendRequestBodyPacedWithDeadline(
                    self.stream_id,
                    pending.bytes[pending.committed..pending.len],
                    true,
                    &progress,
                    deadline,
                ) catch |err| {
                    pending.committed += progress.committed_bytes;
                    if (progress.fin_committed) {
                        self.pending_write = .none;
                        self.application_write_pending.store(false, .release);
                        self.close_sent.store(true, .release);
                    }
                    return err;
                },
                .server => self.h3.sendResponseBodyPacedWithDeadline(
                    self.stream_id,
                    pending.bytes[pending.committed..pending.len],
                    true,
                    &progress,
                    deadline,
                ) catch |err| {
                    pending.committed += progress.committed_bytes;
                    if (progress.fin_committed) {
                        self.pending_write = .none;
                        self.application_write_pending.store(false, .release);
                        self.close_sent.store(true, .release);
                    }
                    return err;
                },
            }
            pending.committed += progress.committed_bytes;
            std.debug.assert(
                pending.committed == pending.len and progress.fin_committed,
            );
            self.pending_write = .none;
            self.application_write_pending.store(false, .release);
            self.close_sent.store(true, .release);
        }

        fn closeSent(self: *const Self) bool {
            return self.close_sent.load(.acquire);
        }

        fn closeFullySent(self: *const Self) bool {
            return self.closeSent() and !self.pending_write.isClose();
        }

        fn closeReceived(self: *const Self) bool {
            return self.receiveFailed() or self.close_received.load(.acquire);
        }

        fn receiveFailed(self: *const Self) bool {
            return self.receive_failed.load(.acquire);
        }

        fn writeAborted(self: *const Self) bool {
            return self.write_aborted.load(.acquire);
        }

        fn ensureNoPendingWrites(self: *Self) Error!void {
            if (self.application_write_pending.load(.acquire) or
                self.automatic_write_pending.load(.acquire))
            {
                return error.WriteInProgress;
            }
        }

        fn pendingAutomaticControlOpcode(
            self: *Self,
            delivery: PendingAutomaticControl.Delivery,
        ) Error!?websocket.Opcode {
            if (!self.automatic_write_pending.load(.acquire)) return null;
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            const pending = self.pending_auto_control orelse return null;
            if (pending.delivery != delivery) {
                return error.WriteInProgress;
            }
            return pending.opcode;
        }

        fn writeFrame(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            frame_fin: bool,
            fin_stream: bool,
        ) Error!void {
            return self.writeFrameExtended(
                opcode,
                payload,
                frame_fin,
                fin_stream,
                false,
            );
        }

        fn writeFrameExtended(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            frame_fin: bool,
            fin_stream: bool,
            rsv1: bool,
        ) Error!void {
            var mask_key: ?[4]u8 = null;
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                mask_key = key;
            }
            if (opcode.isControl()) {
                // Control frames are at most 125 bytes, so encode them into
                // one stable stack slice. Besides avoiding vectored overhead,
                // this keeps zero-length Close frames on the same DATA path as
                // non-empty controls instead of relying on empty-part handling.
                var encoded_storage: [websocket.max_frame_header_len + 125]u8 = undefined;
                const frame = try websocket.writeFrameInto(
                    &encoded_storage,
                    opcode,
                    payload,
                    .{
                        .fin = frame_fin,
                        .mask_key = mask_key,
                        .rsv1 = rsv1,
                    },
                );
                try self.writeBytes(frame, fin_stream);
                return;
            }
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                opcode,
                payload,
                .{ .fin = frame_fin, .mask_key = mask_key, .rsv1 = rsv1 },
            );
            if (mask_key) |mask| {
                try self.writeMaskedParts(header, &.{payload}, mask, fin_stream);
            } else {
                try self.writeParts(&.{ header, payload }, fin_stream);
            }
        }

        fn writeBinarySlices(
            self: *Self,
            parts: []const []const u8,
            payload_len: usize,
        ) Error!void {
            var mask_key: ?[4]u8 = null;
            if (role == .client) {
                var key: [4]u8 = undefined;
                try std.Io.randomSecure(self.io(), &key);
                mask_key = key;
            }
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                .binary,
                payload_len,
                .{ .mask_key = mask_key },
            );
            if (mask_key) |mask| {
                try self.writeMaskedParts(
                    header,
                    parts,
                    mask,
                    false,
                );
                return;
            }

            try self.writeUnmaskedParts(header, parts);
        }

        fn writeUnmaskedParts(
            self: *Self,
            header: []const u8,
            payload_parts: []const []const u8,
        ) Error!void {
            var parts: [max_batched_payload_slices + 1][]const u8 = undefined;
            var part_index: usize = 0;
            var header_pending = true;
            while (true) {
                var count: usize = 0;
                if (header_pending) {
                    parts[count] = header;
                    count += 1;
                    header_pending = false;
                }
                while (part_index < payload_parts.len and count < parts.len) {
                    const part = payload_parts[part_index];
                    part_index += 1;
                    if (part.len == 0) continue;
                    parts[count] = part;
                    count += 1;
                }
                if (count == 0) return;
                try self.writeParts(parts[0..count], false);
                if (part_index == payload_parts.len) return;
            }
        }

        fn writeMaskedParts(
            self: *Self,
            header: []const u8,
            payload_parts: []const []const u8,
            mask_key: [4]u8,
            fin_stream: bool,
        ) Error!void {
            var scratch: [16 * 1024]u8 = undefined;
            var part_index: usize = 0;
            var part_offset: usize = 0;
            var mask_offset: usize = 0;
            var header_pending = true;
            while (part_index < payload_parts.len) {
                var count: usize = 0;
                while (part_index < payload_parts.len and count < scratch.len) {
                    const part = payload_parts[part_index];
                    if (part_offset == part.len) {
                        part_index += 1;
                        part_offset = 0;
                        continue;
                    }
                    const chunk_len = @min(
                        scratch.len - count,
                        part.len - part_offset,
                    );
                    try websocket.applyMaskCopy(
                        scratch[count..][0..chunk_len],
                        part[part_offset..][0..chunk_len],
                        mask_key,
                        mask_offset,
                    );
                    count += chunk_len;
                    part_offset += chunk_len;
                    mask_offset += chunk_len;
                }
                if (count == 0) break;
                if (header_pending) {
                    try self.writeParts(
                        &.{ header, scratch[0..count] },
                        fin_stream and part_index == payload_parts.len,
                    );
                    header_pending = false;
                } else {
                    try self.writeBytes(
                        scratch[0..count],
                        fin_stream and part_index == payload_parts.len,
                    );
                }
            }
            if (header_pending) try self.writeBytes(header, fin_stream);
        }

        fn compressMessage(self: *Self, payload: []const u8) Error![]const u8 {
            if (self.compression_send_context_takeover) {
                return self.compression_send.preview(
                    self.allocator,
                    payload,
                    self.compression_send_max_window_bits,
                ) catch |err| switch (err) {
                    error.PreviewPending => error.WriteInProgress,
                    else => |other| @errorCast(other),
                };
            }
            try self.compression_send.prepare(self.allocator, payload.len);
            return websocket.compressMessageVortIntoWindowWithEncoder(
                &self.compression_send.encoder.?,
                &self.compression_send.payload,
                payload,
                self.compression_send_max_window_bits,
            );
        }

        fn compressMessageParts(
            self: *Self,
            parts: []const []const u8,
            payload_len: usize,
        ) Error![]const u8 {
            if (self.compression_send_context_takeover) {
                return self.compression_send.previewFragments(
                    self.allocator,
                    parts,
                    payload_len,
                    self.compression_send_max_window_bits,
                ) catch |err| switch (err) {
                    error.PreviewPending => error.WriteInProgress,
                    else => |other| @errorCast(other),
                };
            }
            try self.compression_send.prepare(self.allocator, payload_len);
            return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
                &self.compression_send.encoder.?,
                &self.compression_send.payload,
                parts,
                self.compression_send_max_window_bits,
            );
        }

        fn commitCompressionPreviewLocked(self: *Self) void {
            if (self.compression_send_context_takeover) {
                self.compression_send.commitPreview() catch unreachable;
            }
        }

        fn discardCompressionPreviewLocked(self: *Self) void {
            if (self.compression_send_context_takeover) {
                self.compression_send.discardPreview();
            }
        }

        fn writeCompressedFragments(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            frame_count: usize,
        ) Error!void {
            if (try self.writeCompressedFragmentBatch(
                opcode,
                payload,
                frame_count,
            )) return;
            for (0..frame_count) |index| {
                const range = compressedFragmentRange(
                    payload.len,
                    frame_count,
                    index,
                );
                try self.writeFrameExtended(
                    if (index == 0) opcode else .continuation,
                    payload[range.start..range.end],
                    index + 1 == frame_count,
                    false,
                    index == 0,
                );
            }
        }

        fn writeUncompressedFragments(
            self: *Self,
            opcode: websocket.Opcode,
            fragments: []const []const u8,
        ) Error!void {
            if (try self.writeFragmentBatch(
                opcode,
                fragments,
                false,
            )) return;
            for (fragments, 0..) |fragment, index| {
                try self.writeFrame(
                    if (index == 0) opcode else .continuation,
                    fragment,
                    index + 1 == fragments.len,
                    false,
                );
            }
        }

        fn writeFragmentBatch(
            self: *Self,
            opcode: websocket.Opcode,
            fragments: []const []const u8,
            compressed: bool,
        ) Error!bool {
            if (fragments.len > max_batched_fragments) return false;
            var wire_len: usize = 0;
            for (fragments) |fragment| {
                wire_len = std.math.add(
                    usize,
                    wire_len,
                    websocket.max_frame_header_len,
                ) catch return false;
                wire_len = std.math.add(
                    usize,
                    wire_len,
                    fragment.len,
                ) catch return false;
            }
            if (wire_len > fragmented_write_scratch_len) return false;

            var encoded: [fragmented_write_scratch_len]u8 align(64) =
                undefined;
            var mask_keys: [max_batched_fragments][4]u8 = undefined;
            if (role == .client) {
                try common.randomMaskKeys(
                    self.io(),
                    mask_keys[0..fragments.len],
                );
            }
            var offset: usize = 0;
            for (fragments, 0..) |fragment, index| {
                var mask_key: ?[4]u8 = null;
                if (role == .client) {
                    mask_key = mask_keys[index];
                }
                const frame = try websocket.writeFrameInto(
                    encoded[offset..],
                    if (index == 0) opcode else .continuation,
                    fragment,
                    .{
                        .fin = index + 1 == fragments.len,
                        .mask_key = mask_key,
                        .rsv1 = compressed and index == 0,
                    },
                );
                offset += frame.len;
            }
            try self.writeBytes(encoded[0..offset], false);
            return true;
        }

        fn writeCompressedFragmentBatch(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            frame_count: usize,
        ) Error!bool {
            if (frame_count > max_batched_fragments) return false;
            var fragments: [max_batched_fragments][]const u8 = undefined;
            for (fragments[0..frame_count], 0..) |*fragment, index| {
                const range = compressedFragmentRange(
                    payload.len,
                    frame_count,
                    index,
                );
                fragment.* = payload[range.start..range.end];
            }
            return self.writeFragmentBatch(
                opcode,
                fragments[0..frame_count],
                true,
            );
        }

        fn writeBytes(
            self: *Self,
            bytes: []const u8,
            fin: bool,
        ) Error!void {
            switch (role) {
                .client => try self.h3.sendRequestBodyPaced(
                    self.stream_id,
                    bytes,
                    fin,
                ),
                .server => try self.h3.sendResponseBodyPaced(
                    self.stream_id,
                    bytes,
                    fin,
                ),
            }
        }

        fn writeParts(
            self: *Self,
            parts: []const []const u8,
            fin: bool,
        ) Error!void {
            switch (role) {
                .client => try self.h3.sendRequestBodyPartsPaced(
                    self.stream_id,
                    parts,
                    fin,
                ),
                .server => try self.h3.sendResponseBodyPartsPaced(
                    self.stream_id,
                    parts,
                    fin,
                ),
            }
        }

        fn ensureBuffered(
            self: *Self,
            required: usize,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!void {
            while (message_buffer.unreadLen(
                &self.inbuf,
                self.inbuf_consumed,
            ) < required) {
                if (self.receive_finished) return error.ConnectionClosed;
                const count = try self.appendPayloadChunk(deadline);
                if (count == 0) continue;
            }
        }

        /// Buffer only the missing WebSocket header bytes. Caller-buffer data
        /// frames send their payload directly to the final destination, so
        /// reading ahead here would stage most of the first H3 DATA chunk in
        /// `inbuf` only to copy it out immediately afterward.
        fn ensureBufferedExact(
            self: *Self,
            required: usize,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!void {
            while (true) {
                const buffered = message_buffer.unreadLen(
                    &self.inbuf,
                    self.inbuf_consumed,
                );
                if (buffered >= required) return;
                if (self.receive_finished) return error.ConnectionClosed;
                const destination = try message_buffer.reserveAppendAfterConsumed(
                    &self.inbuf,
                    &self.inbuf_consumed,
                    self.allocator,
                    required - buffered,
                );
                const count = self.readPayloadChunkInto(
                    destination,
                    deadline,
                ) catch |err| {
                    message_buffer.commitAppend(&self.inbuf, 0);
                    return err;
                };
                message_buffer.commitAppend(&self.inbuf, count);
                if (count == 0) continue;
            }
        }

        /// Read the current frame body while validating uncompressed text as
        /// HTTP/3 DATA becomes available. This avoids waiting for an attacker
        /// to finish a large advertised frame after its prefix is already
        /// known to violate RFC 3629.
        fn ensureIncomingFrameBuffered(
            self: *Self,
            header: websocket.FrameHeader,
            total_len: usize,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!void {
            const options: websocket.ParseFrameOptions = switch (role) {
                .client => .{
                    .expect_mask = .unmasked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
                .server => .{
                    .expect_mask = .masked,
                    .allow_rsv1 = self.permessage_deflate,
                    .validate_utf8 = false,
                },
            };
            // Protocol/header errors are fully knowable before any payload
            // validation and retain precedence over malformed UTF-8.
            try websocket.validateFrameHeader(header, options);
            const message_kind: IncomingDataKind = switch (header.opcode) {
                .text => blk: {
                    if (self.incoming_data_kind != .none) {
                        return error.InvalidFrame;
                    }
                    // A timeout can leave a validated prefix of this same
                    // frame buffered. Preserve its validator when resuming.
                    if (self.incoming_frame_validated == 0) {
                        self.incoming_text_utf8.reset();
                    }
                    break :blk if (header.rsv1)
                        .compressed_text
                    else
                        .text;
                },
                .binary => blk: {
                    if (self.incoming_data_kind != .none) {
                        return error.InvalidFrame;
                    }
                    break :blk .binary;
                },
                .continuation => blk: {
                    if (self.incoming_data_kind == .none) {
                        return error.InvalidFrame;
                    }
                    break :blk self.incoming_data_kind;
                },
                else => .none,
            };
            const validate_text = message_kind == .text;
            var validated = @max(
                header.header_len,
                self.incoming_frame_validated,
            );
            errdefer self.incoming_frame_validated = validated;
            while (message_buffer.unreadLen(
                &self.inbuf,
                self.inbuf_consumed,
            ) < total_len) {
                if (validate_text) {
                    try self.validateBufferedTextRange(
                        header,
                        &validated,
                        total_len,
                    );
                }
                const buffered = message_buffer.unreadLen(
                    &self.inbuf,
                    self.inbuf_consumed,
                );
                try self.ensureBuffered(
                    @min(total_len, buffered + 1),
                    deadline,
                );
            }
            if (validate_text) {
                try self.validateBufferedTextRange(
                    header,
                    &validated,
                    total_len,
                );
                if (header.fin) try self.incoming_text_utf8.finish();
            }

            if (!header.opcode.isControl()) {
                self.incoming_data_kind =
                    if (header.fin) .none else message_kind;
            }
            self.incoming_frame_validated = 0;
        }

        fn validateBufferedTextRange(
            self: *Self,
            header: websocket.FrameHeader,
            validated: *usize,
            total_len: usize,
        ) Error!void {
            const available = message_buffer.unread(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const available_end = @min(available.len, total_len);
            if (available_end <= validated.*) return;
            const bytes = available[validated.*..available_end];
            if (header.mask_key) |mask| {
                try self.incoming_text_utf8.feedMasked(
                    bytes,
                    mask,
                    validated.* - header.header_len,
                );
            } else {
                try self.incoming_text_utf8.feed(bytes);
            }
            validated.* = available_end;
        }

        fn appendPayloadChunk(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!usize {
            return switch (role) {
                .client => while (true) {
                    var event = (if (deadline) |absolute|
                        try self.h3.receiveResponseEventWithDeadline(
                            self.stream_id,
                            absolute,
                        )
                    else
                        try self.h3.receiveResponseEvent(self.stream_id)) orelse
                        continue;
                    defer event.deinit(self.allocator);
                    switch (event) {
                        .data_available => {
                            const available = try self.h3
                                .availableResponseData(self.stream_id);
                            if (available == 0) continue;
                            const out = try message_buffer
                                .reserveAppendAfterConsumed(
                                &self.inbuf,
                                &self.inbuf_consumed,
                                self.allocator,
                                @min(available, max_payload_read_chunk),
                            );
                            const count = try self.h3.readResponseData(
                                self.stream_id,
                                out,
                            );
                            message_buffer.commitAppend(&self.inbuf, count);
                            if (count != 0) break count;
                        },
                        .finished => {
                            self.receive_finished = true;
                            break 0;
                        },
                        else => return error.InvalidHandshake,
                    }
                },
                .server => while (true) {
                    var event = if (deadline) |absolute|
                        try self.h3.receiveRequestEventForWithDeadline(
                            self.stream_id,
                            absolute,
                        )
                    else
                        try self.h3.receiveRequestEventFor(self.stream_id);
                    defer event.deinit(self.allocator);
                    switch (event) {
                        .reset => return error.ConnectionClosed,
                        .message => |message| {
                            std.debug.assert(message.stream_id == self.stream_id);
                            switch (message.value) {
                                .data_available => {
                                    const available = try self.h3
                                        .availableRequestData(self.stream_id);
                                    if (available == 0) continue;
                                    const out = try message_buffer
                                        .reserveAppendAfterConsumed(
                                        &self.inbuf,
                                        &self.inbuf_consumed,
                                        self.allocator,
                                        @min(
                                            available,
                                            max_payload_read_chunk,
                                        ),
                                    );
                                    const count = try self.h3.readRequestData(
                                        self.stream_id,
                                        out,
                                    );
                                    message_buffer.commitAppend(
                                        &self.inbuf,
                                        count,
                                    );
                                    if (count != 0) break count;
                                },
                                .finished => {
                                    self.receive_finished = true;
                                    break 0;
                                },
                                else => return error.InvalidHandshake,
                            }
                        },
                    }
                },
            };
        }

        fn readPayloadChunkInto(
            self: *Self,
            out: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!usize {
            std.debug.assert(out.len != 0);
            return switch (role) {
                .client => while (true) {
                    var event = (if (deadline) |absolute|
                        try self.h3.receiveResponseEventWithDeadline(
                            self.stream_id,
                            absolute,
                        )
                    else
                        try self.h3.receiveResponseEvent(self.stream_id)) orelse
                        continue;
                    defer event.deinit(self.allocator);
                    switch (event) {
                        .data_available => {
                            const count = try self.h3.readResponseData(
                                self.stream_id,
                                out,
                            );
                            if (count != 0) break count;
                        },
                        .finished => {
                            self.receive_finished = true;
                            break 0;
                        },
                        else => return error.InvalidHandshake,
                    }
                },
                .server => while (true) {
                    var event = if (deadline) |absolute|
                        try self.h3.receiveRequestEventForWithDeadline(
                            self.stream_id,
                            absolute,
                        )
                    else
                        try self.h3.receiveRequestEventFor(self.stream_id);
                    defer event.deinit(self.allocator);
                    switch (event) {
                        .reset => return error.ConnectionClosed,
                        .message => |message| {
                            std.debug.assert(message.stream_id == self.stream_id);
                            switch (message.value) {
                                .data_available => {
                                    const count = try self.h3.readRequestData(
                                        self.stream_id,
                                        out,
                                    );
                                    if (count != 0) break count;
                                },
                                .finished => {
                                    self.receive_finished = true;
                                    break 0;
                                },
                                else => return error.InvalidHandshake,
                            }
                        },
                    }
                },
            };
        }

        fn discardBuffered(self: *Self, len: usize) void {
            _ = message_buffer.discardPrefix(
                &self.inbuf,
                &self.inbuf_consumed,
                len,
            );
        }

        fn io(self: *const Self) std.Io {
            return self.h3.established.connection.endpoint.io;
        }
    };
}

pub const Client = struct {
    pub fn connectSession(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
    ) Error!ClientConnection {
        var attempt = try connectSessionAttempt(allocator, h3, options);
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectSessionAttempt(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        h3.options.local_settings.enable_connect_protocol = true;
        return connectAttemptEstablishedBefore(
            allocator,
            h3,
            options,
            null,
            h3,
        );
    }

    /// Complete RFC 9220 negotiation on an existing HTTP/3 connection before
    /// one absolute awake-clock deadline. The caller keeps ownership of `h3`
    /// on failure and transfers it to the returned WebSocket on success.
    pub fn connectSessionWithDeadline(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ClientConnection {
        var attempt = try connectSessionAttemptWithDeadline(
            allocator,
            h3,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectSessionAttemptWithDeadline(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const absolute = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            deadline,
        );
        h3.options.local_settings.enable_connect_protocol = true;
        return connectAttemptEstablishedBefore(
            allocator,
            h3,
            options,
            absolute,
            h3,
        );
    }

    pub fn connectSessionWithTimeout(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ClientConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectSessionWithDeadline(
            allocator,
            h3,
            options,
            .fromNow(
                h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn connectSessionAttemptWithTimeout(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeClient,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectSessionAttemptWithDeadline(
            allocator,
            h3,
            options,
            .fromNow(
                h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        server: std.Io.net.IpAddress,
        h3_limits: http3.runtime.Limits,
        h3_options: http3.runtime.HandshakeClientOptions,
        options: ConnectOptions,
    ) Error!ClientConnection {
        var attempt = try connectAttempt(
            allocator,
            io,
            local_address,
            server,
            h3_limits,
            h3_options,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        server: std.Io.net.IpAddress,
        h3_limits: http3.runtime.Limits,
        h3_options: http3.runtime.HandshakeClientOptions,
        options: ConnectOptions,
    ) Error!ConnectAttempt {
        try preflightClientOptions(allocator, options);
        var h3_options_with_connect = h3_options;
        h3_options_with_connect.session.local_settings
            .enable_connect_protocol = true;
        var h3 = try http3.runtime.HandshakeClient.connect(
            allocator,
            io,
            local_address,
            server,
            h3_limits,
            h3_options_with_connect,
        );
        errdefer h3.deinit();
        return connectAttemptEstablishedBefore(
            allocator,
            &h3,
            options,
            null,
            null,
        );
    }

    /// Establish QUIC/TLS and finish the RFC 9220 Extended CONNECT under one
    /// caller-owned deadline. Passing the original timestamp to every HTTP/3
    /// receive phase prevents SETTINGS or response traffic from renewing it.
    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        server: std.Io.net.IpAddress,
        h3_limits: http3.runtime.Limits,
        h3_options: http3.runtime.HandshakeClientOptions,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ClientConnection {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            h3_limits,
            h3_options,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        server: std.Io.net.IpAddress,
        h3_limits: http3.runtime.Limits,
        h3_options: http3.runtime.HandshakeClientOptions,
        options: ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        const absolute = try deadline_policy.usableAwake(io, deadline);
        try preflightClientOptions(allocator, options);
        var h3_options_with_connect = h3_options;
        h3_options_with_connect.session.local_settings
            .enable_connect_protocol = true;
        var h3 = try http3.runtime.HandshakeClient.connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            h3_limits,
            h3_options_with_connect,
            absolute,
        );
        errdefer h3.deinit();
        return connectAttemptEstablishedBefore(
            allocator,
            &h3,
            options,
            absolute,
            null,
        );
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        server: std.Io.net.IpAddress,
        h3_limits: http3.runtime.Limits,
        h3_options: http3.runtime.HandshakeClientOptions,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ClientConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            h3_limits,
            h3_options,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        server: std.Io.net.IpAddress,
        h3_limits: http3.runtime.Limits,
        h3_options: http3.runtime.HandshakeClientOptions,
        options: ConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            h3_limits,
            h3_options,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Connect to a complete HTTPS URL, deriving authority, path/query, DNS
    /// destination, and SNI while retaining HTTP/3's all-address fallback.
    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
    ) Error!ClientConnection {
        var attempt = try connectUriAttempt(
            allocator,
            io,
            local_address,
            uri_text,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ClientConnection {
        var attempt = try connectUriAttemptWithDeadline(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectUriWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ClientConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriWithDeadline(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectUriAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
    ) Error!ConnectAttempt {
        return connectUriAttemptBefore(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            null,
        );
    }

    pub fn connectUriAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        return connectUriAttemptBefore(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            try deadline_policy.usableAwake(io, deadline),
        );
    }

    pub fn connectUriAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectUriAttemptWithDeadline(
            allocator,
            io,
            local_address,
            uri_text,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn connectUriAttemptBefore(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: std.Io.net.IpAddress,
        uri_text: []const u8,
        options: UriConnectOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        try validateClientExtraHeaders(options.extra_headers);
        try validateProtocols(options.protocols);
        const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
        var endpoint = try http3.runtime.uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try http3.runtime.uriRequestTargetAlloc(allocator, uri);
        defer allocator.free(path);

        if (options.cookies != null) {
            try cookie_handshake.validate(uri_text, options.extra_headers);
        }

        var h3_options = options.h3;
        h3_options.session.local_settings.enable_connect_protocol = true;
        if (h3_options.handshake.server_name == null) {
            h3_options.handshake.server_name = endpoint.tls_host;
        }
        var h3_client = if (options.socks5_proxy) |proxy|
            if (deadline) |absolute|
                try http3.socks5_runtime.connectHostWithDeadline(
                    allocator,
                    io,
                    local_address,
                    proxy,
                    endpoint.tls_host,
                    endpoint.port,
                    options.h3_limits,
                    h3_options,
                    absolute,
                )
            else
                try http3.socks5_runtime.connectHost(
                    allocator,
                    io,
                    local_address,
                    proxy,
                    endpoint.tls_host,
                    endpoint.port,
                    options.h3_limits,
                    h3_options,
                )
        else if (deadline) |absolute|
            try http3.runtime.HandshakeClient.connectUriWithDeadline(
                allocator,
                io,
                local_address,
                uri,
                options.h3_limits,
                h3_options,
                absolute,
            )
        else
            try http3.runtime.HandshakeClient.connectUri(
                allocator,
                io,
                local_address,
                uri,
                options.h3_limits,
                h3_options,
            );
        errdefer h3_client.deinit();
        return connectAttemptEstablishedBefore(
            allocator,
            &h3_client,
            .{
                .authority = endpoint.authority,
                .path = path,
                .protocols = options.protocols,
                .require_subprotocol = options.require_subprotocol,
                .origin = options.origin,
                .extra_headers = options.extra_headers,
                .cookies = options.cookies,
                .enable_permessage_deflate = options.enable_permessage_deflate,
                .allow_context_takeover = options.allow_context_takeover,
                .context_takeover = options.context_takeover,
                .client_max_window_bits = options.client_max_window_bits,
                .server_max_window_bits = options.server_max_window_bits,
                .compression_threshold = options.compression_threshold,
                .limits = options.limits,
            },
            deadline,
            null,
        );
    }
};

fn preflightClientOptions(
    allocator: std.mem.Allocator,
    options: ConnectOptions,
) Error!void {
    try validateClientExtraHeaders(options.extra_headers);
    try validateProtocols(options.protocols);
    if (options.cookies != null) {
        const scope = try cookie_handshake.scopeUriAlloc(
            allocator,
            "https",
            options.authority,
            options.path,
        );
        defer allocator.free(scope);
        try cookie_handshake.validate(scope, options.extra_headers);
    }
}

fn connectAttemptEstablishedBefore(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeClient,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
    restore_to: ?*http3.runtime.HandshakeClient,
) Error!ConnectAttempt {
    try validateClientExtraHeaders(options.extra_headers);
    try validateProtocols(options.protocols);
    const cookie_scope: ?[]u8 = if (options.cookies != null)
        try cookie_handshake.scopeUriAlloc(
            allocator,
            "https",
            options.authority,
            options.path,
        )
    else
        null;
    defer if (cookie_scope) |uri| allocator.free(uri);
    var prepared_cookie: ?cookie_handshake.Prepared = if (options.cookies) |cookie_options|
        try cookie_handshake.prepare(
            allocator,
            h3.established.connection.endpoint.io,
            cookie_options,
            cookie_scope.?,
            options.extra_headers,
        )
    else
        null;
    defer if (prepared_cookie) |*prepared| prepared.deinit();
    const peer_settings = if (deadline) |absolute|
        try h3.receivePeerSettingsWithDeadline(absolute)
    else
        try h3.receivePeerSettings();
    if (!peer_settings.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    var protocol_value_stack: [handshake_headers.protocol_value_stack_capacity]u8 = undefined;
    var protocol_value = try handshake_headers.prepareProtocolValue(
        allocator,
        options.protocols,
        &protocol_value_stack,
    );
    defer protocol_value.deinit(allocator);
    const extension_policy: websocket.ExtensionNegotiation.Policy = .{
        .enable_permessage_deflate = options.enable_permessage_deflate,
        .allow_context_takeover = options.allow_context_takeover,
        .context_takeover = options.context_takeover,
    };
    var extension_offer_storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
    const extension_offer = try websocket.ExtensionNegotiation.offerValueInto(
        &extension_offer_storage,
        extension_policy,
        options.client_max_window_bits,
        options.server_max_window_bits,
    );
    const field_count = std.math.add(
        usize,
        2 + @as(usize, @intFromBool(protocol_value.value.len != 0)) +
            @as(usize, @intFromBool(options.origin != null)) +
            @as(usize, @intFromBool(extension_offer != null)) +
            @as(usize, @intFromBool(
                prepared_cookie != null and
                    prepared_cookie.?.value.len != 0,
            )),
        options.extra_headers.len,
    ) catch return error.PayloadTooLarge;
    var fields_stack: [handshake_storage.stack_capacity]http3.Qpack.HeaderField = undefined;
    const fields = try handshake_storage.acquire(
        http3.Qpack.HeaderField,
        allocator,
        &fields_stack,
        field_count,
    );
    defer handshake_storage.release(
        http3.Qpack.HeaderField,
        allocator,
        &fields_stack,
        fields,
    );
    var field_index: usize = 0;
    fields[field_index] = .{ .name = ":protocol", .value = "websocket" };
    field_index += 1;
    fields[field_index] = .{
        .name = "sec-websocket-version",
        .value = "13",
    };
    field_index += 1;
    if (protocol_value.value.len != 0) {
        fields[field_index] = .{
            .name = "sec-websocket-protocol",
            .value = protocol_value.value,
        };
        field_index += 1;
    }
    if (options.origin) |origin| {
        fields[field_index] = .{ .name = "origin", .value = origin };
        field_index += 1;
    }
    if (extension_offer) |value| {
        fields[field_index] = .{
            .name = "sec-websocket-extensions",
            .value = value,
        };
        field_index += 1;
    }
    @memcpy(
        fields[field_index..][0..options.extra_headers.len],
        options.extra_headers,
    );
    field_index += options.extra_headers.len;
    if (prepared_cookie) |prepared| if (prepared.value.len != 0) {
        fields[field_index] = .{
            .name = "cookie",
            .value = prepared.value,
            .never_indexed = true,
        };
        field_index += 1;
    };
    std.debug.assert(field_index == fields.len);
    if (deadline) |absolute| {
        // Header construction is local work but remains part of the caller's
        // operation. Do not emit CONNECT after its absolute budget elapsed.
        _ = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            absolute,
        );
    }
    const stream_id = try h3.startRequest(.{
        .method = "CONNECT",
        .path = options.path,
        .scheme = "https",
        .authority = options.authority,
        .headers = fields,
    }, null);
    errdefer if (restore_to != null) {
        h3.abandonExtendedConnect(stream_id);
    };
    var response = if (deadline) |absolute|
        try receiveResponseHeadWithDeadline(h3, stream_id, absolute)
    else
        try receiveResponseHead(h3, stream_id);
    errdefer response.deinit(allocator);
    if (!h3.control.settings.peer.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    if (options.cookies) |cookie_options| {
        try cookie_handshake.store(
            h3.established.connection.endpoint.io,
            cookie_options,
            cookie_scope.?,
            response.headers,
        );
    }
    if (response.status >= 200 and response.status < 300) {
        // Successful Extended CONNECT transfers receive-loop ownership from
        // the HTTP/3 handshake adapter to the WebSocket session while the
        // stream remains open. Flush the response HEAD's delayed ACK before
        // that handoff so a short-lived server recovery drain can complete.
        if (deadline) |absolute|
            _ = try h3.established.connection
                .flushPendingAckWithDeadline(absolute)
        else
            _ = try h3.established.connection.flushPendingAck();
    }
    var body: []u8 = &.{};
    var trailers: []http3.Qpack.HeaderField = &.{};
    var stream_complete = false;
    if (response.status < 200 or response.status >= 300) {
        const rejection = try receiveRejectionBodyBefore(
            h3,
            stream_id,
            response.content_length,
            options.limits.max_rejection_body_bytes,
            deadline,
        );
        body = rejection.body;
        trailers = rejection.trailers;
        stream_complete = true;
    }
    errdefer allocator.free(body);
    errdefer http3.Qpack.freeDecodedFields(allocator, trailers);
    const owned_h3 = h3.*;
    h3.* = undefined;
    return .{
        .h3 = owned_h3,
        .restore_to = restore_to,
        .stream_id = stream_id,
        .response = response,
        .response_body = body,
        .response_trailers = trailers,
        .stream_complete = stream_complete,
        .options = options,
    };
}

pub const Server = struct {
    transport: http3.runtime.HandshakeServer,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: std.Io.net.IpAddress,
        limits: http3.runtime.Limits,
        options: http3.runtime.HandshakeServerOptions,
    ) Error!Server {
        var enabled = options;
        enabled.session.local_settings.enable_connect_protocol = true;
        return .{ .transport = try .bind(
            allocator,
            io,
            bind_address,
            limits,
            enabled,
        ) };
    }

    pub fn deinit(self: *Server) void {
        self.transport.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) std.Io.net.IpAddress {
        return self.transport.address();
    }

    pub fn accept(
        self: *Server,
        options: AcceptOptions,
    ) Error!ServerConnection {
        var pending = try self.receiveUpgradeRequest(options);
        errdefer pending.deinit();
        return pending.accept();
    }

    /// Carry one absolute deadline through QUIC/TLS, peer SETTINGS, the first
    /// WebSocket Extended CONNECT request, and the local 200 response.
    pub fn acceptWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ServerConnection {
        const absolute = try deadline_policy.usableAwake(
            self.transport.quic_server.endpoint.io,
            deadline,
        );
        var pending = try self.receiveUpgradeRequestWithDeadline(
            options,
            absolute,
        );
        errdefer pending.deinit();
        return pending.accept();
    }

    pub fn acceptWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!ServerConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(
            options,
            .fromNow(
                self.transport.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// Receive and validate an RFC 9220 CONNECT without sending 200. This
    /// server-level form transfers the complete HTTP/3 session to the pending
    /// decision, matching the ownership of `ServerConnection`.
    pub fn receiveUpgradeRequest(
        self: *Server,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        var h3 = try self.transport.accept();
        errdefer h3.deinit();
        return receiveServerUpgradeBefore(
            self.transport.allocator,
            &h3,
            options,
            null,
            null,
        );
    }

    pub fn receiveUpgradeRequestWithDeadline(
        self: *Server,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        const absolute = try deadline_policy.usableAwake(
            self.transport.quic_server.endpoint.io,
            deadline,
        );
        var h3 = try self.transport.acceptWithDeadline(absolute);
        errdefer h3.deinit();
        return receiveServerUpgradeBefore(
            self.transport.allocator,
            &h3,
            options,
            absolute,
            null,
        );
    }

    pub fn receiveUpgradeRequestWithTimeout(
        self: *Server,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveUpgradeRequestWithDeadline(
            options,
            .fromNow(
                self.transport.quic_server.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn acceptSession(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
    ) Error!ServerConnection {
        var pending = try receiveServerUpgradeBefore(
            allocator,
            h3,
            options,
            null,
            h3,
        );
        return pending.accept() catch |err| {
            pending.restoreSession();
            return err;
        };
    }

    pub fn acceptSessionWithDeadline(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ServerConnection {
        const absolute = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            deadline,
        );
        var pending = try receiveServerUpgradeBefore(
            allocator,
            h3,
            options,
            absolute,
            h3,
        );
        return pending.accept() catch |err| {
            pending.restoreSession();
            return err;
        };
    }

    pub fn acceptSessionWithTimeout(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!ServerConnection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return acceptSessionWithDeadline(
            allocator,
            h3,
            options,
            .fromNow(
                h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn receiveSessionUpgradeRequest(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
    ) Error!PendingUpgrade {
        return receiveServerUpgradeBefore(
            allocator,
            h3,
            options,
            null,
            h3,
        );
    }

    pub fn receiveSessionUpgradeRequestWithDeadline(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingUpgrade {
        const absolute = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            deadline,
        );
        return receiveServerUpgradeBefore(
            allocator,
            h3,
            options,
            absolute,
            h3,
        );
    }

    pub fn receiveSessionUpgradeRequestWithTimeout(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
        timeout: std.Io.Duration,
    ) Error!PendingUpgrade {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveSessionUpgradeRequestWithDeadline(
            allocator,
            h3,
            options,
            .fromNow(
                h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }
};

fn receiveServerUpgradeBefore(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeServerSession,
    options: AcceptOptions,
    deadline: ?std.Io.Clock.Timestamp,
    restore_to: ?*http3.runtime.HandshakeServerSession,
) Error!PendingUpgrade {
    if (deadline) |absolute| {
        _ = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            absolute,
        );
    }
    try h3.ensureSettingsSent();
    var request = if (deadline) |absolute|
        try receiveRequestHeadWithDeadline(h3, absolute)
    else
        try receiveRequestHead(h3);
    var request_owned = true;
    errdefer if (request_owned) request.head.deinit(allocator);
    var request_pending = true;
    errdefer if (request_pending) {
        h3.rejectRequest(request.stream_id) catch {};
    };
    validateRequestHandshake(
        request.head,
        options.allowed_origins,
    ) catch |err| switch (err) {
        error.UnsupportedVersion => {
            try validateRequestForVersionNegotiation(
                request.head,
                options.allowed_origins,
            );
            try validateVersionNegotiationHeaders(
                allocator,
                request.head.headers,
                options.extra_headers,
            );
            const owned_h3 = h3.*;
            h3.* = undefined;
            request_owned = false;
            request_pending = false;
            var pending = PendingUpgrade{
                .allocator = allocator,
                .h3 = owned_h3,
                // Always restore before returning the typed error. For an
                // owning server this lets its outer errdefer close only after
                // the bounded recovery drain below; caller-owned sessions
                // keep the submitted response in their recovery state.
                .restore_to = h3,
                .options = options,
                .deadline = deadline,
                .request = request,
                .selected_protocol = null,
                .selected_extension = null,
                .negotiated_extension = .{},
            };
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var rejected = try pending.rejectUnsupportedVersionRetained();
            pending_owned = false;
            defer rejected.deinit();
            if (restore_to == null) {
                if (deadline) |absolute| {
                    rejected.waitForRecoveryIdleWithDeadline(absolute) catch {};
                } else {
                    rejected.waitForRecoveryIdleWithTimeout(
                        rejection_drain_timeout,
                    ) catch {};
                }
            }
            return err;
        },
        else => return err,
    };
    const selected_protocol = try selectSubprotocol(
        allocator,
        request.head.headers,
        options.protocols,
    );
    errdefer if (selected_protocol) |protocol| allocator.free(protocol);
    if (options.require_subprotocol and selected_protocol == null) {
        return error.InvalidSubprotocol;
    }
    const extension_policy: websocket.ExtensionNegotiation.Policy = .{
        .enable_permessage_deflate = options.enable_permessage_deflate,
        .allow_context_takeover = options.allow_context_takeover,
        .context_takeover = options.context_takeover,
        .accept_client_max_window_bits = options.client_max_window_bits,
        .accept_server_max_window_bits = options.server_max_window_bits,
    };
    const selected_extension = try acceptExtensions(
        allocator,
        request.head.headers,
        extension_policy,
    );
    errdefer if (selected_extension) |extension| allocator.free(extension);
    const negotiated_extension = if (selected_extension) |extension|
        try websocket.ExtensionNegotiation.validateResponseWithPolicy(
            extension,
            extension_policy,
        )
    else
        websocket.ExtensionNegotiation{};
    try validateServerExtraHeaders(options.extra_headers);
    const owned_h3 = h3.*;
    h3.* = undefined;
    request_owned = false;
    request_pending = false;
    return .{
        .allocator = allocator,
        .h3 = owned_h3,
        .restore_to = restore_to,
        .options = options,
        .deadline = deadline,
        .request = request,
        .selected_protocol = selected_protocol,
        .selected_extension = selected_extension,
        .negotiated_extension = negotiated_extension,
    };
}

/// A validated RFC 9220 request awaiting application admission. The value
/// temporarily owns the complete HTTP/3 session because the current WebSocket
/// adapter uses a single-owner QUIC receive loop. Caller-supplied sessions are
/// restored after rejection or destruction; acceptance transfers ownership to
/// the resulting WebSocket connection.
pub const PendingUpgrade = struct {
    allocator: std.mem.Allocator,
    h3: http3.runtime.HandshakeServerSession,
    restore_to: ?*http3.runtime.HandshakeServerSession = null,
    options: AcceptOptions,
    deadline: ?std.Io.Clock.Timestamp,
    request: RequestHead,
    selected_protocol: ?[]u8,
    selected_extension: ?[]u8,
    negotiated_extension: websocket.ExtensionNegotiation,

    pub fn deinit(self: *PendingUpgrade) void {
        self.h3.rejectRequest(self.request.stream_id) catch {};
        self.finish();
    }

    fn restoreSession(self: *PendingUpgrade) void {
        std.debug.assert(self.restore_to != null);
        self.finish();
    }

    fn finish(self: *PendingUpgrade) void {
        const allocator = self.allocator;
        self.request.head.deinit(allocator);
        if (self.selected_protocol) |protocol| allocator.free(protocol);
        if (self.selected_extension) |extension| allocator.free(extension);
        if (self.restore_to) |destination| {
            destination.* = self.h3;
        } else {
            self.h3.deinit();
        }
        self.* = undefined;
    }

    pub fn streamId(self: PendingUpgrade) u62 {
        return self.request.stream_id;
    }

    pub fn target(self: PendingUpgrade) []const u8 {
        return self.request.head.path;
    }

    pub fn authority(self: PendingUpgrade) ?[]const u8 {
        return self.request.head.authority;
    }

    pub fn headers(self: PendingUpgrade) []const http3.Qpack.HeaderField {
        return self.request.head.headers;
    }

    pub fn header(self: PendingUpgrade, name: []const u8) ?[]const u8 {
        for (self.request.head.headers) |field| {
            if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
        }
        return null;
    }

    pub fn accept(self: *PendingUpgrade) Error!ServerConnection {
        return self.acceptWithHeaders(&.{});
    }

    pub fn acceptWithHeaders(
        self: *PendingUpgrade,
        additional_headers: []const http3.Qpack.HeaderField,
    ) Error!ServerConnection {
        const allocator = self.allocator;
        try validateServerExtraHeaders(additional_headers);
        const application_count = std.math.add(
            usize,
            self.options.extra_headers.len,
            additional_headers.len,
        ) catch return error.PayloadTooLarge;
        const header_count = std.math.add(
            usize,
            @as(usize, @intFromBool(self.selected_protocol != null)) +
                @as(usize, @intFromBool(self.selected_extension != null)),
            application_count,
        ) catch return error.PayloadTooLarge;
        var headers_stack: [handshake_storage.stack_capacity]http3.Qpack.HeaderField = undefined;
        const response_headers = try handshake_storage.acquire(
            http3.Qpack.HeaderField,
            allocator,
            &headers_stack,
            header_count,
        );
        defer handshake_storage.release(
            http3.Qpack.HeaderField,
            allocator,
            &headers_stack,
            response_headers,
        );
        var header_index: usize = 0;
        if (self.selected_protocol) |protocol| {
            response_headers[header_index] = .{
                .name = "sec-websocket-protocol",
                .value = protocol,
            };
            header_index += 1;
        }
        if (self.selected_extension) |extension| {
            response_headers[header_index] = .{
                .name = "sec-websocket-extensions",
                .value = extension,
            };
            header_index += 1;
        }
        @memcpy(
            response_headers[header_index..][0..self.options.extra_headers.len],
            self.options.extra_headers,
        );
        header_index += self.options.extra_headers.len;
        @memcpy(response_headers[header_index..], additional_headers);
        if (self.deadline) |absolute| {
            // Request validation and extension selection remain within the same
            // admission budget; never send a successful response after expiry.
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
            );
        }
        const response: http3.Response = .{
            .status = 200,
            .headers = response_headers,
            .request_method = "CONNECT",
            .extended_connect = true,
        };
        if (self.deadline) |absolute|
            try self.h3.startResponseWithDeadline(
                self.request.stream_id,
                response,
                null,
                absolute,
            )
        else
            try self.h3.startResponse(
                self.request.stream_id,
                response,
                null,
            );
        const stream_id = self.request.stream_id;
        const options = self.options;
        const selected_protocol = self.selected_protocol;
        const negotiated_extension = self.negotiated_extension;
        self.request.head.deinit(allocator);
        if (self.selected_extension) |extension| allocator.free(extension);
        const owned_h3 = self.h3;
        self.* = undefined;
        return .init(
            allocator,
            stream_id,
            owned_h3,
            options.limits,
            selected_protocol,
            negotiated_extension,
            options.compression_threshold,
        );
    }

    /// Send a header-only final non-2xx response on this CONNECT stream. Use
    /// `rejectWithBody` when diagnostics require DATA or trailers.
    pub fn reject(
        self: *PendingUpgrade,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) Error!void {
        return self.rejectWithBody(
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    /// Send a header-only rejection while returning ownership of the HTTP/3
    /// recovery state to the application. The caller must keep the returned
    /// value alive until its delivery policy is satisfied, then call `deinit`.
    pub fn rejectRetained(
        self: *PendingUpgrade,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
    ) Error!RejectedUpgrade {
        return self.rejectWithBodyRetained(
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    /// Reject this CONNECT stream with an HTTP/3 response entity. Client-side
    /// retention is governed by `Limits.max_rejection_body_bytes`.
    pub fn rejectWithBody(
        self: *PendingUpgrade,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        const deadline = self.deadline;
        var rejected = try self.rejectWithBodyRetained(
            status,
            response_headers,
            body,
            trailers,
        );
        defer rejected.deinit();
        if (rejected.restore_to == null) {
            if (deadline) |absolute| {
                rejected.waitForRecoveryIdleWithDeadline(absolute) catch {};
            } else {
                rejected.waitForRecoveryIdleWithTimeout(
                    rejection_drain_timeout,
                ) catch {};
            }
        }
    }

    /// Send a complete rejection entity while retaining the connection until
    /// the caller explicitly finishes ACK/loss/PTO processing. This is useful
    /// when reliable delivery is part of the application's admission policy.
    pub fn rejectWithBodyRetained(
        self: *PendingUpgrade,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!RejectedUpgrade {
        try validateServerExtraHeaders(response_headers);
        try validateServerExtraHeaders(trailers);
        return self.rejectWithBodyRetainedPrepared(
            status,
            response_headers,
            body,
            trailers,
        );
    }

    fn rejectUnsupportedVersionRetained(
        self: *PendingUpgrade,
    ) Error!RejectedUpgrade {
        return self.rejectWithBodyRetainedPrepared(
            426,
            &.{.{
                .name = "sec-websocket-version",
                .value = "13",
            }},
            &.{},
            &.{},
        );
    }

    fn rejectWithBodyRetainedPrepared(
        self: *PendingUpgrade,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!RejectedUpgrade {
        if (status < 300 or status > 599) return error.InvalidStatus;
        const response: http3.Response = .{
            .status = status,
            .headers = response_headers,
            .body = body,
            .trailers = trailers,
            .request_method = "CONNECT",
            .extended_connect = true,
        };
        if (self.deadline) |absolute| {
            try self.h3.sendResponsePacedWithDeadline(
                self.request.stream_id,
                response,
                absolute,
            );
        } else {
            try self.h3.sendResponsePaced(
                self.request.stream_id,
                response,
            );
        }
        try self.h3.finishRejectedRequest(self.request.stream_id);
        const rejected = RejectedUpgrade{
            .allocator = self.allocator,
            .h3 = self.h3,
            .restore_to = self.restore_to,
            .request = self.request,
            .selected_protocol = self.selected_protocol,
            .selected_extension = self.selected_extension,
            .status = status,
        };
        self.* = undefined;
        return rejected;
    }

    pub fn forbidden(self: *PendingUpgrade) Error!void {
        return self.reject(403, &.{});
    }

    pub fn notFound(self: *PendingUpgrade) Error!void {
        return self.reject(404, &.{});
    }

    pub fn tooManyRequests(self: *PendingUpgrade) Error!void {
        return self.reject(429, &.{});
    }
};

/// Owns an RFC 9220 rejection after its final response was submitted. Keeping
/// this value alive preserves QUIC recovery state so applications that require
/// confirmed delivery can drive ACK/loss/PTO processing before teardown.
pub const RejectedUpgrade = struct {
    allocator: std.mem.Allocator,
    h3: http3.runtime.HandshakeServerSession,
    restore_to: ?*http3.runtime.HandshakeServerSession = null,
    request: RequestHead,
    selected_protocol: ?[]u8,
    selected_extension: ?[]u8,
    status: u16,

    pub fn deinit(self: *RejectedUpgrade) void {
        self.request.head.deinit(self.allocator);
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.selected_extension) |extension| self.allocator.free(extension);
        if (self.restore_to) |destination| {
            destination.* = self.h3;
        } else {
            self.h3.deinit();
        }
        self.* = undefined;
    }

    /// Process one timer-aware QUIC receive while the rejection remains owned.
    pub fn serviceTransport(self: *RejectedUpgrade) Error!void {
        try self.h3.established.connection.servicePacketServicingTimers();
    }

    /// Wait until the rejected CONNECT response is acknowledged. Pure receive-
    /// credit advertisements do not prolong this application boundary.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *RejectedUpgrade,
        timeout: std.Io.Duration,
    ) Error!void {
        return self.h3.waitForRecoveryIdleWithTimeout(timeout);
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *RejectedUpgrade,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.h3.waitForRecoveryIdleWithDeadline(deadline);
    }
};

const RequestHead = struct {
    stream_id: u62,
    head: http3.DecodedRequestHead,
};

fn receiveRequestHead(
    h3: *http3.runtime.HandshakeServerSession,
) Error!RequestHead {
    return receiveRequestHeadBefore(h3, null);
}

fn receiveRequestHeadWithDeadline(
    h3: *http3.runtime.HandshakeServerSession,
    deadline: std.Io.Clock.Timestamp,
) Error!RequestHead {
    return receiveRequestHeadBefore(h3, deadline);
}

fn receiveRequestHeadBefore(
    h3: *http3.runtime.HandshakeServerSession,
    deadline: ?std.Io.Clock.Timestamp,
) Error!RequestHead {
    while (true) {
        var event = if (deadline) |absolute|
            try h3.receiveRequestEventWithDeadline(absolute)
        else
            try h3.receiveRequestEvent();
        defer event.deinit(h3.established.connection.endpoint.allocator);
        switch (event) {
            .reset => return error.InvalidHandshake,
            .message => |*message| switch (message.value) {
                .head => |*head| {
                    if (head.* != .request) return error.InvalidHandshake;
                    const owned = head.request;
                    message.value = .finished;
                    return .{ .stream_id = message.stream_id, .head = owned };
                },
                else => return error.InvalidHandshake,
            },
        }
    }
}

fn receiveResponseHead(
    h3: *http3.runtime.HandshakeClient,
    stream_id: u62,
) Error!http3.DecodedResponseHead {
    return receiveResponseHeadBefore(h3, stream_id, null);
}

fn receiveResponseHeadWithDeadline(
    h3: *http3.runtime.HandshakeClient,
    stream_id: u62,
    deadline: std.Io.Clock.Timestamp,
) Error!http3.DecodedResponseHead {
    return receiveResponseHeadBefore(h3, stream_id, deadline);
}

fn receiveResponseHeadBefore(
    h3: *http3.runtime.HandshakeClient,
    stream_id: u62,
    deadline: ?std.Io.Clock.Timestamp,
) Error!http3.DecodedResponseHead {
    while (true) {
        var event = (if (deadline) |absolute|
            try h3.receiveResponseEventWithDeadline(stream_id, absolute)
        else
            try h3.receiveResponseEvent(stream_id)) orelse continue;
        defer event.deinit(h3.allocator);
        switch (event) {
            .head => |*head| {
                if (head.* != .response) return error.InvalidHandshake;
                if (head.response.status < 200) continue;
                const owned = head.response;
                event = .finished;
                return owned;
            },
            else => return error.InvalidHandshake,
        }
    }
}

const RejectionEntity = struct {
    body: []u8,
    trailers: []http3.Qpack.HeaderField,
};

fn finalizeRejectionBody(
    body: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    content_length: ?usize,
) std.mem.Allocator.Error![]u8 {
    if (content_length != null) return body.toOwnedSliceAssert();
    return body.toOwnedSlice(allocator);
}

fn receiveRejectionBodyBefore(
    h3: *http3.runtime.HandshakeClient,
    stream_id: u62,
    content_length: ?usize,
    max_body_bytes: usize,
    deadline: ?std.Io.Clock.Timestamp,
) Error!RejectionEntity {
    if ((content_length orelse 0) > max_body_bytes) {
        return error.MessageTooLarge;
    }
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(h3.allocator);
    if (content_length) |expected| {
        // A validated declared length lets fragmented DATA land in one exact
        // allocation instead of repeatedly growing the retained rejection.
        try body.ensureTotalCapacityPrecise(h3.allocator, expected);
    }
    var trailers: []http3.Qpack.HeaderField = &.{};
    errdefer http3.Qpack.freeDecodedFields(h3.allocator, trailers);
    var scratch: [16 * 1024]u8 = undefined;

    while (true) {
        var event = (if (deadline) |absolute|
            try h3.receiveResponseEventWithDeadline(stream_id, absolute)
        else
            try h3.receiveResponseEvent(stream_id)) orelse continue;
        defer event.deinit(h3.allocator);
        switch (event) {
            .data_available => {
                const remaining = max_body_bytes -| body.items.len;
                const read = try h3.readResponseData(
                    stream_id,
                    scratch[0..@min(scratch.len, remaining +| 1)],
                );
                if (read > remaining) return error.MessageTooLarge;
                try body.appendSlice(h3.allocator, scratch[0..read]);
            },
            .trailers => |value| {
                if (trailers.len != 0) return error.InvalidHandshake;
                trailers = value.fields;
                event = .finished;
            },
            .finished => break,
            .push_promise => continue,
            .head => return error.InvalidHandshake,
        }
    }
    return .{
        .body = try finalizeRejectionBody(
            &body,
            h3.allocator,
            content_length,
        ),
        .trailers = trailers,
    };
}

test "WebSocket H3 declared rejection body retains one exact allocation" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(tracking.allocator());

    try body.ensureTotalCapacityPrecise(tracking.allocator(), 9);
    try body.appendSlice(tracking.allocator(), "try");
    try body.appendSlice(tracking.allocator(), " later");
    const owned = try finalizeRejectionBody(
        &body,
        tracking.allocator(),
        9,
    );
    defer tracking.allocator().free(owned);
    try std.testing.expectEqualStrings("try later", owned);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
}

fn validateRequestHandshake(
    request: http3.DecodedRequestHead,
    allowed_origins: []const []const u8,
) Error!void {
    try validateRequestHandshakePrefix(request);
    try websocket.validateClientVersion(
        try requiredHeader(request.headers, "sec-websocket-version"),
    );
    try validateRequestHandshakeSuffix(request, allowed_origins);
}

fn validateRequestForVersionNegotiation(
    request: http3.DecodedRequestHead,
    allowed_origins: []const []const u8,
) Error!void {
    try validateRequestHandshakePrefix(request);
    try websocket.validateClientVersionSyntax(
        try requiredHeader(request.headers, "sec-websocket-version"),
    );
    try validateRequestHandshakeSuffix(request, allowed_origins);
}

fn validateRequestHandshakePrefix(
    request: http3.DecodedRequestHead,
) Error!void {
    if (!std.mem.eql(u8, request.method, "CONNECT") or
        !std.mem.eql(u8, request.scheme, "https") or
        request.authority == null or request.path.len == 0 or
        !std.mem.eql(
            u8,
            try requiredHeader(request.headers, ":protocol"),
            "websocket",
        ))
    {
        return error.InvalidHandshake;
    }
}

fn validateRequestHandshakeSuffix(
    request: http3.DecodedRequestHead,
    allowed_origins: []const []const u8,
) Error!void {
    try rejectLegacyHeaders(request.headers);
    try validateOrigin(request.headers, allowed_origins);
}

fn validateVersionNegotiationHeaders(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
    server_headers: []const http3.Qpack.HeaderField,
) Error!void {
    if (try selectSubprotocol(allocator, headers, &.{})) |protocol| {
        allocator.free(protocol);
    }
    if (try acceptExtensions(allocator, headers, .{})) |extension| {
        allocator.free(extension);
    }
    try validateServerExtraHeaders(server_headers);
}

fn validateServerHandshake(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
    try handshake_headers.validateOfferedProtocols(offered_protocols);
    try rejectLegacyHeaders(headers);
    if (try optionalHeader(headers, "sec-websocket-version")) |_| {
        return error.InvalidHandshake;
    }
    if (try optionalHeader(headers, "sec-websocket-protocol")) |selected| {
        const protocol = std.mem.trim(u8, selected, " \t");
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
        for (offered_protocols) |offered| {
            if (std.mem.eql(u8, protocol, offered)) {
                return try allocator.dupe(u8, protocol);
            }
        }
        return error.InvalidSubprotocol;
    }
    return null;
}

test "WebSocket HTTP3 permits null subprotocol selection" {
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try validateServerHandshake(
            std.testing.allocator,
            &.{},
            &.{"chat.v1"},
        ),
    );
}

fn selectSubprotocol(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
    supported: []const []const u8,
) Error!?[]u8 {
    return handshake_headers.selectSubprotocol(
        allocator,
        headers,
        supported,
    );
}

fn validateProtocols(protocols: []const []const u8) Error!void {
    return handshake_headers.validateOfferedProtocols(protocols);
}

fn acceptExtensions(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
    policy: websocket.ExtensionNegotiation.Policy,
) Error!?[]u8 {
    return websocket.ExtensionNegotiation.acceptClientHeadersWithPolicy(
        allocator,
        headers,
        policy,
    );
}

fn validateOrigin(
    headers: []const http3.Qpack.HeaderField,
    allowed: []const []const u8,
) Error!void {
    if (allowed.len == 0) return;
    const origin = try optionalHeader(headers, "origin");
    return origin_policy.validateValue(origin, allowed);
}

fn validateClientExtraHeaders(
    headers: []const http3.Qpack.HeaderField,
) Error!void {
    for (headers) |header| {
        if (std.mem.startsWith(u8, header.name, ":") or
            isOwnedHeader(header.name) or
            isLegacyHeader(header.name) or
            std.ascii.eqlIgnoreCase(header.name, "content-length"))
        {
            return error.InvalidHandshake;
        }
    }
}

fn validateServerExtraHeaders(
    headers: []const http3.Qpack.HeaderField,
) Error!void {
    for (headers) |header| {
        if (std.mem.startsWith(u8, header.name, ":") or
            std.ascii.eqlIgnoreCase(header.name, "sec-websocket-protocol") or
            std.ascii.eqlIgnoreCase(header.name, "sec-websocket-version") or
            std.ascii.eqlIgnoreCase(header.name, "sec-websocket-extensions") or
            std.ascii.eqlIgnoreCase(header.name, "content-length") or
            isLegacyHeader(header.name))
        {
            return error.InvalidHandshake;
        }
    }
}

fn isOwnedHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "sec-websocket-version") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-extensions") or
        std.ascii.eqlIgnoreCase(name, "origin");
}

fn isLegacyHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "upgrade") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-key") or
        std.ascii.eqlIgnoreCase(name, "sec-websocket-accept");
}

fn rejectLegacyHeaders(headers: []const http3.Qpack.HeaderField) Error!void {
    for (headers) |header| {
        if (isLegacyHeader(header.name)) return error.InvalidHandshake;
    }
}

fn requiredHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) Error![]const u8 {
    return (try optionalHeader(headers, name)) orelse error.MissingHeader;
}

fn optionalHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, name)) continue;
        if (found != null) return error.InvalidHandshake;
        found = header.value;
    }
    return found;
}

fn validateFragmentedText(fragments: []const []const u8) bool {
    var validator: websocket.Utf8Validator = .{};
    for (fragments) |fragment| validator.feed(fragment) catch return false;
    validator.finish() catch return false;
    return true;
}

const FragmentRange = struct { start: usize, end: usize };

fn compressedFragmentRange(
    total_len: usize,
    frame_count: usize,
    index: usize,
) FragmentRange {
    std.debug.assert(frame_count != 0);
    std.debug.assert(index < frame_count);
    const base = total_len / frame_count;
    const extra = total_len % frame_count;
    const start = index * base + @min(index, extra);
    const len = base + @as(usize, if (index < extra) 1 else 0);
    return .{ .start = start, .end = start + len };
}

test "WebSocket RFC 9220 connections keep resumable writes compact" {
    if (@sizeOf(usize) == 8) {
        // Guard the WebSocket wrapper's footprint independently from the
        // embedded HTTP/3 runtime, whose protocol state and safety-only codec
        // storage evolve separately. No per-frame checkpoint lives here.
        const wrapper_size: usize = 1392;
        const client_size = @sizeOf(http3.runtime.HandshakeClient) + wrapper_size;
        const server_size = @sizeOf(http3.runtime.HandshakeServerSession) + wrapper_size;
        try std.testing.expectEqual(@as(usize, 296), @sizeOf(PendingWrite));
        try std.testing.expectEqual(client_size, @sizeOf(ClientConnection));
        try std.testing.expectEqual(server_size, @sizeOf(ServerConnection));
    }
}

pub const testing = if (builtin.is_test) struct {
    pub const FragmentRangeForTest = FragmentRange;

    pub fn pendingCloseProgress(
        connection: anytype,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_write.closeConst() orelse
            return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingPingProgress(
        connection: anytype,
    ) ?struct { committed: usize, total: usize } {
        const pending = connection.pending_write.pingConst() orelse
            return null;
        return .{ .committed = pending.committed, .total = pending.len };
    }

    pub fn pendingAutomaticControlProgress(
        connection: anytype,
    ) ?struct {
        opcode: websocket.Opcode,
        committed: usize,
        total: usize,
        retains_frame: bool,
    } {
        const pending = connection.pending_auto_control orelse return null;
        return .{
            .opcode = pending.opcode,
            .committed = pending.committed,
            .total = pending.len,
            .retains_frame = pending.frame != null,
        };
    }

    pub fn bufferInitial(connection: anytype, bytes: []const u8) !void {
        try message_buffer.appendAfterConsumed(
            &connection.inbuf,
            &connection.inbuf_consumed,
            connection.allocator,
            bytes,
        );
    }

    pub fn queueAutomaticControl(
        connection: anytype,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) !void {
        try connection.beginAutomaticControl(
            opcode,
            payload,
            .message,
            null,
        );
    }

    pub fn pendingMessageProgress(
        connection: anytype,
    ) ?MessageWriteProgress {
        const pending = switch (connection.pending_write) {
            .message => |value| value,
            else => return null,
        };
        return .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
        };
    }

    pub fn validateBinaryInPlace(
        connection: anytype,
        payload_len: usize,
    ) Error!void {
        return connection.validateBinaryInPlace(payload_len);
    }

    pub fn receiveStorageReleased(connection: anytype) bool {
        return connection.receiveFailed() and
            connection.inbuf.capacity == 0 and
            connection.inbuf.items.len == 0 and
            connection.inbuf_consumed == 0 and
            connection.message_assembler == null and
            !connection.message_into.active() and
            connection.message_frame_receive.header == null and
            connection.compression_receive.payload.capacity == 0 and
            connection.compression_receive.decoded.capacity == 0 and
            connection.compression_receive.context == null;
    }

    pub fn writeAborted(connection: anytype) bool {
        return connection.writeAborted();
    }

    pub fn outboundStorageReleased(connection: anytype) bool {
        return connection.pending_write.isNone() and
            connection.pending_auto_control == null and
            !connection.application_write_pending.load(.acquire) and
            !connection.automatic_write_pending.load(.acquire) and
            connection.compression_send.payload.capacity == 0 and
            connection.compression_send.encoder == null and
            connection.compression_send.context == null;
    }

    pub fn beginPendingMessage(
        connection: anytype,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) !void {
        try connection.beginPendingMessageLocked(opcode, payload);
    }

    pub fn beginPendingControl(
        connection: anytype,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) !void {
        return switch (opcode) {
            .ping => connection.beginPendingPingLocked(payload),
            .close => connection.beginPendingCloseLocked(payload),
            else => error.InvalidFrame,
        };
    }

    pub fn markPendingMessageCommitted(
        connection: anytype,
        committed: usize,
    ) void {
        const pending = connection.pending_write.messagePtr().?;
        std.debug.assert(committed <= pending.totalLen());
        pending.committed = committed;
    }

    pub fn markPendingControlCommitted(
        connection: anytype,
        opcode: websocket.Opcode,
        committed: usize,
    ) void {
        const pending = switch (opcode) {
            .ping => connection.pending_write.pingPtr().?,
            .close => connection.pending_write.closePtr().?,
            else => unreachable,
        };
        std.debug.assert(committed <= pending.len);
        pending.committed = committed;
    }

    pub fn failReceiveAndFinish(
        connection: anytype,
        code: websocket.CloseCode,
    ) void {
        if (connection.failReceive()) {
            connection.finishReceiveFailure(code, null);
        }
    }

    /// Split one message around control traffic without exposing raw frame
    /// construction as part of the production connection API.
    pub fn writeFrame(
        connection: anytype,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        return connection.writeFrame(opcode, payload, fin, false);
    }

    pub fn fragmentedTextIsValid(value: []const []const u8) bool {
        return validateFragmentedText(value);
    }

    pub fn compressedFragmentRangeForTest(
        total_len: usize,
        frame_count: usize,
        index: usize,
    ) FragmentRangeForTest {
        return compressedFragmentRange(total_len, frame_count, index);
    }
} else struct {};

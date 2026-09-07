//! RFC 9220 WebSocket over an authenticated HTTP/3 Extended CONNECT stream.
//!
//! WebSocket bytes are carried in HTTP/3 DATA frames while QUIC continues to
//! provide loss recovery and flow control. Complete and fragmented messages
//! share the RFC 6455 codec and no-context-takeover permessage-deflate engine.

const std = @import("std");
const builtin = @import("builtin");
const websocket = @import("../mod.zig");
const common = @import("common.zig");
const compression_scratch = @import("compression_scratch.zig");
const origin_policy = @import("origin_policy.zig");
const handshake_headers = @import("handshake/headers.zig");
const handshake_storage = @import("handshake/storage.zig");
const message_buffer = @import("message/buffer.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const http3 = @import("../../http3/mod.zig");
const rejection_drain_timeout: std.Io.Duration = .fromSeconds(5);
const max_payload_read_chunk: usize = 16 * 1024;

const IncomingDataKind = enum {
    none,
    binary,
    text,
    compressed_text,
};

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

pub const Error = websocket.Error || http3.runtime.Error || error{
    ConnectionClosed,
    ConcurrencyUnavailable,
    InvalidResponse,
    InvalidOrigin,
    InvalidSubprotocol,
    MessageTooLarge,
    UnexpectedPong,
    Timeout,
} || std.Io.RandomSecureError;

pub const ConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    protocols: []const []const u8 = &.{},
    origin: ?[]const u8 = null,
    extra_headers: []const http3.Qpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    compression_threshold: usize = 32,
    limits: common.Limits = .{},
};

/// URI-based RFC 9220 connection options. Authority, request target, DNS
/// destination, and default TLS server name are derived from the HTTPS URI.
pub const UriConnectOptions = struct {
    protocols: []const []const u8 = &.{},
    origin: ?[]const u8 = null,
    extra_headers: []const http3.Qpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
    compression_threshold: usize = 32,
    limits: common.Limits = .{},
    h3_limits: http3.runtime.Limits = .{},
    h3: http3.runtime.HandshakeClientOptions,
};

pub const AcceptOptions = struct {
    protocols: []const []const u8 = &.{},
    /// Reject the RFC 9220 handshake unless one of `protocols` was selected.
    require_subprotocol: bool = false,
    allowed_origins: []const []const u8 = &.{},
    extra_headers: []const http3.Qpack.HeaderField = &.{},
    enable_permessage_deflate: bool = false,
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
        if (!self.accepted()) return error.InvalidResponse;
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
        const negotiated_extension = try websocket.ExtensionNegotiation
            .validateResponse(try optionalHeader(
            self.response.headers,
            "sec-websocket-extensions",
        ));
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

        allocator: std.mem.Allocator,
        stream_id: u62,
        h3: switch (role) {
            .client => http3.runtime.HandshakeClient,
            .server => http3.runtime.HandshakeServerSession,
        },
        limits: common.Limits,
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
        compression_threshold: usize = 32,
        compression_send_max_window_bits: u8 = 15,
        compression_send: compression_scratch.SendScratch = .{},
        compression_receive: compression_scratch.Scratch = .{},
        /// Receive progress and public writers may run on separate threads.
        /// The send mutex orders wire writes; atomics make their shared Close
        /// observations race-free without holding that mutex across QUIC reads.
        close_sent: std.atomic.Value(bool) = .init(false),
        close_received: std.atomic.Value(bool) = .init(false),
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
                .limits = limits,
                .selected_protocol = selected_protocol,
                .permessage_deflate = negotiated_extension.permessage_deflate,
                .compression_threshold = compression_threshold,
                .compression_send_max_window_bits = switch (role) {
                    .client => negotiated_extension.client_max_window_bits orelse 15,
                    .server => negotiated_extension.server_max_window_bits orelse 15,
                },
            };
        }

        pub fn deinit(self: *Self) void {
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

        pub fn sendText(self: *Self, text: []const u8) Error!void {
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try common.validateOutgoingMessage(self.limits, .text, text);
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            try self.sendDataFrameValidatedLocked(.text, text);
        }

        pub fn sendBinary(self: *Self, payload: []const u8) Error!void {
            if (self.closeSent() or self.closeReceived()) {
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
            if (self.closeSent() or self.closeReceived()) {
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
            try self.writeParts(&.{ header, payload }, false);
        }

        /// Test the role/extension/state validation without constructing a
        /// live QUIC session. Kept private to the implementation module's
        /// testing facade below.
        fn validateBinaryInPlace(self: *const Self, payload_len: usize) Error!void {
            if (role != .client or self.permessage_deflate) {
                return error.InvalidFrame;
            }
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            try common.validateOutgoingMessageLength(
                self.limits,
                payload_len,
            );
        }

        /// Send two borrowed slices as one binary WebSocket message. The H3
        /// server path preserves both slices through HTTP/3 DATA framing; the
        /// client masks them through bounded stack storage while maintaining
        /// one continuous RFC 6455 mask offset. Compression consumes both
        /// slices directly without first joining caller plaintext.
        pub fn sendBinaryParts(
            self: *Self,
            first: []const u8,
            second: []const u8,
        ) Error!void {
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            const parts = [_][]const u8{ first, second };
            const payload_len = try common.validateOutgoingMessageParts(
                self.limits,
                &parts,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            if (self.permessage_deflate and
                payload_len >= self.compression_threshold)
            {
                const compressed = try self.compressMessageParts(
                    &parts,
                    payload_len,
                );
                if (compressed.len < payload_len) {
                    try self.writeFrameExtended(
                        .binary,
                        compressed,
                        true,
                        false,
                        true,
                    );
                    return;
                }
            }
            try self.writeBinaryParts(
                first,
                second,
                payload_len,
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
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            const total = try common.validateOutgoingFragments(
                self.limits,
                opcode,
                fragments,
            );
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            if (self.permessage_deflate and
                total >= self.compression_threshold)
            {
                try self.compression_send.prepare(self.allocator, total);
                const compressed = try websocket
                    .compressMessageFragmentsVortIntoWindowWithEncoder(
                    &self.compression_send.encoder.?,
                    &self.compression_send.payload,
                    fragments,
                    self.compression_send_max_window_bits,
                );
                if (compressed.len < total) {
                    try self.writeCompressedFragments(
                        opcode,
                        compressed,
                        fragments.len,
                    );
                    return;
                }
            }
            for (fragments, 0..) |fragment, index| {
                try self.writeFrame(
                    if (index == 0) opcode else .continuation,
                    fragment,
                    index + 1 == fragments.len,
                    false,
                );
            }
        }

        pub fn sendPing(self: *Self, payload: []const u8) Error!void {
            try self.sendControlFrame(.ping, payload);
        }

        pub fn sendPong(self: *Self, payload: []const u8) Error!void {
            try self.sendControlFrame(.pong, payload);
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
            {
                self.send_mutex.lockUncancelable(self.io());
                defer self.send_mutex.unlock(self.io());
                _ = try deadline_policy.usableAwake(self.io(), deadline);
                try self.sendControlFrameLocked(.ping, payload);
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
            return self.readPingEvent(payload, deadline);
        }

        pub fn sendClose(
            self: *Self,
            code: websocket.CloseCode,
            reason: []const u8,
        ) Error!void {
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

        fn echoCloseFrame(self: *Self, payload: []const u8) Error!void {
            self.send_mutex.lockUncancelable(self.io());
            defer self.send_mutex.unlock(self.io());
            if (!self.closeSent()) {
                try self.sendControlFrameLocked(.close, payload);
            }
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
            defer frame.deinit(self.allocator);
            if (frame.header.opcode != .close) return error.InvalidFrame;
            return websocket.parseClosePayloadOwned(
                self.allocator,
                frame.payload,
            );
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
            defer frame.deinit(self.allocator);
            if (frame.header.opcode != .close) return error.InvalidFrame;
            return websocket.parseClosePayloadOwned(
                self.allocator,
                frame.payload,
            );
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
            if (!self.closeSent()) {
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
                    if (!self.closeSent()) {
                        try self.sendControlFrameLocked(.close, payload);
                    }
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
            if (!self.closeSent()) return error.InvalidFrame;
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

        fn receiveMessageInternal(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!common.OwnedMessage {
            errdefer |err| self.closeAfterReceiveError(err);
            if (self.message_into.active()) return error.InvalidFrame;
            if (self.message_assembler == null) {
                self.message_assembler = websocket.MessageAssembler.initLimited(
                    self.allocator,
                    self.limits.max_message_bytes,
                );
            }
            while (true) {
                var frame = try self.receiveFrameInternal(deadline);
                defer frame.deinit(self.allocator);
                switch (frame.header.opcode) {
                    .ping, .pong => continue,
                    .close => return error.ConnectionClosed,
                    else => {
                        const assembled = (try self.message_assembler.?.feedUtf8Validated(
                            frame,
                            self.incoming_text_utf8,
                        )) orelse
                            continue;
                        self.message_assembler.?.deinit();
                        self.message_assembler = null;
                        if (assembled.compressed) {
                            errdefer self.allocator.free(assembled.payload);
                            const payload = try websocket.decompressMessage(
                                self.allocator,
                                assembled.payload,
                                self.limits.max_message_bytes,
                            );
                            self.allocator.free(assembled.payload);
                            errdefer self.allocator.free(payload);
                            if (assembled.opcode == .text and
                                !std.unicode.utf8ValidateSlice(payload))
                            {
                                return error.InvalidUtf8;
                            }
                            return .{
                                .opcode = assembled.opcode,
                                .payload = payload,
                                .was_compressed = true,
                            };
                        }
                        return .{
                            .opcode = assembled.opcode,
                            .payload = assembled.payload,
                        };
                    },
                }
            }
        }

        fn resetMessageIntoAfterError(self: *Self, err: anyerror) void {
            // Timeout is resumable because `inbuf`, the completed-fragment
            // offset, and compressed bytes are connection-owned. All other
            // failures terminate this caller-buffer operation; retaining its
            // borrowed pointer would make a later receive spuriously require
            // memory that the caller no longer promised to keep alive.
            if (err != error.Timeout) {
                self.message_into.reset();
                self.message_frame_receive.reset();
            }
        }

        /// Receive one complete RFC 9220 message into caller-owned storage.
        /// The output must cover `limits.max_message_bytes`, allowing timeout
        /// recovery to retain only offsets and compressed scratch rather than
        /// allocating an intermediate uncompressed message.
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
            if (self.message_assembler != null) return error.InvalidFrame;
            if (out.len < self.limits.max_message_bytes) {
                return error.BufferTooShort;
            }
            try self.message_into.validateOutput(out);
            errdefer |err| self.resetMessageIntoAfterError(err);
            errdefer |err| self.closeAfterReceiveError(err);

            var control_storage: [125]u8 = undefined;
            while (true) {
                const frame = try self.receiveMessageFrameIntoInternal(
                    out,
                    &control_storage,
                    deadline,
                );
                switch (frame.header.opcode) {
                    .ping, .pong => continue,
                    .close => return error.ConnectionClosed,
                    .text, .binary => {
                        std.debug.assert(self.message_into.active());
                    },
                    .continuation => {
                        std.debug.assert(self.message_into.active());
                    },
                    else => return error.InvalidFrame,
                }

                if (!frame.header.fin) continue;

                const message_opcode = self.message_into.opcode orelse
                    return error.InvalidFrame;
                const was_compressed = self.message_into.compressed;
                const payload = if (was_compressed)
                    try websocket.decompressMessageInto(
                        out[0..self.limits.max_message_bytes],
                        self.compression_receive
                            .payload.items[0..self.message_into.written],
                        self.compression_receive.payload.allocatedSlice(),
                        self.compression_receive.flate_window.?,
                    )
                else
                    out[0..self.message_into.written];
                if (self.message_into.payloadNeedsFinalUtf8Validation() and
                    !std.unicode.utf8ValidateSlice(payload))
                {
                    return error.InvalidUtf8;
                }
                self.message_into.reset();
                return .{
                    .opcode = message_opcode,
                    .payload = payload,
                    .was_compressed = was_compressed,
                };
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
            const total_len = std.math.add(
                usize,
                header.header_len,
                payload_len,
            ) catch return error.PayloadTooLarge;
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
                .ping => {
                    if (!self.closeSent()) try self.sendPong(frame.payload);
                },
                .close => {
                    self.close_received.store(true, .release);
                    if (!self.closeSent()) try self.echoCloseFrame(frame.payload);
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
                    websocket.applyMask(
                        destination[state.payload_written..][0..read],
                        mask,
                        state.payload_written,
                    );
                }
                if (state.message_kind == .text) {
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
            try self.compression_receive.prepare(
                self.allocator,
                self.limits.max_message_bytes,
            );
        }

        pub fn receiveFrame(self: *Self) Error!websocket.Frame {
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            return self.receiveFrameInternal(null);
        }

        pub fn receiveFrameWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!websocket.Frame {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            return self.receiveFrameInternal(.fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        pub fn receiveFrameWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!websocket.Frame {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            if (self.message_assembler != null or self.message_into.active()) {
                return error.InvalidFrame;
            }
            return self.receiveFrameInternal(deadline);
        }

        fn readPingEvent(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!PingEvent {
            while (true) {
                var frame = try self.receiveFrameInternal(deadline);
                switch (frame.header.opcode) {
                    .ping => {
                        frame.deinit(self.allocator);
                        continue;
                    },
                    .pong => {
                        defer frame.deinit(self.allocator);
                        if (!std.mem.eql(u8, frame.payload, payload)) {
                            return error.UnexpectedPong;
                        }
                        return .{ .pong = {} };
                    },
                    .close => {
                        defer frame.deinit(self.allocator);
                        return .{ .closed = try websocket.parseClosePayloadOwned(
                            self.allocator,
                            frame.payload,
                        ) };
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

        fn readCloseHandshakeEvent(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!CloseHandshakeEvent {
            while (true) {
                var frame = try self.receiveFrameInternal(deadline);
                switch (frame.header.opcode) {
                    .ping, .pong => {
                        frame.deinit(self.allocator);
                        continue;
                    },
                    .close => {
                        defer frame.deinit(self.allocator);
                        return .{ .closed = try websocket.parseClosePayloadOwned(
                            self.allocator,
                            frame.payload,
                        ) };
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
        ) Error!websocket.Frame {
            errdefer |err| self.closeAfterReceiveError(err);
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
            const frame = try websocket.parseFrameWithHeader(
                self.allocator,
                available[0..total_len],
                header,
                options,
            );
            self.discardBuffered(frame.consumed);
            switch (frame.header.opcode) {
                .ping => {
                    if (!self.closeSent()) try self.sendPong(frame.payload);
                },
                .close => {
                    self.close_received.store(true, .release);
                    if (!self.closeSent()) try self.echoCloseFrame(frame.payload);
                },
                else => {},
            }
            return frame;
        }

        fn closeAfterReceiveError(self: *Self, err: anyerror) void {
            const code = common.closeCodeForReceiveError(err) orelse return;
            // Nested receive helpers can observe the same error. Emit at most
            // one failure Close while preserving the original receive error.
            if (self.closeSent()) return;
            self.sendClose(code, "") catch {};
        }

        fn sendDataFrameValidatedLocked(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
        ) Error!void {
            if (self.closeSent() or self.closeReceived()) {
                return error.ConnectionClosed;
            }
            if (self.permessage_deflate and
                payload.len >= self.compression_threshold)
            {
                const compressed = try self.compressMessage(payload);
                if (compressed.len < payload.len) {
                    try self.writeFrameExtended(
                        opcode,
                        compressed,
                        true,
                        false,
                        true,
                    );
                    return;
                }
            }
            try self.writeFrame(opcode, payload, true, false);
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
            if (self.closeSent()) return error.ConnectionClosed;
            try self.writeFrame(opcode, payload, true, opcode == .close);
            if (opcode == .close) self.close_sent.store(true, .release);
        }

        fn closeSent(self: *const Self) bool {
            return self.close_sent.load(.acquire);
        }

        fn closeReceived(self: *const Self) bool {
            return self.close_received.load(.acquire);
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

        fn writeBinaryParts(
            self: *Self,
            first: []const u8,
            second: []const u8,
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
                    &.{ first, second },
                    mask,
                    false,
                );
                return;
            }

            // The HTTP/3 body API accepts arbitrary slices and emits one
            // continuous byte stream, so the server can retain both borrowed
            // inputs without allocating a plaintext join.
            try self.writeParts(&.{ header, first, second }, false);
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
            try self.compression_send.prepare(self.allocator, payload_len);
            return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
                &self.compression_send.encoder.?,
                &self.compression_send.payload,
                parts,
                self.compression_send_max_window_bits,
            );
        }

        fn writeCompressedFragments(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
            frame_count: usize,
        ) Error!void {
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

        var h3_options = options.h3;
        h3_options.session.local_settings.enable_connect_protocol = true;
        if (h3_options.handshake.server_name == null) {
            h3_options.handshake.server_name = endpoint.tls_host;
        }
        var h3_client = if (deadline) |absolute|
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
                .origin = options.origin,
                .extra_headers = options.extra_headers,
                .enable_permessage_deflate = options.enable_permessage_deflate,
                .compression_threshold = options.compression_threshold,
                .limits = options.limits,
            },
            deadline,
            null,
        );
    }
};

fn connectAttemptEstablishedBefore(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeClient,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
    restore_to: ?*http3.runtime.HandshakeClient,
) Error!ConnectAttempt {
    try validateClientExtraHeaders(options.extra_headers);
    try validateProtocols(options.protocols);
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
    const field_count = std.math.add(
        usize,
        2 + @as(usize, @intFromBool(protocol_value.value.len != 0)) +
            @as(usize, @intFromBool(options.origin != null)) +
            @as(usize, @intFromBool(options.enable_permessage_deflate)),
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
    if (options.enable_permessage_deflate) {
        fields[field_index] = .{
            .name = "sec-websocket-extensions",
            .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        };
        field_index += 1;
    }
    @memcpy(fields[field_index..], options.extra_headers);
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
    errdefer request.head.deinit(allocator);
    errdefer h3.rejectRequest(request.stream_id) catch {};
    try validateRequestHandshake(
        request.head,
        options.allowed_origins,
    );
    const selected_protocol = try selectSubprotocol(
        allocator,
        request.head.headers,
        options.protocols,
    );
    errdefer if (selected_protocol) |protocol| allocator.free(protocol);
    if (options.require_subprotocol and selected_protocol == null) {
        return error.InvalidSubprotocol;
    }
    const selected_extension = try acceptExtensions(
        allocator,
        request.head.headers,
        options.enable_permessage_deflate,
    );
    errdefer if (selected_extension) |extension| allocator.free(extension);
    const negotiated_extension = if (selected_extension) |extension|
        try websocket.ExtensionNegotiation.validateResponse(extension)
    else
        websocket.ExtensionNegotiation{};
    try validateServerExtraHeaders(options.extra_headers);
    const owned_h3 = h3.*;
    h3.* = undefined;
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
        self.finish(false);
    }

    fn restoreSession(self: *PendingUpgrade) void {
        std.debug.assert(self.restore_to != null);
        self.finish(false);
    }

    fn finish(self: *PendingUpgrade, drain_before_close: bool) void {
        const allocator = self.allocator;
        self.request.head.deinit(allocator);
        if (self.selected_protocol) |protocol| allocator.free(protocol);
        if (self.selected_extension) |extension| allocator.free(extension);
        if (self.restore_to) |destination| {
            destination.* = self.h3;
        } else {
            if (drain_before_close) {
                if (self.deadline) |absolute| {
                    self.h3.waitForRecoveryIdleWithDeadline(absolute) catch {};
                } else {
                    self.h3.waitForRecoveryIdleWithTimeout(
                        rejection_drain_timeout,
                    ) catch {};
                }
            }
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
        try self.h3.startResponse(
            self.request.stream_id,
            .{
                .status = 200,
                .headers = response_headers,
                .request_method = "CONNECT",
                .extended_connect = true,
            },
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

    /// Reject this CONNECT stream with an HTTP/3 response entity. Client-side
    /// retention is governed by `Limits.max_rejection_body_bytes`.
    pub fn rejectWithBody(
        self: *PendingUpgrade,
        status: u16,
        response_headers: []const http3.Qpack.HeaderField,
        body: []const u8,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (status < 300 or status > 599) return error.InvalidStatus;
        try validateServerExtraHeaders(response_headers);
        try validateServerExtraHeaders(trailers);
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
        self.finish(true);
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
    if (!std.mem.eql(u8, request.method, "CONNECT") or
        !std.mem.eql(u8, request.scheme, "https") or
        request.authority == null or request.path.len == 0 or
        !std.mem.eql(
            u8,
            try requiredHeader(request.headers, ":protocol"),
            "websocket",
        ) or
        !std.mem.eql(
            u8,
            try requiredHeader(request.headers, "sec-websocket-version"),
            "13",
        ))
    {
        return error.InvalidHandshake;
    }
    try rejectLegacyHeaders(request.headers);
    try validateOrigin(request.headers, allowed_origins);
}

fn validateServerHandshake(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
    offered_protocols: []const []const u8,
) Error!?[]u8 {
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
    if (offered_protocols.len != 0) return error.InvalidSubprotocol;
    return null;
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
    for (protocols) |protocol| {
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
    }
}

fn acceptExtensions(
    allocator: std.mem.Allocator,
    headers: []const http3.Qpack.HeaderField,
    enabled: bool,
) Error!?[]u8 {
    if (!enabled) return null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-extensions",
        )) continue;
        if (try websocket.ExtensionNegotiation.accept(
            allocator,
            header.value,
            true,
        )) |accepted| return accepted;
    }
    return null;
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

pub const testing = if (builtin.is_test) struct {
    pub const FragmentRangeForTest = FragmentRange;

    pub fn validateBinaryInPlace(
        connection: anytype,
        payload_len: usize,
    ) Error!void {
        return connection.validateBinaryInPlace(payload_len);
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

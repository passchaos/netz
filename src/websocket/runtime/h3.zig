//! RFC 9220 WebSocket over an authenticated HTTP/3 Extended CONNECT stream.
//!
//! WebSocket bytes are carried in HTTP/3 DATA frames while QUIC continues to
//! provide loss recovery and flow control. Complete and fragmented messages
//! share the RFC 6455 codec and no-context-takeover permessage-deflate engine.

const std = @import("std");
const websocket = @import("../mod.zig");
const common = @import("common.zig");
const compression_scratch = @import("compression_scratch.zig");
const origin_policy = @import("origin_policy.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const http3 = @import("../../http3/mod.zig");

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
/// metadata remains owned and inspectable until `deinit` or `requireAccepted`.
pub const ConnectAttempt = struct {
    h3: ?http3.runtime.HandshakeClient,
    stream_id: u62,
    response: http3.DecodedResponseHead,
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

    pub fn deinit(self: *ConnectAttempt) void {
        const allocator = self.h3.?.allocator;
        self.response.deinit(allocator);
        if (self.h3) |*client| client.deinit();
        self.* = undefined;
    }

    pub fn requireAccepted(self: *ConnectAttempt) Error!ClientConnection {
        if (!self.accepted()) return error.InvalidResponse;
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
        message_assembler: ?websocket.MessageAssembler = null,
        message_into: common.MessageIntoReceiveState = .{},
        permessage_deflate: bool = false,
        compression_threshold: usize = 32,
        compression_send_max_window_bits: u8 = 15,
        compression_send: compression_scratch.SendScratch = .{},
        compression_receive: compression_scratch.Scratch = .{},
        close_sent: bool = false,
        close_received: bool = false,
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
            if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
            try self.sendDataFrame(.text, text);
        }

        pub fn sendBinary(self: *Self, payload: []const u8) Error!void {
            try self.sendDataFrame(.binary, payload);
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
            if (self.close_sent or self.close_received) {
                return error.ConnectionClosed;
            }
            const payload_len = std.math.add(
                usize,
                first.len,
                second.len,
            ) catch return error.PayloadTooLarge;
            if (payload_len > self.limits.max_frame_bytes or
                payload_len > self.limits.max_message_bytes)
            {
                return error.MessageTooLarge;
            }
            if (self.permessage_deflate and
                payload_len >= self.compression_threshold)
            {
                const parts = [_][]const u8{ first, second };
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
            if (opcode != .text and opcode != .binary) {
                return error.InvalidFrame;
            }
            if (self.close_sent or self.close_received) {
                return error.ConnectionClosed;
            }
            if (fragments.len == 0) return error.InvalidFrame;
            const total = try fragmentedPayloadLen(fragments);
            for (fragments) |fragment| {
                if (fragment.len > self.limits.max_frame_bytes) {
                    return error.MessageTooLarge;
                }
            }
            if (total > self.limits.max_message_bytes) {
                return error.MessageTooLarge;
            }
            if (opcode == .text and !validateFragmentedText(fragments)) {
                return error.InvalidUtf8;
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
        /// one total budget across interleaved application frames.
        pub fn pingWithDeadline(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) Error!PingEvent {
            _ = try deadline_policy.usableAwake(self.io(), deadline);
            try self.sendPing(payload);
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
            try self.sendCloseFrame(.{ .code = code, .reason = reason });
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
            try self.sendControlFrame(.close, payload);
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
            if (!self.close_sent) {
                try self.sendCloseFrame(close_frame);
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
            if (!self.close_sent) return error.InvalidFrame;
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
                        const assembled = (try self.message_assembler.?.feed(frame)) orelse
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
            if (err != error.Timeout) self.message_into.reset();
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

            var control_storage: [125]u8 = undefined;
            while (true) {
                const frame_out = if (self.message_into.compressed)
                    self.compression_receive
                        .payload.items[self.message_into.written..]
                else
                    out[self.message_into.written..];
                const frame = try self.receiveFrameIntoInternal(
                    frame_out,
                    &control_storage,
                    deadline,
                );
                switch (frame.header.opcode) {
                    .ping, .pong => continue,
                    .close => return error.ConnectionClosed,
                    .text, .binary => {
                        if (self.message_into.active()) {
                            return error.InvalidFrame;
                        }
                        self.message_into.begin(
                            out,
                            frame.header.opcode,
                            frame.header.rsv1,
                        );
                        if (self.message_into.compressed and
                            !self.permessage_deflate)
                        {
                            return error.UnexpectedRsv;
                        }
                        if (self.message_into.compressed) {
                            try self.ensureCompressionReceiveScratch();
                            // The first frame was decoded before RSV1 selected
                            // compressed scratch. Copy it once; continuation
                            // frames decode directly into retained storage.
                            if (frame.payload.len != 0) {
                                @memcpy(
                                    self.compression_receive
                                        .payload.items[0..frame.payload.len],
                                    frame.payload,
                                );
                            }
                        }
                    },
                    .continuation => {
                        if (!self.message_into.active()) {
                            return error.InvalidFrame;
                        }
                        if (frame.header.rsv1) return error.UnexpectedRsv;
                    },
                    else => return error.InvalidFrame,
                }

                const next_written = std.math.add(
                    usize,
                    self.message_into.written,
                    frame.payload.len,
                ) catch return error.PayloadTooLarge;
                if (next_written > self.limits.max_message_bytes) {
                    return error.PayloadTooLarge;
                }
                self.message_into.written = next_written;
                if (!frame.header.fin) continue;

                const message_opcode = self.message_into.opcode orelse
                    return error.InvalidFrame;
                const payload = if (self.message_into.compressed)
                    try websocket.decompressMessageInto(
                        out[0..self.limits.max_message_bytes],
                        self.compression_receive
                            .payload.items[0..self.message_into.written],
                        self.compression_receive.payload.allocatedSlice(),
                        self.compression_receive.flate_window.?,
                    )
                else
                    out[0..self.message_into.written];
                if (message_opcode == .text and
                    !std.unicode.utf8ValidateSlice(payload))
                {
                    return error.InvalidUtf8;
                }
                self.message_into.reset();
                return .{ .opcode = message_opcode, .payload = payload };
            }
        }

        fn receiveFrameIntoInternal(
            self: *Self,
            out: []u8,
            control_out: *[125]u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!websocket.BorrowedFrame {
            if (self.close_sent and self.close_received) {
                return error.ConnectionClosed;
            }
            try self.ensureBuffered(2, deadline);
            const second = self.inbuf.items[1];
            var header_len: usize = 2;
            const length_code = second & 0x7f;
            if (length_code == 126) {
                header_len += 2;
            } else if (length_code == 127) {
                header_len += 8;
            }
            if ((second & 0x80) != 0) header_len += 4;
            try self.ensureBuffered(header_len, deadline);

            const header = try websocket.FrameHeader.parse(self.inbuf.items);
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
            try self.ensureBuffered(total_len, deadline);
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
            const frame = try websocket.parseFrameInto(
                payload_out,
                self.inbuf.items[0..total_len],
                options,
            );
            self.discardBuffered(frame.consumed);
            switch (frame.header.opcode) {
                .ping => {
                    if (!self.close_sent) try self.sendPong(frame.payload);
                },
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) {
                        try self.sendControlFrame(.close, frame.payload);
                    }
                },
                else => {},
            }
            return frame;
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
            if (self.close_sent and self.close_received) {
                return error.ConnectionClosed;
            }
            try self.ensureBuffered(2, deadline);
            const second = self.inbuf.items[1];
            var header_len: usize = 2;
            const length_code = second & 0x7f;
            if (length_code == 126) {
                header_len += 2;
            } else if (length_code == 127) {
                header_len += 8;
            }
            if ((second & 0x80) != 0) header_len += 4;
            try self.ensureBuffered(header_len, deadline);

            const header = try websocket.FrameHeader.parse(self.inbuf.items);
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
            try self.ensureBuffered(total_len, deadline);
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
            const frame = try websocket.parseFrameOptions(
                self.allocator,
                self.inbuf.items[0..total_len],
                options,
            );
            self.discardBuffered(frame.consumed);
            switch (frame.header.opcode) {
                .ping => {
                    if (!self.close_sent) try self.sendPong(frame.payload);
                },
                .close => {
                    self.close_received = true;
                    if (!self.close_sent) {
                        try self.sendControlFrame(.close, frame.payload);
                    }
                },
                else => {},
            }
            return frame;
        }

        fn sendDataFrame(
            self: *Self,
            opcode: websocket.Opcode,
            payload: []const u8,
        ) Error!void {
            if (self.close_sent or self.close_received) {
                return error.ConnectionClosed;
            }
            if (payload.len > self.limits.max_frame_bytes or
                payload.len > self.limits.max_message_bytes)
            {
                return error.MessageTooLarge;
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
            if (self.close_sent) return error.ConnectionClosed;
            try self.writeFrame(opcode, payload, true, opcode == .close);
            if (opcode == .close) self.close_sent = true;
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
            while (self.inbuf.items.len < required) {
                if (self.receive_finished) return error.ConnectionClosed;
                var scratch: [16 * 1024]u8 = undefined;
                const count = try self.readPayloadChunk(&scratch, deadline);
                if (count == 0) continue;
                try self.inbuf.appendSlice(
                    self.allocator,
                    scratch[0..count],
                );
            }
        }

        fn readPayloadChunk(
            self: *Self,
            out: []u8,
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
                        try self.h3.receiveRequestEventWithDeadline(absolute)
                    else
                        try self.h3.receiveRequestEvent();
                    defer event.deinit(self.allocator);
                    switch (event) {
                        .reset => return error.ConnectionClosed,
                        .message => |message| {
                            if (message.stream_id != self.stream_id) {
                                return error.InvalidHandshake;
                            }
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
            if (len == self.inbuf.items.len) {
                self.inbuf.clearRetainingCapacity();
                return;
            }
            const remaining = self.inbuf.items[len..];
            @memmove(self.inbuf.items[0..remaining.len], remaining);
            self.inbuf.shrinkRetainingCapacity(remaining.len);
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
        h3.options.local_settings.enable_connect_protocol = true;
        return connectEstablishedBefore(allocator, h3, options, null);
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
        const absolute = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            deadline,
        );
        h3.options.local_settings.enable_connect_protocol = true;
        return connectEstablishedBefore(
            allocator,
            h3,
            options,
            absolute,
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
        return connectAttemptEstablishedBefore(allocator, &h3, options, null);
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
        );
    }
};

fn connectEstablishedBefore(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeClient,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ClientConnection {
    var attempt = try connectAttemptEstablishedBefore(
        allocator,
        h3,
        options,
        deadline,
    );
    errdefer attempt.deinit();
    return attempt.requireAccepted();
}

fn connectAttemptEstablishedBefore(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeClient,
    options: ConnectOptions,
    deadline: ?std.Io.Clock.Timestamp,
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
    var fields: std.ArrayList(http3.Qpack.HeaderField) = .empty;
    defer fields.deinit(allocator);
    try fields.append(allocator, .{
        .name = ":protocol",
        .value = "websocket",
    });
    try fields.append(allocator, .{
        .name = "sec-websocket-version",
        .value = "13",
    });
    var protocol_value: std.ArrayList(u8) = .empty;
    defer protocol_value.deinit(allocator);
    for (options.protocols, 0..) |protocol, index| {
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
        if (index != 0) try protocol_value.appendSlice(allocator, ", ");
        try protocol_value.appendSlice(allocator, protocol);
    }
    if (protocol_value.items.len != 0) {
        try fields.append(allocator, .{
            .name = "sec-websocket-protocol",
            .value = protocol_value.items,
        });
    }
    if (options.origin) |origin| {
        try fields.append(allocator, .{ .name = "origin", .value = origin });
    }
    if (options.enable_permessage_deflate) {
        try fields.append(allocator, .{
            .name = "sec-websocket-extensions",
            .value = "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        });
    }
    try fields.appendSlice(allocator, options.extra_headers);
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
        .headers = fields.items,
    }, null);
    var response = if (deadline) |absolute|
        try receiveResponseHeadWithDeadline(h3, stream_id, absolute)
    else
        try receiveResponseHead(h3, stream_id);
    errdefer response.deinit(allocator);
    if (!h3.control.settings.peer.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const owned_h3 = h3.*;
    h3.* = undefined;
    return .{
        .h3 = owned_h3,
        .stream_id = stream_id,
        .response = response,
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
        var h3 = try self.transport.accept();
        errdefer h3.deinit();
        return acceptServerSessionBefore(
            self.transport.allocator,
            &h3,
            options,
            null,
        );
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
        var h3 = try self.transport.acceptWithDeadline(absolute);
        errdefer h3.deinit();
        return acceptServerSessionBefore(
            self.transport.allocator,
            &h3,
            options,
            absolute,
        );
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

    pub fn acceptSession(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
    ) Error!ServerConnection {
        return acceptServerSessionBefore(allocator, h3, options, null);
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
        return acceptServerSessionBefore(
            allocator,
            h3,
            options,
            absolute,
        );
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
};

fn acceptServerSessionBefore(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeServerSession,
    options: AcceptOptions,
    deadline: ?std.Io.Clock.Timestamp,
) Error!ServerConnection {
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
    defer request.head.deinit(allocator);
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
    const selected_extension = try acceptExtensions(
        allocator,
        request.head.headers,
        options.enable_permessage_deflate,
    );
    defer if (selected_extension) |extension| allocator.free(extension);
    const negotiated_extension = if (selected_extension) |extension|
        try websocket.ExtensionNegotiation.validateResponse(extension)
    else
        websocket.ExtensionNegotiation{};
    try validateServerExtraHeaders(options.extra_headers);
    var headers: std.ArrayList(http3.Qpack.HeaderField) = .empty;
    defer headers.deinit(allocator);
    if (selected_protocol) |protocol| {
        try headers.append(allocator, .{
            .name = "sec-websocket-protocol",
            .value = protocol,
        });
    }
    if (selected_extension) |extension| {
        try headers.append(allocator, .{
            .name = "sec-websocket-extensions",
            .value = extension,
        });
    }
    try headers.appendSlice(allocator, options.extra_headers);
    if (deadline) |absolute| {
        // Request validation and extension selection remain within the same
        // admission budget; never send a successful response after expiry.
        _ = try deadline_policy.usableAwake(
            h3.established.connection.endpoint.io,
            absolute,
        );
    }
    try h3.startResponse(
        request.stream_id,
        .{
            .status = 200,
            .headers = headers.items,
            .request_method = "CONNECT",
            .extended_connect = true,
        },
        null,
    );
    const owned_h3 = h3.*;
    h3.* = undefined;
    return .init(
        allocator,
        request.stream_id,
        owned_h3,
        options.limits,
        selected_protocol,
        negotiated_extension,
        options.compression_threshold,
    );
}

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
                const owned = head.response;
                event = .finished;
                return owned;
            },
            else => return error.InvalidHandshake,
        }
    }
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
    try validateProtocols(supported);
    var selected: ?[]const u8 = null;
    var seen: std.ArrayList([]const u8) = .empty;
    defer seen.deinit(allocator);
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(
            header.name,
            "sec-websocket-protocol",
        )) continue;
        var requested = std.mem.splitScalar(u8, header.value, ',');
        while (requested.next()) |raw| {
            const candidate = std.mem.trim(u8, raw, " \t");
            if (!websocket.validSubprotocolToken(candidate)) {
                return error.InvalidSubprotocol;
            }
            for (seen.items) |previous| {
                if (std.mem.eql(u8, previous, candidate)) {
                    return error.InvalidSubprotocol;
                }
            }
            try seen.append(allocator, candidate);
            if (selected != null) continue;
            for (supported) |protocol| {
                if (std.mem.eql(u8, candidate, protocol)) {
                    selected = protocol;
                    break;
                }
            }
        }
    }
    if (selected) |protocol| return try allocator.dupe(u8, protocol);
    return null;
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

fn fragmentedPayloadLen(fragments: []const []const u8) Error!usize {
    var total: usize = 0;
    for (fragments) |fragment| {
        total = std.math.add(usize, total, fragment.len) catch
            return error.PayloadTooLarge;
    }
    return total;
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

pub const testing = struct {
    pub const FragmentRangeForTest = FragmentRange;

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
};

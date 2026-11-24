//! HTTP/2 WebSocket connection state over RFC 8441 streams.

const std = @import("std");
const websocket = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const AllocatingMessageReceiver = runtime.AllocatingMessageReceiver;
const CloseHandshakeEvent = runtime.CloseHandshakeEvent;
const Connection = runtime.Connection;
const Error = runtime.Error;
const IncomingDataKind = runtime.IncomingDataKind;
const Limits = runtime.Limits;
const Message = runtime.Message;
const MessageFrameReceiveState = runtime.MessageFrameReceiveState;
const MessageIntoReceiveState = runtime.MessageIntoReceiveState;
const MessageWriteProgress = runtime.MessageWriteProgress;
const OwnedMessage = runtime.OwnedMessage;
const PendingAutomaticControl = runtime.PendingAutomaticControl;
const PendingControlFrame = runtime.PendingControlFrame;
const PendingH2Message = runtime.PendingH2Message;
const PendingH2Write = runtime.PendingH2Write;
const PingEvent = runtime.PingEvent;
const Role = runtime.Role;
const Server = runtime.Server;
const automatic_control = runtime.automatic_control;
const canSendOpcode = runtime.canSendOpcode;
const closeAfterReceiveError = runtime.closeAfterReceiveError;
const common = runtime.common;
const compressedFragmentRange = runtime.compressedFragmentRange;
const compression_scratch = runtime.compression_scratch;
const control_admission = runtime.control_admission;
const copyMessagePartsAt = runtime.copyMessagePartsAt;
const deadline_policy = runtime.deadline_policy;
const default_compression_threshold = runtime.default_compression_threshold;
const ensureIncomingFrameBuffered = runtime.ensureIncomingFrameBuffered;
const failReceive = runtime.failReceive;
const fragmentedWireLen = runtime.fragmentedWireLen;
const frame_validation = runtime.frame_validation;
const http2_runtime = runtime.http2_runtime;
const masked_write_scratch_len = runtime.masked_write_scratch_len;
const message_buffer = runtime.message_buffer;
const message_state = runtime.message_state;
const ping_control = runtime.ping_control;
const receiveMessageIntoDirectConnection = runtime.receiveMessageIntoDirectConnection;
const receive_cleanup = runtime.receive_cleanup;
const timed_mutex = runtime.timed_mutex;
const tls_stream = runtime.tls_stream;
const writeMaskedTunnelPayloadSlices = runtime.writeMaskedTunnelPayloadSlices;
const writeMaskedTunnelPayloadSlicesWithWriter = runtime.writeMaskedTunnelPayloadSlicesWithWriter;
const writeUnmaskedTunnelPayloadSlices = runtime.writeUnmaskedTunnelPayloadSlices;

pub const H2Connection = struct {
    const PingReader = ping_control.Reader(.{
        .Error = Error,
        .receive = receiveFrameAutoInternal,
        .io = struct {
            fn get(connection: *const H2Connection) std.Io {
                return connection.tunnel.connection.io;
            }
        }.get,
    });
    allocator: std.mem.Allocator,
    tunnel: http2_runtime.Tunnel,
    tunnel_owned: bool = false,
    role: Role,
    limits: common.MessageLimits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    inbuf_consumed: usize = 0,
    send_mutex: std.Io.Mutex = .init,
    /// RFC 8441 keeps the same split receive/write ownership as HTTP/1.
    close_sent: std.atomic.Value(bool) = .init(false),
    close_received: std.atomic.Value(bool) = .init(false),
    /// Terminal protocol errors and abrupt END_STREAM/reset release
    /// receive-only storage immediately.
    receive_failed: std.atomic.Value(bool) = .init(false),
    /// Set when a retained outbound WebSocket frame forces this CONNECT stream
    /// to be reset instead of appending a protocol Close after a partial frame.
    write_aborted: std.atomic.Value(bool) = .init(false),
    receive_abort_pending: std.atomic.Value(bool) = .init(false),
    application_write_pending: std.atomic.Value(bool) = .init(false),
    automatic_write_pending: std.atomic.Value(bool) = .init(false),
    /// Receive-owned control storage is published separately from send state.
    automatic_control_waiting: std.atomic.Value(bool) = .init(false),
    automatic_control_admission: ?control_admission.Admission = null,
    incoming_data_kind: IncomingDataKind = .none,
    incoming_text_utf8: websocket.Utf8Validator = .{},
    incoming_frame_validated: usize = 0,
    message_assembler: ?websocket.MessageAssembler = null,
    message_into: MessageIntoReceiveState = .{},
    message_frame_receive: MessageFrameReceiveState = .{},
    /// A bounded application message, Ping, or Close may own the HTTP/2 DATA
    /// sequence. These transaction shapes are mutually exclusive.
    pending_write: PendingH2Write = .none,
    /// Automatic Pong/Close transaction retained independently from an
    /// application-initiated Ping or Close.
    pending_auto_control: ?PendingAutomaticControl = null,
    pending_tunnel_data: ?http2_runtime.OwnedTunnelData = null,
    pending_tunnel_data_offset: usize = 0,
    receive_finished: bool = false,
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,
    compression_send_context_takeover: bool = false,
    compression_receive_context_takeover: bool = false,
    compression_threshold: usize = default_compression_threshold,
    compression_send_max_window_bits: u8 = 15,
    compression_receive_max_window_bits: u8 = 15,
    compression_send: compression_scratch.SendScratch = .{},
    compression_receive: compression_scratch.Scratch = .{},

    pub fn init(
        allocator: std.mem.Allocator,
        tunnel: http2_runtime.Tunnel,
        role: Role,
        limits: Limits,
        selected_protocol: ?[]u8,
        negotiated_extension: websocket.ExtensionNegotiation,
        compression_threshold: usize,
    ) H2Connection {
        return .{
            .allocator = allocator,
            .tunnel = tunnel,
            .tunnel_owned = true,
            .role = role,
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

    pub fn close(self: *H2Connection) void {
        self.finishDeferredReceiveAbortLocked(null);
        self.pending_write.clear();
        control_admission.clear(self);
        if (self.pending_auto_control) |*pending| {
            pending.deinit(self.allocator);
        }
        if (self.pending_tunnel_data) |*data| {
            data.deinit(self.tunnel.connection.allocator);
        }
        if (self.tunnel_owned) {
            self.tunnel.connection.abandonExtendedConnect(
                self.tunnel.stream_id,
            );
        }
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.message_assembler) |*assembler| assembler.deinit();
        self.inbuf.deinit(self.allocator);
        self.compression_send.deinit(self.allocator);
        self.compression_receive.deinit(self.allocator);
        self.* = undefined;
    }

    /// Return TLS identity and negotiation state for the shared HTTP/2
    /// connection. These are connection-wide values, not per-WebSocket-stream
    /// properties, and remain valid while the parent connection is alive.
    pub fn peerCertificates(
        self: *const H2Connection,
    ) ?[]const []const u8 {
        return self.tunnel.connection.peerCertificates();
    }

    pub fn negotiatedAlpn(self: *const H2Connection) ?[]const u8 {
        return self.tunnel.connection.negotiatedAlpn();
    }

    /// Remote transport IP peer; null for Unix or unavailable native queries.
    pub fn peerAddress(self: *const H2Connection) ?std.Io.net.IpAddress {
        return self.tunnel.connection.peerAddress();
    }

    pub fn negotiatedCipherSuite(
        self: *const H2Connection,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.tunnel.connection.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: *const H2Connection,
    ) ?tls_stream.TranscriptHash {
        return self.tunnel.connection.negotiatedTranscriptHash();
    }

    pub fn negotiatedTlsProtocol(
        self: *const H2Connection,
    ) ?tls_stream.Protocol {
        return self.tunnel.connection.negotiatedTlsProtocol();
    }

    pub fn wasTlsSessionResumed(self: *const H2Connection) ?bool {
        return self.tunnel.connection.wasTlsSessionResumed();
    }

    /// Return and clear a TLS 1.2 session ticket. TLS 1.3 and cleartext h2c
    /// report null.
    pub fn takeTls12SessionTicket(
        self: *H2Connection,
    ) ?tls_stream.Tls12SessionTicket {
        return self.tunnel.connection.takeTls12SessionTicket();
    }

    /// Return and clear a TLS 1.3 session ticket. TLS 1.2 and cleartext h2c
    /// report null.
    pub fn takeTls13SessionTicket(
        self: *H2Connection,
    ) tls_stream.Error!?tls_stream.Tls13SessionTicket {
        return self.tunnel.connection.takeTls13SessionTicket();
    }

    pub fn exportKeyingMaterial(
        self: *const H2Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.tunnel.connection.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    /// RFC 8441 runs over the parent HTTP/2 connection, so TLS traffic-key
    /// control belongs to that shared transport rather than this logical
    /// WebSocket stream. Cleartext h2c reports the same explicit unavailable
    /// error as the ordinary WebSocket adapter.
    pub fn updateTrafficKeys(
        self: *H2Connection,
        request_peer_update: bool,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.unlockSendBefore(null);
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        try self.tunnel.connection.updateTrafficKeys(request_peer_update);
    }

    pub fn keyUpdateCounts(
        self: *const H2Connection,
    ) ?tls_stream.KeyUpdateCounts {
        return self.tunnel.connection.keyUpdateCounts();
    }

    pub fn sendText(self: *H2Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendTextWithTimeout(
        self: *H2Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendTextWithDeadline(
            text,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Send one text frame under an absolute deadline. After partial progress,
    /// retry with the same payload slice until `frame_committed` is true.
    pub fn sendTextWithDeadline(
        self: *H2Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingMessage(self.limits, .text, text);
        return self.sendMessageWithDeadlineLocked(
            .text,
            text,
            progress,
            deadline,
        );
    }

    pub fn sendBinary(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    pub fn sendBinaryWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    /// Binary counterpart to `sendTextWithDeadline`; progress counts the
    /// complete RFC 6455 frame and is cumulative across same-slice retries.
    pub fn sendBinaryWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
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

    /// Send one text or binary message under an absolute transport deadline.
    /// `sendTextWithDeadline` and `sendBinaryWithDeadline` are the typed
    /// convenience forms; this variant keeps the opcode-driven `sendMessage`
    /// shape while bounding lock admission and tunnel output with one deadline.
    pub fn sendMessageWithDeadline(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingMessage(self.limits, opcode, payload);
        return self.sendMessageWithDeadlineLocked(
            opcode,
            payload,
            progress,
            deadline,
        );
    }

    pub fn sendMessageWithTimeout(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendMessageWithDeadline(
            opcode,
            payload,
            progress,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// Mask a mutable RFC 8441 client payload in place and submit its header
    /// and body as one ordered HTTP/2 tunnel sequence. The payload remains
    /// masked after return. Server connections and negotiated compression use
    /// the immutable send APIs instead.
    pub fn sendBinaryInPlace(
        self: *H2Connection,
        payload: []u8,
    ) Error!void {
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        if (!canSendOpcode(.binary, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(
            self.limits,
            .binary,
            payload,
        );
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.unlockSendBefore(null);
        try self.ensureCanSendOpcodeLocked(.binary);

        var mask_key: [4]u8 = undefined;
        try std.Io.randomSecure(self.tunnel.connection.io, &mask_key);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            .binary,
            payload,
            .{ .mask_key = mask_key },
        );
        websocket.applyMask(payload, mask_key, 0);
        // `Tunnel.writeParts` is synchronous: every DATA write has consumed
        // its borrowed slices before return, so ownership immediately returns
        // to the caller even when flow control split the message.
        self.tunnel.writeParts(header, payload, false) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendBinaryInPlaceWithTimeout(
        self: *H2Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryInPlaceWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendBinaryInPlaceWithDeadline(
        self: *H2Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        try common.validateOutgoingMessageLength(self.limits, payload.len);
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
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
            if (control_admission.pending(self)) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.binary);
            try self.beginPendingInPlaceLocked(payload);
        }
        try self.resumePendingInPlaceLocked(payload, progress, deadline);
    }

    pub fn beginPendingInPlaceLocked(
        self: *H2Connection,
        payload: []u8,
    ) Error!void {
        var pending = PendingH2Message{
            .opcode = .binary,
            .source = .in_place,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        var key: [4]u8 = undefined;
        try std.Io.randomSecure(self.tunnel.connection.io, &key);
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

    pub fn resumePendingInPlaceLocked(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = self.pending_write.messagePtr().?;
        while (pending.committed < pending.totalLen()) {
            const header_offset = @min(pending.committed, pending.header_len);
            const payload_offset = pending.committed - header_offset;
            const bytes = if (header_offset < pending.header_len)
                pending.header[header_offset..pending.header_len]
            else
                payload[payload_offset..];
            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeWithDeadline(
                bytes,
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
        }
        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        self.pending_write = .none;
        self.application_write_pending.store(false, .release);
    }

    /// Compatibility wrapper for the two-slice RFC 8441 text form.
    pub fn sendTextParts(
        self: *H2Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.sendTextSlices(&.{ first, second });
    }

    /// Compatibility wrapper for the two-slice RFC 8441 binary form.
    pub fn sendBinaryParts(
        self: *H2Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.sendBinarySlices(&.{ first, second });
    }

    /// Send borrowed slices as one RFC 6455 text frame over HTTP/2.
    pub fn sendTextSlices(
        self: *H2Connection,
        parts: []const []const u8,
    ) Error!void {
        return self.sendMessageSlices(.text, parts);
    }

    /// Send borrowed slices as one RFC 6455 text or binary frame over HTTP/2.
    /// HTTP/2 DATA flow-control boundaries do not become WebSocket
    /// continuations. Text slices are validated as one UTF-8 message.
    pub fn sendMessageSlices(
        self: *H2Connection,
        opcode: websocket.Opcode,
        parts: []const []const u8,
    ) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            opcode,
            parts,
        );
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.unlockSendBefore(null);
        try self.ensureCanSendOpcodeLocked(opcode);

        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
                parts,
                payload_len,
            );
            if (compressed.len < payload_len) {
                self.writeFrameLockedExtended(
                    opcode,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
                self.commitCompressionPreviewLocked();
                return;
            }
            self.discardCompressionPreviewLocked();
        }

        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            opcode,
            payload_len,
            .{ .mask_key = mask_key },
        );
        if (mask_key) |mask| {
            writeMaskedTunnelPayloadSlices(
                &self.tunnel,
                header,
                parts,
                mask,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        } else {
            var writer = self.tunnel.beginWriteSequence() catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            writeUnmaskedTunnelPayloadSlices(
                &writer,
                header,
                parts,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
        }
    }

    /// Send borrowed slices as one RFC 6455 binary frame over HTTP/2.
    pub fn sendBinarySlices(
        self: *H2Connection,
        parts: []const []const u8,
    ) Error!void {
        return self.sendMessageSlices(.binary, parts);
    }

    pub fn sendTextSlicesWithTimeout(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        return self.sendMessageSlicesWithTimeout(
            .text,
            parts,
            progress,
            timeout,
        );
    }

    pub fn sendBinarySlicesWithTimeout(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        return self.sendMessageSlicesWithTimeout(
            .binary,
            parts,
            progress,
            timeout,
        );
    }

    pub fn sendMessageSlicesWithTimeout(
        self: *H2Connection,
        opcode: websocket.Opcode,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendMessageSlicesWithDeadline(
            opcode,
            parts,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendTextSlicesWithDeadline(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.sendMessageSlicesWithDeadline(
            .text,
            parts,
            progress,
            deadline,
        );
    }

    /// Send borrowed slices as one RFC 6455 binary frame over RFC 8441 under
    /// one absolute deadline. Retry with the same descriptor array until the
    /// complete frame commits.
    pub fn sendBinarySlicesWithDeadline(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        return self.sendMessageSlicesWithDeadline(
            .binary,
            parts,
            progress,
            deadline,
        );
    }

    /// Send borrowed slices as one text or binary frame over RFC 8441 under
    /// one absolute deadline. Retry with the same descriptor array until the
    /// complete frame commits.
    pub fn sendMessageSlicesWithDeadline(
        self: *H2Connection,
        opcode: websocket.Opcode,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            opcode,
            parts,
        );
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_write.isPing() or self.pending_write.isClose()) {
            return error.WriteInProgress;
        }
        if (self.pending_write.messagePtr()) |pending| {
            if (!pending.matchesParts(opcode, parts)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (control_admission.pending(self)) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(opcode);
            try self.beginPendingMessagePartsLocked(opcode, parts, payload_len);
        }
        try self.resumePendingMessagePartsLocked(parts, progress, deadline);
    }

    pub fn sendPing(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPingWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingControlFrame(self.limits, .ping, payload);
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.pending_write.isMessage() or self.pending_write.isClose()) {
            return error.WriteInProgress;
        }
        if (!self.pending_write.isPing()) {
            if (!self.pending_write.isNone() or
                control_admission.pending(self))
            {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.ping);
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

    pub fn sendPong(self: *H2Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendPongWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPongWithDeadline(
            payload,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendPongWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingControlFrame(self.limits, .pong, payload);
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
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
            if (control_admission.pending(self)) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.pong)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingPongLocked(payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    /// RFC 8441 counterpart to `Connection.pingWithTimeout`.
    pub fn pingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingWithDeadline(payload, deadline);
    }

    pub fn pingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        try common.validateOutgoingControlFrame(
            self.limits,
            .ping,
            payload,
        );
        if (control_admission.pending(self) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcodeBefore(.ping_wait, deadline);
            return self.readPingEvent(payload, deadline);
        }
        {
            try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
            defer self.unlockSendBefore(deadline);
            _ = try deadline_policy.usableAwake(
                self.tunnel.connection.io,
                deadline,
            );
            if (self.pending_write.isMessage() or
                self.pending_write.isClose())
            {
                return error.WriteInProgress;
            }
            if (!self.pending_write.isPing()) {
                if (!self.pending_write.isNone() or
                    control_admission.pending(self))
                {
                    return error.WriteInProgress;
                }
                try self.ensureCanSendOpcodeLocked(.ping);
                try self.beginPendingPingLocked(payload);
            }
            try self.resumePendingPingLocked(payload, deadline);
        }
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithDeadline(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (control_admission.pending(self) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcodeBefore(.ping_wait, deadline);
            return self.readPingEvent(payload, deadline);
        }
        {
            try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
            defer self.unlockSendBefore(deadline);
            if (self.pending_write.isMessage() or
                self.pending_write.isClose())
            {
                return error.WriteInProgress;
            }
            try self.resumePendingPingLocked(payload, deadline);
        }
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithTimeout(
        self: *H2Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continuePingWithDeadline(
            payload,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn readPingEvent(
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        return PingReader.read(self, payload, deadline);
    }

    pub fn sendClose(self: *H2Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        try self.sendCloseFrame(.{ .code = code, .reason = reason });
    }

    pub fn sendCloseWithTimeout(
        self: *H2Connection,
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
        self: *H2Connection,
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
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendCloseFrameWithDeadline(
            close_frame,
            progress,
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendCloseFrameWithDeadline(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try common.validateOutgoingControlFrame(self.limits, .close, payload);
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
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
                control_admission.pending(self))
            {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(.close);
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

    pub fn sendCloseFrame(self: *H2Connection, close_frame: ?websocket.CloseFrame) Error!void {
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try self.sendFrame(.close, payload);
    }

    pub fn receiveCloseFrame(self: *H2Connection) Error!?websocket.OwnedCloseFrame {
        var frame = try self.receiveFrame();
        errdefer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return frame.takeClose(self.allocator);
    }

    pub fn receiveCloseFrameWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!?websocket.OwnedCloseFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveCloseFrameWithDeadline(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// RFC 8441 counterpart to
    /// `Connection.receiveCloseFrameWithDeadline`.
    pub fn receiveCloseFrameWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?websocket.OwnedCloseFrame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        var frame = try self.receiveFrameWithDeadline(deadline);
        errdefer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return frame.takeClose(self.allocator);
    }

    /// RFC 8441 relative-budget counterpart to
    /// `receiveFrameWithDeadline`.
    pub fn receiveFrameWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// RFC 8441 counterpart to `Connection.receiveFrameWithDeadline`.
    pub fn receiveFrameWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(deadline);
    }

    /// Send Close on the extended CONNECT stream and wait under one absolute
    /// deadline. In-flight application frames are returned rather than lost.
    pub fn closeWithTimeout(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.closeWithDeadline(close_frame, deadline);
    }

    /// RFC 8441 close progress under a caller-owned absolute deadline.
    pub fn closeWithDeadline(
        self: *H2Connection,
        close_frame: ?websocket.CloseFrame,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (control_admission.pending(self) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcodeBefore(.close_wait, deadline);
            return self.readCloseHandshakeEvent(deadline);
        }
        {
            try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
            defer self.unlockSendBefore(deadline);
            _ = try deadline_policy.usableAwake(
                self.tunnel.connection.io,
                deadline,
            );
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_write.isMessage() or
                self.pending_write.isPing())
            {
                return error.WriteInProgress;
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
                if (self.pending_write.closePtr()) |pending| {
                    if (!pending.matches(payload)) {
                        return error.WriteInProgress;
                    }
                } else {
                    if (!self.pending_write.isNone() or
                        control_admission.pending(self))
                    {
                        return error.WriteInProgress;
                    }
                    try self.beginPendingCloseLocked(payload);
                }
            }
            try self.resumePendingCloseLocked(deadline);
        }
        return self.readCloseHandshakeEvent(deadline);
    }

    /// RFC 8441 close progress under the original caller-owned deadline.
    pub fn continueCloseWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.receiveFailed() or self.writeAborted()) {
            return error.ConnectionClosed;
        }
        if (control_admission.pending(self) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcodeBefore(.close_wait, deadline);
            return self.readCloseHandshakeEvent(deadline);
        }
        {
            try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
            defer self.unlockSendBefore(deadline);
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

    pub fn continueCloseWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continueCloseWithDeadline(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readCloseHandshakeEvent(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        while (true) {
            var frame = try self.receiveFrameAutoInternal(
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
                    return .{ .closed = try frame.takeClose(self.allocator) };
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

    pub fn sendFrame(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        try common.validateOutgoingControlFrame(
            self.limits,
            opcode,
            payload,
        );
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.unlockSendBefore(null);
        try self.sendFrameValidatedLocked(opcode, payload);
    }

    pub fn sendFrameValidatedLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        try self.ensureCanSendOpcodeLocked(opcode);
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
        if (opcode == .close) self.close_sent.store(true, .release);
    }

    pub fn beginPendingPingLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending: PendingControlFrame = .{};
        @memcpy(pending.payload[0..payload.len], payload);
        pending.payload_len = payload.len;
        var mask_key: ?[4]u8 = null;
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
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
        self: *H2Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = self.pending_write.pingPtr() orelse return;
        if (!pending.matches(payload)) return error.WriteInProgress;
        var progress: http2_runtime.TunnelWriteProgress = .{};
        self.tunnel.writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            false,
            &progress,
            deadline,
        ) catch |err| {
            pending.committed += progress.committed_bytes;
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(pending.committed == pending.len);
        self.pending_write = .none;
        self.application_write_pending.store(false, .release);
    }

    pub fn beginPendingCloseLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending: PendingControlFrame = .{};
        @memcpy(pending.payload[0..payload.len], payload);
        pending.payload_len = payload.len;
        var mask_key: ?[4]u8 = null;
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
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

    pub fn resumePendingCloseLocked(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.writeAborted()) return error.ConnectionClosed;
        const pending = self.pending_write.closePtr() orelse return;
        var progress: http2_runtime.TunnelWriteProgress = .{};
        self.tunnel.writeWithDeadline(
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
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(
            pending.committed == pending.len and progress.fin_committed,
        );
        self.pending_write = .none;
        self.application_write_pending.store(false, .release);
        self.close_sent.store(true, .release);
    }

    pub fn sendMessageWithDeadlineLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );

        if (self.pending_write.messagePtr()) |pending| {
            if (!pending.matches(opcode, payload)) {
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return error.WriteInProgress;
            }
        } else {
            if (control_admission.pending(self)) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(opcode);
            try self.beginPendingMessageLocked(opcode, payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    pub fn beginPendingMessageLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending = PendingH2Message{
            .opcode = opcode,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
        };
        var encoded_payload = payload;
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                encoded_payload = compressed;
                pending.compressed = true;
            } else {
                self.discardCompressionPreviewLocked();
            }
        }
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
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

    pub fn beginPendingPongLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending = PendingH2Message{
            .opcode = .pong,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
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

    pub fn beginPendingMessagePartsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        parts: []const []const u8,
        payload_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending = PendingH2Message{
            .opcode = opcode,
            .source = .slices,
            .original_ptr = @intFromPtr(parts.ptr),
            .original_len = parts.len,
        };
        var encoded_len = payload_len;
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            payload_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
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
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            pending.mask_key = key;
        }
        const header = try websocket.writeFrameHeaderForLengthInto(
            &pending.header,
            opcode,
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

    pub fn resumePendingMessageLocked(
        self: *H2Connection,
        original_payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = self.pending_write.messagePtr().?;
        const encoded_payload = if (pending.compressed)
            self.compression_send.payload.items[0..pending.payload_len]
        else
            original_payload;
        var masked: [masked_write_scratch_len]u8 = undefined;

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

            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeSlicesWithDeadline(
                parts[0..part_count],
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
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

    pub fn resumePendingMessagePartsLocked(
        self: *H2Connection,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = self.pending_write.messagePtr().?;
        var scratch: [masked_write_scratch_len + websocket.max_frame_header_len]u8 align(64) = undefined;

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

            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeSlicesWithDeadline(
                &.{scratch[0..wire_len]},
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
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

    pub fn sendMessage(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(self.limits, opcode, payload);
        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.unlockSendBefore(null);
        try self.ensureCanSendOpcodeLocked(opcode);

        if (self.permessage_deflate and
            payload.len >= self.compression_threshold)
        {
            const compressed = try self.compressMessageLocked(payload);
            if (compressed.len < payload.len) {
                self.writeFrameLockedExtended(
                    opcode,
                    compressed,
                    true,
                    .{ .rsv1 = true },
                ) catch |err| {
                    self.abortAfterUnboundedMessageWriteLocked();
                    return err;
                };
                self.commitCompressionPreviewLocked();
                return;
            }
            self.discardCompressionPreviewLocked();
        }
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendFragmented(self: *H2Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );

        if (self.permessage_deflate) {
            self.send_mutex.lockUncancelable(self.tunnel.connection.io);
            defer self.unlockSendBefore(null);
            try self.ensureCanSendOpcodeLocked(opcode);
            if (plain_len >= self.compression_threshold) {
                const compressed = try self.compressMessagePartsLocked(
                    fragments,
                    plain_len,
                );
                if (compressed.len < plain_len) {
                    self.writeCompressedFragmentsLocked(
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
            self.writeUncompressedFragmentsLocked(
                opcode,
                fragments,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            return;
        }

        self.send_mutex.lockUncancelable(self.tunnel.connection.io);
        defer self.unlockSendBefore(null);
        try self.ensureCanSendOpcodeLocked(opcode);

        self.writeUncompressedFragmentsLocked(opcode, fragments) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendFragmentedWithTimeout(
        self: *H2Connection,
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
            .fromNow(self.tunnel.connection.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendFragmentedWithDeadline(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
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
            if (control_admission.pending(self)) {
                return error.WriteInProgress;
            }
            try self.ensureCanSendOpcodeLocked(opcode);
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

    pub fn beginPendingFragmentedLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        plain_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending = PendingH2Message{
            .opcode = opcode,
            .source = .fragmented,
            .original_ptr = @intFromPtr(fragments.ptr),
            .original_len = fragments.len,
        };
        errdefer self.discardCompressionPreviewLocked();
        if (self.permessage_deflate and
            plain_len >= self.compression_threshold)
        {
            const compressed = try self.compressMessagePartsLocked(
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
            self.role == .client,
        );
        self.pending_write = .{ .message = pending };
        self.application_write_pending.store(true, .release);
        errdefer {
            self.pending_write = .none;
            self.application_write_pending.store(false, .release);
        }
        try self.preparePendingFragmentLocked(fragments, 0);
    }

    pub fn preparePendingFragmentLocked(
        self: *H2Connection,
        fragments: []const []const u8,
        index: usize,
    ) Error!void {
        const pending = self.pending_write.messagePtr().?;
        std.debug.assert(pending.source == .fragmented);
        const range: message_state.FragmentRange = if (pending.compressed)
            compressedFragmentRange(
                pending.fragmented_payload_total,
                fragments.len,
                index,
            )
        else
            .{ .start = 0, .end = fragments[index].len };
        const mask_key: ?[4]u8 = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
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

    pub fn resumePendingFragmentedLocked(
        self: *H2Connection,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        var scratch: [masked_write_scratch_len]u8 = undefined;
        while (self.pending_write.messagePtr()) |pending| {
            const frame_committed = pending.committed - pending.fragment_start;
            const header_offset = @min(frame_committed, pending.header_len);
            const payload_offset = frame_committed - header_offset;
            var len: usize = 0;
            if (header_offset < pending.header_len) {
                const header = pending.header[header_offset..pending.header_len];
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
            const count = @min(scratch.len - len, payload.len - payload_offset);
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
            var tunnel_progress: http2_runtime.TunnelWriteProgress = .{};
            self.tunnel.writeWithDeadline(
                scratch[0..len],
                false,
                &tunnel_progress,
                deadline,
            ) catch |err| {
                pending.committed += tunnel_progress.committed_bytes;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.wire_total,
                };
                return err;
            };
            pending.committed += tunnel_progress.committed_bytes;
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

    pub fn receiveFrame(self: *H2Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(null);
    }

    pub fn receiveFrameInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        if (self.receiveFailed()) return error.ConnectionClosed;
        try self.ensureNoPendingWrites();
        errdefer |err| closeAfterReceiveError(self, err, deadline);
        if (self.closeSent() and self.closeReceived()) return error.ConnectionClosed;
        try self.ensureBufferedWithDeadline(2, deadline);
        var available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );
        const second = available[1];
        var header_len: usize = 2;
        const len_code = second & 0x7f;
        if (len_code == 126) header_len += 2 else if (len_code == 127) header_len += 8;
        if ((second & 0x80) != 0) header_len += 4;
        try self.ensureBufferedWithDeadline(header_len, deadline);
        available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );
        const header = try websocket.FrameHeader.parse(available);
        const payload_len = std.math.cast(usize, header.payload_len) orelse return error.PayloadTooLarge;
        if (payload_len > self.limits.max_frame_bytes) return error.MessageTooLarge;
        const total_len = try header.wireLen();
        const validation = frame_validation.Checkpoint.capture(self);
        try ensureIncomingFrameBuffered(self, header, total_len, deadline);
        available = message_buffer.unread(
            &self.inbuf,
            self.inbuf_consumed,
        );

        const parse_options: websocket.ParseFrameOptions = switch (self.role) {
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
            parse_options,
        );
        errdefer frame.deinit(self.allocator);
        self.discardBuffered(frame.consumed);
        if (self.closeReceived() and frame.header.opcode != .close) return error.ConnectionClosed;
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
            ) catch |err| switch (err) {
                error.PreviewPending => return error.InvalidFrame,
                error.OutOfMemory => {
                    _ = failReceive(self);
                    return error.OutOfMemory;
                },
                else => |other| return @errorCast(other),
            };
        }
        if (frame.header.opcode == .close) self.close_received.store(true, .release);
        return frame;
    }

    pub fn receiveFrameAuto(self: *H2Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(null, .frame);
    }

    pub fn receiveFrameAutoWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
            .frame,
        );
    }

    pub fn receiveFrameAutoWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(deadline, .frame);
    }

    pub fn receiveFrameAutoInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!websocket.Frame {
        if (try self.pendingAutomaticControlOpcodeBefore(delivery, deadline)) |_| {
            if (try self.resumeAutomaticControl(deadline)) |frame| {
                return frame;
            }
            return self.receiveFrameAutoInternal(deadline, delivery);
        }
        while (true) {
            const frame = try self.receiveFrameInternal(deadline);
            switch (frame.header.opcode) {
                .ping => {
                    if (!canSendOpcode(
                        .pong,
                        self.closeSent(),
                        self.closeReceived(),
                    )) return frame;
                    try self.beginAutomaticControlBefore(.pong, frame.payload, delivery, frame, deadline, 0);
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                .close => {
                    if (self.closeSent()) return frame;
                    try self.beginAutomaticControlBefore(.close, frame.payload, delivery, frame, deadline, 0);
                    return (try self.resumeAutomaticControl(deadline)) orelse
                        unreachable;
                },
                else => return frame,
            }
        }
    }

    pub fn receiveMessage(self: *H2Connection) Error!OwnedMessage {
        return self.receiveMessageInternal(null);
    }

    pub fn receiveMessageWithTimeout(
        self: *H2Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedMessage {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveMessageInternal(.fromNow(
            self.tunnel.connection.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one RFC 8441 message under a caller-owned absolute deadline.
    /// HTTP/2 connection-control frames and WebSocket control frames share the
    /// same deadline rather than extending upper-layer inactivity budgets.
    pub fn receiveMessageWithDeadline(
        self: *H2Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return self.receiveMessageInternal(deadline);
    }

    pub fn receiveMessageInternal(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        return AllocatingMessageReceiver(H2Connection).receive(self, deadline);
    }

    /// Receive one complete message into caller-owned storage.
    ///
    /// HTTP/2 tunnel chunks may split WebSocket frame headers or payloads. This
    /// adapter decodes uncompressed fragments directly into `out`; compressed
    /// input uses only the reusable codec scratch before inflating into `out`.
    /// Timeout, cancellation and executor admission errors retain progress;
    /// retry an incomplete message with the same output pointer and length.
    pub fn receiveMessageInto(
        self: *H2Connection,
        out: []u8,
    ) Error!Message {
        return receiveMessageIntoDirectConnection(self, out, null);
    }

    pub fn receiveMessageIntoWithTimeout(
        self: *H2Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) Error!Message {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveMessageIntoDirectConnection(
            self,
            out,
            .fromNow(
                self.tunnel.connection.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    /// RFC 8441 caller-buffer receive under one absolute deadline. HTTP/2
    /// connection-control and WebSocket control frames cannot renew it.
    pub fn receiveMessageIntoWithDeadline(
        self: *H2Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Message {
        _ = try deadline_policy.usableAwake(
            self.tunnel.connection.io,
            deadline,
        );
        return receiveMessageIntoDirectConnection(self, out, deadline);
    }

    pub fn ensureCompressionReceiveScratch(self: *H2Connection) Error!void {
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

    pub fn compressMessageLocked(
        self: *H2Connection,
        payload: []const u8,
    ) Error![]const u8 {
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
        try self.compression_send.prepare(
            self.allocator,
            payload.len,
        );
        return websocket.compressMessageVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            payload,
            self.compression_send_max_window_bits,
        );
    }

    pub fn compressMessagePartsLocked(
        self: *H2Connection,
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
        try self.compression_send.prepare(
            self.allocator,
            payload_len,
        );
        return websocket.compressMessageFragmentsVortIntoWindowWithEncoder(
            &self.compression_send.encoder.?,
            &self.compression_send.payload,
            parts,
            self.compression_send_max_window_bits,
        );
    }

    pub fn commitCompressionPreviewLocked(self: *H2Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.commitPreview() catch unreachable;
        }
    }

    pub fn discardCompressionPreviewLocked(self: *H2Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.discardPreview();
        }
    }

    pub fn abortAfterUnboundedMessageWriteLocked(self: *H2Connection) void {
        self.discardCompressionPreviewLocked();
        self.abortTunnelAfterReceiveFailureLocked(null);
    }

    pub fn writeFrameLocked(self: *H2Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        try self.writeFrameLockedExtended(opcode, payload, fin, .{});
    }

    pub fn writeFrameLockedExtended(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
        options: struct { rsv1: bool = false },
    ) Error!void {
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try std.Io.randomSecure(self.tunnel.connection.io, &key);
            break :blk key;
        } else null;
        if (opcode.isControl()) {
            // Control payloads are capped at 125 bytes by RFC 6455, so keep
            // their complete frame on the stack. This also avoids retaining a
            // growable buffer solely for tiny Ping/Pong/Close writes.
            var encoded_storage: [websocket.max_frame_header_len + 125]u8 =
                undefined;
            const frame = try websocket.writeFrameInto(
                &encoded_storage,
                opcode,
                payload,
                .{
                    .fin = fin,
                    .mask_key = mask_key,
                    .rsv1 = options.rsv1,
                },
            );
            try self.tunnel.write(frame, opcode == .close);
            return;
        }
        if (mask_key == null) {
            // RFC 8441 server frames do not require masking. Keep the frame
            // header on the stack and let HTTP/2 frame the header plus borrowed
            // application payload as one ordered tunnel byte sequence.
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                opcode,
                payload,
                .{
                    .fin = fin,
                    .rsv1 = options.rsv1,
                },
            );
            try self.tunnel.writeParts(header, payload, false);
            return;
        }
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            opcode,
            payload,
            .{
                .fin = fin,
                .mask_key = mask_key,
                .rsv1 = options.rsv1,
            },
        );
        const payload_parts = [_][]const u8{payload};
        try writeMaskedTunnelPayloadSlices(
            &self.tunnel,
            header,
            &payload_parts,
            mask_key.?,
        );
    }

    pub fn writeCompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var writer = try self.tunnel.beginWriteSequence();
        var frame_index: usize = 0;
        while (frame_index < frame_count) {
            const batch_count = @min(
                max_batched_frames,
                frame_count - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;

            if (self.role == .client) {
                // Each RFC 6455 fragment has its own mask key. Batch only when
                // all encoded payload bytes fit bounded stack storage; larger
                // compressed messages stream one frame at a time below.
                var masked: [masked_write_scratch_len]u8 align(64) = undefined;
                var mask_keys: [max_batched_frames][4]u8 = undefined;
                try common.randomMaskKeys(
                    self.tunnel.connection.io,
                    mask_keys[0..batch_count],
                );
                var masked_len: usize = 0;
                var fits = true;
                for (0..batch_count) |batch_index| {
                    const index = frame_index + batch_index;
                    const range = compressedFragmentRange(
                        compressed_payload.len,
                        frame_count,
                        index,
                    );
                    if (range.end - range.start >
                        masked.len - masked_len)
                    {
                        fits = false;
                        break;
                    }
                    const payload = compressed_payload[range.start..range.end];
                    const mask_key = mask_keys[batch_index];
                    parts[batch_index * 2] =
                        try websocket.writeFrameHeaderInto(
                            &headers[batch_index],
                            if (index == 0) opcode else .continuation,
                            payload,
                            .{
                                .fin = index + 1 == frame_count,
                                .mask_key = mask_key,
                                .rsv1 = index == 0,
                            },
                        );
                    try websocket.applyMaskCopy(
                        masked[masked_len..][0..payload.len],
                        payload,
                        mask_key,
                        0,
                    );
                    parts[batch_index * 2 + 1] =
                        masked[masked_len..][0..payload.len];
                    masked_len += payload.len;
                }
                if (fits) {
                    const part_count = std.math.mul(
                        usize,
                        batch_count,
                        2,
                    ) catch return error.PayloadTooLarge;
                    try writer.writeSlices(
                        parts[0..part_count],
                        false,
                    );
                    frame_index += batch_count;
                    continue;
                }

                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    frame_index,
                );
                const payload = compressed_payload[range.start..range.end];
                var mask_key: [4]u8 = undefined;
                try std.Io.randomSecure(
                    self.tunnel.connection.io,
                    &mask_key,
                );
                const header = try websocket.writeFrameHeaderInto(
                    &headers[0],
                    if (frame_index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = frame_index + 1 == frame_count,
                        .mask_key = mask_key,
                        .rsv1 = frame_index == 0,
                    },
                );
                const payload_parts = [_][]const u8{payload};
                try writeMaskedTunnelPayloadSlicesWithWriter(
                    &writer,
                    header,
                    &payload_parts,
                    mask_key,
                );
                frame_index += 1;
                continue;
            }

            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    index,
                );
                const payload = compressed_payload[range.start..range.end];
                parts[batch_index * 2] = try websocket.writeFrameHeaderInto(
                    &headers[batch_index],
                    if (index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = index + 1 == frame_count,
                        .rsv1 = index == 0,
                    },
                );
                parts[batch_index * 2 + 1] = payload;
            }
            const part_count = std.math.mul(
                usize,
                batch_count,
                2,
            ) catch return error.PayloadTooLarge;
            try writer.writeSlices(parts[0..part_count], false);
            frame_index += batch_count;
        }
    }

    pub fn writeUncompressedFragmentsLocked(
        self: *H2Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var writer = try self.tunnel.beginWriteSequence();
        var frame_index: usize = 0;
        while (frame_index < fragments.len) {
            const batch_count = @min(
                max_batched_frames,
                fragments.len - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;

            if (self.role == .client) {
                var masked: [masked_write_scratch_len]u8 align(64) = undefined;
                var mask_keys: [max_batched_frames][4]u8 = undefined;
                try common.randomMaskKeys(
                    self.tunnel.connection.io,
                    mask_keys[0..batch_count],
                );
                var masked_len: usize = 0;
                var fits = true;
                for (0..batch_count) |batch_index| {
                    const index = frame_index + batch_index;
                    const payload = fragments[index];
                    if (payload.len > masked.len - masked_len) {
                        fits = false;
                        break;
                    }
                    const mask_key = mask_keys[batch_index];
                    parts[batch_index * 2] =
                        try websocket.writeFrameHeaderInto(
                            &headers[batch_index],
                            if (index == 0) opcode else .continuation,
                            payload,
                            .{
                                .fin = index + 1 == fragments.len,
                                .mask_key = mask_key,
                            },
                        );
                    try websocket.applyMaskCopy(
                        masked[masked_len..][0..payload.len],
                        payload,
                        mask_key,
                        0,
                    );
                    parts[batch_index * 2 + 1] =
                        masked[masked_len..][0..payload.len];
                    masked_len += payload.len;
                }
                if (fits) {
                    const part_count = std.math.mul(
                        usize,
                        batch_count,
                        2,
                    ) catch return error.PayloadTooLarge;
                    try writer.writeSlices(parts[0..part_count], false);
                    frame_index += batch_count;
                    continue;
                }

                const payload = fragments[frame_index];
                var mask_key: [4]u8 = undefined;
                try std.Io.randomSecure(
                    self.tunnel.connection.io,
                    &mask_key,
                );
                const header = try websocket.writeFrameHeaderInto(
                    &headers[0],
                    if (frame_index == 0) opcode else .continuation,
                    payload,
                    .{
                        .fin = frame_index + 1 == fragments.len,
                        .mask_key = mask_key,
                    },
                );
                const payload_parts = [_][]const u8{payload};
                try writeMaskedTunnelPayloadSlicesWithWriter(
                    &writer,
                    header,
                    &payload_parts,
                    mask_key,
                );
                frame_index += 1;
                continue;
            }

            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const payload = fragments[index];
                parts[batch_index * 2] = try websocket.writeFrameHeaderInto(
                    &headers[batch_index],
                    if (index == 0) opcode else .continuation,
                    payload,
                    .{ .fin = index + 1 == fragments.len },
                );
                parts[batch_index * 2 + 1] = payload;
            }
            const part_count = std.math.mul(
                usize,
                batch_count,
                2,
            ) catch return error.PayloadTooLarge;
            try writer.writeSlices(parts[0..part_count], false);
            frame_index += batch_count;
        }
    }

    fn ensureBuffered(self: *H2Connection, len: usize) Error!void {
        return self.ensureBufferedWithDeadline(len, null);
    }

    pub fn ensureBufferedWithDeadline(
        self: *H2Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            if (self.receive_finished) return error.ConnectionClosed;
            const count = try self.appendTunnelDataChunk(deadline);
            if (count == 0) return error.ConnectionClosed;
        }
    }

    pub fn ensureBufferedExactWithDeadline(
        self: *H2Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            if (self.receive_finished) return error.ConnectionClosed;
            const missing = len - message_buffer.unreadLen(
                &self.inbuf,
                self.inbuf_consumed,
            );
            const destination = try message_buffer.reserveAppendAfterConsumed(
                &self.inbuf,
                &self.inbuf_consumed,
                self.allocator,
                missing,
            );
            const count = try self.readMessagePayloadChunk(
                destination,
                deadline,
            );
            if (count == 0) return error.ConnectionClosed;
            message_buffer.commitAppend(&self.inbuf, count);
        }
    }

    fn appendTunnelDataChunk(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        while (true) {
            if (self.pending_tunnel_data) |*pending| {
                const remaining =
                    pending.data[self.pending_tunnel_data_offset..];
                try message_buffer.appendAfterConsumed(
                    &self.inbuf,
                    &self.inbuf_consumed,
                    self.allocator,
                    remaining,
                );
                const count = remaining.len;
                const end_stream = pending.end_stream;
                pending.deinit(self.tunnel.connection.allocator);
                self.pending_tunnel_data = null;
                self.pending_tunnel_data_offset = 0;
                if (end_stream) self.receive_finished = true;
                return count;
            }
            if (self.receive_finished) return 0;
            const data = if (deadline) |absolute|
                try self.tunnel.readWithDeadline(absolute)
            else
                try self.tunnel.read();
            if (data.data.len == 0) {
                const end_stream = data.end_stream;
                var empty = data;
                empty.deinit(self.tunnel.connection.allocator);
                if (end_stream) {
                    self.receive_finished = true;
                    return 0;
                }
                continue;
            }
            self.pending_tunnel_data = data;
        }
    }

    pub fn readMessagePayloadChunk(
        self: *H2Connection,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        std.debug.assert(out.len != 0);
        while (true) {
            if (self.pending_tunnel_data) |*pending| {
                const remaining =
                    pending.data[self.pending_tunnel_data_offset..];
                const count = @min(out.len, remaining.len);
                @memcpy(out[0..count], remaining[0..count]);
                self.pending_tunnel_data_offset += count;
                if (self.pending_tunnel_data_offset == pending.data.len) {
                    const end_stream = pending.end_stream;
                    pending.deinit(self.tunnel.connection.allocator);
                    self.pending_tunnel_data = null;
                    self.pending_tunnel_data_offset = 0;
                    if (end_stream) self.receive_finished = true;
                }
                return count;
            }
            if (self.receive_finished) return 0;
            const data = if (deadline) |absolute|
                try self.tunnel.readWithDeadline(absolute)
            else
                try self.tunnel.read();
            if (data.data.len == 0) {
                const end_stream = data.end_stream;
                var empty = data;
                empty.deinit(self.tunnel.connection.allocator);
                if (end_stream) {
                    self.receive_finished = true;
                    return 0;
                }
                continue;
            }
            self.pending_tunnel_data = data;
        }
    }

    pub fn discardBuffered(self: *H2Connection, len: usize) void {
        _ = message_buffer.discardPrefix(
            &self.inbuf,
            &self.inbuf_consumed,
            len,
        );
    }

    /// Same post-lock invariant as the TCP/TLS adapter: no RFC 8441 DATA may
    /// be queued after an earlier writer has committed the Close frame.
    pub fn canSendOpcodeLocked(
        self: *const H2Connection,
        opcode: websocket.Opcode,
    ) bool {
        if (self.writeAborted()) return false;
        if (self.receiveFailed()) return false;
        return canSendOpcode(opcode, self.closeSent(), self.closeReceived());
    }

    fn ensureCanSendOpcodeLocked(
        self: *const H2Connection,
        opcode: websocket.Opcode,
    ) Error!void {
        if (!self.pending_write.isNone()) return error.WriteInProgress;
        if (control_admission.pending(self)) return error.WriteInProgress;
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;
    }

    pub fn closeSent(self: *const H2Connection) bool {
        return self.close_sent.load(.acquire);
    }

    pub fn closeReceived(self: *const H2Connection) bool {
        return self.receiveFailed() or self.close_received.load(.acquire);
    }

    pub fn receiveFailed(self: *const H2Connection) bool {
        return self.receive_failed.load(.acquire);
    }

    pub fn writeAborted(self: *const H2Connection) bool {
        return self.write_aborted.load(.acquire);
    }

    pub fn ensureNoPendingWrites(self: *H2Connection) Error!void {
        if (self.application_write_pending.load(.acquire) or
            control_admission.pending(self))
        {
            return error.WriteInProgress;
        }
    }

    fn pendingAutomaticControlOpcode(
        self: *H2Connection,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!?websocket.Opcode {
        return self.pendingAutomaticControlOpcodeBefore(delivery, null);
    }

    pub fn pendingAutomaticControlOpcodeBefore(
        self: *H2Connection,
        delivery: PendingAutomaticControl.Delivery,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?websocket.Opcode {
        if (!control_admission.pending(self)) return null;
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        if (self.automatic_control_admission) |waiting| {
            if (waiting.delivery != delivery) return error.WriteInProgress;
            return waiting.opcode;
        }
        const pending = self.pending_auto_control orelse return null;
        if (pending.delivery != delivery) return error.WriteInProgress;
        return pending.opcode;
    }

    fn abortTunnelAfterReceiveFailureLocked(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        receive_cleanup.request(self);
        self.finishDeferredReceiveAbortLocked(deadline);
    }

    fn abortReceiveTransportLocked(self: *H2Connection, deadline: ?std.Io.Clock.Timestamp) bool {
        self.tunnel.abort(deadline);
        return true;
    }

    pub fn finishDeferredReceiveAbortLocked(self: *H2Connection, deadline: ?std.Io.Clock.Timestamp) void {
        if (!self.receive_abort_pending.load(.acquire)) return;
        receive_cleanup.finishLocked(self, self.tunnel.connection.io, deadline, true, abortReceiveTransportLocked);
    }

    pub fn unlockSendBefore(self: *H2Connection, deadline: ?std.Io.Clock.Timestamp) void {
        self.finishDeferredReceiveAbortLocked(deadline);
        self.send_mutex.unlock(self.tunnel.connection.io);
    }

    pub fn deferReceiveAbort(self: *H2Connection, deadline: ?std.Io.Clock.Timestamp) void {
        receive_cleanup.request(self);
        // Publication may race the original holder's unlock. A free mutex
        // lets this receiver retire local state without waiting again.
        if (self.send_mutex.tryLock()) {
            defer self.send_mutex.unlock(self.tunnel.connection.io);
            self.finishDeferredReceiveAbortLocked(deadline);
        }
    }

    pub fn finishReceiveFailure(
        self: *H2Connection,
        code: websocket.CloseCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline) catch {
            self.deferReceiveAbort(deadline);
            return;
        };
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        if (!self.pending_write.isNone() or
            control_admission.pending(self))
        {
            self.abortTunnelAfterReceiveFailureLocked(deadline);
            return;
        }
        if (self.closeSent()) return;
        var storage: [125]u8 = undefined;
        const payload = websocket.writeClosePayloadInto(
            &storage,
            .{ .code = code },
        ) catch return;
        if (deadline) |absolute| {
            self.beginPendingCloseLocked(payload) catch {
                self.abortTunnelAfterReceiveFailureLocked(deadline);
                return;
            };
            self.resumePendingCloseLocked(absolute) catch {
                self.abortTunnelAfterReceiveFailureLocked(deadline);
            };
            return;
        }
        self.writeFrameLocked(.close, payload, true) catch {
            self.abortTunnelAfterReceiveFailureLocked(deadline);
            return;
        };
        self.close_sent.store(true, .release);
    }

    pub fn finishAbruptReceiveEnd(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline) catch {
            self.deferReceiveAbort(deadline);
            return;
        };
        defer self.send_mutex.unlock(self.tunnel.connection.io);
        self.abortTunnelAfterReceiveFailureLocked(deadline);
    }

    pub fn beginAutomaticControl(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        delivery: PendingAutomaticControl.Delivery,
        frame: ?websocket.Frame,
    ) Error!void {
        return self.beginAutomaticControlBefore(opcode, payload, delivery, frame, null, 0);
    }

    pub fn beginAutomaticControlBefore(
        self: *H2Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        delivery: PendingAutomaticControl.Delivery,
        frame: ?websocket.Frame,
        deadline: ?std.Io.Clock.Timestamp,
        consumed_input: usize,
    ) Error!void {
        try control_admission.stage(self, opcode, payload, delivery, frame, consumed_input);
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        const consumed = try control_admission.admit(self, self.tunnel.connection.io, self.role, false);
        if (consumed != 0) self.discardBuffered(consumed);
    }

    pub fn resumeAutomaticControl(
        self: *H2Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?websocket.Frame {
        try timed_mutex.lock(&self.send_mutex, self.tunnel.connection.io, deadline);
        defer self.unlockSendBefore(deadline);
        const consumed = try control_admission.admit(self, self.tunnel.connection.io, self.role, false);
        if (consumed != 0) self.discardBuffered(consumed);
        const pending = if (self.pending_auto_control) |*value|
            value
        else
            return null;
        if (!self.pending_write.isNone()) {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(pending.opcode)) {
            pending.writes_reply = false;
        }
        try automatic_control.resumeEncoding(pending, self.tunnel.connection.io, self.role);
        var progress: http2_runtime.TunnelWriteProgress = .{};
        if (!pending.complete() and deadline != null) {
            const absolute = deadline.?;
            _ = try deadline_policy.usableAwake(
                self.tunnel.connection.io,
                absolute,
            );
            self.tunnel.writeWithDeadline(
                pending.bytes[pending.committed..pending.len],
                pending.opcode == .close,
                &progress,
                absolute,
            ) catch |err| {
                pending.committed += progress.committed_bytes;
                pending.fin_committed =
                    pending.fin_committed or progress.fin_committed;
                return err;
            };
        } else if (!pending.complete()) {
            self.tunnel.write(
                pending.bytes[pending.committed..pending.len],
                pending.opcode == .close,
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            progress.committed_bytes = pending.len - pending.committed;
            progress.fin_committed = pending.opcode == .close;
        }
        pending.committed += progress.committed_bytes;
        pending.fin_committed = pending.fin_committed or progress.fin_committed;
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
};

//! WebSocket connection state, framing, and message handoff.

const std = @import("std");
const secure_random = @import("../../internal/secure_random.zig");
const websocket = @import("../mod.zig");
const net = std.Io.net;
const socket_address = @import("../../internal/socket_address.zig");
const runtime = @import("../runtime.zig");

const AllocatingMessageReceiver = runtime.AllocatingMessageReceiver;
const CloseHandshakeEvent = runtime.CloseHandshakeEvent;
const Error = runtime.Error;
const IncomingDataKind = runtime.IncomingDataKind;
const Message = runtime.Message;
const MessageFrameReceiveState = runtime.MessageFrameReceiveState;
const MessageIntoReceiveState = runtime.MessageIntoReceiveState;
const MessageWriteProgress = runtime.MessageWriteProgress;
const OwnedMessage = runtime.OwnedMessage;
const PendingAutomaticControl = runtime.PendingAutomaticControl;
const PendingControlFrame = runtime.PendingControlFrame;
const PendingMessage = runtime.PendingMessage;
const PendingWrite = runtime.PendingWrite;
const PingEvent = runtime.PingEvent;
const Role = runtime.Role;
const RuntimeTransport = runtime.RuntimeTransport;
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
const http1_runtime = runtime.http1_runtime;
const masked_write_scratch_len = runtime.masked_write_scratch_len;
const message_buffer = runtime.message_buffer;
const message_state = runtime.message_state;
const ping_control = runtime.ping_control;
const receiveMessageIntoDirectConnection = runtime.receiveMessageIntoDirectConnection;
const receive_cleanup = runtime.receive_cleanup;
const timed_mutex = runtime.timed_mutex;
const tls_stream = runtime.tls_stream;
const transportStream = runtime.transportStream;
const transport_read_scratch_len = runtime.transport_read_scratch_len;
const vail = runtime.vail;
const wire = runtime.wire;
const writeMaskedPayload = runtime.writeMaskedPayload;
const writeMaskedPayloadParts = runtime.writeMaskedPayloadParts;
const writeUnmaskedPayloadSlices = runtime.writeUnmaskedPayloadSlices;

pub const Connection = struct {
    const PingReader = ping_control.Reader(.{
        .Error = Error,
        .receive = receiveFrameAutoInternal,
        .io = struct {
            fn get(connection: *const Connection) std.Io {
                return connection.io;
            }
        }.get,
    });
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    tls_conn: ?*http1_runtime.TlsClientConnection = null,
    tls_vail_conn: ?*tls_stream.ClientConnection = null,
    tls_server_conn: ?*tls_stream.ServerConnection = null,
    role: Role,
    limits: common.MessageLimits = .{},
    inbuf: std.ArrayList(u8) = .empty,
    inbuf_consumed: usize = 0,
    send_mutex: std.Io.Mutex = .init,
    /// Read progress and application writers may observe close state on
    /// different threads, while the send mutex orders complete wire writes.
    close_sent: std.atomic.Value(bool) = .init(false),
    close_received: std.atomic.Value(bool) = .init(false),
    /// A fatal receive failure permanently retires the input half so an
    /// offending or truncated prefix cannot be reparsed. Protocol failures
    /// send Close; abrupt transport ends terminate without fabricating one.
    receive_failed: std.atomic.Value(bool) = .init(false),
    /// A fatal receive raced a retained outbound transaction, so the byte
    /// stream was aborted instead of appending a Close after a partial frame.
    write_aborted: std.atomic.Value(bool) = .init(false),
    receive_abort_pending: std.atomic.Value(bool) = .init(false),
    /// Lock-free receive-side visibility for resumable application/Ping/Close
    /// transactions. The transaction details remain protected by send_mutex.
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
    selected_protocol: ?[]u8 = null,
    permessage_deflate: bool = false,
    compression_send_context_takeover: bool = false,
    compression_receive_context_takeover: bool = false,
    compression_threshold: usize = default_compression_threshold,
    /// Maximum LZ77 distance for messages emitted by this endpoint. The field
    /// follows the role-specific RFC 7692 direction selected at handshake.
    compression_send_max_window_bits: u8 = 15,
    compression_receive_max_window_bits: u8 = 15,
    compression_send: compression_scratch.SendScratch = .{},
    compression_receive: compression_scratch.Scratch = .{},
    /// One HTTP/1 application frame may outlive a bounded socket write. The
    /// caller retains the original payload; this state retains its mask,
    /// compression output, header, and exact transport cursor.
    pending_write: PendingWrite = .none,
    /// Automatic Pong/Close bytes and, for receiveFrameAuto, the peer frame
    /// that must be delivered after a bounded reply resumes to completion.
    pending_auto_control: ?PendingAutomaticControl = null,

    /// Remote transport IP peer. Unix streams and unavailable native queries
    /// return null; a proxy tunnel reports its connected proxy's address.
    pub fn peerAddress(self: *const Connection) ?net.IpAddress {
        return if (self.role == .server)
            socket_address.accepted(self.stream)
        else
            socket_address.connected(self.io, self.stream);
    }

    /// Return the authenticated peer certificate chain. Server-side WSS
    /// returns a verified client chain when mTLS succeeded; vail-backed WSS
    /// clients return the verified server chain. Other transports return null.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        if (self.tls_server_conn) |connection| {
            return connection.peerCertificates();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.peerCertificates();
        }
        return null;
    }

    /// Return authenticated TLS cipher-suite metadata for vail-backed
    /// WSS. Cleartext and Zig standard-library TLS transports return null.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.NegotiatedCipherSuite {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedCipherSuite();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedCipherSuite();
        }
        return null;
    }

    /// Return the negotiated WSS ALPN value for vail-backed transports.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedAlpn();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedAlpn();
        }
        return null;
    }

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedProtocol();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedProtocol();
        }
        return null;
    }

    pub fn wasTlsSessionResumed(self: *const Connection) ?bool {
        if (self.tls_server_conn) |connection| {
            return connection.wasResumed();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.wasResumed();
        }
        return null;
    }

    pub fn takeTls12SessionTicket(
        self: *Connection,
    ) ?tls_stream.Tls12SessionTicket {
        const connection = self.tls_vail_conn orelse return null;
        return connection.takeTls12SessionTicket();
    }

    pub fn takeTls13SessionTicket(
        self: *Connection,
    ) tls_stream.Error!?tls_stream.Tls13SessionTicket {
        const connection = self.tls_vail_conn orelse return null;
        return connection.takeTls13SessionTicket();
    }

    /// Return the transcript/HKDF hash implied by the negotiated WSS suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        if (self.tls_server_conn) |connection| {
            return connection.negotiatedTranscriptHash();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.negotiatedTranscriptHash();
        }
        return null;
    }

    /// Start a TLS 1.3 application traffic-key update for vail-backed WSS.
    /// The connection send mutex keeps this control record ordered with every
    /// WebSocket frame writer.
    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.unlockSendBefore(null);
        if (!self.canSendOpcodeLocked(.binary)) {
            return error.ConnectionClosed;
        }
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        if (self.tls_server_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        if (self.tls_vail_conn) |connection| {
            return connection.updateTrafficKeys(request_peer_update);
        }
        return error.TlsKeyUpdateUnavailable;
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        if (self.tls_server_conn) |connection| {
            return connection.keyUpdateCounts();
        }
        if (self.tls_vail_conn) |connection| {
            return connection.keyUpdateCounts();
        }
        return null;
    }

    /// Export RFC 8446 channel-bound keying material for vail-backed WSS.
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        if (self.tls_server_conn) |connection| {
            return connection.exportKeyingMaterial(label, context, out);
        }
        if (self.tls_vail_conn) |connection| {
            return connection.exportKeyingMaterial(label, context, out);
        }
        return error.ExporterUnavailable;
    }

    pub fn bufferInitial(self: *Connection, bytes: []const u8) Error!void {
        try message_buffer.appendAfterConsumed(
            &self.inbuf,
            &self.inbuf_consumed,
            self.allocator,
            bytes,
        );
    }

    pub fn transport(self: *Connection) RuntimeTransport {
        if (self.tls_server_conn) |conn| return .{ .tls_server = conn };
        if (self.tls_vail_conn) |conn| return .{ .tls_vail = conn };
        if (self.tls_conn) |conn| return .{ .tls = conn };
        return .{ .tcp = .{ .io = self.io, .stream = self.stream } };
    }

    pub fn close(self: *Connection) void {
        self.finishDeferredReceiveAbortLocked(null);
        self.pending_write.clear();
        control_admission.clear(self);
        if (self.pending_auto_control) |*pending| {
            pending.deinit(self.allocator);
        }
        if (self.selected_protocol) |protocol| self.allocator.free(protocol);
        if (self.message_assembler) |*assembler| assembler.deinit();
        self.inbuf.deinit(self.allocator);
        self.compression_send.deinit(self.allocator);
        self.compression_receive.deinit(self.allocator);
        self.transport().close();
        self.* = undefined;
    }

    pub fn sendText(self: *Connection, text: []const u8) Error!void {
        try self.sendMessage(.text, text);
    }

    pub fn sendTextWithTimeout(
        self: *Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendTextWithDeadline(text, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send one HTTP/1 WebSocket text frame under an absolute transport
    /// deadline. After partial progress retry with the identical payload slice
    /// until `frame_committed` is true.
    pub fn sendTextWithDeadline(
        self: *Connection,
        text: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingMessage(self.limits, .text, text);
        return self.sendMessageWithDeadlineLocked(
            .text,
            text,
            progress,
            deadline,
        );
    }

    pub fn sendBinary(self: *Connection, payload: []const u8) Error!void {
        try self.sendMessage(.binary, payload);
    }

    pub fn sendBinaryWithTimeout(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryWithDeadline(payload, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendBinaryWithDeadline(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
    /// shape while bounding lock admission and output with one deadline.
    pub fn sendMessageWithDeadline(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingMessage(self.limits, opcode, payload);
        return self.sendMessageWithDeadlineLocked(
            opcode,
            payload,
            progress,
            deadline,
        );
    }

    pub fn sendMessageWithTimeout(
        self: *Connection,
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
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Compatibility wrapper for the two-slice text-message form.
    pub fn sendTextParts(
        self: *Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.sendTextSlices(&.{ first, second });
    }

    /// Compatibility wrapper for the two-slice binary-message form.
    pub fn sendBinaryParts(
        self: *Connection,
        first: []const u8,
        second: []const u8,
    ) Error!void {
        return self.sendBinarySlices(&.{ first, second });
    }

    /// Send borrowed slices as one FIN-terminated text message.
    pub fn sendTextSlices(
        self: *Connection,
        parts: []const []const u8,
    ) Error!void {
        return self.sendMessageSlices(.text, parts);
    }

    /// Send borrowed slices as one FIN-terminated text or binary message.
    ///
    /// The uncompressed server path uses scatter/gather without concatenating
    /// caller data. Clients mask through bounded stack storage while preserving
    /// one continuous four-byte mask phase across every slice. Negotiated
    /// compression consumes the same logical message without a plaintext join.
    /// Text slices are validated as one UTF-8 message, so code points may span
    /// slice boundaries.
    pub fn sendMessageSlices(
        self: *Connection,
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
        self.send_mutex.lockUncancelable(self.io);
        defer self.unlockSendBefore(null);
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;

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

        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        if (self.role == .server) {
            const header = try websocket.writeFrameHeaderForLengthInto(
                &header_storage,
                opcode,
                payload_len,
                .{},
            );
            writeUnmaskedPayloadSlices(self.transport(), header, parts) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            return;
        }

        var mask_key: [4]u8 = undefined;
        try secure_random.fill(self.io, &mask_key);
        const header = try websocket.writeFrameHeaderForLengthInto(
            &header_storage,
            opcode,
            payload_len,
            .{ .mask_key = mask_key },
        );
        writeMaskedPayloadParts(
            self.transport(),
            header,
            parts,
            mask_key,
        ) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    /// Send borrowed slices as one FIN-terminated binary message.
    pub fn sendBinarySlices(
        self: *Connection,
        parts: []const []const u8,
    ) Error!void {
        return self.sendMessageSlices(.binary, parts);
    }

    pub fn sendTextSlicesWithTimeout(
        self: *Connection,
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
        self: *Connection,
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
        self: *Connection,
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
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendTextSlicesWithDeadline(
        self: *Connection,
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

    /// Send borrowed slices as one binary frame under an absolute deadline.
    /// Retry with the same descriptor array and stable payload bytes until
    /// `frame_committed` is true.
    pub fn sendBinarySlicesWithDeadline(
        self: *Connection,
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

    /// Send borrowed slices as one text or binary frame under an absolute
    /// deadline. Retry with the same descriptor array and stable payload bytes
    /// until `frame_committed` is true.
    pub fn sendMessageSlicesWithDeadline(
        self: *Connection,
        opcode: websocket.Opcode,
        parts: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const payload_len = try common.validateOutgoingMessageParts(
            self.limits,
            opcode,
            parts,
        );
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            if (!self.canSendOpcodeLocked(opcode)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingMessagePartsLocked(opcode, parts, payload_len);
        }
        try self.resumePendingMessagePartsLocked(parts, progress, deadline);
    }

    /// Send one binary message by masking the caller buffer in place.
    ///
    /// This opt-in API matches mutable-buffer WebSocket clients such as
    /// websocket.zig. The payload remains masked after return; callers that
    /// need immutable input should continue using `sendBinary`.
    pub fn sendBinaryInPlace(
        self: *Connection,
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
        self.send_mutex.lockUncancelable(self.io);
        defer self.unlockSendBefore(null);
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(.binary)) return error.ConnectionClosed;

        var mask_key: [4]u8 = undefined;
        try secure_random.fill(self.io, &mask_key);
        var header_storage: [websocket.max_frame_header_len]u8 = undefined;
        const header = try websocket.writeFrameHeaderInto(
            &header_storage,
            .binary,
            payload,
            .{ .mask_key = mask_key },
        );
        websocket.applyMask(payload, mask_key, 0);
        self.transport().writeAllParts(header, payload) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendBinaryInPlaceWithTimeout(
        self: *Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendBinaryInPlaceWithDeadline(
            payload,
            progress,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendBinaryInPlaceWithDeadline(
        self: *Connection,
        payload: []u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.role != .client or self.permessage_deflate) {
            return error.InvalidFrame;
        }
        try common.validateOutgoingMessageLength(self.limits, payload.len);
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            if (!self.canSendOpcodeLocked(.binary)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingInPlaceLocked(payload);
        }
        try self.resumePendingInPlaceLocked(payload, progress, deadline);
    }

    pub fn beginPendingInPlaceLocked(
        self: *Connection,
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
        try secure_random.fill(self.io, &key);
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
        self: *Connection,
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
            var committed: usize = 0;
            self.transport().writeWithDeadline(
                bytes,
                &committed,
                deadline,
            ) catch |err| {
                pending.committed += committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += committed;
        }
        progress.* = .{
            .committed_bytes = pending.committed,
            .total_bytes = pending.totalLen(),
            .frame_committed = true,
        };
        self.pending_write = .none;
        self.application_write_pending.store(false, .release);
    }

    pub fn sendPing(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.ping, payload);
    }

    pub fn sendPingWithTimeout(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPingWithDeadline(payload, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendPingWithDeadline(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingControlFrame(self.limits, .ping, payload);
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_write.isMessage() or self.pending_write.isClose()) {
            return error.WriteInProgress;
        }
        if (!self.pending_write.isPing()) {
            if (!self.pending_write.isNone() or
                control_admission.pending(self))
            {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(.ping)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingControlLocked(
                .ping,
                payload,
            );
        }
        const total = self.pending_write.pingPtr().?.len;
        self.resumePendingControlLocked(
            .ping,
            payload,
            deadline,
        ) catch |err| {
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

    pub fn sendPong(self: *Connection, payload: []const u8) Error!void {
        try self.sendFrame(.pong, payload);
    }

    pub fn sendPongWithTimeout(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPongWithDeadline(payload, progress, .fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendPongWithDeadline(
        self: *Connection,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try common.validateOutgoingControlFrame(self.limits, .pong, payload);
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
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

    /// Send Ping once and wait for the matching Pong under one deadline.
    /// Interleaved application frames are returned with ownership so callers
    /// can process them and resume through `continuePingWithDeadline`.
    pub fn pingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingWithDeadline(payload, deadline);
    }

    pub fn pingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            try timed_mutex.lock(&self.send_mutex, self.io, deadline);
            defer self.unlockSendBefore(deadline);
            _ = try deadline_policy.usableAwake(self.io, deadline);
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
                if (!self.canSendOpcodeLocked(.ping)) {
                    return error.ConnectionClosed;
                }
                try self.beginPendingControlLocked(
                    .ping,
                    payload,
                );
            }
            try self.resumePendingControlLocked(
                .ping,
                payload,
                deadline,
            );
        }
        return self.readPingEvent(payload, deadline);
    }

    pub fn continuePingWithDeadline(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (control_admission.pending(self) and
            !self.application_write_pending.load(.acquire))
        {
            _ = try self.pendingAutomaticControlOpcodeBefore(.ping_wait, deadline);
            return self.readPingEvent(payload, deadline);
        }
        {
            try timed_mutex.lock(&self.send_mutex, self.io, deadline);
            defer self.unlockSendBefore(deadline);
            try self.resumePendingControlLocked(
                .ping,
                payload,
                deadline,
            );
        }
        return self.readPingEvent(payload, deadline);
    }

    /// Resume a Ping after the caller handles an interleaved application
    /// frame, deriving a fresh bounded wait without retransmitting Ping.
    pub fn continuePingWithTimeout(
        self: *Connection,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) Error!PingEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continuePingWithDeadline(
            payload,
            .fromNow(
                self.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn readPingEvent(
        self: *Connection,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PingEvent {
        return PingReader.read(self, payload, deadline);
    }

    pub fn sendClose(self: *Connection, code: websocket.CloseCode, reason: []const u8) Error!void {
        try self.sendCloseFrame(.{ .code = code, .reason = reason });
    }

    pub fn sendCloseWithTimeout(
        self: *Connection,
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
        self: *Connection,
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
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        timeout: std.Io.Duration,
    ) Error!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendCloseFrameWithDeadline(
            close_frame,
            progress,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendCloseFrameWithDeadline(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try common.validateOutgoingControlFrame(self.limits, .close, payload);
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            if (!self.canSendOpcodeLocked(.close)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingControlLocked(
                .close,
                payload,
            );
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

    pub fn sendCloseFrame(self: *Connection, close_frame: ?websocket.CloseFrame) Error!void {
        var storage: [125]u8 = undefined;
        const payload = try websocket.writeClosePayloadInto(
            &storage,
            close_frame,
        );
        try self.sendFrame(.close, payload);
    }

    pub fn receiveCloseFrame(self: *Connection) Error!?websocket.OwnedCloseFrame {
        var frame = try self.receiveFrame();
        errdefer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return frame.takeClose(self.allocator);
    }

    pub fn receiveCloseFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!?websocket.OwnedCloseFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveCloseFrameWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive and parse one peer Close frame under an absolute deadline.
    /// Partial frame bytes remain buffered for a later receive. This strict
    /// typed helper rejects an intervening application or control frame.
    pub fn receiveCloseFrameWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!?websocket.OwnedCloseFrame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var frame = try self.receiveFrameWithDeadline(deadline);
        errdefer frame.deinit(self.allocator);
        if (frame.header.opcode != .close) return error.InvalidFrame;
        return frame.takeClose(self.allocator);
    }

    /// Relative-budget counterpart to `receiveFrameWithDeadline`. Partial
    /// frame bytes remain buffered so a later receive can resume exactly.
    pub fn receiveFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one frame under a caller-owned absolute deadline. The same
    /// deadline covers partial headers, payload bytes, and TLS records.
    pub fn receiveFrameWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(deadline);
    }

    /// Send Close once and wait up to `timeout` for peer-close progress.
    ///
    /// Ping/Pong frames are consumed under one absolute deadline. An in-flight
    /// application frame is returned to the caller, who can process it and
    /// call this method again with a new bounded wait; it is never hidden or
    /// discarded.
    pub fn closeWithTimeout(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.closeWithDeadline(close_frame, deadline);
    }

    /// Send Close once and advance the handshake under an absolute deadline.
    /// Reuse this entry point after `.application` to retain one total budget.
    pub fn closeWithDeadline(
        self: *Connection,
        close_frame: ?websocket.CloseFrame,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            try timed_mutex.lock(&self.send_mutex, self.io, deadline);
            defer self.unlockSendBefore(deadline);
            _ = try deadline_policy.usableAwake(self.io, deadline);
            if (self.receiveFailed() or self.writeAborted()) {
                return error.ConnectionClosed;
            }
            if (self.pending_write.isMessage() or
                self.pending_write.isPing())
            {
                return error.WriteInProgress;
            }
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
                    if (!self.canSendOpcodeLocked(.close)) {
                        return error.ConnectionClosed;
                    }
                    try self.beginPendingControlLocked(
                        .close,
                        payload,
                    );
                }
            }
            try self.resumePendingCloseLocked(deadline);
        }
        return self.readCloseHandshakeEvent(deadline);
    }

    /// Continue a previously started close handshake under the caller's
    /// original deadline after handling an `.application` event.
    pub fn continueCloseWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!CloseHandshakeEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            try timed_mutex.lock(&self.send_mutex, self.io, deadline);
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

    /// Resume an already-started Close handshake under a new relative wait.
    /// This never emits a second Close frame.
    pub fn continueCloseWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!CloseHandshakeEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.continueCloseWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readCloseHandshakeEvent(
        self: *Connection,
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

    pub fn sendFrame(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        try common.validateOutgoingControlFrame(
            self.limits,
            opcode,
            payload,
        );
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        self.send_mutex.lockUncancelable(self.io);
        defer self.unlockSendBefore(null);
        try self.sendFrameValidatedLocked(opcode, payload);
    }

    pub fn sendFrameValidatedLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;
        self.writeFrameLocked(opcode, payload, true) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
        if (opcode == .close) self.close_sent.store(true, .release);
    }

    pub fn beginPendingControlLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        std.debug.assert(opcode == .ping or opcode == .close);
        var pending: PendingControlFrame = .{};
        @memcpy(pending.payload[0..payload.len], payload);
        pending.payload_len = payload.len;
        var mask_key: ?[4]u8 = null;
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try secure_random.fill(self.io, &key);
            mask_key = key;
        }
        const encoded = try websocket.writeFrameInto(
            &pending.bytes,
            opcode,
            payload,
            .{ .mask_key = mask_key },
        );
        pending.len = encoded.len;
        self.pending_write = switch (opcode) {
            .ping => .{ .ping = pending },
            .close => .{ .close = pending },
            else => unreachable,
        };
        self.application_write_pending.store(true, .release);
    }

    fn resumePendingControlLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = switch (opcode) {
            .ping => self.pending_write.pingPtr(),
            .close => self.pending_write.closePtr(),
            else => unreachable,
        } orelse return;
        if (!pending.matches(payload)) return error.WriteInProgress;
        var committed: usize = 0;
        self.transport().writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            &committed,
            deadline,
        ) catch |err| {
            pending.committed += committed;
            return err;
        };
        pending.committed += committed;
        std.debug.assert(pending.committed == pending.len);
        self.pending_write = .none;
        self.application_write_pending.store(false, .release);
    }

    pub fn resumePendingCloseLocked(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.writeAborted()) return error.ConnectionClosed;
        const pending = self.pending_write.closePtr() orelse return;
        var committed: usize = 0;
        self.transport().writeWithDeadline(
            pending.bytes[pending.committed..pending.len],
            &committed,
            deadline,
        ) catch |err| {
            pending.committed += committed;
            return err;
        };
        pending.committed += committed;
        std.debug.assert(pending.committed == pending.len);
        self.pending_write = .none;
        self.application_write_pending.store(false, .release);
        self.close_sent.store(true, .release);
    }

    pub fn sendMessage(self: *Connection, opcode: websocket.Opcode, payload: []const u8) Error!void {
        if (opcode != .text and opcode != .binary) return error.InvalidFrame;
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        try common.validateOutgoingMessage(self.limits, opcode, payload);
        self.send_mutex.lockUncancelable(self.io);
        defer self.unlockSendBefore(null);
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;

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

    pub fn sendMessageWithDeadlineLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.pending_write.isPing() or self.pending_write.isClose()) {
            return error.WriteInProgress;
        }

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
            if (!self.canSendOpcodeLocked(opcode)) {
                return error.ConnectionClosed;
            }
            try self.beginPendingMessageLocked(opcode, payload);
        }
        try self.resumePendingMessageLocked(payload, progress, deadline);
    }

    pub fn beginPendingMessageLocked(
        self: *Connection,
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
            try secure_random.fill(self.io, &key);
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
        self: *Connection,
        payload: []const u8,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending = PendingMessage{
            .opcode = .pong,
            .original_ptr = @intFromPtr(payload.ptr),
            .original_len = payload.len,
            .payload_len = payload.len,
        };
        if (self.role == .client) {
            var key: [4]u8 = undefined;
            try secure_random.fill(self.io, &key);
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
        self: *Connection,
        opcode: websocket.Opcode,
        parts: []const []const u8,
        payload_len: usize,
    ) Error!void {
        std.debug.assert(self.pending_write.isNone());
        var pending = PendingMessage{
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
            try secure_random.fill(self.io, &key);
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

    fn pendingPayload(
        self: *Connection,
        original_payload: []const u8,
    ) []const u8 {
        const pending = self.pending_write.messagePtr().?;
        return if (pending.compressed)
            self.compression_send.payload.items[0..pending.payload_len]
        else
            original_payload;
    }

    pub fn fillPendingMessageChunk(
        self: *Connection,
        original_payload: []const u8,
        out: []u8,
    ) Error![]const u8 {
        const pending = self.pending_write.messagePtr().?;
        const encoded_payload = self.pendingPayload(original_payload);
        const header_offset = @min(
            pending.committed,
            pending.header_len,
        );
        const payload_offset = pending.committed - header_offset;
        var out_len: usize = 0;
        if (header_offset < pending.header_len) {
            const header = pending.header[header_offset..pending.header_len];
            @memcpy(out[0..header.len], header);
            out_len = header.len;
        }
        const count = @min(
            out.len - out_len,
            encoded_payload.len - payload_offset,
        );
        if (pending.mask_key) |mask| {
            try websocket.applyMaskCopy(
                out[out_len..][0..count],
                encoded_payload[payload_offset..][0..count],
                mask,
                payload_offset,
            );
        } else {
            @memcpy(
                out[out_len..][0..count],
                encoded_payload[payload_offset..][0..count],
            );
        }
        out_len += count;
        return out[0..out_len];
    }

    pub fn resumePendingMessageLocked(
        self: *Connection,
        original_payload: []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.receiveFailed()) return error.ConnectionClosed;
        const pending = self.pending_write.messagePtr().?;
        var scratch: [masked_write_scratch_len]u8 align(64) = undefined;

        while (pending.committed < pending.totalLen()) {
            const wire_bytes = try self.fillPendingMessageChunk(
                original_payload,
                &scratch,
            );

            var transport_committed: usize = 0;
            self.transport().writeWithDeadline(
                wire_bytes,
                &transport_committed,
                deadline,
            ) catch |err| {
                pending.committed += transport_committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += transport_committed;
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
        self: *Connection,
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

            var transport_committed: usize = 0;
            self.transport().writeWithDeadline(
                scratch[0..wire_len],
                &transport_committed,
                deadline,
            ) catch |err| {
                pending.committed += transport_committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.totalLen(),
                };
                return err;
            };
            pending.committed += transport_committed;
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

    pub fn sendFragmented(self: *Connection, opcode: websocket.Opcode, fragments: []const []const u8) Error!void {
        if (!canSendOpcode(opcode, self.closeSent(), self.closeReceived())) {
            return error.ConnectionClosed;
        }
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );

        if (self.permessage_deflate) {
            self.send_mutex.lockUncancelable(self.io);
            defer self.unlockSendBefore(null);
            if (!self.pending_write.isNone() or control_admission.pending(self)) {
                return error.WriteInProgress;
            }
            if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;
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

        self.send_mutex.lockUncancelable(self.io);
        defer self.unlockSendBefore(null);
        if (!self.pending_write.isNone() or control_admission.pending(self)) {
            return error.WriteInProgress;
        }
        if (!self.canSendOpcodeLocked(opcode)) return error.ConnectionClosed;

        self.writeUncompressedFragmentsLocked(
            opcode,
            fragments,
        ) catch |err| {
            self.abortAfterUnboundedMessageWriteLocked();
            return err;
        };
    }

    pub fn sendFragmentedWithTimeout(
        self: *Connection,
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
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn sendFragmentedWithDeadline(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
        progress: *MessageWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const plain_len = try common.validateOutgoingFragments(
            self.limits,
            opcode,
            fragments,
        );
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        _ = try deadline_policy.usableAwake(self.io, deadline);
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
            if (!self.canSendOpcodeLocked(opcode)) {
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

    pub fn beginPendingFragmentedLocked(
        self: *Connection,
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
        self: *Connection,
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
            try secure_random.fill(self.io, &key);
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
        self: *Connection,
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
            var committed: usize = 0;
            self.transport().writeWithDeadline(
                scratch[0..len],
                &committed,
                deadline,
            ) catch |err| {
                pending.committed += committed;
                progress.* = .{
                    .committed_bytes = pending.committed,
                    .total_bytes = pending.wire_total,
                };
                return err;
            };
            pending.committed += committed;
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

    pub fn receiveFrame(self: *Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameInternal(null);
    }

    pub fn receiveFrameInternal(
        self: *Connection,
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
        if (self.closeReceived() and frame.header.opcode != .close) {
            return error.ConnectionClosed;
        }
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

    pub fn receiveFrameAuto(self: *Connection) Error!websocket.Frame {
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(null, .frame);
    }

    pub fn receiveFrameAutoWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!websocket.Frame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(
            .fromNow(
                self.io,
                .{ .raw = timeout, .clock = .awake },
            ),
            .frame,
        );
    }

    pub fn receiveFrameAutoWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!websocket.Frame {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.message_assembler != null or self.message_into.active()) {
            return error.InvalidFrame;
        }
        return self.receiveFrameAutoInternal(deadline, .frame);
    }

    pub fn receiveFrameAutoInternal(
        self: *Connection,
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
                    // tungstenite queues automatic Pong replies only while the
                    // connection is still active.  After we have sent Close,
                    // the peer may still deliver in-flight control frames, but
                    // replying with a fresh Pong would write after our close
                    // handshake started.
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

    pub fn receiveMessage(self: *Connection) Error!OwnedMessage {
        return self.receiveMessageInternal(null);
    }

    /// Receive one complete message within one relative application budget.
    pub fn receiveMessageWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedMessage {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveMessageInternal(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Receive one complete message under a caller-owned absolute deadline.
    ///
    /// The deadline is deliberately unchanged across continuation and control
    /// frames. Protocols such as MQTT can therefore enforce one packet-level
    /// inactivity budget without WebSocket Ping/Pong traffic extending it.
    pub fn receiveMessageWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.receiveMessageInternal(deadline);
    }

    pub fn receiveMessageInternal(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedMessage {
        return AllocatingMessageReceiver(Connection).receive(self, deadline);
    }

    /// Receive one complete message into caller-owned storage.
    ///
    /// `out` must be at least `limits.max_message_bytes`; this lets the method
    /// consume arbitrarily fragmented messages transactionally without finding
    /// a later fragment that no longer fits after earlier frames were removed
    /// from the transport buffer. Control frames retain the same automatic
    /// Pong/Close behavior as `receiveMessage`. Negotiated compressed messages
    /// use reusable connection scratch and inflate directly into `out`.
    /// Timeout, cancellation and executor admission errors retain progress;
    /// retry an incomplete message with the same output pointer and length.
    /// A final compressed decode OOM retains its owned input and permits a
    /// later retry with a new output slice.
    pub fn receiveMessageInto(
        self: *Connection,
        out: []u8,
    ) Error!Message {
        return receiveMessageIntoDirectConnection(self, out, null);
    }

    pub fn receiveMessageIntoWithTimeout(
        self: *Connection,
        out: []u8,
        timeout: std.Io.Duration,
    ) Error!Message {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return receiveMessageIntoDirectConnection(
            self,
            out,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Caller-buffer counterpart to `receiveMessageWithDeadline`. The same
    /// absolute deadline spans every fragment, TLS read, and interleaved
    /// control frame while preserving the allocation-avoiding receive path.
    pub fn receiveMessageIntoWithDeadline(
        self: *Connection,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Message {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return receiveMessageIntoDirectConnection(self, out, deadline);
    }

    pub fn ensureCompressionReceiveScratch(self: *Connection) Error!void {
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
        self: *Connection,
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
        self: *Connection,
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

    pub fn commitCompressionPreviewLocked(self: *Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.commitPreview() catch unreachable;
        }
    }

    pub fn discardCompressionPreviewLocked(self: *Connection) void {
        if (self.compression_send_context_takeover) {
            self.compression_send.discardPreview();
        }
    }

    pub fn abortAfterUnboundedMessageWriteLocked(self: *Connection) void {
        self.discardCompressionPreviewLocked();
        self.write_aborted.store(true, .release);
        transportStream(self.transport()).shutdown(self.io, .both) catch {};
        common.clearPendingOutboundLocked(self);
    }

    pub fn writeFrameLocked(self: *Connection, opcode: websocket.Opcode, payload: []const u8, fin: bool) Error!void {
        try self.writeFrameLockedExtended(opcode, payload, fin, .{});
    }

    pub fn writeFrameLockedExtended(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        fin: bool,
        options: struct { rsv1: bool = false },
    ) Error!void {
        const mask_key = if (self.role == .client) blk: {
            var key: [4]u8 = undefined;
            try secure_random.fill(self.io, &key);
            break :blk key;
        } else null;

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
        if (mask_key) |mask| {
            try writeMaskedPayload(
                self.transport(),
                header,
                payload,
                mask,
            );
        } else {
            try self.transport().writeAllParts(header, payload);
        }
    }

    pub fn writeCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        if (self.role == .client and
            try self.writeMaskedCompressedFragmentsBatchLocked(
                opcode,
                compressed_payload,
                frame_count,
            ))
        {
            return;
        }
        if (self.role == .server) {
            try self.writeUnmaskedCompressedFragmentsLocked(
                opcode,
                compressed_payload,
                frame_count,
            );
            return;
        }
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(compressed_payload.len, frame_count, index);
            try self.writeFrameLockedExtended(
                if (index == 0) opcode else .continuation,
                compressed_payload[range.start..range.end],
                index + 1 == frame_count,
                .{ .rsv1 = index == 0 },
            );
        }
    }

    fn writeMaskedCompressedFragmentsBatchLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!bool {
        const header_bound = std.math.mul(
            usize,
            frame_count,
            websocket.max_frame_header_len,
        ) catch return false;
        const required = std.math.add(
            usize,
            header_bound,
            compressed_payload.len,
        ) catch return false;
        if (required > masked_write_scratch_len) return false;

        // Mask each frame with its own RFC 6455 key, but stage the small
        // compressed message in the same bounded scratch already used by the
        // ordinary client masking path. One transport write then preserves all
        // frame boundaries without sixteen loopback syscalls for a 16-slice
        // application message. Larger messages retain the streaming fallback.
        var encoded: [masked_write_scratch_len]u8 align(64) = undefined;
        const max_mask_key_batch: usize = 16;
        var mask_keys: [max_mask_key_batch][4]u8 = undefined;
        var cursor: usize = 0;
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(
                compressed_payload.len,
                frame_count,
                index,
            );
            const payload = compressed_payload[range.start..range.end];
            const mask_key_index = index % max_mask_key_batch;
            if (mask_key_index == 0) {
                const key_count = @min(
                    max_mask_key_batch,
                    frame_count - index,
                );
                try common.randomMaskKeys(
                    self.io,
                    mask_keys[0..key_count],
                );
            }
            const mask_key = mask_keys[mask_key_index];
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                if (index == 0) opcode else .continuation,
                payload,
                .{
                    .fin = index + 1 == frame_count,
                    .mask_key = mask_key,
                    .rsv1 = index == 0,
                },
            );
            @memcpy(encoded[cursor..][0..header.len], header);
            cursor += header.len;
            try websocket.applyMaskCopy(
                encoded[cursor..][0..payload.len],
                payload,
                mask_key,
                0,
            );
            cursor += payload.len;
        }
        try self.transport().writeAll(encoded[0..cursor]);
        return true;
    }

    fn writeUnmaskedCompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        compressed_payload: []const u8,
        frame_count: usize,
    ) Error!void {
        // One logical message can contain many intentionally tiny compressed
        // continuation frames. Batch their stack headers and borrowed payload
        // ranges so TCP/std-TLS perform bounded writes/flushes instead of one
        // per frame. Larger frame counts fall back to the ordinary loop below.
        const max_batched_frames: usize = 16;
        if (frame_count > max_batched_frames) {
            for (0..frame_count) |index| {
                const range = compressedFragmentRange(
                    compressed_payload.len,
                    frame_count,
                    index,
                );
                try self.writeFrameLockedExtended(
                    if (index == 0) opcode else .continuation,
                    compressed_payload[range.start..range.end],
                    index + 1 == frame_count,
                    .{ .rsv1 = index == 0 },
                );
            }
            return;
        }

        var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
        var parts: [max_batched_frames * 2][]const u8 = undefined;
        for (0..frame_count) |index| {
            const range = compressedFragmentRange(
                compressed_payload.len,
                frame_count,
                index,
            );
            const payload = compressed_payload[range.start..range.end];
            parts[index * 2] = try websocket.writeFrameHeaderInto(
                &headers[index],
                if (index == 0) opcode else .continuation,
                payload,
                .{
                    .fin = index + 1 == frame_count,
                    .rsv1 = index == 0,
                },
            );
            parts[index * 2 + 1] = payload;
        }
        try self.transport().writeAllSlices(parts[0 .. frame_count * 2]);
    }

    pub fn writeUncompressedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) Error!void {
        if (self.role == .client and
            try self.writeMaskedUncompressedFragmentsBatchLocked(
                opcode,
                fragments,
            ))
        {
            return;
        }
        if (self.role == .server) {
            try self.writeUnmaskedFragmentsLocked(opcode, fragments);
            return;
        }
        for (fragments, 0..) |fragment, index| {
            try self.writeFrameLocked(
                if (index == 0) opcode else .continuation,
                fragment,
                index + 1 == fragments.len,
            );
        }
    }

    fn writeMaskedUncompressedFragmentsBatchLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) Error!bool {
        var required = std.math.mul(
            usize,
            fragments.len,
            websocket.max_frame_header_len,
        ) catch return false;
        for (fragments) |fragment| {
            required = std.math.add(
                usize,
                required,
                fragment.len,
            ) catch return false;
        }
        if (required > masked_write_scratch_len) return false;

        var encoded: [masked_write_scratch_len]u8 align(64) = undefined;
        const max_mask_key_batch: usize = 16;
        var mask_keys: [max_mask_key_batch][4]u8 = undefined;
        var cursor: usize = 0;
        for (fragments, 0..) |fragment, index| {
            const mask_key_index = index % max_mask_key_batch;
            if (mask_key_index == 0) {
                const key_count = @min(
                    max_mask_key_batch,
                    fragments.len - index,
                );
                try common.randomMaskKeys(
                    self.io,
                    mask_keys[0..key_count],
                );
            }
            const frame = try websocket.writeFrameInto(
                encoded[cursor..],
                if (index == 0) opcode else .continuation,
                fragment,
                .{
                    .fin = index + 1 == fragments.len,
                    .mask_key = mask_keys[mask_key_index],
                },
            );
            cursor += frame.len;
        }
        try self.transport().writeAll(encoded[0..cursor]);
        return true;
    }

    fn writeUnmaskedFragmentsLocked(
        self: *Connection,
        opcode: websocket.Opcode,
        fragments: []const []const u8,
    ) Error!void {
        const max_batched_frames: usize = 16;
        var frame_index: usize = 0;
        while (frame_index < fragments.len) {
            const batch_count = @min(
                max_batched_frames,
                fragments.len - frame_index,
            );
            var headers: [max_batched_frames][websocket.max_frame_header_len]u8 = undefined;
            var parts: [max_batched_frames * 2][]const u8 = undefined;
            for (0..batch_count) |batch_index| {
                const index = frame_index + batch_index;
                const fragment = fragments[index];
                parts[batch_index * 2] =
                    try websocket.writeFrameHeaderInto(
                        &headers[batch_index],
                        if (index == 0) opcode else .continuation,
                        fragment,
                        .{ .fin = index + 1 == fragments.len },
                    );
                parts[batch_index * 2 + 1] = fragment;
            }
            try self.transport().writeAllSlices(
                parts[0 .. batch_count * 2],
            );
            frame_index += batch_count;
        }
    }

    fn ensureBuffered(self: *Connection, len: usize) Error!void {
        return self.ensureBufferedWithDeadline(len, null);
    }

    /// Fill exactly the requested prefix without reading payload bytes that a
    /// caller-buffer receive can place directly in its final destination.
    pub fn ensureBufferedExactWithDeadline(
        self: *Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
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
            const count = if (deadline) |absolute|
                try self.transport().readWithDeadline(destination, absolute)
            else
                try self.transport().read(destination);
            if (count == 0) return error.ConnectionClosed;
            message_buffer.commitAppend(&self.inbuf, count);
        }
    }

    pub fn readMessagePayloadChunk(
        self: *Connection,
        out: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!usize {
        if (deadline) |absolute| {
            return self.transport().readWithDeadline(out, absolute);
        }
        return self.transport().read(out);
    }

    pub fn ensureBufferedWithDeadline(
        self: *Connection,
        len: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        var scratch: [transport_read_scratch_len]u8 = undefined;
        while (message_buffer.unreadLen(
            &self.inbuf,
            self.inbuf_consumed,
        ) < len) {
            const n = if (deadline) |absolute|
                try self.transport().readWithDeadline(&scratch, absolute)
            else
                try self.transport().read(&scratch);
            if (n == 0) return error.ConnectionClosed;
            // One socket read commonly returns one complete WebSocket frame.
            // ArrayList's geometric append growth retained roughly 6.5 KiB for
            // every 4 KiB benchmark connection. Exact growth preserves the
            // same reuse while retaining only bytes the transport delivered.
            try message_buffer.appendAfterConsumed(
                &self.inbuf,
                &self.inbuf_consumed,
                self.allocator,
                scratch[0..n],
            );
        }
    }

    pub fn discardBuffered(self: *Connection, len: usize) void {
        _ = message_buffer.discardPrefix(
            &self.inbuf,
            &self.inbuf_consumed,
            len,
        );
    }

    /// Call only while holding `send_mutex`. Every writer repeats its close
    /// check here so one queued behind an earlier Close cannot append a frame.
    pub fn canSendOpcodeLocked(
        self: *const Connection,
        opcode: websocket.Opcode,
    ) bool {
        if (self.writeAborted()) return false;
        if (self.receiveFailed()) return false;
        return canSendOpcode(opcode, self.closeSent(), self.closeReceived());
    }

    pub fn closeSent(self: *const Connection) bool {
        return self.close_sent.load(.acquire);
    }

    pub fn closeReceived(self: *const Connection) bool {
        return self.receiveFailed() or self.close_received.load(.acquire);
    }

    pub fn receiveFailed(self: *const Connection) bool {
        return self.receive_failed.load(.acquire);
    }

    pub fn writeAborted(self: *const Connection) bool {
        return self.write_aborted.load(.acquire);
    }

    pub fn ensureNoPendingWrites(self: *Connection) Error!void {
        if (self.application_write_pending.load(.acquire) or
            control_admission.pending(self))
        {
            return error.WriteInProgress;
        }
    }

    fn pendingAutomaticControlOpcode(
        self: *Connection,
        delivery: PendingAutomaticControl.Delivery,
    ) Error!?websocket.Opcode {
        return self.pendingAutomaticControlOpcodeBefore(delivery, null);
    }

    pub fn pendingAutomaticControlOpcodeBefore(
        self: *Connection,
        delivery: PendingAutomaticControl.Delivery,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?websocket.Opcode {
        if (!control_admission.pending(self)) return null;
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        if (self.automatic_control_admission) |waiting| {
            if (waiting.delivery != delivery) return error.WriteInProgress;
            return waiting.opcode;
        }
        const pending = self.pending_auto_control orelse return null;
        if (pending.delivery != delivery) return error.WriteInProgress;
        return pending.opcode;
    }

    fn abortReceiveTransportLocked(self: *Connection, deadline: ?std.Io.Clock.Timestamp) bool {
        _ = deadline;
        transportStream(self.transport()).shutdown(self.io, .both) catch {};
        return true;
    }

    pub fn finishDeferredReceiveAbortLocked(self: *Connection, deadline: ?std.Io.Clock.Timestamp) void {
        if (!self.receive_abort_pending.load(.acquire)) return;
        receive_cleanup.finishLocked(self, self.io, deadline, false, abortReceiveTransportLocked);
    }

    pub fn unlockSendBefore(self: *Connection, deadline: ?std.Io.Clock.Timestamp) void {
        self.finishDeferredReceiveAbortLocked(deadline);
        self.send_mutex.unlock(self.io);
    }

    pub fn deferReceiveAbort(self: *Connection, deadline: ?std.Io.Clock.Timestamp) void {
        receive_cleanup.request(self);
        transportStream(self.transport()).shutdown(self.io, .both) catch {};
        // Publication may race the original holder's unlock. A free mutex
        // lets this receiver retire local state without waiting again.
        if (self.send_mutex.tryLock()) {
            defer self.send_mutex.unlock(self.io);
            self.finishDeferredReceiveAbortLocked(deadline);
        }
    }

    pub fn finishReceiveFailure(
        self: *Connection,
        code: websocket.CloseCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        timed_mutex.lock(&self.send_mutex, self.io, deadline) catch {
            self.deferReceiveAbort(deadline);
            return;
        };
        defer self.send_mutex.unlock(self.io);
        if (!self.pending_write.isNone() or
            control_admission.pending(self))
        {
            self.write_aborted.store(true, .release);
            transportStream(self.transport()).shutdown(self.io, .both) catch {};
            common.clearPendingOutboundLocked(self);
            return;
        }
        if (self.closeSent()) return;
        var storage: [125]u8 = undefined;
        const payload = websocket.writeClosePayloadInto(
            &storage,
            .{ .code = code },
        ) catch return;
        if (deadline) |absolute| {
            self.beginPendingControlLocked(
                .close,
                payload,
            ) catch {
                self.write_aborted.store(true, .release);
                transportStream(self.transport()).shutdown(self.io, .both) catch {};
                common.clearPendingOutboundLocked(self);
                return;
            };
            self.resumePendingCloseLocked(absolute) catch {
                self.write_aborted.store(true, .release);
                transportStream(self.transport()).shutdown(self.io, .both) catch {};
                common.clearPendingOutboundLocked(self);
            };
            return;
        }
        self.writeFrameLocked(.close, payload, true) catch {
            self.write_aborted.store(true, .release);
            transportStream(self.transport()).shutdown(self.io, .both) catch {};
            return;
        };
        self.close_sent.store(true, .release);
    }

    pub fn finishAbruptReceiveEnd(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        timed_mutex.lock(&self.send_mutex, self.io, deadline) catch {
            self.deferReceiveAbort(deadline);
            return;
        };
        defer self.send_mutex.unlock(self.io);
        self.write_aborted.store(true, .release);
        transportStream(self.transport()).shutdown(self.io, .both) catch {};
        common.clearPendingOutboundLocked(self);
    }

    pub fn beginAutomaticControl(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        delivery: PendingAutomaticControl.Delivery,
        frame: ?websocket.Frame,
    ) Error!void {
        return self.beginAutomaticControlBefore(opcode, payload, delivery, frame, null, 0);
    }

    pub fn beginAutomaticControlBefore(
        self: *Connection,
        opcode: websocket.Opcode,
        payload: []const u8,
        delivery: PendingAutomaticControl.Delivery,
        frame: ?websocket.Frame,
        deadline: ?std.Io.Clock.Timestamp,
        consumed_input: usize,
    ) Error!void {
        try control_admission.stage(self, opcode, payload, delivery, frame, consumed_input);
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        const consumed = try control_admission.admit(self, self.io, self.role, true);
        if (consumed != 0) self.discardBuffered(consumed);
    }

    pub fn resumeAutomaticControl(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?websocket.Frame {
        try timed_mutex.lock(&self.send_mutex, self.io, deadline);
        defer self.unlockSendBefore(deadline);
        const consumed = try control_admission.admit(self, self.io, self.role, true);
        if (consumed != 0) self.discardBuffered(consumed);
        const pending = if (self.pending_auto_control) |*value|
            value
        else
            return null;
        if (!self.pending_write.isNone()) return error.WriteInProgress;
        if (!self.canSendOpcodeLocked(pending.opcode)) {
            pending.writes_reply = false;
        }
        try automatic_control.resumeEncoding(pending, self.io, self.role);
        if (!pending.complete() and deadline != null) {
            const absolute = deadline.?;
            _ = try deadline_policy.usableAwake(self.io, absolute);
            var committed: usize = 0;
            self.transport().writeWithDeadline(
                pending.bytes[pending.committed..pending.len],
                &committed,
                absolute,
            ) catch |err| {
                pending.committed += committed;
                return err;
            };
            pending.committed += committed;
        } else if (!pending.complete()) {
            var committed: usize = 0;
            self.transport().finishPendingTimedWrite(&committed) catch |err| {
                pending.committed += committed;
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            pending.committed += committed;
            std.debug.assert(pending.committed <= pending.len);
            self.transport().writeAll(
                pending.bytes[pending.committed..pending.len],
            ) catch |err| {
                self.abortAfterUnboundedMessageWriteLocked();
                return err;
            };
            pending.committed = pending.len;
        }
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

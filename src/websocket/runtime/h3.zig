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
const http3 = @import("../../http3/mod.zig");

pub const Error = websocket.Error || http3.runtime.Error || error{
    ConnectionClosed,
    ConcurrencyUnavailable,
    InvalidResponse,
    InvalidOrigin,
    InvalidSubprotocol,
    MessageTooLarge,
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
        permessage_deflate: bool = false,
        compression_threshold: usize = 32,
        compression_send_max_window_bits: u8 = 15,
        compression_send: compression_scratch.SendScratch = .{},
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
            var total: usize = 0;
            for (fragments) |fragment| {
                total = std.math.add(usize, total, fragment.len) catch
                    return error.PayloadTooLarge;
                if (fragment.len > self.limits.max_frame_bytes) {
                    return error.MessageTooLarge;
                }
            }
            if (total > self.limits.max_message_bytes) {
                return error.MessageTooLarge;
            }
            var joined: std.ArrayList(u8) = .empty;
            defer joined.deinit(self.allocator);
            const needs_join = opcode == .text or
                (self.permessage_deflate and
                    total >= self.compression_threshold);
            if (needs_join) {
                try joined.ensureTotalCapacity(self.allocator, total);
                for (fragments) |fragment| {
                    joined.appendSliceAssumeCapacity(fragment);
                }
            }
            if (opcode == .text and !std.unicode.utf8ValidateSlice(joined.items)) {
                return error.InvalidUtf8;
            }
            if (self.permessage_deflate and
                total >= self.compression_threshold)
            {
                const compressed = try self.compressMessage(joined.items);
                if (compressed.len < total) {
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

        pub fn sendClose(
            self: *Self,
            code: websocket.CloseCode,
            reason: []const u8,
        ) Error!void {
            var payload_storage: [125]u8 = undefined;
            const payload = try websocket.writeClosePayloadInto(
                &payload_storage,
                .{ .code = code, .reason = reason },
            );
            try self.sendControlFrame(.close, payload);
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
            return self.receiveMessageInternal(deadline);
        }

        fn receiveMessageInternal(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!common.OwnedMessage {
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
                            defer self.allocator.free(assembled.payload);
                            const payload = try websocket.decompressMessage(
                                self.allocator,
                                assembled.payload,
                                self.limits.max_message_bytes,
                            );
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

        pub fn receiveFrame(self: *Self) Error!websocket.Frame {
            return self.receiveFrameInternal(null);
        }

        pub fn receiveFrameWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) Error!websocket.Frame {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveFrameInternal(.fromNow(
                self.io(),
                .{ .raw = timeout, .clock = .awake },
            ));
        }

        pub fn receiveFrameWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) Error!websocket.Frame {
            return self.receiveFrameInternal(deadline);
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
            var header_storage: [websocket.max_frame_header_len]u8 = undefined;
            const header = try websocket.writeFrameHeaderInto(
                &header_storage,
                opcode,
                payload,
                .{ .fin = frame_fin, .mask_key = mask_key, .rsv1 = rsv1 },
            );
            if (mask_key) |mask| {
                var scratch: [16 * 1024]u8 = undefined;
                var offset: usize = 0;
                var header_pending = true;
                while (offset < payload.len) {
                    const count = @min(scratch.len, payload.len - offset);
                    try websocket.applyMaskCopy(
                        scratch[0..count],
                        payload[offset..][0..count],
                        mask,
                        offset,
                    );
                    if (header_pending) {
                        try self.writeParts(
                            &.{ header, scratch[0..count] },
                            fin_stream and offset + count == payload.len,
                        );
                        header_pending = false;
                    } else {
                        try self.writeBytes(
                            scratch[0..count],
                            fin_stream and offset + count == payload.len,
                        );
                    }
                    offset += count;
                }
                if (header_pending) try self.writeBytes(header, fin_stream);
            } else {
                try self.writeParts(&.{ header, payload }, fin_stream);
            }
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
        if (!h3.options.local_settings.enable_connect_protocol) {
            return error.ExtendedConnectDisabled;
        }
        return connectEstablished(allocator, h3, options);
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
        return connectEstablished(allocator, &h3, options);
    }
};

fn connectEstablished(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeClient,
    options: ConnectOptions,
) Error!ClientConnection {
    try validateClientExtraHeaders(options.extra_headers);
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
    const stream_id = try h3.startRequest(.{
        .method = "CONNECT",
        .path = options.path,
        .scheme = "https",
        .authority = options.authority,
        .headers = fields.items,
    }, null);
    var response = try receiveResponseHead(h3, stream_id);
    defer response.deinit(allocator);
    if (response.status < 200 or response.status >= 300) {
        return error.InvalidResponse;
    }
    if (!h3.control.settings.peer.enable_connect_protocol) {
        return error.ExtendedConnectDisabled;
    }
    const selected_protocol = try validateServerHandshake(
        allocator,
        response.headers,
        options.protocols,
    );
    errdefer if (selected_protocol) |protocol| allocator.free(protocol);
    const negotiated_extension = try websocket.ExtensionNegotiation
        .validateResponse(try optionalHeader(
        response.headers,
        "sec-websocket-extensions",
    ));
    if (negotiated_extension.permessage_deflate and
        !options.enable_permessage_deflate)
    {
        return error.InvalidExtension;
    }
    const owned_h3 = h3.*;
    h3.* = undefined;
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
        return acceptServerSession(self.transport.allocator, &h3, options);
    }

    pub fn acceptSession(
        allocator: std.mem.Allocator,
        h3: *http3.runtime.HandshakeServerSession,
        options: AcceptOptions,
    ) Error!ServerConnection {
        return acceptServerSession(allocator, h3, options);
    }
};

fn acceptServerSession(
    allocator: std.mem.Allocator,
    h3: *http3.runtime.HandshakeServerSession,
    options: AcceptOptions,
) Error!ServerConnection {
    try h3.ensureSettingsSent();
    var request = try receiveRequestHead(h3);
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
    while (true) {
        var event = try h3.receiveRequestEvent();
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
    while (true) {
        var event = (try h3.receiveResponseEvent(stream_id)) orelse continue;
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
    for (supported) |protocol| {
        if (!websocket.validSubprotocolToken(protocol)) {
            return error.InvalidSubprotocol;
        }
    }
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

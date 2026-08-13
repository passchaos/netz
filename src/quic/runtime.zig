const std = @import("std");
const builtin = @import("builtin");
const quic = @import("mod.zig");

const net = std.Io.net;

pub const Error = quic.Error || error{
    EmptyDatagram,
    DatagramTooLarge,
    TrailingBytes,
    NoConnectionRoute,
    EcnUnavailable,
    InvalidGroSegment,
} || quic.connection_router.Error || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveError || std.Io.RandomSecureError || std.Io.Cancelable;
pub const ReceiveTimeoutError = Error ||
    std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

pub const Limits = struct {
    max_datagram_size: usize = 65_535,
    max_frames_per_datagram: usize = 256,
    /// Best-effort SO_RCVBUF target for UDP sockets.
    ///
    /// High-throughput QUIC workloads can burst many datagrams before the peer
    /// gets scheduled to drain its socket. A larger kernel receive queue avoids
    /// local benchmark drops that would otherwise force PTO recovery or leave
    /// simple blocking examples waiting for a response the kernel discarded.
    /// The kernel may clamp or double this value; unsupported platforms ignore
    /// it.
    socket_receive_buffer_bytes: usize = 4 * 1024 * 1024,
    /// Use Linux UDP_SEGMENT when a batch is already laid out as compatible
    /// contiguous segments. Unsupported kernels still fall back automatically.
    enable_gso_send: bool = true,
    /// Enable Linux UDP_GRO coalescing. Coalesced packets are exposed through
    /// the batch receive API without per-packet syscalls. Keep this opt-in
    /// because single-datagram consumers cannot amortize GRO bookkeeping.
    enable_gro_receive: bool = false,
};

pub const SendManyBytesResult = struct {
    /// Number of datagrams successfully handed to the socket, always a prefix
    /// of the caller's slice.
    sent_count: usize,
    /// A batch syscall can send a non-empty prefix before reporting the error
    /// for the next datagram. Keeping that progress lets stateful transports
    /// commit consumed packet numbers instead of accidentally reusing them.
    send_error: ?net.Socket.SendError = null,
};

pub const Server = struct {
    endpoint: Endpoint,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .endpoint = try .bind(allocator, io, bind_address, limits) };
    }

    pub fn deinit(self: *Server) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn receive(self: *Server) Error!OwnedDatagram {
        return self.endpoint.receive();
    }

    pub fn receiveBytesHandlingVersionNegotiation(self: *Server, supported_versions: []const u32) Error!OwnedBytes {
        return self.endpoint.receiveBytesHandlingVersionNegotiation(supported_versions);
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiation(
        self: *Server,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
    ) Error!RoutedBytes {
        return self.endpoint.receiveRoutedBytesHandlingVersionNegotiation(router, supported_versions);
    }

    pub fn sendFrames(self: *Server, to: net.IpAddress, frames: []const quic.Frame) Error!void {
        try self.endpoint.sendFrames(to, frames);
    }
};

pub const Client = struct {
    endpoint: Endpoint,
    peer: net.IpAddress,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, peer: net.IpAddress, limits: Limits) Error!Client {
        return .{
            .endpoint = try .bind(allocator, io, local_address, limits),
            .peer = peer,
        };
    }

    pub fn deinit(self: *Client) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn sendFrames(self: *Client, frames: []const quic.Frame) Error!void {
        try self.endpoint.sendFrames(self.peer, frames);
    }

    pub fn receive(self: *Client) Error!OwnedDatagram {
        return self.endpoint.receive();
    }
};

pub const Endpoint = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    socket: net.Socket,
    limits: Limits = .{},
    receive_ecn_enabled: bool = false,
    send_ecn_mark: quic.packet_space.EcnCodepoint = .not_ect,
    gso_send_enabled: bool = udpGsoSupported(),
    gro_receive_enabled: bool = false,
    socket_receive_mutex: std.Io.Mutex = .init,
    pending_receive_mutex: std.Io.Mutex = .init,
    pending_received: std.ArrayList(OwnedBytes) = .empty,
    pending_receive_index: usize = 0,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Endpoint {
        var endpoint = Endpoint{
            .io = io,
            .allocator = allocator,
            .socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .limits = limits,
            .gso_send_enabled = limits.enable_gso_send and udpGsoSupported(),
        };
        errdefer endpoint.deinit();
        endpoint.configureSocketReceiveBuffer();
        endpoint.enableEcnReceive();
        endpoint.enableGroReceive();
        return endpoint;
    }

    pub fn deinit(self: *Endpoint) void {
        for (self.pending_received.items[self.pending_receive_index..]) |*pending| {
            pending.deinit(self.allocator);
        }
        self.pending_received.deinit(self.allocator);
        self.socket.close(self.io);
        self.* = undefined;
    }

    pub fn address(self: Endpoint) net.IpAddress {
        return self.socket.address;
    }

    pub fn gsoSendEnabled(self: Endpoint) bool {
        return self.gso_send_enabled;
    }

    pub fn groReceiveEnabled(self: Endpoint) bool {
        return self.gro_receive_enabled;
    }

    pub fn sendBytes(self: *Endpoint, to: net.IpAddress, bytes: []const u8) Error!void {
        try self.sendBytesWithEcn(to, bytes, .not_ect);
    }

    /// Send one UDP datagram with the requested ECN codepoint on platforms
    /// where the socket API exposes TOS/TCLASS marking.  Unsupported platforms
    /// reject non-Not-ECT marks instead of silently pretending ECN validation
    /// can run.
    pub fn sendBytesWithEcn(self: *Endpoint, to: net.IpAddress, bytes: []const u8, ecn: quic.packet_space.EcnCodepoint) Error!void {
        if (bytes.len == 0) return error.EmptyDatagram;
        if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        try self.applyOutgoingEcnMark(ecn);
        try self.socket.send(self.io, &to, bytes);
    }

    /// Send multiple UDP datagrams through the backend's batch primitive.
    ///
    /// Zig's Threaded backend maps this to Linux `sendmmsg` in chunks of 64
    /// messages; other backends retain identical semantics with a safe
    /// per-message fallback. Validation happens before the first syscall so
    /// invalid input cannot produce a partially sent batch.
    pub fn sendManyBytes(self: *Endpoint, to: net.IpAddress, datagrams: []const []const u8) Error!void {
        const result = try self.sendManyBytesProgress(to, datagrams);
        if (result.send_error) |err| return err;
        std.debug.assert(result.sent_count == datagrams.len);
    }

    /// Send a batch while preserving progress if the socket accepts a prefix.
    ///
    /// Linux `sendmmsg` and the portable per-message fallback can both report
    /// an error after earlier datagrams have already left the process. A plain
    /// error union cannot carry that count, so stateful callers such as QUIC
    /// recovery use this result to commit the sent prefix and roll back only
    /// the unsent suffix. Validation and ECN setup still fail through the error
    /// union because they happen before the first datagram can be emitted.
    pub fn sendManyBytesProgress(self: *Endpoint, to: net.IpAddress, datagrams: []const []const u8) Error!SendManyBytesResult {
        if (datagrams.len == 0) return .{ .sent_count = 0 };
        for (datagrams) |bytes| {
            if (bytes.len == 0) return error.EmptyDatagram;
            if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        }
        try self.applyOutgoingEcnMark(.not_ect);

        if (self.gso_send_enabled) {
            if (gsoPlan(datagrams)) |plan| {
                if (self.sendGso(to, plan)) |result| return result;
            }
        }

        // Match the Threaded backend's Linux sendmmsg chunk size. Keeping the
        // descriptors on the stack makes steady-state batch submission
        // allocation-free on every backend.
        var message_storage: [64]net.OutgoingMessage = undefined;
        var offset: usize = 0;
        while (offset < datagrams.len) {
            const count = @min(message_storage.len, datagrams.len - offset);
            const messages = message_storage[0..count];
            const chunk = datagrams[offset..][0..count];
            for (messages, chunk) |*message, bytes| {
                message.* = .{
                    .address = &to,
                    .data_ptr = bytes.ptr,
                    .data_len = bytes.len,
                };
            }
            const send_error, const sent_count = self.io.vtable.netSend(
                self.io.userdata,
                self.socket.handle,
                messages,
                .{},
            );
            if (sent_count > count) {
                // The backend violated its ABI, so the exact count is
                // unknowable. Conservatively consume the entire submitted
                // chunk: reusing any of its QUIC packet numbers would be worse
                // than treating an unsent datagram as lost.
                return .{ .sent_count = offset + count, .send_error = error.Unexpected };
            }
            for (messages[0..sent_count], chunk[0..sent_count]) |message, bytes| {
                if (message.data_len != bytes.len) {
                    return .{
                        .sent_count = offset + sent_count,
                        .send_error = error.MessageOversize,
                    };
                }
            }
            offset += sent_count;
            if (send_error) |err| {
                return .{ .sent_count = offset, .send_error = err };
            }
            // Socket.sendMany assumes the backend always supplies an error
            // alongside a short count. Preserve that contract violation as an
            // explicit result instead of spinning if a custom backend is bad.
            if (sent_count != count) {
                return .{ .sent_count = offset, .send_error = error.Unexpected };
            }
        }
        return .{ .sent_count = offset };
    }

    /// Submit a Linux UDP GSO super-packet. Returning `null` means the kernel
    /// rejected GSO before accepting data and the caller should retry through
    /// the portable send-many path.
    fn sendGso(self: *Endpoint, to: net.IpAddress, plan: GsoPlan) ?SendManyBytesResult {
        var control: [udp_gso_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        const control_slice = encodeUdpGsoControl(&control, plan.segment_size);
        var message: net.OutgoingMessage = .{
            .address = &to,
            .data_ptr = plan.data_ptr,
            .data_len = plan.total_len,
            .control = control_slice,
        };
        const send_error, const sent_count = self.io.vtable.netSend(
            self.io.userdata,
            self.socket.handle,
            (&message)[0..1],
            .{},
        );
        if (sent_count == 1) {
            return .{
                .sent_count = plan.segment_count,
                .send_error = if (message.data_len == plan.total_len)
                    send_error
                else
                    error.MessageOversize,
            };
        }
        if (sent_count > 1) {
            // The backend violated its ABI. Conservatively consume every
            // segment because the exact subset visible on the network is no
            // longer knowable and QUIC packet numbers must never be reused.
            return .{ .sent_count = plan.segment_count, .send_error = error.Unexpected };
        }
        const err = send_error orelse return .{ .sent_count = 0, .send_error = error.Unexpected };
        if (gsoFallbackError(err)) {
            // Linux reports unsupported UDP_SEGMENT through an I/O-style
            // socket error. Zig deliberately normalizes undocumented errno
            // values to Unexpected, so remember the failure and avoid paying
            // for another speculative GSO syscall on this endpoint.
            self.gso_send_enabled = false;
            return null;
        }
        return .{ .sent_count = 0, .send_error = err };
    }

    pub fn sendFrames(self: *Endpoint, to: net.IpAddress, frames: []const quic.Frame) Error!void {
        var payload_len: usize = 0;
        for (frames) |frame| {
            payload_len = std.math.add(
                usize,
                payload_len,
                try frame.wireLen(),
            ) catch return error.InvalidFrameLength;
        }
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.ensureTotalCapacity(self.allocator, payload_len);
        for (frames) |frame| try frame.write(&payload, self.allocator);
        try self.sendBytes(to, payload.items);
    }

    /// Build a Version Negotiation response for a received unsupported-version
    /// long-header datagram.
    ///
    /// This is intentionally version-independent: it only peeks the invariant
    /// long-header fields, validates endpoint configuration, and then delegates
    /// packet serialization to `quic.writeVersionNegotiationPacket`.  Malformed
    /// or truncated trigger datagrams are dropped by returning `null`, which is
    /// the safer socket-loop behavior for attacker-controlled UDP input.
    pub fn versionNegotiationResponse(
        self: *Endpoint,
        datagram: []const u8,
        supported_versions: []const u32,
    ) Error!?[]u8 {
        try validateSupportedVersions(supported_versions);
        const ids = peekUnsupportedVersionConnectionIds(datagram, supported_versions) orelse return null;

        var response: std.ArrayList(u8) = .empty;
        errdefer response.deinit(self.allocator);
        try quic.writeVersionNegotiationPacket(&response, self.allocator, .{
            .first_byte = try versionNegotiationFirstByte(self.io),
            .destination_connection_id = ids.source_connection_id,
            .source_connection_id = ids.destination_connection_id,
            .versions = supported_versions,
        });
        return try response.toOwnedSlice(self.allocator);
    }

    /// Send Version Negotiation to `to` when `datagram` is an unsupported QUIC
    /// long-header packet. Returns `false` for short headers, already-supported
    /// versions, received Version Negotiation packets, or malformed datagrams.
    pub fn sendVersionNegotiationIfUnsupported(
        self: *Endpoint,
        to: net.IpAddress,
        datagram: []const u8,
        supported_versions: []const u32,
    ) Error!bool {
        const response = (try self.versionNegotiationResponse(datagram, supported_versions)) orelse return false;
        defer self.allocator.free(response);
        try self.sendBytes(to, response);
        return true;
    }

    pub fn receive(self: *Endpoint) Error!OwnedDatagram {
        var raw = try self.receiveBytes();
        errdefer raw.deinit(self.allocator);
        if (raw.bytes.len == 0) return error.EmptyDatagram;

        var frames: std.ArrayList(quic.Frame) = .empty;
        errdefer {
            quic.deinitOwnedFrameSlice(frames.items, self.allocator);
            frames.deinit(self.allocator);
        }

        var pos: usize = 0;
        while (pos < raw.bytes.len) {
            if (frames.items.len >= self.limits.max_frames_per_datagram) return error.DatagramTooLarge;
            var parsed = try quic.parseFrameOwned(self.allocator, raw.bytes[pos..]);
            var appended = false;
            defer if (!appended) parsed.deinitOwned(self.allocator);
            if (parsed.consumed == 0) return error.TrailingBytes;
            try frames.append(self.allocator, parsed.frame);
            appended = true;
            pos += parsed.consumed;
        }

        const owned_frames = try frames.toOwnedSlice(self.allocator);
        return .{
            .from = raw.from,
            .bytes = raw.bytes,
            .ecn = raw.ecn,
            .frames = owned_frames,
            .shared_buffer = raw.shared_buffer,
        };
    }

    pub fn receiveBytes(self: *Endpoint) Error!OwnedBytes {
        return self.receiveBytesWithEcn();
    }

    /// Receive one datagram with a caller-supplied deadline.
    ///
    /// Pending GRO segments are consumed before arming a kernel timeout. This
    /// keeps timed handshake loops compatible with the ordinary receive FIFO.
    pub fn receiveBytesTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        if (self.takePendingReceived()) |pending| return pending;
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (self.takePendingReceived()) |pending| return pending;
        return self.receiveKernelBytesTimeout(timeout);
    }

    /// Receive one kernel datagram, which may contain multiple UDP_GRO
    /// segments. The returned batch owns one allocation and exposes individual
    /// datagrams as borrowed slices through `datagramAt`.
    pub fn receiveBytesBatch(self: *Endpoint) Error!OwnedBytesBatch {
        return self.receiveBytesBatchWithEcn();
    }

    pub fn receiveBytesBatchWithEcn(self: *Endpoint) Error!OwnedBytesBatch {
        if (self.takePendingReceived()) |pending| {
            return ownedBytesAsBatch(pending);
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        // Another receive may have filled the FIFO while this caller waited
        // for the socket. Recheck before issuing an unnecessary blocking recv.
        if (self.takePendingReceived()) |pending| return ownedBytesAsBatch(pending);
        return self.receiveKernelBytesBatchWithEcn();
    }

    /// Receive one UDP datagram and preserve the kernel-reported ECN codepoint.
    /// If ancillary ECN reception was unavailable when the socket was bound,
    /// callers get `.not_ect`, matching the conservative QUIC fallback.
    pub fn receiveBytesWithEcn(self: *Endpoint) Error!OwnedBytes {
        if (self.takePendingReceived()) |pending| return pending;
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (self.takePendingReceived()) |pending| return pending;

        var batch = try self.receiveKernelBytesBatchWithEcn();
        errdefer batch.deinit(self.allocator);
        if (batch.segment_count == 1) {
            const result: OwnedBytes = .{
                .from = batch.from,
                .bytes = batch.storage,
                .ecn = batch.ecn,
                .shared_buffer = batch.shared_buffer,
            };
            batch.disown();
            return result;
        }

        self.pending_receive_mutex.lockUncancelable(self.io);
        defer self.pending_receive_mutex.unlock(self.io);
        try self.ensurePendingReceivedCapacity(batch.segment_count - 1);
        const shared = try self.allocator.create(SharedReceiveBuffer);
        shared.* = .{
            .allocator = self.allocator,
            .storage = batch.storage,
            .references = .init(batch.segment_count),
        };
        batch.disown();
        var index: usize = 1;
        while (index < batch.segment_count) : (index += 1) {
            self.pending_received.appendAssumeCapacity(.{
                .from = batch.from,
                .bytes = batch.datagramAtUnchecked(index),
                .ecn = batch.ecn,
                .shared_buffer = shared,
            });
        }
        return .{
            .from = batch.from,
            .bytes = batch.datagramAtUnchecked(0),
            .ecn = batch.ecn,
            .shared_buffer = shared,
        };
    }

    fn receiveKernelBytesBatchWithEcn(self: *Endpoint) Error!OwnedBytesBatch {
        const receive_capacity = if (self.gro_receive_enabled)
            std.math.maxInt(u16)
        else
            self.limits.max_datagram_size;
        const buffer = try self.allocator.alloc(u8, receive_capacity);
        var buffer_owned = true;
        errdefer if (buffer_owned) self.allocator.free(buffer);
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        @memset(&control_buffer, 0);
        var incoming: net.IncomingMessage = .init;
        incoming.control = &control_buffer;
        const maybe_err, const count = (try self.io.operate(.{ .net_receive = .{
            .socket_handle = self.socket.handle,
            .message_buffer = (&incoming)[0..1],
            .data_buffer = buffer,
            .flags = .{},
        } })).net_receive;
        if (maybe_err) |err| return err;
        std.debug.assert(count == 1);
        if (incoming.data.len == 0) return error.EmptyDatagram;
        if (incoming.flags.trunc or incoming.flags.ctrunc) return error.DatagramTooLarge;

        const control = receiveControlFromBytes(incoming.control);
        const ecn = if (self.receive_ecn_enabled) control.ecn else .not_ect;
        const segment_size = control.gro_segment_size orelse {
            if (incoming.data.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
            // Most allocator implementations can shrink this allocation in
            // place. Returning the receive storage directly removes the
            // previous alloc-copy-free cycle even when GRO is not involved.
            const bytes = try self.allocator.realloc(buffer, incoming.data.len);
            return .{
                .from = incoming.from,
                .storage = bytes,
                .segment_size = bytes.len,
                .segment_count = 1,
                .ecn = ecn,
            };
        };
        if (!self.gro_receive_enabled or
            segment_size == 0 or
            segment_size > self.limits.max_datagram_size or
            incoming.data.len <= segment_size)
        {
            return error.InvalidGroSegment;
        }

        const segment_count = std.math.divCeil(usize, incoming.data.len, segment_size) catch
            return error.InvalidGroSegment;
        if (segment_count < 2 or segment_count > udp_gro_max_segments) return error.InvalidGroSegment;
        const storage = try self.allocator.realloc(buffer, incoming.data.len);
        buffer_owned = false;
        return .{
            .from = incoming.from,
            .storage = storage,
            .segment_size = segment_size,
            .segment_count = segment_count,
            .ecn = ecn,
        };
    }

    fn receiveKernelBytesTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        const receive_capacity = if (self.gro_receive_enabled)
            std.math.maxInt(u16)
        else
            self.limits.max_datagram_size;
        const buffer = try self.allocator.alloc(u8, receive_capacity);
        errdefer self.allocator.free(buffer);
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        @memset(&control_buffer, 0);
        var incoming: net.IncomingMessage = .init;
        incoming.control = &control_buffer;
        const maybe_err, const count = (try self.io.operateTimeout(
            .{ .net_receive = .{
                .socket_handle = self.socket.handle,
                .message_buffer = (&incoming)[0..1],
                .data_buffer = buffer,
                .flags = .{},
            } },
            timeout,
        )).net_receive;
        if (maybe_err) |err| return err;
        std.debug.assert(count == 1);
        if (incoming.data.len == 0) return error.EmptyDatagram;
        if (incoming.flags.trunc or incoming.flags.ctrunc) {
            return error.DatagramTooLarge;
        }
        const control = receiveControlFromBytes(incoming.control);
        if (control.gro_segment_size) |segment_size| {
            if (!self.gro_receive_enabled or
                segment_size == 0 or
                segment_size > self.limits.max_datagram_size or
                incoming.data.len < segment_size)
            {
                return error.InvalidGroSegment;
            }
            // Timed handshake reads consume one logical datagram. Queue any
            // additional GRO segments into the same FIFO used by normal reads.
            const segment_count = std.math.divCeil(
                usize,
                incoming.data.len,
                segment_size,
            ) catch return error.InvalidGroSegment;
            if (segment_count > 1) {
                const storage = try self.allocator.realloc(
                    buffer,
                    incoming.data.len,
                );
                const shared = try self.allocator.create(
                    SharedReceiveBuffer,
                );
                shared.* = .{
                    .allocator = self.allocator,
                    .storage = storage,
                    .references = .init(segment_count),
                };
                self.pending_receive_mutex.lockUncancelable(self.io);
                defer self.pending_receive_mutex.unlock(self.io);
                try self.ensurePendingReceivedCapacity(segment_count - 1);
                var index: usize = 1;
                while (index < segment_count) : (index += 1) {
                    const start = index * segment_size;
                    const end = @min(start + segment_size, storage.len);
                    self.pending_received.appendAssumeCapacity(.{
                        .from = incoming.from,
                        .bytes = storage[start..end],
                        .ecn = if (self.receive_ecn_enabled)
                            control.ecn
                        else
                            .not_ect,
                        .shared_buffer = shared,
                    });
                }
                return .{
                    .from = incoming.from,
                    .bytes = storage[0..segment_size],
                    .ecn = if (self.receive_ecn_enabled)
                        control.ecn
                    else
                        .not_ect,
                    .shared_buffer = shared,
                };
            }
        }
        if (incoming.data.len > self.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        const bytes = try self.allocator.realloc(
            buffer,
            incoming.data.len,
        );
        return .{
            .from = incoming.from,
            .bytes = bytes,
            .ecn = if (self.receive_ecn_enabled)
                control.ecn
            else
                .not_ect,
        };
    }

    fn takePendingReceived(self: *Endpoint) ?OwnedBytes {
        self.pending_receive_mutex.lockUncancelable(self.io);
        defer self.pending_receive_mutex.unlock(self.io);
        if (self.pending_receive_index >= self.pending_received.items.len) return null;

        const pending = self.pending_received.items[self.pending_receive_index];
        self.pending_receive_index += 1;
        self.compactPendingReceivedIfSparse();
        return pending;
    }

    fn pendingReceivedCount(self: *const Endpoint) usize {
        return self.pending_received.items.len - self.pending_receive_index;
    }

    fn ensurePendingReceivedCapacity(
        self: *Endpoint,
        additional_count: usize,
    ) std.mem.Allocator.Error!void {
        if (self.pending_receive_index != 0 and
            self.pending_received.items.len + additional_count >
                self.pending_received.capacity)
        {
            self.compactPendingReceived();
        }
        try self.pending_received.ensureUnusedCapacity(
            self.allocator,
            additional_count,
        );
    }

    fn compactPendingReceivedIfSparse(self: *Endpoint) void {
        if (self.pending_receive_index == 0) return;
        if (self.pending_receive_index == self.pending_received.items.len or
            self.pending_receive_index >= self.pending_received.items.len / 2)
        {
            self.compactPendingReceived();
        }
    }

    fn compactPendingReceived(self: *Endpoint) void {
        if (self.pending_receive_index == 0) return;
        const remaining = self.pendingReceivedCount();
        if (remaining != 0) {
            @memmove(
                self.pending_received.items[0..remaining],
                self.pending_received.items[self.pending_receive_index..],
            );
        }
        self.pending_received.items.len = remaining;
        self.pending_receive_index = 0;
    }

    fn enableEcnReceive(self: *Endpoint) void {
        if (!socketEcnSupported()) return;
        const enabled: u32 = 1;
        const enabled_bytes = std.mem.asBytes(&enabled);
        self.receive_ecn_enabled = switch (self.socket.address) {
            .ip4 => rawSetSockOpt(self.socket.handle, ipproto_ip, ip_recvtos, enabled_bytes),
            .ip6 => rawSetSockOpt(self.socket.handle, ipproto_ipv6, ipv6_recvtclass, enabled_bytes),
        };
    }

    fn configureSocketReceiveBuffer(self: *Endpoint) void {
        if (self.limits.socket_receive_buffer_bytes == 0) return;
        const size: u32 = std.math.cast(
            u32,
            self.limits.socket_receive_buffer_bytes,
        ) orelse std.math.maxInt(u32);
        _ = rawSetSockOpt(
            self.socket.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVBUF,
            std.mem.asBytes(&size),
        );
    }

    fn enableGroReceive(self: *Endpoint) void {
        if (!self.limits.enable_gro_receive or !udpGroSupported()) return;
        const enabled: u32 = 1;
        self.gro_receive_enabled = rawSetSockOpt(
            self.socket.handle,
            udp_gso_level,
            udp_gro_segment,
            std.mem.asBytes(&enabled),
        );
    }

    fn applyOutgoingEcnMark(self: *Endpoint, ecn: quic.packet_space.EcnCodepoint) Error!void {
        if (ecn == self.send_ecn_mark) return;
        if (!socketEcnSupported()) {
            if (ecn == .not_ect) {
                self.send_ecn_mark = .not_ect;
                return;
            }
            return error.EcnUnavailable;
        }
        const mark: u32 = ecnCodepointBits(ecn);
        const mark_bytes = std.mem.asBytes(&mark);
        const marked = switch (self.socket.address) {
            .ip4 => rawSetSockOpt(self.socket.handle, ipproto_ip, ip_tos, mark_bytes),
            .ip6 => rawSetSockOpt(self.socket.handle, ipproto_ipv6, ipv6_tclass, mark_bytes),
        };
        if (!marked) return error.EcnUnavailable;
        self.send_ecn_mark = ecn;
    }

    /// Receive the next non-Version-Negotiation-triggering datagram.
    ///
    /// Unsupported-version long headers are answered on the same UDP path and
    /// consumed; the caller receives the next datagram that should continue
    /// through normal routing/packet processing. This mirrors mature QUIC
    /// endpoint loops that perform Version Negotiation before CID routing.
    pub fn receiveBytesHandlingVersionNegotiation(self: *Endpoint, supported_versions: []const u32) Error!OwnedBytes {
        try validateSupportedVersions(supported_versions);
        while (true) {
            var raw = try self.receiveBytes();
            errdefer raw.deinit(self.allocator);
            if (try self.sendVersionNegotiationIfUnsupported(raw.from, raw.bytes, supported_versions)) {
                raw.deinit(self.allocator);
                continue;
            }
            return raw;
        }
    }

    pub fn receiveRoutedBytes(self: *Endpoint, router: quic.connection_router.Router) Error!RoutedBytes {
        var raw = try self.receiveBytes();
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagramFrom(raw.from, raw.bytes)) orelse return error.NoConnectionRoute;
        return .{ .datagram = raw, .route = routed.route, .destination_connection_id = routed.destination_connection_id };
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiation(
        self: *Endpoint,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
    ) Error!RoutedBytes {
        var raw = try self.receiveBytesHandlingVersionNegotiation(supported_versions);
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagramFrom(raw.from, raw.bytes)) orelse return error.NoConnectionRoute;
        return .{ .datagram = raw, .route = routed.route, .destination_connection_id = routed.destination_connection_id };
    }

    pub fn receiveManyConcurrent(self: *Endpoint, count: usize) Error!OwnedDatagramBatch {
        var group: std.Io.Group = .init;
        const datagrams = try self.allocator.alloc(?OwnedDatagram, count);
        errdefer self.allocator.free(datagrams);
        @memset(datagrams, null);
        const errors = try self.allocator.alloc(?anyerror, count);
        errdefer self.allocator.free(errors);
        @memset(errors, null);

        for (datagrams, errors) |*datagram, *err_slot| {
            const task = ReceiveTask{
                .endpoint = self,
                .datagram = datagram,
                .err = err_slot,
            };
            group.async(self.io, ReceiveTask.run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .datagrams = datagrams, .errors = errors };
    }
};

const EcnCmsgHdr = switch (builtin.os.tag) {
    .linux, .macos => std.c.cmsghdr,
    else => extern struct {
        len: usize,
        level: i32,
        type: i32,
    },
};

const ecn_control_buffer_len = cmsgSpace(@sizeOf(u32)) * 2;
const udp_gso_level: i32 = 17; // SOL_UDP on Linux.
const udp_gso_segment: i32 = 103; // UDP_SEGMENT from linux/udp.h.
const udp_gso_max_segments: usize = 64;
const udp_gso_control_len = cmsgSpace(@sizeOf(u16));
const udp_gro_segment: u32 = 104; // UDP_GRO from linux/udp.h.
const udp_gro_max_segments: usize = 64;
const receive_control_buffer_len = ecn_control_buffer_len + cmsgSpace(@sizeOf(i32));

const ipproto_ip: i32 = 0;
const ip_tos: u32 = switch (builtin.os.tag) {
    .linux => 1,
    .macos => 3,
    else => 0,
};
const ip_recvtos: u32 = switch (builtin.os.tag) {
    .linux => 13,
    .macos => 27,
    else => 0,
};
const ip_tos_cmsg_type: i32 = switch (builtin.os.tag) {
    .linux => 1,
    .macos => 27,
    else => 0,
};
const ipproto_ipv6: i32 = switch (builtin.os.tag) {
    .linux, .macos => std.posix.IPPROTO.IPV6,
    else => 0,
};
const ipv6_tclass: u32 = switch (builtin.os.tag) {
    .linux => 67,
    .macos => 36,
    else => 0,
};
const ipv6_recvtclass: u32 = switch (builtin.os.tag) {
    .linux => 66,
    .macos => 35,
    else => 0,
};

pub fn socketEcnSupported() bool {
    return switch (builtin.os.tag) {
        .linux, .macos => true,
        else => false,
    };
}

pub fn udpGsoSupported() bool {
    return builtin.os.tag == .linux;
}

pub fn udpGroSupported() bool {
    return builtin.os.tag == .linux;
}

const GsoPlan = struct {
    data_ptr: [*]const u8,
    total_len: usize,
    segment_size: u16,
    segment_count: usize,
};

/// Return a zero-copy GSO plan only when the caller's datagrams already have
/// the exact memory layout required by UDP_SEGMENT: contiguous equal-sized
/// segments, with only the final segment allowed to be shorter.
fn gsoPlan(datagrams: []const []const u8) ?GsoPlan {
    if (!udpGsoSupported() or datagrams.len < 2 or datagrams.len > udp_gso_max_segments) return null;
    const segment_size = std.math.cast(u16, datagrams[0].len) orelse return null;
    if (segment_size == 0) return null;

    var total_len = datagrams[0].len;
    var previous = datagrams[0];
    for (datagrams[1..], 1..) |bytes, index| {
        if (@intFromPtr(bytes.ptr) != @intFromPtr(previous.ptr) + previous.len) return null;
        const is_last = index == datagrams.len - 1;
        if ((!is_last and bytes.len != segment_size) or (is_last and bytes.len > segment_size)) return null;
        total_len = std.math.add(usize, total_len, bytes.len) catch return null;
        previous = bytes;
    }
    // Linux stores the UDP super-packet length in a 16-bit field. This bound
    // also matches mature s2n-quic's GSO aggregation limit.
    if (total_len > std.math.maxInt(u16)) return null;
    return .{
        .data_ptr = datagrams[0].ptr,
        .total_len = total_len,
        .segment_size = segment_size,
        .segment_count = datagrams.len,
    };
}

fn encodeUdpGsoControl(storage: *[udp_gso_control_len]u8, segment_size: u16) []const u8 {
    @memset(storage, 0);
    const header: *EcnCmsgHdr = @ptrCast(@alignCast(storage));
    header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(u16),
        .level = udp_gso_level,
        .type = udp_gso_segment,
    };
    @memcpy(
        storage[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u16)],
        std.mem.asBytes(&segment_size),
    );
    return storage;
}

fn gsoFallbackError(err: net.Socket.SendError) bool {
    // Linux uses EIO for a rejected UDP_SEGMENT operation. Zig's portable
    // socket error set has no EIO case, so std.Io normalizes it to Unexpected.
    return err == error.Unexpected;
}

fn rawSetSockOpt(fd: std.posix.socket_t, level: i32, optname: u32, opt: []const u8) bool {
    std.posix.setsockopt(fd, level, optname, opt) catch return false;
    return true;
}

fn ecnCodepointBits(ecn: quic.packet_space.EcnCodepoint) u32 {
    return switch (ecn) {
        .not_ect => 0b00,
        .ect0 => 0b10,
        .ect1 => 0b01,
        .ce => 0b11,
    };
}

fn ecnFromBits(bits: u2) quic.packet_space.EcnCodepoint {
    return switch (bits) {
        0b00 => .not_ect,
        0b10 => .ect0,
        0b01 => .ect1,
        0b11 => .ce,
    };
}

fn cmsgSpace(data_len: usize) usize {
    return std.mem.alignForward(usize, @sizeOf(EcnCmsgHdr) + data_len, @alignOf(EcnCmsgHdr));
}

fn ecnFromControl(control: []const u8) quic.packet_space.EcnCodepoint {
    return receiveControlFromBytes(control).ecn;
}

const ReceiveControl = struct {
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    gro_segment_size: ?usize = null,
};

fn receiveControlFromBytes(control: []const u8) ReceiveControl {
    var result: ReceiveControl = .{};
    if (!socketEcnSupported() and !udpGroSupported()) return result;
    var offset: usize = 0;
    while (offset + @sizeOf(EcnCmsgHdr) <= control.len) {
        const header: *const EcnCmsgHdr = @ptrCast(@alignCast(control[offset..].ptr));
        const cmsg_len: usize = @intCast(header.len);
        if (cmsg_len < @sizeOf(EcnCmsgHdr) or offset + cmsg_len > control.len) break;
        const data = control[offset + @sizeOf(EcnCmsgHdr) .. offset + cmsg_len];
        const ipv4_tos = header.level == ipproto_ip and header.type == ip_tos_cmsg_type;
        const ipv6_tclass_cmsg = header.level == ipproto_ipv6 and header.type == @as(i32, @intCast(ipv6_tclass));
        if ((ipv4_tos or ipv6_tclass_cmsg) and data.len != 0) {
            result.ecn = ecnFromBits(@truncate(data[0] & 0x03));
        } else if (header.level == udp_gso_level and
            header.type == @as(i32, @intCast(udp_gro_segment)) and
            data.len >= @sizeOf(i32))
        {
            const segment_size = std.mem.bytesToValue(i32, data[0..@sizeOf(i32)]);
            if (segment_size > 0) result.gro_segment_size = @intCast(segment_size);
        }
        offset += cmsgSpace(cmsg_len - @sizeOf(EcnCmsgHdr));
    }
    return result;
}

const LongHeaderConnectionIds = struct {
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
};

fn validateSupportedVersions(supported_versions: []const u32) Error!void {
    if (supported_versions.len == 0) return error.InvalidVersionNegotiation;
    var has_real_version = false;
    for (supported_versions) |version| {
        if (version == quic.Version.negotiation.wireValue()) return error.InvalidVersionNegotiation;
        if (!quic.isReservedVersionWire(version)) has_real_version = true;
    }
    if (!has_real_version) return error.InvalidVersionNegotiation;
}

fn versionListContains(supported_versions: []const u32, version: u32) bool {
    if (quic.isReservedVersionWire(version)) return false;
    for (supported_versions) |supported| {
        if (quic.isReservedVersionWire(supported)) continue;
        if (supported == version) return true;
    }
    return false;
}

fn versionNegotiationFirstByte(io: std.Io) std.Io.RandomSecureError!u8 {
    // RFC 9000 leaves the Version Negotiation first byte's lower bits unused.
    // Mature stacks randomize them (while forcing Header Form=1) so endpoints do
    // not ossify on one fixed long-header/type-specific pattern.
    var byte: [1]u8 = undefined;
    try std.Io.randomSecure(io, &byte);
    return byte[0] | 0x80;
}

fn peekUnsupportedVersionConnectionIds(datagram: []const u8, supported_versions: []const u32) ?LongHeaderConnectionIds {
    if (datagram.len < 5) return null;
    const first_byte = datagram[0];
    if ((first_byte & 0x80) == 0) return null;
    // Valid QUIC packets have the fixed bit set. Dropping fixed-bit-clear
    // datagrams also avoids replying to random non-QUIC UDP traffic.
    if ((first_byte & 0x40) == 0) return null;

    const version = std.mem.readInt(u32, datagram[1..5], .big);
    if (version == quic.Version.negotiation.wireValue()) return null;
    if (versionListContains(supported_versions, version)) return null;

    if (datagram.len < 6) return null;
    const dcid_len = datagram[5];
    if (dcid_len > 20) return null;
    const dcid_start: usize = 6;
    const dcid_end = dcid_start + @as(usize, dcid_len);
    if (datagram.len < dcid_end + 1) return null;

    const scid_len = datagram[dcid_end];
    if (scid_len > 20) return null;
    const scid_start = dcid_end + 1;
    const scid_end = scid_start + @as(usize, scid_len);
    if (datagram.len < scid_end) return null;

    return .{
        .version = version,
        .destination_connection_id = datagram[dcid_start..dcid_end],
        .source_connection_id = datagram[scid_start..scid_end],
    };
}

const ReceiveTask = struct {
    endpoint: *Endpoint,
    datagram: *?OwnedDatagram,
    err: *?anyerror,

    fn run(task: ReceiveTask) std.Io.Cancelable!void {
        task.datagram.* = task.endpoint.receive() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

const SharedReceiveBuffer = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    references: std.atomic.Value(usize),

    fn release(self: *SharedReceiveBuffer) void {
        // Each GRO segment owns one reference. The acquire pairs with releases
        // from other threads so the final owner can safely free both objects.
        if (self.references.fetchSub(1, .release) != 1) return;
        _ = self.references.load(.acquire);
        const allocator = self.allocator;
        allocator.free(self.storage);
        allocator.destroy(self);
    }
};

pub const OwnedBytesBatch = struct {
    from: net.IpAddress,
    storage: []u8,
    segment_size: usize,
    segment_count: usize,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    shared_buffer: ?*SharedReceiveBuffer = null,
    owns_storage: bool = true,

    pub fn datagramAt(self: OwnedBytesBatch, index: usize) ?[]const u8 {
        if (index >= self.segment_count) return null;
        return self.datagramAtUnchecked(index);
    }

    pub fn datagramAtMutable(self: *OwnedBytesBatch, index: usize) ?[]u8 {
        if (index >= self.segment_count) return null;
        return self.datagramAtUnchecked(index);
    }

    fn datagramAtUnchecked(self: OwnedBytesBatch, index: usize) []u8 {
        const start = index * self.segment_size;
        const end = @min(start + self.segment_size, self.storage.len);
        return self.storage[start..end];
    }

    fn disown(self: *OwnedBytesBatch) void {
        self.owns_storage = false;
    }

    pub fn deinit(self: *OwnedBytesBatch, allocator: std.mem.Allocator) void {
        if (self.owns_storage) {
            if (self.shared_buffer) |shared| {
                shared.release();
            } else {
                allocator.free(self.storage);
            }
        }
        self.* = undefined;
    }
};

pub const OwnedBytes = struct {
    from: net.IpAddress,
    bytes: []u8,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    shared_buffer: ?*SharedReceiveBuffer = null,

    pub fn deinit(self: *OwnedBytes, allocator: std.mem.Allocator) void {
        if (self.shared_buffer) |shared| {
            shared.release();
        } else {
            allocator.free(self.bytes);
        }
        self.* = undefined;
    }
};

fn ownedBytesAsBatch(bytes: OwnedBytes) OwnedBytesBatch {
    return .{
        .from = bytes.from,
        .storage = bytes.bytes,
        .segment_size = bytes.bytes.len,
        .segment_count = 1,
        .ecn = bytes.ecn,
        .shared_buffer = bytes.shared_buffer,
    };
}

pub const RoutedBytes = struct {
    datagram: OwnedBytes,
    route: quic.connection_router.Route,
    destination_connection_id: []const u8,

    pub fn deinit(self: *RoutedBytes, allocator: std.mem.Allocator) void {
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    frames: []quic.Frame,
    shared_buffer: ?*SharedReceiveBuffer = null,

    pub fn deinit(self: *OwnedDatagram, allocator: std.mem.Allocator) void {
        quic.deinitOwnedFrameSlice(self.frames, allocator);
        allocator.free(self.frames);
        if (self.shared_buffer) |shared| {
            shared.release();
        } else {
            allocator.free(self.bytes);
        }
        self.* = undefined;
    }
};

pub const OwnedDatagramBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?OwnedDatagram,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedDatagramBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedDatagramBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedDatagramBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            if (datagram != null) count += 1;
        }
        return count;
    }
};

test "QUIC UDP endpoint sends and receives frame datagrams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client.deinit();

    const outbound = [_]quic.Frame{
        .{ .ping = {} },
        .{ .datagram = .{ .data = "hello", .length_present = true } },
    };
    try client.sendFrames(&outbound);

    var received = try server.receive();
    defer received.deinit(allocator);
    try std.testing.expect(received.from.eql(&client.address()));
    try std.testing.expectEqual(@as(usize, 2), received.frames.len);
    try std.testing.expectEqualStrings("hello", received.frames[1].datagram.data);

    const response = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "world", .fin = true } },
    };
    try server.sendFrames(received.from, &response);

    var client_received = try client.receive();
    defer client_received.deinit(allocator);
    try std.testing.expect(client_received.from.eql(&server.address()));
    try std.testing.expectEqual(@as(usize, 1), client_received.frames.len);
    try std.testing.expectEqualStrings("world", client_received.frames[0].stream.data);
}

test "QUIC UDP endpoint round-trips ECN marks" {
    if (!socketEcnSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client.deinit();
    if (!server.endpoint.receive_ecn_enabled) return error.SkipZigTest;

    client.endpoint.sendBytesWithEcn(server.address(), "ect0", .ect0) catch |err| switch (err) {
        error.EcnUnavailable => return error.SkipZigTest,
        else => return err,
    };
    var ect0 = try server.endpoint.receiveBytesWithEcn();
    defer ect0.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect0, ect0.ecn);
    try std.testing.expectEqualSlices(u8, "ect0", ect0.bytes);

    try client.endpoint.sendBytesWithEcn(server.address(), "ect1", .ect1);
    var ect1 = try server.endpoint.receiveBytesWithEcn();
    defer ect1.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect1, ect1.ecn);
    try std.testing.expectEqualSlices(u8, "ect1", ect1.bytes);

    try client.endpoint.sendBytesWithEcn(server.address(), "ce", .ce);
    var ce = try server.endpoint.receiveBytesWithEcn();
    defer ce.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ce, ce.ecn);
    try std.testing.expectEqualSlices(u8, "ce", ce.bytes);

    // A normal send after ECT traffic must clear the cached TOS/TCLASS mark so
    // callers that are not probing ECN do not accidentally keep marking packets.
    try client.endpoint.sendBytes(server.address(), "plain");
    var plain = try server.endpoint.receiveBytesWithEcn();
    defer plain.deinit(allocator);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.not_ect, plain.ecn);
    try std.testing.expectEqualSlices(u8, "plain", plain.bytes);
}

test "QUIC UDP endpoint builds Version Negotiation for unsupported versions" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const datagram = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x02,
        0xaa,
        0xbb,
        0x03,
        0x11,
        0x22,
        0x33,
        0x00,
    };

    const response = (try endpoint.versionNegotiationResponse(&datagram, &supported_versions)) orelse return error.TestUnexpectedResult;
    defer allocator.free(response);

    var parsed = try quic.parseVersionNegotiationPacket(allocator, response);
    defer parsed.deinit(allocator);
    try std.testing.expect((parsed.first_byte & 0x80) != 0);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22, 0x33 }, parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xaa, 0xbb }, parsed.source_connection_id);
    try std.testing.expectEqualSlices(u32, &supported_versions, parsed.versions);

    const supported_with_grease = [_]u32{
        quic.Version.version_1.wireValue(),
        0x0a0a0a0a,
    };
    var reserved_trigger = datagram;
    std.mem.writeInt(u32, reserved_trigger[1..5], 0x0a0a0a0a, .big);
    const greased_response = (try endpoint.versionNegotiationResponse(&reserved_trigger, &supported_with_grease)) orelse return error.TestUnexpectedResult;
    defer allocator.free(greased_response);

    var parsed_greased = try quic.parseVersionNegotiationPacket(allocator, greased_response);
    defer parsed_greased.deinit(allocator);
    try std.testing.expectEqualSlices(u32, &supported_with_grease, parsed_greased.versions);
}

test "QUIC UDP endpoint ignores non-triggering Version Negotiation inputs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var endpoint = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const supported = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
    };
    const version_negotiation = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x00,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
        0x00,
        0x00,
        0x01,
    };
    const fixed_bit_clear = [_]u8{
        0x80,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x01,
        0xaa,
        0x01,
        0xbb,
        0x00,
    };
    const short_header = [_]u8{ 0x40, 0xaa, 0xbb };
    const truncated = [_]u8{ 0xc0, 0xfa, 0xce, 0xb0, 0x0c, 0x04, 0xaa };
    const too_long_cid = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        21,
    } ++ ([_]u8{0xaa} ** 21);

    try std.testing.expect((try endpoint.versionNegotiationResponse(&supported, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&version_negotiation, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&fixed_bit_clear, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&short_header, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&truncated, &supported_versions)) == null);
    try std.testing.expect((try endpoint.versionNegotiationResponse(&too_long_cid, &supported_versions)) == null);

    try std.testing.expectError(error.InvalidVersionNegotiation, endpoint.versionNegotiationResponse(&supported, &.{}));
    try std.testing.expectError(error.InvalidVersionNegotiation, endpoint.versionNegotiationResponse(
        &supported,
        &.{quic.Version.negotiation.wireValue()},
    ));
    try std.testing.expectError(error.InvalidVersionNegotiation, endpoint.versionNegotiationResponse(
        &supported,
        &.{0x0a0a0a0a},
    ));
}

test "QUIC UDP endpoint sends Version Negotiation before returning next datagram" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client.deinit();

    const supported_versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    const unsupported = [_]u8{
        0xc0,
        0xfa,
        0xce,
        0xb0,
        0x0c,
        0x03,
        's',
        'r',
        'v',
        0x03,
        'c',
        'l',
        'i',
        0x00,
    };
    const supported = [_]u8{
        0xc0,
        0x00,
        0x00,
        0x00,
        0x01,
        0x03,
        's',
        'r',
        'v',
        0x03,
        'c',
        'l',
        'i',
        0x00,
    };

    const Shared = struct {
        endpoint: *Endpoint,
        supported_versions: []const u32,
        received: ?OwnedBytes = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.received = shared.endpoint.receiveBytesHandlingVersionNegotiation(shared.supported_versions) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{
        .endpoint = &server.endpoint,
        .supported_versions = &supported_versions,
    };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try client.endpoint.sendBytes(server.address(), &unsupported);
    var response = try client.endpoint.receiveBytes();
    defer response.deinit(allocator);
    try std.testing.expect(response.from.eql(&server.address()));

    var parsed = try quic.parseVersionNegotiationPacket(allocator, response.bytes);
    defer parsed.deinit(allocator);
    try std.testing.expectEqualSlices(u8, "cli", parsed.destination_connection_id);
    try std.testing.expectEqualSlices(u8, "srv", parsed.source_connection_id);
    try std.testing.expectEqualSlices(u32, &supported_versions, parsed.versions);

    try client.endpoint.sendBytes(server.address(), &supported);
    receiver.join();
    if (shared.err) |err| return err;
    var accepted = shared.received.?;
    defer accepted.deinit(allocator);
    try std.testing.expect(accepted.from.eql(&client.address()));
    try std.testing.expectEqualSlices(u8, &supported, accepted.bytes);
}

test "QUIC UDP endpoint receives many datagrams with std.Io async" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_b.deinit();

    const Shared = struct {
        endpoint: *Endpoint,
        batch: ?OwnedDatagramBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.endpoint.receiveManyConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .endpoint = &server.endpoint };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const frames_a = [_]quic.Frame{.{ .datagram = .{ .data = "a", .length_present = true } }};
    const frames_b = [_]quic.Frame{.{ .datagram = .{ .data = "b", .length_present = true } }};
    try client_a.sendFrames(&frames_a);
    try client_b.sendFrames(&frames_b);

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_a = false;
    var saw_b = false;
    for (batch.datagrams) |maybe_datagram| {
        const datagram = maybe_datagram.?;
        try std.testing.expectEqual(@as(usize, 1), datagram.frames.len);
        const payload = datagram.frames[0].datagram.data;
        if (std.mem.eql(u8, payload, "a")) saw_a = true;
        if (std.mem.eql(u8, payload, "b")) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

test "QUIC UDP endpoint sends many datagrams in one batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();

    const datagrams = [_][]const u8{ "first", "second", "third" };
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    sender.allocator = no_alloc.allocator();
    try sender.sendManyBytes(receiver.address(), &datagrams);
    try std.testing.expect(!no_alloc.has_induced_failure);
    for (datagrams) |expected| {
        var received = try receiver.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }

    const invalid = [_][]const u8{ "valid-but-must-not-send", "" };
    try std.testing.expectError(error.EmptyDatagram, sender.sendManyBytes(receiver.address(), &invalid));
}

test "QUIC UDP GSO planner requires a contiguous equal-sized prefix" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const storage = "aaaabbbbcc";
    const valid = [_][]const u8{
        storage[0..4],
        storage[4..8],
        storage[8..10],
    };
    const plan = gsoPlan(&valid) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 3), plan.segment_count);
    try std.testing.expectEqual(@as(u16, 4), plan.segment_size);
    try std.testing.expectEqual(@as(usize, storage.len), plan.total_len);
    try std.testing.expectEqual(@intFromPtr(storage.ptr), @intFromPtr(plan.data_ptr));

    const discontiguous = [_][]const u8{ "aaaa", "bbbb" };
    try std.testing.expect(gsoPlan(&discontiguous) == null);
    const short_middle = [_][]const u8{
        storage[0..4],
        storage[4..6],
        storage[6..10],
    };
    try std.testing.expect(gsoPlan(&short_middle) == null);
}

test "QUIC UDP GSO control message encodes native segment size" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    var control: [udp_gso_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
    const encoded = encodeUdpGsoControl(&control, 1200);
    try std.testing.expectEqual(@as(usize, udp_gso_control_len), encoded.len);
    const header: *const EcnCmsgHdr = @ptrCast(@alignCast(encoded.ptr));
    try std.testing.expectEqual(@as(usize, @sizeOf(EcnCmsgHdr) + @sizeOf(u16)), header.len);
    try std.testing.expectEqual(udp_gso_level, header.level);
    try std.testing.expectEqual(udp_gso_segment, header.type);
    try std.testing.expectEqual(
        @as(u16, 1200),
        std.mem.bytesToValue(u16, encoded[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u16)]),
    );
}

test "QUIC UDP receive control decodes ECN and GRO segment size" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const ecn_len = cmsgSpace(@sizeOf(u32));
    var control: [cmsgSpace(@sizeOf(u32)) + cmsgSpace(@sizeOf(i32))]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
    @memset(&control, 0);

    const ecn_header: *EcnCmsgHdr = @ptrCast(@alignCast(control[0..].ptr));
    ecn_header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(u32),
        .level = ipproto_ip,
        .type = ip_tos_cmsg_type,
    };
    const ecn_value: u32 = ecnCodepointBits(.ect0);
    @memcpy(
        control[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u32)],
        std.mem.asBytes(&ecn_value),
    );

    const gro_header: *EcnCmsgHdr = @ptrCast(@alignCast(control[ecn_len..].ptr));
    gro_header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(i32),
        .level = udp_gso_level,
        .type = @intCast(udp_gro_segment),
    };
    const gro_value: i32 = 1200;
    @memcpy(
        control[ecn_len + @sizeOf(EcnCmsgHdr) ..][0..@sizeOf(i32)],
        std.mem.asBytes(&gro_value),
    );

    const decoded = receiveControlFromBytes(&control);
    try std.testing.expectEqual(quic.packet_space.EcnCodepoint.ect0, decoded.ecn);
    try std.testing.expectEqual(@as(?usize, 1200), decoded.gro_segment_size);
}

test "QUIC UDP endpoint segments a contiguous GSO super-packet" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .enable_gro_receive = true,
    });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();

    const storage = "aaaabbbbcc";
    const datagrams = [_][]const u8{
        storage[0..4],
        storage[4..8],
        storage[8..10],
    };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    if (!sender.gsoSendEnabled()) return error.SkipZigTest;
    if (!receiver.groReceiveEnabled()) return error.SkipZigTest;

    var received = try receiver.receiveBytesBatch();
    defer received.deinit(allocator);
    try std.testing.expectEqual(datagrams.len, received.segment_count);
    try std.testing.expectEqual(@as(usize, 4), received.segment_size);
    for (datagrams, 0..) |expected, index| {
        try std.testing.expectEqualStrings(expected, received.datagramAt(index).?);
    }
    try std.testing.expect(received.datagramAt(datagrams.len) == null);
}

test "QUIC UDP GRO shared storage survives frame-datagram ownership transfer" {
    if (!udpGroSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 128,
        .enable_gro_receive = true,
    });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();
    if (!receiver.groReceiveEnabled()) return error.SkipZigTest;

    // Frame type 0x01 is PING and zero bytes are PADDING. Use realistic-sized
    // segments because some NIC/kernel combinations reject one-byte GSO
    // segments even though the payload is otherwise valid.
    const segment = [_]u8{0x01} ++ [_]u8{0x00} ** 15;
    const storage = segment ++ segment;
    const datagrams = [_][]const u8{ storage[0..segment.len], storage[segment.len..] };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    if (!sender.gsoSendEnabled()) return error.SkipZigTest;

    var first = try receiver.receive();
    defer first.deinit(allocator);
    var second = try receiver.receive();
    defer second.deinit(allocator);
    try std.testing.expect(first.shared_buffer != null);
    try std.testing.expectEqual(first.shared_buffer, second.shared_buffer);
    // Consecutive PADDING bytes are represented as one parsed frame.
    try std.testing.expectEqual(@as(usize, 2), first.frames.len);
    try std.testing.expectEqual(@as(usize, 2), second.frames.len);
    try std.testing.expect(first.frames[0] == .ping);
    try std.testing.expect(second.frames[0] == .ping);
}

const RejectFirstGsoSend = struct {
    delegate: std.Io,
    calls: usize = 0,
    gso_calls: usize = 0,
    fallback_calls: usize = 0,

    fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *RejectFirstGsoSend = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        if (messages.len == 1 and messages[0].control.len != 0) {
            self.gso_calls += 1;
            return .{ error.Unexpected, 0 };
        }
        self.fallback_calls += 1;
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

test "QUIC endpoint pending receive queue reuses consumed slots" {
    const allocator = std.testing.allocator;
    var endpoint = Endpoint{
        .io = undefined,
        .allocator = allocator,
        .socket = undefined,
    };
    defer endpoint.pending_received.deinit(allocator);

    try endpoint.pending_received.ensureTotalCapacityPrecise(allocator, 4);
    for (0..4) |index| {
        const byte = try allocator.alloc(u8, 1);
        byte[0] = @intCast(index);
        endpoint.pending_received.appendAssumeCapacity(.{
            .from = .{ .ip4 = .loopback(443) },
            .bytes = byte,
        });
    }

    endpoint.pending_received.items[0].deinit(allocator);
    endpoint.pending_receive_index = 1;
    try std.testing.expectEqual(@as(usize, 3), endpoint.pendingReceivedCount());

    try endpoint.ensurePendingReceivedCapacity(1);
    try std.testing.expectEqual(@as(usize, 0), endpoint.pending_receive_index);
    try std.testing.expectEqual(@as(usize, 3), endpoint.pending_received.items.len);
    try std.testing.expectEqual(@as(usize, 4), endpoint.pending_received.capacity);
    try std.testing.expectEqual(@as(u8, 1), endpoint.pending_received.items[0].bytes[0]);

    const replacement = try allocator.alloc(u8, 1);
    replacement[0] = 9;
    endpoint.pending_received.appendAssumeCapacity(.{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = replacement,
    });
    try std.testing.expectEqual(@as(usize, 4), endpoint.pending_received.items.len);

    for (endpoint.pending_received.items) |*pending| pending.deinit(allocator);
    endpoint.pending_received.clearRetainingCapacity();
}

test "QUIC UDP endpoint disables rejected GSO and retries send-many" {
    if (!udpGsoSupported()) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer receiver.deinit();
    var sender = try Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 128 });
    defer sender.deinit();

    var rejecting = RejectFirstGsoSend{ .delegate = sender.io };
    var rejecting_vtable = sender.io.vtable.*;
    rejecting_vtable.netSend = RejectFirstGsoSend.netSend;
    sender.io = .{ .userdata = &rejecting, .vtable = &rejecting_vtable };
    defer sender.io = rejecting.delegate;

    const storage = "aaaabbbb";
    const datagrams = [_][]const u8{ storage[0..4], storage[4..8] };
    try sender.sendManyBytes(receiver.address(), &datagrams);
    try std.testing.expect(!sender.gsoSendEnabled());
    try std.testing.expectEqual(@as(usize, 2), rejecting.calls);
    try std.testing.expectEqual(@as(usize, 1), rejecting.gso_calls);
    try std.testing.expectEqual(@as(usize, 1), rejecting.fallback_calls);

    for (datagrams) |expected| {
        var received = try receiver.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }

    try sender.sendManyBytes(receiver.address(), &datagrams);
    try std.testing.expectEqual(@as(usize, 3), rejecting.calls);
    try std.testing.expectEqual(@as(usize, 1), rejecting.gso_calls);
    try std.testing.expectEqual(@as(usize, 2), rejecting.fallback_calls);
    for (datagrams) |expected| {
        var received = try receiver.receiveBytes();
        defer received.deinit(allocator);
        try std.testing.expectEqualStrings(expected, received.bytes);
    }
}

test "QUIC UDP endpoint routes protected short datagrams by DCID" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer server.deinit();

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer client_b.deinit();

    var router = quic.connection_router.Router.init(allocator);
    defer router.deinit();
    try router.register("conn-a", .{ .connection_index = 10, .sequence_number = 1 });
    try router.register("conn-b", .{ .connection_index = 11, .sequence_number = 2 });

    const keys = quic.protection.deriveAes128Keys([_]u8{0x5a} ** quic.protection.secret_len);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try (quic.Frame{ .ping = {} }).write(&payload, allocator);

    const packet_a = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "conn-a",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(packet_a);
    const packet_b = try quic.protection.sealShortPacket(allocator, keys, .{
        .destination_connection_id = "conn-b",
        .packet_number = 0,
        .payload = payload.items,
    });
    defer allocator.free(packet_b);

    try client_a.endpoint.sendBytes(server.address(), packet_a);
    try client_b.endpoint.sendBytes(server.address(), packet_b);

    var first = try server.endpoint.receiveRoutedBytes(router);
    defer first.deinit(allocator);
    var second = try server.endpoint.receiveRoutedBytes(router);
    defer second.deinit(allocator);

    const first_idx = first.route.connection_index;
    const second_idx = second.route.connection_index;
    try std.testing.expect((first_idx == 10 and second_idx == 11) or (first_idx == 11 and second_idx == 10));
    if (first_idx == 10) {
        try std.testing.expectEqualStrings("conn-a", first.destination_connection_id);
        try std.testing.expectEqualStrings("conn-b", second.destination_connection_id);
    } else {
        try std.testing.expectEqualStrings("conn-b", first.destination_connection_id);
        try std.testing.expectEqualStrings("conn-a", second.destination_connection_id);
    }
}

const std = @import("std");
const webrtc = @import("mod.zig");

const net = std.Io.net;
const stun = webrtc.stun;

pub const Error = webrtc.Error || error{
    EmptyDatagram,
    DatagramTooLarge,
    UnexpectedStunMessage,
    MissingXorMappedAddress,
    MissingIceAttribute,
} || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveError || std.Io.RandomSecureError || std.Io.Cancelable;

pub const Limits = struct {
    max_datagram_size: usize = 2048,
};

pub const Peer = struct {
    endpoint: PeerEndpoint,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Peer {
        return .{ .endpoint = try .bind(allocator, io, bind_address, limits) };
    }

    pub fn deinit(self: *Peer) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Peer) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn bindingRequest(self: *Peer, to: net.IpAddress) Error!BindingResponse {
        return self.endpoint.bindingRequest(to);
    }

    pub fn iceBindingRequest(self: *Peer, to: net.IpAddress, options: stun.BindingRequestOptions) Error!BindingResponse {
        return self.endpoint.iceBindingRequest(to, options);
    }

    pub fn receiveBindingRequest(self: *Peer) Error!StunDatagram {
        return self.endpoint.receiveBindingRequest();
    }

    pub fn receiveIceBindingRequest(self: *Peer, expected_username: []const u8, password: []const u8) Error!IceBindingRequest {
        return self.endpoint.receiveIceBindingRequest(expected_username, password);
    }

    pub fn respondBindingSuccess(self: *Peer, request: StunDatagram) Error!void {
        try self.endpoint.respondBindingSuccess(request);
    }

    pub fn respondIceBindingSuccess(self: *Peer, request: StunDatagram, password: []const u8) Error!void {
        try self.endpoint.respondIceBindingSuccess(request, password);
    }

    pub fn sendRtpPacket(self: *Peer, to: net.IpAddress, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        try self.endpoint.sendRtpPacket(to, options, payload);
    }

    pub fn receiveRtpPacket(self: *Peer) Error!RtpDatagram {
        return self.endpoint.receiveRtpPacket();
    }

    pub fn sendSrtpPacket(self: *Peer, to: net.IpAddress, context: *webrtc.srtp.Context, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        try self.endpoint.sendSrtpPacket(to, context, options, payload);
    }

    pub fn receiveSrtpPacket(self: *Peer, context: *webrtc.srtp.Context) Error!SrtpDatagram {
        return self.endpoint.receiveSrtpPacket(context);
    }

    pub fn sendRtcpPacket(self: *Peer, to: net.IpAddress, packet: webrtc.rtcp.Packet) Error!void {
        try self.endpoint.sendRtcpPacket(to, packet);
    }

    pub fn receiveRtcpPacket(self: *Peer) Error!RtcpDatagram {
        return self.endpoint.receiveRtcpPacket();
    }

    pub fn sendSrtcpPacket(self: *Peer, to: net.IpAddress, context: *webrtc.srtp.Context, packet: webrtc.rtcp.Packet) Error!void {
        try self.endpoint.sendSrtcpPacket(to, context, packet);
    }

    pub fn sendSrtcpCompound(self: *Peer, to: net.IpAddress, context: *webrtc.srtp.Context, packets: []const webrtc.rtcp.Packet) Error!void {
        try self.endpoint.sendSrtcpCompound(to, context, packets);
    }

    pub fn receiveSrtcpPacket(self: *Peer, context: *webrtc.srtp.Context) Error!SrtcpDatagram {
        return self.endpoint.receiveSrtcpPacket(context);
    }

    pub fn receiveSrtcpCompound(self: *Peer, context: *webrtc.srtp.Context) Error!SrtcpCompoundDatagram {
        return self.endpoint.receiveSrtcpCompound(context);
    }

    pub fn sendDtlsRecord(self: *Peer, to: net.IpAddress, options: webrtc.dtls.WriteOptions, fragment: []const u8) Error!void {
        try self.endpoint.sendDtlsRecord(to, options, fragment);
    }

    pub fn receiveDtlsRecord(self: *Peer) Error!DtlsDatagram {
        return self.endpoint.receiveDtlsRecord();
    }

    pub fn receiveManyConcurrent(self: *Peer, count: usize) Error!PeerDatagramBatch {
        return self.endpoint.receiveManyConcurrent(count);
    }
};

pub const PeerEndpoint = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    socket: net.Socket,
    limits: Limits = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!PeerEndpoint {
        return .{
            .io = io,
            .allocator = allocator,
            .socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *PeerEndpoint) void {
        self.socket.close(self.io);
        self.* = undefined;
    }

    pub fn address(self: PeerEndpoint) net.IpAddress {
        return self.socket.address;
    }

    pub fn sendBytes(self: *PeerEndpoint, to: net.IpAddress, bytes: []const u8) Error!void {
        if (bytes.len == 0) return error.EmptyDatagram;
        if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        try self.socket.send(self.io, &to, bytes);
    }

    pub fn bindingRequest(self: *PeerEndpoint, to: net.IpAddress) Error!BindingResponse {
        var transaction_id: [12]u8 = undefined;
        try std.Io.randomSecure(self.io, &transaction_id);

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try stun.write(&encoded, self.allocator, .request, .binding, transaction_id, &.{});
        try self.sendBytes(to, encoded.items);

        while (true) {
            var datagram = try self.receiveStunDatagram();
            errdefer datagram.deinit(self.allocator);
            if (!datagram.from.eql(&to)) {
                datagram.deinit(self.allocator);
                continue;
            }
            if (!std.mem.eql(u8, &datagram.message.transaction_id, &transaction_id)) {
                datagram.deinit(self.allocator);
                continue;
            }
            if (datagram.message.method != .binding or datagram.message.class != .success_response) {
                return error.UnexpectedStunMessage;
            }
            const mapped = try findXorMappedAddress(datagram.message);
            return .{ .datagram = datagram, .mapped_address = mapped };
        }
    }

    pub fn iceBindingRequest(self: *PeerEndpoint, to: net.IpAddress, options: stun.BindingRequestOptions) Error!BindingResponse {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try stun.writeIceBindingRequest(&encoded, self.allocator, options);
        try self.sendBytes(to, encoded.items);

        while (true) {
            var datagram = try self.receiveStunDatagram();
            errdefer datagram.deinit(self.allocator);
            if (!datagram.from.eql(&to)) {
                datagram.deinit(self.allocator);
                continue;
            }
            if (!std.mem.eql(u8, &datagram.message.transaction_id, &options.transaction_id)) {
                datagram.deinit(self.allocator);
                continue;
            }
            if (datagram.message.method != .binding or datagram.message.class != .success_response) {
                return error.UnexpectedStunMessage;
            }
            try stun.validateFingerprint(datagram.bytes);
            try stun.validateMessageIntegrity(datagram.bytes, options.password);
            const mapped = try findXorMappedAddress(datagram.message);
            return .{ .datagram = datagram, .mapped_address = mapped };
        }
    }

    pub fn receiveBindingRequest(self: *PeerEndpoint) Error!StunDatagram {
        while (true) {
            var datagram = try self.receiveStunDatagram();
            errdefer datagram.deinit(self.allocator);
            if (datagram.message.method == .binding and datagram.message.class == .request) return datagram;
            datagram.deinit(self.allocator);
        }
    }

    pub fn receiveIceBindingRequest(self: *PeerEndpoint, expected_username: []const u8, password: []const u8) Error!IceBindingRequest {
        while (true) {
            var datagram = try self.receiveBindingRequest();
            errdefer datagram.deinit(self.allocator);
            const validated = stun.validateIceBindingRequest(datagram.bytes, datagram.message, expected_username, password) catch |err| switch (err) {
                error.InvalidStunMessage,
                error.InvalidStunAttribute,
                error.MissingStunAttribute,
                error.BadMessageIntegrity,
                error.BadFingerprint,
                => {
                    datagram.deinit(self.allocator);
                    continue;
                },
                else => |e| return e,
            };
            return .{ .datagram = datagram, .validated = validated };
        }
    }

    pub fn respondBindingSuccess(self: *PeerEndpoint, request: StunDatagram) Error!void {
        try writeBindingSuccess(self, request);
    }

    pub fn respondIceBindingSuccess(self: *PeerEndpoint, request: StunDatagram, password: []const u8) Error!void {
        try writeAuthenticatedBindingSuccess(self, request, password);
    }

    pub fn sendRtpPacket(self: *PeerEndpoint, to: net.IpAddress, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        // WebRTC eventually protects RTP with SRTP after DTLS keying.  This
        // plain-RTP method is intentionally scoped to local testing and to the
        // pre-SRTP runtime layer so STUN and media demultiplexing can be
        // exercised over one UDP 5-tuple.
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try webrtc.rtp.writePacket(&encoded, self.allocator, options, payload);
        try self.sendBytes(to, encoded.items);
    }

    pub fn sendSrtpPacket(self: *PeerEndpoint, to: net.IpAddress, context: *webrtc.srtp.Context, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try context.protectRtpPacket(&encoded, self.allocator, options, payload);
        try self.sendBytes(to, encoded.items);
    }

    pub fn sendDtlsRecord(self: *PeerEndpoint, to: net.IpAddress, options: webrtc.dtls.WriteOptions, fragment: []const u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try webrtc.dtls.writeRecord(&encoded, self.allocator, options, fragment);
        try self.sendBytes(to, encoded.items);
    }

    pub fn sendRtcpPacket(self: *PeerEndpoint, to: net.IpAddress, packet: webrtc.rtcp.Packet) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try webrtc.rtcp.writePacket(&encoded, self.allocator, packet);
        try self.sendBytes(to, encoded.items);
    }

    pub fn sendSrtcpPacket(self: *PeerEndpoint, to: net.IpAddress, context: *webrtc.srtp.Context, packet: webrtc.rtcp.Packet) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try context.protectRtcpPacket(&encoded, self.allocator, packet);
        try self.sendBytes(to, encoded.items);
    }

    pub fn sendSrtcpCompound(self: *PeerEndpoint, to: net.IpAddress, context: *webrtc.srtp.Context, packets: []const webrtc.rtcp.Packet) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try context.protectRtcpCompound(&encoded, self.allocator, packets);
        try self.sendBytes(to, encoded.items);
    }

    pub fn receiveRtpPacket(self: *PeerEndpoint) Error!RtpDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeRtp(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            var packet = try webrtc.rtp.Packet.parse(self.allocator, raw.bytes);
            errdefer packet.deinit(self.allocator);
            return .{ .from = raw.from, .bytes = raw.bytes, .packet = packet };
        }
    }

    pub fn receiveSrtpPacket(self: *PeerEndpoint, context: *webrtc.srtp.Context) Error!SrtpDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeRtp(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            var authenticated = try context.unprotectRtp(self.allocator, raw.bytes);
            errdefer authenticated.deinit(self.allocator);
            return .{ .from = raw.from, .bytes = raw.bytes, .authenticated = authenticated };
        }
    }

    pub fn receiveRtcpPacket(self: *PeerEndpoint) Error!RtcpDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeRtcp(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            var parsed = try webrtc.rtcp.parsePacket(self.allocator, raw.bytes);
            errdefer parsed.deinit(self.allocator);
            return .{ .from = raw.from, .bytes = raw.bytes, .packet = parsed.packet };
        }
    }

    pub fn receiveSrtcpPacket(self: *PeerEndpoint, context: *webrtc.srtp.Context) Error!SrtcpDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeRtcp(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            var authenticated = try context.unprotectRtcp(self.allocator, raw.bytes);
            errdefer authenticated.deinit(self.allocator);
            return .{ .from = raw.from, .bytes = raw.bytes, .authenticated = authenticated };
        }
    }

    pub fn receiveSrtcpCompound(self: *PeerEndpoint, context: *webrtc.srtp.Context) Error!SrtcpCompoundDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeRtcp(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            var authenticated = try context.unprotectRtcpCompound(self.allocator, raw.bytes);
            errdefer authenticated.deinit(self.allocator);
            return .{ .from = raw.from, .bytes = raw.bytes, .authenticated = authenticated };
        }
    }

    pub fn receiveDtlsRecord(self: *PeerEndpoint) Error!DtlsDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeDtls(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            const record = try webrtc.dtls.Record.parse(raw.bytes);
            return .{ .from = raw.from, .bytes = raw.bytes, .record = record };
        }
    }

    pub fn receiveAny(self: *PeerEndpoint) Error!PeerDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (looksLikeStun(raw.bytes)) {
                var message = try stun.parse(self.allocator, raw.bytes);
                errdefer message.deinit(self.allocator);
                return .{ .stun = .{ .from = raw.from, .bytes = raw.bytes, .message = message } };
            }
            if (looksLikeDtls(raw.bytes)) {
                const record = try webrtc.dtls.Record.parse(raw.bytes);
                return .{ .dtls = .{ .from = raw.from, .bytes = raw.bytes, .record = record } };
            }
            if (looksLikeRtcp(raw.bytes)) {
                var parsed = try webrtc.rtcp.parsePacket(self.allocator, raw.bytes);
                errdefer parsed.deinit(self.allocator);
                return .{ .rtcp = .{ .from = raw.from, .bytes = raw.bytes, .packet = parsed.packet } };
            }
            if (looksLikeRtp(raw.bytes)) {
                var packet = try webrtc.rtp.Packet.parse(self.allocator, raw.bytes);
                errdefer packet.deinit(self.allocator);
                return .{ .rtp = .{ .from = raw.from, .bytes = raw.bytes, .packet = packet } };
            }
            raw.deinit(self.allocator);
        }
    }

    pub fn receiveManyConcurrent(self: *PeerEndpoint, count: usize) Error!PeerDatagramBatch {
        var group: std.Io.Group = .init;
        const datagrams = try self.allocator.alloc(?PeerDatagram, count);
        errdefer self.allocator.free(datagrams);
        @memset(datagrams, null);
        const errors = try self.allocator.alloc(?anyerror, count);
        errdefer self.allocator.free(errors);
        @memset(errors, null);

        for (datagrams, errors) |*datagram, *err_slot| {
            const task = PeerReceiveTask{
                .endpoint = self,
                .datagram = datagram,
                .err = err_slot,
            };
            group.async(self.io, PeerReceiveTask.run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .datagrams = datagrams, .errors = errors };
    }

    fn receiveStunDatagram(self: *PeerEndpoint) Error!StunDatagram {
        while (true) {
            var raw = try self.receiveRaw();
            errdefer raw.deinit(self.allocator);
            if (!looksLikeStun(raw.bytes)) {
                raw.deinit(self.allocator);
                continue;
            }
            var message = try stun.parse(self.allocator, raw.bytes);
            errdefer message.deinit(self.allocator);
            return .{ .from = raw.from, .bytes = raw.bytes, .message = message };
        }
    }

    fn receiveRaw(self: *PeerEndpoint) Error!RawDatagram {
        const buffer = try self.allocator.alloc(u8, self.limits.max_datagram_size);
        defer self.allocator.free(buffer);
        const incoming = try self.socket.receive(self.io, buffer);
        if (incoming.data.len == 0) return error.EmptyDatagram;
        const bytes = try self.allocator.dupe(u8, incoming.data);
        return .{ .from = incoming.from, .bytes = bytes };
    }
};

const PeerReceiveTask = struct {
    endpoint: *PeerEndpoint,
    datagram: *?PeerDatagram,
    err: *?anyerror,

    fn run(task: PeerReceiveTask) std.Io.Cancelable!void {
        task.datagram.* = task.endpoint.receiveAny() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

pub const RtpServer = struct {
    endpoint: RtpEndpoint,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!RtpServer {
        return .{ .endpoint = try .bind(allocator, io, bind_address, limits) };
    }

    pub fn deinit(self: *RtpServer) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: RtpServer) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn sendPacket(self: *RtpServer, to: net.IpAddress, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        try self.endpoint.sendPacket(to, options, payload);
    }

    pub fn receivePacket(self: *RtpServer) Error!RtpDatagram {
        return self.endpoint.receivePacket();
    }
};

pub const RtpClient = struct {
    endpoint: RtpEndpoint,
    peer: net.IpAddress,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, peer: net.IpAddress, limits: Limits) Error!RtpClient {
        return .{
            .endpoint = try .bind(allocator, io, local_address, limits),
            .peer = peer,
        };
    }

    pub fn deinit(self: *RtpClient) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: RtpClient) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn sendPacket(self: *RtpClient, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        try self.endpoint.sendPacket(self.peer, options, payload);
    }

    pub fn receivePacket(self: *RtpClient) Error!RtpDatagram {
        return self.endpoint.receivePacket();
    }
};

pub const RtpEndpoint = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    socket: net.Socket,
    limits: Limits = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!RtpEndpoint {
        return .{
            .io = io,
            .allocator = allocator,
            .socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *RtpEndpoint) void {
        self.socket.close(self.io);
        self.* = undefined;
    }

    pub fn address(self: RtpEndpoint) net.IpAddress {
        return self.socket.address;
    }

    pub fn sendPacket(self: *RtpEndpoint, to: net.IpAddress, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        // This runtime intentionally sends plain RTP.  DTLS/SRTP negotiation is
        // a higher WebRTC layer; keeping raw RTP available makes loopback media
        // pipelines and codec tests usable while those layers are built out.
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try webrtc.rtp.writePacket(&encoded, self.allocator, options, payload);
        try self.sendBytes(to, encoded.items);
    }

    pub fn sendBytes(self: *RtpEndpoint, to: net.IpAddress, bytes: []const u8) Error!void {
        if (bytes.len == 0) return error.EmptyDatagram;
        if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        try self.socket.send(self.io, &to, bytes);
    }

    pub fn receivePacket(self: *RtpEndpoint) Error!RtpDatagram {
        const buffer = try self.allocator.alloc(u8, self.limits.max_datagram_size);
        defer self.allocator.free(buffer);
        const incoming = try self.socket.receive(self.io, buffer);
        if (incoming.data.len == 0) return error.EmptyDatagram;
        const bytes = try self.allocator.dupe(u8, incoming.data);
        errdefer self.allocator.free(bytes);
        var packet = try webrtc.rtp.Packet.parse(self.allocator, bytes);
        errdefer packet.deinit(self.allocator);
        return .{ .from = incoming.from, .bytes = bytes, .packet = packet };
    }
};

pub const RtpDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    packet: webrtc.rtp.Packet,

    pub fn deinit(self: *RtpDatagram, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const SrtpDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    authenticated: webrtc.srtp.AuthenticatedRtp,

    pub fn deinit(self: *SrtpDatagram, allocator: std.mem.Allocator) void {
        self.authenticated.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const SrtcpDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    authenticated: webrtc.srtp.AuthenticatedRtcp,

    pub fn deinit(self: *SrtcpDatagram, allocator: std.mem.Allocator) void {
        self.authenticated.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const SrtcpCompoundDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    authenticated: webrtc.srtp.AuthenticatedRtcpCompound,

    pub fn deinit(self: *SrtcpCompoundDatagram, allocator: std.mem.Allocator) void {
        self.authenticated.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const DtlsDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    record: webrtc.dtls.Record,

    pub fn deinit(self: *DtlsDatagram, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const RtcpDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    packet: webrtc.rtcp.Packet,

    pub fn deinit(self: *RtcpDatagram, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const PeerDatagram = union(enum) {
    stun: StunDatagram,
    dtls: DtlsDatagram,
    rtcp: RtcpDatagram,
    rtp: RtpDatagram,

    pub fn deinit(self: *PeerDatagram, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .stun => |*datagram| datagram.deinit(allocator),
            .dtls => |*datagram| datagram.deinit(allocator),
            .rtcp => |*datagram| datagram.deinit(allocator),
            .rtp => |*datagram| datagram.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const PeerDatagramBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?PeerDatagram,
    errors: []?anyerror,

    pub fn deinit(self: *PeerDatagramBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: PeerDatagramBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: PeerDatagramBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            if (datagram != null) count += 1;
        }
        return count;
    }
};

pub const StunServer = struct {
    endpoint: StunEndpoint,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!StunServer {
        return .{ .endpoint = try .bind(allocator, io, bind_address, limits) };
    }

    pub fn deinit(self: *StunServer) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: StunServer) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn receiveBindingRequest(self: *StunServer) Error!StunDatagram {
        while (true) {
            var datagram = try self.endpoint.receive();
            errdefer datagram.deinit(self.endpoint.allocator);
            if (datagram.message.method == .binding and datagram.message.class == .request) return datagram;
            datagram.deinit(self.endpoint.allocator);
        }
    }

    pub fn receiveIceBindingRequest(self: *StunServer, expected_username: []const u8, password: []const u8) Error!IceBindingRequest {
        while (true) {
            var datagram = try self.receiveBindingRequest();
            errdefer datagram.deinit(self.endpoint.allocator);
            const validated = stun.validateIceBindingRequest(datagram.bytes, datagram.message, expected_username, password) catch |err| switch (err) {
                error.InvalidStunMessage,
                error.InvalidStunAttribute,
                error.MissingStunAttribute,
                error.BadMessageIntegrity,
                error.BadFingerprint,
                => {
                    datagram.deinit(self.endpoint.allocator);
                    continue;
                },
                else => |e| return e,
            };
            return .{ .datagram = datagram, .validated = validated };
        }
    }

    pub fn respondBindingSuccess(self: *StunServer, request: StunDatagram) Error!void {
        try writeBindingSuccess(&self.endpoint, request);
    }

    pub fn respondIceBindingSuccess(self: *StunServer, request: StunDatagram, password: []const u8) Error!void {
        try writeAuthenticatedBindingSuccess(&self.endpoint, request, password);
    }
};

pub const StunClient = struct {
    endpoint: StunEndpoint,
    server: net.IpAddress,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits) Error!StunClient {
        return .{
            .endpoint = try .bind(allocator, io, local_address, limits),
            .server = server,
        };
    }

    pub fn deinit(self: *StunClient) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: StunClient) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn bindingRequest(self: *StunClient) Error!BindingResponse {
        var transaction_id: [12]u8 = undefined;
        try std.Io.randomSecure(self.endpoint.io, &transaction_id);

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.endpoint.allocator);
        try stun.write(&encoded, self.endpoint.allocator, .request, .binding, transaction_id, &.{});
        try self.endpoint.sendBytes(self.server, encoded.items);

        while (true) {
            var datagram = try self.endpoint.receive();
            errdefer datagram.deinit(self.endpoint.allocator);
            if (!datagram.from.eql(&self.server)) {
                datagram.deinit(self.endpoint.allocator);
                continue;
            }
            if (!std.mem.eql(u8, &datagram.message.transaction_id, &transaction_id)) {
                datagram.deinit(self.endpoint.allocator);
                continue;
            }
            if (datagram.message.method != .binding or datagram.message.class != .success_response) {
                return error.UnexpectedStunMessage;
            }
            const mapped = try findXorMappedAddress(datagram.message);
            return .{ .datagram = datagram, .mapped_address = mapped };
        }
    }

    pub fn iceBindingRequest(self: *StunClient, options: stun.BindingRequestOptions) Error!BindingResponse {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.endpoint.allocator);
        try stun.writeIceBindingRequest(&encoded, self.endpoint.allocator, options);
        try self.endpoint.sendBytes(self.server, encoded.items);

        while (true) {
            var datagram = try self.endpoint.receive();
            errdefer datagram.deinit(self.endpoint.allocator);
            if (!datagram.from.eql(&self.server)) {
                datagram.deinit(self.endpoint.allocator);
                continue;
            }
            if (!std.mem.eql(u8, &datagram.message.transaction_id, &options.transaction_id)) {
                datagram.deinit(self.endpoint.allocator);
                continue;
            }
            if (datagram.message.method != .binding or datagram.message.class != .success_response) {
                return error.UnexpectedStunMessage;
            }
            try stun.validateFingerprint(datagram.bytes);
            try stun.validateMessageIntegrity(datagram.bytes, options.password);
            const mapped = try findXorMappedAddress(datagram.message);
            return .{ .datagram = datagram, .mapped_address = mapped };
        }
    }
};

pub const StunEndpoint = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    socket: net.Socket,
    limits: Limits = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!StunEndpoint {
        return .{
            .io = io,
            .allocator = allocator,
            .socket = try bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp }),
            .limits = limits,
        };
    }

    pub fn deinit(self: *StunEndpoint) void {
        self.socket.close(self.io);
        self.* = undefined;
    }

    pub fn address(self: StunEndpoint) net.IpAddress {
        return self.socket.address;
    }

    pub fn sendBytes(self: *StunEndpoint, to: net.IpAddress, bytes: []const u8) Error!void {
        if (bytes.len == 0) return error.EmptyDatagram;
        if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        try self.socket.send(self.io, &to, bytes);
    }

    pub fn receive(self: *StunEndpoint) Error!StunDatagram {
        const buffer = try self.allocator.alloc(u8, self.limits.max_datagram_size);
        defer self.allocator.free(buffer);
        const incoming = try self.socket.receive(self.io, buffer);
        if (incoming.data.len == 0) return error.EmptyDatagram;
        const bytes = try self.allocator.dupe(u8, incoming.data);
        errdefer self.allocator.free(bytes);
        var message = try stun.parse(self.allocator, bytes);
        errdefer message.deinit(self.allocator);
        return .{ .from = incoming.from, .bytes = bytes, .message = message };
    }
};

pub const StunDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    message: stun.Message,

    pub fn deinit(self: *StunDatagram, allocator: std.mem.Allocator) void {
        self.message.deinit(allocator);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const IceBindingRequest = struct {
    datagram: StunDatagram,
    validated: stun.ValidatedIceBindingRequest,

    pub fn deinit(self: *IceBindingRequest, allocator: std.mem.Allocator) void {
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const BindingResponse = struct {
    datagram: StunDatagram,
    mapped_address: stun.XorMappedAddress,

    pub fn deinit(self: *BindingResponse, allocator: std.mem.Allocator) void {
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

const RawDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,

    fn deinit(self: *RawDatagram, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn writeBindingSuccess(endpoint: anytype, request: StunDatagram) Error!void {
    var value: std.ArrayList(u8) = .empty;
    defer value.deinit(endpoint.allocator);
    const family, const addr_bytes, const port = ipAddressParts(request.from) orelse return error.UnsupportedAddressFamily;
    try stun.writeXorMappedAddress(&value, endpoint.allocator, family, port, addr_bytes, request.message.transaction_id);
    const attrs = [_]stun.Attribute{.{ .attr_type = .xor_mapped_address, .value = value.items }};
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try stun.write(&encoded, endpoint.allocator, .success_response, .binding, request.message.transaction_id, &attrs);
    try endpoint.sendBytes(request.from, encoded.items);
}

fn writeAuthenticatedBindingSuccess(endpoint: anytype, request: StunDatagram, password: []const u8) Error!void {
    var value: std.ArrayList(u8) = .empty;
    defer value.deinit(endpoint.allocator);
    const family, const addr_bytes, const port = ipAddressParts(request.from) orelse return error.UnsupportedAddressFamily;
    try stun.writeXorMappedAddress(&value, endpoint.allocator, family, port, addr_bytes, request.message.transaction_id);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try stun.writeAuthenticatedBindingSuccess(&encoded, endpoint.allocator, request.message.transaction_id, value.items, password);
    try endpoint.sendBytes(request.from, encoded.items);
}

fn findXorMappedAddress(message: stun.Message) Error!stun.XorMappedAddress {
    for (message.attributes) |attribute| {
        if (attribute.attr_type == .xor_mapped_address) {
            return stun.parseXorMappedAddress(attribute.value, message.transaction_id);
        }
    }
    return error.MissingXorMappedAddress;
}

fn ipAddressParts(address: net.IpAddress) ?struct { stun.AddressFamily, []const u8, u16 } {
    return switch (address) {
        .ip4 => |ip4| .{ .ipv4, &ip4.bytes, ip4.port },
        .ip6 => |ip6| .{ .ipv6, &ip6.bytes, ip6.port },
    };
}

fn looksLikeStun(bytes: []const u8) bool {
    if (bytes.len < 20 or (bytes[0] & 0xc0) != 0) return false;
    return std.mem.readInt(u32, bytes[4..][0..4], .big) == stun.magic_cookie;
}

fn looksLikeRtp(bytes: []const u8) bool {
    return bytes.len >= 12 and (bytes[0] & 0xc0) == 0x80 and !looksLikeRtcp(bytes);
}

fn looksLikeRtcp(bytes: []const u8) bool {
    if (bytes.len < 4 or (bytes[0] & 0xc0) != 0x80) return false;
    return switch (bytes[1]) {
        192...223 => true,
        else => false,
    };
}

fn looksLikeDtls(bytes: []const u8) bool {
    if (bytes.len < 13) return false;
    return switch (bytes[0]) {
        20, 21, 22, 23 => true,
        else => false,
    };
}

test "WebRTC STUN runtime binding request over UDP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try StunServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *StunServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *StunServer) !void {
            var request = try server_ptr.receiveBindingRequest();
            defer request.deinit(server_ptr.endpoint.allocator);
            try server_ptr.respondBindingSuccess(request);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try StunClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer client.deinit();
    var response = try client.bindingRequest();
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    const client_ip4 = client.address().ip4;
    try std.testing.expectEqual(stun.AddressFamily.ipv4, response.mapped_address.family);
    try std.testing.expectEqual(client_ip4.port, response.mapped_address.port);
    try std.testing.expectEqualStrings(&client_ip4.bytes, response.mapped_address.bytes());
}

test "WebRTC STUN runtime authenticated ICE binding request" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try StunServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const password = "shared-ice-password";
    const transaction_id: [12]u8 = .{ 0x10, 0x20, 0x30, 0x40, 1, 2, 3, 4, 5, 6, 7, 8 };
    const expected_priority = stun.priority(126, 65_535, 1);

    const Shared = struct {
        server: *StunServer,
        password: []const u8,
        expected_priority: u32,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, shared.password, shared.expected_priority) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *StunServer, password_bytes: []const u8, expected: u32) !void {
            var request = try server_ptr.receiveIceBindingRequest("remote:local", password_bytes);
            defer request.deinit(server_ptr.endpoint.allocator);
            try std.testing.expectEqualStrings("remote:local", request.validated.username);
            try std.testing.expectEqual(expected, request.validated.priority);
            try std.testing.expectEqual(stun.IceRole.controlling, request.validated.role);
            try std.testing.expectEqual(@as(u64, 0x0102030405060708), request.validated.tie_breaker);
            try std.testing.expect(request.validated.use_candidate);
            try server_ptr.respondIceBindingSuccess(request.datagram, password_bytes);
        }
    };

    var shared = Shared{ .server = &server, .password = password, .expected_priority = expected_priority };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try StunClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer client.deinit();
    var response = try client.iceBindingRequest(.{
        .transaction_id = transaction_id,
        .username = "remote:local",
        .password = password,
        .priority = expected_priority,
        .role = .controlling,
        .tie_breaker = 0x0102030405060708,
        .use_candidate = true,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    const client_ip4 = client.address().ip4;
    try std.testing.expectEqual(stun.AddressFamily.ipv4, response.mapped_address.family);
    try std.testing.expectEqual(client_ip4.port, response.mapped_address.port);
    try stun.validateFingerprint(response.datagram.bytes);
    try stun.validateMessageIntegrity(response.datagram.bytes, password);
}

test "WebRTC ICE binding receive helper drops unauthenticated requests" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try StunServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const password = "shared-ice-password";
    const expected_priority = stun.priority(126, 65_535, 1);

    const Shared = struct {
        server: *StunServer,
        password: []const u8,
        expected_priority: u32,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server, shared.password, shared.expected_priority) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *StunServer, password_bytes: []const u8, expected: u32) !void {
            var request = try server_ptr.receiveIceBindingRequest("remote:local", password_bytes);
            defer request.deinit(server_ptr.endpoint.allocator);
            try std.testing.expectEqual(expected, request.validated.priority);
            try std.testing.expectEqual(stun.IceRole.controlled, request.validated.role);
            try std.testing.expectEqual(@as(u64, 0x1112131415161718), request.validated.tie_breaker);
            try std.testing.expect(!request.validated.use_candidate);
            try server_ptr.respondIceBindingSuccess(request.datagram, password_bytes);
        }
    };

    var shared = Shared{ .server = &server, .password = password, .expected_priority = expected_priority };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var bad_client = try StunClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer bad_client.deinit();
    var bad_encoded: std.ArrayList(u8) = .empty;
    defer bad_encoded.deinit(allocator);
    try stun.writeIceBindingRequest(&bad_encoded, allocator, .{
        .transaction_id = .{ 0xaa, 0xaa, 0xaa, 0xaa, 1, 2, 3, 4, 5, 6, 7, 8 },
        .username = "remote:local",
        .password = "wrong-password",
        .priority = expected_priority,
        .role = .controlled,
        .tie_breaker = 0x0102030405060708,
    });
    try bad_client.endpoint.sendBytes(server.address(), bad_encoded.items);

    var good_client = try StunClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer good_client.deinit();
    var response = try good_client.iceBindingRequest(.{
        .transaction_id = .{ 0xbb, 0xbb, 0xbb, 0xbb, 1, 2, 3, 4, 5, 6, 7, 8 },
        .username = "remote:local",
        .password = password,
        .priority = expected_priority,
        .role = .controlled,
        .tie_breaker = 0x1112131415161718,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebRTC RTP runtime sends and receives packets over UDP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try RtpServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    var client = try RtpClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{});
    defer client.deinit();

    try client.sendPacket(.{
        .marker = true,
        .payload_type = 111,
        .sequence_number = 1,
        .timestamp = 160,
        .ssrc = 0x01020304,
    }, "opus-frame");

    var inbound = try server.receivePacket();
    defer inbound.deinit(allocator);
    const client_addr = client.address();
    try std.testing.expect(inbound.from.eql(&client_addr));
    try std.testing.expect(inbound.packet.header.marker);
    try std.testing.expectEqual(@as(u7, 111), inbound.packet.header.payload_type);
    try std.testing.expectEqual(@as(u16, 1), inbound.packet.header.sequence_number);
    try std.testing.expectEqual(@as(u32, 160), inbound.packet.header.timestamp);
    try std.testing.expectEqual(@as(u32, 0x01020304), inbound.packet.header.ssrc);
    try std.testing.expectEqualStrings("opus-frame", inbound.packet.payload);

    try server.sendPacket(inbound.from, .{
        .payload_type = 111,
        .sequence_number = 2,
        .timestamp = 320,
        .ssrc = 0x05060708,
    }, "server-frame");

    var response = try client.receivePacket();
    defer response.deinit(allocator);
    const server_addr = server.address();
    try std.testing.expect(response.from.eql(&server_addr));
    try std.testing.expectEqual(@as(u16, 2), response.packet.header.sequence_number);
    try std.testing.expectEqual(@as(u32, 320), response.packet.header.timestamp);
    try std.testing.expectEqualStrings("server-frame", response.packet.payload);
}

test "WebRTC peer runtime sends authenticated SRTCP and rejects replay" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const auth_key = [_]u8{0x5a} ** webrtc.srtp.hmac_sha1_len;
    var sender_context = webrtc.srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    var receiver_context = webrtc.srtp.Context{ .keys = .{ .auth_key = &auth_key } };

    var receiver = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();

    try sender.sendSrtcpPacket(receiver.address(), &sender_context, .{ .picture_loss_indication = .{
        .sender_ssrc = 0x01020304,
        .media_ssrc = 0x11121314,
    } });

    var protected = try receiver.receiveSrtcpPacket(&receiver_context);
    defer protected.deinit(allocator);
    try std.testing.expect(protected.from.eql(&sender.address()));
    try std.testing.expectEqual(@as(u31, 0), protected.authenticated.verified.index);
    try std.testing.expectEqual(@as(u32, 0x11121314), protected.authenticated.rtcp.picture_loss_indication.media_ssrc);

    var replay_bytes: std.ArrayList(u8) = .empty;
    defer replay_bytes.deinit(allocator);
    try sender_context.protectRtcpPacket(&replay_bytes, allocator, .{ .picture_loss_indication = .{
        .sender_ssrc = 0x01020304,
        .media_ssrc = 0x22222222,
    } });
    try sender.endpoint.sendBytes(receiver.address(), replay_bytes.items);
    var first = try receiver.receiveSrtcpPacket(&receiver_context);
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 0x22222222), first.authenticated.rtcp.picture_loss_indication.media_ssrc);

    try sender.endpoint.sendBytes(receiver.address(), replay_bytes.items);
    try std.testing.expectError(error.SrtpReplay, receiver.receiveSrtcpPacket(&receiver_context));
}

test "WebRTC peer runtime sends authenticated compound SRTCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const auth_key = [_]u8{0x6b} ** webrtc.srtp.hmac_sha1_len;
    var sender_context = webrtc.srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    var receiver_context = webrtc.srtp.Context{ .keys = .{ .auth_key = &auth_key } };

    var receiver = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();

    var sdes_items = [_]webrtc.rtcp.SdesItem{.{ .item_type = .cname, .value = "runtime@example.test" }};
    var sdes_chunks = [_]webrtc.rtcp.SdesChunk{.{ .ssrc = 0x01020304, .items = &sdes_items }};
    const packets = [_]webrtc.rtcp.Packet{
        .{ .receiver_report = .{ .sender_ssrc = 0x01020304 } },
        .{ .source_description = .{ .chunks = &sdes_chunks } },
        .{ .picture_loss_indication = .{ .sender_ssrc = 0x01020304, .media_ssrc = 0x11223344 } },
    };
    try sender.sendSrtcpCompound(receiver.address(), &sender_context, &packets);

    var protected = try receiver.receiveSrtcpCompound(&receiver_context);
    defer protected.deinit(allocator);
    try std.testing.expect(protected.from.eql(&sender.address()));
    try std.testing.expectEqual(@as(u31, 0), protected.authenticated.verified.index);
    try std.testing.expectEqual(@as(usize, 3), protected.authenticated.rtcp.len);
    try std.testing.expectEqualStrings("runtime@example.test", protected.authenticated.rtcp[1].source_description.cname(0x01020304).?);
    try std.testing.expectEqual(@as(u32, 0x11223344), protected.authenticated.rtcp[2].picture_loss_indication.media_ssrc);
}

test "WebRTC peer runtime sends authenticated SRTP and rejects replay" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const auth_key = [_]u8{0xa5} ** webrtc.srtp.hmac_sha1_len;
    var sender_context = webrtc.srtp.Context{ .keys = .{ .auth_key = &auth_key } };
    var receiver_context = webrtc.srtp.Context{ .keys = .{ .auth_key = &auth_key } };

    var receiver = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();

    try sender.sendSrtpPacket(receiver.address(), &sender_context, .{
        .marker = true,
        .payload_type = 111,
        .sequence_number = 1,
        .timestamp = 480,
        .ssrc = 0x01020304,
    }, "authenticated-media");

    var protected = try receiver.receiveSrtpPacket(&receiver_context);
    defer protected.deinit(allocator);
    try std.testing.expect(protected.from.eql(&sender.address()));
    try std.testing.expectEqual(@as(u16, 1), protected.authenticated.rtp.header.sequence_number);
    try std.testing.expectEqual(@as(u64, 1), protected.authenticated.verified.packet_index);
    try std.testing.expectEqualStrings("authenticated-media", protected.authenticated.rtp.payload);

    var replay_bytes: std.ArrayList(u8) = .empty;
    defer replay_bytes.deinit(allocator);
    try sender_context.protectRtpPacket(&replay_bytes, allocator, .{
        .payload_type = 111,
        .sequence_number = 2,
        .timestamp = 960,
        .ssrc = 0x01020304,
    }, "replay-once");
    try sender.endpoint.sendBytes(receiver.address(), replay_bytes.items);
    var replay_first = try receiver.receiveSrtpPacket(&receiver_context);
    defer replay_first.deinit(allocator);
    try std.testing.expectEqualStrings("replay-once", replay_first.authenticated.rtp.payload);

    try sender.endpoint.sendBytes(receiver.address(), replay_bytes.items);
    try std.testing.expectError(error.SrtpReplay, receiver.receiveSrtpPacket(&receiver_context));
}

test "WebRTC peer runtime multiplexes STUN DTLS and RTP on one UDP socket" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Peer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Peer) !void {
            var request = try server_ptr.receiveBindingRequest();
            defer request.deinit(server_ptr.endpoint.allocator);
            try server_ptr.respondBindingSuccess(request);

            var dtls = try server_ptr.receiveDtlsRecord();
            defer dtls.deinit(server_ptr.endpoint.allocator);
            try std.testing.expectEqual(webrtc.dtls.ContentType.handshake, dtls.record.content_type);
            try std.testing.expectEqualStrings("client-hello", dtls.record.fragment);
            try server_ptr.sendDtlsRecord(dtls.from, .{
                .content_type = .handshake,
                .epoch = 0,
                .sequence_number = 2,
            }, "server-hello");

            var media = try server_ptr.receiveRtpPacket();
            defer media.deinit(server_ptr.endpoint.allocator);
            try std.testing.expectEqualStrings("client-media", media.packet.payload);
            try server_ptr.sendRtpPacket(media.from, .{
                .payload_type = 111,
                .sequence_number = 12,
                .timestamp = 960,
                .ssrc = 0x0a0b0c0d,
            }, "server-media");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer client.deinit();

    var response = try client.bindingRequest(server.address());
    defer response.deinit(allocator);
    const client_ip4 = client.address().ip4;
    try std.testing.expectEqual(stun.AddressFamily.ipv4, response.mapped_address.family);
    try std.testing.expectEqual(client_ip4.port, response.mapped_address.port);

    try client.sendDtlsRecord(server.address(), .{
        .content_type = .handshake,
        .epoch = 0,
        .sequence_number = 1,
    }, "client-hello");
    var dtls_response = try client.receiveDtlsRecord();
    defer dtls_response.deinit(allocator);
    try std.testing.expectEqual(webrtc.dtls.ContentType.handshake, dtls_response.record.content_type);
    try std.testing.expectEqual(@as(u48, 2), dtls_response.record.sequence_number);
    try std.testing.expectEqualStrings("server-hello", dtls_response.record.fragment);

    try client.sendRtpPacket(server.address(), .{
        .marker = true,
        .payload_type = 111,
        .sequence_number = 11,
        .timestamp = 480,
        .ssrc = 0x01020304,
    }, "client-media");

    var media_response = try client.receiveRtpPacket();
    defer media_response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    const server_addr = server.address();
    try std.testing.expect(media_response.from.eql(&server_addr));
    try std.testing.expectEqual(@as(u16, 12), media_response.packet.header.sequence_number);
    try std.testing.expectEqualStrings("server-media", media_response.packet.payload);
}

test "WebRTC peer runtime sends and receives RTCP feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer receiver.deinit();
    var sender = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer sender.deinit();

    try receiver.sendRtcpPacket(sender.address(), .{ .picture_loss_indication = .{
        .sender_ssrc = 0x01020304,
        .media_ssrc = 0x11121314,
    } });

    var inbound_pli = try sender.receiveRtcpPacket();
    defer inbound_pli.deinit(allocator);
    try std.testing.expect(inbound_pli.from.eql(&receiver.address()));
    try std.testing.expectEqual(@as(u32, 0x01020304), inbound_pli.packet.picture_loss_indication.sender_ssrc);
    try std.testing.expectEqual(@as(u32, 0x11121314), inbound_pli.packet.picture_loss_indication.media_ssrc);

    var nack_pairs = [_]webrtc.rtcp.NackPair{.{ .packet_id = 44, .lost_packet_bitmask = 0b101 }};
    try sender.sendRtcpPacket(receiver.address(), .{ .transport_layer_nack = .{
        .sender_ssrc = 0x22232425,
        .media_ssrc = 0x33343536,
        .pairs = &nack_pairs,
    } });

    var inbound_nack = try receiver.endpoint.receiveAny();
    defer inbound_nack.deinit(allocator);
    switch (inbound_nack) {
        .rtcp => |rtcp| {
            try std.testing.expectEqual(@as(u32, 0x22232425), rtcp.packet.transport_layer_nack.sender_ssrc);
            try std.testing.expect(rtcp.packet.transport_layer_nack.pairs[0].contains(44));
            try std.testing.expect(rtcp.packet.transport_layer_nack.pairs[0].contains(45));
            try std.testing.expect(rtcp.packet.transport_layer_nack.pairs[0].contains(47));
            try std.testing.expect(!rtcp.packet.transport_layer_nack.pairs[0].contains(46));
        },
        else => return error.UnexpectedStunMessage,
    }
}

test "WebRTC peer receives mixed datagrams with std.Io async demux" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    var client = try Peer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer client.deinit();

    const Shared = struct {
        peer: *Peer,
        batch: ?PeerDatagramBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.peer.receiveManyConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .peer = &server };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try client.sendDtlsRecord(server.address(), .{
        .content_type = .handshake,
        .epoch = 0,
        .sequence_number = 9,
    }, "dtls-nine");
    try client.sendRtpPacket(server.address(), .{
        .payload_type = 111,
        .sequence_number = 33,
        .timestamp = 1440,
        .ssrc = 0x10111213,
    }, "rtp-thirty-three");

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_dtls = false;
    var saw_rtp = false;
    for (batch.datagrams) |maybe_datagram| {
        switch (maybe_datagram.?) {
            .dtls => |dtls| {
                try std.testing.expectEqual(@as(u48, 9), dtls.record.sequence_number);
                try std.testing.expectEqualStrings("dtls-nine", dtls.record.fragment);
                saw_dtls = true;
            },
            .rtp => |rtp| {
                try std.testing.expectEqual(@as(u16, 33), rtp.packet.header.sequence_number);
                try std.testing.expectEqualStrings("rtp-thirty-three", rtp.packet.payload);
                saw_rtp = true;
            },
            .rtcp => return error.UnexpectedStunMessage,
            .stun => return error.UnexpectedStunMessage,
        }
    }
    try std.testing.expect(saw_dtls);
    try std.testing.expect(saw_rtp);
}

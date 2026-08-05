const std = @import("std");
const webrtc = @import("mod.zig");

const net = std.Io.net;
const stun = webrtc.stun;

pub const Error = webrtc.Error || error{
    EmptyDatagram,
    DatagramTooLarge,
    UnexpectedStunMessage,
    MissingXorMappedAddress,
} || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveError || std.Io.RandomSecureError;

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

    pub fn receiveBindingRequest(self: *Peer) Error!StunDatagram {
        return self.endpoint.receiveBindingRequest();
    }

    pub fn respondBindingSuccess(self: *Peer, request: StunDatagram) Error!void {
        try self.endpoint.respondBindingSuccess(request);
    }

    pub fn sendRtpPacket(self: *Peer, to: net.IpAddress, options: webrtc.rtp.WriteOptions, payload: []const u8) Error!void {
        try self.endpoint.sendRtpPacket(to, options, payload);
    }

    pub fn receiveRtpPacket(self: *Peer) Error!RtpDatagram {
        return self.endpoint.receiveRtpPacket();
    }

    pub fn sendDtlsRecord(self: *Peer, to: net.IpAddress, options: webrtc.dtls.WriteOptions, fragment: []const u8) Error!void {
        try self.endpoint.sendDtlsRecord(to, options, fragment);
    }

    pub fn receiveDtlsRecord(self: *Peer) Error!DtlsDatagram {
        return self.endpoint.receiveDtlsRecord();
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

    pub fn receiveBindingRequest(self: *PeerEndpoint) Error!StunDatagram {
        while (true) {
            var datagram = try self.receiveStunDatagram();
            errdefer datagram.deinit(self.allocator);
            if (datagram.message.method == .binding and datagram.message.class == .request) return datagram;
            datagram.deinit(self.allocator);
        }
    }

    pub fn respondBindingSuccess(self: *PeerEndpoint, request: StunDatagram) Error!void {
        try writeBindingSuccess(self, request);
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

    pub fn sendDtlsRecord(self: *PeerEndpoint, to: net.IpAddress, options: webrtc.dtls.WriteOptions, fragment: []const u8) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try webrtc.dtls.writeRecord(&encoded, self.allocator, options, fragment);
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

pub const DtlsDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    record: webrtc.dtls.Record,

    pub fn deinit(self: *DtlsDatagram, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
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

    pub fn respondBindingSuccess(self: *StunServer, request: StunDatagram) Error!void {
        try writeBindingSuccess(&self.endpoint, request);
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
    return bytes.len >= 12 and (bytes[0] & 0xc0) == 0x80;
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

const std = @import("std");
const webtransport = @import("mod.zig");
const http3 = @import("../http3/mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;

pub const Error = webtransport.Error || http3.runtime.Error || error{
    InvalidConnect,
    MissingDatagram,
};

pub const Limits = struct {
    http3: http3.runtime.Limits = .{},
};

pub const Server = struct {
    h3: http3.runtime.Server,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .h3 = try .bind(allocator, io, bind_address, limits.http3) };
    }

    pub fn deinit(self: *Server) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.h3.address();
    }

    pub fn accept(self: *Server) Error!AcceptedSession {
        var request = try self.h3.receiveRequest();
        errdefer request.deinit(self.h3.quic_server.endpoint.allocator);
        if (!std.mem.eql(u8, request.request.method, "CONNECT")) return error.InvalidConnect;
        if (!std.mem.eql(u8, findHeader(request.request.headers, ":protocol") orelse "", "webtransport")) {
            return error.InvalidConnect;
        }
        const session_id = webtransport.SessionId.init(request.stream_id);
        try self.h3.sendResponse(request.from, request.stream_id, .{ .status = 200 });
        return .{ .request = request, .session_id = session_id };
    }

    pub fn receiveDatagram(self: *Server) Error!OwnedDatagram {
        return receiveDatagramFromEndpoint(&self.h3.quic_server.endpoint);
    }

    pub fn sendDatagram(self: *Server, to: net.IpAddress, session_id: webtransport.SessionId, payload: []const u8) Error!void {
        try sendDatagramFromEndpoint(&self.h3.quic_server.endpoint, to, session_id, payload);
    }
};

pub const ProtectedServer = struct {
    h3: http3.runtime.ProtectedServer,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        config: http3.runtime.ProtectedConfig,
    ) Error!ProtectedServer {
        return .{ .h3 = try .bind(allocator, io, bind_address, limits.http3, config) };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: ProtectedServer) net.IpAddress {
        return self.h3.address();
    }

    pub fn accept(self: *ProtectedServer) Error!AcceptedProtectedSession {
        var request = try self.h3.receiveRequest();
        errdefer request.deinit(self.h3.quic_server.endpoint.allocator);
        if (!std.mem.eql(u8, request.request.method, "CONNECT")) return error.InvalidConnect;
        if (!std.mem.eql(u8, findHeader(request.request.headers, ":protocol") orelse "", "webtransport")) {
            return error.InvalidConnect;
        }
        const session_id = webtransport.SessionId.init(request.stream_id);
        try self.h3.sendResponse(request.from, request.stream_id, .{ .status = 200 });
        return .{ .request = request, .session_id = session_id };
    }

    pub fn receiveDatagram(self: *ProtectedServer) Error!OwnedProtectedDatagram {
        return receiveProtectedDatagramFromEndpoint(
            &self.h3.quic_server.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
        );
    }

    pub fn sendDatagram(self: *ProtectedServer, to: net.IpAddress, session_id: webtransport.SessionId, payload: []const u8) Error!void {
        try sendProtectedDatagramFromEndpoint(
            &self.h3.quic_server.endpoint,
            to,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            session_id,
            payload,
        );
    }
};

pub const HandshakeServer = struct {
    h3: http3.runtime.HandshakeServer,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        options: http3.runtime.HandshakeServerOptions,
    ) Error!HandshakeServer {
        return .{ .h3 = try .bind(allocator, io, bind_address, limits.http3, options) };
    }

    pub fn deinit(self: *HandshakeServer) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: HandshakeServer) net.IpAddress {
        return self.h3.address();
    }

    pub fn accept(self: *HandshakeServer) Error!AcceptedHandshakeSession {
        var session = try self.h3.accept();
        errdefer session.deinit();

        var request = try session.receiveRequest();
        errdefer request.deinit(session.established.connection.endpoint.allocator);
        if (!std.mem.eql(u8, request.request.method, "CONNECT")) return error.InvalidConnect;
        if (!std.mem.eql(u8, findHeader(request.request.headers, ":protocol") orelse "", "webtransport")) {
            return error.InvalidConnect;
        }
        const session_id = webtransport.SessionId.init(request.stream_id);
        try session.sendResponse(request.stream_id, .{ .status = 200 });
        return .{ .h3 = session, .request = request, .session_id = session_id };
    }
};

pub const AcceptedSession = struct {
    request: http3.runtime.OwnedRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *AcceptedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const AcceptedProtectedSession = struct {
    request: http3.runtime.OwnedProtectedRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *AcceptedProtectedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
    }
};

pub const AcceptedHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    request: http3.runtime.OwnedHandshakeRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *AcceptedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.request.deinit(allocator);
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn receiveDatagram(self: *AcceptedHandshakeSession) Error!OwnedHandshakeDatagram {
        return receiveHandshakeDatagramFromConnection(&self.h3.established.connection);
    }

    pub fn receiveManyDatagrams(self: *AcceptedHandshakeSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        return receiveManyHandshakeDatagrams(&self.h3.established.connection, count);
    }

    pub fn sendDatagram(self: *AcceptedHandshakeSession, payload: []const u8) Error!void {
        try sendHandshakeDatagramFromConnection(&self.h3.established.connection, self.session_id, payload);
    }
};

pub const ClientSession = struct {
    h3: http3.runtime.Client,
    session_id: webtransport.SessionId,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ConnectOptions,
    ) Error!ClientSession {
        var h3_client = try http3.runtime.Client.connect(allocator, io, local_address, server, options.limits.http3);
        errdefer h3_client.deinit();

        _ = options.origin;
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
        });
        defer response.deinit(allocator);
        if (response.response.status < 200 or response.response.status >= 300) return error.InvalidConnect;

        return .{ .h3 = h3_client, .session_id = .init(0) };
    }

    pub fn deinit(self: *ClientSession) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn address(self: ClientSession) net.IpAddress {
        return self.h3.address();
    }

    pub fn sendDatagram(self: *ClientSession, payload: []const u8) Error!void {
        try sendDatagramFromEndpoint(&self.h3.quic_client.endpoint, self.h3.quic_client.peer, self.session_id, payload);
    }

    pub fn receiveDatagram(self: *ClientSession) Error!OwnedDatagram {
        return receiveDatagramFromEndpoint(&self.h3.quic_client.endpoint);
    }
};

pub const HandshakeClientSession = struct {
    h3: http3.runtime.HandshakeClient,
    session_id: webtransport.SessionId,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
    ) Error!HandshakeClientSession {
        var h3_client = try http3.runtime.HandshakeClient.connect(allocator, io, local_address, server, options.limits.http3, options.h3);
        errdefer h3_client.deinit();
        _ = options.origin;
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
        });
        defer response.deinit(allocator);
        if (response.response.status < 200 or response.response.status >= 300) return error.InvalidConnect;
        return .{ .h3 = h3_client, .session_id = .init(0) };
    }

    pub fn deinit(self: *HandshakeClientSession) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn sendDatagram(self: *HandshakeClientSession, payload: []const u8) Error!void {
        try sendHandshakeDatagramFromConnection(&self.h3.established.connection, self.session_id, payload);
    }

    pub fn receiveDatagram(self: *HandshakeClientSession) Error!OwnedHandshakeDatagram {
        return receiveHandshakeDatagramFromConnection(&self.h3.established.connection);
    }

    pub fn receiveManyDatagrams(self: *HandshakeClientSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        return receiveManyHandshakeDatagrams(&self.h3.established.connection, count);
    }
};

pub const ProtectedClientSession = struct {
    h3: http3.runtime.ProtectedClient,
    session_id: webtransport.SessionId,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: ProtectedConnectOptions,
    ) Error!ProtectedClientSession {
        var h3_client = try http3.runtime.ProtectedClient.connect(allocator, io, local_address, server, options.limits.http3, options.config);
        errdefer h3_client.deinit();
        _ = options.origin;
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
        });
        defer response.deinit(allocator);
        if (response.response.status < 200 or response.response.status >= 300) return error.InvalidConnect;
        return .{ .h3 = h3_client, .session_id = .init(0) };
    }

    pub fn deinit(self: *ProtectedClientSession) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn sendDatagram(self: *ProtectedClientSession, payload: []const u8) Error!void {
        try sendProtectedDatagramFromEndpoint(
            &self.h3.quic_client.endpoint,
            self.h3.quic_client.peer,
            self.h3.config.send_keys,
            self.h3.config.peer_connection_id,
            &self.h3.next_packet_number,
            self.session_id,
            payload,
        );
    }

    pub fn receiveDatagram(self: *ProtectedClientSession) Error!OwnedProtectedDatagram {
        return receiveProtectedDatagramFromEndpoint(
            &self.h3.quic_client.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
        );
    }
};

pub const ConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    limits: Limits = .{},
};

pub const ProtectedConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    limits: Limits = .{},
    config: http3.runtime.ProtectedConfig,
};

pub const HandshakeConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    limits: Limits = .{},
    h3: http3.runtime.HandshakeClientOptions,
};

pub const OwnedDatagram = struct {
    quic_datagram: quic.runtime.OwnedDatagram,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedDatagram, allocator: std.mem.Allocator) void {
        self.quic_datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedProtectedDatagram = struct {
    packet: quic.one_rtt.ReceivedPacket,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedProtectedDatagram, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedHandshakeDatagram = struct {
    packet: quic.one_rtt.ReceivedPacket,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedHandshakeDatagram, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedHandshakeDatagramBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?OwnedHandshakeDatagram,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedHandshakeDatagramBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedHandshakeDatagramBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedHandshakeDatagramBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            if (datagram != null) count += 1;
        }
        return count;
    }
};

fn sendDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded.items, .length_present = true } }};
    try endpoint.sendFrames(to, &frames);
}

fn receiveDatagramFromEndpoint(endpoint: *quic.runtime.Endpoint) Error!OwnedDatagram {
    while (true) {
        var datagram = try endpoint.receive();
        errdefer datagram.deinit(endpoint.allocator);
        for (datagram.frames) |frame| {
            if (frame == .datagram) {
                const wt = try webtransport.Datagram.parse(frame.datagram.data);
                return .{ .quic_datagram = datagram, .datagram = wt };
            }
        }
        datagram.deinit(endpoint.allocator);
    }
}

fn sendHandshakeDatagramFromConnection(
    connection: *quic.one_rtt.Connection,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, connection.endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded.items, .length_present = true } }};
    try connection.send(&frames);
}

fn receiveHandshakeDatagramFromConnection(connection: *quic.one_rtt.Connection) Error!OwnedHandshakeDatagram {
    while (true) {
        var packet = try connection.receivePacket();
        errdefer packet.deinit(connection.endpoint.allocator);
        for (packet.frames) |frame| {
            if (frame == .datagram) {
                const wt = try webtransport.Datagram.parse(frame.datagram.data);
                return .{ .packet = packet, .datagram = wt };
            }
        }
        packet.deinit(connection.endpoint.allocator);
    }
}

fn receiveManyHandshakeDatagrams(connection: *quic.one_rtt.Connection, count: usize) Error!OwnedHandshakeDatagramBatch {
    var group: std.Io.Group = .init;
    const datagrams = try connection.endpoint.allocator.alloc(?OwnedHandshakeDatagram, count);
    errdefer connection.endpoint.allocator.free(datagrams);
    @memset(datagrams, null);
    const errors = try connection.endpoint.allocator.alloc(?anyerror, count);
    errdefer connection.endpoint.allocator.free(errors);
    @memset(errors, null);

    for (datagrams, errors) |*datagram, *err_slot| {
        const task = HandshakeDatagramTask{
            .connection = connection,
            .datagram = datagram,
            .err = err_slot,
        };
        group.async(connection.endpoint.io, HandshakeDatagramTask.run, .{task});
    }

    try group.await(connection.endpoint.io);
    return .{ .allocator = connection.endpoint.allocator, .datagrams = datagrams, .errors = errors };
}

const HandshakeDatagramTask = struct {
    connection: *quic.one_rtt.Connection,
    datagram: *?OwnedHandshakeDatagram,
    err: *?anyerror,

    fn run(task: HandshakeDatagramTask) std.Io.Cancelable!void {
        task.datagram.* = receiveHandshakeDatagramFromConnection(task.connection) catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

fn sendProtectedDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    packet_number: *u64,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded.items, .length_present = true } }};
    try quic.one_rtt.sendFrames(endpoint, to, keys, .{
        .destination_connection_id = destination_connection_id,
        .packet_number = packet_number.*,
        .frames = &frames,
    });
    packet_number.* += 1;
}

fn receiveProtectedDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    keys: quic.protection.PacketProtectionKeys,
    local_connection_id_len: usize,
    expected_packet_number: *u64,
    max_frames: usize,
) Error!OwnedProtectedDatagram {
    while (true) {
        var packet = try quic.one_rtt.receive(endpoint, keys, local_connection_id_len, expected_packet_number.*, max_frames);
        errdefer packet.deinit(endpoint.allocator);
        expected_packet_number.* = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame == .datagram) {
                const wt = try webtransport.Datagram.parse(frame.datagram.data);
                return .{ .packet = packet, .datagram = wt };
            }
        }
        packet.deinit(endpoint.allocator);
    }
}

fn findHeader(headers: []const http3.Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "WebTransport runtime CONNECT and datagrams over HTTP/3 dev runtime" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());

            var datagram = try server_ptr.receiveDatagram();
            defer datagram.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("client-dgram", datagram.datagram.payload);

            try server_ptr.sendDatagram(datagram.quic_datagram.from, accepted.session_id, "server-dgram");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
    });
    defer client.deinit();

    try client.sendDatagram("client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("server-dgram", response.datagram.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport protected runtime CONNECT and datagrams over QUIC 1-RTT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            var datagram = try server_ptr.receiveDatagram();
            defer datagram.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("protected-client-dgram", datagram.datagram.payload);
            try server_ptr.sendDatagram(datagram.packet.from, accepted.session_id, "protected-server-dgram");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-protected",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .config = .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    });
    defer client.deinit();

    try client.sendDatagram("protected-client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("protected-server-dgram", response.datagram.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake runtime CONNECT and datagrams over QUIC handshake" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xea, 0xce, 0x10, 0x01, 0xea, 0xce, 0x10, 0x02 };
    const client_cid = [_]u8{ 0xea, 0xce, 0x10, 0x03 };
    const server_cid = [_]u8{ 0xea, 0xce, 0x10, 0x04 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());

            var datagram = try accepted.receiveDatagram();
            defer datagram.deinit(accepted.h3.established.connection.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("handshake-client-dgram", datagram.datagram.payload);
            try accepted.sendDatagram("handshake-server-dgram");
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-handshake",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .h3 = .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            },
        },
    });
    defer client.deinit();

    try client.sendDatagram("handshake-client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("handshake-server-dgram", response.datagram.payload);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake session receives datagrams with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xba, 0xce, 0x20, 0x01, 0xba, 0xce, 0x20, 0x02 };
    const client_cid = [_]u8{ 0xba, 0xce, 0x20, 0x03 };
    const server_cid = [_]u8{ 0xba, 0xce, 0x20, 0x04 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            var batch = try accepted.receiveManyDatagrams(2);
            defer batch.deinit();
            if (batch.firstError()) |err| return err;
            try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

            var saw_one = false;
            var saw_two = false;
            for (batch.datagrams) |maybe_datagram| {
                const datagram = maybe_datagram.?;
                try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
                if (std.mem.eql(u8, datagram.datagram.payload, "batch-one")) saw_one = true;
                if (std.mem.eql(u8, datagram.datagram.payload, "batch-two")) saw_two = true;
            }
            try std.testing.expect(saw_one);
            try std.testing.expect(saw_two);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-handshake-batch",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .h3 = .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
            },
        },
    });
    defer client.deinit();

    try client.sendDatagram("batch-one");
    try client.sendDatagram("batch-two");

    thread.join();
    if (shared.err) |err| return err;
}

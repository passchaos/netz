const std = @import("std");
const webtransport = @import("mod.zig");
const http3 = @import("../http3/mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;
const datagram_stack_capacity: usize = 4096;

pub const Error = webtransport.Error || http3.runtime.Error || error{
    InvalidConnect,
    MissingDatagram,
};

pub const Limits = struct {
    http3: http3.runtime.Limits = .{},
    max_session_streams: usize = 128,
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
        try validateConnectRequest(request.request);
        const session_id = webtransport.SessionId.init(request.stream_id);
        if (!session_id.isClientInitiatedBidirectional()) return error.InvalidConnect;
        try self.h3.sendResponse(request.from, request.stream_id, connectResponse());
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
        return .{ .h3 = try .bind(allocator, io, bind_address, limits.http3, webTransportProtectedConfig(config)) };
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
        try validateConnectRequest(request.request);
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        const session_id = webtransport.SessionId.init(request.stream_id);
        if (!session_id.isClientInitiatedBidirectional()) return error.InvalidConnect;
        try self.h3.sendResponse(request.from, request.stream_id, connectResponse());
        return .{ .request = request, .session_id = session_id };
    }

    pub fn receiveDatagram(self: *ProtectedServer) Error!OwnedProtectedDatagram {
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        return receiveProtectedDatagramFromEndpoint(
            &self.h3.quic_server.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
        );
    }

    pub fn sendDatagram(self: *ProtectedServer, to: net.IpAddress, session_id: webtransport.SessionId, payload: []const u8) Error!void {
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
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
    limits: Limits,

    pub fn bind(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        limits: Limits,
        options: http3.runtime.HandshakeServerOptions,
    ) Error!HandshakeServer {
        return .{
            .h3 = try .bind(
                allocator,
                io,
                bind_address,
                limits.http3,
                webTransportHandshakeServerOptions(options),
            ),
            .limits = limits,
        };
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
        try validateConnectRequest(request.request);
        try webtransport.ensureDatagramsNegotiated(session.options.local_settings, session.control.settings.peer);
        const session_id = webtransport.SessionId.init(request.stream_id);
        if (!session_id.isClientInitiatedBidirectional()) return error.InvalidConnect;
        try session.sendResponse(request.stream_id, connectResponse());
        var streams = try initHandshakeStreamRegistry(
            session.established.connection.endpoint.allocator,
            session_id,
            .server,
            session.options.local_settings,
            session.control.settings.peer,
            self.limits.max_session_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        return .{
            .h3 = session,
            .request = request,
            .session_id = session_id,
            .streams = streams,
        };
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
    streams: webtransport.StreamRegistry,

    pub fn deinit(self: *AcceptedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        self.request.deinit(allocator);
        self.streams.deinit();
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn receiveDatagram(self: *AcceptedHandshakeSession) Error!OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveHandshakeDatagramFromConnection(&self.h3.established.connection);
    }

    pub fn receiveManyDatagrams(self: *AcceptedHandshakeSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveManyHandshakeDatagrams(&self.h3.established.connection, count);
    }

    pub fn sendDatagram(self: *AcceptedHandshakeSession, payload: []const u8) Error!void {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        try sendHandshakeDatagramFromConnection(&self.h3.established.connection, self.session_id, payload);
    }

    pub fn maxDatagramPayloadSize(self: AcceptedHandshakeSession) ?usize {
        return webtransport.maxDatagramPayloadSize(self.h3.established.connection.maxDatagramPayloadSize(), self.session_id);
    }

    pub fn datagramsNegotiated(self: AcceptedHandshakeSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer) catch return false;
        return true;
    }

    pub fn stats(self: AcceptedHandshakeSession) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn getStats(self: AcceptedHandshakeSession) quic.one_rtt.ConnectionStats {
        return self.stats();
    }

    pub fn openBidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return (try self.streams.openLocal(.bidirectional)).stream_id;
    }

    pub fn openUnidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        // Server push and WebTransport uni streams share the server-initiated
        // QUIC stream-ID space. Consume the HTTP/3 session's allocator so a
        // later push cannot reuse this ID.
        const stream_id =
            try self.h3.reserveServerUnidirectionalStreamId();
        const stream = try self.streams.registerLocal(
            stream_id,
            .unidirectional,
        );
        return stream.stream_id;
    }

    pub fn sendStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try sendHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
    }

    pub fn receiveStream(
        self: *AcceptedHandshakeSession,
    ) Error!OwnedHandshakeStream {
        return receiveHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
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

        var header_buf: [3]http3.Qpack.HeaderField = undefined;
        const headers = connectRequestHeaders(options.origin, &header_buf);
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = headers,
        });
        defer response.deinit(allocator);
        try validateConnectResponse(response.response);

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
    streams: webtransport.StreamRegistry,

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: HandshakeConnectOptions,
    ) Error!HandshakeClientSession {
        var h3_client = try http3.runtime.HandshakeClient.connect(allocator, io, local_address, server, options.limits.http3, webTransportHandshakeClientOptions(options.h3));
        errdefer h3_client.deinit();
        var header_buf: [3]http3.Qpack.HeaderField = undefined;
        const headers = connectRequestHeaders(options.origin, &header_buf);
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = headers,
        });
        defer response.deinit(allocator);
        try validateConnectResponse(response.response);
        try webtransport.ensureDatagramsNegotiated(h3_client.options.local_settings, h3_client.control.settings.peer);
        const session_id = webtransport.SessionId.init(0);
        var streams = try initHandshakeStreamRegistry(
            allocator,
            session_id,
            .client,
            h3_client.options.local_settings,
            h3_client.control.settings.peer,
            options.limits.max_session_streams,
            null,
            null,
        );
        errdefer streams.deinit();
        return .{
            .h3 = h3_client,
            .session_id = session_id,
            .streams = streams,
        };
    }

    pub fn deinit(self: *HandshakeClientSession) void {
        self.streams.deinit();
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn sendDatagram(self: *HandshakeClientSession, payload: []const u8) Error!void {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        try sendHandshakeDatagramFromConnection(&self.h3.established.connection, self.session_id, payload);
    }

    pub fn receiveDatagram(self: *HandshakeClientSession) Error!OwnedHandshakeDatagram {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveHandshakeDatagramFromConnection(&self.h3.established.connection);
    }

    pub fn receiveManyDatagrams(self: *HandshakeClientSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        try webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer);
        return receiveManyHandshakeDatagrams(&self.h3.established.connection, count);
    }

    pub fn maxDatagramPayloadSize(self: HandshakeClientSession) ?usize {
        return webtransport.maxDatagramPayloadSize(self.h3.established.connection.maxDatagramPayloadSize(), self.session_id);
    }

    pub fn datagramsNegotiated(self: HandshakeClientSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.options.local_settings, self.h3.control.settings.peer) catch return false;
        return true;
    }

    pub fn stats(self: HandshakeClientSession) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn getStats(self: HandshakeClientSession) quic.one_rtt.ConnectionStats {
        return self.stats();
    }

    pub fn openBidirectionalStream(
        self: *HandshakeClientSession,
    ) Error!u62 {
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        // HTTP requests and WebTransport bidi streams share client-initiated
        // QUIC IDs. Advance the HTTP/3 allocator transactionally.
        const stream_id =
            try self.h3.reserveClientBidirectionalStreamId();
        const stream = try self.streams.registerLocal(
            stream_id,
            .bidirectional,
        );
        return stream.stream_id;
    }

    pub fn openUnidirectionalStream(
        self: *HandshakeClientSession,
    ) Error!u62 {
        try webtransport.ensureNegotiated(
            self.h3.options.local_settings,
            self.h3.control.settings.peer,
        );
        return (try self.streams.openLocal(.unidirectional)).stream_id;
    }

    pub fn sendStream(
        self: *HandshakeClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try sendHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
    }

    pub fn receiveStream(
        self: *HandshakeClientSession,
    ) Error!OwnedHandshakeStream {
        return receiveHandshakeSessionStream(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
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
        var h3_client = try http3.runtime.ProtectedClient.connect(allocator, io, local_address, server, options.limits.http3, webTransportProtectedConfig(options.config));
        errdefer h3_client.deinit();
        var header_buf: [3]http3.Qpack.HeaderField = undefined;
        const headers = connectRequestHeaders(options.origin, &header_buf);
        var response = try h3_client.request(.{
            .method = "CONNECT",
            .path = options.path,
            .scheme = "https",
            .authority = options.authority,
            .headers = headers,
        });
        defer response.deinit(allocator);
        try validateConnectResponse(response.response);
        try webtransport.ensureDatagramsNegotiated(h3_client.config.local_settings, h3_client.control.settings.peer);
        return .{ .h3 = h3_client, .session_id = .init(0) };
    }

    pub fn deinit(self: *ProtectedClientSession) void {
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn sendDatagram(self: *ProtectedClientSession, payload: []const u8) Error!void {
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
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
        try webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer);
        return receiveProtectedDatagramFromEndpoint(
            &self.h3.quic_client.endpoint,
            self.h3.config.receive_keys,
            self.h3.config.local_connection_id.len,
            &self.h3.expected_packet_number,
            self.h3.config.max_frames_per_packet,
        );
    }

    pub fn datagramsNegotiated(self: ProtectedClientSession) bool {
        webtransport.ensureDatagramsNegotiated(self.h3.config.local_settings, self.h3.control.settings.peer) catch return false;
        return true;
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

fn webTransportProtectedConfig(config: http3.runtime.ProtectedConfig) http3.runtime.ProtectedConfig {
    var out = config;
    out.local_settings = webtransport.defaultSettings(out.local_settings);
    return out;
}

fn webTransportHandshakeServerOptions(options: http3.runtime.HandshakeServerOptions) http3.runtime.HandshakeServerOptions {
    var out = options;
    out.session.local_settings = webtransport.defaultSettings(out.session.local_settings);
    return out;
}

fn webTransportHandshakeClientOptions(options: http3.runtime.HandshakeClientOptions) http3.runtime.HandshakeClientOptions {
    var out = options;
    out.session.local_settings = webtransport.defaultSettings(out.session.local_settings);
    return out;
}

fn validateConnectRequest(request: anytype) Error!void {
    if (!std.mem.eql(u8, request.method, "CONNECT")) return error.InvalidConnect;
    if (!std.mem.eql(u8, findHeader(request.headers, ":protocol") orelse "", "webtransport")) {
        return error.InvalidConnect;
    }
    if (!(http3.capsule.protocolEnabled(request.headers) catch return error.InvalidConnect)) {
        return error.InvalidConnect;
    }
}

fn connectResponse() http3.Response {
    return .{ .status = 200, .headers = &.{http3.capsule.protocol_header} };
}

fn validateConnectResponse(response: anytype) Error!void {
    if (response.status < 200 or response.status >= 300) return error.InvalidConnect;
    if (!(http3.capsule.protocolEnabled(response.headers) catch return error.InvalidConnect)) {
        return error.InvalidConnect;
    }
}

fn connectRequestHeaders(origin: []const u8, out: *[3]http3.Qpack.HeaderField) []const http3.Qpack.HeaderField {
    var count: usize = 0;
    out[count] = .{ .name = ":protocol", .value = "webtransport" };
    count += 1;
    out[count] = http3.capsule.protocol_header;
    count += 1;
    // Keep the historical "/" default from ConnectOptions as "not supplied";
    // real WebTransport clients can pass an Origin value and have it carried in
    // the CONNECT request for server-side policy checks.
    if (origin.len != 0 and !std.mem.eql(u8, origin, "/")) {
        out[count] = .{ .name = "origin", .value = origin };
        count += 1;
    }
    return out[0..count];
}

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
    bytes: []u8,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedHandshakeDatagram, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
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

const handshake_stream = @import("runtime/stream.zig");
pub const OwnedHandshakeStream = handshake_stream.OwnedHandshakeStream;
const initHandshakeStreamRegistry = handshake_stream.initRegistry;
const sendHandshakeSessionStream = handshake_stream.send;
const receiveHandshakeSessionStream = handshake_stream.receive;

fn sendDatagramFromEndpoint(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!void {
    var storage: [datagram_stack_capacity]u8 = undefined;
    if (try encodeDatagramIntoStack(&storage, session_id, payload)) |encoded| {
        const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded, .length_present = true } }};
        try endpoint.sendFrames(to, &frames);
        return;
    }

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    try (webtransport.Datagram{ .session_id = session_id, .payload = payload }).write(&encoded, endpoint.allocator);
    const frames = [_]quic.Frame{.{ .datagram = .{ .data = encoded.items, .length_present = true } }};
    try endpoint.sendFrames(to, &frames);
}

fn encodeDatagramIntoStack(
    storage: *[datagram_stack_capacity]u8,
    session_id: webtransport.SessionId,
    payload: []const u8,
) Error!?[]const u8 {
    if (!session_id.isClientInitiatedBidirectional()) return error.InvalidSessionId;
    const prefix = try quic.varint.encodeInto(storage, session_id.quarterStreamId());
    const total_len = std.math.add(usize, prefix.len, payload.len) catch return error.IntegerOverflow;
    if (total_len > storage.len) return null;
    @memcpy(storage[prefix.len..total_len], payload);
    return storage[0..total_len];
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
    try connection.sendDatagram(encoded.items);
}

fn receiveHandshakeDatagramFromConnection(connection: *quic.one_rtt.Connection) Error!OwnedHandshakeDatagram {
    while (true) {
        if (try popHandshakeDatagramFromConnection(connection)) |datagram| return datagram;
        var packet = try connection.receivePacket();
        packet.deinit(connection.endpoint.allocator);
    }
}

fn popHandshakeDatagramFromConnection(connection: *quic.one_rtt.Connection) Error!?OwnedHandshakeDatagram {
    const allocator = connection.endpoint.allocator;
    const capacity = connection.config.local_max_datagram_frame_size orelse connection.config.max_datagram_size;
    if (capacity == 0) return null;

    var buffer = try allocator.alloc(u8, capacity);
    errdefer allocator.free(buffer);
    const payload = (try connection.popDatagram(buffer)) orelse {
        allocator.free(buffer);
        return null;
    };
    if (payload.len != buffer.len) buffer = try allocator.realloc(buffer, payload.len);
    const wt = try webtransport.Datagram.parse(buffer);
    return .{ .bytes = buffer, .datagram = wt };
}

fn drainQueuedHandshakeDatagrams(connection: *quic.one_rtt.Connection, datagrams: []?OwnedHandshakeDatagram) Error!usize {
    var count: usize = 0;
    while (count < datagrams.len) {
        const datagram = (try popHandshakeDatagramFromConnection(connection)) orelse break;
        datagrams[count] = datagram;
        count += 1;
    }
    return count;
}

fn receiveManyHandshakeDatagrams(connection: *quic.one_rtt.Connection, count: usize) Error!OwnedHandshakeDatagramBatch {
    const datagrams = try connection.endpoint.allocator.alloc(?OwnedHandshakeDatagram, count);
    errdefer connection.endpoint.allocator.free(datagrams);
    @memset(datagrams, null);
    const errors = try connection.endpoint.allocator.alloc(?anyerror, count);
    errdefer connection.endpoint.allocator.free(errors);
    @memset(errors, null);

    const filled = try drainQueuedHandshakeDatagrams(connection, datagrams);
    if (filled == count) return .{ .allocator = connection.endpoint.allocator, .datagrams = datagrams, .errors = errors };

    // A QUIC connection owns packet-number, ACK, flow-control, and DATAGRAM
    // queue state.  Unlike independent endpoint receives, multiple concurrent
    // receivePacket() calls on the same Connection would race those mutable
    // invariants.  Batch reception therefore drains one connection
    // sequentially while still returning the ergonomic batch/error shape used
    // by the higher-level runtime.
    for (datagrams[filled..], errors[filled..]) |*datagram, *err_slot| {
        datagram.* = receiveHandshakeDatagramFromConnection(connection) catch |err| {
            err_slot.* = err;
            break;
        };
        err_slot.* = null;
    }
    return .{ .allocator = connection.endpoint.allocator, .datagrams = datagrams, .errors = errors };
}

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

test "WebTransport runtime CONNECT headers advertise Capsule-Protocol" {
    var default_buf: [3]http3.Qpack.HeaderField = undefined;
    const default_headers = connectRequestHeaders("/", &default_buf);
    try std.testing.expectEqual(@as(usize, 2), default_headers.len);
    try std.testing.expectEqualStrings("webtransport", findHeader(default_headers, ":protocol").?);
    try std.testing.expect(try http3.capsule.protocolEnabled(default_headers));
    try validateConnectRequest(.{ .method = "CONNECT", .headers = default_headers });

    var origin_buf: [3]http3.Qpack.HeaderField = undefined;
    const origin_headers = connectRequestHeaders("https://example.com", &origin_buf);
    try std.testing.expectEqual(@as(usize, 3), origin_headers.len);
    try std.testing.expectEqualStrings("https://example.com", findHeader(origin_headers, "origin").?);
    try std.testing.expect(try http3.capsule.protocolEnabled(origin_headers));
    try validateConnectRequest(.{ .method = "CONNECT", .headers = origin_headers });

    const missing_capsule = [_]http3.Qpack.HeaderField{
        .{ .name = ":protocol", .value = "webtransport" },
    };
    try std.testing.expectError(
        error.InvalidConnect,
        validateConnectRequest(.{ .method = "CONNECT", .headers = &missing_capsule }),
    );

    const response = connectResponse();
    try validateConnectResponse(response);
    try std.testing.expect(try http3.capsule.protocolEnabled(response.headers));
    try std.testing.expectError(error.InvalidConnect, validateConnectResponse(.{
        .status = 200,
        .headers = &[_]http3.Qpack.HeaderField{},
    }));
}

test "WebTransport cleartext accept validates CONNECT session id direction" {
    try std.testing.expect(webtransport.SessionId.init(0).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(1).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(2).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(3).isClientInitiatedBidirectional());
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
    const large_stream_payload = try allocator.alloc(u8, 12 * 1024);
    defer allocator.free(large_stream_payload);
    for (large_stream_payload, 0..) |*byte, index| {
        byte.* = @truncate(index);
    }

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
        large_stream_payload: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());

            var client_bidi = try accepted.receiveStream();
            defer client_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                client_bidi.direction,
            );
            try std.testing.expect(!client_bidi.locally_initiated);
            try std.testing.expectEqualStrings(
                "client-bidi",
                client_bidi.payload,
            );
            try accepted.sendStream(
                client_bidi.stream_id,
                "server-bidi",
                true,
            );

            var client_uni = try accepted.receiveStream();
            defer client_uni.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.unidirectional,
                client_uni.direction,
            );
            try std.testing.expectEqualStrings(
                "client-uni",
                client_uni.payload,
            );

            var large_bidi = try accepted.receiveStream();
            defer large_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                large_bidi.direction,
            );
            try std.testing.expectEqualSlices(
                u8,
                shared.large_stream_payload,
                large_bidi.payload,
            );

            const server_uni_id =
                try accepted.openUnidirectionalStream();
            try accepted.sendStream(
                server_uni_id,
                "server-uni",
                true,
            );

            var datagram = try accepted.receiveDatagram();
            defer datagram.deinit(accepted.h3.established.connection.endpoint.allocator);
            try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
            try std.testing.expectEqualStrings("handshake-client-dgram", datagram.datagram.payload);
            try accepted.sendDatagram("handshake-server-dgram");
            const stats = accepted.getStats();
            try std.testing.expectEqual(@as(u64, 1), stats.datagrams_received);
            try std.testing.expectEqual(@as(u64, 1), stats.datagrams_sent);
            try std.testing.expect(stats.packets_received > 0);
            try std.testing.expect(stats.packets_sent > 0);
        }
    };

    var shared = Shared{
        .server = &server,
        .large_stream_payload = large_stream_payload,
    };
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

    const client_bidi_id = try client.openBidirectionalStream();
    try client.sendStream(client_bidi_id, "client-bidi", true);
    const client_uni_id = try client.openUnidirectionalStream();
    try client.sendStream(client_uni_id, "client-uni", true);
    const large_bidi_id = try client.openBidirectionalStream();
    try client.sendStream(large_bidi_id, large_stream_payload, true);

    var server_bidi = try client.receiveStream();
    defer server_bidi.deinit();
    try std.testing.expectEqual(client_bidi_id, server_bidi.stream_id);
    try std.testing.expect(server_bidi.locally_initiated);
    try std.testing.expectEqualStrings("server-bidi", server_bidi.payload);

    var server_uni = try client.receiveStream();
    defer server_uni.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.unidirectional,
        server_uni.direction,
    );
    try std.testing.expect(!server_uni.locally_initiated);
    try std.testing.expectEqualStrings("server-uni", server_uni.payload);

    try client.sendDatagram("handshake-client-dgram");
    var response = try client.receiveDatagram();
    defer response.deinit(allocator);
    try std.testing.expectEqual(client.session_id.value, response.datagram.session_id.value);
    try std.testing.expectEqualStrings("handshake-server-dgram", response.datagram.payload);
    const stats = client.stats();
    try std.testing.expectEqual(@as(u64, 1), stats.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 1), stats.datagrams_received);
    try std.testing.expect(stats.packets_sent > 0);
    try std.testing.expect(stats.packets_received > 0);

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

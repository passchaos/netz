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

pub const AcceptedSession = struct {
    request: http3.runtime.OwnedRequest,
    session_id: webtransport.SessionId,

    pub fn deinit(self: *AcceptedSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.* = undefined;
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

pub const ConnectOptions = struct {
    authority: []const u8,
    path: []const u8 = "/",
    origin: []const u8 = "/",
    limits: Limits = .{},
};

pub const OwnedDatagram = struct {
    quic_datagram: quic.runtime.OwnedDatagram,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *OwnedDatagram, allocator: std.mem.Allocator) void {
        self.quic_datagram.deinit(allocator);
        self.* = undefined;
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

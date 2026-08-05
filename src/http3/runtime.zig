const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;

pub const Error = http3.Error || quic.runtime.Error || error{
    MissingStreamFrame,
    UnexpectedStream,
};

pub const Limits = struct {
    quic: quic.runtime.Limits = .{},
};

pub const Server = struct {
    quic_server: quic.runtime.Server,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .quic_server = try .bind(allocator, io, bind_address, limits.quic) };
    }

    pub fn deinit(self: *Server) void {
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *Server) Error!OwnedRequest {
        var datagram = try self.quic_server.receive();
        errdefer datagram.deinit(self.quic_server.endpoint.allocator);
        const stream = findStreamFrame(datagram.frames) orelse return error.MissingStreamFrame;
        var request = try http3.decodeRequest(self.quic_server.endpoint.allocator, stream.data);
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        return .{
            .from = datagram.from,
            .stream_id = @intCast(stream.stream_id),
            .datagram = datagram,
            .request = request,
        };
    }

    pub fn sendResponse(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        try response.write(&encoded, self.quic_server.endpoint.allocator);
        const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = stream_id, .data = encoded.items, .fin = true } }};
        try self.quic_server.sendFrames(to, &frames);
    }
};

pub const Client = struct {
    quic_client: quic.runtime.Client,
    next_stream_id: u62 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits) Error!Client {
        return .{ .quic_client = try .connect(allocator, io, local_address, server, limits.quic) };
    }

    pub fn deinit(self: *Client) void {
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.quic_client.address();
    }

    pub fn request(self: *Client, request_options: http3.Request) Error!OwnedResponse {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // client-initiated bidirectional stream ids.

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.write(&encoded, self.quic_client.endpoint.allocator);

        const frames = [_]quic.Frame{.{ .stream = .{ .stream_id = stream_id, .data = encoded.items, .fin = true } }};
        try self.quic_client.sendFrames(&frames);

        while (true) {
            var datagram = try self.quic_client.receive();
            errdefer datagram.deinit(self.quic_client.endpoint.allocator);
            const stream = findStreamFrame(datagram.frames) orelse {
                datagram.deinit(self.quic_client.endpoint.allocator);
                continue;
            };
            if (stream.stream_id != stream_id) return error.UnexpectedStream;
            var response = try http3.decodeResponse(self.quic_client.endpoint.allocator, stream.data);
            errdefer response.deinit(self.quic_client.endpoint.allocator);
            return .{ .datagram = datagram, .response = response };
        }
    }
};

pub const OwnedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    datagram: quic.runtime.OwnedDatagram,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const OwnedResponse = struct {
    datagram: quic.runtime.OwnedDatagram,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

fn findStreamFrame(frames: []const quic.Frame) ?quic.StreamFrame {
    for (frames) |frame| {
        if (frame == .stream) return frame.stream;
    }
    return null;
}

test "HTTP/3 runtime exchanges request and response over QUIC UDP frame endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
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
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3", request.request.path);
            try std.testing.expectEqualStrings("ping", request.request.body);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3",
        .authority = "localhost",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
}

const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;

pub const Error = http3.Error || quic.runtime.Error || quic.one_rtt.Error || quic.stream_state.Error || error{
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

pub const ProtectedConfig = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_stream_frame_data: usize = 1200,
};

pub const ProtectedServer = struct {
    quic_server: quic.runtime.Server,
    config: ProtectedConfig,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedServer {
        return .{ .quic_server = try .bind(allocator, io, bind_address, limits.quic), .config = config };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: ProtectedServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *ProtectedServer) Error!OwnedProtectedRequest {
        const assembled = try self.receiveStreamBytes(null);
        errdefer self.quic_server.endpoint.allocator.free(assembled.bytes);
        var request = try http3.decodeRequest(self.quic_server.endpoint.allocator, assembled.bytes);
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    pub fn sendResponse(self: *ProtectedServer, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        try response.write(&encoded, self.quic_server.endpoint.allocator);
        var send_state = quic.stream_state.SendState.init(stream_id);
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_server.endpoint.allocator);
        try send_state.appendFrames(&frames, self.quic_server.endpoint.allocator, encoded.items, self.config.max_stream_frame_data, true);
        try quic.one_rtt.sendFrames(&self.quic_server.endpoint, to, self.config.send_keys, .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = self.next_packet_number,
            .frames = frames.items,
        });
        self.next_packet_number += 1;
    }

    fn receiveStreamBytes(self: *ProtectedServer, expected_stream_id: ?u62) Error!AssembledStream {
        var recv: ?quic.stream_state.RecvState = null;
        defer if (recv) |*state| state.deinit();
        var from: ?net.IpAddress = null;
        var stream_id: ?u62 = expected_stream_id;

        while (true) {
            var packet = try quic.one_rtt.receive(
                &self.quic_server.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                self.expected_packet_number,
                self.config.max_frames_per_packet,
            );
            defer packet.deinit(self.quic_server.endpoint.allocator);
            self.expected_packet_number = packet.packet.packet_number + 1;
            if (from == null) from = packet.from;

            for (packet.frames) |frame| {
                if (frame != .stream) continue;
                const incoming_id: u62 = @intCast(frame.stream.stream_id);
                if (stream_id) |id| {
                    if (incoming_id != id) continue;
                } else {
                    stream_id = incoming_id;
                    recv = quic.stream_state.RecvState.init(self.quic_server.endpoint.allocator, incoming_id, self.config.max_stream_buffer);
                }
                if (recv == null) recv = quic.stream_state.RecvState.init(self.quic_server.endpoint.allocator, incoming_id, self.config.max_stream_buffer);
                if (recv) |*state| {
                    try state.insert(frame.stream);
                    if (state.final_size != null and state.contiguous_end >= state.final_size.?) {
                        const bytes = try self.quic_server.endpoint.allocator.dupe(u8, state.buffer.items[0..state.final_size.?]);
                        return .{ .from = from.?, .stream_id = stream_id.?, .bytes = bytes };
                    }
                }
            }
        }
    }
};

pub const ProtectedClient = struct {
    quic_client: quic.runtime.Client,
    config: ProtectedConfig,
    next_stream_id: u62 = 0,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedClient {
        return .{ .quic_client = try .connect(allocator, io, local_address, server, limits.quic), .config = config };
    }

    pub fn deinit(self: *ProtectedClient) void {
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn request(self: *ProtectedClient, request_options: http3.Request) Error!OwnedProtectedResponse {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4;

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.write(&encoded, self.quic_client.endpoint.allocator);
        var send_state = quic.stream_state.SendState.init(stream_id);
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_client.endpoint.allocator);
        try send_state.appendFrames(&frames, self.quic_client.endpoint.allocator, encoded.items, self.config.max_stream_frame_data, true);
        try quic.one_rtt.sendFrames(&self.quic_client.endpoint, self.quic_client.peer, self.config.send_keys, .{
            .destination_connection_id = self.config.peer_connection_id,
            .packet_number = self.next_packet_number,
            .frames = frames.items,
        });
        self.next_packet_number += 1;

        const assembled = try self.receiveStreamBytes(stream_id);
        errdefer self.quic_client.endpoint.allocator.free(assembled.bytes);
        var response = try http3.decodeResponse(self.quic_client.endpoint.allocator, assembled.bytes);
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    fn receiveStreamBytes(self: *ProtectedClient, expected_stream_id: u62) Error!AssembledStream {
        var recv = quic.stream_state.RecvState.init(self.quic_client.endpoint.allocator, expected_stream_id, self.config.max_stream_buffer);
        defer recv.deinit();
        var from: ?net.IpAddress = null;
        while (true) {
            var packet = try quic.one_rtt.receive(
                &self.quic_client.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                self.expected_packet_number,
                self.config.max_frames_per_packet,
            );
            defer packet.deinit(self.quic_client.endpoint.allocator);
            self.expected_packet_number = packet.packet.packet_number + 1;
            if (from == null) from = packet.from;
            for (packet.frames) |frame| {
                if (frame != .stream or frame.stream.stream_id != expected_stream_id) continue;
                try recv.insert(frame.stream);
                if (recv.final_size != null and recv.contiguous_end >= recv.final_size.?) {
                    const bytes = try self.quic_client.endpoint.allocator.dupe(u8, recv.buffer.items[0..recv.final_size.?]);
                    return .{ .from = from.?, .stream_id = expected_stream_id, .bytes = bytes };
                }
            }
        }
    }
};

pub const OwnedProtectedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedProtectedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedProtectedResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedProtectedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

const AssembledStream = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
};

fn findStreamFrame(frames: []const quic.Frame) ?quic.StreamFrame {
    for (frames) |frame| {
        if (frame == .stream) return frame.stream;
    }
    return null;
}

test "HTTP/3 protected runtime exchanges request and response over QUIC 1-RTT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .max_stream_frame_data = 7,
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
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/protected-h3", request.request.path);
            try std.testing.expectEqualStrings("ping split across stream frames", request.request.body);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/protected-h3",
        .authority = "localhost",
        .body = "ping split across stream frames",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
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

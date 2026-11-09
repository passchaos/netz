//! WebSocket transport adapter for DERP frames.
//!
//! `netz` owns RFC 6455 framing, HTTP Upgrade, and TLS. This adapter only
//! bridges DERP frames to binary WebSocket messages.

const std = @import("std");
const netz_runtime = @import("../../runtime.zig");
const websocket_runtime = @import("../../websocket/runtime.zig");
const frame_mod = @import("frame.zig");
const client_mod = @import("client.zig");
const relay_mod = @import("relay.zig");
const types = @import("../types.zig");

pub const IpAddress = std.Io.net.IpAddress;
pub const Backend = netz_runtime.Backend;
pub const runtime = websocket_runtime;
pub const Limits = runtime.Limits;

pub const Error = frame_mod.Error || error{
    ExpectedBinaryFrame,
};

pub const OwnedFrame = struct {
    frame: frame_mod.Frame,
    packet: ?[]u8 = null,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedFrame) void {
        if (self.packet) |packet| self.allocator.free(packet);
        self.* = undefined;
    }
};

pub const Link = struct {
    connection: runtime.Connection,
    allocator: std.mem.Allocator,

    pub fn send(
        self: *Link,
        frame: frame_mod.Frame,
        max_payload_bytes: usize,
    ) !void {
        const encoded = try frame.encode(self.allocator, max_payload_bytes);
        defer self.allocator.free(encoded);
        try self.connection.sendBinary(encoded);
    }

    pub fn receive(self: *Link, max_payload_bytes: usize) !OwnedFrame {
        var message = try self.connection.receiveMessage();
        defer message.deinit(self.allocator);
        if (message.opcode != .binary) return error.ExpectedBinaryFrame;
        const decoded = try frame_mod.decode(message.payload, max_payload_bytes);

        var owned = OwnedFrame{
            .frame = decoded.frame,
            .allocator = self.allocator,
        };
        switch (decoded.frame) {
            .send_packet => |value| {
                const packet = try self.allocator.dupe(u8, value.packet);
                owned.packet = packet;
                owned.frame = .{ .send_packet = .{
                    .destination = value.destination,
                    .packet = packet,
                } };
            },
            .recv_packet => |value| {
                const packet = try self.allocator.dupe(u8, value.packet);
                owned.packet = packet;
                owned.frame = .{ .recv_packet = .{
                    .source = value.source,
                    .packet = packet,
                } };
            },
            else => {},
        }
        return owned;
    }

    pub fn close(self: *Link) void {
        self.connection.close();
    }
};

pub const Server = struct {
    server: runtime.Server,
    allocator: std.mem.Allocator,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: IpAddress,
        limits: Limits,
    ) !Server {
        return .{
            .server = try runtime.Server.listen(allocator, io, bind_address, limits),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Server) void {
        self.server.deinit();
    }

    pub fn address(self: *const Server) IpAddress {
        return self.server.address();
    }

    pub fn accept(self: *Server, options: runtime.AcceptOptions) !Link {
        return .{
            .connection = try self.server.accept(options),
            .allocator = self.allocator,
        };
    }
};

pub fn connect(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: []const u8,
    options: runtime.ConnectOptions,
) !Link {
    return .{
        .connection = try runtime.Client.connectUri(allocator, io, uri, options),
        .allocator = allocator,
    };
}

test "netz websocket transport surface is reachable" {
    try std.testing.expect(@hasDecl(runtime, "Server"));
    try std.testing.expect(@hasDecl(runtime, "Client"));
    try std.testing.expect(@hasDecl(runtime, "Connection"));
    try std.testing.expect(@hasDecl(runtime, "AcceptOptions"));
    try std.testing.expect(@hasDecl(runtime, "ConnectOptions"));
}

pub const ClientLink = struct {
    link: Link,
    client: client_mod.Client,
    max_payload: usize,

    pub fn connectTo(
        allocator: std.mem.Allocator,
        io: std.Io,
        uri: []const u8,
        client_key: types.NodeKey,
        expected_server_key: ?types.NodeKey,
        limits: Limits,
    ) !ClientLink {
        var link = try connect(allocator, io, uri, .{ .limits = limits });
        errdefer link.close();

        var client = client_mod.Client.init(client_key);
        client.expected_server_key = expected_server_key;
        try client.beginConnect();

        var server_frame = try link.receive(frame_mod.default_max_payload_bytes);
        defer server_frame.deinit();
        const key = switch (server_frame.frame) {
            .server_key => |value| value.key,
            else => return error.ExpectedServerKey,
        };
        try client.onServerKey(key);
        try link.send(.{ .client_info = .{
            .client_key = client_key,
        } }, frame_mod.default_max_payload_bytes);

        return .{
            .link = link,
            .client = client,
            .max_payload = frame_mod.default_max_payload_bytes,
        };
    }

    pub fn sendPing(self: *ClientLink, nonce: [16]u8) !void {
        try self.link.send(.{ .ping = .{ .nonce = nonce } }, self.max_payload);
    }

    pub fn sendPacket(
        self: *ClientLink,
        destination: types.NodeKey,
        packet: []const u8,
    ) !void {
        if (self.client.state != .connected) return error.NotConnected;
        if (packet.len > frame_mod.max_packet_bytes) return error.PacketTooLarge;
        try self.link.send(.{ .send_packet = .{
            .destination = destination,
            .packet = packet,
        } }, self.max_payload);
    }

    pub fn receivePacket(self: *ClientLink) !OwnedFrame {
        while (true) {
            var owned = try self.link.receive(self.max_payload);
            const action = self.client.handleFrame(owned.frame) catch |err| {
                owned.deinit();
                return err;
            };
            switch (action) {
                .deliver => return owned,
                .pong => |frame| {
                    try self.link.send(frame, self.max_payload);
                    owned.deinit();
                },
                .restart => {
                    owned.deinit();
                    return error.RelayRestarting;
                },
                .none, .peer_gone, .peer_present => owned.deinit(),
            }
        }
    }

    pub fn close(self: *ClientLink) void {
        self.link.close();
    }
};

pub const RelayServer = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    server: Server,
    relay: relay_mod.Relay,
    links: std.AutoHashMap(types.NodeKey, *Link),
    mutex: std.Io.Mutex = .init,
    error_value: ?anyerror = null,
    max_payload: usize,
    group: std.Io.Group = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: IpAddress,
        limits: Limits,
        server_key: types.NodeKey,
        max_peers: usize,
    ) !RelayServer {
        return .{
            .allocator = allocator,
            .io = io,
            .server = try Server.listen(allocator, io, bind_address, limits),
            .relay = relay_mod.Relay.init(allocator, server_key, max_peers),
            .links = std.AutoHashMap(types.NodeKey, *Link).init(allocator),
            .max_payload = frame_mod.default_max_payload_bytes,
        };
    }

    pub fn deinit(self: *RelayServer) void {
        self.group.cancel(self.io);
        self.server.deinit();
        self.relay.deinit();
        self.links.deinit();
        self.* = undefined;
    }

    pub fn address(self: *const RelayServer) IpAddress {
        return self.server.address();
    }

    pub fn authorize(self: *RelayServer, key: types.NodeKey) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        try self.relay.authorize(key);
    }

    /// Accept `count` connections, run them concurrently, and wait for all of
    /// them to finish. This is a bounded relay session suitable for tests and
    /// small deployments; a long-running daemon can call it repeatedly.
    pub fn serveConnections(self: *RelayServer, count: usize) !void {
        var accepted: usize = 0;
        while (accepted < count) : (accepted += 1) {
            const link = try self.server.accept(.{});
            const context = try self.allocator.create(ConnectionContext);
            context.* = .{ .server = self, .link = link };
            self.group.async(self.io, ConnectionContext.run, .{context});
        }
        try self.group.await(self.io);
        if (self.error_value) |err| return err;
    }

    fn recordError(self: *RelayServer, err: anyerror) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.error_value == null) self.error_value = err;
    }

    const ConnectionContext = struct {
        server: *RelayServer,
        link: Link,
        client_key: types.NodeKey = [_]u8{0} ** types.node_key_len,
        attached: bool = false,

        fn run(context: *ConnectionContext) std.Io.Cancelable!void {
            context.runFallible() catch |err| {
                if (!context.attached) context.server.recordError(err);
            };
        }

        fn runFallible(context: *ConnectionContext) !void {
            const self = context.server;
            defer {
                self.mutex.lockUncancelable(self.io);
                if (self.links.get(context.client_key)) |link| {
                    if (link == &context.link) _ = self.links.remove(context.client_key);
                }
                _ = self.relay.detach(context.client_key);
                self.mutex.unlock(self.io);
                context.link.close();
                self.allocator.destroy(context);
            }

            try context.link.send(.{ .server_key = .{
                .key = self.relay.server_key,
            } }, self.max_payload);

            var info_frame = try context.link.receive(self.max_payload);
            defer info_frame.deinit();
            const info = switch (info_frame.frame) {
                .client_info => |value| value,
                else => return error.ExpectedClientInfo,
            };
            context.client_key = info.client_key;

            self.mutex.lockUncancelable(self.io);
            _ = self.relay.attach(context.client_key) catch |err| {
                self.mutex.unlock(self.io);
                return err;
            };
            self.links.put(context.client_key, &context.link) catch |err| {
                _ = self.relay.detach(context.client_key);
                self.mutex.unlock(self.io);
                return err;
            };
            self.mutex.unlock(self.io);
            context.attached = true;

            while (true) {
                var owned = try context.link.receive(self.max_payload);
                defer owned.deinit();
                const action = try self.relay.handleFrame(context.client_key, owned.frame);
                switch (action) {
                    .none => {},
                    .reply => |frame| try context.link.send(frame, self.max_payload),
                    .forward => |forward| {
                        self.mutex.lockUncancelable(self.io);
                        defer self.mutex.unlock(self.io);
                        if (self.links.get(forward.to)) |destination| {
                            destination.send(forward.frame, self.max_payload) catch {};
                        }
                    },
                    .peer_present, .peer_gone => {},
                }
            }
        }
    };
};

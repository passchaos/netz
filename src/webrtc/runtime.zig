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
        var value: std.ArrayList(u8) = .empty;
        defer value.deinit(self.endpoint.allocator);
        const family, const addr_bytes, const port = ipAddressParts(request.from) orelse return error.UnsupportedAddressFamily;
        try stun.writeXorMappedAddress(&value, self.endpoint.allocator, family, port, addr_bytes, request.message.transaction_id);
        const attrs = [_]stun.Attribute{.{ .attr_type = .xor_mapped_address, .value = value.items }};
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.endpoint.allocator);
        try stun.write(&encoded, self.endpoint.allocator, .success_response, .binding, request.message.transaction_id, &attrs);
        try self.endpoint.sendBytes(request.from, encoded.items);
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

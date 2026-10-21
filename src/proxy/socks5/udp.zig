//! RFC 1928 SOCKS5 UDP datagram framing and association data plane.
//!
//! SOCKS5 fragmentation is deliberately unsupported: RFC 1928 permits a
//! client to drop fragmented datagrams, and silently accepting only one piece
//! would corrupt the application payload. Callers provide framing storage so
//! steady-state forwarding does not allocate.

const std = @import("std");

const net = std.Io.net;

pub const max_header_len: usize = 3 + 1 + 1 + 255 + 2;

pub const AddressError = net.HostName.ValidateError || error{
    InvalidTargetPort,
    ProxyAddressTypeUnsupported,
};

pub const CodecError = AddressError || error{
    BufferTooSmall,
    FragmentationUnsupported,
    MalformedDatagram,
};

pub const Error = CodecError || net.Socket.SendError ||
    net.Socket.ReceiveTimeoutError || error{
    DatagramTruncated,
    UnexpectedRelaySource,
};

pub const Address = union(enum) {
    ip: net.IpAddress,
    domain: struct {
        host: []const u8,
        port: u16,
    },

    pub fn fromHost(host: []const u8, target_port: u16) AddressError!Address {
        if (target_port == 0) return error.InvalidTargetPort;
        return if (net.IpAddress.parse(host, target_port)) |ip|
            .{ .ip = ip }
        else |_|
            .{ .domain = .{
                .host = (try net.HostName.init(host)).bytes,
                .port = target_port,
            } };
    }

    pub fn getPort(self: Address) u16 {
        return switch (self) {
            .ip => |ip| ip.getPort(),
            .domain => |domain| domain.port,
        };
    }
};

pub const OwnedAddress = union(enum) {
    ip: net.IpAddress,
    domain: struct {
        bytes: [255]u8,
        len: u8,
        port: u16,

        pub fn host(self: *const @This()) []const u8 {
            return self.bytes[0..self.len];
        }
    },
};

pub const Datagram = struct {
    source: Address,
    payload: []u8,
};

pub fn headerLen(address: Address) CodecError!usize {
    return switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => 3 + 1 + 4 + 2,
            .ip6 => 3 + 1 + 16 + 2,
        },
        .domain => |domain| blk: {
            _ = try net.HostName.init(domain.host);
            if (domain.host.len > 255) {
                return error.ProxyAddressTypeUnsupported;
            }
            break :blk 3 + 1 + 1 + domain.host.len + 2;
        },
    };
}

/// Encode one complete SOCKS5 UDP request into caller-owned storage.
pub fn encodeDatagram(
    output: []u8,
    destination: Address,
    payload: []const u8,
) CodecError![]const u8 {
    if (output.len < 4) return error.BufferTooSmall;
    output[0..3].* = .{ 0, 0, 0 };
    const payload_offset = try encodeAddress(output, 3, destination);
    const total_len = std.math.add(usize, payload_offset, payload.len) catch
        return error.BufferTooSmall;
    if (output.len < total_len) return error.BufferTooSmall;
    @memcpy(output[payload_offset..total_len], payload);
    return output[0..total_len];
}

/// Decode one complete SOCKS5 UDP response in place. The returned hostname and
/// payload borrow `bytes` and remain valid until the caller reuses that buffer.
pub fn decodeDatagram(bytes: []u8) CodecError!Datagram {
    if (bytes.len < 4 or bytes[0] != 0 or bytes[1] != 0) {
        return error.MalformedDatagram;
    }
    if (bytes[2] != 0) return error.FragmentationUnsupported;
    const decoded = try decodeAddress(bytes, 3);
    return .{
        .source = decoded.address,
        .payload = bytes[decoded.end..],
    };
}

/// Owns both halves of an RFC 1928 UDP association. Keeping `control` open is
/// required by the protocol; closing it terminates the association.
pub fn Association(comptime Control: type) type {
    return struct {
        const Self = @This();

        io: std.Io,
        control: Control,
        socket: net.Socket,
        relay: net.IpAddress,

        pub fn init(
            io: std.Io,
            control: Control,
            socket: net.Socket,
            relay: net.IpAddress,
        ) Self {
            return .{
                .io = io,
                .control = control,
                .socket = socket,
                .relay = relay,
            };
        }

        pub fn address(self: *const Self) net.IpAddress {
            return self.socket.address;
        }

        pub fn relayAddress(self: *const Self) net.IpAddress {
            return self.relay;
        }

        pub fn sendTo(
            self: *const Self,
            destination: Address,
            payload: []const u8,
            framing_storage: []u8,
        ) Error!void {
            const encoded = try encodeDatagram(
                framing_storage,
                destination,
                payload,
            );
            try self.socket.send(self.io, &self.relay, encoded);
        }

        pub fn receiveInto(self: *const Self, storage: []u8) Error!Datagram {
            return self.finishReceive(try self.socket.receive(self.io, storage));
        }

        pub fn receiveIntoTimeout(
            self: *const Self,
            storage: []u8,
            timeout: std.Io.Timeout,
        ) Error!Datagram {
            return self.finishReceive(try self.socket.receiveTimeout(
                self.io,
                storage,
                timeout,
            ));
        }

        fn finishReceive(
            self: *const Self,
            message: net.IncomingMessage,
        ) Error!Datagram {
            if (!message.from.eql(&self.relay)) {
                return error.UnexpectedRelaySource;
            }
            if (message.flags.trunc) return error.DatagramTruncated;
            return decodeDatagram(message.data);
        }

        pub fn deinit(self: *Self) void {
            self.socket.close(self.io);
            self.control.deinit();
            self.* = undefined;
        }
    };
}

fn encodeAddress(
    output: []u8,
    initial_offset: usize,
    address: Address,
) CodecError!usize {
    var offset = initial_offset;
    if (output.len -| offset < 1) return error.BufferTooSmall;
    switch (address) {
        .ip => |ip| switch (ip) {
            .ip4 => |value| {
                if (output.len - offset < 1 + value.bytes.len + 2) {
                    return error.BufferTooSmall;
                }
                output[offset] = 0x01;
                offset += 1;
                @memcpy(output[offset..][0..value.bytes.len], &value.bytes);
                offset += value.bytes.len;
            },
            .ip6 => |value| {
                if (output.len - offset < 1 + value.bytes.len + 2) {
                    return error.BufferTooSmall;
                }
                output[offset] = 0x04;
                offset += 1;
                @memcpy(output[offset..][0..value.bytes.len], &value.bytes);
                offset += value.bytes.len;
            },
        },
        .domain => |domain| {
            _ = try net.HostName.init(domain.host);
            if (domain.host.len > 255) {
                return error.ProxyAddressTypeUnsupported;
            }
            if (output.len - offset < 2 + domain.host.len + 2) {
                return error.BufferTooSmall;
            }
            output[offset] = 0x03;
            output[offset + 1] = @intCast(domain.host.len);
            offset += 2;
            @memcpy(output[offset..][0..domain.host.len], domain.host);
            offset += domain.host.len;
        },
    }
    std.mem.writeInt(u16, output[offset..][0..2], address.getPort(), .big);
    return offset + 2;
}

fn decodeAddress(
    bytes: []u8,
    initial_offset: usize,
) CodecError!struct { address: Address, end: usize } {
    if (bytes.len -| initial_offset < 1) return error.MalformedDatagram;
    var offset = initial_offset + 1;
    const address: Address = switch (bytes[initial_offset]) {
        0x01 => blk: {
            if (bytes.len - offset < 4 + 2) return error.MalformedDatagram;
            const ip = net.IpAddress{ .ip4 = .{
                .bytes = bytes[offset..][0..4].*,
                .port = std.mem.readInt(u16, bytes[offset + 4 ..][0..2], .big),
            } };
            offset += 4 + 2;
            break :blk .{ .ip = ip };
        },
        0x04 => blk: {
            if (bytes.len - offset < 16 + 2) return error.MalformedDatagram;
            const ip = net.IpAddress{ .ip6 = .{
                .bytes = bytes[offset..][0..16].*,
                .port = std.mem.readInt(u16, bytes[offset + 16 ..][0..2], .big),
            } };
            offset += 16 + 2;
            break :blk .{ .ip = ip };
        },
        0x03 => blk: {
            if (bytes.len - offset < 1) return error.MalformedDatagram;
            const host_len: usize = bytes[offset];
            offset += 1;
            if (host_len == 0 or bytes.len - offset < host_len + 2) {
                return error.MalformedDatagram;
            }
            const host = bytes[offset..][0..host_len];
            _ = net.HostName.init(host) catch return error.MalformedDatagram;
            const port = std.mem.readInt(
                u16,
                bytes[offset + host_len ..][0..2],
                .big,
            );
            offset += host_len + 2;
            break :blk .{ .domain = .{ .host = host, .port = port } };
        },
        else => return error.MalformedDatagram,
    };
    return .{ .address = address, .end = offset };
}

test "SOCKS5 UDP datagrams preserve IPv4 IPv6 and domain targets" {
    const cases = [_]Address{
        .{ .ip = try net.IpAddress.parse("192.0.2.1", 443) },
        .{ .ip = try net.IpAddress.parse("2001:db8::1", 8443) },
        try .fromHost("origin.example", 53),
    };
    for (cases) |destination| {
        var storage: [128]u8 = undefined;
        const encoded = try encodeDatagram(&storage, destination, "payload");
        const decoded = try decodeDatagram(@constCast(encoded));
        try std.testing.expectEqualStrings("payload", decoded.payload);
        try std.testing.expectEqual(destination.getPort(), decoded.source.getPort());
        switch (destination) {
            .ip => |expected| try std.testing.expect(decoded.source.ip.eql(&expected)),
            .domain => |expected| try std.testing.expectEqualStrings(
                expected.host,
                decoded.source.domain.host,
            ),
        }
    }
}

test "SOCKS5 UDP rejects fragments malformed packets and short storage" {
    var fragmented = [_]u8{ 0, 0, 1, 1, 127, 0, 0, 1, 0, 53 };
    try std.testing.expectError(
        error.FragmentationUnsupported,
        decodeDatagram(&fragmented),
    );
    var reserved = [_]u8{ 0, 1, 0, 1, 127, 0, 0, 1, 0, 53 };
    try std.testing.expectError(error.MalformedDatagram, decodeDatagram(&reserved));
    var truncated = [_]u8{ 0, 0, 0, 4, 0 };
    try std.testing.expectError(error.MalformedDatagram, decodeDatagram(&truncated));

    var short: [9]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        encodeDatagram(
            &short,
            .{ .ip = try net.IpAddress.parse("127.0.0.1", 53) },
            "x",
        ),
    );
}

test "SOCKS5 UDP reserves the complete 255-byte domain header" {
    var host: [255]u8 = @splat('a');
    host[63] = '.';
    host[127] = '.';
    host[191] = '.';
    const destination = Address{ .domain = .{
        .host = &host,
        .port = 443,
    } };
    try std.testing.expectEqual(max_header_len, try headerLen(destination));
    var storage: [max_header_len + 1]u8 = undefined;
    const encoded = try encodeDatagram(&storage, destination, "x");
    try std.testing.expectEqual(storage.len, encoded.len);
    const decoded = try decodeDatagram(@constCast(encoded));
    try std.testing.expectEqualStrings(&host, decoded.source.domain.host);
    try std.testing.expectEqualStrings("x", decoded.payload);
}

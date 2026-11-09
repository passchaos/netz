//! Shared identity, endpoint, and capability types.
//!
//! The mesh protocol layer never implements cryptographic primitives itself.
//! Node IDs are derived from a public key with Vail's SHA-256 implementation,
//! and control-plane signatures are verified with Vail's Ed25519 verifier.

const std = @import("std");
const vail = @import("vail");
const wire = @import("wire.zig");

pub const node_key_len = 32;
pub const NodeKey = [node_key_len]u8;
pub const NodeId = [node_key_len]u8;

pub const max_hostname_len = 253;
pub const max_tag_len = 63;
pub const max_endpoints = 16;
pub const max_endpoint_ports = 8;

pub fn nodeIdFromKey(key: NodeKey) NodeId {
    return vail.crypto.sha256.hash(&key);
}

pub const IpFamily = enum(u8) {
    v4 = 1,
    v6 = 2,
    _,

    pub fn isKnown(self: IpFamily) bool {
        return self == .v4 or self == .v6;
    }
};

/// A compact, wire-stable endpoint representation.
///
/// IPv4 addresses live in the first four bytes of `addr`; the remaining bytes
/// are zero. Keeping the representation explicit avoids depending on host
/// struct layout in a protocol that must round-trip across machines.
pub const Endpoint = struct {
    family: IpFamily = .v4,
    addr: [16]u8 = [_]u8{0} ** 16,
    port: u16 = 0,

    pub fn fromV4(addr: [4]u8, port: u16) Endpoint {
        var out = Endpoint{
            .family = .v4,
            .port = port,
        };
        out.addr[0..4].* = addr;
        return out;
    }

    pub fn fromV6(addr: [16]u8, port: u16) Endpoint {
        return .{ .family = .v6, .addr = addr, .port = port };
    }

    pub fn isValid(self: Endpoint) bool {
        if (!self.family.isKnown()) return false;
        if (self.port == 0) return false;
        return true;
    }

    pub fn eql(a: Endpoint, b: Endpoint) bool {
        return a.family == b.family and a.port == b.port and
            std.mem.eql(u8, &a.addr, &b.addr);
    }

    pub fn write(self: Endpoint, out: *wire.Writer) !void {
        if (!self.isValid()) return error.InvalidEndpoint;
        try out.writeU8(@intFromEnum(self.family));
        switch (self.family) {
            .v4 => try out.writeSlice(self.addr[0..4]),
            .v6 => try out.writeSlice(self.addr[0..16]),
            else => unreachable,
        }
        try out.writeU16(self.port);
    }

    pub fn read(input: *wire.Reader) !Endpoint {
        const family: IpFamily = @enumFromInt(try input.readU8());
        const addr: [16]u8 = switch (family) {
            .v4 => blk: {
                var value = [_]u8{0} ** 16;
                value[0..4].* = try input.readFixed(4);
                break :blk value;
            },
            .v6 => try input.readFixed(16),
            else => return error.InvalidEndpoint,
        };
        const port = try input.readU16();
        const endpoint = Endpoint{ .family = family, .addr = addr, .port = port };
        if (!endpoint.isValid()) return error.InvalidEndpoint;
        return endpoint;
    }
};

pub const Capabilities = packed struct(u32) {
    direct: bool = false,
    derp: bool = false,
    exit_node: bool = false,
    subnet_router: bool = false,
    magic_dns: bool = false,
    acl: bool = false,
    reserved: u26 = 0,

    pub fn fromInt(value: u32) Capabilities {
        return @bitCast(value);
    }

    pub fn toInt(self: Capabilities) u32 {
        return @bitCast(self);
    }
};

pub const NatType = enum(u8) {
    unknown = 0,
    open_internet = 1,
    full_cone = 2,
    restricted_cone = 3,
    port_restricted_cone = 4,
    symmetric = 5,
    blocked = 6,
    _,
};

pub const PathKind = enum(u8) {
    none = 0,
    direct = 1,
    derp = 2,
    _,
};

pub const NodeName = struct {
    bytes: [max_hostname_len]u8 = [_]u8{0} ** max_hostname_len,
    len: u8 = 0,

    pub fn init(name: []const u8) !NodeName {
        if (name.len > max_hostname_len) return error.NameTooLong;
        var out = NodeName{};
        out.bytes[0..name.len].* = name[0..name.len].*;
        out.len = @intCast(name.len);
        return out;
    }

    pub fn slice(self: *const NodeName) []const u8 {
        return self.bytes[0..self.len];
    }
};

test "node id derives from key deterministically" {
    const key = [_]u8{0x42} ** node_key_len;
    const first = nodeIdFromKey(key);
    const second = nodeIdFromKey(key);
    try std.testing.expectEqualSlices(u8, &first, &second);
    try std.testing.expectEqual(@as(usize, 32), first.len);
}

test "endpoint wire round trip" {
    var writer = wire.Writer.init(std.testing.allocator);
    defer writer.deinit();

    const v4 = Endpoint.fromV4(.{ 10, 0, 0, 7 }, 41641);
    const v6 = Endpoint.fromV6(.{ 0x20, 0x01, 0x0d, 0xb8 } ++ [_]u8{0} ** 12, 41641);
    try v4.write(&writer);
    try v6.write(&writer);

    var reader = wire.Reader.init(writer.slice());
    try std.testing.expect(Endpoint.eql(v4, try Endpoint.read(&reader)));
    try std.testing.expect(Endpoint.eql(v6, try Endpoint.read(&reader)));
    try reader.expectEnd();
}

test "endpoint rejects zero port and unknown family" {
    var writer = wire.Writer.init(std.testing.allocator);
    defer writer.deinit();
    try std.testing.expectError(
        error.InvalidEndpoint,
        Endpoint.fromV4(.{ 1, 2, 3, 4 }, 0).write(&writer),
    );

    var reader = wire.Reader.init(&.{ 9, 0x01, 0x02, 0x03, 0x04, 0x00, 0x01 });
    try std.testing.expectError(error.InvalidEndpoint, Endpoint.read(&reader));
}

test "capabilities are bit stable" {
    const caps = Capabilities{
        .direct = true,
        .derp = true,
        .exit_node = true,
    };
    try std.testing.expectEqual(@as(u32, 0b111), caps.toInt());
    try std.testing.expectEqual(caps, Capabilities.fromInt(0b111));
}

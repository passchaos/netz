//! RFC 9484 IP-configuration Capsule codecs.

const std = @import("std");
const wire = @import("../../internal/wire.zig");
const quic = @import("../../quic/mod.zig");
const capsule = @import("../capsule.zig");

pub const address_assign_type = capsule.CapsuleType.address_assign;
pub const address_request_type = capsule.CapsuleType.address_request;
pub const route_advertisement_type = capsule.CapsuleType.route_advertisement;

pub const Error = wire.Error || error{
    IntegerOverflow,
    InvalidFrame,
    InvalidHeader,
    InvalidCapsule,
};

pub const IpAddress = union(enum) {
    ipv4: [4]u8,
    ipv6: [16]u8,

    pub fn version(self: IpAddress) u8 {
        return switch (self) {
            .ipv4 => 4,
            .ipv6 => 6,
        };
    }

    pub fn maxPrefixLength(self: IpAddress) u8 {
        return switch (self) {
            .ipv4 => 32,
            .ipv6 => 128,
        };
    }

    pub fn bytes(self: *const IpAddress) []const u8 {
        return switch (self.*) {
            .ipv4 => |*address| address,
            .ipv6 => |*address| address,
        };
    }
};

pub const AddressPrefix = struct {
    request_id: u62,
    address: IpAddress,
    prefix_length: u8,

    pub fn validate(self: AddressPrefix) error{InvalidCapsule}!void {
        if (self.prefix_length > self.address.maxPrefixLength() or
            !hostBitsZero(self.address.bytes(), self.prefix_length))
        {
            return error.InvalidCapsule;
        }
    }
};

pub const AddressIterator = struct {
    cursor: wire.Cursor,
    request_ids_must_be_nonzero: bool,

    pub fn next(self: *AddressIterator) error{InvalidCapsule}!?AddressPrefix {
        if (self.cursor.eof()) return null;
        const request_id_value = quic.varint.decode(&self.cursor) catch
            return error.InvalidCapsule;
        const request_id: u62 = @intCast(request_id_value);
        if (self.request_ids_must_be_nonzero and request_id == 0) {
            return error.InvalidCapsule;
        }
        const version = self.cursor.readByte() catch
            return error.InvalidCapsule;
        const address = switch (version) {
            4 => IpAddress{ .ipv4 = (self.cursor.readSlice(4) catch
                return error.InvalidCapsule)[0..4].* },
            6 => IpAddress{ .ipv6 = (self.cursor.readSlice(16) catch
                return error.InvalidCapsule)[0..16].* },
            else => return error.InvalidCapsule,
        };
        const prefix_length = self.cursor.readByte() catch
            return error.InvalidCapsule;
        const result = AddressPrefix{
            .request_id = request_id,
            .address = address,
            .prefix_length = prefix_length,
        };
        try result.validate();
        return result;
    }
};

pub fn parseAddressAssign(value: []const u8) error{InvalidCapsule}!AddressIterator {
    return validatedAddressIterator(value, false, true);
}

pub fn parseAddressRequest(value: []const u8) error{InvalidCapsule}!AddressIterator {
    return validatedAddressIterator(value, true, false);
}

pub fn writeAddressAssignInto(
    out: []u8,
    addresses: []const AddressPrefix,
) Error![]u8 {
    return writeAddressListInto(out, address_assign_type, addresses, false);
}

pub fn writeAddressRequestInto(
    out: []u8,
    addresses: []const AddressPrefix,
) Error![]u8 {
    if (addresses.len == 0) return error.InvalidCapsule;
    return writeAddressListInto(out, address_request_type, addresses, true);
}

pub const Route = union(enum) {
    ipv4: struct {
        start: [4]u8,
        end: [4]u8,
        ip_protocol: u8 = 0,
    },
    ipv6: struct {
        start: [16]u8,
        end: [16]u8,
        ip_protocol: u8 = 0,
    },

    pub fn version(self: Route) u8 {
        return switch (self) {
            .ipv4 => 4,
            .ipv6 => 6,
        };
    }

    pub fn protocol(self: Route) u8 {
        return switch (self) {
            .ipv4 => |route| route.ip_protocol,
            .ipv6 => |route| route.ip_protocol,
        };
    }

    pub fn startBytes(self: *const Route) []const u8 {
        return switch (self.*) {
            .ipv4 => |*route| &route.start,
            .ipv6 => |*route| &route.start,
        };
    }

    pub fn endBytes(self: *const Route) []const u8 {
        return switch (self.*) {
            .ipv4 => |*route| &route.end,
            .ipv6 => |*route| &route.end,
        };
    }

    pub fn validate(self: Route) error{InvalidCapsule}!void {
        if (std.mem.order(u8, self.startBytes(), self.endBytes()) == .gt) {
            return error.InvalidCapsule;
        }
    }
};

pub const RouteIterator = struct {
    cursor: wire.Cursor,

    pub fn next(self: *RouteIterator) error{InvalidCapsule}!?Route {
        if (self.cursor.eof()) return null;
        const version = self.cursor.readByte() catch
            return error.InvalidCapsule;
        const route = switch (version) {
            4 => Route{ .ipv4 = .{
                .start = (self.cursor.readSlice(4) catch
                    return error.InvalidCapsule)[0..4].*,
                .end = (self.cursor.readSlice(4) catch
                    return error.InvalidCapsule)[0..4].*,
                .ip_protocol = self.cursor.readByte() catch
                    return error.InvalidCapsule,
            } },
            6 => Route{ .ipv6 = .{
                .start = (self.cursor.readSlice(16) catch
                    return error.InvalidCapsule)[0..16].*,
                .end = (self.cursor.readSlice(16) catch
                    return error.InvalidCapsule)[0..16].*,
                .ip_protocol = self.cursor.readByte() catch
                    return error.InvalidCapsule,
            } },
            else => return error.InvalidCapsule,
        };
        try route.validate();
        return route;
    }
};

pub fn parseRouteAdvertisement(
    value: []const u8,
) error{InvalidCapsule}!RouteIterator {
    const iterator = RouteIterator{ .cursor = .init(value) };
    var validation = iterator;
    var previous: ?Route = null;
    while (try validation.next()) |route| {
        if (previous) |prior| try validateRouteOrder(prior, route);
        previous = route;
    }
    return iterator;
}

pub fn writeRouteAdvertisementInto(
    out: []u8,
    routes: []const Route,
) Error![]u8 {
    var value_len: usize = 0;
    for (routes, 0..) |route, index| {
        try route.validate();
        if (index != 0) try validateRouteOrder(routes[index - 1], route);
        for (routes[0..index]) |previous| {
            if (previous.version() == route.version() and
                (previous.protocol() == 0 or route.protocol() == 0) and
                rangesOverlap(previous, route))
            {
                return error.InvalidCapsule;
            }
        }
        value_len = std.math.add(
            usize,
            value_len,
            2 * route.startBytes().len + 2,
        ) catch return error.IntegerOverflow;
    }
    const total_len = try capsuleEncodedLen(
        route_advertisement_type,
        value_len,
    );
    if (out.len < total_len) return error.BufferTooShort;
    var offset = try writeCapsuleHeader(
        out,
        route_advertisement_type,
        value_len,
    );
    for (routes) |route| {
        out[offset] = route.version();
        offset += 1;
        @memcpy(out[offset..][0..route.startBytes().len], route.startBytes());
        offset += route.startBytes().len;
        @memcpy(out[offset..][0..route.endBytes().len], route.endBytes());
        offset += route.endBytes().len;
        out[offset] = route.protocol();
        offset += 1;
    }
    std.debug.assert(offset == total_len);
    return out[0..offset];
}

fn validatedAddressIterator(
    value: []const u8,
    request_ids_must_be_nonzero: bool,
    empty_allowed: bool,
) error{InvalidCapsule}!AddressIterator {
    const iterator = AddressIterator{
        .cursor = .init(value),
        .request_ids_must_be_nonzero = request_ids_must_be_nonzero,
    };
    var validation = iterator;
    var count: usize = 0;
    while (try validation.next()) |_| count += 1;
    if (!empty_allowed and count == 0) return error.InvalidCapsule;
    return iterator;
}

fn writeAddressListInto(
    out: []u8,
    capsule_type: u64,
    addresses: []const AddressPrefix,
    request_ids_must_be_nonzero: bool,
) Error![]u8 {
    var value_len: usize = 0;
    for (addresses, 0..) |address, index| {
        try address.validate();
        if (request_ids_must_be_nonzero and address.request_id == 0) {
            return error.InvalidCapsule;
        }
        if (request_ids_must_be_nonzero) {
            for (addresses[0..index]) |previous| {
                if (previous.request_id == address.request_id) {
                    return error.InvalidCapsule;
                }
            }
        }
        value_len = std.math.add(
            usize,
            value_len,
            try quic.varint.length(address.request_id) +
                address.address.bytes().len + 2,
        ) catch return error.IntegerOverflow;
    }
    const total_len = try capsuleEncodedLen(capsule_type, value_len);
    if (out.len < total_len) return error.BufferTooShort;
    var offset = try writeCapsuleHeader(out, capsule_type, value_len);
    for (addresses) |address| {
        const request_id = try quic.varint.encodeInto(
            out[offset..],
            address.request_id,
        );
        offset += request_id.len;
        out[offset] = address.address.version();
        offset += 1;
        const bytes = address.address.bytes();
        @memcpy(out[offset..][0..bytes.len], bytes);
        offset += bytes.len;
        out[offset] = address.prefix_length;
        offset += 1;
    }
    std.debug.assert(offset == total_len);
    return out[0..offset];
}

fn writeCapsuleHeader(
    out: []u8,
    capsule_type: u64,
    value_len: usize,
) Error!usize {
    var offset: usize = 0;
    const encoded_type = try quic.varint.encodeInto(out, capsule_type);
    offset += encoded_type.len;
    const encoded_len = try quic.varint.encodeInto(
        out[offset..],
        std.math.cast(u64, value_len) orelse return error.IntegerOverflow,
    );
    offset += encoded_len.len;
    return offset;
}

fn capsuleEncodedLen(capsule_type: u64, value_len: usize) Error!usize {
    return capsule.encodedLen(capsule_type, value_len) catch |err| switch (err) {
        error.OutOfMemory => unreachable,
        else => |other| return @errorCast(other),
    };
}

fn validateRouteOrder(before: Route, after: Route) error{InvalidCapsule}!void {
    if (before.version() > after.version() or
        (before.version() == after.version() and
            before.protocol() > after.protocol()))
    {
        return error.InvalidCapsule;
    }
    if (before.version() == after.version() and
        before.protocol() == after.protocol() and
        std.mem.order(u8, before.endBytes(), after.startBytes()) != .lt)
    {
        return error.InvalidCapsule;
    }
}

fn rangesOverlap(a: Route, b: Route) bool {
    return std.mem.order(u8, a.startBytes(), b.endBytes()) != .gt and
        std.mem.order(u8, b.startBytes(), a.endBytes()) != .gt;
}

fn hostBitsZero(bytes: []const u8, prefix_length: u8) bool {
    const full_bytes = prefix_length / 8;
    const partial_bits = prefix_length % 8;
    var index: usize = full_bytes;
    if (partial_bits != 0) {
        const host_mask: u8 = (@as(u8, 1) << @intCast(8 - partial_bits)) - 1;
        if ((bytes[index] & host_mask) != 0) return false;
        index += 1;
    }
    for (bytes[index..]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

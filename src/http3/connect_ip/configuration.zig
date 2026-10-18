//! Bounded RFC 9484 configuration state across reliable Capsules.

const std = @import("std");
const capsules = @import("capsules.zig");

pub const Limits = struct {
    max_request_ids_per_direction: usize = 1024,
    max_assigned_prefixes: usize = 64,
    max_routes: usize = 256,
};

pub const Error = std.mem.Allocator.Error || error{
    InvalidCapsule,
    ExcessiveLoad,
    DuplicateRequestId,
    UnknownRequestId,
};

pub const ApplyResult = enum {
    address_assign,
    address_request,
    route_advertisement,
    unknown,
};

pub const State = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    local_request_ids: std.AutoHashMapUnmanaged(u62, void) = .empty,
    peer_request_ids: std.AutoHashMapUnmanaged(u62, void) = .empty,
    local_request_id_staging: std.ArrayList(u62) = .empty,
    peer_request_id_staging: std.ArrayList(u62) = .empty,
    assignments: std.ArrayList(capsules.AddressPrefix) = .empty,
    assignment_staging: std.ArrayList(capsules.AddressPrefix) = .empty,
    routes: std.ArrayList(capsules.Route) = .empty,
    route_staging: std.ArrayList(capsules.Route) = .empty,
    local_prepare_active: bool = false,
    assignment_revision: u64 = 0,
    route_revision: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, limits: Limits) State {
        return .{ .allocator = allocator, .limits = limits };
    }

    pub fn deinit(self: *State) void {
        self.local_request_ids.deinit(self.allocator);
        self.peer_request_ids.deinit(self.allocator);
        self.local_request_id_staging.deinit(self.allocator);
        self.peer_request_id_staging.deinit(self.allocator);
        self.assignments.deinit(self.allocator);
        self.assignment_staging.deinit(self.allocator);
        self.routes.deinit(self.allocator);
        self.route_staging.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn assignedPrefixes(self: *const State) []const capsules.AddressPrefix {
        return self.assignments.items;
    }

    pub fn advertisedRoutes(self: *const State) []const capsules.Route {
        return self.routes.items;
    }

    pub fn localRequestCount(self: *const State) usize {
        return self.local_request_ids.count();
    }

    pub fn peerRequestCount(self: *const State) usize {
        return self.peer_request_ids.count();
    }

    /// Record an ADDRESS_REQUEST only after its complete Capsule is committed
    /// to the transport. IDs remain reserved for the tunnel lifetime.
    pub fn recordLocalAddressRequest(
        self: *State,
        value: []const u8,
    ) Error!void {
        try self.prepareLocalCapsule(capsules.address_request_type, value);
        self.commitPreparedLocalCapsule();
    }

    pub fn prepareLocalCapsule(
        self: *State,
        capsule_type: u64,
        value: []const u8,
    ) Error!void {
        if (self.local_prepare_active) return error.InvalidCapsule;
        if (capsule_type != capsules.address_request_type) return;
        var iterator = capsules.parseAddressRequest(value) catch
            return error.InvalidCapsule;
        try self.collectRequestIds(
            &iterator,
            &self.local_request_ids,
            &self.local_request_id_staging,
        );
        try self.ensureRequestIdCapacity(
            &self.local_request_ids,
            self.local_request_id_staging.items.len,
        );
        self.local_prepare_active = true;
    }

    pub fn commitPreparedLocalCapsule(self: *State) void {
        if (!self.local_prepare_active) return;
        for (self.local_request_id_staging.items) |request_id| {
            self.local_request_ids.putAssumeCapacityNoClobber(request_id, {});
        }
        self.local_request_id_staging.clearRetainingCapacity();
        self.local_prepare_active = false;
    }

    pub fn discardPreparedLocalCapsule(self: *State) void {
        if (!self.local_prepare_active) return;
        self.local_request_id_staging.clearRetainingCapacity();
        self.local_prepare_active = false;
    }

    pub fn applyPeerCapsule(
        self: *State,
        capsule_type: u64,
        value: []const u8,
    ) Error!ApplyResult {
        return switch (capsule_type) {
            capsules.address_assign_type => result: {
                try self.applyAddressAssign(value);
                break :result .address_assign;
            },
            capsules.address_request_type => result: {
                var iterator = capsules.parseAddressRequest(value) catch
                    return error.InvalidCapsule;
                try self.collectRequestIds(
                    &iterator,
                    &self.peer_request_ids,
                    &self.peer_request_id_staging,
                );
                try self.commitRequestIds(
                    &self.peer_request_ids,
                    &self.peer_request_id_staging,
                );
                break :result .address_request;
            },
            capsules.route_advertisement_type => result: {
                try self.applyRoutes(value);
                break :result .route_advertisement;
            },
            else => .unknown,
        };
    }

    pub fn sourceIsAssigned(
        self: *const State,
        address: capsules.IpAddress,
    ) bool {
        for (self.assignments.items) |assignment| {
            if (prefixContains(assignment, address)) return true;
        }
        return false;
    }

    pub fn routeAllows(
        self: *const State,
        destination: capsules.IpAddress,
        ip_protocol: u8,
    ) bool {
        for (self.routes.items) |route| {
            if (route.version() != destination.version() or
                std.mem.order(
                    u8,
                    destination.bytes(),
                    route.startBytes(),
                ) == .lt or
                std.mem.order(
                    u8,
                    destination.bytes(),
                    route.endBytes(),
                ) == .gt)
            {
                continue;
            }
            if (route.protocol() == 0 or route.protocol() == ip_protocol or
                isIcmp(destination.version(), ip_protocol))
            {
                return true;
            }
        }
        return false;
    }

    fn collectRequestIds(
        self: *State,
        iterator: *capsules.AddressIterator,
        existing: *const std.AutoHashMapUnmanaged(u62, void),
        staging: *std.ArrayList(u62),
    ) Error!void {
        staging.clearRetainingCapacity();
        while (iterator.next() catch return error.InvalidCapsule) |request| {
            if (existing.contains(request.request_id) or
                containsId(staging.items, request.request_id))
            {
                return error.DuplicateRequestId;
            }
            const retained = std.math.add(
                usize,
                existing.count(),
                staging.items.len,
            ) catch return error.ExcessiveLoad;
            if (retained >= self.limits.max_request_ids_per_direction) {
                return error.ExcessiveLoad;
            }
            try staging.append(
                self.allocator,
                request.request_id,
            );
        }
    }

    fn commitRequestIds(
        self: *State,
        destination: *std.AutoHashMapUnmanaged(u62, void),
        staging: *std.ArrayList(u62),
    ) Error!void {
        try self.ensureRequestIdCapacity(destination, staging.items.len);
        for (staging.items) |request_id| {
            destination.putAssumeCapacityNoClobber(request_id, {});
        }
        staging.clearRetainingCapacity();
    }

    fn ensureRequestIdCapacity(
        self: *State,
        destination: *std.AutoHashMapUnmanaged(u62, void),
        additional_len: usize,
    ) Error!void {
        try destination.ensureUnusedCapacity(
            self.allocator,
            std.math.cast(
                u32,
                additional_len,
            ) orelse return error.ExcessiveLoad,
        );
    }

    fn applyAddressAssign(self: *State, value: []const u8) Error!void {
        var iterator = capsules.parseAddressAssign(value) catch
            return error.InvalidCapsule;
        self.assignment_staging.clearRetainingCapacity();
        self.peer_request_id_staging.clearRetainingCapacity();
        while (iterator.next() catch return error.InvalidCapsule) |assignment| {
            if (assignment.request_id != 0) {
                if (!self.local_request_ids.contains(assignment.request_id)) {
                    return error.UnknownRequestId;
                }
                if (containsId(
                    self.peer_request_id_staging.items,
                    assignment.request_id,
                )) return error.DuplicateRequestId;
                try self.peer_request_id_staging.append(
                    self.allocator,
                    assignment.request_id,
                );
            }
            if (isRejectedAssignment(assignment)) continue;
            if (self.assignment_staging.items.len >=
                self.limits.max_assigned_prefixes)
            {
                return error.ExcessiveLoad;
            }
            try self.assignment_staging.append(self.allocator, assignment);
        }
        std.mem.swap(
            std.ArrayList(capsules.AddressPrefix),
            &self.assignments,
            &self.assignment_staging,
        );
        self.assignment_staging.clearRetainingCapacity();
        self.peer_request_id_staging.clearRetainingCapacity();
        self.assignment_revision +|= 1;
    }

    fn applyRoutes(self: *State, value: []const u8) Error!void {
        var iterator = capsules.parseRouteAdvertisement(value) catch
            return error.InvalidCapsule;
        self.route_staging.clearRetainingCapacity();
        while (iterator.next() catch return error.InvalidCapsule) |route| {
            if (self.route_staging.items.len >= self.limits.max_routes) {
                return error.ExcessiveLoad;
            }
            for (self.route_staging.items) |previous| {
                if (previous.version() == route.version() and
                    (previous.protocol() == 0 or route.protocol() == 0) and
                    rangesOverlap(previous, route))
                {
                    return error.InvalidCapsule;
                }
            }
            try self.route_staging.append(self.allocator, route);
        }
        std.mem.swap(
            std.ArrayList(capsules.Route),
            &self.routes,
            &self.route_staging,
        );
        self.route_staging.clearRetainingCapacity();
        self.route_revision +|= 1;
    }
};

fn containsId(ids: []const u62, expected: u62) bool {
    for (ids) |request_id| {
        if (request_id == expected) return true;
    }
    return false;
}

fn isRejectedAssignment(assignment: capsules.AddressPrefix) bool {
    if (assignment.request_id == 0 or
        assignment.prefix_length != assignment.address.maxPrefixLength())
    {
        return false;
    }
    for (assignment.address.bytes()) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

fn prefixContains(
    prefix: capsules.AddressPrefix,
    address: capsules.IpAddress,
) bool {
    if (prefix.address.version() != address.version()) return false;
    const expected = prefix.address.bytes();
    const actual = address.bytes();
    const full_bytes = prefix.prefix_length / 8;
    if (!std.mem.eql(u8, expected[0..full_bytes], actual[0..full_bytes])) {
        return false;
    }
    const partial_bits = prefix.prefix_length % 8;
    if (partial_bits == 0) return true;
    const shift: u3 = @intCast(8 - partial_bits);
    const mask: u8 = @as(u8, 0xff) << shift;
    return (expected[full_bytes] & mask) == (actual[full_bytes] & mask);
}

fn rangesOverlap(a: capsules.Route, b: capsules.Route) bool {
    return std.mem.order(u8, a.startBytes(), b.endBytes()) != .gt and
        std.mem.order(u8, b.startBytes(), a.endBytes()) != .gt;
}

fn isIcmp(version: u8, protocol: u8) bool {
    return (version == 4 and protocol == 1) or
        (version == 6 and protocol == 58);
}

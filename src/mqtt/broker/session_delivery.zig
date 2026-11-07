//! Aggregation plan for publications matching durable MQTT Session routes.
//!
//! MQTT permits one client to have multiple matching subscriptions. The
//! resulting Application Message is queued once per Session, with the highest
//! effective QoS, Retain As Published enabled if any match requests it, and
//! every matching subscription's Identifier attached to that one PUBLISH.
//! Equal Identifier values remain separate occurrences (MQTT-3.3.4-4).

const std = @import("std");
const mqtt = @import("../mod.zig");
const router = @import("../router.zig");
const session_route = @import("session_route.zig");

pub const Route = struct {
    route_id: u64,
    qos: mqtt.QoS,
    retain: bool,
    identifier_offset: usize = 0,
    identifier_capacity: usize = 0,
    identifier_count: usize = 0,
    /// Subscriber ID that the broker should leave in every raw match after
    /// durable enqueueing. Zero drops offline matches from the flush plan; a
    /// connection ID selects transient delivery; a Session ID selects the
    /// durable Session drain.
    output_subscriber_id: router.SubscriberId = 0,
    durable_target_emitted: bool = false,
};

pub const scratch_capacity = 32;

pub const Scratch = struct {
    routes: [scratch_capacity]Route = undefined,
    identifiers: [scratch_capacity]usize = undefined,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    routes_storage: []Route,
    routes: []Route,
    identifiers: []usize,
    route_index: std.AutoHashMapUnmanaged(u64, usize),
    owns_storage: bool,

    pub fn init(
        allocator: std.mem.Allocator,
        matches: []const router.Match,
        source_qos: mqtt.QoS,
        source_retain: bool,
        upgrade_outgoing_qos: bool,
    ) std.mem.Allocator.Error!Plan {
        return initWithScratch(
            allocator,
            matches,
            source_qos,
            source_retain,
            upgrade_outgoing_qos,
            null,
        );
    }

    pub fn initWithScratch(
        allocator: std.mem.Allocator,
        matches: []const router.Match,
        source_qos: mqtt.QoS,
        source_retain: bool,
        upgrade_outgoing_qos: bool,
        scratch: ?*Scratch,
    ) std.mem.Allocator.Error!Plan {
        var stable_match_count: usize = 0;
        for (matches) |match| {
            stable_match_count += @intFromBool(
                session_route.sessionRouteId(match.subscriber_id) != null,
            );
        }
        if (stable_match_count == 0) return .{
            .allocator = allocator,
            .routes_storage = &.{},
            .routes = &.{},
            .identifiers = &.{},
            .route_index = .empty,
            .owns_storage = false,
        };

        const use_scratch = scratch != null and
            stable_match_count <= scratch_capacity;
        const routes_storage = if (use_scratch)
            scratch.?.routes[0..stable_match_count]
        else
            try allocator.alloc(Route, stable_match_count);
        errdefer if (!use_scratch) allocator.free(routes_storage);
        var route_index: std.AutoHashMapUnmanaged(u64, usize) = .empty;
        errdefer route_index.deinit(allocator);
        if (!use_scratch) {
            try route_index.ensureTotalCapacity(
                allocator,
                @intCast(stable_match_count),
            );
        }

        var route_count: usize = 0;
        var identifier_capacity: usize = 0;
        for (matches) |match| {
            const route_id = session_route.sessionRouteId(
                match.subscriber_id,
            ) orelse continue;
            const effective_qos = if (upgrade_outgoing_qos)
                match.subscription.qos
            else
                minQos(source_qos, match.subscription.qos);
            const existing_index = if (use_scratch)
                findRouteIndex(routes_storage[0..route_count], route_id)
            else
                route_index.get(route_id);
            if (existing_index == null) {
                if (!use_scratch) {
                    route_index.putAssumeCapacityNoClobber(
                        route_id,
                        route_count,
                    );
                }
                routes_storage[route_count] = .{
                    .route_id = route_id,
                    .qos = effective_qos,
                    .retain = source_retain and
                        match.subscription.retain_as_published,
                };
                route_count += 1;
            } else {
                const route = &routes_storage[existing_index.?];
                route.qos = maxQos(route.qos, effective_qos);
                route.retain = route.retain or
                    (source_retain and
                        match.subscription.retain_as_published);
            }
            if (match.subscription_identifier != null) {
                routes_storage[existing_index orelse route_count - 1]
                    .identifier_capacity += 1;
                identifier_capacity += 1;
            }
        }

        var next_identifier: usize = 0;
        for (routes_storage[0..route_count]) |*route| {
            route.identifier_offset = next_identifier;
            next_identifier += route.identifier_capacity;
        }
        std.debug.assert(next_identifier == identifier_capacity);
        const identifiers = if (use_scratch)
            scratch.?.identifiers[0..identifier_capacity]
        else
            try allocator.alloc(usize, identifier_capacity);
        errdefer if (!use_scratch) allocator.free(identifiers);

        // The first pass assigns each route enough contiguous space for all
        // identifiers. The second pass preserves one occurrence per matching
        // subscription, including equal values, in router match order.
        for (matches) |match| {
            const identifier = match.subscription_identifier orelse continue;
            const route_id = session_route.sessionRouteId(
                match.subscriber_id,
            ) orelse continue;
            const route = &routes_storage[
                if (use_scratch)
                    findRouteIndex(routes_storage[0..route_count], route_id).?
                else
                    route_index.get(route_id).?
            ];
            identifiers[route.identifier_offset + route.identifier_count] =
                identifier;
            route.identifier_count += 1;
        }

        return .{
            .allocator = allocator,
            .routes_storage = routes_storage,
            .routes = routes_storage[0..route_count],
            .identifiers = identifiers,
            .route_index = route_index,
            .owns_storage = !use_scratch,
        };
    }

    pub fn deinit(self: *Plan) void {
        self.route_index.deinit(self.allocator);
        if (self.owns_storage) {
            self.allocator.free(self.identifiers);
            self.allocator.free(self.routes_storage);
        }
        self.* = undefined;
    }

    pub fn routeForId(self: *Plan, route_id: u64) *Route {
        const index = if (self.owns_storage)
            self.route_index.get(route_id).?
        else
            findRouteIndex(self.routes, route_id).?;
        return &self.routes[index];
    }

    pub fn identifiersFor(
        self: Plan,
        route: *const Route,
    ) []const usize {
        return self.identifiers[route.identifier_offset..][0..route.identifier_count];
    }

    pub fn nextOutputSubscriberId(
        self: *Plan,
        route_id: u64,
    ) router.SubscriberId {
        const route = self.routeForId(route_id);
        if (session_route.sessionRouteId(route.output_subscriber_id) == null) {
            // Transient delivery still needs every raw match so the live queue
            // merger can collect each subscription's identifier and options.
            return route.output_subscriber_id;
        }
        if (route.durable_target_emitted) return 0;
        route.durable_target_emitted = true;
        return route.output_subscriber_id;
    }
};

fn findRouteIndex(routes: []const Route, route_id: u64) ?usize {
    for (routes, 0..) |route, index| {
        if (route.route_id == route_id) return index;
    }
    return null;
}

fn minQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) < @intFromEnum(b)) a else b;
}

fn maxQos(a: mqtt.QoS, b: mqtt.QoS) mqtt.QoS {
    return if (@intFromEnum(a) >= @intFromEnum(b)) a else b;
}

test "Session delivery plan aggregates route options and identifiers" {
    const stable = session_route.sessionSubscriberId(7);
    const matches = [_]router.Match{
        .{
            .subscriber_id = stable,
            .subscription = .{
                .topic_filter = "devices/#",
                .qos = .at_most_once,
            },
            .subscription_identifier = 3,
        },
        .{
            .subscriber_id = 42,
            .subscription = .{ .topic_filter = "devices/one" },
            .subscription_identifier = 8,
        },
        .{
            .subscriber_id = stable,
            .subscription = .{
                .topic_filter = "devices/+",
                .qos = .exactly_once,
                .retain_as_published = true,
            },
            .subscription_identifier = 9,
        },
        .{
            .subscriber_id = stable,
            .subscription = .{
                .topic_filter = "devices/one",
                .qos = .at_least_once,
            },
            .subscription_identifier = 3,
        },
    };

    var plan = try Plan.init(
        std.testing.allocator,
        &matches,
        .at_least_once,
        true,
        false,
    );
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.routes.len);
    const route = &plan.routes[0];
    try std.testing.expectEqual(@as(u64, 7), route.route_id);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, route.qos);
    try std.testing.expect(route.retain);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 3, 9, 3 },
        plan.identifiersFor(route),
    );
    route.output_subscriber_id = stable;
    try std.testing.expectEqual(stable, plan.nextOutputSubscriberId(7));
    try std.testing.expectEqual(
        @as(router.SubscriberId, 0),
        plan.nextOutputSubscriberId(7),
    );
}

test "Session delivery plan preserves equal identifiers per matching filter and route" {
    const first = session_route.sessionSubscriberId(7);
    const second = session_route.sessionSubscriberId(8);
    const matches = [_]router.Match{
        .{ .subscriber_id = first, .subscription = .{ .topic_filter = "#" }, .subscription_identifier = 7 },
        .{ .subscriber_id = second, .subscription = .{ .topic_filter = "a/#" }, .subscription_identifier = 7 },
        .{ .subscriber_id = first, .subscription = .{ .topic_filter = "+/#" }, .subscription_identifier = 7 },
        .{ .subscriber_id = second, .subscription = .{ .topic_filter = "a/x" }, .subscription_identifier = 7 },
        .{ .subscriber_id = first, .subscription = .{ .topic_filter = "a/+" }, .subscription_identifier = 7 },
    };
    for ([_]bool{ false, true }) |use_scratch| {
        var scratch: Scratch = .{};
        var plan = try Plan.initWithScratch(std.testing.allocator, &matches, .at_least_once, false, false, if (use_scratch) &scratch else null);
        defer plan.deinit();
        try std.testing.expectEqual(@as(usize, 2), plan.routes.len);
        try std.testing.expectEqualSlices(usize, &.{ 7, 7, 7 }, plan.identifiersFor(&plan.routes[0]));
        try std.testing.expectEqualSlices(usize, &.{ 7, 7 }, plan.identifiersFor(&plan.routes[1]));
    }
}

test "Session delivery plan allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testAllocationFailures,
        .{},
    );
}

test "Session delivery plan can upgrade source QoS" {
    const stable = session_route.sessionSubscriberId(13);
    const matches = [_]router.Match{.{
        .subscriber_id = stable,
        .subscription = .{
            .topic_filter = "upgrade/#",
            .qos = .exactly_once,
        },
        .subscription_identifier = null,
    }};
    var plan = try Plan.init(
        std.testing.allocator,
        &matches,
        .at_most_once,
        false,
        true,
    );
    defer plan.deinit();
    try std.testing.expectEqual(
        mqtt.QoS.exactly_once,
        plan.routes[0].qos,
    );
}

test "Session delivery plan uses caller scratch without allocation" {
    const stable = session_route.sessionSubscriberId(17);
    var matches: [scratch_capacity]router.Match = undefined;
    for (&matches, 0..) |*match, index| {
        match.* = .{
            .subscriber_id = stable,
            .subscription = .{
                .topic_filter = "scratch/#",
                .qos = if (index == matches.len - 1)
                    .exactly_once
                else
                    .at_most_once,
                .retain_as_published = index == matches.len - 1,
            },
            .subscription_identifier = index + 1,
        };
    }
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var scratch: Scratch = .{};
    var plan = try Plan.initWithScratch(
        failing.allocator(),
        &matches,
        .at_least_once,
        true,
        false,
        &scratch,
    );
    defer plan.deinit();

    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), plan.routes.len);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, plan.routes[0].qos);
    try std.testing.expect(plan.routes[0].retain);
    try std.testing.expectEqual(
        scratch_capacity,
        plan.identifiersFor(&plan.routes[0]).len,
    );
}

test "Session delivery plan falls back beyond caller scratch" {
    var matches: [scratch_capacity + 1]router.Match = undefined;
    for (&matches, 1..) |*match, route_id| {
        match.* = .{
            .subscriber_id = session_route.sessionSubscriberId(route_id),
            .subscription = .{ .topic_filter = "fallback/#" },
            .subscription_identifier = null,
        };
    }
    var scratch: Scratch = .{};
    var plan = try Plan.initWithScratch(
        std.testing.allocator,
        &matches,
        .at_most_once,
        false,
        false,
        &scratch,
    );
    defer plan.deinit();

    try std.testing.expect(plan.owns_storage);
    try std.testing.expectEqual(matches.len, plan.routes.len);
    try std.testing.expectEqual(
        @as(u64, scratch_capacity + 1),
        plan.routeForId(scratch_capacity + 1).route_id,
    );
}

fn testAllocationFailures(allocator: std.mem.Allocator) !void {
    const stable = session_route.sessionSubscriberId(11);
    const matches = [_]router.Match{
        .{
            .subscriber_id = stable,
            .subscription = .{ .topic_filter = "sensors/#" },
            .subscription_identifier = 1,
        },
        .{
            .subscriber_id = stable,
            .subscription = .{
                .topic_filter = "sensors/+",
                .qos = .at_least_once,
            },
            .subscription_identifier = 2,
        },
    };
    var plan = try Plan.init(
        allocator,
        &matches,
        .at_least_once,
        false,
        false,
    );
    defer plan.deinit();
    try std.testing.expectEqualSlices(
        usize,
        &.{ 1, 2 },
        plan.identifiersFor(&plan.routes[0]),
    );
}

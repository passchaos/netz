//! Aggregation plan for publications matching durable MQTT Session routes.
//!
//! MQTT permits one client to have multiple matching subscriptions. The
//! resulting Application Message is queued once per Session, with the highest
//! effective QoS, Retain As Published enabled if any match requests it, and
//! every distinct Subscription Identifier attached to that one PUBLISH.

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

pub const Plan = struct {
    allocator: std.mem.Allocator,
    routes_storage: []Route,
    routes: []Route,
    identifiers: []usize,
    route_index: std.AutoHashMapUnmanaged(u64, usize),

    pub fn init(
        allocator: std.mem.Allocator,
        matches: []const router.Match,
        source_qos: mqtt.QoS,
        source_retain: bool,
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
        };

        const routes_storage = try allocator.alloc(
            Route,
            stable_match_count,
        );
        errdefer allocator.free(routes_storage);
        var route_index: std.AutoHashMapUnmanaged(u64, usize) = .empty;
        errdefer route_index.deinit(allocator);
        try route_index.ensureTotalCapacity(
            allocator,
            @intCast(stable_match_count),
        );

        var route_count: usize = 0;
        var identifier_capacity: usize = 0;
        for (matches) |match| {
            const route_id = session_route.sessionRouteId(
                match.subscriber_id,
            ) orelse continue;
            const effective_qos = minQos(source_qos, match.subscription.qos);
            const result = route_index.getOrPutAssumeCapacity(route_id);
            if (!result.found_existing) {
                result.value_ptr.* = route_count;
                routes_storage[route_count] = .{
                    .route_id = route_id,
                    .qos = effective_qos,
                    .retain = source_retain and
                        match.subscription.retain_as_published,
                };
                route_count += 1;
            } else {
                const route = &routes_storage[result.value_ptr.*];
                route.qos = maxQos(route.qos, effective_qos);
                route.retain = route.retain or
                    (source_retain and
                        match.subscription.retain_as_published);
            }
            if (match.subscription_identifier != null) {
                routes_storage[result.value_ptr.*]
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
        const identifiers = try allocator.alloc(usize, identifier_capacity);
        errdefer allocator.free(identifiers);

        // The first pass assigns each route enough contiguous space for all
        // raw identifiers. The second pass preserves router match order while
        // compacting duplicate values inside each route's reserved segment.
        for (matches) |match| {
            const identifier = match.subscription_identifier orelse continue;
            const route_id = session_route.sessionRouteId(
                match.subscriber_id,
            ) orelse continue;
            const route = &routes_storage[route_index.get(route_id).?];
            const existing = identifiers[route.identifier_offset..][0..route.identifier_count];
            if (std.mem.indexOfScalar(usize, existing, identifier) != null) {
                continue;
            }
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
        };
    }

    pub fn deinit(self: *Plan) void {
        self.route_index.deinit(self.allocator);
        if (self.routes_storage.len != 0) {
            self.allocator.free(self.identifiers);
            self.allocator.free(self.routes_storage);
        }
        self.* = undefined;
    }

    pub fn routeForId(self: *Plan, route_id: u64) *Route {
        return &self.routes[self.route_index.get(route_id).?];
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
    );
    defer plan.deinit();
    try std.testing.expectEqual(@as(usize, 1), plan.routes.len);
    const route = &plan.routes[0];
    try std.testing.expectEqual(@as(u64, 7), route.route_id);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, route.qos);
    try std.testing.expect(route.retain);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 3, 9 },
        plan.identifiersFor(route),
    );
    route.output_subscriber_id = stable;
    try std.testing.expectEqual(stable, plan.nextOutputSubscriberId(7));
    try std.testing.expectEqual(
        @as(router.SubscriberId, 0),
        plan.nextOutputSubscriberId(7),
    );
}

test "Session delivery plan allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testAllocationFailures,
        .{},
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
    );
    defer plan.deinit();
    try std.testing.expectEqualSlices(
        usize,
        &.{ 1, 2 },
        plan.identifiersFor(&plan.routes[0]),
    );
}

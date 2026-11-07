//! Native ADS peers and scoped events for the managed federation facade.
const std = @import("std");
const grpc = @import("../../../mod.zig");
const managed = @import("../managed.zig");
const bootstrap = @import("../../bootstrap.zig");
const ads = @import("../../ads.zig");
const delta = @import("../../ads/delta.zig");
const names = @import("names.zig");
const gpa = std.testing.allocator;
pub const listener = "xdstp://A/envoy.config.listener.v3.Listener/frontend";
pub const routes = "xdstp://B/envoy.config.route.v3.RouteConfiguration/routes";
pub const cluster_a = "xdstp://A/envoy.config.cluster.v3.Cluster/a";
pub const cluster_b = "xdstp://B/envoy.config.cluster.v3.Cluster/b";
pub const cluster_b2 = "xdstp://B/envoy.config.cluster.v3.Cluster/b2";
pub const endpoint_a = "xdstp://A/envoy.config.endpoint.v3.ClusterLoadAssignment/a";
pub const endpoint_b = "xdstp://B/envoy.config.endpoint.v3.ClusterLoadAssignment/b";
pub const endpoint_b2 = "xdstp://B/envoy.config.endpoint.v3.ClusterLoadAssignment/b2";
pub fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
pub fn wait(io: std.Io, event: *std.Io.Event) !void {
    try event.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } });
}
pub fn report(comptime mode: managed.Mode, facade: anytype, phase: []const u8, index: usize, operation: []const u8, err: anyerror, authority: []const u8, url: []const u8, nonce: []const u8) void {
    std.debug.print("federated native mode={s} phase={s} step={d} operation={s} error={s} authority={s} url={s} nonce={s}\n", .{ @tagName(mode), phase, index, operation, @errorName(err), authority, url, nonce });
    for (facade.registry.desired.items) |watch| {
        std.debug.print("  desired url={s} count={d}\n", .{ watch.type_url, watch.values.len });
        for (watch.values) |name| std.debug.print("    name={s}\n", .{name});
    }
    for (facade.registry.sessions.items) |session| {
        const failure = if (session.client.stream) |stream| if (stream.call.failureValue()) |value| @errorName(value) else "none" else "none";
        std.debug.print("  session authority={s} active={} stream={} failure={s} epoch={d} pending={} provisional={} prepares={d}\n", .{ session.authority, facade.registry.active(session), session.client.stream != null, failure, session.client.subscriptions.epoch, session.pending != null, session.provisional, session.pending_prepares });
        if (session.pending) |pending| {
            if (pending) |event| {
                std.debug.print("    queued result={s}\n", .{@tagName(event)});
                if (event == .update) std.debug.print("    queued url={s} nonce={s}\n", .{ event.update.response.value.type_url, event.update.response.value.nonce });
            } else |failure_value| std.debug.print("    queued error={s}\n", .{@errorName(failure_value)});
        }
        for (session.client.subscriptions.entries.items) |subscription| {
            std.debug.print("    subscription url={s} nonce={s} dirty={} pending_sequence={?d}\n", .{ subscription.type_url, subscription.nonce, subscription.dirty, subscription.pending_sequence });
            for (subscription.names) |name| std.debug.print("      name={s}\n", .{name});
        }
    }
}
pub fn configuration(a_port: u16, b_port: u16) !*bootstrap.Bootstrap {
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"federated-node\"}},\"authorities\":{{\"A\":{{\"xds_servers\":[{{\"server_uri\":\"127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}],\"server_features\":[\"trusted_xds_server\",\"ignore_resource_deletion\"]}}]}},\"B\":{{\"xds_servers\":[{{\"server_uri\":\"127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}]}}}}}}", .{ a_port, a_port, b_port });
    defer gpa.free(json);
    return bootstrap.parse(gpa, json, .{});
}
pub const Step = struct {
    url: []const u8,
    name: []const u8,
    version: []const u8,
    bytes: ?[]const u8,
    extra: ?struct { name: []const u8, bytes: []const u8 } = null,
    trigger: bool = true,
    gate: ?*std.Io.Event = null,
    ack: ?*std.Io.Event = null,
};
fn encoded(comptime mode: managed.Mode, step: Step) ![]u8 {
    const Resource = if (mode == .sotw) ads.codec.Any else delta.codec.Resource;
    var resources: [2]Resource = undefined;
    var count: usize = 0;
    if (step.bytes) |value| {
        resources[count] = if (mode == .sotw) .{ .type_url = step.url, .value = value } else .{ .name = step.name, .version = step.version, .resource = .{ .type_url = step.url, .value = value } };
        count += 1;
    }
    if (step.extra) |extra| {
        resources[count] = if (mode == .sotw) .{ .type_url = step.url, .value = extra.bytes } else .{ .name = extra.name, .version = step.version, .resource = .{ .type_url = step.url, .value = extra.bytes } };
        count += 1;
    }
    return if (mode == .sotw)
        ads.codec.encodeResponse(gpa, .{ .type_url = step.url, .version = step.version, .nonce = step.version, .resources = resources[0..count] }, 65536)
    else
        delta.codec.encodeResponse(gpa, .{ .type_url = step.url, .nonce = step.version, .resources = resources[0..count], .removed = if (step.bytes == null) &.{step.name} else &.{} }, .{});
}
pub fn offline(comptime mode: managed.Mode, facade: *managed.Managed(mode), step: Step) !managed.Managed(mode).Event {
    const session = try facade.registry.forName(step.name);
    const bytes = try encoded(mode, step);
    defer gpa.free(bytes);
    var response = if (mode == .sotw) try ads.codec.decodeResponse(gpa, bytes, .{}) else try delta.codec.decodeResponse(gpa, bytes, .{});
    errdefer response.deinit();
    const token = try session.client.subscriptions.received(response.value);
    return .{ .session = session.retain(), .result = .{ .update = .{ .response = response, .token = token, .source = session.client.source.?.retain() } } };
}
pub fn Peer(comptime mode: managed.Mode) type {
    return struct {
        const Codec = if (mode == .sotw) ads.codec else delta.codec;
        const Collector = struct {
            request: ?Codec.OwnedRequest = null,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                if (self.request != null) return error.UnexpectedRequest;
                self.request = if (mode == .sotw) try Codec.decodeRequest(gpa, message.payload, 65536, 100) else try Codec.decodeRequest(gpa, message.payload, .{});
            }
        };
        fn read(stream: anytype, authority: []const u8, steps: []const Step, seen: *[8]bool, first: *bool) !Codec.OwnedRequest {
            var collector: Collector = .{};
            errdefer if (collector.request) |*value| value.deinit();
            while (collector.request == null) {
                var event = try stream.readRequestEventWithTimeout(.fromSeconds(5), &collector, Collector.consume);
                defer event.deinit();
                if (event == .finished or event == .reset) return error.EndedEarly;
            }
            var request = collector.request.?;
            errdefer request.deinit();
            if (first.*) {
                const node = try ads.codec.encodeNode(gpa, .{ .id = "federated-node" });
                defer gpa.free(node);
                try std.testing.expectEqualSlices(u8, node, request.value.node.?);
                first.* = false;
            }
            const subscribed = if (mode == .sotw) request.value.names else request.value.subscribe;
            for (subscribed) |name| {
                try std.testing.expect(names.belongs(name, authority));
                for (steps, 0..) |step, index| if (std.mem.eql(u8, step.url, request.value.type_url) and std.mem.eql(u8, step.name, name)) {
                    seen[index] = true;
                };
            }
            if (mode == .delta) for (request.value.unsubscribe) |name| try std.testing.expect(names.belongs(name, authority));
            return request;
        }
        pub fn run(io: std.Io, listener_server: *grpc.runtime.Server, authority: []const u8, steps: []const Step, hold: *std.Io.Event) !void {
            var connection = try listener_server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer stream.deinit();
            try std.testing.expectEqualStrings(if (mode == .sotw) ads.path else delta.path, stream.transport.path);
            try stream.startResponse(.{});
            var seen = [_]bool{false} ** 8;
            var first = true;
            for (steps, 0..) |step, index| {
                while (step.trigger and !seen[index]) {
                    var request = try read(&stream, authority, steps, &seen, &first);
                    request.deinit();
                }
                if (step.gate) |gate| try wait(io, gate);
                const bytes = try encoded(mode, step);
                defer gpa.free(bytes);
                try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(bytes));
                while (true) {
                    var ack = try read(&stream, authority, steps, &seen, &first);
                    defer ack.deinit();
                    if (!std.mem.eql(u8, step.url, ack.value.type_url) or !std.mem.eql(u8, step.version, ack.value.nonce)) continue;
                    try std.testing.expect(ack.value.nack == null);
                    if (mode == .sotw) try std.testing.expectEqualStrings(step.version, ack.value.version);
                    break;
                }
                if (step.ack) |event| event.set(io);
            }
            try hold.wait(io);
            stream.finishOk() catch {};
        }
    };
}
pub const Backend = struct {
    pub fn run(io: std.Io, server: *grpc.runtime.Server, body: []const u8, calls_per_connection: []const usize, entered: *std.Io.Event, release: *std.Io.Event) !void {
        for (calls_per_connection) |count| {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            for (0..count) |_| {
                var unary = try connection.readUnaryWithTimeout(.fromSeconds(5));
                defer unary.deinit();
                if (std.mem.eql(u8, unary.request.message.payload, "hold")) {
                    entered.set(io);
                    try release.wait(io);
                }
                try connection.writeUnary(unary.transport.stream_id, .{ .message = body });
            }
        }
    }
};
pub fn call(channel: grpc.SharedChannel, path: []const u8, message: []const u8, body: []const u8) !void {
    var sender = channel.sender();
    defer sender.deinit();
    var response = try sender.unary(.{ .path = path, .message = message, .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings(body, response.message.?.payload);
}

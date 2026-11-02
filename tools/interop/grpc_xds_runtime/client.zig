//! Full ADS chain creates application child topology without static endpoints.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const xds = grpc.xds;
const gpa = std.heap.c_allocator;
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn apply(controller: *xds.runtime.Controller, client: *xds.ads.Client, channel: grpc.SharedChannel, io: std.Io) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    _ = try controller.applyWithDeadline(client, event.update, channel, until(io));
}
fn call(sender: grpc.SharedChannelSender, path: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = path, .message = "request", .authority = "backend.test", .wait_for_ready = false, .timeout = .{ .value = 4, .unit = .second } });
}
fn first(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return call(sender, "/fixture.Runtime/A");
}
fn beta(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return call(sender, "/fixture.Runtime/B");
}
fn held(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return call(sender, "/fixture.Runtime/Held");
}
fn phase(client: *xds.ads.Client, io: std.Io, url: []const u8, name: []const u8) !void {
    const current = client.subscriptions.find(url).?.names;
    const names = try gpa.alloc([]const u8, current.len + 1);
    defer gpa.free(names);
    @memcpy(names[0..current.len], current);
    names[current.len] = name;
    try client.setSubscription(url, names);
    _ = try client.flushWithDeadline(until(io));
}
fn noRoute(sender: grpc.SharedChannelSender) !void {
    var value = try call(sender, "/fixture.Runtime/A");
    defer value.deinit();
    try std.testing.expect(value.status == .unavailable and value.transport == null and !value.was_dropped);
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();
    var control = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var discovery = try xds.ads.Client.init(gpa, control_sender, .{ .node = .{ .id = "netz-auto-xds" } });
    defer discovery.deinit();
    var destination = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    const controller = try xds.runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startWithDeadline(&discovery, destination, until(io));
    try std.testing.expectEqual(@as(usize, 0), destination.configuredEndpointCount());
    try discovery.connectWithDeadline(until(io));
    try apply(controller, &discovery, destination, io); // LDS -> RDS name
    try noRoute(sender);
    try apply(controller, &discovery, destination, io); // RDS -> two CDS names
    var waiting = try io.concurrent(first, .{sender});
    defer _ = waiting.cancel(io) catch {};
    try apply(controller, &discovery, destination, io); // CDS -> EDS names
    try apply(controller, &discovery, destination, io); // EDS -> endpoints
    var ready = try waiting.await(io);
    defer ready.deinit();
    try std.testing.expectEqualStrings("a", ready.message.?.payload);
    var b = try beta(sender);
    defer b.deinit();
    try std.testing.expectEqualStrings("b", b.message.?.payload);
    var active = try io.concurrent(held, .{sender});
    defer _ = active.cancel(io) catch {};
    const active_until = until(io);
    while ((try destination.clusterCircuitStats("cluster:a")).active == 0) {
        if (active_until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    var blocked = try first(sender);
    defer blocked.deinit();
    try std.testing.expect(blocked.was_dropped and blocked.transport == null);
    var independent = try beta(sender);
    defer independent.deinit();
    try std.testing.expectEqualStrings("b", independent.message.?.payload);
    var release = try call(sender, "/fixture.Runtime/Release");
    defer release.deinit();
    var held_reply = try active.await(io);
    defer held_reply.deinit();
    try std.testing.expectEqualStrings("a", held_reply.message.?.payload);
    try phase(&discovery, io, xds.eds.type_url, "phase-drop");
    try apply(controller, &discovery, destination, io);
    var dropped = try beta(sender);
    defer dropped.deinit();
    try std.testing.expect(dropped.was_dropped and std.mem.endsWith(u8, dropped.status_message, "b-drop"));
    var available = try first(sender);
    defer available.deinit();
    try std.testing.expectEqualStrings("a", available.message.?.payload);
    try phase(&discovery, io, xds.cds.type_url, "phase-name");
    try apply(controller, &discovery, destination, io);
    var new_b = try io.concurrent(beta, .{sender});
    defer _ = new_b.cancel(io) catch {};
    try apply(controller, &discovery, destination, io);
    var changed = try new_b.await(io);
    defer changed.deinit();
    try std.testing.expectEqualStrings("b", changed.message.?.payload);
    var old_route = try io.concurrent(held, .{sender});
    defer _ = old_route.cancel(io) catch {};
    const hold_until = until(io);
    while ((try destination.clusterCircuitStats("cluster:a")).active == 0) {
        if (hold_until.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    try phase(&discovery, io, xds.cds.type_url, "phase-bad");
    var invalid = try discovery.nextWithDeadline(until(io));
    defer invalid.deinit();
    const revision = destination.configurationRevision();
    try std.testing.expectError(error.DuplicateCdsResource, controller.applyWithDeadline(&discovery, invalid.update, destination, until(io)));
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try std.testing.expectEqualStrings("c2", discovery.acceptedVersion(xds.cds.type_url).?);
    try discovery.rejectWithDeadline(invalid.update, .{ .message = "DuplicateCdsResource" }, until(io));
    try apply(controller, &discovery, destination, io);
    var latest = try first(sender);
    defer latest.deinit();
    try std.testing.expectEqualStrings("b", latest.message.?.payload);
    var release_old = try call(sender, "/fixture.Runtime/Release");
    defer release_old.deinit();
    var old_reply = try old_route.await(io);
    defer old_reply.deinit();
    try std.testing.expectEqualStrings("a", old_reply.message.?.payload);
    try phase(&discovery, io, xds.lds.type_url, "phase-delete");
    try apply(controller, &discovery, destination, io);
    try noRoute(sender);
    var terminal = try discovery.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    std.debug.print("RUNTIME_RESULT {{\"status\":\"passed\",\"automatic_chain\":true,\"pending_discovery\":true,\"cluster_isolation\":true,\"drop_isolation\":true,\"service_name_switch\":true,\"nack_preserved\":true,\"listener_deleted\":true}}\n", .{});
}

//! Inline/dynamic LDS to RDS to actual unary/streaming application routing.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const lds = grpc.xds.lds;
const ads = grpc.xds.ads;
const allocator = std.heap.c_allocator;
const manager = "{\"loadBalancingConfig\":[{\"xds_cluster_manager_experimental\":{\"children\":{\"cluster:a\":{\"childPolicy\":[{\"round_robin\":{}}]},\"cluster:b\":{\"childPolicy\":[{\"round_robin\":{}}]}}}}]}";
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn apply(controller: *lds.Controller, client: *ads.Client, channel: grpc.SharedChannel, io: std.Io) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    _ = try controller.applyWithDeadline(client, event.update, channel, until(io));
}
fn phase(client: *ads.Client, io: std.Io, name: []const u8) !void {
    try client.setSubscription(lds.type_url, &.{ "frontend", name });
    _ = try client.flushWithDeadline(until(io));
}
fn call(sender: grpc.SharedChannelSender, path: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = path, .authority = "backend.test", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}
fn slow(sender: grpc.SharedChannelSender) !grpc.UnaryResponse {
    return call(sender, "/fixture.Lds/Slow");
}
fn fast(sender: grpc.SharedChannelSender, label: []const u8) !void {
    for (0..5) |_| {
        var response = try call(sender, "/fixture.Lds/Fast");
        defer response.deinit();
        try std.testing.expectEqualStrings(label, response.message.?.payload);
    }
}
fn timeout(sender: grpc.SharedChannelSender, io: std.Io, milliseconds: u32) !void {
    const started = std.Io.Clock.awake.now(io);
    var result: ?grpc.UnaryResponse = slow(sender) catch |err| blk: {
        try std.testing.expect(err == error.Timeout);
        break :blk null;
    };
    if (result) |*response| {
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.deadline_exceeded, response.status);
    }
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < @as(i96, milliseconds) * std.time.ns_per_ms);
}
fn noRoute(sender: grpc.SharedChannelSender) !void {
    var response = try call(sender, "/fixture.Lds/Fast");
    defer response.deinit();
    try std.testing.expect(response.status == .unavailable and response.message == null and response.transport == null and !response.was_dropped);
}
fn deniedUnary(sender: grpc.SharedChannelSender) !void {
    var response = try sender.unary(.{ .path = "/fixture.Lds/Fast", .authority = "backend.test", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second }, .metadata = &.{.{ .name = "x-deny", .value = "1" }} });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.permission_denied, response.status);
    try std.testing.expect(response.message == null and response.transport == null and !response.was_dropped);
}
fn deniedStream(sender: grpc.SharedChannelSender) !void {
    try std.testing.expectError(error.PermissionDenied, sender.startDuplex(.{ .path = "/fixture.Lds/Stream", .authority = "backend.test", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second }, .metadata = &.{.{ .name = "x-deny", .value = "1" }} }));
}
fn headerAllowed(sender: grpc.SharedChannelSender, label: []const u8) !void {
    var response = try sender.unary(.{ .path = "/fixture.Lds/Fast", .authority = "backend.test", .message = "request", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second }, .metadata = &.{.{ .name = "x-deny", .value = "1" }} });
    defer response.deinit();
    try std.testing.expectEqualStrings(label, response.message.?.payload);
}
fn stream(sender: grpc.SharedChannelSender, label: []const u8) !void {
    var duplex = try sender.startDuplex(.{ .path = "/fixture.Lds/Stream", .authority = "backend.test", .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
    defer duplex.deinit();
    var writer = duplex.writer();
    defer writer.deinit();
    var reader = duplex.reader();
    defer reader.deinit();
    try writer.writeFinalMessage("request");
    var count: usize = 0;
    while (true) {
        var event = try reader.nextWithTimeout(.fromSeconds(3));
        defer event.deinit(allocator);
        switch (event) {
            .message => |message| {
                try std.testing.expectEqualStrings(label, message.payload);
                count += 1;
            },
            .terminal => |terminal| {
                try std.testing.expectEqual(grpc.Status.ok, terminal.status);
                try std.testing.expectEqual(@as(usize, 1), count);
                return;
            },
            else => {},
        }
    }
}
fn reject(controller: *lds.Controller, client: *ads.Client, destination: grpc.SharedChannel, io: std.Io, expected: lds.Error) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    const revision = destination.configurationRevision();
    try std.testing.expectError(expected, controller.applyWithDeadline(client, event.update, destination, until(io)));
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try std.testing.expectEqualStrings("l3", client.acceptedVersion(lds.type_url).?);
    try client.rejectWithDeadline(event.update, .{ .message = @errorName(expected) }, until(io));
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var control = try grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var client = try ads.Client.init(allocator, control_sender, .{ .node = .{ .id = "netz-lds-node" } });
    defer client.deinit();
    var controller = try lds.Controller.init(allocator, .{ .listener_name = "frontend", .authority = "backend.test" });
    defer controller.deinit();
    try controller.subscribe(&client);
    try client.connectWithDeadline(until(io));
    var endpoints: [2]grpc.ChannelEndpoint = undefined;
    for (&endpoints, args[2..], 0..) |*endpoint, port, index| endpoint.* = .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, port, 10)) }, .hierarchical_path = if (index == 0) &.{"cluster:a"} else &.{"cluster:b"} } };
    var destination = try grpc.SharedChannel.init(allocator, io, .{ .resolved = .{ .endpoints = &endpoints } }, .{ .service_config_json = manager });
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    try apply(&controller, &client, destination, io); // l1 inline
    try fast(sender, "a");
    try deniedUnary(sender);
    try deniedStream(sender);
    try stream(sender, "a");
    try timeout(sender, io, 150);
    var uncapped = try call(sender, "/fixture.Lds/NoCap");
    defer uncapped.deinit();
    try std.testing.expectEqualStrings("a", uncapped.message.?.payload);
    try phase(&client, io, "phase-rds");
    try apply(&controller, &client, destination, io); // l2 dynamic, clear inline
    try noRoute(sender);
    try apply(&controller, &client, destination, io); // r1
    try fast(sender, "b");
    try stream(sender, "b");
    const cached = controller.routes.?;
    var old = try io.concurrent(slow, .{sender});
    defer _ = old.cancel(io) catch {};
    try apply(&controller, &client, destination, io); // l3, same RDS -> cached projection
    try std.testing.expect(controller.routes.? == cached);
    try timeout(sender, io, 100);
    var completed = try old.await(io);
    defer completed.deinit();
    try std.testing.expectEqualStrings("b", completed.message.?.payload);
    try phase(&client, io, "phase-bad");
    try reject(&controller, &client, destination, io, error.InvalidLdsResource);
    try reject(&controller, &client, destination, io, error.UnsupportedLdsFeature);
    try reject(&controller, &client, destination, io, error.InvalidLdsResource);
    try apply(&controller, &client, destination, io); // l4 new RDS name
    try noRoute(sender);
    try apply(&controller, &client, destination, io); // r2 old name cannot restore
    try noRoute(sender);
    try apply(&controller, &client, destination, io); // r3 new matching resource
    try fast(sender, "a");
    try phase(&client, io, "phase-inline");
    try apply(&controller, &client, destination, io); // l5 inline
    try fast(sender, "b");
    try headerAllowed(sender, "b");
    const revision = destination.configurationRevision();
    try apply(&controller, &client, destination, io); // r4 ignored in inline mode
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try fast(sender, "b");
    try phase(&client, io, "phase-delete");
    try apply(&controller, &client, destination, io); // l6 omission
    try noRoute(sender);
    const removed = destination.configurationRevision();
    try apply(&controller, &client, destination, io); // r5 ignored after deletion
    try std.testing.expectEqual(removed, destination.configurationRevision());
    try noRoute(sender);
    var terminal = try client.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    std.debug.print("LDS_RESULT {{\"status\":\"passed\",\"inline\":true,\"dynamic\":true,\"cached_projection\":true,\"zero_override\":true,\"old_deadline_preserved\":true,\"name_change_cleared\":true,\"late_rds_ignored\":true,\"deleted\":true,\"rbac_denied\":true,\"rbac_stream_denied\":true,\"rbac_header_scope\":true,\"nacks\":3}}\n", .{});
}

const std = @import("std");
const netz = @import("netz");
const ads = netz.grpc.xds.ads;
const cds = netz.grpc.xds.cds;
const eds = netz.grpc.xds.eds;
const allocator = std.heap.c_allocator;
fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn apply(controller: *cds.Controller, client: *ads.Client, destination: netz.grpc.SharedChannel, io: std.Io) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    _ = try controller.applyWithDeadline(client, event.update, destination, until(io));
}
fn trigger(client: *ads.Client, type_url: []const u8, name: []const u8, phase: []const u8, io: std.Io) !void {
    try client.setSubscription(type_url, &.{ name, phase });
    _ = try client.flushWithDeadline(until(io));
}
fn reject(controller: *cds.Controller, client: *ads.Client, destination: netz.grpc.SharedChannel, io: std.Io, expected: cds.Error, version: []const u8) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    const revision = destination.configurationRevision();
    try std.testing.expectError(expected, controller.applyWithDeadline(client, event.update, destination, until(io)));
    try std.testing.expectEqual(revision, destination.configurationRevision());
    try std.testing.expectEqualStrings(version, client.acceptedVersion(event.update.response.value.type_url).?);
    try client.rejectWithDeadline(event.update, .{ .message = @errorName(expected) }, until(io));
}
fn call(sender: netz.grpc.SharedChannelSender, hash: ?u64) !netz.grpc.UnaryResponse {
    return sender.unary(.{ .path = "/fixture.Cds/Unary", .message = "request", .request_hash = hash, .wait_for_ready = true, .timeout = .{ .value = 3, .unit = .second } });
}
fn count(sender: netz.grpc.SharedChannelSender, amount: usize, hashes: bool) ![2]usize {
    var counts = [_]usize{ 0, 0 };
    for (0..amount) |index| {
        const hash: ?u64 = if (hashes) std.hash.XxHash64.hash(0, std.mem.asBytes(&index)) else null;
        var response = try call(sender, hash);
        defer response.deinit();
        const slot: usize = if (std.mem.eql(u8, response.message.?.payload, "a")) 0 else if (std.mem.eql(u8, response.message.?.payload, "b")) 1 else return error.UnexpectedBackend;
        counts[slot] += 1;
        if (hashes) {
            var repeated = try call(sender, hash);
            defer repeated.deinit();
            try std.testing.expectEqualStrings(response.message.?.payload, repeated.message.?.payload);
            counts[slot] += 1;
        }
    }
    return counts;
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var control = try netz.grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var discovery = try ads.Client.init(allocator, control_sender, .{ .node = .{ .id = "netz-cds-node" } });
    defer discovery.deinit();
    var controller = try cds.Controller.init(allocator, .{ .cluster_name = "backend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    try controller.subscribe(&discovery);
    try discovery.connectWithDeadline(until(io));
    var destination = try netz.grpc.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    try apply(&controller, &discovery, destination, io); // c1, await service-a
    try std.testing.expectEqual(@as(usize, 0), destination.configuredEndpointCount());
    try apply(&controller, &discovery, destination, io); // e1
    destination.connect();
    for (0..2) |index| {
        var watch = destination.watchEndpointConnectivity(index).?;
        defer watch.deinit();
        while (watch.snapshot().state != .ready) _ = try watch.nextWithTimeout(.fromSeconds(3));
    }
    const locality = try count(sender, 160, false);
    try std.testing.expect(locality[1] > 95 and locality[1] < 145);
    try trigger(&discovery, cds.type_url, "backend", "phase-close", io);
    try apply(&controller, &discovery, destination, io); // c2, same EDS, ring + zero
    try std.testing.expect(!controller.cluster.?.value.policy.locality_weighted);
    try std.testing.expectEqual(@as(usize, 2), destination.configuredEndpointCount());
    var dropped = try call(sender, 1);
    defer dropped.deinit();
    try std.testing.expectEqual(netz.grpc.Status.unavailable, dropped.status);
    try std.testing.expect(dropped.was_dropped and dropped.message == null);
    try trigger(&discovery, cds.type_url, "backend", "phase-open", io);
    try apply(&controller, &discovery, destination, io); // c3, ring reopened
    const ring = try count(sender, 40, true);
    try std.testing.expect(ring[0] != 0 and ring[1] != 0);
    try trigger(&discovery, cds.type_url, "backend", "phase-bad", io);
    try reject(&controller, &discovery, destination, io, error.InvalidCdsResource, "c3");
    try reject(&controller, &discovery, destination, io, error.DuplicateCdsResource, "c3");
    try reject(&controller, &discovery, destination, io, error.UnsupportedCdsFeature, "c3");
    try apply(&controller, &discovery, destination, io); // c4, typed WrrLocality + new EDS
    try std.testing.expectEqual(@as(usize, 0), destination.configuredEndpointCount());
    try std.testing.expectEqualStrings("service-b", controller.cluster.?.value.edsName());
    try std.testing.expect(controller.cluster.?.value.policy.locality_weighted);
    try apply(&controller, &discovery, destination, io); // e2, only b
    const switched = try count(sender, 20, false);
    try std.testing.expectEqual(@as(usize, 20), switched[1]);
    try trigger(&discovery, eds.type_url, "service-b", "phase-eds-bad", io);
    try reject(&controller, &discovery, destination, io, error.InvalidEdsResource, "e2");
    try apply(&controller, &discovery, destination, io); // c5, cluster deleted
    try std.testing.expect(controller.cluster == null);
    try apply(&controller, &discovery, destination, io); // late EDS cannot restore
    try std.testing.expectEqual(@as(usize, 0), destination.configuredEndpointCount());
    try std.testing.expectError(error.ConnectionUnavailable, sender.unary(.{ .path = "/fixture.Cds/Unary", .message = "request", .wait_for_ready = false }));
    var terminal = try discovery.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(netz.grpc.Status.ok, terminal.terminal.status);
    std.debug.print("CDS_RESULT {{\"status\":\"passed\",\"locality\":[{d},{d}],\"ring\":[{d},{d}],\"switched\":[{d},{d}],\"nacks\":4,\"zero_limit_pre_wire\":true,\"cache_republished\":true,\"switch_cleared_old\":true,\"late_eds_ignored\":true}}\n", .{ locality[0], locality[1], ring[0], ring[1], switched[0], switched[1] });
}

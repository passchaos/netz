//! Production Managed federation, retained selectors, and automatic source LRS.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const xds = grpc.xds;
const gpa = std.heap.c_allocator;
const canary = "xdstp://A/envoy.config.cluster.v3.Cluster/canary";
const main_a = "xdstp://A/envoy.config.cluster.v3.Cluster/main";
const main_b = "xdstp://B/envoy.config.cluster.v3.Cluster/main";
const main_b_eds = "xdstp://B/envoy.config.endpoint.v3.ClusterLoadAssignment/main";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn configure(options: *xds.runtime.Options) void {
    options.automatic_lrs = .{ .poll_interval = .fromMilliseconds(25), .connect_timeout = .fromSeconds(2), .reporter = .{ .locality = .{ .region = "r", .zone = "z" } } };
}
fn gate(io: std.Io, port: u16) !grpc.SharedChannel {
    return grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(port) } } }, .{});
}
fn barrier(sender: grpc.SharedChannelSender, label: []const u8) !void {
    var response = try sender.unary(.{ .path = "/fixture.Federation/Barrier", .message = label, .timeout = .{ .value = 5, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings(label, response.message.?.payload);
}
fn app(sender: grpc.SharedChannelSender, label: []const u8, source: []const u8, is_canary: bool) !void {
    var response = try sender.unary(.{ .path = if (is_canary) "/fixture.Federation/Canary" else "/fixture.Federation/Main", .message = label, .wait_for_ready = false, .timeout = .{ .value = if (std.mem.eql(u8, label, "held-b")) 25 else 5, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    const expected = try std.fmt.allocPrint(gpa, "{s}:{s}", .{ source, label });
    defer gpa.free(expected);
    try std.testing.expectEqualStrings(expected, response.message.?.payload);
}
fn index(managed: anytype, name: []const u8) !usize {
    for (managed.controller.entries.items, 0..) |item, i| if (std.mem.eql(u8, item.identity.name, name)) return i;
    return error.MissingClusterEntry;
}
fn desiredContains(managed: anytype, name: []const u8) bool {
    for (managed.registry.desired.items) |watch| for (watch.values) |value| {
        if (std.mem.eql(u8, value, name)) return true;
    };
    return false;
}
fn apply(managed: anytype, data: grpc.SharedChannel, io: std.Io, reject: bool) !void {
    var event = try managed.nextWithDeadline(deadline(io));
    defer event.deinit();
    const received = try event.result;
    try std.testing.expect(received == .update);
    const revision = data.configurationRevision();
    if (reject) {
        try std.testing.expectError(error.UnsupportedCdsFeature, managed.applyWithDeadline(&event, deadline(io)));
        try std.testing.expectEqual(revision, data.configurationRevision());
        try managed.rejectWithDeadline(&event, "UnsupportedCdsFeature", deadline(io));
    } else _ = try managed.applyWithDeadline(&event, deadline(io));
    const record = try std.json.Stringify.valueAlloc(gpa, .{ .authority = event.authority(), .type_url = received.update.response.value.type_url, .nonce = received.update.response.value.nonce, .rejected = reject, .revision = data.configurationRevision() }, .{});
    defer gpa.free(record);
    std.debug.print("FEDERATION_EVENT {s}\n", .{record});
}
fn status(managed: anytype, phase: []const u8, excluded: bool) !void {
    const snapshot = try managed.fetchClientStatus(gpa, if (excluded) "\x18\x01" else "", .{});
    defer gpa.free(snapshot);
    const encoded = try gpa.alloc(u8, std.base64.standard.Encoder.calcSize(snapshot.len));
    defer gpa.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, snapshot);
    const record = try std.json.Stringify.valueAlloc(gpa, .{ .phase = phase, .bytes = encoded }, .{});
    defer gpa.free(record);
    std.debug.print("FEDERATION_CSDS {s}\n", .{record});
}
fn run(comptime mode: xds.runtime.managed.Mode, io: std.Io, configuration: *xds.bootstrap.Bootstrap, port_a: u16, port_b: u16) !void {
    var data = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer data.deinit();
    var sender = data.sender();
    defer sender.deinit();
    const Managed = xds.runtime.managed.Managed(mode);
    const managed = try Managed.createForTarget(gpa, io, configuration, data, "xds://A/service", .{ .configure = configure });
    defer managed.deinit();
    var control_a = try gate(io, port_a);
    defer control_a.deinit();
    var gate_a = control_a.sender();
    defer gate_a.deinit();
    var control_b = try gate(io, port_b);
    defer control_b.deinit();
    var gate_b = control_b.sender();
    defer gate_b.deinit();
    try std.testing.expect(managed.controller.options.lrs == null);
    try std.testing.expect(data.state.lrs_stats.allocator == null);
    _ = try managed.startWithDeadline(deadline(io));
    try std.testing.expectEqual(@as(usize, 0), data.configuredEndpointCount());
    for (0..6) |_| try apply(managed, data, io, false);
    try std.testing.expectEqual(@as(usize, 2), data.configuredEndpointCount());
    const b_cluster = managed.controller.entries.items[try index(managed, main_b)].cluster.?;
    b_cluster.retain();
    defer b_cluster.release();
    const b_snapshot = managed.controller.entries.items[try index(managed, main_b)].snapshot.?;
    b_snapshot.retain();
    defer b_snapshot.release();
    const source_b = b_cluster.discovery_source.?;
    _ = source_b.retain();
    defer source_b.release();
    const source_a = managed.controller.entries.items[try index(managed, canary)].cluster.?.discovery_source.?;
    _ = source_a.retain();
    defer source_a.release();
    try std.testing.expect(source_b.server.ignore_resource_deletion);
    try std.testing.expect(!source_a.server.ignore_resource_deletion);
    try std.testing.expect(!std.mem.eql(u8, source_a.key, source_b.key));
    try app(sender, "initial-b", "B", false);
    try app(sender, "initial-canary-a", "A", true);
    var held = try io.concurrent(app, .{ sender, "held-b", "B", false });
    defer _ = held.cancel(io) catch {};
    try barrier(gate_b, "held-entered");

    try barrier(gate_b, "omit-b");
    try apply(managed, data, io, false);
    try std.testing.expect(managed.controller.entries.items[try index(managed, main_b)].cluster.? == b_cluster);
    try std.testing.expect(managed.controller.entries.items[try index(managed, main_b)].snapshot.? == b_snapshot);
    try app(sender, "b-omission", "B", false);
    try barrier(gate_a, "omit-a");
    try apply(managed, data, io, false);
    try std.testing.expect(managed.controller.entries.items[try index(managed, canary)].cluster == null);
    try std.testing.expect(managed.controller.entries.items[try index(managed, main_b)].cluster.? == b_cluster);
    try std.testing.expect(managed.controller.entries.items[try index(managed, main_b)].snapshot.? == b_snapshot);
    try app(sender, "a-omission-b", "B", false);
    try barrier(gate_a, "restore-a");
    try apply(managed, data, io, false);
    try apply(managed, data, io, false);
    try app(sender, "restored-canary-a", "A", true);
    try barrier(gate_a, "malformed-a");
    try apply(managed, data, io, true);
    try status(managed, "nacked", false);
    try status(managed, "excluded", true);
    try std.testing.expect(managed.controller.entries.items[try index(managed, main_b)].cluster.? == b_cluster);
    try std.testing.expect(managed.controller.entries.items[try index(managed, main_b)].snapshot.? == b_snapshot);
    try app(sender, "nack-b", "B", false);

    const retained_revision = data.configurationRevision();
    try barrier(gate_b, "switch-route");
    try apply(managed, data, io, false);
    try std.testing.expectEqual(retained_revision, data.configurationRevision());
    try app(sender, "pending-rds-b", "B", false);
    try barrier(gate_a, "complete-a-cds");
    try apply(managed, data, io, false);
    try std.testing.expectEqual(retained_revision, data.configurationRevision());
    try app(sender, "pending-cds-b", "B", false);
    try barrier(gate_a, "complete-a-eds");
    try apply(managed, data, io, false);
    try std.testing.expect(data.configurationRevision() > retained_revision);
    try app(sender, "replacement-a", "A", false);
    const active_source = managed.controller.entries.items[try index(managed, main_a)].cluster.?.discovery_source.?;
    try std.testing.expectEqualSlices(u8, source_a.key, active_source.key);
    try barrier(gate_b, "release-held");
    try held.await(io);
    _ = try managed.synchronizeWithDeadline(deadline(io));
    try std.testing.expect(!desiredContains(managed, main_b));
    try std.testing.expect(!desiredContains(managed, main_b_eds));
    try barrier(gate_b, "final-reports");
    try status(managed, "final", false);
    var bytes_a: [32]u8 = undefined;
    var bytes_b: [32]u8 = undefined;
    @memcpy(&bytes_a, source_a.key);
    @memcpy(&bytes_b, source_b.key);
    const key_a = std.fmt.bytesToHex(bytes_a, .lower);
    const key_b = std.fmt.bytesToHex(bytes_b, .lower);
    std.debug.print("FEDERATION_RESULT {{\"status\":\"passed\",\"mode\":\"{s}\",\"source_a\":\"{s}\",\"source_b\":\"{s}\",\"managed_resource_routing\":true,\"source_features_isolated\":true,\"foreign_cache_preserved\":true,\"pending_route_retained\":true,\"held_completion_retained_b\":true,\"automatic_lrs\":true,\"manual_subscription_routing\":false}}\n", .{ @tagName(mode), key_a, key_b });
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 5) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, args[1], gpa, .limited(1024 * 1024));
    defer gpa.free(bytes);
    const configuration = try xds.bootstrap.parse(gpa, bytes, .{});
    defer configuration.deinit();
    const a = try std.fmt.parseInt(u16, args[2], 10);
    const b = try std.fmt.parseInt(u16, args[3], 10);
    if (std.mem.eql(u8, args[4], "sotw")) try run(.sotw, io, configuration, a, b) else if (std.mem.eql(u8, args[4], "delta")) try run(.delta, io, configuration, a, b) else return error.InvalidArguments;
}

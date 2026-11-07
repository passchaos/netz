//! Automatic source-pinned LRS with actual managed discovery and app traffic.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const xds = grpc.xds;
const ads = xds.ads;
const runtime = xds.runtime;
const Plane = xds.control_plane.ControlPlane;
const gpa = std.heap.c_allocator;
const node: ads.codec.Node = .{ .id = "managed-automatic-node", .client_features = &.{"fixture.automatic_lrs"} };

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
fn plane(io: std.Io, port: u16) !*Plane {
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"bootstrap-node\"}}}}", .{port});
    defer gpa.free(json);
    const configuration = try xds.bootstrap.parse(gpa, json, .{});
    defer configuration.deinit();
    return Plane.init(gpa, io, configuration, .{});
}
fn request(comptime marker: []const u8) grpc.StreamingRequestOptions {
    return .{ .path = ads.path, .wait_for_ready = true, .metadata = &.{.{ .name = "x-source", .value = marker }} };
}
fn destination(io: std.Io) !grpc.SharedChannel {
    return grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
}
fn controller() !*runtime.Controller {
    return runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
        .automatic_lrs = .{ .poll_interval = .fromMilliseconds(25), .connect_timeout = .fromSeconds(2), .reporter = .{ .locality = .{ .region = "r", .zone = "z" } } },
    });
}
fn applyNext(owner: *runtime.Controller, client: *ads.Client, data: grpc.SharedChannel, until: std.Io.Clock.Timestamp) !void {
    var event = try client.nextWithDeadline(until);
    defer event.deinit();
    try std.testing.expect(event == .update);
    _ = try owner.applyWithDeadline(client, event.update, data, until);
}
fn setup(owner: *runtime.Controller, client: *ads.Client, data: grpc.SharedChannel, until: std.Io.Clock.Timestamp) !void {
    try std.testing.expect(data.state.lrs_stats.allocator == null);
    try std.testing.expect(owner.options.lrs == null);
    _ = try owner.startWithDeadline(client, data, until);
    try client.connectWithDeadline(until);
    try applyNext(owner, client, data, until); // LDS inline routes.
    try applyNext(owner, client, data, until); // CDS enables only eligible.
    try applyNext(owner, client, data, until); // EDS routes both clusters.
    try std.testing.expect(data.state.lrs_stats.allocator != null);
}
fn selection(data: grpc.SharedChannel, expected: []const u8, io: std.Io) !void {
    data.state.lrs_stats.mutex.lockUncancelable(io);
    defer data.state.lrs_stats.mutex.unlock(io);
    const selected = data.state.lrs_stats.selection orelse return error.MissingAutomaticSelection;
    const identity = selected.find("eligible", "eds-eligible") orelse return error.MissingAutomaticIdentity;
    try std.testing.expectEqualSlices(u8, expected, identity.source_key);
    try std.testing.expect(selected.find("ignored", "eds-ignored") == null);
}
fn barrier(sender: grpc.SharedChannelSender, name: []const u8) !void {
    var response = try sender.unary(.{ .path = "/fixture.Automatic/Barrier", .message = name, .wait_for_ready = true, .timeout = .{ .value = 5, .unit = .second } });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings(name, response.message.?.payload);
}
fn app(sender: grpc.SharedChannelSender, name: []const u8, eligible: bool, expected: grpc.Status) !void {
    var response = try sender.unary(.{
        .path = if (eligible) "/fixture.Automatic/Eligible" else "/fixture.Automatic/Ignored",
        .message = name,
        .metadata = &.{.{ .name = "x-call", .value = name }},
        .wait_for_ready = true,
        .timeout = .{ .value = if (std.mem.eql(u8, name, "held")) 15 else 5, .unit = .second },
    });
    defer response.deinit();
    try std.testing.expectEqual(expected, response.status);
    if (expected == .ok) try std.testing.expectEqualStrings(name, response.message.?.payload) else try std.testing.expect(response.message == null);
}
fn hexKey(key: []const u8) ![64]u8 {
    try std.testing.expectEqual(@as(usize, 32), key.len);
    var bytes: [32]u8 = undefined;
    @memcpy(&bytes, key);
    return std.fmt.bytesToHex(bytes, .lower);
}

fn provenance(io: std.Io, a: *Plane, b: *Plane) !void {
    var discovery = try a.newSotwClient(.{ .node = node, .request = request("A") });
    defer discovery.deinit();
    const source_a = discovery.source.?.retain();
    defer source_a.release();
    var data = try destination(io);
    defer data.deinit();
    const owner = try controller();
    defer owner.deinit();
    try setup(owner, &discovery, data, deadline(io));
    try selection(data, source_a.key, io);
    var sender = data.sender();
    defer sender.deinit();
    var gate = a.sender();
    defer gate.deinit();
    try app(sender, "first", true, .ok);
    try app(sender, "ignored-a", false, .ok);
    var held = try io.concurrent(app, .{ sender, "held", true, grpc.Status.ok });
    defer _ = held.cancel(io) catch {};
    try barrier(gate, "held-entered");

    const transition = deadline(io);
    try b.rebindSotw(&discovery, request("B"));
    const source_b = discovery.source.?.retain();
    defer source_b.release();
    try std.testing.expect(!std.mem.eql(u8, source_a.key, source_b.key));
    try discovery.connectWithDeadline(transition);
    _ = try owner.synchronizeWithDeadline(&discovery, data, transition);
    try applyNext(owner, &discovery, data, transition); // B EDS, cached A CDS.
    try std.testing.expectEqualStrings("c-a", discovery.acceptedVersion(xds.cds.type_url).?);
    try selection(data, source_a.key, io);
    try app(sender, "cached", true, .ok);
    try barrier(gate, "cached-source-a"); // Exact A counts and no B LRS.

    var gate_b = b.sender();
    defer gate_b.deinit();
    try barrier(gate_b, "send-b-nack");
    const rejection = deadline(io);
    var bad = try discovery.nextWithDeadline(rejection);
    defer bad.deinit();
    try std.testing.expect(bad == .update);
    const revision = data.configurationRevision();
    try std.testing.expectError(error.UnsupportedCdsFeature, owner.applyWithDeadline(&discovery, bad.update, data, rejection));
    try std.testing.expectEqual(revision, data.configurationRevision());
    try std.testing.expectEqualStrings("c-a", discovery.acceptedVersion(xds.cds.type_url).?);
    try discovery.rejectWithDeadline(bad.update, .{ .message = "UnsupportedCdsFeature" }, rejection);
    try selection(data, source_a.key, io);
    try barrier(gate_b, "send-b-replacement");
    try applyNext(owner, &discovery, data, deadline(io)); // Same CDS bytes, new source.
    try std.testing.expectEqualStrings("c-b", discovery.acceptedVersion(xds.cds.type_url).?);
    try selection(data, source_b.key, io);
    try app(sender, "new", true, .unavailable);
    try app(sender, "ignored-b", false, .ok);
    try barrier(gate_b, "release-held-after-b-report");
    try held.await(io);
    try barrier(gate, "final-source-reports");
    const key_a = try hexKey(source_a.key);
    const key_b = try hexKey(source_b.key);
    std.debug.print("AUTOMATIC_LRS_PROVENANCE {{\"source_a\":\"{s}\",\"source_b\":\"{s}\",\"cached_cds_retained_a\":true,\"identical_replacement_moved_to_b\":true,\"held_completion_retained_a\":true,\"nack_preserved_a\":true,\"default_stats_enabled_automatically\":true,\"explicit_lrs_options\":false}}\n", .{ key_a, key_b });
}

fn refused(io: std.Io, c: *Plane) !void {
    var discovery = try c.newSotwClient(.{ .node = node, .request = request("C") });
    defer discovery.deinit();
    var data = try destination(io);
    defer data.deinit();
    const owner = try controller();
    defer owner.deinit();
    try std.testing.expect(data.state.lrs_stats.allocator == null and owner.options.lrs == null);
    const startup = deadline(io);
    _ = try owner.startWithDeadline(&discovery, data, startup);
    try discovery.connectWithDeadline(startup);
    try applyNext(owner, &discovery, data, startup);
    var event = try discovery.nextWithDeadline(startup);
    defer event.deinit();
    try std.testing.expect(event == .update);
    const publication = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(250) });
    const until = if (std.Io.Clock.Timestamp.compare(publication, .lt, startup)) publication else startup;
    const revision = data.configurationRevision();
    _ = try owner.applyWithDeadline(&discovery, event.update, data, until);
    try std.testing.expect(data.configurationRevision() > revision);
    try std.testing.expectEqualStrings("c-c", discovery.acceptedVersion(xds.cds.type_url).?);
    try applyNext(owner, &discovery, data, startup);
    var sender = data.sender();
    defer sender.deinit();
    try app(sender, "refused-lrs-published", true, .ok);
    try selection(data, discovery.source.?.key, io);
    var snapshot = try data.lrsStatsSnapshot(gpa);
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(usize, 1), snapshot.entries.len);
    const entry = snapshot.entries[0];
    try std.testing.expectEqualStrings("eligible", entry.cluster);
    try std.testing.expectEqualStrings("eds-eligible", entry.service_name);
    try std.testing.expectEqualSlices(u8, discovery.source.?.key, entry.source_key);
    try std.testing.expectEqual(@as(u64, 1), entry.issued);
    try std.testing.expectEqual(@as(u64, 1), entry.successful);
    try std.testing.expectEqual(@as(u64, 0), entry.error_requests);
    try std.testing.expectEqual(@as(u64, 1), entry.cpu_utilization.count);
    std.debug.print("AUTOMATIC_LRS_REFUSED {{\"accepted_cds_before_lrs_network\":true,\"publication_budget_ms\":250,\"collection_issued\":1,\"collection_successful\":1,\"source_key\":\"{s}\"}}\n", .{try hexKey(discovery.source.?.key)});
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.init(gpa);
    defer backend.deinit();
    const io = backend.io();
    const a = try plane(io, try std.fmt.parseInt(u16, args[1], 10));
    defer a.deinit();
    const b = try plane(io, try std.fmt.parseInt(u16, args[2], 10));
    defer b.deinit();
    const c = try plane(io, try std.fmt.parseInt(u16, args[3], 10));
    defer c.deinit();
    try provenance(io, a, b);
    try refused(io, c);
    std.debug.print("AUTOMATIC_LRS_RESULT {{\"status\":\"passed\",\"mode\":\"sotw\",\"managed_factory\":true,\"real_application_traffic\":true,\"source_pinned_reports\":true,\"unavailable_lrs_did_not_block_publication\":true}}\n", .{});
}

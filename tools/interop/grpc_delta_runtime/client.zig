//! Typed delta LDS/RDS/CDS/EDS discovery drives real application RPCs.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const xds = grpc.xds;
const delta = xds.ads.delta;
const gpa = std.heap.c_allocator;

fn until(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

fn apply(controller: *xds.runtime.Controller, client: *delta.Client, destination: grpc.SharedChannel, io: std.Io) !void {
    var event = try client.nextWithDeadline(until(io));
    defer event.deinit();
    if (event != .update) return error.EndedEarly;
    _ = try controller.applyDeltaWithDeadline(client, event.update, destination, until(io));
}

fn call(sender: grpc.SharedChannelSender, path: []const u8) !grpc.UnaryResponse {
    return sender.unary(.{ .path = path, .message = "request", .authority = "backend.test", .wait_for_ready = false, .timeout = .{ .value = 4, .unit = .second } });
}

fn expectAvailable(sender: grpc.SharedChannelSender) !void {
    var value = try call(sender, "/fixture.Runtime/A");
    defer value.deinit();
    try std.testing.expectEqualStrings("a", value.message.?.payload);
}

fn expectUnavailable(sender: grpc.SharedChannelSender) !void {
    var value = call(sender, "/fixture.Runtime/A") catch |err| switch (err) {
        // An explicit EDS removal leaves the cluster selected but without a
        // ready endpoint; listener deletion rejects the route earlier.
        error.ConnectionUnavailable => return,
        else => return err,
    };
    defer value.deinit();
    try std.testing.expect(value.status == .unavailable and value.transport == null);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();
    var control = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[2], 10)) } } }, .{});
    defer control.deinit();
    var control_sender = control.sender();
    defer control_sender.deinit();
    var destination = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) } } }, .{});
    defer destination.deinit();
    var sender = destination.sender();
    defer sender.deinit();
    var discovery = try delta.Client.init(gpa, control_sender, .{ .node = .{ .id = "netz-delta-runtime" } });
    defer discovery.deinit();
    const controller = try xds.runtime.Controller.create(gpa, .{ .listener_name = "frontend", .target = .{ .authority = "backend.test" } });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&discovery, destination, until(io));
    try discovery.connectWithDeadline(until(io));

    try apply(controller, &discovery, destination, io); // LDS listener -> RDS name
    try apply(controller, &discovery, destination, io); // RDS routes -> CDS cluster a
    try apply(controller, &discovery, destination, io); // CDS cluster a -> EDS service
    try apply(controller, &discovery, destination, io); // EDS assignment -> endpoints
    try std.testing.expectEqual(@as(usize, 1), destination.configuredEndpointCount());
    try expectAvailable(sender);

    try apply(controller, &discovery, destination, io); // explicit EDS removal
    try std.testing.expectEqual(@as(usize, 0), destination.configuredEndpointCount());
    try expectUnavailable(sender);

    try apply(controller, &discovery, destination, io); // EDS resource restored
    try std.testing.expectEqual(@as(usize, 1), destination.configuredEndpointCount());
    try expectAvailable(sender);

    try apply(controller, &discovery, destination, io); // explicit LDS removal
    try expectUnavailable(sender);

    var terminal = try discovery.nextWithDeadline(until(io));
    defer terminal.deinit();
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    std.debug.print("DELTA_RUNTIME_RESULT {{\"status\":\"passed\",\"typed_chain\":true,\"eds_removal\":true,\"eds_restore\":true,\"lds_removal\":true,\"reused_backend\":true}}\n", .{});
}

//! CSDS FetchClientStatus over a real h2c server connection.
const std = @import("std");
const grpc = @import("../mod.zig");
const xds_runtime = @import("runtime.zig");
const delta = @import("ads/delta.zig");
const lds = @import("lds.zig");
const rds = @import("rds.zig");
const lds_fixture = @import("lds/testing.zig");
const rds_fixture = @import("rds/testing.zig");
const csds_service = @import("csds_service.zig");
const gpa = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(3) });
}

fn deltaUpdate(client: *delta.Client, url: []const u8, nonce: []const u8, resources: []const delta.codec.Resource) !delta.Update {
    const encoded = try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = nonce, .resources = resources }, .{});
    defer gpa.free(encoded);
    var response = try delta.codec.decodeResponse(gpa, encoded, .{});
    errdefer response.deinit();
    return .{ .response = response, .token = try client.subscriptions.received(response.value) };
}

fn deltaPayload(url: []const u8, name: []const u8, version: []const u8, bytes: []const u8) delta.codec.Resource {
    return .{ .name = name, .version = version, .resource = .{ .type_url = url, .value = bytes } };
}

test "gRPC CSDS FetchClientStatus over a real h2c connection" {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try grpc.SharedChannel.init(gpa, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var discovery = try delta.Client.init(gpa, sender, .{ .node = .{ .id = "test" } });
    defer discovery.deinit();
    const controller = try xds_runtime.Controller.create(gpa, .{
        .listener_name = "frontend",
        .target = .{ .authority = "backend.test" },
    });
    defer controller.deinit();
    _ = try controller.startDeltaWithDeadline(&discovery, channel, deadline(io));

    const routes = try rds_fixture.encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
    defer gpa.free(routes);
    const listener = try lds_fixture.encode(gpa, .{ .inline_rds = routes });
    defer gpa.free(listener);
    var update = try deltaUpdate(&discovery, lds.type_url, "l1", &.{deltaPayload(lds.type_url, "frontend", "v1", listener)});
    defer update.deinit();
    try std.testing.expectError(error.AdsNotConnected, controller.applyDeltaWithDeadline(&discovery, update, channel, deadline(io)));

    var server = try grpc.runtime.Server.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();

    const Shared = struct {
        server: *grpc.runtime.Server,
        controller: *xds_runtime.Controller,
        discovery: *delta.Client,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            var request = connection.readUnary() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit();
            const handled = csds_service.respondFetch(
                &connection,
                &request,
                self.controller,
                self.discovery,
                gpa,
                "\x0a\x06node-1",
            ) catch |err| {
                self.err = err;
                return;
            };
            if (!handled) self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server, .controller = controller, .discovery = &discovery };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try grpc.runtime.Client.connect(
        gpa,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var response = try client.unary(.{
        .path = csds_service.fetch_path,
        .authority = "localhost",
        .message = "",
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    const payload = response.message.?.payload;
    try std.testing.expect(std.mem.indexOf(u8, payload, lds.type_url) != null);
    try std.testing.expect(std.mem.indexOf(u8, payload, "frontend") != null);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

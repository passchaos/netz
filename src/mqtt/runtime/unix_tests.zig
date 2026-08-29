const std = @import("std");
const mqtt = @import("../mod.zig");
const runtime = @import("../runtime.zig");

test "MQTT Unix server handles concurrent clients" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(io, &path_storage);
    const suffix = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/mqtt.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(allocator, io, address, .{
        .max_packet_size = 4096,
    });
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        result: ?runtime.ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.result = self.server.serveConcurrent(
                @This(),
                self,
                handle,
                2,
                .{ .protocol = .v5 },
            ) catch |err| {
                self.err = err;
                return;
            };
        }

        fn handle(
            self: *@This(),
            accepted: *runtime.AcceptedClient,
        ) runtime.Error!void {
            _ = self;
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(accepted.connection.allocator);
            const expected_payload = if (std.mem.eql(
                u8,
                accepted.connect.connect.client_id,
                "mqtt-unix-one",
            ))
                "one"
            else if (std.mem.eql(
                u8,
                accepted.connect.connect.client_id,
                "mqtt-unix-two",
            ))
                "two"
            else
                return error.UnexpectedPacket;
            if (publish.publish.qos != mqtt.QoS.at_least_once or
                !std.mem.eql(u8, publish.publish.topic, "unix/qos1") or
                !std.mem.eql(u8, publish.publish.payload, expected_payload))
            {
                return error.UnexpectedPacket;
            }
            try accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            );
            var disconnect = try accepted.connection.readDisconnect();
            disconnect.deinit(accepted.connection.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: std.Io.net.UnixAddress,
        client_id: []const u8,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.Client.connectUnix(
                self.allocator,
                self.io,
                self.address,
                .{ .protocol = .v5, .client_id = self.client_id },
            );
            defer client.close();
            try client.publish(
                "unix/qos1",
                self.payload,
                .{ .qos = .at_least_once },
            );
            try client.disconnect(0);
        }
    };
    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = address, .client_id = "mqtt-unix-one", .payload = "one" },
        .{ .allocator = allocator, .io = io, .address = address, .client_id = "mqtt-unix-two", .payload = "two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    client_one.join();
    client_two.join();

    thread.join();
    joined = true;
    defer if (shared.result) |*result| result.deinit();
    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "MQTT Unix server caller timeout bounds CONNECT admission" {
    if (comptime @import("builtin").os.tag == .windows) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const directory_len = try tmp.dir.realPath(io, &path_storage);
    const suffix = try std.fmt.bufPrint(
        path_storage[directory_len..],
        "/mqtt-timeout.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try runtime.UnixServer.listen(
        allocator,
        io,
        address,
        .{},
    );
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *runtime.UnixServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var pending = self.server.acceptPendingWithTimeout(
                .{},
                .fromMilliseconds(30),
            ) catch |err| {
                self.err = err;
                return;
            };
            pending.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try address.connect(io);
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
    try std.testing.expectError(
        error.Timeout,
        server.acceptPendingWithTimeout(.{}, .zero),
    );
}

const std = @import("std");
const mqtt = @import("../mod.zig");
const mqtt_ws = @import("../websocket_runtime.zig");

test "MQTT over WebSocket exchanges QoS 1 on a Unix socket" {
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
        "/mqtt-ws.sock",
        .{},
    );
    const full_path = path_storage[0 .. directory_len + suffix.len];
    const address = try std.Io.net.UnixAddress.init(full_path);
    var server = try mqtt_ws.UnixServer.listen(allocator, io, address, .{
        .limits = .{ .max_packet_size = 4096 },
        .max_head_bytes = 4096,
    });
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, full_path) catch {};
    }

    const Shared = struct {
        server: *mqtt_ws.UnixServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            var publish = accepted.connection.readPublish() catch |err| {
                self.err = err;
                return;
            };
            defer publish.deinit(self.server.allocator);
            if (publish.publish.qos != mqtt.QoS.at_least_once or
                !std.mem.eql(u8, publish.publish.topic, "unix/ws/qos1"))
            {
                self.err = error.UnexpectedPacket;
                return;
            }
            accepted.connection.writePubAck(
                publish.publish.packet_id.?,
                0,
            ) catch |err| {
                self.err = err;
                return;
            };
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                self.err = err;
                return;
            };
            disconnect.deinit(self.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try mqtt_ws.Client.connectUnix(allocator, io, address, .{
        .mqtt = .{ .protocol = .v5, .client_id = "mqtt-ws-unix" },
        .host = "localhost",
        .target = "/mqtt",
        .max_head_bytes = 4096,
    });
    defer client.close();
    try client.publish(
        "unix/ws/qos1",
        "local websocket",
        .{ .qos = .at_least_once },
    );
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

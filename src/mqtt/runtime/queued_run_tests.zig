const std = @import("std");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const netz_runtime = @import("../../runtime.zig");

const WorkerMode = enum { thread, io_task };

test "MQTT queued run workers report terminal handler failure" {
    try runQueuedWaitFailure(.thread);
    try runQueuedWaitFailure(.io_task);
}

fn runQueuedWaitFailure(worker_mode: WorkerMode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            self.release.waitUncancelable(self.server.io);
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            event: *reconnect.ClientEvent,
        ) !void {
            if (event.* == .connected) return error.TestExpectedError;
        }
    };

    var release: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .release = &release };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer {
        release.set(io);
        if (!server_joined) server_thread.join();
    }
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "queued-wait-failure" },
        .{},
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    const run_options: reconnect.RunQueuedOptions = .{
        .queue_capacity = 1,
        .serve = .{
            .poll = .{ .timeout = .fromSeconds(1) },
        },
    };
    var run = switch (worker_mode) {
        .thread => try client.runQueued(
            Handler,
            &handler,
            Handler.handle,
            run_options,
        ),
        .io_task => try client.runQueuedAsync(
            Handler,
            &handler,
            Handler.handle,
            run_options,
        ),
    };
    var run_deinitialized = false;
    defer {
        if (!run_deinitialized) _ = run.deinit();
    }

    const Waiter = struct {
        run: *reconnect.QueuedRun,
        terminal: ?anyerror = null,

        fn wait(self: *@This()) void {
            self.terminal = self.run.wait() catch |err| err;
        }
    };
    var waiter = Waiter{ .run = &run };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.wait, .{&waiter});
    const terminal = try run.waitTimeout(.fromSeconds(1));
    try std.testing.expectEqual(error.TestExpectedError, terminal.?);
    try std.testing.expect(run.isFinished());
    try std.testing.expectEqual(
        error.TestExpectedError,
        (try run.wait()).?,
    );
    waiter_thread.join();
    try std.testing.expectEqual(error.TestExpectedError, waiter.terminal.?);

    release.set(io);
    const deinit_result = run.deinit();
    run_deinitialized = true;
    try std.testing.expectEqual(error.TestExpectedError, deinit_result.?);
    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued event workers preserve timeout budget and clean result" {
    try runQueuedEventWait(.thread);
    try runQueuedEventWait(.io_task);
}

fn runQueuedEventWait(worker_mode: WorkerMode) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        release: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var accepted = self.server.accept(.{ .protocol = .v5 }) catch |err| {
                self.err = err;
                return;
            };
            defer accepted.deinit(self.server.allocator);
            self.release.waitUncancelable(self.server.io);
        }
    };
    var release: std.Io.Event = .unset;
    var shared = Shared{ .server = &server, .release = &release };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var server_joined = false;
    defer {
        release.set(io);
        if (!server_joined) server_thread.join();
    }
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "queued-wait-clean" },
        .{},
        &shutdown,
    );
    defer client.deinit();
    var events = try reconnect.ClientEventQueue.init(allocator, io, 1);
    defer events.deinit();
    const run_options: reconnect.RunQueuedOptions = .{
        .queue_capacity = 1,
        .serve = .{
            .poll = .{
                .timeout = .fromSeconds(1),
                .cancellation_check_interval = .fromMilliseconds(5),
            },
        },
    };
    var run = switch (worker_mode) {
        .thread => try client.runQueuedEvents(&events, run_options),
        .io_task => try client.runQueuedEventsAsync(&events, run_options),
    };
    var run_deinitialized = false;
    defer {
        if (!run_deinitialized) _ = run.deinit();
    }

    var connected = try events.receive();
    defer connected.deinit();
    try std.testing.expect(connected.value == .connected);
    try std.testing.expect(!run.isFinished());
    try std.testing.expectError(
        error.Timeout,
        run.waitTimeout(.fromMilliseconds(1)),
    );
    try std.testing.expectError(
        error.Timeout,
        run.waitWithDeadline(.{ .raw = .zero, .clock = .real }),
    );
    try std.testing.expect(!run.isFinished());

    run.stop();
    const terminal = try run.waitWithDeadline(.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    }));
    try std.testing.expect(terminal == null);
    try std.testing.expect(run.isFinished());

    release.set(io);
    try std.testing.expect(run.deinit() == null);
    run_deinitialized = true;
    server_thread.join();
    server_joined = true;
    if (shared.err) |err| return err;
}

test "MQTT queued async worker runs on zio std.Io" {
    const allocator = std.testing.allocator;
    var backend = try netz_runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept(.{ .protocol = .v5 });
            defer accepted.deinit(self.server.allocator);
            var publish = try accepted.connection.readPublish();
            defer publish.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "async/zio",
                publish.publish.topic,
            );
            try std.testing.expectEqualStrings(
                "executor",
                publish.publish.payload,
            );
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(self.server.allocator);
            try std.testing.expectEqual(
                @as(u8, 0),
                disconnect.disconnect.reason_code,
            );
        }
    };
    const Handler = struct {
        fn handle(
            _: *@This(),
            _: *reconnect.Client,
            _: *reconnect.ClientEvent,
        ) !void {}
    };

    var shared = Shared{ .server = &server };
    var server_task = io.async(Shared.run, .{&shared});
    defer server_task.cancel(io);
    var shutdown: std.Io.Event = .unset;
    var client = try reconnect.Client.init(
        allocator,
        io,
        server.address(),
        .{ .protocol = .v5, .client_id = "queued-async-zio" },
        .{},
        &shutdown,
    );
    defer client.deinit();
    var handler: Handler = .{};
    var run = try client.runQueuedAsync(
        Handler,
        &handler,
        Handler.handle,
        .{
            .queue_capacity = 2,
            .serve = .{
                .poll = .{ .timeout = .fromSeconds(1) },
            },
        },
    );
    var run_deinitialized = false;
    defer if (!run_deinitialized) {
        _ = run.deinit();
    };
    var completions = try reconnect.CompletionQueue.init(allocator, io, 2);
    defer completions.deinit();

    const publish_id = try run.publishQueued(
        &completions,
        "async/zio",
        "executor",
        .{},
    );
    var publish_completion = try completions.receive();
    defer publish_completion.deinit();
    try std.testing.expectEqual(
        publish_id,
        publish_completion.command_id,
    );
    switch (try publish_completion.result) {
        .publish => |packet_id| try std.testing.expect(packet_id == null),
        else => return error.UnexpectedPacket,
    }

    const disconnect_id = try run.disconnectQueued(
        &completions,
        0,
        &.{},
    );
    var disconnect_completion = try completions.receive();
    defer disconnect_completion.deinit();
    try std.testing.expectEqual(
        disconnect_id,
        disconnect_completion.command_id,
    );
    try std.testing.expect(try disconnect_completion.result == .disconnect);
    try std.testing.expect((try run.waitTimeout(.fromSeconds(1))) == null);
    try std.testing.expect(run.deinit() == null);
    run_deinitialized = true;

    server_task.await(io);
    if (shared.err) |err| return err;
}

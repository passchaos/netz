const std = @import("std");
const grpc = @import("../../mod.zig");
const shared = @import("../shared.zig");

test "gRPC SharedChannel weighted round robin follows OOB endpoint weights" {
    const weighted_calls = 200;
    const fallback_calls = 40;
    const total_calls = weighted_calls + fallback_calls;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var a_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer a_server.deinit();
    var b_server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer b_server.deinit();
    var completed: std.atomic.Value(usize) = .init(0);
    var a_stats: Server.Stats = .{};
    var b_stats: Server.Stats = .{};
    var a_task = io.async(Server.run, .{ &a_server, "a", 1.0, &completed, &a_stats, total_calls });
    defer _ = a_task.cancel(io) catch {};
    var b_task = io.async(Server.run, .{ &b_server, "b", 3.0, &completed, &b_stats, total_calls });
    defer _ = b_task.cancel(io) catch {};
    const endpoints = [_]grpc.ChannelEndpoint{
        .{ .cleartext_ip = .{ .address = a_server.address() } },
        .{ .cleartext_ip = .{ .address = b_server.address() } },
    };
    var client = try shared.SharedChannel.init(allocator, io, .{ .resolved = .{
        .policy = .weighted_round_robin,
        .endpoints = &endpoints,
    } }, .{ .service_config_json =
        \\{"loadBalancingConfig":[{"weighted_round_robin":{
        \\ "enableOobLoadReport":true,"oobReportingPeriod":"1s",
        \\ "blackoutPeriod":"0s","weightUpdatePeriod":"0.1s",
        \\ "weightExpirationPeriod":"2s"}}]}
    });
    var client_live = true;
    defer if (client_live) client.deinit();
    var a_watch = client.watchEndpointOrca(0).?;
    defer a_watch.deinit();
    var b_watch = client.watchEndpointOrca(1).?;
    defer b_watch.deinit();
    var sender = client.sender();
    var first_call = try io.concurrent(call, .{sender});
    defer _ = first_call.cancel(io) catch {};
    var second_call = try io.concurrent(call, .{sender});
    defer _ = second_call.cancel(io) catch {};
    try waitReport(&a_watch);
    try waitReport(&b_watch);
    // Allow the configured scheduler snapshot boundary to elapse.
    try std.Io.sleep(io, .fromMilliseconds(120), .awake);
    var counts = [_]usize{ 0, 0 };
    var initial = try first_call.await(io);
    try countResponse(&counts, &initial);
    initial.deinit();
    var second_initial = try second_call.await(io);
    try countResponse(&counts, &second_initial);
    second_initial.deinit();
    for (2..weighted_calls) |index| {
        var response = call(sender) catch |err| {
            dumpFailure(index, err, &completed, &a_stats, &b_stats);
            return err;
        };
        defer response.deinit();
        try countResponse(&counts, &response);
    }
    try std.testing.expect(counts[1] > counts[0] * 2);
    try std.testing.expect(counts[1] < counts[0] * 4);
    // The server intentionally sends no second OOB report. Once both weights
    // expire, weighted_round_robin must resume round-robin admission.
    try std.Io.sleep(io, .fromMilliseconds(2100), .awake);
    var fallback_counts = [_]usize{ 0, 0 };
    for (weighted_calls..total_calls) |index| {
        var response = call(sender) catch |err| {
            dumpFailure(index, err, &completed, &a_stats, &b_stats);
            return err;
        };
        defer response.deinit();
        try countResponse(&fallback_counts, &response);
    }
    try std.testing.expectEqual(fallback_counts[0], fallback_counts[1]);
    sender.deinit();
    client.deinit();
    client_live = false;
    try a_task.await(io);
    try b_task.await(io);
}

fn dumpFailure(
    index: usize,
    err: anyerror,
    completed: *const std.atomic.Value(usize),
    a_stats: *const Server.Stats,
    b_stats: *const Server.Stats,
) void {
    std.debug.print(
        "WRR call {d} failed: {s}, completed={d}, a={d} stage={s} error={s}, b={d} stage={s} error={s}\n",
        .{
            index,
            @errorName(err),
            completed.load(.acquire),
            a_stats.completed.load(.acquire),
            @tagName(a_stats.currentStage()),
            a_stats.errorName(),
            b_stats.completed.load(.acquire),
            @tagName(b_stats.currentStage()),
            b_stats.errorName(),
        },
    );
}

fn call(sender: shared.Sender) !grpc.UnaryResponse {
    return sender.unary(.{
        .path = "/demo.Wrr/Unary",
        .authority = "localhost",
        .message = "request",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(20, .second),
    });
}

fn countResponse(counts: *[2]usize, response: *const grpc.UnaryResponse) !void {
    const label = response.message.?.payload;
    if (std.mem.eql(u8, label, "a")) counts[0] += 1 else if (std.mem.eql(u8, label, "b")) counts[1] += 1 else return error.UnexpectedBackend;
}

fn waitReport(watch: *shared.OrcaOobWatch) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(watch.tracker.io, .{ .raw = .fromSeconds(15), .clock = .awake });
    while (true) {
        var update = try watch.nextWithDeadline(deadline);
        defer update.deinit();
        if (update.header.status == .ready and update.report != null) return;
    }
}

const Server = struct {
    const ErrorInt = std.meta.Int(.unsigned, @bitSizeOf(anyerror));
    const Stage = enum(u8) {
        starting,
        accepting_connection,
        accepting_bootstrap,
        reporting,
        serving,
        shutdown,
        done,
        failed,
    };
    const Stats = struct {
        completed: std.atomic.Value(usize) = .init(0),
        stage: std.atomic.Value(u8) = .init(@intFromEnum(Stage.starting)),
        failure_code: std.atomic.Value(ErrorInt) = .init(0),

        fn setStage(self: *Stats, stage: Stage) void {
            self.stage.store(@intFromEnum(stage), .release);
        }

        fn currentStage(self: *const Stats) Stage {
            return @enumFromInt(self.stage.load(.acquire));
        }

        fn errorName(self: *const Stats) []const u8 {
            const code = self.failure_code.load(.acquire);
            return if (code == 0) "none" else @errorName(@errorFromInt(code));
        }
    };

    fn run(
        listener: *grpc.runtime.Server,
        label: []const u8,
        qps: f64,
        completed: *std.atomic.Value(usize),
        stats: *Stats,
        target: usize,
    ) !void {
        runInner(listener, label, qps, completed, stats, target) catch |err| {
            stats.failure_code.store(@intFromError(err), .release);
            stats.setStage(.failed);
            return err;
        };
        stats.setStage(.done);
    }

    fn runInner(listener: *grpc.runtime.Server, label: []const u8, qps: f64, completed: *std.atomic.Value(usize), stats: *Stats, target: usize) !void {
        stats.setStage(.accepting_connection);
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        stats.setStage(.accepting_bootstrap);
        var reports: ?grpc.orca_oob.ServerSession = null;
        while (reports == null) {
            var accepted = try connection.acceptDuplexWithTimeout(.fromSeconds(20));
            if (std.mem.eql(u8, accepted.path, grpc.orca_oob.path)) {
                reports = try grpc.orca_oob.accept(accepted);
                stats.setStage(.reporting);
                if (try reports.?.writeReport(.{
                    .cpu_utilization = 1,
                    .rps_fractional = qps,
                }) != .complete) return error.UnexpectedFlowControl;
            } else {
                respond(&accepted, label) catch |err| {
                    accepted.deinit();
                    return err;
                };
                accepted.deinit();
                _ = completed.fetchAdd(1, .release);
                _ = stats.completed.fetchAdd(1, .release);
            }
        }
        defer reports.?.deinit();
        stats.setStage(.serving);
        while (completed.load(.acquire) < target) {
            var business = connection.acceptDuplexWithTimeout(.fromSeconds(20)) catch |err| switch (err) {
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer business.deinit();
            try respond(&business, label);
            _ = completed.fetchAdd(1, .release);
            _ = stats.completed.fetchAdd(1, .release);
        }
        stats.setStage(.shutdown);
        connection.connection.gracefulShutdownWithTimeout(.fromSeconds(2)) catch {};
    }

    fn respond(business: *grpc.ServerDuplex, label: []const u8) !void {
        var seen = false;
        const Consumer = struct {
            seen: *bool,
            fn consume(self: *@This(), _: grpc.StreamingMessage) !void {
                if (self.seen.*) return error.UnexpectedRequest;
                self.seen.* = true;
            }
        };
        var consumer = Consumer{ .seen = &seen };
        while (true) {
            var event = try business.readRequestEventWithTimeout(.fromSeconds(10), &consumer, Consumer.consume);
            defer event.deinit();
            switch (event) {
                .messages => {},
                .finished => break,
                .reset => return error.UnexpectedReset,
            }
        }
        try business.startResponse(.{});
        if (try business.writeMessage(label) != .complete) return error.UnexpectedFlowControl;
        try business.finishOk();
    }
};

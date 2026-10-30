const std = @import("std");
const grpc = @import("../../../mod.zig");
const shared = @import("../../shared.zig");

test "gRPC SharedChannel ORCA reports fan out and reconnect per endpoint" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer server.deinit();
    var task = io.async(Server.run, .{&server});

    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{
            .channel = .{ .backoff = .{
                .initial_backoff = .fromMilliseconds(10),
                .multiplier = 1,
                .jitter = 0,
                .max_backoff = .fromMilliseconds(10),
                .min_connect_timeout = .fromSeconds(1),
            } },
            .operation_timeout = .fromSeconds(2),
            .orca_oob = .{
                .report_interval = .fromMilliseconds(10),
                .request_cost_names = &.{"query"},
            },
        },
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    var first = client.watchEndpointOrca(0).?;
    defer first.deinit();
    var second = client.watchEndpointOrca(0).?;
    defer second.deinit();

    var first_update = try nextReady(&first, 0.25);
    defer first_update.deinit();
    var second_update = try nextReady(&second, 0.25);
    defer second_update.deinit();
    try std.testing.expect(
        first_update.report.?.bytes.ptr != second_update.report.?.bytes.ptr,
    );
    try expectFilteredCost(first_update.report.?.report);
    try expectFilteredCost(second_update.report.?.report);

    var sender = client.sender();
    var response = try sender.unary(.{
        .path = "/demo.Orca/Unary",
        .authority = "localhost",
        .message = "ping",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(3, .second),
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc.Status.ok, response.status);
    try std.testing.expectEqualStrings("pong", response.message.?.payload);

    var reconnected = try nextReady(&first, 0.75);
    defer reconnected.deinit();
    sender.deinit();
    client.deinit();
    client_live = false;
    try task.await(io);
}

test "gRPC SharedChannel ORCA UNIMPLEMENTED disables only telemetry" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        4096,
    );
    defer server.deinit();
    var task = io.async(ServerUnimplemented.run, .{&server});
    var client = try shared.SharedChannel.init(
        allocator,
        io,
        .{ .cleartext_ip = .{ .address = server.address() } },
        .{ .orca_oob = .{ .report_interval = .fromSeconds(1) } },
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    var watch = client.watchEndpointOrca(0).?;
    defer watch.deinit();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    });
    while (true) {
        var update = try watch.nextWithDeadline(deadline);
        defer update.deinit();
        if (update.header.status == .unimplemented) break;
    }
    var sender = client.sender();
    var response = try sender.unary(.{
        .path = "/demo.Orca/Unary",
        .authority = "localhost",
        .message = "ping",
        .wait_for_ready = true,
        .timeout = try grpc.Timeout.init(3, .second),
    });
    defer response.deinit();
    try std.testing.expectEqualStrings("pong", response.message.?.payload);
    sender.deinit();
    client.deinit();
    client_live = false;
    try task.await(io);
}

fn nextReady(
    watch: *shared.OrcaOobWatch,
    expected_cpu: f64,
) !shared.OrcaOobUpdate {
    const deadline = std.Io.Clock.Timestamp.fromNow(watch.tracker.io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    while (true) {
        var update = try watch.nextWithDeadline(deadline);
        if (update.header.status == .ready and
            update.report.?.report.cpu_utilization == expected_cpu)
        {
            return update;
        }
        update.deinit();
    }
}

fn expectFilteredCost(report: grpc.orca.LoadReport) !void {
    try std.testing.expectEqual(@as(usize, 1), report.request_cost.len);
    try std.testing.expectEqualStrings("query", report.request_cost[0].name);
    try std.testing.expectEqual(@as(f64, 3), report.request_cost[0].value);
}

const Server = struct {
    fn run(listener: *grpc.runtime.Server) !void {
        try serveFirst(listener);
        try serveSecond(listener);
    }

    fn serveFirst(listener: *grpc.runtime.Server) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var reports = try acceptReports(&connection);
        defer reports.deinit();
        try expectRequest(&reports);
        try writeReport(&reports, 0.25);

        try serveBusiness(&connection);
    }

    fn serveBusiness(connection: *grpc.runtime.ServerConnection) !void {
        var business = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
        defer business.deinit();
        if (!std.mem.eql(u8, business.path, "/demo.Orca/Unary")) {
            return error.UnexpectedMethod;
        }
        var seen = false;
        const Consumer = struct {
            seen: *bool,
            fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                if (self.seen.* or message.was_compressed or
                    !std.mem.eql(u8, message.payload, "ping"))
                {
                    return error.UnexpectedRequest;
                }
                self.seen.* = true;
            }
        };
        var consumer = Consumer{ .seen = &seen };
        while (true) {
            var event = try business.readRequestEventWithTimeout(
                .fromSeconds(3),
                &consumer,
                Consumer.consume,
            );
            defer event.deinit();
            switch (event) {
                .messages => {},
                .finished => |terminal| {
                    if (!seen or terminal.message_count != 1) {
                        return error.UnexpectedRequest;
                    }
                    break;
                },
                .reset => return error.UnexpectedReset,
            }
        }
        try business.startResponse(.{});
        if (try business.writeMessage("pong") != .complete) {
            return error.UnexpectedFlowControl;
        }
        try business.finishOk();
    }

    fn serveSecond(listener: *grpc.runtime.Server) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        var reports = try acceptReports(&connection);
        defer reports.deinit();
        try expectRequest(&reports);
        try writeReport(&reports, 0.75);
        _ = reports.waitForPeerResetWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
            error.ConnectionClosed,
            error.ConnectionResetByPeer,
            error.SocketUnconnected,
            error.UnexpectedEof,
            => return,
            else => return err,
        };
    }

    fn acceptReports(
        connection: *grpc.runtime.ServerConnection,
    ) !grpc.orca_oob.ServerSession {
        const accepted = try connection.acceptDuplexWithTimeout(
            .fromSeconds(3),
        );
        return grpc.orca_oob.accept(accepted);
    }

    fn expectRequest(reports: *grpc.orca_oob.ServerSession) !void {
        const request = reports.request.request;
        if (request.report_interval.nanoseconds !=
            std.Io.Duration.fromMilliseconds(10).nanoseconds or
            request.request_cost_names.len != 1 or
            !std.mem.eql(u8, request.request_cost_names[0], "query"))
        {
            return error.UnexpectedRequest;
        }
    }

    fn writeReport(
        reports: *grpc.orca_oob.ServerSession,
        cpu: f64,
    ) !void {
        if (try reports.writeReport(.{
            .cpu_utilization = cpu,
            .request_cost = &.{
                .{ .name = "query", .value = 3 },
                .{ .name = "ignored", .value = 9 },
            },
        }) != .complete) return error.UnexpectedFlowControl;
    }
};

const ServerUnimplemented = struct {
    fn run(listener: *grpc.runtime.Server) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(3));
        defer connection.deinit();
        var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(3));
        defer stream.deinit();
        if (!std.mem.eql(u8, stream.path, grpc.orca_oob.path)) {
            return error.UnexpectedMethod;
        }
        try stream.finish(
            .unimplemented,
            "ORCA disabled",
            &.{},
            &.{},
        );
        _ = try stream.drainRequestAfterResponseWithDeadline(
            .fromNow(connection.connection.io, .{
                .raw = .fromSeconds(3),
                .clock = .awake,
            }),
        );
        try Server.serveBusiness(&connection);
    }
};

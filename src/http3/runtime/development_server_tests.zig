const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;

test "HTTP/3 dev runtime serves concurrent clients end to end" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    // Small STREAM fragments force each response through several UDP sends.
    // This exercises both concurrent handler dispatch and serialized use of
    // the development endpoint's shared send state.
    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
            .max_stream_frame_data = 8,
        },
    );
    defer server.deinit();

    const Context = struct {
        io: std.Io,
        entered: std.atomic.Value(usize) = .init(0),
        both_entered: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: runtime.OwnedRequest,
        ) runtime.Error!http3.Response {
            // Both clients intentionally use request stream 0. Their split
            // request bodies therefore verify that the server keys assembly
            // by UDP peer as well as by the QUIC stream ID.
            const entered = self.entered.fetchAdd(1, .acq_rel) + 1;
            if (entered == 2) {
                self.both_entered.set(self.io);
            } else {
                // Neither response may be produced until both handler tasks
                // are active, proving dispatch is concurrent rather than only
                // concurrent at the socket-receive layer.
                try self.both_entered.wait(self.io);
            }
            if (!std.mem.eql(u8, request.request.method, "POST")) {
                return error.InvalidHeader;
            }
            if (std.mem.eql(u8, request.request.path, "/serve-a") and
                std.mem.eql(u8, request.request.body, "alpha"))
            {
                return .{
                    .status = 201,
                    .body = "response-from-concurrent-handler-a",
                };
            }
            if (std.mem.eql(u8, request.request.path, "/serve-b") and
                std.mem.eql(u8, request.request.body, "beta"))
            {
                return .{
                    .status = 202,
                    .body = "response-from-concurrent-handler-b",
                };
            }
            return .{ .status = 404, .body = "missing" };
        }
    };

    const Shared = struct {
        server: *runtime.Server,
        context: Context,
        result: ?runtime.ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                Context,
                &shared.context,
                Context.handle,
                2,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{
        .server = &server,
        .context = .{ .io = io },
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        path: []const u8,
        body: []const u8,
        expected_status: u16,
        expected_body: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try runtime.Client.connect(
                task.allocator,
                task.io,
                .{ .ip4 = .loopback(0) },
                task.address,
                .{
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                    .max_stream_frame_data = 8,
                },
            );
            defer client.deinit();

            var response = try client.request(.{
                .method = "POST",
                .path = task.path,
                .authority = "localhost",
                .body = task.body,
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(
                task.expected_status,
                response.response.status,
            );
            try std.testing.expectEqualStrings(
                task.expected_body,
                response.response.body,
            );
            try std.testing.expect(response.extra_datagrams.len != 0);
        }
    };

    var clients = [_]ClientTask{
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/serve-a",
            .body = "alpha",
            .expected_status = 201,
            .expected_body = "response-from-concurrent-handler-a",
        },
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/serve-b",
            .body = "beta",
            .expected_status = 202,
            .expected_body = "response-from-concurrent-handler-b",
        },
    };
    const client_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_a.join();
    client_b.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.receivedCount());
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "HTTP/3 dev runtime correlates handler failure with owned request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
    );
    defer server.deinit();

    const Context = struct {
        fn handle(
            _: *@This(),
            _: runtime.OwnedRequest,
        ) runtime.Error!http3.Response {
            return error.InvalidHeader;
        }
    };
    const Shared = struct {
        server: *runtime.Server,
        context: Context = .{},
        result: ?runtime.ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(
                Context,
                &shared.context,
                Context.handle,
                1,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
    );
    defer client.deinit();
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/handler-failure",
        .authority = "localhost",
    }).write(&encoded, allocator);
    try client.quic_client.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items,
        .fin = true,
    } }});

    server_thread.join();
    defer if (shared.result) |*result| result.deinit();
    if (shared.err) |err| return err;

    const result = shared.result.?;
    try std.testing.expectEqual(@as(usize, 1), result.receivedCount());
    try std.testing.expectEqual(@as(usize, 0), result.successCount());
    try std.testing.expect(result.errors[0].? == error.InvalidHeader);
    try std.testing.expectEqualStrings(
        "/handler-failure",
        result.requests[0].?.request.path,
    );
}

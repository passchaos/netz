const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const net = std.Io.net;
const large_header_value =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test "HTTP/3 dev runtime fragments large final headers within UDP MTU" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: runtime.Limits = .{
        .quic = .{ .max_datagram_size = 1200 },
        .max_stream_frame_data = 1200,
    };
    var headers: [80]http3.Qpack.HeaderField = undefined;
    for (&headers) |*header| {
        header.* = .{
            .name = "x-many",
            .value = large_header_value,
            .never_indexed = true,
        };
    }

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();
    const Shared = struct {
        server: *runtime.Server,
        headers: []const http3.Qpack.HeaderField,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var request = try self.server.receiveRequestWithTimeout(
                .fromSeconds(3),
            );
            defer request.deinit(self.server.quic_server.endpoint.allocator);
            try self.server.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = self.headers,
                .body = "fragmented-finish",
            });
        }
    };
    var shared = Shared{ .server = &server, .headers = &headers };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
    );
    defer client.deinit();
    var response = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/large-final-head",
        .authority = "localhost",
    }, .fromSeconds(3));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "fragmented-finish",
        response.response.body,
    );
    var count: usize = 0;
    for (response.response.headers) |header| {
        count += @intFromBool(std.ascii.eqlIgnoreCase(
            header.name,
            "x-many",
        ));
    }
    try std.testing.expectEqual(headers.len, count);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 dev aggregate request preserves ready state across allocation failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();
    var client = try runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
    );
    defer client.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/retry-ready",
        .authority = "localhost",
    }).write(&encoded, allocator);
    try client.quic_client.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .data = encoded.items,
        .fin = true,
    } }});
    while (true) {
        if (try server.request_streams.prepareReady(allocator)) |prepared_value| {
            var prepared = prepared_value;
            prepared.deinit(allocator);
            break;
        }
        var datagram = try server.quic_server.receiveWithDeadline(.fromNow(
            io,
            .{ .raw = .fromSeconds(1), .clock = .awake },
        ));
        var owned = true;
        defer if (owned) datagram.deinit(allocator);
        if (try server.request_streams.insertDatagram(&datagram)) {
            owned = false;
        }
    }

    var failed_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        server.request_streams.prepareReady(failed_alloc.allocator()),
    );
    try std.testing.expect(failed_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), server.request_streams.count());

    var fail_decode = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 1, .resize_fail_index = 0 },
    );
    server.quic_server.endpoint.allocator = fail_decode.allocator();
    try std.testing.expectError(error.OutOfMemory, server.receiveRequest());
    server.quic_server.endpoint.allocator = allocator;
    try std.testing.expect(fail_decode.has_induced_failure);
    try std.testing.expectEqual(
        fail_decode.allocated_bytes,
        fail_decode.freed_bytes,
    );
    try std.testing.expectEqual(@as(usize, 1), server.request_streams.count());

    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings("/retry-ready", request.request.path);
    try std.testing.expect(server.request_streams.isEmpty());
}

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

test "HTTP/3 dev concurrent handler converts informational status and isolates its error" {
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
            request: runtime.OwnedRequest,
        ) runtime.Error!http3.Response {
            if (std.mem.eql(u8, request.request.path, "/invalid-final")) {
                return .{ .status = 103 };
            }
            return .{ .status = 204 };
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
                2,
            ) catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        path: []const u8,
        expected_status: u16,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            task.runFallible() catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try runtime.Client.connect(
                task.allocator,
                task.io,
                .{ .ip4 = .loopback(0) },
                task.address,
                .{ .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                } },
            );
            defer client.deinit();
            var response = try client.request(.{
                .method = "GET",
                .path = task.path,
                .authority = "localhost",
            });
            defer response.deinit(task.allocator);
            try std.testing.expectEqual(
                task.expected_status,
                response.response.status,
            );
            try std.testing.expectEqualStrings("", response.response.body);
        }
    };
    var clients = [_]ClientTask{
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/invalid-final",
            .expected_status = 500,
        },
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .path = "/sibling",
            .expected_status = 204,
        },
    };
    const invalid_client = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const sibling_client = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    invalid_client.join();
    sibling_client.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    try std.testing.expectEqual(@as(usize, 2), result.receivedCount());
    try std.testing.expectEqual(@as(usize, 1), result.successCount());
    var saw_invalid = false;
    var saw_sibling = false;
    for (result.requests, result.errors) |request, request_error| {
        const owned = request.?;
        if (std.mem.eql(u8, owned.request.path, "/invalid-final")) {
            try std.testing.expectEqual(error.InvalidStatus, request_error.?);
            saw_invalid = true;
        } else if (std.mem.eql(u8, owned.request.path, "/sibling")) {
            try std.testing.expect(request_error == null);
            saw_sibling = true;
        } else {
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expect(saw_invalid);
    try std.testing.expect(saw_sibling);
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

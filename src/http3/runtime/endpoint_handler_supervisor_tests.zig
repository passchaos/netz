const std = @import("std");
const http3 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const quic = @import("../../quic/mod.zig");

const net = std.Io.net;

test "HTTP/3 endpoint handler supervisor observes shutdown while idle" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{ .handshake = .{ .local_connection_id = "handler-idle" } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{});
    defer endpoint.deinit();

    const Context = struct {
        calls: usize = 0,

        fn handle(
            self: *@This(),
            _: *const runtime.OwnedEndpointRequest,
        ) runtime.Error!http3.Response {
            self.calls += 1;
            return .{ .status = 204 };
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        shutdown: *std.Io.Event,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.endpoint.serveHandlersUntil(
                Context,
                &self.context,
                Context.handle,
                .{
                    .shutdown = self.shutdown,
                    .supported_versions = &.{
                        quic.Version.version_1.wireValue(),
                    },
                    .max_handler_tasks = 2,
                    .max_pending_requests = 4,
                    .poll_interval = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(2),
                    },
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared{ .endpoint = &endpoint, .shutdown = &shutdown };
    try std.testing.expectError(
        error.InvalidServeOptions,
        endpoint.serveHandlersUntil(
            Context,
            &shared.context,
            Context.handle,
            .{
                .shutdown = &shutdown,
                .supported_versions = &.{
                    quic.Version.version_1.wireValue(),
                },
                .max_handler_tasks = 0,
            },
        ),
    );
    try std.testing.expectError(
        error.InvalidServeOptions,
        endpoint.serveHandlersUntil(
            Context,
            &shared.context,
            Context.handle,
            .{
                .shutdown = &shutdown,
                .supported_versions = &.{},
            },
        ),
    );
    try std.testing.expectError(
        error.InvalidServeOptions,
        endpoint.serveHandlersUntil(
            Context,
            &shared.context,
            Context.handle,
            .{
                .shutdown = &shutdown,
                .supported_versions = &.{
                    quic.Version.version_1.wireValue(),
                },
                .max_pending_requests = @as(usize, std.math.maxInt(u32)) + 1,
            },
        ),
    );
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    try std.Io.sleep(io, .fromMilliseconds(20), .awake);
    shutdown.set(io);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.context.calls);
}

test "HTTP/3 endpoint handler supervisor runs owned requests concurrently" {
    var allocator_state: std.heap.DebugAllocator(.{
        .thread_safe = true,
    }) = .init;
    defer std.testing.expect(allocator_state.deinit() == .ok) catch
        @panic("HTTP/3 handler supervisor leak");
    const allocator = allocator_state.allocator();
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = "handler-supervisor",
            .random = [_]u8{0xc1} ** 32,
            .x25519_secret_key = [_]u8{0xc2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 2,
        .max_connections = 2,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();

    const Context = struct {
        const response_headers = [_]http3.Qpack.HeaderField{.{
            .name = "x-handler",
            .value = "concurrent",
        }};
        const response_trailers = [_]http3.Qpack.HeaderField{.{
            .name = "x-handler-trailer",
            .value = "complete",
        }};

        io: std.Io,
        entered: std.atomic.Value(usize) = .init(0),
        both_entered: std.Io.Event = .unset,

        fn handle(
            self: *@This(),
            request: *const runtime.OwnedEndpointRequest,
        ) runtime.Error!http3.Response {
            if (request.was_early_data) return error.InvalidHeader;
            const forwarded_early = std.mem.eql(
                u8,
                request.path,
                "/handler-one",
            );
            if (request.mightHaveBeenEarly() != forwarded_early) {
                return error.InvalidHeader;
            }
            if (request.body.len == 0 or request.trailers.len != 1) {
                return error.InvalidHeader;
            }
            if (self.entered.fetchAdd(1, .acq_rel) + 1 == 2) {
                self.both_entered.set(self.io);
            }
            self.both_entered.waitTimeout(self.io, .{
                .duration = .{
                    .clock = .awake,
                    .raw = .fromSeconds(2),
                },
            }) catch return error.InvalidHeader;
            return .{
                .status = 200,
                .headers = &response_headers,
                .body = request.body,
                .trailers = &response_trailers,
            };
        }
    };
    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        original_dcid: []const u8,
        local_cid: []const u8,
        path: []const u8,
        body: []const u8,
        trailer: []const u8,
        forwarded_early: bool,
        random: [32]u8,
        secret: [32]u8,
        completed: *std.atomic.Value(usize),
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.shutdown.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var client = try runtime.HandshakeClient.connect(
                self.allocator,
                self.io,
                .{ .ip4 = .loopback(0) },
                self.address,
                .{ .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 16,
                } },
                .{ .handshake = .{
                    .original_destination_connection_id = self.original_dcid,
                    .local_connection_id = self.local_cid,
                    .server_name = "localhost",
                    .random = self.random,
                    .x25519_secret_key = self.secret,
                    .handshake_recovery = .{
                        .initial_pto_ms = 20,
                        .max_pto_ms = 40,
                        .max_duration_ms = 2_000,
                    },
                } },
            );
            defer client.deinit();
            var response = try client.requestWithTimeout(.{
                .method = "POST",
                .path = self.path,
                .authority = "localhost",
                .headers = if (self.forwarded_early) &.{.{
                    .name = "early-data",
                    .value = "1",
                }} else &.{},
                .body = self.body,
                .trailers = &.{.{
                    .name = "x-client-trailer",
                    .value = self.trailer,
                }},
            }, .fromSeconds(5));
            defer response.deinit(self.allocator);
            try std.testing.expectEqual(@as(u16, 200), response.response.status);
            try std.testing.expectEqualStrings(
                self.body,
                response.response.body,
            );
            var saw_path = false;
            for (response.response.headers) |header| {
                if (std.ascii.eqlIgnoreCase(header.name, "x-handler")) {
                    try std.testing.expectEqualStrings("concurrent", header.value);
                    saw_path = true;
                }
            }
            var saw_trailer = false;
            for (response.response.trailers) |trailer| {
                if (std.ascii.eqlIgnoreCase(
                    trailer.name,
                    "x-handler-trailer",
                )) {
                    try std.testing.expectEqualStrings(
                        "complete",
                        trailer.value,
                    );
                    saw_trailer = true;
                }
            }
            try std.testing.expect(saw_path and saw_trailer);
            if (self.completed.fetchAdd(1, .acq_rel) + 1 == 2) {
                self.shutdown.set(self.io);
            }
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        shutdown: *std.Io.Event,
        response_allocator: std.mem.Allocator,
        context: Context,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.endpoint.serveHandlersUntil(
                Context,
                &self.context,
                Context.handle,
                .{
                    .shutdown = self.shutdown,
                    .supported_versions = &.{
                        quic.Version.version_1.wireValue(),
                    },
                    .max_handler_tasks = 2,
                    .max_pending_requests = 4,
                    .max_request_body_bytes = 64,
                    .response_allocator = self.response_allocator,
                    .poll_interval = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(1),
                    },
                    .error_policy = .stop,
                },
            ) catch |err| {
                self.err = err;
                self.shutdown.set(self.context.io);
            };
        }
    };

    var shutdown: std.Io.Event = .unset;
    var completed: std.atomic.Value(usize) = .init(0);
    var shared = Shared{
        .endpoint = &endpoint,
        .shutdown = &shutdown,
        .response_allocator = allocator,
        .context = .{ .io = io },
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var clients = [_]ClientTask{
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .original_dcid = "handler-route-1",
            .local_cid = "handler-client-1",
            .path = "/handler-one",
            .body = "request-one",
            .trailer = "trailer-one",
            .forwarded_early = true,
            .random = [_]u8{0xc3} ** 32,
            .secret = [_]u8{0xc4} ** 32,
            .completed = &completed,
            .shutdown = &shutdown,
        },
        .{
            .allocator = allocator,
            .io = io,
            .address = server.address(),
            .original_dcid = "handler-route-2",
            .local_cid = "handler-client-2",
            .path = "/handler-two",
            .body = "request-two",
            .trailer = "trailer-two",
            .forwarded_early = false,
            .random = [_]u8{0xc5} ** 32,
            .secret = [_]u8{0xc6} ** 32,
            .completed = &completed,
            .shutdown = &shutdown,
        },
    };
    const client_a = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_b = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        shared.context.both_entered.set(io);
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        client_a.join();
        client_b.join();
        server_thread.join();
    };

    client_a.join();
    client_b.join();
    shutdown.set(io);
    server_thread.join();
    joined = true;
    for (&clients) |*client| if (client.err) |err| return err;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), completed.load(.acquire));
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.entered.load(.acquire),
    );
}

test "HTTP/3 endpoint handler supervisor isolates handler failure" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .local_connection_id = "handler-failure",
            .random = [_]u8{0xd1} ** 32,
            .x25519_secret_key = [_]u8{0xd2} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer server.deinit();
    var endpoint = try runtime.EndpointServer.init(&server, .{
        .max_pending_handshakes = 1,
        .max_connections = 1,
        .inbox_capacity = 8,
        .handshake_timeout_ms = 2_000,
    });
    var endpoint_owned = true;
    defer if (endpoint_owned) endpoint.deinit();

    const Context = struct {
        handler_calls: std.atomic.Value(usize) = .init(0),
        observed_errors: usize = 0,
        observed_handle: ?u64 = null,
        observed_stream: ?u62 = null,

        fn handle(
            self: *@This(),
            request: *const runtime.OwnedEndpointRequest,
        ) runtime.Error!http3.Response {
            _ = self.handler_calls.fetchAdd(1, .acq_rel);
            if (std.mem.eql(u8, request.path, "/fail")) {
                return error.InvalidHeader;
            }
            if (!std.mem.eql(u8, request.path, "/recover")) {
                return error.InvalidUri;
            }
            return .{ .status = 200, .body = "recovered" };
        }

        fn observe(raw: *anyopaque, event: runtime.EndpointHandlerErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (event.stage != .handler or event.err != error.InvalidHeader) {
                return;
            }
            self.observed_errors += 1;
            self.observed_handle = event.connection_handle;
            self.observed_stream = event.stream_id;
        }
    };
    const Shared = struct {
        endpoint: *runtime.EndpointServer,
        shutdown: *std.Io.Event,
        context: Context = .{},
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.endpoint.serveHandlersUntil(
                Context,
                &self.context,
                Context.handle,
                .{
                    .shutdown = self.shutdown,
                    .supported_versions = &.{
                        quic.Version.version_1.wireValue(),
                    },
                    .max_handler_tasks = 1,
                    .max_pending_requests = 3,
                    .max_request_body_bytes = 4,
                    .stop_after_responses = 1,
                    .poll_interval = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(1),
                    },
                    .error_policy = .continue_serving,
                    .error_observer = .{
                        .context = &self.context,
                        .observe = Context.observe,
                    },
                },
            ) catch |err| {
                self.err = err;
                self.shutdown.set(
                    self.endpoint.server.quic_server.endpoint.io,
                );
            };
        }
    };
    var shutdown: std.Io.Event = .unset;
    var shared = Shared{ .endpoint = &endpoint, .shutdown = &shutdown };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shutdown.set(io);
        if (endpoint_owned) {
            endpoint.deinit();
            endpoint_owned = false;
        }
        server_thread.join();
    };

    var client = try runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{ .handshake = .{
            .original_destination_connection_id = "failure-route",
            .local_connection_id = "failure-client",
            .server_name = "localhost",
            .random = [_]u8{0xd3} ** 32,
            .x25519_secret_key = [_]u8{0xd4} ** 32,
            .handshake_recovery = .{
                .initial_pto_ms = 20,
                .max_pto_ms = 40,
                .max_duration_ms = 2_000,
            },
        } },
    );
    defer client.deinit();
    try std.testing.expectError(
        error.RequestRejected,
        client.requestWithTimeout(.{
            .method = "POST",
            .path = "/too-large",
            .authority = "localhost",
            .body = "12345",
        }, .fromSeconds(5)),
    );
    try std.testing.expectError(
        error.RequestRejected,
        client.requestWithTimeout(.{
            .method = "GET",
            .path = "/fail",
            .authority = "localhost",
        }, .fromSeconds(5)),
    );
    var response = try client.requestWithTimeout(.{
        .method = "GET",
        .path = "/recover",
        .authority = "localhost",
    }, .fromSeconds(5));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("recovered", response.response.body);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.handler_calls.load(.acquire),
    );
    try std.testing.expectEqual(@as(usize, 1), shared.context.observed_errors);
    try std.testing.expect(shared.context.observed_handle != null);
    try std.testing.expectEqual(@as(?u62, 4), shared.context.observed_stream);
}

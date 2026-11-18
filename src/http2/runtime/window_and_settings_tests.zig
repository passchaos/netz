//! HTTP/2 window-update, adaptive-window, and SETTINGS-ACK tests.

const std = @import("std");
const http2 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const Client = runtime.Client;
const ClientDuplexStream = runtime.ClientDuplexStream;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const Connection = runtime.Connection;
const DuplexHeaderBlockSlot = runtime.DuplexHeaderBlockSlot;
const Error = runtime.Error;
const ExtendedConnectResponse = runtime.ExtendedConnectResponse;
const GoAwayRetryDisposition = runtime.GoAwayRetryDisposition;
const Limits = runtime.Limits;
const OwnedFrameSlot = runtime.OwnedFrameSlot;
const OwnedRequest = runtime.OwnedRequest;
const OwnedResponse = runtime.OwnedResponse;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const ResponseTimeoutError = runtime.ResponseTimeoutError;
const RetainedFrameSlot = runtime.RetainedFrameSlot;
const Server = runtime.Server;
const ServerDuplexStream = runtime.ServerDuplexStream;
const StapledOcspPolicy = runtime.StapledOcspPolicy;
const StreamingRequest = runtime.StreamingRequest;
const StreamingResponse = runtime.StreamingResponse;
const StreamingResponseHead = runtime.StreamingResponseHead;
const appendAutomaticDateHeaderValue = runtime.appendAutomaticDateHeaderValue;
const appendFrameBytes = runtime.appendFrameBytes;
const bdp = runtime.bdp;
const builtin = runtime.builtin;
const client_authority = runtime.client_authority;
const client_duplex_owner = runtime.client_duplex_owner;
const concurrent = runtime.concurrent;
const containsHttpToken = runtime.containsHttpToken;
const data_frame_budget = runtime.data_frame_budget;
const decodeOwnedHeaders = runtime.decodeOwnedHeaders;
const default_flow_window = runtime.default_flow_window;
const default_max_frame_size = runtime.default_max_frame_size;
const encodeFrameHeader = runtime.encodeFrameHeader;
const endpoint_host = runtime.endpoint_host;
const expectClientConnectionErrorGoAway = runtime.expectClientConnectionErrorGoAway;
const expectServerInitialConnectionErrorGoAway = runtime.expectServerInitialConnectionErrorGoAway;
const findHeader = runtime.findHeader;
const flag_ack = runtime.flag_ack;
const flag_end_headers = runtime.flag_end_headers;
const flag_end_stream = runtime.flag_end_stream;
const freeHeaders = runtime.freeHeaders;
const freeStackFirstHeaderFieldBuffer = runtime.freeStackFirstHeaderFieldBuffer;
const graceful_shutdown_ping_payload = runtime.graceful_shutdown_ping_payload;
const host_connect = runtime.host_connect;
const http1_runtime = runtime.http1_runtime;
const http_date = runtime.http_date;
const max_flow_window = runtime.max_flow_window;
const max_max_frame_size = runtime.max_max_frame_size;
const outbound_headers = runtime.outbound_headers;
const peer_metadata = runtime.peer_metadata;
const push = runtime.push;
const queueTestPendingRequest = runtime.queueTestPendingRequest;
const readExact = runtime.readExact;
const readFrame = runtime.readFrame;
const settingsForLimits = runtime.settingsForLimits;
const stackFirstHeaderFieldBuffer = runtime.stackFirstHeaderFieldBuffer;
const stripSuccessfulConnectContentLength = runtime.stripSuccessfulConnectContentLength;
const test_socket = runtime.test_socket;
const testing = runtime.testing;
const tls_stream = runtime.tls_stream;
const vail = runtime.vail;
const validateHeaderBlock = runtime.validateHeaderBlock;
const validateHeaderListSize = runtime.validateHeaderListSize;
const validateLocalLimits = runtime.validateLocalLimits;
const validateOutgoingResponseBodyForStatus = runtime.validateOutgoingResponseBodyForStatus;
const validateResponseBodyForStatus = runtime.validateResponseBodyForStatus;
const verifiedTlsClientOptions = runtime.verifiedTlsClientOptions;
const webtransport_settings = runtime.webtransport_settings;
const writeAll = runtime.writeAll;
const writeFrame = runtime.writeFrame;
const writeInitialSettings = runtime.writeInitialSettings;

test "HTTP/2 DATA receive releases WINDOW_UPDATE capacity" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 128 * 1024 },
    );
    defer server.deinit();

    const request_body = try allocator.alloc(u8, 40_000);
    defer allocator.free(request_body);
    @memset(request_body, 'q');

    const response_body = try allocator.alloc(u8, 40_000);
    defer allocator.free(response_body);
    @memset(response_body, 'r');

    const Shared = struct {
        server: *Server,
        expected_request: []const u8,
        response_body: []const u8,
        response_window_updates: usize = 0,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings("/release-capacity", request.path);
            try std.testing.expectEqualSlices(u8, shared.expected_request, request.body);

            try connection.writeResponse(request.stream_id, .{
                .status = 200,
                .body = shared.response_body,
            });

            var conn_update = try connection.readWindowUpdate();
            defer conn_update.deinit(shared.server.allocator);
            try std.testing.expectEqual(@as(u31, 0), conn_update.window_update.stream_id);
            try std.testing.expect(conn_update.window_update.increment > 0);
            shared.response_window_updates += 1;

            var stream_update = try connection.readWindowUpdate();
            defer stream_update.deinit(shared.server.allocator);
            try std.testing.expectEqual(request.stream_id, stream_update.window_update.stream_id);
            try std.testing.expect(stream_update.window_update.increment > 0);
            shared.response_window_updates += 1;
        }
    };

    var shared = Shared{
        .server = &server,
        .expected_request = request_body,
        .response_body = response_body,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 128 * 1024,
    });
    defer client.close();

    var response = try client.request(.{
        .method = "POST",
        .path = "/release-capacity",
        .authority = "localhost",
        .body = request_body,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualSlices(u8, response_body, response.body);
    try std.testing.expect(client.send_connection_window.value > default_flow_window - @as(i64, @intCast(request_body.len)));

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.response_window_updates);
}

test "HTTP/2 SETTINGS_INITIAL_WINDOW_SIZE updates stream send windows" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    const first = try connection.sendStreamWindow(1);
    try std.testing.expectEqual(@as(?usize, 0), connection.send_stream_window_index.get(1));
    try first.reserve(1024);
    try std.testing.expectEqual(@as(i64, default_flow_window - 1024), first.value);

    const settings = [_]http2.Setting{.{ .id = .initial_window_size, .value = 70_000 }};
    try connection.applySettings(&settings);
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 70_000 - 1024), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(@as(i64, 70_000), (try connection.sendStreamWindow(3)).value);
    try std.testing.expectEqual(@as(?usize, 1), connection.send_stream_window_index.get(3));

    (try connection.sendStreamWindow(1)).value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
    }));
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(max_flow_window, (try connection.sendStreamWindow(1)).value);

    (try connection.sendStreamWindow(1)).value = 100;
    (try connection.sendStreamWindow(3)).value = max_flow_window;
    try std.testing.expectError(error.FlowControlViolation, connection.applySettings(&.{
        .{ .id = .initial_window_size, .value = std.math.maxInt(i31) },
    }));
    try std.testing.expectEqual(@as(i64, 70_000), connection.peer_initial_stream_window);
    try std.testing.expectEqual(@as(i64, 100), (try connection.sendStreamWindow(1)).value);
    try std.testing.expectEqual(max_flow_window, (try connection.sendStreamWindow(3)).value);
}

test "HTTP/2 adaptive window queues behind initial SETTINGS ACK" {
    const allocator = std.testing.allocator;
    const adaptive_target: u32 = 100_000;
    const sample_bytes: usize = adaptive_target / 2;
    const final_bytes: usize = 1;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_frame_payload = 64 * 1024,
            .max_body_bytes = 128 * 1024,
            .adaptive_window = true,
            .adaptive_window_max = 1024 * 1024,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var connection = try shared.server.accept();
            defer connection.close();
            try std.testing.expect(connection.awaiting_settings_ack);

            var request = try connection.readRequest();
            defer request.deinit(shared.server.allocator);
            try std.testing.expectEqualStrings(
                "/adaptive-window",
                request.path,
            );
            try std.testing.expectEqual(
                sample_bytes + final_bytes,
                request.body.len,
            );

            // The BDP ACK arrived before the initial SETTINGS ACK. Processing
            // the latter emitted exactly one merged adaptive update and began
            // a fresh SETTINGS acknowledgement wait.
            try std.testing.expect(connection.awaiting_settings_ack);
            try std.testing.expectEqual(
                @as(?u32, adaptive_target),
                connection.adaptive_pending_stream_target,
            );
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.adaptive_queued_target,
            );
            try std.testing.expectEqual(
                adaptive_target,
                connection.recv_connection_window_target,
            );
            try std.testing.expectEqual(
                adaptive_target,
                connection.recv_stream_window_target,
            );
            try std.testing.expectEqual(
                @as(u32, adaptive_target / 2),
                connection.dataFrameBudgetMaximum(),
            );
            try std.testing.expect(
                (try connection.recvStreamWindow(1)).value >
                    default_flow_window,
            );
            try std.testing.expectEqual(
                @as(i64, adaptive_target),
                (try connection.recvStreamWindow(3)).value,
            );

            const user_ping = [_]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &user_ping, &observed);
            try std.testing.expect(!connection.awaiting_settings_ack);
            try std.testing.expectEqual(
                @as(?u32, null),
                connection.adaptive_pending_stream_target,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const stream = try server.address().connect(io, .{ .mode = .stream });
    defer stream.close(io);
    try writeAll(io, stream, http2.connection_preface);
    try writeFrame(allocator, io, stream, .settings, 0, 0, &.{});

    var server_settings = try readFrame(allocator, io, stream, .{});
    defer server_settings.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.settings,
        server_settings.frame.header.frame_type,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        server_settings.frame.header.flags & flag_ack,
    );
    var server_ack = try readFrame(allocator, io, stream, .{});
    defer server_ack.deinit(allocator);
    try std.testing.expectEqual(
        http2.FrameType.settings,
        server_ack.frame.header.frame_type,
    );
    try std.testing.expect(server_ack.frame.header.flags & flag_ack != 0);

    var request_block: std.ArrayList(u8) = .empty;
    defer request_block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&request_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/adaptive-window" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "content-length", .value = "50001" },
    });
    try writeFrame(
        allocator,
        io,
        stream,
        .headers,
        flag_end_headers,
        1,
        request_block.items,
    );
    var data: [default_max_frame_size]u8 = undefined;
    @memset(&data, 'd');
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(allocator, io, stream, .data, 0, 1, &data);
    try writeFrame(
        allocator,
        io,
        stream,
        .data,
        0,
        1,
        data[0 .. sample_bytes - 3 * default_max_frame_size],
    );

    var probe_payload: ?[8]u8 = null;
    while (probe_payload == null) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type == .ping) {
            try std.testing.expectEqual(
                @as(u8, 0),
                frame.frame.header.flags & flag_ack,
            );
            probe_payload = (try http2.PingPayload.parse(frame.frame)).data;
            try std.testing.expect(bdp.isProbePayload(probe_payload.?));
        }
    }

    // Deliberately acknowledge the probe before the server's initial
    // SETTINGS. The target must remain queued until that older transaction is
    // acknowledged. The final DATA keeps readRequest alive long enough to
    // process both control frames first.
    try writeFrame(
        allocator,
        io,
        stream,
        .ping,
        flag_ack,
        0,
        &probe_payload.?,
    );
    try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
    try writeFrame(
        allocator,
        io,
        stream,
        .data,
        flag_end_stream,
        1,
        "!",
    );

    var saw_connection_growth = false;
    var saw_adaptive_settings = false;
    while (!saw_adaptive_settings) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        switch (frame.frame.header.frame_type) {
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(
                    frame.frame,
                );
                if (update.stream_id == 0 and
                    update.increment ==
                        adaptive_target - default_flow_window)
                {
                    saw_connection_growth = true;
                }
            },
            .settings => {
                try std.testing.expectEqual(
                    @as(u8, 0),
                    frame.frame.header.flags & flag_ack,
                );
                const settings = try http2.parseSettings(
                    allocator,
                    frame.frame.payload,
                );
                defer allocator.free(settings);
                for (settings) |setting| {
                    if (setting.id == .initial_window_size and
                        setting.value == adaptive_target)
                    {
                        saw_adaptive_settings = true;
                    }
                }
            },
            else => {},
        }
    }
    try std.testing.expect(saw_connection_growth);

    try writeFrame(allocator, io, stream, .settings, flag_ack, 0, &.{});
    // Internal probe-shaped requests are acknowledged as connection control
    // and cannot escape through the public user-PING receive API.
    try writeFrame(
        allocator,
        io,
        stream,
        .ping,
        0,
        0,
        &probe_payload.?,
    );
    const user_ping = [_]u8{ 6, 2, 6, 4, 3, 3, 8, 3 };
    try writeFrame(allocator, io, stream, .ping, 0, 0, &user_ping);
    while (true) {
        var frame = try readFrame(allocator, io, stream, .{});
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type != .ping or
            frame.frame.header.flags & flag_ack == 0) continue;
        const echoed = (try http2.PingPayload.parse(frame.frame)).data;
        if (bdp.isProbePayload(echoed)) continue;
        try std.testing.expectEqualSlices(u8, &user_ping, &echoed);
        break;
    }

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 adaptive window coalesces pending targets" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .awaiting_settings_ack = true,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.queueAdaptiveWindowTarget(100_000);
    try connection.queueAdaptiveWindowTarget(80_000);
    try connection.queueAdaptiveWindowTarget(120_000);
    try std.testing.expectEqual(
        @as(?u32, 120_000),
        connection.adaptive_queued_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_connection_window_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_stream_window_target,
    );
}

test "HTTP/2 user PING rejects the adaptive probe namespace" {
    var estimator = bdp.Estimator.init(65_535, bdp.default_max_window);
    const probe = estimator.recordData(1, 0) orelse
        return error.TestUnexpectedResult;
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.InvalidFrame, connection.ping(probe));
}

test "HTTP/2 client connect handles interleaved PING before settings" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            defer stream.close(shared.io);

            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(shared.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            var client_settings = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
            defer client_settings.deinit(shared.allocator);
            try std.testing.expectEqual(http2.FrameType.settings, client_settings.frame.header.frame_type);

            const ping_payload = [_]u8{ 7, 0, 7, 0, 7, 0, 7, 0 };
            try writeFrame(shared.allocator, shared.io, stream, .ping, 0, 0, &ping_payload);
            try writeInitialSettings(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 }, .server);
            try writeFrame(shared.allocator, shared.io, stream, .settings, flag_ack, 0, &.{});

            while (true) {
                var frame = try readFrame(shared.allocator, shared.io, stream, .{ .max_frame_payload = 4096 });
                defer frame.deinit(shared.allocator);
                if (frame.frame.header.frame_type == .settings and (frame.frame.header.flags & flag_ack) != 0) continue;
                try std.testing.expectEqual(http2.FrameType.ping, frame.frame.header.frame_type);
                try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
                try std.testing.expectEqualSlices(u8, &ping_payload, frame.frame.payload);
                break;
            }
        }
    };

    var shared = Shared{ .allocator = allocator, .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, listener.socket.address, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    try std.testing.expect(!client.awaiting_settings_ack);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 server clears settings ACK on first control read" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();
            try std.testing.expect(connection.awaiting_settings_ack);

            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(u8, &[_]u8{ 3, 1, 4, 1, 5, 9, 2, 6 }, &observed);
            try std.testing.expect(!connection.awaiting_settings_ack);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    _ = try client.ping(.{ 3, 1, 4, 1, 5, 9, 2, 6 });

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client connect clears initial settings ACK wait" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            // The server has not read the client's ACK yet after accept returns.
            std.testing.expect(connection.awaiting_settings_ack) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.close();
    try std.testing.expect(!client.awaiting_settings_ack);

    thread.join();
    if (shared.err) |err| return err;
}

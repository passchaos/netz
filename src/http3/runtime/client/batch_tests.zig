const std = @import("std");
const http3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const quic = @import("../../../quic/mod.zig");

test "HTTP/3 handshake batch correlates reversed responses and isolates deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    const original_dcid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0 };
    const client_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    const server_cid = [_]u8{ 0xc5, 0xc6, 0xc7, 0xc8 };
    var server = try runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();

    const Worker = struct {
        server: *runtime.HandshakeServer,
        cancel_requests_ready: *std.Io.Event,
        cancellation_code: ?u64 = null,
        active_cancellation_code: ?u64 = null,
        active_stream_id: ?u62 = null,
        active_peer_closed: bool = false,
        active_http_live: bool = false,
        active_latched: ?u64 = null,
        active_stopped: ?u64 = null,
        active_trace: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithTimeout(.fromSeconds(10));
            defer session.deinit();

            var first = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer first.deinit(self.server.allocator);
            var second = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/first", first.request.path);
            try std.testing.expectEqualStrings("body", first.request.body);
            try std.testing.expectEqual(@as(usize, 1), first.request.trailers.len);
            try std.testing.expectEqualStrings(
                "x-end",
                first.request.trailers[0].name,
            );
            try std.testing.expectEqualStrings("done", first.request.trailers[0].value);
            try std.testing.expectEqualStrings("/second", second.request.path);
            try session.sendResponse(second.stream_id, .{
                .status = 202,
                .request_method = second.request.method,
                .body = "second",
            });
            try session.sendResponse(first.stream_id, .{
                .status = 201,
                .request_method = first.request.method,
                .body = "first",
            });

            var timed = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer timed.deinit(self.server.allocator);
            var sibling = try session.receiveRequestWithTimeout(.fromSeconds(5));
            defer sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/timeout", timed.request.path);
            try std.testing.expectEqualStrings("/sibling", sibling.request.path);
            const canceled = try session.receivePeerResponseCancellationWithTimeout(
                timed.stream_id,
                .fromSeconds(5),
            );
            self.cancellation_code = canceled.application_error_code;
            try session.sendResponse(sibling.stream_id, .{
                .status = 203,
                .request_method = sibling.request.method,
                .body = "sibling",
            });

            var active_cancel = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer active_cancel.deinit(self.server.allocator);
            var active_sibling = try session.receiveRequestWithTimeout(
                .fromSeconds(5),
            );
            defer active_sibling.deinit(self.server.allocator);
            try std.testing.expectEqualStrings(
                "/active-cancel",
                active_cancel.request.path,
            );
            try std.testing.expectEqualStrings(
                "/active-sibling",
                active_sibling.request.path,
            );
            var trace_storage: [64 * 1024]u8 = undefined;
            var trace_output: std.Io.Writer = .fixed(&trace_storage);
            var trace = quic.qlog.Trace.init(&trace_output, .{});
            var trace_observer = quic.qlog.Observer.init(&trace);
            session.established.connection.config.qlog_observer = &trace_observer;
            self.cancel_requests_ready.set(
                self.server.quic_server.endpoint.io,
            );
            self.active_stream_id = active_cancel.stream_id;
            const active = session.receivePeerResponseCancellationWithTimeout(
                active_cancel.stream_id,
                .fromSeconds(5),
            ) catch |err| {
                self.active_peer_closed = session.established.connection.peerStreamClosed(active_cancel.stream_id);
                self.active_http_live = session.request_lifecycle.contains(active_cancel.stream_id);
                self.active_latched = session.request_lifecycle.peerResponseCancellation(active_cancel.stream_id);
                if (session.established.connection.streamStopped(active_cancel.stream_id)) |stop| self.active_stopped = stop.application_error_code;
                self.active_trace = try allocator.dupe(u8, trace_output.buffered());
                std.debug.print("server cancellation stats={any}\n", .{session.established.connection.stats()});
                return err;
            };
            self.active_cancellation_code = active.application_error_code;
            try session.sendResponse(active_sibling.stream_id, .{
                .status = 204,
                .request_method = active_sibling.request.method,
            });
        }
    };
    var cancel_requests_ready: std.Io.Event = .unset;
    var worker = Worker{
        .server = &server,
        .cancel_requests_ready = &cancel_requests_ready,
    };
    defer if (worker.active_trace) |trace| allocator.free(trace);
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&worker});
    var joined = false;
    defer if (!joined) thread.join();

    const uri = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);
    var client = runtime.HandshakeClient.connectUri(
        allocator,
        io,
        .{ .ip4 = .unspecified(0) },
        try std.Uri.parse(uri),
        limits,
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        } },
    ) catch |err| {
        thread.join();
        joined = true;
        if (worker.err) |server_err| return server_err;
        return err;
    };
    defer client.deinit();

    const Results = struct {
        allocator: std.mem.Allocator,
        expected_status: [2]u16,
        expected_body: [2][]const u8,
        order: [2]usize = undefined,
        order_len: usize = 0,
        completed: [2]bool = .{ false, false },
        errors: [2]?anyerror = .{ null, null },

        fn observe(
            raw: *anyopaque,
            index: usize,
            result: runtime.BatchOwnedHandshakeResponseResult,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.order[self.order_len] = index;
            self.order_len += 1;
            switch (result) {
                .response => |response_value| {
                    var response = response_value;
                    defer response.deinit(self.allocator);
                    std.testing.expectEqual(
                        self.expected_status[index],
                        response.response.status,
                    ) catch |err| {
                        self.errors[index] = err;
                        return;
                    };
                    std.testing.expectEqualStrings(
                        self.expected_body[index],
                        response.response.body,
                    ) catch |err| {
                        self.errors[index] = err;
                        return;
                    };
                    self.completed[index] = true;
                },
                .err => |err| self.errors[index] = err,
            }
        }
    };

    const common_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var reversed = Results{
        .allocator = allocator,
        .expected_status = .{ 201, 202 },
        .expected_body = .{ "first", "second" },
    };
    try client.requestBatchWithPerStreamDeadlines(
        &.{
            .{
                .method = "POST",
                .path = "/first",
                .authority = "localhost",
                .body = "body",
                .trailers = &.{.{ .name = "x-end", .value = "done" }},
            },
            .{ .method = "GET", .path = "/second", .authority = "localhost" },
        },
        &.{ common_deadline, common_deadline },
        .{ .context = &reversed, .on_result = Results.observe },
    );
    try std.testing.expectEqualSlices(usize, &.{ 1, 0 }, &reversed.order);
    try std.testing.expectEqual([2]bool{ true, true }, reversed.completed);
    try std.testing.expect(reversed.errors[0] == null);
    try std.testing.expect(reversed.errors[1] == null);

    var bounded = Results{
        .allocator = allocator,
        .expected_status = .{ 0, 203 },
        .expected_body = .{ "", "sibling" },
    };
    try client.requestBatchWithPerStreamDeadlines(
        &.{
            .{ .method = "GET", .path = "/timeout", .authority = "localhost" },
            .{ .method = "GET", .path = "/sibling", .authority = "localhost" },
        },
        &.{
            std.Io.Clock.Timestamp.fromNow(io, .{
                .raw = .fromMilliseconds(30),
                .clock = .awake,
            }),
            std.Io.Clock.Timestamp.fromNow(io, .{
                .raw = .fromSeconds(5),
                .clock = .awake,
            }),
        },
        .{ .context = &bounded, .on_result = Results.observe },
    );
    try std.testing.expectEqual(@as(usize, 2), bounded.order_len);
    try std.testing.expectEqual(error.Timeout, bounded.errors[0].?);
    try std.testing.expect(bounded.completed[1]);
    try std.testing.expect(bounded.errors[1] == null);

    const CancelState = struct {
        io: std.Io,
        event: std.Io.Event = .unset,
        mutex: std.Io.Mutex = .init,
        canceled: [2]bool = .{ false, false },

        fn request(self: *@This(), index: usize) void {
            self.mutex.lockUncancelable(self.io);
            self.canceled[index] = true;
            self.mutex.unlock(self.io);
            self.event.set(self.io);
        }

        fn take(raw: *anyopaque, index: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            const value = self.canceled[index];
            self.canceled[index] = false;
            return value;
        }

        fn acknowledge(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (!self.canceled[0] and !self.canceled[1]) self.event.reset();
        }
    };
    const Canceler = struct {
        fn run(
            ready: *std.Io.Event,
            state: *CancelState,
        ) std.Io.Cancelable!void {
            try ready.wait(state.io);
            state.request(0);
        }
    };
    var cancel_state = CancelState{ .io = io };
    var canceler = try std.Io.concurrent(
        io,
        Canceler.run,
        .{ &cancel_requests_ready, &cancel_state },
    );
    var canceler_active = true;
    defer if (canceler_active) {
        canceler.cancel(io) catch {};
        canceler.await(io) catch {};
    };
    var actively_canceled = Results{
        .allocator = allocator,
        .expected_status = .{ 0, 204 },
        .expected_body = .{ "", "" },
    };
    const active_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    var client_trace_storage: [64 * 1024]u8 = undefined;
    var client_trace_output: std.Io.Writer = .fixed(&client_trace_storage);
    var client_trace = quic.qlog.Trace.init(&client_trace_output, .{});
    var client_trace_observer = quic.qlog.Observer.init(&client_trace);
    client.established.connection.config.qlog_observer = &client_trace_observer;
    try client.requestBatchWithPerStreamDeadlinesAndCancellation(
        &.{
            .{ .method = "GET", .path = "/active-cancel", .authority = "localhost" },
            .{ .method = "GET", .path = "/active-sibling", .authority = "localhost" },
        },
        &.{ active_deadline, active_deadline },
        .{ .context = &actively_canceled, .on_result = Results.observe },
        .{
            .event = &cancel_state.event,
            .context = &cancel_state,
            .take_canceled = CancelState.take,
            .acknowledge = CancelState.acknowledge,
        },
    );
    try std.testing.expectEqual(
        error.Canceled,
        actively_canceled.errors[0].?,
    );
    if (!actively_canceled.completed[1]) {
        try canceler.await(io);
        canceler_active = false;
        thread.join();
        joined = true;
        std.debug.print("active sibling error={any} server={any} id={any} peer_closed={} http_live={} latched={any} stopped={any}\n", .{ actively_canceled.errors[1], worker.err, worker.active_stream_id, worker.active_peer_closed, worker.active_http_live, worker.active_latched, worker.active_stopped });
        if (worker.active_stream_id) |id| std.debug.print("client cancellation send={any} receive={any} recovery={d}\n", .{ client.established.connection.sendStreamStats(id), client.established.connection.recvStreamStats(id), client.established.connection.pendingRecoveryCount() });
        std.debug.print("CLIENT_TRACE\n{s}\nSERVER_TRACE\n{s}\n", .{ client_trace_output.buffered(), worker.active_trace orelse "" });
    }
    try std.testing.expect(actively_canceled.completed[1]);
    try std.testing.expect(actively_canceled.errors[1] == null);
    try canceler.await(io);
    canceler_active = false;

    thread.join();
    joined = true;
    if (worker.err) |err| return err;
    try std.testing.expectEqual(
        @as(?u64, http3.ApplicationErrorCode.request_cancelled),
        worker.cancellation_code,
    );
    try std.testing.expectEqual(
        @as(?u64, http3.ApplicationErrorCode.request_cancelled),
        worker.active_cancellation_code,
    );
    try std.testing.expect(client.isReusable());
}

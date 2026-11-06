//! Aggregate response heads make a later unprocessed GOAWAY unsafe to replay.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const grpc = @import("../../../grpc/call.zig");
const grpc_wire = @import("../../../grpc/wire.zig");
const channel = @import("../../../grpc/channel.zig");
const window = @import("../flow/window.zig");
const allocator = std.testing.allocator;
const message = "request-with-a-suspended-upload-suffix";
const path = "/demo.Commitment/Unary";
const timeout: std.Io.Duration = .fromSeconds(2);
const Scenario = enum { no_head, final_head, informational_head, forbidden_head, accepted, local_data_budget, local_window_error, accepted_window_error };

fn responseStarted(scenario: Scenario) bool {
    return scenario == .final_head or scenario == .informational_head or scenario == .forbidden_head;
}

fn localFailure(scenario: Scenario) bool {
    return scenario == .local_data_budget or scenario == .local_window_error or scenario == .accepted_window_error;
}

const Peer = struct {
    server: *runtime.Server,
    done: *std.Io.Event,
    scenario: Scenario,
    suspended: bool,
    is_grpc: bool,
    requests: usize = 0,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        self.serve() catch |err| {
            std.debug.print("GOAWAY peer failed: {s}, scenario={s}, suspended={}\n", .{ @errorName(err), @tagName(self.scenario), self.suspended });
            self.err = err;
        };
    }

    fn serve(self: *@This()) !void {
        const attempts: usize = if (self.is_grpc and self.scenario == .no_head) 2 else 1;
        for (0..attempts) |index| {
            var connection = try self.server.acceptWithTimeout(timeout);
            defer connection.close();
            if (self.suspended) {
                // Reading only the request head leaves the eight-byte stream
                // window exhausted. The aggregate reader must resume the
                // upload between HEADERS and GOAWAY without replaying it.
                var stream = try connection.acceptDuplexRequestWithTimeout(timeout);
                defer stream.deinit();
                self.requests += 1;
                try std.testing.expectEqualStrings(path, stream.path);
                try std.testing.expect(stream.expected_request_length.? > 8);
                if (localFailure(self.scenario)) {
                    // Drain the already-sent DATA prefix without granting
                    // credit: the event API would refund its eight bytes and
                    // let the client leave the initial blocked-send phase.
                    const before = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = timeout, .clock = .awake });
                    var prefix_seen = false;
                    for (0..16) |_| {
                        var frame = try runtime.testing.readOwnedServerDuplexFrameWithDeadline(&connection, stream.stream_id, before);
                        defer frame.deinit(allocator);
                        if (frame.frame.header.frame_type != .data) continue;
                        try std.testing.expectEqual(stream.stream_id, frame.frame.header.stream_id);
                        try std.testing.expectEqual(@as(usize, 8), (try http2.DataPayload.parse(frame.frame)).data.len);
                        try std.testing.expectEqual(@as(u8, 0), frame.frame.header.flags & 1);
                        prefix_seen = true;
                        break;
                    }
                    try std.testing.expect(prefix_seen);
                }
                try self.reject(&connection, stream.stream_id);
                return;
            }
            var request = try connection.readRequestWithTimeout(timeout);
            defer request.deinit(allocator);
            self.requests += 1;
            try std.testing.expectEqualStrings(path, request.path);
            if (self.is_grpc) {
                try std.testing.expect(grpc.headerValue(request.headers, "grpc-previous-rpc-attempts") == null);
                try std.testing.expectEqualStrings("preserved", grpc.headerValue(request.headers, "x-commitment").?);
                var parsed = try grpc.parseUnaryRequest(allocator, &request, 4096);
                defer parsed.deinit();
                try std.testing.expectEqualStrings(message, parsed.message.payload);
            } else {
                try std.testing.expectEqualStrings(if (self.scenario == .forbidden_head) "" else message, request.body);
            }
            if (index == 0 and self.scenario != .accepted) {
                try self.reject(&connection, request.stream_id);
                continue;
            }
            try connection.sendGoAwayWithTimeout(request.stream_id, .no_error, "accepted", timeout);
            if (self.is_grpc) {
                try grpc.writeUnaryResponse(&connection, allocator, request.stream_id, .{ .message = "reply" });
            } else {
                try connection.writeResponseWithTimeout(request.stream_id, .{ .body = "reply" }, timeout);
            }
        }
    }

    fn reject(self: *@This(), connection: *runtime.Connection, id: u31) !void {
        switch (self.scenario) {
            .final_head => {
                var writer = try connection.startResponseWithTimeout(id, .{
                    .headers = &.{.{ .name = "content-type", .value = "application/grpc" }},
                }, timeout);
                // Deliberately leave the response open for the contradictory
                // GOAWAY instead of appending DATA FIN or RST_STREAM.
                writer.finished = true;
            },
            .informational_head => try connection.writeInformationalResponseWithTimeout(id, 103, &.{}, timeout),
            .forbidden_head => try runtime.testing.writeHeaders(connection, id, &.{.{ .name = ":status", .value = "200" }}, false),
            .no_head => {},
            .accepted => unreachable,
            .local_data_budget => {
                var writer = try connection.startResponseWithTimeout(id, .{
                    .headers = &.{.{ .name = "content-type", .value = "application/grpc" }},
                }, timeout);
                try writer.writeWithTimeout("x", timeout);
                writer.finished = true;
            },
            .local_window_error, .accepted_window_error => {
                if (self.scenario == .accepted_window_error) try connection.sendGoAwayWithTimeout(id, .no_error, "accepted", timeout);
                // A nonzero remaining connection window overflows when the
                // peer grants the maximum increment, before any response head.
                try runtime.testing.writeRawFrame(connection, .window_update, 0, 0, &.{ 0x7f, 0xff, 0xff, 0xff });
            },
        }
        if (localFailure(self.scenario)) {
            // These failures originate at the client. The server never
            // declares this request unprocessed, and receives the precise
            // local protocol/policy GOAWAY instead of a replayed request.
            const before = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = timeout, .clock = .awake });
            var goaway_seen = false;
            for (0..16) |_| {
                var frame = try runtime.testing.readOwnedServerDuplexFrameWithDeadline(connection, id, before);
                defer frame.deinit(allocator);
                if (frame.frame.header.frame_type != .goaway) {
                    switch (frame.frame.header.frame_type) {
                        .settings, .ping, .window_update, .rst_stream => {},
                        else => return error.UnexpectedFrame,
                    }
                    continue;
                }
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try std.testing.expectEqual(@as(u31, 0), goaway.last_stream_id);
                try std.testing.expectEqual(if (self.scenario == .local_data_budget) http2.ErrorCode.enhance_your_calm else http2.ErrorCode.flow_control_error, goaway.error_code);
                try std.testing.expectEqualStrings(if (self.scenario == .local_data_budget) "too_many_data_frames" else "connection-window-overflow", goaway.debug_data);
                goaway_seen = true;
                break;
            }
            try std.testing.expect(goaway_seen);
            try self.done.wait(connection.io);
            return;
        }
        try connection.sendGoAwayWithTimeout(0, .no_error, "unprocessed", timeout);
        // Keep the socket open until the call returns so closing a peer with
        // an unread upload cannot race delivery of the response and GOAWAY.
        if (responseStarted(self.scenario)) try self.done.wait(connection.io);
    }
};

const Connector = struct {
    address: std.Io.net.IpAddress,
    limits: runtime.Limits = .{},
    calls: usize = 0,

    fn connect(context: ?*anyopaque, alloc: std.mem.Allocator, io: std.Io, deadline: std.Io.Clock.Timestamp) runtime.Error!runtime.Connection {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.calls += 1;
        return runtime.Client.connectWithDeadline(alloc, io, self.address, self.limits, deadline);
    }
};

fn unary(client: *channel.Channel) !void {
    var response = try client.unary(.{
        .path = path,
        .authority = "localhost",
        .message = message,
        .timeout = try grpc_wire.Timeout.fromDuration(timeout),
        .metadata = &.{.{ .name = "x-commitment", .value = "preserved" }},
    });
    defer response.deinit();
    try std.testing.expectEqual(grpc_wire.Status.ok, response.status);
    try std.testing.expectEqualStrings("reply", response.message.?.payload);
}

fn exerciseGrpc(scenario: Scenario, suspended: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .initial_window_size = if (suspended) 8 else 65_535,
    });
    defer server.deinit();
    var done: std.Io.Event = .unset;
    var peer: Peer = .{ .server = &server, .done = &done, .scenario = scenario, .suspended = suspended, .is_grpc = true };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        done.set(io);
        thread.join();
    };
    var connector: Connector = .{
        .address = server.address(),
        .limits = .{ .data_frame_budget = if (scenario == .local_data_budget) 0 else runtime.automatic_data_frame_budget },
    };
    var client = try channel.Channel.init(allocator, io, .{
        .custom = .{ .context = &connector, .connect_fn = Connector.connect },
    }, .{});
    defer client.deinit();
    const result = unary(&client);
    done.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    if (responseStarted(scenario) or localFailure(scenario)) {
        try std.testing.expectError(error.InvalidFrame, result);
    } else try result;
    const expected: usize = if (scenario == .no_head) 2 else 1;
    try std.testing.expectEqual(expected, connector.calls);
    try std.testing.expectEqual(expected, peer.requests);
}

fn http2Request(client: *runtime.Connection, scenario: Scenario) !void {
    var response = try client.requestWithTimeout(.{
        .method = if (scenario == .forbidden_head) "HEAD" else "POST",
        .path = path,
        .authority = "localhost",
        .body = if (scenario == .forbidden_head) "" else message,
    }, timeout);
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("reply", response.body);
}

fn exerciseHttp2(scenario: Scenario, suspended: bool) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .initial_window_size = if (suspended) 8 else 65_535,
    });
    defer server.deinit();
    var done: std.Io.Event = .unset;
    var peer: Peer = .{ .server = &server, .done = &done, .scenario = scenario, .suspended = suspended, .is_grpc = false };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) {
        done.set(io);
        thread.join();
    };
    var client = try runtime.Client.connectWithTimeout(allocator, io, server.address(), .{
        .data_frame_budget = if (scenario == .local_data_budget) 0 else runtime.automatic_data_frame_budget,
    }, timeout);
    defer client.close();
    const result = http2Request(&client, scenario);
    done.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    if (responseStarted(scenario) or localFailure(scenario)) {
        try std.testing.expectError(error.InvalidFrame, result);
    } else if (scenario == .no_head) {
        try std.testing.expectError(error.ConnectionGoAway, result);
        try std.testing.expectEqual(runtime.GoAwayRetryDisposition.safe_to_retry, client.goAwayRetryDisposition(1));
    } else {
        try result;
        try std.testing.expectEqual(runtime.GoAwayRetryDisposition.may_have_been_processed, client.goAwayRetryDisposition(1));
    }
    const peer_boundary: ?u31 = if (scenario == .accepted or scenario == .accepted_window_error) 1 else if (localFailure(scenario)) null else 0;
    try std.testing.expectEqual(peer_boundary, client.peerGoAwayLastStreamId());
    try std.testing.expectEqual(@as(usize, 0), client.activeLocalStreamCount());
    try std.testing.expectEqual(@as(usize, 0), client.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), client.recv_stream_windows.items.len);
    try std.testing.expect(!client.isReusable());
    if (localFailure(scenario)) {
        try std.testing.expect(client.aggregate_timeout_unusable);
        try std.testing.expectEqual(@as(?u31, 0), client.local_goaway_last_stream_id);
        try std.testing.expectEqual(window.default_value, client.recv_connection_window.value);
        try std.testing.expectEqual(if (scenario == .accepted_window_error) runtime.GoAwayRetryDisposition.may_have_been_processed else runtime.GoAwayRetryDisposition.no_goaway, client.goAwayRetryDisposition(1));
    }
    if (suspended) try std.testing.expectEqual(@as(i64, window.default_value - 8), client.send_connection_window.value);
}

test "gRPC ordinary aggregate GOAWAY does not replay final or informational response heads" {
    try exerciseGrpc(.final_head, false);
    try exerciseGrpc(.informational_head, false);
}

test "gRPC ordinary aggregate GOAWAY does not replay a suspended upload after response heads" {
    try exerciseGrpc(.final_head, true);
    try exerciseGrpc(.informational_head, true);
}

test "gRPC ordinary aggregate GOAWAY retries an unprocessed stream and completes an accepted stream" {
    try exerciseGrpc(.no_head, false);
    try exerciseGrpc(.accepted, false);
}

test "HTTP/2 aggregate GOAWAY preserves commitment cleanup and peer retirement" {
    for ([_]bool{ false, true }) |suspended| {
        try exerciseHttp2(.final_head, suspended);
        try exerciseHttp2(.informational_head, suspended);
    }
    try exerciseHttp2(.forbidden_head, false);
    try exerciseHttp2(.no_head, false);
    try exerciseHttp2(.accepted, false);
}

test "gRPC ordinary aggregate GOAWAY does not replay local DATA or window failures" {
    for ([_]Scenario{ .local_data_budget, .local_window_error, .accepted_window_error }) |scenario| {
        try exerciseGrpc(scenario, false);
        try exerciseHttp2(scenario, false);
    }
    // The initial upload has not created PendingResponse yet when flow credit
    // runs out. Its send failure needs the same proof as response reception.
    try exerciseGrpc(.local_window_error, true);
    try exerciseHttp2(.local_window_error, true);
}

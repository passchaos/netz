//! HTTP/2 graceful-shutdown tests moved out of the runtime test root.

const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
const http2 = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const BlockedOutput = @import("testing/blocked_output.zig").BlockedOutput;

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

test "HTTP/2 graceful shutdown sends maximum GOAWAY ping and final boundary" {
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
            connection.last_peer_client_stream_id = 3;
            connection.last_peer_processed_stream_id = 3;
            try connection.gracefulShutdown();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer client.close();

    var first = try client.readGoAway();
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u31), first.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, first.goaway.error_code);

    const shutdown_payload = [_]u8{ 0x0b, 0x7b, 0xa2, 0xf0, 0x8b, 0x9b, 0xfe, 0x54 };
    const observed = try client.readPing();
    try std.testing.expectEqualSlices(u8, &shutdown_payload, &observed);

    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), final.goaway.last_stream_id);
    try std.testing.expectEqual(http2.ErrorCode.no_error, final.goaway.error_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown admits request HEADERS before final GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        path: ?[]u8 = null,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            var request = try connection.readRequest();
            defer request.deinit(self.server.allocator);
            self.path = try self.server.allocator.dupe(u8, request.path);
        }
    };

    var shared = Shared{ .server = &server };
    defer if (shared.path) |path| allocator.free(path);
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();

    var first = try client.readGoAway();
    defer first.deinit(allocator);
    try std.testing.expectEqual(std.math.maxInt(u31), first.goaway.last_stream_id);
    var ping_frame = try client.readOwnedFrame();
    defer ping_frame.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping_frame.frame.header.frame_type);
    const ping_data = (try http2.PingPayload.parse(ping_frame.frame)).data;
    try std.testing.expectEqualSlices(
        u8,
        &graceful_shutdown_ping_payload,
        &ping_data,
    );

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/during-shutdown" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":authority", .value = "localhost" },
    });
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_headers | flag_end_stream,
        1,
        block.items,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        flag_ack,
        0,
        &graceful_shutdown_ping_payload,
    );

    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), final.goaway.last_stream_id);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings("/during-shutdown", shared.path.?);
}

test "HTTP/2 graceful shutdown refuses overload and retires queued marker" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_concurrent_streams = 1 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        marker_count: usize = 99,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            try std.testing.expectEqual(
                @as(?u31, 1),
                connection.local_goaway_last_stream_id,
            );
            while (connection.graceful_preadmitted_peer_streams.items.len != 0) {
                const frame = (try connection.readBufferedFrame()).frame;
                if (frame.header.frame_type == .headers and
                    connection.gracefulPreadmittedIndex(
                        frame.header.stream_id,
                    ) != null)
                {
                    const headers = try connection.readHeaderBlock(frame);
                    freeHeaders(self.server.allocator, headers);
                    if (connection.gracefulPreadmittedIndex(
                        frame.header.stream_id,
                    )) |index| {
                        _ = connection.graceful_preadmitted_peer_streams
                            .orderedRemove(index);
                    }
                    continue;
                }
                if (try connection.handleConnectionFrame(frame)) continue;
                return error.UnexpectedFrame;
            }
            self.marker_count =
                connection.graceful_preadmitted_peer_streams.items.len;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_concurrent_streams = 1 },
    );
    defer client.close();
    _ = try client.sendCompleteRequest(.{
        .path = "/held",
        .authority = "localhost",
    });

    var initial = try client.readGoAway();
    defer initial.deinit(allocator);
    var ping = try client.readOwnedFrame();
    defer ping.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping.frame.header.frame_type);
    try client.writeHeaders(3, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/refused-during-shutdown" },
        .{ .name = ":scheme", .value = "http" },
    }, true);
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        flag_ack,
        0,
        ping.frame.payload,
    );
    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.refused_stream,
        reset.reset.error_code,
    );
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), final.goaway.last_stream_id);
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        0,
        0,
        &.{ 7, 6, 5, 4, 3, 2, 1, 0 },
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 0), shared.marker_count);
}

test "HTTP/2 graceful shutdown preadmits dependent HPACK blocks in order" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqualStrings("/one", first.path);
            try std.testing.expectEqualStrings("/two", second.path);
            try std.testing.expectEqualStrings(
                "shared",
                findHeader(second.headers, "x-dynamic").?,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var initial = try client.readGoAway();
    defer initial.deinit(allocator);
    var ping_frame = try client.readOwnedFrame();
    defer ping_frame.deinit(allocator);

    var encoder = http2.Hpack.Encoder{};
    defer encoder.deinit(allocator);
    const block_one = try allocator.dupe(u8, try encoder.encodeBlockRetained(
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/one" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = "x-dynamic", .value = "shared" },
        },
    ));
    defer allocator.free(block_one);
    const block_two = try allocator.dupe(u8, try encoder.encodeBlockRetained(
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/two" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = "x-dynamic", .value = "shared" },
        },
    ));
    defer allocator.free(block_two);
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 1, block_one);
    try writeFrame(allocator, io, client.stream, .headers, flag_end_headers | flag_end_stream, 3, block_two);
    try writeFrame(allocator, io, client.stream, .ping, flag_ack, 0, &graceful_shutdown_ping_payload);

    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), final.goaway.last_stream_id);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown ignores stale PING ACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var first = try client.readGoAway();
    defer first.deinit(allocator);
    var ping_frame = try client.readOwnedFrame();
    defer ping_frame.deinit(allocator);
    try std.testing.expectEqual(http2.FrameType.ping, ping_frame.frame.header.frame_type);

    const stale = [_]u8{ 1, 3, 3, 7, 0, 0, 0, 1 };
    try writeFrame(allocator, io, client.stream, .ping, flag_ack, 0, &stale);
    try writeFrame(
        allocator,
        io,
        client.stream,
        .ping,
        flag_ack,
        0,
        &graceful_shutdown_ping_payload,
    );
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), final.goaway.last_stream_id);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown rejects client role before writing" {
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
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.UnexpectedFrame, connection.gracefulShutdown());
    try std.testing.expectEqual(@as(?u31, null), connection.local_goaway_last_stream_id);
}

test "HTTP/2 graceful shutdown reserves its synchronization PING" {
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
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.InvalidFrame,
        connection.ping(graceful_shutdown_ping_payload),
    );
}

test "HTTP/2 completed graceful shutdown ignores expired wait budgets" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .graceful_shutdown_phase = .complete,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try connection.gracefulShutdownWithTimeout(.zero);
    try connection.gracefulShutdownWithDeadline(.{
        .raw = .zero,
        .clock = .real,
    });
}

test "HTTP/2 graceful shutdown write failure is terminal" {
    try native_protocol_io.runStream(gracefulShutdownWriteFailureIsTerminal);
}

fn gracefulShutdownWriteFailureIsTerminal(io: std.Io) !void {
    const FailingWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(header.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: FailingWriter = .{ .delegate = io };
    const observed_io = forwarded_io.observer(&writer, .{ .netWrite = FailingWriter.write });
    var connection = Connection{
        .io = observed_io,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(error.NetworkDown, connection.gracefulShutdown());
    const writes = writer.writes;
    try std.testing.expectError(error.ConnectionClosed, connection.gracefulShutdown());
    try std.testing.expectEqual(writes, writer.writes);
}

test "HTTP/2 graceful shutdown deadline bounds a blocked GOAWAY write" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.initStalled(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;

    try std.testing.expectError(
        error.Timeout,
        connection.gracefulShutdownWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(.failed, connection.graceful_shutdown_phase);
    try std.testing.expectEqual(
        @as(?u31, null),
        connection.local_goaway_last_stream_id,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
}

test "HTTP/2 graceful shutdown fails closed when PING ACK write times out" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try BlockedOutput.initStalled(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    connection.local_goaway_last_stream_id = std.math.maxInt(u31);
    connection.graceful_shutdown_phase = .synchronizing;
    var ping_storage: [http2.PingPayload.encoded_len]u8 = undefined;
    const peer_ping = http2.PingPayload.writeInto(
        &ping_storage,
        .{ 9, 8, 7, 6, 5, 4, 3, 2 },
        false,
    );
    try connection.frame_reader.buffer.appendSlice(allocator, peer_ping);

    try std.testing.expectError(
        error.Timeout,
        connection.gracefulShutdownWithTimeout(.fromMilliseconds(20)),
    );
    try std.testing.expectEqual(.failed, connection.graceful_shutdown_phase);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.gracefulShutdownWithTimeout(.fromSeconds(1)),
    );
}

test "HTTP/2 graceful shutdown bounds final GOAWAY write" {
    try native_protocol_io.runStream(gracefulShutdownBoundsFinalGoawayWrite);
}

fn gracefulShutdownBoundsFinalGoawayWrite(io: std.Io) !void {
    const RecordingWriter = struct {
        delegate: std.Io,
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            var total = header.len;
            for (data[0 .. data.len - 1]) |part| total += part.len;
            total += data[data.len - 1].len * splat;
            self.bytes.appendSlice(std.testing.allocator, header) catch {
                return error.SystemResources;
            };
            for (data[0 .. data.len - 1]) |part| {
                self.bytes.appendSlice(std.testing.allocator, part) catch {
                    return error.SystemResources;
                };
            }
            var repeated: usize = 0;
            while (repeated < splat) : (repeated += 1) {
                self.bytes.appendSlice(
                    std.testing.allocator,
                    data[data.len - 1],
                ) catch return error.SystemResources;
            }
            return total;
        }
    };

    var writer: RecordingWriter = .{ .delegate = io };
    defer writer.bytes.deinit(std.testing.allocator);
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = RecordingWriter.write }),
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
        .local_goaway_last_stream_id = std.math.maxInt(u31),
        .graceful_shutdown_phase = .synchronized,
    };
    defer {
        connection.send_stream_windows.deinit(std.testing.allocator);
        connection.send_stream_window_index.deinit(std.testing.allocator);
        connection.recv_stream_windows.deinit(std.testing.allocator);
        connection.recv_stream_window_index.deinit(std.testing.allocator);
        connection.active_local_streams.deinit(std.testing.allocator);
        connection.active_local_index.deinit(std.testing.allocator);
        connection.active_peer_streams.deinit(std.testing.allocator);
        connection.active_peer_index.deinit(std.testing.allocator);
        connection.hpack_decoder.deinit(std.testing.allocator);
        connection.hpack_encoder.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.Timeout,
        connection.gracefulShutdownWithDeadline(.{
            .raw = .zero,
            .clock = .real,
        }),
    );
    try std.testing.expect(!connection.gracefulShutdownComplete());
    try std.testing.expectEqual(
        .synchronized,
        connection.graceful_shutdown_phase,
    );
    try std.testing.expectEqual(@as(usize, 0), writer.bytes.items.len);
}

test "HTTP/2 graceful shutdown timeout resumes one outstanding ping" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        first_ping_seen: std.Io.Event = .unset,
        allow_ack: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
                shared.first_ping_seen.set(shared.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            // The client side drives graceful shutdown in this white-box test;
            // it needs a server-role connection without a second frame reader.
            var connection = try shared.server.accept();
            defer connection.close();
            // The peer SETTINGS ACK is the final handshake frame queued by
            // Client.connect; consume it before observing shutdown frames.
            while (true) {
                var frame = try readFrame(
                    shared.server.allocator,
                    shared.io,
                    connection.stream,
                    shared.server.limits,
                );
                defer frame.deinit(shared.server.allocator);
                if (frame.frame.header.frame_type == .settings and
                    (frame.frame.header.flags & flag_ack) != 0)
                {
                    break;
                }
            }
            var first = try readFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                shared.server.limits,
            );
            defer first.deinit(shared.server.allocator);
            try std.testing.expectEqual(http2.FrameType.goaway, first.frame.header.frame_type);
            var ping = try readFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                shared.server.limits,
            );
            defer ping.deinit(shared.server.allocator);
            try std.testing.expectEqual(http2.FrameType.ping, ping.frame.header.frame_type);
            try std.testing.expectEqual(@as(u8, 0), ping.frame.header.flags & flag_ack);
            shared.first_ping_seen.set(shared.io);
            try shared.allow_ack.wait(shared.io);
            try writeFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                .ping,
                flag_ack,
                0,
                ping.frame.payload,
            );
            var final = try readFrame(
                shared.server.allocator,
                shared.io,
                connection.stream,
                shared.server.limits,
            );
            defer final.deinit(shared.server.allocator);
            try std.testing.expectEqual(http2.FrameType.goaway, final.frame.header.frame_type);
            try std.testing.expectEqual(@as(u31, 0), (try http2.GoAwayPayload.parse(final.frame)).last_stream_id);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.allow_ack.set(io);
        thread.join();
    };

    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    client.role = .server;
    try std.testing.expectError(
        error.Timeout,
        client.gracefulShutdownWithTimeout(.fromMilliseconds(20)),
    );
    try shared.first_ping_seen.wait(io);
    shared.allow_ack.set(io);
    try client.gracefulShutdownWithTimeout(.fromSeconds(1));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown narrows an existing local GOAWAY" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.sendGoAway(7, .no_error, "draining");
            try connection.gracefulShutdown();
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();

    var first = try client.readGoAway();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 7), first.goaway.last_stream_id);
    const ping_data = try client.readPing();
    try std.testing.expectEqualSlices(
        u8,
        &graceful_shutdown_ping_payload,
        &ping_data,
    );
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), final.goaway.last_stream_id);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 graceful shutdown ignores streams above final boundary" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            try connection.gracefulShutdown();
            // Stream 1 is above the final zero boundary. Its HEADERS must be
            // decoded and ignored so the following connection PING remains
            // usable rather than surfacing ConnectionGoAway.
            const observed = try connection.readPing();
            try std.testing.expectEqualSlices(
                u8,
                &[_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 },
                &observed,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var first = try client.readGoAway();
    defer first.deinit(allocator);
    _ = try client.readPing();
    var final = try client.readGoAway();
    defer final.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 0), final.goaway.last_stream_id);

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/too-late" },
        .{ .name = ":scheme", .value = "http" },
    });
    try writeFrame(
        allocator,
        io,
        client.stream,
        .headers,
        flag_end_headers | flag_end_stream,
        1,
        block.items,
    );
    const payload = [_]u8{ 9, 8, 7, 6, 5, 4, 3, 2 };
    try writeFrame(allocator, io, client.stream, .ping, 0, 0, &payload);
    while (true) {
        var frame = try client.readOwnedFrame();
        defer frame.deinit(allocator);
        if (frame.frame.header.frame_type != .ping) continue;
        try std.testing.expect((frame.frame.header.flags & flag_ack) != 0);
        break;
    }

    thread.join();
    if (shared.err) |err| return err;
}

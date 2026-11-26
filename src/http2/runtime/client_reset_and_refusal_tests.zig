//! HTTP/2 client reset, sibling drain, and refusal tests.

const std = @import("std");
const forwarded_io = @import("../../internal/testing/forwarded_io.zig");
const native_protocol_io = @import("../../internal/testing/native_protocol_io.zig");
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

test "HTTP/2 local protocol error reset budget closes real connection" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .max_local_error_reset_streams = 1,
    };

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        io: std.Io,
        ready: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.ready.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var first = try connection.readRequest();
            defer first.deinit(self.server.allocator);
            var second = try connection.readRequest();
            defer second.deinit(self.server.allocator);
            try std.testing.expectEqual(@as(u31, 1), first.stream_id);
            try std.testing.expectEqual(@as(u31, 3), second.stream_id);
            (try connection.sendStreamWindow(first.stream_id)).value =
                max_flow_window;
            (try connection.sendStreamWindow(second.stream_id)).value =
                max_flow_window;
            self.ready.set(self.io);

            if (connection.readRequestWithTimeout(.fromSeconds(2))) |request| {
                var unexpected = request;
                unexpected.deinit(self.server.allocator);
                return error.TestUnexpectedResult;
            } else |err| {
                try std.testing.expectEqual(
                    error.ConnectionGoAway,
                    err,
                );
            }
            try std.testing.expectEqual(
                @as(usize, 1),
                connection.local_error_reset_streams,
            );
            try std.testing.expect(connection.aggregate_timeout_unusable);
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    _ = try client.sendCompleteRequest(.{
        .path = "/first",
        .authority = "localhost",
    });
    _ = try client.sendCompleteRequest(.{
        .path = "/second",
        .authority = "localhost",
    });
    try shared.ready.wait(io);
    if (shared.err) |err| return err;

    const overflow = [_]u8{ 0, 0, 0, 1 };
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        1,
        &overflow,
    );
    try writeFrame(
        allocator,
        io,
        client.stream,
        .window_update,
        0,
        3,
        &overflow,
    );

    var reset = try client.readResetStreamWithTimeout(.fromSeconds(2));
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), reset.reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.flow_control_error,
        reset.reset.error_code,
    );

    var goaway = try client.readGoAwayWithTimeout(.fromSeconds(2));
    defer goaway.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 3), goaway.goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_internal_resets",
        goaway.goaway.debug_data,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 client ignores in-flight frames after local reset" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
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
            var first = try connection.readRequest();
            defer first.deinit(server_ptr.allocator);
            var second = try connection.readRequest();
            defer second.deinit(server_ptr.allocator);

            try connection.writeHeaders(first.stream_id, &.{.{
                .name = ":status",
                .value = "200",
            }}, false);
            try writeFrame(
                server_ptr.allocator,
                server_ptr.io,
                connection.stream,
                .data,
                0,
                first.stream_id,
                "late",
            );
            try connection.writeHeaders(first.stream_id, &.{.{
                .name = "x-late-trailer",
                .value = "discarded",
            }}, true);
            try connection.writeResponse(second.stream_id, .{
                .status = 200,
                .body = "ok",
                .request_method = second.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    const first = try client.sendCompleteRequest(.{
        .path = "/cancel",
        .authority = "localhost",
    });
    const second = try client.sendCompleteRequest(.{
        .path = "/sibling",
        .authority = "localhost",
    });
    try client.sendResetStream(first.stream_id, .cancel);

    var response = try client.readResponse(
        second.stream_id,
        second.request_method,
        second.extended_connect,
        null,
    );
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len),
        client.recv_connection_window.value,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 client drains buffered sibling after reset peer close" {
    try native_protocol_io.runStream(clientDrainsBufferedSiblingAfterResetPeerClose);
}

fn clientDrainsBufferedSiblingAfterResetPeerClose(io: std.Io) !void {
    const allocator = std.testing.allocator;

    // Model the exact race deterministically: one transport read has already
    // retained both streams, then the peer closes before the client returns
    // connection credit for DATA that raced with its RST_STREAM.
    var buffered_frames: std.ArrayList(u8) = .empty;
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .data,
        0,
        1,
        "late",
    );
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .headers,
        flag_end_headers,
        3,
        &.{0x88}, // HPACK static-table index for `:status: 200`.
    );
    try appendFrameBytes(
        &buffered_frames,
        allocator,
        .data,
        flag_end_stream,
        3,
        "ok",
    );

    const ClosedWriter = struct {
        delegate: std.Io,
        writes: usize = 0,
        fail_with_network_down: bool = false,

        fn now(
            _: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            return .zero;
        }

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.fail_with_network_down) return error.NetworkDown;
            return error.SocketUnconnected;
        }
    };

    var writer: ClosedWriter = .{ .delegate = io };
    const closed_io = forwarded_io.observer(&writer, .{
        .now = ClosedWriter.now,
        .netWrite = ClosedWriter.write,
    });

    var connection = Connection{
        .io = closed_io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .frame_reader = .{ .buffer = buffered_frames },
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.frame_reader.deinit(allocator);
    }
    try connection.prepareLocallyResetStreamsAt(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);

    var response = try connection.readResponse(3, "GET", false, null);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), writer.writes);
    try std.testing.expectEqualStrings("ok", response.body);
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len),
        connection.recv_connection_window.value,
    );

    connection.recv_connection_window.value -= 7;
    writer.fail_with_network_down = true;
    try std.testing.expectError(
        error.NetworkDown,
        connection.releaseLateResetConnectionCapacity(7),
    );
    // Non-terminal transport failures remain observable and the generic
    // WINDOW_UPDATE transaction must roll its optimistic accounting back.
    try std.testing.expectEqual(
        @as(i64, default_flow_window - "ok".len - 7),
        connection.recv_connection_window.value,
    );
}

test "HTTP/2 ignores unknown extension connection frames" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };

    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = 3,
            .frame_type = @enumFromInt(0xff),
            .flags = 0xa5,
            .stream_id = 0,
        },
        .payload = "ext",
    }));
    try std.testing.expect(!try connection.handleConnectionFrame(.{
        .header = .{
            .length = 0,
            .frame_type = .data,
            .flags = flag_end_stream,
            .stream_id = 1,
        },
        .payload = &.{},
    }));
}

test "HTTP/2 ignores WINDOW_UPDATE for inactive streams" {
    var connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
        .next_client_stream_id = 3,
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

    const inactive_update = http2.Frame{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 1 },
        .payload = &.{ 0, 0, 0, 10 },
    };
    try std.testing.expect(try connection.handleConnectionFrame(inactive_update));
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);

    try connection.addActiveLocalStream(1);
    try std.testing.expect(try connection.handleConnectionFrame(inactive_update));
    try std.testing.expectEqual(@as(usize, 1), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(i64, default_flow_window + 10), (try connection.sendStreamWindow(1)).value);

    const peer_update = http2.Frame{
        .header = .{ .length = 4, .frame_type = .window_update, .flags = 0, .stream_id = 3 },
        .payload = &.{ 0, 0, 0, 7 },
    };
    try connection.addActivePeerStream(3);
    try std.testing.expect(try connection.handleConnectionFrame(peer_update));
    try std.testing.expectEqual(@as(i64, default_flow_window + 7), (try connection.sendStreamWindow(3)).value);
}

test "HTTP/2 stream window helpers reject connection stream id" {
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

    try std.testing.expectError(error.InvalidStreamId, connection.sendStreamWindow(0));
    try std.testing.expectError(error.InvalidStreamId, connection.recvStreamWindow(0));
    try std.testing.expectEqual(@as(usize, 0), connection.send_stream_windows.items.len);
    try std.testing.expectEqual(@as(usize, 0), connection.recv_stream_windows.items.len);
}

test "HTTP/2 reset retirement clears both stream windows" {
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

    _ = try connection.sendStreamWindow(1);
    _ = try connection.recvStreamWindow(1);
    connection.forgetStreamWindows(1);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.send_stream_windows.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.recv_stream_windows.items.len,
    );
    try std.testing.expect(!connection.send_stream_window_index.contains(1));
    try std.testing.expect(!connection.recv_stream_window_index.contains(1));
}

test "HTTP/2 refusal write failure makes later request reads terminal" {
    try native_protocol_io.runStream(refusalWriteFailureMakesLaterRequestReadsTerminal);
}

fn refusalWriteFailureMakesLaterRequestReadsTerminal(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
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

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http2.Hpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/refused" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(
        error.NetworkDown,
        connection.refusePeerRequestStreamUntil(
            3,
            .{
                .header = .{
                    .length = @intCast(block.items.len),
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = 3,
                },
                .payload = block.items,
            },
            null,
            false,
        ),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
    try std.testing.expect(!connection.wasLocallyResetAt(3, 0));
}

test "HTTP/2 refusal decode failure makes later request reads terminal" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    try std.testing.expectError(
        error.MessageTooLarge,
        connection.refusePeerRequestStreamUntil(
            3,
            .{
                .header = .{
                    .length = 1,
                    .frame_type = .headers,
                    .flags = flag_end_headers,
                    .stream_id = 3,
                },
                // An indexed integer whose continuation byte is missing.
                .payload = &.{0xff},
            },
            null,
            false,
        ),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(error.ConnectionClosed, connection.readRequest());
}

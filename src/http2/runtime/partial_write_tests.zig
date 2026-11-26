//! HTTP/2 partial-write and fail-closed tests.

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

test "HTTP/2 bodyless request batch partial HEADERS write fails closed" {
    try native_protocol_io.runStream(bodylessRequestBatchPartialHeadersWriteFailsClosed);
}

fn bodylessRequestBatchPartialHeadersWriteFailsClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    const requests = [_]RequestOptions{
        .{ .path = "/first", .authority = "localhost" },
        .{ .path = "/second", .authority = "localhost" },
    };
    var responses: [requests.len]OwnedResponse = undefined;
    try std.testing.expectError(
        error.NetworkDown,
        connection.requestBatchInto(&requests, &responses),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(u31, 5), connection.next_client_stream_id);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
}

test "HTTP/2 single request partial HEADERS write fails closed" {
    try native_protocol_io.runStream(singleRequestPartialHeadersWriteFailsClosed);
}

fn singleRequestPartialHeadersWriteFailsClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expectEqual(@as(usize, 0), connection.activeLocalStreamCount());
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.isReusable());
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendCompleteRequest(.{ .authority = "localhost" }),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 single HEADERS encode failure preserves live HPACK state" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .default_scheme = "http",
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.write_batch.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }

    _ = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{
        .name = "x-live",
        .value = "one",
    }});
    const live_entries =
        connection.hpack_encoder.dynamic_table.entries.items.len;
    try connection.addActiveLocalStream(1);
    {
        var failing = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            connection.writeHeaders(1, &.{.{
                .name = "x-staged",
                .value = "two",
            }}, true),
        );
        try std.testing.expect(failing.has_induced_failure);
    }
    try std.testing.expectEqual(
        live_entries,
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expect(connection.outboundStreamIsActive(1));
}

test "HTTP/2 PUSH_PROMISE partial write rolls back state and fails closed" {
    try native_protocol_io.runStream(pushPromisePartialWriteRollsBackStateAndFailsClosed);
}

fn pushPromisePartialWriteRollsBackStateAndFailsClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.push_state.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.response_semantics.deinit(allocator);
        connection.response_semantics_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
        connection.deinitStagedHpackEncoder();
    }
    try connection.addActivePeerStream(1);

    const headers = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-push-dynamic", .value = "one" },
    };
    try std.testing.expectError(
        error.NetworkDown,
        connection.promisePush(1, &headers),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.push_state.localStatus(2) == null);
    try std.testing.expect(!connection.response_semantics_index.contains(2));
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.promisePush(1, &headers),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 partial DATA frame write fails connection closed" {
    try native_protocol_io.runStream(partialDataFrameWriteFailsConnectionClosed);
}

fn partialDataFrameWriteFailsConnectionClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeData(1, "payload", false),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writeData(1, "retry", false),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 partial extension control write fails connection closed" {
    try native_protocol_io.runStream(partialExtensionControlWriteFailsConnectionClosed);
}

fn partialExtensionControlWriteFailsConnectionClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.deinitPeerMetadata();
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.sendOrigins(&.{"https://example.com"}),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendAlternativeService(
            0,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 application batch reset partial write fails closed" {
    try native_protocol_io.runStream(applicationBatchResetPartialWriteFailsClosed);
}

fn applicationBatchResetPartialWriteFailsClosed(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: std.atomic.Value(usize) = .init(0),

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.writes.fetchAdd(1, .monotonic) == 0) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const peer = listener.accept(io) catch |err| {
        stream.close(io);
        return err;
    };
    defer peer.close(io);
    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = stream,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 0 },
    };
    defer {
        connection.io = io;
        connection.close();
    }

    const states = [_]Connection.BatchResponseState{
        .{
            .stream_id = 1,
            .request_method = "GET",
            .extended_connect = false,
        },
        .{
            .stream_id = 3,
            .request_method = "GET",
            .extended_connect = false,
        },
    };
    try std.testing.expectError(
        error.NetworkDown,
        connection.writeBatchResponseResets(&states),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes.load(.acquire));
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendGoAway(0, .no_error, &.{}),
    );
    var responses: [1]OwnedResponse = undefined;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.requestBatchInto(
            &.{.{ .authority = "localhost" }},
            &responses,
        ),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes.load(.acquire));
}

test "HTTP/2 adaptive window partial write fails closed without local commit" {
    try native_protocol_io.runStream(adaptiveWindowPartialWriteFailsClosedWithoutLocalCommit);
}

fn adaptiveWindowPartialWriteFailsClosedWithoutLocalCommit(io: std.Io) !void {
    const allocator = std.testing.allocator;
    const PartialWriter = struct {
        delegate: std.Io,
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            bytes: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            if (self.writes == 1) return @min(bytes.len, 4);
            return error.NetworkDown;
        }
    };

    var writer: PartialWriter = .{ .delegate = io };
    var connection = Connection{
        .io = forwarded_io.observer(&writer, .{ .netWrite = PartialWriter.write }),
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
    }

    const target: u32 = 100_000;
    try std.testing.expectError(
        error.NetworkDown,
        connection.sendAdaptiveWindowUpdate(target),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_connection_window_target,
    );
    try std.testing.expectEqual(
        @as(u32, @intCast(default_flow_window)),
        connection.recv_stream_window_target,
    );
    try std.testing.expect(!connection.awaiting_settings_ack);
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendWindowUpdate(0, 1),
    );
    try std.testing.expectEqual(@as(usize, 2), writer.writes);
}

test "HTTP/2 internal error GOAWAY bypasses public fail-fast guard" {
    if (comptime builtin.os.tag != .linux) return;
    try native_protocol_io.runStream(internalErrorGoawayBypassesPublicFailFastGuard);
}

fn internalErrorGoawayBypassesPublicFailFastGuard(io: std.Io) !void {
    const RecordingWriter = struct {
        delegate: std.Io,
        bytes: [128]u8 = undefined,
        len: usize = 0,
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
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var writer: RecordingWriter = .{ .delegate = io };
    var fixture = try @import("testing/blocked_output.zig").BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    connection.io = forwarded_io.observer(&writer, .{ .netWrite = RecordingWriter.write });
    defer connection.io = io;
    connection.serve_read_connection_error = .frame_sequence;

    connection.sendServeReadError(error.UnexpectedFrame);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(writer.len != 0);
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    try std.testing.expectEqual(http2.FrameType.goaway, frame.header.frame_type);
    const goaway = try http2.GoAwayPayload.parse(frame);
    try std.testing.expectEqual(http2.ErrorCode.protocol_error, goaway.error_code);
    try std.testing.expectEqualStrings("frame-sequence", goaway.debug_data);

    const writes = writer.writes;
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.sendGoAway(0, .no_error, &.{}),
    );
    try std.testing.expectEqual(writes, writer.writes);
}

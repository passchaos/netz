//! HTTP/2 reset-history, protocol-error-budget, and refusal tests.

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

test "HTTP/2 local reset history honors capacity and retention duration" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 2 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    const second: i96 = std.time.ns_per_s;
    try connection.prepareLocallyResetStreamsAt(3, 0);
    try std.testing.expect(connection.locally_reset_streams.capacity >= 2);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(3, 0);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    // Duplicate resets do not consume another slot.
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, second / 2);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.locallyResetStreamCount(),
    );
    // Capacity pressure cannot evict IDs before their minimum retention time.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, second / 2);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    try std.testing.expect(connection.wasLocallyResetAt(1, second));
    try std.testing.expect(connection.wasLocallyResetAt(3, second));
    try std.testing.expect(!connection.wasLocallyResetAt(5, second));

    // Expiration is strict: exactly one second remains tolerated, while the
    // first later nanosecond reclaims both FIFO entries for new resets.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, second + 1);
    connection.rememberLocallyResetStreamAtAssumeCapacity(7, second + 1);
    try std.testing.expectEqual(
        connection.locallyResetStreamCount(),
        connection.locally_reset_stream_index.count(),
    );
    try std.testing.expect(!connection.wasLocallyResetAt(1, second + 1));
    try std.testing.expect(!connection.wasLocallyResetAt(3, second + 1));
    try std.testing.expect(connection.wasLocallyResetAt(5, second + 1));
    try std.testing.expect(connection.wasLocallyResetAt(7, second + 1));

    // An expired duplicate is a fresh reset and receives a new retention
    // deadline instead of being discarded by a stale hash hit.
    connection.rememberLocallyResetStreamAtAssumeCapacity(5, 2 * second + 2);
    try std.testing.expect(connection.wasLocallyResetAt(5, 3 * second + 2));
    try std.testing.expect(!connection.wasLocallyResetAt(5, 3 * second + 3));
}

test "HTTP/2 local reset history may be disabled" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 0 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.prepareLocallyResetStreamsAt(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.locally_reset_streams.capacity,
    );
    try std.testing.expect(!connection.wasLocallyResetAt(1, 0));
}

test "HTTP/2 configured reset history controls late-frame tolerance" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
    }

    try connection.prepareLocallyResetStreamsAt(2, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(1, 0);
    connection.rememberLocallyResetStreamAtAssumeCapacity(3, 0);
    const reset_payload = [_]u8{ 0, 0, 0, 8 };
    try std.testing.expect(try connection
        .discardLateFrameForLocallyResetStreamAt(.{
        .header = .{
            .length = reset_payload.len,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = 1,
        },
        .payload = &reset_payload,
    }, 0));
    try std.testing.expect(!try connection
        .discardLateFrameForLocallyResetStreamAt(.{
        .header = .{
            .length = reset_payload.len,
            .frame_type = .rst_stream,
            .flags = 0,
            .stream_id = 3,
        },
        .payload = &reset_payload,
    }, 0));
}

test "HTTP/2 local protocol error reset budget emits terminal GOAWAY" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            var repeated: usize = 0;
            while (repeated < splat) : (repeated += 1) {
                total += data[data.len - 1].len;
                self.bytes.appendSlice(
                    allocator,
                    data[data.len - 1],
                ) catch return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(allocator);
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = test_socket.stream(),
        .role = .server,
        .limits = .{ .max_local_error_reset_streams = 1 },
        .last_peer_processed_stream_id = 3,
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.writeLocalErrorResetStream(
        1,
        .flow_control_error,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.local_error_reset_streams,
    );
    try std.testing.expect(!connection.aggregate_timeout_unusable);

    const reset_frame = try http2.Frame.parse(writer.bytes.items);
    try std.testing.expectEqual(
        http2.FrameType.rst_stream,
        reset_frame.header.frame_type,
    );
    const reset = try http2.ResetStreamPayload.parse(reset_frame);
    try std.testing.expectEqual(@as(u31, 1), reset.stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.flow_control_error,
        reset.error_code,
    );

    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.writeLocalErrorResetStream(3, .protocol_error),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.local_error_reset_streams,
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);

    const goaway_frame = try http2.Frame.parse(
        writer.bytes.items[reset_frame.consumed()..],
    );
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway_frame.header.frame_type,
    );
    const goaway = try http2.GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 3), goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_internal_resets",
        goaway.debug_data,
    );
    try std.testing.expectEqual(
        writer.bytes.items.len,
        reset_frame.consumed() + goaway_frame.consumed(),
    );
}

test "HTTP/2 excessive padded empty DATA emits terminal GOAWAY" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        var active: std.atomic.Value(?*@This()) = .init(null);
        bytes: std.ArrayList(u8) = .empty,

        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self = active.load(.acquire).?;
            var total = header.len;
            self.bytes.appendSlice(allocator, header) catch
                return error.SystemResources;
            for (data[0 .. data.len - 1]) |part| {
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            for (0..splat) |_| {
                const part = data[data.len - 1];
                total += part.len;
                self.bytes.appendSlice(allocator, part) catch
                    return error.SystemResources;
            }
            return total;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    defer writer.bytes.deinit(allocator);
    RecordingWriter.active.store(&writer, .release);
    defer RecordingWriter.active.store(null, .release);
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = threaded.io().userdata, .vtable = &vtable },
        .allocator = allocator,
        .stream = test_socket.stream(),
        .role = .server,
        .last_peer_processed_stream_id = 1,
    };
    defer {
        connection.send_stream_windows.deinit(allocator);
        connection.send_stream_window_index.deinit(allocator);
        connection.recv_stream_windows.deinit(allocator);
        connection.recv_stream_window_index.deinit(allocator);
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }
    connection.applyLocalLimits();

    // PADDED with Pad Length 1 and one padding octet has no application
    // payload. Flow control still charges both bytes, while the independent
    // lifetime frame-count guard rejects the 101st non-final empty DATA.
    const padded_empty = [_]u8{ 1, 0 };
    const frame = http2.Frame{
        .header = .{
            .length = padded_empty.len,
            .frame_type = .data,
            .flags = 0x08,
            .stream_id = 1,
        },
        .payload = &padded_empty,
    };
    for (0..data_frame_budget.max_empty_frames) |_| {
        const data = try connection.receiveDataPayload(1, frame);
        defer connection.releaseDataFrameBudget(data);
        try std.testing.expectEqual(@as(usize, 0), data.data.len);
    }
    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.receiveDataPayload(1, frame),
    );
    try std.testing.expect(connection.aggregate_timeout_unusable);

    const goaway_frame = try http2.Frame.parse(writer.bytes.items);
    try std.testing.expectEqual(
        http2.FrameType.goaway,
        goaway_frame.header.frame_type,
    );
    const goaway = try http2.GoAwayPayload.parse(goaway_frame);
    try std.testing.expectEqual(@as(u31, 1), goaway.last_stream_id);
    try std.testing.expectEqual(
        http2.ErrorCode.enhance_your_calm,
        goaway.error_code,
    );
    try std.testing.expectEqualStrings(
        "too_many_data_frames",
        goaway.debug_data,
    );
}

test "HTTP/2 application reset does not consume protocol error budget" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [http2.ResetStreamPayload.encoded_len]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_local_error_reset_streams = 0 },
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    try connection.sendResetStream(1, .cancel);
    try std.testing.expectEqual(@as(usize, 0), connection.local_error_reset_streams);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    const frame = try http2.Frame.parse(writer.bytes[0..writer.len]);
    const reset = try http2.ResetStreamPayload.parse(frame);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.error_code);
}

test "HTTP/2 local protocol error reset budget may be disabled" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        bytes: [2 * http2.ResetStreamPayload.encoded_len]u8 = undefined,
        len: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(header.len, self.bytes.len - self.len);
            if (count == 0) return error.SocketUnconnected;
            @memcpy(self.bytes[self.len..][0..count], header[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{ .max_local_error_reset_streams = null },
    };
    defer {
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }

    try connection.writeLocalErrorResetStream(1, .protocol_error);
    try connection.writeLocalErrorResetStream(3, .flow_control_error);
    try std.testing.expectEqual(@as(usize, 2), connection.local_error_reset_streams);
    try std.testing.expect(!connection.aggregate_timeout_unusable);
    try std.testing.expectEqual(@sizeOf(@TypeOf(writer.bytes)), writer.len);
}

test "HTTP/2 failed protocol error reset write is terminal and uncounted" {
    const FailingWriter = struct {
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

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var writer: FailingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = FailingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        connection.locally_reset_streams.deinit(std.testing.allocator);
        connection.locally_reset_stream_index.deinit(std.testing.allocator);
    }

    try std.testing.expectError(
        error.NetworkDown,
        connection.writeLocalErrorResetStream(1, .protocol_error),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.local_error_reset_streams);
    try std.testing.expect(connection.aggregate_timeout_unusable);
}

test "HTTP/2 abandoning peer request releases state after reset write failure" {
    if (comptime builtin.os.tag != .linux) return;
    const allocator = std.testing.allocator;
    const FailingWriter = struct {
        fn write(
            _: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            return error.NetworkDown;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try @import("testing/blocked_output.zig").BlockedOutput.init(io, .server);
    defer fixture.deinit();
    const connection = &fixture.connection;
    var vtable = io.vtable.*;
    vtable.netWrite = FailingWriter.write;
    connection.io = .{ .userdata = io.userdata, .vtable = &vtable };
    defer connection.io = io;
    connection.limits = .{
        .max_concurrent_streams = 1,
        .max_reset_stream_history = 0,
    };

    try connection.reservePeerStream(1);
    try connection.rememberResponseSemantics(1, "POST", null, .{});
    _ = try connection.sendStreamWindow(1);
    _ = try connection.recvStreamWindow(1);
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(connection.hasRecvStreamWindow(1));

    connection.abandonPeerRequest(1, .internal_error);
    try std.testing.expect(!connection.outboundStreamIsActive(1));
    try std.testing.expect(!connection.hasRecvStreamWindow(1));
    try std.testing.expect(!connection.response_semantics_index.contains(1));
    try std.testing.expect(connection.priority_state.get(1) == null);

    // The failed best-effort RST must not strand the sole concurrency slot.
    try connection.reservePeerStream(3);
    try std.testing.expect(connection.outboundStreamIsActive(3));
}

test "HTTP/2 reset history allocation failure precedes wire write" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var recording_vtable = threaded.io().vtable.*;
    recording_vtable.netWrite = RecordingWriter.write;
    const recording_io = std.Io{
        .userdata = &writer,
        .vtable = &recording_vtable,
    };
    var connection = Connection{
        .io = recording_io,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_reset_stream_history = 1 },
    };
    defer {
        connection.active_local_streams.deinit(allocator);
        connection.active_local_index.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.addActiveLocalStream(1);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.sendResetStream(1, .cancel),
    );
    connection.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), writer.writes);
    try std.testing.expect(connection.outboundStreamIsActive(1));
    try std.testing.expect(!connection.wasLocallyResetAt(1, 0));
}

test "HTTP/2 refusal reserves reset history before consuming headers" {
    const allocator = std.testing.allocator;
    const RecordingWriter = struct {
        writes: usize = 0,

        fn write(
            context: ?*anyopaque,
            _: net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.writes += 1;
            return error.SocketUnconnected;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var writer: RecordingWriter = .{};
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = RecordingWriter.write;
    var connection = Connection{
        .io = .{ .userdata = &writer, .vtable = &vtable },
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .limits = .{
            .max_concurrent_streams = 1,
            .max_reset_stream_history = 1,
        },
    };
    defer {
        connection.active_peer_streams.deinit(allocator);
        connection.active_peer_index.deinit(allocator);
        connection.priority_state.deinit(allocator);
        connection.locally_reset_streams.deinit(allocator);
        connection.locally_reset_stream_index.deinit(allocator);
    }
    try connection.active_peer_streams.ensureUnusedCapacity(allocator, 1);
    try connection.active_peer_index.ensureUnusedCapacity(allocator, 1);
    try std.testing.expectEqual(
        Connection.PeerRequestAdmission.admitted,
        try connection.claimPeerRequestStream(1),
    );
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.claimPeerRequestStream(3),
    );
    connection.allocator = allocator;
    try std.testing.expectEqual(@as(usize, 0), writer.writes);
    try std.testing.expectEqual(@as(u31, 1), connection.last_peer_client_stream_id);
    try std.testing.expect(connection.aggregate_timeout_unusable);
    try std.testing.expect(!connection.wasLocallyResetAt(3, 0));
}

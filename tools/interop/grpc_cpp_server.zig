//! One-shot netz server for focused upstream gRPC C++ client scenarios.

const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

const duplex_service_path = "/grpc.testing.TestService/FullDuplexCall";
const unary_service_path = "/grpc.testing.TestService/UnaryCall";
const client_streaming_service_path =
    "/grpc.testing.TestService/StreamingInputCall";
const server_streaming_service_path =
    "/grpc.testing.TestService/StreamingOutputCall";
const unimplemented_method_path =
    "/grpc.testing.TestService/UnimplementedCall";
const unimplemented_service_path =
    "/grpc.testing.UnimplementedService/UnimplementedCall";
const message_limit = messages.max_payload_size + 64;
const echo_initial_key = "x-grpc-test-echo-initial";
const echo_initial_value = "test_initial_metadata_value";
const echo_trailing_key = "x-grpc-test-echo-trailing-bin";
const echo_trailing_value = "\x0a\x0b\x0a\x0b\x0a\x0b";
const canonical_request_sizes = [_]usize{ 27_182, 8, 1_828, 45_904 };
const canonical_response_sizes = [_]usize{ 31_415, 9, 2_653, 58_979 };
const canonical_response_sizes_u32 = [_]u32{ 31_415, 9, 2_653, 58_979 };
const status_message = "This is a test message";
const special_status_message =
    "\t\ntest with whitespace\r\nand Unicode BMP ☺ and non-BMP 😈\t\n";

const Scenario = enum {
    ping_pong,
    empty_stream,
    cancel_after_first_response,
    timeout_on_sleeping_server,
    custom_metadata,
    client_compressed_unary,
    server_compressed_unary,
    client_compressed_streaming,
    server_compressed_streaming,
    status_code_and_message,
    special_status_message,
    unimplemented_method,
    unimplemented_service,
    client_streaming,
    server_streaming,

    fn parse(raw: []const u8) !Scenario {
        return std.meta.stringToEnum(Scenario, raw) orelse error.InvalidArgument;
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 and args.len != 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const scenario = try Scenario.parse(args[2]);
    const tls_enabled = args.len == 4 and
        std.mem.eql(u8, args[3], "--tls");
    if (args.len == 4 and !tls_enabled) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 64 * 1024,
        .max_body_bytes = message_limit,
        .initial_window_size = 512 * 1024,
        .initial_connection_window_size = 2 * 1024 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var clear_server: netz.grpc.runtime.Server = undefined;
    var tls_server: netz.grpc.runtime.TlsServer = undefined;
    if (tls_enabled) {
        tls_server = try .listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            .{
                .transport = .{
                    .identity = .{
                        .certificate_chain = &.{&certificate_der},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = key_pair,
                        } },
                    },
                    .limits = limits,
                },
                .max_message_size = message_limit,
            },
        );
    } else {
        clear_server = try .listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
            message_limit,
        );
    }
    defer if (tls_enabled) tls_server.deinit() else clear_server.deinit();

    std.debug.print(
        "netz grpc server ready: port={d} scenario={s} transport={s} " ++
            "client_io=grpc-cpp-posix-event-engine server_io=zio-std-io\n",
        .{ port, @tagName(scenario), if (tls_enabled) "tls" else "h2c" },
    );

    var connection = if (tls_enabled)
        tls_server.accept() catch |err| {
            if (scenario == .timeout_on_sleeping_server and
                err == error.UnexpectedEof)
            {
                std.debug.print(
                    "netz grpc server completed: scenario={s} transport=tls " ++
                        "outcome=local-deadline-before-tls-accept " ++
                        "client_io=grpc-cpp-posix-event-engine server_io=zio-std-io\n",
                    .{@tagName(scenario)},
                );
                return;
            }
            return err;
        }
    else
        try clear_server.accept();
    defer connection.deinit();
    std.debug.print(
        "netz grpc server accepted: scenario={s} transport={s}\n",
        .{ @tagName(scenario), if (tls_enabled) "tls" else "h2c" },
    );
    if (tls_enabled and
        !std.mem.eql(u8, connection.negotiatedAlpn() orelse "", "h2"))
    {
        return error.InvalidAlpn;
    }
    switch (scenario) {
        .custom_metadata => try serveCustomMetadata(allocator, &connection),
        .client_compressed_unary => try serveClientCompressedUnary(
            allocator,
            &connection,
        ),
        .server_compressed_unary => try serveServerCompressedUnary(
            allocator,
            &connection,
        ),
        .client_compressed_streaming => try serveClientCompressedStreaming(
            allocator,
            io,
            &connection,
        ),
        .server_compressed_streaming => try serveServerCompressedStreaming(
            allocator,
            &connection,
        ),
        .status_code_and_message => try serveStatusCodeAndMessage(
            &connection,
        ),
        .special_status_message => try serveSpecialStatusMessage(
            &connection,
        ),
        .unimplemented_method => try serveUnimplementedRoute(
            &connection,
            unimplemented_method_path,
        ),
        .unimplemented_service => try serveUnimplementedRoute(
            &connection,
            unimplemented_service_path,
        ),
        .client_streaming => try serveClientStreaming(allocator, &connection),
        .server_streaming => try serveServerStreaming(allocator, &connection),
        else => {
            var stream = try connection.acceptDuplex();
            defer stream.deinit();
            if (!std.mem.eql(u8, stream.path, duplex_service_path)) {
                try stream.finish(.unimplemented, null, &.{}, &.{});
                return error.UnexpectedMethod;
            }
            try serveScenario(allocator, io, &stream, scenario);
        },
    }
    std.debug.print(
        "netz grpc server completed: scenario={s} transport={s} " ++
            "client_io=grpc-cpp-posix-event-engine server_io=zio-std-io\n",
        .{ @tagName(scenario), if (tls_enabled) "tls" else "h2c" },
    );
}

fn serveUnimplementedRoute(
    connection: *netz.grpc.runtime.ServerConnection,
    expected_path: []const u8,
) !void {
    var unary = try connection.readUnary();
    defer unary.deinit();
    if (!std.mem.eql(u8, unary.request.path, expected_path)) {
        return error.UnexpectedMethod;
    }
    if (unary.request.message.payload.len != 0 or
        unary.request.was_compressed)
    {
        return error.UnexpectedRequest;
    }
    try connection.writeUnary(unary.request.stream_id, .{
        .status = .unimplemented,
        .trailers_only = true,
    });
}

fn serveStatusCodeAndMessage(
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    {
        var unary = try connection.readUnary();
        defer unary.deinit();
        if (!std.mem.eql(u8, unary.request.path, unary_service_path)) {
            return error.UnexpectedMethod;
        }
        const requested = try messages.decodeStatusRequest(
            unary.request.message.payload,
        );
        try expectStatus(requested, status_message);
        try connection.writeUnary(unary.request.stream_id, .{
            .status = .unknown,
            .status_message = requested.message,
            .trailers_only = true,
        });
    }

    var stream = try connection.acceptDuplex();
    defer stream.deinit();
    if (!std.mem.eql(u8, stream.path, duplex_service_path)) {
        return error.UnexpectedMethod;
    }
    var observer = StatusObserver{ .expected_message = status_message };
    while (!observer.matches) {
        var event = try stream.readRequestEvent(
            &observer,
            StatusObserver.consume,
        );
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => return error.UnexpectedEndOfStream,
            .reset => return error.UnexpectedReset,
        }
    }
    try stream.finish(.unknown, status_message, &.{}, &.{});
}

fn serveSpecialStatusMessage(
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    var unary = try connection.readUnary();
    defer unary.deinit();
    if (!std.mem.eql(u8, unary.request.path, unary_service_path)) {
        return error.UnexpectedMethod;
    }
    const requested = try messages.decodeStatusRequest(
        unary.request.message.payload,
    );
    try expectStatus(requested, special_status_message);
    try connection.writeUnary(unary.request.stream_id, .{
        .status = .unknown,
        .status_message = requested.message,
        .trailers_only = true,
    });
}

const StatusObserver = struct {
    expected_message: []const u8,
    matches: bool = false,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (self.matches or message.was_compressed) {
            return error.UnexpectedRequest;
        }
        try expectStatus(
            try messages.decodeStatusRequest(message.payload),
            self.expected_message,
        );
        self.matches = true;
    }
};

fn expectStatus(
    status: messages.EchoStatus,
    expected_message: []const u8,
) !void {
    if (status.code != @intFromEnum(netz.grpc.Status.unknown) or
        !std.mem.eql(u8, status.message, expected_message))
    {
        return error.UnexpectedStatus;
    }
}

fn serveClientCompressedUnary(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    for ([_]bool{ true, true, false }, 0..) |expected, index| {
        var unary = try connection.readUnary();
        defer unary.deinit();
        if (!std.mem.eql(u8, unary.request.path, unary_service_path)) {
            return error.UnexpectedMethod;
        }
        const request = try messages.decodeSimpleRequest(
            unary.request.message.payload,
        );
        if (request.expect_compressed != expected) {
            return error.UnexpectedRequest;
        }
        const matches = unary.request.was_compressed == expected;
        if (index == 0) {
            if (matches) return error.UnexpectedCompressionProbe;
            try connection.writeUnary(unary.request.stream_id, .{
                .status = .invalid_argument,
                .status_message = "Compressed request expectation not met.",
                .trailers_only = true,
            });
            continue;
        }
        if (!matches) return error.UnexpectedCompression;
        try writeUnaryPayload(allocator, connection, &unary, false);
    }
}

fn serveServerCompressedUnary(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    for ([_]bool{ true, false }) |compressed| {
        var unary = try connection.readUnary();
        defer unary.deinit();
        if (!std.mem.eql(u8, unary.request.path, unary_service_path)) {
            return error.UnexpectedMethod;
        }
        const request = try messages.decodeSimpleRequest(
            unary.request.message.payload,
        );
        if (request.response_compressed != compressed or
            unary.request.was_compressed)
        {
            return error.UnexpectedCompression;
        }
        try writeUnaryPayload(allocator, connection, &unary, compressed);
    }
}

fn writeUnaryPayload(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
    unary: *const netz.grpc.runtime.OwnedUnaryRequest,
    compressed: bool,
) !void {
    const request = try messages.decodeSimpleRequest(
        unary.request.message.payload,
    );
    if (request.response_size != 314_159 or
        request.request_body_size != 271_828)
    {
        return error.UnexpectedRequest;
    }
    const response = try messages.encodeSimpleResponseAlloc(
        allocator,
        request.response_size,
    );
    defer allocator.free(response);
    try connection.writeUnary(unary.request.stream_id, .{
        .message = response,
        .compression = if (compressed) .gzip else .identity,
        .request_accepted_encodings = unary.request.accepted_encodings,
    });
}

const InputStreamAccumulator = struct {
    count: usize = 0,
    total: usize = 0,
    expected_sizes: []const usize = &canonical_request_sizes,
    expected_compression: ?[]const bool = null,
    compression_matches: bool = true,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (self.count == self.expected_sizes.len) {
            return error.UnexpectedRequest;
        }
        const request = try messages.decodeStreamingInputCallRequest(
            message.payload,
        );
        if (request.request_body_size != self.expected_sizes[self.count]) {
            return error.UnexpectedRequest;
        }
        if (self.expected_compression) |expected| {
            if (request.expect_compressed != expected[self.count] or
                message.was_compressed != expected[self.count])
            {
                self.compression_matches = false;
            }
        } else if (request.expect_compressed != null) {
            return error.UnexpectedRequest;
        }
        self.total = std.math.add(
            usize,
            self.total,
            request.request_body_size,
        ) catch return error.MessageTooLarge;
        self.count += 1;
    }
};

fn serveClientCompressedStreaming(
    allocator: std.mem.Allocator,
    io: std.Io,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    const probe_sizes = [_]usize{27_182};
    const probe_compression = [_]bool{true};
    {
        var probe = InputStreamAccumulator{
            .expected_sizes = &probe_sizes,
            .expected_compression = &probe_compression,
        };
        var probe_stream = try connection.acceptDuplex();
        defer probe_stream.deinit();
        if (!std.mem.eql(
            u8,
            probe_stream.path,
            client_streaming_service_path,
        )) return error.UnexpectedMethod;
        while (probe.count == 0) {
            var event = try probe_stream.readRequestEvent(
                &probe,
                InputStreamAccumulator.consume,
            );
            defer event.deinit();
            switch (event) {
                .messages => {},
                .finished => return error.UnexpectedEndOfStream,
                .reset => return error.UnexpectedReset,
            }
        }
        if (probe.count != probe_sizes.len or probe.compression_matches) {
            return error.UnexpectedCompressionProbe;
        }
        try probe_stream.finish(
            .invalid_argument,
            "Compressed request expectation not met.",
            &.{},
            &.{},
        );
        const cleanup_deadline = std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = .fromSeconds(5),
            .clock = .awake,
        });
        _ = try probe_stream.drainRequestAfterResponseWithDeadline(
            cleanup_deadline,
        );
    }

    const expected_sizes = [_]usize{ 27_182, 45_904 };
    const expected_compression = [_]bool{ true, false };
    var accumulator = InputStreamAccumulator{
        .expected_sizes = &expected_sizes,
        .expected_compression = &expected_compression,
    };
    var request = try connection.readStreaming(
        &accumulator,
        InputStreamAccumulator.consume,
    );
    defer request.deinit();
    if (!std.mem.eql(u8, request.path, client_streaming_service_path) or
        accumulator.count != expected_sizes.len or
        !accumulator.compression_matches)
    {
        return error.UnexpectedCompression;
    }
    try writeStreamingInputResponse(
        allocator,
        connection,
        &request,
        accumulator.total,
    );
}

fn serveClientStreaming(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    var accumulator = InputStreamAccumulator{};
    var request = try connection.readStreaming(
        &accumulator,
        InputStreamAccumulator.consume,
    );
    defer request.deinit();
    if (!std.mem.eql(u8, request.path, client_streaming_service_path) or
        accumulator.count != canonical_request_sizes.len or
        request.message_count != canonical_request_sizes.len)
    {
        return error.UnexpectedRequest;
    }
    try writeStreamingInputResponse(
        allocator,
        connection,
        &request,
        accumulator.total,
    );
}

fn writeStreamingInputResponse(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
    request: *const netz.grpc.StreamingRequest,
    aggregate: usize,
) !void {
    const response = try messages.encodeStreamingInputCallResponseAlloc(
        allocator,
        aggregate,
    );
    defer allocator.free(response);
    var writer = try connection.startStreamingResponse(
        request.transport.stream_id,
        .{
            .request_accepted_encodings = request.accepted_encodings,
            .max_message_size = message_limit,
        },
    );
    defer writer.deinit();
    try writer.writeMessage(response);
    try writer.finishOk();
}

fn serveServerStreaming(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    var request = try connection.readUnary();
    defer request.deinit();
    if (!std.mem.eql(u8, request.request.path, server_streaming_service_path)) {
        return error.UnexpectedMethod;
    }
    var parameter_storage: [16]messages.ResponseParameter = undefined;
    const parameters = try messages.decodeStreamingOutputCallResponseParameters(
        request.request.message.payload,
        &parameter_storage,
    );
    if (parameters.len != canonical_response_sizes_u32.len) {
        return error.UnexpectedRequest;
    }
    for (parameters, canonical_response_sizes_u32) |parameter, size| {
        if (parameter.size != size or parameter.interval_us != 0 or
            parameter.compressed != null)
        {
            return error.UnexpectedRequest;
        }
    }
    var writer = try connection.startStreamingResponse(
        request.request.stream_id,
        .{
            .request_accepted_encodings = request.request.accepted_encodings,
            .max_message_size = message_limit,
        },
    );
    defer writer.deinit();
    for (parameters) |parameter| {
        const response = try messages.encodeStreamingOutputCallResponseAlloc(
            allocator,
            parameter.size,
        );
        defer allocator.free(response);
        try writer.writeMessage(response);
    }
    try writer.finishOk();
}

fn serveServerCompressedStreaming(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    var request = try connection.readUnary();
    defer request.deinit();
    if (!std.mem.eql(u8, request.request.path, server_streaming_service_path)) {
        return error.UnexpectedMethod;
    }
    var storage: [2]messages.ResponseParameter = undefined;
    const parameters = try messages.decodeStreamingOutputCallResponseParameters(
        request.request.message.payload,
        &storage,
    );
    const expected = [_]messages.ResponseParameter{
        .{ .size = 31_415, .compressed = true },
        .{ .size = 92_653, .compressed = false },
    };
    if (parameters.len != expected.len) return error.UnexpectedRequest;
    for (parameters, expected) |actual, wanted| {
        if (actual.size != wanted.size or
            actual.interval_us != wanted.interval_us or
            actual.compressed != wanted.compressed)
        {
            return error.UnexpectedRequest;
        }
    }
    var writer = try connection.startStreamingResponse(
        request.request.stream_id,
        .{
            .compression = .gzip,
            .request_accepted_encodings = request.request.accepted_encodings,
            .max_message_size = message_limit,
        },
    );
    defer writer.deinit();
    for (parameters) |parameter| {
        const response = try messages.encodeStreamingOutputCallResponseAlloc(
            allocator,
            parameter.size,
        );
        defer allocator.free(response);
        try writer.writeMessageWithOptions(response, .{
            .disable_compression = !parameter.compressed.?,
        });
    }
    try writer.finishOk();
}

fn serveCustomMetadata(
    allocator: std.mem.Allocator,
    connection: *netz.grpc.runtime.ServerConnection,
) !void {
    {
        var unary = try connection.readUnary();
        defer unary.deinit();
        if (!std.mem.eql(u8, unary.request.path, unary_service_path)) {
            return error.UnexpectedMethod;
        }
        try expectEchoMetadata(unary.request.headers);
        const request = try messages.decodeSimpleRequest(
            unary.request.message.payload,
        );
        try expectRequestSizes(request.request_body_size, request.response_size);
        const response = try messages.encodeSimpleResponseAlloc(
            allocator,
            request.response_size,
        );
        defer allocator.free(response);
        try connection.writeUnary(unary.request.stream_id, .{
            .message = response,
            .request_accepted_encodings = unary.request.accepted_encodings,
            .initial_metadata = &.{.{
                .name = echo_initial_key,
                .value = echo_initial_value,
            }},
            .trailing_binary_metadata = &.{.{
                .name = echo_trailing_key,
                .value = echo_trailing_value,
            }},
        });
    }

    var stream = try connection.acceptDuplex();
    defer stream.deinit();
    if (!std.mem.eql(u8, stream.path, duplex_service_path)) {
        return error.UnexpectedMethod;
    }
    try expectEchoMetadata(stream.requestHeaders());

    var queue = RequestQueue{ .allocator = allocator };
    defer queue.deinit();
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
        .initial_metadata = &.{.{
            .name = echo_initial_key,
            .value = echo_initial_value,
        }},
        .max_message_size = message_limit,
    });
    const streaming_request = try nextRequest(&stream, &queue, null);
    try expectRequest(streaming_request, 271_828, 314_159);
    try expectFinished(&stream, &queue, null);
    try writeResponse(&stream, &queue, null, 314_159);
    try stream.finish(
        .ok,
        null,
        &.{},
        &.{.{
            .name = echo_trailing_key,
            .value = echo_trailing_value,
        }},
    );
}

fn expectEchoMetadata(
    headers: []const netz.http2.Hpack.HeaderField,
) !void {
    if (!std.mem.eql(
        u8,
        netz.grpc.call.headerValue(headers, echo_initial_key) orelse
            return error.MissingMetadata,
        echo_initial_value,
    )) return error.UnexpectedMetadata;

    const decoded_len = try netz.grpc.binaryMetadataFieldsDecodedUpperBound(
        headers,
        echo_trailing_key,
    );
    var scratch: [64]u8 = undefined;
    if (decoded_len > scratch.len) return error.UnexpectedMetadata;
    var values = try netz.grpc.BinaryMetadataIterator.init(
        headers,
        echo_trailing_key,
        scratch[0..decoded_len],
    );
    const value = (try values.next()) orelse return error.MissingMetadata;
    if (!std.mem.eql(u8, value.value, echo_trailing_value) or
        try values.next() != null)
    {
        return error.UnexpectedMetadata;
    }
}

fn expectRequestSizes(request_size: usize, response_size: u32) !void {
    if (request_size != 271_828 or response_size != 314_159) {
        return error.UnexpectedRequest;
    }
}

const RequestQueue = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(messages.RequestOptions) = .empty,

    fn deinit(self: *@This()) void {
        self.items.deinit(self.allocator);
    }

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        try self.items.append(
            self.allocator,
            try messages.decodeStreamingOutputCallRequest(message.payload),
        );
    }
};

fn serveScenario(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    scenario: Scenario,
) !void {
    var queue = RequestQueue{ .allocator = allocator };
    defer queue.deinit();

    const deadline = if (stream.timeout) |timeout|
        std.Io.Clock.Timestamp.fromNow(io, .{
            .raw = timeout.duration(),
            .clock = .awake,
        })
    else
        null;

    switch (scenario) {
        .ping_pong => try servePingPong(io, stream, &queue, deadline),
        .empty_stream => try serveEmpty(stream, &queue, deadline),
        .cancel_after_first_response => try serveCancellation(io, stream, &queue, deadline),
        .timeout_on_sleeping_server => try serveSleepingDeadline(io, stream, &queue),
        .custom_metadata,
        .client_compressed_unary,
        .server_compressed_unary,
        .client_compressed_streaming,
        .server_compressed_streaming,
        .status_code_and_message,
        .special_status_message,
        .unimplemented_method,
        .unimplemented_service,
        .client_streaming,
        .server_streaming,
        => unreachable,
    }
}

fn servePingPong(
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
        .max_message_size = message_limit,
    });
    for (canonical_request_sizes, canonical_response_sizes) |request_size, response_size| {
        const request = try nextRequest(stream, queue, deadline);
        try expectRequest(request, request_size, response_size);
        try maybeSleep(io, request.interval_us, deadline);
        try writeResponse(stream, queue, deadline, response_size);
    }
    try expectFinished(stream, queue, deadline);
    try stream.finishOk();
}

fn serveEmpty(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try expectFinished(stream, queue, deadline);
    try stream.finishOk();
}

fn serveCancellation(
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    try stream.startResponse(.{
        .request_accepted_encodings = stream.accepted_encodings,
        .max_message_size = message_limit,
    });
    const request = try nextRequest(stream, queue, deadline);
    try expectRequest(request, 27_182, 31_415);
    try maybeSleep(io, request.interval_us, deadline);
    writeResponse(stream, queue, deadline, 31_415) catch |err| switch (err) {
        // Cancellation can race the last flow-control slice of the first
        // response. Observing the peer's CANCEL there is equivalent to seeing
        // it in the receive loop below.
        error.PeerCancelled => return,
        else => return err,
    };

    while (true) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => return error.ExpectedCancellation,
            .reset => |reset| {
                if (reset.error_code != .cancel) return error.UnexpectedReset;
                return;
            },
        }
    }
}

fn serveSleepingDeadline(
    io: std.Io,
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
) !void {
    const timeout = stream.timeout orelse return error.MissingTimeout;
    if (timeout.duration().nanoseconds > std.time.ns_per_s) {
        return error.UnexpectedTimeout;
    }
    // grpc-cpp owns deadline enforcement in this reverse-direction case. Its
    // one-millisecond deadline can expire before or after the complete request
    // reaches this process, so wait for the resulting CANCEL with a separate
    // generous harness watchdog instead of restarting grpc-timeout at accept.
    const watchdog = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(5),
        .clock = .awake,
    });
    while (true) {
        var event = readEvent(stream, queue, watchdog) catch |err| switch (err) {
            error.Timeout => {
                try stream.finish(
                    .deadline_exceeded,
                    "deadline exceeded",
                    &.{},
                    &.{},
                );
                const cleanup_deadline = std.Io.Clock.Timestamp.fromNow(
                    io,
                    .{
                        .raw = .fromSeconds(5),
                        .clock = .awake,
                    },
                );
                const drained = try stream
                    .drainRequestAfterResponseWithDeadline(cleanup_deadline);
                switch (drained) {
                    .finished => return,
                    .reset => |reset| {
                        if (reset.error_code != .cancel and
                            reset.error_code != .no_error)
                        {
                            return error.UnexpectedReset;
                        }
                        return;
                    },
                }
            },
            else => return err,
        };
        defer event.deinit();
        switch (event) {
            .messages => {
                while (queue.items.items.len != 0) {
                    const request = queue.items.orderedRemove(0);
                    if (request.response_size != null or
                        request.request_body_size != 27_182)
                    {
                        return error.UnexpectedRequest;
                    }
                }
            },
            .finished => return error.ExpectedDeadline,
            .reset => |reset| {
                if (reset.error_code != .cancel) return error.UnexpectedReset;
                return;
            },
        }
    }
}

fn nextRequest(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: anytype,
) !messages.RequestOptions {
    while (queue.items.items.len == 0) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => return error.UnexpectedEndOfStream,
            .reset => return error.UnexpectedReset,
        }
    }
    return queue.items.orderedRemove(0);
}

fn expectFinished(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (queue.items.items.len != 0) return error.UnexpectedRequest;
    while (true) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => if (queue.items.items.len != 0) return error.UnexpectedRequest,
            .finished => return,
            .reset => return error.UnexpectedReset,
        }
    }
}

fn readEvent(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
) !netz.grpc.ServerDuplexEvent {
    return if (deadline) |absolute|
        stream.readRequestEventWithDeadline(
            absolute,
            queue,
            RequestQueue.consume,
        )
    else
        stream.readRequestEvent(queue, RequestQueue.consume);
}

fn expectRequest(
    request: messages.RequestOptions,
    request_size: usize,
    response_size: usize,
) !void {
    if (request.request_body_size != request_size or
        request.response_size != @as(u32, @intCast(response_size)))
    {
        return error.UnexpectedRequest;
    }
}

fn writeResponse(
    stream: *netz.grpc.ServerDuplex,
    queue: *RequestQueue,
    deadline: ?std.Io.Clock.Timestamp,
    response_size: usize,
) !void {
    const encoded = try messages.encodeStreamingOutputCallResponseAlloc(
        queue.allocator,
        response_size,
    );
    defer queue.allocator.free(encoded);

    var result = try stream.writeMessage(encoded);
    while (result == .peer_event) {
        var event = try readEvent(stream, queue, deadline);
        defer event.deinit();
        switch (event) {
            .messages => {},
            .finished => {},
            .reset => |reset| {
                if (reset.error_code == .cancel) return error.PeerCancelled;
                return error.UnexpectedReset;
            },
        }
        result = try stream.resumeMessage();
    }
}

fn maybeSleep(
    io: std.Io,
    interval_us: u32,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    if (interval_us == 0) return;
    var duration = std.Io.Duration.fromMicroseconds(interval_us);
    if (deadline) |absolute| {
        const remaining = absolute.durationFromNow(io).raw;
        if (remaining.nanoseconds <= 0) return error.Timeout;
        if (remaining.nanoseconds < duration.nanoseconds) duration = remaining;
    }
    try std.Io.sleep(io, duration, .awake);
    if (deadline) |absolute| {
        if (absolute.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
    }
}

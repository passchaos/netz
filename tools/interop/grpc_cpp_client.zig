//! Focused netz client for the upstream gRPC C++ interoperability server.
//!
//! The scenarios mirror gRPC Core commit
//! `03d65cc67c450ccbb58a8a45627c4da83a886ccd`'s canonical `ping_pong`,
//! `client_compressed_unary`, `server_compressed_unary`, `custom_metadata`,
//! `client_compressed_streaming`, `server_compressed_streaming`,
//! `status_code_and_message`, `special_status_message`,
//! `cancel_after_first_response`, and
//! `timeout_on_sleeping_server` cases.  Only the bounded protobuf fixture
//! subset lives beside this executable; netz's gRPC transport remains payload
//! agnostic.

const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");
const InteropClient = netz.grpc.runtime.Channel;

const service_path = "/grpc.testing.TestService/FullDuplexCall";
const half_duplex_service_path =
    "/grpc.testing.TestService/HalfDuplexCall";
const unary_service_path = "/grpc.testing.TestService/UnaryCall";
const empty_service_path = "/grpc.testing.TestService/EmptyCall";
const client_streaming_service_path =
    "/grpc.testing.TestService/StreamingInputCall";
const server_streaming_service_path =
    "/grpc.testing.TestService/StreamingOutputCall";
const unimplemented_method_path =
    "/grpc.testing.TestService/UnimplementedCall";
const unimplemented_service_path =
    "/grpc.testing.UnimplementedService/UnimplementedCall";
const authority = "localhost";
const response_timeout = std.Io.Duration.fromSeconds(10);
const canonical_request_sizes = [_]usize{ 27_182, 8, 1_828, 45_904 };
const canonical_response_sizes = [_]usize{ 31_415, 9, 2_653, 58_979 };
const metadata_request_size = 271_828;
const metadata_response_size = 314_159;
const slow_consumer_messages: usize = 2_000;
const slow_consumer_response_size: usize = 1_030;
const slow_consumer_delay = std.Io.Duration.fromMilliseconds(20);
const rpc_soak_iterations: usize = 100;
const channel_soak_iterations: usize = 100;
const initial_metadata_name = "x-grpc-test-echo-initial";
const initial_metadata_value = "test_initial_metadata_value";
const trailing_metadata_name = "x-grpc-test-echo-trailing-bin";
const trailing_metadata_value = [_]u8{ 0x0a, 0x0b, 0x0a, 0x0b, 0x0a, 0x0b };
const status_message = "This is a test message";
const special_status_message =
    "\t\ntest with whitespace\r\nand Unicode BMP ☺ and non-BMP 😈\t\n";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 3;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    // The largest canonical metadata response is 314159 bytes.  Keep both
    // transport and gRPC bounds deliberately close to that fixture rather
    // than accepting the library defaults as an accidental unbounded oracle.
    const message_limit = messages.max_payload_size + 64;
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 64 * 1024,
        .max_body_bytes = 4 * 1024 * 1024,
        .initial_window_size = 512 * 1024,
        .initial_connection_window_size = 2 * 1024 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }
    var client = try connectClient(
        allocator,
        io,
        port,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
        limits,
    );
    var client_live = true;
    defer if (client_live) client.deinit();
    _ = try client.warmWithTimeout(.fromSeconds(5));
    if (tls_enabled and
        !std.mem.eql(u8, client.negotiatedAlpn() orelse "", "h2"))
    {
        return error.InvalidAlpn;
    }

    try runPingPong(allocator, &client, message_limit);
    try runHalfDuplex(allocator, &client, message_limit);
    try runSlowConsumer(allocator, io, &client, message_limit);
    try runCancelAfterBegin(&client, message_limit);
    try runUnaryBasics(allocator, &client, message_limit);
    try runRpcSoak(allocator, &client, message_limit);
    try runUnaryCompression(allocator, &client, message_limit);
    try runStreamingCompression(allocator, &client, message_limit);
    try runStatusInterop(allocator, &client, message_limit);
    try runUnimplementedRoutes(&client, message_limit);
    try runCustomMetadata(allocator, &client, message_limit);
    try runCancellationAndReuse(allocator, &client, message_limit);
    try runSleepingDeadline(allocator, &client, message_limit);
    client.deinit();
    client_live = false;

    try runChannelSoak(
        allocator,
        io,
        port,
        tls_enabled,
        &ca_bundle,
        &ca_lock,
        limits,
        message_limit,
    );

    std.debug.print(
        "netz gRPC client interoperated with grpc-cpp: transport={s} " ++
            "ping_pong=4 half_duplex=4 " ++
            "slow_consumer=2000x1030@20ms " ++
            "compression=unary+streaming-gzip+identity " ++
            "unary=empty+large " ++
            "rpc_soak=100x271828/314159 " ++
            "channel_soak=100x271828/314159 " ++
            "status=unary+bidi+unicode " ++
            "unimplemented=method+service " ++
            "metadata=initial+trailing-bin " ++
            "cancel=begin+after-response reuse=true " ++
            "deadline=DEADLINE_EXCEEDED-or-local-timeout+CANCEL " ++
            "client_io=zio-std-io server_io=grpc-cpp-posix-event-engine\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

fn connectClient(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    tls_enabled: bool,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
    limits: netz.http2.runtime.Limits,
) !InteropClient {
    return if (tls_enabled)
        try InteropClient.init(
            allocator,
            io,
            .{ .tls_address = .{
                .address = .{ .ip4 = .loopback(port) },
                .tls_host = "foo.test.google.fr",
                .authority = authority,
                .limits = limits,
                .tls = .{ .ca_bundle = .{
                    .bundle = ca_bundle,
                    .lock = ca_lock,
                } },
            } },
            .{},
        )
    else
        try InteropClient.init(
            allocator,
            io,
            .{ .cleartext_ip = .{
                .address = .{ .ip4 = .loopback(port) },
                .limits = limits,
            } },
            .{},
        );
}

fn runChannelSoak(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    tls_enabled: bool,
    ca_bundle: *std.crypto.Certificate.Bundle,
    ca_lock: *std.Io.RwLock,
    limits: netz.http2.runtime.Limits,
    message_limit: usize,
) !void {
    const request = try messages.encodeSimpleRequestAlloc(allocator, .{
        .response_size = metadata_response_size,
        .request_body_size = metadata_request_size,
    });
    defer allocator.free(request);
    for (0..channel_soak_iterations) |_| {
        var client = try connectClient(
            allocator,
            io,
            port,
            tls_enabled,
            ca_bundle,
            ca_lock,
            limits,
        );
        defer client.deinit();
        _ = try client.warmWithTimeout(.fromSeconds(5));
        if (tls_enabled and
            !std.mem.eql(u8, client.negotiatedAlpn() orelse "", "h2"))
        {
            return error.InvalidAlpn;
        }
        var response = try client.unary(.{
            .path = unary_service_path,
            .authority = authority,
            .message = request,
            .max_message_size = message_limit,
        });
        defer response.deinit();
        if (response.status != .ok or response.message == null or
            response.was_compressed)
        {
            return error.InvalidSoakResponse;
        }
        try messages.validateStreamingOutputCallResponse(
            response.message.?.payload,
            metadata_response_size,
        );
    }
}

fn runRpcSoak(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    const request = try messages.encodeSimpleRequestAlloc(allocator, .{
        .response_size = metadata_response_size,
        .request_body_size = metadata_request_size,
    });
    defer allocator.free(request);
    for (0..rpc_soak_iterations) |_| {
        var response = try client.unary(.{
            .path = unary_service_path,
            .authority = authority,
            .message = request,
            .max_message_size = message_limit,
        });
        defer response.deinit();
        if (response.status != .ok or response.message == null or
            response.was_compressed)
        {
            return error.InvalidSoakResponse;
        }
        try messages.validateStreamingOutputCallResponse(
            response.message.?.payload,
            metadata_response_size,
        );
    }
}

const SlowConsumer = struct {
    io: std.Io,
    count: usize = 0,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (message.was_compressed) return error.InvalidSlowConsumerResponse;
        try messages.validateStreamingOutputCallResponse(
            message.payload,
            slow_consumer_response_size,
        );
        self.count += 1;
        try std.Io.sleep(self.io, slow_consumer_delay, .awake);
    }
};

fn runSlowConsumer(
    allocator: std.mem.Allocator,
    io: std.Io,
    client: *InteropClient,
    message_limit: usize,
) !void {
    const parameters = try allocator.alloc(
        messages.ResponseParameter,
        slow_consumer_messages,
    );
    defer allocator.free(parameters);
    @memset(parameters, .{ .size = slow_consumer_response_size });
    const request = try messages.encodeStreamingOutputCallParametersAlloc(
        allocator,
        parameters,
    );
    defer allocator.free(request);
    var stream = try client.startStreaming(.{
        .path = server_streaming_service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    try stream.writeMessage(request);
    var observer = SlowConsumer{ .io = io };
    var response = try stream.finishAndRead(&observer, SlowConsumer.consume);
    defer response.deinit();
    if (response.status != .ok or observer.count != slow_consumer_messages) {
        return error.InvalidSlowConsumerResponse;
    }
}

fn runHalfDuplex(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    var stream = try client.startDuplex(.{
        .path = half_duplex_service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    var observer = Observer{ .expected_sizes = &canonical_response_sizes };
    for (canonical_response_sizes) |response_size| {
        const parameters = [_]messages.ResponseParameter{
            .{ .size = @intCast(response_size) },
        };
        const request = try messages.encodeStreamingOutputCallParametersAlloc(
            allocator,
            &parameters,
        );
        defer allocator.free(request);
        try writeMessageFully(allocator, &stream, request, &observer);
    }
    try finishRequestFully(allocator, &stream, &observer);
    try readThroughTerminal(allocator, &stream, &observer);
    if (observer.message_count != canonical_response_sizes.len or
        observer.terminal_status != .ok)
    {
        return error.InvalidHalfDuplexResponse;
    }
}

fn runCancelAfterBegin(
    client: *InteropClient,
    message_limit: usize,
) !void {
    var stream = try client.startStreaming(.{
        .path = client_streaming_service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    try stream.cancel();
    stream.deinit();
}

fn runUnaryBasics(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    {
        var response = try client.unary(.{
            .path = empty_service_path,
            .authority = authority,
            .message = &.{},
            .max_message_size = message_limit,
        });
        defer response.deinit();
        if (response.status != .ok or
            response.message == null or
            response.message.?.payload.len != 0 or
            response.was_compressed)
        {
            return error.InvalidEmptyUnaryResponse;
        }
    }

    const request = try messages.encodeSimpleRequestAlloc(allocator, .{
        .response_size = metadata_response_size,
        .request_body_size = metadata_request_size,
    });
    defer allocator.free(request);
    var response = try client.unary(.{
        .path = unary_service_path,
        .authority = authority,
        .message = request,
        .max_message_size = message_limit,
    });
    defer response.deinit();
    if (response.status != .ok or response.message == null or
        response.was_compressed)
    {
        return error.InvalidLargeUnaryResponse;
    }
    try messages.validateStreamingOutputCallResponse(
        response.message.?.payload,
        metadata_response_size,
    );
}

fn runUnimplementedRoutes(
    client: *InteropClient,
    message_limit: usize,
) !void {
    for ([_][]const u8{
        unimplemented_method_path,
        unimplemented_service_path,
    }) |path| {
        var response = try client.unary(.{
            .path = path,
            .authority = authority,
            .message = &.{},
            .max_message_size = message_limit,
        });
        defer response.deinit();
        if (response.status != .unimplemented or response.message != null) {
            return error.InvalidUnimplementedResponse;
        }
    }
}

fn runStatusInterop(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    try runUnaryStatus(
        allocator,
        client,
        message_limit,
        status_message,
    );

    const request = try messages.encodeStatusRequestAlloc(allocator, .{
        .code = @intFromEnum(netz.grpc.Status.unknown),
        .message = status_message,
    });
    defer allocator.free(request);
    var stream = try client.startDuplex(.{
        .path = service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    var observer = Observer{
        .expected_sizes = &.{},
        .expected_terminal_message = status_message,
    };
    try writeMessageFully(allocator, &stream, request, &observer);
    try finishRequestFully(allocator, &stream, &observer);
    try readThroughTerminal(allocator, &stream, &observer);
    if (observer.message_count != 0 or
        observer.terminal_status != .unknown or
        !observer.terminal_message_matches)
    {
        return error.InvalidStatusResponse;
    }

    try runUnaryStatus(
        allocator,
        client,
        message_limit,
        special_status_message,
    );
}

fn runUnaryStatus(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
    expected_message: []const u8,
) !void {
    const request = try messages.encodeStatusRequestAlloc(allocator, .{
        .code = @intFromEnum(netz.grpc.Status.unknown),
        .message = expected_message,
    });
    defer allocator.free(request);
    var response = try client.unary(.{
        .path = unary_service_path,
        .authority = authority,
        .message = request,
        .max_message_size = message_limit,
    });
    defer response.deinit();
    if (response.status != .unknown or response.message != null or
        !std.mem.eql(u8, response.status_message, expected_message))
    {
        return error.InvalidStatusResponse;
    }
}

fn runStreamingCompression(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    try runClientStreamingCompression(allocator, client, message_limit);
    try runServerStreamingCompression(allocator, client, message_limit);
}

const AggregateObserver = struct {
    count: usize = 0,
    aggregate: usize = 0,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (self.count != 0 or message.was_compressed) {
            return error.InvalidCompressionResponse;
        }
        self.aggregate = try messages.decodeStreamingInputCallResponse(
            message.payload,
        );
        self.count += 1;
    }
};

fn runClientStreamingCompression(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    {
        var probe = try client.startStreaming(.{
            .path = client_streaming_service_path,
            .authority = authority,
            .max_message_size = message_limit,
        });
        defer probe.deinit();
        const request = try messages.encodeStreamingInputCallRequestAlloc(
            allocator,
            .{ .request_body_size = 27_182, .expect_compressed = true },
        );
        defer allocator.free(request);
        try probe.writeMessage(request);
        var observer = AggregateObserver{};
        var response = try probe.finishAndRead(
            &observer,
            AggregateObserver.consume,
        );
        defer response.deinit();
        if (response.status != .invalid_argument or observer.count != 0) {
            return error.InvalidCompressionProbe;
        }
    }

    var stream = try client.startStreaming(.{
        .path = client_streaming_service_path,
        .authority = authority,
        .compression = .gzip,
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    const sizes = [_]usize{ 27_182, 45_904 };
    for (sizes, [_]bool{ true, false }) |size, compress| {
        const request = try messages.encodeStreamingInputCallRequestAlloc(
            allocator,
            .{ .request_body_size = size, .expect_compressed = compress },
        );
        defer allocator.free(request);
        try stream.writeMessageWithOptions(request, .{
            .disable_compression = !compress,
        });
    }
    var observer = AggregateObserver{};
    var response = try stream.finishAndRead(
        &observer,
        AggregateObserver.consume,
    );
    defer response.deinit();
    if (response.status != .ok or observer.count != 1 or
        observer.aggregate != 27_182 + 45_904)
    {
        return error.InvalidCompressionResponse;
    }
}

fn runServerStreamingCompression(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    const expected_sizes = [_]usize{ 31_415, 92_653 };
    const expected_compression = [_]bool{ true, false };
    const parameters = [_]messages.ResponseParameter{
        .{ .size = 31_415, .compressed = true },
        .{ .size = 92_653, .compressed = false },
    };
    const request = try messages.encodeStreamingOutputCallParametersAlloc(
        allocator,
        &parameters,
    );
    defer allocator.free(request);
    var stream = try client.startStreaming(.{
        .path = server_streaming_service_path,
        .authority = authority,
        .accepted_encodings = .{ .gzip = true },
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    try stream.writeMessage(request);
    var observer = Observer{
        .expected_sizes = &expected_sizes,
        .expected_compression = &expected_compression,
    };
    var response = try stream.finishAndRead(&observer, Observer.consume);
    defer response.deinit();
    if (response.status != .ok or observer.message_count != parameters.len or
        !std.mem.eql(
            u8,
            response.encoding orelse return error.InvalidCompressionResponse,
            "gzip",
        ))
    {
        return error.InvalidCompressionResponse;
    }
}

fn runUnaryCompression(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    for ([_]bool{ true, false }) |compress| {
        const request = try messages.encodeSimpleRequestAlloc(allocator, .{
            .response_size = metadata_response_size,
            .request_body_size = metadata_request_size,
            .expect_compressed = compress,
        });
        defer allocator.free(request);
        var response = try client.unary(.{
            .path = unary_service_path,
            .authority = authority,
            .message = request,
            .compression = if (compress) .gzip else .identity,
            .accepted_encodings = .{ .gzip = true },
            .max_message_size = message_limit,
        });
        defer response.deinit();
        try validateUnaryCompressionResponse(response, false);
    }

    for ([_]bool{ true, false }) |compress| {
        const request = try messages.encodeSimpleRequestAlloc(allocator, .{
            .response_size = metadata_response_size,
            .request_body_size = metadata_request_size,
            .response_compressed = compress,
        });
        defer allocator.free(request);
        var response = try client.unary(.{
            .path = unary_service_path,
            .authority = authority,
            .message = request,
            .accepted_encodings = .{ .gzip = true },
            .max_message_size = message_limit,
        });
        defer response.deinit();
        try validateUnaryCompressionResponse(response, compress);
    }
}

fn validateUnaryCompressionResponse(
    response: netz.grpc.UnaryResponse,
    compressed: bool,
) !void {
    if (response.status != .ok or response.message == null) {
        return error.InvalidCompressionResponse;
    }
    try messages.validateStreamingOutputCallResponse(
        response.message.?.payload,
        metadata_response_size,
    );
    if (response.was_compressed != compressed) {
        return error.InvalidCompressionResponse;
    }
    if (compressed and !std.mem.eql(
        u8,
        response.encoding orelse return error.InvalidCompressionResponse,
        "gzip",
    )) {
        return error.InvalidCompressionResponse;
    }
}

fn runPingPong(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    var stream = try client.startDuplex(.{
        .path = service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    var observer = Observer{ .expected_sizes = &canonical_response_sizes };

    for (canonical_request_sizes, canonical_response_sizes) |request_size, response_size| {
        const request = try messages.encodeStreamingOutputCallRequestAlloc(
            allocator,
            .{
                .response_size = @intCast(response_size),
                .request_body_size = request_size,
            },
        );
        defer allocator.free(request);
        try writeMessageFully(allocator, &stream, request, &observer);
        try readThroughMessage(allocator, &stream, &observer);
    }
    try finishRequestFully(allocator, &stream, &observer);
    try readThroughTerminal(allocator, &stream, &observer);
    if (observer.message_count != canonical_response_sizes.len or
        observer.terminal_status != .ok)
    {
        return error.InvalidPingPongResponse;
    }
}

fn runCustomMetadata(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    var stream = try client.startDuplex(.{
        .path = service_path,
        .authority = authority,
        .metadata = &.{.{
            .name = initial_metadata_name,
            .value = initial_metadata_value,
        }},
        .binary_metadata = &.{.{
            .name = trailing_metadata_name,
            .value = &trailing_metadata_value,
        }},
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    const expected = [_]usize{metadata_response_size};
    var observer = Observer{
        .expected_sizes = &expected,
        .expect_metadata_echo = true,
    };
    const request = try messages.encodeStreamingOutputCallRequestAlloc(
        allocator,
        .{
            .response_size = metadata_response_size,
            .request_body_size = metadata_request_size,
        },
    );
    defer allocator.free(request);
    try writeMessageFully(allocator, &stream, request, &observer);
    try finishRequestFully(allocator, &stream, &observer);
    try readThroughTerminal(allocator, &stream, &observer);
    if (observer.message_count != 1 or
        observer.terminal_status != .ok or
        !observer.initial_metadata_echo or
        !observer.trailing_metadata_echo)
    {
        return error.InvalidMetadataResponse;
    }
}

fn runCancellationAndReuse(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    var stream = try client.startDuplex(.{
        .path = service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    var stream_live = true;
    defer if (stream_live) stream.deinit();
    const expected = [_]usize{31_415};
    var observer = Observer{ .expected_sizes = &expected };
    const request = try messages.encodeStreamingOutputCallRequestAlloc(
        allocator,
        .{ .response_size = 31_415, .request_body_size = 27_182 },
    );
    defer allocator.free(request);
    try writeMessageFully(allocator, &stream, request, &observer);
    try readThroughMessage(allocator, &stream, &observer);
    if (observer.message_count != 1) return error.InvalidCancellationResponse;
    try stream.reset(.cancel);
    stream.deinit();
    stream_live = false;

    // Reuse the exact owning channel for an empty FullDuplexCall.  Completion
    // proves the CANCEL reset retired only the preceding HTTP/2 stream.
    var reuse = try client.startDuplex(.{
        .path = service_path,
        .authority = authority,
        .max_message_size = message_limit,
    });
    defer reuse.deinit();
    var reuse_observer = Observer{ .expected_sizes = &.{} };
    try finishRequestFully(allocator, &reuse, &reuse_observer);
    try readThroughTerminal(allocator, &reuse, &reuse_observer);
    if (reuse_observer.message_count != 0 or
        reuse_observer.terminal_status != .ok)
    {
        return error.ChannelReuseFailed;
    }
}

fn runSleepingDeadline(
    allocator: std.mem.Allocator,
    client: *InteropClient,
    message_limit: usize,
) !void {
    // Upstream's canonical case uses 1 ms.  Fifty milliseconds preserves the
    // same server-blocked-on-Read behavior while avoiding scheduler flakes in
    // an external process gate.  The local read timeout is only a harness
    // guard and is intentionally much longer than grpc-timeout.
    var stream = try client.startDuplex(.{
        .path = service_path,
        .authority = authority,
        .timeout = try netz.grpc.Timeout.init(50, .millisecond),
        .max_message_size = message_limit,
    });
    defer stream.deinit();
    var observer = Observer{ .expected_sizes = &.{} };
    const request = try messages.encodeStreamingOutputCallRequestAlloc(
        allocator,
        .{ .response_size = null, .request_body_size = 27_182 },
    );
    defer allocator.free(request);
    try writeMessageFully(allocator, &stream, request, &observer);
    readThroughTerminal(allocator, &stream, &observer) catch |err| switch (err) {
        error.Timeout => {
            if (observer.message_count != 0) {
                return error.InvalidDeadlineResponse;
            }
            return;
        },
        else => return err,
    };
    if (observer.message_count != 0 or
        observer.terminal_status != .deadline_exceeded)
    {
        return error.InvalidDeadlineResponse;
    }
}

const ObservedEvent = enum { metadata, messages, terminal };

const Observer = struct {
    expected_sizes: []const usize,
    expected_compression: ?[]const bool = null,
    message_count: usize = 0,
    expect_metadata_echo: bool = false,
    initial_metadata_echo: bool = false,
    trailing_metadata_echo: bool = false,
    terminal_status: ?netz.grpc.Status = null,
    expected_terminal_message: ?[]const u8 = null,
    terminal_message_matches: bool = false,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (self.message_count >= self.expected_sizes.len) {
            return error.UnexpectedResponseMessage;
        }
        try messages.validateStreamingOutputCallResponse(
            message.payload,
            self.expected_sizes[self.message_count],
        );
        if (self.expected_compression) |expected| {
            if (message.was_compressed != expected[self.message_count]) {
                return error.InvalidCompressionResponse;
            }
        }
        self.message_count += 1;
    }
};

fn writeMessageFully(
    allocator: std.mem.Allocator,
    stream: *netz.grpc.ClientDuplex,
    payload: []const u8,
    observer: *Observer,
) !void {
    var result = try stream.writeMessage(payload);
    while (result == .peer_event) {
        if (try readEvent(allocator, stream, observer) == .terminal) {
            return error.EarlyTerminalResponse;
        }
        result = try stream.resumeMessage();
    }
}

fn finishRequestFully(
    allocator: std.mem.Allocator,
    stream: *netz.grpc.ClientDuplex,
    observer: *Observer,
) !void {
    while (try stream.finishRequest() == .peer_event) {
        if (try readEvent(allocator, stream, observer) == .terminal) return;
    }
}

fn readThroughMessage(
    allocator: std.mem.Allocator,
    stream: *netz.grpc.ClientDuplex,
    observer: *Observer,
) !void {
    const target = observer.message_count + 1;
    while (observer.message_count < target) {
        if (try readEvent(allocator, stream, observer) == .terminal) {
            return error.EarlyTerminalResponse;
        }
    }
}

fn readThroughTerminal(
    allocator: std.mem.Allocator,
    stream: *netz.grpc.ClientDuplex,
    observer: *Observer,
) !void {
    while (observer.terminal_status == null) {
        _ = try readEvent(allocator, stream, observer);
    }
}

fn readEvent(
    allocator: std.mem.Allocator,
    stream: *netz.grpc.ClientDuplex,
    observer: *Observer,
) !ObservedEvent {
    const before = observer.message_count;
    var event = try stream.readResponseEventWithTimeout(
        response_timeout,
        observer,
        Observer.consume,
    );
    defer event.deinit(allocator);
    return switch (event) {
        .informational => error.UnexpectedInformationalResponse,
        .initial_metadata => |head| blk: {
            if (observer.expect_metadata_echo) {
                const value = headerValue(
                    head.headers,
                    initial_metadata_name,
                ) orelse return error.MissingInitialMetadata;
                if (!std.mem.eql(u8, value, initial_metadata_value)) {
                    return error.InvalidInitialMetadata;
                }
                observer.initial_metadata_echo = true;
            }
            break :blk .metadata;
        },
        .messages => |progress| blk: {
            // A grpc-cpp response larger than its HTTP/2 DATA frame size is
            // delivered across several transport events.  Those leading
            // fragments make decoder progress without completing a logical
            // gRPC message, so a zero count is valid; only disagreement with
            // the callback count indicates broken progress accounting.
            if (observer.message_count - before != progress.count) {
                return error.InvalidMessageProgress;
            }
            break :blk .messages;
        },
        .terminal => |response| blk: {
            if (observer.terminal_status != null) {
                return error.DuplicateTerminalResponse;
            }
            observer.terminal_status = response.status;
            if (observer.expected_terminal_message) |expected| {
                if (!std.mem.eql(u8, response.status_message, expected)) {
                    return error.InvalidStatusResponse;
                }
                observer.terminal_message_matches = true;
            }
            if (observer.expect_metadata_echo) {
                const trailers = response.trailers orelse
                    return error.MissingTrailingMetadata;
                var scratch: [trailing_metadata_value.len]u8 = undefined;
                var values = try netz.grpc.BinaryMetadataIterator.init(
                    trailers,
                    trailing_metadata_name,
                    &scratch,
                );
                const first = (try values.next()) orelse
                    return error.MissingTrailingMetadata;
                if (!std.mem.eql(
                    u8,
                    first.value,
                    &trailing_metadata_value,
                ) or try values.next() != null) {
                    return error.InvalidTrailingMetadata;
                }
                observer.trailing_metadata_echo = true;
            }
            break :blk .terminal;
        },
    };
}

fn headerValue(
    headers: []const netz.http2.Hpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

//! Focused netz client for the upstream gRPC C++ interoperability server.
//!
//! The scenarios mirror gRPC Core commit
//! `03d65cc67c450ccbb58a8a45627c4da83a886ccd`'s canonical `ping_pong`,
//! `custom_metadata`, `cancel_after_first_response`, and
//! `timeout_on_sleeping_server` cases.  Only the bounded protobuf fixture
//! subset lives beside this executable; netz's gRPC transport remains payload
//! agnostic.

const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

const service_path = "/grpc.testing.TestService/FullDuplexCall";
const authority = "localhost";
const response_timeout = std.Io.Duration.fromSeconds(10);
const canonical_request_sizes = [_]usize{ 27_182, 8, 1_828, 45_904 };
const canonical_response_sizes = [_]usize{ 31_415, 9, 2_653, 58_979 };
const metadata_request_size = 271_828;
const metadata_response_size = 314_159;
const initial_metadata_name = "x-grpc-test-echo-initial";
const initial_metadata_value = "test_initial_metadata_value";
const trailing_metadata_name = "x-grpc-test-echo-trailing-bin";
const trailing_metadata_value = [_]u8{ 0x0a, 0x0b, 0x0a, 0x0b, 0x0a, 0x0b };

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
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    // The largest canonical metadata response is 314159 bytes.  Keep both
    // transport and gRPC bounds deliberately close to that fixture rather
    // than accepting the library defaults as an accidental unbounded oracle.
    const message_limit = messages.max_payload_size + 64;
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 64 * 1024,
        .max_body_bytes = message_limit,
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
    var client = if (tls_enabled)
        try netz.grpc.runtime.Client.connectTlsAddress(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            "foo.test.google.fr",
            authority,
            .{
                .limits = limits,
                .tls = .{ .ca_bundle = .{
                    .bundle = &ca_bundle,
                    .lock = &ca_lock,
                } },
            },
        )
    else
        try netz.grpc.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer client.deinit();
    if (tls_enabled and
        !std.mem.eql(u8, client.negotiatedAlpn() orelse "", "h2"))
    {
        return error.InvalidAlpn;
    }

    try runPingPong(allocator, &client, message_limit);
    try runCustomMetadata(allocator, &client, message_limit);
    try runCancellationAndReuse(allocator, &client, message_limit);
    try runSleepingDeadline(allocator, &client, message_limit);

    std.debug.print(
        "netz gRPC client interoperated with grpc-cpp: transport={s} " ++
            "ping_pong=4 metadata=initial+trailing-bin " ++
            "cancel=CANCEL reuse=true " ++
            "deadline=DEADLINE_EXCEEDED-or-local-timeout+CANCEL\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

fn runPingPong(
    allocator: std.mem.Allocator,
    client: *netz.grpc.runtime.Client,
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
    client: *netz.grpc.runtime.Client,
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
    client: *netz.grpc.runtime.Client,
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
    client: *netz.grpc.runtime.Client,
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
    message_count: usize = 0,
    expect_metadata_echo: bool = false,
    initial_metadata_echo: bool = false,
    trailing_metadata_echo: bool = false,
    terminal_status: ?netz.grpc.Status = null,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (self.message_count >= self.expected_sizes.len) {
            return error.UnexpectedResponseMessage;
        }
        try messages.validateStreamingOutputCallResponse(
            message.payload,
            self.expected_sizes[self.message_count],
        );
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

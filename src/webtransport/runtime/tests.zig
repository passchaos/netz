//! Tests moved out of the WebTransport runtime root.

const std = @import("std");

test {
    _ = @import("trust_deadline_tests.zig");
    _ = @import("stream/tests/socket_deadline.zig");
}
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const AcceptedHandshakeSession = runtime.AcceptedHandshakeSession;
const AcceptedProtectedSession = runtime.AcceptedProtectedSession;
const ClientSession = runtime.ClientSession;
const HandshakeClientSession = runtime.HandshakeClientSession;
const HandshakeServer = runtime.HandshakeServer;
const HandshakeUriConnectOptions = runtime.HandshakeUriConnectOptions;
const Limits = runtime.Limits;
const PendingSessionClose = runtime.PendingSessionClose;
const ProtectedClientSession = runtime.ProtectedClientSession;
const ProtectedConnectOptions = runtime.ProtectedConnectOptions;
const ProtectedServer = runtime.ProtectedServer;
const Server = runtime.Server;
const StatefulProtectedClientSession = runtime.StatefulProtectedClientSession;
const StatefulProtectedConnectOptions = runtime.StatefulProtectedConnectOptions;
const StatefulProtectedServer = runtime.StatefulProtectedServer;
const application_protocol = runtime.application_protocol;
const early_streams = runtime.early_streams;
const endpoint_client = runtime.endpoint_client;
const finalizeRejectionBody = runtime.finalizeRejectionBody;
const handshake_stream = runtime.handshake_stream;
const preferPeerError = runtime.preferPeerError;
const protected_control = runtime.protected_control;
const sendHandshakeDatagramForTest = runtime.sendHandshakeDatagramForTest;
const session_control = runtime.session_control;
const stream_batch = runtime.stream_batch;
const testBodyPartsSuffix = runtime.testBodyPartsSuffix;
const testing = runtime.testing;

test {
    _ = @import("stream/recovery_tests.zig");
    _ = @import("layout_tests.zig");
}

test "WebTransport pending close uses inline then exact heap storage" {
    const short_reason = [_]u8{'s'} ** 120;
    var no_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var short = try PendingSessionClose.init(
        no_alloc.allocator(),
        17,
        &short_reason,
    );
    defer short.deinit();
    try std.testing.expect(short.storage == .local);
    try std.testing.expectEqual(@as(usize, 128), short.len);
    try std.testing.expect(try short.matches(17, &short_reason));

    const long_reason = [_]u8{'l'} ** 121;
    try std.testing.expectError(
        error.OutOfMemory,
        PendingSessionClose.init(no_alloc.allocator(), 18, &long_reason),
    );
    var long = try PendingSessionClose.init(
        std.testing.allocator,
        18,
        &long_reason,
    );
    defer long.deinit();
    try std.testing.expect(long.storage == .heap);
    try std.testing.expectEqual(@as(usize, 129), long.len);
    try std.testing.expect(try long.matches(18, &long_reason));
    try std.testing.expect(!try long.matches(19, &long_reason));
}

test {
    _ = @import("connect/admission_tests.zig");
    _ = @import("connect/required_flow_tests.zig");
    _ = @import("connect/required_endpoint_tests.zig");
    _ = @import("connect/endpoint_rejection_tests.zig");
    _ = @import("connect/endpoint_buffered_admission_tests.zig");
    _ = @import("connect/message_failure_tests.zig");
    _ = @import("endpoint_server/serve_tests.zig");
    _ = @import("endpoint_server/serve_failure_tests.zig");
    _ = @import("endpoint_server/serve_connection_tests.zig");
    _ = @import("connect/capacity_tests.zig");
    _ = @import("connect/session_capacity_tests.zig");
    _ = @import("endpoint_dispatcher_tests.zig");
    _ = @import("endpoint_client_tests.zig");
    _ = @import("endpoint_client/stream_control_tests.zig");
    _ = @import("endpoint_client/stream_control_lifecycle_tests.zig");
    _ = @import("endpoint_client/close_tests.zig");
    _ = @import("endpoint_client/drain_tests.zig");
    _ = @import("endpoint_server_tests.zig");
    _ = @import("development_lifecycle_tests.zig");
    _ = @import("development_stream_tests.zig");
    _ = @import("recovery_tests.zig");
    _ = @import("flow/configuration_tests.zig");
}

test "WebTransport URI connect rejects non-HTTPS and userinfo before I/O" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const options = HandshakeUriConnectOptions{
        .h3 = .{ .handshake = .{
            .original_destination_connection_id = "original",
            .local_connection_id = "local",
        } },
    };
    try std.testing.expectError(
        error.InvalidUri,
        HandshakeClientSession.connectUri(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "http://example.com/wt",
            options,
        ),
    );
    try std.testing.expectError(
        error.InvalidUri,
        HandshakeClientSession.connectUri(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://user@example.com/wt",
            options,
        ),
    );
    var proxied = options;
    proxied.socks5_proxy = .{ .host = "127.0.0.1", .port = 0 };
    try std.testing.expectError(
        error.InvalidProxyPort,
        HandshakeClientSession.connectUri(
            allocator,
            threaded.io(),
            .{ .ip4 = .loopback(0) },
            "https://proxy-only.invalid/wt",
            proxied,
        ),
    );
}

test "WebTransport declared rejection body retains one exact allocation" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(tracking.allocator());

    try body.ensureTotalCapacityPrecise(tracking.allocator(), 9);
    try body.appendSlice(tracking.allocator(), "try");
    try body.appendSlice(tracking.allocator(), " later");
    const owned = try finalizeRejectionBody(
        &body,
        tracking.allocator(),
        9,
    );
    defer tracking.allocator().free(owned);
    try std.testing.expectEqualStrings("try later", owned);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
}

test "WebTransport DATAGRAM waiter recovers a lost control packet" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const operation_timeout = std.Io.Duration.fromSeconds(30);
    const original_dcid =
        [_]u8{ 0x57, 0x54, 0x44, 0x47, 0x50, 0x00, 0x00, 0x01 };
    const client_cid = [_]u8{ 0x57, 0x54, 0x44, 0x47, 0x50, 0x00, 0x00, 0x02 };
    const server_cid = [_]u8{ 0x57, 0x54, 0x44, 0x47, 0x50, 0x00, 0x00, 0x03 };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xc3} ** 32,
            .x25519_secret_key = [_]u8{0xc4} ** 32,
        } },
    );
    defer server.deinit();

    const Shared = struct {
        const Stage = enum {
            accept,
            open_stream,
            send_stream,
            read_stop,
            send_datagram,
        };

        server: *HandshakeServer,
        io: std.Io,
        timeout: std.Io.Duration,
        stage: Stage = .accept,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                std.debug.print(
                    "WebTransport DATAGRAM waiter server failed during {s}: {s}\n",
                    .{ @tagName(shared.stage), @errorName(err) },
                );
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const deadline = std.Io.Clock.Timestamp.fromNow(
                shared.io,
                .{ .raw = shared.timeout, .clock = .awake },
            );
            var accepted = try shared.server.acceptWithDeadline(deadline);
            defer accepted.deinit();
            var buffer: [32]u8 = undefined;
            shared.stage = .open_stream;
            const stream_id = try accepted.openUnidirectionalStreamWithDeadline(
                deadline,
            );
            shared.stage = .send_stream;
            var committed: usize = 0;
            try accepted.sendStreamWithDeadline(
                stream_id,
                "stop",
                false,
                &committed,
                deadline,
            );
            try std.testing.expectEqual(@as(usize, "stop".len), committed);
            shared.stage = .read_stop;
            while (true) {
                const event = try accepted.readStreamWithDeadline(
                    &buffer,
                    deadline,
                );
                if (event != .stopped) continue;
                try std.testing.expectEqual(stream_id, event.stopped.stream_id);
                try std.testing.expectEqual(
                    @as(?u32, 88),
                    event.stopped.error_info.application_code,
                );
                break;
            }
            shared.stage = .send_datagram;
            try accepted.sendDatagramWithDeadline("cancel observed", deadline);
        }
    };

    var shared = Shared{
        .server = &server,
        .io = io,
        .timeout = operation_timeout,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    const ClientStage = enum {
        connect,
        read_stream,
        stop_stream,
        receive_datagram,
        join,
    };
    var client_stage: ClientStage = .connect;
    errdefer std.debug.print(
        "WebTransport DATAGRAM waiter client failed during {s}\n",
        .{@tagName(client_stage)},
    );
    var drop_enabled = false;
    var dropped: usize = 0;
    const DropFirst = struct {
        fn send(context: *anyopaque, _: []const u8) bool {
            const state: *struct { enabled: *bool, count: *usize } =
                @ptrCast(@alignCast(context));
            if (!state.enabled.* or state.count.* != 0) return false;
            state.count.* = 1;
            return true;
        }
    };
    var drop_state = .{ .enabled = &drop_enabled, .count = &dropped };
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = operation_timeout, .clock = .awake },
    );
    var client = try HandshakeClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-datagram-pto",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
                .send_interceptor = .{
                    .context = &drop_state,
                    .should_drop = DropFirst.send,
                },
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc1} ** 32,
                .x25519_secret_key = [_]u8{0xc2} ** 32,
            } },
        },
        deadline,
    );
    defer client.deinit();
    // A server-created unidirectional stream gives the client a receive side
    // on which STOP_SENDING is valid.
    client_stage = .read_stream;
    var stopped: ?u62 = null;
    var buffer: [32]u8 = undefined;
    while (stopped == null) {
        const event = try client.readStreamWithDeadline(&buffer, deadline);
        if (event != .data) return error.UnexpectedStreamEvent;
        try std.testing.expectEqualStrings(
            "stop",
            buffer[0..event.data.bytes],
        );
        stopped = event.data.stream_id;
    }
    drop_enabled = true;
    client_stage = .stop_stream;
    try client.stopStreamWithDeadline(stopped.?, 88, deadline);

    client_stage = .receive_datagram;
    var observed = try client.receiveDatagramWithDeadline(deadline);
    defer observed.deinit(allocator);
    try std.testing.expectEqualStrings(
        "cancel observed",
        observed.datagram.payload,
    );
    try std.testing.expectEqual(@as(usize, 1), dropped);

    client_stage = .join;
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport cleartext accept validates CONNECT session id direction" {
    try std.testing.expect(webtransport.SessionId.init(0).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(1).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(2).isClientInitiatedBidirectional());
    try std.testing.expect(!webtransport.SessionId.init(3).isClientInitiatedBidirectional());
}

test "WebTransport development runtime exposes pending admission metadata" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            .origin_policy = .{
                .exact = &.{"https://example.test"},
            },
        },
    );
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
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqual(pending.request.from, pending.peerAddress());
            try std.testing.expectEqualStrings("localhost", pending.authority().?);
            try std.testing.expectEqualStrings("/admission", pending.path());
            try std.testing.expectEqualStrings(
                "https://example.test",
                pending.origin().?,
            );
            try std.testing.expectEqualStrings(
                "netz-dev-client",
                pending.userAgent().?,
            );
            var accepted = try pending.acceptWithHeaders(&.{.{
                .name = "x-admission",
                .value = "accepted",
            }});
            pending_owned = false;
            defer accepted.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/admission",
            .origin = "https://example.test",
            .headers = &.{.{
                .name = "user-agent",
                .value = "netz-dev-client",
            }},
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            },
        },
    );
    defer client.deinit();
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-admission").?,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport development runtime sends explicit rejection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
    );
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
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var rejected = try pending.rejectWithBody(
                429,
                &.{.{
                    .name = "retry-after",
                    .value = "5",
                }},
                "slow down",
                &.{.{ .name = "x-final", .value = "true" }},
            );
            pending_owned = false;
            defer rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u16, 429), rejected.status);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var attempt = try ClientSession.connectAttempt(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/busy",
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
                .max_rejection_body_bytes = 9,
            },
        },
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 429), attempt.status());
    try std.testing.expectEqualStrings(
        "5",
        attempt.responseHeader("retry-after").?,
    );
    try std.testing.expectEqualStrings(
        "9",
        attempt.responseHeader("content-length").?,
    );
    try std.testing.expectEqualStrings("slow down", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "x-final",
        attempt.trailers()[0].name,
    );
    try std.testing.expectEqualStrings(
        "true",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport development rejected CONNECT enforces body limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
    );
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
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var rejected = try pending.rejectWithBody(
                413,
                &.{},
                "12345",
                &.{},
            );
            pending_owned = false;
            defer rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.MessageTooLarge,
        ClientSession.connectAttempt(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{
                .authority = "localhost",
                .path = "/too-large",
                .limits = .{
                    .http3 = .{
                        .quic = .{ .max_datagram_size = 4096 },
                    },
                    .max_rejection_body_bytes = 4,
                },
            },
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected runtime sends explicit rejection entity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x20, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x20, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_frames_per_packet = 1,
            .max_stream_frame_data = 3,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var pending = try self.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var rejected = try pending.rejectWithBody(
                503,
                &.{.{ .name = "retry-after", .value = "7" }},
                "try later",
                &.{.{ .name = "x-final", .value = "protected" }},
            );
            pending_owned = false;
            defer rejected.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u16, 503), rejected.status);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var attempt = try ProtectedClientSession.connectAttempt(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/protected-busy",
            .limits = .{
                .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
                .max_rejection_body_bytes = 9,
            },
            .config = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .max_frames_per_packet = 1,
                .max_stream_frame_data = 3,
            },
        },
    );
    defer attempt.deinit();
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u16, 503), attempt.status());
    try std.testing.expectEqualStrings(
        "7",
        attempt.responseHeader("retry-after").?,
    );
    try std.testing.expectEqualStrings(
        "9",
        attempt.responseHeader("content-length").?,
    );
    try std.testing.expectEqualStrings("try later", attempt.body());
    try std.testing.expectEqual(@as(usize, 1), attempt.trailers().len);
    try std.testing.expectEqualStrings(
        "x-final",
        attempt.trailers()[0].name,
    );
    try std.testing.expectEqualStrings(
        "protected",
        attempt.trailers()[0].value,
    );
    try std.testing.expectError(
        error.SessionRejected,
        attempt.requireAccepted(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected pending deinit retires request capacity" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x21, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x21, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe5} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe6} ** quic.protection.secret_len,
    );
    const limits: Limits = .{ .http3 = .{
        .quic = .{ .max_datagram_size = 4096 },
        .max_concurrent_request_streams = 1,
    } };
    const server_config: http3.runtime.ProtectedConfig = .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    };
    const client_config: http3.runtime.ProtectedConfig = .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = webtransport.defaultSettings(.{}),
    };

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        server_config,
    );
    defer server.deinit();
    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |_| {
                var pending = try self.server.receiveSessionRequest();
                pending.deinit();
            }
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try http3.runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits.http3,
        client_config,
    );
    defer client.deinit();
    for (0..2) |index| {
        const stream_id = try client.startRequest(.{
            .method = "CONNECT",
            .path = if (index == 0) "/drop-one" else "/drop-two",
            .scheme = "https",
            .authority = "localhost",
            .headers = &.{
                .{ .name = ":protocol", .value = "webtransport" },
                http3.capsule.protocol_header,
            },
        }, null);
        try std.testing.expectError(
            error.RequestRejected,
            client.receiveResponseEvent(stream_id),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport runtime CONNECT and datagrams over HTTP/3 dev runtime" {
    const allocator = std.testing.allocator;
    const ExpireAfterFirstCheckIo = struct {
        delegate: std.Io,
        now_ns: i96,
        now_calls: usize = 0,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.now_calls += 1;
            const advance: i96 = if (self.now_calls == 1)
                0
            else
                std.time.ns_per_s;
            return .fromNanoseconds(self.now_ns + advance);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            return self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    });
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
            var accepted = try server_ptr.accept();
            defer accepted.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());
            try std.testing.expectEqual(
                @as(?usize, 4092),
                accepted.maxDatagramPayloadSize(),
            );
            var maximum = try server_ptr.receiveDatagram();
            defer maximum.deinit(
                server_ptr.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqual(
                accepted.session_id.value,
                maximum.datagram.session_id.value,
            );
            try std.testing.expectEqual(
                @as(usize, 4092),
                maximum.datagram.payload.len,
            );
            try std.testing.expect(std.mem.allEqual(
                u8,
                maximum.datagram.payload,
                0xa5,
            ));

            for ([_][]const u8{ "client-one", "client-two" }) |expected| {
                var datagram = try server_ptr.receiveDatagram();
                defer datagram.deinit(
                    server_ptr.h3.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqual(
                    accepted.session_id.value,
                    datagram.datagram.session_id.value,
                );
                try std.testing.expectEqualStrings(
                    expected,
                    datagram.datagram.payload,
                );
            }

            try std.testing.expectError(
                error.Timeout,
                server_ptr.sendDatagramWithDeadline(
                    accepted.request.from,
                    accepted.session_id,
                    "not-sent",
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            var rejected_batch_count: usize = 99;
            try std.testing.expectError(
                error.Timeout,
                accepted.sendDatagramsWithDeadline(
                    &.{ "not", "sent" },
                    &rejected_batch_count,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                rejected_batch_count,
            );
            var server_committed: usize = 99;
            try accepted.sendDatagramsWithTimeout(
                &.{ "server-one", "server-two" },
                &server_committed,
                .fromSeconds(1),
            );
            try std.testing.expectEqual(@as(usize, 2), server_committed);
            try std.testing.expectError(
                error.Timeout,
                accepted.drainWithDeadline(
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expect(
                testing.pendingDrainProgress(&accepted) == null,
            );
            try std.testing.expect(
                !accepted.control.control.local_drain_started,
            );
            server_ptr.h3.peer_state_mutex.lockUncancelable(
                server_ptr.h3.quic_server.endpoint.io,
            );
            try std.testing.expectError(
                error.ConcurrencyUnavailable,
                accepted.drainWithDeadline(.fromNow(
                    server_ptr.h3.quic_server.endpoint.io,
                    .{ .raw = .fromSeconds(1), .clock = .awake },
                )),
            );
            server_ptr.h3.peer_state_mutex.unlock(
                server_ptr.h3.quic_server.endpoint.io,
            );
            const drain_progress = testing.pendingDrainProgress(
                &accepted,
            ) orelse return error.TestUnexpectedResult;
            try std.testing.expectEqual(@as(usize, 0), drain_progress.committed);
            try std.testing.expect(accepted.control.control.local_drain_started);
            try accepted.drainWithTimeout(.fromSeconds(1));
            try std.testing.expect(accepted.control.control.local_drain_sent);
            server_ptr.h3.response_send_mutex.lockUncancelable(
                server_ptr.h3.quic_server.endpoint.io,
            );
            try std.testing.expectError(
                error.ConcurrencyUnavailable,
                accepted.receiveSessionEventWithTimeout(.fromSeconds(1)),
            );
            server_ptr.h3.response_send_mutex.unlock(
                server_ptr.h3.quic_server.endpoint.io,
            );
            const pending_close = accepted.pending_session_event orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(pending_close == .closed);
            try std.testing.expectEqual(@as(u32, 31), pending_close.closed.code);
            try std.testing.expectEqualStrings(
                "dev done",
                pending_close.closed.reason,
            );
            try std.testing.expect(
                !accepted.control.control.local_close_sent,
            );
            const closed = try accepted.receiveSessionEventWithTimeout(
                .fromSeconds(1),
            );
            try std.testing.expect(closed == .closed);
            try std.testing.expectEqual(@as(u32, 31), closed.closed.code);
            try std.testing.expectEqualStrings("dev done", closed.closed.reason);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
    });
    defer client.deinit();
    try std.testing.expectEqual(@as(usize, 4092), client.maxDatagramSize());
    const maximum_datagram = try allocator.alloc(
        u8,
        client.maxDatagramSize(),
    );
    defer allocator.free(maximum_datagram);
    @memset(maximum_datagram, 0xa5);
    const oversized_datagram = try allocator.alloc(
        u8,
        client.maxDatagramSize() + 1,
    );
    defer allocator.free(oversized_datagram);

    var size_probe = ExpireAfterFirstCheckIo{
        .delegate = client.h3.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var size_probe_vtable = size_probe.delegate.vtable.*;
    size_probe_vtable.now = ExpireAfterFirstCheckIo.now;
    size_probe_vtable.netSend = ExpireAfterFirstCheckIo.netSend;
    client.h3.quic_client.endpoint.io = .{
        .userdata = &size_probe,
        .vtable = &size_probe_vtable,
    };
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagram(oversized_datagram),
    );
    try std.testing.expectEqual(@as(usize, 0), size_probe.send_calls);
    client.h3.quic_client.endpoint.io = size_probe.delegate;
    try client.sendDatagram(maximum_datagram);

    try std.testing.expectError(
        error.Timeout,
        client.receiveDatagramWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveDatagramWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramWithTimeout("not-sent", .zero),
    );
    var rejected_batch_count: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramsWithTimeout(
            &.{ "not", "sent" },
            &rejected_batch_count,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected_batch_count);
    var body_progress: http3.runtime.DevelopmentBodyWriteProgress = .{
        .send_attempted = true,
        .completed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendSessionDataWithTimeout(
            "not-sent",
            false,
            &body_progress,
            .zero,
        ),
    );
    try std.testing.expect(!body_progress.send_attempted);
    try std.testing.expect(!body_progress.completed);
    var client_committed: usize = 99;
    try client.sendDatagramsWithDeadline(
        &.{ "client-one", "client-two" },
        &client_committed,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 2), client_committed);
    for ([_][]const u8{ "server-one", "server-two" }) |expected| {
        var response = try client.receiveDatagram();
        defer response.deinit(allocator);
        try std.testing.expectEqual(
            client.session_id.value,
            response.datagram.session_id.value,
        );
        try std.testing.expectEqualStrings(expected, response.datagram.payload);
    }
    const draining = try client.receiveSessionEventWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expect(draining == .draining);
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(
            31,
            "dev done",
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expect(testing.pendingCloseProgress(&client) == null);
    try std.testing.expect(!client.control.control.local_close_started);
    var expiring = ExpireAfterFirstCheckIo{
        .delegate = client.h3.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var expiring_vtable = expiring.delegate.vtable.*;
    expiring_vtable.now = ExpireAfterFirstCheckIo.now;
    expiring_vtable.netSend = ExpireAfterFirstCheckIo.netSend;
    client.h3.quic_client.endpoint.io = .{
        .userdata = &expiring,
        .vtable = &expiring_vtable,
    };
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(31, "dev done", .{
            .clock = .awake,
            .raw = .fromNanoseconds(expiring.now_ns + 1),
        }),
    );
    const close_progress = testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 0), close_progress.committed);
    try std.testing.expectEqual(@as(usize, 0), expiring.send_calls);
    try std.testing.expect(client.control.control.local_close_started);
    try std.testing.expect(!client.control.control.local_close_failed);
    try std.testing.expect(!client.h3.request_unusable);
    client.h3.quic_client.endpoint.io = expiring.delegate;
    try client.closeWithTimeout(31, "dev done", .fromSeconds(1));
    const peer_fin = try client.receiveSessionEventWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expect(peer_fin == .closed);
    try std.testing.expectEqual(@as(u32, 0), peer_fin.closed.code);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport development close deadline fails closed after a visible prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Server,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
                self.accepted.set(self.server.h3.quic_server.endpoint.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.accept();
            defer session.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            self.accepted.set(self.server.h3.quic_server.endpoint.io);
            try self.release.wait(self.server.h3.quic_server.endpoint.io);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        thread.join();
    };

    var client = try ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/development-close-fail-closed",
            .limits = .{ .http3 = .{
                .quic = .{ .max_datagram_size = 4096 },
                .max_stream_frame_data = 32,
            } },
        },
    );
    defer client.deinit();
    try shared.accepted.wait(io);
    client.h3.quic_client.endpoint.limits.max_datagram_size = 96;

    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };
    var timed = DeadlineAfterSendIo{
        .delegate = client.h3.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.h3.quic_client.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    defer client.h3.quic_client.endpoint.io = timed.delegate;

    const reason = "0123456789abcdef" ** 16;
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(41, reason, .{
            .clock = .awake,
            .raw = .fromNanoseconds(timed.now_ns + 1),
        }),
    );
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
    try std.testing.expect(client.h3.request_unusable);
    try std.testing.expect(client.control.control.local_close_failed);
    try std.testing.expect(!client.control.control.local_close_started);
    try std.testing.expect(testing.pendingCloseProgress(&client) == null);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("must-not-send"),
    );
    try client.closeWithTimeout(99, "ignored", .fromSeconds(1));

    shared.release.set(io);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport development server close deadline preserves zero-progress state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
    );
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
            var session = try self.server.accept();
            defer session.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectError(
                error.Timeout,
                session.closeWithDeadline(
                    42,
                    "server done",
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expect(
                testing.pendingCloseProgress(&session) == null,
            );
            try std.testing.expect(
                !session.control.control.local_close_started,
            );
            try session.closeWithTimeout(
                42,
                "server done",
                .fromSeconds(1),
            );
            try std.testing.expect(session.control.control.local_close_sent);
            const peer_fin = try session.receiveSessionEventWithTimeout(
                .fromSeconds(1),
            );
            try std.testing.expect(peer_fin == .closed);
            try std.testing.expectEqual(@as(u32, 0), peer_fin.closed.code);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try ClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/development-server-close-deadline",
            .limits = .{ .http3 = .{
                .quic = .{ .max_datagram_size = 4096 },
            } },
        },
    );
    defer client.deinit();
    const closed = try client.receiveSessionEventWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 42), closed.closed.code);
    try std.testing.expectEqualStrings("server done", closed.closed.reason);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected runtime CONNECT and datagrams over QUIC 1-RTT" {
    const allocator = std.testing.allocator;
    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xb1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xb2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .max_stream_frame_data = 5,
    });
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        io: std.Io,
        initial_timeout_done: std.Io.Event = .unset,
        close_sent: std.Io.Event = .unset,
        sibling_stream_id: u62 = 4,
        err: ?anyerror = null,
        failed: std.atomic.Value(bool) = .init(false),

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
                shared.failed.store(true, .release);
                shared.initial_timeout_done.set(shared.io);
                shared.close_sent.set(shared.io);
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            try std.testing.expectError(
                error.Timeout,
                server_ptr.receiveSessionRequestWithDeadline(.{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectError(
                error.Timeout,
                server_ptr.receiveSessionRequestWithTimeout(
                    .fromMilliseconds(10),
                ),
            );
            shared.initial_timeout_done.set(shared.io);
            var pending = try server_ptr.receiveSessionRequestWithDeadline(
                .fromNow(shared.io, .{
                    .raw = .fromSeconds(1),
                    .clock = .awake,
                }),
            );
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            try std.testing.expectEqualStrings(
                "localhost",
                pending.authority().?,
            );
            try std.testing.expectEqualStrings(
                "/wt-protected",
                pending.path(),
            );
            var accepted = try pending.acceptWithHeaders(&.{.{
                .name = "x-protected-admission",
                .value = "accepted",
            }});
            pending_owned = false;
            defer accepted.deinit(server_ptr.h3.quic_server.endpoint.allocator);
            try std.testing.expectEqual(
                @as(?usize, 4067),
                accepted.maxDatagramPayloadSize(server_ptr),
            );
            var control_buffer: [64]u8 = undefined;
            const expected_control = "protected-client-control";
            var control_len: usize = 0;
            while (control_len < expected_control.len) {
                const control = try server_ptr.receiveSessionDataWithTimeout(
                    accepted.session_id,
                    control_buffer[control_len..],
                    .fromSeconds(3),
                );
                try std.testing.expect(!control.fin);
                control_len += control.bytes;
            }
            try std.testing.expectEqualStrings(
                expected_control,
                control_buffer[0..control_len],
            );
            // The ordinary request was ready first. The targeted session read
            // above must leave its events buffered for this explicit sibling
            // consumer rather than returning InvalidSessionState.
            var sibling_head = try server_ptr.h3
                .receiveRequestEventForWithTimeout(
                shared.sibling_stream_id,
                .fromSeconds(1),
            );
            defer sibling_head.deinit(allocator);
            try std.testing.expect(sibling_head == .message);
            try std.testing.expect(sibling_head.message.value == .head);
            try std.testing.expectEqualStrings(
                "/protected-sibling",
                sibling_head.message.value.head.request.path,
            );
            var sibling_finished = try server_ptr.h3
                .receiveRequestEventForWithTimeout(
                shared.sibling_stream_id,
                .fromSeconds(1),
            );
            defer sibling_finished.deinit(allocator);
            try std.testing.expect(sibling_finished == .message);
            try std.testing.expect(
                sibling_finished.message.value == .finished,
            );
            try server_ptr.h3.sendResponseWithTimeout(
                accepted.request.from,
                shared.sibling_stream_id,
                .{ .status = 204 },
                .fromSeconds(3),
            );
            try std.testing.expectError(
                error.Timeout,
                accepted.drainWithDeadline(
                    server_ptr,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expect(
                testing.pendingDrainProgress(&accepted) == null,
            );
            try std.testing.expect(
                !accepted.control.control.local_drain_started,
            );
            var timed = DeadlineAfterSendIo{
                .delegate = server_ptr.h3.quic_server.endpoint.io,
                .now_ns = std.Io.Clock.awake.now(
                    server_ptr.h3.quic_server.endpoint.io,
                ).nanoseconds,
            };
            var timed_vtable = timed.delegate.vtable.*;
            timed_vtable.now = DeadlineAfterSendIo.now;
            timed_vtable.netSend = DeadlineAfterSendIo.netSend;
            server_ptr.h3.quic_server.endpoint.io = .{
                .userdata = &timed,
                .vtable = &timed_vtable,
            };
            try std.testing.expectError(
                error.Timeout,
                accepted.drainWithDeadline(
                    server_ptr,
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(timed.now_ns + 1),
                    },
                ),
            );
            const drain_progress = testing.pendingDrainProgress(
                &accepted,
            ) orelse return error.TestUnexpectedResult;
            try std.testing.expect(drain_progress.committed > 0);
            try std.testing.expect(
                drain_progress.committed < drain_progress.total,
            );
            try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
            try std.testing.expect(
                !accepted.control.control.local_drain_sent,
            );
            server_ptr.h3.quic_server.endpoint.io = timed.delegate;
            try accepted.drainWithTimeout(server_ptr, .fromSeconds(1));
            try std.testing.expect(
                testing.pendingDrainProgress(&accepted) == null,
            );
            try std.testing.expect(accepted.control.control.local_drain_sent);
            var maximum = try server_ptr.receiveDatagramWithTimeout(
                .fromSeconds(3),
            );
            defer maximum.deinit(
                server_ptr.h3.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqual(
                accepted.session_id.value,
                maximum.datagram.session_id.value,
            );
            try std.testing.expectEqual(
                @as(usize, 4067),
                maximum.datagram.payload.len,
            );
            try std.testing.expect(std.mem.allEqual(
                u8,
                maximum.datagram.payload,
                0x5a,
            ));
            for ([_][]const u8{ "protected-client-one", "protected-client-two" }) |expected| {
                var datagram = try server_ptr.receiveDatagramWithTimeout(
                    .fromSeconds(3),
                );
                defer datagram.deinit(
                    server_ptr.h3.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqual(
                    accepted.session_id.value,
                    datagram.datagram.session_id.value,
                );
                try std.testing.expectEqualStrings(
                    expected,
                    datagram.datagram.payload,
                );
            }
            const datagram_packet_number = server_ptr.h3.next_packet_number;
            try std.testing.expectError(
                error.Timeout,
                server_ptr.sendDatagramWithDeadline(
                    accepted.request.from,
                    accepted.session_id,
                    "not-sent",
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                datagram_packet_number,
                server_ptr.h3.next_packet_number,
            );
            var server_committed: usize = 99;
            try accepted.sendDatagramsWithTimeout(
                server_ptr,
                &.{ "protected-server-one", "protected-server-two" },
                &server_committed,
                .fromSeconds(1),
            );
            try std.testing.expectEqual(@as(usize, 2), server_committed);
            // The client first forces a partial CLOSE write, then resumes it.
            // Wait for the complete close before constraining the response
            // direction so this assertion does not race UDP delivery.
            try shared.close_sent.waitTimeout(shared.io, .{
                .duration = .{
                    .raw = .fromSeconds(3),
                    .clock = .awake,
                },
            });
            const response_entry = server_ptr.h3.outbound_bodies.find(
                accepted.session_id.value,
            ).?;
            response_entry.flow_limit = response_entry.send.next_offset - 1;
            try std.testing.expectError(
                error.Timeout,
                accepted.receiveSessionEventWithTimeout(
                    server_ptr,
                    .fromMilliseconds(20),
                ),
            );
            const pending_close = accepted.pending_session_event orelse
                return error.TestUnexpectedResult;
            try std.testing.expect(pending_close == .closed);
            try std.testing.expectEqual(@as(u32, 91), pending_close.closed.code);
            try std.testing.expectEqualStrings(
                "protected done",
                pending_close.closed.reason,
            );
            try std.testing.expect(
                !accepted.control.control.local_close_sent,
            );
            response_entry.flow_limit = null;
            const close_event = try accepted.receiveSessionEventWithTimeout(
                server_ptr,
                .fromSeconds(1),
            );
            try std.testing.expect(close_event == .closed);
            try std.testing.expectEqual(
                @as(u32, 91),
                close_event.closed.code,
            );
            try std.testing.expectEqualStrings(
                "protected done",
                close_event.closed.reason,
            );
        }
    };

    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try shared.initial_timeout_done.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(3),
        .clock = .awake,
    } });

    const connect_options: ProtectedConnectOptions = .{
        .authority = "localhost",
        .path = "/wt-protected",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .config = .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_frame_data = 5,
        },
    };
    try std.testing.expectError(
        error.Timeout,
        ProtectedClientSession.connectAttemptWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        ProtectedClientSession.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .zero,
        ),
    );
    var client = try ProtectedClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        connect_options,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer client.deinit();
    try std.testing.expectEqual(@as(usize, 4067), client.maxDatagramSize());
    const maximum_datagram = try allocator.alloc(
        u8,
        client.maxDatagramSize(),
    );
    defer allocator.free(maximum_datagram);
    @memset(maximum_datagram, 0x5a);
    const oversized_datagram = try allocator.alloc(
        u8,
        client.maxDatagramSize() + 1,
    );
    defer allocator.free(oversized_datagram);

    var size_probe = DeadlineAfterSendIo{
        .delegate = client.h3.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var size_probe_vtable = size_probe.delegate.vtable.*;
    size_probe_vtable.now = DeadlineAfterSendIo.now;
    size_probe_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.h3.quic_client.endpoint.io = .{
        .userdata = &size_probe,
        .vtable = &size_probe_vtable,
    };
    const size_probe_packet_number = client.h3.next_packet_number;
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagram(oversized_datagram),
    );
    try std.testing.expectEqual(@as(usize, 0), size_probe.send_calls);
    try std.testing.expectEqual(
        size_probe_packet_number,
        client.h3.next_packet_number,
    );
    client.h3.quic_client.endpoint.io = size_probe.delegate;
    try std.testing.expectEqualStrings(
        "accepted",
        client.responseHeader("x-protected-admission").?,
    );

    const sibling_stream_id = try client.h3.sendRequestWithTimeout(
        .{
            .method = "GET",
            .path = "/protected-sibling",
            .authority = "localhost",
        },
        .fromSeconds(3),
    );
    try std.testing.expectEqual(shared.sibling_stream_id, sibling_stream_id);
    var session_data_progress: http3.runtime.BodyWriteProgress = .{};
    try client.sendSessionDataWithTimeout(
        "protected-client-control",
        false,
        &session_data_progress,
        .fromSeconds(3),
    );
    var sibling_response = client.h3.receiveResponseWithTimeout(
        sibling_stream_id,
        .fromSeconds(1),
    ) catch |err| return preferPeerError(&shared, err);
    defer sibling_response.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 204),
        sibling_response.response.status,
    );
    const drain = client.receiveSessionEventWithTimeout(
        .fromSeconds(3),
    ) catch |err| return preferPeerError(&shared, err);
    try std.testing.expect(drain == .draining);
    try client.sendDatagramWithTimeout(maximum_datagram, .fromSeconds(3));
    const datagram_packet_number = client.h3.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramWithTimeout("not-sent", .zero),
    );
    try std.testing.expectEqual(
        datagram_packet_number,
        client.h3.next_packet_number,
    );
    var client_committed: usize = 99;
    try client.sendDatagramsWithDeadline(
        &.{ "protected-client-one", "protected-client-two" },
        &client_committed,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 2), client_committed);
    for ([_][]const u8{ "protected-server-one", "protected-server-two" }) |expected| {
        var response = client.receiveDatagramWithTimeout(
            .fromSeconds(3),
        ) catch |err| return preferPeerError(&shared, err);
        defer response.deinit(allocator);
        try std.testing.expectEqual(
            client.session_id.value,
            response.datagram.session_id.value,
        );
        try std.testing.expectEqualStrings(expected, response.datagram.payload);
    }
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(
            91,
            "protected done",
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expect(testing.pendingCloseProgress(&client) == null);
    try std.testing.expect(!client.control.control.local_close_started);
    var timed = DeadlineAfterSendIo{
        .delegate = client.h3.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.h3.quic_client.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    try std.testing.expectError(
        error.Timeout,
        client.closeWithDeadline(91, "protected done", .{
            .clock = .awake,
            .raw = .fromNanoseconds(timed.now_ns + 1),
        }),
    );
    const close_progress = testing.pendingCloseProgress(&client) orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(close_progress.committed > 0);
    try std.testing.expect(close_progress.committed < close_progress.total);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);
    try std.testing.expect(!client.control.control.local_close_sent);
    client.h3.quic_client.endpoint.io = timed.delegate;
    try client.closeWithTimeout(91, "protected done", .fromSeconds(1));
    shared.close_sent.set(io);
    try std.testing.expect(testing.pendingCloseProgress(&client) == null);
    try std.testing.expect(client.control.control.local_close_sent);
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("protected-late"),
    );
    // The lightweight adapter deliberately has no retransmission owner. Wait
    // until its server thread has submitted the final FIN before starting the
    // client budget, so scheduler delay is not mistaken for packet loss.
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    const peer_fin = try client.receiveSessionEventWithTimeout(.fromSeconds(3));
    try std.testing.expect(peer_fin == .closed);
    try std.testing.expectEqual(@as(u32, 0), peer_fin.closed.code);
    try std.testing.expectEqualStrings("", peer_fin.closed.reason);
}

test "WebTransport protected session DATA slices resume exact suffix" {
    const allocator = std.testing.allocator;
    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x6d, 0x73, 0x67, 0x01 };
    const server_cid = [_]u8{ 0x6d, 0x73, 0x67, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_frames_per_packet = 2,
            .max_stream_frame_data = 48,
        },
    );
    defer server.deinit();

    var expected_storage: [256]u8 = undefined;
    const expected_capsule = try http3.capsule.writeInto(
        &expected_storage,
        0x2a,
        "protected-sliced-control-payload",
    );
    const split_a = 1;
    const split_b = expected_capsule.len - 4;
    const parts = [_][]const u8{
        expected_capsule[0..split_a],
        &.{},
        expected_capsule[split_a..split_b],
        expected_capsule[split_b..],
    };

    const Shared = struct {
        server: *ProtectedServer,
        io: std.Io,
        expected: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var pending = try shared.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var accepted = try pending.accept();
            pending_owned = false;
            defer accepted.deinit(
                shared.server.h3.quic_server.endpoint.allocator,
            );

            var received: [256]u8 = undefined;
            var used: usize = 0;
            while (used < shared.expected.len) {
                const read = try shared.server.receiveSessionData(
                    accepted.session_id,
                    received[used..],
                );
                try std.testing.expect(!read.fin);
                used += read.bytes;
            }
            try std.testing.expectEqualSlices(
                u8,
                shared.expected,
                received[0..used],
            );

            var response_progress: http3.runtime.BodyWriteProgress = .{};
            try shared.server.sendSessionDataSlicesWithTimeout(
                accepted.request.from,
                accepted.session_id,
                &.{ shared.expected[0..2], &.{}, shared.expected[2..] },
                false,
                &response_progress,
                .fromSeconds(1),
            );
            try std.testing.expectEqual(
                shared.expected.len,
                response_progress.committed_bytes,
            );
            try std.testing.expect(!response_progress.fin_committed);
        }
    };

    var shared = Shared{
        .server = &server,
        .io = io,
        .expected = expected_capsule,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try ProtectedClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-protected-slices",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .config = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 48,
            },
        },
    );
    defer client.deinit();

    var invalid_progress: http3.runtime.BodyWriteProgress = .{
        .committed_bytes = 99,
        .fin_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client.sendSessionDataSlicesWithTimeout(
            &parts,
            false,
            &invalid_progress,
            .zero,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_progress.committed_bytes,
    );
    try std.testing.expect(!invalid_progress.fin_committed);

    var timed = DeadlineAfterSendIo{
        .delegate = client.h3.quic_client.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.quic_client.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.h3.quic_client.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    var progress: http3.runtime.BodyWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendSessionDataSlicesWithDeadline(
            &parts,
            false,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(
        progress.committed_bytes < expected_capsule.len,
    );
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

    client.h3.quic_client.endpoint.io = timed.delegate;
    var suffix_storage: [parts.len][]const u8 = undefined;
    const suffix = testBodyPartsSuffix(
        &parts,
        progress.committed_bytes,
        &suffix_storage,
    );
    try client.sendSessionDataSlicesWithTimeout(
        suffix,
        false,
        &progress,
        .fromSeconds(1),
    );
    var suffix_len: usize = 0;
    for (suffix) |part| suffix_len += part.len;
    try std.testing.expectEqual(suffix_len, progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);

    var response: [256]u8 = undefined;
    var response_len: usize = 0;
    while (response_len < expected_capsule.len) {
        const read = try client.receiveSessionDataWithTimeout(
            response[response_len..],
            .fromSeconds(1),
        );
        try std.testing.expect(!read.fin);
        response_len += read.bytes;
    }
    try std.testing.expectEqualSlices(
        u8,
        expected_capsule,
        response[0..response_len],
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected control receive deadlines preserve parser state" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xfa, 0xce, 0x10, 0x01 };
    const server_cid = [_]u8{ 0xfa, 0xce, 0x10, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd2} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_frame_data = 5,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        io: std.Io,
        client_timeout_done: std.Io.Event = .unset,
        close_prefix_sent: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var pending = try shared.server.receiveSessionRequest();
            var pending_owned = true;
            defer if (pending_owned) pending.deinit();
            var accepted = try pending.accept();
            pending_owned = false;
            defer accepted.deinit(
                shared.server.h3.quic_server.endpoint.allocator,
            );

            try std.testing.expectError(
                error.Timeout,
                accepted.receiveSessionEventWithTimeout(
                    shared.server,
                    .fromMilliseconds(5),
                ),
            );
            try shared.client_timeout_done.wait(shared.io);
            try shared.server.sendSessionData(
                accepted.request.from,
                accepted.session_id,
                "server-after-timeout",
                false,
            );

            var close_storage: [64]u8 = undefined;
            const close = try session_control.writeCloseInto(
                &close_storage,
                71,
                "server done",
            );
            try std.Io.sleep(
                shared.io,
                .fromMilliseconds(5),
                .awake,
            );
            try shared.server.sendSessionData(
                accepted.request.from,
                accepted.session_id,
                close[0..3],
                false,
            );
            shared.close_prefix_sent.set(shared.io);
            try std.Io.sleep(shared.io, .fromMilliseconds(25), .awake);
            try shared.server.sendSessionData(
                accepted.request.from,
                accepted.session_id,
                close[3..],
                true,
            );
            try accepted.control.control.recordLocalClose(71);
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try ProtectedClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-protected-deadline",
            .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096 } } },
            .config = .{
                .receive_keys = server_keys,
                .send_keys = client_keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .max_stream_frame_data = 5,
            },
        },
    );
    defer client.deinit();

    try std.testing.expectError(
        error.Timeout,
        server.receiveDatagramWithTimeout(.zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client.receiveDatagramWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
    var control_bytes: [64]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionDataWithTimeout(
            &control_bytes,
            .fromMilliseconds(5),
        ),
    );
    shared.client_timeout_done.set(io);
    const read = try client.receiveSessionDataWithDeadline(
        &control_bytes,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqualStrings(
        "server-after-timeout",
        control_bytes[0..read.bytes],
    );
    try shared.close_prefix_sent.wait(io);
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionEventWithTimeout(.fromMilliseconds(5)),
    );
    const request_entry = client.h3.outbound_bodies.find(
        client.session_id.value,
    ).?;
    request_entry.flow_limit = request_entry.send.next_offset - 1;
    try std.testing.expectError(
        error.Timeout,
        client.receiveSessionEventWithTimeout(.fromMilliseconds(50)),
    );
    const pending_close = client.pending_session_event orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(pending_close == .closed);
    try std.testing.expectEqual(@as(u32, 71), pending_close.closed.code);
    try std.testing.expectEqualStrings(
        "server done",
        pending_close.closed.reason,
    );
    try std.testing.expect(!client.control.control.local_close_sent);
    request_entry.flow_limit = null;
    const closed = try client.receiveSessionEventWithTimeout(.fromSeconds(1));
    try std.testing.expect(closed == .closed);
    try std.testing.expectEqual(@as(u32, 71), closed.closed.code);
    try std.testing.expectEqualStrings("server done", closed.closed.reason);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport protected control deadlines reject invalid budgets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe1} ** quic.protection.secret_len,
    );
    const config: http3.runtime.ProtectedConfig = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "wt-deadline",
        .peer_connection_id = "wt-deadline-peer",
    };

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        config,
    );
    defer server.deinit();
    var server_session = AcceptedProtectedSession{
        .request = undefined,
        .session_id = .init(0),
        .control = protected_control.Reader.init(
            try session_control.Control.init(std.testing.allocator, .init(0)),
        ),
    };
    defer server_session.control.deinit();
    try std.testing.expectError(
        error.Timeout,
        server_session.receiveSessionEventWithTimeout(&server, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        server_session.receiveSessionEventWithDeadline(
            &server,
            .{ .raw = .zero, .clock = .real },
        ),
    );
    var server_datagram_committed: usize = 99;
    const server_packet_number = server.h3.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        server_session.sendDatagramsWithDeadline(
            &server,
            &.{ "not", "sent" },
            &server_datagram_committed,
            .{ .raw = .zero, .clock = .real },
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), server_datagram_committed);
    try std.testing.expectEqual(
        server_packet_number,
        server.h3.next_packet_number,
    );
    try std.testing.expectError(
        error.Timeout,
        server_session.drainWithTimeout(&server, .zero),
    );
    try std.testing.expect(
        testing.pendingDrainProgress(&server_session) == null,
    );
    try std.testing.expect(
        !server_session.control.control.local_drain_started,
    );
    try std.testing.expectError(
        error.Timeout,
        server_session.closeWithDeadline(
            &server,
            70,
            "invalid-clock",
            .{ .raw = .zero, .clock = .real },
        ),
    );
    try std.testing.expect(
        testing.pendingCloseProgress(&server_session) == null,
    );
    try std.testing.expect(
        !server_session.control.control.local_close_started,
    );

    var client_h3 = try http3.runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        config,
    );
    var client_session = ProtectedClientSession{
        .h3 = client_h3,
        .session_id = .init(0),
        .response = undefined,
        .control = protected_control.Reader.init(
            try session_control.Control.init(std.testing.allocator, .init(0)),
        ),
    };
    client_h3 = undefined;
    defer {
        client_session.control.deinit();
        client_session.h3.deinit();
    }
    var buffer: [16]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        client_session.receiveSessionDataWithTimeout(&buffer, .zero),
    );
    try std.testing.expectError(
        error.Timeout,
        client_session.receiveSessionEventWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
    var client_datagram_committed: usize = 99;
    const client_packet_number = client_session.h3.next_packet_number;
    try std.testing.expectError(
        error.Timeout,
        client_session.sendDatagramsWithTimeout(
            &.{ "not", "sent" },
            &client_datagram_committed,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), client_datagram_committed);
    try std.testing.expectEqual(
        client_packet_number,
        client_session.h3.next_packet_number,
    );
    var progress: http3.runtime.BodyWriteProgress = .{
        .committed_bytes = 99,
        .fin_committed = true,
    };
    try std.testing.expectError(
        error.Timeout,
        client_session.sendSessionDataWithTimeout(
            "not-sent",
            false,
            &progress,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectError(
        error.Timeout,
        client_session.drainWithDeadline(
            .{ .raw = .zero, .clock = .real },
        ),
    );
    try std.testing.expect(
        testing.pendingDrainProgress(&client_session) == null,
    );
    try std.testing.expect(
        !client_session.control.control.local_drain_started,
    );
    try std.testing.expectError(
        error.Timeout,
        client_session.closeWithTimeout(70, "zero", .zero),
    );
    try std.testing.expect(
        testing.pendingCloseProgress(&client_session) == null,
    );
    try std.testing.expect(
        !client_session.control.control.local_close_started,
    );
}

test "WebTransport stateful preconfigured runtime exchanges associated streams" {
    const allocator = std.testing.allocator;
    const ClientStage = enum {
        setup,
        connect,
        datagrams,
        session_data,
        streams,
        reset_stop,
        close,
    };
    var client_stage: ClientStage = .setup;
    errdefer std.debug.print(
        "WebTransport stateful associated-stream client failed during {s}\n",
        .{@tagName(client_stage)},
    );

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const server_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc1} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc2} ** quic.protection.secret_len,
    );
    const local_settings = webtransport.defaultSettings(.{});
    var drop_associated_stream = false;
    var dropped_associated_datagrams: usize = 0;
    const DropFirstAssociatedDatagram = struct {
        fn send(context: *anyopaque, _: []const u8) bool {
            const state: *struct {
                enabled: *bool,
                count: *usize,
            } = @ptrCast(@alignCast(context));
            if (!state.enabled.* or state.count.* != 0) return false;
            state.count.* = 1;
            return true;
        }
    };
    var drop_state = .{
        .enabled = &drop_associated_stream,
        .count = &dropped_associated_datagrams,
    };

    var server = try StatefulProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{ .quic = .{ .max_datagram_size = 4096 } },
            .max_session_streams = 2,
        },
        .{ .local_settings = local_settings },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    defer server.deinit();

    const Shared = struct {
        const Stage = enum {
            initial_timeout,
            accept,
            datagrams,
            session_data,
            streams,
            reset_stop,
            close,
        };

        server: *StatefulProtectedServer,
        io: std.Io,
        initial_timeout_done: std.Io.Event = .unset,
        stage: Stage = .initial_timeout,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                std.debug.print(
                    "WebTransport stateful associated-stream server failed during {s}: {s}\n",
                    .{ @tagName(self.stage), @errorName(err) },
                );
                self.err = err;
                self.initial_timeout_done.set(self.io);
            };
        }

        fn runFallible(self: *@This()) !void {
            try std.testing.expectError(
                error.Timeout,
                self.server.receiveSessionRequestWithDeadline(.{
                    .clock = .real,
                    .raw = .zero,
                }),
            );
            try std.testing.expectError(
                error.Timeout,
                self.server.receiveSessionRequestWithTimeout(
                    .fromMilliseconds(10),
                ),
            );
            self.initial_timeout_done.set(self.io);
            self.stage = .accept;
            var session = try self.server.acceptWithDeadline(.fromNow(
                self.io,
                .{ .raw = .fromSeconds(1), .clock = .awake },
            ));
            defer session.deinit();
            self.stage = .datagrams;
            var datagrams = try session.receiveManyDatagramsWithTimeout(
                3,
                .fromSeconds(3),
            );
            defer datagrams.deinit();
            if (datagrams.firstError()) |err| return err;
            const expected_datagrams = [_][]const u8{
                "stateful-one",
                "stateful-two",
                "stateful-three",
            };
            for (datagrams.datagrams, expected_datagrams) |maybe, expected| {
                const datagram = maybe orelse return error.MissingDatagram;
                try std.testing.expectEqualStrings(
                    expected,
                    datagram.datagram.payload,
                );
            }
            var datagrams_sent: usize = 99;
            try session.sendDatagramsWithTimeout(
                &.{ "stateful-reply-one", "stateful-reply-two" },
                &datagrams_sent,
                .fromSeconds(3),
            );
            try std.testing.expectEqual(@as(usize, 2), datagrams_sent);
            self.stage = .session_data;
            const session_data_event = try session
                .receiveSessionEventWithTimeout(.fromSeconds(3));
            try std.testing.expect(session_data_event == .draining);

            // The first bidi packet is deliberately lost below, so the later
            // uni stream may complete first. Association routing must remain
            // correct across streams while the missing bidi prefix/data is
            // recovered.
            self.stage = .streams;
            var received_bidi = false;
            var received_uni = false;
            while (!received_bidi or !received_uni) {
                var received = try session.receiveStreamWithTimeout(
                    .fromSeconds(3),
                );
                defer received.deinit();
                switch (received.direction) {
                    .bidirectional => {
                        try std.testing.expect(!received_bidi);
                        try std.testing.expectEqualStrings(
                            "client-bidi",
                            received.payload,
                        );
                        try session.sendStreamSlices(
                            received.stream_id,
                            &.{ "server-", &.{}, "bidi" },
                            true,
                        );
                        received_bidi = true;
                    },
                    .unidirectional => {
                        try std.testing.expect(!received_uni);
                        try std.testing.expectEqualStrings(
                            "client-uni",
                            received.payload,
                        );
                        received_uni = true;
                    },
                }
            }

            const server_uni = try session.openUnidirectionalStream();
            try session.sendStream(server_uni, "server-uni", true);

            self.stage = .reset_stop;
            var reset_buffer: [32]u8 = undefined;
            while (true) {
                const event = try session.readStreamWithTimeout(
                    &reset_buffer,
                    .fromSeconds(3),
                );
                switch (event) {
                    .reset => |reset| {
                        try std.testing.expectEqual(
                            @as(?u32, 91),
                            reset.error_info.application_code,
                        );
                        break;
                    },
                    .data => {},
                    else => return error.UnexpectedStreamEvent,
                }
            }

            const stopped_uni = try session.openUnidirectionalStream();
            try session.sendStream(stopped_uni, "stop-this", false);
            while (true) {
                const event = try session.readStreamWithTimeout(
                    &reset_buffer,
                    .fromSeconds(3),
                );
                switch (event) {
                    .stopped => |stopped| {
                        try std.testing.expectEqual(stopped_uni, stopped.stream_id);
                        try std.testing.expectEqual(
                            @as(?u32, 92),
                            stopped.error_info.application_code,
                        );
                        break;
                    },
                    .data => {},
                    else => return error.UnexpectedStreamEvent,
                }
            }

            self.stage = .close;
            try session.drain();
            const close_event = try session.receiveSessionEventWithTimeout(
                .fromSeconds(3),
            );
            try std.testing.expect(close_event == .closed);
            try std.testing.expectEqual(
                @as(u32, 93),
                close_event.closed.code,
            );
            try std.testing.expectEqualStrings(
                "stateful done",
                close_event.closed.reason,
            );
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    try shared.initial_timeout_done.wait(io);

    const connect_options: StatefulProtectedConnectOptions = .{
        .authority = "localhost",
        .path = "/wt-stateful-protected",
        .limits = .{
            .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .send_interceptor = .{
                    .context = &drop_state,
                    .should_drop = DropFirstAssociatedDatagram.send,
                },
            } },
            .max_session_streams = 2,
        },
        .h3 = .{ .local_settings = local_settings },
        .transport = .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_transport_parameters = quic.practical_transport_parameters,
            .peer_transport_parameters = quic.practical_transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    };
    try std.testing.expectError(
        error.Timeout,
        StatefulProtectedClientSession.connectAttemptWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expectError(
        error.Timeout,
        StatefulProtectedClientSession.connectAttemptWithTimeout(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            connect_options,
            .zero,
        ),
    );
    client_stage = .connect;
    var client = try StatefulProtectedClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        connect_options,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer client.deinit();
    try std.testing.expect(client.datagramsNegotiated());
    try std.testing.expect(client.maxDatagramSize() != 0);
    try std.testing.expectEqual(
        client.address(),
        client.session.h3.address(),
    );
    client_stage = .datagrams;
    var invalid_datagram_count: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramsWithTimeout(
            &.{"not-sent"},
            &invalid_datagram_count,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), invalid_datagram_count);
    var datagrams_sent: usize = 99;
    try client.sendDatagramsWithDeadline(
        &.{ "stateful-one", "stateful-two", "stateful-three" },
        &datagrams_sent,
        .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 3), datagrams_sent);
    var datagrams = try client.receiveManyDatagramsWithTimeout(
        2,
        .fromSeconds(3),
    );
    defer datagrams.deinit();
    if (datagrams.firstError()) |err| return err;
    const expected_datagrams = [_][]const u8{
        "stateful-reply-one",
        "stateful-reply-two",
    };
    for (datagrams.datagrams, expected_datagrams) |maybe, expected| {
        const datagram = maybe orelse return error.MissingDatagram;
        try std.testing.expectEqualStrings(
            expected,
            datagram.datagram.payload,
        );
    }
    const before_invalid_open = client.stats().outgoing_streams_created;
    const before_invalid_registry = client.session.streams.registered().len;
    try std.testing.expectError(
        error.Timeout,
        client.openBidirectionalStreamWithDeadline(.{
            .clock = .real,
            .raw = .zero,
        }),
    );
    try std.testing.expectError(
        error.Timeout,
        client.openUnidirectionalStreamWithTimeout(.zero),
    );
    try std.testing.expectEqual(
        before_invalid_open,
        client.stats().outgoing_streams_created,
    );
    try std.testing.expectEqual(
        before_invalid_registry,
        client.session.streams.registered().len,
    );
    client_stage = .session_data;
    var unknown_storage: [64]u8 = undefined;
    const unknown = try http3.capsule.writeInto(
        &unknown_storage,
        0x2a,
        "stateful-session-data",
    );
    var drain_storage: [16]u8 = undefined;
    const drain = try session_control.writeDrainInto(&drain_storage);
    var session_data_progress: http3.runtime.BodyWriteProgress = .{};
    try client.sendSessionDataSlicesWithTimeout(
        &.{ unknown[0..1], unknown[1..], &.{}, drain },
        false,
        &session_data_progress,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        unknown.len + drain.len,
        session_data_progress.committed_bytes,
    );
    try std.testing.expect(!session_data_progress.fin_committed);

    // Practical transport parameters provide immediate credit. Exercise both
    // bounded directions and verify the QUIC reservation counter advances.
    client_stage = .streams;
    const bidi = try client.openBidirectionalStreamWithTimeout(
        .fromSeconds(1),
    );
    try std.testing.expectEqual(
        before_invalid_open + 1,
        client.stats().outgoing_streams_created,
    );
    // CONNECT and SETTINGS are complete, so the next client datagram carries
    // the first associated stream's modern prefix. Consume it before the UDP
    // socket and require the complete 1-RTT owner to recover it while later
    // STREAM offsets are already in flight.
    drop_associated_stream = true;
    try client.sendStreamSlices(
        bidi,
        &.{ "client-", &.{}, "bi", "di" },
        true,
    );
    const uni = try client.openUnidirectionalStreamWithDeadline(.fromNow(
        io,
        .{ .raw = .fromSeconds(1), .clock = .awake },
    ));
    try std.testing.expectEqual(
        before_invalid_open + 2,
        client.stats().outgoing_streams_created,
    );
    try client.sendStream(uni, "client-uni", true);

    var response_bidi = try client.receiveStreamWithTimeout(.fromSeconds(3));
    defer response_bidi.deinit();
    try std.testing.expectEqual(bidi, response_bidi.stream_id);
    try std.testing.expectEqualStrings("server-bidi", response_bidi.payload);
    var response_uni = try client.receiveStreamWithTimeout(.fromSeconds(3));
    defer response_uni.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.unidirectional,
        response_uni.direction,
    );
    try std.testing.expectEqualStrings("server-uni", response_uni.payload);
    try std.testing.expectEqual(
        @as(usize, 1),
        dropped_associated_datagrams,
    );
    try std.testing.expect(client.stats().packets_lost >= 1);

    client_stage = .reset_stop;
    const reset_bidi = try client.openBidirectionalStream();
    // Completed streams no longer consume the runtime's retained-record cap.
    // The newly opened live stream remains registered for cancellation events.
    try std.testing.expect(client.session.streams.get(bidi) == null);
    try std.testing.expect(client.session.streams.get(reset_bidi) != null);
    try std.testing.expectEqual(@as(usize, 1), client.session.streams.registered().len);
    try client.sendStream(reset_bidi, "before-reset", false);
    try client.resetStream(reset_bidi, 91);
    var stop_buffer: [32]u8 = undefined;
    var stop_sent = false;
    while (!stop_sent) {
        const event = try client.readStreamWithTimeout(
            &stop_buffer,
            .fromSeconds(3),
        );
        switch (event) {
            .data => |data| {
                if (data.direction == .unidirectional and
                    !data.locally_initiated)
                {
                    const stream = client.session.streams.get(
                        data.stream_id,
                    ) orelse return error.UnknownStream;
                    try std.testing.expect(stream.stop_sent == null);
                    try std.testing.expectError(
                        error.Timeout,
                        client.stopStreamWithTimeout(
                            data.stream_id,
                            92,
                            .zero,
                        ),
                    );
                    try std.testing.expect(stream.stop_sent == null);
                    try client.stopStreamWithDeadline(
                        data.stream_id,
                        92,
                        .fromNow(io, .{
                            .raw = .fromSeconds(3),
                            .clock = .awake,
                        }),
                    );
                    stop_sent = true;
                }
            },
            else => {},
        }
    }
    client_stage = .close;
    const drain_event = try client.receiveSessionEventWithTimeout(
        .fromSeconds(3),
    );
    try std.testing.expect(drain_event == .draining);
    try client.close(93, "stateful done");
    try std.testing.expectError(
        error.InvalidSessionState,
        client.openUnidirectionalStream(),
    );
    try std.testing.expectError(
        error.InvalidSessionState,
        client.sendDatagram("after-close"),
    );
    try std.testing.expect(client.session.h3.hasConnectDatagramAssociation(
        client.session.session_id.value,
    ));
    const peer_fin = try client.receiveSessionEventWithTimeout(
        .fromSeconds(3),
    );
    try std.testing.expect(peer_fin == .closed);
    try std.testing.expect(client.session.h3.hasConnectDatagramAssociation(
        client.session.session_id.value,
    ));
    try std.testing.expectError(
        error.ConnectDatagramAssociationClosed,
        client.receiveDatagram(),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake runtime CONNECT and datagrams over QUIC handshake" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xea, 0xce, 0x10, 0x01, 0xea, 0xce, 0x10, 0x02 };
    const client_cid = [_]u8{ 0xea, 0xce, 0x10, 0x03 };
    const server_cid = [_]u8{ 0xea, 0xce, 0x10, 0x04 };
    const large_stream_payload = try allocator.alloc(u8, 12 * 1024);
    defer allocator.free(large_stream_payload);
    for (large_stream_payload, 0..) |*byte, index| {
        byte.* = @truncate(index);
    }

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .application_protocols = .{ .values = &.{ "backup", "quoted\"value" }, .required = true },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        large_stream_payload: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const server_ptr = shared.server;
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            try std.testing.expect(accepted.session_id.isClientInitiatedBidirectional());
            try std.testing.expect(accepted.applicationProtocol().?.eql("quoted\"value"));
            const max_datagram_size = accepted.maxDatagramSize();
            try std.testing.expect(max_datagram_size != 0);
            const oversized = try server_ptr.h3.quic_server.endpoint.allocator
                .alloc(u8, max_datagram_size + 1);
            defer server_ptr.h3.quic_server.endpoint.allocator.free(oversized);
            try std.testing.expectError(
                error.DatagramTooLarge,
                accepted.sendDatagram(oversized),
            );

            var client_bidi = try accepted.receiveStream();
            defer client_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                client_bidi.direction,
            );
            try std.testing.expect(!client_bidi.locally_initiated);
            try std.testing.expectEqualStrings(
                "client-bidi",
                client_bidi.payload,
            );
            try accepted.sendStream(
                client_bidi.stream_id,
                "server-bidi",
                true,
            );

            var client_uni = try accepted.receiveStream();
            defer client_uni.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.unidirectional,
                client_uni.direction,
            );
            try std.testing.expectEqualStrings(
                "client-uni",
                client_uni.payload,
            );

            var large_bidi = try accepted.receiveStream();
            defer large_bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                large_bidi.direction,
            );
            try std.testing.expectEqualSlices(
                u8,
                shared.large_stream_payload,
                large_bidi.payload,
            );

            const server_uni_id =
                try accepted.openUnidirectionalStream();
            try accepted.sendStream(
                server_uni_id,
                "server-uni",
                true,
            );

            var short_datagram: [4]u8 = undefined;
            try std.testing.expectError(
                error.BufferTooShort,
                accepted.receiveDatagramInto(&short_datagram),
            );
            var first_datagram: [64]u8 = undefined;
            const first_payload = try accepted.receiveDatagramInto(
                &first_datagram,
            );
            try std.testing.expectEqualStrings(
                "handshake-client-one",
                first_payload,
            );
            var remaining_storage: [2][64]u8 = undefined;
            var remaining_outputs = [_][]u8{
                &remaining_storage[0],
                &remaining_storage[1],
            };
            var received_count: usize = 99;
            try accepted.receiveDatagramsInto(
                &remaining_outputs,
                &received_count,
            );
            try std.testing.expectEqual(@as(usize, 2), received_count);
            const client_payloads = [_][]const u8{
                "handshake-client-two",
                "handshake-client-three",
            };
            for (remaining_outputs, client_payloads) |actual, expected| {
                try std.testing.expectEqualStrings(expected, actual);
            }
            var committed: usize = 99;
            try accepted.sendDatagramsWithTimeout(
                &.{
                    "handshake-server-one",
                    "handshake-server-two",
                    "handshake-server-three",
                },
                &committed,
                .fromSeconds(1),
            );
            try std.testing.expectEqual(@as(usize, 3), committed);
            const stats = accepted.getStats();
            try std.testing.expectEqual(@as(u64, 3), stats.datagrams_received);
            try std.testing.expectEqual(@as(u64, 3), stats.datagrams_sent);
            try std.testing.expect(stats.packets_received > 0);
            try std.testing.expect(stats.packets_sent > 0);
        }
    };

    var shared = Shared{
        .server = &server,
        .large_stream_payload = large_stream_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-handshake",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } }, .application_protocols = .{ .values = &.{ "quoted\"value", "backup" }, .required = true } },
        .h3 = .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            },
        },
    });
    defer client.deinit();
    try std.testing.expect(client.applicationProtocol().?.eql("quoted\"value"));
    try std.testing.expectError(
        error.Timeout,
        client.serviceTransportWithTimeout(.zero),
    );
    const max_datagram_size = client.maxDatagramSize();
    try std.testing.expect(max_datagram_size != 0);
    const oversized = try allocator.alloc(u8, max_datagram_size + 1);
    defer allocator.free(oversized);
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagram(oversized),
    );
    const before_invalid_batch = client.stats();
    var oversized_batch_count: usize = 99;
    try std.testing.expectError(
        error.DatagramTooLarge,
        client.sendDatagramsWithDeadline(
            &.{ "valid", oversized },
            &oversized_batch_count,
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), oversized_batch_count);
    try std.testing.expectEqual(
        before_invalid_batch.packets_sent,
        client.stats().packets_sent,
    );
    try std.testing.expectEqual(
        before_invalid_batch.datagrams_sent,
        client.stats().datagrams_sent,
    );
    var invalid_datagram_batch_progress: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramsWithTimeout(
            &.{"not-sent"},
            &invalid_datagram_batch_progress,
            .zero,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        invalid_datagram_batch_progress,
    );

    const client_bidi_id = try client.openBidirectionalStream();
    try client.sendStream(client_bidi_id, "client-bidi", true);
    const client_uni_id = try client.openUnidirectionalStream();
    try client.sendStream(client_uni_id, "client-uni", true);
    const large_bidi_id = try client.openBidirectionalStream();
    try client.sendStream(large_bidi_id, large_stream_payload, true);

    var server_bidi = try client.receiveStream();
    defer server_bidi.deinit();
    try std.testing.expectEqual(client_bidi_id, server_bidi.stream_id);
    try std.testing.expect(server_bidi.locally_initiated);
    try std.testing.expectEqualStrings("server-bidi", server_bidi.payload);

    var server_uni = try client.receiveStream();
    defer server_uni.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.unidirectional,
        server_uni.direction,
    );
    try std.testing.expect(!server_uni.locally_initiated);
    try std.testing.expectEqualStrings("server-uni", server_uni.payload);

    var committed_datagrams: usize = 99;
    try client.sendDatagramsWithDeadline(
        &.{
            "handshake-client-one",
            "handshake-client-two",
            "handshake-client-three",
        },
        &committed_datagrams,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 3), committed_datagrams);
    var first_response_storage: [64]u8 = undefined;
    const first_response = try client.receiveDatagramIntoWithDeadline(
        &first_response_storage,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqualStrings(
        "handshake-server-one",
        first_response,
    );
    var remaining_response_storage: [2][64]u8 = undefined;
    var remaining_response_outputs = [_][]u8{
        &remaining_response_storage[0],
        &remaining_response_storage[1],
    };
    var received_response_count: usize = 99;
    try client.receiveDatagramsIntoWithTimeout(
        &remaining_response_outputs,
        &received_response_count,
        .fromSeconds(1),
    );
    try std.testing.expectEqual(@as(usize, 2), received_response_count);
    const server_payloads = [_][]const u8{
        "handshake-server-two",
        "handshake-server-three",
    };
    for (remaining_response_outputs, server_payloads) |actual, expected| {
        try std.testing.expectEqualStrings(expected, actual);
    }
    const stats = client.stats();
    try std.testing.expectEqual(@as(u64, 3), stats.datagrams_sent);
    try std.testing.expectEqual(@as(u64, 3), stats.datagrams_received);
    try std.testing.expect(stats.packets_sent > 0);
    try std.testing.expect(stats.packets_received > 0);

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport handshake session DATA slices resume exact suffix" {
    const allocator = std.testing.allocator;
    const DeadlineAfterSendIo = struct {
        delegate: std.Io,
        now_ns: i96,
        send_calls: usize = 0,

        fn now(
            userdata: ?*anyopaque,
            _: std.Io.Clock,
        ) std.Io.Timestamp {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            return .fromNanoseconds(self.now_ns);
        }

        fn netSend(
            userdata: ?*anyopaque,
            socket_handle: net.Socket.Handle,
            messages: []net.OutgoingMessage,
            flags: net.SendFlags,
        ) struct { ?net.Socket.SendError, usize } {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.send_calls += 1;
            const result = self.delegate.vtable.netSend(
                self.delegate.userdata,
                socket_handle,
                messages,
                flags,
            );
            if (result[1] != 0) self.now_ns += std.time.ns_per_s;
            return result;
        }
    };

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x73, 0x6c, 0x69, 0x63, 0x65, 0x73, 0x01, 0x02 };
    const client_cid = [_]u8{ 0x73, 0x6c, 0x69, 0x01 };
    const server_cid = [_]u8{ 0x73, 0x6c, 0x69, 0x02 };
    const session_options: http3.runtime.HandshakeSessionOptions = .{
        .max_frames_per_packet = 2,
        .max_stream_frame_data = 48,
        .paced_body_chunk_bytes = 16,
    };
    const stream_payload = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(stream_payload);
    for (stream_payload, 0..) |*byte, index| byte.* = @truncate(index);

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xa3} ** 32,
                .x25519_secret_key = [_]u8{0xa4} ** 32,
            },
            .session = session_options,
        },
    );
    defer server.deinit();

    var unknown_storage: [128]u8 = undefined;
    const unknown = try http3.capsule.writeInto(
        &unknown_storage,
        0x2a,
        "handshake-session-data-slices-cross-packet-boundary-0123456789",
    );
    var drain_storage: [16]u8 = undefined;
    const drain = try session_control.writeDrainInto(&drain_storage);
    const parts = [_][]const u8{
        unknown[0..1],
        &.{},
        unknown[1 .. unknown.len - 3],
        unknown[unknown.len - 3 ..],
        drain[0..1],
        drain[1..],
    };
    const total_len = unknown.len + drain.len;

    const Shared = struct {
        server: *HandshakeServer,
        io: std.Io,
        parts: []const []const u8,
        total_len: usize,
        stream_payload: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            var accepted = try shared.server.accept();
            defer accepted.deinit();

            const request_event = try accepted
                .receiveSessionEventWithTimeout(.fromSeconds(2));
            try std.testing.expect(request_event == .draining);

            var invalid_progress: http3.runtime.BodyWriteProgress = .{
                .committed_bytes = 99,
                .fin_committed = true,
            };
            try std.testing.expectError(
                error.Timeout,
                accepted.sendSessionDataSlicesWithDeadline(
                    shared.parts,
                    false,
                    &invalid_progress,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                invalid_progress.committed_bytes,
            );
            try std.testing.expect(!invalid_progress.fin_committed);

            var timed = DeadlineAfterSendIo{
                .delegate = accepted.h3.established.connection.endpoint.io,
                .now_ns = std.Io.Clock.awake.now(
                    accepted.h3.established.connection.endpoint.io,
                ).nanoseconds,
            };
            var timed_vtable = timed.delegate.vtable.*;
            timed_vtable.now = DeadlineAfterSendIo.now;
            timed_vtable.netSend = DeadlineAfterSendIo.netSend;
            accepted.h3.established.connection.endpoint.io = .{
                .userdata = &timed,
                .vtable = &timed_vtable,
            };
            var progress: http3.runtime.BodyWriteProgress = .{};
            try std.testing.expectError(
                error.Timeout,
                accepted.sendSessionDataSlicesWithDeadline(
                    shared.parts,
                    false,
                    &progress,
                    .{
                        .clock = .awake,
                        .raw = .fromNanoseconds(timed.now_ns + 1),
                    },
                ),
            );
            try std.testing.expect(progress.committed_bytes > 0);
            try std.testing.expect(
                progress.committed_bytes < shared.total_len,
            );
            try std.testing.expect(!progress.fin_committed);
            try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

            accepted.h3.established.connection.endpoint.io = timed.delegate;
            var suffix_storage: [parts.len][]const u8 = undefined;
            const suffix = testBodyPartsSuffix(
                shared.parts,
                progress.committed_bytes,
                &suffix_storage,
            );
            const remaining = shared.total_len - progress.committed_bytes;
            try accepted.sendSessionDataSlicesWithTimeout(
                suffix,
                false,
                &progress,
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                remaining,
                progress.committed_bytes,
            );
            try std.testing.expect(!progress.fin_committed);

            var received = try accepted.receiveStreamWithTimeout(
                .fromSeconds(3),
            );
            defer received.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                received.direction,
            );
            try std.testing.expectEqualStrings(
                "seed",
                received.payload[0..4],
            );
            try std.testing.expectEqualSlices(
                u8,
                shared.stream_payload,
                received.payload[4..],
            );
            var response_committed: usize = 99;
            try accepted.sendStreamSlicesWithTimeout(
                received.stream_id,
                &.{ "server-", &.{}, "reply" },
                true,
                &response_committed,
                .fromSeconds(2),
            );
            try std.testing.expectEqual(
                "server-reply".len,
                response_committed,
            );
        }
    };

    var shared = Shared{
        .server = &server,
        .io = io,
        .parts = &parts,
        .total_len = total_len,
        .stream_payload = stream_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-handshake-slices",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "localhost",
                    .random = [_]u8{0xa1} ** 32,
                    .x25519_secret_key = [_]u8{0xa2} ** 32,
                },
                .session = session_options,
            },
        },
    );
    defer client.deinit();
    const stream_id = try client.openBidirectionalStream();
    var invalid_stream_progress: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendStreamSlicesWithTimeout(
            stream_id,
            &.{"not-sent"},
            false,
            &invalid_stream_progress,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), invalid_stream_progress);
    try std.testing.expect(
        !client.streams.get(stream_id).?.prefix_sent,
    );
    try client.sendStream(stream_id, "seed", false);

    var timed = DeadlineAfterSendIo{
        .delegate = client.h3.established.connection.endpoint.io,
        .now_ns = std.Io.Clock.awake.now(
            client.h3.established.connection.endpoint.io,
        ).nanoseconds,
    };
    var timed_vtable = timed.delegate.vtable.*;
    timed_vtable.now = DeadlineAfterSendIo.now;
    timed_vtable.netSend = DeadlineAfterSendIo.netSend;
    client.h3.established.connection.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    var progress: http3.runtime.BodyWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendSessionDataSlicesWithDeadline(
            &parts,
            false,
            &progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expect(progress.committed_bytes > 0);
    try std.testing.expect(progress.committed_bytes < total_len);
    try std.testing.expect(!progress.fin_committed);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

    client.h3.established.connection.endpoint.io = timed.delegate;
    var suffix_storage: [parts.len][]const u8 = undefined;
    const suffix = testBodyPartsSuffix(
        &parts,
        progress.committed_bytes,
        &suffix_storage,
    );
    const remaining = total_len - progress.committed_bytes;
    try client.sendSessionDataSlicesWithTimeout(
        suffix,
        false,
        &progress,
        .fromSeconds(2),
    );
    try std.testing.expectEqual(remaining, progress.committed_bytes);
    try std.testing.expect(!progress.fin_committed);

    const stream_parts = [_][]const u8{
        stream_payload[0..1],
        &.{},
        stream_payload[1..8193],
        stream_payload[8193..24577],
        stream_payload[24577..],
    };
    timed.now_ns = std.Io.Clock.awake.now(timed.delegate).nanoseconds;
    timed.send_calls = 0;
    client.h3.established.connection.endpoint.io = .{
        .userdata = &timed,
        .vtable = &timed_vtable,
    };
    var stream_progress: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        client.sendStreamSlicesWithDeadline(
            stream_id,
            &stream_parts,
            true,
            &stream_progress,
            .{
                .clock = .awake,
                .raw = .fromNanoseconds(timed.now_ns + 1),
            },
        ),
    );
    try std.testing.expect(stream_progress > 0);
    try std.testing.expect(stream_progress < stream_payload.len);
    try std.testing.expectEqual(@as(usize, 1), timed.send_calls);

    client.h3.established.connection.endpoint.io = timed.delegate;
    var stream_suffix_storage: [stream_parts.len][]const u8 = undefined;
    const stream_suffix = testBodyPartsSuffix(
        &stream_parts,
        stream_progress,
        &stream_suffix_storage,
    );
    const stream_remaining = stream_payload.len - stream_progress;
    try client.sendStreamSlicesWithTimeout(
        stream_id,
        stream_suffix,
        true,
        &stream_progress,
        .fromSeconds(3),
    );
    try std.testing.expectEqual(stream_remaining, stream_progress);

    const response_event = try client
        .receiveSessionEventWithTimeout(.fromSeconds(2));
    try std.testing.expect(response_event == .draining);
    var response_stream = try client.receiveStreamWithTimeout(
        .fromSeconds(3),
    );
    defer response_stream.deinit();
    try std.testing.expectEqual(stream_id, response_stream.stream_id);
    try std.testing.expectEqualStrings(
        "server-reply",
        response_stream.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport bounded DATAGRAM send waits for congestion ACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid =
        [_]u8{ 0x62, 0x64, 0x67, 0x01, 0x62, 0x64, 0x67, 0x02 };
    const client_cid = [_]u8{ 0x62, 0x64, 0x67, 0x03 };
    const server_cid = [_]u8{ 0x62, 0x64, 0x67, 0x04 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .http3 = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x63} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        release_receive: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var accepted = try self.server.accept();
            defer accepted.deinit();
            const before = accepted.stats();
            try std.testing.expectError(
                error.Timeout,
                accepted.sendDatagramWithTimeout("not-sent", .zero),
            );
            try std.testing.expectEqual(
                before.datagrams_sent,
                accepted.stats().datagrams_sent,
            );
            try self.release_receive.wait(self.server.h3.quic_server.endpoint.io);
            var first = try accepted.receiveDatagram();
            defer first.deinit(
                accepted.h3.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "fill-window",
                first.datagram.payload,
            );
            var second = try accepted.receiveDatagram();
            defer second.deinit(
                accepted.h3.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "after-ack",
                second.datagram.payload,
            );
            try accepted.sendDatagramWithTimeout(
                "server-bounded",
                .fromSeconds(5),
            );
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/wt-bounded-datagram",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            } } },
            .h3 = .{ .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x65} ** 32,
                .x25519_secret_key = [_]u8{0x66} ** 32,
            } },
        },
    );
    defer client.deinit();

    try client.sendDatagram("fill-window");
    quic.one_rtt.testing.clampCongestionWindowToBytesInFlight(
        &client.h3.established.connection,
    );
    const before = client.stats();
    try std.testing.expectError(
        error.Timeout,
        client.sendDatagramWithTimeout("not-sent", .zero),
    );
    try std.testing.expectEqual(
        before.datagrams_sent,
        client.stats().datagrams_sent,
    );

    shared.release_receive.set(io);
    try client.sendDatagramWithTimeout(
        "after-ack",
        .fromSeconds(5),
    );
    try std.testing.expectEqual(
        before.datagrams_sent + 1,
        client.stats().datagrams_sent,
    );
    var response = try client.receiveDatagramWithTimeout(.fromSeconds(5));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings(
        "server-bounded",
        response.datagram.payload,
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "WebTransport handshake session receives datagrams with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xba, 0xce, 0x20, 0x01, 0xba, 0xce, 0x20, 0x02 };
    const client_cid = [_]u8{ 0xba, 0xce, 0x20, 0x03 };
    const server_cid = [_]u8{ 0xba, 0xce, 0x20, 0x04 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x93} ** 32,
            .x25519_secret_key = [_]u8{0x94} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var accepted = try server_ptr.accept();
            defer accepted.deinit();
            var batch = try accepted.receiveManyDatagrams(2);
            defer batch.deinit();
            if (batch.firstError()) |err| return err;
            try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

            var saw_one = false;
            var saw_two = false;
            for (batch.datagrams) |maybe_datagram| {
                const datagram = maybe_datagram.?;
                try std.testing.expectEqual(accepted.session_id.value, datagram.datagram.session_id.value);
                if (std.mem.eql(u8, datagram.datagram.payload, "batch-one")) saw_one = true;
                if (std.mem.eql(u8, datagram.datagram.payload, "batch-two")) saw_two = true;
            }
            try std.testing.expect(saw_one);
            try std.testing.expect(saw_two);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClientSession.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .authority = "localhost",
        .path = "/wt-handshake-batch",
        .limits = .{ .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } } },
        .h3 = .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
            },
        },
    });
    defer client.deinit();

    try client.sendDatagram("batch-one");
    try client.sendDatagram("batch-two");

    thread.join();
    if (shared.err) |err| return err;
}

test "WebTransport owning and caller-buffer DATAGRAM batches retain partial progress" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xeb} ** quic.protection.secret_len,
    );
    const client_cid = "wt-batch-client";
    const server_cid = "wt-batch-server";
    var transport_parameters = quic.practical_transport_parameters;
    transport_parameters.max_datagram_frame_size = 1200;
    const settings = webtransport.defaultSettings(.{});

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();

    var h3 = try http3.runtime.HandshakeServerSession.initPreconfigured(
        &server_endpoint,
        peer_endpoint.address(),
        .{ .local_settings = settings },
        .{
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = server_cid,
            .peer_connection_id = client_cid,
            .local_transport_parameters = transport_parameters,
            .peer_transport_parameters = transport_parameters,
            .one_rtt = .{ .enable_pacing = false },
        },
    );
    var h3_owned = true;
    defer if (h3_owned) h3.deinit();
    h3.control.settings.markSent(settings);
    h3.control.settings.markReceived(settings);
    try h3.connect_datagrams.register(0);
    var streams = try handshake_stream.initRegistry(
        allocator,
        .init(0),
        .server,
        settings,
        settings,
        8,
        null,
        null,
    );
    var streams_owned = true;
    defer if (streams_owned) streams.deinit();
    var session = AcceptedHandshakeSession{
        .h3 = h3,
        .request = undefined,
        .session_id = .init(0),
        .streams = streams,
        .control = try session_control.Control.init(
            std.testing.allocator,
            .init(0),
        ),
    };
    h3_owned = false;
    streams_owned = false;
    defer {
        session.control.deinit();
        session.streams.deinit();
        session.h3.deinit();
    }
    var peer = try quic.one_rtt.Connection.init(&peer_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = client_cid,
        .peer_connection_id = server_cid,
        .local_max_datagram_frame_size = 1200,
        .peer_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer peer.deinit();

    var empty_outputs: [0][]u8 = .{};
    var empty_count: usize = 99;
    try session.receiveDatagramsInto(&empty_outputs, &empty_count);
    try std.testing.expectEqual(@as(usize, 0), empty_count);
    var timeout_storage: [1][8]u8 = undefined;
    var timeout_outputs = [_][]u8{&timeout_storage[0]};
    var timeout_count: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        session.receiveDatagramsIntoWithTimeout(
            &timeout_outputs,
            &timeout_count,
            .zero,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), timeout_count);

    try sendHandshakeDatagramForTest(&peer, .init(0), "caller-first");
    var caller_storage: [2][32]u8 = undefined;
    var caller_outputs = [_][]u8{
        &caller_storage[0],
        &caller_storage[1],
    };
    var caller_count: usize = 99;
    try std.testing.expectError(
        error.Timeout,
        session.receiveDatagramsIntoWithTimeout(
            &caller_outputs,
            &caller_count,
            .fromMilliseconds(20),
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), caller_count);
    try std.testing.expectEqualStrings("caller-first", caller_outputs[0]);

    try sendHandshakeDatagramForTest(&peer, .init(0), "caller-second");
    var caller_resumed_storage: [32]u8 = undefined;
    var caller_resumed_outputs = [_][]u8{&caller_resumed_storage};
    caller_count = 99;
    try session.receiveDatagramsIntoWithDeadline(
        &caller_resumed_outputs,
        &caller_count,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    try std.testing.expectEqual(@as(usize, 1), caller_count);
    try std.testing.expectEqualStrings(
        "caller-second",
        caller_resumed_outputs[0],
    );

    try sendHandshakeDatagramForTest(&peer, .init(0), "owned-first");
    var batch = try session.receiveManyDatagramsWithTimeout(
        2,
        .fromMilliseconds(20),
    );
    defer batch.deinit();
    try std.testing.expectEqual(@as(usize, 1), batch.receivedCount());
    try std.testing.expectEqual(error.Timeout, batch.firstError().?);
    try std.testing.expectEqualStrings(
        "owned-first",
        batch.datagrams[0].?.datagram.payload,
    );
    try std.testing.expect(batch.datagrams[1] == null);

    try sendHandshakeDatagramForTest(&peer, .init(0), "owned-second");
    var resumed = try session.receiveManyDatagramsWithDeadline(
        1,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    defer resumed.deinit();
    try std.testing.expectEqual(@as(usize, 1), resumed.receivedCount());
    try std.testing.expect(resumed.firstError() == null);
    try std.testing.expectEqualStrings(
        "owned-second",
        resumed.datagrams[0].?.datagram.payload,
    );
}

test {
    _ = @import("datagram/tests/codec.zig");
    _ = @import("datagram/tests/send.zig");
    _ = @import("stream_tests.zig");
    _ = @import("stream_incremental.zig");
    _ = @import("stream/tests/batch.zig");
    _ = @import("stream/pagination_tests.zig");
    _ = @import("development_control_tests.zig");
    _ = stream_batch;
    _ = @import("session_control_tests.zig");
    _ = @import("session_control/endpoint_rejection_tests.zig");
    _ = @import("session_control/handshake_rejection_tests.zig");
    _ = @import("session_control/connection_lifecycle_tests.zig");
    _ = @import("session_control/connect_termination_tests.zig");
    _ = @import("session_control/connect_sibling_tests.zig");
    _ = @import("session_control/lightweight_termination_tests.zig");
    _ = @import("session_control/receive_termination_tests.zig");
    _ = @import("session_control/receive_sibling_tests.zig");
    _ = @import("session_control/send_buffered_close_tests.zig");
    _ = @import("session_control/close_metadata_tests.zig");
    _ = @import("session_control/flow_tests.zig");
    _ = @import("flow/receive.zig");
    _ = @import("flow/write.zig");
    _ = @import("flow/send.zig");
    _ = @import("flow/streams.zig");
    _ = @import("flow/grant.zig");
    _ = @import("flow/datagram.zig");
    _ = @import("stream/reset.zig");
    _ = @import("connection_close_tests.zig");
}

test {
    _ = @import("connect/negotiation.zig");
    _ = @import("connect/pending_request.zig");
    _ = @import("goaway_tests.zig");
}

test {
    _ = @import("connect/application_protocol.zig");
}

test {
    _ = @import("association/tests/pending.zig");
}

test {
    _ = @import("association/tests/discovery.zig");
    _ = @import("association/tests/abandoned.zig");
    _ = @import("association/tests/invalid_session_id.zig");
}

test {
    _ = @import("association/tests/early_datagram.zig");
}

test {
    _ = @import("association/tests/early_streams.zig");
    _ = @import("association/tests/admission.zig");
}

test {
    _ = @import("endpoint_server/removal_tests.zig");
}

test {
    _ = @import("endpoint_client/removal_tests.zig");
    _ = @import("endpoint_client/removal_deadline_tests.zig");
    _ = @import("endpoint_client/receive_credit_tests.zig");
    _ = @import("endpoint_client/terminal_tests.zig");
    _ = @import("endpoint_client/connection_close_tests.zig");
    _ = @import("endpoint_client/flow_tests.zig");
    _ = @import("endpoint_client/open_timeout_tests.zig");
    _ = @import("endpoint_client/open_head_tests.zig");
    _ = @import("endpoint_client/open_rejection_tests.zig");
}

test {
    _ = @import("endpoint_server/close_tests.zig");
    _ = @import("endpoint_server/stream_control_tests.zig");
    _ = @import("endpoint_server/application_tests.zig");
    _ = @import("flow/open_control_tests.zig");
    _ = @import("endpoint_server/stream_control_terminal_tests.zig");
    _ = @import("flow/progress/wait_tests.zig");
    _ = @import("flow/progress/delivery_tests.zig");
    _ = @import("flow/progress/stream_wait_tests.zig");
    _ = @import("stream/wait/tests.zig");
    _ = @import("stream/wait/lifecycle_tests.zig");
    _ = @import("stream/wait/timer_tests.zig");
    _ = @import("stream/wait/shared_tests.zig");
    _ = @import("stream/wait/deadline_tests.zig");
    _ = @import("stream/reset/wait_tests.zig");
    _ = @import("stream/reset/shared_wait_tests.zig");
    _ = @import("stream/reset/timer_tests.zig");
    _ = @import("stream/reset/backpressure_tests.zig");
}

test "WebTransport protected datagram timeout rejects non-positive budgets before receive" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        std.testing.allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x42} ** quic.protection.secret_len,
    );
    var packet_number: u64 = 0;
    try std.testing.expectError(
        error.Timeout,
        runtime.receiveProtectedDatagramFromEndpointWithTimeout(
            &endpoint,
            keys,
            8,
            &packet_number,
            8,
            .fromNanoseconds(0),
        ),
    );
    try std.testing.expectEqual(@as(u64, 0), packet_number);
}

//! HTTP/2 ORIGIN and ALTSVC state tests moved out of the runtime test root.

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

test "HTTP/2 runtime accumulates server ORIGIN entries" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            connection.sendOrigins(&.{
                "https://example.com",
                "https://cdn.example.com",
            }) catch |err| {
                shared.err = err;
                return;
            };
            // Duplicate entries are legal; clients maintain set semantics.
            connection.sendOrigins(&.{
                "https://cdn.example.com",
                "https://img.example.com",
            }) catch |err| {
                shared.err = err;
                return;
            };
            const ping = connection.readPing() catch |err| {
                shared.err = err;
                return;
            };
            _ = ping;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_peer_origins = 2 },
    );
    defer client.close();
    // Any connection-level read pumps ORIGIN through shared state. Two reads
    // consume the two frames without requiring a synthetic request stream.
    var first = try readFrame(allocator, io, client.stream, client.limits);
    defer first.deinit(allocator);
    try std.testing.expect(try client.handleConnectionFrame(first.frame));
    var second = try readFrame(allocator, io, client.stream, client.limits);
    defer second.deinit(allocator);
    try std.testing.expect(try client.handleConnectionFrame(second.frame));
    try std.testing.expectEqual(@as(usize, 2), client.peerOrigins().len);
    try std.testing.expectEqualStrings(
        "https://cdn.example.com",
        client.peerOrigins()[1],
    );
    try std.testing.expect(client.peerOriginKnown("https://cdn.example.com"));
    try std.testing.expect(!client.peerOriginKnown("https://img.example.com"));
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.peer_origins.?.getIndex("https://cdn.example.com"),
    );
    try std.testing.expect(
        client.peer_origins.?.getIndex("https://img.example.com") == null,
    );
    try std.testing.expect(
        client.peer_origins.?.getIndex("https://missing.example.com") == null,
    );
    _ = try client.ping([_]u8{0x41} ** 8);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 duplicate ORIGIN entry does not allocate" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storePeerOrigin("https://example.com");
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storePeerOrigin("https://example.com");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), connection.peerOrigins().len);
}

test "HTTP/2 ORIGIN state enforces connection bound" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_peer_origins = 2 },
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storePeerOrigin("https://one.example");
    try connection.storePeerOrigin("https://two.example");
    const capacity = connection.peer_origins.?.capacity();
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storePeerOrigin("https://one.example");
    try connection.storePeerOrigin("https://three.example");
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 2), connection.peerOrigins().len);
    try std.testing.expectEqual(capacity, connection.peer_origins.?.capacity());
    try std.testing.expect(!connection.peerOriginKnown(
        "https://three.example",
    ));
}

test "HTTP/2 runtime ignores invalid ORIGIN envelope and client origin" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitPeerMetadata();
    }
    const payload = [_]u8{ 0, 1, 'x' };
    // Non-zero stream and incompatible flags are ignored per RFC 8336.
    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = payload.len,
            .frame_type = .origin,
            .flags = 0,
            .stream_id = 1,
        },
        .payload = &payload,
    }));
    try std.testing.expect(try connection.handleConnectionFrame(.{
        .header = .{
            .length = payload.len,
            .frame_type = .origin,
            .flags = 1,
            .stream_id = 0,
        },
        .payload = &payload,
    }));
    try std.testing.expectEqual(@as(usize, 0), connection.peerOrigins().len);

    var server_connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
    };
    defer {
        server_connection.deinitPeerMetadata();
    }
    try std.testing.expect(try server_connection.handleConnectionFrame(.{
        .header = .{
            .length = payload.len,
            .frame_type = .origin,
            .flags = 0,
            .stream_id = 0,
        },
        .payload = &payload,
    }));
    try std.testing.expectEqual(
        @as(usize, 0),
        server_connection.peerOrigins().len,
    );
}

test "HTTP/2 runtime receives connection and stream ALTSVC frames" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var connection = shared.server.accept() catch |err| {
                shared.err = err;
                return;
            };
            defer connection.close();
            connection.sendAlternativeService(
                0,
                "https://example.com",
                "h3=\":443\"; ma=3600",
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.sendAlternativeService(
                0,
                "https://example.com",
                "h3=\":8443\"; ma=60",
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.sendAlternativeService(
                1,
                "",
                "h2=\"alt.example.com:443\"",
            ) catch |err| {
                shared.err = err;
                return;
            };
            connection.sendAlternativeService(
                3,
                "",
                "h2=\"ignored.example.com:443\"",
            ) catch |err| {
                shared.err = err;
                return;
            };
            _ = connection.readPing() catch |err| {
                shared.err = err;
                return;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(
        allocator,
        io,
        server.address(),
        .{
            .max_frame_payload = 4096,
            .max_alternative_services = 2,
        },
    );
    defer client.close();
    inline for (0..4) |_| {
        var frame = try readFrame(
            allocator,
            io,
            client.stream,
            client.limits,
        );
        defer frame.deinit(allocator);
        try std.testing.expect(try client.handleConnectionFrame(frame.frame));
    }
    try std.testing.expectEqual(
        @as(usize, 2),
        client.alternativeServices().len,
    );
    try std.testing.expectEqualStrings(
        "https://example.com",
        client.alternativeServices()[0].origin,
    );
    try std.testing.expectEqualStrings(
        "h3=\":8443\"; ma=60",
        client.alternativeServices()[0].field_value,
    );
    try std.testing.expectEqual(
        @as(u31, 1),
        client.alternativeServices()[1].stream_id,
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        client.alternative_services.?.getIndex(
            0,
            "https://example.com",
        ),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.alternative_services.?.getIndex(1, ""),
    );
    try std.testing.expect(
        client.alternative_services.?.getIndex(
            0,
            "https://missing.example.com",
        ) == null,
    );
    try std.testing.expect(
        client.alternative_services.?.getIndex(3, "") == null,
    );
    _ = try client.ping([_]u8{0x42} ** 8);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 ALTSVC identical replacement does not allocate" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storeAlternativeService(
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storeAlternativeService(
        0,
        "https://example.com",
        "h3=\":443\"; ma=3600",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.alternativeServices().len,
    );
}

test "HTTP/2 ALTSVC state enforces connection bound" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
        .limits = .{ .max_alternative_services = 2 },
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storeAlternativeService(
        0,
        "https://one.example",
        "h3=\":443\"; ma=60",
    );
    try connection.storeAlternativeService(
        1,
        "",
        "h2=\"two.example:443\"",
    );
    try connection.storeAlternativeService(
        0,
        "https://one.example",
        "h3=\":8443\"; ma=30",
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.alternativeServices().len,
    );
    try std.testing.expectEqualStrings(
        "h3=\":8443\"; ma=30",
        connection.alternativeServices()[0].field_value,
    );

    const capacity = connection.alternative_services.?.capacity();
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const saved_allocator = connection.allocator;
    connection.allocator = no_alloc.allocator();
    defer connection.allocator = saved_allocator;
    try connection.storeAlternativeService(
        3,
        "",
        "h3=\"three.example:443\"",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 2),
        connection.alternativeServices().len,
    );
    try std.testing.expectEqual(
        capacity,
        connection.alternative_services.?.capacity(),
    );
}

test "HTTP/2 zero advertisement bounds retain no peer metadata" {
    const allocator = std.testing.allocator;
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    var connection = Connection{
        .io = undefined,
        .allocator = no_alloc.allocator(),
        .stream = undefined,
        .role = .client,
        .limits = .{
            .max_peer_origins = 0,
            .max_alternative_services = 0,
        },
    };
    defer {
        connection.deinitPeerMetadata();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    try connection.storePeerOrigin("https://ignored.example");
    try connection.storeAlternativeService(
        0,
        "https://ignored.example",
        "h3=\":443\"",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), connection.peerOrigins().len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.alternativeServices().len,
    );
}

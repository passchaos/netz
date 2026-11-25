//! HTTP/2 runtime state, TLS-option, and lazy-allocation tests.

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

test "HTTP/2 TLS options preserve stapled OCSP policy" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .stapled_ocsp = .require,
        .request_ocsp = true,
    });
    try std.testing.expectEqual(StapledOcspPolicy.require, mapped.stapled_ocsp);
    try std.testing.expect(mapped.request_ocsp);
    try std.testing.expectEqualStrings("h2", mapped.alpn_protocols[0]);
}

test "HTTP/2 TLS options forward native certificate environment" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .environ = std.testing.environ,
    });
    try std.testing.expect(mapped.system_environ != null);
}

test "HTTP/2 TLS options forward reusable native trust store" {
    var store = vail.x509.trust.SystemStore.initEmpty(std.testing.allocator);
    defer store.deinit();
    const mapped = verifiedTlsClientOptions("example.com", .{
        .system_store = &store,
    });
    try std.testing.expect(mapped.system_store != null);
}

test "HTTP/2 TLS options forward bundled root selection" {
    const mapped = verifiedTlsClientOptions("example.com", .{
        .root_source = .bundled,
    });
    try std.testing.expectEqual(tls_stream.RootSource.bundled, mapped.root_source);
}

test "HTTP/2 connection keeps optional state compact" {
    if (@sizeOf(usize) == 8) {
        // Keep the original mutable owner budget independent of source,
        // interface and resolver policy stored in Limits.
        const connection_owner_size: usize = switch (builtin.mode) {
            .Debug, .ReleaseSafe => 1_696,
            .ReleaseFast, .ReleaseSmall => 1_616,
        };
        try std.testing.expectEqual(connection_owner_size, @sizeOf(Connection) - @sizeOf(Limits));
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(OwnedFrameSlot));
        try std.testing.expectEqual(@as(usize, 56), @sizeOf(RetainedFrameSlot));
        try std.testing.expectEqual(
            @as(usize, 40),
            @sizeOf(DuplexHeaderBlockSlot),
        );
        try std.testing.expectEqual(
            @as(usize, 128),
            @sizeOf(ClientDuplexStream),
        );
        try std.testing.expectEqual(
            // Includes the pull-body `current_body` DATA owner and retained
            // request trailers used by `nextBody`; both are per active stream.
            @as(usize, 304),
            @sizeOf(ServerDuplexStream),
        );
        try std.testing.expectEqual(
            @sizeOf(?*peer_metadata.Origins),
            @sizeOf(@FieldType(Connection, "peer_origins")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*peer_metadata.AlternativeServices),
            @sizeOf(@FieldType(Connection, "alternative_services")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*http2.Hpack.Decoder),
            @sizeOf(@FieldType(Connection, "graceful_preadmit_decoder")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*http2.Hpack.Encoder),
            @sizeOf(@FieldType(Connection, "hpack_encoder_staging")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Connection, "push_state")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Connection, "priority_state")),
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Connection, "webtransport_settings")),
        );
    }

    const connection = Connection{
        .io = undefined,
        .allocator = std.testing.allocator,
        .stream = undefined,
        .role = .client,
    };
    try std.testing.expect(connection.peer_origins == null);
    try std.testing.expect(connection.alternative_services == null);
    try std.testing.expect(connection.graceful_preadmit_decoder == null);
    try std.testing.expect(connection.hpack_encoder_staging == null);
    try std.testing.expect(connection.push_state.state == null);
    try std.testing.expect(connection.priority_state.state == null);
    try std.testing.expect(!connection.borrowed_pending_frame.hasValue());
    try std.testing.expect(!connection.pending_application_overflow.hasValue());
    try std.testing.expect(!connection.duplex_pending_frame.hasValue());
    try std.testing.expect(!connection.pending_duplex_request_head.hasValue());
    try std.testing.expect(!connection.pending_duplex_sibling_header.hasValue());
    try std.testing.expectEqual(@as(usize, 0), connection.peerOrigins().len);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.alternativeServices().len,
    );
}

test "HTTP/2 compact owned frame slot transfers ownership" {
    const allocator = std.testing.allocator;
    var slot = OwnedFrameSlot{};
    slot.deinit(allocator);
    try std.testing.expect(!slot.hasValue());

    const bytes = try allocator.alloc(u8, http2.FrameHeader.encoded_len);
    slot.put(.{ .bytes = bytes, .frame = undefined });
    try std.testing.expect(slot.hasValue());
    var owned = slot.take() orelse return error.TestUnexpectedResult;
    try std.testing.expect(!slot.hasValue());
    owned.deinit(allocator);

    const second = try allocator.alloc(u8, http2.FrameHeader.encoded_len);
    slot.put(.{ .bytes = second, .frame = undefined });
    slot.deinit(allocator);
    try std.testing.expect(!slot.hasValue());
}

test "HTTP/2 compact duplex header slot uses stream zero as empty" {
    var slot = DuplexHeaderBlockSlot{};
    try std.testing.expect(!slot.hasValue());
    slot.put(.{
        .stream_id = 1,
        .end_stream = true,
        .end_headers = true,
    });
    try std.testing.expect(slot.hasValue());
    try std.testing.expectEqual(@as(u31, 1), slot.getPtr().?.stream_id);
    slot.deinit(std.testing.allocator);
    try std.testing.expect(!slot.hasValue());
}

test "HTTP/2 lazy staged HPACK encoder rolls back allocation failure" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .client,
    };
    defer {
        connection.deinitStagedHpackEncoder();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    _ = try connection.hpack_encoder.encodeBlockRetained(allocator, &.{.{
        .name = "x-live",
        .value = "one",
    }});
    const live_entries =
        connection.hpack_encoder.dynamic_table.entries.items.len;

    {
        var failing = std.testing.FailingAllocator.init(allocator, .{
            // The staging object allocation succeeds; copying its non-empty
            // dynamic table then fails and must destroy the detached object.
            .fail_index = 1,
        });
        connection.allocator = failing.allocator();
        defer connection.allocator = allocator;
        try std.testing.expectError(
            error.OutOfMemory,
            connection.prepareStagedHpackEncoder(),
        );
    }

    try std.testing.expect(connection.hpack_encoder_staging == null);
    try std.testing.expectEqual(
        live_entries,
        connection.hpack_encoder.dynamic_table.entries.items.len,
    );
    const staging = try connection.prepareStagedHpackEncoder();
    try std.testing.expectEqual(
        live_entries,
        staging.dynamic_table.entries.items.len,
    );
}

test "HTTP/2 lazy graceful HPACK clone rolls back allocation failure" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .io = undefined,
        .allocator = allocator,
        .stream = undefined,
        .role = .server,
        .graceful_shutdown_phase = .synchronizing,
    };
    defer {
        connection.clearGracefulPreadmitDecoder();
        connection.hpack_decoder.deinit(allocator);
        connection.hpack_encoder.deinit(allocator);
    }

    const inserted = try connection.hpack_decoder.decodeBlockOwnedWithLimit(
        allocator,
        "\x40\x01x\x01y",
        1,
        64,
    );
    freeHeaders(allocator, inserted);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        // The shadow object allocation succeeds; cloning its non-empty
        // dynamic table then fails and must destroy the detached object.
        .fail_index = 1,
    });
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.preadmitGracefulPeerRequest(.{
            .header = .{
                .length = 0,
                .frame_type = .headers,
                .flags = flag_end_headers | flag_end_stream,
                .stream_id = 1,
            },
            .payload = &.{},
        }),
    );
    connection.allocator = allocator;
    try std.testing.expect(connection.graceful_preadmit_decoder == null);
    try std.testing.expect(
        connection.graceful_preadmit_base_processed_stream_id == null,
    );
}

test "HTTP/2 lazy peer metadata creation is transactional" {
    const allocator = std.testing.allocator;

    var origin_failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    var origin_connection = Connection{
        .io = undefined,
        .allocator = origin_failing.allocator(),
        .stream = undefined,
        .role = .client,
    };
    defer {
        origin_connection.deinitPeerMetadata();
        origin_connection.hpack_decoder.deinit(allocator);
        origin_connection.hpack_encoder.deinit(allocator);
    }
    try std.testing.expectError(
        error.OutOfMemory,
        origin_connection.storePeerOrigin("https://example.com"),
    );
    try std.testing.expect(origin_connection.peer_origins == null);
    origin_connection.allocator = allocator;
    try origin_connection.storePeerOrigin("https://example.com");

    var alternative_failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 1,
    });
    var alternative_connection = Connection{
        .io = undefined,
        .allocator = alternative_failing.allocator(),
        .stream = undefined,
        .role = .client,
    };
    defer {
        alternative_connection.deinitPeerMetadata();
        alternative_connection.hpack_decoder.deinit(allocator);
        alternative_connection.hpack_encoder.deinit(allocator);
    }
    try std.testing.expectError(
        error.OutOfMemory,
        alternative_connection.storeAlternativeService(
            0,
            "https://example.com",
            "h3=\":443\"",
        ),
    );
    try std.testing.expect(alternative_connection.alternative_services == null);
    alternative_connection.allocator = allocator;
    try alternative_connection.storeAlternativeService(
        0,
        "https://example.com",
        "h3=\":443\"",
    );
}

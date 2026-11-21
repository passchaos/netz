//! HTTP/2 runtime tests moved out of the runtime root.

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

test {
    _ = @import("batch_deadline_tests.zig");
    _ = @import("client_and_upgrade_tests.zig");
    _ = @import("client_reset_and_refusal_tests.zig");
    _ = @import("client_response_tests.zig");
    _ = @import("concurrent_and_malformed_tests.zig");
    _ = @import("concurrent_tests.zig");
    _ = @import("connect_tunnel_tests.zig");
    _ = @import("content_length_and_date_tests.zig");
    _ = @import("control_readers_tests.zig");
    _ = @import("extended_connect_tests.zig");
    _ = @import("flow_control_tests.zig");
    _ = @import("goaway_and_stream_state_tests.zig");
    _ = @import("graceful_shutdown_tests.zig");
    _ = @import("h2c_runtime_tests.zig");
    _ = @import("headers_priority_tests.zig");
    _ = @import("origin_altsvc_tests.zig");
    _ = @import("partial_write_tests.zig");
    _ = @import("pending_request_tests.zig");
    _ = @import("request_body_batch_tests.zig");
    _ = @import("protocol_error_tests.zig");
    _ = @import("reset_history_and_budget_tests.zig");
    _ = @import("settings_and_capacity_tests.zig");
    _ = @import("writer_deadline_tests.zig");
    _ = @import("runtime_state_tests.zig");
    _ = @import("serve_batch_tests.zig");
    _ = @import("stream_and_header_tests.zig");
    _ = @import("settings/webtransport_tests.zig");
    _ = @import("stream_reset_tests.zig");
    _ = @import("streaming_request_and_rollback_tests.zig");
    _ = @import("window_and_settings_tests.zig");
    _ = @import("client/authority_tests.zig");
    _ = @import("client/authority_deadline_tests.zig");
    _ = @import("client/authority_uri_tests.zig");
    _ = @import("headers/authority_reuse_tests.zig");
    _ = client_authority;
    _ = endpoint_host;
    _ = host_connect;
    _ = @import("connect/deadline_tests.zig");
    _ = @import("connect/output_deadline_tests.zig");
    _ = @import("connect/owned_accept.zig");
    _ = @import("connect/protocol_error_tests.zig");
    _ = @import("connect/tls_protocol_error_tests.zig");
    _ = @import("control/extension_deadline_tests.zig");
    _ = @import("control/output_deadline_tests.zig");
    _ = @import("control/protocol_error_deadline_tests.zig");
    _ = @import("control/tls_close_tests.zig");
    _ = @import("push/output_deadline_tests.zig");
    _ = @import("request/output_deadline_tests.zig");
    _ = @import("request/complete_deadline_tests.zig");
    _ = @import("request/cleanup_deadline_tests.zig");
    _ = @import("request/batch_output_deadline_tests.zig");
    _ = @import("request/batch_progress_tests.zig");
    _ = @import("request/batch_tls_deadline_tests.zig");
    _ = @import("request/complete_early_response_tests.zig");
    _ = @import("request/upload_tests.zig");
    _ = @import("response/output_deadline_tests.zig");
    _ = @import("response/stream_roundtrip_tests.zig");
    _ = @import("response/goaway_commitment_tests.zig");
    _ = @import("stream/termination_tests.zig");
    _ = @import("stream/peer_termination_tests.zig");
    _ = client_duplex_owner;
    _ = @import("duplex/client_tests.zig");
    _ = @import("duplex/client_pump_tests.zig");
    _ = @import("duplex/server_tests.zig");
    _ = @import("duplex/pump_tests.zig");
    _ = @import("ping_probe_tests.zig");
    _ = @import("ping_enforcement_tests.zig");
    _ = @import("duplex/response_capacity_tests.zig");
    _ = @import("duplex/batched_credit_tests.zig");
}

test {
    _ = @import("connect/rejection_tests.zig");
    _ = @import("frame/retention_tests.zig");
    _ = @import("headers/limit_reuse_tests.zig");
    _ = @import("headers/reset_deadline_tests.zig");
    _ = @import("reset/header_failure_tests.zig");
    _ = @import("request/batch_error_tests.zig");
    _ = @import("response/credit_lifecycle_tests.zig");
    _ = @import("response/credit_failure_tests.zig");
    _ = @import("response/allocation_failure_tests.zig");
    _ = @import("response/forbidden_body_tests.zig");
    _ = @import("response/batch_trailer_sync_tests.zig");
    _ = @import("response/batch_trailer_failure_tests.zig");
    _ = @import("response/padding_credit_tests.zig");
    _ = @import("response/padding_failure_tests.zig");
    _ = @import("request/padding_credit_tests.zig");
    _ = @import("flow/tests/padding.zig");
    _ = @import("push/padding_credit_tests.zig");
    _ = @import("push/credit_failure_tests.zig");
    _ = @import("push/credit_refill_tests.zig");
    _ = @import("push/credit_fault_tests.zig");
    _ = @import("push/credit_transport_tests.zig");
    _ = @import("push/late_credit_tests.zig");
    _ = @import("request/body_length_tests.zig");
    _ = @import("request/credit_failure_tests.zig");
    _ = @import("request/allocation_failure_tests.zig");
    _ = @import("response/body_length_tests.zig");
    _ = @import("frame/tests/io.zig");
    _ = @import("frame/tests/wire.zig");
    _ = @import("flow/tests/window.zig");
    _ = @import("flow/tests/data.zig");
    _ = @import("headers/tests/message.zig");
    _ = @import("../../http/field_value_tests.zig");
    _ = @import("headers/value_reuse_tests.zig");
    _ = @import("tls_tests.zig");
    _ = @import("push_tests.zig");
    _ = @import("priority_tests.zig");
    _ = @import("priority/legacy_tests.zig");
    _ = @import("priority/dictionary_tests.zig");
    _ = @import("priority/metadata_tests.zig");
    _ = @import("priority/legacy_shutdown_tests.zig");
    _ = @import("streaming_response_tests.zig");
    _ = @import("response_batch_tests.zig");
    _ = @import("informational_batch_tests.zig");
    _ = @import("response_writer_tests.zig");
    _ = @import("request_writer_tests.zig");
    _ = @import("ping_timeout_tests.zig");
    _ = @import("close_timeout_tests.zig");
    _ = @import("refusal_tests.zig");
    _ = @import("connect_udp_tests.zig");
    _ = @import("connect_udp_relay_tests.zig");
    _ = @import("connect_ip_tests.zig");
    _ = @import("handshake_timeout_tests.zig");
    _ = @import("proxy_tests.zig");
    _ = @import("redirect_tests.zig");
    _ = @import("server_lifecycle_tests.zig");
    _ = @import("unix_tests.zig");
}

test {
    _ = @import("push/receive_tests.zig");
    _ = @import("push/receive_order_tests.zig");
    _ = @import("push/receive_lifecycle_tests.zig");
    _ = @import("push/receive_error_tests.zig");
    _ = @import("push/receive_store_tests.zig");
}

test "HTTP/2 owned stream timeout closes the transport before the handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{},
    );
    defer listener.deinit(io);
    const peer = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer peer.close(io);
    const stream = try listener.accept(io);
    const FakeServer = struct {
        io: std.Io,
        calls: usize = 0,

        pub fn acceptStreamMaybeBefore(
            self: *@This(),
            _: net.Stream,
            _: ?std.Io.Clock.Timestamp,
        ) Error!Connection {
            self.calls += 1;
            return error.InvalidFrame;
        }
    };
    var server = FakeServer{ .io = io };
    try std.testing.expectError(
        error.Timeout,
        runtime.acceptOwnedStreamWithTimeout(
            &server,
            stream,
            .fromNanoseconds(0),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), server.calls);
    var buffer: [1]u8 = undefined;
    const n = try @import("../../internal/stream_io.zig").readSomeWithDeadline(
        io,
        peer,
        &buffer,
        .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }),
    );
    try std.testing.expectEqual(@as(usize, 0), n);
}

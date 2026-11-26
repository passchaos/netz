//! HTTP/2 connection state, frames, streams, and request/response writers.

const std = @import("std");
const http2 = @import("../mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const accept_deadline = @import("../../internal/accept.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const net = std.Io.net;
const socket_address = @import("../../internal/socket_address.zig");
const runtime = @import("../runtime.zig");
const frame_io = @import("frame/io.zig");
const frame_wire = @import("frame/wire.zig");
const flow_window = @import("flow/window.zig");
const flow_output = @import("flow/output.zig");
const outbound_headers = @import("headers/connection.zig");
const client_authority = @import("client/authority.zig");
const client_duplex_owner = @import("duplex/client_owner.zig");
const DuplexOwners = @import("duplex/owners.zig").Owners;
const duplex_wake = @import("duplex/wake.zig");
const buffered_frame_wake = @import("frame/wake.zig");
const socket_options = @import("../../internal/socket_options.zig");
const tcp_connect = @import("../../internal/tcp_connect.zig");
const endpoint_host = @import("../../internal/endpoint_host.zig");
const host_connect = @import("client/host_connect.zig");
const uri_redirect = @import("../../http1/runtime/redirect.zig");

const Error = runtime.Error;
const Limits = runtime.Limits;
const RuntimeTransport = runtime.RuntimeTransport;
const Role = runtime.Role;
const PeerResetInfo = runtime.PeerResetInfo;
const StreamResponseSemantics = runtime.StreamResponseSemantics;
const RequestOptions = runtime.RequestOptions;
const ResponseOptions = runtime.ResponseOptions;
const OwnedResponse = runtime.OwnedResponse;
const RequestWriter = runtime.RequestWriter;
const ResponseWriter = runtime.ResponseWriter;
const ClientDuplexStream = runtime.ClientDuplexStream;
const ServerDuplexStream = runtime.ServerDuplexStream;
const Tunnel = runtime.Tunnel;
const DuplexHeaderBlock = runtime.DuplexHeaderBlock;
const FlowWindow = runtime.FlowWindow;

/// Restore credit that was reserved earlier. The pre-reservation window was
/// valid, so failure means another operation already violated the invariant.
/// Debug and ReleaseSafe still trap through `assert`; ReleaseFast keeps the
/// conservative window value instead of executing undefined behavior.
fn restoreWindow(window: *FlowWindow, amount: u31) void {
    window.update(amount) catch |err| {
        std.debug.assert(err == error.FlowControlViolation);
    };
}

fn restoreWindowDelta(window: *FlowWindow, delta: i64) void {
    window.adjust(delta) catch |err| {
        std.debug.assert(err == error.FlowControlViolation);
    };
}

fn accountCredit(
    controls: anytype,
    state_index: usize,
    before: i64,
    after: i64,
    adaptive_increment: u31,
) void {
    flow_credit.account(
        controls,
        state_index,
        before,
        after,
        adaptive_increment,
    ) catch |err| std.debug.assert(err == error.MessageTooLarge);
}
const freeHeaders = runtime.freeHeaders;
const OwnedRequest = runtime.OwnedRequest;
const ReceivedDataPayload = runtime.ReceivedDataPayload;
const validateHeaderBlock = runtime.validateHeaderBlock;
const awakeNowNanos = runtime.awakeNowNanos;
const default_flow_window = runtime.default_flow_window;
const legacy_priority = @import("priority/legacy.zig");
const data_frame_budget = @import("data_frame_budget.zig");
const message_headers = @import("headers/message.zig");
const push = @import("push.zig");
const priority_runtime = @import("priority.zig");
const ping_policy = @import("ping_enforcement.zig");
const default_max_frame_size = runtime.default_max_frame_size;
const max_flow_window = runtime.max_flow_window;
const graceful_shutdown_ping_payload = runtime.graceful_shutdown_ping_payload;
const forbidden_response_body = runtime.forbidden_response_body;
const header_block_limits = runtime.header_block_limits;
const webtransport_settings = runtime.webtransport_settings;
const peer_metadata = runtime.peer_metadata;
const http_date = runtime.http_date;
const flow_capacity = runtime.flow_capacity;
const flow_credit = runtime.flow_credit;
const header_output = runtime.header_output;
const protocol_error_output = runtime.protocol_error_output;
const request_batch_cleanup = runtime.request_batch_cleanup;
const request_cleanup = runtime.request_cleanup;
const response_cleanup = runtime.response_cleanup;
const response_scheduler = runtime.response_scheduler;
const response_start = runtime.response_start;
const response_trailers = runtime.response_trailers;
const stream_termination = runtime.stream_termination;
const complete_request = runtime.complete_request;
const complete_upload = runtime.complete_upload;
const bdp = runtime.bdp;
const requestHeaderLookup = message_headers.requestHeaderLookup;
const flag_end_stream = runtime.flag_end_stream;
const decodeOwnedHeaders = runtime.decodeOwnedHeaders;
const StreamWindowEntry = runtime.StreamWindowEntry;
const RetainedFrame = runtime.RetainedFrame;
const PendingRequest = runtime.PendingRequest;
const ResponseTimeoutError = runtime.ResponseTimeoutError;
const RequestTimeoutError = runtime.RequestTimeoutError;
const tcpTransport = runtime.tcpTransport;
const InformationalObserver = runtime.InformationalObserver;
const StreamingResponse = runtime.StreamingResponse;
const StreamingResponseHead = runtime.StreamingResponseHead;
const StreamingRequest = runtime.StreamingRequest;
const StreamingRequestHead = runtime.StreamingRequestHead;
const BatchInformationalObserver = runtime.BatchInformationalObserver;
const BatchOwnedResponseObserver = runtime.BatchOwnedResponseObserver;
const BatchStreamingResponseObserver = runtime.BatchStreamingResponseObserver;
const BatchCancellationObserver = runtime.BatchCancellationObserver;
const max_settings_payload_len = runtime.max_settings_payload_len;
const ignoreStreamingResponseHead = runtime.ignoreStreamingResponseHead;
const StreamingRequestOptions = runtime.StreamingRequestOptions;
const methodIsConnect = runtime.methodIsConnect;
const stackFirstHeaderFieldBuffer = runtime.stackFirstHeaderFieldBuffer;
const freeStackFirstHeaderFieldBuffer = runtime.freeStackFirstHeaderFieldBuffer;
const encodeSettingsPayloadInto = runtime.encodeSettingsPayloadInto;
const responseStreamErrorCode = runtime.responseStreamErrorCode;
const PromisedRequest = runtime.PromisedRequest;
const validateHeaderListSize = message_headers.validateHeaderListSize;
const requestShouldDefaultContentLength = message_headers.requestShouldDefaultContentLength;
const validateResponseContentLength = message_headers.validateResponseContentLength;
const appendHeaderBlockBytes = frame_wire.appendHeaderBlock;
const batch_output = @import("request/batch_output.zig");
const AcceptedConnectIp = runtime.AcceptedConnectIp;
const AcceptedConnectUdp = runtime.AcceptedConnectUdp;
const AlternativeService = runtime.AlternativeService;
const Client = runtime.Client;
const ClientDuplexPumpEvent = runtime.ClientDuplexPumpEvent;
const ConcurrentHandlerServeError = runtime.ConcurrentHandlerServeError;
const ConcurrentHandlerServeResult = runtime.ConcurrentHandlerServeResult;
const ConnectIpSession = runtime.ConnectIpSession;
const ConnectUdpSession = runtime.ConnectUdpSession;
const ExtendedConnectAttempt = runtime.ExtendedConnectAttempt;
const ExtendedConnectRequest = runtime.ExtendedConnectRequest;
const ExtendedConnectResponse = runtime.ExtendedConnectResponse;
const GoAwayRetryDisposition = runtime.GoAwayRetryDisposition;
const KeepAliveOptions = runtime.KeepAliveOptions;
const KeepAliveResult = runtime.KeepAliveResult;
const OwnedFrame = runtime.OwnedFrame;
const OwnedGoAway = runtime.OwnedGoAway;
const OwnedResetStream = runtime.OwnedResetStream;
const OwnedWindowUpdate = runtime.OwnedWindowUpdate;
const PingEnforcementStats = runtime.PingEnforcementStats;
const Server = runtime.Server;
const ServerDuplexPumpEvent = runtime.ServerDuplexPumpEvent;
const StreamingResponseOptions = runtime.StreamingResponseOptions;
const advertisedMaxFrameSize = runtime.advertisedMaxFrameSize;
const appendAutomaticDateHeaderValue = runtime.appendAutomaticDateHeaderValue;
const appendPushPromiseBlockBytes = runtime.appendPushPromiseBlockBytes;
const calcMaxContinuationFrames = runtime.calcMaxContinuationFrames;
const checkedBodyLength = runtime.checkedBodyLength;
const checkedResponseBodyLength = runtime.checkedResponseBodyLength;
const clientInitiatedStreamId = runtime.clientInitiatedStreamId;
const concurrent = runtime.concurrent;
const contentLength = runtime.contentLength;
const countInformationalResponse = runtime.countInformationalResponse;
const encodeFrameHeader = runtime.encodeFrameHeader;
const encodeWindowUpdateFrame = runtime.encodeWindowUpdateFrame;
const findHeader = runtime.findHeader;
const flag_ack = runtime.flag_ack;
const flag_end_headers = runtime.flag_end_headers;
const handshake_protocol_error = runtime.handshake_protocol_error;
const http1 = runtime.http1;
const http3 = runtime.http3;
const ignoreStreamingRequestHead = runtime.ignoreStreamingRequestHead;
const informationalResponseToSkip = runtime.informationalResponseToSkip;
const max_data_frames_per_write = runtime.max_data_frames_per_write;
const max_data_frames_with_headers = runtime.max_data_frames_with_headers;
const methodIsHead = runtime.methodIsHead;
const normalizeHandlerResponse = runtime.normalizeHandlerResponse;
const notifyInformationalResponse = runtime.notifyInformationalResponse;
const readFrame = runtime.readFrame;
const requestAuthority = runtime.requestAuthority;
const reservedInternalPingPayload = runtime.reservedInternalPingPayload;
const responseForbidsBody = runtime.responseForbidsBody;
const responseHeaderLookup = runtime.responseHeaderLookup;
const responseSemanticsFromMethod = runtime.responseSemanticsFromMethod;
const responseShouldDefaultContentLengthValue = runtime.responseShouldDefaultContentLengthValue;
const responseWriteSuppressesBodySemantics = runtime.responseWriteSuppressesBodySemantics;
const serveRequestStreamErrorCode = runtime.serveRequestStreamErrorCode;
const statusIsInformational = runtime.statusIsInformational;
const streamingRequestFromOwned = runtime.streamingRequestFromOwned;
const stripSuccessfulConnectContentLength = runtime.stripSuccessfulConnectContentLength;
const vail = runtime.vail;
const validateDeclaredRequestLength = runtime.validateDeclaredRequestLength;
const validateDeclaredResponseLengthValue = runtime.validateDeclaredResponseLengthValue;
const validateExpectedContentLength = runtime.validateExpectedContentLength;
const validateOutgoingResponseBodyForStatus = runtime.validateOutgoingResponseBodyForStatus;
const validateOutgoingResponseBodyForStatusWithLength = runtime.validateOutgoingResponseBodyForStatusWithLength;
const validateResponseBodyForRequestSemanticsWithLength = runtime.validateResponseBodyForRequestSemanticsWithLength;
const writeAll = runtime.writeAll;
const writeFrameTransport = runtime.writeFrameTransport;
const writeFrameTransportWithDeadline = runtime.writeFrameTransportWithDeadline;
const DataSliceCursor = runtime.DataSliceCursor;
const DeferredHeaderBlock = runtime.DeferredHeaderBlock;
const DeferredPendingHeaderSlot = runtime.DeferredPendingHeaderSlot;
const DuplexHeaderBlockSlot = runtime.DuplexHeaderBlockSlot;
const Http2ConcurrentEngine = runtime.Http2ConcurrentEngine;
const LocallyResetStream = runtime.LocallyResetStream;
const OwnedFrameSlot = runtime.OwnedFrameSlot;
const ResponseBodySemantics = runtime.ResponseBodySemantics;
const RetainedFrameSlot = runtime.RetainedFrameSlot;
const ServeReadConnectionError = runtime.ServeReadConnectionError;
const ServeReadStreamError = runtime.ServeReadStreamError;

pub const Connection = struct {
    const RefusedHeaders = @import("headers/refusal.zig").Reader(.{
        .Error = Error,
        .readHeaders = readHeaderBlockUntil,
        .freeHeaders = freeHeaders,
        .validate = validateHeaderBlock,
        .lookup = requestHeaderLookup,
    });
    const InboundHeaders = @import("headers/inbound.zig").Reader(.{
        .Error = Error,
        .takeDeferred = takeDeferredHeaderBlock,
        .popQueued = popQueuedApplicationFrame,
        .maxContinuations = maxContinuationFrames,
        .readDuplex = readOwnedFrameForDuplexWithDeadline,
        .readRaw = readOwnedFrameRawWithDeadline,
        .readQueued = readOwnedFrameWithDeadline,
        .parseFirstHeaders = legacy_priority.parseHeaders,
        .recordStreamError = recordResponseStreamReadError,
    });
    const LateResetFrames = @import("reset/late.zig").Handler(.{
        .Error = Error,
        .wasReset = wasLocallyResetAt,
        .resumeDeferred = resumeDeferredHeaderBlockUntil,
        .collect = collectHeaderBlockUntil,
        .freeHeaders = freeHeaders,
        .refund = releaseLateResetConnectionCapacityUntil,
        .preadmitted = gracefulPreadmittedIndex,
    });
    const DataReceiver = @import("flow/data.zig").Receiver(.{
        .ErrorType = Error,
        .ResultType = ReceivedDataPayload,
        .recvWindow = recvStreamWindow,
        .clockNs = awakeNowNanos,
        .writeControl = writeControlFrameUntil,
        .grantAdaptive = sendQueuedAdaptiveWindowUpdateAfterData,
        .budgetMaximum = dataFrameBudgetMaximum,
        .lastProcessed = lastPeerProcessedStreamId,
        .sendGoAway = sendProtocolGoAway,
        .endStreamFlag = flag_end_stream,
    });
    const PushLifecycle = @import("push/connection.zig").Lifecycle(.{
        .Error = Error,
        .Response = OwnedResponse,
        .Header = DuplexHeaderBlock,
        .initHeader = DuplexHeaderBlock.init,
        .parseHeaders = legacy_priority.parseHeaders,
        .resumeHeader = DuplexHeaderBlock.resumeUntil,
        .deinitHeader = DuplexHeaderBlock.deinit,
        .prepareQueued = completeDeferredHeadersBeforePushRead,
        .readRaw = readTransportFrameRawWithDeadline,
        .handleConnection = handleConnectionFrameUntil,
        .recordGoAway = recordPeerGoAway,
        .queueSibling = queueDuplexSiblingFrameUntil,
        .releasePeer = releasePeerStream,
        .forgetWindows = forgetStreamWindows,
        .reset = writeResetStreamFrameUntil,
        .promise = receivePushPromiseUntil,
        .wasReset = wasLocallyReset,
        .discardReset = discardLateFrameForLocallyResetStreamUntil,
        .activate = addActivePeerStream,
        .goAway = sendProtocolGoAway,
        .processed = lastPeerProcessedStreamId,
        .takeData = receiveDataPayload,
        .releaseData = releaseDataFrameBudget,
        .returnCredit = releaseConnectionCapacityUntil,
        .credit = releaseReceivedDataCapacityUntil,
        .decodeHeaders = decodeOwnedHeaders,
        .freeHeaders = freeHeaders,
    });

    io: std.Io,
    allocator: std.mem.Allocator,
    stream: net.Stream,
    transport: ?RuntimeTransport = null,
    role: Role,
    limits: Limits = .{},
    next_client_stream_id: u31 = 1,
    send_connection_window: FlowWindow = .{},
    recv_connection_window: FlowWindow = .{},
    recv_connection_window_target: u32 = @intCast(default_flow_window),
    recv_stream_window_target: u32 = @intCast(default_flow_window),
    data_frame_budget: data_frame_budget.State = .{},
    send_stream_windows: std.ArrayList(StreamWindowEntry) = .empty,
    send_stream_window_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    recv_stream_windows: std.ArrayList(StreamWindowEntry) = .empty,
    recv_stream_window_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    active_local_streams: std.ArrayList(u31) = .empty,
    active_local_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    active_peer_streams: std.ArrayList(u31) = .empty,
    active_peer_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    push_state: push.LazyState = .{},
    pending_push_header: ?*DuplexHeaderBlock = null,
    push_ingress_headers_active: bool = false,
    priority_state: priority_runtime.LazyState = .{},
    response_semantics: std.ArrayList(StreamResponseSemantics) = .empty,
    response_semantics_index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    hpack_decoder: http2.Hpack.Decoder = .{},
    hpack_encoder: http2.Hpack.Encoder = .{},
    /// Transactional batch encoding copies live HPACK state here. Successful
    /// batches swap the encoders, so both sides retain their dynamic-table and
    /// scratch capacity for the next batch. Single-message connections avoid
    /// carrying a second encoder by allocating this state on first batch use.
    hpack_encoder_staging: ?*http2.Hpack.Encoder = null,
    /// Reassembles only fragmented HEADERS/PUSH_PROMISE blocks. A single-frame
    /// block is decoded directly from frame-reader storage, avoiding this copy
    /// on the common path while retaining capacity for later continuations.
    header_block_scratch: std.ArrayList(u8) = .empty,
    write_batch: std.ArrayList(u8) = .empty,
    batch_data_headers: std.ArrayList(
        [http2.FrameHeader.encoded_len]u8,
    ) = .empty,
    batch_data_parts: std.ArrayList([]const u8) = .empty,
    frame_reader: frame_io.Reader = .{},
    /// Application frames temporarily consumed by a connection-level wait.
    /// The cursor avoids shifting on every pop, while compaction reuses storage
    /// after a burst. Frames stay in exact wire order so HPACK CONTINUATION and
    /// DATA semantics remain owned by the eventual request/response reader.
    pending_application_frames: std.ArrayList(RetainedFrame) = .empty,
    pending_application_frame_head: usize = 0,
    /// Sibling header blocks encountered by a duplex frame pump are decoded in
    /// wire order. Their raw frames remain in the ordinary pending queue; the
    /// later stream reader consumes these fields instead of mutating HPACK a
    /// second time.
    duplex_sibling_headers: std.ArrayList(DeferredHeaderBlock) = .empty,
    pending_duplex_sibling_header: DeferredPendingHeaderSlot = .{},
    /// New request streams seen by the graceful-shutdown PING pump are
    /// admitted before the final GOAWAY boundary is selected, but their raw
    /// HEADERS remain queued so HPACK is decoded exactly once in wire order.
    graceful_preadmitted_peer_streams: std.ArrayList(GracefulPeerRequest) =
        .empty,
    /// Processed-stream boundary before the current speculative graceful
    /// admission run. Rollback restores it while preserving observed IDs.
    graceful_preadmit_base_processed_stream_id: ?u31 = null,
    /// Lazily allocated shadow HPACK state advances across preadmission checks
    /// in exact wire order. The live decoder remains untouched until queued
    /// frames are later delivered to the application request reader.
    graceful_preadmit_decoder: ?*http2.Hpack.Decoder = null,
    /// Scratch readers expose borrowed slices. When their next frame comes
    /// from the owning pending queue, retain that allocation until the next
    /// connection read invalidates the borrow.
    borrowed_pending_frame: OwnedFrameSlot = .{},
    /// Emergency ownership slot used when queue growth or its configured cap
    /// makes a PING wait fail after consuming one more frame from the wire. It
    /// follows the queued prefix and keeps the next application read lossless.
    pending_application_overflow: RetainedFrameSlot = .{},
    /// Duplex handles are driven serially by one connection owner. Ordinary
    /// aggregate readers remain excluded while any duplex handle is active.
    duplex_reader_active: bool = false,
    duplex_owners: DuplexOwners = .{},
    /// User callbacks may borrow decoded headers or DATA backed by the active
    /// read operation. Reentering any receive path from such a callback would
    /// advance the shared frame reader and invalidate that borrow. Sending on
    /// another stream remains legal until it itself needs receive progress.
    callback_reader_active: bool = false,
    /// One active-stream frame captured by a flow-control wait. It is separate
    /// from sibling frames so the duplex reader can consume it first without
    /// repeatedly cycling an unrelated queued frame.
    duplex_pending_frame: RetainedFrameSlot = .{},
    /// A bounded duplex accept retains an incomplete HEADERS/CONTINUATION
    /// sequence here so timeout never discards connection-wide HPACK input.
    pending_duplex_request_head: DuplexHeaderBlockSlot = .{},
    /// Awake-clock timestamp of the last frame removed from transport. Queued
    /// application frames were already accounted for at ingress and therefore
    /// do not make an idle connection look newly active when later consumed.
    last_peer_frame_at: ?std.Io.Timestamp = null,
    /// A background owner may submit one liveness PING without blocking its
    /// application-frame pump. Exact ACK matching clears the pending payload;
    /// the owner separately supplies and enforces the liveness deadline.
    ping_probe_payload: ?[8]u8 = null,
    ping_probe_acknowledged: bool = false,
    ping_enforcement: ping_policy.State = .{},
    peer_initial_stream_window: i64 = default_flow_window,
    peer_max_frame_size: usize = default_max_frame_size,
    peer_max_header_list_size: usize = std.math.maxInt(usize),
    peer_max_concurrent_streams: ?u32 = null,
    /// A peer can defer retiring a reset stream until its current receive
    /// batch ends. Synchronize before new admission when the reset released
    /// the last advertised slot; use the next operation's original deadline.
    peer_reset_admission_pending: bool = false,
    peer_enable_connect_protocol: bool = false,
    webtransport_settings: webtransport_settings.LazyState = .{},
    peer_enable_push: bool = true,
    peer_no_rfc7540_priorities: bool = false,
    peer_priority_setting_seen: bool = false,
    peer_initial_settings_applied: bool = false,
    awaiting_settings_ack: bool = false,
    adaptive_window: ?bdp.Estimator = null,
    adaptive_pending_stream_target: ?u32 = null,
    adaptive_queued_target: ?u32 = null,
    last_peer_client_stream_id: u31 = 0,
    /// Highest peer request accepted for application processing. Keep this
    /// separate from the observed-stream cursor because REFUSED_STREAM closes
    /// a stream without claiming that its request might have been processed.
    last_peer_processed_stream_id: u31 = 0,
    peer_goaway_last_stream_id: ?u31 = null,
    /// Sticky classification for grpc-core's keepalive throttling signal.
    /// The debug bytes are consumed from frame storage, so retain only the
    /// exact allocation-free predicate needed by channel owners.
    peer_goaway_too_many_pings: bool = false,
    local_goaway_last_stream_id: ?u31 = null,
    /// Two-phase server shutdown sends its maximum GOAWAY exactly once, then
    /// resumes the fixed PING barrier after a bounded wait times out.
    graceful_shutdown_phase: enum {
        open,
        synchronizing,
        synchronized,
        complete,
        failed,
    } = .open,
    /// Message allocation failure, aggregate timeout, or an indeterminate write
    /// may leave a partially decoded HPACK block, DATA sequence, or frame prefix whose
    /// ownership cannot be reconstructed by a later call. Fail closed instead
    /// of allowing subsequent operations or pooled reuse against ambiguous
    /// connection state.
    aggregate_timeout_unusable: bool = false,
    terminal_write_failed: bool = false,
    /// Several frame and HPACK parsers share low-level errors such as
    /// BufferTooShort. Preserve only protocol failures whose RFC connection
    /// error mapping is known, rather than guessing from the public error tag.
    serve_read_connection_error: ?ServeReadConnectionError = null,
    serve_read_stream_error: ?ServeReadStreamError = null,
    pending_accept_reset_overflowed: bool = false,
    pending_requests: std.ArrayList(PendingRequest) = .empty,
    pending_request_head: usize = 0,
    pending_accept_reset_streams: usize = 0,
    /// Lifetime count of resets emitted for peer-caused stream protocol
    /// errors. Application cancellation, timeouts, and REFUSED_STREAM do not
    /// consume this budget.
    local_error_reset_streams: usize = 0,
    peer_origins: ?*peer_metadata.Origins = null,
    alternative_services: ?*peer_metadata.AlternativeServices = null,
    /// Peers may have stream frames in flight when RST_STREAM reaches them. A
    /// bounded timestamped FIFO lets another response reader discard those
    /// late frames for a minimum duration without connection-lifetime growth.
    locally_reset_streams: std.ArrayList(LocallyResetStream) = .empty,
    locally_reset_stream_index: std.AutoHashMapUnmanaged(u31, void) = .empty,
    locally_reset_stream_head: usize = 0,
    /// Most recently consumed peer reset. Readers still return
    /// `error.StreamReset`; protocol adapters can take this payload
    /// immediately afterward to preserve the wire reason in their own error
    /// model. A later reset replaces an untaken value.
    last_peer_reset: ?http2.ResetStreamPayload = null,
    last_peer_reset_response_started: bool = true,
    default_authority: ?[]u8 = null,
    /// An IP constructor supplies an implicit numeric default. Explicit Host
    /// may replace it; URI/TLS/adopted authorities retain their origin binding.
    default_authority_is_ip: bool = false,
    /// Borrowed default used when RequestOptions.scheme is omitted.  Cleartext
    /// constructors set this to `http`, while the ALPN-authenticated TLS
    /// constructor sets it to `https`.
    default_scheme: ?[]const u8 = null,

    pub fn deinitPeerMetadata(self: *Connection) void {
        if (self.peer_origins) |origins| {
            origins.deinit(self.allocator);
            self.allocator.destroy(origins);
            self.peer_origins = null;
        }
        if (self.alternative_services) |services| {
            services.deinit(self.allocator);
            self.allocator.destroy(services);
            self.alternative_services = null;
        }
    }

    /// Resolve the scheme that request encoders will place in `:scheme`.
    /// Protocol adapters use this to bind auxiliary state to the exact same
    /// origin as the eventual HTTP/2 request.
    pub fn resolveRequestScheme(
        self: *const Connection,
        explicit: ?[]const u8,
    ) []const u8 {
        return explicit orelse self.default_scheme orelse "https";
    }

    /// Resolve the authority that request encoders will place in `:authority`.
    /// The returned slice remains connection-owned when it comes from the
    /// constructor default.
    pub fn resolveRequestAuthority(
        self: *const Connection,
        explicit: ?[]const u8,
    ) ?[]const u8 {
        return explicit orelse self.default_authority;
    }

    /// Resolve the exact request authority, including a caller-provided Host
    /// header. Protocol adapters can use this same origin for cookie policy.
    pub fn resolveRequestAuthorityFromHeaders(
        self: *const Connection,
        explicit: ?[]const u8,
        headers: []const http2.Hpack.HeaderField,
    ) ?[]const u8 {
        if (!self.default_authority_is_ip and self.default_authority != null) return self.resolveRequestAuthority(explicit);
        return client_authority.resolve(explicit, headers, self.default_authority);
    }

    /// Replace a numeric resolved-address default with its logical authority.
    /// The connection owns the copied value until close. This is primarily
    /// used by resolvers that keep routing addresses separate from HTTP origin.
    pub fn replaceDefaultAuthority(
        self: *Connection,
        authority: []const u8,
    ) Error!void {
        if (authority.len == 0) return error.InvalidHeader;
        try client_authority.replace(
            self.allocator,
            &self.default_authority,
            authority,
        );
        self.default_authority_is_ip = false;
    }

    pub fn close(self: *Connection) void {
        if (self.default_authority) |authority| self.allocator.free(authority);
        self.send_stream_windows.deinit(self.allocator);
        self.send_stream_window_index.deinit(self.allocator);
        self.recv_stream_windows.deinit(self.allocator);
        self.recv_stream_window_index.deinit(self.allocator);
        self.active_local_streams.deinit(self.allocator);
        self.active_local_index.deinit(self.allocator);
        self.active_peer_streams.deinit(self.allocator);
        self.active_peer_index.deinit(self.allocator);
        self.push_state.deinit(self.allocator);
        if (self.pending_push_header) |pending| {
            pending.deinit(self.allocator);
            self.allocator.destroy(pending);
        }
        self.priority_state.deinit(self.allocator);
        self.webtransport_settings.deinit(self.allocator);
        self.response_semantics.deinit(self.allocator);
        self.response_semantics_index.deinit(self.allocator);
        for (self.pending_requests.items[self.pending_request_head..]) |*pending| pending.deinit(self.allocator);
        self.pending_requests.deinit(self.allocator);
        self.deinitPeerMetadata();
        self.locally_reset_streams.deinit(self.allocator);
        self.locally_reset_stream_index.deinit(self.allocator);
        self.hpack_decoder.deinit(self.allocator);
        self.hpack_encoder.deinit(self.allocator);
        self.deinitStagedHpackEncoder();
        self.header_block_scratch.deinit(self.allocator);
        self.write_batch.deinit(self.allocator);
        self.batch_data_headers.deinit(self.allocator);
        self.batch_data_parts.deinit(self.allocator);
        self.borrowed_pending_frame.deinit(self.allocator);
        for (self.pending_application_frames.items[self.pending_application_frame_head..]) |*frame| frame.deinit(self.allocator);
        self.pending_application_frames.deinit(self.allocator);
        for (self.duplex_sibling_headers.items) |entry| freeHeaders(self.allocator, entry.headers);
        self.duplex_sibling_headers.deinit(self.allocator);
        self.pending_duplex_sibling_header.deinit(self.allocator);
        self.graceful_preadmitted_peer_streams.deinit(self.allocator);
        self.clearGracefulPreadmitDecoder();
        self.pending_application_overflow.deinit(self.allocator);
        self.pending_duplex_request_head.deinit(self.allocator);
        self.duplex_pending_frame.deinit(self.allocator);
        self.frame_reader.deinit(self.allocator);
        // A blocked peer cannot extend the connection lifetime past teardown:
        // the TLS close_notify gets the same finite bound as GOAWAY frames.
        self.transportForIo().closeWithTerminalBudget(self.io, self.limits);
        self.* = undefined;
    }

    /// Retire a terminal lease without any TLS shutdown output.
    pub fn closeWithoutCloseNotify(self: *Connection) void {
        if (self.transport) |transport| switch (transport) {
            .tls_client => |connection| switch (connection.records) {
                inline else => |*records| records.failed = true,
            },
            .tls_server => |connection| switch (connection.records) {
                inline else => |*records| records.failed = true,
            },
            .tcp => {},
        };
        self.close();
    }

    pub fn closeWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!void {
        defer self.closeWithoutCloseNotify();
        if (self.transport) |transport| switch (transport) {
            .tls_client => |connection| try connection.sendCloseNotifyWithDeadline(deadline),
            .tls_server => |connection| try connection.sendCloseNotifyWithDeadline(deadline),
            .tcp => {},
        };
    }

    /// Convenience form of `closeWithDeadline` using an awake-clock budget.
    /// An expired budget still retires the transport, matching the deadline
    /// form's no-output cleanup contract.
    pub fn closeWithTimeout(self: *Connection, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) {
            self.closeWithoutCloseNotify();
            return error.Timeout;
        }
        return self.closeWithDeadline(.fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Whether an exclusive client lease can safely return this connection to
    /// an idle pool. GOAWAY, live streams, queued application frames, or push
    /// mode make reuse ambiguous, so the pool closes those connections rather
    /// than exposing state from one borrower to the next.
    pub fn isReusable(self: *const Connection) bool {
        return self.role == .client and
            !self.aggregate_timeout_unusable and
            !self.pending_accept_reset_overflowed and
            self.peer_goaway_last_stream_id == null and
            self.local_goaway_last_stream_id == null and
            self.active_local_streams.items.len == 0 and
            self.active_peer_streams.items.len == 0 and
            self.duplex_owners.count() == 0 and
            self.pending_requests.items.len == self.pending_request_head and
            self.pending_application_frames.items.len ==
                self.pending_application_frame_head and
            !self.pending_application_overflow.hasValue() and
            self.duplex_sibling_headers.items.len == 0 and
            !self.pending_duplex_sibling_header.hasValue() and
            !self.duplex_pending_frame.hasValue() and
            !self.borrowed_pending_frame.hasValue() and
            self.response_semantics.items.len == 0 and
            self.push_state.isQuiescent() and
            !self.limits.enable_push;
    }

    /// Return the current SETTINGS_MAX_CONCURRENT_STREAMS value advertised by
    /// the peer. `null` means the peer omitted the setting and therefore left
    /// the RFC default unbounded. Later SETTINGS frames may change this value.
    pub fn peerMaxConcurrentStreams(self: *const Connection) ?u32 {
        return self.peer_max_concurrent_streams;
    }

    /// Return the peer-concurrency capacity visible to the next locally
    /// initiated stream. `null` means the peer advertised no finite limit;
    /// zero means the next open will be rejected for concurrency. Idle request
    /// streams reserved by PRIORITY_UPDATE count toward the limit, except that
    /// a reservation for the exact next stream is not charged twice. Re-query
    /// after each open because later stream IDs may have their own reservations.
    pub fn availableLocalStreamCapacity(self: *const Connection) ?u32 {
        const limit = self.peer_max_concurrent_streams orelse return null;
        const used = self.localStreamConcurrencyUsed();
        if (used >= limit) return 0;
        return limit - @as(u32, @intCast(used));
    }

    pub fn activeLocalStreamCount(self: *const Connection) usize {
        return self.active_local_streams.items.len;
    }

    pub fn activePeerStreamCount(self: *const Connection) usize {
        return self.active_peer_streams.items.len;
    }

    /// Whether the peer has opted into RFC 8441 Extended CONNECT. The setting
    /// is false until an enabling SETTINGS frame has been processed.
    pub fn peerExtendedConnectEnabled(self: *const Connection) bool {
        return self.peer_enable_connect_protocol;
    }

    /// Last WebTransport SETTINGS whose ACK this endpoint completely sent.
    /// Capture this value at CONNECT admission; later updates belong to new
    /// Sessions and must not modify an established Session's initial credit.
    pub fn peerWebTransportSettings(self: *const Connection) http2.WebTransportSettings {
        return self.webtransport_settings.peerAcknowledged();
    }

    /// Last locally advertised WebTransport SETTINGS acknowledged by the peer.
    pub fn localWebTransportSettings(self: *const Connection) http2.WebTransportSettings {
        return self.webtransport_settings.localAcknowledged(
            if (self.awaiting_settings_ack)
                .{}
            else
                self.limits.webtransport,
        );
    }

    pub fn updateWebTransportSettingsWithDeadline(self: *Connection, settings: http2.WebTransportSettings, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.awaiting_settings_ack) return error.SettingsAckPending;
        if (settings.enabled and !self.limits.enable_connect_protocol) return error.InvalidSetting;
        var values: [7]http2.Setting = undefined;
        var payload: [max_settings_payload_len]u8 = undefined;
        const encoded = try encodeSettingsPayloadInto(&payload, settings.write(&values));
        try self.webtransport_settings.prepareLocal(
            self.allocator,
            self.limits.webtransport,
        );
        try self.writeControlFrameUntil(.settings, 0, encoded, deadline);
        self.webtransport_settings.setLocalSent(settings);
        self.awaiting_settings_ack = true;
    }

    pub fn updateWebTransportSettingsWithTimeout(self: *Connection, settings: http2.WebTransportSettings, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.updateWebTransportSettingsWithDeadline(settings, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn localStreamConcurrencyUsed(self: *const Connection) usize {
        if (self.role != .client) {
            return self.active_local_streams.items.len;
        }
        const next_reserved =
            self.priority_state.containsIdleRequest(self.next_client_stream_id);
        return self.active_local_streams.items.len +
            self.priority_state.idleRequestCount() -
            @intFromBool(next_reserved);
    }

    pub fn transportForIo(self: *Connection) RuntimeTransport {
        return self.transport orelse tcpTransport(self.io, self.stream);
    }

    fn encryptedTransport(self: *const Connection) bool {
        const transport = self.transport orelse return false;
        return switch (transport) {
            .tls_client, .tls_server => true,
            .tcp => false,
        };
    }

    /// Return the verified peer certificate chain for vail-backed TLS. Server
    /// connections expose an authenticated client chain; client connections
    /// expose the authenticated server chain. Slices remain valid until close.
    pub fn peerCertificates(
        self: *const Connection,
    ) ?[]const []const u8 {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_server => |connection| connection.peerCertificates(),
            .tls_client => |connection| connection.peerCertificates(),
            .tcp => null,
        };
    }

    /// Return the ALPN selected by a vail-backed TLS transport. HTTP/2's TLS
    /// constructors require `h2`, while cleartext h2c has no ALPN state.
    pub fn negotiatedAlpn(self: *const Connection) ?[]const u8 {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.negotiatedAlpn(),
            .tls_server => |connection| connection.negotiatedAlpn(),
            .tcp => null,
        };
    }

    /// Remote transport IP peer, including on client-created connections.
    /// Accepted connections use cached accept metadata; clients query the native
    /// socket. Unix streams and unavailable native queries return null.
    pub fn peerAddress(self: *const Connection) ?net.IpAddress {
        return if (self.role == .server)
            socket_address.accepted(self.stream)
        else
            socket_address.connected(self.io, self.stream);
    }

    pub fn negotiatedTlsProtocol(
        self: *const Connection,
    ) ?tls_stream.Protocol {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.negotiatedProtocol(),
            .tls_server => |connection| connection.negotiatedProtocol(),
            .tcp => null,
        };
    }

    pub fn wasTlsSessionResumed(self: *const Connection) ?bool {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.wasResumed(),
            .tls_server => |connection| connection.wasResumed(),
            .tcp => null,
        };
    }

    pub fn takeTls12SessionTicket(
        self: *Connection,
    ) ?tls_stream.Tls12SessionTicket {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.takeTls12SessionTicket(),
            .tls_server, .tcp => null,
        };
    }

    pub fn takeTls13SessionTicket(
        self: *Connection,
    ) tls_stream.Error!?tls_stream.Tls13SessionTicket {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.takeTls13SessionTicket(),
            .tls_server, .tcp => null,
        };
    }

    /// Return authenticated TLS cipher-suite metadata when this HTTP/2
    /// connection uses a vail-backed TLS transport.
    pub fn negotiatedCipherSuite(
        self: *const Connection,
    ) ?tls_stream.NegotiatedCipherSuite {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.negotiatedCipherSuite(),
            .tls_server => |connection| connection.negotiatedCipherSuite(),
            .tcp => null,
        };
    }

    /// Return the transcript/HKDF hash selected by the TLS cipher suite.
    pub fn negotiatedTranscriptHash(
        self: *const Connection,
    ) ?tls_stream.TranscriptHash {
        const transport = self.transport orelse return null;
        return switch (transport) {
            .tls_client => |connection| connection.negotiatedTranscriptHash(),
            .tls_server => |connection| connection.negotiatedTranscriptHash(),
            .tcp => null,
        };
    }

    /// Start a TLS 1.3 application traffic-key update. The transport serializes
    /// the KeyUpdate handshake message with all HTTP/2 writes and rotates only
    /// after the old-key record has reached the socket.
    pub fn updateTrafficKeys(
        self: *Connection,
        request_peer_update: bool,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        const transport = self.transport orelse
            return error.PostHandshakeTlsUnavailable;
        transport.updateTrafficKeys(request_peer_update) catch |err| {
            return switch (err) {
                // These are rejected before a KeyUpdate record or epoch change.
                error.WriteInProgress,
                error.KeyUpdateRequestPending,
                => err,
                // Every other TLS KeyUpdate failure is terminal at the record
                // layer (including an unknown ciphertext prefix). Prevent HTTP/2
                // siblings from appending records to that failed connection.
                else => {
                    self.aggregate_timeout_unusable = true;
                    return err;
                },
            };
        };
    }

    pub fn keyUpdateCounts(
        self: *const Connection,
    ) ?tls_stream.KeyUpdateCounts {
        const transport = self.transport orelse return null;
        return transport.keyUpdateCounts();
    }

    /// Export RFC 8446 channel-bound keying material for TLS connections.
    pub fn exportKeyingMaterial(
        self: *const Connection,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        const transport = self.transport orelse
            return error.PostHandshakeTlsUnavailable;
        return switch (transport) {
            .tls_client => |connection| connection.exportKeyingMaterial(
                label,
                context,
                out,
            ),
            .tls_server => |connection| connection.exportKeyingMaterial(
                label,
                context,
                out,
            ),
            .tcp => error.PostHandshakeTlsUnavailable,
        };
    }

    /// Take the peer's most recently consumed RST_STREAM payload.
    ///
    /// This is intended for the error path immediately following
    /// `error.StreamReset`. The connection allows only one active frame
    /// reader, so taking rather than retaining the payload prevents a stale
    /// reset from being attributed to a later operation.
    pub fn takeLastPeerReset(self: *Connection) ?http2.ResetStreamPayload {
        const info = self.takeLastPeerResetInfo() orelse return null;
        return info.reset;
    }

    /// Take reset payload and response-commit evidence together, clearing both
    /// so a later operation cannot inherit another stream's replay hint.
    pub fn takeLastPeerResetInfo(self: *Connection) ?PeerResetInfo {
        const reset = self.last_peer_reset orelse return null;
        const info: PeerResetInfo = .{ .reset = reset, .response_started = self.last_peer_reset_response_started };
        self.last_peer_reset = null;
        self.last_peer_reset_response_started = true;
        return info;
    }

    pub fn request(self: *Connection, options: RequestOptions) Error!OwnedResponse {
        return self.requestWithInformational(options, null);
    }

    /// Send a complete request and bound the entire response read with one
    /// absolute awake-clock budget. A timeout makes this connection unusable:
    /// aggregate response state may include a partial HPACK block or body and
    /// cannot safely be reconstructed by a later call. Pools therefore discard
    /// the lease rather than exposing cross-request protocol state.
    pub fn requestWithTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn requestWithDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        return self.requestWithInformationalAndDeadline(
            options,
            null,
            deadline,
        );
    }

    /// Send a complete request and observe interim responses under one
    /// caller-owned deadline shared with the final response.
    pub fn requestWithInformationalAndDeadline(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const pending = try self.sendCompleteRequestUntil(options, deadline);
        return self.readResponseAndUploadUntil(
            pending.stream_id,
            pending.request_method,
            pending.extended_connect,
            informational,
            deadline,
            pending.upload,
        );
    }

    pub fn requestWithInformationalAndTimeout(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestWithInformationalAndDeadline(
            options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Wait for a previously sent complete request. These split forms are
    /// useful when an event loop or batch sender already owns the stream ID.
    pub fn readResponseWithTimeout(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithDeadline(
            stream_id,
            request_method,
            extended_connect,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn readResponseWithDeadline(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        return self.readResponseWithInformationalAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            null,
            deadline,
        );
    }

    pub fn readResponseWithInformationalAndDeadline(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readResponseUntil(
            stream_id,
            request_method,
            extended_connect,
            informational,
            deadline,
        );
    }

    pub fn readResponseWithInformationalAndTimeout(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseWithInformationalAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Send a complete request and observe each ordered interim response before
    /// returning the final response. Header slices borrow decoder storage only
    /// for the callback duration. Status 101 remains final HTTP semantics.
    pub fn requestWithInformational(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        const pending = try self.sendCompleteRequest(options);
        return self.readResponseAndUploadUntil(
            pending.stream_id,
            pending.request_method,
            pending.extended_connect,
            informational,
            null,
            pending.upload,
        );
    }

    /// Send a request and deliver response DATA without body aggregation.
    ///
    /// Initial headers and trailers in the returned value are owned until
    /// `StreamingResponse.deinit`. Each DATA slice borrows the connection frame
    /// reader and is valid only for the duration of `consume`. The callback
    /// must not retain it. A callback error cancels a still-open stream with
    /// RST_STREAM(CANCEL) before returning the original callback error.
    pub fn requestStreaming(
        self: *Connection,
        options: RequestOptions,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithHead(
            options,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithHeadAndDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithHeadAndDeadline(
            options,
            deadline,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithHeadAndTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithHeadAndDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            begin,
            consume,
        );
    }

    /// Send a request and deliver its final response head and body under one
    /// absolute awake-clock deadline. The head callback always precedes DATA.
    pub fn requestStreamingWithHeadAndDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHeadAndDeadline(
            options,
            null,
            deadline,
            context,
            begin,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndDeadline(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHeadAndDeadline(
            options,
            informational,
            deadline,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndTimeout(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithInformationalAndHeadAndDeadline(
            options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn requestStreamingWithInformationalAndHeadAndTimeout(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestStreamingWithInformationalAndHeadAndDeadline(
            options,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            begin,
            consume,
        );
    }

    /// Observe ordered informational heads and the final head before DATA.
    /// The deadline is validated before allocating or sending the request.
    pub fn requestStreamingWithInformationalAndHeadAndDeadline(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        _ = try deadline_policy.usableAwake(self.io, deadline);
        const pending = try self.sendCompleteRequestUntil(options, deadline);
        return self.readResponseStreamingWithHeadUntil(
            pending,
            informational,
            deadline,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithTimeout(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithDeadline(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            deadline,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithHeadAndTimeout(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithHeadAndDeadline(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            null,
            deadline,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndDeadline(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            informational,
            deadline,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndTimeout(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithInformationalAndHeadAndTimeout(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResponseStreamingWithInformationalAndHeadAndDeadline(
            stream_id,
            request_method,
            extended_connect,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            begin,
            consume,
        );
    }

    /// Wait for an existing stream while exposing every interim head and the
    /// final head under the same absolute awake-clock deadline as its body.
    pub fn readResponseStreamingWithInformationalAndHeadAndDeadline(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readResponseStreamingWithHeadUntil(
            .{
                .stream_id = stream_id,
                .request_method = request_method,
                .extended_connect = extended_connect,
            },
            informational,
            deadline,
            context,
            begin,
            consume,
        );
    }

    /// Stream response DATA while observing ordered interim response heads.
    pub fn requestStreamingWithInformational(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.requestStreamingWithInformationalAndHead(
            options,
            informational,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    /// Send a request and report final response HEADERS before any DATA.
    ///
    /// Protocol adapters such as gRPC need the selected content/message
    /// encoding before decoding the first body bytes. The head borrows the
    /// eventual `StreamingResponse` allocation and must not be retained.
    pub fn requestStreamingWithHead(
        self: *Connection,
        options: RequestOptions,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        const pending = try self.sendCompleteRequest(options);
        return self.readResponseStreamingWithHead(
            pending,
            null,
            context,
            begin,
            consume,
        );
    }

    /// Streaming response receive with ordered observation of preceding 1xx
    /// heads. Informational callbacks run before the final-head callback.
    pub fn requestStreamingWithInformationalAndHead(
        self: *Connection,
        options: RequestOptions,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        const pending = try self.sendCompleteRequest(options);
        return self.readResponseStreamingWithHead(
            pending,
            informational,
            context,
            begin,
            consume,
        );
    }

    pub const PendingResponse = struct {
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        upload: ?complete_upload.Upload = null,
    };

    fn resumeCompleteUploadUntil(self: *Connection, upload: *complete_upload.Upload, stream_id: u31, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return upload.progress(self, stream_id, deadline, .{
            .ErrorType = Error,
            .data = writeDataTrackedUntil,
            .headers = writeHeadersUntil,
        });
    }

    fn rejectResponseCallback(self: *Connection, stream_id: u31, upload: ?*complete_upload.Upload, remote_ended: bool, amount: usize, deadline: ?std.Io.Clock.Timestamp) void {
        const unfinished_upload = if (upload) |remaining| !remaining.finished else false;
        response_cleanup.callbackRejectedBefore(self, stream_id, remote_ended and !unfinished_upload, amount, response_cleanup.cleanupDeadline(self, deadline), .{
            .refund = releaseConnectionCapacityUntil,
            .reset = writeResetStreamFrameUntil,
            .forgetWindows = forgetStreamWindows,
        });
        if (upload) |remaining| remaining.finished = true;
    }

    pub fn sendCompleteRequest(
        self: *Connection,
        options: RequestOptions,
    ) Error!PendingResponse {
        return self.sendCompleteRequestUntil(options, null);
    }

    pub fn sendCompleteRequestWithDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingResponse {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.sendCompleteRequestUntil(options, absolute);
    }

    pub fn sendCompleteRequestWithTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
    ) Error!PendingResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendCompleteRequestWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendCompleteRequestUntil(self: *Connection, options: RequestOptions, deadline: ?std.Io.Clock.Timestamp) Error!PendingResponse {
        const requested_stream_id = self.next_client_stream_id;
        return complete_request.send(self, options, deadline, .{
            .ErrorType = Error,
            .PendingType = PendingResponse,
            .resolveAuthority = resolveRequestAuthorityFromHeaders,
            .synchronize = synchronizePeerResetAdmissionUntil,
            .reserve = reserveNextClientStreamId,
            .release = releaseLocalStream,
            .forgetWindows = forgetStreamWindows,
            .discard = failDiscardedResponseBefore,
            .headers = writeHeadersUntil,
            .burst = writeHeadersThenDataUntil,
            .data = writeDataTrackedUntil,
        }) catch |err| {
            if (err == error.StreamReset) {
                if (self.last_peer_reset) |reset| {
                    if (reset.stream_id == requested_stream_id and self.next_client_stream_id > requested_stream_id) self.last_peer_reset_response_started = false;
                }
            }
            // A blocked initial upload can observe a local protocol failure
            // before creating PendingResponse. Only peer unprocessed-stream
            // evidence may escape to the unary transparent replay driver.
            if (err == error.ConnectionGoAway and
                (self.aggregate_timeout_unusable or self.goAwayRetryDisposition(requested_stream_id) != .safe_to_retry)) return error.InvalidFrame;
            return err;
        };
    }

    /// Start a client request whose DATA is supplied incrementally.
    ///
    /// `body_length` adds Content-Length when the caller did not provide one;
    /// an explicit header must agree. CONNECT uses a dedicated tunnel API and
    /// is rejected here so DATA cannot be confused with tunnel bytes.
    pub fn startRequest(
        self: *Connection,
        options: StreamingRequestOptions,
    ) Error!RequestWriter {
        return self.startRequestUntil(options, null);
    }

    /// Start an incremental request under a caller-owned awake-clock
    /// deadline. Local preparation and actual HEADERS/CONTINUATION output
    /// use the same timestamp without renewing the caller's budget.
    pub fn startRequestWithDeadline(
        self: *Connection,
        options: StreamingRequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!RequestWriter {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.startRequestUntil(options, deadline);
    }

    pub fn startRequestWithTimeout(
        self: *Connection,
        options: StreamingRequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!RequestWriter {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startRequestWithDeadline(options, .fromNow(self.io, .{
            .raw = timeout,
            .clock = .awake,
        }));
    }

    fn startRequestUntil(
        self: *Connection,
        options: StreamingRequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!RequestWriter {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .client) return error.UnexpectedFrame;
        try self.synchronizePeerResetAdmissionUntil(deadline);
        self.last_peer_reset = null;
        var request_options = options;
        request_options.authority = self.resolveRequestAuthorityFromHeaders(request_options.authority, request_options.headers);
        const method_is_connect = methodIsConnect(request_options.method);
        if (method_is_connect and request_options.authority == null) {
            return error.MissingPseudoHeader;
        }
        const scheme = request_options.scheme orelse
            self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = try stackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_capacity,
        );
        defer freeStackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_buffer,
        );
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        // Traditional HTTP/2 CONNECT omits :path and :scheme; its DATA
        // frames are tunnel bytes rather than an HTTP request body.
        if (!method_is_connect) {
            fields.appendAssumeCapacity(.{
                .name = ":path",
                .value = request_options.path,
            });
            fields.appendAssumeCapacity(.{
                .name = ":scheme",
                .value = scheme,
            });
        }
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buffer: [16]u8 = undefined;
        if (request_options.priority) |priority| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = priority.serialize(&priority_buffer),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .request,
        );

        const declared_length = try contentLength(fields.items);
        if (method_is_connect and (declared_length orelse 0) != 0) {
            return error.InvalidContentLength;
        }
        const expected_length = if (method_is_connect)
            null
        else
            request_options.body_length orelse declared_length;
        if (request_options.body_length) |body_length| {
            if (declared_length) |declared| {
                if (declared != body_length) {
                    return error.InvalidContentLength;
                }
            } else if (!method_is_connect) {
                var content_length_buffer: [32]u8 = undefined;
                const value = std.fmt.bufPrint(
                    &content_length_buffer,
                    "{}",
                    .{body_length},
                ) catch unreachable;
                fields.appendAssumeCapacity(.{
                    .name = "content-length",
                    .value = value,
                });
            }
        }
        try validateHeaderBlock(fields.items, .request);
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.io, absolute);
        }

        const stream_id = try self.reserveNextClientStreamId();
        var stream_owned = true;
        errdefer if (stream_owned) self.releaseLocalStream(stream_id);
        // An aggregate CONNECT carries no tunnel bytes through this API, so
        // close its request half at HEADERS. A streaming tunnel keeps the
        // request side open and writes DATA later.
        const end_stream = method_is_connect and
            (request_options.body_length orelse 0) == 0 and
            declared_length == null;
        try self.writeHeadersUntil(stream_id, fields.items, end_stream, deadline);
        stream_owned = false;
        return .{
            .connection = self,
            .stream_id = stream_id,
            .expected_length = expected_length,
            .head_request = methodIsHead(request_options.method),
            .connect_request = method_is_connect,
            .body_finished = end_stream,
        };
    }

    /// Send several bodyless requests before waiting for their responses.
    ///
    /// Responses are returned in request order even when peer frames arrive in
    /// a different stream order. Request bodies/trailers are intentionally
    /// rejected for now: a body can exhaust flow-control credit while earlier
    /// responses are already arriving, which requires a fully duplex scheduler
    /// rather than this blocking connection's bounded batch pump.
    ///
    /// On success every `responses` element is initialized and owned by the
    /// caller. Deinitialize each with the connection allocator.
    pub fn requestBatchInto(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
    ) Error!void {
        return self.requestBatchWithInformationalIntoUntil(
            requests,
            responses,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Send a bodyless request batch and aggregate every response under one
    /// relative budget. The timeout is converted once before request staging;
    /// it is not renewed by an interim or completed sibling response. Socket
    /// writes retain the transport's blocking contract, while every response
    /// frame and continuation read uses the resulting absolute deadline.
    pub fn requestBatchIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBatchIntoWithDeadline(
            requests,
            responses,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Absolute-deadline form of `requestBatchIntoWithTimeout`. The awake-clock
    /// deadline is validated before stream IDs, HPACK state, or wire bytes are
    /// mutated. A timeout after submission cancels unfinished streams and makes
    /// the connection ineligible for reuse because aggregate state was lost.
    pub fn requestBatchIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.requestBatchWithInformationalIntoWithDeadline(
            requests,
            responses,
            null,
            deadline,
        );
    }

    /// Send a bodyless batch whose members carry independent absolute
    /// deadlines. Each expired stream receives RST_STREAM(CANCEL) and reports
    /// `Timeout` without retiring or cancelling later-deadline siblings.
    ///
    /// The observer is invoked exactly once for every request after request
    /// validation succeeds. Successful response ownership transfers through
    /// the callback. A connection-level failure is reported to every
    /// unfinished member and is also returned to the caller. The observer must
    /// not re-enter this connection before the batch method returns.
    pub fn requestBatchWithPerStreamDeadlines(
        self: *Connection,
        requests: []const RequestOptions,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedResponseObserver,
    ) ResponseTimeoutError!void {
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
        }
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            16 * 1024,
            deadlines,
            .{ .owned = observer },
            null,
        ) catch |err| return @errorCast(err);
    }

    /// Active-cancellation form. `cancellation.event` interrupts a blocked
    /// frame read; the observer consumes only selected request indices.
    pub fn requestBatchWithPerStreamDeadlinesAndCancellation(
        self: *Connection,
        requests: []const RequestOptions,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedResponseObserver,
        cancellation: BatchCancellationObserver,
    ) ResponseTimeoutError!void {
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
        }
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            16 * 1024,
            deadlines,
            .{ .owned = observer },
            cancellation,
        ) catch |err| return @errorCast(err);
    }

    /// Callback-streaming form of `requestBatchWithPerStreamDeadlines`.
    /// Final heads and DATA are delivered in wire order while terminal owned
    /// headers/trailers and the exact streamed byte count transfer through the
    /// observer. Callback failure cancels only that request stream.
    pub fn requestBatchStreamingWithPerStreamDeadlines(
        self: *Connection,
        requests: []const RequestOptions,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchStreamingResponseObserver,
    ) anyerror!void {
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
        }
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            16 * 1024,
            deadlines,
            .{ .streaming = observer },
            null,
        );
    }

    /// Active-cancellation form of
    /// `requestBatchStreamingWithPerStreamDeadlines`.
    pub fn requestBatchStreamingWithPerStreamDeadlinesAndCancellation(
        self: *Connection,
        requests: []const RequestOptions,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchStreamingResponseObserver,
        cancellation: BatchCancellationObserver,
    ) anyerror!void {
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
        }
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            16 * 1024,
            deadlines,
            .{ .streaming = observer },
            cancellation,
        );
    }

    /// Full-duplex body/trailer form of
    /// `requestBatchWithPerStreamDeadlines`. Upload DATA advances round-robin;
    /// an expired member stops borrowing its body immediately and only live
    /// streams commit terminal request trailers.
    pub fn requestBodyBatchWithPerStreamDeadlines(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedResponseObserver,
    ) ResponseTimeoutError!void {
        if (body_chunk_size == 0) return error.InvalidFrameSize;
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            body_chunk_size,
            deadlines,
            .{ .owned = observer },
            null,
        ) catch |err| return @errorCast(err);
    }

    /// Active-cancellation form of
    /// `requestBodyBatchWithPerStreamDeadlines`.
    pub fn requestBodyBatchWithPerStreamDeadlinesAndCancellation(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchOwnedResponseObserver,
        cancellation: BatchCancellationObserver,
    ) ResponseTimeoutError!void {
        if (body_chunk_size == 0) return error.InvalidFrameSize;
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            body_chunk_size,
            deadlines,
            .{ .owned = observer },
            cancellation,
        ) catch |err| return @errorCast(err);
    }

    /// Full-duplex callback-streaming form of
    /// `requestBodyBatchWithPerStreamDeadlines`. Uploads stop borrowing an
    /// expired or callback-rejected member while surviving streams continue.
    pub fn requestBodyBatchStreamingWithPerStreamDeadlines(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchStreamingResponseObserver,
    ) anyerror!void {
        if (body_chunk_size == 0) return error.InvalidFrameSize;
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            body_chunk_size,
            deadlines,
            .{ .streaming = observer },
            null,
        );
    }

    /// Active-cancellation form of
    /// `requestBodyBatchStreamingWithPerStreamDeadlines`.
    pub fn requestBodyBatchStreamingWithPerStreamDeadlinesAndCancellation(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: BatchStreamingResponseObserver,
        cancellation: BatchCancellationObserver,
    ) anyerror!void {
        if (body_chunk_size == 0) return error.InvalidFrameSize;
        return self.requestBatchWithPerStreamDeadlinesChunked(
            requests,
            body_chunk_size,
            deadlines,
            .{ .streaming = observer },
            cancellation,
        );
    }

    fn requestBatchWithPerStreamDeadlinesChunked(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        deadlines: []const ?std.Io.Clock.Timestamp,
        observer: IndividualBatchObserver,
        cancellation: ?BatchCancellationObserver,
    ) anyerror!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != deadlines.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }
        for (requests, deadlines) |request_options, deadline| {
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
            try validateHeaderBlock(
                request_options.trailers,
                .request_trailers,
            );
            try validateHeaderListSize(
                request_options.trailers,
                self.peer_max_header_list_size,
            );
            if (deadline) |absolute| {
                if (absolute.clock != .awake) return error.Timeout;
            }
        }

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };
        var controls_stack: [16]IndividualBatchControl = undefined;
        const controls = if (requests.len <= controls_stack.len)
            controls_stack[0..requests.len]
        else
            try self.allocator.alloc(IndividualBatchControl, requests.len);
        defer if (controls.ptr != controls_stack[0..].ptr) {
            self.allocator.free(controls);
        };
        const Admission = enum { pending, admitted, timed_out, canceled };
        var admissions_stack: [16]Admission = undefined;
        const admissions = if (requests.len <= admissions_stack.len)
            admissions_stack[0..requests.len]
        else
            try self.allocator.alloc(Admission, requests.len);
        defer if (admissions.ptr != admissions_stack[0..].ptr) {
            self.allocator.free(admissions);
        };
        @memset(admissions, .pending);

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        const original_next_stream_id = self.next_client_stream_id;
        const staged_encoder = try self.prepareStagedHpackEncoder();
        var started: usize = 0;
        var request_heads_committed = false;
        errdefer if (!request_heads_committed) {
            self.next_client_stream_id = original_next_stream_id;
        };
        defer for (states[0..started], controls[0..started]) |
            *state,
            control,
        | {
            if (!control.reported) self.releaseLocalStream(state.stream_id);
            self.forgetStreamWindows(state.stream_id);
            state.deinit(self.allocator);
        };

        const cancellation_pending = if (cancellation) |cancel|
            cancel.event.isSet()
        else
            false;
        for (requests, deadlines, 0..) |
            request_options,
            deadline,
            request_index,
        | {
            if (cancellation_pending and cancellation.?.take_canceled(
                cancellation.?.context,
                request_index,
            )) {
                admissions[request_index] = .canceled;
                continue;
            }
            if (deadline) |absolute| {
                if (absolute.durationFromNow(self.io).raw.nanoseconds <= 0) {
                    admissions[request_index] = .timed_out;
                    continue;
                }
            }
            const pending = try self.appendRequestHeadToBatch(
                request_options,
                batch,
                staged_encoder,
            );
            states[started] = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
                .request_done = request_options.body.len == 0 and
                    request_options.trailers.len == 0,
            };
            controls[started] = .{
                .request_index = request_index,
                .deadline = deadline,
            };
            admissions[request_index] = .admitted;
            started += 1;
        }
        if (cancellation_pending) cancellation.?.acknowledge(
            cancellation.?.context,
        );

        for (admissions, 0..) |admission, request_index| switch (admission) {
            .admitted => {},
            .timed_out => observer.reportError(request_index, error.Timeout),
            .canceled => observer.reportError(request_index, error.Canceled),
            .pending => unreachable,
        };
        if (started == 0) return;
        try self.synchronizePeerResetAdmissionUntil(earliestIndividualBatchDeadline(controls[0..started]));

        var views_stack: [16]BatchDataView = undefined;
        const views = if (started <= views_stack.len)
            views_stack[0..started]
        else
            try self.allocator.alloc(BatchDataView, started);
        defer if (views.ptr != views_stack[0..].ptr) {
            self.allocator.free(views);
        };
        var offsets_stack: [16]usize = undefined;
        const offsets = if (started <= offsets_stack.len)
            offsets_stack[0..started]
        else
            try self.allocator.alloc(usize, started);
        defer if (offsets.ptr != offsets_stack[0..].ptr) {
            self.allocator.free(offsets);
        };
        var round_reserved_stack: [16]usize = undefined;
        const round_reserved = if (started <= round_reserved_stack.len)
            round_reserved_stack[0..started]
        else
            try self.allocator.alloc(usize, started);
        defer if (round_reserved.ptr != round_reserved_stack[0..].ptr) {
            self.allocator.free(round_reserved);
        };
        @memset(offsets, 0);
        for (views, controls[0..started], states[0..started]) |
            *view,
            control,
            state,
        | {
            const request_options = requests[control.request_index];
            view.* = .{
                .stream_id = state.stream_id,
                .body = request_options.body,
                .ends_with_trailers = request_options.trailers.len != 0,
            };
        }
        try self.prepareBodyBatchData(views, body_chunk_size);
        for (states[0..started], views) |state, view| {
            if (view.body.len != 0) {
                _ = try self.sendStreamWindow(state.stream_id);
            }
        }

        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        while (true) {
            var progress: batch_output.Progress = .{};
            batch_output.bytes(self.transportForIo(), batch.items, earliestIndividualBatchDeadline(controls[0..started]), &progress) catch |err| {
                if (err == error.Timeout and progress.canDiscard(self.transportForIo())) {
                    const now = std.Io.Clock.awake.now(self.io).nanoseconds;
                    var removed = false;
                    for (states[0..started], controls[0..started]) |*state, *control| {
                        if (control.reported) continue;
                        if (control.deadline) |absolute| {
                            if (absolute.raw.nanoseconds <= now) {
                                self.releaseLocalStream(state.stream_id);
                                self.forgetStreamWindows(state.stream_id);
                                control.reported = true;
                                state.done = true;
                                state.request_done = true;
                                observer.reportError(control.request_index, error.Timeout);
                                removed = true;
                            }
                        }
                    }
                    if (!removed) return err;
                    const rebuilt = try self.prepareStagedHpackEncoder();
                    batch.clearRetainingCapacity();
                    for (states[0..started], controls[0..started]) |state, control| {
                        if (control.reported) continue;
                        _ = try self.appendRequestHeadToBatchAt(requests[control.request_index], batch, rebuilt, state.stream_id);
                    }
                    if (batch.items.len == 0) return;
                    continue;
                }
                self.commitStagedHpackEncoder();
                request_heads_committed = true;
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                self.reportIndividualBatchError(states[0..started], controls[0..started], observer, err);
                return err;
            };
            self.commitStagedHpackEncoder();
            request_heads_committed = true;
            break;
        }

        errdefer |err| self.abortIndividualResponseBatch(states[0..started], controls[0..started], observer, err);
        try self.writeRequestBodyBatchDataWithPerStreamDeadlines(
            views,
            offsets,
            round_reserved,
            body_chunk_size,
            states[0..started],
            controls[0..started],
            observer,
            cancellation,
        );
        try self.writeRequestTrailersWithPerStreamDeadlines(
            requests,
            states[0..started],
            controls[0..started],
            observer,
            cancellation,
        );

        try self.readResponseBatchWithPerStreamDeadlines(states[0..started], controls[0..started], observer, cancellation);
    }

    /// Aggregate a bodyless response batch while observing each ordered 1xx
    /// head. The callback identifies both the request-array index and HTTP/2
    /// stream, and its header slices remain valid only for that callback.
    pub fn requestBatchWithInformationalInto(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
    ) Error!void {
        return self.requestBatchWithInformationalIntoUntil(
            requests,
            responses,
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Bounded bodyless batch aggregation with ordered 1xx observation.
    /// Informational responses share the batch's single unrenewed budget.
    pub fn requestBatchWithInformationalIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBatchWithInformationalIntoWithDeadline(
            requests,
            responses,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Absolute-deadline form of
    /// `requestBatchWithInformationalIntoWithTimeout`.
    pub fn requestBatchWithInformationalIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.requestBatchWithInformationalIntoUntil(
            requests,
            responses,
            informational,
            deadline,
        );
    }

    fn requestBatchWithInformationalIntoUntil(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != responses.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
            // CONNECT transitions the stream into a tunnel whose lifetime
            // cannot be represented by an owned, completed batch response.
            // Use openConnectTunnel/openExtendedConnect for those streams.
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
        }

        try self.synchronizePeerResetAdmissionUntil(deadline);

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };
        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        const staged_encoder = try self.prepareStagedHpackEncoder();
        const original_next_stream_id = self.next_client_stream_id;
        var started: usize = 0;
        var requests_written = false;
        errdefer if (!requests_written) {
            self.next_client_stream_id = original_next_stream_id;
        };
        errdefer |err| {
            if (requests_written and err == error.Timeout) {
                self.aggregate_timeout_unusable = true;
            }
            if (requests_written and
                (err == error.Timeout or
                    self.serve_read_connection_error != null or
                    !self.aggregate_timeout_unusable))
            {
                self.writeBatchResponseResetsBefore(states[0..started], response_cleanup.cleanupDeadline(self, if (err == error.Timeout) null else deadline)) catch {};
            }
            for (states[0..started]) |*state| {
                self.releaseLocalStream(state.stream_id);
                self.forgetStreamWindows(state.stream_id);
                state.deinit(self.allocator);
            }
        }
        for (requests, states) |request_options, *state| {
            const pending = try self.appendBodylessRequestToBatch(
                request_options,
                batch,
                staged_encoder,
            );
            state.* = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
            };
            started += 1;
        }
        var progress: batch_output.Progress = .{};
        batch_output.bytes(self.transportForIo(), batch.items, deadline, &progress) catch |err| {
            if (err != error.Timeout or !progress.canDiscard(self.transportForIo())) {
                self.commitStagedHpackEncoder();
                requests_written = true;
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
            }
            return @errorCast(err);
        };
        self.commitStagedHpackEncoder();
        requests_written = true;

        try self.readResponseBatch(states, informational, deadline);
        for (states, responses) |*state, *response| {
            response.* = .{
                .headers = state.headers.?,
                .status = state.status.?,
                .body = state.body_owned.?,
                .body_allowed = !state.forbids_body,
                .trailers = state.trailers,
            };
            state.headers = null;
            state.body_owned = null;
            state.trailers = &.{};
            self.releaseLocalStream(state.stream_id);
        }
    }

    /// Send bodyless request heads and stream interleaved response DATA.
    ///
    /// Response metadata is returned in request order, while `consume`
    /// receives that same request index plus each borrowed DATA slice. This is
    /// the no-aggregation counterpart to `requestBatchInto`. If the callback
    /// fails, unfinished streams are cancelled and no output element becomes
    /// caller-owned. A transport write failure may have exposed only a prefix
    /// of the staged request set, so the connection must be closed rather than
    /// reused after such an error.
    pub fn requestBatchStreamingInto(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBatchStreamingWithInformationalIntoUntil(
            requests,
            responses,
            null,
            null,
            context,
            consume,
        );
    }

    /// Stream a bodyless response batch under one relative budget. The
    /// timeout is converted once before request staging and is not renewed by
    /// control traffic, response heads, DATA, or completed sibling streams.
    pub fn requestBatchStreamingIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBatchStreamingIntoWithDeadline(
            requests,
            responses,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Absolute-deadline form of `requestBatchStreamingIntoWithTimeout`. The
    /// awake-clock timestamp is validated before stream IDs, HPACK state, or
    /// wire bytes are mutated. A transport read timeout discards call-local
    /// response state, so unfinished streams are cancelled and the connection
    /// is retired from reuse.
    pub fn requestBatchStreamingIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBatchStreamingWithInformationalIntoWithDeadline(
            requests,
            responses,
            null,
            deadline,
            context,
            consume,
        );
    }

    /// Stream a bodyless response batch while observing its correlated 1xx
    /// heads. Informational callbacks run in wire order before the final head
    /// and DATA callbacks for their respective streams.
    pub fn requestBatchStreamingWithInformationalInto(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBatchStreamingWithInformationalIntoUntil(
            requests,
            responses,
            informational,
            null,
            context,
            consume,
        );
    }

    /// Stream a bodyless response batch with ordered 1xx observation under one
    /// relative budget. Informational heads share the unrenewed batch timeout.
    pub fn requestBatchStreamingWithInformationalIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBatchStreamingWithInformationalIntoWithDeadline(
            requests,
            responses,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Absolute-deadline form of
    /// `requestBatchStreamingWithInformationalIntoWithTimeout`.
    pub fn requestBatchStreamingWithInformationalIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.requestBatchStreamingWithInformationalIntoUntil(
            requests,
            responses,
            informational,
            deadline,
            context,
            consume,
        );
    }

    fn requestBatchStreamingWithInformationalIntoUntil(
        self: *Connection,
        requests: []const RequestOptions,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != responses.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }
        for (requests) |request_options| {
            if (request_options.body.len != 0 or
                request_options.trailers.len != 0)
            {
                return error.InvalidContentLength;
            }
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
        }

        try self.synchronizePeerResetAdmissionUntil(deadline);

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        const staged_encoder = try self.prepareStagedHpackEncoder();
        const original_next_stream_id = self.next_client_stream_id;
        var started: usize = 0;
        var requests_written = false;
        var read_timed_out = false;
        errdefer if (!requests_written) {
            self.next_client_stream_id = original_next_stream_id;
        };
        errdefer {
            if (read_timed_out) {
                self.aggregate_timeout_unusable = true;
            }
            if (requests_written and
                (read_timed_out or
                    self.serve_read_connection_error != null or
                    !self.aggregate_timeout_unusable))
            {
                self.writeBatchResponseResetsBefore(states[0..started], response_cleanup.cleanupDeadline(self, if (read_timed_out) null else deadline)) catch {};
            }
            for (states[0..started]) |*state| {
                self.releaseLocalStream(state.stream_id);
                self.forgetStreamWindows(state.stream_id);
                state.deinit(self.allocator);
            }
        }
        for (requests, states) |request_options, *state| {
            const pending = try self.appendBodylessRequestToBatch(
                request_options,
                batch,
                staged_encoder,
            );
            state.* = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
            };
            started += 1;
        }
        var progress: batch_output.Progress = .{};
        batch_output.bytes(self.transportForIo(), batch.items, deadline, &progress) catch |err| {
            if (err != error.Timeout or !progress.canDiscard(self.transportForIo())) {
                self.commitStagedHpackEncoder();
                requests_written = true;
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
            }
            return err;
        };
        self.commitStagedHpackEncoder();
        requests_written = true;

        try self.readResponseBatchStreaming(
            states,
            informational,
            deadline,
            &read_timed_out,
            context,
            consume,
        );
        for (states, responses) |*state, *response| {
            response.* = .{
                .headers = state.headers.?,
                .status = state.status.?,
                .body_bytes = state.body_bytes,
                .trailers = state.trailers,
            };
            state.headers = null;
            state.trailers = &.{};
            self.releaseLocalStream(state.stream_id);
        }
    }

    /// Send a body-bearing batch with one connection-owned full-duplex pump.
    /// Request DATA advances round-robin across streams. When every unfinished
    /// body is flow-controlled, the same owner processes WINDOW_UPDATE and
    /// early response frames before resuming the exact unsent suffix. Optional
    /// request trailers are staged under a second HPACK transaction and carry
    /// END_STREAM only after every body byte is committed.
    /// `body_chunk_size` preserves the caller's application contribution size
    /// while HTTP/2 frame splitting still obeys the negotiated maximum.
    pub fn requestBodyBatchInto(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
    ) Error!void {
        return self.requestBodyBatchWithInformationalIntoUntil(
            requests,
            body_chunk_size,
            responses,
            null,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Send a body batch and aggregate every response under one relative
    /// budget. The timeout is converted once before request staging and is not
    /// renewed by upload flow-control progress or sibling responses.
    pub fn requestBodyBatchIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBodyBatchIntoWithDeadline(
            requests,
            body_chunk_size,
            responses,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Absolute-deadline form of `requestBodyBatchIntoWithTimeout`. Deadline
    /// validation precedes stream, HPACK, flow-control, and wire mutation. A
    /// post-submission timeout cancels unfinished streams and retires the
    /// connection from reuse.
    pub fn requestBodyBatchIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.requestBodyBatchWithInformationalIntoWithDeadline(
            requests,
            body_chunk_size,
            responses,
            null,
            deadline,
        );
    }

    /// Send a bounded body batch and observe correlated interim responses.
    /// Each stream has its own `max_informational_responses` allowance; one
    /// busy stream therefore cannot consume another stream's limit.
    pub fn requestBodyBatchWithInformationalInto(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
    ) Error!void {
        return self.requestBodyBatchWithInformationalIntoUntil(
            requests,
            body_chunk_size,
            responses,
            informational,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    /// Bounded body-bearing batch aggregation with ordered 1xx observation.
    /// Informational responses share the batch's single unrenewed budget.
    pub fn requestBodyBatchWithInformationalIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBodyBatchWithInformationalIntoWithDeadline(
            requests,
            body_chunk_size,
            responses,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Absolute-deadline form of
    /// `requestBodyBatchWithInformationalIntoWithTimeout`.
    pub fn requestBodyBatchWithInformationalIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.requestBodyBatchWithInformationalIntoUntil(
            requests,
            body_chunk_size,
            responses,
            informational,
            deadline,
        );
    }

    /// Send a flow-controlled request-body batch and stream every
    /// interleaved response DATA slice to `consume`. Response metadata is
    /// returned in request order without retaining aggregate response bodies.
    pub fn requestBodyBatchStreamingInto(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBodyBatchStreamingWithInformationalIntoUntil(
            requests,
            body_chunk_size,
            responses,
            null,
            null,
            context,
            consume,
        );
    }

    /// Relative-timeout form of `requestBodyBatchStreamingInto`. The budget is
    /// converted once before request staging and is not renewed by completed
    /// siblings, upload flow-control progress, or response callbacks.
    pub fn requestBodyBatchStreamingIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBodyBatchStreamingIntoWithDeadline(
            requests,
            body_chunk_size,
            responses,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Absolute-deadline form of `requestBodyBatchStreamingIntoWithTimeout`.
    /// Validation precedes stream, HPACK, flow-control, and wire mutation.
    pub fn requestBodyBatchStreamingIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBodyBatchStreamingWithInformationalIntoWithDeadline(
            requests,
            body_chunk_size,
            responses,
            null,
            deadline,
            context,
            consume,
        );
    }

    /// Stream responses to a bounded request-body batch while observing each
    /// correlated informational head in wire order.
    pub fn requestBodyBatchStreamingWithInformationalInto(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBodyBatchStreamingWithInformationalIntoUntil(
            requests,
            body_chunk_size,
            responses,
            informational,
            null,
            context,
            consume,
        );
    }

    /// Relative-timeout form of
    /// `requestBodyBatchStreamingWithInformationalInto`.
    pub fn requestBodyBatchStreamingWithInformationalIntoWithTimeout(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.requestBodyBatchStreamingWithInformationalIntoWithDeadline(
            requests,
            body_chunk_size,
            responses,
            informational,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Absolute-deadline form of
    /// `requestBodyBatchStreamingWithInformationalIntoWithTimeout`.
    pub fn requestBodyBatchStreamingWithInformationalIntoWithDeadline(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.requestBodyBatchStreamingWithInformationalIntoUntil(
            requests,
            body_chunk_size,
            responses,
            informational,
            deadline,
            context,
            consume,
        );
    }

    fn requestBodyBatchStreamingWithInformationalIntoUntil(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []StreamingResponse,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.requestBodyBatchIntoMode(
            true,
            requests,
            body_chunk_size,
            responses,
            informational,
            deadline,
            context,
            consume,
        );
    }

    fn requestBodyBatchWithInformationalIntoUntil(
        self: *Connection,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: []OwnedResponse,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.requestBodyBatchIntoMode(
            false,
            requests,
            body_chunk_size,
            responses,
            informational,
            deadline,
            {},
            undefined,
        ) catch |err| return @errorCast(err);
    }

    fn requestBodyBatchIntoMode(
        self: *Connection,
        comptime streaming_response: bool,
        requests: []const RequestOptions,
        body_chunk_size: usize,
        responses: anytype,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.role != .client) return error.UnexpectedFrame;
        if (requests.len != responses.len) return error.InvalidResponse;
        if (requests.len == 0) return;
        if (body_chunk_size == 0) return error.InvalidFrameSize;
        if (self.active_local_streams.items.len != 0) {
            return error.UnexpectedFrame;
        }

        for (requests) |request_options| {
            if (methodIsConnect(request_options.method)) {
                return error.InvalidHeader;
            }
            try validateHeaderBlock(
                request_options.trailers,
                .request_trailers,
            );
            try validateHeaderListSize(
                request_options.trailers,
                self.peer_max_header_list_size,
            );
        }

        try self.synchronizePeerResetAdmissionUntil(deadline);

        var states_stack: [16]BatchResponseState = undefined;
        const states = if (requests.len <= states_stack.len)
            states_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchResponseState, requests.len);
        defer if (states.ptr != states_stack[0..].ptr) {
            self.allocator.free(states);
        };
        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        var trailer_batch: std.ArrayList(u8) = .empty;
        defer trailer_batch.deinit(self.allocator);
        const original_next_stream_id = self.next_client_stream_id;
        const staged_encoder = try self.prepareStagedHpackEncoder();
        var started: usize = 0;
        var request_heads_committed = false;
        var responses_pending = false;
        var read_timed_out = false;
        errdefer |err| {
            if (request_heads_committed and
                (if (streaming_response)
                    read_timed_out
                else
                    err == error.Timeout))
            {
                self.aggregate_timeout_unusable = true;
            }
            if (responses_pending and
                ((if (streaming_response)
                    read_timed_out
                else
                    err == error.Timeout) or
                    self.serve_read_connection_error != null or
                    !self.aggregate_timeout_unusable))
            {
                self.writeBatchResponseResetsBefore(states[0..started], response_cleanup.cleanupDeadline(self, if (err == error.Timeout) null else deadline)) catch {};
            }
            // Before staged HPACK state is committed no HEADERS were written,
            // so local stream IDs roll back with the transaction. Once the
            // write succeeds, IDs remain consumed on later I/O failures.
            if (!request_heads_committed) {
                self.next_client_stream_id = original_next_stream_id;
            }
            for (states[0..started]) |*state| {
                self.releaseLocalStream(state.stream_id);
                self.forgetStreamWindows(state.stream_id);
                state.deinit(self.allocator);
            }
        }
        for (requests, states) |request_options, *state| {
            const pending = try self.appendRequestHeadToBatch(
                request_options,
                batch,
                staged_encoder,
            );
            state.* = .{
                .stream_id = pending.stream_id,
                .request_method = pending.request_method,
                .extended_connect = pending.extended_connect,
                .request_done = request_options.body.len == 0 and
                    request_options.trailers.len == 0,
            };
            started += 1;
        }
        var views_stack: [16]BatchDataView = undefined;
        const views = if (requests.len <= views_stack.len)
            views_stack[0..requests.len]
        else
            try self.allocator.alloc(BatchDataView, requests.len);
        defer if (views.ptr != views_stack[0..].ptr) {
            self.allocator.free(views);
        };
        var offsets_stack: [16]usize = undefined;
        const offsets = if (requests.len <= offsets_stack.len)
            offsets_stack[0..requests.len]
        else
            try self.allocator.alloc(usize, requests.len);
        defer if (offsets.ptr != offsets_stack[0..].ptr) {
            self.allocator.free(offsets);
        };
        var round_reserved_stack: [16]usize = undefined;
        const round_reserved =
            if (requests.len <= round_reserved_stack.len)
                round_reserved_stack[0..requests.len]
            else
                try self.allocator.alloc(usize, requests.len);
        defer if (round_reserved.ptr != round_reserved_stack[0..].ptr) {
            self.allocator.free(round_reserved);
        };
        @memset(offsets, 0);
        for (views, requests, states) |*view, request_options, state| {
            view.* = .{
                .stream_id = state.stream_id,
                .body = request_options.body,
                .ends_with_trailers = request_options.trailers.len != 0,
            };
        }
        try self.prepareBodyBatchData(views, body_chunk_size);

        // Materialize every send window before HEADERS become visible. The
        // DATA scheduler is then allocation-free after wire commitment.
        for (states) |state| {
            _ = try self.sendStreamWindow(state.stream_id);
        }

        var progress: batch_output.Progress = .{};
        batch_output.bytes(self.transportForIo(), batch.items, deadline, &progress) catch |err| {
            if (err != error.Timeout or !progress.canDiscard(self.transportForIo())) {
                self.commitStagedHpackEncoder();
                request_heads_committed = true;
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
            }
            return @errorCast(err);
        };
        self.commitStagedHpackEncoder();
        request_heads_committed = true;
        responses_pending = true;
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        // Stage terminal trailer blocks only after the initial HEADERS state
        // is committed. An upload/reset failure before trailers are written
        // can then reuse the connection without advancing local HPACK beyond
        // the peer. The trailer stage is committed only after its wire write.
        if (hasRequestTrailers(requests)) {
            const trailer_encoder = try self.prepareStagedHpackEncoder();
            for (requests, states) |request_options, state| {
                if (request_options.trailers.len == 0) continue;
                try self.appendRequestTrailersToBatch(
                    state.stream_id,
                    request_options.trailers,
                    &trailer_batch,
                    trailer_encoder,
                );
            }
        }
        try self.writeRequestBodyBatchDataUntil(
            streaming_response,
            views,
            offsets,
            round_reserved,
            body_chunk_size,
            states,
            informational,
            deadline,
            &read_timed_out,
            context,
            consume,
        );
        try self.writeRequestBodyBatchTrailersUntil(
            requests,
            states,
            trailer_batch.items,
            deadline,
            &read_timed_out,
        );

        if (streaming_response) {
            try self.readResponseBatchStreaming(
                states,
                informational,
                deadline,
                &read_timed_out,
                context,
                consume,
            );
            for (states, responses) |*state, *response| {
                response.* = .{
                    .headers = state.headers.?,
                    .status = state.status.?,
                    .body_bytes = state.body_bytes,
                    .trailers = state.trailers,
                };
                state.headers = null;
                state.trailers = &.{};
                self.releaseLocalStream(state.stream_id);
            }
        } else {
            try self.readResponseBatch(states, informational, deadline);
            for (states, responses) |*state, *response| {
                response.* = .{
                    .headers = state.headers.?,
                    .status = state.status.?,
                    .body = state.body_owned.?,
                    .body_allowed = !state.forbids_body,
                    .trailers = state.trailers,
                };
                state.headers = null;
                state.body_owned = null;
                state.trailers = &.{};
                self.releaseLocalStream(state.stream_id);
            }
        }
    }

    fn appendRequestHeadToBatch(
        self: *Connection,
        options: RequestOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
    ) Error!PendingResponse {
        return self.appendRequestHeadToBatchAt(options, batch, encoder, null);
    }

    fn appendRequestHeadToBatchAt(
        self: *Connection,
        options: RequestOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
        existing_stream_id: ?u31,
    ) Error!PendingResponse {
        var request_options = options;
        request_options.authority = self.resolveRequestAuthorityFromHeaders(request_options.authority, request_options.headers);
        const scheme =
            request_options.scheme orelse self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = try stackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_capacity,
        );
        defer freeStackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_buffer,
        );
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        fields.appendAssumeCapacity(.{
            .name = ":path",
            .value = request_options.path,
        });
        fields.appendAssumeCapacity(.{
            .name = ":scheme",
            .value = scheme,
        });
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .request,
        );
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(
            request_options.method,
            fields.items,
            request_options.body.len,
        )) {
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{request_options.body.len},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .request);
        try validateDeclaredRequestLength(
            fields.items,
            request_options.body.len,
        );
        try validateHeaderListSize(
            fields.items,
            self.peer_max_header_list_size,
        );

        const stream_id = existing_stream_id orelse try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            fields.items,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            request_options.body.len == 0 and
                request_options.trailers.len == 0,
            self.outboundFramePayloadLimit(),
        );
        return .{
            .stream_id = stream_id,
            .request_method = request_options.method,
            .extended_connect = false,
        };
    }

    fn appendRequestTrailersToBatch(
        self: *Connection,
        stream_id: u31,
        trailers: []const http2.Hpack.HeaderField,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
    ) Error!void {
        std.debug.assert(trailers.len != 0);
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            trailers,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            true,
            self.outboundFramePayloadLimit(),
        );
    }

    fn writeRequestBodyBatchTrailersUntil(
        self: *Connection,
        requests: []const RequestOptions,
        states: []BatchResponseState,
        trailer_bytes: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
        read_timed_out: *bool,
    ) !void {
        if (trailer_bytes.len == 0) return;
        if (deadline) |absolute| {
            _ = deadline_policy.usableAwake(
                self.io,
                absolute,
            ) catch |err| {
                read_timed_out.* = err == error.Timeout;
                return err;
            };
        }
        var progress: batch_output.Progress = .{};
        batch_output.bytes(self.transportForIo(), trailer_bytes, deadline, &progress) catch |err| {
            // A partial wide write cannot identify which terminal HEADERS
            // reached the peer, so the connection must not be reused.
            read_timed_out.* = err == error.Timeout;
            if (err != error.Timeout or !progress.canDiscard(self.transportForIo())) {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
            }
            return err;
        };
        self.commitStagedHpackEncoder();
        for (requests, states) |request_options, *state| {
            if (request_options.trailers.len != 0) {
                state.request_done = true;
            }
        }
    }

    fn writeRequestTrailersWithPerStreamDeadlines(
        self: *Connection,
        requests: []const RequestOptions,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        cancellation: ?BatchCancellationObserver,
    ) ResponseTimeoutError!void {
        for (states, controls) |*state, *control| {
            if (control.reported) continue;
            const trailers = requests[control.request_index].trailers;
            if (trailers.len == 0) continue;

            while (!control.reported) {
                if (try self.cancelIndividualBatchRequests(
                    states,
                    controls,
                    observer,
                    cancellation,
                )) {
                    continue;
                }
                if (try self.expireIndividualBatchDeadlines(
                    states,
                    controls,
                    observer,
                )) {
                    continue;
                }
                const batch = &self.write_batch;
                batch.clearRetainingCapacity();
                const encoder = try self.prepareStagedHpackEncoder();
                try self.appendRequestTrailersToBatch(
                    state.stream_id,
                    trailers,
                    batch,
                    encoder,
                );

                const deadline = earliestIndividualBatchDeadline(controls);
                var committed: usize = 0;
                if (deadline) |absolute| {
                    self.transportForIo().writeAllWithDeadline(
                        batch.items,
                        &committed,
                        absolute,
                    ) catch |err| {
                        if (err == error.Timeout and committed == 0 and !self.transportForIo().hasPendingWrite()) {
                            continue;
                        }
                        self.aggregate_timeout_unusable = true;
                        self.terminal_write_failed = true;
                        return err;
                    };
                } else {
                    self.transportForIo().writeAll(batch.items) catch |err| {
                        self.aggregate_timeout_unusable = true;
                        return err;
                    };
                }
                self.commitStagedHpackEncoder();
                state.request_done = true;
                if (state.done) {
                    try self.finishIndividualBatchResponse(
                        state,
                        control,
                        observer,
                    );
                }
                break;
            }
        }
    }

    fn hasRequestTrailers(requests: []const RequestOptions) bool {
        for (requests) |request_options| {
            if (request_options.trailers.len != 0) return true;
        }
        return false;
    }

    fn writeRequestBodyBatchDataUntil(
        self: *Connection,
        comptime streaming_response: bool,
        views: []const BatchDataView,
        offsets: []usize,
        round_reserved: []usize,
        application_chunk_size: usize,
        states: []BatchResponseState,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        read_timed_out: *bool,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        std.debug.assert(views.len == offsets.len);
        std.debug.assert(views.len == round_reserved.len);
        const frame_limit = self.outboundFramePayloadLimit();
        var remaining_streams = views.len;
        for (views) |view| {
            if (view.body.len == 0) remaining_streams -= 1;
        }
        var next_stream: usize = 0;

        while (remaining_streams != 0) {
            self.batch_data_headers.clearRetainingCapacity();
            self.batch_data_parts.clearRetainingCapacity();
            @memset(round_reserved, 0);
            var made_progress = false;
            var reserved_connection_bytes: usize = 0;
            var wire_write_started = false;
            errdefer if (!wire_write_started) {
                restoreWindow(
                    &self.send_connection_window,
                    @intCast(reserved_connection_bytes),
                );
                for (views, round_reserved) |view, bytes| {
                    if (bytes == 0) continue;
                    if (self.sendStreamWindow(view.stream_id) catch null) |window| {
                        restoreWindow(window, @intCast(bytes));
                    }
                }
            };

            const pass_start = next_stream;
            var scanned: usize = 0;
            while (scanned < views.len) : (scanned += 1) {
                const index = (pass_start + scanned) % views.len;
                const view = views[index];
                const offset = &offsets[index];
                if (offset.* == view.body.len) continue;
                if (self.send_connection_window.available() == 0) break;
                const stream_window = try self.sendStreamWindow(
                    view.stream_id,
                );
                const contribution_len = @min(
                    application_chunk_size,
                    view.body.len - offset.*,
                    self.send_connection_window.available(),
                    stream_window.available(),
                );
                if (contribution_len == 0) continue;
                try self.appendBodyBatchContribution(
                    view,
                    offset,
                    contribution_len,
                    frame_limit,
                    stream_window,
                );
                reserved_connection_bytes += contribution_len;
                round_reserved[index] = contribution_len;
                if (offset.* == view.body.len) remaining_streams -= 1;
                made_progress = true;
                next_stream = (index + 1) % views.len;
            }

            if (made_progress) {
                if (deadline) |absolute| {
                    _ = deadline_policy.usableAwake(
                        self.io,
                        absolute,
                    ) catch |err| {
                        read_timed_out.* = err == error.Timeout;
                        return err;
                    };
                }
                var progress: batch_output.Progress = .{};
                batch_output.parts(self.allocator, self.transportForIo(), self.batch_data_parts.items, &self.write_batch, deadline, &progress) catch |err| {
                    wire_write_started = progress.submitted;
                    read_timed_out.* = err == error.Timeout;
                    if (progress.submitted and (err != error.Timeout or !progress.canDiscard(self.transportForIo()))) {
                        self.aggregate_timeout_unusable = true;
                        self.terminal_write_failed = true;
                    }
                    return err;
                };
                wire_write_started = true;
                for (views, offsets, states, round_reserved) |
                    view,
                    offset,
                    *state,
                    bytes,
                | {
                    if (bytes != 0 and offset == view.body.len) {
                        state.request_done = !view.ends_with_trailers;
                    }
                }
                continue;
            }

            const frame = (self.readBufferedFrameWithDeadline(deadline) catch |err| {
                read_timed_out.* = deadline != null and err == error.Timeout;
                return err;
            }).frame;
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                try self.recordPeerGoAway(goaway);
                for (states) |state| {
                    if (!state.done and
                        state.stream_id > goaway.last_stream_id)
                    {
                        return error.ConnectionGoAway;
                    }
                }
                continue;
            }
            try self.processBodyBatchResponseFrame(
                streaming_response,
                states,
                informational,
                deadline,
                read_timed_out,
                null,
                context,
                consume,
                frame,
            );
        }
    }

    fn writeRequestBodyBatchDataWithPerStreamDeadlines(
        self: *Connection,
        views: []const BatchDataView,
        offsets: []usize,
        round_reserved: []usize,
        application_chunk_size: usize,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        cancellation: ?BatchCancellationObserver,
    ) anyerror!void {
        std.debug.assert(views.len == offsets.len);
        std.debug.assert(views.len == round_reserved.len);
        std.debug.assert(views.len == states.len);
        std.debug.assert(views.len == controls.len);
        const frame_limit = self.outboundFramePayloadLimit();
        var remaining_streams: usize = 0;
        for (views, controls) |view, control| {
            remaining_streams += @intFromBool(
                !control.reported and view.body.len != 0,
            );
        }
        var next_stream: usize = 0;

        while (remaining_streams != 0) {
            for (views, offsets, controls) |view, *offset, control| {
                if (control.reported and offset.* < view.body.len) {
                    offset.* = view.body.len;
                    remaining_streams -= 1;
                }
            }
            if (remaining_streams == 0) break;
            if (try self.cancelIndividualBatchRequests(
                states,
                controls,
                observer,
                cancellation,
            )) {
                continue;
            }
            if (try self.expireIndividualBatchDeadlines(
                states,
                controls,
                observer,
            )) {
                continue;
            }

            self.batch_data_headers.clearRetainingCapacity();
            self.batch_data_parts.clearRetainingCapacity();
            @memset(round_reserved, 0);
            var made_progress = false;
            var reserved_connection_bytes: usize = 0;
            var wire_write_started = false;
            errdefer if (!wire_write_started) {
                restoreWindow(
                    &self.send_connection_window,
                    @intCast(reserved_connection_bytes),
                );
                for (views, round_reserved) |view, bytes| {
                    if (bytes == 0) continue;
                    if (self.sendStreamWindow(view.stream_id) catch null) |window| {
                        restoreWindow(window, @intCast(bytes));
                    }
                }
            };

            const pass_start = next_stream;
            var scanned: usize = 0;
            while (scanned < views.len) : (scanned += 1) {
                const index = (pass_start + scanned) % views.len;
                if (controls[index].reported) continue;
                const view = views[index];
                const offset = &offsets[index];
                if (offset.* == view.body.len) continue;
                if (self.send_connection_window.available() == 0) break;
                const stream_window = try self.sendStreamWindow(
                    view.stream_id,
                );
                const contribution_len = @min(
                    application_chunk_size,
                    view.body.len - offset.*,
                    self.send_connection_window.available(),
                    stream_window.available(),
                );
                if (contribution_len == 0) continue;
                try self.appendBodyBatchContribution(
                    view,
                    offset,
                    contribution_len,
                    frame_limit,
                    stream_window,
                );
                reserved_connection_bytes += contribution_len;
                round_reserved[index] = contribution_len;
                if (offset.* == view.body.len) remaining_streams -= 1;
                made_progress = true;
                next_stream = (index + 1) % views.len;
            }

            if (made_progress) {
                var progress: batch_output.Progress = .{};
                batch_output.parts(self.allocator, self.transportForIo(), self.batch_data_parts.items, &self.write_batch, earliestIndividualBatchDeadline(controls), &progress) catch |err| {
                    wire_write_started = progress.submitted;
                    if (err == error.Timeout and progress.canDiscard(self.transportForIo())) {
                        batch_output.undoRound(self, views, offsets, round_reserved, &remaining_streams, .{ .window = sendStreamWindow });
                        wire_write_started = true;
                        _ = try self.expireIndividualBatchDeadlines(states, controls, observer);
                        continue;
                    }
                    if (progress.submitted) {
                        self.aggregate_timeout_unusable = true;
                        self.terminal_write_failed = true;
                    }
                    return err;
                };
                wire_write_started = true;
                for (views, offsets, states, controls, round_reserved) |
                    view,
                    offset,
                    *state,
                    *control,
                    bytes,
                | {
                    if (bytes == 0 or control.reported or
                        offset != view.body.len) continue;
                    state.request_done = !view.ends_with_trailers;
                    if (state.done and state.request_done) {
                        try self.finishIndividualBatchResponse(
                            state,
                            control,
                            observer,
                        );
                    }
                }
                continue;
            }
            try self.readOneIndividualBatchResponseFrame(
                states,
                controls,
                observer,
                cancellation,
            );
        }
    }

    fn processBodyBatchResponseFrame(
        self: *Connection,
        comptime streaming_response: bool,
        states: []BatchResponseState,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        read_timed_out: *bool,
        adaptive_connection_increment: ?*u31,
        context: anytype,
        comptime consume: anytype,
        frame: http2.Frame,
    ) anyerror!void {
        const state_index = findBatchResponseStateIndex(
            states,
            frame.header.stream_id,
        ) orelse return error.UnexpectedFrame;
        const state = &states[state_index];
        if (state.done) return error.UnexpectedFrame;
        errdefer |err| if (self.serve_read_connection_error == null) {
            const code: ?http2.ErrorCode =
                if (err == error.UnexpectedFrame)
                    .protocol_error
                else
                    responseStreamErrorCode(err);
            if (code) |value| {
                self.recordResponseStreamReadError(
                    state.stream_id,
                    value,
                );
            }
        };

        switch (frame.header.frame_type) {
            .push_promise => {
                if (!self.limits.enable_push) {
                    try self.rejectDisabledPushPromise(frame);
                    unreachable;
                }
                self.receivePushPromiseUntil(frame, deadline) catch |err| {
                    read_timed_out.* =
                        deadline != null and err == error.Timeout;
                    return @errorCast(err);
                };
            },
            .headers => {
                if (state.headers != null) {
                    state.trailers = self.readResponseTrailersUntil(
                        frame,
                        state.forbids_body,
                        deadline,
                    ) catch |err| {
                        read_timed_out.* =
                            deadline != null and err == error.Timeout;
                        return @errorCast(err);
                    };
                    var trailers_owned = true;
                    errdefer if (trailers_owned) {
                        freeHeaders(self.allocator, state.trailers);
                        state.trailers = &.{};
                    };
                    try validateResponseContentLength(state.content_length, if (streaming_response)
                        state.body_bytes
                    else
                        state.body.items.len, !state.forbids_body);
                    state.done = true;
                    trailers_owned = false;
                    return;
                }

                const headers = self.readHeaderBlockUntil(
                    frame,
                    deadline,
                ) catch |err| {
                    read_timed_out.* =
                        deadline != null and err == error.Timeout;
                    return @errorCast(err);
                };
                var headers_owned_by_state = false;
                errdefer if (!headers_owned_by_state) {
                    freeHeaders(self.allocator, headers);
                };
                try validateHeaderBlock(headers, .response);
                const lookup = try responseHeaderLookup(headers);
                const status_text = lookup.status orelse
                    return error.MissingPseudoHeader;
                const status = std.fmt.parseInt(
                    u16,
                    status_text,
                    10,
                ) catch return error.InvalidStatus;
                if (informationalResponseToSkip(status)) {
                    if ((frame.header.flags & flag_end_stream) != 0 or
                        lookup.content_length != null)
                    {
                        return error.InvalidContentLength;
                    }
                    try countInformationalResponse(
                        &state.informational_count,
                        self.limits.max_informational_responses,
                    );
                    if (informational) |observer| {
                        try self.beginBorrowedReadCallback();
                        defer self.endBorrowedReadCallback();
                        observer.on_response(
                            observer.context,
                            state_index,
                            state.stream_id,
                            .{ .headers = headers, .status = status },
                        );
                    }
                    freeHeaders(self.allocator, headers);
                    return;
                }

                state.headers = headers;
                headers_owned_by_state = true;
                state.status = status;
                state.content_length = lookup.content_length;
                state.forbids_body = responseForbidsBody(
                    status,
                    state.request_method,
                    state.extended_connect,
                );
                if (!state.forbids_body and (lookup.content_length orelse 0) > self.limits.max_body_bytes) {
                    return error.MessageTooLarge;
                }
                if (state.forbids_body) {
                    const traditional_connect =
                        methodIsConnect(state.request_method) and
                        !state.extended_connect;
                    if (traditional_connect and
                        (lookup.content_length orelse 0) != 0)
                    {
                        return error.InvalidContentLength;
                    }
                    if ((statusIsInformational(status) or status == 204) and
                        lookup.content_length != null)
                    {
                        return error.InvalidContentLength;
                    }
                } else if (!streaming_response) {
                    if (lookup.content_length) |body_len| {
                        try state.body.ensureTotalCapacityPrecise(
                            self.allocator,
                            body_len,
                        );
                        state.body_capacity_exact = true;
                    }
                }
                if ((frame.header.flags & flag_end_stream) != 0) {
                    try validateResponseContentLength(state.content_length, 0, !state.forbids_body);
                    state.done = true;
                    return;
                }
            },
            .data => {
                if (state.headers == null) return error.UnexpectedFrame;
                const data = try self.receiveDataPayload(
                    state.stream_id,
                    frame,
                );
                defer self.releaseDataFrameBudget(data);
                if (adaptive_connection_increment) |increment| increment.* = data.adaptive_connection_increment;
                const body_len = checkedResponseBodyLength(
                    state.content_length,
                    if (streaming_response)
                        state.body_bytes
                    else
                        state.body.items.len,
                    data.data.len,
                    self.limits.max_body_bytes,
                    !state.forbids_body,
                    (frame.header.flags & flag_end_stream) != 0,
                ) catch |err| {
                    self.releaseConnectionCapacity(frame.payload.len) catch {};
                    return @errorCast(err);
                };
                if (streaming_response) {
                    state.body_bytes = body_len;
                    if (data.data.len != 0) {
                        try self.beginBorrowedReadCallback();
                        defer self.endBorrowedReadCallback();
                        consume(context, state_index, data.data) catch |err| {
                            self.releaseConnectionCapacity(
                                frame.payload.len,
                            ) catch {};
                            if ((frame.header.flags & flag_end_stream) != 0) {
                                state.done = true;
                            }
                            return @errorCast(err);
                        };
                    }
                } else {
                    try state.body.appendSlice(self.allocator, data.data);
                }
                try self.releaseReceivedDataCapacityUntil(
                    state.stream_id,
                    data,
                    (frame.header.flags & flag_end_stream) != 0,
                    deadline,
                );
                if ((frame.header.flags & flag_end_stream) != 0) {
                    state.done = true;
                    return;
                }
            },
            .rst_stream => {
                const reset = try http2.ResetStreamPayload.parse(frame);
                try self.recordResetStream(reset);
                state.request_done = true;
                state.done = true;
                return error.StreamReset;
            },
            else => return error.UnexpectedFrame,
        }
    }

    const BatchDataView = struct {
        stream_id: u31,
        body: []const u8,
        ends_with_trailers: bool = false,
    };

    fn responseBatchSelection(
        self: *const Connection,
        views: []const BatchDataView,
        offsets: []const usize,
        candidates: []response_scheduler.Candidate,
    ) ?response_scheduler.Selection {
        std.debug.assert(views.len == offsets.len);
        std.debug.assert(views.len == candidates.len);
        for (views, offsets, candidates) |view, offset, *candidate| {
            candidate.* = .{
                .stream_id = view.stream_id,
                .remaining = view.body.len - offset,
                .send_capacity = self.sendStreamWindowAvailable(
                    view.stream_id,
                ),
                .priority = self.responsePriority(view.stream_id),
            };
        }
        return response_scheduler.select(candidates);
    }

    fn prepareBodyBatchData(
        self: *Connection,
        views: []const BatchDataView,
        application_chunk_size: usize,
    ) Error!void {
        const frame_limit = self.outboundFramePayloadLimit();
        var max_body_len: usize = 0;
        for (views) |view| max_body_len = @max(max_body_len, view.body.len);
        self.batch_data_headers.clearRetainingCapacity();
        self.batch_data_parts.clearRetainingCapacity();
        if (max_body_len == 0) return;

        // A caller may use an arbitrarily large application contribution to
        // mean "all remaining bytes". Cap scratch sizing at the largest
        // actual body instead of reserving for frames that cannot be emitted.
        const per_round_frames = std.math.divCeil(
            usize,
            @min(application_chunk_size, max_body_len),
            frame_limit,
        ) catch return error.MessageTooLarge;
        const header_capacity = std.math.mul(
            usize,
            views.len,
            per_round_frames,
        ) catch return error.MessageTooLarge;
        try self.batch_data_headers.ensureTotalCapacity(
            self.allocator,
            header_capacity,
        );
        const parts_capacity = std.math.mul(
            usize,
            header_capacity,
            2,
        ) catch return error.MessageTooLarge;
        try self.batch_data_parts.ensureTotalCapacity(
            self.allocator,
            parts_capacity,
        );
    }

    fn appendBodylessRequestToBatch(
        self: *Connection,
        options: RequestOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
    ) Error!PendingResponse {
        var request_options = options;
        request_options.authority = self.resolveRequestAuthorityFromHeaders(request_options.authority, request_options.headers);
        const scheme =
            request_options.scheme orelse self.default_scheme orelse "https";

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            7,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);

        const method_is_connect = methodIsConnect(request_options.method);
        const extended_connect = request_options.protocol != null;
        fields.appendAssumeCapacity(.{
            .name = ":method",
            .value = request_options.method,
        });
        if (!method_is_connect or extended_connect) {
            fields.appendAssumeCapacity(.{
                .name = ":path",
                .value = request_options.path,
            });
            fields.appendAssumeCapacity(.{
                .name = ":scheme",
                .value = scheme,
            });
        }
        if (request_options.protocol) |protocol| {
            if (!self.peer_enable_connect_protocol) {
                return error.ExtendedConnectDisabled;
            }
            fields.appendAssumeCapacity(.{
                .name = ":protocol",
                .value = protocol,
            });
        }
        if (request_options.authority) |authority| {
            fields.appendAssumeCapacity(.{
                .name = ":authority",
                .value = authority,
            });
        }
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .request,
        );
        var content_length_buf: [32]u8 = undefined;
        if (requestShouldDefaultContentLength(
            request_options.method,
            fields.items,
            0,
        )) {
            const content_length = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{0},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .request);
        try validateDeclaredRequestLength(fields.items, 0);
        try validateHeaderListSize(
            fields.items,
            self.peer_max_header_list_size,
        );

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            fields.items,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            true,
            self.outboundFramePayloadLimit(),
        );
        return .{
            .stream_id = stream_id,
            .request_method = request_options.method,
            .extended_connect = extended_connect,
        };
    }

    pub fn prepareStagedHpackEncoder(
        self: *Connection,
    ) Error!*http2.Hpack.Encoder {
        if (self.hpack_encoder_staging) |staging| {
            try staging.copyFromRetainingCapacity(
                self.allocator,
                &self.hpack_encoder,
            );
            return staging;
        }

        const staging = try self.allocator.create(http2.Hpack.Encoder);
        staging.* = .{};
        errdefer {
            staging.deinit(self.allocator);
            self.allocator.destroy(staging);
        }
        try staging.copyFromRetainingCapacity(
            self.allocator,
            &self.hpack_encoder,
        );
        self.hpack_encoder_staging = staging;
        return staging;
    }

    fn commitStagedHpackEncoder(self: *Connection) void {
        const staging = self.hpack_encoder_staging orelse unreachable;
        std.mem.swap(
            http2.Hpack.Encoder,
            &self.hpack_encoder,
            staging,
        );
    }

    pub fn deinitStagedHpackEncoder(self: *Connection) void {
        if (self.hpack_encoder_staging) |staging| {
            staging.deinit(self.allocator);
            self.allocator.destroy(staging);
            self.hpack_encoder_staging = null;
        }
    }

    pub const BatchResponseState = struct {
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        headers: ?[]http2.Hpack.HeaderField = null,
        status: ?u16 = null,
        content_length: ?usize = null,
        body: std.ArrayList(u8) = .empty,
        body_owned: ?[]u8 = null,
        body_capacity_exact: bool = false,
        trailers: []http2.Hpack.HeaderField = &.{},
        forbids_body: bool = false,
        done: bool = false,
        body_bytes: usize = 0,
        informational_count: usize = 0,
        request_done: bool = true,

        pub fn deinit(
            self: *BatchResponseState,
            allocator: std.mem.Allocator,
        ) void {
            if (self.headers) |headers| freeHeaders(allocator, headers);
            freeHeaders(allocator, self.trailers);
            if (self.body_owned) |body| {
                allocator.free(body);
            } else {
                self.body.deinit(allocator);
            }
            self.* = undefined;
        }
    };

    const IndividualBatchControl = struct {
        request_index: usize,
        deadline: ?std.Io.Clock.Timestamp,
        reported: bool = false,
        terminate_requested: bool = false,
        unreleased_connection_bytes: usize = 0,
    };

    const IndividualBatchObserver = union(enum) {
        owned: BatchOwnedResponseObserver,
        streaming: BatchStreamingResponseObserver,

        fn isStreaming(self: IndividualBatchObserver) bool {
            return switch (self) {
                .owned => false,
                .streaming => true,
            };
        }

        fn reportError(
            self: IndividualBatchObserver,
            request_index: usize,
            err: anyerror,
        ) void {
            switch (self) {
                .owned => |observer| observer.on_result(
                    observer.context,
                    request_index,
                    .{ .err = err },
                ),
                .streaming => |observer| observer.on_result(
                    observer.context,
                    request_index,
                    .{ .err = err },
                ),
            }
        }

        fn notifyHead(
            self: IndividualBatchObserver,
            request_index: usize,
            head: StreamingResponseHead,
        ) anyerror!void {
            switch (self) {
                .owned => {},
                .streaming => |observer| if (observer.on_head) |on_head| {
                    try on_head(observer.context, request_index, head);
                },
            }
        }

        fn notifyData(
            self: IndividualBatchObserver,
            request_index: usize,
            data: []const u8,
        ) anyerror!void {
            switch (self) {
                .owned => unreachable,
                .streaming => |observer| try observer.on_data(
                    observer.context,
                    request_index,
                    data,
                ),
            }
        }

        pub fn finish(
            self: IndividualBatchObserver,
            connection: *Connection,
            state: *BatchResponseState,
            control: *IndividualBatchControl,
        ) Error!void {
            std.debug.assert(state.done);
            std.debug.assert(!control.reported);
            switch (self) {
                .owned => |observer| {
                    state.body_owned = if (state.body_capacity_exact)
                        state.body.toOwnedSliceAssert()
                    else
                        try state.body.toOwnedSlice(connection.allocator);
                    const response: OwnedResponse = .{
                        .headers = state.headers.?,
                        .status = state.status.?,
                        .body = state.body_owned.?,
                        .body_allowed = !state.forbids_body,
                        .trailers = state.trailers,
                    };
                    state.headers = null;
                    state.body_owned = null;
                    state.trailers = &.{};
                    control.reported = true;
                    connection.releaseLocalStream(state.stream_id);
                    observer.on_result(
                        observer.context,
                        control.request_index,
                        .{ .response = response },
                    );
                },
                .streaming => |observer| {
                    const response: StreamingResponse = .{
                        .headers = state.headers.?,
                        .status = state.status.?,
                        .body_bytes = state.body_bytes,
                        .trailers = state.trailers,
                    };
                    state.headers = null;
                    state.trailers = &.{};
                    control.reported = true;
                    connection.releaseLocalStream(state.stream_id);
                    observer.on_result(
                        observer.context,
                        control.request_index,
                        .{ .response = response },
                    );
                },
            }
        }
    };

    fn reportIndividualBatchError(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        err: anyerror,
    ) void {
        for (states, controls) |*state, *control| {
            if (control.reported) continue;
            state.done = true;
            state.request_done = true;
            control.reported = true;
            self.releaseLocalStream(state.stream_id);
            self.releasePeerStream(state.stream_id);
            self.forgetStreamWindows(state.stream_id);
            observer.reportError(control.request_index, err);
        }
    }

    fn abortIndividualResponseBatch(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        err: anyerror,
    ) void {
        if (self.serve_read_connection_error != null and !self.terminal_write_failed) {
            self.sendServeReadError(err);
        }
        var unreleased: usize = 0;
        for (controls) |control| {
            if (!control.reported) {
                unreleased = std.math.add(
                    usize,
                    unreleased,
                    control.unreleased_connection_bytes,
                ) catch std.math.maxInt(usize);
            }
        }
        const before = response_cleanup.cleanupDeadline(self, null);
        if (!self.aggregate_timeout_unusable and unreleased != 0) {
            if (before) |absolute| self.releaseConnectionCapacityUntil(unreleased, absolute) catch {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
            } else {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
            }
        }
        if (!self.aggregate_timeout_unusable) self.writeBatchResponseResetsBefore(states, before) catch {};
        self.reportIndividualBatchError(states, controls, observer, err);
    }

    fn finishIndividualBatchResponse(
        self: *Connection,
        state: *BatchResponseState,
        control: *IndividualBatchControl,
        observer: IndividualBatchObserver,
    ) Error!void {
        return observer.finish(self, state, control);
    }

    fn failIndividualStreamingCallback(
        self: *Connection,
        states: []BatchResponseState,
        state_index: usize,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        err: anyerror,
    ) Error!void {
        const state = &states[state_index];
        const control = &controls[state_index];
        if (control.unreleased_connection_bytes != 0) {
            try self.releaseConnectionCapacity(
                control.unreleased_connection_bytes,
            );
            control.unreleased_connection_bytes = 0;
        }
        try self.writeBatchResponseResets(
            states[state_index..][0..1],
        );
        self.releaseLocalStream(state.stream_id);
        self.releasePeerStream(state.stream_id);
        self.forgetStreamWindows(state.stream_id);
        state.done = true;
        state.request_done = true;
        control.reported = true;
        observer.reportError(control.request_index, err);
    }

    fn expireIndividualBatchDeadlines(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
    ) Error!bool {
        const now_ns = std.Io.Clock.awake.now(self.io).nanoseconds;
        for (controls) |*control| {
            if (control.reported) continue;
            const deadline = control.deadline orelse continue;
            if (deadline.raw.nanoseconds <= now_ns) {
                control.terminate_requested = true;
            }
        }
        return self.finishTerminatedIndividualBatch(
            states,
            controls,
            observer,
            error.Timeout,
        );
    }

    fn cancelIndividualBatchRequests(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        cancellation: ?BatchCancellationObserver,
    ) Error!bool {
        const cancel = cancellation orelse return false;
        if (!cancel.event.isSet()) return false;
        for (controls) |*control| {
            if (control.reported) continue;
            if (cancel.take_canceled(
                cancel.context,
                control.request_index,
            )) {
                control.terminate_requested = true;
            }
        }
        cancel.acknowledge(cancel.context);
        return self.finishTerminatedIndividualBatch(
            states,
            controls,
            observer,
            error.Canceled,
        );
    }

    fn finishTerminatedIndividualBatch(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        err: anyerror,
    ) Error!bool {
        var terminate_count: usize = 0;
        var unreleased: usize = 0;
        for (controls) |control| {
            if (control.reported or !control.terminate_requested) continue;
            terminate_count += 1;
            unreleased = std.math.add(
                usize,
                unreleased,
                control.unreleased_connection_bytes,
            ) catch return error.MessageTooLarge;
        }
        if (terminate_count == 0) return false;

        var outer: ?std.Io.Clock.Timestamp = null;
        const now = std.Io.Clock.awake.now(self.io).nanoseconds;
        for (controls) |control| {
            if (control.reported) continue;
            if (control.deadline) |absolute| if (absolute.raw.nanoseconds > now) {
                outer = deadline_policy.earlier(outer, absolute);
            };
        }
        const before = response_cleanup.cleanupDeadline(self, outer);
        if (before == null) {
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return error.Timeout;
        }
        if (unreleased != 0) {
            self.releaseConnectionCapacityUntil(unreleased, before) catch |failure| {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                return failure;
            };
        }
        try self.prepareLocallyResetStreams(terminate_count);
        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        for (states, controls) |state, control| {
            if (control.reported or !control.terminate_requested) continue;
            try http2.ResetStreamPayload.write(
                batch,
                self.allocator,
                state.stream_id,
                .cancel,
            );
        }
        var progress: batch_output.Progress = .{};
        batch_output.bytes(self.transportForIo(), batch.items, before, &progress) catch |wire_err| {
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return wire_err;
        };
        for (states, controls) |*state, *control| {
            if (control.reported or !control.terminate_requested) continue;
            control.unreleased_connection_bytes = 0;
            control.terminate_requested = false;
            self.rememberLocallyResetStreamAssumeCapacity(state.stream_id);
            self.releaseLocalStream(state.stream_id);
            self.releasePeerStream(state.stream_id);
            self.forgetStreamWindows(state.stream_id);
            state.done = true;
            state.request_done = true;
            control.reported = true;
            observer.reportError(control.request_index, err);
        }
        return true;
    }

    fn earliestIndividualBatchDeadline(
        controls: []const IndividualBatchControl,
    ) ?std.Io.Clock.Timestamp {
        var earliest: ?std.Io.Clock.Timestamp = null;
        for (controls) |control| {
            if (control.reported) continue;
            earliest = deadline_policy.earlier(earliest, control.deadline);
        }
        return earliest;
    }

    fn readOneIndividualBatchResponseFrame(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        cancellation: ?BatchCancellationObserver,
    ) anyerror!void {
        const deadline = earliestIndividualBatchDeadline(controls);
        var push_generation = self.pushedCreditGeneration();
        defer self.synchronizePushedCredit(controls, &push_generation);
        const read_result: InterruptibleFrameRead = if (cancellation) |cancel|
            self.readBufferedFrameWithDeadlineOrWake(
                deadline,
                cancel.event,
            ) catch |err| switch (err) {
                error.Timeout => return,
                else => |other| return other,
            }
        else
            .{ .frame = (self.readBufferedFrameWithDeadline(
                deadline,
            ) catch |err| switch (err) {
                error.Timeout => return,
                else => |other| return other,
            }) };
        self.synchronizePushedCredit(controls, &push_generation);
        const frame = switch (read_result) {
            .frame => |borrowed| borrowed.frame,
            .wake => return,
        };
        if (try self.handleConnectionFrameUntil(frame, deadline)) return;
        if (frame.header.frame_type == .goaway) {
            try self.recordPeerGoAway(
                try http2.GoAwayPayload.parse(frame),
            );
            return error.ConnectionGoAway;
        }

        const state_index = findBatchResponseStateIndex(
            states,
            frame.header.stream_id,
        ) orelse return error.UnexpectedFrame;
        const state = &states[state_index];
        const control = &controls[state_index];
        if (control.reported) {
            if (frame.header.frame_type == .rst_stream) {
                try self.recordResetStream(
                    try http2.ResetStreamPayload.parse(frame),
                );
                return;
            }
            return error.UnexpectedFrame;
        }

        const connection_before = self.recv_connection_window.value;
        var adaptive_connection_increment: u31 = 0;
        var read_timed_out = false;
        const had_final_head = state.headers != null;
        var callback_error: ?anyerror = null;
        const DataContext = struct {
            observer: IndividualBatchObserver,
            request_index: usize,
            callback_error: *?anyerror,

            fn consume(
                context: *@This(),
                _: usize,
                data: []const u8,
            ) anyerror!void {
                context.observer.notifyData(
                    context.request_index,
                    data,
                ) catch |err| {
                    context.callback_error.* = err;
                    return err;
                };
            }
        };
        var data_context: DataContext = .{
            .observer = observer,
            .request_index = control.request_index,
            .callback_error = &callback_error,
        };
        const process_result = switch (observer) {
            .owned => self.processBodyBatchResponseFrame(
                false,
                states,
                null,
                deadline,
                &read_timed_out,
                &adaptive_connection_increment,
                {},
                undefined,
                frame,
            ),
            .streaming => self.processBodyBatchResponseFrame(
                true,
                states,
                null,
                deadline,
                &read_timed_out,
                &adaptive_connection_increment,
                &data_context,
                DataContext.consume,
                frame,
            ),
        };
        if (push_generation == self.pushedCreditGeneration()) {
            try flow_credit.account(
                controls,
                state_index,
                connection_before,
                self.recv_connection_window.value,
                adaptive_connection_increment,
            );
        } else self.synchronizePushedCredit(controls, &push_generation);
        process_result catch |err| {
            if (callback_error) |application_error| {
                try self.failIndividualStreamingCallback(
                    states,
                    state_index,
                    controls,
                    observer,
                    application_error,
                );
                return;
            }
            if (err == error.Timeout) {
                // A HEADERS/CONTINUATION sequence is connection-serial. If it
                // stalls across the earliest member deadline, no sibling frame
                // can legally make progress until the block finishes.
                self.aggregate_timeout_unusable = true;
                return error.Timeout;
            }
            if (err == error.StreamReset) {
                if (control.unreleased_connection_bytes != 0) {
                    try self.releaseConnectionCapacity(
                        control.unreleased_connection_bytes,
                    );
                    control.unreleased_connection_bytes = 0;
                }
                state.done = true;
                state.request_done = true;
                control.reported = true;
                observer.reportError(control.request_index, error.StreamReset);
                return;
            }
            if (self.serve_read_connection_error != null or
                self.aggregate_timeout_unusable)
            {
                return @errorCast(err);
            }
            if (self.serve_read_stream_error) |stream_error| {
                if (stream_error.stream_id == state.stream_id) {
                    if (control.unreleased_connection_bytes != 0) {
                        try self.releaseConnectionCapacity(
                            control.unreleased_connection_bytes,
                        );
                        control.unreleased_connection_bytes = 0;
                    }
                    try self.writeLocalErrorResetStream(
                        state.stream_id,
                        stream_error.code,
                    );
                    self.releaseLocalStream(state.stream_id);
                    self.releasePeerStream(state.stream_id);
                    self.forgetStreamWindows(state.stream_id);
                    self.serve_read_stream_error = null;
                    state.done = true;
                    state.request_done = true;
                    control.reported = true;
                    observer.reportError(control.request_index, err);
                    return;
                }
            }
            return @errorCast(err);
        };
        if (observer.isStreaming() and !had_final_head and
            state.headers != null)
        {
            self.beginBorrowedReadCallback() catch |err| {
                return @errorCast(err);
            };
            const head_result = observer.notifyHead(
                control.request_index,
                .{
                    .headers = state.headers.?,
                    .status = state.status.?,
                    .body_allowed = !state.forbids_body,
                },
            );
            self.endBorrowedReadCallback();
            head_result catch |err| {
                try self.failIndividualStreamingCallback(
                    states,
                    state_index,
                    controls,
                    observer,
                    err,
                );
                return;
            };
        }
        if (state.done and state.request_done) {
            try self.finishIndividualBatchResponse(
                state,
                control,
                observer,
            );
        }
    }

    fn readResponseBatchWithPerStreamDeadlines(
        self: *Connection,
        states: []BatchResponseState,
        controls: []IndividualBatchControl,
        observer: IndividualBatchObserver,
        cancellation: ?BatchCancellationObserver,
    ) anyerror!void {
        while (true) {
            var unfinished: usize = 0;
            for (controls) |control| {
                unfinished += @intFromBool(!control.reported);
            }
            if (unfinished == 0) return;

            if (try self.cancelIndividualBatchRequests(
                states,
                controls,
                observer,
                cancellation,
            )) {
                continue;
            }
            if (try self.expireIndividualBatchDeadlines(
                states,
                controls,
                observer,
            )) {
                continue;
            }
            try self.readOneIndividualBatchResponseFrame(
                states,
                controls,
                observer,
                cancellation,
            );
        }
    }

    pub fn readResponseBatch(
        self: *Connection,
        states: []BatchResponseState,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        var current_stream_id: ?u31 = null;
        errdefer |err| if (self.serve_read_connection_error == null) {
            if (current_stream_id) |stream_id| {
                const code: ?http2.ErrorCode =
                    if (err == error.UnexpectedFrame)
                        .protocol_error
                    else
                        responseStreamErrorCode(err);
                if (code) |value| {
                    self.recordResponseStreamReadError(stream_id, value);
                }
            }
        };
        var remaining: usize = 0;
        for (states) |state| remaining += @intFromBool(!state.done);
        while (remaining != 0) {
            current_stream_id = null;
            const frame = (try self.readBufferedFrameWithDeadline(deadline)).frame;
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                try self.recordPeerGoAway(goaway);
                for (states) |state| {
                    if (!state.done and state.stream_id > goaway.last_stream_id) {
                        return error.ConnectionGoAway;
                    }
                }
                continue;
            }

            const state_index = findBatchResponseStateIndex(
                states,
                frame.header.stream_id,
            ) orelse return error.UnexpectedFrame;
            const state = &states[state_index];
            current_stream_id = state.stream_id;
            if (state.done) return error.UnexpectedFrame;
            switch (frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        try self.rejectDisabledPushPromise(frame);
                        unreachable;
                    }
                    try self.receivePushPromiseUntil(frame, deadline);
                },
                .headers => {
                    if (state.headers != null) {
                        state.trailers = try self.readResponseTrailersUntil(
                            frame,
                            state.forbids_body,
                            deadline,
                        );
                        try validateResponseContentLength(state.content_length, state.body.items.len, !state.forbids_body);
                        state.done = true;
                        remaining -= 1;
                        continue;
                    }

                    const headers = try self.readHeaderBlockUntil(
                        frame,
                        deadline,
                    );
                    var headers_owned_by_state = false;
                    errdefer if (!headers_owned_by_state) {
                        freeHeaders(self.allocator, headers);
                    };
                    try validateHeaderBlock(headers, .response);
                    const lookup = try responseHeaderLookup(headers);
                    const status_text = lookup.status orelse
                        return error.MissingPseudoHeader;
                    const status = std.fmt.parseInt(
                        u16,
                        status_text,
                        10,
                    ) catch return error.InvalidStatus;
                    if (informationalResponseToSkip(status)) {
                        if ((frame.header.flags & flag_end_stream) != 0 or
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                        countInformationalResponse(
                            &state.informational_count,
                            self.limits.max_informational_responses,
                        ) catch {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .enhance_your_calm,
                            );
                            return error.TooManyInformationalResponses;
                        };
                        if (informational) |observer| {
                            try self.beginBorrowedReadCallback();
                            defer self.endBorrowedReadCallback();
                            observer.on_response(
                                observer.context,
                                state_index,
                                state.stream_id,
                                .{ .headers = headers, .status = status },
                            );
                        }
                        freeHeaders(self.allocator, headers);
                        continue;
                    }

                    state.headers = headers;
                    headers_owned_by_state = true;
                    state.status = status;
                    state.content_length = lookup.content_length;
                    state.forbids_body = responseForbidsBody(
                        status,
                        state.request_method,
                        state.extended_connect,
                    );
                    if (state.forbids_body) {
                        const traditional_connect =
                            methodIsConnect(state.request_method) and
                            !state.extended_connect;
                        if (traditional_connect and
                            (lookup.content_length orelse 0) != 0)
                        {
                            return error.InvalidContentLength;
                        }
                        if ((statusIsInformational(status) or status == 204) and
                            lookup.content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                    }
                    if (!state.forbids_body) {
                        if (lookup.content_length) |body_len| {
                            if (body_len > self.limits.max_body_bytes) {
                                return error.MessageTooLarge;
                            }
                            try state.body.ensureTotalCapacityPrecise(
                                self.allocator,
                                body_len,
                            );
                            state.body_capacity_exact = true;
                        }
                    }
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try validateResponseContentLength(state.content_length, 0, !state.forbids_body);
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .data => {
                    if (state.headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        state.stream_id,
                        frame,
                    );
                    defer self.releaseDataFrameBudget(data);
                    _ = checkedResponseBodyLength(
                        state.content_length,
                        state.body.items.len,
                        data.data.len,
                        self.limits.max_body_bytes,
                        !state.forbids_body,
                        (frame.header.flags & flag_end_stream) != 0,
                    ) catch |err| {
                        self.releaseConnectionCapacity(
                            frame.payload.len,
                        ) catch {};
                        return @errorCast(err);
                    };
                    try state.body.appendSlice(self.allocator, data.data);
                    try self.releaseReceivedDataCapacityUntil(
                        state.stream_id,
                        data,
                        (frame.header.flags & flag_end_stream) != 0,
                        deadline,
                    );
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(
                        frame,
                    );
                    try self.recordResetStream(reset);
                    state.done = true;
                    return error.StreamReset;
                },
                else => return error.UnexpectedFrame,
            }
        }

        // Acquire all body ownership before exposing any output element, so an
        // allocation failure leaves cleanup entirely inside the state array.
        for (states) |*state| {
            state.body_owned = if (state.body_capacity_exact)
                state.body.toOwnedSliceAssert()
            else
                try state.body.toOwnedSlice(self.allocator);
        }
    }

    fn readResponseBatchStreaming(
        self: *Connection,
        states: []BatchResponseState,
        informational: ?BatchInformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        read_timed_out: *bool,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        var remaining: usize = 0;
        for (states) |state| remaining += @intFromBool(!state.done);
        while (remaining != 0) {
            const frame = (self.readBufferedFrameWithDeadline(deadline) catch |err| {
                read_timed_out.* = deadline != null and err == error.Timeout;
                return err;
            }).frame;
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                try self.recordPeerGoAway(goaway);
                for (states) |state| {
                    if (!state.done and
                        state.stream_id > goaway.last_stream_id)
                    {
                        return error.ConnectionGoAway;
                    }
                }
                continue;
            }

            const state_index = findBatchResponseStateIndex(
                states,
                frame.header.stream_id,
            ) orelse return error.UnexpectedFrame;
            const state = &states[state_index];
            if (state.done) return error.UnexpectedFrame;
            switch (frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        try self.rejectDisabledPushPromise(frame);
                        unreachable;
                    }
                    self.receivePushPromiseUntil(frame, deadline) catch |err| {
                        read_timed_out.* =
                            deadline != null and err == error.Timeout;
                        return err;
                    };
                },
                .headers => {
                    if (state.headers != null) {
                        state.trailers = self.readResponseTrailersUntil(
                            frame,
                            state.forbids_body,
                            deadline,
                        ) catch |err| {
                            read_timed_out.* =
                                deadline != null and err == error.Timeout;
                            return err;
                        };
                        var trailers_owned = true;
                        errdefer if (trailers_owned) {
                            freeHeaders(self.allocator, state.trailers);
                            state.trailers = &.{};
                        };
                        validateResponseContentLength(state.content_length, state.body_bytes, !state.forbids_body) catch |err| {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .protocol_error,
                            );
                            return err;
                        };
                        state.done = true;
                        remaining -= 1;
                        trailers_owned = false;
                        continue;
                    }

                    const headers = self.readHeaderBlockUntil(
                        frame,
                        deadline,
                    ) catch |err| {
                        read_timed_out.* =
                            deadline != null and err == error.Timeout;
                        return err;
                    };
                    var headers_owned_by_state = false;
                    errdefer if (!headers_owned_by_state) {
                        freeHeaders(self.allocator, headers);
                    };
                    validateHeaderBlock(headers, .response) catch |err| {
                        self.recordResponseStreamReadError(
                            state.stream_id,
                            .protocol_error,
                        );
                        return err;
                    };
                    const lookup = try responseHeaderLookup(headers);
                    const status_text = lookup.status orelse {
                        self.recordResponseStreamReadError(
                            state.stream_id,
                            .protocol_error,
                        );
                        return error.MissingPseudoHeader;
                    };
                    const status = std.fmt.parseInt(
                        u16,
                        status_text,
                        10,
                    ) catch {
                        self.recordResponseStreamReadError(
                            state.stream_id,
                            .protocol_error,
                        );
                        return error.InvalidStatus;
                    };
                    if (informationalResponseToSkip(status)) {
                        if ((frame.header.flags & flag_end_stream) != 0 or
                            lookup.content_length != null)
                        {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .protocol_error,
                            );
                            return error.InvalidContentLength;
                        }
                        countInformationalResponse(
                            &state.informational_count,
                            self.limits.max_informational_responses,
                        ) catch {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .enhance_your_calm,
                            );
                            return error.TooManyInformationalResponses;
                        };
                        if (informational) |observer| {
                            try self.beginBorrowedReadCallback();
                            defer self.endBorrowedReadCallback();
                            observer.on_response(
                                observer.context,
                                state_index,
                                state.stream_id,
                                .{ .headers = headers, .status = status },
                            );
                        }
                        freeHeaders(self.allocator, headers);
                        continue;
                    }

                    state.headers = headers;
                    headers_owned_by_state = true;
                    state.status = status;
                    state.content_length = lookup.content_length;
                    state.forbids_body = responseForbidsBody(
                        status,
                        state.request_method,
                        state.extended_connect,
                    );
                    if (!state.forbids_body and (lookup.content_length orelse 0) > self.limits.max_body_bytes) {
                        self.recordResponseStreamReadError(
                            state.stream_id,
                            .enhance_your_calm,
                        );
                        return error.MessageTooLarge;
                    }
                    if (state.forbids_body) {
                        const traditional_connect =
                            methodIsConnect(state.request_method) and
                            !state.extended_connect;
                        if (traditional_connect and
                            (lookup.content_length orelse 0) != 0)
                        {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .protocol_error,
                            );
                            return error.InvalidContentLength;
                        }
                        if ((statusIsInformational(status) or status == 204) and
                            lookup.content_length != null)
                        {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .protocol_error,
                            );
                            return error.InvalidContentLength;
                        }
                    }
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        validateResponseContentLength(state.content_length, 0, !state.forbids_body) catch |err| {
                            self.recordResponseStreamReadError(
                                state.stream_id,
                                .protocol_error,
                            );
                            return err;
                        };
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .data => {
                    if (state.headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        state.stream_id,
                        frame,
                    );
                    defer self.releaseDataFrameBudget(data);
                    state.body_bytes = checkedResponseBodyLength(
                        state.content_length,
                        state.body_bytes,
                        data.data.len,
                        self.limits.max_body_bytes,
                        !state.forbids_body,
                        (frame.header.flags & flag_end_stream) != 0,
                    ) catch |err| {
                        self.releaseConnectionCapacity(
                            frame.payload.len,
                        ) catch {};
                        self.recordResponseStreamReadError(
                            state.stream_id,
                            responseStreamErrorCode(err).?,
                        );
                        return err;
                    };
                    if (data.data.len != 0) {
                        consume(
                            context,
                            state_index,
                            data.data,
                        ) catch |err| {
                            // Restore exact charged credit before the outer
                            // cleanup cancels every unfinished stream. Relying
                            // on low-watermark updates here would leak usable
                            // connection credit across callback failures. The
                            // doomed stream does not need its credit restored.
                            self.releaseConnectionCapacity(
                                frame.payload.len,
                            ) catch {};
                            // A final DATA already closed the remote half; do
                            // not emit a redundant reset for that stream while
                            // cancelling the rest of the batch.
                            if ((frame.header.flags &
                                flag_end_stream) != 0)
                            {
                                state.done = true;
                            }
                            return err;
                        };
                    }
                    try self.releaseReceivedDataCapacityUntil(
                        state.stream_id,
                        data,
                        (frame.header.flags & flag_end_stream) != 0,
                        deadline,
                    );
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        state.done = true;
                        remaining -= 1;
                    }
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(frame);
                    try self.recordResetStream(reset);
                    state.done = true;
                    return error.StreamReset;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    /// Cancel every unfinished member of a streaming response batch in one
    /// transport write. Application callback failure is a batch-wide abort;
    /// emitting one tiny write per RST_STREAM magnifies syscall and delayed-ACK
    /// cost exactly when the connection is already unwinding an error path.
    pub fn writeBatchResponseResets(
        self: *Connection,
        states: []const BatchResponseState,
    ) Error!void {
        return self.writeBatchResponseResetsBefore(states, response_cleanup.cleanupDeadline(self, null));
    }

    fn writeBatchResponseResetsBefore(self: *Connection, states: []const BatchResponseState, before: ?std.Io.Clock.Timestamp) Error!void {
        if (before) |absolute| return self.writeBatchResponseResetsUntil(states, absolute);
        self.aggregate_timeout_unusable = true;
        self.terminal_write_failed = true;
        for (states) |state| self.forgetStreamWindows(state.stream_id);
    }

    fn writeBatchResponseResetsUntil(
        self: *Connection,
        states: []const BatchResponseState,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.terminal_write_failed) return error.ConnectionClosed;
        if (self.serve_read_connection_error != null) {
            self.sendServeReadError(error.InvalidFrame);
            return;
        }
        var has_local_error_reset = false;
        if (self.serve_read_stream_error) |stream_error| {
            for (states) |state| {
                if ((!state.done or !state.request_done) and
                    state.stream_id == stream_error.stream_id)
                {
                    has_local_error_reset = true;
                    break;
                }
            }
        }
        if (has_local_error_reset) try self.ensureLocalErrorResetBudgetUntil(deadline);
        try self.prepareLocallyResetStreams(states.len);
        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        for (states) |state| {
            if (state.done and state.request_done) continue;
            try http2.ResetStreamPayload.write(
                batch,
                self.allocator,
                state.stream_id,
                if (self.serve_read_stream_error) |stream_error|
                    if (stream_error.stream_id == state.stream_id)
                        stream_error.code
                    else
                        .cancel
                else
                    .cancel,
            );
        }
        if (batch.items.len != 0) {
            var progress: batch_output.Progress = .{};
            batch_output.bytes(self.transportForIo(), batch.items, deadline, &progress) catch |err| {
                // The transport cannot report how much of this RST_STREAM
                // batch reached the peer. Even application-only cancellation
                // therefore leaves the shared frame stream ambiguous.
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                return err;
            };
        }
        if (has_local_error_reset) self.local_error_reset_streams +|= 1;
        for (states) |state| {
            if (!state.done or !state.request_done) {
                self.rememberLocallyResetStreamAssumeCapacity(
                    state.stream_id,
                );
                self.forgetStreamWindows(state.stream_id);
            }
        }
    }

    fn findBatchResponseStateIndex(
        states: []const BatchResponseState,
        stream_id: u31,
    ) ?usize {
        if (states.len == 0 or stream_id < states[0].stream_id) return null;
        const delta = stream_id - states[0].stream_id;
        if ((delta & 1) != 0) return null;
        const index: usize = delta / 2;
        if (index >= states.len or states[index].stream_id != stream_id) {
            return null;
        }
        return index;
    }

    pub fn takePromisedRequest(
        self: *Connection,
    ) ?PromisedRequest {
        return self.push_state.take();
    }

    pub fn readPushedResponse(
        self: *Connection,
        promise: PromisedRequest,
    ) Error!OwnedResponse {
        return self.readPushedResponseBefore(promise, null);
    }

    pub fn readPushedResponseWithDeadline(self: *Connection, promise: PromisedRequest, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!OwnedResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readPushedResponseBefore(promise, deadline);
    }

    pub fn readPushedResponseWithTimeout(self: *Connection, promise: PromisedRequest, timeout: std.Io.Duration) ResponseTimeoutError!OwnedResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readPushedResponseWithDeadline(promise, .fromNow(self.io, .{ .clock = .awake, .raw = timeout }));
    }

    fn readPushedResponseBefore(self: *Connection, promise: PromisedRequest, deadline: ?std.Io.Clock.Timestamp) Error!OwnedResponse {
        return PushLifecycle.read(self, promise, deadline);
    }

    /// Refuses a server push that was announced by PUSH_PROMISE.
    ///
    /// The stream ID remains valid after `takePromisedRequest` transfers the
    /// request headers to the caller. Cancellation consumes that owned request,
    /// emits RST_STREAM(CANCEL), and makes later reads or duplicate cancellation
    /// invalid. The caller must not deinitialize or use `promise` afterward.
    pub fn cancelPush(
        self: *Connection,
        promise: *PromisedRequest,
    ) Error!void {
        return self.cancelPushUntil(promise, null);
    }

    pub fn cancelPushWithDeadline(
        self: *Connection,
        promise: *PromisedRequest,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.cancelPushUntil(promise, absolute);
    }

    pub fn cancelPushWithTimeout(
        self: *Connection,
        promise: *PromisedRequest,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.cancelPushWithDeadline(
            promise,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn cancelPushUntil(
        self: *Connection,
        promise: *PromisedRequest,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.role != .client) return error.UnexpectedFrame;
        const promised_stream_id = promise.promised_stream_id;
        if (!self.push_state.isRemoteReserved(promised_stream_id)) {
            return error.InvalidStreamId;
        }
        if (self.push_state.hasPending(promised_stream_id)) {
            return error.InvalidStreamId;
        }
        errdefer if (self.aggregate_timeout_unusable) {
            self.releasePeerStream(promised_stream_id);
            self.forgetStreamWindows(promised_stream_id);
        };
        try self.prepareLocallyResetStreams(1);
        try PushLifecycle.returnHeldCredit(self, promised_stream_id, 0, null);
        if (self.terminal_write_failed) return error.ConnectionClosed;
        self.writeResetStreamFramePreparedUntil(
            promised_stream_id,
            .cancel,
            deadline,
        ) catch |err| {
            self.terminal_write_failed = true;
            return err;
        };
        _ = self.push_state.cancelRemote(
            self.allocator,
            promised_stream_id,
        );
        self.releasePeerStream(promised_stream_id);
        self.forgetStreamWindows(promised_stream_id);
        promise.deinit(self.allocator);
    }

    pub fn peerOrigins(self: Connection) []const []u8 {
        const origins = self.peer_origins orelse return &.{};
        return origins.items();
    }

    pub fn alternativeServices(
        self: Connection,
    ) []const AlternativeService {
        const services = self.alternative_services orelse return &.{};
        return services.items();
    }

    /// Return the most recent RFC 9218 signal for a request or promised push.
    pub fn peerPriority(
        self: Connection,
        stream_id: u31,
    ) ?http2.ExtensiblePriority {
        const update = self.priority_state.get(stream_id) orelse return null;
        return update.priority();
    }

    pub fn peerPriorityFieldValue(
        self: Connection,
        stream_id: u31,
    ) ?[]const u8 {
        const update = self.priority_state.get(stream_id) orelse return null;
        return update.field_value;
    }

    fn effectiveRequestPriority(
        self: Connection,
        stream_id: u31,
        header_priority: http2.ExtensiblePriority,
    ) http2.ExtensiblePriority {
        return self.peerPriority(stream_id) orelse header_priority;
    }

    /// Send an HTTP/2 PRIORITY_UPDATE after the peer opted into RFC 9218.
    ///
    /// RFC 9218 only permits clients to send this frame. The target may be a
    /// request stream that has not opened yet, but a push target must already
    /// have been promised by the server.
    pub fn sendPriorityUpdate(
        self: *Connection,
        stream_id: u31,
        value: http2.ExtensiblePriority,
    ) Error!void {
        var field_value_buf: [16]u8 = undefined;
        return self.sendPriorityUpdateRawUntil(
            stream_id,
            value.serialize(&field_value_buf),
            null,
        );
    }

    pub fn sendPriorityUpdateWithDeadline(
        self: *Connection,
        stream_id: u31,
        value: http2.ExtensiblePriority,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        var field_value_buf: [16]u8 = undefined;
        return self.sendPriorityUpdateRawUntil(
            stream_id,
            value.serialize(&field_value_buf),
            absolute,
        );
    }

    pub fn sendPriorityUpdateWithTimeout(
        self: *Connection,
        stream_id: u31,
        value: http2.ExtensiblePriority,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPriorityUpdateWithDeadline(
            stream_id,
            value,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Raw variant that preserves extension parameters unknown to Netz.
    pub fn sendPriorityUpdateRaw(
        self: *Connection,
        stream_id: u31,
        field_value: []const u8,
    ) Error!void {
        return self.sendPriorityUpdateRawUntil(
            stream_id,
            field_value,
            null,
        );
    }

    pub fn sendPriorityUpdateRawWithDeadline(
        self: *Connection,
        stream_id: u31,
        field_value: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.sendPriorityUpdateRawUntil(
            stream_id,
            field_value,
            absolute,
        );
    }

    pub fn sendPriorityUpdateRawWithTimeout(
        self: *Connection,
        stream_id: u31,
        field_value: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendPriorityUpdateRawWithDeadline(
            stream_id,
            field_value,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendPriorityUpdateRawUntil(
        self: *Connection,
        stream_id: u31,
        field_value: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .client) return error.UnexpectedFrame;
        if (!self.peer_no_rfc7540_priorities) {
            return error.UnexpectedFrame;
        }
        if (stream_id == 0) return error.InvalidStreamId;
        if (!clientInitiatedStreamId(stream_id) and
            !self.push_state.isRemoteReserved(stream_id) and
            !self.outboundStreamIsActive(stream_id))
        {
            // Even IDs that have not appeared in PUSH_PROMISE are idle push
            // streams, which RFC 9218 explicitly forbids reprioritizing.
            return error.InvalidStreamId;
        }
        const idle_request = clientInitiatedStreamId(stream_id) and
            stream_id >= self.next_client_stream_id and
            !self.outboundStreamIsActive(stream_id);
        const already_reserved =
            self.priority_state.containsIdleRequest(stream_id);
        if (idle_request) {
            try self.priority_state.reserveIdleRequest(
                self.allocator,
                stream_id,
                self.active_local_streams.items.len,
                self.peer_max_concurrent_streams,
                self.limits.max_idle_priority_updates,
            );
        }
        errdefer if (idle_request and !already_reserved) {
            _ = self.priority_state.activateRequest(stream_id);
        };
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.PriorityUpdatePayload.write(
            &encoded,
            self.allocator,
            stream_id,
            field_value,
        );
        try self.writeEncodedControlUntil(encoded.items, deadline);
    }

    /// Read and apply the next peer PRIORITY_UPDATE, skipping ordinary
    /// connection-management frames. Servers can use this when priority
    /// signaling arrives while no request reader is currently pumping frames.
    pub fn readPriorityUpdate(
        self: *Connection,
    ) Error!http2.PriorityUpdatePayload {
        return self.readPriorityUpdateUntil(null);
    }

    pub fn readPriorityUpdateWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!http2.PriorityUpdatePayload {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readPriorityUpdateUntil(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Wait for one RFC 9218 PRIORITY_UPDATE under an absolute deadline.
    /// Connection-control frames may be processed along the way, but none of
    /// them renews the caller's budget and partial frame bytes remain buffered.
    pub fn readPriorityUpdateWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!http2.PriorityUpdatePayload {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readPriorityUpdateUntil(deadline);
    }

    fn readPriorityUpdateUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!http2.PriorityUpdatePayload {
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type == .priority_update) {
                const update =
                    try http2.PriorityUpdatePayload.parse(frame.frame);
                if (!try self.handleConnectionFrameUntil(frame.frame, deadline)) {
                    return error.UnexpectedFrame;
                }
                if (self.peerPriorityFieldValue(
                    update.prioritized_stream_id,
                )) |owned| {
                    return .{
                        .prioritized_stream_id = update.prioritized_stream_id,
                        .field_value = owned,
                    };
                }
                continue;
            }
            if (try self.handleConnectionOrGoAwayFrameUntil(frame.frame, deadline)) {
                continue;
            }
            return error.UnexpectedFrame;
        }
    }

    pub fn openConnectUdp(
        self: *Connection,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        path_storage: []u8,
    ) Error!ConnectUdpSession {
        return self.openConnectUdpUntil(
            template,
            target,
            variables,
            path_storage,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn openConnectUdpWithTimeout(
        self: *Connection,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        path_storage: []u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ConnectUdpSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openConnectUdpWithDeadline(
            template,
            target,
            variables,
            path_storage,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn openConnectUdpWithDeadline(
        self: *Connection,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        path_storage: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ConnectUdpSession {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.openConnectUdpUntil(
            template,
            target,
            variables,
            path_storage,
            deadline,
        );
    }

    fn openConnectUdpUntil(
        self: *Connection,
        template: http3.connect_udp.UriTemplate,
        target: http3.connect_udp.Target,
        variables: []const http3.connect_udp.Variable,
        path_storage: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ConnectUdpSession {
        try target.validate();
        if (!std.mem.eql(u8, template.scheme, "https")) {
            return error.InvalidUriTemplate;
        }
        const request_path = try template.expandRequestTargetInto(
            path_storage,
            target.host,
            target.port,
            variables,
        );
        const headers = [_]http2.Hpack.HeaderField{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        var response = if (deadline) |absolute|
            try self.openExtendedConnectWithDeadline(.{
                .method = "CONNECT",
                .path = request_path,
                .scheme = template.scheme,
                .protocol = http3.connect_udp.protocol,
                .authority = template.authority,
                .headers = &headers,
            }, absolute)
        else
            try self.openExtendedConnect(.{
                .method = "CONNECT",
                .path = request_path,
                .scheme = template.scheme,
                .protocol = http3.connect_udp.protocol,
                .authority = template.authority,
                .headers = &headers,
            });
        var response_owned = true;
        defer if (response_owned) response.deinit(self.allocator);
        http3.connect_udp.validateResponseHead(
            response.status,
            response.headers,
        ) catch |err| {
            response.tunnel.abort(deadline);
            return err;
        };
        const tunnel = response.tunnel;
        response.deinit(self.allocator);
        response_owned = false;
        return ConnectUdpSession.init(
            self.allocator,
            self.io,
            tunnel,
            .{},
        );
    }

    pub fn openConnectIp(
        self: *Connection,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        path_storage: []u8,
    ) Error!ConnectIpSession {
        return self.openConnectIpUntil(
            template,
            scope,
            variables,
            path_storage,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn openConnectIpWithTimeout(
        self: *Connection,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        path_storage: []u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ConnectIpSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openConnectIpWithDeadline(
            template,
            scope,
            variables,
            path_storage,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn openConnectIpWithDeadline(
        self: *Connection,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        path_storage: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ConnectIpSession {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.openConnectIpUntil(
            template,
            scope,
            variables,
            path_storage,
            deadline,
        );
    }

    fn openConnectIpUntil(
        self: *Connection,
        template: http3.connect_ip.UriTemplate,
        scope: http3.connect_ip.Scope,
        variables: []const http3.connect_ip.Variable,
        path_storage: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ConnectIpSession {
        if (!self.encryptedTransport()) return error.EncryptionRequired;
        try scope.validate();
        if (!std.mem.eql(u8, template.scheme(), "https")) {
            return error.InvalidUriTemplate;
        }
        const request_path = try template.expandRequestTargetInto(
            path_storage,
            scope,
            variables,
        );
        const headers = [_]http2.Hpack.HeaderField{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        var response = if (deadline) |absolute|
            try self.openExtendedConnectWithDeadline(.{
                .method = "CONNECT",
                .path = request_path,
                .scheme = template.scheme(),
                .protocol = http3.connect_ip.protocol,
                .authority = template.authority(),
                .headers = &headers,
            }, absolute)
        else
            try self.openExtendedConnect(.{
                .method = "CONNECT",
                .path = request_path,
                .scheme = template.scheme(),
                .protocol = http3.connect_ip.protocol,
                .authority = template.authority(),
                .headers = &headers,
            });
        var response_owned = true;
        defer if (response_owned) response.deinit(self.allocator);
        http3.connect_ip.validateResponseHead(
            response.status,
            response.headers,
        ) catch |err| {
            response.tunnel.abort(deadline);
            return err;
        };
        const tunnel = response.tunnel;
        response.deinit(self.allocator);
        response_owned = false;
        return ConnectIpSession.init(self.allocator, self.io, tunnel, .{});
    }

    pub fn openExtendedConnect(self: *Connection, options: RequestOptions) Error!ExtendedConnectResponse {
        var attempt = try self.openExtendedConnectAttemptUntil(options, null);
        errdefer attempt.deinit(self.allocator);
        return attempt.requireAccepted();
    }

    /// Open an Extended CONNECT stream while preserving a final non-2xx
    /// response for application authentication, redirect, or retry policy.
    pub fn openExtendedConnectAttempt(
        self: *Connection,
        options: RequestOptions,
    ) Error!ExtendedConnectAttempt {
        return self.openExtendedConnectAttemptUntil(options, null);
    }

    /// Open an RFC 8441-style Extended CONNECT stream and wait for its final
    /// response under one absolute awake-clock deadline. Informational and
    /// connection-control frames do not renew the caller's budget.
    pub fn openExtendedConnectWithDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectResponse {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var attempt = try self.openExtendedConnectAttemptUntil(
            options,
            deadline,
        );
        errdefer attempt.deinit(self.allocator);
        return attempt.requireAccepted();
    }

    pub fn openExtendedConnectAttemptWithDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectAttempt {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.openExtendedConnectAttemptUntil(options, deadline);
    }

    pub fn openExtendedConnectWithTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ExtendedConnectResponse {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openExtendedConnectWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn openExtendedConnectAttemptWithTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ExtendedConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openExtendedConnectAttemptWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    /// Start an Extended CONNECT whose request and response halves are routed
    /// by the connection's single-owner duplex scheduler. Multiple returned
    /// handles may remain active; one owner must serially pump or poll them.
    pub fn startExtendedConnectDuplex(
        self: *Connection,
        options: RequestOptions,
    ) Error!ClientDuplexStream {
        return self.startExtendedConnectDuplexUntil(options, null);
    }

    pub fn startExtendedConnectDuplexWithDeadline(
        self: *Connection,
        options: RequestOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ClientDuplexStream {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.startExtendedConnectDuplexUntil(options, deadline);
    }

    pub fn startExtendedConnectDuplexWithTimeout(
        self: *Connection,
        options: RequestOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ClientDuplexStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startExtendedConnectDuplexWithDeadline(
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn startExtendedConnectDuplexUntil(
        self: *Connection,
        options: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ClientDuplexStream {
        if ((self.duplex_reader_active and self.duplex_owners.count() == 0) or
            self.callback_reader_active)
        {
            return error.UnexpectedFrame;
        }
        const stream_id = try self.writeExtendedConnectRequestUntil(
            options,
            deadline,
        );
        var stream_owned = true;
        errdefer if (stream_owned) self.releaseLocalStream(stream_id);
        self.duplex_owners.acquire();
        self.duplex_reader_active = true;
        stream_owned = false;
        return .{
            .connection = self,
            .registered = true,
            .stream_id = stream_id,
            .expected_request_length = null,
            .extended_connect = true,
        };
    }

    fn openExtendedConnectAttemptUntil(
        self: *Connection,
        options: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectAttempt {
        const stream_id = try self.writeExtendedConnectRequestUntil(
            options,
            deadline,
        );
        errdefer self.releaseLocalStream(stream_id);
        return self.readExtendedConnectAttemptUntil(stream_id, deadline);
    }

    fn writeExtendedConnectRequestUntil(
        self: *Connection,
        options: RequestOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!u31 {
        if (self.role != .client) return error.UnexpectedFrame;
        var request_options = options;
        request_options.authority = self.resolveRequestAuthorityFromHeaders(
            request_options.authority,
            request_options.headers,
        );
        if (!methodIsConnect(request_options.method)) return error.InvalidHeader;
        const protocol = request_options.protocol orelse return error.InvalidHeader;
        if (!self.peer_enable_connect_protocol) return error.ExtendedConnectDisabled;
        if (request_options.body.len != 0 or request_options.trailers.len != 0) return error.InvalidContentLength;
        const scheme = self.resolveRequestScheme(request_options.scheme);

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            @as(usize, 5) + @intFromBool(request_options.priority != null),
        ) catch return error.MessageTooLarge;
        const fields_buffer = try stackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_capacity,
        );
        defer freeStackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_buffer,
        );
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{ .name = ":method", .value = "CONNECT" });
        fields.appendAssumeCapacity(.{ .name = ":path", .value = request_options.path });
        fields.appendAssumeCapacity(.{ .name = ":scheme", .value = scheme });
        fields.appendAssumeCapacity(.{ .name = ":protocol", .value = protocol });
        if (request_options.authority) |authority| fields.appendAssumeCapacity(.{ .name = ":authority", .value = authority });
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .request,
        );
        try validateHeaderBlock(fields.items, .request);

        const stream_id = try self.reserveNextClientStreamId();
        var stream_owned = true;
        errdefer if (stream_owned) self.releaseLocalStream(stream_id);
        // Extended CONNECT establishes a bidirectional byte tunnel.  The
        // opening HEADERS therefore deliberately keeps the stream open instead
        // of using END_STREAM like a request with no body would.
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.io, absolute);
        }
        try self.writeHeadersUntil(stream_id, fields.items, false, deadline);
        stream_owned = false;
        return stream_id;
    }

    pub fn openConnectTunnel(self: *Connection, options: RequestOptions) Error!ExtendedConnectResponse {
        if (self.role != .client) return error.UnexpectedFrame;
        var request_options = options;
        request_options.authority = self.resolveRequestAuthorityFromHeaders(request_options.authority, request_options.headers);
        if (!methodIsConnect(request_options.method) or request_options.protocol != null) return error.InvalidHeader;
        if (request_options.authority == null) return error.MissingPseudoHeader;
        if (request_options.body.len != 0 or request_options.trailers.len != 0) return error.InvalidContentLength;

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            request_options.headers.len,
            @as(usize, 2) + @intFromBool(request_options.priority != null),
        ) catch return error.MessageTooLarge;
        const fields_buffer = try stackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_capacity,
        );
        defer freeStackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_buffer,
        );
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{ .name = ":method", .value = "CONNECT" });
        fields.appendAssumeCapacity(.{ .name = ":authority", .value = request_options.authority.? });
        var priority_buf: [16]u8 = undefined;
        if (request_options.priority) |value| {
            fields.appendAssumeCapacity(.{
                .name = "priority",
                .value = value.serialize(&priority_buf),
            });
        }
        fields.appendSliceAssumeCapacity(request_options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .request,
        );
        try validateHeaderBlock(fields.items, .request);

        const stream_id = try self.reserveNextClientStreamId();
        errdefer self.releaseLocalStream(stream_id);
        // Traditional HTTP/2 CONNECT also establishes a tunnel on the stream.
        // Keep the request side open so DATA frames can flow immediately after
        // the peer accepts with a 2xx response.
        try self.writeHeaders(stream_id, fields.items, false);
        return self.readExtendedConnectResponse(stream_id);
    }

    pub fn readConnectUdpRequest(
        self: *Connection,
    ) Error!ExtendedConnectRequest {
        var connect_request = try self.readExtendedConnectRequest(
            http3.connect_udp.protocol,
        );
        errdefer connect_request.deinit(self.allocator);
        try http3.connect_udp.validateRequestFields(
            connect_request.method,
            connect_request.path,
            connect_request.scheme,
            connect_request.authority,
            connect_request.headers,
        );
        return connect_request;
    }

    pub fn readConnectUdpRequestWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readConnectUdpRequestWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readConnectUdpRequestWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var connect_request = try self.readExtendedConnectRequestWithDeadline(
            http3.connect_udp.protocol,
            deadline,
        );
        errdefer connect_request.deinit(self.allocator);
        try http3.connect_udp.validateRequestFields(
            connect_request.method,
            connect_request.path,
            connect_request.scheme,
            connect_request.authority,
            connect_request.headers,
        );
        return connect_request;
    }

    pub fn acceptConnectUdpDefault(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        target_host_storage: []u8,
    ) Error!AcceptedConnectUdp {
        const target = try http3.connect_udp.parseDefaultPath(
            connect_request.path,
            target_host_storage,
        );
        return .{
            .target = target,
            .session = try self.acceptConnectUdpForTarget(
                connect_request,
                target,
            ),
        };
    }

    pub fn acceptConnectUdpForTarget(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        target: http3.connect_udp.Target,
    ) Error!ConnectUdpSession {
        try http3.connect_udp.validateRequestFields(
            connect_request.method,
            connect_request.path,
            connect_request.scheme,
            connect_request.authority,
            connect_request.headers,
        );
        try target.validate();
        const response_headers = [_]http2.Hpack.HeaderField{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        const tunnel = try self.acceptExtendedConnect(
            connect_request,
            &response_headers,
        );
        return ConnectUdpSession.init(
            self.allocator,
            self.io,
            tunnel,
            .{},
        );
    }

    pub fn readConnectIpRequest(
        self: *Connection,
    ) Error!ExtendedConnectRequest {
        if (!self.encryptedTransport()) return error.EncryptionRequired;
        var connect_request = try self.readExtendedConnectRequest(
            http3.connect_ip.protocol,
        );
        errdefer connect_request.deinit(self.allocator);
        try http3.connect_ip.validateRequestFields(
            connect_request.method,
            connect_request.path,
            connect_request.scheme,
            connect_request.authority,
            connect_request.headers,
        );
        return connect_request;
    }

    pub fn readConnectIpRequestWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readConnectIpRequestWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readConnectIpRequestWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        if (!self.encryptedTransport()) return error.EncryptionRequired;
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var connect_request = try self.readExtendedConnectRequestWithDeadline(
            http3.connect_ip.protocol,
            deadline,
        );
        errdefer connect_request.deinit(self.allocator);
        try http3.connect_ip.validateRequestFields(
            connect_request.method,
            connect_request.path,
            connect_request.scheme,
            connect_request.authority,
            connect_request.headers,
        );
        return connect_request;
    }

    pub fn acceptConnectIpDefault(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        target_storage: []u8,
    ) Error!AcceptedConnectIp {
        const scope = try http3.connect_ip.parseDefaultPath(
            connect_request.path,
            target_storage,
        );
        return .{
            .scope = scope,
            .session = try self.acceptConnectIpForScope(connect_request, scope),
        };
    }

    pub fn acceptConnectIpForScope(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        scope: http3.connect_ip.Scope,
    ) Error!ConnectIpSession {
        if (!self.encryptedTransport()) return error.EncryptionRequired;
        try http3.connect_ip.validateRequestFields(
            connect_request.method,
            connect_request.path,
            connect_request.scheme,
            connect_request.authority,
            connect_request.headers,
        );
        try scope.validate();
        const response_headers = [_]http2.Hpack.HeaderField{.{
            .name = http3.capsule.header_name,
            .value = http3.capsule.header_value_true,
        }};
        const tunnel = try self.acceptExtendedConnect(
            connect_request,
            &response_headers,
        );
        return ConnectIpSession.init(self.allocator, self.io, tunnel, .{});
    }

    pub fn readExtendedConnectRequest(self: *Connection, expected_protocol: []const u8) Error!ExtendedConnectRequest {
        return self.readExtendedConnectRequestUntil(
            expected_protocol,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn readExtendedConnectRequestWithDeadline(
        self: *Connection,
        expected_protocol: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readExtendedConnectRequestUntil(
            expected_protocol,
            deadline,
        );
    }

    pub fn readExtendedConnectRequestWithTimeout(
        self: *Connection,
        expected_protocol: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readExtendedConnectRequestWithDeadline(
            expected_protocol,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn readExtendedConnectRequestUntil(
        self: *Connection,
        expected_protocol: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectRequest {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (!self.limits.enable_connect_protocol) return error.ExtendedConnectDisabled;
        var active_stream_id: ?u31 = null;
        errdefer |err| if (err == error.Timeout) {
            // A timeout before a complete HEADERS frame is resumable because
            // frame_reader retains its byte progress. Once an Extended
            // CONNECT header block has started, stack-local HPACK assembly is
            // no longer recoverable, so reset that stream and fail closed.
            if (active_stream_id) |stream_id| {
                self.aggregate_timeout_unusable = true;
                self.writeResetStreamFrame(stream_id, .cancel) catch {};
                self.releasePeerStream(stream_id);
                self.forgetStreamWindows(stream_id);
            }
        };
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    const stream_id = frame.frame.header.stream_id;
                    const admission = try self.claimPeerRequestStream(
                        stream_id,
                    );
                    if (admission != .admitted) {
                        try self.refusePeerRequestStreamUntil(
                            stream_id,
                            frame.frame,
                            deadline,
                            admission == .refused_reset_sent,
                        );
                        continue;
                    }
                    errdefer self.releasePeerStream(stream_id);
                    active_stream_id = stream_id;
                    if ((frame.frame.header.flags & flag_end_stream) != 0) return error.ConnectionClosed;

                    const headers = try self.readHeaderBlockUntil(
                        frame.frame,
                        deadline,
                    );
                    errdefer freeHeaders(self.allocator, headers);
                    try validateHeaderBlock(headers, .request);
                    const lookup = try requestHeaderLookup(headers);
                    const method = lookup.method orelse return error.MissingPseudoHeader;
                    const protocol = lookup.protocol orelse return error.InvalidHeader;
                    if (!methodIsConnect(method)) return error.InvalidHeader;
                    if (!std.mem.eql(u8, protocol, expected_protocol)) return error.InvalidHeader;
                    const request_priority =
                        self.effectiveRequestPriority(
                            stream_id,
                            lookup.priority,
                        );
                    try self.rememberResponseSemantics(
                        stream_id,
                        method,
                        protocol,
                        request_priority,
                    );
                    if (deadline) |absolute| {
                        _ = try deadline_policy.usableAwake(
                            self.io,
                            absolute,
                        );
                    }

                    return .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = lookup.path orelse "",
                        .scheme = lookup.scheme orelse "",
                        .authority = lookup.requestAuthority(),
                        .protocol = protocol,
                        .priority = request_priority,
                    };
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    if (self.streamIsIdle(reset.stream_id)) {
                        return error.InvalidFrame;
                    }
                    try self.recordResetStream(reset);
                    continue;
                },
                .goaway => continue,
                else => return error.UnexpectedFrame,
            }
        }
    }

    pub fn acceptExtendedConnect(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!Tunnel {
        return self.acceptExtendedConnectUntil(connect_request, response_headers, null);
    }

    /// Submit the successful response under the handshake's original budget.
    pub fn acceptExtendedConnectWithDeadline(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        response_headers: []const http2.Hpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!Tunnel {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptExtendedConnectUntil(connect_request, response_headers, deadline);
    }

    pub fn acceptExtendedConnectWithTimeout(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        response_headers: []const http2.Hpack.HeaderField,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!Tunnel {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptExtendedConnectWithDeadline(connect_request, response_headers, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn acceptExtendedConnectUntil(
        self: *Connection,
        connect_request: ExtendedConnectRequest,
        response_headers: []const http2.Hpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!Tunnel {
        if (self.role != .server) return error.UnexpectedFrame;
        try self.writeExtendedConnectResponseUntil(connect_request.stream_id, 200, response_headers, false, deadline);
        return .{ .connection = self, .stream_id = connect_request.stream_id };
    }

    pub fn acceptConnectTunnel(
        self: *Connection,
        connect_request: OwnedRequest,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!Tunnel {
        if (self.role != .server) return error.UnexpectedFrame;
        if (!methodIsConnect(connect_request.method) or connect_request.protocol != null) return error.InvalidHeader;
        if (connect_request.body.len != 0 or connect_request.trailers.len != 0) return error.InvalidContentLength;
        try self.writeExtendedConnectResponse(connect_request.stream_id, 200, response_headers, false);
        return .{ .connection = self, .stream_id = connect_request.stream_id };
    }

    pub fn rejectExtendedConnect(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
    ) Error!void {
        return self.rejectExtendedConnectWithBody(
            stream_id,
            status,
            response_headers,
            &.{},
            &.{},
        );
    }

    pub fn rejectExtendedConnectWithDeadline(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        return self.rejectExtendedConnectWithBodyWithDeadline(stream_id, status, response_headers, &.{}, &.{}, deadline);
    }

    pub fn rejectExtendedConnectWithTimeout(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectExtendedConnectWithDeadline(stream_id, status, response_headers, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Reject an Extended CONNECT request with an ordinary HTTP response
    /// entity. After response DATA/trailers FIN, NO_ERROR stops the open
    /// request direction. Late DATA/trailers retain connection credit and
    /// HPACK ordering while sibling requests remain available.
    pub fn rejectExtendedConnectWithBody(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        body: []const u8,
        trailers: []const http2.Hpack.HeaderField,
    ) Error!void {
        return self.rejectExtendedConnectWithBodyUntil(stream_id, status, response_headers, body, trailers, null);
    }

    /// Bound response HEADERS, flow-control waits, DATA and trailers together.
    pub fn rejectExtendedConnectWithBodyWithDeadline(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        body: []const u8,
        trailers: []const http2.Hpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.rejectExtendedConnectWithBodyUntil(stream_id, status, response_headers, body, trailers, deadline);
    }

    pub fn rejectExtendedConnectWithBodyWithTimeout(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        body: []const u8,
        trailers: []const http2.Hpack.HeaderField,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectExtendedConnectWithBodyWithDeadline(stream_id, status, response_headers, body, trailers, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn rejectExtendedConnectWithBodyUntil(
        self: *Connection,
        stream_id: u31,
        status: u16,
        response_headers: []const http2.Hpack.HeaderField,
        body: []const u8,
        trailers: []const http2.Hpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (status < 300 or statusIsInformational(status)) {
            return error.InvalidStatus;
        }
        // RFC 9113 section 8.1 permits NO_ERROR after a complete response to
        // stop an unfinished request. CONNECT has an open request direction;
        // preflight reset history before exposing any response bytes so late
        // DATA/trailers keep their connection-credit and HPACK obligations.
        try self.prepareLocallyResetStreams(1);
        try self.writeResponseInternalUntil(stream_id, .{
            .status = status,
            .headers = response_headers,
            .body = body,
            .trailers = trailers,
            .request_method = "CONNECT",
            .extended_connect = true,
        }, true, deadline);
        try self.writeResetStreamFrameUntil(stream_id, .no_error, deadline);
        self.forgetStreamWindows(stream_id);
    }

    pub fn readRequest(self: *Connection) Error!OwnedRequest {
        var owned_request = self.readRequestUntil(null) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
        owned_request.from = self.peerAddress();
        return owned_request;
    }

    /// Read one complete server request within a relative budget. A timeout
    /// before stream admission preserves the frame reader; after a HEADERS
    /// block is claimed, discarded aggregate state makes the connection
    /// intentionally unusable rather than risking HPACK or DATA desync.
    pub fn readRequestWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) RequestTimeoutError!OwnedRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readRequestWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readRequestWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) RequestTimeoutError!OwnedRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        var owned_request = try self.readRequestUntil(deadline);
        owned_request.from = self.peerAddress();
        return owned_request;
    }

    fn readRequestUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) RequestTimeoutError!OwnedRequest {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.popPendingRequest()) |pending| return pending;
        var active_stream_id: ?u31 = null;
        var cleanup_budget: request_cleanup.Budget = .{};
        errdefer |err| if (self.serve_read_connection_error == null) {
            if (active_stream_id) |stream_id| {
                if (serveRequestStreamErrorCode(err)) |code| {
                    self.serve_read_stream_error = .{
                        .stream_id = stream_id,
                        .code = code,
                    };
                }
            }
        };
        errdefer |err| if (err == error.Timeout or err == error.OutOfMemory) {
            // Request headers/body/trailers are stack-owned during aggregation.
            // Once a stream has been admitted, a retry cannot reconstruct that
            // state, so cancel it and fail the connection closed.
            if (active_stream_id) |stream_id| {
                self.failDiscardedRequestBefore(stream_id, cleanup_budget.get(self, deadline, err == error.Timeout));
            }
        };
        var receive_credit: flow_credit.Tracker = .{};
        errdefer |err| if (active_stream_id != null or receive_credit.unreleased_connection_bytes != 0) {
            self.releaseDiscardedMessageCapacityBefore(receive_credit.unreleased_connection_bytes, cleanup_budget.get(self, deadline, err == error.Timeout));
        };
        while (true) {
            var pending_owned: ?OwnedFrame = null;
            defer if (pending_owned) |*owned| {
                owned.deinit(self.allocator);
            };
            const frame = if (self.pendingApplicationFrameCount() != 0) blk: {
                pending_owned = try self.readOwnedFrameWithDeadline(deadline);
                break :blk pending_owned.?.frame;
            } else (try self.readBufferedFrameWithDeadline(deadline)).frame;
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            switch (frame.header.frame_type) {
                .headers => {
                    const stream_id = frame.header.stream_id;
                    const admission = try self.claimPeerRequestStream(
                        stream_id,
                    );
                    if (admission != .admitted) {
                        try self.refusePeerRequestStreamUntil(
                            stream_id,
                            frame,
                            deadline,
                            admission == .refused_reset_sent,
                        );
                        continue;
                    }
                    errdefer self.releasePeerStream(stream_id);
                    active_stream_id = stream_id;
                    const headers = try self.readHeaderBlockUntil(
                        frame,
                        deadline,
                    );
                    errdefer freeHeaders(self.allocator, headers);
                    try validateHeaderBlock(headers, .request);
                    var trailers: []http2.Hpack.HeaderField = &.{};
                    errdefer freeHeaders(self.allocator, trailers);
                    var body: std.ArrayList(u8) = .empty;
                    errdefer body.deinit(self.allocator);

                    const lookup = try requestHeaderLookup(headers);
                    const method = lookup.method orelse return error.MissingPseudoHeader;
                    const protocol = lookup.protocol;
                    if (protocol != null and !self.limits.enable_connect_protocol) {
                        return error.ExtendedConnectDisabled;
                    }
                    const expected_request_len = lookup.content_length;
                    const is_connect = methodIsConnect(method);
                    const is_extended_connect = is_connect and protocol != null;
                    if (is_connect and !is_extended_connect and (expected_request_len orelse 0) != 0) return error.InvalidContentLength;
                    if (expected_request_len) |body_len| {
                        if (body_len > self.limits.max_body_bytes) {
                            return error.MessageTooLarge;
                        }
                        // The Content-Length has already passed strict header
                        // validation. Reserve the final aggregate once rather
                        // than repeatedly growing while DATA frames arrive.
                        try body.ensureTotalCapacityPrecise(
                            self.allocator,
                            body_len,
                        );
                    }

                    // RFC 9110 10.1.1: release an expecting peer before the
                    // first request DATA frame is consumed. END_STREAM means
                    // there is no body to wait for, so no interim head is sent.
                    if (lookup.expects_continue and
                        (!is_connect or is_extended_connect) and
                        (frame.header.flags & flag_end_stream) == 0)
                    {
                        if (deadline) |absolute| {
                            try self.writeInformationalResponseWithDeadline(
                                stream_id,
                                100,
                                &.{},
                                absolute,
                            );
                        } else {
                            try self.writeInformationalResponse(
                                stream_id,
                                100,
                                &.{},
                            );
                        }
                    }

                    if ((!is_connect or is_extended_connect) and (frame.header.flags & flag_end_stream) == 0) {
                        while (true) {
                            var incoming = try self.readRequestBodyFrameUntil(
                                stream_id,
                                &body,
                                expected_request_len,
                                deadline,
                                &receive_credit,
                                &cleanup_budget,
                            );
                            switch (incoming) {
                                .direct_data => |end_stream| {
                                    if (end_stream) break;
                                    continue;
                                },
                                .owned_frame => |*owned| {
                                    defer owned.deinit(self.allocator);
                                    if (try self.handleConnectionFrameUntil(
                                        owned.frame,
                                        deadline,
                                    )) continue;
                                    if (owned.frame.header.stream_id !=
                                        stream_id)
                                    {
                                        if (owned.frame.header.frame_type ==
                                            .rst_stream)
                                        {
                                            const reset = try http2.ResetStreamPayload.parse(
                                                owned.frame,
                                            );
                                            if (self.streamIsIdle(
                                                reset.stream_id,
                                            )) {
                                                return error.InvalidFrame;
                                            }
                                            try self.recordResetStream(reset);
                                            continue;
                                        }
                                        if (try self.queueCompletePeerRequestFrameUntil(
                                            owned.frame,
                                            deadline,
                                            &cleanup_budget,
                                        )) continue;
                                        return error.UnexpectedFrame;
                                    }
                                    switch (owned.frame.header.frame_type) {
                                        .data => {
                                            const connection_before = self.recv_connection_window.value;
                                            const data =
                                                try self.receiveDataPayload(
                                                    stream_id,
                                                    owned.frame,
                                                );
                                            defer receive_credit.observe(connection_before, self.recv_connection_window.value, data.adaptive_connection_increment);
                                            defer self.releaseDataFrameBudget(data);
                                            _ = checkedBodyLength(
                                                expected_request_len,
                                                body.items.len,
                                                data.data.len,
                                                self.limits.max_body_bytes,
                                                (owned.frame.header.flags & flag_end_stream) != 0,
                                            ) catch |err| {
                                                self.releaseDiscardedMessageCapacityBefore(owned.frame.payload.len, cleanup_budget.get(self, deadline, false));
                                                return @errorCast(err);
                                            };
                                            try body.appendSlice(
                                                self.allocator,
                                                data.data,
                                            );
                                            try self.releaseReceivedDataCapacityUntil(
                                                stream_id,
                                                data,
                                                (owned.frame.header.flags &
                                                    flag_end_stream) != 0,
                                                deadline,
                                            );
                                            if ((owned.frame.header.flags &
                                                flag_end_stream) != 0) break;
                                        },
                                        .headers => {
                                            if ((owned.frame.header.flags &
                                                flag_end_stream) == 0)
                                            {
                                                return error.UnexpectedFrame;
                                            }
                                            trailers =
                                                try self.readHeaderBlockUntil(
                                                    owned.frame,
                                                    deadline,
                                                );
                                            try validateHeaderBlock(
                                                trailers,
                                                .request_trailers,
                                            );
                                            try validateExpectedContentLength(
                                                lookup.content_length,
                                                body.items.len,
                                            );
                                            break;
                                        },
                                        .rst_stream => {
                                            const reset = try http2.ResetStreamPayload.parse(
                                                owned.frame,
                                            );
                                            try self.recordResetStream(reset);
                                            return error.StreamReset;
                                        },
                                        else => return error.UnexpectedFrame,
                                    }
                                },
                            }
                        }
                    }

                    try validateExpectedContentLength(lookup.content_length, body.items.len);
                    const request_priority =
                        self.effectiveRequestPriority(
                            stream_id,
                            lookup.priority,
                        );
                    try self.rememberResponseSemantics(
                        stream_id,
                        method,
                        protocol,
                        request_priority,
                    );
                    const owned_body = if (expected_request_len != null)
                        body.toOwnedSliceAssert()
                    else
                        try body.toOwnedSlice(self.allocator);
                    return .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = lookup.path orelse "",
                        .scheme = lookup.scheme orelse "",
                        .authority = lookup.requestAuthority(),
                        .protocol = protocol,
                        .body = owned_body,
                        .trailers = trailers,
                        .priority = request_priority,
                    };
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(
                        frame,
                    );
                    if (self.streamIsIdle(reset.stream_id)) {
                        return error.InvalidFrame;
                    }
                    try self.recordResetStream(reset);
                    continue;
                },
                .goaway => continue,
                else => return error.UnexpectedFrame,
            }
        }
    }

    /// Read a complete request while delivering DATA without aggregation.
    ///
    /// Header and trailer fields in the returned value are owned and remain
    /// valid until `StreamingRequest.deinit`. Each DATA slice is borrowed from
    /// connection scratch and is valid only for the duration of `consume`.
    /// This lets handlers hash, parse, forward, or discard large bodies without
    /// a body-sized allocation. The callback must consume the slice before
    /// returning and must not retain it.
    pub fn readRequestStreaming(
        self: *Connection,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        return self.readRequestStreamingWithHeadUntil(
            context,
            ignoreStreamingRequestHead,
            consume,
            null,
        );
    }

    pub fn readRequestStreamingWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readRequestStreamingWithDeadline(
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Stream one server request under a caller-owned absolute awake-clock
    /// deadline. Partial input remains retryable only until HEADERS admits a
    /// stream; after that, a read timeout cancels the stream and prevents reuse
    /// because decoder progress is not retained. Application callback errors
    /// retain the unbounded API's stream-local cancellation semantics.
    pub fn readRequestStreamingWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readRequestStreamingWithHeadUntil(
            context,
            ignoreStreamingRequestHead,
            consume,
            deadline,
        );
    }

    /// Read a request while reporting its validated HEADERS before any DATA.
    ///
    /// `begin` and `consume` share `context`. The head and DATA slices are
    /// borrowed for their callback duration; owned headers/trailers are
    /// returned in `StreamingRequest`.
    pub fn readRequestStreamingWithHead(
        self: *Connection,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        return self.readRequestStreamingWithHeadUntil(
            context,
            begin,
            consume,
            null,
        );
    }

    pub fn readRequestStreamingWithHeadAndTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readRequestStreamingWithHeadAndDeadline(
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            begin,
            consume,
        );
    }

    /// Deadline-bounded streaming request receive with validated head delivery
    /// before DATA. The same deadline spans both callbacks and trailers.
    pub fn readRequestStreamingWithHeadAndDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingRequest {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readRequestStreamingWithHeadUntil(
            context,
            begin,
            consume,
            deadline,
        );
    }

    /// Begin a step-driven request receive. The returned object owns the sole
    /// connection frame reader and keeps the response half independently open.
    pub fn acceptDuplexRequest(
        self: *Connection,
    ) Error!ServerDuplexStream {
        return self.acceptDuplexRequestUntil(null);
    }

    pub fn acceptDuplexRequestWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!ServerDuplexStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptDuplexRequestWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn acceptDuplexRequestWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ServerDuplexStream {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.acceptDuplexRequestUntil(deadline);
    }

    fn acceptDuplexRequestUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ServerDuplexStream {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server or
            (self.duplex_reader_active and
                self.duplex_owners.count() == 0 and
                !self.pending_duplex_request_head.hasValue()))
        {
            return error.UnexpectedFrame;
        }
        if (self.pending_duplex_request_head.getPtr()) |pending| {
            const stream_id = pending.stream_id;
            const end_stream = pending.end_stream;
            const headers = (pending.resumeUntil(self, deadline) catch |err| {
                if (err != error.Timeout) {
                    self.pending_duplex_request_head.deinit(self.allocator);
                    self.cancelPeerRequest(stream_id);
                    self.refreshDuplexReaderActive();
                }
                return err;
            }).?;
            self.pending_duplex_request_head.deinit(self.allocator);
            return self.finishAcceptedDuplexRequest(
                stream_id,
                headers,
                end_stream,
            );
        }
        while (true) {
            if (self.duplex_owners.count() != 0) {
                if (try self.acceptQueuedDuplexRequest()) |stream| {
                    return stream;
                }
                var frame = try self.readOwnedFrameForDuplexWithDeadline(
                    deadline,
                );
                var frame_owned = true;
                defer if (frame_owned) frame.deinit(self.allocator);
                if (try self.handleConnectionFrameUntil(
                    frame.frame,
                    deadline,
                )) continue;
                if (frame.frame.header.frame_type == .goaway) continue;
                const stream_id = frame.frame.header.stream_id;
                const initial_headers =
                    frame.frame.header.frame_type == .headers and
                    !self.pending_duplex_sibling_header.hasValue() and
                    (stream_id > self.last_peer_client_stream_id or
                        self.gracefulPreadmittedIndex(stream_id) != null);
                if (initial_headers) {
                    if (try self.acceptDuplexRequestFrameUntil(
                        frame.frame,
                        deadline,
                    )) |stream| return stream;
                    continue;
                }
                try self.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) continue;
            if (frame.frame.header.frame_type != .headers) {
                return error.UnexpectedFrame;
            }
            if (try self.acceptDuplexRequestFrameUntil(
                frame.frame,
                deadline,
            )) |stream| return stream;
        }
    }

    fn acceptDuplexRequestFrameUntil(
        self: *Connection,
        first: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!?ServerDuplexStream {
        const stream_id = first.header.stream_id;
        const admission = try self.claimPeerRequestStream(stream_id);
        if (admission != .admitted) {
            try self.refusePeerRequestStreamUntil(
                stream_id,
                first,
                deadline,
                admission == .refused_reset_sent,
            );
            return null;
        }
        self.duplex_reader_active = true;
        const pending_value = DuplexHeaderBlock.init(self, first) catch |err| {
            self.cancelPeerRequest(stream_id);
            self.refreshDuplexReaderActive();
            return err;
        };
        self.pending_duplex_request_head.put(pending_value);
        const pending = self.pending_duplex_request_head.getPtr().?;
        const end_stream = pending.end_stream;
        const headers = (pending.resumeUntil(self, deadline) catch |err| {
            if (err != error.Timeout) {
                self.pending_duplex_request_head.deinit(self.allocator);
                self.cancelPeerRequest(stream_id);
                self.refreshDuplexReaderActive();
            }
            return err;
        }).?;
        self.pending_duplex_request_head.deinit(self.allocator);
        return try self.finishAcceptedDuplexRequest(
            stream_id,
            headers,
            end_stream,
        );
    }

    fn acceptQueuedDuplexRequest(
        self: *Connection,
    ) Error!?ServerDuplexStream {
        const stream_id = self.queuedUnclaimedDuplexRequest() orelse
            return null;
        var frame = self.popQueuedFrameForStream(stream_id).?;
        defer frame.deinit(self.allocator);
        const admission = try self.claimPeerRequestStream(stream_id);
        const end_stream =
            (frame.frame.header.flags & flag_end_stream) != 0;
        const headers = self.takeDeferredHeaderBlock(
            frame.frame,
            true,
            false,
        ) catch |err| {
            if (admission == .admitted) {
                self.cancelPeerRequest(stream_id);
                self.refreshDuplexReaderActive();
                return err;
            }
            if (err != error.MessageTooLarge or
                self.aggregate_timeout_unusable or
                self.serve_read_connection_error != null or
                self.hpack_decoder.lastDecodeWasCompressionError())
            {
                self.aggregate_timeout_unusable = true;
                return err;
            }
            try self.finishPredecodedRefusal(
                stream_id,
                admission,
                .refused_stream,
            );
            return null;
        } orelse return error.UnexpectedFrame;
        if (admission != .admitted) {
            defer freeHeaders(self.allocator, headers);
            const reset_code: http2.ErrorCode = blk: {
                validateHeaderBlock(headers, .request) catch
                    break :blk .protocol_error;
                _ = requestHeaderLookup(headers) catch
                    break :blk .protocol_error;
                break :blk .refused_stream;
            };
            try self.finishPredecodedRefusal(
                stream_id,
                admission,
                reset_code,
            );
            return null;
        }
        return try self.finishAcceptedDuplexRequest(
            stream_id,
            headers,
            end_stream,
        );
    }

    fn queuedUnclaimedDuplexRequest(self: *Connection) ?u31 {
        for (self.pending_application_frames.items[self.pending_application_frame_head..]) |entry| {
            const frame = entry.frame;
            if (frame.header.frame_type != .headers or
                !self.deferredHeaderIsDecoded(frame)) continue;
            if (!self.peerStreamIsActive(frame.header.stream_id) or
                self.gracefulPreadmittedIndex(frame.header.stream_id) != null)
            {
                return frame.header.stream_id;
            }
        }
        if (self.pending_application_overflow.getPtr()) |entry| {
            const frame = entry.frame;
            if (frame.header.frame_type == .headers and
                self.deferredHeaderIsDecoded(frame) and
                (!self.peerStreamIsActive(frame.header.stream_id) or
                    self.gracefulPreadmittedIndex(frame.header.stream_id) !=
                        null))
            {
                return frame.header.stream_id;
            }
        }
        return null;
    }

    fn finishPredecodedRefusal(
        self: *Connection,
        stream_id: u31,
        admission: PeerRequestAdmission,
        reset_code: http2.ErrorCode,
    ) Error!void {
        if (admission == .refused_reset_sent) return;
        self.writeResetStreamFramePrepared(stream_id, reset_code) catch |err| {
            self.aggregate_timeout_unusable = true;
            return err;
        };
        self.local_error_reset_streams +|= 1;
    }

    fn finishAcceptedDuplexRequest(
        self: *Connection,
        stream_id: u31,
        headers: []http2.Hpack.HeaderField,
        end_stream: bool,
    ) Error!ServerDuplexStream {
        errdefer freeHeaders(self.allocator, headers);
        errdefer self.cancelPeerRequest(stream_id);
        errdefer self.refreshDuplexReaderActive();
        try validateHeaderBlock(headers, .request);
        const lookup = try requestHeaderLookup(headers);
        const method = lookup.method orelse return error.MissingPseudoHeader;
        const protocol = lookup.protocol;
        if (protocol != null and !self.limits.enable_connect_protocol) {
            return error.ExtendedConnectDisabled;
        }
        const is_connect = methodIsConnect(method);
        const extended_connect = is_connect and protocol != null;
        if (is_connect and !extended_connect and
            (lookup.content_length orelse 0) != 0)
        {
            return error.InvalidContentLength;
        }
        // A declared length above the server-wide cap is a property of this
        // request, not of the connection. Accept the stream so the handler can
        // answer 413; the body read reports PayloadTooLarge. Returning an error
        // here would make one oversize request fatal to every multiplexed
        // sibling stream.
        const request_body_over_limit =
            (lookup.content_length orelse 0) > self.limits.max_body_bytes;
        const request_priority = self.effectiveRequestPriority(
            stream_id,
            lookup.priority,
        );
        try self.rememberResponseSemantics(
            stream_id,
            method,
            protocol,
            request_priority,
        );
        self.duplex_owners.acquire();
        self.duplex_reader_active = true;
        return .{
            .connection = self,
            .registered = true,
            .stream_id = stream_id,
            .headers = headers,
            .method = method,
            .path = lookup.path orelse "",
            .scheme = lookup.scheme orelse "",
            .authority = lookup.requestAuthority(),
            .protocol = protocol,
            .expected_request_length = lookup.content_length,
            .request_body_over_limit = request_body_over_limit,
            .request_finished = end_stream or
                (is_connect and !extended_connect),
            .priority = request_priority,
        };
    }

    fn readRequestStreamingWithHeadUntil(
        self: *Connection,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
        deadline: ?std.Io.Clock.Timestamp,
    ) !StreamingRequest {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.popPendingRequest()) |pending_value| {
            var pending = pending_value;
            var pending_owned = true;
            errdefer if (pending_owned) pending.deinit(self.allocator);
            {
                try self.beginBorrowedReadCallback();
                defer self.endBorrowedReadCallback();
                begin(
                    context,
                    StreamingRequestHead.fromOwned(pending),
                ) catch |err| {
                    self.cancelPeerRequest(pending.stream_id);
                    return @as(anyerror!StreamingRequest, err);
                };
            }
            if (pending.body.len != 0) {
                {
                    try self.beginBorrowedReadCallback();
                    defer self.endBorrowedReadCallback();
                    consume(context, pending.body) catch |err| {
                        self.cancelPeerRequest(pending.stream_id);
                        return @as(anyerror!StreamingRequest, err);
                    };
                }
            }
            const result = streamingRequestFromOwned(pending);
            self.allocator.free(pending.body);
            pending_owned = false;
            return result;
        }

        var active_stream_id: ?u31 = null;
        var read_timed_out = false;
        var callback_failed = false;
        var cleanup_budget: request_cleanup.Budget = .{};
        // Callbacks may themselves return Timeout or OutOfMemory. Keep their
        // stream-local rejection policy separate from internal failures that
        // discard decoder/body progress and prevent connection reuse.
        errdefer |failure| if (read_timed_out or
            (failure == error.OutOfMemory and !callback_failed))
        {
            if (active_stream_id) |stream_id| {
                self.failDiscardedRequestBefore(stream_id, cleanup_budget.get(self, deadline, read_timed_out));
            }
        };
        var receive_credit: flow_credit.Tracker = .{};
        errdefer if (active_stream_id != null or receive_credit.unreleased_connection_bytes != 0) {
            self.releaseDiscardedMessageCapacityBefore(receive_credit.unreleased_connection_bytes, cleanup_budget.get(self, deadline, read_timed_out and !callback_failed));
        };
        while (true) {
            var pending_owned: ?OwnedFrame = null;
            defer if (pending_owned) |*owned| {
                owned.deinit(self.allocator);
            };
            const first = (if (self.pendingApplicationFrameCount() != 0) blk: {
                pending_owned = self.readOwnedFrameWithDeadline(deadline) catch |err| {
                    read_timed_out = deadline != null and err == error.Timeout;
                    return @as(anyerror!StreamingRequest, err);
                };
                break :blk pending_owned.?.frame;
            } else (self.readBufferedFrameWithDeadline(deadline) catch |err| {
                read_timed_out = deadline != null and err == error.Timeout;
                return @as(anyerror!StreamingRequest, err);
            }).frame);
            if (try self.handleConnectionFrameUntil(first, deadline)) continue;
            if (first.header.frame_type == .goaway) continue;
            if (first.header.frame_type != .headers) {
                return error.UnexpectedFrame;
            }

            const stream_id = first.header.stream_id;
            const admission = try self.claimPeerRequestStream(stream_id);
            if (admission != .admitted) {
                try self.refusePeerRequestStreamUntil(
                    stream_id,
                    first,
                    deadline,
                    admission == .refused_reset_sent,
                );
                continue;
            }
            errdefer self.releasePeerStream(stream_id);
            active_stream_id = stream_id;

            const headers = self.readHeaderBlockUntil(
                first,
                deadline,
            ) catch |err| {
                read_timed_out = deadline != null and err == error.Timeout;
                return @as(anyerror!StreamingRequest, err);
            };
            var headers_owned = true;
            errdefer if (headers_owned) freeHeaders(self.allocator, headers);
            try validateHeaderBlock(headers, .request);
            const lookup = try requestHeaderLookup(headers);
            const method = lookup.method orelse
                return error.MissingPseudoHeader;
            const protocol = lookup.protocol;
            if (protocol != null and !self.limits.enable_connect_protocol) {
                return error.ExtendedConnectDisabled;
            }
            const is_connect = methodIsConnect(method);
            const is_extended_connect = is_connect and protocol != null;
            if (is_connect and !is_extended_connect and
                (lookup.content_length orelse 0) != 0)
            {
                return error.InvalidContentLength;
            }
            if (lookup.content_length) |body_len| {
                if (body_len > self.limits.max_body_bytes) {
                    return error.MessageTooLarge;
                }
            }
            // Release an expecting peer before the first request DATA callback.
            if (lookup.expects_continue and
                (!is_connect or is_extended_connect) and
                (first.header.flags & flag_end_stream) == 0)
            {
                if (deadline) |absolute| {
                    try self.writeInformationalResponseWithDeadline(
                        stream_id,
                        100,
                        &.{},
                        absolute,
                    );
                } else {
                    try self.writeInformationalResponse(
                        stream_id,
                        100,
                        &.{},
                    );
                }
            }
            {
                try self.beginBorrowedReadCallback();
                defer self.endBorrowedReadCallback();
                begin(context, .{
                    .stream_id = stream_id,
                    .headers = headers,
                    .method = method,
                    .path = lookup.path orelse "",
                    .scheme = lookup.scheme orelse "",
                    .authority = lookup.requestAuthority(),
                    .protocol = protocol,
                }) catch |err| {
                    // The peer's request half may already carry END_STREAM,
                    // but this server still owns the response half. Cancel
                    // the whole stream so a rejected head cannot leave the
                    // client waiting.
                    callback_failed = true;
                    self.abandonPeerRequestBefore(stream_id, .cancel, cleanup_budget.get(self, deadline, false));
                    return @as(anyerror!StreamingRequest, err);
                };
            }

            var trailers: []http2.Hpack.HeaderField = &.{};
            var trailers_owned = false;
            errdefer if (trailers_owned) {
                freeHeaders(self.allocator, trailers);
            };
            var body_bytes: usize = 0;
            if ((!is_connect or is_extended_connect) and
                (first.header.flags & flag_end_stream) == 0)
            {
                while (true) {
                    const frame = (self.readBufferedFrameWithDeadline(
                        deadline,
                    ) catch |err| {
                        read_timed_out =
                            deadline != null and err == error.Timeout;
                        return @as(anyerror!StreamingRequest, err);
                    }).frame;
                    if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
                    if (frame.header.stream_id != stream_id) {
                        if (frame.header.frame_type == .rst_stream) {
                            const reset =
                                try http2.ResetStreamPayload.parse(frame);
                            if (self.streamIsIdle(reset.stream_id)) {
                                return error.InvalidFrame;
                            }
                            try self.recordResetStream(reset);
                            continue;
                        }
                        if (self.queueCompletePeerRequestFrameUntil(
                            frame,
                            deadline,
                            &cleanup_budget,
                        ) catch |err| {
                            read_timed_out =
                                deadline != null and err == error.Timeout;
                            return @as(anyerror!StreamingRequest, err);
                        }) {
                            continue;
                        }
                        return error.UnexpectedFrame;
                    }
                    switch (frame.header.frame_type) {
                        .data => {
                            const connection_before = self.recv_connection_window.value;
                            const data =
                                try self.receiveDataPayload(stream_id, frame);
                            defer receive_credit.observe(connection_before, self.recv_connection_window.value, data.adaptive_connection_increment);
                            defer self.releaseDataFrameBudget(data);
                            body_bytes = checkedBodyLength(
                                lookup.content_length,
                                body_bytes,
                                data.data.len,
                                self.limits.max_body_bytes,
                                (frame.header.flags & flag_end_stream) != 0,
                            ) catch |err| {
                                self.releaseDiscardedMessageCapacityBefore(frame.payload.len, cleanup_budget.get(self, deadline, false));
                                return @as(anyerror!StreamingRequest, err);
                            };
                            if (data.data.len != 0) {
                                {
                                    try self.beginBorrowedReadCallback();
                                    defer self.endBorrowedReadCallback();
                                    consume(context, data.data) catch |err| {
                                        callback_failed = true;
                                        // Mirror the response-side callback
                                        // contract: once DATA has been
                                        // consumed from the receive window,
                                        // restore exact shared connection
                                        // credit and cancel this stream before
                                        // surfacing the application error.
                                        const before = cleanup_budget.get(self, deadline, false);
                                        self.releaseDiscardedMessageCapacityBefore(frame.payload.len, before);
                                        // Even final request DATA leaves the
                                        // server response half open; terminate
                                        // it when the application rejects the
                                        // body.
                                        self.abandonPeerRequestBefore(stream_id, .cancel, before);
                                        return @as(anyerror!StreamingRequest, err);
                                    };
                                }
                            }
                            try self.releaseReceivedDataCapacityUntil(
                                stream_id,
                                data,
                                (frame.header.flags & flag_end_stream) != 0,
                                deadline,
                            );
                            if ((frame.header.flags & flag_end_stream) != 0) {
                                break;
                            }
                        },
                        .headers => {
                            if ((frame.header.flags & flag_end_stream) == 0) {
                                return error.UnexpectedFrame;
                            }
                            trailers = self.readHeaderBlockUntil(
                                frame,
                                deadline,
                            ) catch |err| {
                                read_timed_out =
                                    deadline != null and err == error.Timeout;
                                return @as(anyerror!StreamingRequest, err);
                            };
                            trailers_owned = true;
                            try validateHeaderBlock(
                                trailers,
                                .request_trailers,
                            );
                            break;
                        },
                        .rst_stream => {
                            const reset = try http2.ResetStreamPayload.parse(
                                frame,
                            );
                            try self.recordResetStream(reset);
                            return error.StreamReset;
                        },
                        else => return error.UnexpectedFrame,
                    }
                }
            }

            try validateExpectedContentLength(
                lookup.content_length,
                body_bytes,
            );
            const request_priority = self.effectiveRequestPriority(
                stream_id,
                lookup.priority,
            );
            try self.rememberResponseSemantics(
                stream_id,
                method,
                protocol,
                request_priority,
            );
            headers_owned = false;
            trailers_owned = false;
            return .{
                .stream_id = stream_id,
                .headers = headers,
                .method = method,
                .path = lookup.path orelse "",
                .scheme = lookup.scheme orelse "",
                .authority = lookup.requestAuthority(),
                .protocol = protocol,
                .body_bytes = body_bytes,
                .trailers = trailers,
                .priority = request_priority,
                .from = self.peerAddress(),
            };
        }
    }

    /// Read an exact batch of interleaved request streams without aggregating
    /// DATA bodies.
    ///
    /// Requests are returned in peer HEADERS order. Each callback receives the
    /// stream ID so one application context can keep independent per-stream
    /// parsers/checksums while DATA frames arrive round-robin. Initial headers
    /// and trailers are owned by each `StreamingRequest`; DATA remains borrowed
    /// for the callback duration. Traditional CONNECT is intentionally rejected
    /// because a completed request batch cannot represent tunnel lifetime.
    pub fn readRequestBatchStreamingInto(
        self: *Connection,
        requests: []StreamingRequest,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        return self.readRequestBatchStreamingIntoUntil(
            requests,
            null,
            context,
            consume,
        );
    }

    /// Read an exact streaming request batch under one relative budget. The
    /// timeout is converted once and is not renewed by control frames, newly
    /// admitted streams, DATA callbacks, or completed sibling requests.
    pub fn readRequestBatchStreamingIntoWithTimeout(
        self: *Connection,
        requests: []StreamingRequest,
        timeout: std.Io.Duration,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readRequestBatchStreamingIntoWithDeadline(
            requests,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            context,
            consume,
        );
    }

    /// Absolute-deadline form of
    /// `readRequestBatchStreamingIntoWithTimeout`. A timeout before stream
    /// admission preserves the buffered frame for retry. Once any request is
    /// admitted or a header block is being assembled, discarded batch state
    /// makes the connection fail closed after cancelling every admitted stream.
    pub fn readRequestBatchStreamingIntoWithDeadline(
        self: *Connection,
        requests: []StreamingRequest,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readRequestBatchStreamingIntoUntil(
            requests,
            deadline,
            context,
            consume,
        );
    }

    fn readRequestBatchStreamingIntoUntil(
        self: *Connection,
        requests: []StreamingRequest,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime consume: anytype,
    ) !void {
        if (self.aggregate_timeout_unusable or
            self.pending_accept_reset_overflowed)
        {
            return error.ConnectionClosed;
        }
        if (self.role != .server) return error.UnexpectedFrame;
        if (requests.len == 0) return;
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;

        var expected_stack: [16]?usize = undefined;
        var done_stack: [16]bool = undefined;
        var credits_stack: [16]flow_credit.Tracker = undefined;
        const expected = if (requests.len <= expected_stack.len)
            expected_stack[0..requests.len]
        else
            try self.allocator.alloc(?usize, requests.len);
        defer if (expected.ptr != expected_stack[0..].ptr) {
            self.allocator.free(expected);
        };
        const done = if (requests.len <= done_stack.len)
            done_stack[0..requests.len]
        else
            try self.allocator.alloc(bool, requests.len);
        defer if (done.ptr != done_stack[0..].ptr) {
            self.allocator.free(done);
        };
        @memset(done, false);
        const credits = if (requests.len <= credits_stack.len) credits_stack[0..requests.len] else try self.allocator.alloc(flow_credit.Tracker, requests.len);
        defer if (credits.ptr != credits_stack[0..].ptr) self.allocator.free(credits);
        @memset(credits, .{});

        var initialized: usize = 0;
        var completed: usize = 0;
        var active_uninitialized_stream_id: ?u31 = null;
        var timeout_lost_state = false;
        var current_stream_id: ?u31 = null;
        var stream_error_code: ?http2.ErrorCode = null;
        var callback_failed = false;
        var cleanup_budget: request_cleanup.Budget = .{};
        errdefer |err| request_batch_cleanup.abort(self, requests[0..initialized], .{
            .cause = err,
            .stream_id = current_stream_id,
            .stream_code = stream_error_code,
            .uninitialized_stream_id = active_uninitialized_stream_id,
            .read_lost_state = timeout_lost_state or
                (err == error.OutOfMemory and !callback_failed and
                    (initialized != 0 or active_uninitialized_stream_id != null)),
            .callback_failed = callback_failed,
            .before = cleanup_budget.get(self, deadline, err == error.Timeout and !callback_failed),
        }, .{
            .sendConnectionError = sendServeReadErrorBefore,
            .streamErrorCode = serveRequestStreamErrorCode,
            .reset = writeResetStreamFrameUntil,
            .terminalReset = writeTerminalResetStreamUntil,
            .errorReset = writeLocalErrorResetStreamUntil,
            .releasePeer = releasePeerStream,
            .forgetWindows = forgetStreamWindows,
            .pendingId = PendingRequest.streamId,
            .deinitPending = PendingRequest.deinit,
        });
        // All batch members are discarded on failure. Reclaim the DATA still
        // held by each member before abort() removes its stream windows.
        errdefer |err| for (credits[0..initialized]) |credit| {
            self.releaseDiscardedMessageCapacityBefore(credit.unreleased_connection_bytes, cleanup_budget.get(self, deadline, err == error.Timeout and !callback_failed));
        };

        while (completed < requests.len) {
            current_stream_id = null;
            stream_error_code = null;
            const frame = (self.readBufferedFrameWithDeadline(deadline) catch |err| {
                timeout_lost_state = deadline != null and
                    err == error.Timeout and initialized != 0;
                return @errorCast(err);
            }).frame;
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            if (frame.header.frame_type == .goaway) {
                try self.recordPeerGoAway(
                    try http2.GoAwayPayload.parse(frame),
                );
                return error.ConnectionGoAway;
            }

            switch (frame.header.frame_type) {
                .headers => {
                    if (findStreamingRequestIndex(
                        requests[0..initialized],
                        frame.header.stream_id,
                    )) |index| {
                        current_stream_id = frame.header.stream_id;
                        // HPACK state is shared across streams. Decode even a
                        // rejected HEADERS block before checking its message
                        // state so later requests keep the same dynamic table.
                        const trailers = self.readHeaderBlockUntil(
                            frame,
                            deadline,
                        ) catch |err| {
                            timeout_lost_state =
                                deadline != null and err == error.Timeout;
                            return @errorCast(err);
                        };
                        var trailers_owned = true;
                        errdefer if (trailers_owned) freeHeaders(self.allocator, trailers);
                        if (done[index] or (frame.header.flags & flag_end_stream) == 0) {
                            stream_error_code = if (done[index]) .stream_closed else .protocol_error;
                            return error.UnexpectedFrame;
                        }
                        try validateHeaderBlock(
                            trailers,
                            .request_trailers,
                        );
                        try self.finishBatchStreamingRequest(
                            &requests[index],
                            expected[index],
                        );
                        requests[index].trailers = trailers;
                        done[index] = true;
                        completed += 1;
                        trailers_owned = false;
                        continue;
                    }

                    const stream_id = frame.header.stream_id;
                    const admission = try self.claimPeerRequestStream(
                        stream_id,
                    );
                    if (admission != .admitted) {
                        self.refusePeerRequestStreamUntil(
                            stream_id,
                            frame,
                            deadline,
                            admission == .refused_reset_sent,
                        ) catch |err| {
                            timeout_lost_state =
                                deadline != null and err == error.Timeout;
                            return @errorCast(err);
                        };
                        continue;
                    }
                    active_uninitialized_stream_id = stream_id;
                    current_stream_id = stream_id;
                    var stream_reserved = true;
                    errdefer if (stream_reserved) {
                        self.releasePeerStream(stream_id);
                    };
                    const headers = self.readHeaderBlockUntil(
                        frame,
                        deadline,
                    ) catch |err| {
                        timeout_lost_state =
                            deadline != null and err == error.Timeout;
                        return @errorCast(err);
                    };
                    var headers_owned = true;
                    errdefer if (headers_owned) {
                        freeHeaders(self.allocator, headers);
                    };
                    try validateHeaderBlock(headers, .request);
                    const lookup = try requestHeaderLookup(headers);
                    const method = lookup.method orelse
                        return error.MissingPseudoHeader;
                    if (initialized == requests.len) {
                        stream_error_code = .refused_stream;
                        return error.UnexpectedFrame;
                    }
                    if (methodIsConnect(method)) {
                        stream_error_code = .refused_stream;
                        return error.InvalidHeader;
                    }
                    if (lookup.protocol != null) {
                        return error.InvalidHeader;
                    }
                    if ((lookup.content_length orelse 0) >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }

                    const index = initialized;
                    const request_priority =
                        self.effectiveRequestPriority(
                            stream_id,
                            lookup.priority,
                        );
                    requests[index] = .{
                        .stream_id = stream_id,
                        .headers = headers,
                        .method = method,
                        .path = lookup.path orelse "",
                        .scheme = lookup.scheme orelse "",
                        .authority = lookup.requestAuthority(),
                        .body_bytes = 0,
                        .priority = request_priority,
                        .from = self.peerAddress(),
                    };
                    expected[index] = lookup.content_length;
                    initialized += 1;
                    headers_owned = false;
                    stream_reserved = false;
                    active_uninitialized_stream_id = null;
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try self.finishBatchStreamingRequest(
                            &requests[index],
                            expected[index],
                        );
                        done[index] = true;
                        completed += 1;
                    }
                },
                .data => {
                    const index = findStreamingRequestIndex(
                        requests[0..initialized],
                        frame.header.stream_id,
                    ) orelse return error.UnexpectedFrame;
                    current_stream_id = frame.header.stream_id;
                    const connection_before = self.recv_connection_window.value;
                    const data = try self.receiveDataPayload(
                        frame.header.stream_id,
                        frame,
                    );
                    defer accountCredit(
                        credits[0..initialized],
                        index,
                        connection_before,
                        self.recv_connection_window.value,
                        data.adaptive_connection_increment,
                    );
                    defer self.releaseDataFrameBudget(data);
                    if (done[index]) {
                        self.releaseDiscardedMessageCapacityBefore(frame.payload.len, cleanup_budget.get(self, deadline, false));
                        stream_error_code = .stream_closed;
                        return error.UnexpectedFrame;
                    }
                    requests[index].body_bytes = checkedBodyLength(
                        expected[index],
                        requests[index].body_bytes,
                        data.data.len,
                        self.limits.max_body_bytes,
                        (frame.header.flags & flag_end_stream) != 0,
                    ) catch |err| {
                        self.releaseDiscardedMessageCapacityBefore(frame.payload.len, cleanup_budget.get(self, deadline, false));
                        return @errorCast(err);
                    };
                    if (data.data.len != 0) {
                        consume(
                            context,
                            frame.header.stream_id,
                            data.data,
                        ) catch |err| {
                            callback_failed = true;
                            // The error path resets every batch member, so no
                            // stream credit will be consumed again. Restore
                            // only the shared connection window.
                            self.releaseDiscardedMessageCapacityBefore(frame.payload.len, cleanup_budget.get(self, deadline, false));
                            return @errorCast(err);
                        };
                    }
                    try self.releaseReceivedDataCapacityUntil(
                        frame.header.stream_id,
                        data,
                        (frame.header.flags & flag_end_stream) != 0,
                        deadline,
                    );
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try self.finishBatchStreamingRequest(
                            &requests[index],
                            expected[index],
                        );
                        done[index] = true;
                        completed += 1;
                    }
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(frame);
                    if (try self.skipBatchStreamingRequestReset(
                        requests,
                        expected,
                        done,
                        credits,
                        &initialized,
                        &completed,
                        reset,
                    )) continue;
                    if (self.streamIsIdle(reset.stream_id)) {
                        return error.InvalidFrame;
                    }
                    if (!self.outboundStreamIsActive(reset.stream_id) or
                        self.wasLocallyReset(reset.stream_id))
                    {
                        try self.recordResetStream(reset);
                        continue;
                    }
                    return error.StreamReset;
                },
                .continuation => {
                    self.serve_read_connection_error = .frame_sequence;
                    return error.UnexpectedFrame;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn finishBatchStreamingRequest(
        self: *Connection,
        streaming_request: *StreamingRequest,
        expected_length: ?usize,
    ) Error!void {
        try validateExpectedContentLength(
            expected_length,
            streaming_request.body_bytes,
        );
        try self.rememberResponseSemantics(
            streaming_request.stream_id,
            streaming_request.method,
            streaming_request.protocol,
            streaming_request.priority,
        );
    }

    fn skipBatchStreamingRequestReset(
        self: *Connection,
        requests: []StreamingRequest,
        expected: []?usize,
        done: []bool,
        credits: []flow_credit.Tracker,
        initialized: *usize,
        completed: *usize,
        reset: http2.ResetStreamPayload,
    ) Error!bool {
        const index = findStreamingRequestIndex(
            requests[0..initialized.*],
            reset.stream_id,
        ) orelse return false;
        try self.recordResetStream(reset);
        try self.releaseConnectionCapacity(credits[index].unreleased_connection_bytes);
        credits[index] = .{};
        if (done[index]) {
            std.debug.assert(completed.* != 0);
            completed.* -= 1;
            self.forgetResponseSemantics(reset.stream_id);
        }
        requests[index].deinit(self.allocator);
        if (index + 1 < initialized.*) {
            @memmove(
                requests[index .. initialized.* - 1],
                requests[index + 1 .. initialized.*],
            );
            @memmove(
                expected[index .. initialized.* - 1],
                expected[index + 1 .. initialized.*],
            );
            @memmove(
                done[index .. initialized.* - 1],
                done[index + 1 .. initialized.*],
            );
            @memmove(credits[index .. initialized.* - 1], credits[index + 1 .. initialized.*]);
        }
        initialized.* -= 1;
        requests[initialized.*] = undefined;
        expected[initialized.*] = null;
        done[initialized.*] = false;
        credits[initialized.*] = .{};
        return true;
    }

    fn findStreamingRequestIndex(
        requests: []const StreamingRequest,
        stream_id: u31,
    ) ?usize {
        for (requests, 0..) |streaming_request, index| {
            if (streaming_request.stream_id == stream_id) return index;
        }
        return null;
    }

    fn readFrameScratch(self: *Connection) Error!http2.Frame {
        return (try self.readBufferedFrame()).frame;
    }

    pub fn readBufferedFrame(self: *Connection) Error!frame_io.BorrowedFrame {
        return self.readBufferedFrameWithDeadline(null);
    }

    fn readBufferedFrameWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!frame_io.BorrowedFrame {
        if (self.duplex_reader_active) return error.UnexpectedFrame;
        while (true) {
            const frame = try self.readBufferedFrameRawWithDeadline(deadline);
            if (try self.discardFrameAboveGracefulBoundaryUntil(
                frame.frame,
                deadline,
            )) continue;
            return frame;
        }
    }

    const InterruptibleFrameRead = buffered_frame_wake.Result(frame_io.BorrowedFrame);

    fn readBufferedFrameWithDeadlineOrWake(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
        wake: *std.Io.Event,
    ) anyerror!InterruptibleFrameRead {
        return buffered_frame_wake.read(self.io, self, deadline, wake, frame_io.BorrowedFrame, Error, readBufferedFrameWithDeadline);
    }

    fn readBufferedFrameRawWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!frame_io.BorrowedFrame {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        // A scratch borrow lasts until the next read. Release the owning frame
        // retained for the previous borrow before replacing its storage.
        self.borrowed_pending_frame.deinit(self.allocator);
        if (try self.popQueuedApplicationFrame()) |frame| {
            self.borrowed_pending_frame.put(frame);
            const pending = self.borrowed_pending_frame.getPtr().?;
            return .{
                .bytes = pending.bytes,
                .frame = pending.frame,
            };
        }
        return self.readTransportFrameWithDeadline(deadline);
    }

    pub fn beginBorrowedReadCallback(self: *Connection) Error!void {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        self.callback_reader_active = true;
    }

    pub fn endBorrowedReadCallback(self: *Connection) void {
        std.debug.assert(self.callback_reader_active);
        self.callback_reader_active = false;
    }

    fn readTransportFrameWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!frame_io.BorrowedFrame {
        while (true) {
            if (!self.push_ingress_headers_active and self.pending_push_header != null) {
                try self.resumePendingPushHeader(deadline);
                continue;
            }
            const borrowed = try self.readTransportFrameRawWithDeadline(deadline);
            if (!self.push_ingress_headers_active) {
                if (self.pending_duplex_sibling_header.getPtr()) |pending| {
                    if (!pending.header.end_headers and (borrowed.frame.header.frame_type != .continuation or borrowed.frame.header.stream_id != pending.header.stream_id)) {
                        self.serve_read_connection_error = .frame_sequence;
                        self.aggregate_timeout_unusable = true;
                        self.sendProtocolGoAway(self.lastPeerProcessedStreamId(), .protocol_error, "header-sequence", deadline);
                        return error.UnexpectedFrame;
                    }
                }
            }
            if (!self.push_ingress_headers_active and try self.receivePushedFrame(borrowed.frame, deadline)) continue;
            return borrowed;
        }
    }

    fn readTransportFrameRawWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!frame_io.BorrowedFrame {
        while (true) {
            const borrowed = self.frame_reader.readTransportWithDeadline(
                self.allocator,
                self.transportForIo(),
                @min(
                    self.limits.max_frame_payload,
                    self.limits.max_frame_size,
                ),
                deadline,
            ) catch |err| {
                if (err == error.InvalidFrame) {
                    if (self.frame_reader.takeEnvelopeViolation()) |violation| {
                        if (self.last_peer_frame_at != null) {
                            self.last_peer_frame_at =
                                std.Io.Clock.awake.now(self.io);
                        }
                        if (violation.stream_id) |stream_id| {
                            var reserved_push = false;
                            if (!self.push_ingress_headers_active and self.role == .client) {
                                if (self.push_state.state) |state| {
                                    if (state.received.get(stream_id)) |entry| {
                                        reserved_push = !entry.started and !entry.finished;
                                        if (entry.started) {
                                            try self.ensureLocalErrorResetBudgetUntil(deadline);
                                            state.received.fail(self.allocator, stream_id, error.InvalidFrame);
                                            self.writeResetStreamFrameUntil(stream_id, violation.error_code, deadline) catch |reset_err| switch (reset_err) {
                                                error.SocketUnconnected, error.ConnectionResetByPeer => {},
                                                else => return reset_err,
                                            };
                                            self.local_error_reset_streams +|= 1;
                                            self.releasePeerStream(stream_id);
                                            self.forgetStreamWindows(stream_id);
                                            continue;
                                        }
                                    }
                                }
                            }
                            if (self.push_ingress_headers_active or reserved_push or self.streamIsIdle(stream_id)) {
                                self.aggregate_timeout_unusable = true;
                                self.sendProtocolGoAway(
                                    self.lastPeerProcessedStreamId(),
                                    .protocol_error,
                                    "frame-envelope",
                                    deadline,
                                );
                            } else {
                                if (response_cleanup.cleanupDeadline(self, deadline)) |before| {
                                    self.writeLocalErrorResetStreamUntil(stream_id, violation.error_code, before) catch {};
                                } else {
                                    self.aggregate_timeout_unusable = true;
                                    self.terminal_write_failed = true;
                                }
                                self.releaseLocalStream(stream_id);
                                self.releasePeerStream(stream_id);
                                self.forgetResponseSemantics(stream_id);
                                self.forgetStreamWindows(stream_id);
                            }
                        } else {
                            self.aggregate_timeout_unusable = true;
                            self.sendProtocolGoAway(
                                self.lastPeerProcessedStreamId(),
                                violation.error_code,
                                "frame-envelope",
                                deadline,
                            );
                        }
                    }
                }
                return err;
            };
            if (self.last_peer_frame_at != null and !self.frame_reader.last_replayed) {
                self.last_peer_frame_at = std.Io.Clock.awake.now(self.io);
            }
            return borrowed;
        }
    }

    pub fn readOwnedFrame(self: *Connection) Error!OwnedFrame {
        return self.readOwnedFrameWithDeadline(null);
    }

    pub fn readOwnedFrameWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedFrame {
        if (self.duplex_reader_active) return error.UnexpectedFrame;
        while (true) {
            var frame = try self.readOwnedFrameRawWithDeadline(deadline);
            if (try self.discardFrameAboveGracefulBoundaryUntil(
                frame.frame,
                deadline,
            )) {
                frame.deinit(self.allocator);
                continue;
            }
            return frame;
        }
    }

    pub fn readOwnedFrameWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readOwnedFrameWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readOwnedFrameForDuplexWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!RetainedFrame {
        if (self.duplex_pending_frame.take()) |frame| return frame;
        while (true) {
            var frame = try self.readRetainedTransportFrameWithDeadline(deadline);
            if (try self.discardFrameAboveGracefulBoundaryUntil(
                frame.frame,
                deadline,
            )) {
                frame.deinit(self.allocator);
                continue;
            }
            return frame;
        }
    }

    pub fn readOwnedFrameForDuplexWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!RetainedFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readOwnedFrameForDuplexWithDeadline(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readOwnedClientDuplexFrameWithDeadline(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!RetainedFrame {
        return client_duplex_owner.read(self, stream_id, deadline, client_duplex_hooks);
    }

    pub fn readOwnedClientDuplexFrameWithTimeout(
        self: *Connection,
        stream_id: u31,
        timeout: std.Io.Duration,
    ) Error!RetainedFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readOwnedClientDuplexFrameWithDeadline(
            stream_id,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn readOwnedServerDuplexFrameWithDeadline(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!RetainedFrame {
        if (try self.pollOwnedServerDuplexFrame(stream_id)) |frame| return frame;
        return self.readOwnedFrameForDuplexWithDeadline(deadline);
    }

    pub fn readOwnedServerDuplexFrameWithTimeout(
        self: *Connection,
        stream_id: u31,
        timeout: std.Io.Duration,
    ) Error!RetainedFrame {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readOwnedServerDuplexFrameWithDeadline(
            stream_id,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn pollOwnedServerDuplexFrame(
        self: *Connection,
        stream_id: u31,
    ) Error!?RetainedFrame {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.peekQueuedFrameForStream(stream_id)) |queued| {
            if (queued.header.frame_type != .headers or
                self.deferredHeaderIsDecoded(queued))
            {
                return self.popQueuedFrameForStream(stream_id).?;
            }
        }
        return null;
    }

    const client_duplex_hooks = .{
        .Error = Error,
        .Frame = RetainedFrame,
        .peek = peekQueuedFrameForStream,
        .pop = popQueuedFrameForStream,
        .readWire = readClientDuplexWireFrame,
        .sequence = validateClientDuplexHeaderSequence,
        .header = queueClientDuplexHeader,
        .decoded = deferredHeaderIsDecoded,
        .connectionFrame = handleConnectionFrameUntil,
        .pushed = receivePushedFrame,
        .sibling = queueDuplexSiblingFrameUntil,
        .discardCanceled = discardQueuedResetFramesUntil,
        .goaway = recordClientDuplexGoAway,
    };

    fn recordClientDuplexGoAway(self: *Connection, frame: http2.Frame) Error!void {
        try self.recordPeerGoAway(try http2.GoAwayPayload.parse(frame));
    }

    pub fn pollOwnedClientDuplexFrame(self: *Connection, stream_id: u31, deadline: ?std.Io.Clock.Timestamp) Error!?RetainedFrame {
        return client_duplex_owner.poll(self, stream_id, deadline, client_duplex_hooks);
    }

    /// Read and route one input frame. Application stream IDs are hints to
    /// poll; connection control and partial HEADERS report progress. One owner
    /// must serially drive this pump and all client duplex handles.
    pub fn pumpClientDuplexWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!ClientDuplexPumpEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.checkClientDuplexPump();
        return client_duplex_owner.pump(self, deadline, client_duplex_hooks);
    }

    /// Advance one client frame under one absolute input/output budget, even
    /// when no stream is active. A single owner must serialize this operation
    /// with every client stream reader. Application frames retain normal
    /// routing and HPACK ordering through the shared duplex owner.
    pub fn pumpClientWithDeadline(self: *Connection, deadline: std.Io.Clock.Timestamp) Error!ClientDuplexPumpEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return client_duplex_owner.pump(self, deadline, client_duplex_hooks);
    }

    pub fn pumpClientWithTimeout(self: *Connection, timeout: std.Io.Duration) Error!ClientDuplexPumpEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.pumpClientWithDeadline(.fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn pumpClientDuplexWithTimeout(self: *Connection, timeout: std.Io.Duration) Error!ClientDuplexPumpEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.pumpClientDuplexWithDeadline(.fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Wake for new commands without abandoning partial input. The canceled
    /// read is joined before return; a simultaneously completed frame is routed.
    pub fn pumpClientDuplexWithDeadlineOrWake(self: *Connection, deadline: std.Io.Clock.Timestamp, wake: *std.Io.Event) Error!ClientDuplexPumpEvent {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        try self.checkClientDuplexPump();
        const result = duplex_wake.read(self, deadline, wake, RetainedFrame, Error, readClientDuplexWireFrame, retainInterruptedClientDuplexFrame) catch |err| return @errorCast(err);
        return switch (result) {
            .frame => |frame| try client_duplex_owner.ingest(self, frame, deadline, client_duplex_hooks),
            .wake => .wake,
        };
    }

    /// Background owners may wait without a read timer when there is no RPC
    /// deadline. Control output receives a fresh finite budget after input or
    /// a command wake completes; this also services an idle client connection.
    pub fn pumpClientUntilOrWake(self: *Connection, read_until: ?std.Io.Clock.Timestamp, output_timeout: std.Io.Duration, wake: *std.Io.Event) Error!ClientDuplexPumpEvent {
        if (output_timeout.nanoseconds <= 0) return error.Timeout;
        if (read_until) |deadline| _ = try deadline_policy.usableAwake(self.io, deadline);
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .client or self.callback_reader_active) return error.UnexpectedFrame;
        const result = duplex_wake.read(self, read_until, wake, RetainedFrame, Error, readClientDuplexWireFrame, retainInterruptedClientDuplexFrame) catch |err| return @errorCast(err);
        return switch (result) {
            .wake => .wake,
            .frame => |frame| try client_duplex_owner.ingest(self, frame, .fromNow(self.io, .{ .raw = output_timeout, .clock = .awake }), client_duplex_hooks),
        };
    }

    /// Sole-owner server pump for new duplex requests and routed DATA on
    /// existing streams. A command wake cancels and joins the socket read;
    /// a simultaneously completed frame wins and remains observable. A null
    /// wake event means no task can enqueue a command, so the read runs
    /// directly on the caller's task instead of through a select.
    pub fn pumpServerUntilOrWake(self: *Connection, read_until: ?std.Io.Clock.Timestamp, output_timeout: std.Io.Duration, wake: ?*std.Io.Event) Error!ServerDuplexPumpEvent {
        return self.pumpServerUntilOrWakeInner(read_until, output_timeout, wake, true);
    }

    /// Same as `pumpServerUntilOrWake` for a deadline the caller built from the
    /// loop's cached clock and knows to be positive. Skips the redundant
    /// clock read that `usableAwake` performs; an already-expired deadline
    /// still times out in the read itself.
    pub fn pumpServerUntilOrWakePrevalidated(self: *Connection, read_until: ?std.Io.Clock.Timestamp, output_timeout: std.Io.Duration, wake: ?*std.Io.Event) Error!ServerDuplexPumpEvent {
        return self.pumpServerUntilOrWakeInner(read_until, output_timeout, wake, false);
    }

    fn pumpServerUntilOrWakeInner(self: *Connection, read_until: ?std.Io.Clock.Timestamp, output_timeout: std.Io.Duration, wake: ?*std.Io.Event, comptime validate_deadline: bool) Error!ServerDuplexPumpEvent {
        if (output_timeout.nanoseconds <= 0) return error.Timeout;
        if (validate_deadline) {
            if (read_until) |deadline| _ = try deadline_policy.usableAwake(self.io, deadline);
        }
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server or self.callback_reader_active) return error.UnexpectedFrame;
        if (try self.acceptQueuedDuplexRequest()) |value| return .{ .request = value };
        const result = duplex_wake.read(self, read_until, wake, RetainedFrame, Error, readClientDuplexWireFrame, retainInterruptedClientDuplexFrame) catch |err| return @errorCast(err);
        return switch (result) {
            .wake => .wake,
            .frame => |input| blk: {
                var frame = input;
                var frame_owned = true;
                defer if (frame_owned) frame.deinit(self.allocator);
                const deadline = std.Io.Clock.Timestamp.fromNow(
                    self.io,
                    .{ .raw = output_timeout, .clock = .awake },
                );
                if (try self.handleConnectionFrameUntil(frame.frame, deadline)) break :blk .progress;
                if (frame.frame.header.frame_type == .goaway) break :blk .progress;
                const stream_id = frame.frame.header.stream_id;
                const initial_headers = frame.frame.header.frame_type == .headers and
                    !self.pending_duplex_sibling_header.hasValue() and
                    (stream_id > self.last_peer_client_stream_id or
                        self.gracefulPreadmittedIndex(stream_id) != null);
                if (initial_headers) {
                    if (try self.acceptDuplexRequestFrameUntil(frame.frame, deadline)) |value| {
                        break :blk .{ .request = value };
                    }
                    break :blk .progress;
                }
                try self.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                break :blk .{ .stream = stream_id };
            },
        };
    }

    /// Already available credit only; no frame read or WINDOW_UPDATE wait.
    pub fn availableClientSendCapacity(self: *const Connection, stream_id: u31) usize {
        return @min(self.send_connection_window.available(), self.sendStreamWindowAvailable(stream_id));
    }

    fn checkClientDuplexPump(self: *const Connection) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .client or self.duplex_owners.count() == 0 or self.callback_reader_active) return error.UnexpectedFrame;
    }

    fn retainInterruptedClientDuplexFrame(self: *Connection, frame: RetainedFrame) void {
        std.debug.assert(!self.duplex_pending_frame.hasValue());
        self.duplex_pending_frame.put(frame);
    }

    fn readClientDuplexWireFrame(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!RetainedFrame {
        const prior = self.push_ingress_headers_active;
        self.push_ingress_headers_active = prior or self.pending_duplex_sibling_header.hasValue();
        defer self.push_ingress_headers_active = prior;
        return self.readOwnedFrameForDuplexWithDeadline(deadline);
    }

    fn validateClientDuplexHeaderSequence(self: *Connection, frame: http2.Frame, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.pending_duplex_sibling_header.getPtr()) |pending| {
            if (frame.header.frame_type == .continuation and frame.header.stream_id == pending.header.stream_id) return;
        } else if (frame.header.frame_type != .continuation) return;
        self.serve_read_connection_error = .frame_sequence;
        self.aggregate_timeout_unusable = true;
        self.sendProtocolGoAway(self.lastPeerProcessedStreamId(), .protocol_error, "header-sequence", deadline);
        return error.UnexpectedFrame;
    }

    fn queueClientDuplexHeader(self: *Connection, frame: RetainedFrame) Error!bool {
        const keep_frame = frame.frame.header.frame_type == .headers;
        if (keep_frame) {
            self.ensurePendingApplicationFrameCapacity() catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
        }
        if (!keep_frame) {
            self.predecodeSiblingFrameRetained(frame.frame, false) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
            return false;
        }
        self.predecodeSiblingFrameRetained(frame.frame, false) catch |err| {
            self.aggregate_timeout_unusable = true;
            return err;
        };
        self.pending_application_frames.appendAssumeCapacity(frame);
        return true;
    }

    fn peekQueuedFrameForStream(self: *Connection, stream_id: u31) ?http2.Frame {
        if (client_duplex_owner.queuedIndex(self.pending_application_frames.items, self.pending_application_frame_head, stream_id)) |index| {
            return self.pending_application_frames.items[index].frame;
        }
        if (self.pending_application_overflow.getPtr()) |frame| {
            if (frame.frame.header.stream_id == stream_id) return frame.frame;
        }
        return null;
    }

    fn popQueuedFrameForStream(self: *Connection, stream_id: u31) ?RetainedFrame {
        if (client_duplex_owner.queuedIndex(self.pending_application_frames.items, self.pending_application_frame_head, stream_id)) |index| {
            const frame = self.pending_application_frames.orderedRemove(index);
            self.compactPendingApplicationFramesIfSparse();
            return frame;
        }
        if (self.pending_application_overflow.getPtr()) |frame| {
            if (frame.frame.header.stream_id == stream_id) return self.pending_application_overflow.take();
        }
        return null;
    }

    fn discardQueuedResetFramesUntil(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!void {
        var index = self.pending_application_frame_head;
        while (index < self.pending_application_frames.items.len) {
            const frame = self.pending_application_frames.items[index].frame;
            if (self.pending_duplex_sibling_header.getPtr()) |pending| {
                if (pending.header.stream_id == frame.header.stream_id) {
                    index += 1;
                    continue;
                }
            }
            if (!self.locally_reset_stream_index.contains(frame.header.stream_id) or
                (frame.header.frame_type == .headers and !self.deferredHeaderIsDecoded(frame)))
            {
                index += 1;
                continue;
            }
            var owned = self.pending_application_frames.orderedRemove(index);
            defer owned.deinit(self.allocator);
            if (!try self.discardLateFrameForLocallyResetStreamUntil(owned.frame, deadline)) return error.UnexpectedFrame;
        }
        self.compactPendingApplicationFramesIfSparse();
    }

    /// Number of client duplex handles that still own a live HTTP/2 half.
    pub fn activeClientDuplexCount(self: *const Connection) usize {
        return if (self.role == .client) self.duplex_owners.count() else 0;
    }

    /// Number of accepted server duplex handles whose request or response
    /// half is still live. One connection owner must drive these handles
    /// serially; their input frames are routed by stream ID.
    pub fn activeServerDuplexCount(self: *const Connection) usize {
        return if (self.role == .server) self.duplex_owners.count() else 0;
    }

    pub fn refreshDuplexReaderActive(self: *Connection) void {
        self.duplex_reader_active =
            self.duplex_owners.count() != 0;
    }

    pub fn releaseClientDuplexOwner(self: *Connection, stream_id: u31) void {
        if (self.pending_duplex_sibling_header.getPtr()) |pending| {
            if (pending.header.stream_id == stream_id) self.aggregate_timeout_unusable = true;
        }
        self.duplex_owners.release();
        self.refreshDuplexReaderActive();
        if (!self.duplex_reader_active and self.pending_duplex_sibling_header.hasValue()) {
            self.aggregate_timeout_unusable = true;
        }
    }

    pub fn releaseServerDuplexOwner(self: *Connection, stream_id: u31) void {
        if (self.pending_duplex_sibling_header.getPtr()) |pending| {
            if (pending.header.stream_id == stream_id) {
                self.aggregate_timeout_unusable = true;
            }
        }
        self.duplex_owners.release();
        self.refreshDuplexReaderActive();
        if (!self.duplex_reader_active and
            self.pending_duplex_sibling_header.hasValue())
        {
            self.aggregate_timeout_unusable = true;
        }
    }

    fn readOwnedTransportFrameWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedFrame {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        self.borrowed_pending_frame.deinit(self.allocator);
        const borrowed = try self.readTransportFrameWithDeadline(deadline);
        return self.copyBorrowedFrame(borrowed);
    }

    fn readRetainedTransportFrameWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!RetainedFrame {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        self.borrowed_pending_frame.deinit(self.allocator);
        const borrowed = try self.readTransportFrameWithDeadline(deadline);
        return self.frame_reader.retainOwned(self.allocator, borrowed);
    }

    pub fn copyBorrowedFrame(self: *Connection, borrowed: frame_io.BorrowedFrame) Error!OwnedFrame {
        if (self.borrowed_pending_frame.getPtr()) |pending| {
            if (pending.bytes.ptr == borrowed.bytes.ptr and pending.bytes.len == borrowed.bytes.len) {
                // A queued owning frame was exposed through a borrowed read.
                // Transfer that owner instead of allocating another copy.
                return self.borrowed_pending_frame.take().?;
            }
        }
        return self.frame_reader.copyOwned(self.allocator, borrowed);
    }

    fn readOwnedFrameRawWithDeadline(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedFrame {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        self.borrowed_pending_frame.deinit(self.allocator);
        if (try self.popQueuedApplicationFrame()) |frame| return frame;
        const borrowed = try self.readTransportFrameWithDeadline(deadline);
        return self.copyBorrowedFrame(borrowed);
    }

    fn popQueuedApplicationFrame(self: *Connection) Error!?OwnedFrame {
        if (self.pending_application_frame_head <
            self.pending_application_frames.items.len)
        {
            const pending = &self.pending_application_frames.items[
                self.pending_application_frame_head
            ];
            const owned = try pending.prepareOwned(self.allocator);
            self.rekeyDeferredFrame(pending.frame, owned.frame);
            pending.commitPreparedOwned(self.allocator);
            self.pending_application_frame_head += 1;
            self.compactPendingApplicationFramesIfSparse();
            return owned;
        }
        if (self.pending_application_overflow.getPtr()) |pending| {
            const owned = try pending.prepareOwned(self.allocator);
            self.rekeyDeferredFrame(pending.frame, owned.frame);
            var retained = self.pending_application_overflow.take().?;
            retained.commitPreparedOwned(self.allocator);
            return owned;
        }
        return null;
    }

    pub fn takeDeferredHeaderBlock(
        self: *Connection,
        first: http2.Frame,
        raw_continuations: bool,
        discard: bool,
    ) Error!?[]http2.Hpack.HeaderField {
        var selected: ?usize = null;
        for (self.duplex_sibling_headers.items, 0..) |entry, index| {
            if (entry.stream_id != first.header.stream_id) continue;
            if (entry.payload_key != 0) {
                if (entry.payload_key != @intFromPtr(first.payload.ptr)) continue;
            } else if (raw_continuations) continue;
            selected = index;
            break;
        }
        const index = selected orelse return null;
        const entry = self.duplex_sibling_headers.items[index];
        for (0..entry.continuation_count) |_| {
            var continuation = self.popQueuedFrameForStream(first.header.stream_id) orelse {
                self.aggregate_timeout_unusable = true;
                return error.UnexpectedFrame;
            };
            defer continuation.deinit(self.allocator);
            if (continuation.frame.header.frame_type != .continuation or
                continuation.frame.header.stream_id != first.header.stream_id)
            {
                self.aggregate_timeout_unusable = true;
                return error.UnexpectedFrame;
            }
        }
        _ = self.duplex_sibling_headers.orderedRemove(index);
        if (self.duplex_sibling_headers.items.len == 0) {
            self.duplex_sibling_headers.clearRetainingCapacity();
        }
        if (!discard) {
            if (entry.decode_error) |err| return err;
        }
        return entry.headers;
    }

    /// Queue ownership transfers only on success. Reserve both raw-frame and
    /// deferred-header storage before changing connection-wide HPACK state.
    pub fn queueDuplexSiblingFrameUntil(self: *Connection, frame: RetainedFrame) Error!void {
        try self.ensurePendingApplicationFrameCapacity();
        self.predecodeSiblingFrame(frame.frame) catch |err| {
            self.aggregate_timeout_unusable = true;
            return err;
        };
        self.pending_application_frames.appendAssumeCapacity(frame);
    }

    fn queueOwnedDuplexSiblingFrameUntil(self: *Connection, frame: OwnedFrame) Error!void {
        try self.ensurePendingApplicationFrameCapacity();
        self.predecodeSiblingFrame(frame.frame) catch |err| {
            self.aggregate_timeout_unusable = true;
            return err;
        };
        self.pending_application_frames.appendAssumeCapacity(
            RetainedFrame.fromOwned(frame),
        );
    }

    fn predecodeSiblingFrame(self: *Connection, frame: http2.Frame) Error!void {
        return self.predecodeSiblingFrameRetained(frame, true);
    }

    fn predecodeSiblingFrameRetained(self: *Connection, frame: http2.Frame, retain_continuation: bool) Error!void {
        if (frame.header.frame_type == .headers and self.deferredHeaderIsDecoded(frame)) return;
        if (!self.pending_duplex_sibling_header.hasValue()) {
            if (frame.header.frame_type != .headers) return;
            try self.pending_duplex_sibling_header.init(self, frame);
        } else {
            const pending = self.pending_duplex_sibling_header.getPtr().?;
            if (frame.header.frame_type != .continuation or frame.header.stream_id != pending.header.stream_id) return error.UnexpectedFrame;
            pending.queued_continuation_count += @intFromBool(retain_continuation);
            try pending.header.appendContinuation(self, frame);
        }
        if (!self.pending_duplex_sibling_header.getPtr().?.header.end_headers) return;
        try self.duplex_sibling_headers.ensureUnusedCapacity(self.allocator, 1);
        const pending = self.pending_duplex_sibling_header.getPtr().?;
        var decode_error: ?Error = null;
        const fields: []http2.Hpack.HeaderField = pending.header.decode(self) catch |err| blk: {
            if (!pending.header.decode_complete) return err;
            decode_error = err;
            break :blk &.{};
        };
        self.duplex_sibling_headers.appendAssumeCapacity(.{
            .stream_id = pending.header.stream_id,
            .headers = fields,
            .continuation_count = pending.queued_continuation_count,
            .payload_key = pending.payload_key,
            .decode_error = decode_error,
        });
        self.pending_duplex_sibling_header.deinit(self.allocator);
    }

    /// A PING wait may stop after retaining a partial normal HEADERS block.
    /// Finish that older HPACK input before reading any later pushed header.
    fn completeDeferredHeadersBeforePushRead(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.pending_application_overflow.getPtr()) |overflow| {
            if (!self.pending_duplex_sibling_header.hasValue() and overflow.frame.header.frame_type == .headers and !self.deferredHeaderIsDecoded(overflow.frame)) {
                try self.pending_duplex_sibling_header.init(self, overflow.frame);
            } else if (self.pending_duplex_sibling_header.getPtr()) |pending| {
                if (!pending.overflow_included and overflow.frame.header.frame_type == .continuation) {
                    if (overflow.frame.header.stream_id != pending.header.stream_id) return error.UnexpectedFrame;
                    pending.queued_continuation_count += 1;
                    pending.overflow_included = true;
                    try pending.header.appendContinuation(self, overflow.frame);
                }
            }
        }
        const pending = self.pending_duplex_sibling_header.getPtr() orelse return;
        try self.duplex_sibling_headers.ensureUnusedCapacity(self.allocator, 1);
        self.push_ingress_headers_active = true;
        defer self.push_ingress_headers_active = false;
        const fields = (try pending.header.resumeUntil(self, deadline)) orelse return error.UnexpectedFrame;
        self.duplex_sibling_headers.appendAssumeCapacity(.{
            .stream_id = pending.header.stream_id,
            .headers = fields,
            .continuation_count = pending.queued_continuation_count,
            .payload_key = pending.payload_key,
        });
        self.pending_duplex_sibling_header.deinit(self.allocator);
    }

    fn deferredHeaderIsDecoded(self: *const Connection, frame: http2.Frame) bool {
        for (self.duplex_sibling_headers.items) |entry| {
            if (entry.stream_id == frame.header.stream_id and entry.payload_key == @intFromPtr(frame.payload.ptr)) return true;
        }
        return false;
    }

    /// Completed/predecoded header metadata identifies its queued wire frame by
    /// payload address. Ordinary readers may copy a shared retained frame into
    /// exact ownership; update that stable key before releasing the old block so
    /// HPACK state is never decoded twice.
    fn rekeyDeferredFrame(self: *Connection, old: http2.Frame, new: http2.Frame) void {
        const old_key = @intFromPtr(old.payload.ptr);
        const new_key = @intFromPtr(new.payload.ptr);
        if (old_key == new_key) return;
        if (self.pending_duplex_sibling_header.getPtr()) |pending| {
            if (pending.payload_key == old_key) pending.payload_key = new_key;
        }
        for (self.duplex_sibling_headers.items) |*entry| {
            if (entry.payload_key == old_key) entry.payload_key = new_key;
        }
    }

    fn compactPendingApplicationFramesIfSparse(self: *Connection) void {
        if (self.pending_application_frame_head == 0) return;
        if (self.pending_application_frame_head ==
            self.pending_application_frames.items.len or
            self.pending_application_frame_head >=
                self.pending_application_frames.items.len / 2)
        {
            self.compactPendingApplicationFrames();
        }
    }

    fn compactPendingApplicationFrames(self: *Connection) void {
        if (self.pending_application_frame_head == 0) return;
        const remaining = self.pending_application_frames.items.len -
            self.pending_application_frame_head;
        if (remaining != 0) {
            @memmove(
                self.pending_application_frames.items[0..remaining],
                self.pending_application_frames.items[self.pending_application_frame_head..],
            );
        }
        self.pending_application_frames.items.len = remaining;
        self.pending_application_frame_head = 0;
    }

    pub fn pendingApplicationFrameCount(self: *const Connection) usize {
        return self.pending_application_frames.items.len -
            self.pending_application_frame_head +
            @intFromBool(self.pending_application_overflow.hasValue());
    }

    pub fn queuePendingApplicationFrame(
        self: *Connection,
        frame: OwnedFrame,
    ) Error!void {
        if (self.role == .client and self.limits.enable_push) return self.queueOwnedDuplexSiblingFrameUntil(frame);
        return self.queueApplicationFrameRaw(frame);
    }

    fn queueApplicationFrameRaw(self: *Connection, frame: OwnedFrame) Error!void {
        if (self.pendingApplicationFrameCount() >=
            self.limits.max_pending_ping_frames)
        {
            return error.MessageTooLarge;
        }
        if (self.pending_application_frame_head != 0 and
            self.pending_application_frames.items.len ==
                self.pending_application_frames.capacity)
        {
            self.compactPendingApplicationFrames();
        }
        try self.pending_application_frames.append(
            self.allocator,
            RetainedFrame.fromOwned(frame),
        );
    }

    fn ensurePendingApplicationFrameCapacity(
        self: *Connection,
    ) Error!void {
        if (self.pendingApplicationFrameCount() >=
            self.limits.max_pending_ping_frames)
        {
            return error.MessageTooLarge;
        }
        if (self.pending_application_frame_head != 0 and
            self.pending_application_frames.items.len ==
                self.pending_application_frames.capacity)
        {
            self.compactPendingApplicationFrames();
        }
        try self.pending_application_frames.ensureUnusedCapacity(
            self.allocator,
            1,
        );
    }

    pub fn recoverPendingApplicationFrameAfterQueueFailure(
        self: *Connection,
        frame: OwnedFrame,
    ) void {
        self.pending_application_overflow.put(RetainedFrame.fromOwned(frame));
    }

    pub const PeerRequestAdmission = enum {
        admitted,
        refused,
        refused_reset_sent,
    };

    const GracefulPeerRequest = struct {
        stream_id: u31,
        admission: PeerRequestAdmission,
    };

    pub fn gracefulPreadmittedIndex(
        self: *const Connection,
        stream_id: u31,
    ) ?usize {
        for (self.graceful_preadmitted_peer_streams.items, 0..) |entry, index| {
            if (entry.stream_id == stream_id) return index;
        }
        return null;
    }

    /// Claim an initial request HEADERS frame. The graceful PING pump may have
    /// already reserved the stream so its admission is reflected in the final
    /// GOAWAY; in that case the eventual request reader consumes only the
    /// marker and must not reserve or advance the stream a second time.
    pub fn claimPeerRequestStream(
        self: *Connection,
        stream_id: u31,
    ) Error!PeerRequestAdmission {
        if (self.role != .server) return error.UnexpectedFrame;
        if (!clientInitiatedStreamId(stream_id)) return error.InvalidFrame;
        // A graceful preadmission can already have reset this stream. Keep its
        // marker until the queued HEADERS is replayed rather than letting the
        // generic late-frame path consume it before this admission lookup.
        if (self.gracefulPreadmittedIndex(stream_id)) |index| {
            const admission = self.graceful_preadmitted_peer_streams
                .orderedRemove(index).admission;
            if (admission == .admitted and
                !self.outboundStreamIsActive(stream_id))
            {
                try self.reservePeerStream(stream_id);
                self.last_peer_processed_stream_id = stream_id;
            }
            return admission;
        }
        if (stream_id <= self.last_peer_client_stream_id) {
            return error.InvalidFrame;
        }
        self.reservePeerStream(stream_id) catch |err| switch (err) {
            error.FlowControlViolation => {
                try self.ensureLocalErrorResetBudget();
                self.prepareLocallyResetStreams(1) catch |alloc_err| {
                    // The caller has already removed initial HEADERS from the
                    // transport. Without reset-history capacity it cannot
                    // safely retry or tolerate frames racing the refusal.
                    self.aggregate_timeout_unusable = true;
                    return alloc_err;
                };
                // A valid new stream that exceeds our advertised concurrency
                // is closed, not idle. Apply the monotonic PRIORITY_UPDATE
                // transition so this stream and skipped lower IDs cannot keep
                // consuming the admission budget after refusal.
                self.priority_state.openRequest(self.allocator, stream_id);
                _ = self.priority_state.remove(self.allocator, stream_id);
                self.last_peer_client_stream_id = stream_id;
                return .refused;
            },
            else => {
                self.aggregate_timeout_unusable = true;
                return err;
            },
        };
        self.last_peer_client_stream_id = stream_id;
        self.last_peer_processed_stream_id = stream_id;
        return .admitted;
    }

    /// Consume and HPACK-validate the entire refused field section before emitting
    /// RST_STREAM. HPACK state is connection-wide, so skipping CONTINUATIONs
    /// or decoder mutations here would corrupt every later request.
    pub fn refusePeerRequestStreamUntil(
        self: *Connection,
        stream_id: u31,
        first: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
        reset_already_sent: bool,
    ) Error!void {
        // A direct refusal reserves reset-history capacity while claiming the
        // stream; graceful preadmission already sent and recorded its reset.
        // Thus, after HPACK advances, this helper performs no allocation.
        const reset_code = try RefusedHeaders.read(self, first, deadline);
        if (!reset_already_sent) {
            self.writeResetStreamFramePrepared(
                stream_id,
                reset_code,
            ) catch |err| {
                // `writeAll` cannot report how much of the frame reached the
                // peer. Never permit another API call to append bytes after a
                // potentially partial RST_STREAM.
                self.aggregate_timeout_unusable = true;
                return err;
            };
            self.local_error_reset_streams +|= 1;
        }
    }

    fn rollbackGracefulPreadmissions(self: *Connection) void {
        for (self.graceful_preadmitted_peer_streams.items) |entry| {
            if (entry.admission != .admitted) continue;
            _ = self.removeActivePeerStream(entry.stream_id);
            self.forgetResponseSemantics(entry.stream_id);
            self.forgetStreamWindows(entry.stream_id);
        }
        if (self.graceful_preadmit_base_processed_stream_id) |base| {
            self.last_peer_processed_stream_id = base;
        }
        // Keep markers and the observed-ID cursor. The raw frames are still
        // queued and must replay their original admitted/refused decisions; a
        // refused stream has already received its wire-visible reset. Admitted
        // markers re-reserve their stream when replayed after this rollback.
        // Priority metadata also stays attached to those markers so replay
        // preserves the same priority the shutdown probe observed.
        self.graceful_preadmit_base_processed_stream_id = null;
        self.clearGracefulPreadmitDecoder();
    }

    /// Admit a request stream observed after phase-one GOAWAY but before the
    /// synchronization ACK. Its HEADERS remains encoded in the pending queue,
    /// preserving connection-wide HPACK order for the application reader.
    pub fn preadmitGracefulPeerRequest(
        self: *Connection,
        frame: http2.Frame,
    ) Error!bool {
        if (self.role != .server or
            self.graceful_shutdown_phase != .synchronizing or
            frame.header.frame_type != .headers)
        {
            return false;
        }
        const stream_id = frame.header.stream_id;
        if (!clientInitiatedStreamId(stream_id)) return error.InvalidFrame;
        if (self.local_goaway_last_stream_id) |last| {
            if (stream_id > last) return false;
        }
        // HEADERS on an existing stream are trailers, not a new request.
        if (stream_id <= self.last_peer_client_stream_id) return false;
        // Only a complete field section can be validated without consuming
        // more transport frames before this frame itself is queued. Keep the
        // fragmented block losslessly queued, but fail shutdown rather than
        // publishing a final boundary that incorrectly declares it retryable.
        if ((frame.header.flags & flag_end_headers) == 0) {
            return error.ResponseAvailable;
        }
        const started_shadow = self.graceful_preadmit_decoder == null;
        if (started_shadow) {
            self.graceful_preadmit_decoder = blk: {
                const decoder = try self.allocator.create(http2.Hpack.Decoder);
                errdefer self.allocator.destroy(decoder);
                decoder.* = try self.hpack_decoder.clone(self.allocator);
                break :blk decoder;
            };
            self.graceful_preadmit_base_processed_stream_id =
                self.last_peer_processed_stream_id;
        }
        errdefer if (started_shadow and
            self.graceful_preadmitted_peer_streams.items.len == 0)
        {
            self.graceful_preadmit_base_processed_stream_id = null;
            self.clearGracefulPreadmitDecoder();
        };
        const parsed = try legacy_priority.parseHeaders(self, frame);
        const headers = try self.graceful_preadmit_decoder.?
            .decodeBlockOwnedWithLimit(
            self.allocator,
            parsed.header_block,
            self.limits.max_header_fields,
            self.limits.max_header_list_size,
        );
        defer freeHeaders(self.allocator, headers);
        try validateHeaderBlock(headers, .request);
        _ = try requestHeaderLookup(headers);
        try self.graceful_preadmitted_peer_streams.ensureUnusedCapacity(
            self.allocator,
            1,
        );
        const admission: PeerRequestAdmission = blk: {
            self.reservePeerStream(stream_id) catch |err| switch (err) {
                error.FlowControlViolation => {
                    try self.ensureLocalErrorResetBudget();
                    // The original HEADERS remains queued for live HPACK
                    // replay, so make reset bookkeeping allocation-safe before
                    // its wire-visible refusal becomes irreversible.
                    try self.prepareLocallyResetStreams(1);
                    self.priority_state.openRequest(
                        self.allocator,
                        stream_id,
                    );
                    _ = self.priority_state.remove(
                        self.allocator,
                        stream_id,
                    );
                    self.writeResetStreamFramePrepared(
                        stream_id,
                        .refused_stream,
                    ) catch |write_err| {
                        self.aggregate_timeout_unusable = true;
                        return write_err;
                    };
                    self.local_error_reset_streams +|= 1;
                    break :blk .refused_reset_sent;
                },
                else => return err,
            };
            self.last_peer_processed_stream_id = stream_id;
            break :blk .admitted;
        };
        self.graceful_preadmitted_peer_streams.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .admission = admission,
        });
        self.last_peer_client_stream_id = stream_id;
        return true;
    }

    pub fn clearGracefulPreadmitDecoder(self: *Connection) void {
        if (self.graceful_preadmit_decoder) |decoder| {
            decoder.deinit(self.allocator);
            self.allocator.destroy(decoder);
        }
        self.graceful_preadmit_decoder = null;
    }

    pub fn popPendingRequest(self: *Connection) ?OwnedRequest {
        while (self.pending_request_head < self.pending_requests.items.len) {
            const pending = self.pending_requests.items[self.pending_request_head];
            self.pending_request_head += 1;
            switch (pending) {
                .ready => |owned_request| {
                    self.compactPendingRequestsIfSparse();
                    return owned_request;
                },
                .reset => {
                    std.debug.assert(self.pending_accept_reset_streams != 0);
                    self.pending_accept_reset_streams -= 1;
                },
            }
        }
        self.compactPendingRequestsIfSparse();
        return null;
    }

    const RequestBodyFrame = union(enum) {
        direct_data: bool,
        owned_frame: OwnedFrame,
    };

    /// Aggregate borrowed, unpadded DATA without materializing an owning frame.
    ///
    /// The general frame reader must allocate an owning frame because callers
    /// may retain its payload. Validate ordinary DATA before appending it to
    /// the final body. Padded DATA and all control/header frames retain
    /// the fully validated owning fallback.
    fn readRequestBodyFrameUntil(
        self: *Connection,
        stream_id: u31,
        body: *std.ArrayList(u8),
        expected_length: ?usize,
        deadline: ?std.Io.Clock.Timestamp,
        receive_credit: *flow_credit.Tracker,
        cleanup_budget: *request_cleanup.Budget,
    ) Error!RequestBodyFrame {
        const borrowed = try self.readBufferedFrameWithDeadline(deadline);
        const header = borrowed.frame.header;
        const is_direct_data = header.frame_type == .data and
            header.stream_id == stream_id and (header.flags & 0x8) == 0;
        if (!is_direct_data) {
            return .{ .owned_frame = try self.copyBorrowedFrame(borrowed) };
        }

        const connection_before = self.recv_connection_window.value;
        const data = try self.receiveDataPayload(stream_id, borrowed.frame);
        defer receive_credit.observe(connection_before, self.recv_connection_window.value, data.adaptive_connection_increment);
        defer self.releaseDataFrameBudget(data);
        _ = checkedBodyLength(expected_length, body.items.len, data.data.len, self.limits.max_body_bytes, (header.flags & flag_end_stream) != 0) catch |err| {
            self.releaseDiscardedMessageCapacityBefore(borrowed.frame.payload.len, cleanup_budget.get(self, deadline, false));
            return @errorCast(err);
        };
        try body.appendSlice(self.allocator, data.data);
        try self.releaseReceivedDataCapacityUntil(
            stream_id,
            data,
            (header.flags & flag_end_stream) != 0,
            deadline,
        );
        return .{
            .direct_data = (header.flags & flag_end_stream) != 0,
        };
    }

    fn queueCompletePeerRequestFrameUntil(
        self: *Connection,
        frame: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
        cleanup_budget: *request_cleanup.Budget,
    ) Error!bool {
        if (frame.header.frame_type != .headers) return false;
        const stream_id = frame.header.stream_id;
        const admission = try self.claimPeerRequestStream(stream_id);
        if (admission != .admitted) {
            try self.refusePeerRequestStreamUntil(
                stream_id,
                frame,
                deadline,
                admission == .refused_reset_sent,
            );
            return true;
        }
        if ((frame.header.flags & flag_end_stream) == 0) {
            // This helper can retain only complete requests. Undo the claim so
            // its caller's existing fail-closed path does not leak capacity.
            self.releasePeerStream(stream_id);
            return false;
        }
        var release_stream_on_error = true;
        errdefer |failure| if (release_stream_on_error) {
            if (failure == error.OutOfMemory) {
                self.failDiscardedRequestBefore(stream_id, cleanup_budget.get(self, deadline, false));
            } else {
                self.releasePeerStream(stream_id);
            }
        };

        const headers = self.readHeaderBlockUntil(frame, deadline) catch |err| {
            if (deadline != null and err == error.Timeout) {
                // END_STREAM makes this a complete request even though its
                // HPACK block still needs CONTINUATION. It was admitted above,
                // so retire it independently from the active request whose
                // reader will also fail closed.
                self.abandonPeerRequestBefore(stream_id, .cancel, cleanup_budget.get(self, deadline, true));
                release_stream_on_error = false;
            }
            return @as(Error!bool, err);
        };
        var headers_owned = true;
        errdefer if (headers_owned) freeHeaders(self.allocator, headers);
        try validateHeaderBlock(headers, .request);
        const empty_body = try self.allocator.alloc(u8, 0);
        var body_owned_by_request = false;
        errdefer if (!body_owned_by_request) self.allocator.free(empty_body);
        const queued_request = try self.requestFromHeadersAndBody(stream_id, headers, empty_body, &.{});
        body_owned_by_request = true;
        headers_owned = false;
        errdefer {
            var owned = queued_request;
            owned.deinit(self.allocator);
        }
        try self.appendPendingRequest(queued_request, self.allocator);
        return true;
    }

    pub fn pendingRequestCount(self: *const Connection) usize {
        return self.pending_requests.items.len - self.pending_request_head;
    }

    pub fn pendingAcceptResetStreamCount(self: *const Connection) usize {
        return self.pending_accept_reset_streams;
    }

    fn pendingAcceptResetOverflowed(self: *const Connection) bool {
        return self.pending_accept_reset_overflowed;
    }

    fn compactPendingRequestsIfSparse(self: *Connection) void {
        if (self.pending_request_head == 0) return;
        if (self.pending_request_head == self.pending_requests.items.len or
            self.pending_request_head >= self.pending_requests.items.len / 2)
        {
            self.compactPendingRequests();
        }
    }

    fn compactPendingRequests(self: *Connection) void {
        if (self.pending_request_head == 0) return;
        const remaining = self.pendingRequestCount();
        if (remaining != 0) {
            @memmove(
                self.pending_requests.items[0..remaining],
                self.pending_requests.items[self.pending_request_head..],
            );
        }
        self.pending_requests.items.len = remaining;
        self.pending_request_head = 0;
    }

    pub fn appendPendingRequest(
        self: *Connection,
        owned_request: OwnedRequest,
        allocator: std.mem.Allocator,
    ) !void {
        if (self.pending_request_head != 0 and
            self.pending_requests.items.len == self.pending_requests.capacity)
        {
            self.compactPendingRequests();
        }
        try self.pending_requests.append(allocator, .{ .ready = owned_request });
    }

    pub fn markPendingRequestReset(
        self: *Connection,
        stream_id: u31,
    ) bool {
        for (self.pending_requests.items[self.pending_request_head..]) |*pending| {
            switch (pending.*) {
                .ready => |*pending_request| {
                    if (pending_request.stream_id != stream_id) continue;
                    var owned = pending_request.*;
                    owned.deinit(self.allocator);
                    pending.* = .{ .reset = stream_id };
                    self.pending_accept_reset_streams += 1;
                    return self.pending_accept_reset_streams >
                        self.limits.max_pending_accept_reset_streams;
                },
                .reset => |pending_stream_id| {
                    if (pending_stream_id == stream_id) return false;
                },
            }
        }
        return false;
    }

    fn cancelPendingAcceptOverflowBefore(self: *Connection, before: ?std.Io.Clock.Timestamp) void {
        self.aggregate_timeout_unusable = true;
        self.pending_accept_reset_overflowed = true;
        for (self.pending_requests.items[self.pending_request_head..]) |*pending| {
            self.abandonPeerRequestBefore(pending.streamId(), .cancel, before);
            pending.deinit(self.allocator);
        }
        self.pending_requests.items.len = 0;
        self.pending_request_head = 0;
        self.pending_accept_reset_streams = 0;
    }

    fn handleQueuedSiblingReset(
        self: *Connection,
        reset: http2.ResetStreamPayload,
    ) Error!bool {
        if (self.streamIsIdle(reset.stream_id)) return error.InvalidFrame;
        try self.recordResetStream(reset);
        return true;
    }

    pub fn requestFromHeadersAndBody(
        self: *Connection,
        stream_id: u31,
        headers: []http2.Hpack.HeaderField,
        body: []u8,
        trailers: []http2.Hpack.HeaderField,
    ) Error!OwnedRequest {
        const lookup = try requestHeaderLookup(headers);
        const method = lookup.method orelse return error.MissingPseudoHeader;
        const protocol = lookup.protocol;
        if (protocol != null and !self.limits.enable_connect_protocol) return error.ExtendedConnectDisabled;
        const expected_request_len = lookup.content_length;
        const is_connect = methodIsConnect(method);
        const is_extended_connect = is_connect and protocol != null;
        if (is_connect and !is_extended_connect and (expected_request_len orelse 0) != 0) return error.InvalidContentLength;
        try validateExpectedContentLength(lookup.content_length, body.len);
        const request_priority = self.effectiveRequestPriority(
            stream_id,
            lookup.priority,
        );
        try self.rememberResponseSemantics(
            stream_id,
            method,
            protocol,
            request_priority,
        );
        return .{
            .stream_id = stream_id,
            .headers = headers,
            .method = method,
            .path = lookup.path orelse "",
            .scheme = lookup.scheme orelse "",
            .authority = lookup.requestAuthority(),
            .protocol = protocol,
            .body = body,
            .trailers = trailers,
            .priority = request_priority,
        };
    }

    fn appendAutomaticDateHeader(
        self: *Connection,
        fields: *std.ArrayList(http2.Hpack.HeaderField),
    ) void {
        if (findHeader(fields.items, "date") != null) return;
        const date = if (self.limits.auto_date_header)
            http_date.valueNow(self.io)
        else
            null;
        appendAutomaticDateHeaderValue(fields, date);
    }

    /// Validate one batch member without reading the clock or mutating the
    /// live HPACK encoder. Batch APIs run this for every member before taking
    /// their shared automatic Date value, preserving validate-before-I/O.
    pub fn validateResponseBatchMember(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        bodyless: bool,
    ) Error!bool {
        if (bodyless and
            (options.body.len != 0 or options.trailers.len != 0))
        {
            return error.InvalidContentLength;
        }
        if (!bodyless and options.trailers.len != 0) {
            return error.InvalidContentLength;
        }
        if (options.status < 100 or options.status > 999 or
            statusIsInformational(options.status))
        {
            return error.InvalidStatus;
        }
        const semantics = self.responseSemanticsFor(stream_id, options);
        if (!bodyless and responseWriteSuppressesBodySemantics(
            options.status,
            semantics,
        )) {
            return error.InvalidContentLength;
        }

        var status_buf: [3]u8 = undefined;
        const status = std.fmt.bufPrint(
            &status_buf,
            "{}",
            .{options.status},
        ) catch return error.InvalidStatus;
        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            options.headers.len,
            3,
        ) catch return error.MessageTooLarge;
        const fields_buffer = try stackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_capacity,
        );
        defer freeStackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_buffer,
        );
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{ .name = ":status", .value = status });
        fields.appendSliceAssumeCapacity(options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .response,
        );
        if (semantics.traditional_connect and
            options.status >= 200 and options.status < 300)
        {
            try stripSuccessfulConnectContentLength(&fields);
        }
        const declared_length = try contentLength(fields.items);
        try validateOutgoingResponseBodyForStatusWithLength(
            options.status,
            declared_length,
            options.body,
            &.{},
        );
        try validateResponseBodyForRequestSemanticsWithLength(
            options.status,
            semantics,
            declared_length,
            options.body,
            &.{},
        );
        try validateDeclaredResponseLengthValue(
            options.status,
            semantics,
            declared_length,
            options.body.len,
        );
        if (responseShouldDefaultContentLengthValue(
            options.status,
            semantics,
            declared_length,
            options.body.len,
        )) {
            var content_length_buf: [32]u8 = undefined;
            const value = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{options.body.len},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = value,
            });
        }
        const needs_automatic_date = self.limits.auto_date_header and
            findHeader(fields.items, "date") == null;
        // Account for the implicit field before touching the wall clock. The
        // actual same-sized value is fetched only after every batch member
        // passes this validation phase.
        if (needs_automatic_date) {
            fields.appendAssumeCapacity(.{
                .name = "date",
                .value = "Thu, 01 Jan 1970 00:00:00 GMT",
            });
        }
        try validateHeaderBlock(fields.items, .response);
        try validateHeaderListSize(fields.items, self.peer_max_header_list_size);
        return needs_automatic_date;
    }

    pub fn writeResponse(self: *Connection, stream_id: u31, options: ResponseOptions) Error!void {
        return self.writeResponseInternal(stream_id, options, true);
    }

    /// Validate and write one complete response under a caller-owned
    /// awake-clock deadline. HEADERS, DATA and trailers consume the same
    /// budget; no phase can renew it.
    pub fn writeResponseWithDeadline(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.writeResponseInternalUntil(
            stream_id,
            options,
            true,
            absolute,
        );
    }

    pub fn writeResponseWithTimeout(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeResponseWithDeadline(
            stream_id,
            options,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn writeResponseInternal(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        release_stream: bool,
    ) Error!void {
        return self.writeResponseInternalUntil(stream_id, options, release_stream, null);
    }

    pub fn writeResponseInternalUntil(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        release_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        return self.writeResponseInternalTrackedUntil(
            stream_id,
            options,
            release_stream,
            deadline,
            null,
        );
    }

    const AggregateResponseWriteProgress = struct {
        head_committed: bool = false,
    };

    fn writeResponseInternalTrackedUntil(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        release_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
        progress: ?*AggregateResponseWriteProgress,
    ) Error!void {
        if (progress) |value| value.* = .{};
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (!self.outboundStreamIsActive(stream_id)) {
            return error.InvalidStreamId;
        }
        var status_buf: [3]u8 = undefined;
        if (options.status < 100 or options.status > 999) return error.InvalidStatus;
        if (statusIsInformational(options.status)) return error.InvalidStatus;
        const semantics = self.responseSemanticsFor(stream_id, options);
        const suppress_body = responseWriteSuppressesBodySemantics(options.status, semantics);
        const status = std.fmt.bufPrint(&status_buf, "{}", .{options.status}) catch return error.InvalidStatus;

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            options.headers.len,
            3,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        var content_length_buf: [32]u8 = undefined;
        fields.appendAssumeCapacity(.{
            .name = ":status",
            .value = status,
        });
        fields.appendSliceAssumeCapacity(options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .response,
        );
        if (semantics.traditional_connect and options.status >= 200 and options.status < 300) {
            try stripSuccessfulConnectContentLength(&fields);
        }
        const declared_response_length = try contentLength(fields.items);
        try validateOutgoingResponseBodyForStatusWithLength(options.status, declared_response_length, options.body, options.trailers);
        try validateResponseBodyForRequestSemanticsWithLength(options.status, semantics, declared_response_length, options.body, options.trailers);
        try validateDeclaredResponseLengthValue(options.status, semantics, declared_response_length, options.body.len);
        if (responseShouldDefaultContentLengthValue(options.status, semantics, declared_response_length, options.body.len)) {
            const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{options.body.len}) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = content_length,
            });
        }
        try validateHeaderBlock(fields.items, .response);
        try validateHeaderBlock(options.trailers, .response_trailers);
        self.appendAutomaticDateHeader(&fields);
        var output_started = false;
        errdefer if (deadline != null and output_started) self.abortExtendedConnect(stream_id, response_cleanup.cleanupDeadline(self, deadline));
        if (deadline == null and !suppress_body and
            options.body.len != 0 and
            options.trailers.len == 0)
        {
            try self.writeHeadersThenData(
                stream_id,
                fields.items,
                options.body,
                true,
            );
            if (progress) |value| value.head_committed = true;
        } else {
            try self.writeHeadersUntil(
                stream_id,
                fields.items,
                suppress_body or
                    (options.body.len == 0 and options.trailers.len == 0),
                deadline,
            );
            output_started = true;
            if (progress) |value| value.head_committed = true;
        }
        if (!suppress_body) {
            if (options.body.len != 0 and (deadline != null or options.trailers.len != 0)) {
                var committed: usize = 0;
                try self.writeDataTrackedUntil(stream_id, options.body, options.trailers.len == 0, &committed, deadline);
            }
            if (options.trailers.len != 0) try self.writeHeadersUntil(stream_id, options.trailers, true, deadline);
        }
        if (release_stream) self.releasePeerStream(stream_id);
    }

    /// Start a response whose DATA is supplied incrementally.
    ///
    /// Unlike `writeResponse`, this sends only the final response HEADERS and
    /// returns a stateful writer. The writer enforces the declared
    /// Content-Length across calls, applies HTTP body-forbidden semantics, and
    /// releases the request stream only after DATA FIN, trailers, or reset.
    pub fn startResponse(
        self: *Connection,
        stream_id: u31,
        options: StreamingResponseOptions,
    ) Error!ResponseWriter {
        return self.startResponseInternal(stream_id, options, true);
    }

    pub fn startResponseWithDeadline(self: *Connection, stream_id: u31, options: StreamingResponseOptions, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!ResponseWriter {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.startResponseInternalUntil(stream_id, options, true, deadline);
    }

    pub fn startResponseWithTimeout(self: *Connection, stream_id: u31, options: StreamingResponseOptions, timeout: std.Io.Duration) ResponseTimeoutError!ResponseWriter {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.startResponseWithDeadline(stream_id, options, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn startResponseInternal(
        self: *Connection,
        stream_id: u31,
        options: StreamingResponseOptions,
        release_at_headers: bool,
    ) Error!ResponseWriter {
        return self.startResponseInternalUntil(stream_id, options, release_at_headers, null);
    }

    pub fn startResponseInternalUntil(
        self: *Connection,
        stream_id: u31,
        options: StreamingResponseOptions,
        release_at_headers: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!ResponseWriter {
        return response_start.start(self, stream_id, options, release_at_headers, deadline, .{
            .ErrorType = Error,
            .WriterType = ResponseWriter,
            .active = outboundStreamIsActive,
            .semantics = responseSemanticsFor,
            .date = appendAutomaticDateHeader,
            .write = writeHeadersUntil,
            .release = releasePeerStream,
        });
    }

    /// Validate, HPACK-encode, and submit bodyless responses as one TCP write.
    ///
    /// This is the server counterpart to `requestBatchInto`: the logical HTTP/2
    /// frames remain separate and ordered, while one syscall avoids creating a
    /// train of tiny TCP segments. Every stream must already be active. On
    /// success the streams are released; on validation/encoding failure no
    /// bytes are written and the caller can close or retry the connection.
    pub fn writeResponseBatch(
        self: *Connection,
        stream_ids: []const u31,
        responses: []const ResponseOptions,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (stream_ids.len != responses.len) return error.InvalidResponse;
        if (stream_ids.len == 0) return;
        for (stream_ids, 0..) |stream_id, index| {
            if (!self.outboundStreamIsActive(stream_id)) {
                return error.InvalidStreamId;
            }
            for (stream_ids[0..index]) |prior| {
                if (prior == stream_id) return error.InvalidStreamId;
            }
        }

        var needs_automatic_date = false;
        for (stream_ids, responses) |stream_id, options| {
            needs_automatic_date =
                try self.validateResponseBatchMember(
                    stream_id,
                    options,
                    true,
                ) or needs_automatic_date;
        }

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        const staged_encoder = try self.prepareStagedHpackEncoder();
        const automatic_date = if (needs_automatic_date)
            http_date.valueNow(self.io)
        else
            null;
        for (stream_ids, responses) |stream_id, options| {
            var status_buf: [3]u8 = undefined;
            const status = std.fmt.bufPrint(
                &status_buf,
                "{}",
                .{options.status},
            ) catch return error.InvalidStatus;
            const semantics = self.responseSemanticsFor(stream_id, options);

            var fields_stack: [16]http2.Hpack.HeaderField = undefined;
            const fields_capacity = std.math.add(
                usize,
                options.headers.len,
                2,
            ) catch return error.MessageTooLarge;
            const fields_buffer = if (fields_capacity <= fields_stack.len)
                fields_stack[0..fields_capacity]
            else
                try self.allocator.alloc(
                    http2.Hpack.HeaderField,
                    fields_capacity,
                );
            defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
                self.allocator.free(fields_buffer);
            };
            var fields: std.ArrayList(http2.Hpack.HeaderField) =
                .initBuffer(fields_buffer);
            fields.appendAssumeCapacity(.{
                .name = ":status",
                .value = status,
            });
            fields.appendSliceAssumeCapacity(options.headers);
            try outbound_headers.stripConnectionHeaders(
                self.allocator,
                &fields,
                .response,
            );
            if (semantics.traditional_connect and
                options.status >= 200 and options.status < 300)
            {
                try stripSuccessfulConnectContentLength(&fields);
            }
            const declared_length = try contentLength(fields.items);
            try validateOutgoingResponseBodyForStatusWithLength(
                options.status,
                declared_length,
                &.{},
                &.{},
            );
            try validateResponseBodyForRequestSemanticsWithLength(
                options.status,
                semantics,
                declared_length,
                &.{},
                &.{},
            );
            try validateDeclaredResponseLengthValue(
                options.status,
                semantics,
                declared_length,
                0,
            );
            appendAutomaticDateHeaderValue(&fields, automatic_date);
            try validateHeaderBlock(fields.items, .response);
            try validateHeaderListSize(
                fields.items,
                self.peer_max_header_list_size,
            );

            const block = try staged_encoder.encodeBlockRetained(
                self.allocator,
                fields.items,
            );
            try appendHeaderBlockBytes(
                batch,
                self.allocator,
                stream_id,
                block,
                true,
                self.outboundFramePayloadLimit(),
            );
        }

        self.transportForIo().writeAll(batch.items) catch |err| {
            self.commitStagedHpackEncoder();
            self.aggregate_timeout_unusable = true;
            return err;
        };
        self.commitStagedHpackEncoder();
        for (stream_ids) |stream_id| self.releasePeerStream(stream_id);
    }

    /// Send complete response bodies round-robin with flow-control backpressure.
    ///
    /// HEADERS are HPACK-staged transactionally, body slices stay borrowed, and
    /// `body_chunk_size` controls each stream's contribution per round. The
    /// method rejects trailers and body-suppressed response semantics because
    /// those require a different completion lifecycle. DATA consumes only
    /// currently available connection/per-stream credit; when every unfinished
    /// stream is blocked, the connection pumps WINDOW_UPDATE and cancellation
    /// frames before resuming. Validation, encoding, and allocation errors
    /// happen before wire I/O and are retryable. A transport or protocol error
    /// after submission begins may leave a partial response set on the wire;
    /// close the connection instead of retrying that batch.
    pub fn writeResponseBodyBatch(
        self: *Connection,
        stream_ids: []const u31,
        responses: []const ResponseOptions,
        body_chunk_size: usize,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (stream_ids.len != responses.len) return error.InvalidResponse;
        if (stream_ids.len == 0) return;
        if (body_chunk_size == 0) return error.InvalidFrameSize;

        var needs_automatic_date = false;
        for (stream_ids, responses, 0..) |stream_id, options, index| {
            if (!self.outboundStreamIsActive(stream_id)) {
                return error.InvalidStreamId;
            }
            for (stream_ids[0..index]) |prior| {
                if (prior == stream_id) return error.InvalidStreamId;
            }
            needs_automatic_date =
                try self.validateResponseBatchMember(
                    stream_id,
                    options,
                    false,
                ) or needs_automatic_date;
        }

        var views_stack: [16]BatchDataView = undefined;
        const views = if (responses.len <= views_stack.len)
            views_stack[0..responses.len]
        else
            try self.allocator.alloc(BatchDataView, responses.len);
        defer if (views.ptr != views_stack[0..].ptr) {
            self.allocator.free(views);
        };
        var offsets_stack: [16]usize = undefined;
        const offsets = if (responses.len <= offsets_stack.len)
            offsets_stack[0..responses.len]
        else
            try self.allocator.alloc(usize, responses.len);
        defer if (offsets.ptr != offsets_stack[0..].ptr) {
            self.allocator.free(offsets);
        };
        @memset(offsets, 0);
        var round_reserved_stack: [16]usize = undefined;
        const round_reserved =
            if (responses.len <= round_reserved_stack.len)
                round_reserved_stack[0..responses.len]
            else
                try self.allocator.alloc(usize, responses.len);
        defer if (round_reserved.ptr != round_reserved_stack[0..].ptr) {
            self.allocator.free(round_reserved);
        };
        var candidates_stack: [16]response_scheduler.Candidate =
            undefined;
        const candidates = if (responses.len <= candidates_stack.len)
            candidates_stack[0..responses.len]
        else
            try self.allocator.alloc(
                response_scheduler.Candidate,
                responses.len,
            );
        defer if (candidates.ptr != candidates_stack[0..].ptr) {
            self.allocator.free(candidates);
        };
        for (views, stream_ids, responses) |*view, stream_id, response| {
            view.* = .{ .stream_id = stream_id, .body = response.body };
        }
        try self.prepareBodyBatchData(views, body_chunk_size);

        // Materialize stream windows before HEADERS are visible so DATA
        // scheduling cannot fail with a local allocation after wire commit.
        for (stream_ids) |stream_id| {
            _ = try self.sendStreamWindow(stream_id);
        }

        const batch = &self.write_batch;
        batch.clearRetainingCapacity();
        const staged_encoder = try self.prepareStagedHpackEncoder();
        const automatic_date = if (needs_automatic_date)
            http_date.valueNow(self.io)
        else
            null;
        for (stream_ids, responses) |stream_id, options| {
            try self.appendResponseHeadToBatch(
                stream_id,
                options,
                batch,
                staged_encoder,
                automatic_date,
            );
        }

        self.transportForIo().writeAll(batch.items) catch |err| {
            // A transport failure may expose only a prefix of the staged HPACK
            // sequence. It cannot be retried or rolled back; commit encoder
            // state so accidental connection reuse fails closed.
            self.commitStagedHpackEncoder();
            self.aggregate_timeout_unusable = true;
            return err;
        };
        self.commitStagedHpackEncoder();
        try self.writeResponseBodyBatchData(
            views,
            offsets,
            round_reserved,
            candidates,
            body_chunk_size,
        );
        for (stream_ids) |stream_id| self.releasePeerStream(stream_id);
    }

    fn writeResponseBodyBatchData(
        self: *Connection,
        views: []const BatchDataView,
        offsets: []usize,
        round_reserved: []usize,
        candidates: []response_scheduler.Candidate,
        application_chunk_size: usize,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        std.debug.assert(views.len == offsets.len);
        std.debug.assert(views.len == round_reserved.len);
        std.debug.assert(views.len == candidates.len);
        const frame_limit = self.outboundFramePayloadLimit();
        var remaining_streams = views.len;
        for (views) |view| {
            if (view.body.len == 0) remaining_streams -= 1;
        }
        var next_stream: usize = 0;

        while (remaining_streams != 0) {
            self.batch_data_headers.clearRetainingCapacity();
            self.batch_data_parts.clearRetainingCapacity();
            @memset(round_reserved, 0);
            var made_progress = false;
            var reserved_connection_bytes: usize = 0;
            var wire_write_started = false;
            errdefer if (!wire_write_started) {
                // Before the wide write starts, every reserved byte can be
                // restored exactly. The successful write clears these counts;
                // any transport error thereafter retains conservative credit
                // because the emitted prefix is unknowable.
                restoreWindow(
                    &self.send_connection_window,
                    @intCast(reserved_connection_bytes),
                );
                for (views, round_reserved) |rollback_view, bytes| {
                    if (bytes == 0) continue;
                    if (self.sendStreamWindow(
                        rollback_view.stream_id,
                    ) catch null) |window| {
                        restoreWindow(window, @intCast(bytes));
                    }
                }
            };
            const pass_start = next_stream;
            const priority_selection =
                if (self.limits.no_rfc7540_priorities)
                    self.responseBatchSelection(
                        views,
                        offsets,
                        candidates,
                    )
                else
                    null;
            var scanned: usize = 0;
            while (scanned < views.len) : (scanned += 1) {
                const index = (pass_start + scanned) % views.len;
                const view = views[index];
                const offset = &offsets[index];
                if (offset.* == view.body.len) continue;
                if (self.send_connection_window.available() == 0) break;
                if (self.limits.no_rfc7540_priorities) {
                    const selection = priority_selection orelse break;
                    if (!selection.includes(candidates, index)) continue;
                }

                const stream_window = try self.sendStreamWindow(
                    view.stream_id,
                );
                const contribution_len = @min(
                    application_chunk_size,
                    view.body.len - offset.*,
                    self.send_connection_window.available(),
                    stream_window.available(),
                );
                if (contribution_len == 0) continue;

                try self.appendBodyBatchContribution(
                    view,
                    offset,
                    contribution_len,
                    frame_limit,
                    stream_window,
                );
                reserved_connection_bytes += contribution_len;
                round_reserved[index] = contribution_len;
                if (offset.* == view.body.len) remaining_streams -= 1;
                made_progress = true;
                if (!self.limits.no_rfc7540_priorities or
                    candidates[index].priority.incremental)
                {
                    // Rotate default and incremental traffic. A small
                    // connection WINDOW_UPDATE therefore cannot repeatedly
                    // feed one stream while equal peers starve.
                    next_stream = (index + 1) % views.len;
                }
            }

            if (made_progress) {
                // A partial wide write consumes an unknown prefix of reserved
                // credit. Keep the conservative reservation and require the
                // caller to close rather than retry this response batch.
                wire_write_started = true;
                const wire_parts = self.batch_data_parts.items;
                const transport = self.transportForIo();
                (if (wire_parts.len == 2)
                    transport.writeAllParts(wire_parts[0], wire_parts[1])
                else
                    transport.writeAllSlices(wire_parts)) catch |err| {
                    self.aggregate_timeout_unusable = true;
                    return err;
                };
                continue;
            }
            try self.waitForResponseBatchCapacity(views, offsets);
        }
    }

    fn appendBodyBatchContribution(
        self: *Connection,
        view: BatchDataView,
        offset: *usize,
        contribution_len: usize,
        frame_limit: usize,
        stream_window: *FlowWindow,
    ) Error!void {
        try self.send_connection_window.reserve(contribution_len);
        errdefer restoreWindow(
            &self.send_connection_window,
            @intCast(contribution_len),
        );
        try stream_window.reserve(contribution_len);
        errdefer restoreWindow(
            stream_window,
            @intCast(contribution_len),
        );

        const contribution_end = offset.* + contribution_len;
        while (offset.* < contribution_end) {
            const end = @min(
                contribution_end,
                offset.* + frame_limit,
            );
            const header_index = self.batch_data_headers.items.len;
            self.batch_data_headers.appendAssumeCapacity(undefined);
            try encodeFrameHeader(
                &self.batch_data_headers.items[header_index],
                .data,
                if (end == view.body.len and !view.ends_with_trailers)
                    flag_end_stream
                else
                    0,
                view.stream_id,
                end - offset.*,
            );
            self.batch_data_parts.appendAssumeCapacity(
                &self.batch_data_headers.items[header_index],
            );
            self.batch_data_parts.appendAssumeCapacity(
                view.body[offset.*..end],
            );
            offset.* = end;
        }
    }

    fn waitForResponseBatchCapacity(
        self: *Connection,
        views: []const BatchDataView,
        offsets: []const usize,
    ) Error!void {
        std.debug.assert(views.len == offsets.len);
        while (!self.responseBatchHasSendCapacity(views, offsets)) {
            // The server-side flow pump consumes every accepted control frame
            // before reading another one, so it can borrow frame-reader storage
            // instead of allocating an OwnedFrame for each WINDOW_UPDATE.
            const frame = try self.readFrameScratch();
            if (try self.handleConnectionFrame(frame)) continue;
            switch (frame.header.frame_type) {
                .goaway => {
                    try self.recordPeerGoAway(
                        try http2.GoAwayPayload.parse(frame),
                    );
                    return error.ConnectionGoAway;
                },
                .rst_stream => {
                    const reset =
                        try http2.ResetStreamPayload.parse(frame);
                    if (findBatchDataViewIndex(
                        views,
                        reset.stream_id,
                    ) != null) {
                        try self.recordResetStream(reset);
                        return error.StreamReset;
                    }
                    if (try self.handleQueuedSiblingReset(reset)) {
                        continue;
                    }
                    return error.UnexpectedFrame;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn responseBatchHasSendCapacity(
        self: *const Connection,
        views: []const BatchDataView,
        offsets: []const usize,
    ) bool {
        if (self.send_connection_window.available() == 0) return false;
        for (views, offsets) |view, offset| {
            if (offset < view.body.len and
                self.sendStreamWindowAvailable(view.stream_id) != 0)
            {
                return true;
            }
        }
        return false;
    }

    fn findBatchDataViewIndex(
        views: []const BatchDataView,
        stream_id: u31,
    ) ?usize {
        for (views, 0..) |view, index| {
            if (view.stream_id == stream_id) return index;
        }
        return null;
    }

    fn appendResponseHeadToBatch(
        self: *Connection,
        stream_id: u31,
        options: ResponseOptions,
        batch: *std.ArrayList(u8),
        encoder: *http2.Hpack.Encoder,
        automatic_date: ?*const [http_date.value_len]u8,
    ) Error!void {
        if (options.status < 100 or options.status > 999 or
            statusIsInformational(options.status))
        {
            return error.InvalidStatus;
        }
        var status_buf: [3]u8 = undefined;
        const status = std.fmt.bufPrint(
            &status_buf,
            "{}",
            .{options.status},
        ) catch return error.InvalidStatus;
        const semantics = self.responseSemanticsFor(stream_id, options);

        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            options.headers.len,
            3,
        ) catch return error.MessageTooLarge;
        const fields_buffer = if (fields_capacity <= fields_stack.len)
            fields_stack[0..fields_capacity]
        else
            try self.allocator.alloc(
                http2.Hpack.HeaderField,
                fields_capacity,
            );
        defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
            self.allocator.free(fields_buffer);
        };
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{
            .name = ":status",
            .value = status,
        });
        fields.appendSliceAssumeCapacity(options.headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .response,
        );
        const declared_length = try contentLength(fields.items);
        try validateOutgoingResponseBodyForStatusWithLength(
            options.status,
            declared_length,
            options.body,
            &.{},
        );
        try validateResponseBodyForRequestSemanticsWithLength(
            options.status,
            semantics,
            declared_length,
            options.body,
            &.{},
        );
        try validateDeclaredResponseLengthValue(
            options.status,
            semantics,
            declared_length,
            options.body.len,
        );
        if (responseShouldDefaultContentLengthValue(
            options.status,
            semantics,
            declared_length,
            options.body.len,
        )) {
            var content_length_buf: [32]u8 = undefined;
            const value = std.fmt.bufPrint(
                &content_length_buf,
                "{}",
                .{options.body.len},
            ) catch unreachable;
            fields.appendAssumeCapacity(.{
                .name = "content-length",
                .value = value,
            });
        }
        try validateHeaderBlock(fields.items, .response);
        appendAutomaticDateHeaderValue(&fields, automatic_date);
        try validateHeaderListSize(
            fields.items,
            self.peer_max_header_list_size,
        );
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            fields.items,
        );
        try appendHeaderBlockBytes(
            batch,
            self.allocator,
            stream_id,
            block,
            options.body.len == 0,
            self.outboundFramePayloadLimit(),
        );
    }

    pub fn promisePush(
        self: *Connection,
        parent_stream_id: u31,
        request_headers: []const http2.Hpack.HeaderField,
    ) Error!u31 {
        return self.promisePushUntil(
            parent_stream_id,
            request_headers,
            null,
        );
    }

    /// Reserve a promised stream and submit its complete PUSH_PROMISE field
    /// section under one caller-owned awake-clock deadline.
    pub fn promisePushWithDeadline(
        self: *Connection,
        parent_stream_id: u31,
        request_headers: []const http2.Hpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!u31 {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.promisePushUntil(
            parent_stream_id,
            request_headers,
            absolute,
        );
    }

    pub fn promisePushWithTimeout(
        self: *Connection,
        parent_stream_id: u31,
        request_headers: []const http2.Hpack.HeaderField,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!u31 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.promisePushWithDeadline(
            parent_stream_id,
            request_headers,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn promisePushUntil(
        self: *Connection,
        parent_stream_id: u31,
        request_headers: []const http2.Hpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!u31 {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server or !self.peerPushEnabled()) {
            return error.UnexpectedFrame;
        }
        if (!clientInitiatedStreamId(parent_stream_id) or
            !self.outboundStreamIsActive(parent_stream_id))
        {
            return error.InvalidStreamId;
        }
        try validateHeaderBlock(request_headers, .request);
        const promised_stream_id = try self.push_state.reserveLocal(
            self.allocator,
        );
        errdefer {
            _ = self.push_state.releaseLocal(promised_stream_id);
            self.forgetResponseSemantics(promised_stream_id);
        }
        try self.rememberResponseSemantics(
            promised_stream_id,
            findHeader(request_headers, ":method") orelse "GET",
            findHeader(request_headers, ":protocol"),
            http2.ExtensiblePriority.parseFields(request_headers),
        );
        const encoder = try self.prepareStagedHpackEncoder();
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            request_headers,
        );
        var submitted = false;
        self.writePushPromiseBlockUntil(
            parent_stream_id,
            promised_stream_id,
            block,
            deadline,
            &submitted,
        ) catch |err| {
            if (submitted) self.aggregate_timeout_unusable = true;
            return err;
        };
        self.commitStagedHpackEncoder();
        return promised_stream_id;
    }

    pub fn writePushedResponse(
        self: *Connection,
        promised_stream_id: u31,
        response: ResponseOptions,
    ) Error!void {
        return self.writePushedResponseUntil(
            promised_stream_id,
            response,
            null,
        );
    }

    /// Write the promised response HEADERS, DATA and trailers without renewing
    /// the deadline between phases.
    pub fn writePushedResponseWithDeadline(
        self: *Connection,
        promised_stream_id: u31,
        response: ResponseOptions,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.writePushedResponseUntil(
            promised_stream_id,
            response,
            absolute,
        );
    }

    pub fn writePushedResponseWithTimeout(
        self: *Connection,
        promised_stream_id: u31,
        response: ResponseOptions,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writePushedResponseWithDeadline(
            promised_stream_id,
            response,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn writePushedResponseUntil(
        self: *Connection,
        promised_stream_id: u31,
        response: ResponseOptions,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        const status = self.push_state.localStatus(
            promised_stream_id,
        ) orelse return error.InvalidStreamId;
        if (status == .canceled) {
            _ = self.push_state.releaseLocal(promised_stream_id);
            self.forgetResponseSemantics(promised_stream_id);
            _ = self.priority_state.remove(
                self.allocator,
                promised_stream_id,
            );
            return error.StreamReset;
        }
        var activated = false;
        errdefer if (activated) {
            self.releaseLocalStream(promised_stream_id);
        };
        if (!self.outboundStreamIsActive(promised_stream_id)) {
            if (self.peer_max_concurrent_streams) |limit| {
                if (self.active_local_streams.items.len >= limit) {
                    return error.FlowControlBlocked;
                }
            }
            try self.addActiveLocalStream(promised_stream_id);
            activated = true;
        }
        var progress: AggregateResponseWriteProgress = .{};
        self.writeResponseInternalTrackedUntil(
            promised_stream_id,
            response,
            true,
            deadline,
            &progress,
        ) catch |err| {
            if (progress.head_committed or
                self.aggregate_timeout_unusable or
                self.push_state.localStatus(promised_stream_id) == .canceled)
            {
                _ = self.push_state.releaseLocal(
                    promised_stream_id,
                );
                self.forgetResponseSemantics(promised_stream_id);
            }
            return err;
        };
        self.releaseLocalStream(promised_stream_id);
        _ = self.push_state.releaseLocal(promised_stream_id);
        self.forgetResponseSemantics(promised_stream_id);
    }

    pub fn peerPushEnabled(self: Connection) bool {
        // Absence of SETTINGS_ENABLE_PUSH means enabled by default for clients.
        // We initialize this true on server connections and update it when
        // client SETTINGS arrive. A server peer can never receive pushes, and
        // RFC 9113 defines its initial value as equivalent to zero.
        return self.role == .server and self.peer_enable_push;
    }

    pub fn serveOne(
        self: *Connection,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
    ) Error!u31 {
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        var owned_request = self.readRequest() catch |err| {
            self.sendServeReadError(err);
            return err;
        };
        const stream_id = owned_request.stream_id;
        defer owned_request.deinit(self.allocator);
        var response = try handler(context, owned_request);
        const invalid_final = normalizeHandlerResponse(
            &response,
            owned_request.method,
            owned_request.protocol != null,
        );
        try self.writeResponse(stream_id, response);
        if (invalid_final) return error.InvalidStatus;
        return stream_id;
    }

    pub fn sendServeReadError(self: *Connection, _: anyerror) void {
        if (self.serve_read_connection_error == null and self.serve_read_stream_error == null) return;
        self.sendServeReadErrorBefore(error.InvalidFrame, response_cleanup.cleanupDeadline(self, null));
    }

    fn sendServeReadErrorBefore(self: *Connection, _: anyerror, before: ?std.Io.Clock.Timestamp) void {
        if (self.serve_read_connection_error == null) {
            if (self.serve_read_stream_error) |stream_error| {
                if (!self.terminal_write_failed) {
                    if (before) |deadline| self.writeLocalErrorResetStreamUntil(stream_error.stream_id, stream_error.code, deadline) catch {
                        self.aggregate_timeout_unusable = true;
                        self.terminal_write_failed = true;
                    } else {
                        self.aggregate_timeout_unusable = true;
                        self.terminal_write_failed = true;
                    }
                }
                self.releasePeerStream(stream_error.stream_id);
                self.forgetStreamWindows(stream_error.stream_id);
            }
            return;
        }
        const mapping: struct {
            code: http2.ErrorCode,
            debug_data: []const u8,
        } = switch (self.serve_read_connection_error orelse return) {
            .compression => .{ .code = .compression_error, .debug_data = "hpack-decode" },
            .frame_sequence => .{ .code = .protocol_error, .debug_data = "frame-sequence" },
            .excessive_header_block => .{ .code = .enhance_your_calm, .debug_data = "header-block-limit" },
            .push_disabled => .{ .code = .protocol_error, .debug_data = "push-disabled" },
        };
        self.sendProtocolGoAwayBefore(
            self.lastPeerProcessedStreamId(),
            mapping.code,
            mapping.debug_data,
            before,
        );
    }

    pub fn serve(
        self: *Connection,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (*HandlerContext, OwnedRequest) Error!ResponseOptions,
        max_requests: usize,
    ) Error!usize {
        var served: usize = 0;
        var last_stream_id: u31 = 0;
        while (served < max_requests) : (served += 1) {
            last_stream_id = try self.serveOne(HandlerContext, context, handler);
        }
        try self.sendGoAway(last_stream_id, .no_error, "serve-complete");
        return served;
    }

    /// Read a bounded batch of complete requests, run the handlers
    /// concurrently, and serialize responses in handler-completion order.
    ///
    /// `Connection` remains the sole frame-reader, HPACK owner, and socket
    /// writer. Workers receive immutable owned requests and never touch the
    /// connection. Response slices may borrow the corresponding request or
    /// caller-managed context because every request remains alive until the
    /// whole batch is complete. The context must support concurrent calls.
    /// While handlers run, the owner services connection-control frames and
    /// retains bounded application frames in wire order for later readers.
    /// Handler failures reset only their stream with INTERNAL_ERROR and are
    /// returned by input index. A handler-returned 1xx is replaced with final
    /// 500 and recorded as InvalidStatus for that index. Setup, request-read,
    /// queue, or response-write failures make the connection unusable and
    /// abort the entire batch.
    /// CONNECT requests are rejected because their open-ended tunnel lifetime
    /// cannot be represented by this completed-response API.
    pub fn serveRequestBatchConcurrent(
        self: *Connection,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!ResponseOptions,
        request_count: usize,
    ) ConcurrentHandlerServeError!ConcurrentHandlerServeResult {
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.active_peer_streams.items.len != 0 or
            self.pendingRequestCount() != 0 or
            self.priority_state.idleRequestCount() != 0)
        {
            return error.InvalidServeOptions;
        }
        if (self.limits.max_concurrent_streams) |limit| {
            if (request_count > limit) return error.InvalidServeOptions;
        }

        const errors = try self.allocator.alloc(?anyerror, request_count);
        errdefer self.allocator.free(errors);
        @memset(errors, null);
        if (request_count == 0) {
            return .{ .allocator = self.allocator, .errors = errors };
        }

        const Worker = RequestBatchHandlerTask(
            HandlerContext,
            handler,
        );
        const requests = try self.allocator.alloc(
            OwnedRequest,
            request_count,
        );
        defer self.allocator.free(requests);
        var initialized: usize = 0;
        defer for (requests[0..initialized]) |*owned_request| {
            owned_request.deinit(self.allocator);
        };
        const completion_storage = try self.allocator.alloc(
            Worker.Completion,
            request_count,
        );
        defer self.allocator.free(completion_storage);
        var completions: Worker.CompletionQueue = .init(completion_storage);
        var group: std.Io.Group = .init;
        var group_finished = false;
        defer if (!group_finished) group.cancel(self.io);
        errdefer {
            self.aggregate_timeout_unusable = true;
            for (requests[0..initialized]) |owned_request| {
                self.releasePeerStream(owned_request.stream_id);
                self.forgetStreamWindows(owned_request.stream_id);
            }
        }

        while (initialized < request_count) {
            self.serve_read_connection_error = null;
            self.serve_read_stream_error = null;
            requests[initialized] = self.readRequest() catch |err| {
                self.sendServeReadError(err);
                return err;
            };
            const index = initialized;
            initialized += 1;
            if (methodIsConnect(requests[index].method)) {
                return error.InvalidHeader;
            }
            try group.concurrent(self.io, Worker.run, .{Worker{
                .io = self.io,
                .completions = &completions,
                .context = context,
                .request = &requests[index],
                .index = index,
            }});
        }

        const CompletionWait = (std.Io.QueueClosedError ||
            std.Io.Cancelable)!Worker.Completion;
        const FrameWait = Error!OwnedFrame;
        const Wake = union(enum) {
            completion: CompletionWait,
            frame: FrameWait,
        };
        var completed: usize = 0;
        while (completed < request_count) {
            var wake_buffer: [2]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(
                self.io,
                &wake_buffer,
            );
            var select_finished = false;
            defer if (!select_finished) {
                while (select.cancel()) |wake| switch (wake) {
                    .completion => {},
                    .frame => |result| if (result) |frame_value| {
                        var frame = frame_value;
                        frame.deinit(self.allocator);
                    } else |_| {},
                };
            };
            try select.concurrent(
                .completion,
                Worker.CompletionQueue.getOne,
                .{ &completions, self.io },
            );
            try select.concurrent(
                .frame,
                Connection.readConcurrentHandlerFrame,
                .{self},
            );

            var completion: ?Worker.Completion = null;
            var frame: ?OwnedFrame = null;
            switch (try select.await()) {
                .completion => |result| completion = result catch |err|
                    switch (err) {
                        error.Closed => unreachable,
                        error.Canceled => return error.Canceled,
                    },
                .frame => |result| frame = try result,
            }
            while (select.cancel()) |wake| switch (wake) {
                .completion => |result| {
                    if (result) |value| {
                        completion = value;
                    } else |err| switch (err) {
                        error.Closed => unreachable,
                        error.Canceled => {},
                    }
                },
                .frame => |result| {
                    if (result) |value| {
                        frame = value;
                    } else |err| switch (err) {
                        error.Canceled => {},
                        else => return err,
                    }
                },
            };
            select_finished = true;

            if (frame) |frame_value| {
                try self.handleConcurrentHandlerFrame(frame_value);
            }
            const handler_completion = completion orelse continue;
            completed += 1;
            const owned_request = &requests[handler_completion.index];
            var response = handler_completion.result catch |handler_error| {
                errors[handler_completion.index] = handler_error;
                self.writeResetStreamFrame(
                    owned_request.stream_id,
                    .internal_error,
                ) catch |write_error| {
                    self.aggregate_timeout_unusable = true;
                    return write_error;
                };
                self.releasePeerStream(owned_request.stream_id);
                self.forgetStreamWindows(owned_request.stream_id);
                continue;
            };
            const invalid_final = normalizeHandlerResponse(
                &response,
                owned_request.method,
                owned_request.protocol != null,
            );
            self.writeResponse(owned_request.stream_id, response) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
            if (invalid_final) {
                errors[handler_completion.index] = error.InvalidStatus;
            }
        }
        try group.await(self.io);
        group_finished = true;
        return .{ .allocator = self.allocator, .errors = errors };
    }

    pub const ConcurrentStream = Http2ConcurrentEngine.Stream;

    /// Continuously accept request streams, run one handler task per stream,
    /// and serialize all connection state through this owner. Handlers pull
    /// request DATA from an owner-filled buffer and may write buffered or
    /// streaming responses, including trailers.
    pub fn serveConcurrentStreams(
        self: *Connection,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            *ConcurrentStream,
        ) anyerror!void,
        options: concurrent.Options,
    ) anyerror!concurrent.Summary {
        var engine = Http2ConcurrentEngine.init(
            self,
            self.allocator,
            self.io,
            options,
        );
        defer engine.deinit();
        return engine.serve(HandlerContext, context, handler);
    }

    fn readConcurrentHandlerFrame(
        self: *Connection,
    ) Error!OwnedFrame {
        return self.readOwnedTransportFrameWithDeadline(null);
    }

    fn handleConcurrentHandlerFrame(
        self: *Connection,
        frame_value: OwnedFrame,
    ) Error!void {
        var frame = frame_value;
        var frame_owned = true;
        defer if (frame_owned) frame.deinit(self.allocator);
        if (try self.handleConnectionOrGoAwayFrame(frame.frame)) return;
        self.queuePendingApplicationFrame(frame) catch |err| {
            self.recoverPendingApplicationFrameAfterQueueFailure(frame);
            frame_owned = false;
            return err;
        };
        frame_owned = false;
    }

    pub fn writeInformationalResponse(self: *Connection, stream_id: u31, status_code: u16, headers: []const http2.Hpack.HeaderField) Error!void {
        return self.writeInformationalResponseUntil(
            stream_id,
            status_code,
            headers,
            null,
        );
    }

    pub fn writeInformationalResponseWithDeadline(
        self: *Connection,
        stream_id: u31,
        status_code: u16,
        headers: []const http2.Hpack.HeaderField,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.writeInformationalResponseUntil(
            stream_id,
            status_code,
            headers,
            absolute,
        );
    }

    pub fn writeInformationalResponseWithTimeout(
        self: *Connection,
        stream_id: u31,
        status_code: u16,
        headers: []const http2.Hpack.HeaderField,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeInformationalResponseWithDeadline(
            stream_id,
            status_code,
            headers,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn writeInformationalResponseUntil(
        self: *Connection,
        stream_id: u31,
        status_code: u16,
        headers: []const http2.Hpack.HeaderField,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (!self.outboundStreamIsActive(stream_id)) {
            return error.InvalidStreamId;
        }
        if (!statusIsInformational(status_code)) return error.InvalidStatus;
        var status_buf: [3]u8 = undefined;
        const status = std.fmt.bufPrint(&status_buf, "{}", .{status_code}) catch return error.InvalidStatus;
        var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
        defer fields.deinit(self.allocator);
        try fields.append(self.allocator, .{ .name = ":status", .value = status });
        for (headers) |header| try fields.append(self.allocator, header);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .response,
        );
        try validateOutgoingResponseBodyForStatus(status_code, fields.items, &.{}, &.{});
        try validateHeaderBlock(fields.items, .response);
        // HTTP/2 informational responses never end the stream; the final
        // response HEADERS still owns END_STREAM/body/trailer semantics.  This
        // mirrors h2's send_informational path rather than abusing the final
        // writeResponse helper.
        try self.writeHeadersUntil(stream_id, fields.items, false, deadline);
    }

    /// Send a PING and wait indefinitely for the ACK carrying the same opaque
    /// payload. Use `pingWithTimeout` for liveness probes against peers that
    /// may remain connected without ever answering.
    pub fn ping(self: *Connection, data: [8]u8) Error![8]u8 {
        if (reservedInternalPingPayload(data)) {
            return error.InvalidFrame;
        }
        return self.pingUntil(data, null);
    }

    /// Send a PING and wait at most `timeout` for its matching ACK.
    ///
    /// The timeout becomes one absolute deadline before the PING is written,
    /// so stale ACKs and interleaved frames cannot renew the health-check
    /// budget. Connection-control frames are handled immediately. Application
    /// frames are retained in wire order for the next request/response reader,
    /// up to `Limits.max_pending_ping_frames`; they are never silently dropped.
    pub fn pingWithTimeout(
        self: *Connection,
        data: [8]u8,
        timeout: std.Io.Duration,
    ) Error![8]u8 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        if (reservedInternalPingPayload(data)) {
            return error.InvalidFrame;
        }
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.pingUntil(data, deadline);
    }

    /// Send a PING and wait for its matching ACK under a caller-owned
    /// awake-clock deadline. Validation happens before writing so a timestamp
    /// from another clock domain, or an already-expired budget, cannot emit a
    /// probe that the caller no longer intends to wait for.
    pub fn pingWithDeadline(
        self: *Connection,
        data: [8]u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error![8]u8 {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        if (reservedInternalPingPayload(data)) {
            return error.InvalidFrame;
        }
        return self.pingUntil(data, absolute);
    }

    /// Submit one PING for a single-reader background owner without waiting
    /// for its ACK. Normal frame pumping continues to process application
    /// streams and records only an ACK with the exact opaque payload.
    ///
    /// The deadline bounds this write only. The owner must enforce its own ACK
    /// deadline, query `takePingProbeAcknowledged`, and call
    /// `abandonPingProbe` if that deadline expires.
    pub fn beginPingProbeWithDeadline(
        self: *Connection,
        data: [8]u8,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        if (reservedInternalPingPayload(data)) return error.InvalidFrame;
        if (self.ping_probe_payload != null or self.ping_probe_acknowledged) {
            return error.WriteInProgress;
        }
        try self.writeControlFrameUntil(.ping, 0, &data, absolute);
        self.ping_probe_payload = data;
    }

    /// Convenience form of `beginPingProbeWithDeadline` using an awake-clock
    /// budget. A non-positive budget is rejected before any frame is written.
    pub fn beginPingProbeWithTimeout(
        self: *Connection,
        data: [8]u8,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.beginPingProbeWithDeadline(
            data,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn pingProbePending(self: *const Connection) bool {
        return self.ping_probe_payload != null;
    }

    pub fn pingEnforcementStats(self: Connection) PingEnforcementStats {
        return self.ping_enforcement.snapshot();
    }

    /// Consume the completion edge for the current background probe. A stale
    /// or mismatched PING ACK never satisfies a later probe.
    pub fn takePingProbeAcknowledged(self: *Connection) bool {
        const acknowledged = self.ping_probe_acknowledged;
        self.ping_probe_acknowledged = false;
        return acknowledged;
    }

    /// Stop tracking an expired background probe. Its late ACK remains a legal
    /// connection-control frame but cannot complete a future payload.
    pub fn abandonPingProbe(self: *Connection) void {
        self.ping_probe_payload = null;
        self.ping_probe_acknowledged = false;
    }

    /// Complete the recommended two-phase HTTP/2 server shutdown handshake.
    /// Existing streams remain usable; the final GOAWAY rejects later request
    /// stream IDs beyond the synchronized processing boundary. This call must
    /// be the connection's sole frame reader for its duration.
    pub fn gracefulShutdown(self: *Connection) Error!void {
        return self.gracefulShutdownUntil(null);
    }

    pub fn gracefulShutdownWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.graceful_shutdown_phase == .failed) {
            return error.ConnectionClosed;
        }
        if (self.graceful_shutdown_phase == .complete) return;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.gracefulShutdownUntil(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Use one absolute awake-clock budget for both GOAWAY writes, the
    /// synchronization PING write, and its matching ACK. Any bounded write
    /// error is terminal because an unknown frame prefix may already be on the
    /// wire; an ACK-read timeout remains resumable without retransmitting.
    pub fn gracefulShutdownWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.graceful_shutdown_phase == .failed) {
            return error.ConnectionClosed;
        }
        if (self.graceful_shutdown_phase == .complete) return;
        return self.gracefulShutdownUntil(
            try deadline_policy.usableAwake(self.io, deadline),
        );
    }

    fn gracefulShutdownUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        if (self.graceful_shutdown_phase == .failed) {
            return error.ConnectionClosed;
        }
        if (self.graceful_shutdown_phase == .complete) return;

        if (self.graceful_shutdown_phase == .open) {
            if (self.local_goaway_last_stream_id == null) {
                self.sendGoAwayUntil(
                    std.math.maxInt(u31),
                    .no_error,
                    &.{},
                    deadline,
                ) catch |err| {
                    // Stream writes expose no committed-byte count. An error
                    // can therefore leave a partial frame (or TLS record) on
                    // the wire; replaying it would corrupt framing.
                    self.graceful_shutdown_phase = .failed;
                    return err;
                };
            }
            if (self.pending_application_overflow.hasValue()) {
                return error.MessageTooLarge;
            }
            self.writeControlFrameUntil(
                .ping,
                0,
                &graceful_shutdown_ping_payload,
                deadline,
            ) catch |err| {
                self.graceful_shutdown_phase = .failed;
                return err;
            };
            // `.synchronizing` means one complete probe is outstanding. Only
            // a read timeout is resumable; no retry can ever retransmit it.
            self.graceful_shutdown_phase = .synchronizing;
        }

        if (self.graceful_shutdown_phase == .synchronizing) {
            _ = self.waitForPingAckUntil(
                graceful_shutdown_ping_payload,
                deadline,
            ) catch |err| {
                if (err == error.Timeout and
                    !self.aggregate_timeout_unusable) return err;
                if (err == error.MessageTooLarge or
                    err == error.ResponseAvailable)
                {
                    self.rollbackGracefulPreadmissions();
                    // The next frame is retained, but the connection-level
                    // PING ACK may still be in flight. Require the application
                    // to drain and restart shutdown explicitly rather than
                    // silently choosing a boundary from rolled-back state.
                    self.graceful_shutdown_phase = .failed;
                    return err;
                }
                // A failed PING response/control write is indistinguishable
                // from a partially committed frame and cannot be retried.
                self.graceful_shutdown_phase = .failed;
                return err;
            };
            // Keep this distinct from `.complete`: if the final GOAWAY write
            // begins, no later call may wait for an ACK already consumed.
            self.graceful_shutdown_phase = .synchronized;
            self.clearGracefulPreadmitDecoder();
            self.graceful_preadmit_base_processed_stream_id = null;
        }
        const boundary = @min(
            self.local_goaway_last_stream_id orelse std.math.maxInt(u31),
            self.lastPeerProcessedStreamId(),
        );
        self.sendGoAwayUntil(
            boundary,
            .no_error,
            &.{},
            deadline,
        ) catch |err| {
            self.graceful_shutdown_phase = .failed;
            return err;
        };
        self.graceful_shutdown_phase = .complete;
        // Markers are needed only to let already-queued HEADERS bypass the
        // monotonic admission check. They stay until those requests are read.
    }

    pub fn gracefulShutdownComplete(self: Connection) bool {
        return self.graceful_shutdown_phase == .complete;
    }

    /// Run one inactivity-triggered keep-alive cycle on this blocking
    /// connection. This method must be the sole frame reader for its duration.
    ///
    /// Frames received before `interval` expires count as activity and are
    /// handled or retained normally, moving the interval forward. Once the
    /// connection has been quiet for the full interval, a PING is sent and its
    /// exact ACK must arrive within `timeout`. The timeout is not refreshed by
    /// unrelated traffic. Callers can repeat this method to drive periodic
    /// keep-alive without introducing a second concurrent transport reader.
    pub fn keepAlive(
        self: *Connection,
        data: [8]u8,
        options: KeepAliveOptions,
    ) Error!KeepAliveResult {
        if (options.interval.nanoseconds <= 0 or
            options.timeout.nanoseconds <= 0)
        {
            return error.Timeout;
        }
        if (!options.while_idle and !self.hasActiveStreams()) {
            return .skipped_idle;
        }
        if (self.pending_application_overflow.hasValue()) {
            return error.MessageTooLarge;
        }
        if (self.last_peer_frame_at == null) {
            // Directly initialized Connections appear in low-level adapters
            // and tests. Treat their first keep-alive call as the activity
            // anchor rather than immediately probing from Timestamp.zero.
            self.last_peer_frame_at = std.Io.Clock.awake.now(self.io);
        }

        while (true) {
            const interval_deadline = std.Io.Clock.Timestamp{
                .raw = self.last_peer_frame_at.?.addDuration(options.interval),
                .clock = .awake,
            };
            const borrowed = self.readTransportFrameWithDeadline(
                interval_deadline,
            ) catch |err| switch (err) {
                error.Timeout => {
                    _ = try self.pingWithTimeout(data, options.timeout);
                    return .acknowledged;
                },
                else => return err,
            };
            try self.handleOrQueueKeepAliveFrame(borrowed, interval_deadline);
            if (!options.while_idle and !self.hasActiveStreams()) {
                return .skipped_idle;
            }
        }
    }

    fn hasActiveStreams(self: *const Connection) bool {
        return self.active_local_streams.items.len != 0 or
            self.active_peer_streams.items.len != 0;
    }

    fn handleOrQueueKeepAliveFrame(
        self: *Connection,
        borrowed: frame_io.BorrowedFrame,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (try self.handleConnectionOrGoAwayFrameUntil(borrowed.frame, deadline)) return;

        var frame = try self.copyBorrowedFrame(borrowed);
        var frame_owned = true;
        defer if (frame_owned) frame.deinit(self.allocator);
        self.queuePendingApplicationFrame(frame) catch |err| {
            self.recoverPendingApplicationFrameAfterQueueFailure(frame);
            frame_owned = false;
            return err;
        };
        frame_owned = false;
    }

    fn pingUntil(
        self: *Connection,
        data: [8]u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![8]u8 {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        // An earlier bounded wait could retain one frame beyond the configured
        // queue cap. Require the application to drain it before another probe
        // can consume later wire data out of order.
        if (self.pending_application_overflow.hasValue()) {
            return error.MessageTooLarge;
        }
        try self.writeControlFrameUntil(.ping, 0, &data, deadline);
        return self.waitForPingAckUntil(data, deadline);
    }

    /// Wait for an already-written PING without emitting another copy. This is
    /// used by retryable graceful-shutdown deadlines so timeout retries do not
    /// create multiple indistinguishable synchronization probes.
    fn waitForPingAckUntil(
        self: *Connection,
        data: [8]u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![8]u8 {
        while (true) {
            // Do not consume the pending queue here: those frames predate this
            // PING and waiting on them would cycle them back into that queue.
            const borrowed = try self.readTransportFrameWithDeadline(deadline);
            if (borrowed.frame.header.frame_type == .ping) {
                if ((borrowed.frame.header.flags & flag_ack) == 0) {
                    const ping_payload = try http2.PingPayload.parse(
                        borrowed.frame,
                    );
                    try self.enforcePeerPingUntil(deadline);
                    try self.writeControlFrameUntil(
                        .ping,
                        flag_ack,
                        &ping_payload.data,
                        deadline,
                    );
                    continue;
                }
                const ack_payload =
                    (try http2.PingPayload.parse(borrowed.frame)).data;
                try self.applyPingAck(ack_payload);
                // Rust h2 keeps outstanding user/shutdown PING payloads and
                // only completes the operation when the ACK echoes that exact
                // opaque value. Unknown ACKs are legal on the wire, but
                // treating one as completion lets a stale peer ACK satisfy a
                // newer health check.
                if (!std.mem.eql(u8, &ack_payload, &data)) continue;
                return ack_payload;
            }
            if (try self.handleConnectionOrGoAwayFrameUntil(borrowed.frame, deadline)) {
                continue;
            }

            var frame = try self.copyBorrowedFrame(borrowed);
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.allocator);
            self.ensurePendingApplicationFrameCapacity() catch |err| {
                self.recoverPendingApplicationFrameAfterQueueFailure(frame);
                frame_owned = false;
                return err;
            };
            _ = self.preadmitGracefulPeerRequest(
                frame.frame,
            ) catch |err| {
                // Admission can allocate after the frame has left transport.
                // Preserve it as the next application frame on every failure.
                self.recoverPendingApplicationFrameAfterQueueFailure(frame);
                frame_owned = false;
                return err;
            };
            if (self.role == .client and self.limits.enable_push) {
                self.predecodeSiblingFrame(frame.frame) catch |err| {
                    self.aggregate_timeout_unusable = true;
                    self.recoverPendingApplicationFrameAfterQueueFailure(frame);
                    frame_owned = false;
                    return err;
                };
            }
            // Capacity was secured before mutating stream admission, so this
            // append cannot strand a preadmitted stream on allocation error.
            self.pending_application_frames.appendAssumeCapacity(
                RetainedFrame.fromOwned(frame),
            );
            frame_owned = false;
        }
    }

    pub fn readPing(self: *Connection) Error![8]u8 {
        return self.readPingUntil(null);
    }

    pub fn readPingWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error![8]u8 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readPingUntil(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readPingWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error![8]u8 {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readPingUntil(deadline);
    }

    fn readPingUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![8]u8 {
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            defer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .ping) {
                if (try self.handleConnectionOrGoAwayFrameUntil(frame.frame, deadline)) continue;
                return error.UnexpectedFrame;
            }
            const ping_payload = try http2.PingPayload.parse(frame.frame);
            if ((frame.frame.header.flags & flag_ack) != 0) {
                try self.applyPingAck(ping_payload.data);
                continue;
            }
            try self.enforcePeerPingUntil(deadline);
            try self.writeControlFrameUntil(
                .ping,
                flag_ack,
                &ping_payload.data,
                deadline,
            );
            if (bdp.isProbePayload(ping_payload.data)) continue;
            return ping_payload.data;
        }
    }

    pub fn sendGoAway(self: *Connection, last_stream_id: u31, error_code: http2.ErrorCode, debug_data: []const u8) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        return self.sendGoAwayUntil(
            last_stream_id,
            error_code,
            debug_data,
            null,
        );
    }

    /// Submit GOAWAY under one caller-owned awake-clock deadline. The local
    /// monotonic Last-Stream-ID boundary changes only after the complete frame
    /// reaches the transport.
    pub fn sendGoAwayWithDeadline(
        self: *Connection,
        last_stream_id: u31,
        error_code: http2.ErrorCode,
        debug_data: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        return self.sendGoAwayUntil(
            last_stream_id,
            error_code,
            debug_data,
            absolute,
        );
    }

    pub fn sendGoAwayWithTimeout(
        self: *Connection,
        last_stream_id: u31,
        error_code: http2.ErrorCode,
        debug_data: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendGoAwayWithDeadline(
            last_stream_id,
            error_code,
            debug_data,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendGoAwayUntil(
        self: *Connection,
        last_stream_id: u31,
        error_code: http2.ErrorCode,
        debug_data: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        try self.validateLocalGoAway(last_stream_id);
        var stack_storage: [256]u8 = undefined;
        const total_len = try http2.GoAwayPayload.encodedLen(debug_data.len);
        if (total_len <= stack_storage.len) {
            const encoded = try http2.GoAwayPayload.writeInto(
                &stack_storage,
                last_stream_id,
                error_code,
                debug_data,
            );
            try self.writeEncodedControlUntil(encoded, deadline);
        } else {
            const storage = try self.allocator.alloc(u8, total_len);
            defer self.allocator.free(storage);
            const encoded = try http2.GoAwayPayload.writeInto(
                storage,
                last_stream_id,
                error_code,
                debug_data,
            );
            try self.writeEncodedControlUntil(encoded, deadline);
        }
        self.local_goaway_last_stream_id = last_stream_id;
    }

    pub fn sendProtocolGoAway(self: *Connection, last: u31, code: http2.ErrorCode, detail: []const u8, operation_deadline: ?std.Io.Clock.Timestamp) void {
        self.aggregate_timeout_unusable = true;
        if (self.terminal_write_failed) return;
        self.sendProtocolGoAwayBefore(last, code, detail, response_cleanup.cleanupDeadline(self, operation_deadline));
    }

    fn sendProtocolGoAwayBefore(self: *Connection, last: u31, code: http2.ErrorCode, detail: []const u8, before: ?std.Io.Clock.Timestamp) void {
        protocol_error_output.goAway(self, last, code, detail, before, sendGoAwayUntil);
    }

    fn writeControlFrameUntil(
        self: *Connection,
        frame_type: http2.FrameType,
        flags: u8,
        payload: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.terminal_write_failed) return error.ConnectionClosed;
        if (deadline) |absolute| {
            var committed: usize = 0;
            writeFrameTransportWithDeadline(
                self.allocator,
                self.transportForIo(),
                frame_type,
                flags,
                0,
                payload,
                &committed,
                absolute,
            ) catch |err| {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                return err;
            };
            if (frame_type == .window_update) {
                self.resetPeerPingEnforcement();
            }
            if (frame_type == .settings and flags & flag_ack != 0) {
                self.webtransport_settings.acknowledgePeer();
            }
            return;
        }
        writeFrameTransport(
            self.allocator,
            self.transportForIo(),
            frame_type,
            flags,
            0,
            payload,
        ) catch |err| {
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return err;
        };
        if (frame_type == .window_update) self.resetPeerPingEnforcement();
        if (frame_type == .settings and flags & flag_ack != 0) {
            self.webtransport_settings.acknowledgePeer();
        }
    }

    fn writeEncodedControlUntil(
        self: *Connection,
        encoded: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.terminal_write_failed) return error.ConnectionClosed;
        if (deadline) |absolute| {
            var committed: usize = 0;
            self.transportForIo().writeAllWithDeadline(
                encoded,
                &committed,
                absolute,
            ) catch |err| {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                return err;
            };
            return;
        }
        return self.transportForIo().writeAll(encoded) catch |err| {
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return err;
        };
    }

    pub fn sendOrigins(
        self: *Connection,
        origins: []const []const u8,
    ) Error!void {
        return self.sendOriginsUntil(origins, null);
    }

    pub fn sendOriginsWithDeadline(
        self: *Connection,
        origins: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.sendOriginsUntil(origins, absolute);
    }

    pub fn sendOriginsWithTimeout(
        self: *Connection,
        origins: []const []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendOriginsWithDeadline(
            origins,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendOriginsUntil(
        self: *Connection,
        origins: []const []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.OriginPayload.write(
            &encoded,
            self.allocator,
            origins,
        );
        try self.writeEncodedControlUntil(encoded.items, deadline);
    }

    pub fn sendAlternativeService(
        self: *Connection,
        stream_id: u31,
        origin: []const u8,
        field_value: []const u8,
    ) Error!void {
        return self.sendAlternativeServiceUntil(
            stream_id,
            origin,
            field_value,
            null,
        );
    }

    pub fn sendAlternativeServiceWithDeadline(
        self: *Connection,
        stream_id: u31,
        origin: []const u8,
        field_value: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.sendAlternativeServiceUntil(
            stream_id,
            origin,
            field_value,
            absolute,
        );
    }

    pub fn sendAlternativeServiceWithTimeout(
        self: *Connection,
        stream_id: u31,
        origin: []const u8,
        field_value: []const u8,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendAlternativeServiceWithDeadline(
            stream_id,
            origin,
            field_value,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendAlternativeServiceUntil(
        self: *Connection,
        stream_id: u31,
        origin: []const u8,
        field_value: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.role != .server) return error.UnexpectedFrame;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        try http2.AltSvcPayload.write(
            &encoded,
            self.allocator,
            stream_id,
            origin,
            field_value,
        );
        try self.writeEncodedControlUntil(encoded.items, deadline);
    }

    pub fn validateLocalGoAway(self: Connection, last_stream_id: u31) Error!void {
        if (self.local_goaway_last_stream_id) |last| {
            if (last_stream_id > last) return error.InvalidFrame;
        }
    }

    pub fn readGoAway(self: *Connection) Error!OwnedGoAway {
        return self.readGoAwayUntil(null);
    }

    pub fn readGoAwayWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedGoAway {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readGoAwayUntil(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readGoAwayWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedGoAway {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readGoAwayUntil(deadline);
    }

    fn readGoAwayUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedGoAway {
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .goaway) {
                if (try self.handleConnectionOrGoAwayFrameUntil(frame.frame, deadline)) {
                    frame.deinit(self.allocator);
                    continue;
                }
                return error.UnexpectedFrame;
            }
            const goaway = try http2.GoAwayPayload.parse(frame.frame);
            try self.recordPeerGoAway(goaway);
            return .{ .frame = frame, .goaway = goaway };
        }
    }

    /// Return the most restrictive Last-Stream-ID observed from peer GOAWAY.
    /// Multiple GOAWAY frames may lower this boundary but cannot raise it.
    pub fn peerGoAwayLastStreamId(self: Connection) ?u31 {
        return self.peer_goaway_last_stream_id;
    }

    pub fn peerGoAwayTooManyPings(self: Connection) bool {
        return self.peer_goaway_too_many_pings;
    }

    /// Classify whether retrying a locally initiated request is safe after the
    /// peer's latest GOAWAY. This reports only processing certainty; callers
    /// must still decide whether the method/body itself is replayable.
    pub fn goAwayRetryDisposition(
        self: Connection,
        stream_id: u31,
    ) GoAwayRetryDisposition {
        const last = self.peer_goaway_last_stream_id orelse
            return .no_goaway;
        return if (stream_id > last)
            .safe_to_retry
        else
            .may_have_been_processed;
    }

    pub fn sendResetStream(self: *Connection, stream_id: u31, error_code: http2.ErrorCode) Error!void {
        return self.sendResetStreamUntil(stream_id, error_code, null);
    }

    pub fn sendResetStreamWithDeadline(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.sendResetStreamUntil(
            stream_id,
            error_code,
            absolute,
        );
    }

    pub fn sendResetStreamWithTimeout(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendResetStreamWithDeadline(
            stream_id,
            error_code,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendResetStreamUntil(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (!self.outboundStreamIsActive(stream_id)) return error.InvalidStreamId;
        try self.writeResetStreamFrameUntil(stream_id, error_code, deadline);
        self.releaseLocalStream(stream_id);
        self.releasePeerStream(stream_id);
        self.forgetStreamWindows(stream_id);
    }

    pub const local_stream_termination_hooks = .{
        .active = outboundStreamIsActive,
        .peerActive = peerStreamIsActive,
        .reset = writeResetStreamFrameUntil,
        .terminalReset = writeTerminalResetStreamUntil,
        .emptyData = flow_output.writeEmpty,
        .transport = transportForIo,
        .releaseLocal = releaseLocalStream,
        .releasePeer = releasePeerStream,
        .forgetWindows = forgetStreamWindows,
    };

    pub fn terminateOwnedStream(self: *Connection, id: u31, code: http2.ErrorCode) Error!void {
        return stream_termination.reset(self, id, code, response_cleanup.cleanupDeadline(self, null), local_stream_termination_hooks);
    }

    /// Explicit terminal output keeps the original bound when applying the
    /// configured cleanup cap. Expired admission leaves ownership untouched.
    pub fn terminateOwnedStreamWithDeadline(self: *Connection, id: u31, code: http2.ErrorCode, deadline: std.Io.Clock.Timestamp) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return stream_termination.reset(self, id, code, response_cleanup.limitDeadline(self, absolute), local_stream_termination_hooks);
    }

    pub fn terminateOwnedStreamWithTimeout(self: *Connection, id: u31, code: http2.ErrorCode, timeout: std.Io.Duration) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.terminateOwnedStreamWithDeadline(id, code, .fromNow(self.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn peerStreamIsActive(self: Connection, id: u31) bool {
        return self.active_peer_index.count() != 0 and self.active_peer_index.contains(id);
    }

    /// Best-effort cleanup for an admitted Extended CONNECT stream whose
    /// protocol adapter is being dropped before a final response. Unlike
    /// `sendResetStream`, local state is released even if the reset cannot be
    /// written, so an infallible adapter destructor cannot leak stream credit.
    pub fn abandonExtendedConnect(
        self: *Connection,
        stream_id: u31,
    ) void {
        if (!self.outboundStreamIsActive(stream_id)) return;
        self.terminateOwnedStream(stream_id, .cancel) catch {};
    }

    /// Fail a tunnel locally when its byte stream can no longer be framed
    /// safely (for example after a timed write and a concurrent protocol
    /// error). A successfully submitted RST preserves healthy siblings; if
    /// the reset itself fails or times out, the parent is marked unusable
    /// because the shared byte-stream prefix is then ambiguous.
    pub fn abortExtendedConnect(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        if (!self.outboundStreamIsActive(stream_id)) {
            self.releaseLocalStream(stream_id);
            self.releasePeerStream(stream_id);
            self.forgetStreamWindows(stream_id);
            return;
        }
        const before = response_cleanup.limitDeadline(self, deadline);
        stream_termination.reset(self, stream_id, http2.ErrorCode.cancel, before, local_stream_termination_hooks) catch {};
    }

    /// Terminate an admitted peer request that an upper protocol adapter can
    /// no longer process. The reset is best effort, but local stream credit,
    /// response semantics, and flow-control windows are always released so a
    /// malformed request cannot consume concurrency for the connection's
    /// remaining lifetime.
    pub fn abandonPeerRequest(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
    ) void {
        if (self.peerStreamIsActive(stream_id)) {
            self.terminateOwnedStream(stream_id, error_code) catch {};
        } else {
            self.releasePeerStream(stream_id);
            self.forgetStreamWindows(stream_id);
        }
    }

    fn abandonPeerRequestBefore(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
        before: ?std.Io.Clock.Timestamp,
    ) void {
        stream_termination.resetFromReader(self, stream_id, error_code, before, local_stream_termination_hooks) catch {};
    }

    pub fn readResetStream(self: *Connection) Error!OwnedResetStream {
        return self.readResetStreamUntil(null);
    }

    pub fn readResetStreamWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedResetStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readResetStreamUntil(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readResetStreamWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedResetStream {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readResetStreamUntil(deadline);
    }

    fn readResetStreamUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedResetStream {
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .rst_stream) {
                if (try self.handleConnectionOrGoAwayFrameUntil(frame.frame, deadline)) {
                    frame.deinit(self.allocator);
                    continue;
                }
                return error.UnexpectedFrame;
            }
            const reset = try http2.ResetStreamPayload.parse(frame.frame);
            try self.recordResetStream(reset);
            return .{ .frame = frame, .reset = reset };
        }
    }

    fn writeResetStreamFrame(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
    ) Error!void {
        return self.writeResetStreamFrameUntil(
            stream_id,
            error_code,
            null,
        );
    }

    /// Once reuse is forbidden, no reset-history allocation is needed to
    /// tolerate later input. Keep terminal cancellation possible under OOM.
    fn writeTerminalResetStream(self: *Connection, stream_id: u31, code: http2.ErrorCode) Error!void {
        return self.writeTerminalResetStreamUntil(stream_id, code, null);
    }

    fn writeTerminalResetStreamUntil(self: *Connection, stream_id: u31, code: http2.ErrorCode, deadline: ?std.Io.Clock.Timestamp) Error!void {
        std.debug.assert(self.aggregate_timeout_unusable);
        if (self.terminal_write_failed) return error.ConnectionClosed;
        var storage: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
        const bytes = try http2.ResetStreamPayload.writeInto(&storage, stream_id, code);
        if (deadline) |absolute| {
            var committed: usize = 0;
            self.transportForIo().writeAllWithDeadline(bytes, &committed, absolute) catch |err| {
                self.terminal_write_failed = true;
                return err;
            };
            return;
        }
        self.transportForIo().writeAll(bytes) catch |err| {
            self.terminal_write_failed = true;
            return err;
        };
    }

    fn notePeerResetAdmission(self: *Connection, stream_id: u31) void {
        if (self.role != .client or !self.active_local_index.contains(stream_id)) return;
        const limit = self.peer_max_concurrent_streams orelse return;
        if (limit != 0 and self.activeLocalStreamCount() >= limit) self.peer_reset_admission_pending = true;
    }

    fn synchronizePeerResetAdmissionUntil(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (!self.peer_reset_admission_pending) return;
        var payload: [8]u8 = undefined;
        std.Io.random(self.io, &payload);
        _ = self.pingUntil(payload, deadline) catch |err| {
            // This admission wait owns the reader. An incomplete control
            // frame cannot be discarded while retaining connection reuse.
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return err;
        };
        self.peer_reset_admission_pending = false;
    }

    fn writeResetStreamFrameUntil(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.terminal_write_failed) return error.ConnectionClosed;
        try self.prepareLocallyResetStreams(1);
        if (deadline) |absolute| {
            var storage: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
            const encoded = try http2.ResetStreamPayload.writeInto(
                &storage,
                stream_id,
                error_code,
            );
            var committed: usize = 0;
            self.transportForIo().writeAllWithDeadline(
                encoded,
                &committed,
                absolute,
            ) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
            self.rememberLocallyResetStreamAssumeCapacity(stream_id);
            self.notePeerResetAdmission(stream_id);
            return;
        }
        return self.writeResetStreamFramePrepared(stream_id, error_code);
    }

    fn writeResetStreamFramePrepared(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
    ) Error!void {
        return self.writeResetStreamFramePreparedUntil(
            stream_id,
            error_code,
            null,
        );
    }

    fn writeResetStreamFramePreparedUntil(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.terminal_write_failed) return error.ConnectionClosed;
        var storage: [http2.ResetStreamPayload.encoded_len]u8 = undefined;
        const encoded = try http2.ResetStreamPayload.writeInto(
            &storage,
            stream_id,
            error_code,
        );
        if (deadline) |absolute| {
            var committed: usize = 0;
            self.transportForIo().writeAllWithDeadline(
                encoded,
                &committed,
                absolute,
            ) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
        } else {
            self.transportForIo().writeAll(encoded) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
        }
        self.rememberLocallyResetStreamAssumeCapacity(stream_id);
        self.notePeerResetAdmission(stream_id);
    }

    pub fn writeLocalErrorResetStream(
        self: *Connection,
        stream_id: u31,
        error_code: http2.ErrorCode,
    ) Error!void {
        return self.writeLocalErrorResetStreamUntil(stream_id, error_code, null);
    }

    fn writeLocalErrorResetStreamUntil(self: *Connection, stream_id: u31, error_code: http2.ErrorCode, deadline: ?std.Io.Clock.Timestamp) Error!void {
        try self.ensureLocalErrorResetBudgetUntil(deadline);
        self.writeResetStreamFrameUntil(stream_id, error_code, deadline) catch |err| {
            // A transport write does not report whether a prefix reached the
            // peer. Never append more HTTP/2 frames to a possibly partial RST.
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return err;
        };
        self.local_error_reset_streams +|= 1;
    }

    fn ensureLocalErrorResetBudget(self: *Connection) Error!void {
        return self.ensureLocalErrorResetBudgetUntil(null);
    }

    fn ensureLocalErrorResetBudgetUntil(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!void {
        const limit = self.limits.max_local_error_reset_streams orelse return;
        if (self.local_error_reset_streams < limit) return;

        self.aggregate_timeout_unusable = true;
        self.sendProtocolGoAway(
            self.lastPeerProcessedStreamId(),
            .enhance_your_calm,
            "too_many_internal_resets",
            deadline,
        );
        return error.ConnectionGoAway;
    }

    fn prepareLocallyResetStreams(
        self: *Connection,
        additional: usize,
    ) std.mem.Allocator.Error!void {
        const limit = self.limits.max_reset_stream_history;
        if (limit == 0) return;
        const retained = self.locallyResetStreamCount();
        if (retained < limit) {
            self.compactLocallyResetStreams();
            const desired = @min(limit, retained +| additional);
            try self.locally_reset_streams.ensureTotalCapacity(
                self.allocator,
                desired,
            );
            try self.locally_reset_stream_index.ensureTotalCapacity(
                self.allocator,
                @intCast(desired),
            );
            return;
        }
        return self.prepareLocallyResetStreamsAt(
            additional,
            std.Io.Clock.awake.now(self.io).nanoseconds,
        );
    }

    pub fn prepareLocallyResetStreamsAt(
        self: *Connection,
        additional: usize,
        now_ns: i96,
    ) std.mem.Allocator.Error!void {
        const limit = self.limits.max_reset_stream_history;
        if (limit == 0) return;
        self.pruneExpiredLocallyResetStreams(now_ns);
        const retained = self.locallyResetStreamCount();
        if (retained >= limit) return;
        self.compactLocallyResetStreams();
        const desired = @min(
            limit,
            retained +| additional,
        );
        try self.locally_reset_streams.ensureTotalCapacity(
            self.allocator,
            desired,
        );
        try self.locally_reset_stream_index.ensureTotalCapacity(
            self.allocator,
            @intCast(desired),
        );
    }

    fn rememberLocallyResetStreamAssumeCapacity(
        self: *Connection,
        stream_id: u31,
    ) void {
        self.rememberLocallyResetStreamAtAssumeCapacity(
            stream_id,
            std.Io.Clock.awake.now(self.io).nanoseconds,
        );
    }

    pub fn rememberLocallyResetStreamAtAssumeCapacity(
        self: *Connection,
        stream_id: u31,
        now_ns: i96,
    ) void {
        const limit = self.limits.max_reset_stream_history;
        if (limit == 0) return;
        self.pruneExpiredLocallyResetStreams(now_ns);
        if (self.locally_reset_stream_index.contains(stream_id)) return;
        if (self.locallyResetStreamCount() >= limit) return;
        self.compactLocallyResetStreams();
        self.locally_reset_streams.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .reset_at_ns = now_ns,
        });
        self.locally_reset_stream_index.putAssumeCapacityNoClobber(
            stream_id,
            {},
        );
    }

    fn wasLocallyReset(self: *Connection, stream_id: u31) bool {
        if (self.locally_reset_stream_index.count() == 0) return false;
        return self.wasLocallyResetAt(
            stream_id,
            std.Io.Clock.awake.now(self.io).nanoseconds,
        );
    }

    pub fn wasLocallyResetAt(
        self: *Connection,
        stream_id: u31,
        now_ns: i96,
    ) bool {
        if (!self.locally_reset_stream_index.contains(stream_id)) return false;
        self.pruneExpiredLocallyResetStreams(now_ns);
        return self.locally_reset_stream_index.contains(stream_id);
    }

    pub fn locallyResetStreamCount(self: *const Connection) usize {
        return self.locally_reset_streams.items.len -
            self.locally_reset_stream_head;
    }

    fn pruneExpiredLocallyResetStreams(
        self: *Connection,
        now_ns: i96,
    ) void {
        const retention_ns = self.limits.reset_stream_duration.nanoseconds;
        while (self.locally_reset_stream_head <
            self.locally_reset_streams.items.len)
        {
            const oldest = self.locally_reset_streams.items[
                self.locally_reset_stream_head
            ];
            if (now_ns <= oldest.reset_at_ns or
                now_ns - oldest.reset_at_ns <= retention_ns) return;
            _ = self.locally_reset_stream_index.remove(oldest.stream_id);
            self.locally_reset_stream_head += 1;
        }
        if (self.locally_reset_stream_head ==
            self.locally_reset_streams.items.len)
        {
            self.locally_reset_streams.clearRetainingCapacity();
            self.locally_reset_stream_head = 0;
        }
    }

    fn compactLocallyResetStreams(self: *Connection) void {
        const head = self.locally_reset_stream_head;
        if (head == 0) return;
        const retained = self.locally_reset_streams.items[head..];
        std.mem.copyForwards(
            LocallyResetStream,
            self.locally_reset_streams.items[0..retained.len],
            retained,
        );
        self.locally_reset_streams.items.len = retained.len;
        self.locally_reset_stream_head = 0;
    }

    fn discardLateFrameForLocallyResetStream(
        self: *Connection,
        frame: http2.Frame,
    ) Error!bool {
        return self.discardLateFrameForLocallyResetStreamUntil(frame, null);
    }

    fn discardLateFrameForLocallyResetStreamUntil(self: *Connection, frame: http2.Frame, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        if (frame.header.stream_id == 0 or
            self.locally_reset_stream_index.count() == 0 or
            !self.locally_reset_stream_index.contains(frame.header.stream_id))
        {
            return false;
        }
        return LateResetFrames.discard(self, frame, std.Io.Clock.awake.now(self.io).nanoseconds, deadline);
    }

    pub fn discardLateFrameForLocallyResetStreamAt(
        self: *Connection,
        frame: http2.Frame,
        now_ns: i96,
    ) Error!bool {
        return LateResetFrames.discard(self, frame, now_ns, null);
    }

    /// RFC 9113 permits a peer to race stream creation against the final
    /// GOAWAY. Frames above that boundary are ignored rather than turning a
    /// graceful drain into a connection failure. HEADERS must still be HPACK
    /// decoded so connection-wide compression state remains synchronized. DATA
    /// still consumes connection credit, which is immediately released because
    /// no application will ever own that payload.
    fn discardFrameAboveGracefulBoundaryUntil(
        self: *Connection,
        frame: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!bool {
        if (self.role != .server or
            self.graceful_shutdown_phase != .complete or
            frame.header.stream_id == 0 or
            !clientInitiatedStreamId(frame.header.stream_id) or
            frame.header.stream_id <=
                (self.local_goaway_last_stream_id orelse return false))
        {
            return false;
        }
        switch (frame.header.frame_type) {
            .headers => {
                const headers = try self.readHeaderBlockRawUntil(
                    frame,
                    deadline,
                );
                freeHeaders(self.allocator, headers);
                if (self.gracefulPreadmittedIndex(
                    frame.header.stream_id,
                )) |index| {
                    const marker = self.graceful_preadmitted_peer_streams
                        .items[index];
                    if (marker.admission == .refused_reset_sent) {
                        _ = self.graceful_preadmitted_peer_streams
                            .orderedRemove(index);
                    }
                }
            },
            .data => {
                _ = try http2.DataPayload.parse(frame);
                try self.recv_connection_window.receive(frame.payload.len);
                try self.releaseConnectionCapacity(frame.payload.len);
            },
            .rst_stream => _ = try http2.ResetStreamPayload.parse(frame),
            .window_update => _ = try http2.WindowUpdatePayload.parse(frame),
            .priority => try legacy_priority.validateFrame(self, frame),
            // A bare CONTINUATION is invalid regardless of GOAWAY. Valid
            // continuations are consumed by the HEADERS branch above.
            .continuation => return error.UnexpectedFrame,
            else => {},
        }
        return true;
    }

    pub fn recordResetStream(
        self: *Connection,
        reset: http2.ResetStreamPayload,
    ) Error!void {
        self.last_peer_reset = reset;
        self.last_peer_reset_response_started = true;
        self.notePeerResetAdmission(reset.stream_id);
        const pending_accept_overflow =
            self.role == .server and self.markPendingRequestReset(reset.stream_id);
        // A reset is legal on a reserved stream even though that stream is not
        // counted as active. Preserve a server-side cancellation marker until
        // writePushedResponse observes it; client-side reservations can be
        // removed immediately because no pushed response may follow.
        if (self.role == .server and
            self.push_state.cancelLocal(reset.stream_id))
        {
            self.releaseLocalStream(reset.stream_id);
            self.releasePeerStream(reset.stream_id);
            self.forgetResponseSemantics(reset.stream_id);
            _ = self.priority_state.remove(
                self.allocator,
                reset.stream_id,
            );
            self.forgetStreamWindows(reset.stream_id);
            if (pending_accept_overflow) return self.failPendingAcceptResetOverflow();
            return;
        }
        if (self.role == .client) {
            if (self.push_state.isRemoteReserved(reset.stream_id)) {
                try PushLifecycle.returnHeldCredit(self, reset.stream_id, 0, null);
            }
            if (self.push_state.cancelRemote(
                self.allocator,
                reset.stream_id,
            )) {
                self.releaseLocalStream(reset.stream_id);
                self.releasePeerStream(reset.stream_id);
                self.forgetStreamWindows(reset.stream_id);
                if (pending_accept_overflow) return self.failPendingAcceptResetOverflow();
                return;
            }
        }
        // A locally completed stream can race with a reset already in flight.
        // Keep accepting that late reset, as the previous runtime did; outbound
        // sendResetStream still rejects streams that were never activated.
        self.releaseLocalStream(reset.stream_id);
        self.releasePeerStream(reset.stream_id);
        self.forgetStreamWindows(reset.stream_id);
        if (pending_accept_overflow) return self.failPendingAcceptResetOverflow();
    }

    fn failPendingAcceptResetOverflow(self: *Connection) Error {
        const before = response_cleanup.cleanupDeadline(self, null);
        self.cancelPendingAcceptOverflowBefore(before);
        self.sendProtocolGoAwayBefore(
            self.lastPeerProcessedStreamId(),
            .enhance_your_calm,
            "too_many_resets",
            before,
        );
        return error.ConnectionGoAway;
    }

    pub fn sendWindowUpdate(self: *Connection, stream_id: u31, increment: u31) Error!void {
        return self.sendWindowUpdateUntil(stream_id, increment, null);
    }

    pub fn sendWindowUpdateWithDeadline(
        self: *Connection,
        stream_id: u31,
        increment: u31,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.sendWindowUpdateUntil(stream_id, increment, absolute);
    }

    pub fn sendWindowUpdateWithTimeout(
        self: *Connection,
        stream_id: u31,
        increment: u31,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendWindowUpdateWithDeadline(
            stream_id,
            increment,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn sendWindowUpdateUntil(
        self: *Connection,
        stream_id: u31,
        increment: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (stream_id == 0) {
            try self.sendWindowUpdatesUntil(
                null,
                increment,
                null,
                deadline,
            );
        } else {
            try self.sendWindowUpdatesUntil(
                stream_id,
                null,
                increment,
                deadline,
            );
        }
    }

    pub fn releaseReceivedCapacity(self: *Connection, stream_id: u31, amount: usize) Error!void {
        return self.releaseReceivedCapacityUntil(stream_id, amount, null);
    }

    pub fn releaseReceivedCapacityWithDeadline(
        self: *Connection,
        stream_id: u31,
        amount: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        const absolute = try deadline_policy.usableAwake(self.io, deadline);
        return self.releaseReceivedCapacityUntil(
            stream_id,
            amount,
            absolute,
        );
    }

    pub fn releaseReceivedCapacityWithTimeout(
        self: *Connection,
        stream_id: u31,
        amount: usize,
        timeout: std.Io.Duration,
    ) ResponseTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.releaseReceivedCapacityWithDeadline(
            stream_id,
            amount,
            .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn releaseReceivedCapacityUntil(
        self: *Connection,
        stream_id: u31,
        amount: usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (amount == 0) return;
        var remaining = amount;
        while (remaining != 0) {
            const increment: u31 = @intCast(@min(remaining, std.math.maxInt(u31)));
            try self.sendWindowUpdatesUntil(
                stream_id,
                increment,
                increment,
                deadline,
            );
            remaining -= increment;
        }
    }

    pub fn releaseConnectionCapacity(
        self: *Connection,
        amount: usize,
    ) Error!void {
        return self.releaseConnectionCapacityUntil(amount, null);
    }

    pub fn releaseConnectionCapacityUntil(self: *Connection, amount: usize, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (amount == 0) return;
        var remaining = amount;
        while (remaining != 0) {
            const increment: u31 = @intCast(
                @min(remaining, std.math.maxInt(u31)),
            );
            try self.sendWindowUpdatesUntil(null, increment, null, deadline);
            remaining -= increment;
        }
    }

    pub fn releaseLateResetConnectionCapacity(
        self: *Connection,
        amount: usize,
    ) Error!void {
        return self.releaseLateResetConnectionCapacityUntil(amount, null);
    }

    fn releaseLateResetConnectionCapacityUntil(self: *Connection, amount: usize, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (amount == 0) return;
        // One inbound DATA payload is bounded by SETTINGS_MAX_FRAME_SIZE,
        // whose protocol maximum fits in a single WINDOW_UPDATE increment.
        const increment = std.math.cast(u31, amount) orelse
            return error.MessageTooLarge;
        self.sendWindowUpdatesUntil(null, increment, null, deadline) catch |err| switch (err) {
            error.SocketUnconnected,
            error.ConnectionResetByPeer,
            => {
                // sendWindowUpdates rolls its receive-window increment back
                // when the write fails. A terminal peer close is harmless in
                // this cleanup-only path: frame_reader may still hold a
                // complete sibling response that arrived before the close.
                // Restore the logical credit locally so parsing those buffered
                // frames observes the same accounting as a successful update.
                self.recv_connection_window.update(increment) catch
                    unreachable;
                // The byte stream is physically closed; this known terminal
                // close must still permit complete buffered sibling frames.
                // Other write failures keep the terminal-write guard set.
                self.terminal_write_failed = false;
            },
            else => return err,
        };
    }

    fn sendWindowUpdates(
        self: *Connection,
        stream_id: ?u31,
        connection_increment: ?u31,
        stream_increment: ?u31,
    ) Error!void {
        return self.sendWindowUpdatesUntil(stream_id, connection_increment, stream_increment, null);
    }

    pub fn sendWindowUpdatesUntil(
        self: *Connection,
        stream_id: ?u31,
        connection_increment: ?u31,
        stream_increment: ?u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (connection_increment == null and stream_increment == null) return;
        if (self.terminal_write_failed) return error.ConnectionClosed;
        if (stream_increment != null) {
            const id = stream_id orelse return error.InvalidStreamId;
            if (!self.outboundStreamIsActive(id) and
                !self.hasRecvStreamWindow(id))
            {
                return error.InvalidStreamId;
            }
        }

        var encoded: [2 * (http2.FrameHeader.encoded_len + 4)]u8 =
            undefined;
        var encoded_len: usize = 0;
        var updated_connection: ?u31 = null;
        errdefer if (updated_connection) |increment| {
            restoreWindowDelta(
                &self.recv_connection_window,
                -@as(i64, increment),
            );
        };
        var updated_stream: ?struct {
            window: *FlowWindow,
            increment: u31,
        } = null;
        errdefer if (updated_stream) |update| {
            restoreWindowDelta(
                update.window,
                -@as(i64, update.increment),
            );
        };
        if (connection_increment) |increment| {
            try self.recv_connection_window.update(increment);
            updated_connection = increment;
            try encodeWindowUpdateFrame(
                encoded[encoded_len..][0 .. http2.FrameHeader.encoded_len + 4],
                0,
                increment,
            );
            encoded_len += http2.FrameHeader.encoded_len + 4;
        }
        if (stream_increment) |increment| {
            const window = try self.recvStreamWindow(stream_id.?);
            try window.update(increment);
            updated_stream = .{
                .window = window,
                .increment = increment,
            };
            try encodeWindowUpdateFrame(
                encoded[encoded_len..][0 .. http2.FrameHeader.encoded_len + 4],
                stream_id.?,
                increment,
            );
            encoded_len += http2.FrameHeader.encoded_len + 4;
        }
        if (deadline) |absolute| {
            var committed: usize = 0;
            self.transportForIo().writeAllWithDeadline(encoded[0..encoded_len], &committed, absolute) catch |err| {
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                return err;
            };
        } else self.transportForIo().writeAll(encoded[0..encoded_len]) catch |err| {
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            return err;
        };
    }

    pub fn addActiveLocalStream(self: *Connection, stream_id: u31) Error!void {
        const slot = try self.active_local_index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) return;
        errdefer _ = self.active_local_index.remove(stream_id);
        try self.active_local_streams.ensureUnusedCapacity(self.allocator, 1);
        const index = self.active_local_streams.items.len;
        self.active_local_streams.appendAssumeCapacity(stream_id);
        slot.value_ptr.* = index;
    }

    pub fn addActivePeerStream(self: *Connection, stream_id: u31) Error!void {
        const slot = try self.active_peer_index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) return;
        errdefer _ = self.active_peer_index.remove(stream_id);
        try self.active_peer_streams.ensureUnusedCapacity(self.allocator, 1);
        const index = self.active_peer_streams.items.len;
        self.active_peer_streams.appendAssumeCapacity(stream_id);
        slot.value_ptr.* = index;
    }

    pub fn removeActiveLocalStream(self: *Connection, stream_id: u31) bool {
        if (self.active_local_index.count() == 0) return false;
        const index = self.active_local_index.get(stream_id) orelse return false;
        const last_index = self.active_local_streams.items.len - 1;
        const removed = self.active_local_streams.swapRemove(index);
        _ = self.active_local_index.remove(removed);
        if (index != last_index) {
            const moved = self.active_local_streams.items[index];
            self.active_local_index.getPtr(moved).?.* = index;
        }
        return true;
    }

    pub fn removeActivePeerStream(self: *Connection, stream_id: u31) bool {
        if (self.active_peer_index.count() == 0) return false;
        const index = self.active_peer_index.get(stream_id) orelse return false;
        const last_index = self.active_peer_streams.items.len - 1;
        const removed = self.active_peer_streams.swapRemove(index);
        _ = self.active_peer_index.remove(removed);
        if (index != last_index) {
            const moved = self.active_peer_streams.items[index];
            self.active_peer_index.getPtr(moved).?.* = index;
        }
        return true;
    }

    pub fn reserveNextClientStreamId(self: *Connection) Error!u31 {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        const stream_id = self.next_client_stream_id;
        if (stream_id > std.math.maxInt(u31) - 2) return error.InvalidStreamId;
        if (self.peer_goaway_last_stream_id) |last| {
            if (stream_id > last) return error.ConnectionGoAway;
        }
        if (self.availableLocalStreamCapacity()) |available| {
            if (available == 0) return error.FlowControlBlocked;
        }
        try self.addActiveLocalStream(stream_id);
        _ = self.priority_state.activateRequest(stream_id);
        self.next_client_stream_id += 2;
        return stream_id;
    }

    pub fn outboundStreamIsActive(self: Connection, stream_id: u31) bool {
        if (self.active_local_index.count() != 0 and
            self.active_local_index.contains(stream_id)) return true;
        return self.active_peer_index.count() != 0 and
            self.active_peer_index.contains(stream_id);
    }

    pub fn streamIsIdle(self: Connection, stream_id: u31) bool {
        std.debug.assert(stream_id != 0);
        if (self.outboundStreamIsActive(stream_id)) return false;

        if (clientInitiatedStreamId(stream_id)) {
            // Client-created stream IDs are monotonically allocated. IDs below
            // the relevant cursor have existed and are now closed; IDs at or
            // above it have never been opened.
            return if (self.role == .server)
                stream_id > self.last_peer_client_stream_id
            else
                stream_id >= self.next_client_stream_id;
        }

        if (self.role == .server) {
            if (self.push_state.localStatus(stream_id) != null) return false;
            return stream_id >= self.push_state.nextLocalStreamId();
        }
        if (self.push_state.isRemoteReserved(stream_id)) return false;
        const last = self.push_state.lastPeerStreamId() orelse return true;
        return stream_id > last;
    }

    pub fn lastPeerProcessedStreamId(self: Connection) u31 {
        if (self.role == .server) return self.last_peer_processed_stream_id;
        return self.push_state.lastPeerStreamId() orelse 0;
    }

    pub fn releaseLocalStream(self: *Connection, stream_id: u31) void {
        if (!self.removeActiveLocalStream(stream_id)) return;
        _ = self.priority_state.remove(
            self.allocator,
            stream_id,
        );
    }

    pub fn recordPeerGoAway(self: *Connection, goaway: http2.GoAwayPayload) Error!void {
        if (self.peer_goaway_last_stream_id) |last| {
            // RFC 9113 §6.8: endpoints may send more than one GOAWAY, but the
            // last-stream-id value must not increase.  h2 rejects an increasing
            // value as a protocol error because it would resurrect streams that
            // were already declared unprocessed.
            if (goaway.last_stream_id > last) return error.InvalidFrame;
        }
        self.peer_goaway_last_stream_id = goaway.last_stream_id;
        self.peer_goaway_too_many_pings = self.peer_goaway_too_many_pings or
            (self.role == .client and
                goaway.error_code == .enhance_your_calm and
                std.mem.eql(u8, goaway.debug_data, "too_many_pings"));
    }

    pub fn handleGoAwayForStream(self: *Connection, stream_id: u31, goaway: http2.GoAwayPayload) Error!void {
        try self.recordPeerGoAway(goaway);
        if (stream_id > goaway.last_stream_id) {
            self.releaseLocalStream(stream_id);
            return error.ConnectionGoAway;
        }
    }

    pub fn reservePeerStream(self: *Connection, stream_id: u31) Error!void {
        if (self.role == .server and
            self.graceful_shutdown_phase == .complete and
            stream_id > (self.local_goaway_last_stream_id orelse 0))
        {
            return error.ConnectionGoAway;
        }
        const was_priority_reserved =
            self.priority_state.containsIdleRequest(stream_id);
        if (self.limits.max_concurrent_streams) |max_streams| {
            const counted = self.active_peer_streams.items.len +
                self.priority_state.idleRequestCount() -
                @intFromBool(was_priority_reserved);
            if (counted >= max_streams) return error.FlowControlViolation;
        }
        try self.addActivePeerStream(stream_id);
        self.priority_state.openRequest(self.allocator, stream_id);
    }

    pub fn releasePeerStream(self: *Connection, stream_id: u31) void {
        _ = self.removeActivePeerStream(stream_id);
        self.forgetResponseSemantics(stream_id);
        _ = self.priority_state.remove(self.allocator, stream_id);
    }

    pub fn rememberResponseSemantics(
        self: *Connection,
        stream_id: u31,
        method: []const u8,
        protocol: ?[]const u8,
        priority: http2.ExtensiblePriority,
    ) Error!void {
        const semantics = StreamResponseSemantics{
            .stream_id = stream_id,
            .head = methodIsHead(method),
            .traditional_connect = methodIsConnect(method) and protocol == null,
            .extended_connect = methodIsConnect(method) and protocol != null,
            .priority = priority,
        };
        const slot = try self.response_semantics_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) {
            self.response_semantics.items[slot.value_ptr.*] = semantics;
            return;
        }
        errdefer _ = self.response_semantics_index.remove(stream_id);
        try self.response_semantics.ensureUnusedCapacity(self.allocator, 1);
        const index = self.response_semantics.items.len;
        self.response_semantics.appendAssumeCapacity(semantics);
        slot.value_ptr.* = index;
    }

    pub fn forgetResponseSemantics(self: *Connection, stream_id: u31) void {
        if (self.response_semantics_index.count() == 0) return;
        const index = self.response_semantics_index.get(stream_id) orelse return;
        const last_index = self.response_semantics.items.len - 1;
        const removed = self.response_semantics.swapRemove(index);
        _ = self.response_semantics_index.remove(removed.stream_id);
        if (index != last_index) {
            const moved = self.response_semantics.items[index];
            self.response_semantics_index.getPtr(moved.stream_id).?.* = index;
        }
    }

    fn responsePriority(self: Connection, stream_id: u31) http2.ExtensiblePriority {
        // PRIORITY_UPDATE has precedence over the request's original Priority
        // field and may arrive after the application accepted the request.
        if (self.peerPriority(stream_id)) |updated| return updated;
        if (self.response_semantics_index.count() == 0) return .{};
        const index = self.response_semantics_index.get(stream_id) orelse
            return .{};
        return self.response_semantics.items[index].priority;
    }

    pub fn responseSemanticsFor(self: Connection, stream_id: u31, options: ResponseOptions) ResponseBodySemantics {
        if (options.request_method) |method| return responseSemanticsFromMethod(method, options.extended_connect);
        if (self.response_semantics_index.count() == 0) return .{};
        if (self.response_semantics_index.get(stream_id)) |index| {
            const entry = self.response_semantics.items[index];
            return .{
                .head = entry.head,
                .traditional_connect = entry.traditional_connect,
                .extended_connect = entry.extended_connect,
            };
        }
        return .{};
    }

    pub fn receiveDataPayload(self: *Connection, stream_id: u31, frame: http2.Frame) Error!ReceivedDataPayload {
        return DataReceiver.receive(self, stream_id, frame);
    }

    pub fn releaseDataFrameBudget(
        self: *Connection,
        data: ReceivedDataPayload,
    ) void {
        self.data_frame_budget.release(data.budget_charge);
    }

    pub fn dataFrameBudgetMaximum(self: Connection) u32 {
        return data_frame_budget.maximum(
            self.limits.data_frame_budget,
            self.recv_connection_window_target,
        );
    }

    pub fn maybeReleaseReceivedCapacity(
        self: *Connection,
        stream_id: u31,
        end_stream: bool,
    ) Error!void {
        return self.maybeReleaseReceivedCapacityUntil(stream_id, end_stream, null);
    }

    fn maybeReleaseReceivedCapacityUntil(self: *Connection, stream_id: u31, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return self.releaseReceivedPaddingCapacityUntil(stream_id, 0, end_stream, deadline);
    }

    pub fn releaseReceivedDataCapacity(self: *Connection, stream_id: u31, data: ReceivedDataPayload, end_stream: bool) Error!void {
        return self.releaseReceivedDataCapacityUntil(stream_id, data, end_stream, null);
    }

    pub fn releaseReceivedDataCapacityUntil(self: *Connection, stream_id: u31, data: ReceivedDataPayload, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return self.releaseReceivedPaddingCapacityUntil(stream_id, data.padding_bytes, end_stream, deadline);
    }

    fn releaseReceivedPaddingCapacityUntil(self: *Connection, stream_id: u31, padding_bytes: u9, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) Error!void {
        const before = self.recv_connection_window.available();
        const connection_target = self.receiveConnectionWindowTarget();
        const stream_available = if (end_stream) 0 else (try self.recvStreamWindow(stream_id)).available();
        const increments = flow_capacity.plan(self.recv_connection_window.available(), stream_available, self.receiveConnectionWindowTarget(), self.receiveStreamWindowTarget(), padding_bytes, end_stream);
        self.sendWindowUpdatesUntil(
            stream_id,
            increments.connection,
            increments.stream,
            deadline,
        ) catch |err| {
            // A committed WINDOW_UPDATE prefix cannot be followed by another
            // refund or reset while the response/request owner unwinds.
            self.aggregate_timeout_unusable = true;
            self.terminal_write_failed = true;
            self.releaseLocalStream(stream_id);
            self.releasePeerStream(stream_id);
            self.forgetStreamWindows(stream_id);
            return err;
        };
        if (before <= connection_target / 2 and before < connection_target) {
            if (self.push_state.state) |state| state.received.returnedAllConnectionCredit();
        }
    }

    fn pushedCreditGeneration(self: *const Connection) usize {
        return if (self.push_state.state) |state| state.received.connection_refill_generation else 0;
    }

    fn synchronizePushedCredit(self: *const Connection, controls: anytype, generation: *usize) void {
        if (self.push_state.state) |state| state.received.synchronizeConnectionCredit(controls, generation);
    }

    fn failDiscardedResponseBefore(self: *Connection, stream_id: u31, before: ?std.Io.Clock.Timestamp) void {
        response_cleanup.failClosedBefore(self, stream_id, before, .{
            .reset = writeTerminalResetStreamUntil,
            .releaseLocal = releaseLocalStream,
            .releasePeer = releasePeerStream,
            .forgetWindows = forgetStreamWindows,
        });
    }

    fn failDiscardedResponse(self: *Connection, stream_id: u31) void {
        self.failDiscardedResponseBefore(stream_id, response_cleanup.cleanupDeadline(self, null));
    }

    fn returnDiscardedResponseCapacity(self: *Connection, amount: usize, before: ?std.Io.Clock.Timestamp) void {
        response_cleanup.returnCapacity(self, amount, before, .{ .refund = releaseConnectionCapacityUntil });
    }

    fn cancelPeerRequest(self: *Connection, stream_id: u31) void {
        // A transport or reset-history allocation failure must not retain
        // local ownership of a request the application has abandoned. Some
        // tests and upgrade paths can surface already-materialized requests
        // without an active stream, where emitting RST_STREAM would itself be
        // invalid and may not have a usable transport.
        if (!self.peerStreamIsActive(stream_id)) {
            self.releasePeerStream(stream_id);
            self.forgetStreamWindows(stream_id);
            return;
        }
        self.abandonPeerRequestBefore(stream_id, .cancel, response_cleanup.cleanupDeadline(self, null));
    }

    fn failDiscardedRequest(self: *Connection, stream_id: u31) void {
        self.failDiscardedRequestBefore(stream_id, response_cleanup.cleanupDeadline(self, null));
    }

    fn failDiscardedRequestBefore(self: *Connection, stream_id: u31, before: ?std.Io.Clock.Timestamp) void {
        request_cleanup.failClosed(self, stream_id, before, .{
            .reset = writeTerminalResetStreamUntil,
            .releasePeer = releasePeerStream,
            .forgetWindows = forgetStreamWindows,
            .pendingId = PendingRequest.streamId,
            .deinitPending = PendingRequest.deinit,
        });
    }

    fn releaseDiscardedMessageCapacity(self: *Connection, amount: usize) void {
        if (amount == 0) return;
        self.releaseDiscardedMessageCapacityBefore(amount, response_cleanup.cleanupDeadline(self, null));
    }

    fn releaseDiscardedMessageCapacityBefore(self: *Connection, amount: usize, before: ?std.Io.Clock.Timestamp) void {
        request_cleanup.refundBefore(self, amount, before, .{ .refund = releaseConnectionCapacityUntil });
    }

    fn releaseDiscardedMessageCapacityUntil(self: *Connection, amount: usize, deadline: ?std.Io.Clock.Timestamp) void {
        if (amount == 0) return;
        self.releaseDiscardedMessageCapacityBefore(amount, response_cleanup.limitDeadline(self, deadline));
    }

    pub fn readWindowUpdate(self: *Connection) Error!OwnedWindowUpdate {
        return self.readWindowUpdateUntil(null);
    }

    pub fn readWindowUpdateWithTimeout(
        self: *Connection,
        timeout: std.Io.Duration,
    ) Error!OwnedWindowUpdate {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readWindowUpdateUntil(.fromNow(
            self.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readWindowUpdateWithDeadline(
        self: *Connection,
        deadline: std.Io.Clock.Timestamp,
    ) Error!OwnedWindowUpdate {
        _ = try deadline_policy.usableAwake(self.io, deadline);
        return self.readWindowUpdateUntil(deadline);
    }

    fn readWindowUpdateUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedWindowUpdate {
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            errdefer frame.deinit(self.allocator);
            if (frame.frame.header.frame_type != .window_update) {
                if (try self.handleConnectionOrGoAwayFrameUntil(frame.frame, deadline)) {
                    frame.deinit(self.allocator);
                    continue;
                }
                return error.UnexpectedFrame;
            }
            const update = try http2.WindowUpdatePayload.parse(frame.frame);
            try self.applyWindowUpdateUntil(update, deadline);
            return .{ .frame = frame, .window_update = update };
        }
    }

    pub fn readResponse(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
    ) Error!OwnedResponse {
        return self.readResponseUntil(
            stream_id,
            request_method,
            extended_connect,
            informational,
            null,
        );
    }

    pub fn readResponseUntil(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!OwnedResponse {
        return self.readResponseAndUploadUntil(stream_id, request_method, extended_connect, informational, deadline, null);
    }

    fn readResponseAndUploadUntil(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        upload_value: ?complete_upload.Upload,
    ) Error!OwnedResponse {
        return self.readResponseAndUploadInnerUntil(stream_id, request_method, extended_connect, informational, deadline, upload_value) catch |err| {
            // Local protocol/policy failures also emit ConnectionGoAway.
            // Only a peer boundary excluding this stream proves that an
            // aggregate caller may transparently replay the request.
            if (err == error.ConnectionGoAway and
                (self.aggregate_timeout_unusable or self.goAwayRetryDisposition(stream_id) != .safe_to_retry)) return error.InvalidFrame;
            return @as(Error!OwnedResponse, err);
        };
    }

    fn readResponseAndUploadInnerUntil(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
        extended_connect: bool,
        informational: ?InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        upload_value: ?complete_upload.Upload,
    ) Error!OwnedResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        var upload = upload_value;
        var cleanup_before: ?std.Io.Clock.Timestamp = null;
        // This aggregate operation destroys its stream owner on every exit.
        // GOAWAY can release concurrency before error reporting, and ordinary
        // completion need not send a reset; neither may retain flow windows.
        defer {
            self.releaseLocalStream(stream_id);
            self.forgetStreamWindows(stream_id);
        }
        errdefer |err| if (err != error.Timeout) {
            self.sendResponseReadError(stream_id, err);
        };
        errdefer |err| if (err == error.Timeout or err == error.OutOfMemory) {
            // Unlike the incremental response-event APIs, this aggregate call
            // keeps partially decoded headers/body only on its stack. Preserve
            // connection integrity by canceling the stream and preventing
            // reuse after that state is discarded.
            self.failDiscardedResponseBefore(stream_id, cleanup_before);
        };
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |h| freeHeaders(self.allocator, h);
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var response_status: ?u16 = null;
        var response_content_length: ?usize = null;
        var body_capacity_exact = false;
        var informational_count: usize = 0;
        var trailers_only = false;
        var receive_credits = [_]flow_credit.Tracker{.{}};
        const receive_credit = &receive_credits[0];
        var push_generation = self.pushedCreditGeneration();
        errdefer |err| {
            self.synchronizePushedCredit(&receive_credits, &push_generation);
            if (err == error.Timeout or err == error.OutOfMemory) {
                cleanup_before = response_cleanup.cleanupDeadline(self, if (err == error.Timeout) null else deadline);
                self.returnDiscardedResponseCapacity(receive_credit.unreleased_connection_bytes, cleanup_before);
            } else {
                self.releaseDiscardedMessageCapacityUntil(receive_credit.unreleased_connection_bytes, deadline);
            }
        }

        while (true) {
            if (upload) |*remaining| self.resumeCompleteUploadUntil(remaining, stream_id, deadline) catch |err| {
                if (err == error.StreamReset) self.last_peer_reset_response_started = headers != null or informational_count != 0;
                // A received response head contradicts GOAWAY's claim that
                // this stream was never processed, including when a blocked
                // upload reads the GOAWAY while waiting for flow credit.
                if (err == error.ConnectionGoAway and (headers != null or informational_count != 0)) return error.InvalidFrame;
                return @as(Error!OwnedResponse, err);
            };
            var pending_owned: ?OwnedFrame = null;
            defer if (pending_owned) |*owned| {
                owned.deinit(self.allocator);
            };
            const frame = if (self.pendingApplicationFrameCount() != 0) blk: {
                pending_owned = try self.readOwnedFrameWithDeadline(deadline);
                break :blk pending_owned.?.frame;
            } else (try self.readBufferedFrameWithDeadline(deadline)).frame;
            self.synchronizePushedCredit(&receive_credits, &push_generation);
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                self.handleGoAwayForStream(stream_id, goaway) catch |err| {
                    if (err == error.ConnectionGoAway and (headers != null or informational_count != 0)) return error.InvalidFrame;
                    return @as(Error!OwnedResponse, err);
                };
                continue;
            }
            if (frame.header.stream_id != stream_id) return error.UnexpectedFrame;
            switch (frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        try self.rejectDisabledPushPromise(frame);
                        unreachable;
                    }
                    try self.receivePushPromiseUntil(
                        frame,
                        deadline,
                    );
                    continue;
                },
                .headers => {
                    if (headers) |h| {
                        if ((frame.header.flags & flag_end_stream) == 0) return error.UnexpectedFrame;
                        _ = h;
                        trailers = try self.readHeaderBlockUntil(
                            frame,
                            deadline,
                        );
                        try validateHeaderBlock(trailers, .response_trailers);
                        try validateExpectedContentLength(response_content_length, body.items.len);
                        break;
                    } else {
                        headers = try self.readHeaderBlockUntil(
                            frame,
                            deadline,
                        );
                        try validateHeaderBlock(headers.?, .response);
                        const lookup = try responseHeaderLookup(headers.?);
                        const status_s = lookup.status orelse return error.MissingPseudoHeader;
                        const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
                        response_status = status;
                        response_content_length = lookup.content_length;
                        if (informationalResponseToSkip(status)) {
                            if ((frame.header.flags & flag_end_stream) != 0) return error.UnexpectedFrame;
                            if (lookup.content_length != null) return error.InvalidContentLength;
                            try notifyInformationalResponse(
                                self,
                                informational,
                                .{ .headers = headers.?, .status = status },
                                &informational_count,
                                self.limits.max_informational_responses,
                            );
                            freeHeaders(self.allocator, headers.?);
                            headers = null;
                            response_status = null;
                            response_content_length = null;
                            continue;
                        }
                        if (responseForbidsBody(status, request_method, extended_connect)) {
                            const traditional_connect = methodIsConnect(request_method) and !extended_connect;
                            if (traditional_connect and (lookup.content_length orelse 0) != 0) return error.InvalidContentLength;
                            if ((statusIsInformational(status) or status == 204) and lookup.content_length != null) return error.InvalidContentLength;
                            if (!traditional_connect and (frame.header.flags & flag_end_stream) == 0) {
                                self.consumeForbiddenResponseBodyUntil(
                                    stream_id,
                                    deadline,
                                ) catch |err| {
                                    if (err == error.ConnectionGoAway) return error.InvalidFrame;
                                    return @as(Error!OwnedResponse, err);
                                };
                            }
                            break;
                        }
                        if (lookup.content_length) |body_len| {
                            if (body_len > self.limits.max_body_bytes) {
                                return error.MessageTooLarge;
                            }
                            try body.ensureTotalCapacityPrecise(
                                self.allocator,
                                body_len,
                            );
                            body_capacity_exact = true;
                        }
                        if ((frame.header.flags & flag_end_stream) != 0) {
                            try validateExpectedContentLength(lookup.content_length, 0);
                            trailers_only = true;
                            break;
                        }
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const connection_before = self.recv_connection_window.value;
                    const data = try self.receiveDataPayload(stream_id, frame);
                    defer receive_credit.observe(connection_before, self.recv_connection_window.value, data.adaptive_connection_increment);
                    defer self.releaseDataFrameBudget(data);
                    _ = checkedResponseBodyLength(
                        response_content_length,
                        body.items.len,
                        data.data.len,
                        self.limits.max_body_bytes,
                        true,
                        (frame.header.flags & flag_end_stream) != 0,
                    ) catch |err| {
                        // The DATA payload already consumed connection credit.
                        // A stream-local size rejection must restore that shared
                        // credit before terminating this response.
                        self.releaseDiscardedMessageCapacity(frame.payload.len);
                        return @errorCast(err);
                    };
                    try body.appendSlice(self.allocator, data.data);
                    try self.releaseReceivedDataCapacityUntil(
                        stream_id,
                        data,
                        (frame.header.flags & flag_end_stream) != 0,
                        deadline,
                    );
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        break;
                    }
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(
                        frame,
                    );
                    try self.recordResetStream(reset);
                    self.last_peer_reset_response_started = headers != null or informational_count != 0;
                    return error.StreamReset;
                },
                else => continue,
            }
        }

        const final_headers = headers orelse return error.MissingPseudoHeader;
        const status = response_status orelse return error.MissingPseudoHeader;
        const owned_body = if (body_capacity_exact)
            body.toOwnedSliceAssert()
        else
            try body.toOwnedSlice(self.allocator);
        if (upload) |*remaining| remaining.finishResponse(self, stream_id, deadline);
        return .{
            .headers = final_headers,
            .status = status,
            .body = owned_body,
            .body_allowed = !responseForbidsBody(status, request_method, extended_connect),
            .trailers = trailers,
            .trailers_only = trailers_only,
        };
    }

    fn sendResponseReadError(
        self: *Connection,
        stream_id: u31,
        err: anyerror,
    ) void {
        if (self.terminal_write_failed) return;
        if (self.serve_read_connection_error != null) {
            self.sendServeReadError(err);
            return;
        }
        const code = responseStreamErrorCode(err) orelse return;
        self.writeLocalErrorResetStream(stream_id, code) catch {};
        self.forgetStreamWindows(stream_id);
    }

    fn recordResponseStreamReadError(
        self: *Connection,
        stream_id: u31,
        code: http2.ErrorCode,
    ) void {
        if (self.serve_read_connection_error != null) return;
        self.serve_read_stream_error = .{
            .stream_id = stream_id,
            .code = code,
        };
    }

    fn sendRecordedResponseReadError(
        self: *Connection,
        stream_id: u31,
    ) void {
        if (self.terminal_write_failed) return;
        if (self.serve_read_connection_error != null) {
            self.sendServeReadError(error.InvalidFrame);
            return;
        }
        const stream_error = self.serve_read_stream_error orelse return;
        std.debug.assert(stream_error.stream_id == stream_id);
        self.writeLocalErrorResetStream(
            stream_id,
            stream_error.code,
        ) catch {};
        self.forgetStreamWindows(stream_id);
    }

    /// Consume one active client response as borrowed DATA events.
    ///
    /// This method is intentionally kept next to the aggregate reader because
    /// both enforce the same informational/status/body/trailer semantics. The
    /// difference is ownership: this path never appends DATA to an ArrayList.
    fn readResponseStreaming(
        self: *Connection,
        pending: PendingResponse,
        context: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHead(
            pending,
            null,
            context,
            ignoreStreamingResponseHead,
            consume,
        );
    }

    pub fn readResponseStreamingWithHead(
        self: *Connection,
        pending: PendingResponse,
        informational: ?InformationalObserver,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) !StreamingResponse {
        return self.readResponseStreamingWithHeadUntil(
            pending,
            informational,
            null,
            context,
            begin,
            consume,
        );
    }

    pub fn readResponseStreamingWithHeadUntil(
        self: *Connection,
        pending: PendingResponse,
        informational: ?InformationalObserver,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime begin: anytype,
        comptime consume: anytype,
    ) anyerror!StreamingResponse {
        if (self.callback_reader_active) return error.UnexpectedFrame;
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        const stream_id = pending.stream_id;
        var upload = pending.upload;
        self.serve_read_connection_error = null;
        self.serve_read_stream_error = null;
        defer self.releaseLocalStream(stream_id);
        var completed = false;
        var callback_failed = false;
        var cleanup_before: ?std.Io.Clock.Timestamp = null;
        errdefer if (!callback_failed and
            (self.serve_read_connection_error != null or
                self.serve_read_stream_error != null))
        {
            self.sendRecordedResponseReadError(stream_id);
        };
        // Internal OOM and bounded read failures discard parser state that a
        // later call cannot reconstruct. Callback rejection and classified
        // protocol errors have their own stream cleanup policy.
        errdefer |failure| if (!completed and !callback_failed and
            (deadline != null or failure == error.OutOfMemory) and
            self.serve_read_connection_error == null and
            self.serve_read_stream_error == null)
        {
            self.failDiscardedResponseBefore(stream_id, cleanup_before);
        };
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |value| {
            freeHeaders(self.allocator, value);
        };
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var status_value: ?u16 = null;
        var expected_body_len: ?usize = null;
        var body_bytes: usize = 0;
        var informational_count: usize = 0;
        var receive_credits = [_]flow_credit.Tracker{.{}};
        const receive_credit = &receive_credits[0];
        var push_generation = self.pushedCreditGeneration();
        errdefer |failure| {
            self.synchronizePushedCredit(&receive_credits, &push_generation);
            if (!completed and !callback_failed and (deadline != null or failure == error.OutOfMemory) and
                self.serve_read_connection_error == null and self.serve_read_stream_error == null)
            {
                cleanup_before = response_cleanup.cleanupDeadline(self, if (failure == error.Timeout) null else deadline);
                self.returnDiscardedResponseCapacity(receive_credit.unreleased_connection_bytes, cleanup_before);
            } else {
                self.releaseDiscardedMessageCapacityUntil(receive_credit.unreleased_connection_bytes, deadline);
            }
        }

        while (true) {
            if (upload) |*remaining| self.resumeCompleteUploadUntil(remaining, stream_id, deadline) catch |err| {
                // A peer reset consumed while pumping upload credit already
                // terminates this stream. Preserve the same stream-local
                // disposition as a reset read directly by this loop.
                if (err == error.StreamReset) completed = true;
                return @as(anyerror!StreamingResponse, err);
            };
            var pending_owned: ?OwnedFrame = null;
            defer if (pending_owned) |*owned| {
                owned.deinit(self.allocator);
            };
            const frame = if (self.pendingApplicationFrameCount() != 0) blk: {
                pending_owned = try self.readOwnedFrameWithDeadline(deadline);
                break :blk pending_owned.?.frame;
            } else (try self.readBufferedFrameWithDeadline(deadline)).frame;
            self.synchronizePushedCredit(&receive_credits, &push_generation);
            if (try self.handleConnectionFrameUntil(frame, deadline)) continue;
            if (frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.header.stream_id != stream_id) {
                return error.UnexpectedFrame;
            }
            switch (frame.header.frame_type) {
                .push_promise => {
                    if (!self.limits.enable_push) {
                        try self.rejectDisabledPushPromise(frame);
                        unreachable;
                    }
                    try self.receivePushPromiseUntil(frame, deadline);
                },
                .headers => {
                    if (headers != null) {
                        if ((frame.header.flags & flag_end_stream) == 0) {
                            return error.UnexpectedFrame;
                        }
                        trailers = try self.readHeaderBlockUntil(
                            frame,
                            deadline,
                        );
                        try validateHeaderBlock(
                            trailers,
                            .response_trailers,
                        );
                        validateExpectedContentLength(
                            expected_body_len,
                            body_bytes,
                        ) catch |err| {
                            self.recordResponseStreamReadError(stream_id, .protocol_error);
                            return @as(anyerror!StreamingResponse, err);
                        };
                        break;
                    }

                    const decoded = try self.readHeaderBlockUntil(
                        frame,
                        deadline,
                    );
                    var decoded_owned = true;
                    errdefer if (decoded_owned) {
                        freeHeaders(self.allocator, decoded);
                    };
                    validateHeaderBlock(decoded, .response) catch |err| {
                        self.recordResponseStreamReadError(
                            stream_id,
                            .protocol_error,
                        );
                        return @as(anyerror!StreamingResponse, err);
                    };
                    const lookup = try responseHeaderLookup(decoded);
                    const status_text = lookup.status orelse {
                        self.recordResponseStreamReadError(
                            stream_id,
                            .protocol_error,
                        );
                        return error.MissingPseudoHeader;
                    };
                    const status = std.fmt.parseInt(
                        u16,
                        status_text,
                        10,
                    ) catch {
                        self.recordResponseStreamReadError(
                            stream_id,
                            .protocol_error,
                        );
                        return error.InvalidStatus;
                    };
                    if (informationalResponseToSkip(status)) {
                        if ((frame.header.flags & flag_end_stream) != 0) {
                            return error.UnexpectedFrame;
                        }
                        if (lookup.content_length != null) {
                            self.recordResponseStreamReadError(
                                stream_id,
                                .protocol_error,
                            );
                            return error.InvalidContentLength;
                        }
                        try notifyInformationalResponse(
                            self,
                            informational,
                            .{ .headers = decoded, .status = status },
                            &informational_count,
                            self.limits.max_informational_responses,
                        );
                        freeHeaders(self.allocator, decoded);
                        decoded_owned = false;
                        continue;
                    }

                    headers = decoded;
                    decoded_owned = false;
                    status_value = status;
                    expected_body_len = lookup.content_length;
                    {
                        try self.beginBorrowedReadCallback();
                        defer self.endBorrowedReadCallback();
                        begin(context, StreamingResponseHead{
                            .headers = decoded,
                            .status = status,
                            .body_allowed = !responseForbidsBody(status, pending.request_method, pending.extended_connect),
                        }) catch |err| {
                            callback_failed = true;
                            self.rejectResponseCallback(stream_id, if (upload) |*remaining| remaining else null, (frame.header.flags & flag_end_stream) != 0, 0, deadline);
                            return @as(anyerror!StreamingResponse, err);
                        };
                    }
                    if (responseForbidsBody(
                        status,
                        pending.request_method,
                        pending.extended_connect,
                    )) {
                        const traditional_connect =
                            methodIsConnect(pending.request_method) and
                            !pending.extended_connect;
                        if (traditional_connect and
                            (lookup.content_length orelse 0) != 0)
                        {
                            self.recordResponseStreamReadError(
                                stream_id,
                                .protocol_error,
                            );
                            return error.InvalidContentLength;
                        }
                        if ((statusIsInformational(status) or
                            status == 204) and
                            lookup.content_length != null)
                        {
                            self.recordResponseStreamReadError(
                                stream_id,
                                .protocol_error,
                            );
                            return error.InvalidContentLength;
                        }
                        if (!traditional_connect and
                            (frame.header.flags & flag_end_stream) == 0)
                        {
                            self.consumeForbiddenResponseBodyUntil(
                                stream_id,
                                deadline,
                            ) catch |err| {
                                if (err == error.StreamReset) completed = true;
                                return @as(anyerror!StreamingResponse, err);
                            };
                        }
                        break;
                    }
                    if ((expected_body_len orelse 0) >
                        self.limits.max_body_bytes)
                    {
                        self.recordResponseStreamReadError(
                            stream_id,
                            .enhance_your_calm,
                        );
                        return error.MessageTooLarge;
                    }
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        try validateExpectedContentLength(
                            expected_body_len,
                            body_bytes,
                        );
                        break;
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const connection_before = self.recv_connection_window.value;
                    const data = try self.receiveDataPayload(
                        stream_id,
                        frame,
                    );
                    defer receive_credit.observe(connection_before, self.recv_connection_window.value, data.adaptive_connection_increment);
                    defer self.releaseDataFrameBudget(data);
                    body_bytes = checkedResponseBodyLength(
                        expected_body_len,
                        body_bytes,
                        data.data.len,
                        self.limits.max_body_bytes,
                        true,
                        (frame.header.flags & flag_end_stream) != 0,
                    ) catch |err| {
                        self.releaseDiscardedMessageCapacity(frame.payload.len);
                        self.recordResponseStreamReadError(
                            stream_id,
                            responseStreamErrorCode(err).?,
                        );
                        return @as(anyerror!StreamingResponse, err);
                    };
                    if (data.data.len != 0) {
                        {
                            try self.beginBorrowedReadCallback();
                            defer self.endBorrowedReadCallback();
                            consume(context, data.data) catch |err| {
                                callback_failed = true;
                                // DATA already consumed connection credit
                                // before application delivery. Restore its
                                // exact charged connection payload before
                                // canceling; a low-watermark-only update would
                                // let repeated small callback failures
                                // gradually starve siblings.
                                self.rejectResponseCallback(stream_id, if (upload) |*remaining| remaining else null, (frame.header.flags & flag_end_stream) != 0, frame.payload.len, deadline);
                                return @as(anyerror!StreamingResponse, err);
                            };
                        }
                    }
                    try self.releaseReceivedDataCapacityUntil(
                        stream_id,
                        data,
                        (frame.header.flags & flag_end_stream) != 0,
                        deadline,
                    );
                    if ((frame.header.flags & flag_end_stream) != 0) {
                        break;
                    }
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(frame);
                    try self.recordResetStream(reset);
                    // A complete peer reset is terminal stream evidence. It
                    // does not abandon partial shared framing like a timeout.
                    completed = true;
                    return error.StreamReset;
                },
                else => return error.UnexpectedFrame,
            }
        }

        if (upload) |*remaining| remaining.finishResponse(self, stream_id, deadline);
        completed = true;
        return .{
            .headers = headers orelse return error.MissingPseudoHeader,
            .status = status_value orelse return error.MissingPseudoHeader,
            .body_bytes = body_bytes,
            .trailers = trailers,
        };
    }

    fn readResponseOnPeerStream(
        self: *Connection,
        stream_id: u31,
        request_method: []const u8,
    ) Error!OwnedResponse {
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |value| {
            freeHeaders(self.allocator, value);
        };
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var response_status: ?u16 = null;
        var response_content_length: ?usize = null;
        var informational_count: usize = 0;
        while (true) {
            var frame = try self.readOwnedFrame();
            defer frame.deinit(self.allocator);
            if (try self.handleConnectionFrame(frame.frame)) continue;
            if (frame.frame.header.stream_id != stream_id) {
                return error.UnexpectedFrame;
            }
            switch (frame.frame.header.frame_type) {
                .headers => {
                    if (headers != null) {
                        trailers = try self.readHeaderBlock(frame.frame);
                        try validateHeaderBlock(
                            trailers,
                            .response_trailers,
                        );
                        if ((frame.frame.header.flags & flag_end_stream) == 0) {
                            return error.UnexpectedFrame;
                        }
                        break;
                    }
                    headers = try self.readHeaderBlock(frame.frame);
                    try validateHeaderBlock(headers.?, .response);
                    const lookup = try responseHeaderLookup(headers.?);
                    const status_text = lookup.status orelse return error.MissingPseudoHeader;
                    response_status = std.fmt.parseInt(u16, status_text, 10) catch
                        return error.InvalidStatus;
                    response_content_length = lookup.content_length;
                    if (informationalResponseToSkip(response_status.?)) {
                        if ((frame.frame.header.flags & flag_end_stream) != 0 or
                            response_content_length != null)
                        {
                            return error.InvalidContentLength;
                        }
                        try notifyInformationalResponse(
                            self,
                            null,
                            .{
                                .headers = headers.?,
                                .status = response_status.?,
                            },
                            &informational_count,
                            self.limits.max_informational_responses,
                        );
                        freeHeaders(self.allocator, headers.?);
                        headers = null;
                        response_status = null;
                        response_content_length = null;
                        continue;
                    }
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        break;
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const data = try self.receiveDataPayload(
                        stream_id,
                        frame.frame,
                    );
                    defer self.releaseDataFrameBudget(data);
                    if (body.items.len + data.data.len >
                        self.limits.max_body_bytes)
                    {
                        return error.MessageTooLarge;
                    }
                    try body.appendSlice(self.allocator, data.data);
                    try self.releaseReceivedDataCapacityUntil(
                        stream_id,
                        data,
                        (frame.frame.header.flags & flag_end_stream) != 0,
                        null,
                    );
                    if ((frame.frame.header.flags & flag_end_stream) != 0) {
                        break;
                    }
                },
                .rst_stream => return error.StreamReset,
                else => return error.UnexpectedFrame,
            }
        }
        const final_headers = headers orelse
            return error.MissingPseudoHeader;
        const status = response_status orelse return error.MissingPseudoHeader;
        const body_allowed = !responseForbidsBody(status, request_method, false);
        try validateResponseContentLength(response_content_length, body.items.len, body_allowed);
        return .{
            .headers = final_headers,
            .status = status,
            .body = try body.toOwnedSlice(self.allocator),
            .body_allowed = body_allowed,
            .trailers = trailers,
        };
    }

    fn occupiedPushSlots(self: *const Connection) usize {
        return PushLifecycle.occupiedPushSlots(self);
    }

    fn resumePendingPushHeader(self: *Connection, deadline: ?std.Io.Clock.Timestamp) Error!void {
        return PushLifecycle.resumePendingPushHeader(self, deadline);
    }

    fn receivePushedFrame(self: *Connection, frame: http2.Frame, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        return PushLifecycle.receivePushedFrame(self, frame, deadline);
    }

    fn readExtendedConnectResponse(self: *Connection, stream_id: u31) Error!ExtendedConnectResponse {
        var attempt = self.readExtendedConnectAttemptUntil(
            stream_id,
            null,
        ) catch |err|
            switch (err) {
                error.Timeout => unreachable,
                else => |other| return @errorCast(other),
            };
        errdefer attempt.deinit(self.allocator);
        return attempt.requireAccepted();
    }

    fn readExtendedConnectAttemptUntil(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!ExtendedConnectAttempt {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        var cleanup_before: ?std.Io.Clock.Timestamp = null;
        errdefer |err| if (err == error.Timeout or err == error.OutOfMemory) {
            // An aggregate CONNECT wait cannot resume after discarding decoded
            // informational heads or a partial HPACK block. Cancel the stream
            // and prevent a pooled caller from reusing ambiguous state.
            self.failDiscardedResponseBefore(stream_id, cleanup_before);
        };
        var informational_count: usize = 0;
        var headers: ?[]http2.Hpack.HeaderField = null;
        errdefer if (headers) |value| freeHeaders(self.allocator, value);
        var trailers: []http2.Hpack.HeaderField = &.{};
        errdefer freeHeaders(self.allocator, trailers);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var status_value: ?u16 = null;
        var expected_body_len: ?usize = null;
        var rejection_started = false;
        errdefer |err| if (rejection_started and err != error.Timeout and err != error.OutOfMemory) {
            if (deadline != null) self.abortExtendedConnect(stream_id, deadline) else self.abandonExtendedConnect(stream_id);
        };
        var receive_credits = [_]flow_credit.Tracker{.{}};
        const receive_credit = &receive_credits[0];
        var push_generation = self.pushedCreditGeneration();
        errdefer |err| {
            self.synchronizePushedCredit(&receive_credits, &push_generation);
            if (err == error.Timeout or err == error.OutOfMemory) {
                cleanup_before = response_cleanup.cleanupDeadline(self, if (err == error.Timeout) null else deadline);
                self.returnDiscardedResponseCapacity(receive_credit.unreleased_connection_bytes, cleanup_before);
            } else {
                self.releaseDiscardedMessageCapacityUntil(receive_credit.unreleased_connection_bytes, deadline);
            }
        }
        while (true) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            defer frame.deinit(self.allocator);
            self.synchronizePushedCredit(&receive_credits, &push_generation);
            if (try self.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) return error.UnexpectedFrame;
            switch (frame.frame.header.frame_type) {
                .headers => {
                    if (headers != null) {
                        if ((frame.frame.header.flags & flag_end_stream) == 0) {
                            return error.UnexpectedFrame;
                        }
                        trailers = try self.readHeaderBlockUntil(
                            frame.frame,
                            deadline,
                        );
                        try validateHeaderBlock(
                            trailers,
                            .response_trailers,
                        );
                        try validateExpectedContentLength(
                            expected_body_len,
                            body.items.len,
                        );
                        break;
                    }

                    const decoded = try self.readHeaderBlockUntil(
                        frame.frame,
                        deadline,
                    );
                    var decoded_owned = true;
                    errdefer if (decoded_owned) {
                        freeHeaders(self.allocator, decoded);
                    };
                    try validateHeaderBlock(decoded, .response);
                    const lookup = try responseHeaderLookup(decoded);
                    const status_s = lookup.status orelse return error.MissingPseudoHeader;
                    const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
                    if (informationalResponseToSkip(status)) {
                        if ((frame.frame.header.flags & flag_end_stream) != 0) return error.UnexpectedFrame;
                        if (lookup.content_length != null) return error.InvalidContentLength;
                        try notifyInformationalResponse(
                            self,
                            null,
                            .{ .headers = decoded, .status = status },
                            &informational_count,
                            self.limits.max_informational_responses,
                        );
                        freeHeaders(self.allocator, decoded);
                        decoded_owned = false;
                        continue;
                    }
                    if (status < 200 or status > 599) {
                        return error.InvalidStatus;
                    }
                    const accepted = status < 300;
                    const ended =
                        (frame.frame.header.flags & flag_end_stream) != 0;
                    if (deadline) |absolute| {
                        _ = try deadline_policy.usableAwake(
                            self.io,
                            absolute,
                        );
                    }
                    if (accepted) {
                        if ((lookup.content_length orelse 0) != 0) {
                            return error.InvalidContentLength;
                        }
                        if (ended) return error.ConnectionClosed;
                        decoded_owned = false;
                        return .{
                            .status = status,
                            .headers = decoded,
                            .body = &.{},
                            .trailers = &.{},
                            .tunnel = .{
                                .connection = self,
                                .stream_id = stream_id,
                            },
                        };
                    }

                    rejection_started = true;
                    headers = decoded;
                    decoded_owned = false;
                    status_value = status;
                    expected_body_len = lookup.content_length;
                    const rejection_forbids_body = responseForbidsBody(
                        status,
                        "CONNECT",
                        true,
                    );
                    if (rejection_forbids_body) {
                        if (!ended) {
                            try self.consumeForbiddenResponseBodyUntil(
                                stream_id,
                                deadline,
                            );
                        }
                        break;
                    }
                    if ((expected_body_len orelse 0) >
                        self.limits.max_body_bytes) return error.MessageTooLarge;
                    if (ended) {
                        try validateExpectedContentLength(
                            expected_body_len,
                            0,
                        );
                        break;
                    }
                },
                .data => {
                    if (headers == null) return error.UnexpectedFrame;
                    const connection_before = self.recv_connection_window.value;
                    const data = try self.receiveDataPayload(
                        stream_id,
                        frame.frame,
                    );
                    defer receive_credit.observe(connection_before, self.recv_connection_window.value, data.adaptive_connection_increment);
                    defer self.releaseDataFrameBudget(data);
                    const ended =
                        (frame.frame.header.flags & flag_end_stream) != 0;
                    _ = try checkedResponseBodyLength(
                        expected_body_len,
                        body.items.len,
                        data.data.len,
                        self.limits.max_body_bytes,
                        true,
                        ended,
                    );
                    try body.appendSlice(self.allocator, data.data);
                    try self.releaseReceivedDataCapacityUntil(
                        stream_id,
                        data,
                        ended,
                        deadline,
                    );
                    if (ended) break;
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    try self.recordResetStream(reset);
                    return error.StreamReset;
                },
                else => continue,
            }
        }

        self.releaseLocalStream(stream_id);
        self.forgetResponseSemantics(stream_id);
        self.forgetStreamWindows(stream_id);
        rejection_started = false;
        return .{
            .status = status_value orelse return error.MissingPseudoHeader,
            .headers = headers orelse return error.MissingPseudoHeader,
            .body = try body.toOwnedSlice(self.allocator),
            .trailers = trailers,
            .tunnel = null,
        };
    }

    pub fn validatePushPromiseForClientStream(self: Connection, frame: http2.Frame) Error!http2.PushPromisePayload {
        if (self.role != .client) return error.InvalidFrame;
        const promise = try http2.PushPromisePayload.parse(frame);
        // RFC 9113 keeps server push tied to a client-initiated stream that is
        // still open or half-closed(remote).  Rust h2 treats a promise on an
        // unknown/inactive parent as a connection protocol error instead of
        // silently discarding it; do the same before considering local push
        // policy.
        if (!clientInitiatedStreamId(promise.stream_id) or !self.outboundStreamIsActive(promise.stream_id)) {
            return error.InvalidFrame;
        }
        // Server-pushed streams are server initiated and must be strictly
        // increasing.  The lightweight runtime does not implement a push queue,
        // but validating the promised id catches malformed peers before the
        // normal "push disabled" rejection path.
        if (clientInitiatedStreamId(promise.promised_stream_id)) return error.InvalidStreamId;
        try self.push_state.validatePeerStreamId(
            promise.promised_stream_id,
        );
        return promise;
    }

    fn rejectDisabledPushPromise(
        self: *Connection,
        frame: http2.Frame,
    ) Error!void {
        _ = try self.validatePushPromiseForClientStream(frame);
        self.aggregate_timeout_unusable = true;
        self.serve_read_connection_error = .push_disabled;
        return error.InvalidFrame;
    }

    pub fn receivePushPromise(
        self: *Connection,
        frame: http2.Frame,
    ) Error!void {
        return self.receivePushPromiseUntil(frame, null);
    }

    fn receivePushPromiseUntil(
        self: *Connection,
        frame: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        const promise = try self.validatePushPromiseForClientStream(frame);
        var flags = frame.header.flags;
        var limit_exceeded = false;
        const byte_limit = header_block_limits.byteLimit(self.limits.max_frame_payload, self.limits.max_header_fields);
        const block = if ((flags & flag_end_headers) != 0)
            promise.header_block
        else blk: {
            self.header_block_scratch.clearRetainingCapacity();
            try self.header_block_scratch.appendSlice(
                self.allocator,
                promise.header_block,
            );
            var continuation_count: usize = 0;
            const max_continuations = self.maxContinuationFrames();
            while ((flags & flag_end_headers) == 0) {
                var continuation = if (self.push_ingress_headers_active)
                    try self.readOwnedTransportFrameWithDeadline(deadline)
                else
                    try self.readOwnedFrameWithDeadline(deadline);
                defer continuation.deinit(self.allocator);
                if (continuation.frame.header.frame_type != .continuation or
                    continuation.frame.header.stream_id != promise.stream_id)
                {
                    return error.UnexpectedFrame;
                }
                continuation_count += 1;
                const next_len = std.math.add(usize, self.header_block_scratch.items.len, continuation.frame.payload.len) catch return error.MessageTooLarge;
                limit_exceeded = header_block_limits.completeOverflow(continuation_count, max_continuations, next_len, byte_limit, (continuation.frame.header.flags & flag_end_headers) != 0) catch |err| {
                    self.serve_read_connection_error = .excessive_header_block;
                    self.aggregate_timeout_unusable = true;
                    return @errorCast(err);
                };
                try self.header_block_scratch.appendSlice(
                    self.allocator,
                    continuation.frame.payload,
                );
                flags = continuation.frame.header.flags;
            }
            break :blk self.header_block_scratch.items;
        };
        if (limit_exceeded) {
            self.hpack_decoder.discardBlock(self.allocator, block) catch |err| {
                if (self.hpack_decoder.lastDecodeWasCompressionError()) {
                    self.serve_read_connection_error = .compression;
                    self.aggregate_timeout_unusable = true;
                }
                return @errorCast(err);
            };
            try self.push_state.notePeerStreamId(self.allocator, promise.promised_stream_id);
            try self.writeLocalErrorResetStream(promise.promised_stream_id, .refused_stream);
            return;
        }
        const headers = try decodeOwnedHeaders(
            self.allocator,
            block,
            self.limits,
            &self.hpack_decoder,
        );
        errdefer freeHeaders(self.allocator, headers);
        try validateHeaderBlock(headers, .request);
        if (self.limits.max_concurrent_streams) |limit| {
            const used = self.occupiedPushSlots();
            if (used >= limit) {
                try self.push_state.notePeerStreamId(
                    self.allocator,
                    promise.promised_stream_id,
                );
                try self.writeLocalErrorResetStream(
                    promise.promised_stream_id,
                    .refused_stream,
                );
                freeHeaders(self.allocator, headers);
                return;
            }
        }
        if (self.push_state.remoteReservedCount() >= self.limits.max_buffered_pushes) {
            try self.push_state.notePeerStreamId(self.allocator, promise.promised_stream_id);
            try self.writeResetStreamFrameUntil(promise.promised_stream_id, .cancel, deadline);
            freeHeaders(self.allocator, headers);
            return;
        }
        try self.push_state.queue(self.allocator, .{
            .parent_stream_id = promise.stream_id,
            .promised_stream_id = promise.promised_stream_id,
            .headers = headers,
        });
    }

    fn consumeForbiddenResponseBody(
        self: *Connection,
        stream_id: u31,
    ) Error!void {
        return self.consumeForbiddenResponseBodyUntil(stream_id, null);
    }

    fn consumeForbiddenResponseBodyUntil(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        return forbidden_response_body.consume(self, stream_id, deadline, .{
            .ErrorType = Error,
            .readFrame = readOwnedFrameWithDeadline,
            .handleConnection = handleConnectionFrameUntil,
            .goAway = handleGoAwayForStream,
            .receive = receiveDataPayload,
            .releaseBudget = releaseDataFrameBudget,
            .releaseCapacity = releaseDiscardedMessageCapacity,
            .refund = sendWindowUpdatesUntil,
            .readHeaders = readHeaderBlockUntil,
            .freeHeaders = freeHeaders,
            .reject = recordResponseStreamReadError,
            .recordReset = recordResetStream,
            .fail = failDiscardedResponse,
        });
    }

    pub fn writeHeaders(self: *Connection, stream_id: u31, headers: []const http2.Hpack.HeaderField, end_stream: bool) Error!void {
        return self.writeHeadersUntil(stream_id, headers, end_stream, null);
    }

    pub fn writeHeadersUntil(self: *Connection, stream_id: u31, headers: []const http2.Hpack.HeaderField, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
        try validateHeaderListSize(headers, self.peer_max_header_list_size);
        const activation = try self.ensureStreamTrackedForOutboundHeaders(stream_id);
        errdefer self.undoStreamActivation(activation, stream_id);
        const encoder = try self.prepareStagedHpackEncoder();
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            headers,
        );
        // Any partial frame prefix makes the transport unrecoverable. HPACK is
        // staged independently so an allocation failure before writing leaves
        // the live encoder unchanged.
        var submitted = false;
        header_output.writeBlock(self.allocator, self.transportForIo(), stream_id, block, end_stream, self.outboundFramePayloadLimit(), &self.write_batch, deadline, &submitted) catch |err| {
            if (submitted) self.aggregate_timeout_unusable = true;
            return err;
        };
        self.commitStagedHpackEncoder();
        self.resetPeerPingEnforcement();
    }

    /// Emit HEADERS and the first DATA burst in one stream write when the
    /// header block and current flow-control credit permit it.
    ///
    /// Small request/response bodies are common and two tiny TCP submissions
    /// can trigger Linux's Nagle/delayed-ACK interaction. Larger or blocked
    /// bodies retain the normal framing and WINDOW_UPDATE-driven fallback.
    fn writeHeadersThenData(
        self: *Connection,
        stream_id: u31,
        headers: []const http2.Hpack.HeaderField,
        data: []const u8,
        end_stream: bool,
    ) Error!void {
        var head_committed = false;
        var written: usize = 0;
        return self.writeHeadersThenDataUntil(stream_id, headers, data, end_stream, null, &head_committed, &written);
    }

    fn writeHeadersThenDataUntil(self: *Connection, stream_id: u31, headers: []const http2.Hpack.HeaderField, data: []const u8, end_stream: bool, deadline: ?std.Io.Clock.Timestamp, head_committed: *bool, written: *usize) Error!void {
        head_committed.* = false;
        written.* = 0;
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        std.debug.assert(data.len != 0);
        try validateHeaderListSize(
            headers,
            self.peer_max_header_list_size,
        );
        const activation =
            try self.ensureStreamTrackedForOutboundHeaders(stream_id);
        errdefer self.undoStreamActivation(activation, stream_id);
        const encoder = try self.prepareStagedHpackEncoder();
        const block = try encoder.encodeBlockRetained(
            self.allocator,
            headers,
        );
        const frame_limit = self.outboundFramePayloadLimit();
        const stream_window = try self.sendStreamWindow(stream_id);
        const burst_limit = frame_limit *| max_data_frames_with_headers;
        const first_data_len = @min(
            data.len,
            burst_limit,
            self.send_connection_window.available(),
            stream_window.available(),
        );
        if (block.len > frame_limit or first_data_len == 0) {
            var submitted = false;
            header_output.writeBlock(self.allocator, self.transportForIo(), stream_id, block, false, frame_limit, &self.write_batch, deadline, &submitted) catch |err| {
                if (submitted) self.aggregate_timeout_unusable = true;
                return err;
            };
            self.commitStagedHpackEncoder();
            self.resetPeerPingEnforcement();
            head_committed.* = true;
            try self.writeDataTrackedUntil(stream_id, data, end_stream, written, deadline);
            return;
        }

        var burst_committed = false;
        try self.send_connection_window.reserve(first_data_len);
        errdefer if (!burst_committed) restoreWindow(
            &self.send_connection_window,
            @intCast(first_data_len),
        );
        try stream_window.reserve(first_data_len);
        errdefer if (!burst_committed) restoreWindow(
            stream_window,
            @intCast(first_data_len),
        );

        var headers_frame: [http2.FrameHeader.encoded_len]u8 = undefined;
        try encodeFrameHeader(
            &headers_frame,
            .headers,
            flag_end_headers,
            stream_id,
            block.len,
        );
        var data_frames: [max_data_frames_per_write][
            http2.FrameHeader.encoded_len
        ]u8 = undefined;
        var parts: [2 + 2 * max_data_frames_per_write][]const u8 =
            undefined;
        parts[0] = &headers_frame;
        parts[1] = block;
        var part_count: usize = 2;
        var offset: usize = 0;
        while (offset < first_data_len) {
            const end = @min(first_data_len, offset + frame_limit);
            const frame_index = (part_count - 2) / 2;
            try encodeFrameHeader(
                &data_frames[frame_index],
                .data,
                if (end_stream and end == data.len)
                    flag_end_stream
                else
                    0,
                stream_id,
                end - offset,
            );
            parts[part_count] = &data_frames[frame_index];
            parts[part_count + 1] = data[offset..end];
            part_count += 2;
            offset = end;
        }
        var submitted = false;
        flow_output.submit(self.allocator, self.transportForIo(), parts[0..part_count], &self.write_batch, deadline, &submitted) catch |err| {
            if (submitted) self.aggregate_timeout_unusable = true;
            return err;
        };
        burst_committed = true;
        written.* = first_data_len;
        self.commitStagedHpackEncoder();
        self.resetPeerPingEnforcement();
        head_committed.* = true;
        if (first_data_len < data.len) {
            var suffix_written: usize = 0;
            defer written.* += suffix_written;
            try self.writeDataTrackedUntil(stream_id, data[first_data_len..], end_stream, &suffix_written, deadline);
        }
    }

    const StreamActivation = enum { none, local, peer };

    fn ensureStreamTrackedForOutboundHeaders(self: *Connection, stream_id: u31) Error!StreamActivation {
        if (stream_id == 0) return error.InvalidStreamId;
        if (self.outboundStreamIsActive(stream_id)) return .none;
        const client_initiated = clientInitiatedStreamId(stream_id);
        if (self.role == .client) {
            if (!client_initiated) return error.InvalidStreamId;
            try self.addActiveLocalStream(stream_id);
            return .local;
        }
        if (!client_initiated) return error.InvalidStreamId;
        try self.addActivePeerStream(stream_id);
        return .peer;
    }

    fn undoStreamActivation(self: *Connection, activation: StreamActivation, stream_id: u31) void {
        switch (activation) {
            .none => {},
            .local => self.releaseLocalStream(stream_id),
            .peer => self.releasePeerStream(stream_id),
        }
    }

    pub fn writeExtendedConnectResponse(
        self: *Connection,
        stream_id: u31,
        status_code: u16,
        response_headers: []const http2.Hpack.HeaderField,
        end_stream: bool,
    ) Error!void {
        return self.writeExtendedConnectResponseUntil(stream_id, status_code, response_headers, end_stream, null);
    }

    fn writeExtendedConnectResponseUntil(
        self: *Connection,
        stream_id: u31,
        status_code: u16,
        response_headers: []const http2.Hpack.HeaderField,
        end_stream: bool,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        var status_buf: [3]u8 = undefined;
        if (status_code < 100 or status_code > 999) return error.InvalidStatus;
        const status = std.fmt.bufPrint(&status_buf, "{}", .{status_code}) catch return error.InvalidStatus;
        var fields_stack: [16]http2.Hpack.HeaderField = undefined;
        const fields_capacity = std.math.add(
            usize,
            response_headers.len,
            2,
        ) catch return error.MessageTooLarge;
        const fields_buffer = try stackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_capacity,
        );
        defer freeStackFirstHeaderFieldBuffer(
            self.allocator,
            &fields_stack,
            fields_buffer,
        );
        var fields: std.ArrayList(http2.Hpack.HeaderField) =
            .initBuffer(fields_buffer);
        fields.appendAssumeCapacity(.{ .name = ":status", .value = status });
        fields.appendSliceAssumeCapacity(response_headers);
        try outbound_headers.stripConnectionHeaders(
            self.allocator,
            &fields,
            .response,
        );
        try validateOutgoingResponseBodyForStatus(status_code, fields.items, &.{}, &.{});
        if (status_code >= 200 and status_code < 300) {
            try stripSuccessfulConnectContentLength(&fields);
        }
        try validateHeaderBlock(fields.items, .response);
        if (!statusIsInformational(status_code)) {
            self.appendAutomaticDateHeader(&fields);
        }
        try self.writeHeadersUntil(stream_id, fields.items, end_stream, deadline);
    }

    pub fn handleConnectionOrGoAwayFrame(self: *Connection, frame: http2.Frame) Error!bool {
        return self.handleConnectionOrGoAwayFrameUntil(frame, null);
    }

    pub fn handleConnectionOrGoAwayFrameUntil(self: *Connection, frame: http2.Frame, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        if (frame.header.frame_type == .goaway) {
            try self.recordPeerGoAway(try http2.GoAwayPayload.parse(frame));
            return true;
        }
        return self.handleConnectionFrameUntil(frame, deadline);
    }

    fn applyWindowUpdate(
        self: *Connection,
        update: http2.WindowUpdatePayload,
    ) Error!void {
        return self.applyWindowUpdateUntil(update, null);
    }

    fn applyWindowUpdateUntil(self: *Connection, update: http2.WindowUpdatePayload, deadline: ?std.Io.Clock.Timestamp) Error!void {
        if (update.stream_id == 0) {
            self.send_connection_window.update(update.increment) catch |err| {
                if (err != error.FlowControlViolation) return err;
                // A connection-window overflow terminates the whole HTTP/2
                // connection with the precise RFC 9113 wire error.
                self.aggregate_timeout_unusable = true;
                self.sendProtocolGoAway(
                    self.lastPeerProcessedStreamId(),
                    .flow_control_error,
                    "connection-window-overflow",
                    deadline,
                );
                return error.ConnectionGoAway;
            };
            return;
        }
        if (self.streamIsIdle(update.stream_id)) {
            // WINDOW_UPDATE on an idle stream is a connection-level protocol
            // error. Updates for closed streams remain ignorable.
            return error.InvalidFrame;
        }
        if (!self.outboundStreamIsActive(update.stream_id)) return;
        (try self.sendStreamWindow(update.stream_id)).update(
            update.increment,
        ) catch |err| {
            if (err != error.FlowControlViolation) return err;
            try self.writeLocalErrorResetStreamUntil(
                update.stream_id,
                .flow_control_error,
                deadline,
            );
            self.releaseLocalStream(update.stream_id);
            self.releasePeerStream(update.stream_id);
            self.forgetStreamWindows(update.stream_id);
        };
    }

    pub fn handleConnectionFrame(self: *Connection, frame: http2.Frame) Error!bool {
        return self.handleConnectionFrameUntil(frame, null);
    }

    pub fn handleConnectionFrameUntil(self: *Connection, frame: http2.Frame, deadline: ?std.Io.Clock.Timestamp) Error!bool {
        if (try self.discardLateFrameForLocallyResetStreamUntil(frame, deadline)) {
            return true;
        }
        switch (frame.header.frame_type) {
            .settings => {
                if ((frame.header.flags & flag_ack) != 0) {
                    try self.applySettingsAck();
                } else {
                    try self.applyPeerSettingsPayload(frame.payload, deadline);
                    try self.writeControlFrameUntil(
                        .settings,
                        flag_ack,
                        &.{},
                        deadline,
                    );
                }
                return true;
            },
            .ping => {
                const ping_payload = try http2.PingPayload.parse(frame);
                if ((frame.header.flags & flag_ack) == 0) {
                    try self.enforcePeerPingUntil(deadline);
                    try self.writeControlFrameUntil(
                        .ping,
                        flag_ack,
                        &ping_payload.data,
                        deadline,
                    );
                } else {
                    try self.applyPingAck(ping_payload.data);
                }
                return true;
            },
            .window_update => {
                const update = try http2.WindowUpdatePayload.parse(frame);
                try self.applyWindowUpdateUntil(update, deadline);
                return true;
            },
            .priority => {
                // PRIORITY can be interleaved with DATA/HEADERS and does not
                // alter the message body.  The envelope validator has already
                // checked stream id and payload length; parse it here so
                // malformed priority payloads still fail before being ignored.
                try legacy_priority.validateFrame(self, frame);
                return true;
            },
            .priority_update => {
                if (self.role != .server) return error.InvalidFrame;
                if (!self.limits.no_rfc7540_priorities) {
                    // The client is advised to stop these after observing a
                    // missing/zero setting. Unknown extension frames remain
                    // ignorable, so discard rather than allocate state.
                    return true;
                }
                const update = try http2.PriorityUpdatePayload.parse(frame);
                const stream_id = update.prioritized_stream_id;
                if (clientInitiatedStreamId(stream_id)) {
                    if (stream_id > self.last_peer_client_stream_id) {
                        try self.priority_state.reserveIdleRequest(
                            self.allocator,
                            stream_id,
                            self.active_peer_streams.items.len,
                            self.limits.max_concurrent_streams,
                            self.limits.max_idle_priority_updates,
                        );
                    } else if (!self.outboundStreamIsActive(stream_id)) {
                        // Closed request streams can be discarded without
                        // retaining attacker-controlled field values.
                        return true;
                    }
                } else {
                    if (!self.push_state.isLocalReserved(stream_id) and
                        !self.outboundStreamIsActive(stream_id))
                    {
                        if (stream_id <
                            self.push_state.nextLocalStreamId())
                        {
                            // A previously promised push is already closed;
                            // RFC 9218 permits discarding this late update.
                            return true;
                        }
                        // An even ID not present in local reservations is an
                        // idle push stream, which RFC 9218 forbids targeting.
                        return error.InvalidFrame;
                    }
                }
                try self.priority_state.store(
                    self.allocator,
                    stream_id,
                    update.field_value,
                );
                return true;
            },
            .rst_stream => {
                const reset = try http2.ResetStreamPayload.parse(frame);
                const reserved_push =
                    (self.role == .server and
                        self.push_state.localStatus(reset.stream_id) != null) or
                    (self.role == .client and
                        self.push_state.isRemoteReserved(reset.stream_id));
                if (reserved_push) {
                    try self.recordResetStream(reset);
                    return true;
                }
                if (self.outboundStreamIsActive(reset.stream_id) or
                    self.streamIsIdle(reset.stream_id))
                {
                    return false;
                }
                // A complete response can race the server's RST_STREAM after
                // it stops an unfinished request body (commonly NO_ERROR).
                // The local stream owner has already consumed END_STREAM and
                // released both halves, so this reset is terminal evidence for
                // an already-closed stream rather than input for a later
                // request. Ignore it without publishing a stale reset reason.
                return true;
            },
            .origin => {
                // ORIGIN is server-to-client only. RFC 8336 requires clients
                // to ignore it when sent on a non-zero stream or with an
                // incompatible reserved flag; envelope validation therefore
                // leaves those cases available for this semantic decision.
                if (self.role != .client or
                    frame.header.stream_id != 0 or
                    (frame.header.flags & 0x0f) != 0)
                {
                    return true;
                }
                var origin = try http2.OriginPayload.parse(
                    self.allocator,
                    frame,
                );
                defer origin.deinit(self.allocator);
                for (origin.origins) |value| {
                    try self.storePeerOrigin(value);
                }
                return true;
            },
            .altsvc => {
                if (self.role != .client or frame.header.flags != 0) {
                    return true;
                }
                const service = try http2.AltSvcPayload.parse(frame);
                try self.storeAlternativeService(
                    frame.header.stream_id,
                    service.origin,
                    service.field_value,
                );
                return true;
            },
            // RFC 9113 section 5.5 requires unknown extension frame types to
            // be ignored. Keep known stream/message frames visible to the
            // caller, while consuming only values that this runtime does not
            // assign protocol semantics to.
            .data,
            .headers,
            .push_promise,
            .goaway,
            .continuation,
            => return false,
            _ => return true,
        }
    }

    fn writeHeaderBlock(self: *Connection, stream_id: u31, block: []const u8, end_stream: bool) Error!void {
        var submitted = false;
        try header_output.writeBlock(self.allocator, self.transportForIo(), stream_id, block, end_stream, self.outboundFramePayloadLimit(), &self.write_batch, null, &submitted);
        self.resetPeerPingEnforcement();
    }

    pub fn readHeaderBlock(self: *Connection, first: http2.Frame) Error![]http2.Hpack.HeaderField {
        return self.readHeaderBlockUntil(first, null);
    }

    fn readResponseTrailersUntil(self: *Connection, frame: http2.Frame, forbids_body: bool, deadline: ?std.Io.Clock.Timestamp) Error![]http2.Hpack.HeaderField {
        errdefer |err| if (self.serve_read_connection_error == null) {
            const code = if (err == error.UnexpectedFrame) http2.ErrorCode.protocol_error else responseStreamErrorCode(err);
            if (code) |value| self.recordResponseStreamReadError(frame.header.stream_id, value);
        };
        return response_trailers.read(self, frame, forbids_body, deadline, .{
            .ErrorType = Error,
            .readHeaders = readHeaderBlockUntil,
            .freeHeaders = freeHeaders,
        });
    }

    fn readHeaderBlockUntil(
        self: *Connection,
        first: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![]http2.Hpack.HeaderField {
        return InboundHeaders.read(self, first, deadline, false);
    }

    fn readHeaderBlockRawUntil(
        self: *Connection,
        first: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error![]http2.Hpack.HeaderField {
        return InboundHeaders.read(self, first, deadline, true);
    }

    fn resumeDeferredHeaderBlockUntil(
        self: *Connection,
        first: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
        raw_continuations: bool,
        discard: bool,
    ) Error!?[]http2.Hpack.HeaderField {
        return InboundHeaders.resumeDeferred(self, first, deadline, raw_continuations, discard);
    }

    fn collectHeaderBlockUntil(
        self: *Connection,
        first: http2.Frame,
        deadline: ?std.Io.Clock.Timestamp,
        raw_continuations: bool,
    ) Error!header_block_limits.Collected {
        return InboundHeaders.collect(self, first, deadline, raw_continuations);
    }

    fn writePushPromiseBlockUntil(
        self: *Connection,
        parent_stream_id: u31,
        promised_stream_id: u31,
        block: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
        submitted: *bool,
    ) Error!void {
        submitted.* = false;
        const chunk_size = self.outboundFramePayloadLimit();
        if (chunk_size <= 4) return error.InvalidFrame;
        if (deadline) |absolute| {
            self.write_batch.clearRetainingCapacity();
            try appendPushPromiseBlockBytes(
                &self.write_batch,
                self.allocator,
                parent_stream_id,
                promised_stream_id,
                block,
                chunk_size,
            );
            var committed: usize = 0;
            submitted.* = true;
            return self.transportForIo().writeAllWithDeadline(
                self.write_batch.items,
                &committed,
                absolute,
            );
        }
        const first_len = @min(block.len, chunk_size - 4);
        var prefix: [http2.FrameHeader.encoded_len + 4]u8 = undefined;
        try encodeFrameHeader(
            prefix[0..http2.FrameHeader.encoded_len],
            .push_promise,
            if (first_len == block.len) flag_end_headers else 0,
            parent_stream_id,
            4 + first_len,
        );
        std.mem.writeInt(
            u32,
            prefix[http2.FrameHeader.encoded_len..],
            promised_stream_id,
            .big,
        );
        submitted.* = true;
        try self.transportForIo().writeAllParts(
            &prefix,
            block[0..first_len],
        );
        var offset = first_len;
        while (offset < block.len) {
            const end = @min(block.len, offset + chunk_size);
            try writeFrameTransport(
                self.allocator,
                self.transportForIo(),
                .continuation,
                if (end == block.len) flag_end_headers else 0,
                parent_stream_id,
                block[offset..end],
            );
            offset = end;
        }
    }

    pub fn maxContinuationFrames(self: Connection) usize {
        if (self.limits.max_continuation_frames) |limit| return limit;
        return calcMaxContinuationFrames(self.limits.max_header_list_size, advertisedMaxFrameSize(self.limits));
    }

    pub fn writeData(self: *Connection, stream_id: u31, data: []const u8, end_stream: bool) Error!void {
        var ignored_written: usize = 0;
        return self.writeDataTracked(
            stream_id,
            data,
            end_stream,
            &ignored_written,
        );
    }

    fn writeDataParts(
        self: *Connection,
        stream_id: u31,
        first: []const u8,
        second: []const u8,
        end_stream: bool,
    ) Error!void {
        return self.writeDataSlices(
            stream_id,
            &.{ first, second },
            end_stream,
        );
    }

    fn writeDataSlices(
        self: *Connection,
        stream_id: u31,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!void {
        try self.prepareDataWrite(stream_id);
        return self.writeDataSlicesPrepared(
            stream_id,
            slices,
            end_stream,
        );
    }

    pub fn prepareDataWrite(
        self: *Connection,
        stream_id: u31,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (!self.outboundStreamIsActive(stream_id)) {
            return error.InvalidStreamId;
        }
        if (self.role == .client and
            self.pendingApplicationFrameCount() != 0)
        {
            return error.ResponseAvailable;
        }
    }

    fn writeDataSlicesPrepared(
        self: *Connection,
        stream_id: u31,
        slices: []const []const u8,
        end_stream: bool,
    ) Error!void {
        var ignored_written: usize = 0;
        return self.writeDataSlicesPreparedTrackedUntil(
            stream_id,
            slices,
            end_stream,
            &ignored_written,
            null,
        ) catch |err| switch (err) {
            error.Timeout => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn writeDataSlicesPreparedTrackedUntil(
        self: *Connection,
        stream_id: u31,
        slices: []const []const u8,
        end_stream: bool,
        written: *usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) ResponseTimeoutError!void {
        written.* = 0;
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.io, absolute);
        }
        var total_len: usize = 0;
        for (slices) |slice| {
            total_len = std.math.add(
                usize,
                total_len,
                slice.len,
            ) catch return error.MessageTooLarge;
        }
        if (total_len == 0) {
            if (deadline) |absolute| {
                _ = try deadline_policy.usableAwake(self.io, absolute);
            }
            flow_output.writeEmpty(self.allocator, self.transportForIo(), stream_id, end_stream, deadline) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
            self.resetPeerPingEnforcement();
            return;
        }

        const wire_part_capacity = std.math.add(
            usize,
            slices.len,
            2 * max_data_frames_per_write,
        ) catch return error.MessageTooLarge;
        // Sixteen WebSocket fragments produce 32 logical slices. Allow their
        // four DATA-frame headers and possible boundary splits to stay on the
        // stack rather than trading a removed payload buffer for descriptor
        // allocation on the common compressed-fragment batch.
        var wire_parts_stack: [80][]const u8 = undefined;
        const wire_parts = if (wire_part_capacity <= wire_parts_stack.len)
            wire_parts_stack[0..wire_part_capacity]
        else
            try self.allocator.alloc([]const u8, wire_part_capacity);
        defer if (wire_parts.ptr != wire_parts_stack[0..].ptr) {
            self.allocator.free(wire_parts);
        };

        const chunk_size = self.outboundFramePayloadLimit();
        var offset: usize = 0;
        var cursor = DataSliceCursor{ .slices = slices };
        while (offset < total_len) {
            if (deadline) |absolute| {
                _ = try deadline_policy.usableAwake(self.io, absolute);
            }
            const stream_window = try self.sendStreamWindow(stream_id);
            const available_credit = @min(
                total_len - offset,
                self.send_connection_window.available(),
                stream_window.available(),
            );
            if (available_credit == 0) {
                self.waitForDuplexSendCapacityUntil(
                    stream_id,
                    deadline,
                ) catch |err| {
                    written.* = offset;
                    return err;
                };
                continue;
            }

            const burst_limit = std.math.mul(
                usize,
                chunk_size,
                max_data_frames_per_write,
            ) catch std.math.maxInt(usize);
            const burst_len = @min(available_credit, burst_limit);
            self.writeDataSlicesBurst(
                stream_id,
                &cursor,
                burst_len,
                end_stream and offset + burst_len == total_len,
                chunk_size,
                stream_window,
                wire_parts,
                deadline,
            ) catch |err| {
                return err;
            };
            offset += burst_len;
            written.* = offset;
        }
    }

    fn writeDataTracked(
        self: *Connection,
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
        written: *usize,
    ) Error!void {
        return self.writeDataTrackedUntil(
            stream_id,
            data,
            end_stream,
            written,
            null,
        );
    }

    pub fn writeDataTrackedUntil(
        self: *Connection,
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
        written: *usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (!self.outboundStreamIsActive(stream_id)) return error.InvalidStreamId;
        if (self.role == .client and
            self.pendingApplicationFrameCount() != 0)
        {
            return error.ResponseAvailable;
        }
        written.* = 0;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.io, absolute);
        }
        const chunk_size = self.outboundFramePayloadLimit();
        if (data.len == 0) {
            flow_output.writeEmpty(self.allocator, self.transportForIo(), stream_id, end_stream, deadline) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
            self.resetPeerPingEnforcement();
            return;
        }

        var offset: usize = 0;
        while (offset < data.len) {
            const stream_window = try self.sendStreamWindow(stream_id);
            const available_credit = @min(
                data.len - offset,
                self.send_connection_window.available(),
                stream_window.available(),
            );
            if (available_credit == 0) {
                try self.waitForSendCapacityUntil(stream_id, deadline);
                continue;
            }

            const burst_limit = std.math.mul(
                usize,
                chunk_size,
                max_data_frames_per_write,
            ) catch std.math.maxInt(usize);
            const burst_len = @min(available_credit, burst_limit);
            self.writeDataBurst(
                stream_id,
                data[offset..][0..burst_len],
                end_stream and offset + burst_len == data.len,
                chunk_size,
                stream_window,
                deadline,
            ) catch |err| {
                return err;
            };
            offset += burst_len;
            written.* = offset;
        }
    }

    /// Duplex counterpart to `writeDataTracked`. Response frames already in
    /// the queue, or encountered while waiting for credit, are preserved and
    /// reported without implicitly closing the request half.
    fn writeDataDuplexTracked(
        self: *Connection,
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
        written: *usize,
    ) Error!void {
        return self.writeDataDuplexTrackedUntil(
            stream_id,
            data,
            end_stream,
            written,
            null,
        );
    }

    pub fn writeDataDuplexTrackedUntil(
        self: *Connection,
        stream_id: u31,
        data: []const u8,
        end_stream: bool,
        written: *usize,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (!self.outboundStreamIsActive(stream_id)) {
            return error.InvalidStreamId;
        }
        written.* = 0;
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(self.io, absolute);
        }
        // For a client these are response frames for the active request and
        // must be surfaced before another write. A server may instead have
        // queued sibling request frames while a long-lived response owns the
        // reader; those must not stall writes on the active stream.
        if (self.role == .client and
            self.pendingApplicationFrameCount() != 0)
        {
            return error.ResponseAvailable;
        }
        if (data.len == 0) {
            flow_output.writeEmpty(self.allocator, self.transportForIo(), stream_id, end_stream, deadline) catch |err| {
                self.aggregate_timeout_unusable = true;
                return err;
            };
            self.resetPeerPingEnforcement();
            return;
        }

        const chunk_size = self.outboundFramePayloadLimit();
        var offset: usize = 0;
        while (offset < data.len) {
            const stream_window = try self.sendStreamWindow(stream_id);
            const available_credit = @min(
                data.len - offset,
                self.send_connection_window.available(),
                stream_window.available(),
            );
            if (available_credit == 0) {
                self.waitForDuplexSendCapacityUntil(
                    stream_id,
                    deadline,
                ) catch |err| {
                    written.* = offset;
                    return err;
                };
                continue;
            }
            const burst_limit = std.math.mul(
                usize,
                chunk_size,
                max_data_frames_per_write,
            ) catch std.math.maxInt(usize);
            const burst_len = @min(available_credit, burst_limit);
            self.writeDataBurst(
                stream_id,
                data[offset..][0..burst_len],
                end_stream and offset + burst_len == data.len,
                chunk_size,
                stream_window,
                deadline,
            ) catch |err| {
                return err;
            };
            offset += burst_len;
            written.* = offset;
        }
    }

    fn waitForDuplexSendCapacity(
        self: *Connection,
        stream_id: u31,
    ) Error!void {
        return self.waitForDuplexSendCapacityUntil(stream_id, null);
    }

    fn waitForDuplexSendCapacityUntil(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (self.send_connection_window.available() == 0 or
            (try self.sendStreamWindow(stream_id)).available() == 0)
        {
            var frame = if (self.role == .client and self.duplex_owners.count() != 0)
                try self.readClientDuplexWireFrame(deadline)
            else
                try self.readOwnedFrameForDuplexWithDeadline(deadline);
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.allocator);
            if (self.role == .client and self.duplex_owners.count() != 0) {
                try self.validateClientDuplexHeaderSequence(frame.frame, deadline);
            }
            if (try self.handleConnectionFrameUntil(frame.frame, deadline)) continue;
            if (frame.frame.header.frame_type == .goaway) {
                const goaway = try http2.GoAwayPayload.parse(frame.frame);
                try self.handleGoAwayForStream(stream_id, goaway);
                continue;
            }
            if (frame.frame.header.stream_id != stream_id) {
                try self.queueDuplexSiblingFrameUntil(frame);
                frame_owned = false;
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .headers, .data, .push_promise => {
                    if (self.duplex_pending_frame.hasValue()) {
                        return error.UnexpectedFrame;
                    }
                    self.duplex_pending_frame.put(frame);
                    frame_owned = false;
                    return error.ResponseAvailable;
                },
                .rst_stream => {
                    _ = try http2.ResetStreamPayload.parse(frame.frame);
                    // Preserve the terminal frame for the duplex event API so
                    // callers receive the typed reset even when it arrived
                    // while a write was pumping flow-control updates.
                    if (self.duplex_pending_frame.hasValue()) {
                        return error.UnexpectedFrame;
                    }
                    self.duplex_pending_frame.put(frame);
                    frame_owned = false;
                    return error.ResponseAvailable;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn writeDataBurst(
        self: *Connection,
        stream_id: u31,
        payload: []const u8,
        end_stream: bool,
        chunk_size: usize,
        stream_window: *FlowWindow,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        std.debug.assert(payload.len != 0);
        std.debug.assert(payload.len <=
            chunk_size *| max_data_frames_per_write);

        try self.send_connection_window.reserve(payload.len);
        errdefer restoreWindow(
            &self.send_connection_window,
            @intCast(payload.len),
        );
        try stream_window.reserve(payload.len);
        errdefer restoreWindow(
            stream_window,
            @intCast(payload.len),
        );

        var submitted = false;
        flow_output.writeBurst(max_data_frames_per_write, self.allocator, self.transportForIo(), stream_id, payload, end_stream, chunk_size, &self.write_batch, deadline, &submitted) catch |err| {
            if (submitted) self.aggregate_timeout_unusable = true;
            return err;
        };
        self.resetPeerPingEnforcement();
    }

    fn writeDataSlicesBurst(
        self: *Connection,
        stream_id: u31,
        cursor: *DataSliceCursor,
        payload_len: usize,
        end_stream: bool,
        chunk_size: usize,
        stream_window: *FlowWindow,
        wire_parts: [][]const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        std.debug.assert(payload_len != 0);
        std.debug.assert(payload_len <=
            chunk_size *| max_data_frames_per_write);

        try self.send_connection_window.reserve(payload_len);
        errdefer restoreWindow(
            &self.send_connection_window,
            @intCast(payload_len),
        );
        try stream_window.reserve(payload_len);
        errdefer restoreWindow(
            stream_window,
            @intCast(payload_len),
        );

        var headers: [max_data_frames_per_write][
            http2.FrameHeader.encoded_len
        ]u8 = undefined;
        var wire_part_count: usize = 0;
        var frame_offset: usize = 0;
        var frame_index: usize = 0;
        while (frame_offset < payload_len) : (frame_index += 1) {
            const frame_end = @min(
                payload_len,
                frame_offset + chunk_size,
            );
            const frame_len = frame_end - frame_offset;
            try encodeFrameHeader(
                &headers[frame_index],
                .data,
                if (end_stream and frame_end == payload_len)
                    flag_end_stream
                else
                    0,
                stream_id,
                frame_len,
            );
            wire_parts[wire_part_count] = &headers[frame_index];
            wire_part_count += 1;
            cursor.appendTo(wire_parts, &wire_part_count, frame_len);
            frame_offset = frame_end;
        }
        var submitted = false;
        flow_output.submit(self.allocator, self.transportForIo(), wire_parts[0..wire_part_count], &self.write_batch, deadline, &submitted) catch |err| {
            if (submitted) self.aggregate_timeout_unusable = true;
            return err;
        };
        self.resetPeerPingEnforcement();
    }

    fn waitForSendCapacity(self: *Connection, stream_id: u31) Error!void {
        return self.waitForSendCapacityUntil(stream_id, null);
    }

    fn waitForSendCapacityUntil(
        self: *Connection,
        stream_id: u31,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        while (self.send_connection_window.available() == 0 or (try self.sendStreamWindow(stream_id)).available() == 0) {
            var frame = try self.readOwnedFrameWithDeadline(deadline);
            var frame_owned = true;
            defer if (frame_owned) frame.deinit(self.allocator);
            if (try self.handleConnectionFrameUntil(frame.frame, deadline)) {
                if (self.push_state.localStatus(stream_id) ==
                    .canceled)
                {
                    return error.StreamReset;
                }
                continue;
            }
            switch (frame.frame.header.frame_type) {
                .goaway => {
                    const goaway = try http2.GoAwayPayload.parse(frame.frame);
                    try self.handleGoAwayForStream(stream_id, goaway);
                },
                .rst_stream => {
                    const reset = try http2.ResetStreamPayload.parse(
                        frame.frame,
                    );
                    if (reset.stream_id == stream_id) {
                        try self.recordResetStream(reset);
                        return error.StreamReset;
                    }
                    if (try self.handleQueuedSiblingReset(reset)) {
                        continue;
                    }
                    if (self.wasLocallyReset(reset.stream_id)) {
                        continue;
                    }
                    return error.UnexpectedFrame;
                },
                .headers, .data, .push_promise => {
                    if (self.role != .client) {
                        return error.UnexpectedFrame;
                    }
                    if (frame.frame.header.stream_id != stream_id) {
                        return error.UnexpectedFrame;
                    }
                    // Transfer the owning frame to the eventual response
                    // reader. This method returns immediately, so its own
                    // contribution stays one frame even though the shared
                    // queue can also retain a bounded PING interleaving burst.
                    try self.queuePendingApplicationFrame(frame);
                    frame_owned = false;
                    return error.ResponseAvailable;
                },
                else => return error.UnexpectedFrame,
            }
        }
    }

    fn applyPingAck(self: *Connection, payload: [8]u8) Error!void {
        try self.applyAdaptivePingAck(payload);
        if (self.ping_probe_payload) |expected| {
            if (std.mem.eql(u8, &expected, &payload)) {
                self.ping_probe_payload = null;
                self.ping_probe_acknowledged = true;
            }
        }
    }

    fn enforcePeerPingUntil(
        self: *Connection,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.role != .server) return;
        const policy = self.limits.ping_enforcement orelse return;
        const excessive = self.ping_enforcement.receive(
            policy,
            std.Io.Clock.awake.now(self.io),
            !self.hasActiveStreams(),
        );
        if (!excessive) return;
        self.sendProtocolGoAway(
            self.lastPeerProcessedStreamId(),
            .enhance_your_calm,
            "too_many_pings",
            deadline,
        );
        return error.ConnectionGoAway;
    }

    fn resetPeerPingEnforcement(self: *Connection) void {
        if (self.role == .server and self.limits.ping_enforcement != null) {
            self.ping_enforcement.reset();
        }
    }

    fn applyAdaptivePingAck(
        self: *Connection,
        payload: [8]u8,
    ) Error!void {
        const estimator = if (self.adaptive_window) |*value| value else return;
        const ack = estimator.acknowledge(payload, awakeNowNanos(self.io));
        if (!ack.matched) return;
        if (ack.target) |target| try self.queueAdaptiveWindowTarget(target);
    }

    pub fn queueAdaptiveWindowTarget(
        self: *Connection,
        target: u32,
    ) Error!void {
        if (target <= self.recv_stream_window_target and
            target <= self.recv_connection_window_target) return;
        self.adaptive_queued_target = if (self.adaptive_queued_target) |old|
            @max(old, target)
        else
            target;
        if (!self.awaiting_settings_ack) {
            try self.sendQueuedAdaptiveWindowUpdate();
        }
    }

    fn sendQueuedAdaptiveWindowUpdate(self: *Connection) Error!void {
        const target = self.adaptive_queued_target orelse return;
        if (try self.sendAdaptiveWindowUpdate(target)) {
            self.adaptive_queued_target = null;
        }
    }

    fn sendQueuedAdaptiveWindowUpdateAfterData(self: *Connection, id: u31, padding_bytes: u9) Error!void {
        const target = self.adaptive_queued_target orelse return;
        if (try self.sendAdaptiveWindowUpdateKeepingPadding(target, id, padding_bytes)) self.adaptive_queued_target = null;
    }

    pub fn applySettingsAck(self: *Connection) Error!void {
        if (!self.awaiting_settings_ack) return error.InvalidFrame;
        self.awaiting_settings_ack = false;
        self.webtransport_settings.acknowledgeLocal();
        self.adaptive_pending_stream_target = null;
        try self.sendQueuedAdaptiveWindowUpdate();
    }

    pub fn sendAdaptiveWindowUpdate(
        self: *Connection,
        target: u32,
    ) Error!bool {
        return self.sendAdaptiveWindowUpdateKeepingPadding(target, null, 0);
    }

    fn sendAdaptiveWindowUpdateKeepingPadding(self: *Connection, target: u32, data_stream: ?u31, padding_bytes: u9) Error!bool {
        if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
        if (target <= self.recv_stream_window_target and
            target <= self.recv_connection_window_target) return true;
        if (self.awaiting_settings_ack) return false;
        if (target > std.math.maxInt(i31)) return error.InvalidSetting;

        var connection_increment: ?u31 = null;
        if (target > self.recv_connection_window_target) {
            const increment: u31 = @intCast(
                target - self.recv_connection_window_target,
            );
            const next = std.math.add(
                i64,
                self.recv_connection_window.value,
                increment,
            ) catch return error.FlowControlViolation;
            // Explicit application releases can leave more connection credit
            // than the adaptive target needs. In that case advancing the
            // logical refill target without another WINDOW_UPDATE avoids a
            // wire overflow while preserving the already-larger peer credit.
            if (next <= max_flow_window - @as(i64, padding_bytes)) connection_increment = increment;
        }
        const stream_delta: i64 = @as(i64, target) -
            self.recv_stream_window_target;
        for (self.recv_stream_windows.items) |entry| {
            const next = std.math.add(
                i64,
                entry.window.value,
                stream_delta,
            ) catch return error.FlowControlViolation;
            // SETTINGS_INITIAL_WINDOW_SIZE applies to every existing stream.
            // Defer the whole update until DATA consumption makes it safe; a
            // selective stream adjustment would desynchronize peer state.
            const reserved: i64 = if (data_stream == entry.stream_id) padding_bytes else 0;
            if (next > max_flow_window - reserved) return false;
        }
        var settings_payload: [6]u8 = undefined;
        std.mem.writeInt(
            u16,
            settings_payload[0..2],
            @intFromEnum(http2.SettingId.initial_window_size),
            .big,
        );
        std.mem.writeInt(u32, settings_payload[2..6], target, .big);
        var encoded: [
            http2.FrameHeader.encoded_len + 4 +
                http2.FrameHeader.encoded_len + settings_payload.len
        ]u8 = undefined;
        var encoded_len: usize = 0;
        if (connection_increment) |increment| {
            try encodeWindowUpdateFrame(
                encoded[0 .. http2.FrameHeader.encoded_len + 4],
                0,
                increment,
            );
            encoded_len += http2.FrameHeader.encoded_len + 4;
        }
        try encodeFrameHeader(
            encoded[encoded_len..][0..http2.FrameHeader.encoded_len],
            .settings,
            0,
            0,
            settings_payload.len,
        );
        encoded_len += http2.FrameHeader.encoded_len;
        @memcpy(
            encoded[encoded_len..][0..settings_payload.len],
            &settings_payload,
        );
        encoded_len += settings_payload.len;
        self.transportForIo().writeAll(encoded[0..encoded_len]) catch |err| {
            // WINDOW_UPDATE and SETTINGS share one transport submission. A
            // failure can expose an unknown prefix of either frame, so neither
            // the wire state nor the local receive-window transaction is
            // retryable on this connection.
            self.aggregate_timeout_unusable = true;
            return err;
        };

        if (connection_increment) |increment| {
            try self.recv_connection_window.update(increment);
        }
        self.recv_connection_window_target = @max(
            self.recv_connection_window_target,
            target,
        );
        for (self.recv_stream_windows.items) |*entry| {
            try entry.window.adjust(stream_delta);
        }
        self.recv_stream_window_target = target;
        self.adaptive_pending_stream_target = target;
        self.awaiting_settings_ack = true;
        return true;
    }

    fn applyInitialWindowSize(self: *Connection, value: u32) Error!void {
        if (value > std.math.maxInt(i31)) return error.InvalidSetting;
        const new_window: i64 = value;
        const delta = new_window - self.peer_initial_stream_window;
        var adjusted: usize = 0;
        errdefer {
            var index: usize = 0;
            while (index < adjusted) : (index += 1) {
                restoreWindowDelta(
                    &self.send_stream_windows.items[index].window,
                    -delta,
                );
            }
        }

        for (self.send_stream_windows.items) |*entry| {
            try entry.window.adjust(delta);
            adjusted += 1;
        }
        self.peer_initial_stream_window = new_window;
    }

    const PeerSettings = @import("settings/apply.zig").Controller(struct {
        pub const ConnectionType = Connection;
        pub const ErrorType = Error;
        pub const applyInitialWindowSize = Connection.applyInitialWindowSize;
    });
    pub const applySettings = PeerSettings.apply;

    pub fn applyPeerSettingsPayload(
        self: *Connection,
        payload: []const u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) Error!void {
        const iterator = http2.SettingsIterator.init(payload) catch |err| {
            self.reportPeerSettingsFailure(payload, err, deadline);
            return err;
        };
        PeerSettings.applyBorrowed(self, iterator) catch |err| {
            self.reportPeerSettingsFailure(payload, err, deadline);
            return err;
        };
    }

    fn reportPeerSettingsFailure(
        self: *Connection,
        payload: []const u8,
        err: anyerror,
        deadline: ?std.Io.Clock.Timestamp,
    ) void {
        const code = handshake_protocol_error.settingsFailureCode(payload, err) orelse return;
        self.sendProtocolGoAway(
            self.lastPeerProcessedStreamId(),
            code,
            "settings-value",
            deadline,
        );
        self.aggregate_timeout_unusable = true;
    }

    pub fn storeAlternativeService(
        self: *Connection,
        stream_id: u31,
        origin_value: []const u8,
        field_value: []const u8,
    ) Error!void {
        if (self.alternative_services) |services| {
            return services.store(
                self.allocator,
                stream_id,
                origin_value,
                field_value,
                self.limits.max_alternative_services,
            );
        }
        if (self.limits.max_alternative_services == 0) return;

        const services = try self.allocator.create(
            peer_metadata.AlternativeServices,
        );
        services.* = .{};
        errdefer {
            services.deinit(self.allocator);
            self.allocator.destroy(services);
        }
        try services.store(
            self.allocator,
            stream_id,
            origin_value,
            field_value,
            self.limits.max_alternative_services,
        );
        self.alternative_services = services;
    }

    pub fn peerOriginKnown(self: Connection, origin: []const u8) bool {
        const origins = self.peer_origins orelse return false;
        return origins.contains(origin);
    }

    pub fn storePeerOrigin(self: *Connection, origin: []const u8) Error!void {
        if (self.peer_origins) |origins| {
            return origins.store(
                self.allocator,
                origin,
                self.limits.max_peer_origins,
            );
        }
        if (self.limits.max_peer_origins == 0) return;

        const origins = try self.allocator.create(peer_metadata.Origins);
        origins.* = .{};
        errdefer {
            origins.deinit(self.allocator);
            self.allocator.destroy(origins);
        }
        try origins.store(
            self.allocator,
            origin,
            self.limits.max_peer_origins,
        );
        self.peer_origins = origins;
    }

    pub fn applyLocalLimits(self: *Connection) void {
        self.hpack_decoder.setMaxDynamicTableSize(self.allocator, self.limits.header_table_size);
        self.hpack_encoder.setMaxDynamicTableSize(
            self.allocator,
            @min(
                http2.Hpack.default_dynamic_table_size,
                self.limits.max_encoder_table_size,
            ),
        );
        self.recv_connection_window.value =
            self.limits.initial_connection_window_size;
        self.recv_connection_window_target =
            self.limits.initial_connection_window_size;
        self.recv_stream_window_target = self.limits.initial_window_size;
        self.data_frame_budget = .{};
        self.adaptive_window = if (self.limits.adaptive_window)
            bdp.Estimator.init(
                // Match Hyper's policy: samples grow the stream window. The
                // connection target may start larger and joins once the
                // estimate overtakes it.
                self.limits.initial_window_size,
                self.limits.adaptive_window_max,
            )
        else
            null;
    }

    fn outboundFramePayloadLimit(self: Connection) usize {
        // The peer's SETTINGS_MAX_FRAME_SIZE caps every frame payload we send.
        // `limits.max_frame_payload` remains a local/test ceiling used by this
        // minimal runtime to force small fragments, so use the stricter value.
        return @max(@as(usize, 1), @min(self.peer_max_frame_size, self.limits.max_frame_payload));
    }

    pub fn receiveConnectionWindowTarget(self: Connection) u32 {
        return if (self.adaptive_window != null)
            self.recv_connection_window_target
        else
            self.limits.initial_connection_window_size;
    }

    pub fn receiveStreamWindowTarget(self: Connection) u32 {
        return if (self.adaptive_window != null)
            self.recv_stream_window_target
        else
            self.limits.initial_window_size;
    }

    pub fn sendStreamWindow(self: *Connection, stream_id: u31) Error!*FlowWindow {
        if (stream_id == 0) return error.InvalidStreamId;
        const slot = try self.send_stream_window_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) {
            return &self.send_stream_windows.items[slot.value_ptr.*].window;
        }
        errdefer _ = self.send_stream_window_index.remove(stream_id);
        try self.send_stream_windows.ensureUnusedCapacity(self.allocator, 1);
        const index = self.send_stream_windows.items.len;
        self.send_stream_windows.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .window = .{ .value = self.peer_initial_stream_window },
        });
        slot.value_ptr.* = index;
        return &self.send_stream_windows.items[index].window;
    }

    fn sendStreamWindowAvailable(
        self: *const Connection,
        stream_id: u31,
    ) usize {
        if (self.send_stream_window_index.count() != 0) {
            if (self.send_stream_window_index.get(stream_id)) |index| {
                return self.send_stream_windows.items[index].window.available();
            }
        }
        if (self.peer_initial_stream_window <= 0) return 0;
        return @intCast(self.peer_initial_stream_window);
    }

    /// A reset closes both stream directions immediately. Unlike a normal
    /// half-close, no later DATA/WINDOW_UPDATE can legally need either window,
    /// so both indexed entries may be retired together.
    pub fn forgetStreamWindows(self: *Connection, stream_id: u31) void {
        self.forgetSendStreamWindow(stream_id);
        self.forgetRecvStreamWindow(stream_id);
    }

    fn forgetSendStreamWindow(self: *Connection, stream_id: u31) void {
        if (self.send_stream_window_index.count() == 0) return;
        const index = self.send_stream_window_index.get(stream_id) orelse
            return;
        const last_index = self.send_stream_windows.items.len - 1;
        const removed = self.send_stream_windows.swapRemove(index);
        _ = self.send_stream_window_index.remove(removed.stream_id);
        if (index != last_index) {
            const moved = self.send_stream_windows.items[index];
            self.send_stream_window_index.getPtr(moved.stream_id).?.* =
                index;
        }
    }

    pub fn recvStreamWindow(self: *Connection, stream_id: u31) Error!*FlowWindow {
        if (stream_id == 0) return error.InvalidStreamId;
        const slot = try self.recv_stream_window_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) {
            return &self.recv_stream_windows.items[slot.value_ptr.*].window;
        }
        errdefer _ = self.recv_stream_window_index.remove(stream_id);
        try self.recv_stream_windows.ensureUnusedCapacity(self.allocator, 1);
        const index = self.recv_stream_windows.items.len;
        self.recv_stream_windows.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .window = .{ .value = @intCast(
                self.receiveStreamWindowTarget(),
            ) },
        });
        slot.value_ptr.* = index;
        return &self.recv_stream_windows.items[index].window;
    }

    fn forgetRecvStreamWindow(self: *Connection, stream_id: u31) void {
        if (self.recv_stream_window_index.count() == 0) return;
        const index = self.recv_stream_window_index.get(stream_id) orelse
            return;
        const last_index = self.recv_stream_windows.items.len - 1;
        const removed = self.recv_stream_windows.swapRemove(index);
        _ = self.recv_stream_window_index.remove(removed.stream_id);
        if (index != last_index) {
            const moved = self.recv_stream_windows.items[index];
            self.recv_stream_window_index.getPtr(moved.stream_id).?.* =
                index;
        }
    }

    pub fn hasRecvStreamWindow(self: Connection, stream_id: u31) bool {
        return self.recv_stream_window_index.count() != 0 and
            self.recv_stream_window_index.contains(stream_id);
    }
};

fn RequestBatchHandlerTask(
    comptime HandlerContext: type,
    comptime handler: *const fn (
        *HandlerContext,
        OwnedRequest,
    ) Error!ResponseOptions,
) type {
    return struct {
        const Self = @This();

        pub const Completion = struct {
            index: usize,
            result: Error!ResponseOptions,
        };
        pub const CompletionQueue = std.Io.Queue(Completion);

        io: std.Io,
        completions: *CompletionQueue,
        context: *HandlerContext,
        request: *const OwnedRequest,
        index: usize,

        fn run(task: Self) std.Io.Cancelable!void {
            // The queue capacity is exactly the batch request count and each
            // task publishes one completion, so admission cannot block.
            task.completions.putOneUncancelable(task.io, .{
                .index = task.index,
                .result = handler(task.context, task.request.*),
            }) catch unreachable;
        }
    };
}

pub fn redirectLocation(
    headers: []const http2.Hpack.HeaderField,
) Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
        if (found != null or header.value.len == 0) {
            return error.InvalidRedirect;
        }
        found = header.value;
    }
    return found;
}

pub fn redirectH2Headers(
    allocator: std.mem.Allocator,
    source: []const http2.Hpack.HeaderField,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http2.Hpack.HeaderField,
) std.mem.Allocator.Error![]const http2.Hpack.HeaderField {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectH2Header(
            header.name,
            remove_credentials,
            remove_body,
        )) retained_count += 1;
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(
        http2.Hpack.HeaderField,
        retained_count,
    );
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectH2Header(
            header.name,
            remove_credentials,
            remove_body,
        )) continue;
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectH2Header(
    name: []const u8,
    remove_credentials: bool,
    remove_body: bool,
) bool {
    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (remove_credentials and uri_redirect.isCrossOriginCredential(name)) {
        return true;
    }
    if (remove_credentials and std.ascii.eqlIgnoreCase(name, "trailer")) {
        return true;
    }
    return remove_body and uri_redirect.isBodyHeader(name);
}

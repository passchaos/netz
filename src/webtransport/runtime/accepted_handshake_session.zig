//! WebTransport accepted handshake session over HTTP/3.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const operation_owner = @import("owner.zig");

const Error = runtime.Error;
const OwnedHandshakeConnectRequest = runtime.OwnedHandshakeConnectRequest;
const OwnedHandshakeDatagram = runtime.OwnedHandshakeDatagram;
const OwnedHandshakeDatagramBatch = runtime.OwnedHandshakeDatagramBatch;
const OwnedHandshakeStream = runtime.OwnedHandshakeStream;
const PendingSessionClose = runtime.PendingSessionClose;
const PendingSessionDrain = runtime.PendingSessionDrain;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const SessionEvent = runtime.SessionEvent;
const StableConnectionId = runtime.StableConnectionId;
const StreamRead = runtime.StreamRead;
const StreamWrite = runtime.StreamWrite;
const StreamWriteResult = runtime.StreamWriteResult;
const application = runtime.application;
const application_protocol = runtime.application_protocol;
const capsule_rejection = runtime.capsule_rejection;
const clearPendingSessionClose = runtime.clearPendingSessionClose;
const connect_negotiation = runtime.connect_negotiation;
const connection_lifecycle = runtime.connection_lifecycle;
const deadline_policy = runtime.deadline_policy;
const flow_cancel = runtime.flow_cancel;
const flow_datagram = runtime.flow_datagram;
const flow_grant = runtime.flow_grant;
const flow_open = runtime.flow_open;
const flow_read = runtime.flow_read;
const flow_streams = runtime.flow_streams;
const flow_write = runtime.flow_write;
const handshake_stream = runtime.handshake_stream;
const incremental_stream = runtime.incremental_stream;
const max_connection_close_reason = runtime.max_connection_close_reason;
const ownedHandshakeDatagram = runtime.ownedHandshakeDatagram;
const receiveHandshakePeerConnectionClose = runtime.receiveHandshakePeerConnectionClose;
const receiveHandshakePeerConnectionCloseUntil = runtime.receiveHandshakePeerConnectionCloseUntil;
const receiveManyHandshakeDatagrams = runtime.receiveManyHandshakeDatagrams;
const receiveManyHandshakeDatagramsUntil = runtime.receiveManyHandshakeDatagramsUntil;
const rejectAdditionalHandshakeRequestsOnce = runtime.rejectAdditionalHandshakeRequestsOnce;
const session_control = runtime.session_control;
const terminalSessionBodySendError = runtime.terminalSessionBodySendError;

pub const AcceptedHandshakeSession = struct {
    h3: http3.runtime.HandshakeServerSession,
    request: OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
    selected_application_protocol: ?application_protocol.String = null,
    streams: webtransport.StreamRegistry,
    control: session_control.Control,
    request_rejection_pending: ?u62 = null,
    pending_drain: ?PendingSessionDrain = null,
    pending_close: ?PendingSessionClose = null,
    pending_session_event: ?SessionEvent = null,

    pub fn ensureApplicationSendOpen(
        self: *AcceptedHandshakeSession,
    ) Error!void {
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try application.ensureOpen(&self.control, &self.h3, &self.streams);
    }

    pub fn applicationProtocol(self: AcceptedHandshakeSession) ?application_protocol.String {
        return self.selected_application_protocol;
    }

    pub fn deinit(self: *AcceptedHandshakeSession) void {
        const allocator = self.h3.established.connection.endpoint.allocator;
        clearPendingSessionClose(&self.pending_close);
        self.control.deinit();
        self.h3.closeConnectDatagramAssociation(
            self.session_id.value,
        ) catch {};
        self.request.deinit(allocator);
        self.streams.deinit();
        self.h3.deinit();
        self.* = undefined;
    }

    pub fn sessionId(
        self: AcceptedHandshakeSession,
    ) webtransport.SessionId {
        return self.session_id;
    }

    pub fn stableId(self: *const AcceptedHandshakeSession) StableConnectionId {
        return self.h3.established.connection.stableId();
    }

    /// Return the currently selected QUIC peer path. This can change after an
    /// authenticated NAT rebinding or active migration.
    pub fn remoteAddress(self: AcceptedHandshakeSession) net.IpAddress {
        return self.h3.established.connection.peerAddress();
    }

    pub fn remoteAddressValidated(self: AcceptedHandshakeSession) bool {
        return self.h3.established.connection.peerAddressValidated();
    }

    pub fn rttNanos(self: AcceptedHandshakeSession) ?u64 {
        return self.stats().smoothed_rtt_ns;
    }

    /// Close the entire HTTP/3 connection with an application error. This is
    /// intentionally distinct from `close`, which sends WT_CLOSE_SESSION on
    /// the Extended CONNECT stream and leaves connection scope to HTTP/3.
    pub fn closeConnection(
        self: *AcceptedHandshakeSession,
        error_code: u62,
        reason: []const u8,
    ) Error!void {
        if (reason.len > max_connection_close_reason) {
            return error.InvalidSessionState;
        }
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try self.h3.established.connection.closeApplication(
            error_code,
            reason,
        );
    }

    pub fn exportKeyingMaterial(
        self: *const AcceptedHandshakeSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.h3.established.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    /// Return the authenticated peer certificate chain retained by the QUIC
    /// handshake, or null for PSK/preconfigured sessions without peer identity.
    pub fn peerCertificates(
        self: *const AcceptedHandshakeSession,
    ) ?[]const []const u8 {
        return self.h3.established.peerCertificates();
    }

    pub fn negotiatedAlpn(self: AcceptedHandshakeSession) []const u8 {
        return self.h3.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: AcceptedHandshakeSession,
    ) quic.tls.cipher_suite.Suite {
        return self.h3.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: AcceptedHandshakeSession,
    ) quic.tls.secret.Hash {
        return self.h3.negotiatedTranscriptHash();
    }

    /// QUIC mandates TLS 1.3; the optional shape matches the other transports.
    pub fn negotiatedTlsProtocol(
        self: AcceptedHandshakeSession,
    ) ?tls_stream.Protocol {
        _ = self;
        return .tls13;
    }

    pub fn wasTlsSessionResumed(self: AcceptedHandshakeSession) ?bool {
        return self.h3.established.resumed;
    }

    /// Whether this connection accepted, rejected or never received 0-RTT.
    pub fn earlyDataStatus(
        self: AcceptedHandshakeSession,
    ) @TypeOf(self.h3.established.early_data_status) {
        return self.h3.established.early_data_status;
    }

    pub fn initiateKeyUpdate(self: *AcceptedHandshakeSession) Error!void {
        try self.h3.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: AcceptedHandshakeSession) u64 {
        return self.h3.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: AcceptedHandshakeSession) u64 {
        return self.h3.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: AcceptedHandshakeSession) bool {
        return self.h3.keyUpdateAwaitingAck();
    }

    pub fn receiveDatagram(self: *AcceptedHandshakeSession) Error!OwnedHandshakeDatagram {
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return ownedHandshakeDatagram(
            try flow_datagram.receive(&self.control, &self.h3, &self.streams, self.session_id.value),
            self.session_id,
        );
    }

    pub fn receiveDatagramWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return ownedHandshakeDatagram(
            try flow_datagram.receiveWithDeadline(
                &self.control,
                &self.h3,
                &self.streams,
                self.session_id.value,
                deadline,
            ),
            self.session_id,
        );
    }

    /// Receive one application DATAGRAM directly into caller storage. The
    /// returned slice aliases `output`; no HTTP/3 association payload is
    /// allocated on the fresh-packet path.
    pub fn receiveDatagramInto(
        self: *AcceptedHandshakeSession,
        output: []u8,
    ) Error![]u8 {
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveInto(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            output,
        );
    }

    pub fn receiveDatagramIntoWithTimeout(
        self: *AcceptedHandshakeSession,
        output: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError![]u8 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramIntoWithDeadline(output, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramIntoWithDeadline(
        self: *AcceptedHandshakeSession,
        output: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError![]u8 {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveIntoWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            output,
            deadline,
        );
    }

    /// Fill an arrival-ordered caller-owned DATAGRAM batch. On failure,
    /// `received_count` identifies the exact completed output prefix.
    pub fn receiveDatagramsInto(
        self: *AcceptedHandshakeSession,
        outputs: [][]u8,
        received_count: *usize,
    ) Error!void {
        received_count.* = 0;
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveManyInto(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            outputs,
            received_count,
        );
    }

    pub fn receiveDatagramsIntoWithTimeout(
        self: *AcceptedHandshakeSession,
        outputs: [][]u8,
        received_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        received_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveDatagramsIntoWithDeadline(outputs, received_count, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveDatagramsIntoWithDeadline(
        self: *AcceptedHandshakeSession,
        outputs: [][]u8,
        received_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        received_count.* = 0;
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.receiveManyIntoWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            outputs,
            received_count,
            deadline,
        );
    }

    pub fn receiveManyDatagrams(self: *AcceptedHandshakeSession, count: usize) Error!OwnedHandshakeDatagramBatch {
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return receiveManyHandshakeDatagrams(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            count,
        );
    }

    /// Receive up to `count` DATAGRAMs within one shared timeout budget. If
    /// the deadline expires after partial progress, the returned batch retains
    /// those DATAGRAMs and records `error.Timeout` in the next error slot.
    pub fn receiveManyDatagramsWithTimeout(
        self: *AcceptedHandshakeSession,
        count: usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveManyDatagramsWithDeadline(count, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveManyDatagramsWithDeadline(
        self: *AcceptedHandshakeSession,
        count: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return receiveManyHandshakeDatagramsUntil(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            count,
            deadline,
        );
    }

    pub fn sendDatagram(self: *AcceptedHandshakeSession, payload: []const u8) Error!void {
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        try flow_datagram.sendDatagram(&self.control, &self.h3, &self.streams, self.session_id.value, payload);
    }

    /// Wait for QUIC congestion and pacing capacity while retaining one total
    /// timeout across all HTTP/3 progress needed to free it.
    pub fn sendDatagramWithTimeout(
        self: *AcceptedHandshakeSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(payload, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramWithDeadline(
        self: *AcceptedHandshakeSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        try flow_datagram.sendWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            payload,
            deadline,
        );
    }

    pub fn sendDatagrams(
        self: *AcceptedHandshakeSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        committed_count.* = 0;
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.sendDatagrams(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            payloads,
            committed_count,
        );
    }

    pub fn sendDatagramsWithTimeout(
        self: *AcceptedHandshakeSession,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramsWithDeadline(payloads, committed_count, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn sendDatagramsWithDeadline(
        self: *AcceptedHandshakeSession,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed_count.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try flow_datagram.prepareSend(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_datagram.sendManyWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
            payloads,
            committed_count,
            deadline,
        );
    }

    /// Send Capsule Protocol bytes on this Session's Extended CONNECT stream.
    pub fn sendSessionData(
        self: *AcceptedHandshakeSession,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return self.h3.sendResponseBodyPaced(
            self.session_id.value,
            data,
            fin,
        );
    }

    pub fn sendSessionDataWithTimeout(
        self: *AcceptedHandshakeSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.sendSessionDataSlicesWithTimeout(
            &.{data},
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *AcceptedHandshakeSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.sendSessionDataSlicesWithDeadline(
            &.{data},
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendSessionDataSlices(
        self: *AcceptedHandshakeSession,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return self.h3.sendResponseBodyPartsPaced(
            self.session_id.value,
            parts,
            fin,
        );
    }

    /// Send borrowed Capsule Protocol slices on this Extended CONNECT stream
    /// under one timeout. Progress spans the logical concatenation of all
    /// slices and therefore identifies the exact suffix to retry.
    pub fn sendSessionDataSlicesWithTimeout(
        self: *AcceptedHandshakeSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        if (timeout.nanoseconds <= 0) return error.Timeout;
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return self.h3.sendResponseBodyPartsPacedWithTimeout(
            self.session_id.value,
            parts,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataSlicesWithDeadline(
        self: *AcceptedHandshakeSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return self.h3.sendResponseBodyPartsPacedWithDeadline(
            self.session_id.value,
            parts,
            fin,
            progress,
            deadline,
        );
    }

    pub fn maxDatagramPayloadSize(self: AcceptedHandshakeSession) ?usize {
        if (!self.datagramsNegotiated()) return null;
        return self.h3.maxConnectDatagramPayloadSize(self.session_id.value);
    }

    /// WebTransport API spelling for the maximum application payload accepted
    /// by `sendDatagram`, after QUIC DATAGRAM and Session ID overhead.
    pub fn maxDatagramSize(self: AcceptedHandshakeSession) usize {
        return self.maxDatagramPayloadSize() orelse 0;
    }

    pub fn datagramsNegotiated(self: AcceptedHandshakeSession) bool {
        connect_negotiation.ensure(&self.h3) catch return false;
        return self.h3.connectDatagramsNegotiated();
    }

    pub fn stats(self: AcceptedHandshakeSession) quic.one_rtt.ConnectionStats {
        return self.h3.established.connection.stats();
    }

    pub fn getStats(self: AcceptedHandshakeSession) quic.one_rtt.ConnectionStats {
        return self.stats();
    }

    /// Wait for an authenticated QUIC CONNECTION_CLOSE from the peer.
    ///
    /// This is intentionally distinct from `receiveSessionEvent`, which reads
    /// WebTransport CLOSE capsules and clean FIN from the Extended CONNECT
    /// stream. Some peers terminate the entire HTTP/3 connection directly.
    pub fn receivePeerConnectionClose(
        self: *AcceptedHandshakeSession,
    ) Error!quic.one_rtt.PeerCloseInfo {
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return receiveHandshakePeerConnectionClose(
            &self.h3.established.connection,
        );
    }

    /// Return authenticated peer CONNECTION_CLOSE metadata already observed
    /// by this session or by its endpoint dispatcher, without reading UDP.
    pub fn pollPeerConnectionClose(
        self: *const AcceptedHandshakeSession,
    ) ?quic.one_rtt.PeerCloseInfo {
        return self.h3.established.connection.peerCloseInfo();
    }

    pub fn receivePeerConnectionCloseWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return receiveHandshakePeerConnectionCloseUntil(
            &self.h3.established.connection,
            deadline,
        );
    }

    pub fn receivePeerConnectionCloseWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receivePeerConnectionCloseWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openBidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        return self.openLocalStream(.bidirectional, null);
    }

    pub fn openBidirectionalStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openBidirectionalStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openBidirectionalStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.openLocalStream(.bidirectional, deadline);
    }

    pub fn openUnidirectionalStream(
        self: *AcceptedHandshakeSession,
    ) Error!u62 {
        return self.openLocalStream(.unidirectional, null);
    }

    pub fn openUnidirectionalStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openUnidirectionalStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn openUnidirectionalStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.openLocalStream(.unidirectional, deadline);
    }

    pub fn openLocalStream(
        self: *AcceptedHandshakeSession,
        direction: webtransport.StreamDirection,
        deadline: ?std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        if (deadline) |absolute| {
            _ = try deadline_policy.usableAwake(
                self.h3.established.connection.endpoint.io,
                absolute,
            );
        }
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        return flow_open.open(&self.control, &self.h3, &self.streams, direction, deadline, false);
    }

    pub fn sendStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try flow_write.send(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
        );
    }

    pub fn sendStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(
            stream_id,
            payload,
            fin,
            committed,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.sendWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            fin,
            committed,
            deadline,
        );
    }

    pub fn sendStreamSlices(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.sendSlices(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            fin,
        );
    }

    pub fn sendStreamSlicesWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(
            stream_id,
            parts,
            fin,
            committed,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn sendStreamSlicesWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        committed.* = 0;
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.sendSlicesWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            fin,
            committed,
            deadline,
        );
    }

    pub fn writeStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.write(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
        );
    }

    pub fn writeStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeStreamWithDeadline(
            stream_id,
            payload,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.writeWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            payload,
            deadline,
        );
    }

    pub fn writeStreamSlices(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        parts: []const []const u8,
    ) Error!usize {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.writeSlices(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
        );
    }

    pub fn writeStreamSlicesWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        parts: []const []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeStreamSlicesWithDeadline(
            stream_id,
            parts,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeStreamSlicesWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        parts: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.writeSlicesWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            parts,
            deadline,
        );
    }

    pub fn setStreamPriority(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try self.streams.setPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
    ) Error!i32 {
        return self.streams.priority(stream_id);
    }

    /// Submit one packet-sized slice per sendable stream in a QUIC packet
    /// batch. Counts commit only the socket-visible prefix.
    pub fn writeStreams(
        self: *AcceptedHandshakeSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) Error!StreamWriteResult {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.writeStreams(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            writes,
            counts,
        );
    }

    pub fn writeStreamsWithTimeout(
        self: *AcceptedHandshakeSession,
        writes: []const StreamWrite,
        counts: []usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamWriteResult {
        if (counts.len < writes.len) return error.BufferTooShort;
        @memset(counts[0..writes.len], 0);
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.writeStreamsWithDeadline(
            writes,
            counts,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn writeStreamsWithDeadline(
        self: *AcceptedHandshakeSession,
        writes: []const StreamWrite,
        counts: []usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamWriteResult {
        if (counts.len < writes.len) return error.BufferTooShort;
        @memset(counts[0..writes.len], 0);
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.writeStreamsWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            writes,
            counts,
            deadline,
        );
    }

    pub fn finishStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
    ) Error!void {
        // Completion means the FIN packet was accepted by the socket. QUIC
        // recovery remains responsible for retransmission until peer ACK.
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.finish(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
        );
    }

    pub fn finishStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishStreamWithDeadline(
            stream_id,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn finishStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_write.finishWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            deadline,
        );
    }

    /// Return cumulative QUIC stream-count credit after a peer-initiated
    /// associated stream has reached a terminal state. Registry accounting is
    /// intentionally retained, so this never replenishes the WT session cap.
    pub fn releaseCompletedPeerStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
    ) Error!bool {
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        if (!try flow_streams.shouldReleasePeer(&self.h3.established.connection, &self.streams, stream_id)) return false;
        return self.h3.established.connection.releaseCompletedPeerStream(
            stream_id,
        );
    }

    pub fn receiveStream(
        self: *AcceptedHandshakeSession,
    ) Error!OwnedHandshakeStream {
        try operation_owner.receive(self);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_read.receive(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
    }

    pub fn receiveStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveStreamWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_read.receiveWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
            deadline,
        );
    }

    /// Poll a FIN-complete associated stream without reading UDP.
    pub fn pollCompleteStream(
        self: *AcceptedHandshakeSession,
    ) Error!?OwnedHandshakeStream {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return handshake_stream.poll(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            self.h3.options.max_stream_buffer,
        );
    }

    /// Read the next stream data/control event without waiting for FIN.
    pub fn readStream(
        self: *AcceptedHandshakeSession,
        out: []u8,
    ) Error!StreamRead {
        try operation_owner.receive(self);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_read.read(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            out,
        );
    }

    pub fn readStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readStreamWithDeadline(out, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_read.readWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            out,
            deadline,
        );
    }

    /// Read only `stream_id`, leaving ready sibling streams untouched.
    pub fn readStreamId(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        out: []u8,
    ) Error!StreamRead {
        try operation_owner.receive(self);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_read.readId(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            out,
        );
    }

    pub fn readStreamIdWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.readStreamIdWithDeadline(stream_id, out, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn readStreamIdWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_read.readIdWithDeadline(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id,
            stream_id,
            out,
            deadline,
        );
    }

    /// Flush a delayed transport ACK before a one-shot session is torn down.
    pub fn flushPendingAck(self: *AcceptedHandshakeSession) Error!bool {
        return self.h3.established.connection.flushPendingAck();
    }

    /// Drive QUIC ACK/loss/PTO processing until every reliable application or
    /// control frame submitted by this session has been acknowledged. Use
    /// this before destroying a short-lived session after its final CLOSE/FIN.
    pub fn waitForRecoveryIdleWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (self.h3.dispatcherBound()) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForRecoveryIdleWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.h3.waitForRecoveryIdleWithDeadline(deadline);
        _ = try self.h3.established.connection
            .flushPendingAckWithDeadline(deadline);
    }

    pub fn waitForStreamRecoveryIdleWithTimeout(self: *AcceptedHandshakeSession, stream_id: u62, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        if (self.h3.dispatcherBound()) return error.InvalidDispatcherState;
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.waitForStreamRecoveryIdleWithDeadline(stream_id, .fromNow(self.h3.established.connection.endpoint.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn waitForStreamRecoveryIdleWithDeadline(self: *AcceptedHandshakeSession, stream_id: u62, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        if (self.h3.dispatcherBound()) return error.InvalidDispatcherState;
        return @import("stream/recovery.zig").wait(ReceiveTimeoutError, &self.control, &self.h3, &self.streams, stream_id, deadline);
    }

    /// Apply one packet selected by the endpoint-wide QUIC dispatcher. HTTP/3
    /// control/QPACK and unrelated requests progress while the detached
    /// WebTransport CONNECT stream and associated streams remain available to
    /// the session-specific pollers below.
    pub fn processPacket(
        self: *AcceptedHandshakeSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try self.h3.processDetachedRequestPacket(
            self.session_id.value,
            packet,
        );
        _ = try rejectAdditionalHandshakeRequestsOnce(
            &self.h3,
            &self.streams,
            self.session_id,
            &self.request_rejection_pending,
        );
    }

    /// Poll already-buffered associated stream state without reading UDP.
    pub fn pollStream(
        self: *AcceptedHandshakeSession,
        out: []u8,
    ) Error!?StreamRead {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        if (out.len == 0) return error.BufferTooShort;
        return incremental_stream.poll(
            &self.h3.established.connection,
            &self.streams,
            self.session_id,
            out,
        );
    }

    /// Poll a queued DATAGRAM for this session without reading UDP.
    pub fn pollDatagram(
        self: *AcceptedHandshakeSession,
    ) Error!?OwnedHandshakeDatagram {
        try connection_lifecycle.ensureDatagramReceiveOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        try connect_negotiation.ensure(&self.h3);
        const datagram = try flow_datagram.poll(
            &self.control,
            &self.h3,
            &self.streams,
            self.session_id.value,
        );
        return if (datagram) |owned|
            ownedHandshakeDatagram(owned, self.session_id)
        else
            null;
    }

    /// Poll the detached CONNECT stream for DRAIN/CLOSE/reset state.
    pub fn pollSessionEvent(
        self: *AcceptedHandshakeSession,
    ) Error!?SessionEvent {
        try operation_owner.buffered(&self.h3);
        self.control.bindFlow(self.streams.flow);
        connection_lifecycle.observeGoAway(&self.control, &self.h3);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        if (capsule_rejection.pending(&self.control)) {
            try capsule_rejection.finish(&self.control, &self.h3.established.connection, &self.streams);
            return capsule_rejection.errorFor(&self.control);
        }
        if (self.pending_session_event == null) {
            self.pending_session_event = self.control.poll(
                &self.h3.established.connection,
            ) catch |err| switch (err) {
                error.InvalidCapsule, error.FlowControlViolation => {
                    try capsule_rejection.finish(
                        &self.control,
                        &self.h3.established.connection,
                        &self.streams,
                    );
                    return err;
                },
                else => {
                    try http3.runtime.closeConnectionForProtocolError(
                        &self.h3.established.connection,
                        err,
                    );
                    return err;
                },
            };
        }
        const event = self.pending_session_event orelse return null;
        try self.finishPolledSessionEvent(event);
        self.pending_session_event = null;
        return event;
    }

    pub fn resetStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_cancel.cancel(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .reset);
    }

    pub fn resetStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn resetStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_cancel.cancelUntil(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .reset, deadline);
    }

    /// Reset after reliably delivering `reliable_size` WebTransport
    /// application bytes; the stream association prefix is accounted for
    /// internally.
    pub fn resetStreamReliably(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_cancel.cancel(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .{ .reliable = reliable_size });
    }

    pub fn resetStreamReliablyWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamReliablyWithDeadline(
            stream_id,
            application_error_code,
            reliable_size,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn resetStreamReliablyWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_cancel.cancelUntil(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .{ .reliable = reliable_size }, deadline);
    }

    pub fn stopStream(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_cancel.cancel(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .stop);
    }

    pub fn stopStreamWithTimeout(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopStreamWithDeadline(
            stream_id,
            application_error_code,
            .fromNow(self.h3.established.connection.endpoint.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    pub fn stopStreamWithDeadline(
        self: *AcceptedHandshakeSession,
        stream_id: u62,
        application_error_code: u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try self.ensureApplicationSendOpen();
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_cancel.cancelUntil(&self.control, &self.h3, &self.streams, stream_id, application_error_code, .stop, deadline);
    }

    pub fn drain(self: *AcceptedHandshakeSession) Error!void {
        try operation_owner.buffered(&self.h3);
        if (self.control.local_drain_sent) return;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        try self.h3.sendResponseBodyPaced(
            self.session_id.value,
            pending.bytes[pending.committed..pending.len],
            false,
        );
        self.pending_drain = null;
        try self.control.recordLocalDrain();
    }

    pub fn drainWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn drainWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try operation_owner.receive(self);
        if (self.control.local_drain_sent) return;
        if (self.pending_drain == null) {
            const pending = try PendingSessionDrain.init();
            try self.control.beginLocalDrain();
            self.pending_drain = pending;
        }
        const pending = &self.pending_drain.?;
        var progress: http3.runtime.BodyWriteProgress = .{};
        self.h3.sendResponseBodyPacedWithDeadline(
            self.session_id.value,
            pending.bytes[pending.committed..pending.len],
            false,
            &progress,
            deadline,
        ) catch |err| {
            pending.committed += progress.committed_bytes;
            if (pending.committed == pending.len) {
                self.pending_drain = null;
                try self.control.recordLocalDrain();
            }
            return err;
        };
        pending.committed += progress.committed_bytes;
        std.debug.assert(pending.committed == pending.len);
        self.pending_drain = null;
        try self.control.recordLocalDrain();
    }

    pub fn close(
        self: *AcceptedHandshakeSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        try operation_owner.buffered(&self.h3);
        if (self.control.local_close_sent or
            self.control.local_close_failed)
        {
            return session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
        }
        if (self.pending_drain != null) return error.InvalidSessionState;
        if (self.pending_close != null) return error.InvalidSessionState;
        var encoded: [4 + session_control.max_close_reason + 16]u8 =
            undefined;
        const capsule = try session_control.writeCloseInto(
            &encoded,
            code,
            reason,
        );
        self.h3.sendResponseBodyPaced(
            self.session_id.value,
            capsule,
            true,
        ) catch |err| {
            if (terminalSessionBodySendError(err)) {
                self.control.recordLocalCloseFailure(code);
            }
            return err;
        };
        // Preserve receive-side routing after the local half-close. The
        // terminal event handler retires the association once peer FIN/reset
        // has been consumed.
        try self.control.recordLocalClose(code);
        try session_control.terminateStreams(
            &self.h3.established.connection,
            &self.streams,
        );
    }

    pub fn closeWithTimeout(
        self: *AcceptedHandshakeSession,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(code, reason, .fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    /// Send the CLOSE_WEBTRANSPORT_SESSION capsule, CONNECT FIN, and all
    /// associated SESSION_GONE terminal frames under one absolute deadline.
    /// A timed-out capsule send retains its exact socket-visible offset.
    pub fn closeWithDeadline(
        self: *AcceptedHandshakeSession,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try operation_owner.receive(self);
        if (self.control.local_close_failed) {
            return session_control.terminateStreamsWithDeadline(
                &self.h3.established.connection,
                &self.streams,
                deadline,
            );
        }
        if (!self.control.local_close_sent) {
            try self.preparePendingClose(code, reason);
            const pending = &self.pending_close.?;
            var progress: http3.runtime.BodyWriteProgress = .{};
            self.h3.sendResponseBodyPacedWithDeadline(
                self.session_id.value,
                pending.remaining(),
                true,
                &progress,
                deadline,
            ) catch |err| {
                pending.committed += progress.committed_bytes;
                if (progress.fin_committed) {
                    const committed_code = pending.code;
                    clearPendingSessionClose(&self.pending_close);
                    try self.control.recordLocalClose(committed_code);
                } else if (terminalSessionBodySendError(err)) {
                    const failed_code = pending.code;
                    clearPendingSessionClose(&self.pending_close);
                    self.control.recordLocalCloseFailure(failed_code);
                }
                return err;
            };
            pending.committed += progress.committed_bytes;
            std.debug.assert(
                pending.committed == pending.len and progress.fin_committed,
            );
            const committed_code = pending.code;
            clearPendingSessionClose(&self.pending_close);
            try self.control.recordLocalClose(committed_code);
        }
        try session_control.terminateStreamsWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            deadline,
        );
    }

    pub fn preparePendingClose(
        self: *AcceptedHandshakeSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        try operation_owner.buffered(&self.h3);
        if (self.pending_drain != null) return error.InvalidSessionState;
        if (self.pending_close) |*pending| {
            if (!try pending.matches(code, reason)) {
                return error.InvalidSessionState;
            }
            return;
        }
        var pending = try PendingSessionClose.init(
            self.h3.established.connection.endpoint.allocator,
            code,
            reason,
        );
        errdefer pending.deinit();
        try self.control.beginLocalClose();
        self.pending_close = pending;
    }

    pub fn receiveSessionEvent(
        self: *AcceptedHandshakeSession,
    ) Error!SessionEvent {
        try operation_owner.receive(self);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        const event = while (true) {
            if (try self.pollSessionEvent()) |ready| break ready;
            try self.receiveControlProgress();
        };
        return event;
    }

    pub fn receiveSessionEventWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        const deadline = std.Io.Clock.Timestamp.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        );
        return self.receiveSessionEventWithDeadline(deadline);
    }

    pub fn receiveSessionEventWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        _ = try deadline_policy.usableAwake(self.h3.established.connection.endpoint.io, deadline);
        try operation_owner.receive(self);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return while (true) {
            if (try self.pollSessionEventWithCleanupDeadline(deadline)) |ready| {
                break ready;
            }
            try self.receiveControlProgressWithDeadline(deadline);
        };
    }

    pub fn pollSessionEventWithCleanupDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!?SessionEvent {
        _ = try deadline_policy.usableAwake(
            self.h3.established.connection.endpoint.io,
            deadline,
        );
        try operation_owner.receive(self);
        self.control.bindFlow(self.streams.flow);
        connection_lifecycle.observeGoAway(&self.control, &self.h3);
        if (capsule_rejection.pending(&self.control)) {
            try capsule_rejection.finishWithDeadline(&self.control, &self.h3.established.connection, &self.streams, deadline);
            return capsule_rejection.errorFor(&self.control);
        }
        if (self.pending_session_event == null) {
            self.pending_session_event = self.control.pollWithDeadline(
                &self.h3.established.connection,
                deadline,
            ) catch |err| switch (err) {
                error.InvalidCapsule, error.FlowControlViolation => {
                    try capsule_rejection.finishWithDeadline(
                        &self.control,
                        &self.h3.established.connection,
                        &self.streams,
                        deadline,
                    );
                    return err;
                },
                else => {
                    try http3.runtime.closeConnectionForProtocolError(
                        &self.h3.established.connection,
                        err,
                    );
                    return err;
                },
            };
        }
        const event = self.pending_session_event orelse return null;
        try self.finishPolledSessionEventWithDeadline(event, deadline);
        self.pending_session_event = null;
        return event;
    }

    pub fn finishPolledSessionEvent(
        self: *AcceptedHandshakeSession,
        event: SessionEvent,
    ) Error!void {
        if (connection_lifecycle.observe(&self.control, &self.h3, &self.streams)) return;
        if (event == .closed or event == .reset) {
            _ = try self.control.rejectPostTerminalData(
                &self.h3.established.connection,
            );
            if (event == .closed and
                !self.control.local_close_sent and
                !self.control.local_close_failed)
            {
                // A caller may still own a partially sent local CLOSE. Do not
                // truncate it with an empty FIN; closeWithDeadline can resume
                // that exact suffix after this peer event is delivered.
                if (self.pending_close == null) {
                    self.h3.sendResponseBodyPaced(
                        self.session_id.value,
                        &.{},
                        true,
                    ) catch |err| {
                        const stream_stats = self.h3.established.connection
                            .sendStreamStats(self.session_id.value);
                        if (stream_stats != null and
                            stream_stats.?.final_size != null)
                        {
                            self.control.local_close_sent = true;
                        }
                        return err;
                    };
                    self.control.local_close_sent = true;
                }
            }
            // Retain the terminal association until session teardown so late
            // datagrams are discarded by terminal state instead of becoming
            // unknown-association traffic.
            try session_control.terminateStreams(
                &self.h3.established.connection,
                &self.streams,
            );
            // The terminal STREAM/FIN or RESET is ACK-eliciting. This is the
            // last application event many short-lived peers consume, so do
            // not leave its acknowledgement behind the delayed-ACK timer.
            _ = self.h3.established.connection.tryFlushPendingAck() catch {};
        }
    }

    pub fn finishPolledSessionEventWithTimeout(
        self: *AcceptedHandshakeSession,
        event: SessionEvent,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.finishPolledSessionEventWithDeadline(
            event,
            .fromNow(
                self.h3.established.connection.endpoint.io,
                .{ .raw = timeout, .clock = .awake },
            ),
        );
    }

    pub fn finishPolledSessionEventWithDeadline(
        self: *AcceptedHandshakeSession,
        event: SessionEvent,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        if (connection_lifecycle.observe(&self.control, &self.h3, &self.streams)) return;
        if (event != .closed and event != .reset) return;
        _ = try self.control.rejectPostTerminalDataWithDeadline(
            &self.h3.established.connection,
            deadline,
        );
        if (event == .closed and !self.control.local_close_sent and
            !self.control.local_close_failed and
            self.pending_close == null)
        {
            var progress: http3.runtime.BodyWriteProgress = .{};
            self.h3.sendResponseBodyPacedWithDeadline(
                self.session_id.value,
                &.{},
                true,
                &progress,
                deadline,
            ) catch |err| {
                if (progress.fin_committed) {
                    self.control.local_close_sent = true;
                }
                return err;
            };
            std.debug.assert(progress.fin_committed);
            self.control.local_close_sent = true;
        }
        try session_control.terminateStreamsWithDeadline(
            &self.h3.established.connection,
            &self.streams,
            deadline,
        );
        _ = self.h3.established.connection.tryFlushPendingAck() catch {};
    }

    pub fn receiveControlProgress(
        self: *AcceptedHandshakeSession,
    ) Error!void {
        try self.h3.receiveDetachedRequestProgress(
            self.session_id.value,
        );
        _ = try rejectAdditionalHandshakeRequestsOnce(
            &self.h3,
            &self.streams,
            self.session_id,
            &self.request_rejection_pending,
        );
    }

    pub fn receiveControlProgressWithTimeout(
        self: *AcceptedHandshakeSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveControlProgressWithDeadline(.fromNow(
            self.h3.established.connection.endpoint.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn receiveControlProgressWithDeadline(
        self: *AcceptedHandshakeSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        try self.h3.receiveDetachedRequestProgressWithDeadline(
            self.session_id.value,
            deadline,
        );
        _ = try rejectAdditionalHandshakeRequestsOnce(
            &self.h3,
            &self.streams,
            self.session_id,
            &self.request_rejection_pending,
        );
    }
    /// Submit one WT_MAX_DATA grant. Backpressure leaves the advertised limit
    /// unchanged so an endpoint loop can retry this same operation.
    pub fn grantData(self: *AcceptedHandshakeSession, maximum: u64) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        return flow_grant.send(&self.control, &self.h3, &self.streams, .{ .max_data = maximum });
    }

    pub fn grantStreams(self: *AcceptedHandshakeSession, direction: webtransport.StreamDirection, maximum: u64) Error!void {
        try connection_lifecycle.ensureOpen(&self.control, &self.h3, &self.streams);
        defer _ = connection_lifecycle.observe(&self.control, &self.h3, &self.streams);
        const capsule: webtransport.Capsule = switch (direction) {
            .bidirectional => .{ .max_streams_bidi = maximum },
            .unidirectional => .{ .max_streams_uni = maximum },
        };
        return flow_grant.send(&self.control, &self.h3, &self.streams, capsule);
    }
};

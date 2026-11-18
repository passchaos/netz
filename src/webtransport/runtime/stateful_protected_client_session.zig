//! WebTransport stateful protected client session.

const std = @import("std");
const webtransport = @import("../mod.zig");
const http3 = @import("../../http3/mod.zig");
const quic = @import("../../quic/mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");

const Error = runtime.Error;
const HandshakeClientSession = runtime.HandshakeClientSession;
const OwnedHandshakeDatagram = runtime.OwnedHandshakeDatagram;
const OwnedHandshakeDatagramBatch = runtime.OwnedHandshakeDatagramBatch;
const OwnedHandshakeStream = runtime.OwnedHandshakeStream;
const ReceiveTimeoutError = runtime.ReceiveTimeoutError;
const SessionEvent = runtime.SessionEvent;
const StableConnectionId = runtime.StableConnectionId;
const StatefulProtectedConnectAttempt = runtime.StatefulProtectedConnectAttempt;
const StatefulProtectedConnectOptions = runtime.StatefulProtectedConnectOptions;
const StreamRead = runtime.StreamRead;
const StreamWrite = runtime.StreamWrite;
const StreamWriteResult = runtime.StreamWriteResult;
const application_protocol = runtime.application_protocol;
const deadline_policy = runtime.deadline_policy;
const validateAdditionalConnectHeaders = runtime.validateAdditionalConnectHeaders;

pub const StatefulProtectedClientSession = struct {
    session: HandshakeClientSession,

    pub fn applicationProtocol(self: StatefulProtectedClientSession) ?application_protocol.String {
        return self.session.applicationProtocol();
    }

    pub fn connect(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!StatefulProtectedClientSession {
        var attempt = try connectAttempt(
            allocator,
            io,
            local_address,
            server,
            options,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!StatefulProtectedClientSession {
        var attempt = try connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        );
        errdefer attempt.deinit();
        return attempt.requireAccepted();
    }

    pub fn connectWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!StatefulProtectedClientSession {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
    ) Error!StatefulProtectedConnectAttempt {
        return .{
            .attempt = try HandshakeClientSession
                .connectPreconfiguredAttempt(
                allocator,
                io,
                local_address,
                server,
                options,
            ),
        };
    }

    pub fn connectAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!StatefulProtectedConnectAttempt {
        _ = try deadline_policy.usableAwake(io, deadline);
        try validateAdditionalConnectHeaders(options.headers, .request);
        try application_protocol.validateRequestPolicy(options.limits.application_protocols, options.headers);
        return .{ .attempt = try HandshakeClientSession
            .connectPreconfiguredAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            deadline,
        ) };
    }

    pub fn connectAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        server: net.IpAddress,
        options: StatefulProtectedConnectOptions,
        timeout: std.Io.Duration,
    ) Error!StatefulProtectedConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAttemptWithDeadline(
            allocator,
            io,
            local_address,
            server,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn deinit(self: *StatefulProtectedClientSession) void {
        self.session.deinit();
        self.* = undefined;
    }

    pub fn address(
        self: StatefulProtectedClientSession,
    ) net.IpAddress {
        return self.session.h3.address();
    }

    pub fn responseHeader(
        self: StatefulProtectedClientSession,
        name: []const u8,
    ) ?[]const u8 {
        return self.session.responseHeader(name);
    }

    pub fn sessionId(
        self: StatefulProtectedClientSession,
    ) webtransport.SessionId {
        return self.session.sessionId();
    }

    pub fn stableId(
        self: *const StatefulProtectedClientSession,
    ) StableConnectionId {
        return self.session.stableId();
    }

    pub fn remoteAddress(
        self: StatefulProtectedClientSession,
    ) net.IpAddress {
        return self.session.remoteAddress();
    }

    pub fn remoteAddressValidated(
        self: StatefulProtectedClientSession,
    ) bool {
        return self.session.remoteAddressValidated();
    }

    pub fn rttNanos(self: StatefulProtectedClientSession) ?u64 {
        return self.session.rttNanos();
    }

    pub fn closeConnection(
        self: *StatefulProtectedClientSession,
        error_code: u62,
        reason: []const u8,
    ) Error!void {
        return self.session.closeConnection(error_code, reason);
    }

    pub fn exportKeyingMaterial(
        self: *const StatefulProtectedClientSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        return self.session.exportKeyingMaterial(
            label,
            context,
            out,
        );
    }

    pub fn peerCertificates(
        self: *const StatefulProtectedClientSession,
    ) ?[]const []const u8 {
        return self.session.peerCertificates();
    }

    pub fn negotiatedAlpn(
        self: StatefulProtectedClientSession,
    ) []const u8 {
        return self.session.negotiatedAlpn();
    }

    pub fn negotiatedCipherSuite(
        self: StatefulProtectedClientSession,
    ) quic.tls.cipher_suite.Suite {
        return self.session.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: StatefulProtectedClientSession,
    ) quic.tls.secret.Hash {
        return self.session.negotiatedTranscriptHash();
    }

    pub fn initiateKeyUpdate(
        self: *StatefulProtectedClientSession,
    ) Error!void {
        return self.session.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(
        self: StatefulProtectedClientSession,
    ) u64 {
        return self.session.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(
        self: StatefulProtectedClientSession,
    ) u64 {
        return self.session.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(
        self: StatefulProtectedClientSession,
    ) bool {
        return self.session.keyUpdateAwaitingAck();
    }

    pub fn sendSessionData(
        self: *StatefulProtectedClientSession,
        data: []const u8,
        fin: bool,
    ) Error!void {
        return self.session.sendSessionData(data, fin);
    }

    pub fn sendSessionDataWithTimeout(
        self: *StatefulProtectedClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendSessionDataWithTimeout(
            data,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataWithDeadline(
        self: *StatefulProtectedClientSession,
        data: []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendSessionDataWithDeadline(
            data,
            fin,
            progress,
            deadline,
        );
    }

    pub fn sendSessionDataSlices(
        self: *StatefulProtectedClientSession,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        return self.session.sendSessionDataSlices(parts, fin);
    }

    pub fn sendSessionDataSlicesWithTimeout(
        self: *StatefulProtectedClientSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendSessionDataSlicesWithTimeout(
            parts,
            fin,
            progress,
            timeout,
        );
    }

    pub fn sendSessionDataSlicesWithDeadline(
        self: *StatefulProtectedClientSession,
        parts: []const []const u8,
        fin: bool,
        progress: *http3.runtime.BodyWriteProgress,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendSessionDataSlicesWithDeadline(
            parts,
            fin,
            progress,
            deadline,
        );
    }

    pub fn openBidirectionalStream(
        self: *StatefulProtectedClientSession,
    ) Error!u62 {
        return self.session.openBidirectionalStream();
    }

    pub fn openBidirectionalStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        return self.session.openBidirectionalStreamWithTimeout(timeout);
    }

    pub fn openBidirectionalStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.session.openBidirectionalStreamWithDeadline(deadline);
    }

    pub fn openUnidirectionalStream(
        self: *StatefulProtectedClientSession,
    ) Error!u62 {
        return self.session.openUnidirectionalStream();
    }

    pub fn openUnidirectionalStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!u62 {
        return self.session.openUnidirectionalStreamWithTimeout(timeout);
    }

    pub fn openUnidirectionalStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!u62 {
        return self.session.openUnidirectionalStreamWithDeadline(deadline);
    }

    pub fn sendStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
    ) Error!void {
        return self.session.sendStream(stream_id, payload, fin);
    }

    pub fn sendStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendStreamWithTimeout(
            stream_id,
            payload,
            fin,
            committed,
            timeout,
        );
    }

    pub fn sendStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendStreamWithDeadline(
            stream_id,
            payload,
            fin,
            committed,
            deadline,
        );
    }

    pub fn sendStreamSlices(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
    ) Error!void {
        return self.session.sendStreamSlices(stream_id, parts, fin);
    }

    pub fn sendStreamSlicesWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        committed: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendStreamSlicesWithTimeout(
            stream_id,
            parts,
            fin,
            committed,
            timeout,
        );
    }

    pub fn sendStreamSlicesWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        parts: []const []const u8,
        fin: bool,
        committed: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendStreamSlicesWithDeadline(
            stream_id,
            parts,
            fin,
            committed,
            deadline,
        );
    }

    pub fn writeStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
    ) Error!usize {
        return self.session.writeStream(stream_id, payload);
    }

    pub fn writeStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        return self.session.writeStreamWithTimeout(
            stream_id,
            payload,
            timeout,
        );
    }

    pub fn writeStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        return self.session.writeStreamWithDeadline(
            stream_id,
            payload,
            deadline,
        );
    }

    pub fn writeStreamSlices(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        parts: []const []const u8,
    ) Error!usize {
        return self.session.writeStreamSlices(stream_id, parts);
    }

    pub fn writeStreamSlicesWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        parts: []const []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        return self.session.writeStreamSlicesWithTimeout(
            stream_id,
            parts,
            timeout,
        );
    }

    pub fn writeStreamSlicesWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        parts: []const []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        return self.session.writeStreamSlicesWithDeadline(
            stream_id,
            parts,
            deadline,
        );
    }

    pub fn setStreamPriority(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        priority: i32,
    ) Error!void {
        return self.session.setStreamPriority(stream_id, priority);
    }

    pub fn streamPriority(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
    ) Error!i32 {
        return self.session.streamPriority(stream_id);
    }

    pub fn writeStreams(
        self: *StatefulProtectedClientSession,
        writes: []const StreamWrite,
        counts: []usize,
    ) Error!StreamWriteResult {
        return self.session.writeStreams(writes, counts);
    }

    pub fn writeStreamsWithTimeout(
        self: *StatefulProtectedClientSession,
        writes: []const StreamWrite,
        counts: []usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamWriteResult {
        return self.session.writeStreamsWithTimeout(writes, counts, timeout);
    }

    pub fn writeStreamsWithDeadline(
        self: *StatefulProtectedClientSession,
        writes: []const StreamWrite,
        counts: []usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamWriteResult {
        return self.session.writeStreamsWithDeadline(
            writes,
            counts,
            deadline,
        );
    }

    pub fn finishStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
    ) Error!void {
        return self.session.finishStream(stream_id);
    }

    pub fn finishStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.finishStreamWithTimeout(stream_id, timeout);
    }

    pub fn finishStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.finishStreamWithDeadline(stream_id, deadline);
    }

    pub fn releaseCompletedPeerStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
    ) Error!bool {
        return self.session.releaseCompletedPeerStream(stream_id);
    }

    pub fn receiveStream(
        self: *StatefulProtectedClientSession,
    ) Error!OwnedHandshakeStream {
        return self.session.receiveStream();
    }

    pub fn receiveStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        return self.session.receiveStreamWithTimeout(timeout);
    }

    pub fn receiveStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeStream {
        return self.session.receiveStreamWithDeadline(deadline);
    }

    pub fn pollCompleteStream(
        self: *StatefulProtectedClientSession,
    ) Error!?OwnedHandshakeStream {
        return self.session.pollCompleteStream();
    }

    pub fn processPacket(
        self: *StatefulProtectedClientSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        return self.session.processPacket(packet);
    }

    pub fn pollStream(
        self: *StatefulProtectedClientSession,
        out: []u8,
    ) Error!?StreamRead {
        return self.session.pollStream(out);
    }

    pub fn readStream(
        self: *StatefulProtectedClientSession,
        out: []u8,
    ) Error!StreamRead {
        return self.session.readStream(out);
    }

    pub fn readStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        return self.session.readStreamWithTimeout(out, timeout);
    }

    pub fn readStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        return self.session.readStreamWithDeadline(out, deadline);
    }

    pub fn readStreamId(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        out: []u8,
    ) Error!StreamRead {
        return self.session.readStreamId(stream_id, out);
    }

    pub fn readStreamIdWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        out: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!StreamRead {
        return self.session.readStreamIdWithTimeout(
            stream_id,
            out,
            timeout,
        );
    }

    pub fn readStreamIdWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        out: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!StreamRead {
        return self.session.readStreamIdWithDeadline(
            stream_id,
            out,
            deadline,
        );
    }

    pub fn flushPendingAck(
        self: *StatefulProtectedClientSession,
    ) Error!bool {
        return self.session.flushPendingAck();
    }

    pub fn waitForRecoveryIdleWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.waitForRecoveryIdleWithTimeout(timeout);
    }

    pub fn waitForRecoveryIdleWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.waitForRecoveryIdleWithDeadline(deadline);
    }

    pub fn waitForStreamRecoveryIdleWithTimeout(self: *StatefulProtectedClientSession, stream_id: u62, timeout: std.Io.Duration) ReceiveTimeoutError!void {
        return self.session.waitForStreamRecoveryIdleWithTimeout(stream_id, timeout);
    }

    pub fn waitForStreamRecoveryIdleWithDeadline(self: *StatefulProtectedClientSession, stream_id: u62, deadline: std.Io.Clock.Timestamp) ReceiveTimeoutError!void {
        return self.session.waitForStreamRecoveryIdleWithDeadline(stream_id, deadline);
    }

    pub fn serviceTransport(
        self: *StatefulProtectedClientSession,
    ) Error!void {
        return self.session.serviceTransport();
    }

    pub fn serviceTransportWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.serviceTransportWithTimeout(timeout);
    }

    pub fn serviceTransportWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.serviceTransportWithDeadline(deadline);
    }

    pub fn resetStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return self.session.resetStream(stream_id, application_error_code);
    }

    pub fn resetStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.resetStreamWithTimeout(
            stream_id,
            application_error_code,
            timeout,
        );
    }

    pub fn resetStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.resetStreamWithDeadline(
            stream_id,
            application_error_code,
            deadline,
        );
    }

    pub fn resetStreamReliably(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
    ) Error!void {
        return self.session.resetStreamReliably(
            stream_id,
            application_error_code,
            reliable_size,
        );
    }

    pub fn resetStreamReliablyWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.resetStreamReliablyWithTimeout(
            stream_id,
            application_error_code,
            reliable_size,
            timeout,
        );
    }

    pub fn resetStreamReliablyWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        reliable_size: u64,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.resetStreamReliablyWithDeadline(
            stream_id,
            application_error_code,
            reliable_size,
            deadline,
        );
    }

    pub fn stopStream(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
    ) Error!void {
        return self.session.stopStream(stream_id, application_error_code);
    }

    pub fn stopStreamWithTimeout(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.stopStreamWithTimeout(
            stream_id,
            application_error_code,
            timeout,
        );
    }

    pub fn stopStreamWithDeadline(
        self: *StatefulProtectedClientSession,
        stream_id: u62,
        application_error_code: u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.stopStreamWithDeadline(
            stream_id,
            application_error_code,
            deadline,
        );
    }

    pub fn sendDatagram(
        self: *StatefulProtectedClientSession,
        payload: []const u8,
    ) Error!void {
        return self.session.sendDatagram(payload);
    }

    pub fn sendDatagramWithTimeout(
        self: *StatefulProtectedClientSession,
        payload: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendDatagramWithTimeout(payload, timeout);
    }

    pub fn sendDatagramWithDeadline(
        self: *StatefulProtectedClientSession,
        payload: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendDatagramWithDeadline(payload, deadline);
    }

    pub fn sendDatagrams(
        self: *StatefulProtectedClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
    ) Error!void {
        return self.session.sendDatagrams(payloads, committed_count);
    }

    pub fn sendDatagramsWithTimeout(
        self: *StatefulProtectedClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.sendDatagramsWithTimeout(
            payloads,
            committed_count,
            timeout,
        );
    }

    pub fn sendDatagramsWithDeadline(
        self: *StatefulProtectedClientSession,
        payloads: []const []const u8,
        committed_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.sendDatagramsWithDeadline(
            payloads,
            committed_count,
            deadline,
        );
    }

    pub fn receiveDatagram(
        self: *StatefulProtectedClientSession,
    ) Error!OwnedHandshakeDatagram {
        return self.session.receiveDatagram();
    }

    pub fn receiveDatagramWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        return self.session.receiveDatagramWithTimeout(timeout);
    }

    pub fn receiveDatagramWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagram {
        return self.session.receiveDatagramWithDeadline(deadline);
    }

    pub fn receiveDatagramInto(
        self: *StatefulProtectedClientSession,
        output: []u8,
    ) Error![]u8 {
        return self.session.receiveDatagramInto(output);
    }

    pub fn receiveDatagramIntoWithTimeout(
        self: *StatefulProtectedClientSession,
        output: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError![]u8 {
        return self.session.receiveDatagramIntoWithTimeout(output, timeout);
    }

    pub fn receiveDatagramIntoWithDeadline(
        self: *StatefulProtectedClientSession,
        output: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError![]u8 {
        return self.session.receiveDatagramIntoWithDeadline(output, deadline);
    }

    pub fn receiveDatagramsInto(
        self: *StatefulProtectedClientSession,
        outputs: [][]u8,
        received_count: *usize,
    ) Error!void {
        return self.session.receiveDatagramsInto(outputs, received_count);
    }

    pub fn receiveDatagramsIntoWithTimeout(
        self: *StatefulProtectedClientSession,
        outputs: [][]u8,
        received_count: *usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.receiveDatagramsIntoWithTimeout(
            outputs,
            received_count,
            timeout,
        );
    }

    pub fn receiveDatagramsIntoWithDeadline(
        self: *StatefulProtectedClientSession,
        outputs: [][]u8,
        received_count: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.receiveDatagramsIntoWithDeadline(
            outputs,
            received_count,
            deadline,
        );
    }

    pub fn pollDatagram(
        self: *StatefulProtectedClientSession,
    ) Error!?OwnedHandshakeDatagram {
        return self.session.pollDatagram();
    }

    pub fn receiveManyDatagrams(
        self: *StatefulProtectedClientSession,
        count: usize,
    ) Error!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagrams(count);
    }

    pub fn receiveManyDatagramsWithTimeout(
        self: *StatefulProtectedClientSession,
        count: usize,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagramsWithTimeout(count, timeout);
    }

    pub fn receiveManyDatagramsWithDeadline(
        self: *StatefulProtectedClientSession,
        count: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedHandshakeDatagramBatch {
        return self.session.receiveManyDatagramsWithDeadline(count, deadline);
    }

    pub fn maxDatagramPayloadSize(
        self: StatefulProtectedClientSession,
    ) ?usize {
        return self.session.maxDatagramPayloadSize();
    }

    pub fn maxDatagramSize(
        self: StatefulProtectedClientSession,
    ) usize {
        return self.session.maxDatagramSize();
    }

    pub fn datagramsNegotiated(
        self: StatefulProtectedClientSession,
    ) bool {
        return self.session.datagramsNegotiated();
    }

    pub fn drain(self: *StatefulProtectedClientSession) Error!void {
        return self.session.drain();
    }

    pub fn drainWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.drainWithTimeout(timeout);
    }

    pub fn drainWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.drainWithDeadline(deadline);
    }

    pub fn close(
        self: *StatefulProtectedClientSession,
        code: u32,
        reason: []const u8,
    ) Error!void {
        return self.session.close(code, reason);
    }

    pub fn closeWithTimeout(
        self: *StatefulProtectedClientSession,
        code: u32,
        reason: []const u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!void {
        return self.session.closeWithTimeout(code, reason, timeout);
    }

    pub fn closeWithDeadline(
        self: *StatefulProtectedClientSession,
        code: u32,
        reason: []const u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        return self.session.closeWithDeadline(code, reason, deadline);
    }

    pub fn receiveSessionEvent(
        self: *StatefulProtectedClientSession,
    ) Error!SessionEvent {
        return self.session.receiveSessionEvent();
    }

    pub fn pollSessionEvent(
        self: *StatefulProtectedClientSession,
    ) Error!?SessionEvent {
        return self.session.pollSessionEvent();
    }

    pub fn receiveSessionEventWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!SessionEvent {
        return self.session.receiveSessionEventWithTimeout(timeout);
    }

    pub fn receiveSessionEventWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!SessionEvent {
        return self.session.receiveSessionEventWithDeadline(deadline);
    }

    pub fn receivePeerConnectionClose(
        self: *StatefulProtectedClientSession,
    ) Error!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionClose();
    }

    pub fn pollPeerConnectionClose(
        self: *const StatefulProtectedClientSession,
    ) ?quic.one_rtt.PeerCloseInfo {
        return self.session.pollPeerConnectionClose();
    }

    pub fn receivePeerConnectionCloseWithDeadline(
        self: *StatefulProtectedClientSession,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionCloseWithDeadline(deadline);
    }

    pub fn receivePeerConnectionCloseWithTimeout(
        self: *StatefulProtectedClientSession,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!quic.one_rtt.PeerCloseInfo {
        return self.session.receivePeerConnectionCloseWithTimeout(timeout);
    }

    pub fn stats(
        self: StatefulProtectedClientSession,
    ) quic.one_rtt.ConnectionStats {
        return self.session.stats();
    }

    pub fn getStats(
        self: StatefulProtectedClientSession,
    ) quic.one_rtt.ConnectionStats {
        return self.stats();
    }
};

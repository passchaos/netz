//! Single-owner virtual-stream session on an established HTTP/2 Tunnel.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const model = @import("state.zig");
const capsules = @import("capsule.zig");
const reader_mod = @import("reader.zig");
const Fifo = @import("../../internal/fifo.zig").Fifo;
pub const Error = model.Error || reader_mod.Error || http2.runtime.Error || error{ PendingWrite, PendingEvent };
pub const Event = model.Event;
pub const Options = struct { max_payload: usize = 1024 * 1024, max_live_streams: usize = 256, max_pending_events: usize = 64, max_pending_bytes: usize = 64 * 1024 };

const BytesPending = struct { bytes: []u8, offset: usize = 0, fin: bool = false };
/// Zero-copy stream write: the encoded capsule header plus borrowed payload
/// slices. `fin` is the virtual-stream FIN carried by the capsule type; the
/// HTTP/2 session stream stays open.
const SlicesPending = struct {
    header: []u8,
    header_offset: usize = 0,
    payload: [][]const u8,
    payload_start: usize = 0,
    payload_inner: usize = 0,
    payload_written: usize = 0,
    stream_id: u62,
    data_len: usize,
    fin: bool,
};
const Pending = union(enum) { bytes: BytesPending, slices: SlicesPending };
const Retained = struct { event: Event, storage: std.ArrayList(u8) };
pub const Session = struct {
    allocator: std.mem.Allocator,
    tunnel: http2.runtime.Tunnel,
    duplex: ?http2.runtime.ClientDuplexStream = null,
    server_duplex: ?http2.runtime.ServerDuplexStream = null,
    state: model.State,
    reader: reader_mod.Reader,
    input: ?http2.runtime.OwnedTunnelData = null,
    duplex_input: ?http2.runtime.DuplexData = null,
    remaining: []const u8 = &.{},
    input_fin: bool = false,
    pending: ?Pending = null,
    terminal: bool = false,
    selected_protocol: ?[]u8 = null,
    pending_terminal: ?Event = null,
    queued: Fifo(Retained) = .{},
    queued_bytes: usize = 0,
    deferred_event: ?Event = null,
    delivered_storage: std.ArrayList(u8) = .empty,
    options: Options,
    response: ?http2.runtime.ExtendedConnectAttempt = null,
    duplex_response: ?http2.runtime.DuplexResponseHead = null,
    response_allocator: std.mem.Allocator = undefined,

    pub fn init(allocator: std.mem.Allocator, tunnel: http2.runtime.Tunnel, receive_limits: model.Limits, send_limits: model.Limits, options: Options) Error!Session {
        if (options.max_payload < 4 or options.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
        const role: model.Role = if (tunnel.connection.role == .client) .client else .server;
        return .{ .allocator = allocator, .tunnel = tunnel, .state = try model.State.init(allocator, role, receive_limits, send_limits, options.max_live_streams), .reader = reader_mod.Reader.init(allocator, options.max_payload), .options = options };
    }
    pub fn initDuplex(allocator: std.mem.Allocator, duplex: http2.runtime.ClientDuplexStream, receive_limits: model.Limits, send_limits: model.Limits, options: Options) Error!Session {
        if (options.max_payload < 4 or options.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
        return .{ .allocator = allocator, .tunnel = undefined, .duplex = duplex, .state = try model.State.init(allocator, .client, receive_limits, send_limits, options.max_live_streams), .reader = reader_mod.Reader.init(allocator, options.max_payload), .options = options };
    }
    pub fn initServerDuplex(allocator: std.mem.Allocator, duplex: http2.runtime.ServerDuplexStream, receive_limits: model.Limits, send_limits: model.Limits, options: Options) Error!Session {
        if (options.max_payload < 4 or options.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
        return .{ .allocator = allocator, .tunnel = undefined, .server_duplex = duplex, .state = try model.State.init(allocator, .server, receive_limits, send_limits, options.max_live_streams), .reader = reader_mod.Reader.init(allocator, options.max_payload), .options = options };
    }
    pub fn deinit(self: *Session) void {
        self.clearInput();
        if (self.duplex) |*duplex| duplex.deinit() else if (self.server_duplex) |*duplex| duplex.deinit() else self.tunnel.abort(null);
        if (self.pending) |*pending| switch (pending.*) {
            .bytes => |value| self.allocator.free(value.bytes),
            .slices => |value| {
                self.allocator.free(value.header);
                self.allocator.free(value.payload);
            },
        };
        self.reader.deinit();
        self.delivered_storage.deinit(self.allocator);
        for (self.queued.slice()) |*retained| retained.storage.deinit(self.allocator);
        self.queued.deinit(self.allocator);
        self.state.deinit();
        if (self.selected_protocol) |value| self.allocator.free(value);
        if (self.response) |*response| response.deinit(self.response_allocator);
        if (self.duplex_response) |*response| response.deinit(self.response_allocator);
        self.* = undefined;
    }
    pub fn unreliableDelivery(_: Session) bool {
        return false;
    }
    pub fn streamIndependence(_: Session) bool {
        return false;
    }
    /// Selected WebTransport application protocol negotiated on CONNECT,
    /// matching `Accepted.applicationProtocol` on the endpoint facades. The
    /// returned slice is borrowed until `deinit`.
    pub fn applicationProtocol(self: Session) ?[]const u8 {
        return self.selected_protocol;
    }
    pub fn responseStatus(self: Session) ?u16 {
        if (self.response) |response| return response.status;
        return if (self.duplex_response) |response| response.status else null;
    }
    pub fn responseHeader(self: Session, name: []const u8) ?[]const u8 {
        if (self.response) |response| return response.responseHeader(name);
        if (self.duplex_response) |response| for (response.headers) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        };
        return null;
    }
    pub fn responseHeaders(self: Session) []const http2.Hpack.HeaderField {
        if (self.response) |response| return response.headers;
        return if (self.duplex_response) |response| response.headers else &.{};
    }
    pub fn multiplexed(self: Session) bool {
        return self.duplex != null or self.server_duplex != null;
    }
    /// Authenticated TLS metadata for the underlying HTTP/2 connection.
    /// Cleartext and retired transports return null.
    pub fn peerCertificates(self: *const Session) ?[]const []const u8 {
        return self.connection().peerCertificates();
    }
    pub fn negotiatedAlpn(self: *const Session) ?[]const u8 {
        return self.connection().negotiatedAlpn();
    }
    pub fn negotiatedCipherSuite(
        self: *const Session,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.connection().negotiatedCipherSuite();
    }
    pub fn negotiatedTranscriptHash(
        self: *const Session,
    ) ?tls_stream.TranscriptHash {
        return self.connection().negotiatedTranscriptHash();
    }
    /// Start a TLS 1.3 traffic-key update on the shared HTTP/2 connection.
    /// The rotation is connection-wide, not scoped to this virtual stream;
    /// cleartext transports return `error.PostHandshakeTlsUnavailable`.
    pub fn initiateKeyUpdate(self: *Session) Error!void {
        try self.connection().updateTrafficKeys(false);
    }
    /// Locally initiated TLS 1.3 key updates on the underlying connection.
    /// Cleartext transports report 0.
    pub fn localKeyUpdateCount(self: *const Session) u64 {
        const counts = self.connection().keyUpdateCounts() orelse return 0;
        return counts.sent;
    }
    /// Peer-initiated TLS 1.3 key updates observed on the underlying
    /// connection. Cleartext transports report 0.
    pub fn peerKeyUpdateCount(self: *const Session) u64 {
        const counts = self.connection().keyUpdateCounts() orelse return 0;
        return counts.received;
    }
    fn connection(self: *const Session) *http2.runtime.Connection {
        if (self.duplex) |*duplex| return duplex.connection;
        if (self.server_duplex) |*duplex| return duplex.connection;
        return self.tunnel.connection;
    }
    fn streamId(self: *Session) u31 {
        if (self.duplex) |duplex| return duplex.streamId();
        if (self.server_duplex) |duplex| return duplex.stream_id;
        return self.tunnel.stream_id;
    }
    fn clearInput(self: *Session) void {
        if (self.input) |*input| input.deinit(self.connection().allocator);
        self.input = null;
        if (self.duplex_input) |*input| input.deinit(self.connection().allocator);
        self.duplex_input = null;
    }

    fn fail(self: *Session, deadline: std.Io.Clock.Timestamp) void {
        self.terminal = true;
        if (self.duplex) |*duplex| duplex.reset(.cancel) catch {} else if (self.server_duplex) |*duplex| duplex.reset(.cancel) catch {} else self.tunnel.abort(deadline);
    }
    fn stage(self: *Session, capsule: capsules.Capsule, fin: bool) Error!void {
        if (self.terminal or self.state.local_closed) return error.SessionClosed;
        if (self.pending != null) return error.PendingWrite;
        const length = try capsule.encodedLen();
        if (length > self.reader.max_payload + 16) return error.CapsuleTooLarge;
        const bytes = try self.allocator.alloc(u8, length);
        errdefer self.allocator.free(bytes);
        _ = try capsule.writeInto(bytes);
        self.pending = .{ .bytes = .{ .bytes = bytes, .fin = fin } };
    }

    /// Resume only the uncommitted encoded suffix. A bounded write interruption
    /// retains the same capsule and exact virtual-stream commit boundary.
    pub fn resumeWriteWithDeadline(self: *Session, deadline: std.Io.Clock.Timestamp) Error!void {
        if (self.terminal) return error.SessionClosed;
        const pending = if (self.pending) |*value| value else return;
        switch (pending.*) {
            .bytes => |*value| try self.resumeBytes(value, deadline),
            .slices => |*value| try self.resumeSlices(value, deadline),
        }
    }

    fn resumeBytes(self: *Session, pending: *BytesPending, deadline: std.Io.Clock.Timestamp) Error!void {
        var progress: http2.runtime.TunnelWriteProgress = .{};
        var response_available = false;
        if (self.duplex) |*duplex| {
            if (pending.offset != pending.bytes.len or (pending.fin and !duplex.requestFinished())) {
                const before = duplex.requestCommittedBytes();
                const result = duplex.writeRequestSlicesWithDeadline(&.{pending.bytes[pending.offset..]}, pending.fin, deadline) catch |err| {
                    progress.committed_bytes = duplex.requestCommittedBytes() - before;
                    progress.fin_committed = duplex.requestFinished();
                    pending.offset += progress.committed_bytes;
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                    return err;
                };
                progress.committed_bytes = result.written;
                progress.fin_committed = duplex.requestFinished();
                response_available = result.response_available;
            } else {
                progress.fin_committed = duplex.requestFinished();
            }
        } else if (self.server_duplex) |*duplex| {
            if (pending.offset != pending.bytes.len or (pending.fin and !duplex.responseFinished())) {
                const before = duplex.responseCommittedBytes();
                const result = duplex.writeResponseSlicesWithDeadline(&.{pending.bytes[pending.offset..]}, pending.fin, deadline) catch |err| {
                    progress.committed_bytes = duplex.responseCommittedBytes() - before;
                    progress.fin_committed = duplex.responseFinished();
                    pending.offset += progress.committed_bytes;
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                    return err;
                };
                progress.committed_bytes = result.written;
                progress.fin_committed = duplex.responseFinished();
                response_available = result.response_available;
            } else {
                progress.fin_committed = duplex.responseFinished();
            }
        } else self.tunnel.writeWithDeadline(pending.bytes[pending.offset..], pending.fin, &progress, deadline) catch |err| {
            pending.offset += progress.committed_bytes;
            if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
            return err;
        };
        pending.offset += progress.committed_bytes;
        if (response_available) return error.ResponseAvailable;
        if (pending.offset != pending.bytes.len or (pending.fin and !progress.fin_committed)) return error.PendingWrite;
        const capsule = (try capsules.Capsule.parse(pending.bytes)).capsule;
        try self.state.commit(capsule);
        self.allocator.free(pending.bytes);
        self.pending = null;
    }

    /// Zero-copy stream writes send the capsule header and borrowed payload
    /// slices directly; the session stream is never ended by this path.
    fn resumeSlices(self: *Session, pending: *SlicesPending, deadline: std.Io.Clock.Timestamp) Error!void {
        if (pending.header_offset < pending.header.len) {
            var written: usize = 0;
            self.writeSlicesTracked(
                &.{pending.header[pending.header_offset..]},
                false,
                &written,
                deadline,
            ) catch |err| {
                pending.header_offset += written;
                return err;
            };
            pending.header_offset += written;
            if (pending.header_offset != pending.header.len) {
                return error.PendingWrite;
            }
        }
        while (true) {
            const remaining = self.remainingPayload(pending);
            if (remaining.len == 0) break;
            var written: usize = 0;
            self.writeSlicesTracked(remaining, false, &written, deadline) catch |err| {
                self.advancePayload(pending, written);
                return err;
            };
            self.advancePayload(pending, written);
            if (pending.payload_written > pending.data_len) {
                return error.PendingWrite;
            }
        }
        if (pending.payload_written != pending.data_len) {
            return error.PendingWrite;
        }
        try self.state.commitStreamLength(
            pending.stream_id,
            pending.data_len,
            pending.fin,
        );
        self.allocator.free(pending.header);
        self.allocator.free(pending.payload);
        self.pending = null;
    }

    fn writeSlicesTracked(
        self: *Session,
        slices: []const []const u8,
        end_stream: bool,
        written: *usize,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        written.* = 0;
        if (self.duplex) |*duplex| {
            const before = duplex.requestCommittedBytes();
            const result = duplex.writeRequestSlicesWithDeadline(slices, end_stream, deadline) catch |err| {
                written.* = duplex.requestCommittedBytes() - before;
                if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                return err;
            };
            written.* = result.written;
            if (result.response_available) return error.ResponseAvailable;
            return;
        }
        if (self.server_duplex) |*duplex| {
            const before = duplex.responseCommittedBytes();
            const result = duplex.writeResponseSlicesWithDeadline(slices, end_stream, deadline) catch |err| {
                written.* = duplex.responseCommittedBytes() - before;
                if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                return err;
            };
            written.* = result.written;
            if (result.response_available) return error.ResponseAvailable;
            return;
        }
        var progress: http2.runtime.TunnelWriteProgress = .{};
        self.tunnel.writeSlicesWithDeadline(slices, end_stream, &progress, deadline) catch |err| {
            written.* = progress.committed_bytes;
            if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
            return err;
        };
        written.* = progress.committed_bytes;
    }

    fn remainingPayload(self: *Session, pending: *SlicesPending) []const []const u8 {
        _ = self;
        if (pending.payload_start >= pending.payload.len) return &.{};
        if (pending.payload_inner != 0) {
            pending.payload[pending.payload_start] =
                pending.payload[pending.payload_start][pending.payload_inner..];
            pending.payload_inner = 0;
        }
        return pending.payload[pending.payload_start..];
    }

    fn advancePayload(self: *Session, pending: *SlicesPending, written: usize) void {
        _ = self;
        var remaining = written;
        while (pending.payload_start < pending.payload.len) {
            const slice_len = pending.payload[pending.payload_start].len -
                pending.payload_inner;
            if (remaining < slice_len) {
                pending.payload_inner += remaining;
                break;
            }
            remaining -= slice_len;
            pending.payload_start += 1;
            pending.payload_inner = 0;
        }
        pending.payload_written += written;
    }
    pub fn resumeWriteWithTimeout(self: *Session, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resumeWriteWithDeadline(.fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    fn submit(self: *Session, capsule: capsules.Capsule, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.stage(capsule, capsule == .close_session);
        return self.resumeWriteWithDeadline(deadline);
    }
    pub fn openStream(self: *Session, direction: model.Direction) Error!u62 {
        if (self.pending != null) return error.PendingWrite;
        return self.state.openStream(direction);
    }
    pub fn sendStreamWithDeadline(self: *Session, id: u62, data: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        if (self.pending != null) return error.PendingWrite;
        while (true) {
            if (self.deferred_event != null) try self.queueDeferred();
            const prepared = self.state.prepareStream(id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked => {
                    const event = try self.receiveTransportWithDeadline(deadline);
                    if (event != .progress) {
                        self.deferred_event = event;
                        try self.queueDeferred();
                    }
                    continue;
                },
                else => return err,
            };
            return self.submit(prepared, deadline);
        }
    }
    pub fn sendStreamWithTimeout(self: *Session, id: u62, data: []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(id, data, fin, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Send one stream capsule whose payload is supplied as multiple slices.
    /// The capsule header is encoded separately and the borrowed payload slices
    /// are written directly, so the caller must keep them valid until the
    /// write completes (including bounded-write retries). The virtual-stream
    /// FIN is carried by the capsule type, not by HTTP/2 END_STREAM.
    pub fn sendStreamSlicesWithDeadline(
        self: *Session,
        id: u62,
        slices: []const []const u8,
        fin: bool,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        if (self.pending != null) return error.PendingWrite;
        var total: usize = 0;
        for (slices) |slice| {
            total = std.math.add(usize, total, slice.len) catch
                return error.CapsuleTooLarge;
        }
        while (true) {
            if (self.deferred_event != null) try self.queueDeferred();
            self.state.prepareStreamLength(id, total, fin) catch |err| switch (err) {
                error.FlowControlBlocked => {
                    const event = try self.receiveTransportWithDeadline(deadline);
                    if (event != .progress) {
                        self.deferred_event = event;
                        try self.queueDeferred();
                    }
                    continue;
                },
                else => return err,
            };
            var header_storage: [capsules.max_stream_header_len]u8 = undefined;
            const header = try capsules.writeStreamHeaderInto(
                &header_storage,
                id,
                total,
                fin,
            );
            const length = std.math.add(
                usize,
                header.len,
                total,
            ) catch return error.CapsuleTooLarge;
            if (length > self.reader.max_payload + 16) {
                return error.CapsuleTooLarge;
            }
            const header_owned = try self.allocator.dupe(u8, header);
            var header_owned_flag = true;
            defer if (header_owned_flag) self.allocator.free(header_owned);
            const payload_owned = try self.allocator.dupe(
                []const u8,
                slices,
            );
            var payload_owned_flag = true;
            defer if (payload_owned_flag) {
                self.allocator.free(payload_owned);
            };
            self.pending = .{ .slices = .{
                .header = header_owned,
                .payload = payload_owned,
                .stream_id = id,
                .data_len = total,
                .fin = fin,
            } };
            header_owned_flag = false;
            payload_owned_flag = false;
            return self.resumeWriteWithDeadline(deadline);
        }
    }

    pub fn sendStreamSlicesWithTimeout(
        self: *Session,
        id: u62,
        slices: []const []const u8,
        fin: bool,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(
            id,
            slices,
            fin,
            .fromNow(self.connection().io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }
    pub fn sendDatagramWithDeadline(self: *Session, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(.{ .datagram = data }, deadline);
    }
    pub fn sendDatagramWithTimeout(self: *Session, data: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(data, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn resetStreamWithDeadline(self: *Session, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(try self.state.prepareReset(id, code), deadline);
    }
    pub fn resetStreamWithTimeout(self: *Session, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(id, code, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn stopSendingWithDeadline(self: *Session, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(try self.state.prepareStop(id, code), deadline);
    }
    pub fn stopSendingWithTimeout(self: *Session, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopSendingWithDeadline(id, code, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantDataWithDeadline(self: *Session, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(try self.state.prepareGrantData(limit), deadline);
    }
    pub fn grantDataWithTimeout(self: *Session, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantDataWithDeadline(limit, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamsWithDeadline(self: *Session, direction: model.Direction, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(try self.state.prepareGrantStreams(direction, limit), deadline);
    }
    pub fn grantStreamsWithTimeout(self: *Session, direction: model.Direction, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamsWithDeadline(direction, limit, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamDataWithDeadline(self: *Session, id: u62, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(try self.state.prepareGrantStreamData(id, limit), deadline);
    }
    pub fn grantStreamDataWithTimeout(self: *Session, id: u62, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamDataWithDeadline(id, limit, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn drainWithDeadline(self: *Session, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(.drain_session, deadline);
    }
    pub fn drainWithTimeout(self: *Session, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(.fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn closeWithDeadline(self: *Session, code: u32, reason: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.submit(.{ .close_session = .{ .code = code, .reason = reason } }, deadline);
    }
    pub fn closeWithTimeout(self: *Session, code: u32, reason: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(code, reason, .fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn consume(self: *Session, id: u62, bytes: u64) Error!void {
        return self.state.consume(id, bytes);
    }
    pub fn retireStream(self: *Session, id: u62) Error!void {
        return self.state.retireStream(id);
    }

    /// Payloads remain valid until the next public receive call, including
    /// while an outgoing operation drives flow-control progress.
    pub fn receiveWithDeadline(self: *Session, deadline: std.Io.Clock.Timestamp) Error!Event {
        self.delivered_storage.deinit(self.allocator);
        self.delivered_storage = .empty;
        if (!self.queued.isEmpty()) {
            const retained = self.queued.popFront().?;
            self.queued_bytes -= retained.storage.items.len;
            self.delivered_storage = retained.storage;
            return retained.event;
        }
        const event = if (self.deferred_event) |event| blk: {
            self.deferred_event = null;
            break :blk event;
        } else try self.receiveTransportWithDeadline(deadline);
        self.delivered_storage = self.takeEventStorage(event);
        return event;
    }
    fn takeEventStorage(self: *Session, event: Event) std.ArrayList(u8) {
        if (event == .stream or event == .datagram or event == .closed) {
            const storage = self.reader.buffer;
            self.reader.buffer = .empty;
            return storage;
        }
        return .empty;
    }
    fn queueDeferred(self: *Session) Error!void {
        const event = self.deferred_event.?;
        const bytes = if (event == .stream or event == .datagram or event == .closed) self.reader.buffer.items.len else 0;
        if (self.queued.len() >= self.options.max_pending_events or bytes > self.options.max_pending_bytes -| self.queued_bytes) return error.PendingEvent;
        try self.queued.ensureUnusedCapacity(self.allocator, 1);
        self.queued.appendAssumeCapacity(.{ .event = event, .storage = self.takeEventStorage(event) });
        self.queued_bytes += bytes;
        self.deferred_event = null;
    }

    /// Consume only frames already routed by the shared HTTP/2 owner. Any
    /// application event is retained in this Session's bounded queue; this
    /// method never reads the socket and is therefore safe for sibling
    /// progress while another Session resumes output.
    pub fn pollWithDeadline(self: *Session, deadline: std.Io.Clock.Timestamp) Error!bool {
        if (self.duplex == null and self.server_duplex == null) return false;
        if (self.terminal) return false;
        var progressed = false;
        while (true) {
            if (self.deferred_event != null) {
                try self.queueDeferred();
                return true;
            }
            if (self.pending_terminal != null) {
                self.deferred_event = try self.finishPeerClose(deadline);
                try self.queueDeferred();
                return true;
            }
            const decoded = self.reader.next(&self.remaining) catch |err| {
                if (err != error.OutOfMemory) self.fail(deadline);
                return err;
            };
            if (decoded) |value| {
                const event = self.state.receive(value) catch |err| {
                    self.fail(deadline);
                    return err;
                };
                if (event == .closed) {
                    if (self.remaining.len != 0) {
                        self.fail(deadline);
                        return error.InvalidCapsule;
                    }
                    self.pending_terminal = event;
                    continue;
                }
                if (event != .progress) {
                    self.deferred_event = event;
                    try self.queueDeferred();
                }
                return true;
            }
            if (self.input_fin) {
                self.reader.finish() catch |err| {
                    self.fail(deadline);
                    return err;
                };
                self.pending_terminal = self.state.receiveFin();
                continue;
            }
            self.clearInput();
            if (self.duplex) |*duplex| {
                var transport_event = (try duplex.pollResponseEventWithDeadline(deadline)) orelse return progressed;
                progressed = true;
                var event_owned = true;
                defer if (event_owned) transport_event.deinit(self.connection().allocator);
                switch (transport_event) {
                    .data => |data| {
                        self.duplex_input = data;
                        event_owned = false;
                        self.remaining = data.data;
                        self.input_fin = duplex.responseFinished();
                    },
                    .finished => self.input_fin = true,
                    .reset => {
                        self.terminal = true;
                        return error.StreamReset;
                    },
                    .informational, .head, .trailers => {
                        self.fail(deadline);
                        return error.UnexpectedFrame;
                    },
                }
            } else if (self.server_duplex) |*duplex| {
                var transport_event = (try duplex.pollRequestEventWithDeadline(deadline)) orelse return progressed;
                progressed = true;
                var event_owned = true;
                defer if (event_owned) transport_event.deinit(self.connection().allocator);
                switch (transport_event) {
                    .data => |data| {
                        self.duplex_input = data;
                        event_owned = false;
                        self.remaining = data.data;
                        self.input_fin = duplex.requestFinished();
                    },
                    .finished => self.input_fin = true,
                    .reset => {
                        self.terminal = true;
                        return error.StreamReset;
                    },
                    .trailers => {
                        self.fail(deadline);
                        return error.UnexpectedFrame;
                    },
                }
            }
        }
    }
    fn receiveTransportWithDeadline(self: *Session, deadline: std.Io.Clock.Timestamp) Error!Event {
        if (self.terminal) return error.SessionClosed;
        if (self.pending_terminal != null) return self.finishPeerClose(deadline);
        while (true) {
            const decoded = self.reader.next(&self.remaining) catch |err| {
                if (err != error.OutOfMemory) self.fail(deadline);
                return err;
            };
            if (decoded) |capsule| {
                const event = self.state.receive(capsule) catch |err| {
                    self.fail(deadline);
                    return err;
                };
                if (event == .closed) {
                    if (self.remaining.len != 0) {
                        self.fail(deadline);
                        return error.InvalidCapsule;
                    }
                    self.pending_terminal = event;
                    return self.finishPeerClose(deadline);
                }
                return event;
            }
            if (self.input_fin) {
                self.reader.finish() catch |err| {
                    self.fail(deadline);
                    return err;
                };
                const event = self.state.receiveFin();
                self.pending_terminal = event;
                return self.finishPeerClose(deadline);
            }
            self.clearInput();
            if (self.duplex) |*duplex| {
                var transport_event = duplex.readResponseEventWithDeadline(deadline) catch |err| {
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                    return err;
                };
                var event_owned = true;
                defer if (event_owned) transport_event.deinit(self.connection().allocator);
                switch (transport_event) {
                    .data => |data| {
                        self.duplex_input = data;
                        event_owned = false;
                        self.remaining = data.data;
                        self.input_fin = duplex.responseFinished();
                    },
                    .finished => self.input_fin = true,
                    .reset => {
                        self.terminal = true;
                        return error.StreamReset;
                    },
                    .informational, .head, .trailers => {
                        self.fail(deadline);
                        return error.UnexpectedFrame;
                    },
                }
            } else if (self.server_duplex) |*duplex| {
                var transport_event = duplex.readRequestEventWithDeadline(deadline) catch |err| {
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                    return err;
                };
                var event_owned = true;
                defer if (event_owned) transport_event.deinit(self.connection().allocator);
                switch (transport_event) {
                    .data => |data| {
                        self.duplex_input = data;
                        event_owned = false;
                        self.remaining = data.data;
                        self.input_fin = duplex.requestFinished();
                    },
                    .finished => self.input_fin = true,
                    .reset => {
                        self.terminal = true;
                        return error.StreamReset;
                    },
                    .trailers => {
                        self.fail(deadline);
                        return error.UnexpectedFrame;
                    },
                }
            } else {
                const input = self.tunnel.readWithDeadline(deadline) catch |err| {
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable) self.fail(deadline);
                    return err;
                };
                self.input = input;
                self.remaining = input.data;
                self.input_fin = input.end_stream;
            }
        }
    }
    fn finishPeerClose(self: *Session, deadline: std.Io.Clock.Timestamp) Error!Event {
        if (self.duplex) |*duplex| {
            if (!duplex.requestFinished()) {
                _ = duplex.finishRequestWithDeadline(deadline) catch |err| {
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                    return err;
                };
            }
        } else if (self.server_duplex) |*duplex| {
            if (!duplex.responseFinished()) {
                _ = duplex.finishResponseWithDeadline(deadline) catch |err| {
                    if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable and err != error.ResponseAvailable) self.fail(deadline);
                    return err;
                };
            }
        } else if (!self.tunnel.send_finished.load(.acquire)) self.tunnel.closeWriteWithDeadline(deadline) catch |err| {
            if (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable) self.fail(deadline);
            return err;
        };
        const event = self.pending_terminal.?;
        self.pending_terminal = null;
        self.terminal = true;
        return event;
    }
    pub fn receiveWithTimeout(self: *Session, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(.fromNow(self.connection().io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn exportKeyingMaterial(self: *Session, label: []const u8, context: []const u8, output: []u8) Error!void {
        if (label.len > 255 or context.len > 255) return error.InvalidScope;
        var buffer: [520]u8 = undefined;
        std.mem.writeInt(u64, buffer[0..8], self.streamId(), .big);
        buffer[8] = @intCast(label.len);
        @memcpy(buffer[9..][0..label.len], label);
        const offset = 9 + label.len;
        buffer[offset] = @intCast(context.len);
        @memcpy(buffer[offset + 1 ..][0..context.len], context);
        return self.connection().exportKeyingMaterial("EXPORTER-WebTransport", buffer[0 .. offset + 1 + context.len], output);
    }
};

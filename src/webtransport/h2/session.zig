//! Single-owner virtual-stream session on an established HTTP/2 Tunnel.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const model = @import("state.zig");
const capsules = @import("capsule.zig");
const reader_mod = @import("reader.zig");
pub const Error = model.Error || reader_mod.Error || http2.runtime.Error || error{ PendingWrite, PendingEvent };
pub const Event = model.Event;
pub const Options = struct { max_payload: usize = 1024 * 1024, max_live_streams: usize = 256, max_pending_events: usize = 64, max_pending_bytes: usize = 64 * 1024 };

const Pending = struct { bytes: []u8, offset: usize = 0, fin: bool = false };
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
    queued: std.ArrayList(Retained) = .empty,
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
        if (self.pending) |pending| self.allocator.free(pending.bytes);
        self.reader.deinit();
        self.delivered_storage.deinit(self.allocator);
        for (self.queued.items) |*retained| retained.storage.deinit(self.allocator);
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
    fn connection(self: *Session) *http2.runtime.Connection {
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
        self.pending = .{ .bytes = bytes, .fin = fin };
    }

    /// Resume only the uncommitted encoded suffix. A bounded write interruption
    /// retains the same capsule and exact virtual-stream commit boundary.
    pub fn resumeWriteWithDeadline(self: *Session, deadline: std.Io.Clock.Timestamp) Error!void {
        if (self.terminal) return error.SessionClosed;
        const pending = if (self.pending) |*value| value else return;
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
        if (self.queued.items.len != 0) {
            const retained = self.queued.orderedRemove(0);
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
        if (self.queued.items.len >= self.options.max_pending_events or bytes > self.options.max_pending_bytes -| self.queued_bytes) return error.PendingEvent;
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

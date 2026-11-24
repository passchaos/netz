//! Public pending-admission and Session routing API.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const tls_stream = @import("../../../tls/mod.zig").stream;
const h2_state = @import("../state.zig");
const runtime = @import("../runtime.zig");
const endpoint = @import("../endpoint_server.zig");
const core = @import("core.zig");

pub const Event = core.Event;
pub const KeyingMaterial = core.KeyingMaterial;
pub const Error = core.Error;
pub const Options = core.Options;
pub const ConnectionHandle = core.ConnectionHandle;
pub const Handle = core.Handle;
pub const Accepted = core.Accepted;

const OwnedListener = core.OwnedListener;
const ManagedConnection = core.ManagedConnection;
const ConnectionSlot = core.ConnectionSlot;
const QueuedRequest = core.QueuedRequest;
const State = core.State;
const acceptLoop = core.acceptLoop;

pub const PendingRequest = struct {
    state: *State,
    connection_handle: ConnectionHandle,
    connection: *ManagedConnection,
    request: endpoint.PendingRequest,

    pub fn path(self: PendingRequest) []const u8 {
        return self.request.path();
    }
    pub fn authority(self: PendingRequest) ?[]const u8 {
        return self.request.authority();
    }
    pub fn origin(self: PendingRequest) ?[]const u8 {
        return self.request.origin();
    }
    pub fn headers(self: PendingRequest) []const http2.Hpack.HeaderField {
        return self.request.headers();
    }
    pub fn header(self: PendingRequest, name: []const u8) ?[]const u8 {
        return self.request.header(name);
    }
    /// Authenticated TLS metadata for the connection carrying this request.
    pub fn peerCertificates(self: PendingRequest) ?[]const []const u8 {
        return self.request.peerCertificates();
    }
    pub fn negotiatedAlpn(self: PendingRequest) ?[]const u8 {
        return self.request.negotiatedAlpn();
    }
    pub fn negotiatedCipherSuite(
        self: PendingRequest,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.request.negotiatedCipherSuite();
    }
    pub fn negotiatedTranscriptHash(
        self: PendingRequest,
    ) ?tls_stream.TranscriptHash {
        return self.request.negotiatedTranscriptHash();
    }
    pub fn negotiatedTlsProtocol(
        self: PendingRequest,
    ) ?tls_stream.Protocol {
        return self.request.negotiatedTlsProtocol();
    }
    pub fn wasTlsSessionResumed(self: PendingRequest) ?bool {
        return self.request.wasTlsSessionResumed();
    }
    pub fn peerAddress(self: PendingRequest) ?std.Io.net.IpAddress {
        return self.request.peerAddress();
    }

    pub fn acceptWithDeadline(
        self: *PendingRequest,
        options: runtime.ServerOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Accepted {
        var accepted = try self.request.acceptWithDeadline(options, deadline);
        const result = Accepted{
            .allocator = accepted.allocator,
            .handle = .{
                .connection = self.connection_handle,
                .session = accepted.handle,
            },
            .selected_protocol = accepted.selected_protocol,
        };
        accepted.selected_protocol = null;
        accepted.deinit();
        self.consume();
        return result;
    }

    pub fn acceptWithTimeout(
        self: *PendingRequest,
        options: runtime.ServerOptions,
        timeout: std.Io.Duration,
    ) Error!Accepted {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(
            self.state.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn rejectWithDeadline(
        self: *PendingRequest,
        options: runtime.RejectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!void {
        try self.request.rejectWithDeadline(options, deadline);
        self.consume();
    }

    pub fn rejectWithTimeout(
        self: *PendingRequest,
        options: runtime.RejectOptions,
        timeout: std.Io.Duration,
    ) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectWithDeadline(options, .fromNow(
            self.state.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn consume(self: *PendingRequest) void {
        const state = self.state;
        const connection = self.connection;
        self.* = undefined;
        connection.release();
        state.release();
    }

    pub fn deinit(self: *PendingRequest) void {
        self.request.deinit();
        self.consume();
    }
};

pub const EndpointListener = struct {
    state: *State,

    pub const testing = struct {
        pub const Snapshot = struct {
            reserved: usize,
            connected: usize,
        };

        pub fn snapshot(listener: EndpointListener) Snapshot {
            listener.state.lock();
            defer listener.state.unlock();
            var reserved: usize = 0;
            var connected: usize = 0;
            for (listener.state.connections) |slot| {
                reserved += @intFromBool(slot.reserved);
                connected += @intFromBool(slot.connection != null);
            }
            return .{ .reserved = reserved, .connected = connected };
        }
    };

    fn init(
        allocator: std.mem.Allocator,
        listener: OwnedListener,
        options: Options,
    ) Error!EndpointListener {
        var owned_listener = listener;
        var listener_owned = true;
        errdefer if (listener_owned) owned_listener.deinit();
        try options.validate();
        const state = try allocator.create(State);
        var state_owned = true;
        errdefer if (state_owned) allocator.destroy(state);
        const connections = try allocator.alloc(
            ConnectionSlot,
            options.max_connections,
        );
        var connections_owned = true;
        errdefer if (connections_owned) allocator.free(connections);
        const requests = try allocator.alloc(
            ?QueuedRequest,
            options.max_pending_requests,
        );
        var requests_owned = true;
        errdefer if (requests_owned) allocator.free(requests);
        @memset(connections, .{});
        @memset(requests, null);
        state.* = .{
            .allocator = allocator,
            .io = owned_listener.io(),
            .options = options,
            .listener = owned_listener,
            .connections = connections,
            .requests = requests,
        };
        listener_owned = false;
        state_owned = false;
        connections_owned = false;
        requests_owned = false;
        var started: usize = 0;
        errdefer {
            state.stop();
            state.release();
        }
        while (started < options.accept_workers) : (started += 1) {
            try state.group.concurrent(state.io, acceptLoop, .{state});
        }
        return .{ .state = state };
    }

    /// Takes ownership of an already listening cleartext HTTP/2 server.
    pub fn initServer(
        allocator: std.mem.Allocator,
        listener: http2.runtime.Server,
        options: Options,
    ) Error!EndpointListener {
        return init(allocator, .{ .cleartext = listener }, options);
    }

    /// Takes ownership of an already listening TLS HTTP/2 server.
    pub fn initTlsServer(
        allocator: std.mem.Allocator,
        listener: http2.runtime.TlsServer,
        options: Options,
    ) Error!EndpointListener {
        return init(allocator, .{ .tls = listener }, options);
    }

    pub fn address(self: EndpointListener) std.Io.net.IpAddress {
        return self.state.listener.address();
    }

    pub fn receiveRequestWithDeadline(
        self: EndpointListener,
        deadline: std.Io.Clock.Timestamp,
    ) Error!PendingRequest {
        self.state.retain();
        errdefer self.state.release();
        const queued = try self.state.takeRequest(deadline);
        return .{
            .state = self.state,
            .connection_handle = queued.connection_handle,
            .connection = queued.connection,
            .request = queued.request,
        };
    }

    pub fn receiveRequestWithTimeout(
        self: EndpointListener,
        timeout: std.Io.Duration,
    ) Error!PendingRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestWithDeadline(.fromNow(
            self.state.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn acquire(
        self: EndpointListener,
        handle: Handle,
        deadline: std.Io.Clock.Timestamp,
    ) Error!*ManagedConnection {
        self.state.retain();
        defer self.state.release();
        return self.state.acquireConnection(handle.connection, deadline);
    }

    pub fn sendDatagramWithDeadline(self: EndpointListener, handle: Handle, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.sendDatagramWithDeadline(handle.session, data, deadline);
    }
    pub fn sendDatagramWithTimeout(self: EndpointListener, handle: Handle, data: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(handle, data, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn receiveWithDeadline(self: EndpointListener, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!Event {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.receiveWithDeadline(handle.session, deadline);
    }
    pub fn receiveWithTimeout(self: EndpointListener, handle: Handle, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn closeWithDeadline(self: EndpointListener, handle: Handle, code: u32, reason: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.closeWithDeadline(handle.session, code, reason, deadline);
    }
    pub fn closeWithTimeout(self: EndpointListener, handle: Handle, code: u32, reason: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(handle, code, reason, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn removeWithDeadline(self: EndpointListener, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!bool {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.removeWithDeadline(handle.session, deadline);
    }
    pub fn removeWithTimeout(self: EndpointListener, handle: Handle, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.removeWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn openStreamWithDeadline(self: EndpointListener, handle: Handle, direction: h2_state.Direction, deadline: std.Io.Clock.Timestamp) Error!u62 {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.openStreamWithDeadline(handle.session, direction, deadline);
    }
    pub fn openStreamWithTimeout(self: EndpointListener, handle: Handle, direction: h2_state.Direction, timeout: std.Io.Duration) Error!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openStreamWithDeadline(handle, direction, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn sendStreamWithDeadline(self: EndpointListener, handle: Handle, id: u62, data: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.sendStreamWithDeadline(handle.session, id, data, fin, deadline);
    }
    pub fn sendStreamWithTimeout(self: EndpointListener, handle: Handle, id: u62, data: []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(handle, id, data, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn sendStreamSlicesWithDeadline(self: EndpointListener, handle: Handle, id: u62, slices: []const []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.sendStreamSlicesWithDeadline(handle.session, id, slices, fin, deadline);
    }
    pub fn sendStreamSlicesWithTimeout(self: EndpointListener, handle: Handle, id: u62, slices: []const []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(handle, id, slices, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn consumeWithDeadline(self: EndpointListener, handle: Handle, id: u62, bytes: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.consumeWithDeadline(handle.session, id, bytes, deadline);
    }
    pub fn consumeWithTimeout(self: EndpointListener, handle: Handle, id: u62, bytes: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.consumeWithDeadline(handle, id, bytes, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn retireStreamWithDeadline(self: EndpointListener, handle: Handle, id: u62, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.retireStreamWithDeadline(handle.session, id, deadline);
    }
    pub fn retireStreamWithTimeout(self: EndpointListener, handle: Handle, id: u62, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.retireStreamWithDeadline(handle, id, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn resetStreamWithDeadline(self: EndpointListener, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.resetStreamWithDeadline(handle.session, id, code, deadline);
    }
    pub fn resetStreamWithTimeout(self: EndpointListener, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn stopSendingWithDeadline(self: EndpointListener, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.stopSendingWithDeadline(handle.session, id, code, deadline);
    }
    pub fn stopSendingWithTimeout(self: EndpointListener, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopSendingWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantDataWithDeadline(self: EndpointListener, handle: Handle, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.grantDataWithDeadline(handle.session, limit, deadline);
    }
    pub fn grantDataWithTimeout(self: EndpointListener, handle: Handle, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantDataWithDeadline(handle, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamsWithDeadline(self: EndpointListener, handle: Handle, direction: h2_state.Direction, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.grantStreamsWithDeadline(handle.session, direction, limit, deadline);
    }
    pub fn grantStreamsWithTimeout(self: EndpointListener, handle: Handle, direction: h2_state.Direction, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamsWithDeadline(handle, direction, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamDataWithDeadline(self: EndpointListener, handle: Handle, id: u62, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.grantStreamDataWithDeadline(handle.session, id, limit, deadline);
    }
    pub fn grantStreamDataWithTimeout(self: EndpointListener, handle: Handle, id: u62, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamDataWithDeadline(handle, id, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn drainWithDeadline(self: EndpointListener, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!void {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.drainWithDeadline(handle.session, deadline);
    }
    pub fn drainWithTimeout(self: EndpointListener, handle: Handle, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn exportKeyingMaterialWithDeadline(self: EndpointListener, handle: Handle, label: []const u8, context: []const u8, length: usize, deadline: std.Io.Clock.Timestamp) Error!KeyingMaterial {
        const connection = try self.acquire(handle, deadline);
        defer connection.release();
        return connection.server.exportKeyingMaterialWithDeadline(handle.session, label, context, length, deadline);
    }
    pub fn exportKeyingMaterialWithTimeout(self: EndpointListener, handle: Handle, label: []const u8, context: []const u8, length: usize, timeout: std.Io.Duration) Error!KeyingMaterial {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.exportKeyingMaterialWithDeadline(handle, label, context, length, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn deinit(self: *EndpointListener) void {
        const state = self.state;
        state.stop();
        state.release();
        self.* = undefined;
    }
};

test {
    _ = core;
    _ = @import("tests.zig");
}

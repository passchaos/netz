//! Connection-owning background client for multiplexed HTTP/2 WebTransport.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const h2_state = @import("state.zig");
const session_mod = @import("session.zig");
const runtime = @import("runtime.zig");
const job_mod = @import("endpoint_client/job.zig");

pub const Handle = job_mod.Handle;
pub const Event = job_mod.Event;
pub const KeyingMaterial = job_mod.Bytes;
pub const Accepted = job_mod.Accepted;
pub const Error = runtime.Error || http2.socks5_runtime.Error || error{ EndpointClosed, EndpointCapacity, EndpointQueueFull, StaleSession, InvalidEndpointOptions };

pub const Options = struct {
    max_sessions: usize = 64,
    max_queued_commands: usize = 256,
    operation_timeout: std.Io.Duration = .fromSeconds(20),

    pub fn validate(self: Options) Error!void {
        if (self.max_sessions == 0 or self.max_sessions > std.math.maxInt(u32) or self.max_queued_commands == 0 or self.operation_timeout.nanoseconds <= 0) return error.InvalidEndpointOptions;
    }
};

pub const ConnectAttempt = struct {
    accepted_session: ?Accepted = null,
    rejection: ?runtime.Rejection = null,
    state: ?*State = null,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.accepted_session != null;
    }
    pub fn status(self: ConnectAttempt) u16 {
        return if (self.accepted_session) |value| value.status else self.rejection.?.status();
    }
    pub fn responseHeader(self: ConnectAttempt, name: []const u8) ?[]const u8 {
        if (self.accepted_session) |value| return value.responseHeader(name);
        return self.rejection.?.responseHeader(name);
    }
    pub fn body(self: ConnectAttempt) []const u8 {
        return if (self.rejection) |rejection| rejection.body() else &.{};
    }
    pub fn trailers(self: ConnectAttempt) []const http2.Hpack.HeaderField {
        return if (self.rejection) |rejection| rejection.trailers() else &.{};
    }
    pub fn requireAccepted(self: *ConnectAttempt) Error!Accepted {
        const value = self.accepted_session orelse return error.SessionRejected;
        const state = self.state.?;
        self.* = undefined;
        state.release();
        return value;
    }
    pub fn deinit(self: *ConnectAttempt) void {
        if (self.accepted_session) |*value| {
            if (self.state) |state| {
                @import("endpoint_client/cleanup.zig").request(state, value.handle);
            }
            value.deinit();
        }
        if (self.rejection) |*rejection| rejection.deinit();
        if (self.state) |state| state.release();
        self.* = undefined;
    }
};

const Slot = struct {
    generation: u64 = 1,
    session: ?session_mod.Session = null,
    failure: ?anyerror = null,
    cleanup: @import("endpoint_client/cleanup.zig").Request = .{},

    pub fn occupied(self: Slot) bool {
        return self.session != null or self.failure != null;
    }
};

const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    options: Options,
    refs: std.atomic.Value(usize) = .init(1),
    mutex: std.Io.Mutex = .init,
    group: std.Io.Group = .init,
    wake: std.Io.Event = .unset,
    connection: http2.runtime.Connection,
    slots: []Slot,
    active_sessions: usize = 0,
    head: ?*Job = null,
    tail: ?*Job = null,
    queued: usize = 0,
    closed: bool = false,
    worker_stopped: bool = false,
    abortive_shutdown: std.atomic.Value(bool) = .init(false),
    cleanup_pending: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,
    failure_code: std.atomic.Value(u16) = .init(0),

    pub const Job = job_mod.Job(State);
    const Worker = @import("endpoint_client/worker.zig").Worker(State);

    pub fn retain(self: *State) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }

    pub fn release(self: *State) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        std.debug.assert(self.closed and self.worker_stopped and self.head == null);
        self.allocator.free(self.slots);
        self.allocator.destroy(self);
    }

    pub fn lock(self: *State) void {
        self.mutex.lockUncancelable(self.io);
    }

    pub fn unlock(self: *State) void {
        self.mutex.unlock(self.io);
    }

    fn finishLocked(self: *State, job: *Job, err: ?anyerror) bool {
        job.err = if (self.closed and err != null) error.EndpointClosed else err;
        const delivered = job.completion.cmpxchgStrong(.waiting, .completed, .release, .acquire) == null;
        if (delivered) {
            job.done.set(self.io);
        }
        job.release();
        return delivered;
    }

    pub fn finish(self: *State, job: *Job, err: ?anyerror) bool {
        self.lock();
        const delivered = self.finishLocked(job, err);
        self.unlock();
        return delivered;
    }

    fn enqueue(self: *State, job: *Job) Error!void {
        return @import("endpoint/queue.zig").enqueue(self, job, .{}) catch |err| return @errorCast(err);
    }
    pub fn claim(self: *State) ?*Job {
        self.lock();
        defer self.unlock();
        const job = self.head orelse return null;
        self.head = job.next;
        if (self.head == null) self.tail = null;
        job.next = null;
        self.queued -= 1;
        return job;
    }

    fn await(self: *State, job: *Job) Error!void {
        while (true) {
            job.done.waitTimeout(self.io, .{ .deadline = job.deadline }) catch |err| {
                if (err == error.Timeout and job.deadline.durationFromNow(self.io).raw.nanoseconds > 0) continue;
                if (!job.abandon()) break;
                self.wake.set(self.io);
                return err;
            };
            break;
        }
        if (job.err) |err| return @errorCast(err);
    }

    fn close(self: *State) void {
        self.lock();
        defer self.unlock();
        if (self.closed) return;
        self.closed = true;
        while (self.head) |job| {
            self.head = job.next;
            if (self.head == null) self.tail = null;
            self.queued -= 1;
            _ = self.finishLocked(job, error.EndpointClosed);
        }
        self.wake.set(self.io);
    }

    pub fn session(self: *State, handle: Handle) Error!*session_mod.Session {
        if (handle.index >= self.slots.len) return error.StaleSession;
        const slot = &self.slots[handle.index];
        if (slot.generation != handle.generation) return error.StaleSession;
        if (slot.failure) |failure| return @errorCast(failure);
        return if (slot.session) |*value| value else error.StaleSession;
    }

    pub fn workerStopped(self: *State, terminal: ?anyerror) void {
        self.lock();
        defer self.unlock();
        if (!self.closed) if (terminal) |failure| {
            self.failure = failure;
            self.failure_code.store(@intFromError(failure), .release);
        };
        while (self.head) |job| {
            self.head = job.next;
            if (self.head == null) self.tail = null;
            self.queued -= 1;
            _ = self.finishLocked(job, terminal orelse error.EndpointClosed);
        }
        self.worker_stopped = true;
        self.wake.set(self.io);
    }
};

pub const EndpointClient = struct {
    state: *State,

    /// Authenticated TLS metadata for the connection owning this endpoint.
    /// These values are fixed at handshake completion; cleartext transports
    /// return null. Call while the endpoint is live and not concurrently with
    /// shutdown, which retires the owned connection.
    pub fn peerCertificates(self: EndpointClient) ?[]const []const u8 {
        return self.state.connection.peerCertificates();
    }
    pub fn negotiatedAlpn(self: EndpointClient) ?[]const u8 {
        return self.state.connection.negotiatedAlpn();
    }
    pub fn negotiatedCipherSuite(
        self: EndpointClient,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.state.connection.negotiatedCipherSuite();
    }
    pub fn negotiatedTranscriptHash(
        self: EndpointClient,
    ) ?tls_stream.TranscriptHash {
        return self.state.connection.negotiatedTranscriptHash();
    }
    /// TLS version of the endpoint's HTTP/2 transport. Cleartext returns null.
    pub fn negotiatedTlsProtocol(
        self: EndpointClient,
    ) ?tls_stream.Protocol {
        return self.state.connection.negotiatedTlsProtocol();
    }
    pub fn wasTlsSessionResumed(self: EndpointClient) ?bool {
        return self.state.connection.wasTlsSessionResumed();
    }
    /// Start a TLS 1.3 traffic-key update on the endpoint's HTTP/2
    /// connection. The rotation is connection-wide and therefore shared by
    /// every multiplexed session; cleartext transports return
    /// `error.PostHandshakeTlsUnavailable`.
    pub fn initiateKeyUpdate(self: EndpointClient) Error!void {
        try self.state.connection.updateTrafficKeys(false);
    }
    /// Locally initiated TLS 1.3 key updates on the endpoint connection.
    /// Cleartext transports report 0.
    pub fn localKeyUpdateCount(self: EndpointClient) u64 {
        const counts = self.state.connection.keyUpdateCounts() orelse return 0;
        return counts.sent;
    }
    /// Peer-initiated TLS 1.3 key updates observed on the endpoint
    /// connection. Cleartext transports report 0.
    pub fn peerKeyUpdateCount(self: EndpointClient) u64 {
        const counts = self.state.connection.keyUpdateCounts() orelse return 0;
        return counts.received;
    }

    /// Takes ownership of an already negotiated HTTP/2 connection.
    pub fn init(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options) Error!EndpointClient {
        return initUntil(allocator, connection_value, options, null);
    }

    /// Transfer ownership on entry and bound owner admission by the original
    /// deadline. Failed or late construction closes the unpublished transport
    /// without TLS shutdown output or an additional cleanup budget.
    pub fn initWithDeadline(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointClient {
        return initUntil(allocator, connection_value, options, deadline);
    }

    /// Relative-timeout counterpart to `initWithDeadline`. A non-positive
    /// duration closes the transferred connection without TLS shutdown output
    /// and returns `Timeout`.
    pub fn initWithTimeout(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options, timeout: std.Io.Duration) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) {
            var connection = connection_value;
            connection.closeWithoutCloseNotify();
            return error.Timeout;
        }
        return initWithDeadline(
            allocator,
            connection_value,
            options,
            .fromNow(connection_value.io, .{
                .raw = timeout,
                .clock = .awake,
            }),
        );
    }

    fn initUntil(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options, deadline: ?std.Io.Clock.Timestamp) Error!EndpointClient {
        return @import("endpoint_client/init.zig").create(EndpointClient, State, Slot, State.Worker.run, allocator, connection_value, options, deadline);
    }

    pub fn connectAddressWithDeadline(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, limits: http2.runtime.Limits, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointClient {
        try options.validate();
        const connection = try http2.runtime.Client.connectWithDeadline(allocator, io, address, limits, deadline);
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn connectAddressWithTimeout(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, limits: http2.runtime.Limits, options: Options, timeout: std.Io.Duration) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectAddressWithDeadline(allocator, io, address, limits, options, .fromNow(io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn connectHostWithDeadline(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, limits: http2.runtime.Limits, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointClient {
        try options.validate();
        const connection = try http2.runtime.Client.connectHostWithDeadline(allocator, io, host, port, limits, deadline);
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn connectHostWithTimeout(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, limits: http2.runtime.Limits, options: Options, timeout: std.Io.Duration) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(allocator, io, host, port, limits, options, .fromNow(io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn connectTlsAddressWithDeadline(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, tls_host: []const u8, authority: []const u8, limits: http2.runtime.Limits, tls_options: http2.runtime.TlsConnectOptions, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointClient {
        try options.validate();
        const connection = try http2.runtime.Client.connectTlsAddressWithDeadline(allocator, io, address, tls_host, authority, limits, tls_options, deadline);
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn connectTlsAddressWithTimeout(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, tls_host: []const u8, authority: []const u8, limits: http2.runtime.Limits, tls_options: http2.runtime.TlsConnectOptions, options: Options, timeout: std.Io.Duration) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsAddressWithDeadline(allocator, io, address, tls_host, authority, limits, tls_options, options, .fromNow(io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn connectTlsHostWithDeadline(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, limits: http2.runtime.Limits, tls_options: http2.runtime.TlsConnectOptions, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointClient {
        try options.validate();
        const connection = try http2.runtime.Client.connectTlsHostWithDeadline(allocator, io, host, port, limits, tls_options, deadline);
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn connectTlsHostWithTimeout(allocator: std.mem.Allocator, io: std.Io, host: []const u8, port: u16, limits: http2.runtime.Limits, tls_options: http2.runtime.TlsConnectOptions, options: Options, timeout: std.Io.Duration) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostWithDeadline(allocator, io, host, port, limits, tls_options, options, .fromNow(io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn connectTlsHostViaProxyWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        proxy: http2.runtime.HttpConnectProxy,
        limits: http2.runtime.Limits,
        tls_options: http2.runtime.TlsConnectOptions,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!EndpointClient {
        try options.validate();
        const connection = try http2.runtime.Client
            .connectTlsHostViaProxyWithDeadline(
            allocator,
            io,
            host,
            port,
            proxy,
            limits,
            tls_options,
            deadline,
        );
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn connectTlsHostViaProxyWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        host: []const u8,
        port: u16,
        proxy: http2.runtime.HttpConnectProxy,
        limits: http2.runtime.Limits,
        tls_options: http2.runtime.TlsConnectOptions,
        options: Options,
        timeout: std.Io.Duration,
    ) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostViaProxyWithDeadline(
            allocator,
            io,
            host,
            port,
            proxy,
            limits,
            tls_options,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }
    pub fn connectTlsHostViaSocks5WithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: http2.socks5_runtime.Proxy,
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits,
        tls_options: http2.runtime.TlsConnectOptions,
        options: Options,
        deadline: std.Io.Clock.Timestamp,
    ) Error!EndpointClient {
        try options.validate();
        const connection = try http2.socks5_runtime.Client
            .connectTlsHostWithDeadline(
            allocator,
            io,
            proxy,
            host,
            port,
            limits,
            tls_options,
            deadline,
        );
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn connectTlsHostViaSocks5WithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        proxy: http2.socks5_runtime.Proxy,
        host: []const u8,
        port: u16,
        limits: http2.runtime.Limits,
        tls_options: http2.runtime.TlsConnectOptions,
        options: Options,
        timeout: std.Io.Duration,
    ) Error!EndpointClient {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectTlsHostViaSocks5WithDeadline(
            allocator,
            io,
            proxy,
            host,
            port,
            limits,
            tls_options,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    fn submit(self: EndpointClient, operation: job_mod.Command, deadline: std.Io.Clock.Timestamp) Error!*State.Job {
        if (deadline.clock != .awake or deadline.durationFromNow(self.state.io).raw.nanoseconds <= 0) return error.Timeout;
        try self.state.io.checkCancel();
        const job = try State.Job.create(self.state, operation, deadline);
        errdefer job.release();
        try self.state.enqueue(job);
        try self.state.await(job);
        return job;
    }

    pub fn connectAttemptWithDeadline(self: EndpointClient, options: runtime.ClientOptions, deadline: std.Io.Clock.Timestamp) Error!ConnectAttempt {
        const job = try self.submit(.{ .connect = options }, deadline);
        defer job.release();
        if (job.accepted != null) {
            self.state.retain();
            return .{ .accepted_session = job.takeAccepted(), .state = self.state };
        }
        return .{ .rejection = job.takeRejection() };
    }

    pub fn connectAttemptWithTimeout(self: EndpointClient, options: runtime.ClientOptions, timeout: std.Io.Duration) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectAttemptWithDeadline(options, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn connectWithDeadline(self: EndpointClient, options: runtime.ClientOptions, deadline: std.Io.Clock.Timestamp) Error!Handle {
        var attempt = try self.connectAttemptWithDeadline(options, deadline);
        errdefer attempt.deinit();
        var accepted = try attempt.requireAccepted();
        defer accepted.deinit();
        return accepted.handle;
    }

    pub fn connectWithTimeout(self: EndpointClient, options: runtime.ClientOptions, timeout: std.Io.Duration) Error!Handle {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(options, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn command(self: EndpointClient, value: job_mod.Command, deadline: std.Io.Clock.Timestamp) Error!void {
        const job = try self.submit(value, deadline);
        job.release();
    }

    pub fn sendDatagramWithDeadline(self: EndpointClient, handle: Handle, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .send_datagram = .{ .handle = handle, .data = data } }, deadline);
    }
    pub fn sendDatagramWithTimeout(self: EndpointClient, handle: Handle, data: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(handle, data, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn receiveWithDeadline(self: EndpointClient, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!Event {
        const job = try self.submit(.{ .receive = handle }, deadline);
        defer job.release();
        return job.takeEvent();
    }
    pub fn receiveWithTimeout(self: EndpointClient, handle: Handle, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn closeWithDeadline(self: EndpointClient, handle: Handle, code: u32, reason: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .close = .{ .handle = handle, .code = code, .reason = reason } }, deadline);
    }
    pub fn closeWithTimeout(self: EndpointClient, handle: Handle, code: u32, reason: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(handle, code, reason, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn removeWithDeadline(self: EndpointClient, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!bool {
        const job = try self.submit(.{ .remove = handle }, deadline);
        defer job.release();
        return job.removed.?;
    }
    pub fn removeWithTimeout(self: EndpointClient, handle: Handle, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.removeWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn openStreamWithDeadline(self: EndpointClient, handle: Handle, direction: h2_state.Direction, deadline: std.Io.Clock.Timestamp) Error!u62 {
        const job = try self.submit(.{ .open_stream = .{ .handle = handle, .direction = direction } }, deadline);
        defer job.release();
        return job.stream_id.?;
    }
    pub fn openStreamWithTimeout(self: EndpointClient, handle: Handle, direction: h2_state.Direction, timeout: std.Io.Duration) Error!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openStreamWithDeadline(handle, direction, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn sendStreamWithDeadline(self: EndpointClient, handle: Handle, id: u62, data: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .send_stream = .{ .handle = handle, .id = id, .data = data, .fin = fin } }, deadline);
    }
    pub fn sendStreamWithTimeout(self: EndpointClient, handle: Handle, id: u62, data: []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(handle, id, data, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Stage multiple payload slices into one command buffer. The command
    /// queue duplicates its input, so the caller's slices only need to remain
    /// valid for this call.
    pub fn sendStreamSlicesWithDeadline(self: EndpointClient, handle: Handle, id: u62, slices: []const []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        var total: usize = 0;
        for (slices) |slice| total = std.math.add(usize, total, slice.len) catch return error.CapsuleTooLarge;
        const data = try self.state.allocator.alloc(u8, total);
        defer self.state.allocator.free(data);
        var offset: usize = 0;
        for (slices) |slice| {
            @memcpy(data[offset..][0..slice.len], slice);
            offset += slice.len;
        }
        return self.sendStreamWithDeadline(handle, id, data, fin, deadline);
    }
    pub fn sendStreamSlicesWithTimeout(self: EndpointClient, handle: Handle, id: u62, slices: []const []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(handle, id, slices, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn consumeWithDeadline(self: EndpointClient, handle: Handle, id: u62, bytes: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .consume = .{ .handle = handle, .id = id, .bytes = bytes } }, deadline);
    }
    pub fn consumeWithTimeout(self: EndpointClient, handle: Handle, id: u62, bytes: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.consumeWithDeadline(handle, id, bytes, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn retireStreamWithDeadline(self: EndpointClient, handle: Handle, id: u62, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .retire_stream = .{ .handle = handle, .id = id } }, deadline);
    }
    pub fn retireStreamWithTimeout(self: EndpointClient, handle: Handle, id: u62, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.retireStreamWithDeadline(handle, id, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn resetStreamWithDeadline(self: EndpointClient, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .reset_stream = .{ .handle = handle, .id = id, .code = code } }, deadline);
    }
    pub fn resetStreamWithTimeout(self: EndpointClient, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn stopSendingWithDeadline(self: EndpointClient, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .stop_sending = .{ .handle = handle, .id = id, .code = code } }, deadline);
    }
    pub fn stopSendingWithTimeout(self: EndpointClient, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopSendingWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantDataWithDeadline(self: EndpointClient, handle: Handle, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .grant_data = .{ .handle = handle, .limit = limit } }, deadline);
    }
    pub fn grantDataWithTimeout(self: EndpointClient, handle: Handle, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantDataWithDeadline(handle, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamsWithDeadline(self: EndpointClient, handle: Handle, direction: h2_state.Direction, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .grant_streams = .{ .handle = handle, .direction = direction, .limit = limit } }, deadline);
    }
    pub fn grantStreamsWithTimeout(self: EndpointClient, handle: Handle, direction: h2_state.Direction, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamsWithDeadline(handle, direction, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamDataWithDeadline(self: EndpointClient, handle: Handle, id: u62, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .grant_stream_data = .{ .handle = handle, .id = id, .limit = limit } }, deadline);
    }
    pub fn grantStreamDataWithTimeout(self: EndpointClient, handle: Handle, id: u62, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamDataWithDeadline(handle, id, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn drainWithDeadline(self: EndpointClient, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .drain = handle }, deadline);
    }
    pub fn drainWithTimeout(self: EndpointClient, handle: Handle, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn exportKeyingMaterialWithDeadline(self: EndpointClient, handle: Handle, label: []const u8, context: []const u8, length: usize, deadline: std.Io.Clock.Timestamp) Error!KeyingMaterial {
        const job = try self.submit(.{ .export_keying_material = .{ .handle = handle, .label = label, .context = context, .length = length } }, deadline);
        defer job.release();
        return job.takeBytes();
    }
    pub fn exportKeyingMaterialWithTimeout(self: EndpointClient, handle: Handle, label: []const u8, context: []const u8, length: usize, timeout: std.Io.Duration) Error!KeyingMaterial {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.exportKeyingMaterialWithDeadline(handle, label, context, length, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Return the transport-owning worker's terminal failure, if any. A
    /// reconnecting owner uses this only to retire the complete connection
    /// generation; stream-local failures remain scoped to their Session.
    pub fn terminalFailure(self: EndpointClient) ?anyerror {
        const code = self.state.failure_code.load(.acquire);
        return if (code == 0) null else @errorFromInt(code);
    }

    /// Request endpoint shutdown without releasing this owner. Retained
    /// results may still release their state after observing EndpointClosed.
    pub fn requestShutdown(self: EndpointClient) void {
        self.state.close();
    }

    pub fn requestShutdownAbortive(self: EndpointClient) void {
        self.state.abortive_shutdown.store(true, .release);
        self.state.wake.set(self.state.io);
    }

    pub fn deinit(self: *EndpointClient) void {
        const state = self.state;
        state.close();
        state.group.cancel(state.io);
        state.release();
        self.* = undefined;
    }

    /// Stop the owner and release its transport without further protocol
    /// output. Used for a candidate whose initialization/publication failed.
    pub fn deinitAbortive(self: *EndpointClient) void {
        self.requestShutdownAbortive();
        self.deinit();
    }
};

test {
    _ = @import("endpoint_client/tests.zig");
    _ = @import("endpoint_client/admission_tests.zig");
    _ = @import("endpoint_client/job_tests.zig");
    _ = @import("endpoint_client/preparation_tests.zig");
    _ = @import("endpoint_client/cleanup_tests.zig");
}

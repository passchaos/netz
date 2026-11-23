//! Connection-owning background server for multiplexed HTTP/2 WebTransport.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const h2_state = @import("state.zig");
const session_mod = @import("session.zig");
const runtime = @import("runtime.zig");
const job_mod = @import("endpoint_server/job.zig");
const waiters = @import("endpoint_server/waiters.zig");

pub const Handle = job_mod.Handle;
pub const PendingHandle = job_mod.PendingHandle;
pub const Event = job_mod.Event;
pub const KeyingMaterial = job_mod.Bytes;
pub const Accepted = job_mod.Accepted;
pub const Error = runtime.Error || error{ EndpointClosed, EndpointCapacity, PendingCapacity, RequestWaiterCapacity, EndpointQueueFull, StaleSession, StalePendingSession, InvalidEndpointOptions };

pub const Options = struct {
    max_sessions: usize = 64,
    max_pending_sessions: usize = 64,
    max_queued_commands: usize = 256,
    /// Includes queued and already waiting receiveRequest operations.
    max_request_waiters: usize = 64,
    operation_timeout: std.Io.Duration = .fromSeconds(20),

    pub fn validate(self: Options) Error!void {
        if (self.max_sessions == 0 or self.max_sessions > std.math.maxInt(u32) or self.max_pending_sessions == 0 or self.max_pending_sessions > std.math.maxInt(u32) or self.max_queued_commands == 0 or self.max_request_waiters == 0 or self.operation_timeout.nanoseconds <= 0) return error.InvalidEndpointOptions;
    }
};

const PendingSlot = struct {
    generation: u64 = 1,
    request: ?runtime.PendingDuplexSession = null,
    claimed: bool = false,
    sequence: u64 = 0,
    cleanup: @import("endpoint/cleanup_request.zig").Request = .{},
};

const SessionSlot = struct {
    generation: u64 = 1,
    session: ?session_mod.Session = null,
    failure: ?anyerror = null,
    pub fn occupied(self: SessionSlot) bool {
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
    pending: []PendingSlot,
    sessions: []SessionSlot,
    pending_count: usize = 0,
    session_count: usize = 0,
    next_sequence: u64 = 1,
    pending_input_blocked: bool = false,
    head: ?*Job = null,
    tail: ?*Job = null,
    receive_head: ?*Job = null,
    receive_tail: ?*Job = null,
    queued: usize = 0,
    waiting_requests: usize = 0,
    cleanup_pending: std.atomic.Value(bool) = .init(false),
    closed: bool = false,
    worker_stopped: bool = false,
    abortive_shutdown: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    pub const Job = job_mod.Job(State);
    const Worker = @import("endpoint_server/worker.zig").Worker(State);

    pub fn retain(self: *State) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *State) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        std.debug.assert(self.closed and self.worker_stopped and self.head == null and self.receive_head == null);
        self.allocator.free(self.pending);
        self.allocator.free(self.sessions);
        self.allocator.destroy(self);
    }
    pub fn lock(self: *State) void {
        self.mutex.lockUncancelable(self.io);
    }
    pub fn unlock(self: *State) void {
        self.mutex.unlock(self.io);
    }

    fn finishLocked(self: *State, job: *Job, err: ?anyerror) bool {
        waiters.complete(self, job);
        job.err = if (self.closed and err != null) error.EndpointClosed else err;
        const delivered = job.completion.cmpxchgStrong(.waiting, .completed, .release, .acquire) == null;
        if (delivered) job.done.set(self.io);
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
        return @import("endpoint/queue.zig").enqueue(self, job, .{ .prepare = pruneWaitersLocked, .admit = admitWaiterLocked }) catch |err| return @errorCast(err);
    }

    fn pruneWaitersLocked(self: *State) void {
        waiters.prune(self, finishLocked);
    }

    fn admitWaiterLocked(self: *State, job: *Job) error{RequestWaiterCapacity}!void {
        return waiters.reserve(self, job);
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
        while (self.receive_head) |job| {
            self.receive_head = job.next;
            if (self.receive_head == null) self.receive_tail = null;
            _ = self.finishLocked(job, error.EndpointClosed);
        }
        self.wake.set(self.io);
    }
    pub fn workerStopped(self: *State, terminal: ?anyerror) void {
        self.lock();
        defer self.unlock();
        if (!self.closed and terminal != null) self.failure = terminal;
        while (self.head) |job| {
            self.head = job.next;
            if (self.head == null) self.tail = null;
            self.queued -= 1;
            _ = self.finishLocked(job, terminal orelse error.EndpointClosed);
        }
        while (self.receive_head) |job| {
            self.receive_head = job.next;
            if (self.receive_head == null) self.receive_tail = null;
            _ = self.finishLocked(job, terminal orelse error.EndpointClosed);
        }
        self.worker_stopped = true;
        self.wake.set(self.io);
    }
    pub fn request(self: *State, handle: PendingHandle) Error!*runtime.PendingDuplexSession {
        if (handle.index >= self.pending.len) return error.StalePendingSession;
        const slot = &self.pending[handle.index];
        if (slot.generation != handle.generation) return error.StalePendingSession;
        return if (slot.request) |*value| value else error.StalePendingSession;
    }
    pub fn session(self: *State, handle: Handle) Error!*session_mod.Session {
        if (handle.index >= self.sessions.len) return error.StaleSession;
        const slot = &self.sessions[handle.index];
        if (slot.generation != handle.generation) return error.StaleSession;
        if (slot.failure) |failure| return @errorCast(failure);
        return if (slot.session) |*value| value else error.StaleSession;
    }
    pub fn waitForRequest(self: *State, job: *Job) void {
        self.lock();
        defer self.unlock();
        std.debug.assert(job.waiting_request);
        if (self.closed) {
            _ = self.finishLocked(job, error.EndpointClosed);
            return;
        }
        job.checkExecution(self.io) catch |err| {
            _ = self.finishLocked(job, err);
            return;
        };
        job.next = null;
        if (self.receive_tail) |tail| tail.next = job else self.receive_head = job;
        self.receive_tail = job;
    }
    pub fn takeRequestWaiter(self: *State) ?*Job {
        self.lock();
        defer self.unlock();
        while (self.receive_head) |job| {
            self.receive_head = job.next;
            if (self.receive_head == null) self.receive_tail = null;
            job.next = null;
            job.checkExecution(self.io) catch |err| {
                _ = self.finishLocked(job, err);
                continue;
            };
            return job;
        }
        return null;
    }
    pub fn nextRequestDeadline(self: *State) ?std.Io.Clock.Timestamp {
        self.lock();
        defer self.unlock();
        var result: ?std.Io.Clock.Timestamp = null;
        var cursor = self.receive_head;
        while (cursor) |job| : (cursor = job.next) {
            if (job.canceled()) return .{ .clock = .awake, .raw = std.Io.Clock.awake.now(self.io) };
            if (result == null or std.Io.Clock.Timestamp.compare(job.deadline, .lt, result.?)) result = job.deadline;
        }
        return result;
    }
};

pub const PendingRequest = struct {
    state: *State,
    data: job_mod.RequestData,

    pub fn handle(self: PendingRequest) PendingHandle {
        return self.data.handle;
    }
    pub fn path(self: PendingRequest) []const u8 {
        return self.data.path;
    }
    pub fn authority(self: PendingRequest) ?[]const u8 {
        return self.data.authority;
    }
    pub fn origin(self: PendingRequest) ?[]const u8 {
        return self.data.origin;
    }
    pub fn headers(self: PendingRequest) []const http2.Hpack.HeaderField {
        return self.data.headers;
    }
    pub fn header(self: PendingRequest, name: []const u8) ?[]const u8 {
        return self.data.header(name);
    }
    /// Authenticated TLS metadata for the connection carrying this request.
    pub fn peerCertificates(self: PendingRequest) ?[]const []const u8 {
        return self.state.connection.peerCertificates();
    }
    pub fn negotiatedAlpn(self: PendingRequest) ?[]const u8 {
        return self.state.connection.negotiatedAlpn();
    }
    pub fn negotiatedCipherSuite(
        self: PendingRequest,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.state.connection.negotiatedCipherSuite();
    }
    pub fn negotiatedTranscriptHash(
        self: PendingRequest,
    ) ?tls_stream.TranscriptHash {
        return self.state.connection.negotiatedTranscriptHash();
    }

    pub fn acceptWithDeadline(self: *PendingRequest, options: runtime.ServerOptions, deadline: std.Io.Clock.Timestamp) Error!Accepted {
        const server = EndpointServer{ .state = self.state };
        const accepted = try server.acceptWithDeadline(self.data.handle, options, deadline);
        self.consume();
        return accepted;
    }
    pub fn acceptWithTimeout(self: *PendingRequest, options: runtime.ServerOptions, timeout: std.Io.Duration) Error!Accepted {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acceptWithDeadline(options, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn rejectWithDeadline(self: *PendingRequest, options: runtime.RejectOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        const server = EndpointServer{ .state = self.state };
        try server.rejectWithDeadline(self.data.handle, options, deadline);
        self.consume();
    }
    pub fn rejectWithTimeout(self: *PendingRequest, options: runtime.RejectOptions, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectWithDeadline(options, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    fn consume(self: *PendingRequest) void {
        const state = self.state;
        self.data.deinit();
        self.* = undefined;
        state.release();
    }
    pub fn deinit(self: *PendingRequest) void {
        const state = self.state;
        @import("endpoint_server/cleanup.zig").request(state, self.data.handle);
        self.data.deinit();
        self.* = undefined;
        state.release();
    }
};

pub const EndpointServer = struct {
    state: *State,

    /// Authenticated TLS metadata for the connection carrying this endpoint.
    /// Cleartext transports return null.
    pub fn peerCertificates(self: *const EndpointServer) ?[]const []const u8 {
        return self.state.connection.peerCertificates();
    }
    pub fn negotiatedAlpn(self: *const EndpointServer) ?[]const u8 {
        return self.state.connection.negotiatedAlpn();
    }
    pub fn negotiatedCipherSuite(
        self: *const EndpointServer,
    ) ?tls_stream.NegotiatedCipherSuite {
        return self.state.connection.negotiatedCipherSuite();
    }
    pub fn negotiatedTranscriptHash(
        self: *const EndpointServer,
    ) ?tls_stream.TranscriptHash {
        return self.state.connection.negotiatedTranscriptHash();
    }

    /// Takes ownership of an already negotiated server HTTP/2 connection.
    pub fn init(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options) Error!EndpointServer {
        return initUntil(allocator, connection_value, options, null);
    }

    /// Transfer ownership on entry, including timeout and cancellation. A
    /// failed or late owner is stopped without further protocol shutdown output.
    pub fn initWithDeadline(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointServer {
        return initUntil(allocator, connection_value, options, deadline);
    }

    /// Relative-timeout counterpart to `initWithDeadline`. A non-positive
    /// duration closes the transferred connection without TLS shutdown output
    /// and returns `Timeout`.
    pub fn initWithTimeout(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options, timeout: std.Io.Duration) Error!EndpointServer {
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

    fn initUntil(allocator: std.mem.Allocator, connection_value: http2.runtime.Connection, options: Options, deadline: ?std.Io.Clock.Timestamp) Error!EndpointServer {
        return @import("endpoint_server/init.zig").create(EndpointServer, State, PendingSlot, SessionSlot, State.Worker.run, allocator, connection_value, options, deadline);
    }
    pub fn acceptConnectionWithDeadline(allocator: std.mem.Allocator, listener: *http2.runtime.Server, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointServer {
        try options.validate();
        const connection = try listener.acceptWithDeadline(deadline);
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn acceptConnectionWithTimeout(allocator: std.mem.Allocator, listener: *http2.runtime.Server, options: Options, timeout: std.Io.Duration) Error!EndpointServer {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return acceptConnectionWithDeadline(allocator, listener, options, .fromNow(listener.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn acceptTlsConnectionWithDeadline(allocator: std.mem.Allocator, listener: *http2.runtime.TlsServer, options: Options, deadline: std.Io.Clock.Timestamp) Error!EndpointServer {
        try options.validate();
        const connection = try listener.acceptWithDeadline(deadline);
        return initWithDeadline(allocator, connection, options, deadline);
    }
    pub fn acceptTlsConnectionWithTimeout(allocator: std.mem.Allocator, listener: *http2.runtime.TlsServer, options: Options, timeout: std.Io.Duration) Error!EndpointServer {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return acceptTlsConnectionWithDeadline(allocator, listener, options, .fromNow(listener.io, .{ .raw = timeout, .clock = .awake }));
    }
    fn submit(self: EndpointServer, operation: job_mod.Command, deadline: std.Io.Clock.Timestamp) Error!*State.Job {
        if (deadline.clock != .awake or deadline.durationFromNow(self.state.io).raw.nanoseconds <= 0) return error.Timeout;
        try self.state.io.checkCancel();
        const job = try State.Job.create(self.state, operation, deadline);
        errdefer job.release();
        try self.state.enqueue(job);
        try self.state.await(job);
        return job;
    }
    pub fn receiveRequestWithDeadline(self: EndpointServer, deadline: std.Io.Clock.Timestamp) Error!PendingRequest {
        const job = try self.submit(.receive_request, deadline);
        defer job.release();
        self.state.retain();
        return .{ .state = self.state, .data = job.takeRequest() };
    }
    pub fn receiveRequestWithTimeout(self: EndpointServer, timeout: std.Io.Duration) Error!PendingRequest {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveRequestWithDeadline(.fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn acceptWithDeadline(self: EndpointServer, pending: PendingHandle, options: runtime.ServerOptions, deadline: std.Io.Clock.Timestamp) Error!Accepted {
        const job = try self.submit(.{ .accept = .{ .handle = pending, .options = options } }, deadline);
        defer job.release();
        return job.takeAccepted();
    }
    pub fn rejectWithDeadline(self: EndpointServer, pending: PendingHandle, options: runtime.RejectOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        const job = try self.submit(.{ .reject = .{ .handle = pending, .options = options } }, deadline);
        job.release();
    }
    pub fn abandonPendingWithDeadline(self: EndpointServer, pending: PendingHandle, deadline: std.Io.Clock.Timestamp) Error!bool {
        const job = try self.submit(.{ .abandon_pending = pending }, deadline);
        defer job.release();
        return job.removed.?;
    }
    pub fn abandonPendingWithTimeout(self: EndpointServer, pending: PendingHandle, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.abandonPendingWithDeadline(pending, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    fn command(self: EndpointServer, value: job_mod.Command, deadline: std.Io.Clock.Timestamp) Error!void {
        const job = try self.submit(value, deadline);
        job.release();
    }
    pub fn sendDatagramWithDeadline(self: EndpointServer, handle: Handle, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .send_datagram = .{ .handle = handle, .data = data } }, deadline);
    }
    pub fn sendDatagramWithTimeout(self: EndpointServer, handle: Handle, data: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(handle, data, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn receiveWithDeadline(self: EndpointServer, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!Event {
        const job = try self.submit(.{ .receive = handle }, deadline);
        defer job.release();
        return job.takeEvent();
    }
    pub fn receiveWithTimeout(self: EndpointServer, handle: Handle, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn closeWithDeadline(self: EndpointServer, handle: Handle, code: u32, reason: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .close = .{ .handle = handle, .code = code, .reason = reason } }, deadline);
    }
    pub fn closeWithTimeout(self: EndpointServer, handle: Handle, code: u32, reason: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(handle, code, reason, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn removeWithDeadline(self: EndpointServer, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!bool {
        const job = try self.submit(.{ .remove = handle }, deadline);
        defer job.release();
        return job.removed.?;
    }
    pub fn removeWithTimeout(self: EndpointServer, handle: Handle, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.removeWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn openStreamWithDeadline(self: EndpointServer, handle: Handle, direction: h2_state.Direction, deadline: std.Io.Clock.Timestamp) Error!u62 {
        const job = try self.submit(.{ .open_stream = .{ .handle = handle, .direction = direction } }, deadline);
        defer job.release();
        return job.stream_id.?;
    }
    pub fn openStreamWithTimeout(self: EndpointServer, handle: Handle, direction: h2_state.Direction, timeout: std.Io.Duration) Error!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openStreamWithDeadline(handle, direction, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn sendStreamWithDeadline(self: EndpointServer, handle: Handle, id: u62, data: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .send_stream = .{ .handle = handle, .id = id, .data = data, .fin = fin } }, deadline);
    }
    pub fn sendStreamWithTimeout(self: EndpointServer, handle: Handle, id: u62, data: []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(handle, id, data, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Stage multiple payload slices into one command buffer. The command
    /// queue duplicates its input, so the caller's slices only need to remain
    /// valid for this call.
    pub fn sendStreamSlicesWithDeadline(self: EndpointServer, handle: Handle, id: u62, slices: []const []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
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
    pub fn sendStreamSlicesWithTimeout(self: EndpointServer, handle: Handle, id: u62, slices: []const []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamSlicesWithDeadline(handle, id, slices, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn consumeWithDeadline(self: EndpointServer, handle: Handle, id: u62, bytes: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .consume = .{ .handle = handle, .id = id, .bytes = bytes } }, deadline);
    }
    pub fn consumeWithTimeout(self: EndpointServer, handle: Handle, id: u62, bytes: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.consumeWithDeadline(handle, id, bytes, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn retireStreamWithDeadline(self: EndpointServer, handle: Handle, id: u62, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .retire_stream = .{ .handle = handle, .id = id } }, deadline);
    }
    pub fn retireStreamWithTimeout(self: EndpointServer, handle: Handle, id: u62, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.retireStreamWithDeadline(handle, id, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn resetStreamWithDeadline(self: EndpointServer, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .reset_stream = .{ .handle = handle, .id = id, .code = code } }, deadline);
    }
    pub fn resetStreamWithTimeout(self: EndpointServer, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn stopSendingWithDeadline(self: EndpointServer, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .stop_sending = .{ .handle = handle, .id = id, .code = code } }, deadline);
    }
    pub fn stopSendingWithTimeout(self: EndpointServer, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopSendingWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantDataWithDeadline(self: EndpointServer, handle: Handle, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .grant_data = .{ .handle = handle, .limit = limit } }, deadline);
    }
    pub fn grantDataWithTimeout(self: EndpointServer, handle: Handle, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantDataWithDeadline(handle, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamsWithDeadline(self: EndpointServer, handle: Handle, direction: h2_state.Direction, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .grant_streams = .{ .handle = handle, .direction = direction, .limit = limit } }, deadline);
    }
    pub fn grantStreamsWithTimeout(self: EndpointServer, handle: Handle, direction: h2_state.Direction, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamsWithDeadline(handle, direction, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamDataWithDeadline(self: EndpointServer, handle: Handle, id: u62, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .grant_stream_data = .{ .handle = handle, .id = id, .limit = limit } }, deadline);
    }
    pub fn grantStreamDataWithTimeout(self: EndpointServer, handle: Handle, id: u62, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamDataWithDeadline(handle, id, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn drainWithDeadline(self: EndpointServer, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.command(.{ .drain = handle }, deadline);
    }
    pub fn drainWithTimeout(self: EndpointServer, handle: Handle, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn exportKeyingMaterialWithDeadline(self: EndpointServer, handle: Handle, label: []const u8, context: []const u8, length: usize, deadline: std.Io.Clock.Timestamp) Error!KeyingMaterial {
        const job = try self.submit(.{ .export_keying_material = .{ .handle = handle, .label = label, .context = context, .length = length } }, deadline);
        defer job.release();
        return job.takeBytes();
    }
    pub fn exportKeyingMaterialWithTimeout(self: EndpointServer, handle: Handle, label: []const u8, context: []const u8, length: usize, timeout: std.Io.Duration) Error!KeyingMaterial {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.exportKeyingMaterialWithDeadline(handle, label, context, length, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    /// Request endpoint shutdown without releasing this owning handle. This
    /// lets a listener manager stop transport progress while retained pending
    /// requests keep the endpoint allocation alive long enough to observe the
    /// terminal EndpointClosed state.
    pub fn requestShutdown(self: EndpointServer) void {
        self.state.close();
    }

    /// Request abortive owner cleanup without acquiring the endpoint mutex.
    pub fn requestShutdownAbortive(self: EndpointServer) void {
        self.state.abortive_shutdown.store(true, .release);
        self.state.wake.set(self.state.io);
    }

    pub fn deinitAbortive(self: *EndpointServer) void {
        self.requestShutdownAbortive();
        self.deinit();
    }

    pub fn deinit(self: *EndpointServer) void {
        const state = self.state;
        state.close();
        state.group.cancel(state.io);
        state.release();
        self.* = undefined;
    }
};

test {
    _ = @import("endpoint_server/tests.zig");
    _ = @import("endpoint_server/admission_tests.zig");
    _ = @import("endpoint_server/waiter_tests.zig");
    _ = @import("endpoint_server/cleanup_tests.zig");
    _ = @import("endpoint_server/init_tests.zig");
}

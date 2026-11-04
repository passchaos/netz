//! Owner-serialized continuous concurrent serving for HTTP/3 request streams.
//!
//! One task owns the HTTP/3 session receive path and every session mutation.
//! Each accepted request gets an independent handler task that talks to the
//! owner through a command queue: body reads, response head, DATA, trailers and
//! cancellation are executed by the owner. The owner keeps receiving and
//! routing sibling events while handlers run, so one slow body or response does
//! not stop stream acceptance.
//!
//! `Stream` methods are safe to call from the handler task; they never touch the
//! session directly.
const std = @import("std");
const http3 = @import("../mod.zig");
const net = std.Io.net;
const Error = @import("error.zig").Error;
const stream_events = @import("stream/events.zig");
const StreamingRequestEvent = stream_events.Request;

pub const Options = struct {
    /// Maximum number of handler tasks running at once. Additional accepted
    /// heads wait in arrival order until a handler completes.
    max_streams: usize = 32,
    /// Optional absolute deadline for the whole serve call.
    deadline: ?std.Io.Clock.Timestamp = null,
    /// Return after this long with no active streams and no incoming events.
    idle_timeout: ?std.Io.Duration = null,
    /// Set by the application to stop accepting new streams, finish active
    /// handlers, and send GOAWAY.
    shutdown: ?*std.Io.Event = null,
    /// Maximum time the owner blocks on one receive attempt before re-checking
    /// command and shutdown wakes while no handler is active.
    poll_interval: std.Io.Duration = .fromMilliseconds(1),
    /// Maximum receive budget while at least one handler is active. The owner
    /// cannot be interrupted by a handler command, so this bounds how long a
    /// queued `startResponse`/`writeData` waits for the next receive poll.
    /// Lower values reduce streaming latency at the cost of more wakeups.
    command_poll_interval: std.Io.Duration = .fromMicroseconds(100),
    /// Per-stream request DATA resident in the owner buffer. Null uses the
    /// session's `max_stream_buffer`; the total body remains bounded by
    /// `max_body_bytes`.
    max_buffered_body_bytes: ?usize = null,
    /// Stack size for handler workers. A per-connection pool grows lazily up
    /// to `max_streams`, so this bounds virtual memory for connections that
    /// actually multiplex. Raise it for handlers with deep native stacks.
    worker_stack_size: usize = 1024 * 1024,
};

pub const Summary = struct {
    accepted: usize = 0,
    completed: usize = 0,
    failed: usize = 0,
    canceled: usize = 0,
    last_stream_id: u64 = 0,
};

/// Adapter contract. `from` is the peer address carried by the event; sessions
/// bound to one peer ignore it.
///
///   receive(session, deadline) Error!StreamingRequestEvent
///   availableBody(session, from, stream_id) Error!usize
///   readBody(session, from, stream_id, out) Error!usize
///   startResponse(session, from, stream_id, response, body_length) Error!void
///   sendBody(session, from, stream_id, data, fin) Error!void
///   finishTrailers(session, from, stream_id, trailers) Error!void
///   cancel(session, from, stream_id, code) Error!void
///   goaway(session, last_stream_id) Error!void
///   maxStreams(session) usize
///   maxBodyBuffer(session) usize
pub fn Engine(comptime Session: type, comptime Adapter: type) type {
    return struct {
        const Self = @This();

        const Command = struct {
            slot: *Slot,
            kind: Kind,
            count: usize = 0,
            result: ?anyerror = null,
            done: std.Io.Event = .unset,
            abandoned: std.atomic.Value(bool) = .init(false),

            const Kind = union(enum) {
                start_response: struct {
                    response: http3.Response,
                    body_length: ?usize,
                },
                write_body: struct {
                    data: []const u8,
                    fin: bool,
                },
                finish_trailers: []const http3.Qpack.HeaderField,
                cancel: u64,
            };
        };

        const Slot = struct {
            engine: *Self,
            stream: Stream,
            from: net.IpAddress,
            stream_id: u62,
            head: http3.DecodedRequestHead,
            trailers: ?http3.DecodedTrailers = null,
            body_mutex: std.Io.Mutex = .init,
            /// Request DATA copied by the owner before `.finished` can retire
            /// the session stream. Bounded by the protocol body limit.
            body: std.ArrayList(u8) = .empty,
            body_offset: usize = 0,
            /// True while the owner stopped reading because the resident
            /// buffer reached `max_buffered_body_bytes`.
            body_blocked: bool = false,
            /// True while the session reader still has DATA for this stream
            /// that the owner has not copied yet.
            body_pending: bool = false,
            body_wake: std.Io.Event = .unset,
            body_finished: bool = false,
            body_error: ?anyerror = null,
            reset_code: ?u64 = null,
            response_finished: bool = false,
            suppress_body: bool = false,
            handler_done: bool = false,
            handler_error: ?anyerror = null,
            canceled: bool = false,

            fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
                self.head.deinit(allocator);
                if (self.trailers) |*trailers| trailers.deinit(allocator);
                self.body.deinit(allocator);
                self.* = undefined;
            }
        };

        pub const Stream = struct {
            engine: *Self,
            slot: *Slot,

            pub fn head(self: Stream) *const http3.DecodedRequestHead {
                return &self.slot.head;
            }

            pub fn streamId(self: Stream) u62 {
                return self.slot.stream_id;
            }

            pub fn from(self: Stream) net.IpAddress {
                return self.slot.from;
            }

            /// Pull the next request DATA slice into `out`. Returns null after
            /// END_STREAM and surfaces a peer reset as `error.StreamReset`.
            pub fn nextBody(
                self: Stream,
                out: []u8,
                deadline: ?std.Io.Clock.Timestamp,
            ) anyerror!?usize {
                return self.engine.nextBody(self.slot, out, deadline);
            }

            /// Trailers received after the request body. The returned slice is
            /// borrowed until the handler returns. The owner publishes it
            /// under `body_mutex`; taking the same lock makes the read
            /// synchronized even if the handler asks before END_STREAM.
            pub fn trailers(self: Stream) ?[]const http3.Qpack.HeaderField {
                self.slot.body_mutex.lockUncancelable(self.engine.io);
                defer self.slot.body_mutex.unlock(self.engine.io);
                return if (self.slot.trailers) |value| value.fields else null;
            }

            /// Start a streaming response head. `body_length` may be null when
            /// the length is not known in advance.
            pub fn startResponse(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response = .{
                    .response = response,
                    .body_length = body_length,
                } } };
                return self.engine.submit(&command, null);
            }

            pub fn startResponseWithDeadline(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response = .{
                    .response = response,
                    .body_length = body_length,
                } } };
                return self.engine.submit(&command, deadline);
            }

            /// Write one response DATA contribution. `data` must stay valid
            /// until this call returns. The call blocks until the owner has
            /// committed it (or returns a timeout/transport error).
            pub fn writeData(self: Stream, data: []const u8, fin: bool) anyerror!void {
                return self.writeDataWithDeadline(data, fin, null);
            }

            pub fn writeDataWithDeadline(
                self: Stream,
                data: []const u8,
                fin: bool,
                deadline: ?std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .write_body = .{
                    .data = data,
                    .fin = fin,
                } } };
                return self.engine.submit(&command, deadline);
            }

            /// Finish the response with an empty DATA FIN.
            pub fn finish(self: Stream) anyerror!void {
                return self.writeData("", true);
            }

            /// Finish the response with response trailers.
            pub fn finishWithTrailers(
                self: Stream,
                fields: []const http3.Qpack.HeaderField,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .finish_trailers = fields } };
                return self.engine.submit(&command, null);
            }

            /// Cancel this stream. The peer observes `code` as the HTTP/3
            /// application error code.
            pub fn reset(self: Stream, code: u64) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .cancel = code } };
                return self.engine.submit(&command, null);
            }
        };

        session: *Session,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        mutex: std.Io.Mutex = .init,
        commands: std.ArrayList(*Command) = .empty,
        commands_blocked: bool = false,
        wake: std.Io.Event = .unset,
        slots: std.ArrayList(*Slot) = .empty,
        pending_heads: std.ArrayList(StreamingRequestEvent) = .empty,
        /// Ready handlers consumed by a lazily grown per-connection worker
        /// pool. A sequential connection keeps one reusable thread instead of
        /// spawning a thread for every request.
        task_mutex: std.Io.Mutex = .init,
        task_cond: std.Io.Condition = .init,
        task_queue: std.ArrayList(*Slot) = .empty,
        workers: std.ArrayList(std.Thread) = .empty,
        idle_workers: usize = 0,
        stopping: bool = false,
        max_buffered_body_bytes: usize = 1,
        active: usize = 0,
        summary: Summary = .{},

        pub fn init(
            session: *Session,
            allocator: std.mem.Allocator,
            io: std.Io,
            options: Options,
        ) Self {
            var self: Self = .{
                .session = session,
                .allocator = allocator,
                .io = io,
                .options = options,
            };
            self.max_buffered_body_bytes =
                options.max_buffered_body_bytes orelse Adapter.maxBodyBuffer(session);
            self.max_buffered_body_bytes = @max(self.max_buffered_body_bytes, 1);
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.cancelCommands();
            self.cancelActive();
            self.slots.deinit(self.allocator);
            for (self.pending_heads.items) |*event| event.deinit(self.allocator);
            self.pending_heads.deinit(self.allocator);
            self.commands.deinit(self.allocator);
            self.task_queue.deinit(self.allocator);
            self.workers.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn serve(
            self: *Self,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) anyerror!Summary {
            const limit = @min(
                self.options.max_streams,
                Adapter.maxStreams(self.session),
            );
            if (limit == 0 or self.options.command_poll_interval.nanoseconds <= 0)
                return error.InvalidServeOptions;

            var idle_deadline: ?std.Io.Clock.Timestamp = null;
            errdefer {
                self.cancelCommands();
                self.cancelActive();
            }

            while (true) {
                try self.spawnPending(limit, Context, context, handler);
                try self.drainCommands();
                self.retryBlockedBodies();
                self.reap();
                try self.spawnPending(limit, Context, context, handler);

                if (self.shutdownRequested()) {
                    try self.stopAccepting();
                    if (self.active == 0 and self.pending_heads.items.len == 0) {
                        break;
                    }
                }

                if (self.active == 0 and self.pending_heads.items.len == 0) {
                    if (idle_deadline == null) {
                        if (self.options.idle_timeout) |timeout| {
                            idle_deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
                                .raw = timeout,
                                .clock = .awake,
                            });
                        }
                    }
                } else idle_deadline = null;

                if (self.options.deadline) |deadline| {
                    if (std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds >= deadline.raw.nanoseconds) {
                        return error.Timeout;
                    }
                }
                if (idle_deadline) |deadline| {
                    if (std.Io.Clock.Timestamp.now(self.io, .awake).raw.nanoseconds >= deadline.raw.nanoseconds) {
                        return error.Timeout;
                    }
                }

                const event = try self.readOrWake(self.effectiveDeadline(idle_deadline));
                if (event) |value| {
                    try self.route(value);
                    idle_deadline = null;
                }
            }

            self.stopWorkers();
            try Adapter.goaway(self.session, self.summary.last_stream_id);
            return self.summary;
        }

        fn effectiveDeadline(self: *Self, idle: ?std.Io.Clock.Timestamp) ?std.Io.Clock.Timestamp {
            const overall = self.options.deadline;
            if (overall == null) return idle;
            if (idle == null) return overall;
            return if (idle.?.raw.nanoseconds < overall.?.raw.nanoseconds) idle else overall;
        }

        fn shutdownRequested(self: *Self) bool {
            const shutdown = self.options.shutdown orelse return false;
            return shutdown.isSet();
        }

        fn stopAccepting(self: *Self) !void {
            for (self.pending_heads.items) |*event| event.deinit(self.allocator);
            self.pending_heads.clearRetainingCapacity();
        }

        fn spawnPending(
            self: *Self,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            while (self.active < limit and self.pending_heads.items.len != 0) {
                const event = self.pending_heads.orderedRemove(0);
                const slot = try self.createSlot(event);
                errdefer {
                    _ = self.slots.pop();
                    slot.deinit(self.allocator);
                    self.allocator.destroy(slot);
                }
                try self.enqueue(slot, limit, Context, context, handler);
            }
        }

        /// Queue a created slot for a worker. Workers are grown lazily so a
        /// sequential connection reuses one thread instead of spawning one
        /// thread per request.
        fn enqueue(
            self: *Self,
            slot: *Slot,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            self.task_mutex.lockUncancelable(self.io);
            const need_worker = self.idle_workers == 0 and
                self.workers.items.len < limit;
            self.task_mutex.unlock(self.io);
            if (need_worker) try self.startWorker(Context, context, handler);

            self.task_mutex.lockUncancelable(self.io);
            self.task_queue.append(self.allocator, slot) catch |err| {
                self.task_mutex.unlock(self.io);
                return err;
            };
            self.task_mutex.unlock(self.io);
            self.task_cond.signal(self.io);
            self.active += 1;
            self.summary.accepted += 1;
        }

        fn Worker(comptime Context: type) type {
            return struct {
                engine: *Self,
                context: *Context,
                handler: *const fn (*Context, *Stream) anyerror!void,

                fn run(worker: @This()) void {
                    const engine = worker.engine;
                    while (true) {
                        engine.task_mutex.lockUncancelable(engine.io);
                        engine.idle_workers += 1;
                        while (engine.task_queue.items.len == 0 and !engine.stopping) {
                            engine.task_cond.wait(engine.io, &engine.task_mutex) catch |err| switch (err) {
                                error.Canceled => {
                                    engine.idle_workers -= 1;
                                    engine.task_mutex.unlock(engine.io);
                                    return;
                                },
                            };
                        }
                        engine.idle_workers -= 1;
                        if (engine.stopping) {
                            engine.task_mutex.unlock(engine.io);
                            return;
                        }
                        const slot = engine.task_queue.orderedRemove(0);
                        engine.task_mutex.unlock(engine.io);

                        worker.handler(worker.context, &slot.stream) catch |err| {
                            slot.handler_error = err;
                        };
                        slot.body_mutex.lockUncancelable(engine.io);
                        slot.handler_done = true;
                        slot.body_mutex.unlock(engine.io);
                        engine.wake.set(engine.io);
                    }
                }
            };
        }

        fn startWorker(
            self: *Self,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            self.task_mutex.lockUncancelable(self.io);
            self.workers.ensureUnusedCapacity(self.allocator, 1) catch |err| {
                self.task_mutex.unlock(self.io);
                return err;
            };
            self.task_mutex.unlock(self.io);
            const thread = try std.Thread.spawn(
                .{ .stack_size = self.options.worker_stack_size },
                Worker(Context).run,
                .{Worker(Context){
                    .engine = self,
                    .context = context,
                    .handler = handler,
                }},
            );
            self.task_mutex.lockUncancelable(self.io);
            self.workers.appendAssumeCapacity(thread);
            self.task_mutex.unlock(self.io);
        }

        fn stopWorkers(self: *Self) void {
            self.task_mutex.lockUncancelable(self.io);
            self.stopping = true;
            const worker_count = self.workers.items.len;
            self.task_mutex.unlock(self.io);
            for (0..worker_count) |_| self.task_cond.signal(self.io);
            for (self.workers.items) |thread| thread.join();
            self.task_mutex.lockUncancelable(self.io);
            self.workers.clearRetainingCapacity();
            self.task_mutex.unlock(self.io);
        }

        fn createSlot(self: *Self, event: StreamingRequestEvent) !*Slot {
            if (event != .message or event.message.value != .head) {
                return error.UnexpectedFrame;
            }
            const slot = try self.allocator.create(Slot);
            errdefer self.allocator.destroy(slot);
            var owned = event;
            const head = owned.message.value.head.request;
            const stream_id = owned.message.stream_id;
            const from = owned.message.from;
            // The slot takes the head; the event must not free it.
            owned.message.value = .finished;
            owned.deinit(self.allocator);
            slot.* = .{
                .engine = self,
                .stream = .{ .engine = self, .slot = slot },
                .from = from,
                .stream_id = stream_id,
                .head = head,
            };
            errdefer slot.deinit(self.allocator);
            self.slots.append(self.allocator, slot) catch |err| return err;
            if (stream_id > self.summary.last_stream_id) self.summary.last_stream_id = stream_id;
            return slot;
        }

        fn route(self: *Self, event: StreamingRequestEvent) !void {
            var owned = event;
            var moved = false;
            defer if (!moved) owned.deinit(self.allocator);
            switch (owned) {
                .message => |*message| {
                    switch (message.value) {
                        .head => {
                            try self.pending_heads.append(self.allocator, owned);
                            moved = true;
                        },
                        .data_available => try self.readBodyIntoSlot(
                            message.from,
                            message.stream_id,
                        ),
                        .trailers => |trailers_value| {
                            const slot = self.find(message.from, message.stream_id) orelse return;
                            slot.body_mutex.lockUncancelable(self.io);
                            if (slot.trailers) |*old| old.deinit(self.allocator);
                            slot.trailers = trailers_value;
                            slot.body_mutex.unlock(self.io);
                            message.value = .finished;
                            moved = true;
                            slot.body_wake.set(self.io);
                        },
                        .finished => {
                            const slot = self.find(message.from, message.stream_id) orelse return;
                            slot.body_mutex.lockUncancelable(self.io);
                            slot.body_finished = true;
                            slot.body_mutex.unlock(self.io);
                            slot.body_wake.set(self.io);
                        },
                        .push_promise => {},
                    }
                },
                .reset => |reset| {
                    const slot = self.find(reset.from, reset.stream_id) orelse return;
                    slot.body_mutex.lockUncancelable(self.io);
                    slot.reset_code = reset.application_error_code;
                    slot.body_mutex.unlock(self.io);
                    slot.body_wake.set(self.io);
                },
            }
        }

        fn readBodyIntoSlot(
            self: *Self,
            from: net.IpAddress,
            stream_id: u62,
        ) !void {
            const slot = self.find(from, stream_id) orelse return;
            const cap = self.max_buffered_body_bytes;
            var scratch: [16 * 1024]u8 = undefined;
            slot.body_mutex.lockUncancelable(self.io);
            slot.body_pending = true;
            slot.body_mutex.unlock(self.io);
            while (true) {
                slot.body_mutex.lockUncancelable(self.io);
                const resident = slot.body.items.len - slot.body_offset;
                slot.body_mutex.unlock(self.io);
                if (resident >= cap) {
                    slot.body_mutex.lockUncancelable(self.io);
                    slot.body_blocked = true;
                    slot.body_mutex.unlock(self.io);
                    // The handler may already be waiting for its first chunk;
                    // the resident bytes are readable even though the owner
                    // stopped pulling more input.
                    slot.body_wake.set(self.io);
                    return;
                }
                const available = Adapter.availableBody(
                    self.session,
                    from,
                    stream_id,
                ) catch |err| switch (err) {
                    // The previous DATA frame was fully consumed. There is no
                    // resident byte to report until the next
                    // `.data_available` event, which is not a protocol error.
                    error.UnexpectedFrame => 0,
                    else => |other| {
                        slot.body_mutex.lockUncancelable(self.io);
                        slot.body_error = other;
                        slot.body_mutex.unlock(self.io);
                        slot.body_wake.set(self.io);
                        return;
                    },
                };
                if (available == 0) {
                    slot.body_mutex.lockUncancelable(self.io);
                    slot.body_pending = false;
                    slot.body_mutex.unlock(self.io);
                    break;
                }
                const room = cap - resident;
                const want = @min(scratch.len, room);
                const count = Adapter.readBody(
                    self.session,
                    from,
                    stream_id,
                    scratch[0..want],
                ) catch |err| {
                    slot.body_mutex.lockUncancelable(self.io);
                    slot.body_error = err;
                    slot.body_mutex.unlock(self.io);
                    slot.body_wake.set(self.io);
                    return;
                };
                if (count == 0) break;
                slot.body_mutex.lockUncancelable(self.io);
                slot.body.appendSlice(self.allocator, scratch[0..count]) catch |err| {
                    slot.body_error = err;
                    slot.body_mutex.unlock(self.io);
                    slot.body_wake.set(self.io);
                    return;
                };
                slot.body_blocked = false;
                slot.body_mutex.unlock(self.io);
            }
            slot.body_mutex.lockUncancelable(self.io);
            slot.body_blocked = false;
            slot.body_pending = false;
            slot.body_mutex.unlock(self.io);
            slot.body_wake.set(self.io);
        }

        /// Retry a stream whose resident buffer was full before the handler
        /// consumed enough bytes. The session reader retains the current DATA
        /// frame, so no new receive event is needed.
        fn retryBlockedBodies(self: *Self) void {
            for (self.slots.items) |slot| {
                slot.body_mutex.lockUncancelable(self.io);
                const pending = slot.body_pending or slot.body_blocked;
                slot.body_mutex.unlock(self.io);
                if (!pending) continue;
                self.readBodyIntoSlot(slot.from, slot.stream_id) catch {};
            }
        }

        fn anyBodyBlocked(self: *Self) bool {
            for (self.slots.items) |slot| {
                slot.body_mutex.lockUncancelable(self.io);
                const blocked = slot.body_blocked;
                slot.body_mutex.unlock(self.io);
                if (blocked) return true;
            }
            return false;
        }

        fn find(self: *Self, from: net.IpAddress, stream_id: u62) ?*Slot {
            for (self.slots.items) |slot| {
                if (slot.stream_id == stream_id and slot.from.eql(&from)) return slot;
            }
            return null;
        }

        fn nextBody(
            self: *Self,
            slot: *Slot,
            out: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) anyerror!?usize {
            while (true) {
                slot.body_mutex.lockUncancelable(self.io);
                if (slot.canceled) {
                    slot.body_mutex.unlock(self.io);
                    return error.Canceled;
                }
                if (slot.reset_code) |_| {
                    slot.body_mutex.unlock(self.io);
                    return error.StreamReset;
                }
                if (slot.body_error) |err| {
                    slot.body_mutex.unlock(self.io);
                    return err;
                }
                if (slot.body_offset < slot.body.items.len) {
                    const available = slot.body.items.len - slot.body_offset;
                    const count = @min(out.len, available);
                    if (count != 0) {
                        @memcpy(
                            out[0..count],
                            slot.body.items[slot.body_offset..][0..count],
                        );
                        slot.body_offset += count;
                    }
                    if (slot.body_offset == slot.body.items.len) {
                        slot.body.clearRetainingCapacity();
                        slot.body_offset = 0;
                    }
                    const needs_retry = slot.body_blocked or slot.body_pending;
                    slot.body_blocked = false;
                    slot.body_mutex.unlock(self.io);
                    if (needs_retry) self.wake.set(self.io);
                    return count;
                }
                if (slot.body_finished) {
                    slot.body_mutex.unlock(self.io);
                    return null;
                }
                slot.body_mutex.unlock(self.io);
                try waitForEvent(self.io, &slot.body_wake, deadline);
                slot.body_wake.reset();
            }
        }

        fn submit(self: *Self, command: *Command, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
            self.mutex.lockUncancelable(self.io);
            self.commands.append(self.allocator, command) catch |err| {
                self.mutex.unlock(self.io);
                return err;
            };
            self.mutex.unlock(self.io);
            self.wake.set(self.io);
            waitForEvent(self.io, &command.done, deadline) catch |err| {
                command.abandoned.store(true, .release);
                // The handler's stack owns the command and its payload. Wait
                // for the owner to observe abandonment or finish execution
                // before unwinding that stack.
                command.done.wait(self.io) catch {};
                return err;
            };
            if (command.result) |failure| return failure;
        }

        fn drainCommands(self: *Self) !void {
            self.commands_blocked = false;
            while (true) {
                self.mutex.lockUncancelable(self.io);
                if (self.commands.items.len == 0) {
                    self.mutex.unlock(self.io);
                    return;
                }
                const command = self.commands.orderedRemove(0);
                self.mutex.unlock(self.io);
                if (command.abandoned.load(.acquire)) {
                    command.done.set(self.io);
                    continue;
                }
                self.execute(command) catch |err| switch (err) {
                    error.FlowControlBlocked,
                    error.CongestionLimited,
                    error.PacingLimited,
                    => {
                        self.mutex.lockUncancelable(self.io);
                        self.commands.append(self.allocator, command) catch {
                            command.result = error.OutOfMemory;
                            command.done.set(self.io);
                            self.mutex.unlock(self.io);
                            continue;
                        };
                        self.mutex.unlock(self.io);
                        self.commands_blocked = true;
                        return;
                    },
                    else => command.result = err,
                };
                command.done.set(self.io);
            }
        }

        fn execute(self: *Self, command: *Command) anyerror!void {
            const slot = command.slot;
            switch (command.kind) {
                .start_response => |value| {
                    try Adapter.startResponse(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        value.response,
                        value.body_length,
                    );
                    slot.suppress_body = value.response.suppressesBody();
                    if (value.body_length == 0 or slot.suppress_body) {
                        slot.response_finished = true;
                    }
                },
                .write_body => |value| {
                    if (slot.suppress_body) {
                        if (value.data.len != 0) return error.InvalidContentLength;
                        if (value.fin) slot.response_finished = true;
                        return;
                    }
                    try Adapter.sendBody(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        value.data,
                        value.fin,
                    );
                    if (value.fin) slot.response_finished = true;
                },
                .finish_trailers => |trailers| {
                    try Adapter.finishTrailers(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        trailers,
                    );
                    slot.response_finished = true;
                },
                .cancel => |code| {
                    try Adapter.cancel(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        code,
                    );
                    slot.response_finished = true;
                },
            }
        }

        fn reap(self: *Self) void {
            var index: usize = 0;
            while (index < self.slots.items.len) {
                const slot = self.slots.items[index];
                // `handler_done` is published under `body_mutex` by the worker;
                // the same lock makes `handler_error` visible to the owner.
                slot.body_mutex.lockUncancelable(self.io);
                const done = slot.handler_done;
                const failure = slot.handler_error;
                slot.body_mutex.unlock(self.io);
                if (!done) {
                    index += 1;
                    continue;
                }
                if (!slot.response_finished and slot.reset_code == null) {
                    Adapter.cancel(self.session, slot.from, slot.stream_id, 0) catch {};
                }
                if (failure != null) {
                    self.summary.failed += 1;
                } else {
                    self.summary.completed += 1;
                }
                if (slot.reset_code != null) self.summary.canceled += 1;
                _ = self.slots.orderedRemove(index);
                slot.deinit(self.allocator);
                self.allocator.destroy(slot);
                self.active -|= 1;
            }
        }

        fn cancelActive(self: *Self) void {
            // Prevent idle workers from taking queued handlers while active
            // handlers are canceled below.
            self.task_mutex.lockUncancelable(self.io);
            self.stopping = true;
            const worker_count = self.workers.items.len;
            self.task_mutex.unlock(self.io);
            for (0..worker_count) |_| self.task_cond.signal(self.io);

            for (self.slots.items) |slot| {
                slot.body_mutex.lockUncancelable(self.io);
                slot.canceled = true;
                slot.body_mutex.unlock(self.io);
                slot.body_wake.set(self.io);
            }
            self.cancelCommands();
            for (self.workers.items) |thread| thread.join();
            self.task_mutex.lockUncancelable(self.io);
            self.workers.clearRetainingCapacity();
            self.task_queue.clearRetainingCapacity();
            self.task_mutex.unlock(self.io);
            for (self.slots.items) |slot| {
                Adapter.cancel(self.session, slot.from, slot.stream_id, 0) catch {};
            }
            for (self.slots.items) |slot| {
                slot.deinit(self.allocator);
                self.allocator.destroy(slot);
            }
            self.slots.clearRetainingCapacity();
            self.active = 0;
        }

        fn cancelCommands(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            var pending = self.commands;
            self.commands = .empty;
            self.commands_blocked = false;
            self.mutex.unlock(self.io);
            for (pending.items) |command| {
                command.abandoned.store(true, .release);
                command.result = error.Canceled;
                command.done.set(self.io);
            }
            pending.deinit(self.allocator);
        }

        fn receivePollInterval(self: *Self) std.Io.Duration {
            if (self.active != 0 and
                self.options.command_poll_interval.nanoseconds <
                    self.options.poll_interval.nanoseconds)
            {
                return self.options.command_poll_interval;
            }
            return self.options.poll_interval;
        }

        fn readOrWake(self: *Self, deadline: ?std.Io.Clock.Timestamp) anyerror!?StreamingRequestEvent {
            // Do not clear a wake that belongs to an already queued command.
            self.wake.reset();
            self.mutex.lockUncancelable(self.io);
            const has_commands = self.commands.items.len != 0;
            self.mutex.unlock(self.io);
            if (has_commands and !self.commands_blocked) return null;

            // A full per-stream body buffer must not let the owner consume
            // `.finished` and retire the session stream before the handler
            // drains it. Wait for handler progress or a command instead of
            // receiving more input.
            const poll = self.receivePollInterval();
            if (self.anyBodyBlocked()) {
                _ = self.wake.waitTimeout(self.io, .{
                    .duration = .{
                        .raw = poll,
                        .clock = .awake,
                    },
                }) catch {};
                return null;
            }

            // Poll the receive path with a short absolute budget instead of
            // cancelling a concurrent `std.Io` operation. The wake event is
            // checked between polls, so command latency is bounded by the
            // active-command poll interval while session state stays
            // single-owner.
            const poll_deadline = std.Io.Clock.Timestamp.addDuration(
                std.Io.Clock.Timestamp.now(self.io, .awake),
                .{ .raw = poll, .clock = .awake },
            );
            const use_deadline = if (deadline) |value|
                if (value.raw.nanoseconds < poll_deadline.raw.nanoseconds) value else poll_deadline
            else
                poll_deadline;
            return Adapter.receive(self.session, use_deadline) catch |err| switch (err) {
                error.Timeout => null,
                else => |other| return other,
            };
        }
    };
}

/// Wait for `event` without treating a spurious futex wakeup as a timeout.
/// `std.Io.Event.waitTimeout` reports `error.Timeout` when the futex returns
/// spuriously, even with `.none`; looping keeps handler deadlines honest.
fn waitForEvent(
    io: std.Io,
    event: *std.Io.Event,
    deadline: ?std.Io.Clock.Timestamp,
) anyerror!void {
    if (deadline) |absolute| {
        while (true) {
            event.waitTimeout(io, .{ .deadline = absolute }) catch |err| switch (err) {
                error.Timeout => {
                    if (std.Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds >=
                        absolute.raw.nanoseconds)
                    {
                        return error.Timeout;
                    }
                    continue;
                },
                error.Canceled => return error.Canceled,
            };
            return;
        }
    }
    event.wait(io) catch |err| return @errorCast(err);
}

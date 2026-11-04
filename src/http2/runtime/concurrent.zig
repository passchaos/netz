//! Owner-serialized continuous concurrent serving for HTTP/2 request streams.
//!
//! One task owns the connection frame reader, HPACK state, socket writer and
//! every `ServerDuplexStream`. Each accepted stream gets an independent handler
//! task that talks to the owner through a command queue. Request DATA is copied
//! into a bounded per-stream buffer by the owner before the stream can be
//! retired, so handlers pull body bytes without touching connection state.
const std = @import("std");
const http2 = @import("../mod.zig");

pub const Options = struct {
    max_streams: usize = 32,
    deadline: ?std.Io.Clock.Timestamp = null,
    idle_timeout: ?std.Io.Duration = null,
    shutdown: ?*std.Io.Event = null,
    /// Maximum time one pump blocks on input before re-checking shutdown and
    /// idle state. Command wakes still interrupt it immediately.
    poll_interval: std.Io.Duration = .fromMilliseconds(5),
    /// Bound for control output after a read or command wake.
    output_timeout: std.Io.Duration = .fromMilliseconds(100),
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
    last_stream_id: u31 = 0,
};

pub const Head = struct {
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8,
    headers: []const http2.Hpack.HeaderField,
    content_length: ?usize,
};

pub fn Engine(
    comptime Connection: type,
    comptime StreamType: type,
    comptime ResponseOptions: type,
) type {
    return struct {
        const Self = @This();

        const Command = struct {
            slot: *Slot,
            kind: Kind,
            result: ?anyerror = null,
            done: std.Io.Event = .unset,
            abandoned: std.atomic.Value(bool) = .init(false),

            const Kind = union(enum) {
                start_response: ResponseOptions,
                write_body: struct {
                    data: []const u8,
                    fin: bool,
                },
                /// Response head and its first DATA contribution in one owner
                /// turn. A sequential request otherwise pays two wake/command
                /// round trips for a single logical response.
                start_response_with_body: struct {
                    options: ResponseOptions,
                    data: []const u8,
                    fin: bool,
                },
                finish_trailers: []const http2.Hpack.HeaderField,
                cancel: http2.ErrorCode,
            };
        };

        const Slot = struct {
            engine: *Self,
            stream: StreamType,
            public_stream: Stream,
            body_mutex: std.Io.Mutex = .init,
            body: std.ArrayList(u8) = .empty,
            body_offset: usize = 0,
            body_wake: std.Io.Event = .unset,
            body_finished: bool = false,
            body_error: ?anyerror = null,
            trailers: ?[]http2.Hpack.HeaderField = null,
            reset_code: ?http2.ErrorCode = null,
            response_finished: bool = false,
            handler_done: bool = false,
            handler_error: ?anyerror = null,
            canceled: bool = false,

            fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
                if (self.trailers) |fields| freeHeaders(allocator, fields);
                self.body.deinit(allocator);
                self.stream.deinit();
                self.* = undefined;
            }
        };

        pub const Stream = struct {
            engine: *Self,
            slot: *Slot,

            pub fn head(self: Stream) Head {
                const stream = &self.slot.stream;
                return .{
                    .method = stream.method,
                    .path = stream.path,
                    .scheme = stream.scheme,
                    .authority = stream.authority,
                    .protocol = stream.protocol,
                    .headers = stream.headers,
                    .content_length = stream.expected_request_length,
                };
            }

            pub fn streamId(self: Stream) u31 {
                return self.slot.stream.stream_id;
            }

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
            pub fn trailers(self: Stream) ?[]const http2.Hpack.HeaderField {
                self.slot.body_mutex.lockUncancelable(self.engine.io);
                defer self.slot.body_mutex.unlock(self.engine.io);
                return self.slot.trailers;
            }

            pub fn startResponse(
                self: Stream,
                options: ResponseOptions,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response = options } };
                return self.engine.submit(&command, null);
            }

            pub fn startResponseWithDeadline(
                self: Stream,
                options: ResponseOptions,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response = options } };
                return self.engine.submit(&command, deadline);
            }

            /// Submit the response head and its first DATA contribution as one
            /// owner command. `data` must stay valid until this call returns.
            pub fn startResponseWithBody(
                self: Stream,
                options: ResponseOptions,
                data: []const u8,
                fin: bool,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response_with_body = .{
                    .options = options,
                    .data = data,
                    .fin = fin,
                } } };
                return self.engine.submit(&command, null);
            }

            pub fn startResponseWithBodyAndDeadline(
                self: Stream,
                options: ResponseOptions,
                data: []const u8,
                fin: bool,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response_with_body = .{
                    .options = options,
                    .data = data,
                    .fin = fin,
                } } };
                return self.engine.submit(&command, deadline);
            }

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

            pub fn finish(self: Stream) anyerror!void {
                return self.writeData("", true);
            }

            pub fn finishWithTrailers(
                self: Stream,
                fields: []const http2.Hpack.HeaderField,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .finish_trailers = fields } };
                return self.engine.submit(&command, null);
            }

            pub fn reset(self: Stream, code: http2.ErrorCode) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .cancel = code } };
                return self.engine.submit(&command, null);
            }
        };

        connection: *Connection,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        mutex: std.Io.Mutex = .init,
        commands: std.ArrayList(*Command) = .empty,
        commands_blocked: bool = false,
        wake: std.Io.Event = .unset,
        slots: std.ArrayList(*Slot) = .empty,
        pending: std.ArrayList(StreamType) = .empty,
        /// Ready handlers. The owner enqueues accepted streams here; a
        /// per-connection worker pool consumes them. Workers are created lazily
        /// so a sequential connection keeps a single reusable thread instead of
        /// spawning one thread per request.
        task_mutex: std.Io.Mutex = .init,
        task_cond: std.Io.Condition = .init,
        task_queue: std.ArrayList(*Slot) = .empty,
        workers: std.ArrayList(std.Thread) = .empty,
        idle_workers: usize = 0,
        stopping: bool = false,
        active: usize = 0,
        summary: Summary = .{},

        pub fn init(
            connection: *Connection,
            allocator: std.mem.Allocator,
            io: std.Io,
            options: Options,
        ) Self {
            return .{
                .connection = connection,
                .allocator = allocator,
                .io = io,
                .options = options,
            };
        }

        pub fn deinit(self: *Self) void {
            self.cancelCommands();
            self.cancelActive();
            for (self.pending.items) |*stream| stream.deinit();
            self.pending.deinit(self.allocator);
            self.slots.deinit(self.allocator);
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
            const limit = @min(self.options.max_streams, self.maxStreams());
            if (limit == 0) return error.InvalidServeOptions;

            var idle_deadline: ?std.Io.Clock.Timestamp = null;
            var peer_closed = false;
            errdefer {
                self.cancelCommands();
                self.cancelActive();
            }

            while (true) {
                try self.spawnPending(limit, Context, context, handler);
                try self.drainCommands();
                self.reap();
                try self.spawnPending(limit, Context, context, handler);

                if (self.shutdownRequested()) {
                    self.discardPending();
                    if (self.active == 0) break;
                }

                if (self.active == 0 and self.pending.items.len == 0) {
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

                const read_until = std.Io.Clock.Timestamp.addDuration(
                    std.Io.Clock.Timestamp.now(self.io, .awake),
                    .{ .raw = self.options.poll_interval, .clock = .awake },
                );
                const event = self.connection.pumpServerUntilOrWake(
                    read_until,
                    self.options.output_timeout,
                    &self.wake,
                ) catch |err| switch (err) {
                    error.Timeout => null,
                    error.ConnectionClosed => {
                        peer_closed = true;
                        break;
                    },
                    else => |other| return other,
                };
                if (event) |value| {
                    switch (value) {
                        .request => |stream| try self.accept(stream, limit, Context, context, handler),
                        .stream => |stream_id| try self.drainSlot(stream_id),
                        .progress, .wake => {},
                    }
                    idle_deadline = null;
                }
            }

            if (peer_closed) {
                self.cancelCommands();
                self.cancelActive();
            } else {
                self.stopWorkers();
            }
            self.connection.sendGoAway(
                self.summary.last_stream_id,
                .no_error,
                "serve-concurrent",
            ) catch |err| switch (err) {
                // The peer may already have closed after its final response.
                error.ConnectionClosed => {},
                else => return err,
            };
            return self.summary;
        }

        fn maxStreams(self: *Self) usize {
            const configured = self.connection.limits.max_concurrent_streams orelse 100;
            return configured;
        }

        fn shutdownRequested(self: *Self) bool {
            const shutdown = self.options.shutdown orelse return false;
            return shutdown.isSet();
        }

        fn discardPending(self: *Self) void {
            for (self.pending.items) |*stream| stream.deinit();
            self.pending.clearRetainingCapacity();
        }

        fn accept(
            self: *Self,
            stream: StreamType,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            if (stream.stream_id > self.summary.last_stream_id) {
                self.summary.last_stream_id = stream.stream_id;
            }
            if (self.active >= limit) {
                try self.pending.append(self.allocator, stream);
                return;
            }
            try self.enqueue(stream, limit, Context, context, handler);
        }

        fn spawnPending(
            self: *Self,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            while (self.active < limit and self.pending.items.len != 0) {
                const stream = self.pending.orderedRemove(0);
                try self.enqueue(stream, limit, Context, context, handler);
            }
        }

        /// Admit one accepted stream into the worker queue. The first worker is
        /// started lazily; additional workers are added only while every
        /// existing worker is busy, so a sequential connection keeps one
        /// reusable thread instead of spawning one thread per request.
        fn enqueue(
            self: *Self,
            stream: StreamType,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            const slot = try self.allocator.create(Slot);
            errdefer self.allocator.destroy(slot);
            slot.* = .{
                .engine = self,
                .stream = stream,
                .public_stream = undefined,
            };
            slot.public_stream = .{ .engine = self, .slot = slot };
            errdefer slot.deinit(self.allocator);
            self.slots.append(self.allocator, slot) catch |err| return err;
            errdefer _ = self.slots.pop();

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

                        worker.handler(worker.context, &slot.public_stream) catch |err| {
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

        fn find(self: *Self, stream_id: u31) ?*Slot {
            for (self.slots.items) |slot| {
                if (slot.stream.stream_id == stream_id) return slot;
            }
            return null;
        }

        fn drainSlot(self: *Self, stream_id: u31) !void {
            const slot = self.find(stream_id) orelse return;
            var saw_finished = false;
            while (true) {
                const maybe = slot.stream.pollRequestEvent() catch |err| switch (err) {
                    // A finished request reports ConnectionClosed on the next
                    // poll; that is the normal end of the event stream.
                    error.ConnectionClosed => {
                        if (saw_finished) break;
                        slot.body_mutex.lockUncancelable(self.io);
                        slot.body_error = err;
                        slot.body_mutex.unlock(self.io);
                        slot.body_wake.set(self.io);
                        return;
                    },
                    else => {
                        slot.body_mutex.lockUncancelable(self.io);
                        slot.body_error = err;
                        slot.body_mutex.unlock(self.io);
                        slot.body_wake.set(self.io);
                        return;
                    },
                };
                var event = maybe orelse break;
                var moved = false;
                defer if (!moved) event.deinit(self.allocator);
                switch (event) {
                    .data => |*data| {
                        slot.body_mutex.lockUncancelable(self.io);
                        slot.body.appendSlice(self.allocator, data.data) catch |err| {
                            slot.body_error = err;
                            slot.body_mutex.unlock(self.io);
                            slot.body_wake.set(self.io);
                            return;
                        };
                        slot.body_mutex.unlock(self.io);
                    },
                    .trailers => |fields| {
                        slot.body_mutex.lockUncancelable(self.io);
                        if (slot.trailers) |old| freeHeaders(self.allocator, old);
                        slot.trailers = fields;
                        slot.body_mutex.unlock(self.io);
                        event = .finished;
                        moved = true;
                    },
                    .finished => {
                        slot.body_mutex.lockUncancelable(self.io);
                        slot.body_finished = true;
                        slot.body_mutex.unlock(self.io);
                        saw_finished = true;
                    },
                    .reset => |reset| {
                        slot.body_mutex.lockUncancelable(self.io);
                        slot.reset_code = reset.error_code;
                        slot.body_mutex.unlock(self.io);
                    },
                }
                slot.body_wake.set(self.io);
            }
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
                    slot.body_mutex.unlock(self.io);
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
            _ = self;
            const slot = command.slot;
            switch (command.kind) {
                .start_response => |options| {
                    try slot.stream.startResponse(options);
                },
                .start_response_with_body => |value| {
                    try slot.stream.startResponse(value.options);
                    const slices = if (value.data.len == 0) &.{} else &.{value.data};
                    _ = try slot.stream.writeResponseSlices(slices, value.fin);
                    if (value.fin) slot.response_finished = true;
                },
                .write_body => |value| {
                    const slices = if (value.data.len == 0) &.{} else &.{value.data};
                    _ = try slot.stream.writeResponseSlices(slices, value.fin);
                    if (value.fin) slot.response_finished = true;
                },
                .finish_trailers => |fields| {
                    try slot.stream.finishResponseTrailers(fields);
                    slot.response_finished = true;
                },
                .cancel => |code| {
                    try slot.stream.reset(code);
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
                    slot.stream.reset(.cancel) catch {};
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
                slot.stream.reset(.cancel) catch {};
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

fn freeHeaders(allocator: std.mem.Allocator, headers: []http2.Hpack.HeaderField) void {
    if (headers.len != 0) {
        if (headers[0].block_storage != null) {
            http2.Hpack.freeOwnedFields(allocator, headers);
            return;
        }
    }
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}
 
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
    /// command and shutdown wakes.
    poll_interval: std.Io.Duration = .fromMilliseconds(1),
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
            body_wake: std.Io.Event = .unset,
            body_finished: bool = false,
            body_error: ?anyerror = null,
            reset_code: ?u64 = null,
            response_finished: bool = false,
            handler_done: bool = false,
            handler_error: ?anyerror = null,
            canceled: bool = false,
            thread: ?std.Thread = null,

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

            /// Trailers received after the request body. Valid until the
            /// handler returns.
            pub fn trailers(self: Stream) ?[]const http3.Qpack.HeaderField {
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
        active: usize = 0,
        summary: Summary = .{},

        pub fn init(
            session: *Session,
            allocator: std.mem.Allocator,
            io: std.Io,
            options: Options,
        ) Self {
            return .{
                .session = session,
                .allocator = allocator,
                .io = io,
                .options = options,
            };
        }

        pub fn deinit(self: *Self) void {
            self.cancelCommands();
            self.cancelActive();
            self.slots.deinit(self.allocator);
            for (self.pending_heads.items) |*event| event.deinit(self.allocator);
            self.pending_heads.deinit(self.allocator);
            self.commands.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn serve(
            self: *Self,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) anyerror!Summary {
            const Task = struct {
                engine: *Self,
                slot: *Slot,
                context: *Context,
                handler: *const fn (*Context, *Stream) anyerror!void,

                fn run(task: @This()) void {
                    task.handler(task.context, &task.slot.stream) catch |err| {
                        task.slot.handler_error = err;
                    };
                    task.engine.wake.set(task.engine.io);
                    task.slot.handler_done = true;
                }
            };

            const limit = @min(
                self.options.max_streams,
                Adapter.maxStreams(self.session),
            );
            if (limit == 0) return error.InvalidServeOptions;

            var idle_deadline: ?std.Io.Clock.Timestamp = null;
            errdefer {
                self.cancelCommands();
                self.cancelActive();
            }

            while (true) {
                try self.spawnPending(limit, Context, context, handler, Task);
                try self.drainCommands();
                self.reap();
                try self.spawnPending(limit, Context, context, handler, Task);

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
            comptime Task: type,
        ) !void {
            while (self.active < limit and self.pending_heads.items.len != 0) {
                const event = self.pending_heads.orderedRemove(0);
                const slot = try self.createSlot(event);
                errdefer {
                    slot.deinit(self.allocator);
                    self.allocator.destroy(slot);
                }
                const thread = std.Thread.spawn(.{}, Task.run, .{Task{
                    .engine = self,
                    .slot = slot,
                    .context = context,
                    .handler = handler,
                }}) catch |err| {
                    slot.deinit(self.allocator);
                    self.allocator.destroy(slot);
                    return err;
                };
                slot.thread = thread;
                self.active += 1;
                self.summary.accepted += 1;
            }
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
            var scratch: [16 * 1024]u8 = undefined;
            while (true) {
                const available = Adapter.availableBody(
                    self.session,
                    from,
                    stream_id,
                ) catch |err| {
                    slot.body_mutex.lockUncancelable(self.io);
                    slot.body_error = err;
                    slot.body_mutex.unlock(self.io);
                    slot.body_wake.set(self.io);
                    return;
                };
                if (available == 0) break;
                const count = Adapter.readBody(
                    self.session,
                    from,
                    stream_id,
                    &scratch,
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
                slot.body_mutex.unlock(self.io);
            }
            slot.body_wake.set(self.io);
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
                    slot.body_mutex.unlock(self.io);
                    return count;
                }
                if (slot.body_finished) {
                    slot.body_mutex.unlock(self.io);
                    return null;
                }
                slot.body_mutex.unlock(self.io);
                slot.body_wake.waitTimeout(self.io, timeoutValue(deadline)) catch |err| switch (err) {
                    error.Timeout => return error.Timeout,
                    error.Canceled => return error.Canceled,
                };
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
            command.done.waitTimeout(self.io, timeoutValue(deadline)) catch |err| {
                command.abandoned.store(true, .release);
                // The handler's stack owns the command and its payload. Wait
                // for the owner to observe abandonment or finish execution
                // before unwinding that stack.
                command.done.wait(self.io) catch {};
                return switch (err) {
                    error.Timeout => error.Timeout,
                    error.Canceled => error.Canceled,
                };
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
                    if (value.body_length == 0) slot.response_finished = true;
                },
                .write_body => |value| {
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
                if (!slot.handler_done) {
                    index += 1;
                    continue;
                }
                if (!slot.response_finished and slot.reset_code == null) {
                    Adapter.cancel(self.session, slot.from, slot.stream_id, 0) catch {};
                }
                if (slot.handler_error != null) {
                    self.summary.failed += 1;
                } else {
                    self.summary.completed += 1;
                }
                if (slot.reset_code != null) self.summary.canceled += 1;
                if (slot.thread) |thread| thread.join();
                _ = self.slots.orderedRemove(index);
                slot.deinit(self.allocator);
                self.allocator.destroy(slot);
                self.active -|= 1;
            }
        }

        fn cancelActive(self: *Self) void {
            for (self.slots.items) |slot| {
                slot.body_mutex.lockUncancelable(self.io);
                slot.canceled = true;
                slot.body_mutex.unlock(self.io);
                slot.body_wake.set(self.io);
            }
            self.cancelCommands();
            for (self.slots.items) |slot| {
                if (slot.thread) |thread| thread.join();
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

        fn readOrWake(self: *Self, deadline: ?std.Io.Clock.Timestamp) anyerror!?StreamingRequestEvent {
            // Do not clear a wake that belongs to an already queued command.
            self.wake.reset();
            self.mutex.lockUncancelable(self.io);
            const has_commands = self.commands.items.len != 0;
            self.mutex.unlock(self.io);
            if (has_commands and !self.commands_blocked) return null;

            // Poll the receive path with a short absolute budget instead of
            // cancelling a concurrent `std.Io` operation. The wake event is
            // checked between polls, so command latency is bounded by the
            // configured poll interval while session state stays single-owner.
            const poll_deadline = std.Io.Clock.Timestamp.addDuration(
                std.Io.Clock.Timestamp.now(self.io, .awake),
                .{ .raw = self.options.poll_interval, .clock = .awake },
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

fn timeoutValue(deadline: ?std.Io.Clock.Timestamp) std.Io.Timeout {
    return if (deadline) |value| .{ .deadline = value } else .none;
}

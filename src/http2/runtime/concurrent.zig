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
            thread: ?std.Thread = null,

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

            pub fn trailers(self: Stream) ?[]const http2.Hpack.HeaderField {
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
                    task.handler(task.context, &task.slot.public_stream) catch |err| {
                        task.slot.handler_error = err;
                    };
                    task.engine.wake.set(task.engine.io);
                    task.slot.handler_done = true;
                }
            };

            const limit = @min(self.options.max_streams, self.maxStreams());
            if (limit == 0) return error.InvalidServeOptions;

            var idle_deadline: ?std.Io.Clock.Timestamp = null;
            var peer_closed = false;
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
                        .request => |stream| try self.accept(stream, limit, Context, context, handler, Task),
                        .stream => |stream_id| try self.drainSlot(stream_id),
                        .progress, .wake => {},
                    }
                    idle_deadline = null;
                }
            }

            if (peer_closed) {
                self.cancelCommands();
                self.cancelActive();
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
            comptime Task: type,
        ) !void {
            if (stream.stream_id > self.summary.last_stream_id) {
                self.summary.last_stream_id = stream.stream_id;
            }
            if (self.active >= limit) {
                try self.pending.append(self.allocator, stream);
                return;
            }
            try self.spawn(stream, Context, context, handler, Task);
        }

        fn spawnPending(
            self: *Self,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
            comptime Task: type,
        ) !void {
            while (self.active < limit and self.pending.items.len != 0) {
                const stream = self.pending.orderedRemove(0);
                try self.spawn(stream, Context, context, handler, Task);
            }
        }

        fn spawn(
            self: *Self,
            stream: StreamType,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
            comptime Task: type,
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
            const thread = std.Thread.spawn(.{}, Task.run, .{Task{
                .engine = self,
                .slot = slot,
                .context = context,
                .handler = handler,
            }}) catch |err| {
                _ = self.slots.pop();
                slot.deinit(self.allocator);
                self.allocator.destroy(slot);
                return err;
            };
            slot.thread = thread;
            self.active += 1;
            self.summary.accepted += 1;
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
            _ = self;
            const slot = command.slot;
            switch (command.kind) {
                .start_response => |options| {
                    try slot.stream.startResponse(options);
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
                if (!slot.handler_done) {
                    index += 1;
                    continue;
                }
                if (!slot.response_finished and slot.reset_code == null) {
                    slot.stream.reset(.cancel) catch {};
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

fn timeoutValue(deadline: ?std.Io.Clock.Timestamp) std.Io.Timeout {
    return if (deadline) |value| .{ .deadline = value } else .none;
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
 
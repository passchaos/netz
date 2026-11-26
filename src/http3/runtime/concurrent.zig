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
const deadline_policy = @import("../../internal/deadline.zig");
const body_writer = @import("concurrent/body_write.zig");
const borrowed_command = @import("../../internal/borrowed_command.zig");

/// Upper bound on the per-stream body reservation derived from a declared
/// Content-Length. Larger bodies grow normally.
const body_preallocate_cap: usize = 64 * 1024;
const net = std.Io.net;
const Error = @import("error.zig").Error;
const Fifo = @import("../../internal/fifo.zig").Fifo;
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
    /// Maximum receive budget while at least one handler is active. The
    /// command wake races the receive, so this only bounds an otherwise idle
    /// read; lower values cost more wakeups without lowering command latency.
    command_poll_interval: std.Io.Duration = .fromMicroseconds(100),
    /// Per-stream request DATA resident in the owner buffer. Null uses the
    /// session's `max_stream_buffer`; the total body remains bounded by
    /// `max_body_bytes`.
    max_buffered_body_bytes: ?usize = null,
    /// Stack size for handler workers. A per-connection pool grows lazily up
    /// to `max_streams`, so this bounds virtual memory for connections that
    /// actually multiplex. Raise it for handlers with deep native stacks.
    worker_stack_size: usize = 1024 * 1024,
    /// Optional cap on worker threads. Null keeps one worker per possible
    /// concurrent handler (`max_streams`). Lower values reduce thread
    /// scheduling contention for CPU-bound handlers; queued handlers wait in
    /// arrival order. Values are clamped to `1..max_streams`.
    max_worker_threads: ?usize = null,
    /// Run handlers for requests that ended with their head on the QUIC
    /// owner instead of a worker thread. The handler may return
    /// `error.InlineDeclined` before producing side effects to fall back to
    /// the worker path.
    inline_bodyless: bool = false,
};

pub const Summary = struct {
    accepted: usize = 0,
    completed: usize = 0,
    failed: usize = 0,
    canceled: usize = 0,
    last_stream_id: u64 = 0,
    /// Total handler worker threads spawned for this serve call.
    workers_spawned: usize = 0,
};

/// Adapter contract. `from` is the peer address carried by the event; sessions
/// bound to one peer ignore it.
///
///   receive(session, deadline) Error!StreamingRequestEvent
///   availableBody(session, from, stream_id) Error!usize
///   readBody(session, from, stream_id, out) Error!usize
///   startResponse(session, from, stream_id, response, body_length, deadline) Error!void
///   sendBody(session, from, stream_id, data, fin, progress, deadline) Error!void
///   finishTrailers(session, from, stream_id, trailers, deadline) Error!void
///   cancel(session, from, stream_id, code, deadline) Error!void
///   goaway(session, last_stream_id) Error!void
///   maxStreams(session) usize
///   maxBodyBuffer(session) usize
pub fn Engine(comptime Session: type, comptime Adapter: type) type {
    return struct {
        const Self = @This();

        const Command = struct {
            slot: *Slot,
            kind: Kind,
            deadline: ?std.Io.Clock.Timestamp = null,
            count: usize = 0,
            result: ?anyerror = null,
            /// Published before done; abandoned commands that were skipped
            /// must not look like successful writes.
            succeeded: bool = false,
            done: std.Io.Event = .unset,
            abandoned: std.atomic.Value(bool) = .init(false),
            informational_written: usize = 0,
            response_started: bool = false,
            body_write: body_writer.State = .{},

            const Kind = union(enum) {
                informational: struct {
                    response: http3.InformationalResponse,
                },
                start_response: struct {
                    response: http3.Response,
                    body_length: ?usize,
                },
                write_body: struct {
                    data: []const u8,
                    fin: bool,
                },
                /// Response head and its first DATA contribution in one owner
                /// turn. A sequential request otherwise pays two wake/command
                /// round trips for what is a single logical response.
                start_response_with_body: struct {
                    response: http3.Response,
                    body_length: ?usize,
                    data: []const u8,
                    fin: bool,
                    informational: []const http3.InformationalResponse = &.{},
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
            /// The request stream ended with the head, so no body events are
            /// needed before running the handler.
            request_finished: bool = false,
            /// True while this slot's handler runs on the QUIC owner.
            /// Per-slot, because a worker may run another handler while the
            /// owner is inline.
            handler_inline: bool = false,
            /// A small declared body is being buffered before the handler
            /// runs on the owner.
            deferred_inline: bool = false,
            deferred_since: ?std.Io.Clock.Timestamp = null,
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
            response_started: bool = false,
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

            pub const DataWriteProgress = body_writer.Progress;

            /// True when this handler runs on the QUIC owner. Handlers that
            /// cannot finish without blocking must return
            /// `error.InlineDeclined` before side effects.
            pub fn isInline(self: Stream) bool {
                return self.slot.handler_inline;
            }

            /// True when the whole request body is already buffered, so a
            /// streaming reader cannot block on `nextBody`.
            pub fn inlineBodyComplete(self: Stream) bool {
                return self.slot.body_finished;
            }

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

            pub fn writeInformationalResponse(self: Stream, status: u16, headers: []const http3.Qpack.HeaderField) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .informational = .{ .response = .{ .status = status, .headers = headers } } } };
                return self.engine.submit(&command, null);
            }

            pub fn writeInformationalResponseWithDeadline(self: Stream, status: u16, headers: []const http3.Qpack.HeaderField, deadline: std.Io.Clock.Timestamp) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .informational = .{ .response = .{ .status = status, .headers = headers } } } };
                return self.engine.submit(&command, deadline);
            }

            pub fn writeInformationalResponseWithTimeout(self: Stream, status: u16, headers: []const http3.Qpack.HeaderField, timeout: std.Io.Duration) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.writeInformationalResponseWithDeadline(
                    status,
                    headers,
                    .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }),
                );
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

            pub fn startResponseWithTimeout(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                timeout: std.Io.Duration,
            ) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.startResponseWithDeadline(
                    response,
                    body_length,
                    .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }),
                );
            }

            /// Submit the response head and its first DATA contribution as one
            /// owner command. `data` must stay valid until this call returns.
            /// HEAD/204/304 responses still suppress the body.
            pub fn startResponseWithBody(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response_with_body = .{
                    .response = response,
                    .body_length = body_length,
                    .data = data,
                    .fin = fin,
                } } };
                return self.engine.submit(&command, null);
            }

            /// Deadline-bounded spelling consistent with
            /// `startResponseWithBodyWithTimeout`.
            pub fn startResponseWithBodyWithDeadline(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                return self.startResponseWithBodyAndDeadline(
                    response,
                    body_length,
                    data,
                    fin,
                    deadline,
                );
            }

            /// Compatibility spelling; prefer
            /// `startResponseWithBodyWithDeadline`.
            pub fn startResponseWithBodyAndDeadline(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response_with_body = .{
                    .response = response,
                    .body_length = body_length,
                    .data = data,
                    .fin = fin,
                } } };
                return self.engine.submit(&command, deadline);
            }

            pub fn startResponseWithBodyWithTimeout(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
                timeout: std.Io.Duration,
            ) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.startResponseWithBodyAndDeadline(
                    response,
                    body_length,
                    data,
                    fin,
                    .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }),
                );
            }

            /// Submit interim heads, the final head and the first body part.
            /// Non-final bodies may continue through writeData/trailers; a
            /// final part also sends any trailers supplied in `response`.
            pub fn startResponseWithBodyAndInformational(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
                informational: []const http3.InformationalResponse,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response_with_body = .{
                    .response = response,
                    .body_length = body_length,
                    .data = data,
                    .fin = fin,
                    .informational = informational,
                } } };
                return self.engine.submit(&command, null);
            }

            pub fn startResponseWithBodyAndInformationalWithDeadline(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
                informational: []const http3.InformationalResponse,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .start_response_with_body = .{
                    .response = response,
                    .body_length = body_length,
                    .data = data,
                    .fin = fin,
                    .informational = informational,
                } } };
                return self.engine.submit(&command, deadline);
            }

            pub fn startResponseWithBodyAndInformationalWithTimeout(
                self: Stream,
                response: http3.Response,
                body_length: ?usize,
                data: []const u8,
                fin: bool,
                informational: []const http3.InformationalResponse,
                timeout: std.Io.Duration,
            ) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.startResponseWithBodyAndInformationalWithDeadline(
                    response,
                    body_length,
                    data,
                    fin,
                    informational,
                    .fromNow(
                        self.engine.io,
                        .{ .raw = timeout, .clock = .awake },
                    ),
                );
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
                var progress: DataWriteProgress = .{};
                return self.writeDataWithProgressAndDeadline(data, fin, &progress, deadline);
            }

            /// Report the exact confirmed DATA prefix on every return path.
            /// After an error, retry data[progress.committed_bytes..] only if
            /// retryable is true, and request FIN only if it was not committed.
            pub fn writeDataWithProgress(self: Stream, data: []const u8, fin: bool, progress: *DataWriteProgress) anyerror!void {
                return self.writeDataWithProgressAndDeadline(data, fin, progress, null);
            }

            pub fn writeDataWithProgressAndDeadline(
                self: Stream,
                data: []const u8,
                fin: bool,
                progress: *DataWriteProgress,
                deadline: ?std.Io.Clock.Timestamp,
            ) anyerror!void {
                progress.* = .{};
                var command = Command{ .slot = self.slot, .kind = .{ .write_body = .{
                    .data = data,
                    .fin = fin,
                } } };
                defer progress.* = command.body_write.progress;
                return self.engine.submit(&command, deadline);
            }

            pub fn writeDataWithProgressAndTimeout(self: Stream, data: []const u8, fin: bool, progress: *DataWriteProgress, timeout: std.Io.Duration) anyerror!void {
                progress.* = .{};
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.writeDataWithProgressAndDeadline(data, fin, progress, .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }));
            }

            pub fn writeDataWithTimeout(
                self: Stream,
                data: []const u8,
                fin: bool,
                timeout: std.Io.Duration,
            ) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.writeDataWithDeadline(
                    data,
                    fin,
                    .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }),
                );
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

            pub fn finishWithTrailersWithDeadline(
                self: Stream,
                fields: []const http3.Qpack.HeaderField,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .finish_trailers = fields } };
                return self.engine.submit(&command, deadline);
            }

            pub fn finishWithTrailersWithTimeout(
                self: Stream,
                fields: []const http3.Qpack.HeaderField,
                timeout: std.Io.Duration,
            ) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.finishWithTrailersWithDeadline(
                    fields,
                    .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }),
                );
            }

            /// Cancel this stream. The peer observes `code` as the HTTP/3
            /// application error code.
            pub fn reset(self: Stream, code: u64) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .cancel = code } };
                return self.engine.submit(&command, null);
            }

            pub fn resetWithDeadline(
                self: Stream,
                code: u64,
                deadline: std.Io.Clock.Timestamp,
            ) anyerror!void {
                var command = Command{ .slot = self.slot, .kind = .{ .cancel = code } };
                return self.engine.submit(&command, deadline);
            }

            pub fn resetWithTimeout(
                self: Stream,
                code: u64,
                timeout: std.Io.Duration,
            ) anyerror!void {
                if (timeout.nanoseconds <= 0) return error.Timeout;
                return self.resetWithDeadline(
                    code,
                    .fromNow(self.engine.io, .{ .raw = timeout, .clock = .awake }),
                );
            }
        };

        session: *Session,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        mutex: std.Io.Mutex = .init,
        commands: Fifo(*Command) = .{},
        commands_blocked: bool = false,
        wake: std.Io.Event = .unset,
        slots: std.ArrayList(*Slot) = .empty,
        pending_heads: Fifo(StreamingRequestEvent) = .{},
        /// Events completed by a receive that raced a command wake. The wake
        /// path retains them so a completed packet is never dropped.
        pending_events: Fifo(StreamingRequestEvent) = .{},
        pending_event_error: ?anyerror = null,
        /// Ready handlers consumed by a lazily grown per-connection worker
        /// pool. A sequential connection keeps one reusable thread instead of
        /// spawning a thread for every request.
        task_mutex: std.Io.Mutex = .init,
        task_cond: std.Io.Condition = .init,
        task_queue: Fifo(*Slot) = .{},
        workers: std.ArrayList(std.Thread) = .empty,
        idle_workers: usize = 0,
        stopping: bool = false,
        max_buffered_body_bytes: usize = 1,
        active: usize = 0,
        /// Slots waiting for a small declared body so the handler can run on
        /// the owner without a worker handoff.
        deferred_slots: std.ArrayList(*Slot) = .empty,
        /// True while a handler runs on the owner. Stream command submissions
        /// then execute in place instead of crossing to the owner.
        inline_active: bool = false,
        /// Slot whose handler currently runs inline on the owner. Commands
        /// from any other slot (including workers) must go through the queue
        /// even while an inline handler is active.
        inline_slot: ?*Slot = null,
        inline_pump: ?*const fn (*Self, *anyopaque) anyerror!void = null,
        inline_pump_state: ?*anyopaque = null,
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
            self.deferred_slots.deinit(self.allocator);
            for (self.pending_heads.slice()) |*event| event.deinit(self.allocator);
            self.pending_heads.deinit(self.allocator);
            for (self.pending_events.slice()) |*event| event.deinit(self.allocator);
            self.pending_events.deinit(self.allocator);
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
                    if (self.active == 0 and self.pending_heads.isEmpty()) {
                        break;
                    }
                }

                if (self.active == 0 and self.pending_heads.isEmpty()) {
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
            for (self.pending_heads.slice()) |*event| event.deinit(self.allocator);
            self.pending_heads.clearRetainingCapacity();
        }

        fn deferredExpired(self: *const Self, slot: *const Slot) bool {
            const since = slot.deferred_since orelse return true;
            const now = std.Io.Clock.Timestamp.now(self.io, .awake);
            return now.raw.nanoseconds - since.raw.nanoseconds >
                std.time.ns_per_ms;
        }

        fn spawnPending(
            self: *Self,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            var deferred_index: usize = 0;
            while (deferred_index < self.deferred_slots.items.len) {
                const slot = self.deferred_slots.items[deferred_index];
                const complete = slot.body_finished and !slot.body_blocked and
                    slot.body_error == null and slot.reset_code == null;
                const fallback = slot.body_blocked or slot.body_error != null or
                    slot.reset_code != null or
                    self.deferredExpired(slot);
                if (complete and !fallback) {
                    if (self.inline_active or self.active >= limit) {
                        deferred_index += 1;
                        continue;
                    }
                    _ = self.deferred_slots.orderedRemove(deferred_index);
                    slot.deferred_inline = false;
                    try self.runInline(slot, limit, Context, context, handler);
                    continue;
                }
                if (!fallback) {
                    deferred_index += 1;
                    continue;
                }
                _ = self.deferred_slots.orderedRemove(deferred_index);
                slot.deferred_inline = false;
                try self.enqueue(slot, limit, Context, context, handler);
            }

            while (self.active < limit and !self.pending_heads.isEmpty()) {
                const event = self.pending_heads.popFront().?;
                const slot = try self.createSlot(event);
                errdefer {
                    _ = self.slots.pop();
                    slot.deinit(self.allocator);
                    self.allocator.destroy(slot);
                }
                if (self.options.inline_bodyless and !self.inline_active and
                    slot.request_finished)
                {
                    try self.runInline(slot, limit, Context, context, handler);
                } else {
                    try self.enqueue(slot, limit, Context, context, handler);
                }
            }
        }

        fn workerLimit(self: *const Self, max_streams: usize) usize {
            const configured = self.options.max_worker_threads orelse max_streams;
            return @max(1, @min(max_streams, configured));
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
                self.workers.items.len < self.workerLimit(limit);
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
                        while (engine.task_queue.isEmpty() and !engine.stopping) {
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
                        const slot = engine.task_queue.popFront().?;
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
            self.summary.workers_spawned += 1;
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
                .request_finished = head.request_finished,
                // A head-complete request has no body events left; publishing
                // this before the handler starts keeps an inline `nextBody`
                // from waiting for a `.finished` event the owner cannot route.
                .body_finished = head.request_finished,
            };
            errdefer slot.deinit(self.allocator);
            // Reserve the declared body once; the cap keeps a large
            // declaration from front-loading per-stream memory.
            if (slot.head.content_length) |length| {
                if (length != 0) {
                    slot.body.ensureTotalCapacity(
                        self.allocator,
                        @min(length, body_preallocate_cap),
                    ) catch {};
                }
            }
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
                            const request = message.value.head.request;
                            if (self.options.inline_bodyless and
                                !self.inline_active and
                                !request.request_finished and
                                request.content_length != null and
                                request.content_length.? != 0 and
                                request.content_length.? <=
                                    self.max_buffered_body_bytes)
                            {
                                // The body is small and bounded; buffer it on
                                // the owner and run the handler inline once
                                // the stream finishes.
                                moved = true;
                                const slot = try self.createSlot(owned);
                                slot.deferred_inline = true;
                                slot.deferred_since =
                                    std.Io.Clock.Timestamp.now(self.io, .awake);
                                try self.deferred_slots.append(
                                    self.allocator,
                                    slot,
                                );
                                return;
                            }
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
            return borrowed_command.submit(self, command, deadline, submitInline, waitForEvent);
        }

        /// Execute a command from the owner thread. Congestion, pacing, and
        /// flow-control limits retry after processing one inbound event,
        /// which is the progress the normal command loop gets between
        /// re-queues.
        fn submitInline(self: *Self, command: *Command) anyerror!void {
            while (true) {
                self.execute(command) catch |err| switch (err) {
                    error.FlowControlBlocked,
                    error.CongestionLimited,
                    error.PacingLimited,
                    => {
                        const pump = self.inline_pump orelse return err;
                        try pump(self, self.inline_pump_state orelse return err);
                        continue;
                    },
                    else => return err,
                };
                return;
            }
        }

        /// Run one head-complete request on the owner. The handler may return
        /// `error.InlineDeclined` before side effects, in which case the slot
        /// moves to the worker queue unchanged.
        fn runInline(
            self: *Self,
            slot: *Slot,
            limit: usize,
            comptime Context: type,
            context: *Context,
            comptime handler: *const fn (*Context, *Stream) anyerror!void,
        ) !void {
            const Pump = struct {
                fn pump(engine: *Self, raw: *anyopaque) anyerror!void {
                    _ = raw;
                    const event = try engine.readOrWake(null);
                    if (event) |value| try engine.route(value);
                }
            };

            self.active += 1;
            self.summary.accepted += 1;
            self.inline_active = true;
            self.inline_slot = slot;
            self.inline_pump = Pump.pump;
            defer {
                self.inline_active = false;
                self.inline_slot = null;
                self.inline_pump = null;
                self.inline_pump_state = null;
            }

            var declined = false;
            slot.handler_inline = true;
            handler(context, &slot.stream) catch |err| {
                if (err == error.InlineDeclined) {
                    declined = true;
                } else {
                    slot.handler_error = err;
                }
            };
            slot.handler_inline = false;
            if (declined) {
                // Drop inline mode before the worker can pick the slot up.
                self.inline_active = false;
                self.inline_slot = null;
                self.inline_pump = null;
                self.inline_pump_state = null;
                try self.enqueue(slot, limit, Context, context, handler);
                return;
            }

            slot.body_mutex.lockUncancelable(self.io);
            slot.handler_done = true;
            slot.body_mutex.unlock(self.io);
            self.reapSlot(slot);
        }

        fn drainCommands(self: *Self) !void {
            return borrowed_command.drain(self, execute);
        }

        fn execute(self: *Self, command: *Command) anyerror!void {
            if (command.deadline) |until| _ = try deadline_policy.usableAwake(self.io, until);
            const slot = command.slot;
            switch (command.kind) {
                .informational => |value| {
                    if (slot.response_started or slot.response_finished) return error.UnexpectedFrame;
                    try Adapter.sendInformational(self.session, slot.from, slot.stream_id, value.response, command.deadline);
                },
                .start_response => |value| {
                    var response = value.response;
                    response.request_method = slot.head.method;
                    try Adapter.startResponse(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        response,
                        value.body_length,
                        command.deadline,
                    );
                    slot.response_started = true;
                    slot.suppress_body = response.suppressesBody();
                    if (value.body_length == 0 or slot.suppress_body) {
                        slot.response_finished = true;
                    }
                },
                .start_response_with_body => |value| {
                    if (!command.response_started and slot.response_started) return error.UnexpectedFrame;
                    var response = value.response;
                    response.request_method = slot.head.method;
                    if (!command.response_started) {
                        var validation = response;
                        validation.body = value.data;
                        try validation.validateHead(self.allocator, Adapter.peerSettings(self.session));
                        const declared = try http3.contentLength(response.headers);
                        if (declared != null and value.body_length != null and declared.? != value.body_length.?) return error.InvalidContentLength;
                        const expected = value.body_length orelse declared;
                        if (!response.suppressesBody()) {
                            if (expected) |length| {
                                if (value.data.len > length or (value.fin and value.data.len != length)) return error.InvalidContentLength;
                            }
                        }
                        for (value.informational) |info| try info.validate(self.allocator, Adapter.peerSettings(self.session));
                    }
                    slot.suppress_body = response.suppressesBody();
                    if (value.informational.len != 0 and value.fin and !slot.suppress_body and (command.deadline == null or (@hasDecl(Adapter, "bounded_complete") and Adapter.bounded_complete))) {
                        try Adapter.sendCompleteResponseWithInformational(
                            self.session,
                            slot.from,
                            slot.stream_id,
                            value.informational,
                            response,
                            value.body_length,
                            value.data,
                            slot.head.method,
                            command.deadline,
                        );
                        slot.response_started = true;
                        slot.response_finished = true;
                        return;
                    }
                    while (command.informational_written < value.informational.len) {
                        try Adapter.sendInformational(self.session, slot.from, slot.stream_id, value.informational[command.informational_written], command.deadline);
                        command.informational_written += 1;
                    }
                    if (slot.suppress_body) {
                        try Adapter.startResponse(self.session, slot.from, slot.stream_id, response, value.body_length, command.deadline);
                        slot.response_started = true;
                        slot.response_finished = true;
                        return;
                    }
                    // A complete buffered response fits in one QUIC packet, so
                    // skip the separate HEADERS and DATA submissions. The fast
                    // path requires the endpoint control streams to be ready;
                    // a very early first response falls back to the regular
                    // head+body path instead of failing the stream.
                    if (!command.response_started and self.active <= 1 and
                        value.fin and
                        value.data.len != 0 and
                        value.response.trailers.len == 0 and
                        (command.deadline == null or (@hasDecl(Adapter, "bounded_complete") and Adapter.bounded_complete)) and
                        (value.body_length == null or
                            value.body_length.? == value.data.len))
                    {
                        if (Adapter.sendCompleteResponse(
                            self.session,
                            slot.from,
                            slot.stream_id,
                            response,
                            value.body_length,
                            value.data,
                            slot.head.method,
                            command.deadline,
                        )) |_| {
                            slot.response_started = true;
                            slot.response_finished = true;
                            return;
                        } else |err| switch (err) {
                            error.MissingSettings, error.DatagramTooLarge, error.FlowControlBlocked => {},
                            else => return err,
                        }
                    }
                    if (!command.response_started) {
                        try Adapter.startResponse(self.session, slot.from, slot.stream_id, response, value.body_length, command.deadline);
                        command.response_started = true;
                        slot.response_started = true;
                    }
                    try self.writeCommandBody(command, value.data, value.fin and response.trailers.len == 0);
                    if (value.fin and response.trailers.len != 0) try Adapter.finishTrailers(self.session, slot.from, slot.stream_id, response.trailers, command.deadline);
                    if (value.fin) slot.response_finished = true;
                },
                .write_body => |value| {
                    if (slot.suppress_body) {
                        if (value.data.len != 0) return error.InvalidContentLength;
                        command.body_write.completed = true;
                        command.body_write.progress.fin_committed = value.fin;
                        if (value.fin) slot.response_finished = true;
                        return;
                    }
                    try self.writeCommandBody(command, value.data, value.fin);
                    if (value.fin) slot.response_finished = true;
                },
                .finish_trailers => |trailers| {
                    try Adapter.finishTrailers(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        trailers,
                        command.deadline,
                    );
                    slot.response_finished = true;
                },
                .cancel => |code| {
                    try Adapter.cancel(
                        self.session,
                        slot.from,
                        slot.stream_id,
                        code,
                        command.deadline,
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
                slot.body_mutex.unlock(self.io);
                if (!done) {
                    index += 1;
                    continue;
                }
                self.reapSlot(slot);
            }
        }

        fn writeCommandBody(self: *Self, command: *Command, data: []const u8, fin: bool) anyerror!void {
            const Context = struct {
                engine: *Self,
                slot: *Slot,
                fn send(ctx: *@This(), suffix: []const u8, final: bool, progress: *body_writer.Progress, deadline: ?std.Io.Clock.Timestamp) anyerror!void {
                    return Adapter.sendBody(ctx.engine.session, ctx.slot.from, ctx.slot.stream_id, suffix, final, progress, deadline);
                }
            };
            var context = Context{ .engine = self, .slot = command.slot };
            defer if (command.body_write.progress.fin_committed) {
                command.slot.response_finished = true;
            };
            return command.body_write.write(data, fin, command.deadline, &context, Context.send);
        }

        /// Retire one completed slot. Inline handlers call this directly so a
        /// batch of N owner-run requests does not rescan every live slot after
        /// each handler.
        fn reapSlot(self: *Self, slot: *Slot) void {
            if (!slot.response_finished and slot.reset_code == null) {
                Adapter.cancel(self.session, slot.from, slot.stream_id, 0, null) catch {};
            }
            if (slot.handler_error != null) {
                self.summary.failed += 1;
            } else {
                self.summary.completed += 1;
            }
            if (slot.reset_code != null) self.summary.canceled += 1;
            self.removeSlot(slot);
            slot.deinit(self.allocator);
            self.allocator.destroy(slot);
            self.active -|= 1;
        }

        fn removeSlot(self: *Self, slot: *Slot) void {
            var index = self.slots.items.len;
            while (index > 0) {
                index -= 1;
                if (self.slots.items[index] == slot) {
                    _ = self.slots.swapRemove(index);
                    return;
                }
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
                Adapter.cancel(self.session, slot.from, slot.stream_id, 0, null) catch {};
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
            for (pending.slice()) |command| {
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
            if (self.pending_event_error) |err| {
                self.pending_event_error = null;
                return err;
            }
            if (!self.pending_events.isEmpty()) {
                return self.pending_events.popFront().?;
            }

            // Do not clear a wake that belongs to an already queued command.
            self.wake.reset();
            self.mutex.lockUncancelable(self.io);
            const has_commands = !self.commands.isEmpty();
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

            // The zio loop's cached awake clock is a scan snapshot: it does
            // not advance while a task runs without yielding. Composing a new
            // deadline from it can produce a timestamp in the past, which
            // `usableAwake` rejects as an immediate timeout and turns the
            // accept pump into a busy loop. Deadlines need a fresh read; the
            // cached snapshot is only safe for observation.
            const poll_deadline = std.Io.Clock.Timestamp.fromNow(
                self.io,
                .{ .raw = poll, .clock = .awake },
            );
            const use_deadline = if (deadline) |value|
                if (value.raw.nanoseconds < poll_deadline.raw.nanoseconds) value else poll_deadline
            else
                poll_deadline;
            return self.receiveOrWake(deadline, use_deadline);
        }

        /// Race one receive against the command wake. A wake that wins cancels
        /// the receive; a receive that completes late is retained in
        /// `pending_events` and delivered on the next owner iteration. The
        /// receive path is a cancellation point, and packets it fully processes
        /// remain queued in the session, so no packet is dropped.
        fn receiveOrWake(
            self: *Self,
            receive_deadline: ?std.Io.Clock.Timestamp,
            poll_deadline: std.Io.Clock.Timestamp,
        ) anyerror!?StreamingRequestEvent {
            if (self.workers.items.len == 0) {
                // Commands and body progress only come from handler workers.
                // With none alive, receive on the owner task instead of
                // spawning a wake arm that would be canceled immediately.
                return Adapter.receive(self.session, poll_deadline) catch |err| switch (err) {
                    error.Timeout => null,
                    else => |other| return other,
                };
            }
            const Selection = union(enum) {
                event: Error!StreamingRequestEvent,
                wake: std.Io.Cancelable!void,
            };
            var results: [2]Selection = undefined;
            var select: std.Io.Select(Selection) = .init(self.io, &results);
            defer while (select.cancel()) |late| switch (late) {
                .event => |result| {
                    if (result) |event| self.retainEvent(event) else |err| switch (err) {
                        error.Timeout, error.Canceled => {},
                        else => self.pending_event_error = err,
                    }
                },
                .wake => |result| result catch {},
            };
            // A periodic owner wake must not become an already-expired
            // admission budget before the receive task can be scheduled.
            try select.concurrent(.event, Adapter.receive, .{ self.session, receive_deadline });
            try select.concurrent(.wake, waitForCommandOrPoll, .{ self.io, &self.wake, poll_deadline });
            switch (try select.await()) {
                .event => |result| return result catch |err| switch (err) {
                    error.Timeout => null,
                    else => |other| return other,
                },
                .wake => |result| try result,
            }
            return null;
        }

        fn retainEvent(self: *Self, event: StreamingRequestEvent) void {
            self.pending_events.append(self.allocator, event) catch {
                var owned = event;
                owned.deinit(self.allocator);
                self.pending_event_error = error.OutOfMemory;
            };
        }
    };
}

/// One wake arm observes commands or an idle poll boundary. The actual
/// receive keeps its independent caller deadline and can enter after scheduling.
fn waitForCommandOrPoll(io: std.Io, event: *std.Io.Event, poll_deadline: std.Io.Clock.Timestamp) std.Io.Cancelable!void {
    waitForEvent(io, event, poll_deadline) catch |err| switch (err) {
        error.Timeout => {},
        error.Canceled => return error.Canceled,
        else => unreachable,
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

//! Caller/worker state for one streaming request on the shared dispatcher.
//!
//! The caller writes body chunks and reads response events; the dispatcher
//! worker owns the lease and pumps QUIC events. Both sides synchronize through
//! one mutex and two conditions, and the worker's receive wait is woken by
//! `activity` whenever the caller enqueues work.

const std = @import("std");
const Guard = @import("../../../internal/mutex_guard.zig").Guard;
const deadline_policy = @import("../../../internal/deadline.zig");
const http3 = @import("../../mod.zig");
const Fifo = @import("../../../internal/fifo.zig").Fifo;

/// Maximum request bytes queued before `writeBody` reports backpressure.
pub const max_pending_write_bytes: usize = 64 * 1024;
/// Maximum response bytes resident before the worker stops reading DATA.
pub const max_pending_read_bytes: usize = 256 * 1024;

pub const CallbackSink = struct {
    context: *anyopaque,
    begin: *const fn (
        context: *anyopaque,
        head: http3.DecodedResponseHead,
    ) anyerror!void,
    data: *const fn (
        context: *anyopaque,
        bytes: []const u8,
    ) anyerror!void,
    end: *const fn (
        context: *anyopaque,
        trailers: []const http3.Qpack.HeaderField,
    ) anyerror!void,
    /// Interim heads borrow their queued storage only for this callback.
    informational: ?*const fn (*anyopaque, http3.DecodedResponseHead) void = null,
};

pub fn Stream(comptime Pool: type) type {
    return struct {
        pool: *Pool,
        allocator: std.mem.Allocator,
        io: std.Io,
        mutex: std.Io.Mutex = .init,
        writer_mutex: std.Io.Mutex = .init,
        accepted_body_bytes: usize = 0,
        expected_body_length: ?usize = null,
        request_closed: bool = false,
        user_ready: std.Io.Event = .unset,
        worker_ready: std.Io.Event = .unset,
        /// Wakes a caller blocked in `writeBodyBlocking` after the worker
        /// drains queued request DATA.
        write_ready: std.Io.Event = .unset,
        /// Set by the caller to interrupt the worker's receive wait.
        activity: std.Io.Event = .unset,
        /// Shared-endpoint dispatchers wait on one owner event for all streams.
        worker_activity: ?*std.Io.Event = null,
        stream_id: ?u62 = null,
        head: ?http3.DecodedResponseHead = null,
        head_delivered: bool = false,
        end_delivered: bool = false,
        /// Bounded by the underlying response reader's configured 1xx limit.
        informational: Fifo(http3.DecodedResponseHead) = .{},
        trailers: ?http3.DecodedTrailers = null,
        data: Fifo([]u8) = .{},
        pending_read_bytes: usize = 0,
        writes: Fifo(Write) = .{},
        pending_write_bytes: usize = 0,
        queued_trailers: ?OwnedTrailers = null,
        /// Worker-only in-flight request data retained across backpressure.
        worker_write: ?Write = null,
        worker_trailers: ?OwnedTrailers = null,
        cancelled: bool = false,
        finished: bool = false,
        err: ?anyerror = null,

        const Self = @This();

        pub const Write = struct {
            data: []u8,
            fin: bool,
            fragment: @import("../send/body_fragment.zig").State = .{},
        };

        pub const OwnedTrailers = struct {
            storage: []u8,
            fields: []http3.Qpack.HeaderField,

            pub fn deinit(
                self: *OwnedTrailers,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.storage);
                allocator.free(self.fields);
                self.* = undefined;
            }
        };

        pub const Sink = CallbackSink;

        pub fn init(
            pool: *Pool,
            allocator: std.mem.Allocator,
            io: std.Io,
        ) Self {
            return .{
                .pool = pool,
                .allocator = allocator,
                .io = io,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.informational.slice()) |value| {
                var head = value;
                head.deinit(self.allocator);
            }
            self.informational.deinit(self.allocator);
            for (self.writes.slice()) |write| self.allocator.free(write.data);
            self.writes.deinit(self.allocator);
            for (self.data.slice()) |bytes| self.allocator.free(bytes);
            self.data.deinit(self.allocator);
            if (self.head) |*head| head.deinit(self.allocator);
            if (self.trailers) |*trailers| trailers.deinit(self.allocator);
            if (self.queued_trailers) |*trailers| trailers.deinit(self.allocator);
            if (self.worker_write) |write| self.allocator.free(write.data);
            if (self.worker_trailers) |*trailers| trailers.deinit(self.allocator);
            self.* = undefined;
        }

        // ---- caller side -------------------------------------------------

        pub fn markStarted(self: *Self, stream_id: u62) void {
            self.mutex.lockUncancelable(self.io);
            self.stream_id = stream_id;
            self.user_ready.set(self.io);
            self.mutex.unlock(self.io);
        }

        pub fn requestStreamId(self: *Self) ?u62 {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.stream_id;
        }

        /// Queue one atomic DATA contribution, or report backpressure without
        /// accepting a prefix. Empty non-final contributions are no-ops.
        pub fn writeBody(self: *Self, data: []const u8, fin: bool) !void {
            if (!self.writer_mutex.tryLock()) return error.ConcurrentWrite;
            defer self.writer_mutex.unlock(self.io);
            var guard = Guard.init(&self.mutex, self.io);
            defer guard.unlock();
            try self.checkRequestOpenLocked();
            try self.validateBodyLengthLocked(data.len, fin);
            if (data.len == 0 and !fin) return;
            if (self.pending_write_bytes +| data.len > max_pending_write_bytes) return error.Backpressure;
            return self.appendBodyLocked(data, fin);
        }

        /// Accept a contribution in bounded pieces while the worker drains
        /// the queue. `acceptedBodyBytes` retains any prefix accepted before
        /// an error; callers retry only the unaccepted suffix.
        pub fn writeBodyBlocking(self: *Self, data: []const u8, fin: bool, deadline: ?std.Io.Clock.Timestamp) !void {
            var accepted: usize = 0;
            return self.writeBodyBlockingTracked(data, fin, &accepted, deadline);
        }

        /// Per-call progress counts copied application bytes owned by the
        /// dispatcher. FIN is queued only with the final accepted piece.
        pub fn writeBodyBlockingTracked(self: *Self, data: []const u8, fin: bool, accepted: *usize, deadline: ?std.Io.Clock.Timestamp) !void {
            accepted.* = 0;
            if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
            var writing = try Guard.initBefore(&self.writer_mutex, self.io, deadline);
            defer writing.unlock();
            {
                var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
                defer guard.unlock();
                try self.checkRequestOpenLocked();
                try self.validateBodyLengthLocked(data.len, fin);
            }
            while (true) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
                var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
                defer guard.unlock();
                try self.checkRequestOpenLocked();
                const remaining = data[accepted.*..];
                if (remaining.len == 0 and !fin) return;
                const available = max_pending_write_bytes - self.pending_write_bytes;
                if (remaining.len == 0 or available != 0) {
                    const count = @min(remaining.len, available);
                    const final = count == remaining.len;
                    try self.appendBodyLocked(remaining[0..count], fin and final);
                    accepted.* += count;
                    if (final) return;
                    continue;
                }
                self.write_ready.reset();
                guard.unlock();
                if (deadline) |absolute|
                    try self.write_ready.waitTimeout(self.io, .{ .deadline = absolute })
                else
                    try self.write_ready.wait(self.io);
            }
        }

        pub fn acceptedBodyBytes(self: *Self) usize {
            var guard = Guard.init(&self.mutex, self.io);
            defer guard.unlock();
            return self.accepted_body_bytes;
        }

        pub fn isRequestClosed(self: *Self) bool {
            var guard = Guard.init(&self.mutex, self.io);
            defer guard.unlock();
            return self.request_closed;
        }

        fn checkRequestOpenLocked(self: *Self) !void {
            if (self.err) |err| return err;
            if (self.finished or self.cancelled) return error.RequestCancelled;
            if (self.request_closed) return error.RequestBodyFinished;
        }

        fn validateBodyLengthLocked(self: *Self, additional: usize, finishing: bool) !void {
            const total = try std.math.add(usize, self.accepted_body_bytes, additional);
            if (self.expected_body_length) |expected| {
                if (total > expected or (finishing and total != expected)) return error.InvalidContentLength;
            }
        }

        fn appendBodyLocked(self: *Self, data: []const u8, fin: bool) !void {
            const total = try std.math.add(usize, self.accepted_body_bytes, data.len);
            const copy = try self.allocator.dupe(u8, data);
            errdefer self.allocator.free(copy);
            try self.writes.append(self.allocator, .{ .data = copy, .fin = fin });
            self.pending_write_bytes += copy.len;
            self.accepted_body_bytes = total;
            if (fin) self.request_closed = true;
            self.wakeWorker();
        }

        pub fn writeTrailers(self: *Self, trailers: []const http3.Qpack.HeaderField) !void {
            return self.writeTrailersBefore(trailers, null);
        }

        pub fn writeTrailersWithDeadline(self: *Self, trailers: []const http3.Qpack.HeaderField, deadline: std.Io.Clock.Timestamp) !void {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.writeTrailersBefore(trailers, deadline);
        }

        fn writeTrailersBefore(self: *Self, trailers: []const http3.Qpack.HeaderField, deadline: ?std.Io.Clock.Timestamp) !void {
            var writing = try Guard.initBefore(&self.writer_mutex, self.io, deadline);
            defer writing.unlock();
            {
                var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
                defer guard.unlock();
                try self.checkRequestOpenLocked();
                try self.validateBodyLengthLocked(0, true);
            }
            var total: usize = 0;
            for (trailers) |field| {
                total = try std.math.add(usize, total, field.name.len);
                total = try std.math.add(usize, total, field.value.len);
            }
            const storage = try self.allocator.alloc(u8, total);
            errdefer self.allocator.free(storage);
            const fields = try self.allocator.alloc(
                http3.Qpack.HeaderField,
                trailers.len,
            );
            errdefer self.allocator.free(fields);
            var offset: usize = 0;
            for (trailers, fields) |source, *target| {
                const name = storage[offset..][0..source.name.len];
                @memcpy(name, source.name);
                offset += source.name.len;
                const value = storage[offset..][0..source.value.len];
                @memcpy(value, source.value);
                offset += source.value.len;
                target.* = .{ .name = name, .value = value, .never_indexed = source.never_indexed };
            }

            var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
            defer guard.unlock();
            try self.checkRequestOpenLocked();
            self.queued_trailers = .{ .storage = storage, .fields = fields };
            self.request_closed = true;
            self.wakeWorker();
        }

        /// Deliver response events to `sink` until the stream finishes.
        pub fn readResponse(
            self: *Self,
            sink: Sink,
            deadline: ?std.Io.Clock.Timestamp,
        ) anyerror!*const http3.DecodedResponseHead {
            while (true) {
                self.mutex.lockUncancelable(self.io);
                if (!self.informational.isEmpty()) {
                    var head = self.informational.popFront().?;
                    self.mutex.unlock(self.io);
                    defer head.deinit(self.allocator);
                    if (sink.informational) |observe| observe(sink.context, head);
                    continue;
                }
                if (self.err) |err| {
                    self.mutex.unlock(self.io);
                    return err;
                }
                if (self.head) |*head| {
                    if (!self.head_delivered) {
                        self.head_delivered = true;
                        self.mutex.unlock(self.io);
                        try sink.begin(sink.context, head.*);
                        continue;
                    }
                }
                if (!self.data.isEmpty()) {
                    const bytes = self.data.popFront().?;
                    self.pending_read_bytes -= bytes.len;
                    self.worker_ready.set(self.io);
                    self.mutex.unlock(self.io);
                    defer self.allocator.free(bytes);
                    try sink.data(sink.context, bytes);
                    continue;
                }
                if (self.finished) {
                    if (self.head == null) {
                        self.mutex.unlock(self.io);
                        return error.RequestCancelled;
                    }
                    const fields = if (self.trailers) |trailers|
                        trailers.fields
                    else
                        &.{};
                    const notify_end = !self.end_delivered;
                    self.end_delivered = true;
                    self.mutex.unlock(self.io);
                    if (notify_end) try sink.end(sink.context, fields);
                    return &self.head.?;
                }
                self.mutex.unlock(self.io);
                if (deadline) |absolute| {
                    self.user_ready.waitTimeout(
                        self.io,
                        .{ .deadline = absolute },
                    ) catch |err| switch (err) {
                        error.Timeout => return error.Timeout,
                        error.Canceled => return error.Canceled,
                    };
                } else {
                    self.user_ready.wait(self.io) catch |err| return err;
                }
                self.user_ready.reset();
            }
        }

        /// Deliver every currently queued response event without waiting.
        /// Returns true once the response is finished. Use this together with
        /// `writeBody`'s `error.Backpressure` for full-duplex callers.
        pub fn pollResponse(
            self: *Self,
            sink: Sink,
        ) anyerror!bool {
            while (true) {
                self.mutex.lockUncancelable(self.io);
                if (!self.informational.isEmpty()) {
                    var head = self.informational.popFront().?;
                    self.mutex.unlock(self.io);
                    defer head.deinit(self.allocator);
                    if (sink.informational) |observe| observe(sink.context, head);
                    continue;
                }
                if (self.err) |err| {
                    self.mutex.unlock(self.io);
                    return err;
                }
                if (self.head) |*head| {
                    if (!self.head_delivered) {
                        self.head_delivered = true;
                        self.mutex.unlock(self.io);
                        try sink.begin(sink.context, head.*);
                        continue;
                    }
                }
                if (!self.data.isEmpty()) {
                    const bytes = self.data.popFront().?;
                    self.pending_read_bytes -= bytes.len;
                    self.worker_ready.set(self.io);
                    self.mutex.unlock(self.io);
                    defer self.allocator.free(bytes);
                    try sink.data(sink.context, bytes);
                    continue;
                }
                if (self.finished) {
                    if (self.head == null) {
                        self.mutex.unlock(self.io);
                        return error.RequestCancelled;
                    }
                    const fields = if (self.trailers) |trailers|
                        trailers.fields
                    else
                        &.{};
                    const notify_end = !self.end_delivered;
                    self.end_delivered = true;
                    self.mutex.unlock(self.io);
                    if (notify_end) try sink.end(sink.context, fields);
                    return true;
                }
                self.mutex.unlock(self.io);
                return false;
            }
        }

        pub fn cancel(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            self.cancelled = true;
            self.worker_ready.set(self.io);
            self.user_ready.set(self.io);
            self.write_ready.set(self.io);
            self.mutex.unlock(self.io);
            self.wakeWorker();
        }

        pub fn isCancelled(self: *Self) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.cancelled;
        }

        pub fn isFinished(self: *Self) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.finished;
        }

        fn wakeWorker(self: *Self) void {
            self.activity.set(self.io);
            if (self.worker_activity) |wake| wake.set(self.io);
        }

        // ---- worker side -------------------------------------------------

        pub fn takeWrite(self: *Self) ?Write {
            self.mutex.lockUncancelable(self.io);
            if (self.writes.isEmpty()) {
                self.mutex.unlock(self.io);
                return null;
            }
            const write = self.writes.popFront().?;
            self.pending_write_bytes -= write.data.len;
            self.write_ready.set(self.io);
            self.mutex.unlock(self.io);
            return write;
        }

        pub fn takeTrailers(self: *Self) ?OwnedTrailers {
            self.mutex.lockUncancelable(self.io);
            const trailers = self.queued_trailers orelse {
                self.mutex.unlock(self.io);
                return null;
            };
            self.queued_trailers = null;
            self.mutex.unlock(self.io);
            return trailers;
        }

        /// Clear a stale wake only when no caller work is queued. Called
        /// under the same mutex as enqueue so a new write cannot be lost.
        pub fn resetActivityIfIdle(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            if (self.writes.isEmpty() and
                self.queued_trailers == null and !self.cancelled)
            {
                self.activity.reset();
            }
            self.mutex.unlock(self.io);
        }

        pub fn deliverHead(self: *Self, head: http3.DecodedResponseHead) void {
            self.mutex.lockUncancelable(self.io);
            if (self.head == null and !self.finished and !self.cancelled) {
                self.head = head;
                self.user_ready.set(self.io);
            } else {
                var dropped = head;
                dropped.deinit(self.allocator);
            }
            self.mutex.unlock(self.io);
        }

        /// Adopt an already-decoded interim head in wire order. The sole
        /// receive owner enforces the configured informational/field limits.
        pub fn deliverInformational(self: *Self, head: http3.DecodedResponseHead) !void {
            var owned = head;
            errdefer owned.deinit(self.allocator);
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.finished or self.cancelled) return error.RequestCancelled;
            if (self.head != null or head.status >= 200) return error.UnexpectedStream;
            try self.informational.append(self.allocator, owned);
            self.user_ready.set(self.io);
        }

        pub fn deliverTrailers(
            self: *Self,
            trailers: http3.DecodedTrailers,
        ) void {
            self.mutex.lockUncancelable(self.io);
            if (self.trailers == null and !self.finished) {
                self.trailers = trailers;
                self.user_ready.set(self.io);
            } else {
                var dropped = trailers;
                dropped.deinit(self.allocator);
            }
            self.mutex.unlock(self.io);
        }

        /// Copy one DATA slice into the bounded response queue. Blocks the
        /// worker while the caller has not drained the queue.
        pub fn deliverData(self: *Self, bytes: []const u8) !void {
            if (bytes.len == 0) return;
            const copy = try self.allocator.dupe(u8, bytes);
            errdefer self.allocator.free(copy);
            self.mutex.lockUncancelable(self.io);
            while (self.pending_read_bytes + copy.len >
                max_pending_read_bytes and
                !self.finished and !self.cancelled)
            {
                self.mutex.unlock(self.io);
                self.worker_ready.wait(self.io) catch {};
                self.worker_ready.reset();
                self.mutex.lockUncancelable(self.io);
            }
            if (self.finished or self.cancelled) {
                self.mutex.unlock(self.io);
                return error.RequestCancelled;
            }
            self.data.append(self.allocator, copy) catch |err| {
                self.mutex.unlock(self.io);
                return err;
            };
            self.pending_read_bytes += copy.len;
            self.user_ready.set(self.io);
            self.mutex.unlock(self.io);
        }

        pub fn finish(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            self.finished = true;
            self.user_ready.set(self.io);
            self.write_ready.set(self.io);
            self.mutex.unlock(self.io);
        }

        pub fn fail(self: *Self, err: anyerror) void {
            self.mutex.lockUncancelable(self.io);
            if (!self.finished) {
                self.err = err;
                self.finished = true;
                self.user_ready.set(self.io);
                self.write_ready.set(self.io);
            }
            self.mutex.unlock(self.io);
        }
    };
}

test {
    _ = @import("stream_command/tests.zig");
}

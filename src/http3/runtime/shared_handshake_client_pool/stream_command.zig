//! Caller/worker state for one streaming request on the shared dispatcher.
//!
//! The caller writes body chunks and reads response events; the dispatcher
//! worker owns the lease and pumps QUIC events. Both sides synchronize through
//! one mutex and two conditions, and the worker's receive wait is woken by
//! `activity` whenever the caller enqueues work.

const std = @import("std");
const http3 = @import("../../mod.zig");

/// Maximum request bytes queued before `writeBody` reports backpressure.
pub const max_pending_write_bytes: usize = 64 * 1024;
/// Maximum response bytes resident before the worker stops reading DATA.
pub const max_pending_read_bytes: usize = 256 * 1024;

pub fn Stream(comptime Pool: type) type {
    return struct {
        pool: *Pool,
        allocator: std.mem.Allocator,
        io: std.Io,
        mutex: std.Io.Mutex = .init,
        user_ready: std.Io.Event = .unset,
        worker_ready: std.Io.Event = .unset,
        /// Set by the caller to interrupt the worker's receive wait.
        activity: std.Io.Event = .unset,
        stream_id: ?u62 = null,
        head: ?http3.DecodedResponseHead = null,
        head_delivered: bool = false,
        trailers: ?http3.DecodedTrailers = null,
        data: std.ArrayListUnmanaged([]u8) = .empty,
        pending_read_bytes: usize = 0,
        writes: std.ArrayListUnmanaged(Write) = .empty,
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

        pub const Sink = struct {
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
        };

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
            for (self.writes.items) |write| self.allocator.free(write.data);
            self.writes.deinit(self.allocator);
            for (self.data.items) |bytes| self.allocator.free(bytes);
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

        /// Queue one request DATA contribution. Returns `error.Backpressure`
        /// without committing when the bounded write queue is full.
        pub fn writeBody(
            self: *Self,
            data: []const u8,
            fin: bool,
        ) !void {
            self.mutex.lockUncancelable(self.io);
            if (self.finished or self.cancelled) {
                self.mutex.unlock(self.io);
                return error.RequestCancelled;
            }
            if (self.pending_write_bytes + data.len >
                max_pending_write_bytes)
            {
                self.mutex.unlock(self.io);
                return error.Backpressure;
            }
            const copy = self.allocator.dupe(u8, data) catch |err| {
                self.mutex.unlock(self.io);
                return err;
            };
            self.writes.append(self.allocator, .{
                .data = copy,
                .fin = fin,
            }) catch |err| {
                self.allocator.free(copy);
                self.mutex.unlock(self.io);
                return err;
            };
            self.pending_write_bytes += copy.len;
            self.activity.set(self.io);
            self.mutex.unlock(self.io);
        }

        /// Queue request trailers. The stream is closed when the worker sends
        /// them.
        pub fn writeTrailers(
            self: *Self,
            trailers: []const http3.Qpack.HeaderField,
        ) !void {
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
                target.* = .{ .name = name, .value = value };
            }

            self.mutex.lockUncancelable(self.io);
            if (self.finished or self.cancelled or
                self.queued_trailers != null)
            {
                self.mutex.unlock(self.io);
                self.allocator.free(storage);
                self.allocator.free(fields);
                return if (self.queued_trailers != null)
                    error.InvalidHeader
                else
                    error.RequestCancelled;
            }
            self.queued_trailers = .{
                .storage = storage,
                .fields = fields,
            };
            self.activity.set(self.io);
            self.mutex.unlock(self.io);
        }

        /// Deliver response events to `sink` until the stream finishes.
        pub fn readResponse(
            self: *Self,
            sink: Sink,
            deadline: ?std.Io.Clock.Timestamp,
        ) anyerror!*const http3.DecodedResponseHead {
            while (true) {
                self.mutex.lockUncancelable(self.io);
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
                if (self.data.items.len != 0) {
                    const bytes = self.data.orderedRemove(0);
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
                    self.mutex.unlock(self.io);
                    try sink.end(sink.context, fields);
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
                if (self.data.items.len != 0) {
                    const bytes = self.data.orderedRemove(0);
                    self.pending_read_bytes -= bytes.len;
                    self.worker_ready.set(self.io);
                    self.mutex.unlock(self.io);
                    defer self.allocator.free(bytes);
                    try sink.data(sink.context, bytes);
                    continue;
                }
                if (self.finished) {
                    const fields = if (self.trailers) |trailers|
                        trailers.fields
                    else
                        &.{};
                    self.mutex.unlock(self.io);
                    try sink.end(sink.context, fields);
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
            self.mutex.unlock(self.io);
            self.activity.set(self.io);
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

        // ---- worker side -------------------------------------------------

        pub fn takeWrite(self: *Self) ?Write {
            self.mutex.lockUncancelable(self.io);
            if (self.writes.items.len == 0) {
                self.mutex.unlock(self.io);
                return null;
            }
            const write = self.writes.orderedRemove(0);
            self.pending_write_bytes -= write.data.len;
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
            if (self.writes.items.len == 0 and
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
            self.mutex.unlock(self.io);
        }

        pub fn fail(self: *Self, err: anyerror) void {
            self.mutex.lockUncancelable(self.io);
            if (!self.finished) {
                self.err = err;
                self.finished = true;
                self.user_ready.set(self.io);
            }
            self.mutex.unlock(self.io);
        }
    };
}

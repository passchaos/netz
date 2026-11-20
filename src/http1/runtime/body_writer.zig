const std = @import("std");
const http1 = @import("../mod.zig");
const runtime_write = @import("write.zig");

pub const State = struct {
    phase: Phase = .idle,
    generation: u64 = 0,
    written: usize = 0,
    reading: bool = false,
    expect_continue_received: bool = false,
    informational_responses_seen: usize = 0,

    pub const Phase = enum {
        idle,
        writing,
        awaiting_peer,
        unusable,
    };

    /// Reserve the single HTTP/1 exchange slot.
    ///
    /// HTTP/1 has no stream identifier, so a stale writer must not become valid
    /// again merely because a later exchange is active. The generation token
    /// distinguishes those lifetimes even when a writer value was copied.
    pub fn begin(self: *State) error{
        ConnectionBusy,
        ConnectionUnusable,
    }!u64 {
        switch (self.phase) {
            .idle => {},
            .writing, .awaiting_peer => return error.ConnectionBusy,
            .unusable => return error.ConnectionUnusable,
        }
        self.generation +%= 1;
        self.written = 0;
        self.expect_continue_received = false;
        self.informational_responses_seen = 0;
        self.phase = .writing;
        return self.generation;
    }

    pub fn ensureAvailable(self: State) error{
        ConnectionBusy,
        ConnectionUnusable,
    }!void {
        if (self.reading) return error.ConnectionBusy;
        return switch (self.phase) {
            .idle => {},
            .writing, .awaiting_peer => error.ConnectionBusy,
            .unusable => error.ConnectionUnusable,
        };
    }

    pub fn beginRead(self: *State) error{
        ConnectionBusy,
        ConnectionUnusable,
    }!void {
        switch (self.phase) {
            .idle => {},
            .writing, .awaiting_peer => return error.ConnectionBusy,
            .unusable => return error.ConnectionUnusable,
        }
        if (self.reading) return error.ConnectionBusy;
        self.generation +%= 1;
        self.written = 0;
        self.reading = true;
    }

    pub fn ensureReadable(self: State) error{
        ConnectionBusy,
        ConnectionUnusable,
    }!void {
        if (self.reading) return error.ConnectionBusy;
        switch (self.phase) {
            .idle => {},
            .writing, .awaiting_peer => return error.ConnectionBusy,
            .unusable => return error.ConnectionUnusable,
        }
    }

    pub fn finishRead(self: *State) void {
        self.reading = false;
    }

    pub fn failRead(self: *State) void {
        self.reading = false;
        self.phase = .unusable;
    }
};

pub fn Writer(comptime RuntimeError: type) type {
    return struct {
        allocator: std.mem.Allocator,
        state: *State,
        generation: u64,
        context: ?*anyopaque,
        write_slices: *const fn (
            context: ?*anyopaque,
            parts: []const []const u8,
            transport_started: *bool,
        ) RuntimeError!void,
        deadline_io: ?std.Io = null,
        write_slices_with_deadline: ?*const fn (
            context: ?*anyopaque,
            parts: []const []const u8,
            committed: *usize,
            transport_started: *bool,
            deadline: std.Io.Clock.Timestamp,
        ) RuntimeError!void = null,
        scratch: *runtime_write.Scratch,
        framing: runtime_write.streaming.Framing,
        expected_length: ?usize,
        announced_trailers: []const http1.Header,
        header_name_casing: runtime_write.HeaderNameCasing,
        reusable_after_finish: bool,
        release_on_finish: bool,
        body_finished: bool = false,
        owns_state: bool = true,
        known_written: usize = 0,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            state: *State,
            generation: u64,
            context: ?*anyopaque,
            write_slices: *const fn (
                context: ?*anyopaque,
                parts: []const []const u8,
                transport_started: *bool,
            ) RuntimeError!void,
            scratch: *runtime_write.Scratch,
            prepared: runtime_write.streaming.Head,
            announced_trailers: []const http1.Header,
            release_on_finish: bool,
        ) Self {
            var self: Self = .{
                .allocator = allocator,
                .state = state,
                .generation = generation,
                .context = context,
                .write_slices = write_slices,
                .scratch = scratch,
                .framing = prepared.framing,
                .expected_length = prepared.expected_length,
                .announced_trailers = announced_trailers,
                .header_name_casing = prepared.header_name_casing,
                .reusable_after_finish = prepared.reusable_after_finish,
                .release_on_finish = release_on_finish,
            };
            if (prepared.framing == .suppressed) {
                self.body_finished = true;
                if (release_on_finish) self.release(prepared.reusable_after_finish);
            }
            return self;
        }

        pub fn initWithDeadline(
            allocator: std.mem.Allocator,
            state: *State,
            generation: u64,
            context: ?*anyopaque,
            write_slices: @FieldType(Self, "write_slices"),
            scratch: *runtime_write.Scratch,
            prepared: runtime_write.streaming.Head,
            announced_trailers: []const http1.Header,
            release_on_finish: bool,
            io: std.Io,
            write_slices_with_deadline: @typeInfo(@FieldType(Self, "write_slices_with_deadline")).optional.child,
        ) Self {
            var self = init(allocator, state, generation, context, write_slices, scratch, prepared, announced_trailers, release_on_finish);
            self.deadline_io = io;
            self.write_slices_with_deadline = write_slices_with_deadline;
            return self;
        }

        /// Abandoning an HTTP/1 body cannot be repaired with a stream reset.
        /// Mark the entire connection unusable so trailing body bytes can never
        /// be mistaken for the next request or response.
        pub fn deinit(self: *Self) void {
            if (self.owns_state and self.isCurrent()) {
                self.state.phase = .unusable;
            }
            self.owns_state = false;
            self.body_finished = true;
        }

        pub fn write(self: *Self, data: []const u8) RuntimeError!void {
            return self.writeUntil(data, null);
        }

        pub fn writeWithDeadline(self: *Self, data: []const u8, deadline: std.Io.Clock.Timestamp) RuntimeError!void {
            try self.checkDeadline(deadline);
            return self.writeUntil(data, deadline);
        }

        pub fn writeWithTimeout(self: *Self, data: []const u8, timeout: std.Io.Duration) RuntimeError!void {
            return self.writeWithDeadline(data, try self.timeoutDeadline(timeout));
        }

        fn writeUntil(self: *Self, data: []const u8, deadline: ?std.Io.Clock.Timestamp) RuntimeError!void {
            try self.ensureWritable();
            try self.reserveLength(data.len, false);
            if (data.len == 0) return;

            switch (self.framing) {
                .fixed => {
                    var committed: usize = 0;
                    self.writeParts(&.{data}, &committed, deadline) catch |err| {
                        self.commit(@min(data.len, committed));
                        return err;
                    };
                },
                .chunked => {
                    var chunk_head_buffer: [runtime_write.chunk_header_buffer_len]u8 = undefined;
                    const chunk_head = std.fmt.bufPrint(
                        &chunk_head_buffer,
                        "{x}\r\n",
                        .{data.len},
                    ) catch return error.InvalidResponse;
                    var committed: usize = 0;
                    self.writeParts(&.{ chunk_head, data, "\r\n" }, &committed, deadline) catch |err| {
                        self.commit(@min(data.len, committed -| chunk_head.len));
                        return err;
                    };
                },
                .suppressed => return error.InvalidContentLength,
            }
            self.commit(data.len);
        }

        /// Write several application chunks in one transport submission.
        ///
        /// Fixed framing treats the slices as one contiguous body contribution.
        /// Chunked framing preserves every application boundary while building
        /// only small hexadecimal descriptors; payload slices remain borrowed.
        pub fn writeChunks(
            self: *Self,
            chunks: []const []const u8,
        ) RuntimeError!void {
            return self.writeChunksUntil(chunks, null);
        }

        pub fn writeChunksWithDeadline(self: *Self, chunks: []const []const u8, deadline: std.Io.Clock.Timestamp) RuntimeError!void {
            try self.checkDeadline(deadline);
            return self.writeChunksUntil(chunks, deadline);
        }

        pub fn writeChunksWithTimeout(self: *Self, chunks: []const []const u8, timeout: std.Io.Duration) RuntimeError!void {
            return self.writeChunksWithDeadline(chunks, try self.timeoutDeadline(timeout));
        }

        fn writeChunksUntil(self: *Self, chunks: []const []const u8, deadline: ?std.Io.Clock.Timestamp) RuntimeError!void {
            try self.ensureWritable();
            var additional: usize = 0;
            var non_empty: usize = 0;
            for (chunks) |chunk| {
                additional = std.math.add(
                    usize,
                    additional,
                    chunk.len,
                ) catch return error.ContentLengthOverflow;
                if (chunk.len != 0) non_empty += 1;
            }
            try self.reserveLength(additional, false);
            if (non_empty == 0) return;

            switch (self.framing) {
                .fixed => {
                    var committed: usize = 0;
                    self.writeParts(chunks, &committed, deadline) catch |err| {
                        self.commit(@min(additional, committed));
                        return err;
                    };
                },
                .chunked => {
                    const streaming = try self.scratch.streamingChunkScratch(
                        self.allocator,
                    );
                    const buffers = try streaming.prepare(
                        self.allocator,
                        non_empty,
                    );
                    const descriptors = buffers.descriptors;
                    const parts = buffers.parts;

                    var part_index: usize = 0;
                    var descriptor_offset: usize = 0;
                    for (chunks) |chunk| {
                        if (chunk.len == 0) continue;
                        const destination =
                            descriptors[descriptor_offset..][0..runtime_write.chunk_header_buffer_len];
                        const rendered = std.fmt.bufPrint(
                            destination,
                            "{x}\r\n",
                            .{chunk.len},
                        ) catch return error.InvalidResponse;
                        parts[part_index] = rendered;
                        parts[part_index + 1] = chunk;
                        parts[part_index + 2] = "\r\n";
                        part_index += 3;
                        descriptor_offset += runtime_write.chunk_header_buffer_len;
                    }
                    var committed: usize = 0;
                    self.writeParts(parts, &committed, deadline) catch |err| {
                        var body_committed: usize = 0;
                        for (parts, 0..) |part, index| {
                            const count = @min(part.len, committed);
                            if (index % 3 == 1) body_committed += count;
                            committed -= count;
                            if (committed == 0) break;
                        }
                        self.commit(body_committed);
                        return err;
                    };
                },
                .suppressed => return error.InvalidContentLength,
            }
            self.commit(additional);
        }

        pub fn finish(self: *Self) RuntimeError!void {
            try self.finishTrailers(&.{});
        }

        pub fn finishWithDeadline(self: *Self, deadline: std.Io.Clock.Timestamp) RuntimeError!void {
            return self.finishTrailersWithDeadline(&.{}, deadline);
        }

        pub fn finishWithTimeout(self: *Self, timeout: std.Io.Duration) RuntimeError!void {
            return self.finishWithDeadline(try self.timeoutDeadline(timeout));
        }

        pub fn finishTrailers(
            self: *Self,
            trailers: []const http1.Header,
        ) RuntimeError!void {
            return self.finishTrailersUntil(trailers, null);
        }

        pub fn finishTrailersWithDeadline(self: *Self, trailers: []const http1.Header, deadline: std.Io.Clock.Timestamp) RuntimeError!void {
            try self.checkDeadline(deadline);
            return self.finishTrailersUntil(trailers, deadline);
        }

        pub fn finishTrailersWithTimeout(self: *Self, trailers: []const http1.Header, timeout: std.Io.Duration) RuntimeError!void {
            return self.finishTrailersWithDeadline(trailers, try self.timeoutDeadline(timeout));
        }

        fn finishTrailersUntil(self: *Self, trailers: []const http1.Header, deadline: ?std.Io.Clock.Timestamp) RuntimeError!void {
            try self.ensureWritable();
            try self.reserveLength(0, true);
            switch (self.framing) {
                .fixed => {
                    if (trailers.len != 0) return error.InvalidTrailer;
                },
                .chunked => {
                    try self.validateAnnouncedTrailers(trailers);
                    const end = try runtime_write.streaming.prepareEndWithCasing(
                        self.allocator,
                        trailers,
                        self.scratch,
                        self.header_name_casing,
                    );
                    var committed: usize = 0;
                    try self.writeParts(&.{end}, &committed, deadline);
                },
                .suppressed => return error.InvalidWriterState,
            }
            self.body_finished = true;
            if (self.release_on_finish) {
                self.release(self.reusable_after_finish);
            } else if (self.isCurrent()) {
                // Request body completion keeps ownership until the matching
                // response is consumed. Recording this in connection state,
                // rather than only in this value, also invalidates copied
                // writer values before they can append bytes after a terminator.
                self.state.phase = .awaiting_peer;
            }
        }

        /// Complete a request exchange after its response has been consumed.
        pub fn release(self: *Self, peer_reusable: bool) void {
            if (!self.owns_state or !self.isCurrent()) return;
            self.known_written = self.state.written;
            self.state.phase = if (self.reusable_after_finish and peer_reusable)
                .idle
            else
                .unusable;
            self.owns_state = false;
        }

        /// Record a transport/parser failure after any part of the exchange may
        /// have reached the peer.
        pub fn fail(self: *Self) void {
            if (self.owns_state and self.isCurrent()) {
                self.known_written = self.state.written;
                self.state.phase = .unusable;
            }
            self.owns_state = false;
            self.body_finished = true;
        }

        pub fn ensureExchangeActive(self: Self) RuntimeError!void {
            if (!self.owns_state or !self.isCurrent()) {
                return error.InvalidWriterState;
            }
        }

        pub fn isBodyFinished(self: Self) bool {
            return self.body_finished or
                (self.state.generation == self.generation and
                    self.state.phase == .awaiting_peer);
        }

        fn ensureWritable(self: Self) RuntimeError!void {
            try self.ensureExchangeActive();
            if (self.body_finished or self.state.phase != .writing) {
                return error.InvalidWriterState;
            }
        }

        fn reserveLength(
            self: Self,
            additional: usize,
            finishing: bool,
        ) RuntimeError!void {
            const total = std.math.add(
                usize,
                self.state.written,
                additional,
            ) catch return error.ContentLengthOverflow;
            if (self.expected_length) |expected| {
                if (total > expected or (finishing and total != expected)) {
                    return error.InvalidContentLength;
                }
            }
        }

        fn writeParts(
            self: *Self,
            parts: []const []const u8,
            committed: *usize,
            deadline: ?std.Io.Clock.Timestamp,
        ) RuntimeError!void {
            committed.* = 0;
            var transport_started = false;
            const result = if (deadline) |absolute|
                self.write_slices_with_deadline.?(self.context, parts, committed, &transport_started, absolute)
            else
                self.write_slices(self.context, parts, &transport_started);
            result catch |err| {
                if (transport_started) self.fail();
                return err;
            };
        }

        /// Known body bytes accepted by successful writes or tracked timed
        /// writes. A transport failure retires HTTP/1 framing; this counter
        /// does not authorize replay on that connection.
        pub fn committedBytes(self: Self) usize {
            return if (self.state.generation == self.generation) self.state.written else self.known_written;
        }

        fn commit(self: *Self, count: usize) void {
            self.state.written += count;
            self.known_written = self.state.written;
        }

        fn checkDeadline(self: *const Self, deadline: std.Io.Clock.Timestamp) RuntimeError!void {
            const io = self.deadline_io orelse return error.UnsupportedDeadline;
            if (self.write_slices_with_deadline == null) return error.UnsupportedDeadline;
            _ = try @import("../../internal/deadline.zig").usableAwake(io, deadline);
        }

        fn timeoutDeadline(self: *const Self, timeout: std.Io.Duration) RuntimeError!std.Io.Clock.Timestamp {
            const io = self.deadline_io orelse return error.UnsupportedDeadline;
            return (try @import("../../internal/deadline.zig").fromTimeout(io, timeout)).?;
        }

        fn validateAnnouncedTrailers(
            self: Self,
            trailers: []const http1.Header,
        ) RuntimeError!void {
            for (trailers) |trailer| {
                var announced = false;
                for (self.announced_trailers) |candidate| {
                    if (trailer.eqlName(candidate.name)) {
                        announced = true;
                        break;
                    }
                }
                if (!announced) return error.InvalidTrailer;
            }
        }

        fn isCurrent(self: Self) bool {
            return (self.state.phase == .writing or
                self.state.phase == .awaiting_peer) and
                self.state.generation == self.generation;
        }
    };
}

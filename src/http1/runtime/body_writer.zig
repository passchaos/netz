const std = @import("std");
const http1 = @import("../mod.zig");
const runtime_write = @import("write.zig");

pub const State = struct {
    phase: Phase = .idle,
    generation: u64 = 0,
    written: usize = 0,
    reading: bool = false,

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
        ) RuntimeError!void,
        scratch: *runtime_write.Scratch,
        framing: runtime_write.streaming.Framing,
        expected_length: ?usize,
        announced_trailers: []const http1.Header,
        reusable_after_finish: bool,
        release_on_finish: bool,
        body_finished: bool = false,
        owns_state: bool = true,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            state: *State,
            generation: u64,
            context: ?*anyopaque,
            write_slices: *const fn (
                context: ?*anyopaque,
                parts: []const []const u8,
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
                .reusable_after_finish = prepared.reusable_after_finish,
                .release_on_finish = release_on_finish,
            };
            if (prepared.framing == .suppressed) {
                self.body_finished = true;
                if (release_on_finish) self.release(prepared.reusable_after_finish);
            }
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
            try self.ensureWritable();
            try self.reserveLength(data.len, false);
            if (data.len == 0) return;

            switch (self.framing) {
                .fixed => try self.writeParts(&.{data}),
                .chunked => {
                    var chunk_head_buffer: [32]u8 = undefined;
                    const chunk_head = std.fmt.bufPrint(
                        &chunk_head_buffer,
                        "{x}\r\n",
                        .{data.len},
                    ) catch return error.InvalidResponse;
                    try self.writeParts(&.{ chunk_head, data, "\r\n" });
                },
                .suppressed => return error.InvalidContentLength,
            }
            self.state.written += data.len;
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
                .fixed => try self.writeParts(chunks),
                .chunked => {
                    const descriptor_bytes = std.math.mul(
                        usize,
                        non_empty,
                        32,
                    ) catch return error.ContentLengthOverflow;
                    const part_count = std.math.mul(
                        usize,
                        non_empty,
                        3,
                    ) catch return error.ContentLengthOverflow;
                    try self.scratch.streaming_chunk_descriptors.resize(
                        self.allocator,
                        descriptor_bytes,
                    );
                    try self.scratch.streaming_parts.resize(
                        self.allocator,
                        part_count,
                    );
                    const descriptors =
                        self.scratch.streaming_chunk_descriptors.items;
                    const parts = self.scratch.streaming_parts.items;

                    var part_index: usize = 0;
                    var descriptor_offset: usize = 0;
                    for (chunks) |chunk| {
                        if (chunk.len == 0) continue;
                        const destination =
                            descriptors[descriptor_offset..][0..32];
                        const rendered = std.fmt.bufPrint(
                            destination,
                            "{x}\r\n",
                            .{chunk.len},
                        ) catch return error.InvalidResponse;
                        parts[part_index] = rendered;
                        parts[part_index + 1] = chunk;
                        parts[part_index + 2] = "\r\n";
                        part_index += 3;
                        descriptor_offset += 32;
                    }
                    try self.writeParts(parts);
                },
                .suppressed => return error.InvalidContentLength,
            }
            self.state.written += additional;
        }

        pub fn finish(self: *Self) RuntimeError!void {
            try self.finishTrailers(&.{});
        }

        pub fn finishTrailers(
            self: *Self,
            trailers: []const http1.Header,
        ) RuntimeError!void {
            try self.ensureWritable();
            try self.reserveLength(0, true);
            switch (self.framing) {
                .fixed => {
                    if (trailers.len != 0) return error.InvalidTrailer;
                },
                .chunked => {
                    try self.validateAnnouncedTrailers(trailers);
                    const end = try runtime_write.streaming.prepareEnd(
                        self.allocator,
                        trailers,
                        self.scratch,
                    );
                    try self.writeParts(&.{end});
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
        ) RuntimeError!void {
            self.write_slices(self.context, parts) catch |err| {
                self.fail();
                return err;
            };
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

//! Reusable no-context-takeover WebSocket compression storage.
//!
//! Zig 0.16's decompressor requires a 64 KiB history window, retained by
//! `Scratch`. The vort sender owns temporary match state per call but appends
//! into `SendScratch.payload`, so connection-level wire storage is still
//! retained independently for concurrent readers and serialized writers.

const std = @import("std");

pub const Scratch = struct {
    payload: std.ArrayList(u8) = .empty,
    flate_window: ?[]u8 = null,

    pub fn deinit(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) void {
        self.payload.deinit(allocator);
        if (self.flate_window) |window| allocator.free(window);
        self.* = undefined;
    }

    pub fn prepare(
        self: *Scratch,
        allocator: std.mem.Allocator,
        max_message_bytes: usize,
    ) !void {
        // RFC 7692 decoding restores a nine-byte sync-flush/final-block tail
        // after the compressed wire payload.
        const capacity = std.math.add(
            usize,
            max_message_bytes,
            9,
        ) catch return error.PayloadTooLarge;
        try self.payload.ensureTotalCapacityPrecise(
            allocator,
            capacity,
        );
        self.payload.clearRetainingCapacity();
        self.payload.items.len = max_message_bytes;
        if (self.flate_window == null) {
            self.flate_window = try allocator.alloc(
                u8,
                std.compress.flate.max_window_len,
            );
        }
    }
};

pub const SendScratch = struct {
    payload: std.ArrayList(u8) = .empty,

    pub fn deinit(
        self: *SendScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.payload.deinit(allocator);
        self.* = undefined;
    }

    pub fn prepare(
        self: *SendScratch,
        allocator: std.mem.Allocator,
        input_len: usize,
    ) !void {
        // Incompressible input may grow by a small DEFLATE framing overhead.
        // Reserving this common bound keeps vort's appended wire bytes in the
        // connection-owned allocation; correctness does not depend on it.
        try self.payload.ensureTotalCapacity(
            allocator,
            input_len +| 64,
        );
        self.payload.clearRetainingCapacity();
    }
};

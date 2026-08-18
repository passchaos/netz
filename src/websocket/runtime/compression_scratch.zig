//! Reusable receive storage for no-context-takeover WebSocket compression.
//!
//! The DEFLATE history window is 64 KiB in Zig 0.16. Keeping it per
//! connection avoids allocating that window for every compressed message,
//! while the payload scratch bounds compressed wire bytes independently from
//! the caller-owned decompressed output.

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

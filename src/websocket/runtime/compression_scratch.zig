//! Reusable WebSocket compression storage and context-takeover transactions.
//!
//! Zig 0.16's decompressor requires a 64 KiB history window, retained by
//! `Scratch`. The sender retains both encoded output and hash-chain workspace
//! per connection, avoiding steady-state allocation churn. Optional stateful
//! codecs keep direction-specific RFC 7692 history; send serialization
//! guarantees that a preview has one owner until commit or discard.

const std = @import("std");
const compression_context = @import("../compression_context.zig");

pub const Scratch = struct {
    payload: std.ArrayList(u8) = .empty,
    decoded: std.ArrayList(u8) = .empty,
    flate_window: ?[]u8 = null,
    context: ?compression_context.DecompressionContext = null,
    frame_message_compressed: bool = false,
    frame_message_text: bool = false,

    pub fn deinit(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) void {
        self.payload.deinit(allocator);
        self.decoded.deinit(allocator);
        if (self.flate_window) |window| allocator.free(window);
        if (self.context) |*context| context.deinit();
        self.* = undefined;
    }

    pub fn prepare(
        self: *Scratch,
        allocator: std.mem.Allocator,
        max_message_bytes: usize,
    ) !void {
        // RFC 7692 decoding restores a nine-byte sync-flush/final-block tail.
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

    pub fn prepareContext(
        self: *Scratch,
        allocator: std.mem.Allocator,
        max_message_bytes: usize,
    ) !void {
        try self.payload.ensureTotalCapacityPrecise(
            allocator,
            max_message_bytes,
        );
        self.payload.clearRetainingCapacity();
        self.payload.items.len = max_message_bytes;
    }

    pub fn decompressContextInto(
        self: *Scratch,
        allocator: std.mem.Allocator,
        output: []u8,
        compressed_payload: []const u8,
        max_window_bits: u8,
    ) ![]u8 {
        const decoded = try self.previewContextInto(
            allocator,
            output,
            compressed_payload,
            max_window_bits,
        );
        self.commitContextPreview();
        return decoded;
    }

    pub fn previewContextInto(
        self: *Scratch,
        allocator: std.mem.Allocator,
        output: []u8,
        compressed_payload: []const u8,
        max_window_bits: u8,
    ) ![]u8 {
        if (self.context == null) {
            self.context = try compression_context.DecompressionContext.init(
                allocator,
                max_window_bits,
            );
        }
        return self.context.?.previewToSlice(
            output,
            compressed_payload,
        );
    }

    pub fn previewContextOwned(
        self: *Scratch,
        allocator: std.mem.Allocator,
        compressed_payload: []const u8,
        max_message_bytes: usize,
        max_window_bits: u8,
    ) ![]u8 {
        if (self.context == null) {
            self.context = try compression_context.DecompressionContext.init(
                allocator,
                max_window_bits,
            );
        }
        self.decoded.clearRetainingCapacity();
        try self.decoded.ensureTotalCapacity(allocator, max_message_bytes);
        const decoded = try self.context.?.previewToSlice(
            self.decoded.allocatedSlice()[0..max_message_bytes],
            compressed_payload,
        );
        self.decoded.items.len = decoded.len;
        return self.decoded.toOwnedSlice(allocator) catch |err| {
            self.context.?.discardPreview();
            return err;
        };
    }

    pub fn commitContextPreview(self: *Scratch) void {
        if (self.context) |*context| context.commitPreview();
    }

    pub fn discardContextPreview(self: *Scratch) void {
        if (self.context) |*context| context.discardPreview();
    }

    pub fn observeFrame(
        self: *Scratch,
        allocator: std.mem.Allocator,
        starts_message: bool,
        compressed: bool,
        text: bool,
        fin: bool,
        payload_bytes: []const u8,
        max_message_bytes: usize,
        max_window_bits: u8,
    ) !void {
        if (starts_message) {
            self.frame_message_compressed = compressed;
            self.frame_message_text = text;
            self.payload.clearRetainingCapacity();
        }
        if (!self.frame_message_compressed) return;
        const next_len = std.math.add(
            usize,
            self.payload.items.len,
            payload_bytes.len,
        ) catch return error.PayloadTooLarge;
        if (next_len > max_message_bytes) return error.PayloadTooLarge;
        try self.payload.appendSlice(allocator, payload_bytes);
        if (!fin) return;
        defer {
            self.payload.clearRetainingCapacity();
            self.frame_message_compressed = false;
            self.frame_message_text = false;
        }

        try self.decoded.ensureTotalCapacity(allocator, max_message_bytes);
        const decoded = try self.previewContextInto(
            allocator,
            self.decoded.allocatedSlice()[0..max_message_bytes],
            self.payload.items,
            max_window_bits,
        );
        self.decoded.items.len = decoded.len;
        if (self.frame_message_text and
            !std.unicode.utf8ValidateSlice(decoded))
        {
            self.discardContextPreview();
            return error.InvalidUtf8;
        }
        self.commitContextPreview();
    }
};

pub const SendScratch = struct {
    payload: std.ArrayList(u8) = .empty,
    encoder: ?@import("../../internal/vort.zig").RawFixedSyncFlushEncoder =
        null,
    context: ?compression_context.CompressionContext = null,

    pub fn deinit(
        self: *SendScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.payload.deinit(allocator);
        if (self.encoder) |*encoder| encoder.deinit();
        if (self.context) |*context| context.deinit();
        self.* = undefined;
    }

    pub fn prepare(
        self: *SendScratch,
        allocator: std.mem.Allocator,
        input_len: usize,
    ) !void {
        // Incompressible input may grow by a small DEFLATE framing overhead.
        // Reserving this common bound keeps appended wire bytes in the
        // connection-owned allocation; correctness does not depend on it.
        try self.payload.ensureTotalCapacity(
            allocator,
            input_len +| 64,
        );
        self.payload.clearRetainingCapacity();
        if (self.encoder == null) {
            self.encoder = .init(allocator);
        }
    }

    pub fn preview(
        self: *SendScratch,
        allocator: std.mem.Allocator,
        payload_bytes: []const u8,
        max_window_bits: u8,
    ) ![]const u8 {
        try self.prepareOutput(allocator, payload_bytes.len);
        if (self.context == null) {
            self.context = try compression_context.CompressionContext.init(
                allocator,
                max_window_bits,
            );
        }
        return self.context.?.previewInto(&self.payload, payload_bytes);
    }

    pub fn previewFragments(
        self: *SendScratch,
        allocator: std.mem.Allocator,
        fragments: []const []const u8,
        input_len: usize,
        max_window_bits: u8,
    ) ![]const u8 {
        try self.prepareOutput(allocator, input_len);
        if (self.context == null) {
            self.context = try compression_context.CompressionContext.init(
                allocator,
                max_window_bits,
            );
        }
        return self.context.?.previewFragmentsInto(
            &self.payload,
            fragments,
        );
    }

    pub fn previewPending(self: SendScratch) bool {
        return if (self.context) |context| context.previewPending() else false;
    }

    pub fn commitPreview(self: *SendScratch) !void {
        if (self.context) |*context| try context.commitPreview();
    }

    pub fn discardPreview(self: *SendScratch) void {
        if (self.context) |*context| context.discardPreview();
    }

    fn prepareOutput(
        self: *SendScratch,
        allocator: std.mem.Allocator,
        input_len: usize,
    ) !void {
        try self.payload.ensureTotalCapacity(
            allocator,
            input_len +| 64,
        );
        self.payload.clearRetainingCapacity();
    }
};

test "runtime send scratch commits and discards takeover previews" {
    const allocator = std.testing.allocator;
    const payload = "runtime context takeover runtime context takeover";
    var scratch: SendScratch = .{};
    defer scratch.deinit(allocator);

    const discarded = try scratch.preview(allocator, payload, 15);
    const discarded_copy = try allocator.dupe(u8, discarded);
    defer allocator.free(discarded_copy);
    try std.testing.expect(scratch.previewPending());
    scratch.discardPreview();

    const first = try scratch.preview(allocator, payload, 15);
    try std.testing.expectEqualSlices(u8, discarded_copy, first);
    try scratch.commitPreview();
    const second = try scratch.preview(allocator, payload, 15);
    try std.testing.expect(second.len < first.len);
    try scratch.commitPreview();
}

test "runtime receive scratch observes fragmented takeover messages" {
    const allocator = std.testing.allocator;
    const payload = "fragment history fragment history fragment history";
    var encoder = try compression_context.CompressionContext.init(
        allocator,
        15,
    );
    defer encoder.deinit();
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(allocator);

    const first = try encoder.compressInto(&wire, payload);
    const first_copy = try allocator.dupe(u8, first);
    defer allocator.free(first_copy);
    const second = try encoder.compressInto(&wire, payload);
    const second_copy = try allocator.dupe(u8, second);
    defer allocator.free(second_copy);
    try std.testing.expect(second_copy.len < first_copy.len);

    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);
    const split = first_copy.len / 2;
    try scratch.observeFrame(
        allocator,
        true,
        true,
        true,
        false,
        first_copy[0..split],
        payload.len,
        15,
    );
    try scratch.observeFrame(
        allocator,
        false,
        false,
        false,
        true,
        first_copy[split..],
        payload.len,
        15,
    );

    var decoded: [payload.len]u8 = undefined;
    try std.testing.expectEqualStrings(
        payload,
        try scratch.decompressContextInto(
            allocator,
            &decoded,
            second_copy,
            15,
        ),
    );
}

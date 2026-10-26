//! gRPC-Web text streams consist of independently padded base64 chunks.
//! A chunk can end anywhere in a gRPC frame; HTTP DATA boundaries are unrelated.

const std = @import("std");

pub const Error = error{ InvalidTextEncoding, InvalidStreamState };

/// Bounded incremental decoder. Callback bytes borrow stack storage until the
/// callback returns. A malformed chunk or failed callback makes it terminal.
pub const Decoder = struct {
    group: [4]u8 = undefined,
    group_len: u3 = 0,
    finished: bool = false,

    pub fn feed(self: *Decoder, bytes: []const u8, context: anytype, comptime consume: anytype) !void {
        if (self.finished) return error.InvalidStreamState;
        errdefer self.finished = true;
        var output: [768]u8 = undefined;
        var output_len: usize = 0;
        for (bytes) |byte| {
            if (std.mem.indexOfScalar(u8, " \t\r\n", byte) != null) continue;
            self.group[self.group_len] = byte;
            self.group_len += 1;
            if (self.group_len != 4) continue;
            if (output.len - output_len < 3) {
                try consume(context, output[0..output_len]);
                output_len = 0;
            }
            output_len += try self.decodeGroup(output[output_len..]);
            self.group_len = 0;
        }
        if (output_len != 0) try consume(context, output[0..output_len]);
    }

    /// An unpadded final chunk of two or three characters is accepted, as in
    /// the original allocating decoder. Explicit padding must be complete.
    pub fn finish(self: *Decoder, context: anytype, comptime consume: anytype) !void {
        if (self.finished) return error.InvalidStreamState;
        self.finished = true;
        if (self.group_len == 0) return;
        if (self.group_len == 1 or std.mem.indexOfScalar(u8, self.group[0..self.group_len], '=') != null) {
            return error.InvalidTextEncoding;
        }
        @memset(self.group[self.group_len..], '=');
        var output: [3]u8 = undefined;
        const len = try self.decodeGroup(&output);
        self.group_len = 0;
        try consume(context, output[0..len]);
    }

    fn decodeGroup(self: *const Decoder, output: []u8) Error!usize {
        const decoder = std.base64.standard.Decoder;
        const len = decoder.calcSizeForSlice(&self.group) catch return error.InvalidTextEncoding;
        decoder.decode(output[0..len], &self.group) catch return error.InvalidTextEncoding;
        return len;
    }
};

/// Validate before allocation, then allocate exactly the decoded size. The
/// shared decoder accepts in-stream padding, not just one padded entity.
pub fn decodeAlloc(allocator: std.mem.Allocator, input: []const u8) (Error || std.mem.Allocator.Error)![]u8 {
    const Size = struct {
        len: usize = 0,
        fn consume(self: *@This(), bytes: []const u8) !void {
            self.len = std.math.add(usize, self.len, bytes.len) catch return error.InvalidTextEncoding;
        }
    };
    var size: Size = .{};
    var validator: Decoder = .{};
    try validator.feed(input, &size, Size.consume);
    try validator.finish(&size, Size.consume);
    const output = try allocator.alloc(u8, size.len);
    errdefer allocator.free(output);
    const Copy = struct {
        bytes: []u8,
        offset: usize = 0,
        fn consume(self: *@This(), bytes: []const u8) error{}!void {
            @memcpy(self.bytes[self.offset..][0..bytes.len], bytes);
            self.offset += bytes.len;
        }
    };
    var copy: Copy = .{ .bytes = output };
    var decoder: Decoder = .{};
    try decoder.feed(input, &copy, Copy.consume);
    try decoder.finish(&copy, Copy.consume);
    return output;
}

/// Allocation-free encoder for a borrowed writer. Call flushPadding after
/// each gRPC message so its tail is observable before the next message.
pub fn EncoderSink(comptime Writer: type) type {
    return struct {
        inner: ?*Writer = null,
        pending: [3]u8 = undefined,
        pending_len: u2 = 0,

        const encoder = std.base64.standard.Encoder;
        const chunk_input = 768;
        const chunk_output = chunk_input / 3 * 4;

        pub fn write(self: *@This(), bytes: []const u8) !void {
            const inner = self.inner orelse return error.InvalidStreamState;
            var input = bytes;
            if (self.pending_len != 0) {
                const take = @min(@as(usize, 3) - self.pending_len, input.len);
                @memcpy(self.pending[self.pending_len..][0..take], input[0..take]);
                self.pending_len += @intCast(take);
                input = input[take..];
                if (self.pending_len == 3) {
                    var group: [4]u8 = undefined;
                    _ = encoder.encode(&group, &self.pending);
                    try inner.write(&group);
                    self.pending_len = 0;
                }
            }
            var encoded: [chunk_output]u8 = undefined;
            while (input.len >= chunk_input) {
                _ = encoder.encode(&encoded, input[0..chunk_input]);
                try inner.write(&encoded);
                input = input[chunk_input..];
            }
            const complete = (input.len / 3) * 3;
            if (complete != 0) {
                const out_len = encoder.calcSize(complete);
                _ = encoder.encode(encoded[0..out_len], input[0..complete]);
                try inner.write(encoded[0..out_len]);
                input = input[complete..];
            }
            if (input.len != 0) {
                @memcpy(self.pending[0..input.len], input);
                self.pending_len = @intCast(input.len);
            }
        }

        pub fn flushPadding(self: *@This()) !void {
            const inner = self.inner orelse return error.InvalidStreamState;
            if (self.pending_len == 0) return;
            var group: [4]u8 = undefined;
            _ = encoder.encode(&group, self.pending[0..self.pending_len]);
            try inner.write(&group);
            self.pending_len = 0;
        }
    };
}

test "gRPC-Web text decoder handles every split through padded chunks" {
    const input = " A A A A A A U=\r\n aGVs bG8= \t";
    const Collector = struct {
        bytes: std.ArrayList(u8) = .empty,
        fn consume(self: *@This(), bytes: []const u8) !void {
            try self.bytes.appendSlice(std.testing.allocator, bytes);
        }
    };
    for (0..input.len + 1) |split| {
        var collector: Collector = .{};
        defer collector.bytes.deinit(std.testing.allocator);
        var decoder: Decoder = .{};
        try decoder.feed(input[0..split], &collector, Collector.consume);
        try decoder.feed(input[split..], &collector, Collector.consume);
        try decoder.finish(&collector, Collector.consume);
        try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o' }, collector.bytes.items);
        try std.testing.expectError(error.InvalidStreamState, decoder.feed("", &collector, Collector.consume));
    }
}

test "gRPC-Web text rejects malformed chunks before allocation" {
    const invalid = [_][]const u8{ "A", "=AAA", "AA=A", "AAA==", "AA=", "AB==", "AAB=", "AA==%AAA", "-_AA" };
    for (invalid) |input| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.InvalidTextEncoding, decodeAlloc(failing.allocator(), input));
        try std.testing.expect(!failing.has_induced_failure);
    }
    const decoded = try decodeAlloc(std.testing.allocator, "YQ==Yg");
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("ab", decoded);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCase, .{});
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const decoded = try decodeAlloc(allocator, "YQ==Yg==Yw==");
    defer allocator.free(decoded);
    try std.testing.expectEqualStrings("abc", decoded);
}

test "gRPC-Web text decoder becomes terminal on callback failure" {
    const Consumer = struct {
        fn consume(_: void, _: []const u8) error{CallbackFailed}!void {
            return error.CallbackFailed;
        }
    };
    var decoder: Decoder = .{};
    try std.testing.expectError(error.CallbackFailed, decoder.feed("YQ==", {}, Consumer.consume));
    try std.testing.expectError(error.InvalidStreamState, decoder.finish({}, Consumer.consume));
}

test "gRPC-Web text bounded buffers round trip large chunks across flush boundaries" {
    const Sink = struct {
        output: std.ArrayList(u8) = .empty,
        fn write(self: *@This(), bytes: []const u8) !void {
            try self.output.appendSlice(std.testing.allocator, bytes);
        }
    };
    var sink: Sink = .{};
    defer sink.output.deinit(std.testing.allocator);
    var encoder: EncoderSink(Sink) = .{ .inner = &sink };
    var payload: [4099]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    // Flushes inside the message, then small writes crossing triplets and the
    // encoder/decoder's bounded buffers. Compare to the original raw bytes.
    try encoder.write(payload[0..769]);
    try encoder.flushPadding();
    try encoder.write(payload[769..770]);
    try encoder.write(payload[770..772]);
    try encoder.write(payload[772..]);
    try encoder.flushPadding();
    const decoded = try decodeAlloc(std.testing.allocator, sink.output.items);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, &payload, decoded);
}

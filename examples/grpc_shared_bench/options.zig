const std = @import("std");

pub const Mode = enum { persistent, calls };
pub const Options = struct {
    mode: Mode = .persistent,
    payload_bytes: usize = 1024,
    warmup: usize = 100,
    iterations: usize = 2000,
    stats: bool = false,

    pub fn total(self: Options) usize {
        return self.warmup + self.iterations;
    }
    pub fn calls(self: Options) usize {
        return if (self.mode == .persistent) 1 else self.total();
    }
};

pub fn parse(init: std.process.Init) !Options {
    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, std.heap.smp_allocator);
    defer args.deinit();
    _ = args.next();
    var options: Options = .{};
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--stats")) {
            options.stats = true;
        } else if (std.mem.startsWith(u8, arg, "--mode=")) {
            options.mode = std.meta.stringToEnum(Mode, arg["--mode=".len..]) orelse return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--payload=")) {
            options.payload_bytes = try std.fmt.parseInt(usize, arg["--payload=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup = try std.fmt.parseInt(usize, arg["--warmup=".len..], 10);
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(usize, arg["--iterations=".len..], 10);
        } else return error.InvalidArgument;
    }
    if (options.iterations == 0 or options.payload_bytes > 16 * 1024 * 1024 - 8) return error.InvalidArgument;
    _ = std.math.add(usize, options.warmup, options.iterations) catch return error.InvalidArgument;
    return options;
}

/// Pre-encoded string field used by upstream EchoRequest/EchoResponse. The
/// transport benchmark deliberately leaves protobuf serialization out of time.
pub fn message(allocator: std.mem.Allocator, size: usize, byte: u8) ![]u8 {
    if (size == 0) return allocator.alloc(u8, 0);
    var prefix: [6]u8 = undefined;
    prefix[0] = 0x0a;
    var length = size;
    var count: usize = 1;
    while (length >= 128) {
        prefix[count] = @as(u8, @truncate(length)) | 0x80;
        count += 1;
        length >>= 7;
    }
    prefix[count] = @intCast(length);
    count += 1;
    const bytes = try allocator.alloc(u8, count + size);
    @memcpy(bytes[0..count], prefix[0..count]);
    @memset(bytes[count..], byte);
    return bytes;
}

const std = @import("std");

pub const max_operations = 8;
pub const timeout = std.Io.Duration.fromSeconds(2);

pub const Bytes = struct {
    value: [3]u8,

    pub fn request(operation: u8, index: usize) Bytes {
        return .{ .value = .{ operation, @intCast(index), 0xc2 } };
    }

    pub fn response(operation: u8, index: usize) Bytes {
        return .{ .value = .{ operation, @intCast(index), 0xd3 } };
    }
};

pub fn kind(operation: u8) u3 {
    return @truncate(operation);
}

pub fn pathBuffer(
    buffer: []u8,
    operation: u8,
    index: usize,
    suffix: []const u8,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "/fuzz/{d}/{d}{s}",
        .{ index, kind(operation), suffix },
    );
}

pub const Summary = struct {
    requests: usize = 0,
    simple: usize = 0,
    request_trailers: usize = 0,
    streaming_requests: usize = 0,
    streaming_responses: usize = 0,
    batches: usize = 0,
    pings: usize = 0,
    cancellations: usize = 0,
    goaways: usize = 0,
    reconnects: usize = 0,
};

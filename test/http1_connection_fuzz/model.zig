const std = @import("std");
const netz = @import("netz");

const http1 = netz.http1;

pub const max_operations = 10;
pub const timeout = std.Io.Duration.fromSeconds(2);

pub const Bytes = struct {
    value: [3]u8,

    pub fn request(operation: u8, index: usize) Bytes {
        return .{ .value = .{ operation, @intCast(index), 0xa1 } };
    }

    pub fn response(operation: u8, index: usize) Bytes {
        return .{ .value = .{ operation, @intCast(index), 0xb2 } };
    }
};

pub fn kind(operation: u8) u3 {
    return @truncate(operation);
}

pub fn requestsKeyUpdate(operation: u8) bool {
    return (operation & 0x08) != 0;
}

pub fn method(operation: u8) http1.Method {
    return switch (kind(operation)) {
        0, 4, 5 => .GET,
        6 => .HEAD,
        1, 2, 3, 7 => .POST,
    };
}

pub fn requestHasBody(operation: u8) bool {
    return switch (kind(operation)) {
        1, 2, 3, 7 => true,
        else => false,
    };
}

pub fn closesConnection(operation: u8) bool {
    return kind(operation) == 5 or kind(operation) == 7;
}

pub fn targetBuffer(
    buffer: []u8,
    operation: u8,
    index: usize,
) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "/fuzz/{d}/{d}",
        .{ index, kind(operation) },
    );
}

pub const Summary = struct {
    requests: usize = 0,
    reused: usize = 0,
    reconnects: usize = 0,
    complete_bodies: usize = 0,
    streaming_fixed_requests: usize = 0,
    streaming_chunked_requests: usize = 0,
    streaming_fixed_responses: usize = 0,
    streaming_chunked_responses: usize = 0,
    head_responses: usize = 0,
    client_closes: usize = 0,
    server_closes: usize = 0,
    key_updates: usize = 0,
};

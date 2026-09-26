const std = @import("std");

pub const client_count = 2;
pub const max_operations = 8;
pub const timeout = std.Io.Duration.fromSeconds(3);
pub const endpoint_timeout = std.Io.Duration.fromSeconds(8);

pub const Kind = enum(u2) {
    datagram,
    stream,
    datagram_pair,
    drain,
};

pub fn clientIndex(operation: u8) usize {
    return operation & 1;
}

pub fn kind(operation: u8) Kind {
    return @enumFromInt(@as(u2, @truncate(operation >> 1)));
}

pub const Payload = struct {
    bytes: [3]u8,

    pub fn baseline(client_index: usize) Payload {
        return .{ .bytes = .{ @intCast(client_index), 0xff, 0xfe } };
    }

    pub fn operation(
        client_index: usize,
        operation_index: usize,
        byte: u8,
    ) Payload {
        return .{ .bytes = .{
            @intCast(client_index),
            @intCast(operation_index),
            byte,
        } };
    }

    pub fn paired(self: Payload) Payload {
        var result = self;
        result.bytes[2] ^= 0x80;
        return result;
    }

    pub fn response(self: Payload) Payload {
        var result = self;
        result.bytes[2] ^= 0xff;
        return result;
    }
};

pub const Summary = struct {
    sessions: usize = 0,
    datagrams: usize = 0,
    streams: usize = 0,
    drains: usize = 0,
    closes: usize = 0,
    routed_to: [client_count]usize = .{0} ** client_count,
};

pub fn expected(input: []const u8) Summary {
    var summary = Summary{
        .sessions = client_count,
        .datagrams = client_count,
        .closes = client_count,
    };
    var drained = [_]bool{false} ** client_count;
    for (input[0..@min(input.len, max_operations)]) |operation| {
        const client_index = clientIndex(operation);
        switch (kind(operation)) {
            .datagram => summary.datagrams += 1,
            .stream => summary.streams += 1,
            .datagram_pair => summary.datagrams += 2,
            .drain => {
                if (!drained[client_index]) {
                    drained[client_index] = true;
                    summary.drains += 1;
                }
            },
        }
    }
    return summary;
}

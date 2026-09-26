const std = @import("std");

pub const max_operations = 16;
pub const receive_timeout = std.Io.Duration.fromMilliseconds(250);
pub const retry_timeout_ns: u64 = 50;

pub const Path = enum(u1) { b, c };

pub fn path(operation: u8) Path {
    return @enumFromInt(@as(u1, @truncate(operation)));
}

pub fn challenge(path_value: Path, serial: u8) [8]u8 {
    return .{
        if (path_value == .b) 0xb0 else 0xc0,
        serial,
        1,
        2,
        3,
        5,
        8,
        13,
    };
}

pub const Summary = struct {
    migrations_started: usize = 0,
    paths_validated: usize = 0,
    late_responses: usize = 0,
    invalid_responses: usize = 0,
    timeout_retries: usize = 0,
    failed_validations: usize = 0,
    rebindings: usize = 0,
    application_round_trips: usize = 0,
};

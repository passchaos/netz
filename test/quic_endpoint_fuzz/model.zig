const std = @import("std");
const netz = @import("netz");

pub const client_count = 4;
pub const capacity = 2;
pub const max_sequence_bytes = 2;
pub const timeout = std.Io.Duration.fromSeconds(3);
pub const endpoint_timeout = std.Io.Duration.fromSeconds(8);

pub const Summary = struct {
    connected: usize = 0,
    capacity_rejections: usize = 0,
    removals: usize = 0,
    stream_round_trips: usize = 0,
    version_2_connections: usize = 0,
    aes_256_connections: usize = 0,
    stale_packets: usize = 0,
    max_live_connections: usize = 0,
};

pub fn byteAt(input: []const u8, index: usize) u8 {
    return if (index < input.len) input[index] else 0;
}

pub fn version(input: []const u8, client_index: usize) netz.quic.Version {
    return if (byteAt(input, 0) & (@as(u8, 1) << @intCast(client_index)) == 0)
        .version_1
    else
        .version_2;
}

pub fn suite(
    input: []const u8,
    client_index: usize,
) netz.quic.tls.cipher_suite.Suite {
    return if (byteAt(input, 1) & (@as(u8, 1) << @intCast(client_index)) == 0)
        .aes_128_gcm_sha256
    else
        .aes_256_gcm_sha384;
}

pub fn victimSelector(input: []const u8, replacement_index: usize) usize {
    const shift: u3 = @intCast(4 + replacement_index - capacity);
    return (byteAt(input, 1) >> shift) & 1;
}

pub fn payload(input: []const u8, client_index: usize) [4]u8 {
    return .{
        @intCast(client_index),
        @intFromBool(version(input, client_index) == .version_2),
        @intFromBool(suite(input, client_index) == .aes_256_gcm_sha384),
        byteAt(input, client_index % max_sequence_bytes),
    };
}

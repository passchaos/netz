//! Mosquitto-compatible anonymous MQTT Client Identifier generation.

const std = @import("std");

pub const random_len = 16;
pub const suffix_len = 36;
pub const max_prefix_len = 50;
pub const max_len = max_prefix_len + suffix_len;

pub fn format(
    out: *[max_len]u8,
    prefix: []const u8,
    random: [random_len]u8,
) []const u8 {
    std.debug.assert(prefix.len <= max_prefix_len);
    @memcpy(out[0..prefix.len], prefix);
    var write_index = prefix.len;
    for (random, 0..) |byte, index| {
        if (index == 4 or index == 6 or
            index == 8 or index == 10)
        {
            out[write_index] = '-';
            write_index += 1;
        }
        out[write_index] = hexDigit(byte >> 4);
        out[write_index + 1] = hexDigit(byte & 0x0f);
        write_index += 2;
    }
    std.debug.assert(write_index == prefix.len + suffix_len);
    return out[0..write_index];
}

fn hexDigit(value: u8) u8 {
    std.debug.assert(value < 16);
    return if (value < 10) '0' + value else 'a' + value - 10;
}

test "anonymous Client Identifier uses UUID layout and prefix" {
    var out: [max_len]u8 = undefined;
    const id = format(
        &out,
        "auto-",
        .{
            0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77,
            0x88, 0x99, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff,
        },
    );
    try std.testing.expectEqualStrings(
        "auto-00112233-4455-6677-8899-aabbccddeeff",
        id,
    );
}

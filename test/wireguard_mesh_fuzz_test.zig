//! Bounded fuzz target for WireGuard and mesh wire codecs.
//!
//! The first input byte selects a codec; the remaining bytes are parsed as a
//! hostile payload. All parsers return borrowed views and enforce their own
//! length and type bounds.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes = 64 * 1024;

fn wireguardSeed(comptime kind: u32, comptime len: usize) [1 + len]u8 {
    var bytes = [_]u8{0} ** (1 + len);
    bytes[0] = switch (kind) {
        1 => 0,
        2 => 1,
        3 => 2,
        else => 3,
    };
    std.mem.writeInt(u32, bytes[1..5], kind, .little);
    return bytes;
}

const initiation_seed = wireguardSeed(
    1,
    netz.vpn.wireguard.message.initiation_size,
);
const response_seed = wireguardSeed(
    2,
    netz.vpn.wireguard.message.response_size,
);
const cookie_seed = wireguardSeed(
    3,
    netz.vpn.wireguard.message.cookie_reply_size,
);
const transport_seed = wireguardSeed(4, 32);

const disco_seed = [_]u8{4} ++ [_]u8{0} ** 64;
const derp_seed = [_]u8{5} ++ [_]u8{0} ** 64;

test "fuzz bounded WireGuard and mesh codecs" {
    try std.testing.fuzz({}, fuzzWireguardMesh, .{ .corpus = &.{
        &initiation_seed,
        &response_seed,
        &cookie_seed,
        &transport_seed,
        &disco_seed,
        &derp_seed,
    } });
}

fn fuzzWireguardMesh(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseWireguardMesh(bytes);
}

fn exerciseWireguardMesh(bytes: []const u8) !void {
    if (bytes.len == 0) return;
    const selector = bytes[0] % 6;
    const payload = bytes[1..];
    switch (selector) {
        0 => _ = netz.vpn.wireguard.message.Initiation.parse(
            payload,
        ) catch {},
        1 => _ = netz.vpn.wireguard.message.Response.parse(
            payload,
        ) catch {},
        2 => _ = netz.vpn.wireguard.message.CookieReply.parse(
            payload,
        ) catch {},
        3 => _ = netz.vpn.wireguard.message.Transport.parse(
            payload,
        ) catch {},
        4 => _ = netz.mesh.disco.message.decode(payload) catch {},
        5 => _ = netz.mesh.derp.frame.decode(
            payload,
            max_input_bytes,
        ) catch {},
        else => unreachable,
    }
}

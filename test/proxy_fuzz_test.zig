//! Bounded fuzz target for the application-proxy wire codecs.
//!
//! The first input byte selects a codec; the remaining bytes are parsed as a
//! hostile payload. Every parser is bounded and returns borrowed views.

const std = @import("std");
const netz = @import("netz");

const max_input_bytes = 64 * 1024;

const socks5_greeting_seed = [_]u8{ 0, 0x05, 0x02, 0x00, 0x02 };
const socks5_request_seed = [_]u8{
    1, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80,
};
const http_connect_seed = [_]u8{2} ++
    "CONNECT example.test:443 HTTP/1.1\r\nHost: example.test\r\n\r\n".*;
const trojan_seed = [_]u8{3} ++ "secret".*;
const vless_address_seed = [_]u8{ 4, 0, 1, 127, 0, 0, 1 };
const vmess_plain_seed = [_]u8{5} ++ [_]u8{0} ** 48;
const tuic_authenticate_seed = [_]u8{6} ++ [_]u8{0} ** 64;
const tuic_connect_seed = [_]u8{ 7, 1, 1, 1, 127, 0, 0, 1, 0, 80 };
const tuic_packet_seed = [_]u8{8} ++ [_]u8{0} ** 32;
const hysteria_client_hello_seed = [_]u8{9} ++ [_]u8{0} ** 32;
const hysteria_request_seed = [_]u8{10} ++ "example.test\x00\x50".*;

test "fuzz bounded proxy codecs" {
    try std.testing.fuzz({}, fuzzProxy, .{ .corpus = &.{
        &socks5_greeting_seed,
        &socks5_request_seed,
        &http_connect_seed,
        &trojan_seed,
        &vless_address_seed,
        &vmess_plain_seed,
        &tuic_authenticate_seed,
        &tuic_connect_seed,
        &tuic_packet_seed,
        &hysteria_client_hello_seed,
        &hysteria_request_seed,
    } });
}

fn fuzzProxy(_: void, smith: *std.testing.Smith) !void {
    var storage: [max_input_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    try exerciseProxy(bytes);
}

fn exerciseProxy(bytes: []const u8) !void {
    if (bytes.len == 0) return;
    const selector = bytes[0] % 11;
    const payload = bytes[1..];
    switch (selector) {
        0 => _ = netz.proxy.socks.codec.parseSocks5Greeting(payload) catch {},
        1 => _ = netz.proxy.socks.codec.parseSocks5Request(payload) catch {},
        2 => _ = netz.proxy.http_connect.protocol.parseRequest(payload) catch {},
        3 => _ = netz.proxy.trojan.protocol.verifyPasswordLine(
            "secret",
            .raw,
            payload,
        ),
        4 => {
            const offset = if (payload.len == 0)
                0
            else
                @as(usize, payload[0]) % payload.len;
            _ = netz.proxy.vless.protocol.decodeAddress(
                payload,
                offset,
                443,
            ) catch {};
        },
        5 => {
            var host_storage: [255]u8 = undefined;
            _ = netz.proxy.vmess.protocol.parsePlainHeader(
                payload,
                &host_storage,
            ) catch {};
        },
        6 => _ = netz.proxy.tuic.protocol.parseAuthenticate(payload) catch {},
        7 => _ = netz.proxy.tuic.protocol.parseConnect(payload) catch {},
        8 => _ = netz.proxy.tuic.protocol.parsePacket(payload) catch {},
        9 => _ = netz.proxy.hysteria.v3_protocol.parseClientHello(
            payload,
        ) catch {},
        10 => _ = netz.proxy.hysteria.v3_protocol.parseRequest(
            payload,
        ) catch {},
        else => unreachable,
    }
}

//! Validate and reserve one complete RFC 6455 server Upgrade response.

const std = @import("std");
const websocket = @import("../mod.zig");
const http1 = @import("../../http1/mod.zig");
const wire = @import("../../internal/wire.zig");

const response_prefix =
    "HTTP/1.1 101 Switching Protocols\r\n" ++
    "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ";

/// Validate and size separate negotiated/configured/application field groups
/// without allocating a flattened descriptor list. Singleton validation spans
/// group boundaries just as it does in the final serialized response.
pub fn encodedLen(client_key: []const u8, groups: []const []const wire.Header) !usize {
    try websocket.validateClientKey(client_key);
    try validateHeaders(groups);
    var len: usize = response_prefix.len + 28 + 4;
    for (groups) |headers| {
        for (headers) |header| {
            len = std.math.add(usize, len, header.name.len) catch return error.PayloadTooLarge;
            len = std.math.add(usize, len, 2) catch return error.PayloadTooLarge;
            len = std.math.add(usize, len, header.value.len) catch return error.PayloadTooLarge;
            len = std.math.add(usize, len, 2) catch return error.PayloadTooLarge;
        }
    }
    return len;
}

pub fn write(list: *std.ArrayList(u8), allocator: std.mem.Allocator, client_key: []const u8, extra_headers: []const wire.Header) !void {
    const response_len = try encodedLen(client_key, &.{extra_headers});
    const key = websocket.acceptKey(client_key);
    try list.ensureUnusedCapacity(allocator, response_len);
    list.appendSliceAssumeCapacity(response_prefix);
    list.appendSliceAssumeCapacity(&key);
    list.appendSliceAssumeCapacity("\r\n");
    for (extra_headers) |header| {
        list.appendSliceAssumeCapacity(header.name);
        list.appendSliceAssumeCapacity(": ");
        list.appendSliceAssumeCapacity(header.value);
        list.appendSliceAssumeCapacity("\r\n");
    }
    list.appendSliceAssumeCapacity("\r\n");
}

fn validateHeaders(groups: []const []const wire.Header) !void {
    var saw_protocol = false;
    var saw_extensions = false;
    for (groups) |headers| {
        for (headers) |header| {
            try http1.validateHeader(header);
            if (header.eqlName("upgrade") or
                header.eqlName("connection") or
                header.eqlName("sec-websocket-accept") or
                header.eqlName("content-length") or
                header.eqlName("transfer-encoding") or
                header.eqlName("trailer"))
            {
                // The writer owns the mandatory fields, while a 101 response cannot
                // carry HTTP/1 message framing. Reject both groups before output.
                return error.InvalidHandshake;
            }
            if (header.eqlName("sec-websocket-protocol")) {
                if (saw_protocol) return error.InvalidHandshake;
                saw_protocol = true;
                if (!websocket.validSubprotocolToken(wire.trimOws(header.value))) return error.InvalidHandshake;
            } else if (header.eqlName("sec-websocket-extensions")) {
                if (saw_extensions) return error.InvalidHandshake;
                saw_extensions = true;
                _ = try websocket.ExtensionNegotiation.validateResponseWithPolicy(
                    header.value,
                    .{
                        .enable_permessage_deflate = true,
                        .allow_context_takeover = true,
                    },
                );
            }
        }
    }
}

test {
    _ = @import("server_tests.zig");
}

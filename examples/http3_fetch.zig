const std = @import("std");
const netz = @import("netz");

const default_uri = "https://robotics.bytedance.com/";
const max_attempts = 3;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const uri = try std.Uri.parse(default_uri);

    // This is a protocol smoke tool, not a production WebPKI client: the QUIC
    // handshake path accepts the certificate chain unless callers provide a
    // `server_auth` verifier.  Keeping the example explicit lets it exercise
    // public HTTP/3 reachability while the verifier policy remains pluggable.
    var response = try fetchWithRetries(allocator, io, uri);
    defer response.deinit(allocator);

    std.debug.print("HTTP/3 {s} -> {d}\n", .{ default_uri, response.response.status });
    for (response.response.headers) |header| {
        std.debug.print("{s}: {s}\n", .{ header.name, header.value });
    }
    const body = response.response.body;
    const preview_len = @min(body.len, 256);
    std.debug.print("body-bytes: {d}\n", .{body.len});
    if (preview_len != 0) {
        std.debug.print("body-preview:\n{s}\n", .{body[0..preview_len]});
    }
}

fn fetchWithRetries(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: std.Uri,
) !netz.http3.runtime.OwnedHandshakeResponse {
    var attempt: usize = 0;
    var last_err: ?anyerror = null;
    while (attempt < max_attempts) : (attempt += 1) {
        return fetchOnce(allocator, io, uri) catch |err| {
            last_err = err;
            std.debug.print(
                "HTTP/3 fetch attempt {d}/{d} failed: {s}\n",
                .{ attempt + 1, max_attempts, @errorName(err) },
            );
            continue;
        };
    }
    return last_err orelse error.Unexpected;
}

fn fetchOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: std.Uri,
) !netz.http3.runtime.OwnedHandshakeResponse {
    var original_dcid: [8]u8 = undefined;
    var local_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &local_cid);

    return try netz.http3.runtime.HandshakeClient.requestUri(
        allocator,
        io,
        .{ .ip4 = .unspecified(0) },
        uri,
        .{ .method = "GET" },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &local_cid,
                .max_crypto_buffer = 64 * 1024,
                .handshake_recovery = .{
                    .initial_pto_ms = 750,
                    .max_pto_ms = 6000,
                    .max_retries = 5,
                },
                .server_auth = null,
            },
            .session = .{ .max_stream_buffer = 512 * 1024 },
        },
    );
}

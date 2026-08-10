const std = @import("std");
const netz = @import("netz");

const default_uri = "https://robotics.bytedance.com/";

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const uri = try std.Uri.parse(default_uri);
    var original_dcid: [8]u8 = undefined;
    var local_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &local_cid);

    // This is a protocol smoke tool, not a production WebPKI client: the QUIC
    // handshake path accepts the certificate chain unless callers provide a
    // `server_auth` verifier.  Keeping the example explicit lets it exercise
    // public HTTP/3 reachability while the verifier policy remains pluggable.
    var response = try netz.http3.runtime.HandshakeClient.requestUri(
        allocator,
        io,
        .{ .ip4 = .unspecified(0) },
        uri,
        .{ .method = "HEAD" },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &local_cid,
            .max_crypto_buffer = 64 * 1024,
            .server_auth = null,
        } },
    );
    defer response.deinit(allocator);

    std.debug.print("HTTP/3 {s} -> {d}\n", .{ default_uri, response.response.status });
    for (response.response.headers) |header| {
        std.debug.print("{s}: {s}\n", .{ header.name, header.value });
    }
}

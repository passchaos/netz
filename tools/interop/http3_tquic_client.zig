//! HTTP/3 client for a two-request exchange with the tquic server tool.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const allocator = init.gpa;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);

    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                // The upstream tquic CLI does not provide a CA option. This
                // direction matches that peer by leaving trust policy unset.
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{ .max_stream_buffer = 64 * 1024 },
        },
    );
    defer client.deinit();

    for ([_][]const u8{ "/one.txt", "/two.txt" }, 0..) |path, index| {
        var response = try client.request(.{
            .method = "GET",
            .path = path,
            .scheme = "https",
            .authority = "localhost",
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        try std.testing.expectEqualStrings(
            if (index == 0) "tquic-one" else "tquic-two",
            response.response.body,
        );
        try std.testing.expectEqualStrings(
            "tquic",
            responseHeader(response.response.headers, "server") orelse
                return error.MissingResponseHeader,
        );
    }
    std.debug.print(
        "netz HTTP/3 client interoperated with tquic: requests=2 connection_reused=true bodies=9,9\n",
        .{},
    );
}

fn responseHeader(
    headers: []const netz.http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

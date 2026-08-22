//! Two-request HTTP/3 server used by the tquic process interoperability gate.

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

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var server_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &server_cid);
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{ .max_stream_buffer = 64 * 1024 },
        },
    );
    defer server.deinit();
    std.debug.print("netz HTTP/3 tquic interop server listening\n", .{});

    var session = try server.accept();
    defer session.deinit();
    var seen: [2]bool = .{ false, false };
    for (0..2) |_| {
        var request = try session.receiveRequest();
        defer request.deinit(allocator);
        try std.testing.expectEqualStrings("GET", request.request.method);
        try std.testing.expectEqualStrings("https", request.request.scheme);
        try std.testing.expect(request.request.authority != null);
        const index: usize = if (std.mem.eql(u8, request.request.path, "/one.txt"))
            0
        else if (std.mem.eql(u8, request.request.path, "/two.txt"))
            1
        else
            return error.InvalidRequest;
        if (seen[index]) return error.DuplicateRequest;
        seen[index] = true;
        const body = if (index == 0) "netz-tquic-one" else "netz-tquic-two";
        try session.sendResponse(request.stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "x-netz-peer", .value = "tquic" }},
            .body = body,
        });
    }
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    std.debug.print(
        "netz HTTP/3 server interoperated with tquic: requests=2 connection_reused=true bodies=14,14\n",
        .{},
    );
}

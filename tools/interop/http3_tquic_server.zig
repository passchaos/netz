//! HTTP/3 server used by the tquic request and graceful-drain process gates.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 4) return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    var force_retry = false;
    var graceful = false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--retry") and !force_retry) {
            force_retry = true;
        } else if (std.mem.eql(u8, arg, "--graceful") and !graceful) {
            graceful = true;
        } else {
            return error.InvalidArguments;
        }
    }
    const allocator = init.gpa;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

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
                .retry = if (force_retry) .{
                    .secret = [_]u8{0x72} **
                        netz.quic.address_validation_token.secret_len,
                    .peer_address = "127.0.0.1",
                    .issued_ns = 1,
                    .lifetime_ns = 60 * std.time.ns_per_s,
                    .nonce = [_]u8{0x73} **
                        netz.quic.address_validation_token.nonce_len,
                } else null,
            },
            .session = .{ .max_stream_buffer = 64 * 1024 },
        },
    );
    defer server.deinit();
    std.debug.print("netz HTTP/3 tquic interop server listening\n", .{});

    var session = try server.accept();
    defer session.deinit();
    try session.sendOrigins(&.{"https://localhost"});
    try std.testing.expectEqual(
        force_retry,
        session.established.retry_processed,
    );
    var seen: [2]bool = .{ false, false };
    const request_count: usize = if (graceful) 1 else 2;
    for (0..request_count) |_| {
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
        if (graceful) {
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            // The initial maximum ID stops tquic from opening new requests.
            // The final ID is one stream beyond the accepted stream, allowing
            // stream 0 to finish while making the boundary exact.
            try session.initiateShutdown();
            try session.completeShutdown();
            try std.testing.expectEqual(
                @as(?u64, 4),
                session.control.local_goaway_id,
            );
            try std.testing.expect(!session.drainComplete());
        }
        try session.sendResponse(request.stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "x-netz-peer", .value = "tquic" }},
            .body = body,
        });
        if (graceful) try std.testing.expect(session.drainComplete());
    }
    if (graceful) {
        // Keep the socket alive briefly after response completion so the
        // external harness can observe both GOAWAY frames and the refused
        // follow-up request before this one-shot server exits.
        try std.Io.sleep(io, .fromMilliseconds(500), .awake);
        std.debug.print(
            "netz HTTP/3 server gracefully drained tquic: retry={} origin=true initial_goaway=max final_goaway=4 active_stream=0 active_drained=true next_rejected=true client_io=tquic-mio server_io=zio-std-io\n",
            .{force_retry},
        );
    } else {
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        std.debug.print(
            "netz HTTP/3 server interoperated with tquic: retry={} origin=true requests=2 connection_reused=true bodies=14,14 client_io=tquic-mio server_io=zio-std-io\n",
            .{force_retry},
        );
    }
}

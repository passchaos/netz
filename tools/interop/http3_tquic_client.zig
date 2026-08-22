//! HTTP/3 client for request and graceful-drain exchanges with tquic.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 5) return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (!std.Io.Dir.path.isAbsolute(args[2])) return error.InvalidArguments;
    var expect_retry = false;
    var graceful = false;
    for (args[3..]) |arg| {
        if (std.mem.eql(u8, arg, "--expect-retry") and !expect_retry) {
            expect_retry = true;
        } else if (std.mem.eql(u8, arg, "--graceful") and !graceful) {
            graceful = true;
        } else {
            return error.InvalidArguments;
        }
    }
    const allocator = init.gpa;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
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
                .server_auth = verifier.clientVerifier(),
                // Keep the retry flight in one Initial. The tquic endpoint
                // routes each Initial datagram before connection state exists,
                // so a multi-datagram post-quantum ClientHello would be split
                // across distinct provisional connections in that peer.
                .key_exchange_groups = &.{.x25519},
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{ .max_stream_buffer = 64 * 1024 },
        },
    );
    defer client.deinit();
    try std.testing.expectEqual(
        expect_retry,
        client.established.retry_processed,
    );
    if (graceful) {
        try runGracefulDrain(allocator, &client, expect_retry);
        return;
    }

    const requests = [_]struct {
        method: []const u8,
        path: []const u8,
        headers: []const netz.http3.Qpack.HeaderField = &.{},
        body: []const u8 = &.{},
        status: u16,
        expected: []const u8,
    }{
        .{
            .method = "GET",
            .path = "/one.txt",
            .status = 200,
            .expected = "tquic-one",
        },
        .{
            .method = "GET",
            .path = "/two.txt",
            .headers = &.{.{ .name = "range", .value = "bytes=2-6" }},
            .status = 206,
            .expected = "uic-t",
        },
        .{
            .method = "POST",
            .path = "/digest",
            .body = "netz-post-body",
            .status = 200,
            .expected = "0a448f311c486f9b70bec2fe6c24fb3a",
        },
    };
    for (requests) |request| {
        var response = try client.request(.{
            .method = request.method,
            .path = request.path,
            .scheme = "https",
            .authority = "localhost",
            .headers = request.headers,
            .body = request.body,
        });
        defer response.deinit(allocator);
        try validateResponse(
            response.response,
            request.status,
            request.expected,
        );
    }
    std.debug.print(
        "netz HTTP/3 client interoperated with tquic: verified=true retry={} requests=3 connection_reused=true get=9 range=206/5 post_md5=32\n",
        .{expect_retry},
    );
}

fn runGracefulDrain(
    allocator: std.mem.Allocator,
    client: *netz.http3.runtime.HandshakeClient,
    expect_retry: bool,
) !void {
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/one.txt",
        .scheme = "https",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), stream_id);
    // Client GOAWAY carries a push ID, not a request-stream boundary. The
    // request and GOAWAY use distinct packets, and stream 0 stays active in
    // netz until the complete response is consumed below.
    try client.sendGoAway(0);
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    try validateResponse(response.response, 200, "tquic-one");

    // tquic acknowledges client shutdown with its highest processed request
    // stream. Zero is deterministic for this one-stream exchange whether its
    // event loop handles GOAWAY immediately before or after request FIN.
    while (client.control.peer_goaway_id == null) {
        try client.receiveProgress();
    }
    try std.testing.expectEqual(@as(?u64, 0), client.control.peer_goaway_id);
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-goaway",
        .scheme = "https",
        .authority = "localhost",
    }));
    std.debug.print(
        "netz HTTP/3 client gracefully drained tquic: retry={} goaway=0 active_stream=0 active_drained=true next_rejected=true\n",
        .{expect_retry},
    );
}

fn validateResponse(
    response: netz.http3.DecodedResponse,
    expected_status: u16,
    expected_body: []const u8,
) !void {
    try std.testing.expectEqual(expected_status, response.status);
    try std.testing.expectEqualStrings(expected_body, response.body);
    try std.testing.expectEqualStrings(
        "tquic",
        responseHeader(response.headers, "server") orelse
            return error.MissingResponseHeader,
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

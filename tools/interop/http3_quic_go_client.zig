//! Certificate-verified HTTP/3 client for process-boundary interoperability
//! with the quic-go fixture maintained in the audited local quicz checkout.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .server_auth = verifier.clientVerifier(),
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer client.deinit();

    const canceled_stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/cancel?from=netz",
        .scheme = "https",
        .authority = "localhost",
    }, null);
    try client.sendRequestBodyPaced(canceled_stream_id, "partial", false);
    try client.cancelRequest(
        canceled_stream_id,
        netz.http3.ApplicationErrorCode.request_cancelled,
    );

    const stream_id = try client.startRequest(.{
        .method = "POST",
        .path = "/interop?from=netz",
        .scheme = "https",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-request",
            .value = "request-header",
        }},
    }, "netz-request".len);
    try client.sendRequestBodyPaced(stream_id, "netz-", false);
    try client.sendRequestBodyPaced(stream_id, "request", false);
    try client.finishRequestTrailersPaced(stream_id, &.{.{
        .name = "x-netz-trailer",
        .value = "request-trailer",
    }});

    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    if (response.response.status != 201 or
        !std.mem.eql(u8, response.response.body, "quic-go-response") or
        !headerEquals(
            response.response.headers,
            "x-quic-go-response",
            "response-header",
        ) or
        !headerEquals(
            response.response.trailers,
            "x-quic-go-trailer",
            "response-trailer",
        ))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/3 client interoperated with quic-go: cancel=H3_REQUEST_CANCELLED request_body=12 request_trailers=1 response_body=16 response_trailers=1\n",
        .{},
    );
}

fn headerEquals(
    headers: []const netz.http3.Qpack.HeaderField,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) {
            return std.mem.eql(u8, header.value, value);
        }
    }
    return false;
}

//! One-shot netz HTTP/3 server for process-boundary interoperability with a
//! certificate-verifying quic-go client.

const std = @import("std");
const netz = @import("netz");

const cancellation_response_size = 128 * 1024;
const stream_receive_window = 8 * 1024;
const connection_receive_window = 24 * 1024;
const read_before_cancel = 12 * 1024;
const cancellation_prefix = "n" ** read_before_cancel;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    var version: netz.quic.Version = .version_1;
    var version_set = false;
    var informational = false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--version=2") and !version_set) {
            version = .version_2;
            version_set = true;
        } else if (std.mem.eql(u8, arg, "--informational") and
            !informational)
        {
            informational = true;
        } else {
            return error.InvalidArgument;
        }
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
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
    var local_transport_parameters = netz.quic.practical_transport_parameters;
    local_transport_parameters.initial_max_data = connection_receive_window;
    local_transport_parameters.initial_max_stream_data_bidi_remote =
        stream_receive_window;

    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .version = version,
                .available_versions = if (version == .version_2)
                    &.{.version_2}
                else
                    &.{ .version_1, .version_2 },
                .local_transport_parameters = local_transport_parameters,
                .initial_one_rtt_config = .{
                    .receive_window = connection_receive_window,
                    .max_receive_window = connection_receive_window,
                    .stream_receive_window = stream_receive_window,
                    .max_stream_receive_window = stream_receive_window,
                    .max_datagram_size = 4096,
                },
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 1200,
            },
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz HTTP/3 quic-go interop server listening on {f}\n",
        .{server.address()},
    );

    var session = try server.accept();
    defer session.deinit();
    if (informational) {
        var request = try session.receiveRequest();
        defer request.deinit(allocator);
        if (!std.mem.eql(
            u8,
            request.request.path,
            "/informational?from=quic-go",
        )) {
            return error.InvalidRequest;
        }
        try session.sendResponseWithInformational(
            request.stream_id,
            &.{
                .{
                    .status = 103,
                    .headers = &.{.{
                        .name = "link",
                        .value = "</netz.css>",
                    }},
                },
                .{
                    .status = 102,
                    .headers = &.{.{
                        .name = "x-progress",
                        .value = "half",
                    }},
                },
            },
            .{
                .status = 200,
                .headers = &.{.{
                    .name = "x-netz-final",
                    .value = "yes",
                }},
                .body = "final",
            },
        );
        try std.Io.sleep(io, .fromMilliseconds(250), .awake);
        std.debug.print(
            "netz HTTP/3 server sent informational responses to quic-go: version={d} statuses=103,102 final=200 body=5\n",
            .{if (version == .version_2) @as(u8, 2) else 1},
        );
        return;
    }

    var canceled = try session.receiveRequest();
    defer canceled.deinit(allocator);
    if (canceled.stream_id != 0 or
        !std.mem.eql(u8, canceled.request.method, "GET") or
        !std.mem.eql(
            u8,
            canceled.request.path,
            "/cancel-response?from=quic-go",
        ) or
        canceled.request.body.len != 0)
    {
        return error.InvalidRequest;
    }
    try session.startResponse(canceled.stream_id, .{
        .status = 200,
        .headers = &.{.{
            .name = "x-netz-cancel",
            .value = "large-response-started",
        }},
    }, cancellation_response_size);

    // The response head lets quic-go start stream 4, but no cancellation body
    // is sent until that sibling is already present on this same session.
    var request = try session.receiveRequest();
    defer request.deinit(allocator);
    if (request.stream_id != 4 or
        !std.mem.eql(u8, request.request.method, "POST") or
        !std.mem.eql(u8, request.request.path, "/interop?from=quic-go") or
        !std.mem.eql(u8, request.request.scheme, "https") or
        request.request.authority == null or
        !std.mem.eql(u8, request.request.authority.?, "localhost") or
        !std.mem.eql(u8, request.request.body, "quic-go-request") or
        !headerEquals(
            request.request.headers,
            "x-quic-go-request",
            "request-header",
        ) or
        !headerEquals(
            request.request.trailers,
            "x-quic-go-trailer",
            "request-trailer",
        ))
    {
        return error.InvalidRequest;
    }
    try session.sendResponseBodyPaced(
        canceled.stream_id,
        cancellation_prefix,
        false,
    );
    const cancellation = try session.receivePeerResponseCancellation(
        canceled.stream_id,
    );
    if (cancellation.application_error_code !=
        netz.http3.ApplicationErrorCode.request_cancelled)
    {
        return error.UnexpectedCancellationCode;
    }

    try session.startResponse(request.stream_id, .{
        .status = 201,
        .headers = &.{.{
            .name = "x-netz-response",
            .value = "response-header",
        }},
    }, "netz-response".len);
    try session.sendResponseBodyPaced(
        request.stream_id,
        "netz-",
        false,
    );
    try session.sendResponseBodyPaced(
        request.stream_id,
        "response",
        false,
    );
    try session.finishResponseTrailersPaced(request.stream_id, &.{.{
        .name = "x-netz-trailer",
        .value = "response-trailer",
    }});
    try std.Io.sleep(io, .fromMilliseconds(250), .awake);
    std.debug.print(
        "netz HTTP/3 server interoperated with quic-go: version={d} cancel=H3_REQUEST_CANCELLED concurrent_sibling=true connection_reused=true stream_window={d} read_before_cancel={d} large_response={d} request_body=15 request_trailers=1 response_body=13 response_trailers=1\n",
        .{
            if (version == .version_2) @as(u8, 2) else 1,
            stream_receive_window,
            read_before_cancel,
            cancellation_response_size,
        },
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

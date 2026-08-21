//! One-shot netz h2c server for process-boundary interoperability with the
//! audited local Hyper client.

const std = @import("std");
const netz = @import("netz");

const constrained_stream_window = 8 * 1024;
const cancel_response_bytes = 128 * 1024;
const sibling_response_bytes = 16 * 1024;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 3 and
        std.mem.eql(u8, args[2], "--tls");
    if (args.len == 3 and !tls_enabled) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 256 * 1024,
        .initial_window_size = constrained_stream_window,
        .initial_connection_window_size = 65_535,
    };
    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    var clear_server: netz.http2.runtime.Server = undefined;
    var tls_server: netz.http2.runtime.TlsServer = undefined;
    if (tls_enabled) {
        tls_server = try .listen(allocator, io, .{ .ip4 = .loopback(port) }, .{
            .limits = limits,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        });
    } else {
        clear_server = try .listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    }
    defer if (tls_enabled) tls_server.deinit() else clear_server.deinit();
    std.debug.print(
        "netz HTTP/2 Hyper interop server listening transport={s} on {f}\n",
        .{ if (tls_enabled) "tls" else "h2c", if (tls_enabled) tls_server.address() else clear_server.address() },
    );

    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer connection.close();
    var request = try connection.readRequest();
    defer request.deinit(allocator);
    if (!std.mem.eql(u8, request.method, "POST") or
        !std.mem.eql(u8, request.path, "/interop?from=hyper") or
        !std.mem.eql(u8, request.scheme, "http") or
        request.authority == null or
        !std.mem.eql(u8, request.authority.?, "localhost") or
        !std.mem.eql(u8, request.body, "hyper-request") or
        !headerEquals(
            request.headers,
            "x-hyper-request",
            "request-header",
        ) or
        !headerEquals(
            request.trailers,
            "x-hyper-trailer",
            "request-trailer",
        ))
    {
        return error.InvalidRequest;
    }

    // Exercise netz's stateful response writer instead of collapsing the
    // response into the single-frame convenience path. Hyper must reassemble
    // both DATA chunks and observe trailing HEADERS with END_STREAM.
    var response = try connection.startResponse(request.stream_id, .{
        .status = 201,
        .headers = &.{.{
            .name = "x-netz-response",
            .value = "response-header",
        }},
        .request_method = request.method,
    });
    defer response.deinit();
    try response.write("netz-");
    try response.write("response");
    try response.finishTrailers(&.{.{
        .name = "x-netz-trailer",
        .value = "response-trailer",
    }});

    std.debug.print(
        "netz HTTP/2 server interoperated with Hyper: transport={s} alpn={s} method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1\n",
        .{ if (tls_enabled) "tls" else "h2c", if (tls_enabled) "h2" else "n/a" },
    );

    // Hyper sends both requests before it consumes either response. Accept
    // both heads first so the test has two simultaneously active streams even
    // if the client's executor assigns their stream IDs in either order.
    var first_concurrent = try connection.readRequest();
    defer first_concurrent.deinit(allocator);
    var second_concurrent = try connection.readRequest();
    defer second_concurrent.deinit(allocator);
    const cancel_request = requestByPath(
        &first_concurrent,
        &second_concurrent,
        "/cancel?from=hyper",
    ) orelse return error.InvalidRequest;
    const sibling_request = requestByPath(
        &first_concurrent,
        &second_concurrent,
        "/sibling?from=hyper",
    ) orelse return error.InvalidRequest;
    if (cancel_request.stream_id == sibling_request.stream_id or
        !std.mem.eql(u8, cancel_request.method, "GET") or
        !std.mem.eql(u8, sibling_request.method, "GET"))
    {
        return error.InvalidRequest;
    }

    var cancel_response = try connection.startResponse(
        cancel_request.stream_id,
        .{
            .status = 200,
            .headers = &.{
                .{ .name = "content-length", .value = "131072" },
                .{ .name = "x-netz-cancel-body", .value = "131072" },
            },
            .request_method = cancel_request.method,
        },
    );
    defer cancel_response.deinit();
    const cancel_chunk = [_]u8{'n'} ** constrained_stream_window;
    // Exactly fill Hyper's advertised per-stream receive window while leaving
    // the declared large response unfinished. The next byte is flow-control
    // blocked until Hyper consumes DATA; dropping that body must reset only
    // this stream.
    try cancel_response.write(&cancel_chunk);
    var reset = try connection.readResetStream();
    defer reset.deinit(allocator);
    if (reset.reset.stream_id != cancel_request.stream_id or
        reset.reset.error_code != .cancel)
    {
        return error.UnexpectedReset;
    }
    // readResetStream retires the stream. Mark the response writer terminal so
    // its defer cannot emit a duplicate reset against the recycled state.
    cancel_response.finished = true;

    const sibling_body = [_]u8{'s'} ** sibling_response_bytes;
    try connection.writeResponse(sibling_request.stream_id, .{
        .status = 200,
        .headers = &.{.{
            .name = "x-netz-sibling",
            .value = "after-cancel",
        }},
        .body = &sibling_body,
        .request_method = sibling_request.method,
    });
    std.debug.print(
        "netz HTTP/2 server observed flow-blocked Hyper cancellation and completed concurrent sibling: transport={s} rst=CANCEL window={} offered={} sibling={}\n",
        .{ if (tls_enabled) "tls" else "h2c", constrained_stream_window, cancel_response_bytes, sibling_response_bytes },
    );
}

fn requestByPath(
    first: *const netz.http2.runtime.OwnedRequest,
    second: *const netz.http2.runtime.OwnedRequest,
    path: []const u8,
) ?*const netz.http2.runtime.OwnedRequest {
    if (std.mem.eql(u8, first.path, path)) return first;
    if (std.mem.eql(u8, second.path, path)) return second;
    return null;
}

fn headerEquals(
    headers: []const netz.http2.Hpack.HeaderField,
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

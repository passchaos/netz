//! One-shot netz HTTP/2 client for process-boundary interoperability with the
//! audited local Hyper server.

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
    const tls_enabled = args.len == 3;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 256 * 1024,
        .initial_window_size = constrained_stream_window,
        .initial_connection_window_size = 65_535,
        .handshake_timeout = .fromSeconds(5),
    };
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }
    var connection = if (tls_enabled)
        try netz.http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        )
    else
        try netz.http2.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer connection.close();

    var response = try connection.request(.{
        .method = "POST",
        .path = "/interop?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-request",
            .value = "request-header",
        }},
        .body = "request-body",
        .trailers = &.{.{
            .name = "x-netz-trailer",
            .value = "request-trailer",
        }},
    });
    defer response.deinit(allocator);

    if (response.status != 201 or
        !std.mem.eql(u8, response.body, "hyper-response") or
        !headerEquals(
            response.headers,
            "x-hyper-response",
            "response-header",
        ) or
        !headerEquals(
            response.trailers,
            "x-hyper-trailer",
            "response-trailer",
        ))
    {
        return error.InvalidResponse;
    }

    std.debug.print(
        "netz HTTP/2 client interoperated with Hyper: transport={s} alpn={s} status=201 body=14 trailers=1\n",
        .{ if (tls_enabled) "tls" else "h2c", if (tls_enabled) "h2" else "n/a" },
    );

    // Hyper's connection driver owns the PING/PONG path independently of a
    // request body. Waiting through an idle interval proves the public netz
    // keep-alive scheduler interoperates with that implementation; the
    // following request proves the same connection remains application-usable.
    var keep_alive = try netz.http2.runtime.KeepAlive.init(.{
        .interval = .fromMilliseconds(25),
        .timeout = .fromSeconds(1),
        .while_idle = true,
    });
    if (try keep_alive.run(&connection) != .acknowledged or
        keep_alive.next_payload != 1)
    {
        return error.InvalidResponse;
    }
    var after_keep_alive = try connection.request(.{
        .method = "GET",
        .path = "/after-keep-alive?from=netz",
        .scheme = "http",
        .authority = "localhost",
    });
    defer after_keep_alive.deinit(allocator);
    if (after_keep_alive.status != 200 or
        !std.mem.eql(u8, after_keep_alive.body, "hyper-still-alive"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/2 keep-alive interoperated with Hyper: transport={s} ack=true next_request=true\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );

    // Open both requests before reading either response. Hyper deliberately
    // withholds the sibling until it observes cancellation of the large body,
    // so completing it proves that only the target stream was retired.
    var cancel_request = try connection.startRequest(.{
        .method = "GET",
        .path = "/cancel?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    });
    defer cancel_request.deinit();
    try cancel_request.finish();

    var sibling_request = try connection.startRequest(.{
        .method = "GET",
        .path = "/sibling?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    });
    defer sibling_request.deinit();
    try sibling_request.finish();

    var cancellation: CancelContext = .{};
    const cancel_result = cancel_request.readResponseStreamingWithHead(
        &cancellation,
        beginCancelResponse,
        cancelResponseBody,
    );
    if (cancel_result) |response_value| {
        var unexpected = response_value;
        unexpected.deinit(allocator);
        return error.ExpectedCancellation;
    } else |err| if (err != error.CancelResponse) {
        return err;
    }
    if (!cancellation.valid_head or
        cancellation.body_bytes != constrained_stream_window or
        cancellation.body_bytes >= cancel_response_bytes)
    {
        return error.InvalidResponse;
    }

    var sibling = try sibling_request.readResponse();
    defer sibling.deinit(allocator);
    if (sibling.status != 200 or
        sibling.body.len != sibling_response_bytes or
        !allBytesEqual(sibling.body, 's') or
        !headerEquals(sibling.headers, "x-hyper-sibling", "after-cancel"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/2 client canceled flow-blocked Hyper stream and completed concurrent sibling: transport={s} rst=CANCEL window={} received={} sibling={}\n",
        .{ if (tls_enabled) "tls" else "h2c", constrained_stream_window, cancellation.body_bytes, sibling.body.len },
    );

    // Hyper begins graceful shutdown while stream 9 is active. Netz processes
    // the initial GOAWAY/PING synchronization and narrower final GOAWAY while
    // still completing that accepted stream, then rejects stream 11 locally.
    var graceful = try connection.startRequest(.{
        .method = "GET",
        .path = "/graceful?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .body_length = 0,
    });
    defer graceful.deinit();
    try graceful.finish();
    var graceful_response = try graceful.readResponse();
    defer graceful_response.deinit(allocator);
    if (graceful_response.status != 200 or
        !std.mem.eql(u8, graceful_response.body, "hyper-drained"))
    {
        return error.InvalidResponse;
    }
    try std.testing.expectError(
        error.ConnectionGoAway,
        connection.request(.{
            .method = "GET",
            .path = "/after-goaway",
            .scheme = "http",
            .authority = "localhost",
        }),
    );
    std.debug.print(
        "netz HTTP/2 client drained Hyper GOAWAY: transport={s} active_stream=9 new_request_refused=true\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

const CancelContext = struct {
    valid_head: bool = false,
    body_bytes: usize = 0,
};

fn beginCancelResponse(
    context: *CancelContext,
    head: netz.http2.runtime.StreamingResponseHead,
) !void {
    context.valid_head = head.status == 200 and
        headerEquals(
            head.headers,
            "content-length",
            "131072",
        ) and
        headerEquals(
            head.headers,
            "x-hyper-cancel-body",
            "131072",
        );
}

fn cancelResponseBody(
    context: *CancelContext,
    data: []const u8,
) error{ CancelResponse, InvalidResponse }!void {
    if (!allBytesEqual(data, 'h')) return error.InvalidResponse;
    context.body_bytes += data.len;
    // The advertised stream window is now fully consumed. Returning an error
    // makes the runtime restore the charged connection credit and emit the
    // target stream's RST_STREAM(CANCEL) before reading the sibling response.
    if (context.body_bytes >= constrained_stream_window) {
        return error.CancelResponse;
    }
}

fn allBytesEqual(bytes: []const u8, expected: u8) bool {
    for (bytes) |byte| if (byte != expected) return false;
    return true;
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

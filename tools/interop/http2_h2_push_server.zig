//! Netz HTTP/2 server that verifies a Rust h2 client disables server push.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    var tls_enabled = false;
    var informational = false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--tls") and !tls_enabled) {
            tls_enabled = true;
        } else if (std.mem.eql(u8, arg, "--informational") and
            !informational)
        {
            informational = true;
        } else {
            return error.InvalidArgument;
        }
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
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
            .limits = .{},
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        });
    } else {
        clear_server = try .listen(allocator, io, .{ .ip4 = .loopback(port) }, .{});
    }
    defer if (tls_enabled) tls_server.deinit() else clear_server.deinit();
    std.debug.print(
        "netz HTTP/2 {s} interop server listening transport={s}\n",
        .{ if (informational) "informational" else "push", if (tls_enabled) "tls" else "h2c" },
    );

    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer connection.close();
    var request = try connection.readRequest();
    defer request.deinit(allocator);
    if (informational) {
        try std.testing.expectEqualStrings("/informational", request.path);
        const response_deadline = std.Io.Clock.Timestamp.fromNow(
            io,
            .{ .clock = .awake, .raw = .fromSeconds(5) },
        );
        try connection.writeInformationalResponseWithDeadline(request.stream_id, 103, &.{
            .{ .name = "link", .value = "</style.css>; rel=preload" },
        }, response_deadline);
        try connection.writeInformationalResponseWithDeadline(request.stream_id, 102, &.{
            .{ .name = "x-progress", .value = "half" },
        }, response_deadline);
        try connection.writeResponseWithDeadline(request.stream_id, .{
            .status = 200,
            .headers = &.{.{ .name = "x-netz-final", .value = "yes" }},
            .body = "final",
            .request_method = request.method,
        }, response_deadline);
        std.debug.print(
            "netz HTTP/2 server sent informational responses to h2: transport={s} statuses=103,102 final=200 body=5 client_io=rust-h2-tokio server_io=zio-std-io\n",
            .{if (tls_enabled) "tls" else "h2c"},
        );
        return;
    }
    try std.testing.expectEqualStrings("/push-disabled", request.path);
    try std.testing.expectError(
        error.UnexpectedFrame,
        connection.promisePush(request.stream_id, &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/must-not-push" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
        }),
    );
    try connection.writeResponse(request.stream_id, .{
        .status = 204,
        .request_method = request.method,
    });
    std.debug.print(
        "netz HTTP/2 server honored h2 push opt-out: transport={s} request_stream=1 promise_rejected=true parent_status=204 client_io=rust-h2-tokio server_io=zio-std-io\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

//! Netz HTTP/2 server that verifies a Rust h2 client disables server push.

const std = @import("std");
const netz = @import("netz");

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
        "netz HTTP/2 push interop server listening transport={s}\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );

    var connection = if (tls_enabled)
        try tls_server.accept()
    else
        try clear_server.accept();
    defer connection.close();
    var request = try connection.readRequest();
    defer request.deinit(allocator);
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
        "netz HTTP/2 server honored h2 push opt-out: transport={s} request_stream=1 promise_rejected=true parent_status=204\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

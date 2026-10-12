//! HTTP/1 client process used by the OpenSSL OCSP stapling gate.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 4) return error.InvalidArgument;
    const tls12 = args.len == 4 and std.mem.eql(u8, args[3], "tls12");
    if (args.len == 4 and !tls12) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[2],
    );
    var ca_lock: std.Io.RwLock = .init;
    var client = try netz.http1.runtime.Client.connectVailTlsHost(
        allocator,
        io,
        "localhost",
        port,
        .{ .response_head_timeout = .fromSeconds(5) },
        .{
            .ca_bundle = .{ .bundle = &ca_bundle, .lock = &ca_lock },
            .stapled_ocsp = .require,
            .alpn_protocols = &.{"http/1.1"},
            .protocol_policy = if (tls12) .tls12_only else .tls13_only,
        },
    );
    defer client.close();
    const expected_protocol: netz.tls.stream.Protocol =
        if (tls12) .tls12 else .tls13;
    if (client.negotiatedTlsProtocol() != expected_protocol) {
        return error.InvalidProtocolVersion;
    }
    var response = try client.request(.{
        .method = .GET,
        .target = "/ocsp",
        .host = "localhost",
    });
    defer response.deinit(allocator);
    if (response.response.status != 200 or
        !std.mem.eql(u8, response.response.body, "ocsp-ok"))
    {
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/1 client required a good OpenSSL OCSP staple: " ++
            "tls={s} status=200\n",
        .{if (tls12) "1.2" else "1.3"},
    );
}

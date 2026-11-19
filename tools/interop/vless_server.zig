//! Minimal VLESS TLS server used by independent-peer interop gates.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var bind_text: []const u8 = "127.0.0.1:18446";
    var uuid_text: []const u8 = "00000000-0000-4000-8000-000000000001";
    var allow_all = false;
    var transport: netz.proxy.vless.server.Transport = .tls;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--bind=")) {
            bind_text = arg["--bind=".len..];
        } else if (std.mem.startsWith(u8, arg, "--uuid=")) {
            uuid_text = arg["--uuid=".len..];
        } else if (std.mem.eql(u8, arg, "--allow-all")) {
            allow_all = true;
        } else if (std.mem.startsWith(u8, arg, "--transport=")) {
            const value = arg["--transport=".len..];
            transport = if (std.mem.eql(u8, value, "tls"))
                .tls
            else if (std.mem.eql(u8, value, "ws"))
                .ws
            else
                return error.InvalidArgument;
        } else return error.InvalidArgument;
    }

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();

    const address = try std.Io.net.IpAddress.parseLiteral(bind_text);
    var server = try netz.proxy.vless.server.Server.init(
        allocator,
        io,
        address,
        .{
            .uuid = try netz.proxy.vless.protocol.parseUuid(uuid_text),
            .tls = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .acl = if (allow_all) .{ .default_action = .allow } else .{},
            .transport = transport,
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz VLESS server listening on {f} transport={s} server_io=zio-std-io\n",
        .{ server.listener.socket.address, @tagName(transport) },
    );
    try server.serve();
}

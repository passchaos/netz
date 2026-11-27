//! Minimal TUIC v5 server used by the independent sing-box interop gate.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var bind_text: []const u8 = "127.0.0.1:18452";
    var uuid_text: []const u8 = "00000000-0000-4000-8000-000000000003";
    var password: []const u8 = "netz-tuic-interop";
    var allow_all = false;
    var single = false;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--bind=")) {
            bind_text = arg["--bind=".len..];
        } else if (std.mem.startsWith(u8, arg, "--uuid=")) {
            uuid_text = arg["--uuid=".len..];
        } else if (std.mem.startsWith(u8, arg, "--password=")) {
            password = arg["--password=".len..];
        } else if (std.mem.eql(u8, arg, "--allow-all")) {
            allow_all = true;
        } else if (std.mem.eql(u8, arg, "--single")) {
            single = true;
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
    var server = try netz.proxy.tuic.server.Server.init(
        allocator,
        io,
        address,
        .{
            .uuid = try netz.proxy.vless.protocol.parseUuid(uuid_text),
            .password = password,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .acl = if (allow_all) .{ .default_action = .allow } else .{},
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz TUIC server listening on {f} server_io=zio-std-io\n",
        .{server.address()},
    );
    if (single) try server.serveOne() else try server.serve();
}

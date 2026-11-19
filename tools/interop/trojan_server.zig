//! Minimal Trojan TLS server used by independent-peer interop gates.
//!
//! The server uses the repository test identity and the standard hashed
//! password proof. Protocol state and relay behavior live in
//! `netz.proxy.trojan`.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var bind_text: []const u8 = "127.0.0.1:18443";
    var password: []const u8 = "netz-trojan-interop";
    var allow_all = false;
    var transport: netz.proxy.trojan.server.Transport = .tls;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--bind=")) {
            bind_text = arg["--bind=".len..];
        } else if (std.mem.startsWith(u8, arg, "--password=")) {
            password = arg["--password=".len..];
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
    if (password.len == 0) return error.InvalidArgument;

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
    var server = try netz.proxy.trojan.server.Server.init(
        allocator,
        io,
        address,
        .{
            .password = password,
            .password_mode = .hashed,
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
        "netz Trojan server listening on {f} transport={s} server_io=zio-std-io\n",
        .{ server.listener.socket.address, @tagName(transport) },
    );
    try server.serve();
}

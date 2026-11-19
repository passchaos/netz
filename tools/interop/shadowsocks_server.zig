//! Minimal Shadowsocks AEAD TCP server used by independent-peer interop gates.
//!
//! The server owns one listener and one bounded task per accepted connection.
//! Protocol state and relay behavior live in `netz.proxy.shadowsocks.tcp`.

const std = @import("std");
const netz = @import("netz");

const cipher = netz.proxy.shadowsocks.cipher;

fn parseMethod(text: []const u8) ?cipher.Algorithm {
    if (std.mem.eql(u8, text, "aes-128-gcm")) return .aes_128_gcm;
    if (std.mem.eql(u8, text, "aes-256-gcm")) return .aes_256_gcm;
    if (std.mem.eql(u8, text, "chacha20-ietf-poly1305")) {
        return .chacha20_ietf_poly1305;
    }
    return null;
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var bind_text: []const u8 = "127.0.0.1:8388";
    var method_text: []const u8 = "aes-256-gcm";
    var password: []const u8 = "netz-interop-password";
    var allow_all = false;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--bind=")) {
            bind_text = arg["--bind=".len..];
        } else if (std.mem.startsWith(u8, arg, "--method=")) {
            method_text = arg["--method=".len..];
        } else if (std.mem.startsWith(u8, arg, "--password=")) {
            password = arg["--password=".len..];
        } else if (std.mem.eql(u8, arg, "--allow-all")) {
            allow_all = true;
        } else return error.InvalidArgument;
    }
    const method = parseMethod(method_text) orelse return error.InvalidArgument;
    if (password.len == 0) return error.InvalidArgument;

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const address = try std.Io.net.IpAddress.parseLiteral(bind_text);
    var listener = try address.listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    std.debug.print(
        "netz Shadowsocks server listening on {f} method={s} server_io=zio-std-io\n",
        .{ listener.socket.address, method_text },
    );

    var connections: std.Io.Group = .init;
    defer connections.cancel(io);
    while (true) {
        const stream = listener.accept(io) catch continue;
        connections.concurrent(
            io,
            serve,
            .{ io, allocator, stream, method, password, allow_all },
        ) catch {
            stream.close(io);
            continue;
        };
    }
}

fn serve(
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: std.Io.net.Stream,
    method: cipher.Algorithm,
    password: []const u8,
    allow_all: bool,
) void {
    defer stream.close(io);
    netz.proxy.shadowsocks.tcp.processConnection(
        allocator,
        io,
        stream,
        stream.socket.address,
        .{
            .method = method,
            .password = password,
            .acl = if (allow_all) .{ .default_action = .allow } else .{},
        },
        null,
        null,
    ) catch |err| {
        std.debug.print("Shadowsocks connection error: {any}\n", .{err});
    };
}

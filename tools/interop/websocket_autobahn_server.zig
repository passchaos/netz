//! Long-lived RFC 6455 echo endpoint for Autobahn Testsuite fuzzingclient.
//!
//! Each accepted connection has an independent worker because Autobahn can
//! begin its next case before the prior peer's close handshake has completely
//! unwound. Protocol failures are expected test inputs and are handled by the
//! runtime's typed Close response rather than terminating this listener.

const std = @import("std");
const netz = @import("netz");

const max_message_bytes: usize = 20_000_000;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const use_tls = args.len == 3 and std.mem.eql(u8, args[2], "--tls");
    if (args.len == 3 and !use_tls) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: netz.websocket.runtime.Limits = .{
        .max_head_bytes = 4096,
        .max_frame_bytes = max_message_bytes,
        .max_message_bytes = max_message_bytes,
    };
    if (use_tls) {
        var certificate_der: [netz.tls.testing.certificate_der_len]u8 =
            undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            netz.tls.testing.certificate_base64,
        );
        const key_pair = try netz.tls.testing.serverKeyPair();
        var server = try netz.websocket.runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = limits,
                .cipher_suites = &.{.aes_128_gcm_sha256},
            },
        );
        defer server.deinit();
        try serveForever(&server);
    } else {
        var server = try netz.websocket.runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
        defer server.deinit();
        try serveForever(&server);
    }
}

fn serveForever(server: anytype) !void {
    std.debug.print(
        "netz Autobahn WebSocket server listening on {f}\n",
        .{server.address()},
    );

    while (true) {
        var connection = server.accept(.{
            .enable_permessage_deflate = true,
        }) catch continue;
        const thread = std.Thread.spawn(
            .{},
            echoConnection,
            .{connection},
        ) catch {
            connection.close();
            continue;
        };
        thread.detach();
    }
}

fn echoConnection(initial: netz.websocket.runtime.Connection) void {
    var connection = initial;
    defer connection.close();
    while (true) {
        var message = connection.receiveMessage() catch return;
        defer message.deinit(connection.allocator);
        switch (message.opcode) {
            .text => connection.sendText(message.payload) catch return,
            .binary => connection.sendBinary(message.payload) catch return,
            else => return,
        }
    }
}

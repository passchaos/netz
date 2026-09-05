//! One-shot HTTP/1.1 WebSocket endpoint for browser interoperability.

const std = @import("std");
const netz = @import("netz");

const protocol = "netz.chrome.v1";
const text_request = "chrome text";
const text_response = "netz text";
const binary_request = "chrome binary";
const binary_response = "netz binary";
const compressed_request = "chrome compressed " ** 128;
const compressed_response = "netz compressed " ** 128;
const ping_payload = "browser-pong";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 and args.len != 5) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const origin = args[2];

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    const limits: netz.websocket.runtime.Limits = .{
        .max_head_bytes = 4096,
        .max_frame_bytes = 4096,
        .max_message_bytes = 4096,
    };
    if (args.len == 5) {
        const certificate_der = try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[3],
            allocator,
            .limited(16 * 1024),
        );
        defer allocator.free(certificate_der);
        const private_scalar = try std.Io.Dir.cwd().readFileAlloc(
            io,
            args[4],
            allocator,
            .limited(33),
        );
        defer allocator.free(private_scalar);
        if (private_scalar.len != 32) return error.InvalidArgument;
        const secret = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey
            .fromBytes(private_scalar[0..32].*);
        const key_pair = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair
            .fromSecretKey(secret);
        var server = try netz.websocket.runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            .{
                .identity = .{
                    .certificate_chain = &.{certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = limits,
                .cipher_suites = &.{.aes_128_gcm_sha256},
            },
        );
        defer server.deinit();
        try serveOnce(&server, origin, "wss");
    } else {
        var server = try netz.websocket.runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
        defer server.deinit();
        try serveOnce(&server, origin, "ws");
    }
}

fn serveOnce(server: anytype, origin: []const u8, scheme: []const u8) !void {
    const allocator = std.heap.c_allocator;
    std.debug.print(
        "netz Chrome WebSocket server listening on {f} scheme={s}\n",
        .{ server.address(), scheme },
    );

    if (server.receiveUpgradeRequest(.{
        .protocols = &.{protocol},
        .require_subprotocol = true,
        .allowed_origins = &.{origin},
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
    })) |unexpected| {
        var pending = unexpected;
        pending.deinit();
        return error.ExpectedOriginRejection;
    } else |err| switch (err) {
        error.InvalidOrigin => {},
        else => return err,
    }

    var pending = try server.receiveUpgradeRequest(.{
        .protocols = &.{protocol},
        .require_subprotocol = true,
        .allowed_origins = &.{origin},
        .enable_permessage_deflate = true,
        .compression_threshold = 0,
    });
    var pending_owned = true;
    defer if (pending_owned) pending.deinit();
    if (!std.mem.eql(u8, pending.target(), "/browser?case=interop")) {
        return error.UnexpectedTarget;
    }
    if (!std.mem.eql(u8, pending.header("origin") orelse return error.MissingOrigin, origin)) {
        return error.UnexpectedOrigin;
    }
    var connection = try pending.acceptWithHeaders(&.{.{
        .name = "X-Netz-Interop",
        .value = "chrome",
    }});
    pending_owned = false;
    defer connection.close();
    if (!std.mem.eql(u8, connection.selected_protocol orelse return error.MissingProtocol, protocol)) {
        return error.UnexpectedProtocol;
    }
    if (!connection.permessage_deflate) return error.MissingCompression;

    var text = try connection.receiveMessageWithTimeout(.fromSeconds(5));
    defer text.deinit(allocator);
    if (text.opcode != .text or !std.mem.eql(u8, text.payload, text_request)) {
        return error.UnexpectedMessage;
    }
    try connection.sendText(text_response);

    var binary = try connection.receiveMessageWithTimeout(.fromSeconds(5));
    defer binary.deinit(allocator);
    if (binary.opcode != .binary or !std.mem.eql(u8, binary.payload, binary_request)) {
        return error.UnexpectedMessage;
    }
    try connection.sendBinary(binary_response);

    var compressed = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer compressed.deinit(allocator);
    if (compressed.opcode != .text or
        !compressed.was_compressed or
        !std.mem.eql(u8, compressed.payload, compressed_request))
    {
        return error.UnexpectedCompressedMessage;
    }
    try connection.sendText(compressed_response);

    var ping = try connection.pingWithTimeout(
        ping_payload,
        .fromSeconds(5),
    );
    defer ping.deinit(allocator);
    if (ping != .pong) return error.UnexpectedMessage;

    try connection.sendClose(.going_away, "netz browser done");
    var close = (try connection.receiveCloseFrameWithTimeout(
        .fromSeconds(5),
    )) orelse return error.MissingClose;
    defer close.deinit(allocator);
    if (close.code != .going_away or
        !std.mem.eql(u8, close.reason, "netz browser done"))
    {
        return error.UnexpectedClose;
    }
    std.debug.print(
        "netz Chrome WebSocket interop passed: scheme={s} rejected-origin accepted-origin subprotocol compressed-text binary ping-pong close=1001/netz-browser-done\n",
        .{scheme},
    );
}

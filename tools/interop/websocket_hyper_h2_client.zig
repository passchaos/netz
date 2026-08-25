//! RFC 8441 client for process-boundary interoperability with Hyper's HTTP/2
//! Extended CONNECT and upgraded byte-stream implementation.

const std = @import("std");
const netz = @import("netz");

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
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .enable_connect_protocol = true,
        .handshake_timeout = .fromSeconds(5),
    };
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    var exported: [32]u8 = undefined;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }
    var h2 = if (tls_enabled)
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
    defer h2.close();
    var websocket = try netz.websocket.runtime.H2Client.open(
        allocator,
        &h2,
        .{
            .authority = "localhost",
            .path = "/websocket",
            .scheme = "http",
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
        },
    );
    defer websocket.close();
    if (tls_enabled) {
        const chain = websocket.peerCertificates() orelse
            return error.MissingPeerCertificate;
        if (chain.len == 0 or
            !std.mem.eql(u8, websocket.negotiatedAlpn().?, "h2") or
            websocket.negotiatedCipherSuite() == null or
            websocket.negotiatedTranscriptHash() == null)
        {
            return error.InvalidTlsMetadata;
        }
        try websocket.exportKeyingMaterial(
            "EXPORTER-netz-rfc8441",
            "hyper",
            &exported,
        );
    } else {
        if (websocket.peerCertificates() != null or
            websocket.negotiatedAlpn() != null or
            websocket.keyUpdateCounts() != null)
        {
            return error.InvalidTlsMetadata;
        }
    }

    try websocket.sendFragmented(.text, &.{ "netz ", "websocket ", "h2" });
    var response = try websocket.receiveMessage();
    defer response.deinit(allocator);
    if (response.opcode != .text or
        !std.mem.eql(u8, response.payload, "hyper websocket h2"))
    {
        return error.UnexpectedWebSocketMessage;
    }
    if (tls_enabled) {
        var peer_exporter = try websocket.receiveMessage();
        defer peer_exporter.deinit(allocator);
        if (peer_exporter.opcode != .binary or
            !std.mem.eql(u8, peer_exporter.payload, &exported))
        {
            return error.InvalidExporter;
        }
        const updates = websocket.keyUpdateCounts() orelse
            return error.MissingKeyUpdate;
        if (updates.received != 1 or updates.sent != 1 or
            updates.awaiting_peer_response)
        {
            return error.InvalidKeyUpdateCount;
        }
    }

    try websocket.sendPing("ping");
    var pong = try websocket.receiveFrame();
    defer pong.deinit(allocator);
    if (pong.header.opcode != .pong or
        !std.mem.eql(u8, pong.payload, "ping"))
    {
        return error.UnexpectedPong;
    }

    var close_event = try websocket.closeWithTimeout(
        .{ .code = .normal_closure, .reason = "done" },
        .fromSeconds(1),
    );
    defer close_event.deinit(allocator);
    const close = close_event.closed orelse
        return error.MissingClosePayload;
    if (close.code != .normal_closure or
        !std.mem.eql(u8, close.reason, "done"))
    {
        return error.UnexpectedClose;
    }

    std.debug.print(
        "netz RFC 8441 client interoperated with Hyper: transport={s} fragmented-text ping pong bounded-close tls_metadata={s} key_update={s}\n",
        .{
            if (tls_enabled) "tls" else "h2c",
            if (tls_enabled) "verified" else "n/a",
            if (tls_enabled) "verified" else "n/a",
        },
    );
}

//! Certificate-verified RFC 9220 client for process-boundary interoperability
//! with a quic-go HTTP/3 server and its independent RFC 6455 codec.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0 or !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }
    const version = try parseVersion(args[3..]);

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const now = std.Io.Clock.real.now(io);
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        now,
        args[2],
    );
    var verifier = netz.quic.tls.trust.BundleVerifier{
        .bundle = &ca_bundle,
        .now_seconds = now.toSeconds(),
    };
    var original_dcid: [8]u8 = undefined;
    var client_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &client_cid);

    var connection = try netz.websocket.runtime.h3.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .version = version,
                .available_versions = availableVersions(version),
                .server_name = "localhost",
                .server_auth = verifier.clientVerifier(),
                .max_crypto_buffer = 64 * 1024,
            },
            // Splitting HTTP/3 DATA prevents the external exchange from
            // accidentally depending on one WebSocket frame per QUIC write.
            .session = .{ .max_stream_frame_data = 16 },
        },
        .{
            .authority = "localhost",
            .path = "/rfc9220",
            .origin = "https://example.test",
            .protocols = &.{"netz-chat"},
            .enable_permessage_deflate = true,
            .compression_threshold = 1,
            .limits = websocketLimits(),
        },
    );
    defer connection.deinit();
    if (!std.mem.eql(u8, connection.negotiatedAlpn(), "h3") or
        connection.peerCertificates() == null or
        connection.peerCertificates().?.len == 0 or
        !connection.permessage_deflate or
        connection.selectedProtocol() == null or
        !std.mem.eql(
            u8,
            connection.selectedProtocol().?,
            "netz-chat",
        ))
    {
        return error.InvalidNegotiatedMetadata;
    }

    try connection.sendFragmented(.text, &.{
        "netz websocket ",
        "h3",
    });
    var response = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer response.deinit(allocator);
    if (response.opcode != .text or
        !std.mem.eql(u8, response.payload, "quic-go websocket h3"))
    {
        return error.UnexpectedWebSocketMessage;
    }
    try connection.sendText(
        "netz compressed websocket h3 netz compressed websocket h3 netz compressed websocket h3",
    );
    var compressed_response = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer compressed_response.deinit(allocator);
    if (compressed_response.opcode != .text or
        !compressed_response.was_compressed or
        !std.mem.eql(
            u8,
            compressed_response.payload,
            "quic-go compressed websocket h3 quic-go compressed websocket h3 quic-go compressed websocket h3",
        ))
    {
        return error.UnexpectedCompressedMessage;
    }
    try connection.sendText(
        "netz second compressed message netz second compressed message netz second compressed message",
    );
    var compressed_again = try connection.receiveMessageWithTimeout(
        .fromSeconds(5),
    );
    defer compressed_again.deinit(allocator);
    if (compressed_again.opcode != .text or
        !compressed_again.was_compressed or
        !std.mem.eql(
            u8,
            compressed_again.payload,
            "quic-go second compressed message quic-go second compressed message quic-go second compressed message",
        ))
    {
        return error.UnexpectedCompressedMessage;
    }

    try connection.sendPing("probe");
    var pong = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer pong.deinit(allocator);
    if (pong.header.opcode != .pong or
        !std.mem.eql(u8, pong.payload, "probe"))
    {
        return error.UnexpectedPong;
    }

    try connection.sendClose(.normal_closure, "done");
    var close = try connection.receiveFrameWithTimeout(.fromSeconds(5));
    defer close.deinit(allocator);
    if (close.header.opcode != .close) return error.UnexpectedClose;
    const parsed = (try netz.websocket.parseClosePayload(close.payload)) orelse
        return error.MissingClosePayload;
    if (parsed.code != .normal_closure or
        !std.mem.eql(u8, parsed.reason, "done"))
    {
        return error.UnexpectedClose;
    }

    std.debug.print(
        "netz RFC 9220 client interoperated with quic-go: version={d} extended_connect=true tls_verified=true origin=true subprotocol=netz-chat masked_fragmented_text=true permessage_deflate=no_context_takeover ping_pong=true close=1000/done\n",
        .{versionNumber(version)},
    );
}

fn parseVersion(args: []const []const u8) !netz.quic.Version {
    if (args.len == 0) return .version_1;
    if (args.len == 1 and std.mem.eql(u8, args[0], "--version=2")) {
        return .version_2;
    }
    return error.InvalidArgument;
}

fn availableVersions(version: netz.quic.Version) []const netz.quic.Version {
    return if (version == .version_2)
        &.{.version_2}
    else
        &.{ .version_1, .version_2 };
}

fn versionNumber(version: netz.quic.Version) u8 {
    return if (version == .version_2) 2 else 1;
}

fn websocketLimits() netz.websocket.runtime.Limits {
    return .{
        .max_frame_bytes = 4096,
        .max_message_bytes = 4096,
    };
}

//! Cross-host HTTP/3 multipath probe.
//!
//! `serve` runs one HTTP/3 server and echoes the peer address observed for
//! every request. `probe` opens one owning HTTP/3 connection per local bind
//! address, so each path can leave through a different NIC:
//!
//! ```text
//! netz-h3-multipath-probe serve --listen=0.0.0.0:4433 --sessions=2
//! netz-h3-multipath-probe probe --server=10.0.0.10:4433 \
//!   --bind=10.0.0.20 --bind=10.0.0.30
//! ```
//!
//! netz implements QUIC connection migration and path validation, not the
//! draft-ietf-quic-multipath extension. This tool therefore exercises
//! application-level multipath over independent QUIC connections.

const std = @import("std");
const netz = @import("netz");

const net = std.Io.net;

const quic_limits: netz.http3.runtime.Limits = .{
    .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 16,
    },
};

const session_options: netz.http3.runtime.HandshakeSessionOptions = .{
    .max_stream_buffer = 64 * 1024,
    .max_stream_frame_data = 512,
};

fn printIp4(address: net.Ip4Address) void {
    std.debug.print("{d}.{d}.{d}.{d}:{d}", .{
        address.bytes[0],
        address.bytes[1],
        address.bytes[2],
        address.bytes[3],
        address.port,
    });
}

fn headerValue(
    request: netz.http3.DecodedRequest,
    name: []const u8,
) ?[]const u8 {
    for (request.headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }
    return null;
}

fn serve(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: *std.process.Args.Iterator,
) !void {
    var listen_text: []const u8 = "0.0.0.0:4433";
    var sessions: usize = 4;
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--listen=")) {
            listen_text = arg["--listen=".len..];
        } else if (std.mem.startsWith(u8, arg, "--sessions=")) {
            sessions = try std.fmt.parseInt(usize, arg["--sessions=".len..], 10);
        } else {
            return error.InvalidArgument;
        }
    }
    if (sessions == 0) return error.InvalidArgument;

    const listen = try net.IpAddress.parseLiteral(listen_text);
    const server_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        listen,
        quic_limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x54} ** 32,
                .x25519_secret_key = [_]u8{0x55} ** 32,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = session_options,
        },
    );
    defer server.deinit();

    std.debug.print("SERVER listening on ", .{});
    printIp4(server.address().ip4);
    std.debug.print(" sessions={d}\n", .{sessions});

    for (0..sessions) |index| {
        var session = try server.accept();
        defer session.deinit();

        var request = try session.receiveRequest();
        defer request.deinit(
            session.established.connection.endpoint.allocator,
        );
        const path = headerValue(request.request, "x-netz-path") orelse "unknown";

        var body_buffer: [160]u8 = undefined;
        const body = try std.fmt.bufPrint(
            &body_buffer,
            "peer={d}.{d}.{d}.{d}:{d} path={s}",
            .{
                session.established.connection.peerAddress().ip4.bytes[0],
                session.established.connection.peerAddress().ip4.bytes[1],
                session.established.connection.peerAddress().ip4.bytes[2],
                session.established.connection.peerAddress().ip4.bytes[3],
                session.established.connection.peerAddress().ip4.port,
                path,
            },
        );
        try session.sendResponse(request.stream_id, .{
            .status = 200,
            .headers = &.{.{
                .name = "content-type",
                .value = "text/plain",
            }},
            .body = body,
        });

        std.debug.print("SERVED {d} peer=", .{index});
        printIp4(session.established.connection.peerAddress().ip4);
        std.debug.print(" path={s}\n", .{path});
    }
}

fn probeOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_address: net.IpAddress,
    local_address: net.IpAddress,
) !void {
    const original_dcid =
        [_]u8{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 };
    var client_cid: [4]u8 = .{
        local_address.ip4.bytes[0],
        local_address.ip4.bytes[1],
        local_address.ip4.bytes[2],
        local_address.ip4.bytes[3],
    };
    var random: [32]u8 = undefined;
    var secret: [32]u8 = undefined;
    for (&random, 0..) |*byte, index| {
        byte.* = local_address.ip4.bytes[index % 4] +% @as(u8, @truncate(index));
    }
    for (&secret, 0..) |*byte, index| {
        byte.* = local_address.ip4.bytes[index % 4] ^ @as(u8, @truncate(index));
    }

    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        local_address,
        server_address,
        quic_limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = random,
                .x25519_secret_key = secret,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = session_options,
        },
    );
    defer client.deinit();

    var label_buffer: [64]u8 = undefined;
    const label = try std.fmt.bufPrint(
        &label_buffer,
        "{d}.{d}.{d}.{d}",
        .{
            local_address.ip4.bytes[0],
            local_address.ip4.bytes[1],
            local_address.ip4.bytes[2],
            local_address.ip4.bytes[3],
        },
    );
    var authority_buffer: [64]u8 = undefined;
    const authority = try std.fmt.bufPrint(
        &authority_buffer,
        "{d}.{d}.{d}.{d}:{d}",
        .{
            server_address.ip4.bytes[0],
            server_address.ip4.bytes[1],
            server_address.ip4.bytes[2],
            server_address.ip4.bytes[3],
            server_address.ip4.port,
        },
    );

    var response = try client.request(.{
        .method = "GET",
        .path = "/multipath",
        .authority = authority,
        .headers = &.{.{
            .name = "x-netz-path",
            .value = label,
        }},
    });
    defer response.deinit(allocator);

    std.debug.print("PATH local={s} -> {d} body={s}\n", .{
        label,
        response.response.status,
        response.response.body,
    });
}

fn probe(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: *std.process.Args.Iterator,
) !void {
    var server_text: ?[]const u8 = null;
    var binds: [16]net.IpAddress = undefined;
    var bind_count: usize = 0;
    while (args.next()) |arg| {
        if (std.mem.startsWith(u8, arg, "--server=")) {
            server_text = arg["--server=".len..];
        } else if (std.mem.startsWith(u8, arg, "--bind=")) {
            if (bind_count == binds.len) return error.TooManyBinds;
            binds[bind_count] = try net.IpAddress.parseLiteral(
                arg["--bind=".len..],
            );
            bind_count += 1;
        } else {
            return error.InvalidArgument;
        }
    }
    const server_address = try net.IpAddress.parseLiteral(
        server_text orelse return error.MissingServer,
    );
    if (bind_count == 0) return error.MissingBind;

    var failures: usize = 0;
    for (binds[0..bind_count]) |local_address| {
        probeOne(allocator, io, server_address, local_address) catch |err| {
            failures += 1;
            std.debug.print("PATH local=", .{});
            printIp4(local_address.ip4);
            std.debug.print(" ERR {s}\n", .{@errorName(err)});
        };
    }
    if (failures != 0) return error.PathFailure;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        allocator,
    );
    defer args.deinit();
    _ = args.next();
    const mode = args.next() orelse return error.MissingMode;
    if (std.mem.eql(u8, mode, "serve")) {
        try serve(allocator, io, &args);
    } else if (std.mem.eql(u8, mode, "probe")) {
        try probe(allocator, io, &args);
    } else {
        return error.InvalidMode;
    }
}

//! Long-lived h2c adapter for the external h2spec conformance runner.
//!
//! h2spec deliberately tears down malformed connections and immediately opens
//! another one. Protocol errors therefore terminate only the current accepted
//! connection; the listener remains available for the rest of the suite.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const use_tls = args.len == 3 and
        std.mem.eql(u8, args[2], "--tls");
    if (args.len == 3 and !use_tls) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 1024 * 1024,
        .max_concurrent_streams = 128,
    };
    if (use_tls) {
        var certificate_der: [netz.tls.testing.certificate_der_len]u8 =
            undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            netz.tls.testing.certificate_base64,
        );
        const key_pair = try netz.tls.testing.serverKeyPair();
        var server = try netz.http2.runtime.TlsServer.listen(
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
            },
        );
        defer server.deinit();
        try serveForever(&server, io, allocator);
    } else {
        var server = try netz.http2.runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
        defer server.deinit();
        try serveForever(&server, io, allocator);
    }
}

fn serveForever(
    server: anytype,
    io: std.Io,
    allocator: std.mem.Allocator,
) !void {
    std.debug.print(
        "netz h2spec server listening on {f}\n",
        .{server.address()},
    );

    while (true) {
        const stream = server.listener.accept(io) catch continue;
        const thread = std.Thread.spawn(
            .{},
            acceptAndServe,
            .{ server, io, allocator, stream },
        ) catch {
            stream.close(io);
            continue;
        };
        thread.detach();
    }
}

fn acceptAndServe(
    server: anytype,
    io: std.Io,
    allocator: std.mem.Allocator,
    stream: std.Io.net.Stream,
) void {
    var connection = server.acceptStream(stream) catch return;
    while (true) {
        var request = connection.readRequest() catch |err| {
            if (err == error.StreamReset) {
                continue;
            }
            // The runtime reports protocol violations to its owner so an
            // application can choose its shutdown policy. This adapter is a
            // conformance endpoint, so make that policy observable on the
            // wire before gracefully closing the test connection.
            if (err != error.ConnectionClosed and
                err != error.ConnectionGoAway)
            {
                connection.sendGoAway(
                    0,
                    .protocol_error,
                    @errorName(err),
                ) catch {};
            }
            break;
        };
        connection.writeResponse(request.stream_id, .{
            .status = 200,
            .headers = &.{.{
                .name = "content-type",
                .value = "text/plain",
            }},
            // Keep at least five bytes so h2spec also exercises the negative
            // SETTINGS_INITIAL_WINDOW_SIZE case instead of skipping it.
            .body = "netz h2spec",
        }) catch {
            request.deinit(allocator);
            break;
        };
        request.deinit(allocator);
    }
    // h2spec's ServerDataLength probe does not close its helper connection.
    // Handling each accepted socket independently prevents that probe from
    // blocking the listener and therefore the remainder of the suite.
    if (@TypeOf(server.*) == netz.http2.runtime.Server) {
        connection.stream.shutdown(io, .send) catch {};
        var drain: [1024]u8 = undefined;
        var reader = connection.stream.reader(io, &drain);
        while (true) {
            _ = reader.interface.takeByte() catch break;
        }
    }
    connection.close();
}

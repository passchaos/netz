const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.initAuto(allocator, .evented_then_threaded);
    defer backend.deinit();
    const io = backend.io();
    std.debug.print("std.Io backend: {t}\n", .{backend.kind});

    const server_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x54} ** 32,
                .x25519_secret_key = [_]u8{0x55} ** 32,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 512,
            },
        },
    );
    defer server.deinit();
    std.debug.print("HTTP/3 server listening on https://127.0.0.1:{d}\n", .{server.address().ip4.port});

    const Shared = struct {
        server: *netz.http3.runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.http3.runtime.HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            std.debug.print("HTTP/3 server received {s} {s} body={s}\n", .{
                request.request.method,
                request.request.path,
                request.request.body,
            });

            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "server", .value = "netz-http3-handshake" },
                },
                .body = "hello from netz HTTP/3 over QUIC",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri_text = try std.fmt.allocPrint(
        allocator,
        "https://127.0.0.1:{d}/h3-local?example=handshake",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri_text);
    const uri = try std.Uri.parse(uri_text);

    const original_dcid = [_]u8{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 };
    const client_cid = [_]u8{ 0x68, 0x69, 0x6a, 0x6b };

    // This local example keeps the verifier unset so the transport handshake
    // stays self-contained. Public-network clients should install WebPKI
    // verification, as `run-http3-fetch --verify` does.
    var response = try netz.http3.runtime.HandshakeClient.requestUri(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{
            .method = "POST",
            .headers = &.{.{ .name = "x-example", .value = "http3-handshake" }},
            .body = "hello over QUIC",
        },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x6c} ** 32,
                .x25519_secret_key = [_]u8{0x6d} ** 32,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 512,
            },
        },
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    std.debug.print("HTTP/3 client received {d}: {s}\n", .{
        response.response.status,
        response.response.body,
    });
}

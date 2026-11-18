//! Carry HTTP/3 requests over two independent QUIC paths.
//!
//! netz implements QUIC connection migration and path validation, not the
//! draft-ietf-quic-multipath extension. This example therefore demonstrates
//! application-level multipath: two owning HTTP/3 clients bind distinct local
//! UDP addresses and issue requests over separate QUIC connections. The same
//! `runPath` helper can be scheduled on separate tasks for racing, failover,
//! or path-selection policies.

const std = @import("std");
const netz = @import("netz");

const net = std.Io.net;
const request_count = 2;

const PathResult = struct {
    local_port: u16,
    status: u16,
    body_bytes: usize,
};

fn requestHeader(
    request: netz.http3.DecodedRequest,
    name: []const u8,
) ?[]const u8 {
    for (request.headers) |header| {
        if (std.mem.eql(u8, header.name, name)) return header.value;
    }
    return null;
}

fn runPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    server_address: net.IpAddress,
    label: []const u8,
    client_cid: [4]u8,
    random: [32]u8,
    secret: [32]u8,
) !PathResult {
    const original_dcid =
        [_]u8{ 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67 };
    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_address,
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = random,
                .x25519_secret_key = secret,
                .max_crypto_buffer = 64 * 1024,
            },
            .session = .{
                .max_stream_buffer = 64 * 1024,
                .max_stream_frame_data = 512,
            },
        },
    );
    defer client.deinit();

    var authority_buffer: [64]u8 = undefined;
    const authority = try std.fmt.bufPrint(
        &authority_buffer,
        "127.0.0.1:{d}",
        .{server_address.ip4.port},
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

    const result = PathResult{
        .local_port = client.endpoint.address().ip4.port,
        .status = response.response.status,
        .body_bytes = response.response.body.len,
    };
    std.debug.print(
        "client {s}: local 127.0.0.1:{d} -> {d} ({d} body bytes)\n",
        .{ label, result.local_port, result.status, result.body_bytes },
    );
    return result;
}

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const server_cid = [_]u8{ 0x50, 0x51, 0x52, 0x53 };
    var server = try netz.http3.runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 16,
        } },
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

    const server_address = server.address();
    std.debug.print(
        "HTTP/3 multipath server listening on https://127.0.0.1:{d}\n",
        .{server_address.ip4.port},
    );

    const ServerTask = struct {
        server: *netz.http3.runtime.HandshakeServer,
        handled: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..request_count) |_| {
                var session = try self.server.accept();
                defer session.deinit();

                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );

                const path = requestHeader(
                    request.request,
                    "x-netz-path",
                ) orelse "unknown";
                std.debug.print(
                    "server received {s} {s} on path {s}\n",
                    .{ request.request.method, request.request.path, path },
                );

                var body_buffer: [64]u8 = undefined;
                const body = try std.fmt.bufPrint(
                    &body_buffer,
                    "hello from {s}",
                    .{path},
                );
                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "content-type",
                        .value = "text/plain",
                    }},
                    .body = body,
                });
                self.handled += 1;
            }
        }
    };

    var server_task_state = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&server_task_state});
    defer server_task.cancel(io);

    const path_a = try runPath(
        allocator,
        io,
        server_address,
        "path-a",
        .{ 0x68, 0x69, 0x6a, 0x6b },
        [_]u8{0x6c} ** 32,
        [_]u8{0x6d} ** 32,
    );
    const path_b = try runPath(
        allocator,
        io,
        server_address,
        "path-b",
        .{ 0x71, 0x72, 0x73, 0x74 },
        [_]u8{0x75} ** 32,
        [_]u8{0x76} ** 32,
    );

    server_task.await(io);
    if (server_task_state.err) |err| return err;

    std.debug.print(
        "multipath summary: {d} request(s), paths 127.0.0.1:{d} and 127.0.0.1:{d}\n",
        .{ server_task_state.handled, path_a.local_port, path_b.local_port },
    );
}

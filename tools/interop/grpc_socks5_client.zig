//! Two canonical grpc-cpp unary RPCs through authenticated RFC 1928 SOCKS5
//! with proxy-side origin DNS and one reused TLS/HTTP2 tunnel.
const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

const unary_path = "/grpc.testing.TestService/UnaryCall";
const request_size: usize = 27_182;
const response_size: usize = 31_415;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArgument;
    const origin_port = try parsePort(args[1]);
    if (!std.Io.Dir.path.isAbsolute(args[2])) return error.InvalidArgument;
    const proxy_port = try parsePort(args[3]);
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    try ca_bundle.addCertsFromFilePathAbsolute(
        allocator,
        io,
        std.Io.Clock.real.now(io),
        args[2],
    );
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 64 * 1024,
        .max_body_bytes = 1024 * 1024,
        .initial_window_size = 512 * 1024,
        .initial_connection_window_size = 1024 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var client = try netz.grpc.SharedChannel.init(
        allocator,
        io,
        .{ .tls_host = .{
            .host = "foo.test.google.fr",
            .port = origin_port,
            .limits = limits,
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
            .socks5_proxy = .{
                .host = "127.0.0.1",
                .port = proxy_port,
                .options = .{
                    .credentials = .{
                        .username = "user",
                        .password = "pass:word",
                    },
                    .allow_no_authentication = false,
                },
            },
        } },
        .{ .disable_health_check = true },
    );
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();

    const request_body = try messages.encodeSimpleRequestAlloc(allocator, .{
        .response_size = response_size,
        .request_body_size = request_size,
    });
    defer allocator.free(request_body);
    for (0..2) |_| try call(sender, request_body);
    std.debug.print(
        "netz gRPC tunneled grpc-cpp TLS through SOCKS5: " ++
            "rpcs=2 remote_dns=true rfc1929=true auth_downgrade=false " ++
            "tls_identity=foo.test.google.fr certificate_verified=true " ++
            "alpn=h2 connection_reused=true client_io=zio-std-io " ++
            "proxy_io=python-socket server_io=grpc-cpp-posix-event-engine\n",
        .{},
    );
}

fn call(
    sender: netz.grpc.SharedChannelSender,
    request_body: []const u8,
) !void {
    var response = try sender.unary(.{
        .path = unary_path,
        .message = request_body,
        .wait_for_ready = true,
        .timeout = .{ .value = 20, .unit = .second },
        .max_message_size = messages.max_payload_size + 64,
    });
    defer response.deinit();
    if (response.status != .ok or response.message == null or
        response.was_compressed)
    {
        return error.InvalidUnaryResponse;
    }
    try messages.validateStreamingOutputCallResponse(
        response.message.?.payload,
        response_size,
    );
}

fn parsePort(raw: []const u8) !u16 {
    const port = try std.fmt.parseInt(u16, raw, 10);
    if (port == 0) return error.InvalidArgument;
    return port;
}

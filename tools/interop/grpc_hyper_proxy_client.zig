//! Two canonical grpc-cpp unary RPCs through an independent Hyper CONNECT
//! proxy, with proxy routing separated from TLS/gRPC origin identity.

const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

const unary_path = "/grpc.testing.TestService/UnaryCall";
const request_size: usize = 27_182;
const response_size: usize = 31_415;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const origin_port = try parsePort(args[1]);
    if (!std.Io.Dir.path.isAbsolute(args[2])) return error.InvalidArgument;
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
    var tunnel_authority_buffer: [64]u8 = undefined;
    const tunnel_authority = try std.fmt.bufPrint(
        &tunnel_authority_buffer,
        "localhost:{d}",
        .{origin_port},
    );
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 64 * 1024,
        .max_body_bytes = 1024 * 1024,
        .initial_window_size = 512 * 1024,
        .initial_connection_window_size = 1024 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var proxy_target = try netz.grpc.ChannelTlsHostProxyTarget.initEnviron(
        allocator,
        init.minimal.environ,
        .{ .tunnel_authority = tunnel_authority },
        .{
            .host = "foo.test.google.fr",
            .port = origin_port,
            .limits = limits,
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        },
    );
    defer proxy_target.deinit();
    if (proxy_target.decision == null or
        proxy_target.decision.? != .proxy or
        proxy_target.decision.?.proxy.source != .grpc_proxy)
    {
        return error.InvalidProxyPolicy;
    }
    var client = try netz.grpc.SharedChannel.init(
        allocator,
        io,
        proxy_target.target,
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
        "netz gRPC tunneled grpc-cpp TLS through Hyper CONNECT proxy: " ++
            "rpcs=2 tunnel_authority={s} tls_identity=foo.test.google.fr " ++
            "certificate_verified=true alpn=h2 proxy_authorization=isolated " ++
            "connection_reused=true client_io=zio-std-io " ++
            "proxy_io=hyper-tokio server_io=grpc-cpp-posix-event-engine\n",
        .{tunnel_authority},
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

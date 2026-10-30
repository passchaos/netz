//! Two-endpoint pick-first failover against independently managed grpc-cpp
//! servers. The runner retires endpoint A after the first canonical unary and
//! starts endpoint B before the second wait-for-ready call.

const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");

const unary_path = "/grpc.testing.TestService/UnaryCall";
const authority = "localhost";
const request_size: usize = 271_828;
const response_size: usize = 314_159;

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 and args.len != 4) return error.InvalidArgument;
    const ports = [_]u16{
        try parsePort(args[1]),
        try parsePort(args[2]),
    };
    if (ports[0] == ports[1]) return error.InvalidArgument;
    const tls_enabled = args.len == 4;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[3])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[3],
        );
    }

    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 64 * 1024,
        .max_body_bytes = 4 * 1024 * 1024,
        .initial_window_size = 512 * 1024,
        .initial_connection_window_size = 2 * 1024 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };
    var endpoints: [2]netz.grpc.ChannelEndpoint = undefined;
    for (&endpoints, ports) |*endpoint, port| {
        endpoint.* = if (tls_enabled) .{ .tls_address = .{
            .address = .{ .ip4 = .loopback(port) },
            .tls_host = "foo.test.google.fr",
            .authority = authority,
            .limits = limits,
            .tls = .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        } } else .{ .cleartext_ip = .{
            .address = .{ .ip4 = .loopback(port) },
            .limits = limits,
        } };
    }
    var channel = try netz.grpc.SharedChannel.init(
        allocator,
        io,
        .{ .resolved = .{
            .endpoints = &endpoints,
            .policy = .pick_first,
        } },
        .{
            .disable_health_check = true,
            .channel = .{ .backoff = .{
                .initial_backoff = .fromMilliseconds(50),
                .max_backoff = .fromMilliseconds(50),
                .multiplier = 1,
                .jitter = 0,
            } },
        },
    );
    defer channel.deinit();
    if (channel.endpointCount() != 2) return error.InvalidEndpointCount;
    var sender = channel.sender();
    defer sender.deinit();
    const request = try messages.encodeSimpleRequestAlloc(allocator, .{
        .response_size = response_size,
        .request_body_size = request_size,
    });
    defer allocator.free(request);

    try call(sender, request);
    std.debug.print(
        "netz grpc-cpp pick-first phase one complete: transport={s} " ++
            "endpoint=0 client_io=zio-std-io " ++
            "server_io=grpc-cpp-posix-event-engine\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
    try std.Io.sleep(io, .fromSeconds(2), .awake);
    try call(sender, request);
    std.debug.print(
        "netz grpc-cpp pick-first failover complete: transport={s} " ++
            "endpoint_order=0->1 rpcs=2 request_bytes={d} " ++
            "response_bytes={d} certificate_verified={} alpn={s} " ++
            "client_io=zio-std-io server_io=grpc-cpp-posix-event-engine\n",
        .{
            if (tls_enabled) "tls" else "h2c",
            request_size,
            response_size,
            tls_enabled,
            if (tls_enabled) "h2" else "none",
        },
    );
}

fn call(
    sender: netz.grpc.SharedChannelSender,
    request: []const u8,
) !void {
    var response = try sender.unary(.{
        .path = unary_path,
        .message = request,
        .timeout = .{ .value = 20, .unit = .second },
        .wait_for_ready = true,
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
    const value = try std.fmt.parseInt(u16, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

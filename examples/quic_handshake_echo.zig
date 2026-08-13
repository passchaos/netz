const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const original_dcid = [_]u8{ 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78 };
    const client_cid = [_]u8{ 0xc1, 0x1e, 0x48, 0x03 };
    const server_cid = [_]u8{ 0x5e, 0x2e, 0x48, 0x03 };
    const payload = "hello over a real netz QUIC handshake";

    const Shared = struct {
        endpoint: *netz.quic.runtime.Endpoint,
        cid: []const u8,
        expected_payload: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(
                shared.endpoint,
                shared.cid,
                shared.expected_payload,
            ) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(
            endpoint: *netz.quic.runtime.Endpoint,
            cid: []const u8,
            expected_payload: []const u8,
        ) !void {
            var established = try netz.quic.handshake.accept(endpoint, .{
                .local_connection_id = cid,
                .random = [_]u8{0x91} ** 32,
                .x25519_secret_key = [_]u8{0x92} ** 32,
                .max_crypto_buffer = 64 * 1024,
            });
            defer established.deinit();

            var request = try established.connection.receivePacket();
            defer request.deinit(endpoint.allocator);
            try expectSingleStreamPayload(request.frames, 0, expected_payload);

            try established.connection.send(&.{.{ .stream = .{
                .stream_id = 0,
                .offset = 0,
                .data = request.frames[0].stream.data,
                .fin = true,
            } }});
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .cid = &server_cid,
        .expected_payload = payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var established = try netz.quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
            .max_crypto_buffer = 64 * 1024,
        },
    );
    defer established.deinit();

    try established.connection.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = payload,
        .fin = true,
    } }});

    var echoed = try established.connection.receivePacket();
    defer echoed.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try expectSingleStreamPayload(echoed.frames, 0, payload);

    std.debug.print("QUIC handshake echo ok: {s}\n", .{payload});
}

fn expectSingleStreamPayload(
    frames: []const netz.quic.Frame,
    stream_id: u64,
    payload: []const u8,
) !void {
    for (frames) |frame| {
        if (frame != .stream) continue;
        const stream = frame.stream;
        if (stream.stream_id != stream_id) return error.UnexpectedStream;
        if (!std.mem.eql(u8, stream.data, payload)) return error.UnexpectedPayload;
        return;
    }
    return error.UnexpectedFrame;
}

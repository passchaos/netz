const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var server_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer client_endpoint.deinit();

    const keys = netz.quic.protection.deriveAes128Keys(
        [_]u8{0x42} ** netz.quic.protection.secret_len,
    );
    const client_cid = [_]u8{ 0xc1, 0x1e, 0x01, 0x00 };
    const server_cid = [_]u8{ 0x5e, 0x2e, 0x01, 0x00 };

    var client = try netz.quic.one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .initial_send_max_streams_bidi = 1,
        .local_endpoint = .client,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try netz.quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .initial_send_max_streams_bidi = 1,
        .local_endpoint = .server,
        .enable_pacing = false,
    });
    defer server.deinit();

    const payload = "hello over netz QUIC";
    try client.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = payload,
        .fin = false,
    } }});

    var received = try server.receivePacket();
    defer received.deinit(allocator);
    try expectSingleStreamPayload(received.frames, 0, payload);

    try server.send(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = received.frames[0].stream.data,
        .fin = true,
    } }});

    var echoed = try client.receivePacket();
    defer echoed.deinit(allocator);
    try expectSingleStreamPayload(echoed.frames, 0, payload);

    std.debug.print("QUIC echo ok: {s}\n", .{payload});
}

fn expectSingleStreamPayload(
    frames: []const netz.quic.Frame,
    stream_id: u64,
    payload: []const u8,
) !void {
    if (frames.len != 1 or frames[0] != .stream) return error.UnexpectedFrame;
    const stream = frames[0].stream;
    if (stream.stream_id != stream_id) return error.UnexpectedStream;
    if (!std.mem.eql(u8, stream.data, payload)) return error.UnexpectedPayload;
}

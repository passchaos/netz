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
        [_]u8{0xd9} ** netz.quic.protection.secret_len,
    );
    const client_cid = [_]u8{ 0xd6, 0xa7, 0x01, 0x00 };
    const server_cid = [_]u8{ 0xd6, 0xa7, 0x02, 0x00 };

    var client = try netz.quic.one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .peer_max_datagram_frame_size = 1200,
        .local_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer client.deinit();
    var server = try netz.quic.one_rtt.Connection.init(&server_endpoint, .{
        .peer = client_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_endpoint = .server,
        .peer_max_datagram_frame_size = 1200,
        .local_max_datagram_frame_size = 1200,
        .enable_pacing = false,
    });
    defer server.deinit();

    const payload = "hello unreliable datagram";
    try client.sendDatagram(payload);

    var received_packet = try server.receivePacket();
    defer received_packet.deinit(allocator);
    var datagram_buf: [128]u8 = undefined;
    const received = (try server.popDatagram(&datagram_buf)) orelse
        return error.MissingDatagram;
    if (!std.mem.eql(u8, received, payload)) return error.UnexpectedPayload;

    try server.sendDatagram(received);
    var echoed_packet = try client.receivePacket();
    defer echoed_packet.deinit(allocator);
    const echoed = (try client.popDatagram(&datagram_buf)) orelse
        return error.MissingDatagram;
    if (!std.mem.eql(u8, echoed, payload)) return error.UnexpectedPayload;

    std.debug.print("QUIC DATAGRAM echo ok: {s}\n", .{payload});
}

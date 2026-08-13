const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var server_endpoint = try netz.quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 1400 });
    defer server_endpoint.deinit();
    var client_endpoint = try netz.quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 1400 });
    defer client_endpoint.deinit();

    const keys = netz.quic.protection.deriveAes128Keys([_]u8{0xc1} ** netz.quic.protection.secret_len);
    const client_cid = [_]u8{ 0xc1, 0x05, 0xe0, 0x01 };
    const server_cid = [_]u8{ 0xc1, 0x05, 0xe0, 0x02 };

    var client = try netz.quic.one_rtt.Connection.init(&client_endpoint, .{
        .peer = server_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
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
        .enable_pacing = false,
    });
    defer server.deinit();

    try client.closeApplication(42, "example complete");
    var close_packet = try server.receivePacket();
    defer close_packet.deinit(allocator);

    if (!server.draining()) return error.CloseNotObserved;
    if (server.close_info == null or !server.close_info.?.application) return error.CloseNotObserved;
    if (server.close_info.?.error_code != 42) return error.CloseNotObserved;
    if (!std.mem.eql(u8, server.close_info.?.reason_phrase, "example complete")) {
        return error.CloseNotObserved;
    }

    std.debug.print("QUIC application close ok: code={d} reason=\"{s}\"\n", .{
        server.close_info.?.error_code,
        server.close_info.?.reason_phrase,
    });
}

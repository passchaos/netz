const std = @import("std");
const netz = @import("netz");

const client_datagram = "wtransport datagram";
const server_datagram = "netz datagram";
const client_bidi = "wtransport bidi";
const server_bidi = "netz bidi";
const client_uni = "wtransport uni";
const server_uni = "netz uni";
const close_ready = "close ready";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0x77, 0x74, 0x63, 0x6c, 0x69, 0x00, 0x00, 0x01 };
    const client_cid = [_]u8{ 0x77, 0x74, 0x63, 0x6c, 0x69, 0x00, 0x00, 0x02 };

    var client = try netz.webtransport.runtime.HandshakeClientSession.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .ip4 = .loopback(port) },
        .{
            .authority = "127.0.0.1",
            .path = "/interop",
            .limits = .{ .http3 = .{ .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 16,
            } } },
            .h3 = .{
                .handshake = .{
                    .original_destination_connection_id = &original_dcid,
                    .local_connection_id = &client_cid,
                    .server_name = "127.0.0.1",
                    .max_crypto_buffer = 64 * 1024,
                },
                .session = .{
                    .max_stream_buffer = 64 * 1024,
                    .max_stream_frame_data = 1200,
                },
            },
        },
    );
    defer client.deinit();

    try client.sendDatagram(client_datagram);
    var datagram = try client.receiveDatagram();
    defer datagram.deinit(allocator);
    if (!std.mem.eql(u8, datagram.datagram.payload, server_datagram)) {
        return error.UnexpectedDatagram;
    }

    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, client_bidi, true);
    var bidi_response = try client.receiveStream();
    defer bidi_response.deinit();
    if (bidi_response.stream_id != bidi or
        !bidi_response.locally_initiated or
        !std.mem.eql(u8, bidi_response.payload, server_bidi))
    {
        return error.UnexpectedBidirectionalStream;
    }

    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, client_uni, true);
    var uni_response = try client.receiveStream();
    defer uni_response.deinit();
    if (uni_response.direction != .unidirectional or
        uni_response.locally_initiated or
        !std.mem.eql(u8, uni_response.payload, server_uni))
    {
        return error.UnexpectedUnidirectionalStream;
    }

    try client.sendDatagram(close_ready);
    std.debug.print(
        "netz WebTransport client interop passed: CONNECT DATAGRAM bidi uni\n",
        .{},
    );
}

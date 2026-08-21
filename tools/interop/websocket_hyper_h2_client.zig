//! RFC 8441 client for process-boundary interoperability with Hyper's HTTP/2
//! Extended CONNECT and upgraded byte-stream implementation.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var h2 = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_frame_payload = 4096,
            .max_body_bytes = 4096,
            .enable_connect_protocol = true,
        },
    );
    defer h2.close();
    var websocket = try netz.websocket.runtime.H2Client.open(
        allocator,
        &h2,
        .{
            .authority = "localhost",
            .path = "/websocket",
            .scheme = "http",
            .limits = .{
                .max_head_bytes = 4096,
                .max_frame_bytes = 4096,
                .max_message_bytes = 4096,
            },
        },
    );
    defer websocket.close();

    try websocket.sendText("netz websocket h2");
    var response = try websocket.receiveMessage();
    defer response.deinit(allocator);
    if (response.opcode != .text or
        !std.mem.eql(u8, response.payload, "hyper websocket h2"))
    {
        return error.UnexpectedWebSocketMessage;
    }

    try websocket.sendPing("ping");
    var pong = try websocket.receiveFrame();
    defer pong.deinit(allocator);
    if (pong.header.opcode != .pong or
        !std.mem.eql(u8, pong.payload, "ping"))
    {
        return error.UnexpectedPong;
    }

    try websocket.sendClose(.normal_closure, "done");
    var close = (try websocket.receiveCloseFrame()) orelse
        return error.MissingClosePayload;
    defer close.deinit(allocator);
    if (close.code != .normal_closure or
        !std.mem.eql(u8, close.reason, "done"))
    {
        return error.UnexpectedClose;
    }

    std.debug.print(
        "netz RFC 8441 client interoperated with Hyper: text ping pong close\n",
        .{},
    );
}

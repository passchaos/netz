//! Native Channelz admin server for the official grpc-js interop gate.
const std = @import("std");
const netz = @import("netz");
const grpc = netz.grpc;
const channelz = grpc.channelz;

pub fn main(_: std.process.Init) !void {
    var gpa_state: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa_state.deinit();
    const gpa = gpa_state.allocator();
    var backend = try netz.runtime.Backend.initZio(gpa);
    defer backend.deinit();
    const io = backend.io();

    var server = try grpc.runtime.Server.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024 * 1024,
    );
    defer server.deinit();
    var registry = channelz.Registry.init(gpa, io);
    defer registry.deinit();

    const channel = try registry.addChannel("frontend", "dns:///frontend.example");
    channel.setState(.ready);
    channel.callStarted();
    channel.callStarted();
    channel.callSucceeded();
    try channel.addTrace("created", .info);
    try channel.addTrace("ready", .info);

    const subchannel = try registry.addSubchannel("backend-child", "dns:///backend.example");
    subchannel.setState(.ready);
    subchannel.callStarted();
    subchannel.callSucceeded();
    try subchannel.addTrace("created", .info);
    try channel.addSubchannel(subchannel);

    const server_info = try registry.addServer("listener");
    server_info.callStarted();
    server_info.callStarted();
    server_info.callStarted();
    server_info.callSucceeded();
    server_info.callSucceeded();
    server_info.callFailed();
    try server_info.addTrace("listening", .warning);

    const socket = try registry.addSocket(
        "listen",
        .{ .tcpip = server.address() },
        null,
    );
    socket.streamStarted();
    socket.streamSucceeded();
    socket.messageSent();
    socket.messageSent();
    socket.messageReceived();
    socket.messageReceived();
    socket.messageReceived();
    try server_info.addListenSocket(socket);

    std.debug.print("CHANNELZ_PORT {d}\n", .{server.address().getPort()});
    var connection = try server.accept();
    defer connection.deinit();
    var served: usize = 0;
    while (true) {
        var request = connection.readUnary() catch break;
        defer request.deinit();
        if (try channelz.serve(&registry, &connection, &request)) {
            served += 1;
        } else {
            try connection.writeUnary(request.request.stream_id, .{
                .status = .unimplemented,
            });
        }
    }
    std.debug.print("CHANNELZ_SERVED {d}\n", .{served});
}

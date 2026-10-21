const std = @import("std");
const netz = @import("netz");

fn parsePort(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, 10);
}

fn awakeTimeout(duration: std.Io.Duration) std.Io.Timeout {
    return .{ .duration = .{ .raw = duration, .clock = .awake } };
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArgument;
    const proxy_port = try parsePort(args[1]);
    const echo_port = try parsePort(args[2]);
    const relay_port = try parsePort(args[3]);

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var association = try netz.proxy.socks5.associateUdpHostWithDeadline(
        allocator,
        io,
        "127.0.0.1",
        proxy_port,
        .{ .socks5 = .{
            .credentials = .{ .username = "user", .password = "secret" },
            .allow_no_authentication = false,
        } },
        .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
    );
    var closed = false;
    defer if (!closed) association.deinit();
    try std.testing.expectEqual(relay_port, association.relayAddress().getPort());

    var send_storage: [512]u8 = undefined;
    try association.sendTo(
        try .fromHost("echo.internal", echo_port),
        "independent udp payload",
        &send_storage,
    );
    var receive_storage: [512]u8 = undefined;
    try std.testing.expectError(
        error.FragmentationUnsupported,
        association.receiveIntoTimeout(
            &receive_storage,
            awakeTimeout(.fromSeconds(3)),
        ),
    );
    const response = try association.receiveIntoTimeout(
        &receive_storage,
        awakeTimeout(.fromSeconds(3)),
    );
    try std.testing.expectEqual(echo_port, response.source.getPort());
    try std.testing.expectEqualStrings(
        "peer:independent udp payload",
        response.payload,
    );

    association.deinit();
    closed = true;
    std.debug.print(
        "SOCKS5 UDP client passed: command=udp-associate auth=strict " ++
            "remote_dns=true wildcard_reply=true fragments=rejected " ++
            "control_lifetime=true client_io=zio-std-io\n",
        .{},
    );
}

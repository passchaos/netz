//! Ordinary Channel admission against the independent C++ Health Watch.
const std = @import("std");
const netz = @import("netz");

pub fn run(allocator: std.mem.Allocator, io: std.Io, target: netz.grpc.ChannelTarget, resolver: netz.grpc.ChannelAddressResolver, tls: bool) !void {
    var channel = try netz.grpc.Channel.init(allocator, io, target, .{
        .health_check_service = "",
        .address_resolver = resolver,
    });
    defer channel.deinit();
    for (0..2) |_| {
        var response = try channel.unary(.{
            .path = "/grpc.testing.TestService/EmptyCall",
            .message = "",
            .timeout = .{ .value = 10, .unit = .second },
            .wait_for_ready = true,
        });
        defer response.deinit();
        if (response.status != .ok or response.message == null or
            response.message.?.payload.len != 0)
        {
            return error.InvalidOrdinaryHealthResponse;
        }
        if (channel.healthServing() != true or channel.healthServingAt(0) != true) {
            return error.InvalidOrdinaryHealthState;
        }
    }
    std.debug.print("netz grpc-cpp ordinary health gate complete: transport={s} calls=2 serving=true reuse=true\n", .{if (tls) "tls" else "h2c"});
}

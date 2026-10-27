//! Two simultaneous streams against the pinned, independently maintained
//! grpc-cpp FullDuplexCall server. One netz owner alternates response reads.
const std = @import("std");
const netz = @import("netz");
const messages = @import("grpc_cpp_messages.zig");
const path = "/grpc.testing.TestService/FullDuplexCall";
const metadata_name = "x-grpc-test-echo-initial";
const metadata_value = "multiplexed-health-owner";

const Observer = struct {
    sizes: []const u32,
    count: usize = 0,
    head_seen: bool = false,
    terminal_seen: bool = false,

    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        if (self.count >= self.sizes.len or message.was_compressed) return error.InvalidMultiplexedResponse;
        try messages.validateStreamingOutputCallResponse(message.payload, self.sizes[self.count]);
        self.count += 1;
    }

    fn step(self: *@This(), stream: *netz.grpc.ClientDuplex, allocator: std.mem.Allocator) !void {
        const connection = stream.transport.connection;
        const deadline = std.Io.Clock.Timestamp.fromNow(connection.io, .{ .raw = .fromSeconds(10), .clock = .awake });
        var commands_ready: std.Io.Event = .unset;
        var event = while (true) {
            if (try stream.pollResponseEventWithDeadline(deadline, self, consume)) |ready| break ready;
            _ = try connection.pumpClientDuplexWithDeadlineOrWake(deadline, &commands_ready);
        };
        defer event.deinit(allocator);
        switch (event) {
            .initial_metadata => |head| {
                for (head.headers) |field| {
                    if (std.mem.eql(u8, field.name, metadata_name) and std.mem.eql(u8, field.value, metadata_value)) {
                        self.head_seen = true;
                        break;
                    }
                }
            },
            .terminal => |terminal| {
                if (terminal.status != .ok) return error.InvalidMultiplexedStatus;
                self.terminal_seen = true;
            },
            else => {},
        }
    }
};

fn send(allocator: std.mem.Allocator, stream: *netz.grpc.ClientDuplex, size: u32) !void {
    const request = try messages.encodeStreamingOutputCallRequestAlloc(allocator, .{
        .response_size = size,
        .request_body_size = 127,
    });
    defer allocator.free(request);
    if (try stream.writeMessage(request) != .complete) return error.UnexpectedMultiplexedBackpressure;
}

pub fn run(allocator: std.mem.Allocator, connection: *netz.http2.runtime.Connection, message_limit: usize) !void {
    const options: netz.grpc.StreamingRequestOptions = .{
        .path = path,
        .authority = "localhost",
        .metadata = &.{.{ .name = metadata_name, .value = metadata_value }},
        .max_message_size = message_limit,
    };
    var a = try netz.grpc.startDuplex(connection, allocator, options);
    defer a.deinit();
    var b = try netz.grpc.startDuplex(connection, allocator, options);
    defer b.deinit();
    if (connection.activeClientDuplexCount() != 2) return error.InvalidMultiplexedOwnership;
    const a_sizes = [_]u32{65553};
    const b_sizes = [_]u32{ 131101, 33 };
    var ao: Observer = .{ .sizes = &a_sizes };
    var bo: Observer = .{ .sizes = &b_sizes };
    try send(allocator, &a, a_sizes[0]);
    try send(allocator, &b, b_sizes[0]);
    while (bo.count == 0) try bo.step(&b, allocator);
    while (ao.count == 0) try ao.step(&a, allocator);
    try a.cancel();
    if (connection.activeClientDuplexCount() != 1) return error.InvalidMultiplexedOwnership;
    try send(allocator, &b, b_sizes[1]);
    if (try b.finishRequest() != .complete) return error.UnexpectedMultiplexedBackpressure;
    while (!bo.terminal_seen) try bo.step(&b, allocator);
    if (!ao.head_seen or !bo.head_seen or ao.count != 1 or bo.count != 2 or connection.activeClientDuplexCount() != 0) {
        return error.InvalidMultiplexedResponse;
    }
}

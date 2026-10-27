const std = @import("std");
const grpc = @import("netz").grpc;

pub const Session = struct {
    rpc: grpc.SharedClientDuplex,
    writer: grpc.SharedStreamWriter,
    reader: grpc.SharedStreamReader,
    allocator: std.mem.Allocator,
    expected: []const u8,

    pub fn open(sender: grpc.SharedChannelSender, allocator: std.mem.Allocator, expected: []const u8) !Session {
        const rpc = try sender.startDuplex(.{
            .path = "/grpc.testing.EchoTestService/BidiStream",
            .wait_for_ready = true,
            .timeout = .{ .value = 300, .unit = .second },
        });
        return .{ .rpc = rpc, .writer = rpc.writer(), .reader = rpc.reader(), .allocator = allocator, .expected = expected };
    }
    pub fn deinit(self: *Session) void {
        self.reader.deinit();
        self.writer.deinit();
        self.rpc.deinit();
        self.* = undefined;
    }
    pub fn exchange(self: *Session, request: []const u8) !void {
        try self.writer.writeMessage(request);
        while (true) {
            var event = try self.reader.nextWithTimeout(.fromSeconds(10));
            defer event.deinit(self.allocator);
            switch (event) {
                .message => |value| {
                    if (value.was_compressed or !std.mem.eql(u8, value.payload, self.expected)) return error.InvalidBenchmarkResponse;
                    return;
                },
                .terminal => return error.EarlyTerminal,
                else => {},
            }
        }
    }
    pub fn finish(self: *Session) !void {
        try self.writer.finishRequest();
        while (true) {
            var event = try self.reader.nextWithTimeout(.fromSeconds(10));
            defer event.deinit(self.allocator);
            switch (event) {
                .terminal => |value| {
                    if (value.status != .ok) return error.InvalidBenchmarkStatus;
                    return;
                },
                .message => return error.ExtraMessage,
                else => {},
            }
        }
    }
};

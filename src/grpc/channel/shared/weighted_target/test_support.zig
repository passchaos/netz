const std = @import("std");
const grpc = @import("../../../mod.zig");

pub const Peer = struct {
    pub fn run(
        listener: *grpc.runtime.Server,
        stop: *std.Io.Event,
        label: []const u8,
        delay: ?std.Io.Duration,
    ) !void {
        var connection = try listener.acceptWithTimeout(.fromSeconds(5));
        defer connection.deinit();
        while (!stop.isSet()) {
            var request = connection.acceptDuplexWithTimeout(
                .fromMilliseconds(100),
            ) catch |err| switch (err) {
                error.Timeout => continue,
                error.ConnectionClosed,
                error.ConnectionResetByPeer,
                error.SocketUnconnected,
                error.UnexpectedEof,
                => return,
                else => return err,
            };
            defer request.deinit();
            var seen = false;
            const Consumer = struct {
                seen: *bool,
                fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
                    if (self.seen.* or
                        !std.mem.eql(u8, "request", message.payload))
                    {
                        return error.UnexpectedPayload;
                    }
                    self.seen.* = true;
                }
            };
            var consumer = Consumer{ .seen = &seen };
            while (true) {
                var event = try request.readRequestEventWithTimeout(
                    .fromSeconds(3),
                    &consumer,
                    Consumer.consume,
                );
                defer event.deinit();
                switch (event) {
                    .messages => {},
                    .finished => break,
                    .reset => return error.UnexpectedReset,
                }
            }
            if (!seen) return error.UnexpectedPayload;
            if (delay) |duration| {
                try std.Io.sleep(connection.connection.io, duration, .awake);
            }
            try request.startResponse(.{});
            if (try request.writeMessage(label) != .complete) {
                return error.UnexpectedFlowControl;
            }
            try request.finishOk();
        }
    }
};

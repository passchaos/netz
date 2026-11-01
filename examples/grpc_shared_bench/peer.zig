const std = @import("std");
const grpc = @import("netz").grpc;
const Options = @import("options.zig").Options;

pub const Peer = struct {
    server: *grpc.runtime.Server,
    options: Options,
    request: []const u8,
    response: []const u8,
    messages: usize = 0,
    finished_calls: usize = 0,
    final_client_stream_window: u32 = 0,
    final_server_stream_window: u32 = 0,

    const Collector = struct {
        expected: []const u8,
        count: usize = 0,
        limit: usize,
        validate: bool,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            if (self.count == self.limit or message.was_compressed) return error.InvalidBenchmarkRequest;
            if (self.validate and !std.mem.eql(u8, self.expected, message.payload)) return error.InvalidBenchmarkRequest;
            if (!self.validate and message.payload.len != self.expected.len) return error.InvalidBenchmarkRequest;
            self.count += 1;
        }
    };

    pub fn run(self: *Peer) !void {
        var connection = try self.server.acceptWithTimeout(.fromSeconds(10));
        defer connection.deinit();
        defer {
            self.final_client_stream_window = @intCast(connection.connection.peer_initial_stream_window);
            self.final_server_stream_window = connection.connection.recv_stream_window_target;
        }
        for (0..self.options.calls()) |_| {
            var rpc = try connection.acceptDuplexWithTimeout(.fromSeconds(10));
            defer rpc.deinit();
            try rpc.startResponse(.{});
            var collector: Collector = .{
                .expected = self.request,
                .limit = if (self.options.mode == .persistent) self.options.total() else 1,
                .validate = self.options.validate,
            };
            var finished = false;
            var replies: usize = 0;
            while (replies < collector.limit) {
                var event = try rpc.readRequestEventWithTimeout(.fromSeconds(10), &collector, Collector.consume);
                defer event.deinit();
                if (event == .reset or event == .finished) return error.EarlyRequestEnd;
                if (collector.count == replies) continue;
                if (collector.count != replies + 1) return error.UnexpectedBatch;
                var result = try rpc.writeMessage(self.response);
                while (result != .complete) {
                    var ready = try rpc.readRequestEventWithTimeout(.fromSeconds(10), &collector, Collector.consume);
                    defer ready.deinit();
                    if (ready == .reset) return error.UnexpectedReset;
                    if (ready == .finished) finished = true;
                    result = try rpc.resumeMessage();
                }
                replies += 1;
            }
            if (!finished) {
                var event = try rpc.readRequestEventWithTimeout(.fromSeconds(10), &collector, Collector.consume);
                defer event.deinit();
                if (event != .finished) return error.ExpectedRequestEnd;
            }
            try rpc.finishOk();
            self.messages += collector.count;
            self.finished_calls += 1;
        }
        // Drain credit output until the client closes the channel, so TCP
        // teardown cannot discard a final response behind unread updates.
        var end = connection.connection.readResetStreamWithTimeout(.fromSeconds(10)) catch |err| switch (err) {
            error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
            else => return err,
        };
        defer end.deinit(connection.connection.allocator);
        return error.UnexpectedReset;
    }
};

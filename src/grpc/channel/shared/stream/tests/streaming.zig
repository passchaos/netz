const std = @import("std");
const grpc = @import("../../../../mod.zig");
const shared = @import("../../../shared.zig");
const stream = @import("../../stream.zig");
const allocator = std.testing.allocator;
const testing = @import("../testing.zig");
const readReply = testing.readReply;
const readOne = testing.readOne;
const wait = testing.wait;

test "gRPC shared duplex ping pong permits independent reads writes and request FIN" {
    const first_message = "compressed-ping-pong-" ** 32;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        count: usize = 0,
        fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
            try std.testing.expectEqualStrings(if (self.count == 0) first_message else "identity", message.payload);
            try std.testing.expectEqual(self.count == 0, message.was_compressed);
            self.count += 1;
        }
        fn run(self: *@This(), server_ptr: *grpc.runtime.Server) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            {
                var rpc = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
                defer rpc.deinit();
                while (self.count != 2) {
                    const before = self.count;
                    var event = try rpc.readRequestEventWithTimeout(.fromSeconds(5), self, consume);
                    defer event.deinit();
                    if (event == .reset or event == .finished) return error.EarlyEnd;
                    if (self.count == before) continue;
                    if (before == 0) try rpc.startResponse(.{ .compression = .gzip, .request_accepted_encodings = rpc.accepted_encodings });
                    const response = if (before == 0) first_message else "identity";
                    var owned = try rpc.allocMessage(response.len);
                    defer owned.deinit();
                    @memcpy(owned.payload(), response);
                    try std.testing.expectEqual(
                        grpc.stream.WriteResult.complete,
                        try rpc.writeOwnedMessageWithOptions(
                            &owned,
                            .{ .disable_compression = before != 0 },
                        ),
                    );
                    try std.testing.expect(!owned.hasValue());
                }
                var finished = try rpc.readRequestEventWithTimeout(.fromSeconds(5), self, consume);
                defer finished.deinit();
                try std.testing.expect(finished == .finished);
                try rpc.finishOk();
            }
            var reset = connection.connection.readResetStreamWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
                error.ConnectionClosed, error.SocketUnconnected, error.ConnectionResetByPeer, error.UnexpectedEof => return,
                else => return err,
            };
            defer reset.deinit(allocator);
            return error.UnexpectedReset;
        }
    };
    var peer_state: Peer = .{};
    var peer = io.async(Peer.run, .{ &peer_state, &server });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address() } }, .{});
    var live = true;
    defer if (live) client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var rpc = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .compression = .gzip, .timeout = .{ .value = 5, .unit = .second }, .wait_for_ready = true });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    var reader = rpc.reader();
    defer reader.deinit();
    const wrong_clock: std.Io.Clock.Timestamp = .{ .raw = .zero, .clock = .real };
    try std.testing.expectError(error.Timeout, reader.nextWithDeadline(wrong_clock));
    try std.testing.expectError(error.Timeout, writer.writeMessageWithDeadline("invalid-clock", wrong_clock));
    var invalid_owned = try writer.allocMessage("invalid-owned".len);
    defer invalid_owned.deinit();
    @memcpy(invalid_owned.payload(), "invalid-owned");
    try std.testing.expectError(
        error.Timeout,
        writer.writeOwnedMessageWithDeadline(&invalid_owned, wrong_clock),
    );
    try std.testing.expect(!invalid_owned.hasValue());
    try std.testing.expectError(error.Timeout, writer.finishRequestWithDeadline(wrong_clock));
    try std.testing.expectError(error.Timeout, reader.nextWithTimeout(.fromMilliseconds(10)));
    var first_owned = try writer.allocMessage(first_message.len);
    defer first_owned.deinit();
    @memcpy(first_owned.payload(), first_message);
    try writer.writeOwnedMessage(&first_owned);
    try std.testing.expect(!first_owned.hasValue());
    try readOne(reader, first_message, true);
    var identity_owned = try writer.allocMessage("identity".len);
    defer identity_owned.deinit();
    @memcpy(identity_owned.payload(), "identity");
    try writer.writeOwnedMessageWithOptions(
        &identity_owned,
        .{ .disable_compression = true },
    );
    try std.testing.expect(!identity_owned.hasValue());
    try readOne(reader, "identity", false);
    try writer.finishRequest();
    var terminal = try reader.nextWithTimeout(.fromSeconds(5));
    defer terminal.deinit(allocator);
    try std.testing.expect(terminal == .terminal);
    try std.testing.expectEqual(grpc.Status.ok, terminal.terminal.status);
    client.deinit();
    live = false;
    try peer.await(io);
}

test "gRPC shared duplex blocked write deadline cancels and preserves Timeout" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .initial_window_size = 0 }, 4096);
    defer server.deinit();
    var accepted: std.Io.Event = .unset;
    const Peer = struct {
        fn unexpected(_: void, _: grpc.StreamingMessage) !void {
            return error.UnexpectedMessage;
        }
        fn run(server_ptr: *grpc.runtime.Server, signal: *std.Io.Event) !void {
            var connection = try server_ptr.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            var rpc = try connection.acceptDuplexWithTimeout(.fromSeconds(5));
            defer rpc.deinit();
            signal.set(connection.connection.io);
            var event = try rpc.readRequestEventWithTimeout(.fromSeconds(5), {}, unexpected);
            defer event.deinit();
            try std.testing.expect(event == .reset);
            try std.testing.expectEqual(@import("../../../../../http2/mod.zig").ErrorCode.cancel, event.reset.error_code);
        }
    };
    var peer = io.async(Peer.run, .{ &server, &accepted });
    defer _ = peer.cancel(io) catch {};
    var client = try shared.SharedChannel.init(allocator, io, .{ .cleartext_ip = .{ .address = server.address(), .limits = .{ .terminal_cleanup_timeout = .fromSeconds(1) } } }, .{});
    defer client.deinit();
    var sender = client.sender();
    defer sender.deinit();
    var rpc = try sender.startDuplex(.{ .path = "/demo.Shared/Bidi", .wait_for_ready = true });
    defer rpc.deinit();
    var writer = rpc.writer();
    defer writer.deinit();
    var reader = rpc.reader();
    defer reader.deinit();
    try wait(&accepted, io);
    try std.testing.expectError(error.Timeout, writer.writeMessageWithTimeout("cannot-send", .fromMilliseconds(10)));
    try std.testing.expectError(error.Timeout, reader.next());
    try peer.await(io);
}

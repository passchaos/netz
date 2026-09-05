const std = @import("std");
const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const whole = @import("../stream.zig");
const incremental = @import("../stream_incremental.zig");

const first_page_streams: usize = 256;
const target_stream_id: u62 = 4;

const Fixture = struct {
    allocator: std.mem.Allocator,
    receiver: *quic.runtime.Endpoint,
    sender: *quic.runtime.Endpoint,
    connection: *quic.one_rtt.Connection,
    registry: webtransport.StreamRegistry,

    fn init(allocator: std.mem.Allocator, io: std.Io) !Fixture {
        const receiver = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(receiver);
        receiver.* = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        errdefer receiver.deinit();
        const sender = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(sender);
        sender.* = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .max_datagram_size = 4096 },
        );
        errdefer sender.deinit();
        const keys = quic.protection.deriveAes128Keys(
            [_]u8{0xb1} ** quic.protection.secret_len,
        );
        const connection = try allocator.create(quic.one_rtt.Connection);
        errdefer allocator.destroy(connection);
        connection.* = try quic.one_rtt.Connection.init(receiver, .{
            .peer = sender.address(),
            .receive_keys = keys,
            .send_keys = keys,
            .local_connection_id = "page-server",
            .peer_connection_id = "page-client",
            .local_endpoint = .server,
            .initial_receive_max_streams_uni = first_page_streams,
            .initial_receive_max_streams_bidi = 2,
            .enable_pacing = false,
        });
        errdefer connection.deinit();
        var registry = try webtransport.StreamRegistry.init(
            allocator,
            .init(0),
            .server,
            .{
                .max_peer_bidi = 2,
                .max_peer_uni = first_page_streams,
            },
        );
        errdefer registry.deinit();
        return .{
            .allocator = allocator,
            .receiver = receiver,
            .sender = sender,
            .connection = connection,
            .registry = registry,
        };
    }

    fn deinit(self: *Fixture) void {
        self.registry.deinit();
        self.connection.deinit();
        self.allocator.destroy(self.connection);
        self.sender.deinit();
        self.allocator.destroy(self.sender);
        self.receiver.deinit();
        self.allocator.destroy(self.receiver);
        self.* = undefined;
    }

    fn populate(self: *Fixture, payload: []const u8) !void {
        for (0..first_page_streams) |index| {
            const stream_id: u62 = @intCast(2 + index * 4);
            try quic.one_rtt.testing.applyReceivedFrames(
                self.connection,
                @intCast(index),
                &.{.{ .stream = .{
                    .stream_id = stream_id,
                    .data = &.{0},
                    .fin = true,
                } }},
                null,
                .not_ect,
            );
        }
        var associated: std.ArrayList(u8) = .empty;
        defer associated.deinit(self.receiver.allocator);
        try webtransport.BidirectionalStreamHeader.write(
            &associated,
            self.receiver.allocator,
            .init(0),
        );
        try associated.appendSlice(self.receiver.allocator, payload);
        try quic.one_rtt.testing.applyReceivedFrames(
            self.connection,
            first_page_streams,
            &.{.{ .stream = .{
                .stream_id = target_stream_id,
                .data = associated.items,
                .fin = true,
            } }},
            null,
            .not_ect,
        );
    }
};

test "WebTransport whole-stream poll reaches the second receive-ID page" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(allocator, threaded.io());
    defer fixture.deinit();
    try fixture.populate("whole-page-two");

    var stream = (try whole.poll(
        fixture.connection,
        &fixture.registry,
        .init(0),
        1024,
    )) orelse return error.TestUnexpectedResult;
    defer stream.deinit();
    try std.testing.expectEqual(target_stream_id, stream.stream_id);
    try std.testing.expectEqualStrings("whole-page-two", stream.payload);
    try std.testing.expect(stream.fin);
}

test "WebTransport incremental stale cursor wraps into second ID page" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(allocator, threaded.io());
    defer fixture.deinit();
    try fixture.populate("incremental-page-two");
    fixture.registry.incremental_poll_cursor = 4092;

    var storage: [64]u8 = undefined;
    const event = (try incremental.poll(
        fixture.connection,
        &fixture.registry,
        .init(0),
        &storage,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expect(event == .data);
    try std.testing.expectEqual(target_stream_id, event.data.stream_id);
    try std.testing.expectEqualStrings(
        "incremental-page-two",
        storage[0..event.data.bytes],
    );
    try std.testing.expect(event.data.fin);
}

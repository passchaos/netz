//! A blocking receive cannot wait on a stream with no receive direction.
const std = @import("std");
const quic = @import("../../mod.zig");
const Backend = @import("../../../runtime.zig").Backend;

const Mode = enum { ordinary, timeout, deadline };

fn receive(connection: *quic.one_rtt.Connection, mode: Mode, id: u62, output: []u8) !void {
    switch (mode) {
        .ordinary => _ = try connection.receiveStreamId(id, output),
        .timeout => _ = try connection.receiveStreamIdWithTimeout(id, output, .fromMilliseconds(20)),
        .deadline => _ = try connection.receiveStreamIdWithDeadline(id, output, .fromNow(connection.endpoint.io, .{ .clock = .awake, .raw = .fromMilliseconds(20) })),
    }
}

fn withinBudget(io: std.Io, connection: *quic.one_rtt.Connection, mode: Mode, id: u62, output: []u8) !void {
    const Wake = union(enum) { done: anyerror!void, expired: std.Io.Cancelable!void };
    var storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &storage);
    defer select.cancelDiscard();
    try select.concurrent(.done, receive, .{ connection, mode, id, output });
    try select.concurrent(.expired, std.Io.sleep, .{ io, std.Io.Duration.fromMilliseconds(100), std.Io.Clock.awake });
    switch (try select.await()) {
        .done => |result| try result,
        .expired => |result| {
            try result;
            return error.TestUnexpectedResult;
        },
    }
}

test "QUIC stream receive target admission rejects local unidirectional waits" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    inline for (.{ .client, .server }) |role| {
        for (std.enums.values(Mode)) |mode| {
            var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, backend.io(), .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
            defer endpoint.deinit();
            const keys = quic.protection.deriveAes128Keys([_]u8{0x8b} ** quic.protection.secret_len);
            var connection = try quic.one_rtt.Connection.init(&endpoint, .{
                .peer = endpoint.address(),
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = "read-target",
                .peer_connection_id = "read-target",
                .local_endpoint = role,
                .enable_pacing = false,
            });
            defer connection.deinit();
            const id = try connection.openUnidirectionalStream();
            var output: [16]u8 = @splat(0xaa);
            // The query remains nullable; blocking receive rejects the target.
            try std.testing.expect((try connection.pollStreamId(@intCast(id), &output)) == null);
            try std.testing.expectError(error.StreamStateError, withinBudget(backend.io(), &connection, mode, @intCast(id), &output));
            try std.testing.expectEqualSlices(u8, &([_]u8{0xaa} ** 16), &output);
            try std.testing.expect(connection.sendStreamStats(id) == null);
        }
    }
}

const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");

const allocator = std.testing.allocator;

const Fixture = struct {
    io: std.Io,
    listener: std.Io.net.Server,
    client: std.Io.net.Stream,
    connection: runtime.Connection,

    fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{
            .ip4 = .loopback(0),
        }).listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const client = try listener.socket.address.connect(
            io,
            .{ .mode = .stream },
        );
        errdefer client.close(io);
        const accepted = try listener.accept(io);
        return .{
            .io = io,
            .listener = listener,
            .client = client,
            .connection = .{
                .io = io,
                .allocator = allocator,
                .stream = accepted,
                .role = .server,
            },
        };
    }

    fn deinit(self: *Fixture) void {
        self.connection.close();
        self.client.close(self.io);
        self.listener.deinit(self.io);
    }

    fn frame(
        self: *Fixture,
        kind: http2.FrameType,
        flags: u8,
        id: u31,
        bytes: []const u8,
    ) !void {
        try wire.appendFrame(
            &self.connection.frame_reader.buffer,
            allocator,
            kind,
            flags,
            id,
            bytes,
        );
    }

    fn requestHeaders(
        self: *Fixture,
        encoder: *http2.Hpack.Encoder,
        id: u31,
        path: []const u8,
    ) !void {
        const block = try encoder.encodeBlockRetained(allocator, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":path", .value = path },
            .{ .name = ":authority", .value = "localhost" },
        });
        try self.frame(.headers, 4, id, block);
    }
};

test "HTTP/2 server duplex handles coexist under one frame reader" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();

    const peer = fixture.connection.peerAddress();
    try std.testing.expect(peer.getPort() != 0);
    try std.testing.expect(
        peer.getPort() != fixture.listener.socket.address.getPort(),
    );

    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.requestHeaders(&encoder, 1, "/first");
    var first = try fixture.connection.acceptDuplexRequest();
    defer first.deinit();
    try std.testing.expect((try first.pollRequestEvent()) == null);

    // Reading stream 1 encounters and retains stream 3 first. Accepting the
    // second handle must reuse that predecoded HPACK state rather than create
    // another transport reader or decode the header block twice.
    try fixture.requestHeaders(&encoder, 3, "/second");
    try fixture.frame(.data, 0, 3, "b");
    try fixture.frame(.data, 0, 1, "a");
    var first_data = try first.readRequestEvent();
    defer first_data.deinit(allocator);
    try std.testing.expectEqualStrings("a", first_data.data.data);

    var second = try fixture.connection.acceptDuplexRequest();
    defer second.deinit();
    try std.testing.expectEqualStrings("/second", second.path);
    try std.testing.expectEqual(
        @as(usize, 2),
        fixture.connection.activeServerDuplexCount(),
    );
    var second_data = (try second.pollRequestEvent()).?;
    defer second_data.deinit(allocator);
    try std.testing.expectEqualStrings("b", second_data.data.data);

    try first.finishResponseHeaders(.{ .status = 200 });
    try second.finishResponseHeaders(.{ .status = 200 });
    try fixture.frame(.data, 1, 1, "");
    try fixture.frame(.data, 1, 3, "");
    var first_finished = try first.readRequestEvent();
    defer first_finished.deinit(allocator);
    try std.testing.expect(first_finished == .finished);
    try std.testing.expectEqual(
        @as(usize, 1),
        fixture.connection.activeServerDuplexCount(),
    );
    var second_finished = try second.readRequestEvent();
    defer second_finished.deinit(allocator);
    try std.testing.expect(second_finished == .finished);
    try std.testing.expectEqual(
        @as(usize, 0),
        fixture.connection.activeServerDuplexCount(),
    );
    try std.testing.expect(!fixture.connection.duplex_reader_active);
}

test "HTTP/2 server duplex nextBody pulls DATA and trailers" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var fixture = try Fixture.init(threaded.io());
    defer fixture.deinit();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.requestHeaders(&encoder, 1, "/body");
    var stream = try fixture.connection.acceptDuplexRequest();
    defer stream.deinit();
    try fixture.frame(.data, 0, 1, "a");
    try fixture.frame(.data, 0, 1, "b");
    var decoder = try stream.streamContentDecoder(allocator, .{ .max_encoded_bytes = 16, .max_decoded_bytes = 16 });
    defer decoder.deinit();
    var output: [16]u8 = undefined;
    var written: usize = 0;
    const first = (try stream.nextBody()).?;
    written += (try decoder.step(first, output[written..])).output_written;
    const second = (try stream.nextBody()).?;
    written += (try decoder.step(second, output[written..])).output_written;
    const finished = try decoder.finish(output[written..]);
    written += finished.output_written;
    try std.testing.expectEqualStrings("ab", output[0..written]);
    const trailers = try encoder.encodeBlockRetained(allocator, &.{.{ .name = "x-trailer", .value = "1" }});
    try fixture.frame(.headers, 5, 1, trailers);
    try std.testing.expect((try stream.nextBody()) == null);
    try std.testing.expectEqual(@as(usize, 1), stream.requestTrailers().?.len);
    try std.testing.expectEqualStrings("x-trailer", stream.requestTrailers().?[0].name);
    try stream.finishResponseHeaders(.{ .status = 200 });
}

test "HTTP/2 server duplex pump races command wake and routes streams" {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    var wake: std.Io.Event = .unset;
    wake.set(io);
    try std.testing.expect((try fixture.connection.pumpServerUntilOrWake(null, .fromSeconds(1), &wake)) == .wake);
    wake.reset();
    var encoder: http2.Hpack.Encoder = .{};
    defer encoder.deinit(allocator);
    try fixture.requestHeaders(&encoder, 1, "/pumped");
    var request_event = try fixture.connection.pumpServerUntilOrWake(null, .fromSeconds(1), &wake);
    var request = request_event.request;
    request_event = undefined;
    defer request.deinit();
    try std.testing.expectEqualStrings("/pumped", request.path);
    try fixture.frame(.data, 1, 1, "payload");
    const routed = try fixture.connection.pumpServerUntilOrWake(null, .fromSeconds(1), &wake);
    try std.testing.expectEqual(@as(u31, 1), routed.stream);
    var data = (try request.pollRequestEvent()).?;
    defer data.deinit(allocator);
    try std.testing.expectEqualStrings("payload", data.data.data);
}

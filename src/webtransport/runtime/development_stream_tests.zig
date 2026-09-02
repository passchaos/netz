const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");

fn futureDeadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{
        .raw = .fromSeconds(2),
        .clock = .awake,
    });
}

test "WebTransport development streams preserve prefixes reverse path and limits" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .http3 = .{
                // Splits both association prefixes and payloads across
                // datagrams, exercising retained side-channel reassembly.
                .max_stream_frame_data = 1,
                .quic = .{
                    .max_datagram_size = 4096,
                    .max_frames_per_datagram = 8,
                },
            },
            .max_session_streams = 1,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        io: std.Io,
        streams_released: *std.atomic.Value(bool),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var session = try self.server.acceptWithDeadline(
                futureDeadline(self.io),
            );
            var session_owned = true;
            defer if (session_owned) session.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            var bidi = try session.receiveStreamWithDeadline(
                futureDeadline(self.io),
            );
            defer bidi.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.bidirectional,
                bidi.direction,
            );
            try std.testing.expect(!bidi.locally_initiated);
            try std.testing.expect(bidi.from.eql(&session.remoteAddress()));
            try std.testing.expectEqualStrings("client bidi", bidi.payload);
            try session.sendStream(bidi.stream_id, "reverse", true);

            var uni = try session.receiveStreamWithDeadline(
                futureDeadline(self.io),
            );
            defer uni.deinit();
            try std.testing.expectEqual(
                webtransport.StreamDirection.unidirectional,
                uni.direction,
            );
            try std.testing.expectEqualStrings("client uni", uni.payload);

            const server_bidi = try session.openBidirectionalStream();
            try session.sendStream(server_bidi, "server bidi", true);
            var server_reverse = try session.receiveStreamWithDeadline(
                futureDeadline(self.io),
            );
            defer server_reverse.deinit();
            try std.testing.expectEqual(server_bidi, server_reverse.stream_id);
            try std.testing.expect(server_reverse.locally_initiated);
            try std.testing.expectEqualStrings(
                "client reverse",
                server_reverse.payload,
            );

            const server_uni = try session.openUnidirectionalStream();
            try session.sendStream(server_uni, "server uni", true);
            const counts = self.server.h3.developmentStreamDebugCounts(
                session.remoteAddress(),
                session.sessionId().value,
            );
            try std.testing.expect(counts.sends >= 3);
            const peer = session.remoteAddress();
            const session_id = session.sessionId().value;
            session.deinit(
                self.server.h3.quic_server.endpoint.allocator,
            );
            session_owned = false;
            const released = self.server.h3.developmentStreamDebugCounts(
                peer,
                session_id,
            );
            try std.testing.expectEqual(@as(usize, 0), released.receives);
            try std.testing.expectEqual(@as(usize, 0), released.sends);
            self.streams_released.store(true, .release);
            return;
        }
    };

    var streams_released = std.atomic.Value(bool).init(false);
    var shared = Shared{
        .server = &server,
        .io = io,
        .streams_released = &streams_released,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.ClientSession.connectWithDeadline(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .authority = "localhost",
            .path = "/development-streams",
            .limits = .{
                .http3 = .{
                    .max_stream_frame_data = 1,
                    .quic = .{
                        .max_datagram_size = 4096,
                        .max_frames_per_datagram = 8,
                    },
                },
                .max_session_streams = 1,
            },
        },
        futureDeadline(io),
    );
    defer client.deinit();

    const bidi = try client.openBidirectionalStream();
    try client.sendStream(bidi, "client bidi", true);
    const uni = try client.openUnidirectionalStream();
    try client.sendStream(uni, "client uni", true);
    try std.testing.expectError(
        error.StreamLimitExceeded,
        client.openBidirectionalStream(),
    );

    var reverse = try client.receiveStreamWithDeadline(futureDeadline(io));
    defer reverse.deinit();
    try std.testing.expectEqual(bidi, reverse.stream_id);
    try std.testing.expect(reverse.locally_initiated);
    try std.testing.expectEqualStrings("reverse", reverse.payload);

    var server_bidi = try client.receiveStreamWithDeadline(futureDeadline(io));
    defer server_bidi.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.bidirectional,
        server_bidi.direction,
    );
    try std.testing.expect(!server_bidi.locally_initiated);
    try std.testing.expectEqualStrings("server bidi", server_bidi.payload);
    try client.sendStream(server_bidi.stream_id, "client reverse", true);

    var server_uni = try client.receiveStreamWithDeadline(futureDeadline(io));
    defer server_uni.deinit();
    try std.testing.expectEqual(
        webtransport.StreamDirection.unidirectional,
        server_uni.direction,
    );
    try std.testing.expectEqualStrings("server uni", server_uni.payload);

    // Every blocking operation above is deadline-bounded, so join cannot hide
    // a peer failure behind an indefinitely sleeping socket receive.
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(streams_released.load(.acquire));
}

test "WebTransport development peer churn reclaims cursor and partial prefix" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const limits: runtime.Limits = .{
        .http3 = .{
            // One peer cursor and one incomplete extension receive are enough
            // to prove that retirement, rather than historical churn, bounds
            // both tables.
            .max_concurrent_request_streams = 1,
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
        },
        .max_session_streams = 1,
    };
    var server = try runtime.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        io: std.Io,
        session_ready: std.Io.Event = .unset,
        release_session: std.Io.Event = .unset,
        peer_ports: [3]u16 = undefined,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..3) |generation| {
                var session = try self.server.acceptWithDeadline(
                    futureDeadline(self.io),
                );
                var owned = true;
                defer if (owned) session.deinit(
                    self.server.h3.quic_server.endpoint.allocator,
                );
                const opened = try session.openBidirectionalStream();
                try std.testing.expectEqual(@as(u62, 1), opened);
                self.session_ready.set(self.io);
                try self.release_session.wait(self.io);
                const peer = session.remoteAddress();
                const session_id = session.sessionId().value;
                self.peer_ports[generation] = switch (peer) {
                    .ip4 => |address| address.port,
                    .ip6 => |address| address.port,
                };
                session.deinit(
                    self.server.h3.quic_server.endpoint.allocator,
                );
                owned = false;
                const released = self.server.h3.developmentStreamDebugCounts(
                    peer,
                    session_id,
                );
                try std.testing.expectEqual(@as(usize, 0), released.receives);
                try std.testing.expectEqual(@as(usize, 0), released.sends);
                self.session_ready.reset();
                self.release_session.reset();
            }
        }
    };
    var shared = Shared{ .server = &server, .io = io };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for (0..3) |generation| {
        var client = try runtime.ClientSession.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            server.address(),
            .{
                .authority = "localhost",
                .path = switch (generation) {
                    0 => "/churn-one",
                    1 => "/churn-two",
                    else => "/churn-three",
                },
                .limits = limits,
            },
            futureDeadline(io),
        );
        if (generation == 0) {
            try shared.session_ready.wait(io);
            // A peer-started uni stream begins with 0x54 and then its Session
            // ID. Send only the first byte of the two-byte stream-type varint:
            // session-targeted cleanup cannot attribute this receive entry.
            try client.h3.quic_client.sendFrames(&.{.{ .stream = .{
                .stream_id = 14,
                .offset = 0,
                .data = &.{0x40},
                .fin = false,
            } }});
            // Pump the packet into server-owned reassembly before deinit sends
            // the CONNECT cancellation that definitively retires the peer.
            try std.testing.expectError(
                error.Timeout,
                server.receiveSessionRequestWithTimeout(
                    .fromMilliseconds(20),
                ),
            );
        }
        shared.release_session.set(io);
        client.deinit();
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.peer_ports[0] != shared.peer_ports[1]);
    try std.testing.expect(shared.peer_ports[0] != shared.peer_ports[2]);
    try std.testing.expect(shared.peer_ports[1] != shared.peer_ports[2]);
}

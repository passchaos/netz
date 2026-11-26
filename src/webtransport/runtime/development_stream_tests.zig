const std = @import("std");
const webtransport = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const http3 = @import("../../http3/mod.zig");

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
            var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
            try session.sendStreamWithTimeout(
                bidi.stream_id,
                "reverse",
                true,
                &progress,
                .fromSeconds(1),
            );
            try std.testing.expect(progress.completed);

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
            try std.testing.expectError(
                error.Timeout,
                session.sendStreamWithDeadline(
                    server_bidi,
                    "server bidi",
                    true,
                    &progress,
                    .{ .clock = .real, .raw = .zero },
                ),
            );
            try std.testing.expect(!progress.send_attempted);
            try std.testing.expect(!progress.completed);
            const server_bidi_state = session.streams.get(server_bidi).?;
            try std.testing.expect(!server_bidi_state.prefix_sent);
            try std.testing.expectEqual(
                @as(u64, 0),
                server_bidi_state.bytes_sent,
            );
            try session.sendStreamSlicesWithDeadline(
                server_bidi,
                &.{ "server ", "bidi" },
                true,
                &progress,
                futureDeadline(self.io),
            );
            try std.testing.expect(progress.completed);
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
            try session.sendStreamSlicesWithTimeout(
                server_uni,
                &.{ "server ", "u" },
                false,
                &progress,
                .fromSeconds(1),
            );
            try std.testing.expect(progress.completed);
            // The second send takes the non-prefix path; the trailing empty
            // slice still carries FIN.
            try session.sendStreamSlicesWithTimeout(
                server_uni,
                &.{ "ni", "" },
                true,
                &progress,
                .fromSeconds(1),
            );
            try std.testing.expect(progress.completed);
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
    var progress: http3.runtime.DevelopmentBodyWriteProgress = .{};
    try std.testing.expectError(
        error.Timeout,
        client.sendStreamWithDeadline(
            bidi,
            "client bidi",
            true,
            &progress,
            .{ .clock = .real, .raw = .zero },
        ),
    );
    try std.testing.expect(!progress.send_attempted);
    try std.testing.expect(!progress.completed);
    const bidi_state = client.streams.get(bidi).?;
    try std.testing.expect(!bidi_state.prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), bidi_state.bytes_sent);
    try client.sendStreamWithTimeout(
        bidi,
        "client bidi",
        true,
        &progress,
        .fromSeconds(1),
    );
    try std.testing.expect(progress.completed);
    const uni = try client.openUnidirectionalStream();
    try client.sendStreamWithDeadline(
        uni,
        "client uni",
        true,
        &progress,
        futureDeadline(io),
    );
    try std.testing.expect(progress.completed);
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
    try client.sendStreamWithTimeout(
        server_bidi.stream_id,
        "client reverse",
        true,
        &progress,
        .fromSeconds(1),
    );
    try std.testing.expect(progress.completed);

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

comptime {
    _ = @import("development_stream/deadline_tests.zig");
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
        session_ready: [3]std.Io.Event = @splat(.unset),
        release_session: [3]std.Io.Event = @splat(.unset),
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
                self.session_ready[generation].set(self.io);
                try self.release_session[generation].wait(self.io);
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
                try std.testing.expectEqual(
                    @as(usize, 0),
                    released.peer_receives,
                );
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
        try shared.session_ready[generation].wait(io);
        if (generation == 0) {
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
        shared.release_session[generation].set(io);
        client.deinit();
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expect(shared.peer_ports[0] != shared.peer_ports[1]);
    try std.testing.expect(shared.peer_ports[0] != shared.peer_ports[2]);
    try std.testing.expect(shared.peer_ports[1] != shared.peer_ports[2]);
}

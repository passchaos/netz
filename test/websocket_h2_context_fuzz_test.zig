//! Bounded context-takeover fuzzing over real RFC 8441 WebSocket streams.

const std = @import("std");
const netz = @import("netz");
const support = @import("websocket_live_context_support.zig");

const http2 = netz.http2.runtime;
const websocket = netz.websocket.runtime;

test "structured live HTTP2 context-takeover sequences cover runtime APIs" {
    try support.requireApiMatrix(try runSequence(
        support.api_matrix_seed[4..],
    ));
    const repeated = try runSequence(support.repeated_history_seed[4..]);
    try std.testing.expect(repeated.messages >= 8);
}

test "fuzz live HTTP2 WebSocket context takeover" {
    try std.testing.fuzz({}, fuzzContextTakeover, .{
        .corpus = support.corpus,
    });
}

test "bounded deterministic live HTTP2 context-takeover mutation smoke" {
    var mutated: [support.max_sequence_bytes]u8 = undefined;
    inline for (support.corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (0..seed.len + 1) |length| {
            _ = try runSequence(seed[0..length]);
        }
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [support.max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x77325f6374785f66);
    const random = prng.random();
    for (0..8) |_| {
        const length = random.uintLessThan(
            usize,
            support.max_sequence_bytes + 1,
        );
        random.bytes(random_bytes[0..length]);
        _ = try runSequence(random_bytes[0..length]);
    }
}

fn fuzzContextTakeover(_: void, smith: *std.testing.Smith) !void {
    var storage: [support.max_sequence_bytes]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    _ = try runSequence(bytes);
}

fn runSequence(bytes: []const u8) !support.Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    const h2_limits: http2.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 16 * 1024,
        .initial_window_size = 16 * 1024,
        .initial_connection_window_size = 65_535,
        .enable_connect_protocol = true,
    };
    var server = try http2.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        h2_limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *http2.Server,
        bytes: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var h2 = try self.server.accept();
            defer h2.close();
            var connection = try websocket.H2Server.accept(
                self.server.allocator,
                &h2,
                .{
                    .enable_permessage_deflate = true,
                    .allow_context_takeover = true,
                    .compression_threshold = 0,
                    .limits = .{
                        .max_head_bytes = 4096,
                        .max_frame_bytes = 2048,
                        .max_message_bytes = support.max_message_bytes,
                    },
                },
            );
            defer connection.close();
            try support.runServer(
                self.server.allocator,
                &connection,
                self.bytes,
            );
        }
    };

    var shared = Shared{ .server = &server, .bytes = bytes };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var h2_client = try http2.Client.connect(
        allocator,
        io,
        server.address(),
        h2_limits,
    );
    defer h2_client.close();
    var client = try websocket.H2Client.open(allocator, &h2_client, .{
        .authority = "localhost",
        .path = "/fuzz-context-takeover",
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
        .compression_threshold = 0,
        .limits = .{
            .max_head_bytes = 4096,
            .max_frame_bytes = 2048,
            .max_message_bytes = support.max_message_bytes,
        },
    });
    defer client.close();
    const summary = try support.runClient(allocator, &client, bytes);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    return summary;
}

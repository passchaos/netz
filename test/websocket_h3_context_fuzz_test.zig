//! Bounded context-takeover fuzzing over authenticated RFC 9220 sessions.

const std = @import("std");
const netz = @import("netz");
const support = @import("websocket_live_context_support.zig");

const http3 = netz.http3.runtime;
const websocket = netz.websocket.runtime.h3;

test "structured live HTTP3 context-takeover sequences cover runtime APIs" {
    try support.requireApiMatrix(try runSequence(
        support.api_matrix_seed[4..],
    ));
    const repeated = try runSequence(support.repeated_history_seed[4..]);
    try std.testing.expect(repeated.messages >= 8);
}

test "fuzz live HTTP3 WebSocket context takeover" {
    try std.testing.fuzz({}, fuzzContextTakeover, .{
        .corpus = support.corpus,
    });
}

test "bounded deterministic live HTTP3 context-takeover mutation smoke" {
    var mutated: [support.max_sequence_bytes]u8 = undefined;
    inline for (support.corpus) |seed_with_prefix| {
        const seed = seed_with_prefix[4..];
        for (seed, 0..) |_, index| {
            @memcpy(mutated[0..seed.len], seed);
            mutated[index] ^= 0xff;
            _ = try runSequence(mutated[0..seed.len]);
        }
    }

    var random_bytes: [support.max_sequence_bytes]u8 = undefined;
    var prng = std.Random.DefaultPrng.init(0x77335f6374785f66);
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
    const original_dcid =
        [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3 };
    const server_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3 };
    const limits: http3.Limits = .{ .quic = .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    } };
    var server = try websocket.Server.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc4} ** 32,
                .x25519_secret_key = [_]u8{0xc5} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 256,
                .max_frames_per_packet = 8,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *websocket.Server,
        allocator: std.mem.Allocator,
        bytes: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept(.{
                .enable_permessage_deflate = true,
                .allow_context_takeover = true,
                .compression_threshold = 0,
                .limits = .{
                    .max_frame_bytes = 2048,
                    .max_message_bytes = support.max_message_bytes,
                },
            });
            defer connection.deinit();
            try support.runServer(
                self.allocator,
                &connection,
                self.bytes,
            );
        }
    };

    var shared = Shared{
        .server = &server,
        .allocator = allocator,
        .bytes = bytes,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try websocket.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        limits,
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc2} ** 32,
                .x25519_secret_key = [_]u8{0xc3} ** 32,
            },
            .session = .{
                .max_stream_frame_data = 256,
                .max_frames_per_packet = 8,
            },
        },
        .{
            .authority = "localhost",
            .path = "/fuzz-context-takeover",
            .enable_permessage_deflate = true,
            .allow_context_takeover = true,
            .compression_threshold = 0,
            .limits = .{
                .max_frame_bytes = 2048,
                .max_message_bytes = support.max_message_bytes,
            },
        },
    );
    defer client.deinit();
    const summary = try support.runClient(allocator, &client, bytes);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    return summary;
}

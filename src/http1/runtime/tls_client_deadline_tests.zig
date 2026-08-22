const std = @import("std");
const http1_runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;

test "standard TLS client deadline preserves buffered plaintext" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const first_record = "buffered plaintext";
    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        certificate: *const [tls_testing.certificate_der_len]u8,
        key_pair: @TypeOf(key_pair),
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const stream = try shared.listener.accept(shared.io);
            var stream_owned = true;
            errdefer if (stream_owned) stream.close(shared.io);
            const connection = try tls_stream.ServerConnection.init(
                allocator,
                shared.io,
                stream,
                .{ .identity = .{
                    .certificate_chain = &.{shared.certificate},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = shared.key_pair,
                    } },
                } },
            );
            stream_owned = false;
            defer connection.deinit();
            try connection.writeAll(first_record);
            try std.Io.sleep(
                shared.io,
                .fromMilliseconds(400),
                .awake,
            );
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
        .certificate = &certificate_der,
        .key_pair = key_pair,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const connection = try http1_runtime.TlsClientConnection.init(
        allocator,
        io,
        stream,
        "localhost",
        .{ .verify_host = false },
    );
    stream_owned = false;
    defer connection.deinit();

    var prefix: [1]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 1),
        try connection.readWithDeadline(
            &prefix,
            .fromNow(io, .{ .raw = .fromMilliseconds(200), .clock = .awake }),
        ),
    );
    try std.testing.expectEqual(first_record[0], prefix[0]);

    var suffix: [first_record.len - 1]u8 = undefined;
    try std.testing.expectEqual(
        suffix.len,
        try connection.readWithDeadline(
            &suffix,
            // The record plaintext was already decrypted by the first read;
            // consuming it must not consult an expired socket deadline.
            .fromNow(io, .{ .raw = .fromNanoseconds(1), .clock = .awake }),
        ),
    );
    try std.testing.expectEqualStrings(first_record[1..], &suffix);

    var next: [1]u8 = undefined;
    try std.testing.expectError(
        error.Timeout,
        connection.readWithDeadline(
            &next,
            .fromNow(io, .{ .raw = .fromMilliseconds(100), .clock = .awake }),
        ),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

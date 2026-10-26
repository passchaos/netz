//! RFC 8879 compress_certificate negotiation on the stream TLS client.
//!
//! The test server never completes a handshake: it captures the TLS record,
//! parses the ClientHello extension block, and closes the connection. This
//! verifies the wire advertisement without depending on server-side
//! compressed Certificate preparation.

const std = @import("std");
const client = @import("versioned_client_connection.zig");
const stream_io = @import("../../internal/stream_io.zig");
const tls_testing = @import("../testing.zig");

const vail = @import("vail");
const cert_compression = vail.tls.certificate_compression;

const extension_type_compress_certificate: u16 = 0x001b;

fn findExtension(
    extensions: []const u8,
    extension_type: u16,
) ?[]const u8 {
    var cursor: usize = 0;
    while (cursor + 4 <= extensions.len) {
        const kind = std.mem.readInt(u16, extensions[cursor..][0..2], .big);
        const length = std.mem.readInt(
            u16,
            extensions[cursor + 2 ..][0..2],
            .big,
        );
        const data_start = cursor + 4;
        if (data_start + length > extensions.len) return null;
        if (kind == extension_type) {
            return extensions[data_start .. data_start + length];
        }
        cursor = data_start + length;
    }
    return null;
}

/// Parse one TLSPlaintext handshake record's ClientHello and return its
/// extension block. The first flight is a single complete record.
fn clientHelloExtensions(record: []const u8) ![]const u8 {
    if (record.len < 5 + 4) return error.HandshakeMessageTooLarge;
    if (record[0] != 0x16) return error.HandshakeMessageTooLarge;
    const record_len = std.mem.readInt(
        u16,
        record[3..5],
        .big,
    );
    if (record.len < 5 + record_len) return error.HandshakeMessageTooLarge;
    const fragment = record[5 .. 5 + record_len];
    if (fragment[0] != 0x01) return error.HandshakeMessageTooLarge;

    var cursor: usize = 4; // skip handshake header
    cursor += 2 + 32; // legacy_version + random
    const session_id_len = fragment[cursor];
    cursor += 1 + session_id_len;
    const cipher_suites_len = std.mem.readInt(
        u16,
        fragment[cursor..][0..2],
        .big,
    );
    cursor += 2 + cipher_suites_len;
    const compression_methods_len = fragment[cursor];
    cursor += 1 + compression_methods_len;
    if (cursor + 2 > fragment.len) return error.HandshakeMessageTooLarge;
    const extensions_len = std.mem.readInt(
        u16,
        fragment[cursor..][0..2],
        .big,
    );
    cursor += 2;
    if (cursor + extensions_len > fragment.len) {
        return error.HandshakeMessageTooLarge;
    }
    return fragment[cursor .. cursor + extensions_len];
}

const Capture = struct {
    listener: *std.Io.net.Server,
    io: std.Io,
    offered: ?[]u16 = null,
    err: ?anyerror = null,

    fn run(self: *@This()) void {
        const stream = self.listener.accept(self.io) catch |err| {
            self.err = err;
            return;
        };
        defer stream.close(self.io);
        var record: [4096]u8 = undefined;
        const deadline = std.Io.Clock.Timestamp.fromNow(self.io, .{
            .raw = std.Io.Duration.fromSeconds(2),
            .clock = .awake,
        });
        var total: usize = 0;
        // Read the complete first TLS record: five-byte header plus fragment.
        while (true) {
            const count = stream_io.readSomeWithDeadline(
                self.io,
                stream,
                record[total..],
                deadline,
            ) catch |err| {
                self.err = err;
                return;
            };
            if (count == 0) {
                self.err = error.UnexpectedEof;
                return;
            }
            total += count;
            if (total >= 5) {
                const fragment_len = std.mem.readInt(
                    u16,
                    record[3..5],
                    .big,
                );
                if (total >= 5 + fragment_len) break;
            }
        }
        const extensions = clientHelloExtensions(record[0..total]) catch |err| {
            self.err = err;
            return;
        };
        if (findExtension(extensions, extension_type_compress_certificate)) |data| {
            if (data.len < 1) {
                self.err = error.HandshakeMessageTooLarge;
                return;
            }
            // RFC 8879: one-byte list length followed by u16 algorithm IDs.
            const algorithm_bytes = data[0];
            if (data.len != 1 + algorithm_bytes or
                algorithm_bytes % 2 != 0)
            {
                self.err = error.HandshakeMessageTooLarge;
                return;
            }
            const algorithm_count = algorithm_bytes / 2;
            const algorithms = std.testing.allocator.alloc(
                u16,
                algorithm_count,
            ) catch {
                self.err = error.OutOfMemory;
                return;
            };
            for (algorithms, 0..) |*algorithm, index| {
                algorithm.* = std.mem.readInt(
                    u16,
                    data[1 + index * 2 ..][0..2],
                    .big,
                );
            }
            self.offered = algorithms;
        }
    }
};

fn captureClientHello(
    comptime configure: fn (
        options: *client.Options,
    ) void,
) !?[]u16 {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (std.Io.net.IpAddress{
        .ip4 = .loopback(0),
    }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();

    var capture = Capture{ .listener = &listener, .io = io };
    const thread = try std.Thread.spawn(.{}, Capture.run, .{&capture});
    var joined = false;
    defer if (!joined) thread.join();

    var stream = try listener.socket.address.connect(io, .{
        .mode = .stream,
    });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);

    var options: client.Options = .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .request_tls12_session_ticket = false,
        .request_tls13_session_ticket = false,
        .handshake_timeout = .fromSeconds(1),
    };
    configure(&options);

    const result = client.Connection.initWithDeadline(
        allocator,
        io,
        stream,
        options,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
    );
    if (result) |connection| {
        stream_owned = false;
        connection.deinit();
    } else |_| {}

    thread.join();
    joined = true;
    if (capture.err) |err| return err;
    return capture.offered;
}

fn defaultConfigure(options: *client.Options) void {
    _ = options;
}

test "TLS client advertises brotli zstd and zlib certificate compression by default" {
    const offered = (try captureClientHello(defaultConfigure)).?;
    defer std.testing.allocator.free(offered);
    try std.testing.expectEqualSlices(u16, &.{
        @intFromEnum(cert_compression.Algorithm.brotli),
        @intFromEnum(cert_compression.Algorithm.zstd),
        @intFromEnum(cert_compression.Algorithm.zlib),
    }, offered);
}

fn disableConfigure(options: *client.Options) void {
    options.certificate_compression_algorithms = &.{};
}

test "TLS client omits certificate compression with an empty algorithm list" {
    const offered = try captureClientHello(disableConfigure);
    try std.testing.expect(offered == null);
}

fn customConfigure(options: *client.Options) void {
    options.certificate_compression_algorithms = &.{
        cert_compression.Algorithm.zstd,
        cert_compression.Algorithm.zlib,
    };
}

test "TLS client preserves a custom certificate compression order" {
    const offered = (try captureClientHello(customConfigure)).?;
    defer std.testing.allocator.free(offered);
    try std.testing.expectEqualSlices(u16, &.{
        @intFromEnum(cert_compression.Algorithm.zstd),
        @intFromEnum(cert_compression.Algorithm.zlib),
    }, offered);
}

test "TLS client rejects duplicate or unsupported certificate compression algorithms" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var listener = try (std.Io.net.IpAddress{
        .ip4 = .loopback(0),
    }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);

    var stream = try listener.socket.address.connect(io, .{
        .mode = .stream,
    });
    defer stream.close(io);
    const invalid_options: client.Options = .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .certificate_compression_algorithms = &.{
            cert_compression.Algorithm.zlib,
            cert_compression.Algorithm.zlib,
        },
    };
    try std.testing.expectError(
        error.InvalidProtocolPolicy,
        client.Connection.init(allocator, io, stream, invalid_options),
    );
}

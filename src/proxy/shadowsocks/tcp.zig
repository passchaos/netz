//! Shadowsocks AEAD TCP server.

const std = @import("std");

const cipher = @import("cipher.zig");
const stream_codec = @import("stream.zig");
const replay = @import("replay.zig");
const codec = @import("../socks/codec.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;

pub const Config = struct {
    method: cipher.Algorithm,
    password: []const u8,
    acl: acl.Policy = .{},
    /// Optional hot-reloadable ACL. Takes precedence over `acl`.
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    handshake_timeout: std.Io.Duration = .fromSeconds(10),
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    relay_buffer_size: usize = 16 * 1024,
    max_initial_bytes: usize = stream_codec.max_payload_len,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    InvalidPassword,
    ReplayDetected,
    TruncatedRequest,
    InitialPayloadTooLarge,
    AuthenticationFailed,
    BufferTooSmall,
};

/// Process one accepted Shadowsocks TCP connection.
pub fn processConnection(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    peer: net.IpAddress,
    config: Config,
    limiter: ?*limits.ConnectionLimiter,
    replay_cache: ?*replay.Cache,
) !void {
    if (config.rate_limiter) |value| {
        const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
        if (!value.allow(peer, 1, now)) return error.RateLimited;
    }
    if (limiter) |value| try value.acquire(peer);
    defer if (limiter) |value| value.release(peer);
    if (config.stats) |value| value.connectionOpened();
    defer if (config.stats) |value| value.connectionClosed();

    if (config.password.len == 0) return error.InvalidPassword;
    const key_length = config.method.keyLength();
    var master_key: [32]u8 = undefined;
    const master = try cipher.deriveMasterKey(
        config.password,
        key_length,
        &master_key,
    );
    defer std.crypto.secureZero(u8, &master_key);

    const handshake_deadline = try io_helpers.deadlineFromTimeout(
        io,
        config.handshake_timeout,
    );
    var salt: [cipher.max_salt_len]u8 = undefined;
    const salt_slice = salt[0..key_length];
    try readExact(io, stream, salt_slice, handshake_deadline);
    if (replay_cache) |cache| {
        if (!cache.accept(salt_slice)) return error.ReplayDetected;
    }

    var subkey: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &subkey);
    try cipher.deriveSubkey(
        config.method,
        master,
        salt_slice,
        subkey[0..key_length],
    );

    const decryptor = try stream_codec.Decryptor.init(
        config.method,
        subkey[0..key_length],
    );
    var cipher_storage: [stream_codec.max_payload_len + 16]u8 = undefined;
    var plaintext_storage: [stream_codec.max_payload_len]u8 = undefined;
    var chunk_reader = try stream_codec.ChunkReader.init(
        io,
        stream,
        decryptor,
        handshake_deadline,
        &cipher_storage,
        &plaintext_storage,
    );
    defer chunk_reader.deinit();

    var first_storage: [stream_codec.max_payload_len]u8 = undefined;
    var first_used: usize = 0;
    var decoded: codec.DecodedAddress = undefined;
    var initial_payload_len: usize = 0;
    while (true) {
        const chunk = (try chunk_reader.readChunk()) orelse
            return error.TruncatedRequest;
        if (first_used + chunk.len > config.max_initial_bytes or
            first_used + chunk.len > first_storage.len)
        {
            return error.InitialPayloadTooLarge;
        }
        @memcpy(first_storage[first_used..][0..chunk.len], chunk);
        first_used += chunk.len;
        decoded = codec.decodeSocks5Address(
            first_storage[0..first_used],
            0,
        ) catch |err| switch (err) {
            error.Incomplete => {
                if (first_used >= codec.max_socks5_request_len) {
                    return error.TruncatedRequest;
                }
                continue;
            },
            else => return err,
        };
        initial_payload_len = first_used - decoded.end;
        break;
    }

    const target: destination.Target = switch (decoded.address) {
        .ip => |ip| .{ .ip = ip },
        .domain => |domain| .{ .domain = .{
            .host = domain.host,
            .port = domain.port,
        } },
    };
    const upstream = destination.connectTarget(
        allocator,
        io,
        reload.policyFor(config.acl, config.policy_store),
        target,
        .connect,
        config.connect_timeout,
    ) catch |err| {
        if (config.stats) |value| {
            if (err == error.DestinationDenied) value.deniedRequest();
        }
        return err;
    };
    defer upstream.close(io);

    var server_salt: [cipher.max_salt_len]u8 = undefined;
    const server_salt_slice = server_salt[0..key_length];
    io.random(server_salt_slice);
    try io_helpers.writeAll(io, stream, server_salt_slice, handshake_deadline);

    var server_subkey: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &server_subkey);
    try cipher.deriveSubkey(
        config.method,
        master,
        server_salt_slice,
        server_subkey[0..key_length],
    );
    const encryptor = try stream_codec.Encryptor.init(
        config.method,
        server_subkey[0..key_length],
    );
    var wire_storage: [stream_codec.max_chunk_wire_len]u8 = undefined;
    var chunk_writer = try stream_codec.ChunkWriter.init(
        io,
        stream,
        encryptor,
        null,
        &wire_storage,
    );
    defer chunk_writer.deinit();

    if (initial_payload_len > 0) {
        try io_helpers.writeAll(
            io,
            upstream,
            first_storage[decoded.end..first_used],
            currentDeadline(io, config.idle_timeout),
        );
    }

    const Shared = struct {
        io: std.Io,
        upstream: net.Stream,
        writer: *stream_codec.ChunkWriter,
        idle_timeout: std.Io.Duration,
        buffer: []u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.pump() catch |err| {
                self.err = err;
                shutdownBoth(self.io, self.upstream, self.writer.stream);
            };
        }

        fn pump(self: *@This()) !void {
            while (true) {
                self.writer.deadline = currentDeadline(
                    self.io,
                    self.idle_timeout,
                );
                const count = io_helpers.readSome(
                    self.io,
                    self.upstream,
                    self.buffer,
                    currentDeadline(self.io, self.idle_timeout),
                ) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                if (count == 0) break;
                try self.writer.writeChunk(self.buffer[0..count]);
            }
            self.writer.stream.shutdown(self.io, .send) catch {};
        }
    };

    const shared_buffer = try allocator.alloc(u8, config.relay_buffer_size);
    defer allocator.free(shared_buffer);
    var shared = Shared{
        .io = io,
        .upstream = upstream,
        .writer = &chunk_writer,
        .idle_timeout = config.idle_timeout,
        .buffer = shared_buffer,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shutdownBoth(io, stream, upstream);
        thread.join();
    };

    while (true) {
        chunk_reader.deadline = currentDeadline(io, config.idle_timeout);
        const chunk = chunk_reader.readChunk() catch |err| switch (err) {
            error.TruncatedChunk => break,
            else => return err,
        } orelse break;
        try io_helpers.writeAll(
            io,
            upstream,
            chunk,
            currentDeadline(io, config.idle_timeout),
        );
    }

    upstream.shutdown(io, .send) catch {};
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn currentDeadline(
    io: std.Io,
    idle_timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, idle_timeout) catch null;
}

fn readExact(
    io: std.Io,
    stream: net.Stream,
    output: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try io_helpers.readSome(
            io,
            stream,
            output[offset..],
            deadline,
        );
        if (count == 0) return error.TruncatedRequest;
        offset += count;
    }
}

fn shutdownBoth(io: std.Io, a: net.Stream, b: net.Stream) void {
    a.shutdown(io, .both) catch {};
    b.shutdown(io, .both) catch {};
}

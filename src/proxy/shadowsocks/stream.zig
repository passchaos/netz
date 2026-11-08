//! Shadowsocks AEAD TCP chunk framing and streaming adapters.

const std = @import("std");

const cipher = @import("cipher.zig");
const io_helpers = @import("../internal/io.zig");

const net = std.Io.net;

pub const max_payload_len: usize = 0x3FFF;
pub const length_block_wire_len: usize = 2 + 16;
pub const max_chunk_wire_len: usize = length_block_wire_len + max_payload_len + 16;

pub const Error = error{
    ChunkTooLarge,
    TruncatedChunk,
    AuthenticationFailed,
    InvalidCiphertext,
    BufferTooSmall,
};

pub const Encryptor = struct {
    aead: cipher.Aead,
    nonce: cipher.Nonce = .{},

    pub fn init(algorithm: cipher.Algorithm, key: []const u8) !Encryptor {
        return .{ .aead = try cipher.Aead.init(algorithm, key) };
    }

    pub fn deinit(self: *Encryptor) void {
        self.aead.deinit();
        self.* = undefined;
    }

    /// Encode one chunk into caller storage. `payload` must fit in one
    /// Shadowsocks chunk.
    pub fn encryptChunk(
        self: *Encryptor,
        output: []u8,
        payload: []const u8,
    ) Error![]const u8 {
        if (payload.len > max_payload_len) return error.ChunkTooLarge;
        if (output.len < length_block_wire_len + payload.len + 16) {
            return error.BufferTooSmall;
        }
        var length_plain: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_plain, @intCast(payload.len), .big);
        self.aead.encrypt(
            output[0..2],
            @ptrCast(&output[2]),
            &length_plain,
            "",
            self.nonce.bytes,
        );
        self.nonce.increment();
        self.aead.encrypt(
            output[18..][0..payload.len],
            @ptrCast(&output[18 + payload.len]),
            payload,
            "",
            self.nonce.bytes,
        );
        self.nonce.increment();
        return output[0 .. length_block_wire_len + payload.len + 16];
    }
};

pub const Decryptor = struct {
    aead: cipher.Aead,
    nonce: cipher.Nonce = .{},

    pub fn init(algorithm: cipher.Algorithm, key: []const u8) !Decryptor {
        return .{ .aead = try cipher.Aead.init(algorithm, key) };
    }

    pub fn deinit(self: *Decryptor) void {
        self.aead.deinit();
        self.* = undefined;
    }

    /// Decode the length block. Returns the payload byte count.
    pub fn decryptLength(self: *Decryptor, block: *const [18]u8) Error!usize {
        var plain: [2]u8 = undefined;
        self.aead.decrypt(
            &plain,
            block[0..2],
            block[2..18].*,
            "",
            self.nonce.bytes,
        ) catch return error.AuthenticationFailed;
        self.nonce.increment();
        const length = std.mem.readInt(u16, &plain, .big);
        if (length > max_payload_len) return error.ChunkTooLarge;
        return length;
    }

    /// Decode one payload block. `output` and `wire` must be separate buffers.
    pub fn decryptPayload(
        self: *Decryptor,
        output: []u8,
        wire: []const u8,
        length: usize,
    ) Error!void {
        if (length > max_payload_len or wire.len != length + 16 or
            output.len < length)
        {
            return error.InvalidCiphertext;
        }
        self.aead.decrypt(
            output[0..length],
            wire[0..length],
            wire[length..][0..16].*,
            "",
            self.nonce.bytes,
        ) catch return error.AuthenticationFailed;
        self.nonce.increment();
    }
};

pub const ChunkReader = struct {
    io: std.Io,
    stream: net.Stream,
    decryptor: Decryptor,
    deadline: ?std.Io.Clock.Timestamp,
    length_cipher: [18]u8 = undefined,
    payload_cipher: []u8,
    plaintext: []u8,

    pub fn init(
        io: std.Io,
        stream: net.Stream,
        decryptor: Decryptor,
        deadline: ?std.Io.Clock.Timestamp,
        cipher_storage: []u8,
        plaintext_storage: []u8,
    ) !ChunkReader {
        if (cipher_storage.len < max_payload_len + 16 or
            plaintext_storage.len < max_payload_len)
        {
            return error.BufferTooSmall;
        }
        return .{
            .io = io,
            .stream = stream,
            .decryptor = decryptor,
            .deadline = deadline,
            .payload_cipher = cipher_storage,
            .plaintext = plaintext_storage,
        };
    }

    pub fn deinit(self: *ChunkReader) void {
        self.decryptor.deinit();
        self.* = undefined;
    }

    /// Read one plaintext chunk. Null means the peer closed cleanly between
    /// chunks.
    pub fn readChunk(self: *ChunkReader) !?[]const u8 {
        const length_read = try readExactAllowEof(
            self.io,
            self.stream,
            &self.length_cipher,
            self.deadline,
        );
        if (length_read == 0) return null;
        if (length_read != self.length_cipher.len) return error.TruncatedChunk;

        const length = self.decryptor.decryptLength(&self.length_cipher) catch
            return error.AuthenticationFailed;
        const wire_len = length + 16;
        try readExact(
            self.io,
            self.stream,
            self.payload_cipher[0..wire_len],
            self.deadline,
        );
        try self.decryptor.decryptPayload(
            self.plaintext,
            self.payload_cipher[0..wire_len],
            length,
        );
        return self.plaintext[0..length];
    }
};

pub const ChunkWriter = struct {
    io: std.Io,
    stream: net.Stream,
    encryptor: Encryptor,
    deadline: ?std.Io.Clock.Timestamp,
    wire: []u8,

    pub fn init(
        io: std.Io,
        stream: net.Stream,
        encryptor: Encryptor,
        deadline: ?std.Io.Clock.Timestamp,
        wire_storage: []u8,
    ) !ChunkWriter {
        if (wire_storage.len < max_chunk_wire_len) return error.BufferTooSmall;
        return .{
            .io = io,
            .stream = stream,
            .encryptor = encryptor,
            .deadline = deadline,
            .wire = wire_storage,
        };
    }

    pub fn deinit(self: *ChunkWriter) void {
        self.encryptor.deinit();
        self.* = undefined;
    }

    pub fn writeChunk(self: *ChunkWriter, payload: []const u8) !void {
        var offset: usize = 0;
        while (offset < payload.len) {
            const take = @min(payload.len - offset, max_payload_len);
            const wire = try self.encryptor.encryptChunk(
                self.wire,
                payload[offset..][0..take],
            );
            try io_helpers.writeAll(
                self.io,
                self.stream,
                wire,
                self.deadline,
            );
            offset += take;
        }
    }
};

fn readExactAllowEof(
    io: std.Io,
    stream: net.Stream,
    output: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) !usize {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try io_helpers.readSome(
            io,
            stream,
            output[offset..],
            deadline,
        );
        if (count == 0) return offset;
        offset += count;
    }
    return offset;
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
        if (count == 0) return error.TruncatedChunk;
        offset += count;
    }
}

test "chunk encryptor and decryptor round trip and reject tampering" {
    const algorithm = cipher.Algorithm.aes_128_gcm;
    const key = [_]u8{0x11} ** 16;
    var encryptor = try Encryptor.init(algorithm, &key);
    defer encryptor.deinit();
    var decryptor = try Decryptor.init(algorithm, &key);
    defer decryptor.deinit();

    var wire: [max_chunk_wire_len]u8 = undefined;
    const first = try encryptor.encryptChunk(&wire, "hello");
    var length_block: [18]u8 = undefined;
    @memcpy(&length_block, first[0..18]);
    const length = try decryptor.decryptLength(&length_block);
    try std.testing.expectEqual(@as(usize, 5), length);
    var plain: [max_payload_len]u8 = undefined;
    try decryptor.decryptPayload(&plain, first[18..], length);
    try std.testing.expectEqualStrings("hello", plain[0..5]);

    const second = try encryptor.encryptChunk(&wire, "world");
    @memcpy(&length_block, second[0..18]);
    const second_length = try decryptor.decryptLength(&length_block);
    try decryptor.decryptPayload(&plain, second[18..], second_length);
    try std.testing.expectEqualStrings("world", plain[0..5]);

    var tampered: [max_chunk_wire_len]u8 = undefined;
    @memcpy(tampered[0..first.len], first);
    tampered[0] ^= 1;
    @memcpy(&length_block, tampered[0..18]);
    try std.testing.expectError(
        error.AuthenticationFailed,
        decryptor.decryptLength(&length_block),
    );
}

test "chunk writer splits oversized payloads at the protocol limit" {
    const algorithm = cipher.Algorithm.chacha20_ietf_poly1305;
    const key = [_]u8{0x22} ** 32;
    var encryptor = try Encryptor.init(algorithm, &key);
    defer encryptor.deinit();
    var decryptor = try Decryptor.init(algorithm, &key);
    defer decryptor.deinit();

    var wire: [max_chunk_wire_len]u8 = undefined;
    var plain: [max_payload_len]u8 = undefined;
    var payload: [max_payload_len * 2 + 1]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);

    var offset: usize = 0;
    while (offset < payload.len) {
        const take = @min(payload.len - offset, max_payload_len);
        const encoded = try encryptor.encryptChunk(
            &wire,
            payload[offset..][0..take],
        );
        var length_block: [18]u8 = undefined;
        @memcpy(&length_block, encoded[0..18]);
        const length = try decryptor.decryptLength(&length_block);
        try decryptor.decryptPayload(&plain, encoded[18..], length);
        try std.testing.expectEqualSlices(
            u8,
            payload[offset..][0..take],
            plain[0..take],
        );
        offset += take;
    }
}

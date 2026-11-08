//! VMess AEAD body chunk framing for AES-128-GCM.

const std = @import("std");
const vail = @import("vail");

const aes_gcm = vail.crypto.aes_gcm;
const chacha = vail.crypto.chacha20_poly1305;

pub const tag_length: usize = 16;
pub const max_payload_len: usize = 0xffff - tag_length;

pub const Algorithm = enum { aes_128_gcm, chacha20_poly1305 };

pub const Context = union(enum) {
    aes_128_gcm: aes_gcm.Aes128Gcm,
    chacha20_poly1305: chacha.Context,

    pub fn deinit(self: *Context) void {
        switch (self.*) {
            .aes_128_gcm => |*value| value.deinit(),
            .chacha20_poly1305 => |*value| value.deinit(),
        }
        self.* = undefined;
    }

    pub fn encrypt(
        self: *const Context,
        ciphertext: []u8,
        tag: *[tag_length]u8,
        plaintext: []const u8,
        nonce: [12]u8,
    ) void {
        switch (self.*) {
            .aes_128_gcm => |*value| value.encrypt(
                ciphertext,
                tag,
                plaintext,
                "",
                nonce,
            ),
            .chacha20_poly1305 => |*value| value.encrypt(
                ciphertext,
                tag,
                plaintext,
                "",
                nonce,
            ),
        }
    }

    pub fn decrypt(
        self: *const Context,
        plaintext: []u8,
        ciphertext: []const u8,
        tag: [tag_length]u8,
        nonce: [12]u8,
    ) !void {
        switch (self.*) {
            .aes_128_gcm => |*value| try value.decrypt(
                plaintext,
                ciphertext,
                tag,
                "",
                nonce,
            ),
            .chacha20_poly1305 => |*value| try value.decrypt(
                plaintext,
                ciphertext,
                tag,
                "",
                nonce,
            ),
        }
    }
};

pub const Error = error{
    ChunkTooLarge,
    InvalidChunk,
    AuthenticationFailed,
    BufferTooSmall,
    TruncatedChunk,
};

pub const Encryptor = struct {
    context: Context,
    iv: [16]u8,
    counter: u16 = 0,

    pub fn init(
        algorithm: Algorithm,
        key: [16]u8,
        iv: [16]u8,
    ) Encryptor {
        return .{
            .context = contextFor(algorithm, key),
            .iv = iv,
        };
    }

    pub fn deinit(self: *Encryptor) void {
        self.context.deinit();
        self.* = undefined;
    }

    pub fn writeChunk(
        self: *Encryptor,
        output: []u8,
        payload: []const u8,
    ) Error!usize {
        if (payload.len > max_payload_len) return error.ChunkTooLarge;
        const total = 2 + payload.len + tag_length;
        if (output.len < total) return error.BufferTooSmall;
        const size: u16 = @intCast(payload.len + tag_length);
        std.mem.writeInt(u16, output[0..2], size, .big);

        var nonce: [12]u8 = self.iv[0..12].*;
        std.mem.writeInt(u16, nonce[0..2], self.counter, .big);
        self.counter +%= 1;
        var tag: [tag_length]u8 = undefined;
        self.context.encrypt(
            output[2..][0..payload.len],
            &tag,
            payload,
            nonce,
        );
        @memcpy(output[2 + payload.len ..][0..tag_length], &tag);
        return total;
    }

    /// Write the zero-length termination chunk.
    pub fn writeTermination(self: *Encryptor, output: []u8) Error!usize {
        return self.writeChunk(output, "");
    }
};

pub const Decryptor = struct {
    context: Context,
    iv: [16]u8,
    counter: u16 = 0,

    pub fn init(
        algorithm: Algorithm,
        key: [16]u8,
        iv: [16]u8,
    ) Decryptor {
        return .{
            .context = contextFor(algorithm, key),
            .iv = iv,
        };
    }

    pub fn deinit(self: *Decryptor) void {
        self.context.deinit();
        self.* = undefined;
    }

    /// Read one chunk. Null means a clean zero-length termination chunk or
    /// end-of-stream before the next size field.
    pub fn readChunk(
        self: *Decryptor,
        connection: anytype,
        output: []u8,
    ) !?[]const u8 {
        var size_bytes: [2]u8 = undefined;
        const read = try readExactAllowEof(connection, &size_bytes);
        if (read == 0) return null;
        if (read != 2) return error.TruncatedChunk;
        const size = std.mem.readInt(u16, &size_bytes, .big);
        if (size < tag_length) return error.InvalidChunk;
        if (output.len < size - tag_length) return error.BufferTooSmall;

        var wire: [0xffff]u8 = undefined;
        try readExact(connection, wire[0..size]);
        const payload_len = size - tag_length;
        var nonce: [12]u8 = self.iv[0..12].*;
        std.mem.writeInt(u16, nonce[0..2], self.counter, .big);
        self.counter +%= 1;
        self.context.decrypt(
            output[0..payload_len],
            wire[0..payload_len],
            wire[payload_len..][0..tag_length].*,
            nonce,
        ) catch return error.AuthenticationFailed;
        if (payload_len == 0) return null;
        return output[0..payload_len];
    }
};

fn contextFor(algorithm: Algorithm, key: [16]u8) Context {
    return switch (algorithm) {
        .aes_128_gcm => .{ .aes_128_gcm = aes_gcm.Aes128Gcm.init(key) },
        .chacha20_poly1305 => blk: {
            var first: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(&key, &first, .{});
            var second: [16]u8 = undefined;
            std.crypto.hash.Md5.hash(&first, &second, .{});
            var derived: [32]u8 = undefined;
            @memcpy(derived[0..16], &first);
            @memcpy(derived[16..32], &second);
            break :blk .{ .chacha20_poly1305 = chacha.Context.init(derived) };
        },
    };
}

fn readExactAllowEof(connection: anytype, output: []u8) !usize {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return offset;
        offset += count;
    }
    return offset;
}

fn readExact(connection: anytype, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try connection.read(output[offset..]);
        if (count == 0) return error.TruncatedChunk;
        offset += count;
    }
}

test "VMess AES-GCM body chunks round trip and terminate" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;
    var encryptor = Encryptor.init(.aes_128_gcm, key, iv);
    defer encryptor.deinit();
    var decryptor = Decryptor.init(.aes_128_gcm, key, iv);
    defer decryptor.deinit();

    var wire: [64]u8 = undefined;
    const first = try encryptor.writeChunk(&wire, "hello");
    var connection = MemoryConnection{ .bytes = wire[0..first] };
    var plain: [64]u8 = undefined;
    const opened = (try decryptor.readChunk(&connection, &plain)).?;
    try std.testing.expectEqualStrings("hello", opened);

    const termination = try encryptor.writeTermination(&wire);
    var end_connection = MemoryConnection{ .bytes = wire[0..termination] };
    try std.testing.expect((try decryptor.readChunk(&end_connection, &plain)) == null);
}

test "VMess AES-GCM body rejects tampering" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;
    var encryptor = Encryptor.init(.aes_128_gcm, key, iv);
    defer encryptor.deinit();
    var decryptor = Decryptor.init(.aes_128_gcm, key, iv);
    defer decryptor.deinit();

    var wire: [64]u8 = undefined;
    const len = try encryptor.writeChunk(&wire, "secret");
    wire[2] ^= 1;
    var connection = MemoryConnection{ .bytes = wire[0..len] };
    var plain: [64]u8 = undefined;
    try std.testing.expectError(
        error.AuthenticationFailed,
        decryptor.readChunk(&connection, &plain),
    );
}

const MemoryConnection = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn read(self: *@This(), output: []u8) !usize {
        const available = self.bytes.len - self.offset;
        const take = @min(available, output.len);
        @memcpy(output[0..take], self.bytes[self.offset..][0..take]);
        self.offset += take;
        return take;
    }
};

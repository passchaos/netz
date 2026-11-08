//! VMess LEGACY body framing: AES-CFB stream with optional FNV chunk auth.

const std = @import("std");

const crypto = @import("crypto.zig");

pub const fnv_overhead: usize = 4;
pub const chunk_stream_option: u8 = 0x01;

pub const Error = error{
    InvalidChunk,
    AuthenticationFailed,
    BufferTooSmall,
    TruncatedChunk,
};

pub const Encryptor = struct {
    cfb: crypto.Cfb,
    chunked: bool,

    pub fn init(
        key: [16]u8,
        iv: [16]u8,
        chunked: bool,
    ) Encryptor {
        return .{
            .cfb = crypto.Cfb.initEncrypt(key, iv),
            .chunked = chunked,
        };
    }

    pub fn writeChunk(
        self: *Encryptor,
        output: []u8,
        payload: []const u8,
    ) Error!usize {
        if (!self.chunked) {
            if (output.len < payload.len) return error.BufferTooSmall;
            self.cfb.process(output[0..payload.len], payload);
            return payload.len;
        }

        const total = 2 + fnv_overhead + payload.len;
        if (output.len < total) return error.BufferTooSmall;
        const size: u16 = @intCast(fnv_overhead + payload.len);
        std.mem.writeInt(u16, output[0..2], size, .big);
        const checksum = crypto.fnv1a32(payload);
        std.mem.writeInt(u32, output[2..6], checksum, .big);
        @memcpy(output[6..][0..payload.len], payload);
        self.cfb.process(output[0..total], output[0..total]);
        return total;
    }

    pub fn writeTermination(self: *Encryptor, output: []u8) Error!usize {
        if (!self.chunked) return 0;
        return self.writeChunk(output, "");
    }
};

pub const Decryptor = struct {
    cfb: crypto.Cfb,
    chunked: bool,

    pub fn init(
        key: [16]u8,
        iv: [16]u8,
        chunked: bool,
    ) Decryptor {
        return .{
            .cfb = crypto.Cfb.initDecrypt(key, iv),
            .chunked = chunked,
        };
    }

    pub fn readChunk(
        self: *Decryptor,
        connection: anytype,
        output: []u8,
    ) !?[]const u8 {
        if (!self.chunked) {
            const count = try connection.read(output);
            if (count == 0) return null;
            self.cfb.process(output[0..count], output[0..count]);
            return output[0..count];
        }

        var size_cipher: [2]u8 = undefined;
        const size_read = try readExactAllowEof(connection, &size_cipher);
        if (size_read == 0) return null;
        if (size_read != 2) return error.TruncatedChunk;
        var size_plain: [2]u8 = undefined;
        self.cfb.process(&size_plain, &size_cipher);
        const size = std.mem.readInt(u16, &size_plain, .big);
        if (size < fnv_overhead) return error.InvalidChunk;
        if (output.len < size - fnv_overhead) return error.BufferTooSmall;

        var cipher: [0xffff]u8 = undefined;
        try readExact(connection, cipher[0..size]);
        self.cfb.process(cipher[0..size], cipher[0..size]);
        const payload_len = size - fnv_overhead;
        const checksum = std.mem.readInt(u32, cipher[0..4], .big);
        const payload = cipher[4..size];
        if (crypto.fnv1a32(payload) != checksum) {
            return error.AuthenticationFailed;
        }
        if (payload_len == 0) return null;
        @memcpy(output[0..payload_len], payload);
        return output[0..payload_len];
    }
};

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

test "VMess LEGACY chunked body round trips and terminates" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;
    var encryptor = Encryptor.init(key, iv, true);
    var decryptor = Decryptor.init(key, iv, true);

    var wire: [64]u8 = undefined;
    const len = try encryptor.writeChunk(&wire, "hello");
    var connection = MemoryConnection{ .bytes = wire[0..len] };
    var plain: [64]u8 = undefined;
    const opened = (try decryptor.readChunk(&connection, &plain)).?;
    try std.testing.expectEqualStrings("hello", opened);

    const end_len = try encryptor.writeTermination(&wire);
    var end_connection = MemoryConnection{ .bytes = wire[0..end_len] };
    try std.testing.expect(
        (try decryptor.readChunk(&end_connection, &plain)) == null,
    );
}

test "VMess LEGACY raw body encrypts and decrypts a stream" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;
    var encryptor = Encryptor.init(key, iv, false);
    var decryptor = Decryptor.init(key, iv, false);

    const payload = "legacy raw body payload";
    var wire: [64]u8 = undefined;
    const len = try encryptor.writeChunk(&wire, payload);
    var connection = MemoryConnection{ .bytes = wire[0..len] };
    var plain: [64]u8 = undefined;
    const opened = (try decryptor.readChunk(&connection, &plain)).?;
    try std.testing.expectEqualStrings(payload, opened);
}

test "VMess LEGACY chunked body rejects FNV tampering" {
    const key = [_]u8{0x11} ** 16;
    const iv = [_]u8{0x22} ** 16;
    var encryptor = Encryptor.init(key, iv, true);
    var decryptor = Decryptor.init(key, iv, true);

    var wire: [64]u8 = undefined;
    const len = try encryptor.writeChunk(&wire, "secret");
    wire[6] ^= 1;
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

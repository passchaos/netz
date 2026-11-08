//! Minimal RFC 6455 WebSocket transport over a TLS byte stream.
//!
//! The wrapper exposes a byte-stream interface: binary/text/continuation
//! payloads are concatenated for reads, while writes are emitted as binary
//! frames. Client frames are masked; server frames are not. Control frames
//! are handled internally and bounded.

const std = @import("std");

const net = std.Io.net;

pub const Config = struct {
    max_head_bytes: usize = 8192,
    max_frame_payload: usize = 64 * 1024,
    path: ?[]const u8 = null,
};

pub const Error = error{
    InvalidUpgrade,
    UnsupportedMethod,
    UnsupportedVersion,
    MissingUpgradeHeader,
    InvalidKey,
    InvalidAccept,
    FrameTooLarge,
    InvalidFrame,
    UnmaskedFrame,
    TruncatedFrame,
    BufferTooSmall,
};

const websocket_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub fn Stream(comptime Inner: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        io: std.Io,
        inner: *Inner,
        frame: []u8,
        frame_start: usize = 0,
        frame_end: usize = 0,
        write_buffer: []u8,
        mask_incoming: bool,
        mask_outgoing: bool,
        closed: bool = false,

        pub fn accept(
            allocator: std.mem.Allocator,
            io: std.Io,
            inner: *Inner,
            config: Config,
        ) !Self {
            var head_storage: [8192]u8 = undefined;
            const max_head = @min(config.max_head_bytes, head_storage.len);
            const head = try readHead(inner, head_storage[0..max_head]);
            const key = try validateUpgrade(head, config.path);
            try sendAccept(inner, key);
            return init(allocator, io, inner, config, true, false);
        }

        pub fn connect(
            allocator: std.mem.Allocator,
            io: std.Io,
            inner: *Inner,
            host: []const u8,
            path: []const u8,
            config: Config,
        ) !Self {
            var key_bytes: [16]u8 = undefined;
            io.random(&key_bytes);
            var key_storage: [32]u8 = undefined;
            const key = std.base64.standard.Encoder.encode(
                &key_storage,
                &key_bytes,
            );

            var request: [512]u8 = undefined;
            const request_head = try std.fmt.bufPrint(
                &request,
                "GET {s} HTTP/1.1\r\n" ++
                    "Host: {s}\r\n" ++
                    "Upgrade: websocket\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Sec-WebSocket-Key: {s}\r\n" ++
                    "Sec-WebSocket-Version: 13\r\n\r\n",
                .{ path, host, key },
            );
            try inner.writeAll(request_head);

            var response_storage: [8192]u8 = undefined;
            const max_head = @min(
                config.max_head_bytes,
                response_storage.len,
            );
            const response = try readHead(
                inner,
                response_storage[0..max_head],
            );
            try validateAccept(response, key);
            return init(allocator, io, inner, config, false, true);
        }

        fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            inner: *Inner,
            config: Config,
            mask_incoming: bool,
            mask_outgoing: bool,
        ) !Self {
            if (config.max_frame_payload == 0) return error.BufferTooSmall;
            const frame = try allocator.alloc(u8, config.max_frame_payload);
            errdefer allocator.free(frame);
            const write_buffer = try allocator.alloc(
                u8,
                config.max_frame_payload,
            );
            return .{
                .allocator = allocator,
                .io = io,
                .inner = inner,
                .frame = frame,
                .write_buffer = write_buffer,
                .mask_incoming = mask_incoming,
                .mask_outgoing = mask_outgoing,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.frame);
            self.allocator.free(self.write_buffer);
            self.* = undefined;
        }

        pub fn read(self: *Self, output: []u8) !usize {
            if (self.frame_start < self.frame_end) {
                return self.copyFrame(output);
            }
            if (self.closed) return 0;
            if (!try self.readNextDataFrame()) {
                self.closed = true;
                return 0;
            }
            return self.copyFrame(output);
        }

        fn copyFrame(self: *Self, output: []u8) usize {
            const available = self.frame_end - self.frame_start;
            const take = @min(available, output.len);
            @memcpy(
                output[0..take],
                self.frame[self.frame_start..][0..take],
            );
            self.frame_start += take;
            return take;
        }

        pub fn writeAll(self: *Self, bytes: []const u8) !void {
            var offset: usize = 0;
            while (offset < bytes.len) {
                const take = @min(bytes.len - offset, self.write_buffer.len);
                try self.writeFrame(0x02, bytes[offset..][0..take], true);
                offset += take;
            }
        }

        fn writeFrame(
            self: *Self,
            opcode: u8,
            payload: []const u8,
            fin: bool,
        ) !void {
            var header: [10]u8 = undefined;
            var header_len: usize = 0;
            const fin_byte: u8 = if (fin) 0x80 else 0;
            header[0] = fin_byte | opcode;
            const mask_bit: u8 = if (self.mask_outgoing) 0x80 else 0;
            if (payload.len <= 125) {
                header[1] = mask_bit | @as(u8, @intCast(payload.len));
                header_len = 2;
            } else if (payload.len <= 0xffff) {
                header[1] = mask_bit | 126;
                std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
                header_len = 4;
            } else {
                header[1] = mask_bit | 127;
                std.mem.writeInt(u64, header[2..10], payload.len, .big);
                header_len = 10;
            }

            var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
            if (self.mask_outgoing) {
                self.io.random(&mask_key);
                @memcpy(header[header_len..][0..4], &mask_key);
                header_len += 4;
                for (payload, 0..) |byte, index| {
                    self.write_buffer[index] = byte ^ mask_key[index % 4];
                }
                try self.inner.writeAll(header[0..header_len]);
                try self.inner.writeAll(self.write_buffer[0..payload.len]);
            } else {
                try self.inner.writeAll(header[0..header_len]);
                try self.inner.writeAll(payload);
            }
        }

        /// Returns false when the peer closed the stream cleanly.
        fn readNextDataFrame(self: *Self) !bool {
            while (true) {
                var header: [2]u8 = undefined;
                const header_read = try readExactAllowEof(self.inner, &header);
                if (header_read == 0) return false;
                if (header_read != 2) return error.TruncatedFrame;
                const opcode = header[0] & 0x0f;
                const masked = (header[1] & 0x80) != 0;
                if ((header[0] & 0x70) != 0) return error.InvalidFrame;
                var payload_len: usize = header[1] & 0x7f;
                if (payload_len == 126) {
                    var extended: [2]u8 = undefined;
                    try readExact(self.inner, &extended);
                    payload_len = std.mem.readInt(u16, &extended, .big);
                } else if (payload_len == 127) {
                    var extended: [8]u8 = undefined;
                    try readExact(self.inner, &extended);
                    const value = std.mem.readInt(u64, &extended, .big);
                    if (value > self.frame.len) return error.FrameTooLarge;
                    payload_len = @intCast(value);
                }
                if (payload_len > self.frame.len) return error.FrameTooLarge;
                if (masked and !self.mask_incoming) {
                    // A server frame must not be masked.
                    return error.InvalidFrame;
                }
                if (!masked and self.mask_incoming) {
                    return error.UnmaskedFrame;
                }

                var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
                if (masked) try readExact(self.inner, &mask_key);
                try readExact(self.inner, self.frame[0..payload_len]);
                if (masked) {
                    for (self.frame[0..payload_len], 0..) |*byte, index| {
                        byte.* ^= mask_key[index % 4];
                    }
                }

                switch (opcode) {
                    0x00, 0x01, 0x02 => {
                        self.frame_start = 0;
                        self.frame_end = payload_len;
                        return true;
                    },
                    0x08 => {
                        self.writeFrame(0x08, self.frame[0..payload_len], true) catch {};
                        return false;
                    },
                    0x09 => {
                        try self.writeFrame(0x0a, self.frame[0..payload_len], true);
                    },
                    0x0a => {},
                    else => return error.InvalidFrame,
                }
            }
        }
    };
}

fn readHead(inner: anytype, storage: []u8) ![]const u8 {
    var used: usize = 0;
    while (used < storage.len) {
        const count = try inner.read(storage[used..][0..1]);
        if (count == 0) return error.InvalidUpgrade;
        used += 1;
        if (used >= 4 and std.mem.endsWith(u8, storage[0..used], "\r\n\r\n")) {
            return storage[0..used];
        }
    }
    return error.BufferTooSmall;
}

fn readExact(inner: anytype, output: []u8) !void {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try inner.read(output[offset..]);
        if (count == 0) return error.TruncatedFrame;
        offset += count;
    }
}

fn readExactAllowEof(inner: anytype, output: []u8) !usize {
    var offset: usize = 0;
    while (offset < output.len) {
        const count = try inner.read(output[offset..]);
        if (count == 0) return offset;
        offset += count;
    }
    return offset;
}

fn validateUpgrade(head: []const u8, path: ?[]const u8) ![]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const request_line = lines.next() orelse return error.InvalidUpgrade;
    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method = parts.next() orelse return error.InvalidUpgrade;
    const target = parts.next() orelse return error.InvalidUpgrade;
    const version = parts.next() orelse return error.InvalidUpgrade;
    if (!std.mem.eql(u8, method, "GET")) return error.UnsupportedMethod;
    if (!std.mem.eql(u8, version, "HTTP/1.1")) {
        return error.UnsupportedVersion;
    }
    if (path) |expected| {
        if (!std.mem.eql(u8, target, expected)) return error.InvalidUpgrade;
    }

    var upgrade = false;
    var connection_upgrade = false;
    var key: ?[]const u8 = null;
    var ws_version = false;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse
            return error.InvalidUpgrade;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Upgrade")) {
            upgrade = std.ascii.eqlIgnoreCase(value, "websocket");
        } else if (std.ascii.eqlIgnoreCase(name, "Connection")) {
            connection_upgrade = headerHasToken(value, "upgrade");
        } else if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Key")) {
            key = value;
        } else if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Version")) {
            ws_version = std.mem.eql(u8, value, "13");
        }
    }
    if (!upgrade or !connection_upgrade) {
        return error.MissingUpgradeHeader;
    }
    if (!ws_version) return error.UnsupportedVersion;
    const key_value = key orelse return error.InvalidKey;
    if (key_value.len != 24) return error.InvalidKey;
    return key_value;
}

fn validateAccept(head: []const u8, key: []const u8) !void {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    const status_line = lines.next() orelse return error.InvalidUpgrade;
    if (!std.mem.startsWith(u8, status_line, "HTTP/1.1 101")) {
        return error.InvalidUpgrade;
    }
    var accept: ?[]const u8 = null;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.findScalar(u8, line, ':') orelse
            return error.InvalidUpgrade;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (std.ascii.eqlIgnoreCase(name, "Sec-WebSocket-Accept")) {
            accept = value;
        }
    }
    const expected = try acceptValue(key);
    if (accept == null or !std.mem.eql(u8, accept.?, &expected)) {
        return error.InvalidAccept;
    }
}

fn sendAccept(inner: anytype, key: []const u8) !void {
    const accept = try acceptValue(key);
    var response: [256]u8 = undefined;
    const head = try std.fmt.bufPrint(
        &response,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    );
    try inner.writeAll(head);
}

fn acceptValue(key: []const u8) ![28]u8 {
    var input: [24 + websocket_guid.len]u8 = undefined;
    @memcpy(input[0..key.len], key);
    @memcpy(input[key.len..][0..websocket_guid.len], websocket_guid);
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(input[0 .. key.len + websocket_guid.len], &digest, .{});
    var encoded: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&encoded, &digest);
    return encoded;
}

fn headerHasToken(value: []const u8, token: []const u8) bool {
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t");
        if (std.ascii.eqlIgnoreCase(trimmed, token)) return true;
    }
    return false;
}

test "WebSocket accept value matches RFC 6455 example" {
    const accept = try acceptValue("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings(
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        &accept,
    );
}

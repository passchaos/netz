//! Bounded HTTP Content-Encoding parsing and whole-representation decoding.
//!
//! RFC 9110 lists codings in the order they were applied. Decoding therefore
//! walks the list in reverse. The caller-buffer API uses two disjoint buffers
//! for stacked codings and always returns the final representation in `out`.

const std = @import("std");
const vort = @import("vort");

pub const max_codings: usize = 8;
pub const accept_encoding = "gzip, deflate, br, zstd";

pub const Error = std.mem.Allocator.Error || error{
    InvalidContentEncoding,
    UnsupportedContentEncoding,
    TooManyContentEncodings,
    DecodedBodyTooLarge,
    AliasedBuffers,
};

pub const Coding = enum {
    identity,
    gzip,
    deflate,
    br,
    zstd,

    pub fn name(self: Coding) []const u8 {
        return switch (self) {
            .identity => "identity",
            .gzip => "gzip",
            .deflate => "deflate",
            .br => "br",
            .zstd => "zstd",
        };
    }
};

pub const DecodedBody = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: *DecodedBody, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
        self.* = undefined;
    }
};

pub const Chain = struct {
    storage: [max_codings]Coding = undefined,
    len: u4 = 0,

    pub fn items(self: *const Chain) []const Coding {
        return self.storage[0..self.len];
    }

    pub fn encoded(self: Chain) bool {
        for (self.items()) |coding| {
            if (coding != .identity) return true;
        }
        return false;
    }

    /// Decode a complete representation with a hard bound on every decoded
    /// layer. An absent encoding, or an explicit `identity`, borrows `input`.
    pub fn decodeAlloc(
        self: Chain,
        allocator: std.mem.Allocator,
        input: []const u8,
        max_output_len: usize,
    ) Error!DecodedBody {
        if (!self.encoded()) {
            if (input.len > max_output_len) {
                return error.DecodedBodyTooLarge;
            }
            return .{ .bytes = input };
        }

        var current = input;
        var owned: ?[]u8 = null;
        errdefer if (owned) |bytes| allocator.free(bytes);
        var index: usize = self.len;
        while (index != 0) {
            index -= 1;
            const coding = self.storage[index];
            if (coding == .identity) continue;
            const decoded = decodeOneAlloc(
                allocator,
                coding,
                current,
                max_output_len,
            ) catch |err| return mapDecodeError(err);
            if (owned) |bytes| allocator.free(bytes);
            owned = decoded;
            current = decoded;
        }
        return .{ .bytes = current, .owned = owned };
    }

    /// Decode into caller-owned storage. `scratch` is required only when two
    /// or more non-identity codings are stacked. The final bytes always reside
    /// in `out`; all input and workspace slices must be disjoint.
    pub fn decodeInto(
        self: Chain,
        input: []const u8,
        out: []u8,
        scratch: []u8,
    ) Error![]u8 {
        const decode_count = self.decodeCount();
        if (decode_count == 0) {
            if (input.len > out.len) return error.DecodedBodyTooLarge;
            if (slicesOverlap(input, out)) return error.AliasedBuffers;
            @memcpy(out[0..input.len], input);
            return out[0..input.len];
        }
        if (slicesOverlap(input, out) or
            (decode_count > 1 and slicesOverlap(input, scratch)) or
            (decode_count > 1 and slicesOverlap(out, scratch)))
        {
            return error.AliasedBuffers;
        }

        var current = input;
        var remaining = decode_count;
        var index: usize = self.len;
        while (index != 0) {
            index -= 1;
            const coding = self.storage[index];
            if (coding == .identity) continue;
            const destination_storage = if ((remaining & 1) == 1)
                out
            else
                scratch;
            const destination = destination_storage[0..@min(
                destination_storage.len,
                out.len,
            )];
            const written = decodeOneInto(
                coding,
                current,
                destination,
            ) catch |err| return mapDecodeError(err);
            current = destination[0..written];
            remaining -= 1;
        }
        std.debug.assert(current.ptr == out.ptr);
        return out[0..current.len];
    }

    fn decodeCount(self: Chain) usize {
        var count: usize = 0;
        for (self.items()) |coding| count += @intFromBool(coding != .identity);
        return count;
    }

    fn appendValue(self: *Chain, value: []const u8) Error!void {
        var members = std.mem.splitScalar(u8, value, ',');
        while (members.next()) |raw_member| {
            const member = std.mem.trim(u8, raw_member, " \t");
            if (member.len == 0 or !validToken(member)) {
                return error.InvalidContentEncoding;
            }
            if (self.len == max_codings) {
                return error.TooManyContentEncodings;
            }
            self.storage[self.len] = parseCoding(member) orelse
                return error.UnsupportedContentEncoding;
            self.len += 1;
        }
    }
};

/// Parse one combined Content-Encoding field. `null` means identity.
pub fn parse(value: ?[]const u8) Error!Chain {
    var result: Chain = .{};
    if (value) |encoded| try result.appendValue(encoded);
    return result;
}

/// Parse every Content-Encoding field in wire order. Header elements only
/// need public `name` and `value` byte-slice fields, so this works with the
/// HTTP/1, HPACK, and QPACK header representations.
pub fn parseHeaders(headers: anytype) Error!Chain {
    var result: Chain = .{};
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "content-encoding")) {
            try result.appendValue(header.value);
        }
    }
    return result;
}

pub fn decodeHeadersAlloc(
    allocator: std.mem.Allocator,
    headers: anytype,
    input: []const u8,
    max_output_len: usize,
) Error!DecodedBody {
    return (try parseHeaders(headers)).decodeAlloc(
        allocator,
        input,
        max_output_len,
    );
}

pub fn decodeHeadersInto(
    headers: anytype,
    input: []const u8,
    out: []u8,
    scratch: []u8,
) Error![]u8 {
    return (try parseHeaders(headers)).decodeInto(
        input,
        out,
        scratch,
    );
}

fn parseCoding(value: []const u8) ?Coding {
    if (std.ascii.eqlIgnoreCase(value, "identity")) return .identity;
    if (std.ascii.eqlIgnoreCase(value, "gzip") or
        std.ascii.eqlIgnoreCase(value, "x-gzip")) return .gzip;
    if (std.ascii.eqlIgnoreCase(value, "deflate")) return .deflate;
    if (std.ascii.eqlIgnoreCase(value, "br")) return .br;
    if (std.ascii.eqlIgnoreCase(value, "zstd")) return .zstd;
    return null;
}

fn validToken(value: []const u8) bool {
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte)) continue;
        switch (byte) {
            '!',
            '#',
            '$',
            '%',
            '&',
            '\'',
            '*',
            '+',
            '-',
            '.',
            '^',
            '_',
            '`',
            '|',
            '~',
            => {},
            else => return false,
        }
    }
    return true;
}

fn decodeOneAlloc(
    allocator: std.mem.Allocator,
    coding: Coding,
    input: []const u8,
    max_output_len: usize,
) ![]u8 {
    return switch (coding) {
        .identity => unreachable,
        .gzip => vort.decodeGzipConcatenatedAllocLimited(
            allocator,
            input,
            max_output_len,
        ),
        .deflate => vort.decodeZlibAllocLimited(
            allocator,
            input,
            max_output_len,
        ),
        .br => vort.brDecodeStreamAllocLimited(
            allocator,
            input,
            max_output_len,
        ),
        .zstd => vort.zstdDecodeConcatenatedFrameAllocLimited(
            allocator,
            input,
            max_output_len,
        ),
    };
}

fn decodeOneInto(
    coding: Coding,
    input: []const u8,
    output: []u8,
) !usize {
    return switch (coding) {
        .identity => unreachable,
        .gzip => vort.decodeGzipConcatenated(
            input,
            output,
        ),
        .deflate => vort.decodeZlib(input, output),
        .br => vort.brDecodeStreamIntoLimited(
            input,
            output,
            output.len,
        ),
        .zstd => vort.zstdDecodeConcatenatedFrameIntoLimited(
            input,
            output,
            output.len,
        ),
    };
}

fn mapDecodeError(err: anyerror) Error {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.OutputTooSmall, error.OutputLimitExceeded => error.DecodedBodyTooLarge,
        else => error.InvalidContentEncoding,
    };
}

fn slicesOverlap(a: []const u8, b: []const u8) bool {
    if (a.len == 0 or b.len == 0) return false;
    const a_start = @intFromPtr(a.ptr);
    const b_start = @intFromPtr(b.ptr);
    return a_start < b_start +| b.len and b_start < a_start +| a.len;
}

test "HTTP content coding parses repeated and stacked fields" {
    const Header = struct { name: []const u8, value: []const u8 };
    const chain = try parseHeaders(&[_]Header{
        .{ .name = "Content-Encoding", .value = "deflate, gzip" },
        .{ .name = "content-encoding", .value = "BR, zstd" },
    });
    try std.testing.expectEqualSlices(
        Coding,
        &.{ .deflate, .gzip, .br, .zstd },
        chain.items(),
    );
    try std.testing.expect(chain.encoded());
    try std.testing.expectEqualStrings("gzip", Coding.gzip.name());
    try std.testing.expectEqual(
        Coding.gzip,
        (try parse("x-gzip")).items()[0],
    );
    const identity = try parse(null);
    try std.testing.expect(!identity.encoded());
    var borrowed = try identity.decodeAlloc(
        std.testing.allocator,
        "plain",
        5,
    );
    defer borrowed.deinit(std.testing.allocator);
    try std.testing.expect(borrowed.owned == null);
    try std.testing.expectEqualStrings("plain", borrowed.bytes);
    try std.testing.expectError(
        error.InvalidContentEncoding,
        parse("gzip,,br"),
    );
    try std.testing.expectError(
        error.InvalidContentEncoding,
        parse("gzip;level=1"),
    );
    try std.testing.expectError(
        error.UnsupportedContentEncoding,
        parse("compress"),
    );
    try std.testing.expectError(
        error.TooManyContentEncodings,
        parse("gzip,gzip,gzip,gzip,gzip,gzip,gzip,gzip,gzip"),
    );
}

test "HTTP content coding decodes Vort gzip deflate Brotli and Zstandard" {
    const allocator = std.testing.allocator;
    const payload = "bounded HTTP content decoding " ** 32;

    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    try expectDecoded(allocator, .deflate, zlib, payload);

    const gzip = try vort.encodeGzipStoredAlloc(allocator, payload);
    defer allocator.free(gzip);
    try expectDecoded(allocator, .gzip, gzip, payload);

    const brotli = try vort.brEncodeStoredStreamAlloc(allocator, payload);
    defer allocator.free(brotli);
    try expectDecoded(allocator, .br, brotli, payload);

    const zstd = try vort.zstdEncodeNativeFrameAlloc(allocator, payload);
    defer allocator.free(zstd);
    try expectDecoded(allocator, .zstd, zstd, payload);
}

test "HTTP content coding reverses stacked encodings into caller buffers" {
    const allocator = std.testing.allocator;
    const payload = "stacked HTTP representation " ** 16;
    const zlib = try vort.encodeZlibStoredAlloc(allocator, payload);
    defer allocator.free(zlib);
    const gzip = try vort.encodeGzipStoredAlloc(allocator, zlib);
    defer allocator.free(gzip);

    const chain = try parse("deflate, gzip");
    var output: [2048]u8 = undefined;
    var scratch: [2048]u8 = undefined;
    const decoded = try chain.decodeInto(gzip, &output, &scratch);
    try std.testing.expectEqualStrings(payload, decoded);

    var owned = try chain.decodeAlloc(allocator, gzip, output.len);
    defer owned.deinit(allocator);
    try std.testing.expectEqualStrings(payload, owned.bytes);
    try std.testing.expect(owned.owned != null);

    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        chain.decodeInto(gzip, output[0 .. payload.len - 1], &scratch),
    );
    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        chain.decodeInto(gzip, &output, scratch[0 .. zlib.len - 1]),
    );
    try std.testing.expectError(
        error.AliasedBuffers,
        chain.decodeInto(gzip, &output, &output),
    );
}

fn expectDecoded(
    allocator: std.mem.Allocator,
    coding: Coding,
    encoded: []const u8,
    expected: []const u8,
) !void {
    var chain: Chain = .{};
    chain.storage[0] = coding;
    chain.len = 1;
    var decoded = try chain.decodeAlloc(
        allocator,
        encoded,
        expected.len,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings(expected, decoded.bytes);

    var output: [2048]u8 = undefined;
    const into = try chain.decodeInto(encoded, &output, &.{});
    try std.testing.expectEqualStrings(expected, into);
    try std.testing.expectError(
        error.DecodedBodyTooLarge,
        chain.decodeAlloc(allocator, encoded, expected.len - 1),
    );
}

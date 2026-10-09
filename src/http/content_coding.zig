//! Bounded HTTP Content-Encoding parsing and whole-representation decoding.
//!
//! RFC 9110 lists codings in the order they were applied. Decoding therefore
//! walks the list in reverse. The caller-buffer API uses two disjoint buffers
//! for stacked codings and always returns the final representation in `out`.

const std = @import("std");
const vort = @import("vort");
const streaming = @import("content_coding/stream.zig");

pub const max_codings: usize = 8;
pub const accept_encoding = "gzip, deflate, br, zstd";

pub const Error = std.mem.Allocator.Error || error{
    InvalidContentEncoding,
    UnsupportedContentEncoding,
    TooManyContentEncodings,
    DecodedBodyTooLarge,
    EncodedBodyTooLarge,
    /// Retained for source compatibility; stacked streams are now supported.
    StreamingStackUnsupported,
    InvalidDecoderState,
    AliasedBuffers,
};

pub const StreamStatus = streaming.Status;
pub const StreamResult = streaming.Result;
pub const StreamOptions = streaming.Options;

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

    /// Build a progressive decoder for the complete encoding chain. Stacked
    /// codings are decoded in reverse application order through bounded
    /// intermediate queues allocated once during initialization.
    pub fn streamDecoder(
        self: Chain,
        allocator: std.mem.Allocator,
        options: StreamOptions,
    ) Error!StreamDecoder {
        return StreamDecoder.initChain(allocator, self.items(), options);
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

pub const StreamDecoder = streaming.Decoder(
    Coding,
    Error,
    mapDecodeError,
    max_codings,
);

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

//! gRPC per-message compression and accepted-encoding negotiation.
//!
//! Each compressed gRPC message is an independent gzip or zlib stream. No
//! compressor state is retained across messages, which is both required by
//! the protocol and important for per-message compression opt-out.

const std = @import("std");
const vort = @import("vort");

pub const Error = error{
    CompressionFailed,
    DecompressedMessageTooLarge,
    DecompressionFailed,
    InvalidCompressionLevel,
    UnsupportedCompression,
} || std.mem.Allocator.Error;

pub const Algorithm = enum {
    identity,
    deflate,
    gzip,

    pub fn name(self: Algorithm) []const u8 {
        return switch (self) {
            .identity => "identity",
            .deflate => "deflate",
            .gzip => "gzip",
        };
    }

    pub fn parse(value: []const u8) ?Algorithm {
        inline for (std.enums.values(Algorithm)) |algorithm| {
            if (std.mem.eql(u8, value, algorithm.name())) {
                return algorithm;
            }
        }
        return null;
    }
};

/// The peer's advertised message decoders. Identity is always available:
/// gRPC peers may send any individual message with its compressed flag clear.
pub const AlgorithmSet = struct {
    deflate: bool = false,
    gzip: bool = false,

    pub const supported: AlgorithmSet = .{
        .deflate = true,
        .gzip = true,
    };

    pub fn contains(self: AlgorithmSet, algorithm: Algorithm) bool {
        return switch (algorithm) {
            .identity => true,
            .deflate => self.deflate,
            .gzip => self.gzip,
        };
    }

    pub fn insert(self: *AlgorithmSet, algorithm: Algorithm) void {
        switch (algorithm) {
            .identity => {},
            .deflate => self.deflate = true,
            .gzip => self.gzip = true,
        }
    }
};

/// Parses `grpc-accept-encoding`, ignoring extensions unknown to netz.
///
/// Unknown entries cannot be selected by this implementation but must not
/// hide known entries in the same comma-separated field.
pub fn parseAcceptEncoding(value: ?[]const u8) AlgorithmSet {
    var result: AlgorithmSet = .{};
    var tokens = std.mem.splitScalar(u8, value orelse "", ',');
    while (tokens.next()) |token| {
        if (Algorithm.parse(std.mem.trim(u8, token, " \t"))) |algorithm| {
            result.insert(algorithm);
        }
    }
    return result;
}

pub fn formatAcceptEncodingInto(
    out: []u8,
    algorithms: AlgorithmSet,
) error{BufferTooSmall}![]u8 {
    var used: usize = 0;
    for ([_]Algorithm{
        .identity,
        .deflate,
        .gzip,
    }) |algorithm| {
        if (!algorithms.contains(algorithm)) continue;
        const delimiter: []const u8 = if (used == 0) "" else ",";
        const required = delimiter.len + algorithm.name().len;
        if (out.len -| used < required) return error.BufferTooSmall;
        @memcpy(out[used..][0..delimiter.len], delimiter);
        used += delimiter.len;
        @memcpy(out[used..][0..algorithm.name().len], algorithm.name());
        used += algorithm.name().len;
    }
    return out[0..used];
}

/// Compression output borrows the input when identity was selected or when
/// the wrapper would not reduce the message size. This mirrors gRPC Core and
/// avoids increasing bandwidth for tiny or incompressible messages.
pub const EncodedPayload = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,
    compressed: bool = false,

    pub fn deinit(self: *EncodedPayload, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
        self.* = undefined;
    }
};

pub fn compressAlloc(
    allocator: std.mem.Allocator,
    algorithm: Algorithm,
    input: []const u8,
    level: u4,
) Error!EncodedPayload {
    if (algorithm == .identity) {
        return .{ .bytes = input };
    }
    if (level > 9) return error.InvalidCompressionLevel;

    // gRPC "deflate" is an RFC 1950 zlib wrapper, never a raw RFC 1951
    // stream. Vort's strict wrapper encoders make that distinction explicit.
    const encoded = switch (algorithm) {
        .identity => unreachable,
        .deflate => vort.encodeZlibLevelAlloc(
            allocator,
            input,
            level,
        ),
        .gzip => vort.encodeGzipLevelAlloc(
            allocator,
            input,
            level,
        ),
    } catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.InvalidBlockPlan => return error.InvalidCompressionLevel,
        else => return error.CompressionFailed,
    };
    if (encoded.len >= input.len) {
        allocator.free(encoded);
        return .{ .bytes = input };
    }
    return .{
        .bytes = encoded,
        .owned = encoded,
        .compressed = true,
    };
}

pub const DecodedPayload = struct {
    bytes: []const u8,
    owned: ?[]u8 = null,

    pub fn deinit(self: *DecodedPayload, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
        self.* = undefined;
    }
};

/// Decodes exactly one wrapper stream and caps the materialized message.
///
/// The strict Vort entry points validate checksums and reject trailing bytes.
/// That prevents accepting a valid first member followed by smuggled data and
/// matches gRPC Core's "all input consumed" requirement.
pub fn decompressAlloc(
    allocator: std.mem.Allocator,
    algorithm: Algorithm,
    input: []const u8,
    max_output_len: usize,
) Error!DecodedPayload {
    if (algorithm == .identity) {
        if (input.len > max_output_len) {
            return error.DecompressedMessageTooLarge;
        }
        return .{ .bytes = input };
    }
    const decoded = switch (algorithm) {
        .identity => unreachable,
        .deflate => vort.decodeZlibAllocLimited(
            allocator,
            input,
            max_output_len,
        ),
        .gzip => decodeGzipAllocLimitedStrict(
            allocator,
            input,
            max_output_len,
        ),
    } catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.OutputLimitExceeded => {
            return error.DecompressedMessageTooLarge;
        },
        else => return error.DecompressionFailed,
    };
    return .{ .bytes = decoded, .owned = decoded };
}

fn decodeGzipAllocLimitedStrict(
    allocator: std.mem.Allocator,
    input: []const u8,
    max_output_len: usize,
) ![]u8 {
    // Use the bounded append decoder so the wrapper is located and validated
    // before ownership is transferred. It consumes exactly one gzip member,
    // verifies CRC/ISIZE, and rejects any bytes after that member.
    var decoded: std.ArrayList(u8) = .empty;
    errdefer decoded.deinit(allocator);
    _ = try vort.decodeGzipAppendLimited(
        allocator,
        &decoded,
        input,
        max_output_len,
    );
    return decoded.toOwnedSlice(allocator);
}

//! gRPC per-message compression and accepted-encoding negotiation.
//!
//! Each compressed gRPC message is an independent gzip or zlib stream. No
//! compressor state is retained across messages, which is both required by
//! the protocol and important for per-message compression opt-out.

const std = @import("std");
const deflate = @import("../internal/deflate.zig");

test {
    _ = @import("compression/negotiation_tests.zig");
}

pub const Error = error{
    CompressionFailed,
    DecompressedMessageTooLarge,
    DecompressionFailed,
    InvalidCompressionLevel,
    UnsupportedCompression,
} || std.mem.Allocator.Error;

pub const Algorithm = @import("compression/algorithm.zig").Algorithm;
pub const AlgorithmSet = @import("compression/algorithm.zig").AlgorithmSet;
pub const parseAcceptEncoding = @import("compression/negotiation.zig").parseValue;
pub const parseAcceptEncodingFields = @import("compression/negotiation.zig").parseFields;
pub const formatAcceptEncodingInto = @import("compression/negotiation.zig").formatInto;

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
    // stream. The strict wrapper encoders make that distinction explicit.
    const encoded = switch (algorithm) {
        .identity => unreachable,
        .deflate => deflate.encodeZlibLevelAlloc(
            allocator,
            input,
            level,
        ),
        .gzip => deflate.encodeGzipLevelAlloc(
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
/// The strict codec entry points validate checksums and reject trailing bytes.
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
        .deflate => deflate.decodeZlibAllocLimited(
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
    _ = try deflate.decodeGzipAppendLimited(
        allocator,
        &decoded,
        input,
        max_output_len,
    );
    return decoded.toOwnedSlice(allocator);
}

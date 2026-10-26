//! gRPC message compression algorithms and accepted decoder capabilities.
const std = @import("std");

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

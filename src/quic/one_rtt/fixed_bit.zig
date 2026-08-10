//! RFC 9287 QUIC Bit emission state for established connections.
//!
//! One secure seed per connection avoids a system entropy call for every
//! packet while preserving an unpredictable sequence. Disabled connections
//! retain the RFC 9000 value of one without initializing random state.

const std = @import("std");

pub const Generator = struct {
    csprng: ?std.Random.DefaultCsprng = null,

    pub fn init(
        io: std.Io,
        enable_greasing: bool,
    ) std.Io.RandomSecureError!Generator {
        if (!enable_greasing) return .{};
        var seed: [std.Random.DefaultCsprng.secret_seed_length]u8 =
            undefined;
        defer std.crypto.secureZero(u8, &seed);
        try std.Io.randomSecure(io, &seed);
        return .{ .csprng = .init(seed) };
    }

    pub fn deinit(self: *Generator) void {
        if (self.csprng) |*csprng| {
            std.crypto.secureZero(
                u8,
                std.mem.asBytes(csprng),
            );
        }
        self.* = undefined;
    }

    pub fn enabled(self: Generator) bool {
        return self.csprng != null;
    }

    pub fn next(self: *Generator) bool {
        const csprng = if (self.csprng) |*value| value else return true;
        return csprng.random().boolean();
    }
};

pub fn randomValue(
    io: std.Io,
    peer_supports: bool,
) std.Io.RandomSecureError!bool {
    if (!peer_supports) return true;
    var byte: [1]u8 = undefined;
    try std.Io.randomSecure(io, &byte);
    return (byte[0] & 1) != 0;
}

test "disabled fixed-bit generator retains the RFC 9000 value" {
    var generator = try Generator.init(undefined, false);
    defer generator.deinit();
    try std.testing.expect(!generator.enabled());
    try std.testing.expect(generator.next());
}

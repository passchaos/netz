//! Incremental message-content hashing with explicit byte and lifetime bounds.
const std = @import("std");
const types = @import("types.zig");
const Set = @import("value.zig").Set;

pub const Options = struct {
    algorithms: types.Algorithms = .{},
    max_content_bytes: usize = std.math.maxInt(usize),
};

pub const Hasher = struct {
    options: Options,
    sha256: std.crypto.hash.sha2.Sha256 = .init(.{}),
    sha512: std.crypto.hash.sha2.Sha512 = .init(.{}),
    bytes: usize = 0,
    finished: bool = false,

    pub fn init(options: Options) types.Error!Hasher {
        try options.algorithms.validate();
        return .{ .options = options };
    }

    /// Feed content after transfer decoding, before Content-Encoding decoding.
    /// Exceeding the quota changes no hash state or byte count.
    pub fn update(self: *Hasher, content: []const u8) types.Error!void {
        if (self.finished) return error.InvalidDigestState;
        if (content.len > self.options.max_content_bytes - self.bytes) return error.DigestContentTooLarge;
        if (self.options.algorithms.sha256) self.sha256.update(content);
        if (self.options.algorithms.sha512) self.sha512.update(content);
        self.bytes += content.len;
    }

    pub fn finish(self: *Hasher) types.Error!Set {
        if (self.finished) return error.InvalidDigestState;
        self.finished = true;
        var output: Set = .{};
        if (self.options.algorithms.sha256) {
            var bytes: [32]u8 = undefined;
            self.sha256.final(&bytes);
            output.sha256 = bytes;
        }
        if (self.options.algorithms.sha512) {
            var bytes: [64]u8 = undefined;
            self.sha512.final(&bytes);
            output.sha512 = bytes;
        }
        return output;
    }
};

pub fn compute(content: []const u8, algorithms: types.Algorithms) types.Error!Set {
    var hasher = try Hasher.init(.{ .algorithms = algorithms });
    try hasher.update(content);
    return hasher.finish();
}

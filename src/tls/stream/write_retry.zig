//! Identify the plaintext already committed to an interrupted TLS record.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Keep no caller pointer: framed transports may reconstruct the same bytes
/// in a different scratch buffer. Capture only when a record write stops.
pub const Fingerprint = struct {
    digest: [Sha256.digest_length]u8 = [_]u8{0} ** Sha256.digest_length,

    pub fn capture(self: *Fingerprint, plaintext: []const u8) void {
        Sha256.hash(plaintext, &self.digest, .{});
    }

    /// Check before socket I/O. The unaccepted tail may grow or change, but
    /// the prefix represented by the pending ciphertext must be identical.
    pub fn validate(self: *const Fingerprint, plaintext_len: usize, bytes: []const u8) error{WriteInProgress}!void {
        if (bytes.len < plaintext_len) return error.WriteInProgress;
        var actual: [Sha256.digest_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &actual);
        Sha256.hash(bytes[0..plaintext_len], &actual, .{});
        if (!std.crypto.timing_safe.eql([Sha256.digest_length]u8, self.digest, actual)) return error.WriteInProgress;
    }

    pub fn clear(self: *Fingerprint) void {
        std.crypto.secureZero(u8, &self.digest);
    }
};

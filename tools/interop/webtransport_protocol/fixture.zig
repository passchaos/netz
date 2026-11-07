const std = @import("std");
const netz = @import("netz");
pub const allocator = std.heap.c_allocator;
pub const escaped = "q\"u\\oted";
pub const escaped_available = "\"q\\\"u\\\\oted\", \"p1\"";
pub const escaped_selected = "\"q\\\"u\\\\oted\"";

pub fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

pub fn report(prefix: []const u8, value: anytype) !void {
    const json = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(json);
    std.debug.print("{s}{s}\n", .{ prefix, json });
}

pub const Identity = struct {
    certificate: []u8,
    key: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,

    pub fn load(io: std.Io, certificate_path: []const u8, scalar_path: []const u8) !Identity {
        const certificate = try std.Io.Dir.cwd().readFileAlloc(io, certificate_path, allocator, .limited(16 * 1024));
        errdefer allocator.free(certificate);
        // Leave one byte for the reader's EOF/overlength probe. An exact
        // 32-byte read limit can fail before EOF is observed in Zig 0.16.
        const scalar = try std.Io.Dir.cwd().readFileAlloc(io, scalar_path, allocator, .limited(33));
        defer allocator.free(scalar);
        if (scalar.len != 32) return error.InvalidIdentity;
        const secret = try std.crypto.sign.ecdsa.EcdsaP256Sha256.SecretKey.fromBytes(scalar[0..32].*);
        return .{ .certificate = certificate, .key = try std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair.fromSecretKey(secret) };
    }
    pub fn deinit(self: Identity) void {
        allocator.free(self.certificate);
    }
};

pub fn header(fields: []const netz.http3.Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (fields) |field| if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    return null;
}

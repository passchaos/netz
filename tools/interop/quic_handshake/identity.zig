//! File-backed P-256 identity shared by handshake benchmark servers.

const std = @import("std");
const netz = @import("netz");

const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

pub const Loaded = struct {
    certificate_der: []u8,
    certificate_chain: [1][]const u8,
    key_pair: EcdsaP256Sha256.KeyPair,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        certificate_path: []const u8,
        private_scalar_path: []const u8,
    ) !Loaded {
        const certificate_der = try std.Io.Dir.cwd().readFileAlloc(
            io,
            certificate_path,
            allocator,
            .limited(64 * 1024),
        );
        errdefer allocator.free(certificate_der);
        const private_scalar = try std.Io.Dir.cwd().readFileAlloc(
            io,
            private_scalar_path,
            allocator,
            .limited(EcdsaP256Sha256.SecretKey.encoded_length + 1),
        );
        defer allocator.free(private_scalar);
        defer std.crypto.secureZero(u8, private_scalar);
        if (private_scalar.len != EcdsaP256Sha256.SecretKey.encoded_length) {
            return error.InvalidPrivateKey;
        }
        const secret = try EcdsaP256Sha256.SecretKey.fromBytes(
            private_scalar[0..EcdsaP256Sha256.SecretKey.encoded_length].*,
        );
        return .{
            .certificate_der = certificate_der,
            .certificate_chain = .{certificate_der},
            .key_pair = try EcdsaP256Sha256.KeyPair.fromSecretKey(secret),
        };
    }

    pub fn deinit(self: *Loaded, allocator: std.mem.Allocator) void {
        allocator.free(self.certificate_der);
        self.* = undefined;
    }

    pub fn serverIdentity(
        self: *const Loaded,
    ) netz.quic.tls.auth.ServerIdentity {
        return .{
            .certificate_chain = &self.certificate_chain,
            .signer = .{ .ecdsa_p256_sha256 = .{
                .key_pair = self.key_pair,
            } },
        };
    }
};

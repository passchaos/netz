//! Built-in X.509 chain, validity, and hostname policy for TLS server auth.
//!
//! `SystemStore` loads the platform CA bundle once and then exposes a
//! zero-allocation verification callback suitable for `auth.ClientVerifier`.

const std = @import("std");
const auth = @import("auth.zig");

const Certificate = std.crypto.Certificate;

pub const BundleVerifier = struct {
    bundle: *const Certificate.Bundle,
    now_seconds: i64,

    pub fn clientVerifier(
        self: *const BundleVerifier,
    ) auth.ClientVerifier {
        return .{
            .verify_trust = verifyCallback,
            .context = @ptrCast(@constCast(self)),
        };
    }

    pub fn verify(
        self: BundleVerifier,
        trust_context: auth.TrustContext,
    ) !void {
        if (trust_context.chain.len == 0) {
            return error.EmptyCertificateChain;
        }
        const leaf = try parseCertificate(trust_context.chain[0]);
        const server_name = trust_context.server_name orelse
            return error.MissingServerName;
        try leaf.verifyHostName(server_name);

        var subject = leaf;
        for (trust_context.chain[1..]) |issuer_der| {
            const issuer = try parseCertificate(issuer_der);
            try subject.verify(issuer, self.now_seconds);
            subject = issuer;
        }
        try self.bundle.verify(subject, self.now_seconds);
    }

    fn verifyCallback(
        context: ?*anyopaque,
        trust_context: auth.TrustContext,
    ) anyerror!void {
        const self: *const BundleVerifier = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        try self.verify(trust_context);
    }
};

pub const SystemStore = struct {
    allocator: std.mem.Allocator,
    bundle: Certificate.Bundle = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        now: std.Io.Timestamp,
    ) Certificate.Bundle.RescanError!SystemStore {
        var result = SystemStore{ .allocator = allocator };
        errdefer result.deinit();
        try result.bundle.rescan(allocator, io, now);
        return result;
    }

    pub fn deinit(self: *SystemStore) void {
        self.bundle.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn verifier(
        self: *const SystemStore,
        now_seconds: i64,
    ) BundleVerifier {
        return .{
            .bundle = &self.bundle,
            .now_seconds = now_seconds,
        };
    }
};

fn parseCertificate(der: []const u8) !Certificate.Parsed {
    return Certificate.parse(.{
        .buffer = der,
        .index = 0,
    });
}

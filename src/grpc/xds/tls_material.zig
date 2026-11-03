//! Inline xDS cluster TLS material shared by EDS, STATIC and DNS projections.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const server_identity_file = @import("../../tls/server_identity_file.zig");

pub const VersionPolicy = tls_stream.VersionPolicy;

pub const Config = struct {
    server_name: []const u8 = "",
    trusted_ca: []const u8 = "",
    certificate_chain: []const u8 = "",
    private_key: []const u8 = "",
    version_policy: ?tls_stream.VersionPolicy = null,
};

pub const Error = std.mem.Allocator.Error || server_identity_file.Error || error{
    InvalidTlsMaterial,
    MissingPrivateKey,
    MissingCertificate,
};

pub const Material = struct {
    allocator: std.mem.Allocator,
    bundle: std.crypto.Certificate.Bundle = .empty,
    bundle_loaded: bool = false,
    lock: std.Io.RwLock = .init,
    identity: ?server_identity_file.Identity = null,
    server_name: []const u8 = "",
    version_policy: ?tls_stream.VersionPolicy = null,

    pub fn create(gpa: std.mem.Allocator, io: std.Io, config: Config) Error!*Material {
        if ((config.certificate_chain.len == 0) != (config.private_key.len == 0)) {
            return if (config.certificate_chain.len == 0) error.MissingCertificate else error.MissingPrivateKey;
        }
        const self = try gpa.create(Material);
        self.* = .{ .allocator = gpa, .server_name = config.server_name, .version_policy = config.version_policy };
        errdefer self.deinit();
        if (config.trusted_ca.len != 0) {
            addCerts(gpa, io, &self.bundle, config.trusted_ca) catch return error.InvalidTlsMaterial;
            if (self.bundle.map.count() == 0) return error.InvalidTlsMaterial;
            self.bundle_loaded = true;
        }
        if (config.certificate_chain.len != 0) {
            self.identity = server_identity_file.parse(gpa, config.certificate_chain, config.private_key) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return error.InvalidTlsMaterial,
            };
        }
        return self;
    }
    pub fn deinit(self: *Material) void {
        if (self.identity) |*identity| identity.deinit();
        self.bundle.deinit(self.allocator);
        self.allocator.destroy(self);
    }
    pub fn serverName(self: *const Material, fallback: []const u8) []const u8 {
        return if (self.server_name.len != 0) self.server_name else fallback;
    }
    pub fn options(self: *Material) http2.runtime.TlsConnectOptions {
        var result: http2.runtime.TlsConnectOptions = .{};
        if (self.version_policy) |policy| result.protocol_policy = policy;
        if (self.bundle_loaded) result.ca_bundle = .{ .bundle = &self.bundle, .lock = &self.lock };
        if (self.identity) |*identity| {
            const value = identity.serverIdentity();
            result.client_identity = .{
                .certificate_chain = value.certificate_chain,
                .signer = value.signer,
                .certificate_type = value.certificate_type,
            };
        }
        return result;
    }
};

fn addCerts(gpa: std.mem.Allocator, io: std.Io, bundle: *std.crypto.Certificate.Bundle, source: []const u8) !void {
    const now = std.Io.Clock.Timestamp.now(io, .real).raw.nanoseconds;
    const now_sec: i64 = @intCast(@divTrunc(now, std.time.ns_per_s));
    const begin_marker = "-----BEGIN CERTIFICATE-----";
    const end_marker = "-----END CERTIFICATE-----";
    if (std.mem.indexOf(u8, source, begin_marker) == null) {
        const start: u32 = @intCast(bundle.bytes.items.len);
        try bundle.bytes.ensureUnusedCapacity(gpa, source.len);
        bundle.bytes.appendSliceAssumeCapacity(source);
        try bundle.parseCert(gpa, start, now_sec);
        return;
    }
    const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
    var start_index: usize = 0;
    while (std.mem.indexOfPos(u8, source, start_index, begin_marker)) |begin| {
        const cert_start = begin + begin_marker.len;
        const cert_end = std.mem.indexOfPos(u8, source, cert_start, end_marker) orelse return error.InvalidTlsMaterial;
        start_index = cert_end + end_marker.len;
        const encoded = std.mem.trim(u8, source[cert_start..cert_end], " \t\r\n");
        try bundle.bytes.ensureUnusedCapacity(gpa, encoded.len / 4 * 3 + 1);
        const decoded_start: u32 = @intCast(bundle.bytes.items.len);
        const dest = bundle.bytes.allocatedSlice()[decoded_start..];
        const decoded_len = base64.decode(dest, encoded) catch return error.InvalidTlsMaterial;
        bundle.bytes.items.len += decoded_len;
        try bundle.parseCert(gpa, decoded_start, now_sec);
    }
}

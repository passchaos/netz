//! Stable ownership of the client handshake's trust store and verifier.
const std = @import("std");
const quic = @import("../mod.zig");
const roots = @import("../../trust.zig");
const loading = @import("../client_trust/loading.zig");

test {
    _ = @import("trust_completion_tests.zig");
}

pub const Error = loading.Error || error{HandshakeTimeout};

pub const Owner = struct {
    system_store: ?quic.tls.trust.SystemStore = null,
    bundle_verifier: ?quic.tls.trust.BundleVerifier = null,
    platform_verifier: ?quic.tls.platform.Verifier = null,
    verifier: ?quic.tls.auth.ClientVerifier = null,

    /// Initialize in its final address: verifier contexts borrow these fields.
    pub fn init(self: *Owner, allocator: std.mem.Allocator, io: std.Io, options: anytype) Error!void {
        self.* = .{};
        errdefer self.deinit();
        const deadline = options.handshake_recovery.deadline;
        try checkpoint(io, deadline);
        const now = std.Io.Timestamp.now(io, .real);
        self.verifier = options.server_auth orelse blk: {
            if (options.system_store) |store| {
                self.bundle_verifier = store.verifier(now.toSeconds());
                break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(self.bundle_verifier.?.clientVerifier());
            }
            if (options.root_source == .platform) {
                self.platform_verifier = loading.complete(io, deadline, quic.tls.platform.Verifier.init(allocator, .{})) catch |err| return sourceError(err);
                break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(self.platform_verifier.?.clientVerifier());
            }
            if (options.root_source == .bundled) {
                self.system_store = loading.complete(io, deadline, roots.initBundledStore(allocator, now)) catch |err| return sourceError(err);
            } else if (options.system_environ) |environ| {
                self.system_store = loading.systemBefore(allocator, io, now, environ, deadline) catch |err| return sourceError(err);
            } else break :blk null;
            self.bundle_verifier = self.system_store.?.verifier(now.toSeconds());
            break :blk quic.tls.auth.ClientVerifier.fromTrustVerifier(self.bundle_verifier.?.clientVerifier());
        };
        try checkpoint(io, deadline);
    }

    pub fn deinit(self: *Owner) void {
        if (self.platform_verifier) |*verifier| verifier.deinit();
        if (self.system_store) |*store| store.deinit();
        self.* = .{};
    }
};

fn sourceError(err: anyerror) Error {
    if (err == error.Timeout) return error.HandshakeTimeout;
    return loading.failure(err);
}

fn checkpoint(io: std.Io, deadline: ?std.Io.Clock.Timestamp) Error!void {
    loading.checkpoint(io, deadline) catch |err| return sourceError(err);
}

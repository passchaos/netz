//! Trust-root source selection shared by netz TLS clients.
//!
//! `root_source = .system` keeps the existing operating-system trust behavior.
//! `root_source = .bundled` uses the Mozilla CCADB TLS roots compiled into the
//! sibling `webpkiz` package, so HTTPS/WSS/MQTT/QUIC clients can run in
//! minimal containers without a system CA bundle.
//!
//! Precedence for callers that also configure explicit trust material:
//! `server_verifier` > `ca_bundle` > `system_store` > `root_source`.
//! `system_environ` refines `.system` only.

const std = @import("std");
const vail = @import("vail");
const webpkiz = @import("webpkiz");

pub const RootSource = enum {
    /// Load roots from the operating system, or from `SSL_CERT_FILE` /
    /// `SSL_CERT_DIR` when the caller supplies `system_environ`.
    system,
    /// Use the compiled-in Mozilla CCADB TLS root set.
    bundled,
};

pub const bundled_anchor_count = webpkiz.tls_server_anchors.len;

const bundled_anchors = blk: {
    var anchors: [webpkiz.tls_server_anchors.len]vail.x509.trust.BundledAnchor =
        undefined;
    for (webpkiz.tls_server_anchors, 0..) |anchor, index| {
        anchors[index] = .{
            .certificate_der = anchor.der,
            .name_constraints = anchor.name_constraints,
        };
    }
    break :blk anchors;
};

/// Build a Vail trust store from the compiled-in Mozilla roots. The store owns
/// its parsed certificates and must be deinitialized by the caller. Reuse one
/// store across handshakes when connection volume matters.
pub fn initBundledStore(
    allocator: std.mem.Allocator,
    now: std.Io.Timestamp,
) !vail.x509.trust.SystemStore {
    return vail.x509.trust.SystemStore.initBundled(
        allocator,
        &bundled_anchors,
        now,
    );
}

/// Build a Zig std certificate bundle from the compiled-in Mozilla roots.
///
/// Zig std cannot represent every root algorithm. Roots it skips remain
/// available through `initBundledStore` and Vail's compatibility verifier, so
/// prefer that path when complete Mozilla coverage is required.
pub fn initBundledBundle(
    allocator: std.mem.Allocator,
    now: std.Io.Timestamp,
) !std.crypto.Certificate.Bundle {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    errdefer bundle.deinit(allocator);
    const now_seconds = now.toSeconds();
    for (webpkiz.tls_server_anchors) |anchor| {
        const start = bundle.bytes.items.len;
        if (start > std.math.maxInt(u32)) {
            return error.CertificateAuthorityBundleTooBig;
        }
        try bundle.bytes.appendSlice(allocator, anchor.der);
        bundle.parseCert(
            allocator,
            @intCast(start),
            now_seconds,
        ) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => bundle.bytes.shrinkRetainingCapacity(start),
        };
    }
    if (bundle.map.count() == 0) return error.NoBundledTrustAnchors;
    return bundle;
}

test "bundled roots load into both trust representations" {
    const now = std.Io.Timestamp{
        .nanoseconds = @as(i96, 1_790_000_000) * std.time.ns_per_s,
    };

    var store = try initBundledStore(std.testing.allocator, now);
    defer store.deinit();
    try std.testing.expectEqual(
        bundled_anchor_count,
        store.compatibleAnchorCount() + store.bundle.map.count(),
    );

    const verifier = store.verifier(now.toSeconds());
    try std.testing.expectEqual(@as(usize, 1), verifier.anchor_constraints.len);
    try std.testing.expect(verifier.anchor_constraints[0].subject.len != 0);
    try std.testing.expect(verifier.anchor_constraints[0].name_constraints.len != 0);

    var bundle = try initBundledBundle(std.testing.allocator, now);
    defer bundle.deinit(std.testing.allocator);
    try std.testing.expect(bundle.map.count() > 0);
}

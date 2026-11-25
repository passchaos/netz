const std = @import("std");
const http = @import("../mod.zig");
const selection = @import("../client/protocol_selection.zig");

test "HTTP effective trust H3-only accepts a verifier over an inactive CA bundle" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    var lock: std.Io.RwLock = .init;
    var client = try http.Client.init(std.testing.allocator, std.testing.io, .{
        .protocol_policy = .http3_only,
        .tls = .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = @splat(7) },
            .ca_bundle = .{ .bundle = &bundle, .lock = &lock },
        },
    });
    defer client.deinit();
}

test "HTTP effective trust H3 preference attempts verifier policy before TCP fallback" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    var lock: std.Io.RwLock = .init;
    var failed = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var options: http.ClientOptions = .{
        .protocol_policy = .prefer_http3,
        .tls = .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = @splat(7) },
            .ca_bundle = .{ .bundle = &bundle, .lock = &lock },
        },
    };
    options.http3.handshake.handshake.original_destination_connection_id = "effective-origin";
    options.http3.handshake.handshake.local_connection_id = "effective-client";
    try std.testing.expectError(error.OutOfMemory, selection.selectHttp3(failed.allocator(), std.testing.io, try std.Uri.parse("https://effective-trust.test/"), options, null));
}

test "HTTP effective trust Alt-Svc pool accepts a verifier over an inactive CA bundle" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    var lock: std.Io.RwLock = .init;
    var pool = try http.Pool.init(std.testing.allocator, std.testing.io, .{
        .client = .{ .tls = .{
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = @splat(7) },
            .ca_bundle = .{ .bundle = &bundle, .lock = &lock },
        } },
        .http3 = .{},
    });
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 0), pool.http3ConnectionCount());
}

test "HTTP effective trust H3-only and Alt-Svc pool reject an active TCP CA bundle" {
    var bundle: std.crypto.Certificate.Bundle = .empty;
    defer bundle.deinit(std.testing.allocator);
    var lock: std.Io.RwLock = .init;
    const options: http.ClientOptions = .{
        .protocol_policy = .http3_only,
        .tls = .{
            .ca_bundle = .{ .bundle = &bundle, .lock = &lock },
            .root_source = .bundled,
        },
    };
    try std.testing.expectError(error.UnsupportedH3TrustConfiguration, http.Client.init(std.testing.allocator, std.testing.io, options));
    // The primary client permits TCP, but the Alt-Svc backend must still reject
    // an active bundle instead of authenticating H3 with lower-priority roots.
    var tcp_options = options;
    tcp_options.protocol_policy = .prefer_http2;
    try std.testing.expectError(error.UnsupportedH3TrustConfiguration, http.Pool.init(std.testing.allocator, std.testing.io, .{
        .client = tcp_options,
        .http3 = .{},
    }));
}

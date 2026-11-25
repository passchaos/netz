//! One membership list for grouped and isolated support test entry points.
const std = @import("std");
pub const Spec = struct {
    path: []const u8,
    imports: enum { none, netz, netz_vail } = .netz,
    force_libc: bool = false,
    apply_filters: bool = true,
    step: ?struct { name: []const u8, description: []const u8 } = null,
};

pub const all: []const Spec = &.{
    .{ .path = "tools/interop/quic_handshake_bench.zig", .imports = .netz_vail },
    .{ .path = "tools/interop/quic_persistent_bench.zig", .step = .{ .name = "test-quic-persistent-bench", .description = "Test persistent QUIC benchmark payload and config helpers" } },
    .{ .path = "tools/interop/quic_datagram_bench.zig" },
    .{ .path = "tools/interop/quic_quic_go_churn.zig" },
    .{ .path = "tools/interop/http3_quic_go_bench.zig" },
    .{ .path = "tools/interop/websocket_h3_quic_go_bench.zig" },
    .{ .path = "tools/interop/exact_certificate_verifier.zig" },
    .{ .path = "examples/support/websocket_send_shape.zig", .imports = .none },
    .{ .path = "examples/support/memory_limiter.zig", .imports = .none, .step = .{ .name = "test-mqtt-memory-limiter", .description = "Test the MQTT broker hard heap-allocation limit" } },
    .{ .path = "examples/support/mqtt_pid_file.zig", .imports = .none, .force_libc = true, .step = .{ .name = "test-mqtt-pid-file", .description = "Test configured MQTT broker PID-file ownership" } },
    .{ .path = "examples/support/mqtt_reloadable_security.zig", .step = .{ .name = "test-mqtt-reloadable-security", .description = "Test atomic MQTT password, ACL, and CRL file reloads" } },
    .{ .path = "examples/support/mqtt_reload_compatibility.zig", .step = .{ .name = "test-mqtt-reload-compatibility", .description = "Test exhaustive MQTT SIGHUP field classification" } },
    .{ .path = "examples/support/mqtt_reloadable_identity.zig", .step = .{ .name = "test-mqtt-reloadable-identity", .description = "Test atomic MQTT TLS identity, key password, client CA, and CRL reloads" } },
    .{ .path = "examples/support/mqtt_configured_bridges.zig", .step = .{ .name = "test-mqtt-configured-bridges", .description = "Test production MQTT bridge configuration adapters" } },
    .{ .path = "tools/interop/webtransport_wtransport_bench.zig" },
    .{ .path = "tools/interop/webtransport_browser_reset.zig", .apply_filters = false },
    .{ .path = "tools/interop/webtransport_churn_protocol.zig", .imports = .none },
};

/// Zig requires literal import operands. Reject registry/import drift while
/// keeping the root readable and the build flags/entry points in one place.
pub fn validateRoot(comptime source: []const u8) void {
    @setEvalBranchQuota(10000);
    var seen = [_]bool{false} ** all.len;
    var offset: usize = 0;
    const marker = "@import(\"";
    while (findImport(source, offset)) |found| {
        const start = found + marker.len;
        const end = start + (std.mem.indexOfScalar(u8, source[start..], '"') orelse @compileError("invalid support import"));
        const path = source[start..end];
        offset = end + 1;
        if (std.mem.eql(u8, path, "build/testing/support_specs.zig")) continue;
        const index = for (all, 0..) |spec, index| {
            if (std.mem.eql(u8, path, spec.path)) break index;
        } else @compileError("unregistered support root: " ++ path);
        if (seen[index]) @compileError("duplicate support import: " ++ path);
        seen[index] = true;
    }
    for (seen, all) |present, spec| {
        if (!present) @compileError("missing support root: " ++ spec.path);
    }
}

fn findImport(comptime source: []const u8, offset: usize) ?usize {
    const marker = "@import(\"";
    var index = offset;
    while (index + marker.len <= source.len) : (index += 1) {
        if (source[index] == '@' and std.mem.startsWith(u8, source[index..], marker)) return index;
    }
    return null;
}

//! Shared auxiliary test root; literal imports match the build registry.
const registry = @import("build/testing/support_specs.zig");
comptime {
    registry.validateRoot(@embedFile("support_test.zig"));
}

test {
    _ = @import("tools/interop/quic_handshake_bench.zig");
    _ = @import("tools/interop/quic_persistent_bench.zig");
    _ = @import("tools/interop/quic_datagram_bench.zig");
    _ = @import("tools/interop/quic_quic_go_churn.zig");
    _ = @import("tools/interop/http3_quic_go_bench.zig");
    _ = @import("tools/interop/websocket_h3_quic_go_bench.zig");
    _ = @import("tools/interop/exact_certificate_verifier.zig");
    _ = @import("examples/support/websocket_send_shape.zig");
    _ = @import("examples/support/memory_limiter.zig");
    _ = @import("examples/support/mqtt_pid_file.zig");
    _ = @import("examples/support/mqtt_reloadable_security.zig");
    _ = @import("examples/support/mqtt_reload_compatibility.zig");
    _ = @import("examples/support/mqtt_reloadable_identity.zig");
    _ = @import("examples/support/mqtt_configured_bridges.zig");
    _ = @import("tools/interop/webtransport_wtransport_bench.zig");
    _ = @import("tools/interop/webtransport_browser_reset.zig");
    _ = @import("tools/interop/webtransport_churn_protocol.zig");
}

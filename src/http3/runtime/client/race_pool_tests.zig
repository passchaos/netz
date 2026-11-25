const runtime = @import("../../runtime.zig");
const shared = @import("../../../internal/testing/connection_race_pool.zig");

test "HTTP3 connection race pool bounds handshake result storage by concurrent attempts" {
    try shared.bounded(runtime.HandshakeClient);
}

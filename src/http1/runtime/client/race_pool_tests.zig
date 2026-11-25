const shared = @import("../../../internal/testing/connection_race_pool.zig");

test "HTTP1 connection race pool bounds large result storage by concurrent attempts" {
    try shared.bounded([4096]u8);
}

test "HTTP1 connection race pool preserves indices and owned success after repeated reuse" {
    try shared.reusedOwnership(false);
}

test "HTTP1 connection race pool accepts large fixed arrays with bounded concurrency" {
    try shared.reusedOwnership(true);
}

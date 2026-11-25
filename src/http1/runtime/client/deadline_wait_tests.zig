const shared = @import("../../../internal/testing/deadline_wait.zig");

test "HTTP1 absolute deadline wait rechecks early sleep completion" {
    try shared.exercise(false);
}

test "HTTP1 absolute deadline wait preserves cancellation after an early wake" {
    try shared.exercise(true);
}

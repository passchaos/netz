const shared = @import("../../../internal/testing/connection_race_admission.zig");

test "HTTP1 connection race admission rejects settled budgets before allocation" {
    try shared.rejected(false, error.Timeout);
    try shared.rejected(true, error.Timeout);
}

test "HTTP1 connection race admission stops a canceled worker before transport entry" {
    try shared.canceledAtWorkerAdmission();
}

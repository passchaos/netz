const exercise = @import("../../internal/testing/finite_serve.zig").exercise;

test "WebSocket finite server joins an entered reader after later accept failure with zero async capacity" {
    try exercise(true, .accept_failure);
}

test "WebSocket finite server closes accepted socket when worker admission is unavailable" {
    try exercise(true, .initial_admission_failure);
}

test "WebSocket finite server cancels prior readers when later worker admission fails" {
    try exercise(true, .partial_admission_failure);
}

test "WebSocket finite server caller cancellation joins both blocked readers" {
    try exercise(true, .await_cancellation);
}

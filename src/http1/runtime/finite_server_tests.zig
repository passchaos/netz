const exercise = @import("../../internal/testing/finite_serve.zig").exercise;

test "HTTP/1 finite server joins an entered reader after later accept failure with zero async capacity" {
    try exercise(false, .accept_failure);
}

test "HTTP/1 finite server closes accepted socket when worker admission is unavailable" {
    try exercise(false, .initial_admission_failure);
}

test "HTTP/1 finite server cancels prior readers when later worker admission fails" {
    try exercise(false, .partial_admission_failure);
}

test "HTTP/1 finite server caller cancellation joins both blocked readers" {
    try exercise(false, .await_cancellation);
}

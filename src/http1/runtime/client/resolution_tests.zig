const runtime = @import("../../runtime.zig");
const shared = @import("../../../internal/testing/native_resolution.zig");

test "HTTP1 native resolver policy routes named and URI connections" {
    try shared.exercise(runtime, false);
}

test "HTTP1 native resolver policy preserves preflight and TLS propagation" {
    try shared.admission(runtime, false);
}

test "HTTP1 native resolver policy composes with source and interface binding" {
    try shared.bindings(runtime);
}

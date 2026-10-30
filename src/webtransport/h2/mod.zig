//! Capsule-based WebTransport over HTTP/2 (draft-ietf-webtrans-http2-15).
pub const capsule = @import("capsule.zig");
pub const Capsule = capsule.Capsule;
pub const CapsuleType = capsule.CapsuleType;
pub const Error = @import("runtime.zig").Error;
pub const Reader = @import("reader.zig").Reader;
pub const state = @import("state.zig");
pub const State = state.State;
pub const Limits = state.Limits;
pub const Session = @import("session.zig").Session;
pub const init_header = @import("init_header.zig");
pub const runtime = @import("runtime.zig");

test {
    _ = capsule;
    _ = @import("reader.zig");
    _ = state;
    _ = @import("runtime_tests.zig");
    _ = @import("session_write_tests.zig");
}

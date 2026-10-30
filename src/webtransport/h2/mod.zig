//! Capsule-based WebTransport over HTTP/2 (draft-ietf-webtrans-http2-15).
pub const capsule = @import("capsule.zig");
pub const Capsule = capsule.Capsule;
pub const CapsuleType = capsule.CapsuleType;
pub const Error = @import("reader.zig").Error;
pub const Reader = @import("reader.zig").Reader;

test {
    _ = capsule;
    _ = @import("reader.zig");
}

//! qlog 0.4 observability for QUIC.
//!
//! The encoder is sink-oriented: callers provide an `std.Io.Writer` backed by
//! a file, socket, allocating writer, or fixed test buffer. I/O errors remain
//! visible to the caller instead of silently disabling diagnostics.

pub const events = @import("events.zig");
pub const frame_adapter = @import("frame_adapter.zig");
pub const encoder = @import("encoder.zig");
pub const observer = @import("observer.zig");

pub const Trace = encoder.Trace;
pub const Options = encoder.Options;
pub const TimeFormat = encoder.TimeFormat;
pub const Observer = observer.Observer;

test {
    _ = @import("tests.zig");
}

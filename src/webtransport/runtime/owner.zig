//! Admit application access before buffered control or lifecycle maintenance.

test {
    _ = @import("owner/tests.zig");
    _ = @import("owner/stream_tests.zig");
}

pub fn callbackBorrowed(h3: anytype) bool {
    const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
    if (comptime @hasField(H3, "callback_reader_active")) return h3.callback_reader_active;
    return false;
}

pub fn buffered(h3: anytype) error{ConcurrentRead}!void {
    if (callbackBorrowed(h3)) return error.ConcurrentRead;
}

/// Shared endpoints keep their socket owner and use pollers for ready data.
pub fn receiveH3(h3: anytype) error{ ConcurrentRead, InvalidDispatcherState }!void {
    try buffered(h3);
    if (h3.dispatcherBound()) return error.InvalidDispatcherState;
}

pub fn receive(session: anytype) error{ ConcurrentRead, InvalidDispatcherState }!void {
    try receiveH3(&session.h3);
    const Session = @typeInfo(@TypeOf(session)).pointer.child;
    if (comptime @hasField(Session, "dispatcher")) {
        if (session.dispatcher != null) return error.InvalidDispatcherState;
    }
}

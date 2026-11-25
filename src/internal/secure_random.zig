//! Secure network entropy with cancellation at the operation boundaries.
const std = @import("std");

pub fn fill(io: std.Io, buffer: []u8) std.Io.RandomSecureError!void {
    try io.checkCancel();
    {
        // zio's entropy offload assumes its blocking work cannot be rejected
        // by a pending cancel before submission. Keep the caller's buffer
        // alive through completion, then deliver cancellation at our boundary.
        const old_protection = io.swapCancelProtection(.blocked);
        defer _ = io.swapCancelProtection(old_protection);
        try io.randomSecure(buffer);
    }
    try io.checkCancel();
}

//! Native timed socket writes for matching zio tasks behind std.Io.
const std = @import("std");
const zio = @import("zio");
const deadline_policy = @import("../internal/deadline.zig");

pub const Error = std.Io.net.Stream.Writer.Error || std.Io.Timeout.Error;

pub fn available(io: std.Io) bool {
    const runtime = zio.Runtime.fromIo(io) orelse return false;
    // blockingIo requests reserved-thread execution rather than task parking.
    if (io.userdata != runtime.io().userdata) return false;
    const coroutine = zio.coro.Coroutine.getCurrent() orelse return false;
    if (matches(&runtime.main_executor, coroutine)) return true;
    for (runtime.executors.items) |executor| {
        if (matches(executor, coroutine)) return true;
    }
    return false;
}

fn matches(executor: anytype, coroutine: *zio.coro.Coroutine) bool {
    // Compare stable parent addresses before reading owner-thread task state.
    if (coroutine.parent_context_ptr != &executor.main_task.coro.context) return false;
    const task = executor.current_task orelse return false;
    return &task.coro == coroutine and executor.no_suspend == 0;
}

/// Null selects the portable std.Io socket path. A native completion retains
/// its known prefix when cancellation races readiness, and joins before return.
pub fn tryWrite(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8, deadline: std.Io.Clock.Timestamp) ?Error!usize {
    if (!available(io)) return null;
    _ = deadline_policy.usableAwake(io, deadline) catch |err| return @as(Error!usize, err);
    var storage: [1]zio.os.iovec_const = undefined;
    const Handle = zio.ev.Backend.NetHandle;
    const handle: Handle = if (@typeInfo(Handle) == .pointer) @ptrCast(stream.socket.handle) else stream.socket.handle;
    const result = zio.net.writeBuf(handle, .fromSlice(bytes, &storage), .fromStd(.{ .deadline = deadline })) catch |err| return @as(Error!usize, mapError(err));
    return @as(Error!usize, if (result == 0) error.SocketUnconnected else result);
}

fn mapError(err: anyerror) Error {
    return switch (err) {
        error.Timeout => error.Timeout,
        error.Canceled => error.Canceled,
        error.ConnectionResetByPeer, error.ConnectionAborted, error.ConnectionTimedOut => error.ConnectionResetByPeer,
        error.SocketNotConnected, error.BrokenPipe => error.SocketUnconnected,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.HostUnreachable => error.HostUnreachable,
        error.NetworkDown => error.NetworkDown,
        error.ConnectionRefused => error.ConnectionRefused,
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.FastOpenAlreadyInProgress => error.FastOpenAlreadyInProgress,
        error.SystemResources => error.SystemResources,
        else => error.Unexpected,
    };
}

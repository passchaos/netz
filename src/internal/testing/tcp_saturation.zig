//! Test-only TCP send-queue saturation.
//!
//! `MSG_DONTWAIT` is not a reliable saturation primitive on every host: a
//! blocking descriptor can still sleep once the peer window closes, so a fill
//! loop can hang before the code under test ever runs. Switch the descriptor
//! to `O_NONBLOCK` for the fill and restore the caller's flags before
//! returning, keeping the blocking-socket write path under test.
const std = @import("std");
const builtin = @import("builtin");

pub const Error = std.posix.UnexpectedError || error{BufferNotSaturated};

/// Fill the outbound TCP queue until the kernel reports `EAGAIN`.
///
/// Returns `error.BufferNotSaturated` when the host accepts `max_bytes`
/// without backpressure (or when the platform has no POSIX descriptor flags),
/// so callers can skip a host-dependent scenario instead of hanging.
pub fn saturateSendBuffer(stream: std.Io.net.Stream, chunk: []const u8) Error!void {
    if (comptime builtin.os.tag == .windows) return error.BufferNotSaturated;
    return saturatePosix(stream, chunk);
}

fn saturatePosix(stream: std.Io.net.Stream, chunk: []const u8) Error!void {
    std.debug.assert(chunk.len != 0);
    const fd = stream.socket.handle;
    const original = try fcntlFlags(fd, std.posix.F.GETFL, 0);
    _ = try fcntlFlags(fd, std.posix.F.SETFL, original | nonBlockBit());
    defer _ = fcntlFlags(fd, std.posix.F.SETFL, original) catch {};

    const max_bytes: usize = 64 * 1024 * 1024;
    var filled: usize = 0;
    while (filled < max_bytes) {
        const rc = std.posix.system.sendto(
            fd,
            chunk.ptr,
            chunk.len,
            std.posix.MSG.NOSIGNAL,
            null,
            0,
        );
        switch (std.posix.errno(rc)) {
            .SUCCESS => filled += @intCast(rc),
            .INTR => continue,
            .AGAIN => return,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
    return error.BufferNotSaturated;
}

fn nonBlockBit() usize {
    return @as(usize, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK");
}

fn fcntlFlags(fd: std.posix.fd_t, command: i32, argument: usize) Error!usize {
    while (true) {
        const rc = std.posix.system.fcntl(fd, command, argument);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => |err| return std.posix.unexpectedErrno(err),
        }
    }
}

test "tcp saturation restores blocking flags after backpressure" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer sender.close(io);
    const peer = try listener.accept(io);
    defer peer.close(io);

    const buffer_size: c_int = 4096;
    try std.posix.setsockopt(
        sender.socket.handle,
        std.posix.SOL.SOCKET,
        std.posix.SO.SNDBUF,
        std.mem.asBytes(&buffer_size),
    );
    const filler = [_]u8{0xa5} ** 4096;
    saturateSendBuffer(sender, &filler) catch |err| switch (err) {
        error.BufferNotSaturated => return error.SkipZigTest,
        else => return err,
    };

    // The helper must hand the descriptor back in blocking mode.
    const flags = try fcntlFlags(sender.socket.handle, std.posix.F.GETFL, 0);
    try std.testing.expectEqual(@as(usize, 0), flags & nonBlockBit());
}

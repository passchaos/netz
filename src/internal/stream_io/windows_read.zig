//! Threaded AFD reads retain native completions through cancellation.
const std = @import("std");
const builtin = @import("builtin");
const windows = std.os.windows;
const net = std.Io.net;

/// Other backends and custom netRead callbacks keep their own read operation.
/// Matching Threaded callbacks use the same AFD receive and asynchronous
/// socket handle, with Batch owning its completion until cancellation joins.
pub fn tryRead(io: std.Io, stream: net.Stream, buffers: [][]u8) ?net.Stream.Reader.Error!usize {
    if (comptime builtin.os.tag != .windows) return null;
    const threaded = std.Io.Threaded.global_single_threaded.io();
    if (io.vtable.netRead != threaded.vtable.netRead or
        io.vtable.batchCancel != threaded.vtable.batchCancel) return null;
    return read(io, stream, buffers);
}

fn read(io: std.Io, stream: net.Stream, data: [][]u8) net.Stream.Reader.Error!usize {
    // Do not submit an already canceled operation. Threaded's ordinary read
    // submits before observing cancellation, and can consume bytes while
    // reporting only Canceled, as the native completion probe established.
    try io.checkCancel();
    var buffers: [std.Io.Threaded.max_iovecs_len]windows.AFD.WSABUF(.@"var") = undefined;
    var buffer_count: windows.ULONG = 0;
    for (data) |buffer| {
        if (buffer.len == 0) continue;
        if (buffer_count == buffers.len) break;
        buffers[buffer_count] = .{
            .len = @intCast(@min(buffer.len, std.math.maxInt(windows.ULONG))),
            .buf = buffer.ptr,
        };
        buffer_count += 1;
    }
    const request: windows.AFD.RECV_INFO = .{
        .BufferArray = &buffers,
        .BufferCount = buffer_count,
        .AfdFlags = .{ .NO_FAST_IO = true, .OVERLAPPED = true },
        .TdiFlags = .{ .NORMAL = true },
    };
    var storage: [1]std.Io.Operation.Storage = undefined;
    var batch: std.Io.Batch = .init(&storage);
    defer cancel(&batch, io);
    _ = batch.add(.{ .device_io_control = .{
        .file = .{ .handle = stream.socket.handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.RECEIVE,
        .in = std.mem.asBytes(&request),
    } });
    while (true) {
        // Threaded's concurrent wait checks cancellation again after every
        // alert. Its async wait holds one alertable syscall across the whole
        // pending loop, so a cancellation alert alone need not end an idle read.
        batch.awaitConcurrent(io, .none) catch |err| {
            if (err == error.Timeout) {
                if (batch.next()) |completion| return readCount(completion);
                continue;
            }
            cancel(&batch, io);
            if (batch.next()) |completion| {
                const count = try readCount(completion);
                // A successful native read, including EOF, remains visible.
                // The caller observes its pending cancellation at the next
                // cancellation point, after saving this accepted prefix.
                if (err == error.Canceled) std.Io.recancel(io);
                return count;
            }
            // An asynchronous Threaded AFD request requires no extra task
            // admission. Keep the ordinary stream-reader error surface if a
            // wrapper nevertheless cannot admit its wait.
            return if (err == error.Canceled) error.Canceled else error.SystemResources;
        };
        if (batch.next()) |completion| return readCount(completion);
    }
}

fn readCount(completion: std.Io.Batch.Completion) net.Stream.Reader.Error!usize {
    const iosb = completion.result.device_io_control;
    return switch (iosb.u.Status) {
        .SUCCESS => iosb.Information,
        .INSUFFICIENT_RESOURCES => error.SystemResources,
        // Successfully canceled operations are omitted from Batch.next.
        else => |status| windows.unexpectedStatus(status),
    };
}

fn cancel(batch: *std.Io.Batch, io: std.Io) void {
    if (batch.pending.head != .none) {
        // Threaded batchCancel first waits for an APC or alert before issuing
        // NtCancelIoFileEx. One self-alert lets an idle read reach that cancel
        // and join without polling or changing the socket's blocking mode.
        const status = windows.ntdll.NtAlertThread(windows.GetCurrentThread());
        std.debug.assert(status == .SUCCESS);
    }
    batch.cancel(io);
}

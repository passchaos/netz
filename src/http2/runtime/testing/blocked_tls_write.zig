//! Per-socket netWrite interceptor for bounded TLS terminal-output tests.
//! One interceptor is active per process; tests run sequentially.
const std = @import("std");

pub const Mode = enum {
    /// Armed writes pass straight through to the real socket.
    healthy,
    /// Every armed write fails immediately.
    disabled,
    /// The first armed write blocks until cancelled or rescued.
    blocked,
    /// One short partial write, then a permanent failure.
    partial,
    /// Let one write through, then block the next.
    close_blocked,
    /// Block the armed TLS close_notify on any socket: plaintext 0x15 alerts
    /// (TLS 1.2) block immediately, while in TLS 1.3 the first encrypted
    /// 0x17 record (the Finished flight) passes and the next one blocks.
    alert_blocked,
};

pub const BlockedTlsWrite = struct {
    var active: std.atomic.Value(?*BlockedTlsWrite) = .init(null);

    io: std.Io,
    mode: Mode,
    socket: std.Io.net.Socket.Handle,
    armed: std.atomic.Value(bool) = .init(false),
    calls: std.atomic.Value(usize) = .init(0),
    canceled: std.atomic.Value(bool) = .init(false),
    // Counts encrypted (0x17) client writes so alert_blocked lets the
    // post-ServerHello Finished flight pass before the TLS 1.3 close_notify.
    post_hello_writes: std.atomic.Value(usize) = .init(0),
    wait: std.Io.Event = .unset,

    /// Replace netWrite on a caller-owned vtable copy and target this socket.
    pub fn install(
        self: *@This(),
        vtable_copy: *std.Io.VTable,
        io: std.Io,
    ) std.Io {
        active.store(self, .release);
        vtable_copy.* = io.vtable.*;
        vtable_copy.netWrite = write;
        return .{ .userdata = io.userdata, .vtable = vtable_copy };
    }

    pub fn clear() void {
        active.store(null, .release);
    }

    pub fn write(
        _: ?*anyopaque,
        socket: std.Io.net.Socket.Handle,
        header: []const u8,
        parts: []const []const u8,
        splat: usize,
    ) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        if (self.armed.load(.acquire) and self.mode == .alert_blocked and
            header.len >= 1 and shouldBlockAlert(header[0], &self.post_hello_writes))
        {
            self.wait.wait(self.io) catch |err| {
                self.canceled.store(true, .release);
                return err;
            };
        }
        if (socket != self.socket or !self.armed.load(.acquire)) {
            return self.io.vtable.netWrite(
                self.io.userdata,
                socket,
                header,
                parts,
                splat,
            );
        }
        const call = self.calls.fetchAdd(1, .monotonic);
        switch (self.mode) {
            .disabled => return error.NetworkDown,
            .partial => return if (call == 0) @min(header.len, 4) else error.NetworkDown,
            .blocked, .close_blocked => {
                if (self.mode == .blocked or call != 0) {
                    self.wait.wait(self.io) catch |err| {
                        self.canceled.store(true, .release);
                        return err;
                    };
                }
            },
            .healthy, .alert_blocked => {},
        }
        return self.io.vtable.netWrite(
            self.io.userdata,
            socket,
            header,
            parts,
            splat,
        );
    }

    /// Release a blocked peer after the bounded path should have cancelled.
    pub fn rescue(self: *@This()) void {
        std.Io.sleep(self.io, .fromMilliseconds(500), .awake) catch {};
        self.wait.set(self.io);
    }
};

/// TLS 1.2 sends alerts as plaintext content type 0x15. In TLS 1.3 every
/// post-ServerHello record uses 0x17, so let the single encrypted Finished
/// flight through and treat the next 0x17 write as the close_notify.
fn shouldBlockAlert(
    content_type: u8,
    post_hello_writes: *std.atomic.Value(usize),
) bool {
    return switch (content_type) {
        0x15 => true,
        0x17 => post_hello_writes.fetchAdd(1, .monotonic) != 0,
        else => false,
    };
}

//! netWrite interceptor for bounded cleartext and TLS output tests.
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
    /// Block selected post-handshake TLS output on any socket. Plaintext 0x15
    /// alerts block immediately; encrypted 0x17 records use the configurable
    /// `post_hello_writes_to_pass` threshold below.
    post_handshake_blocked,
};

pub const BlockedTlsWrite = struct {
    var active: std.atomic.Value(?*BlockedTlsWrite) = .init(null);

    io: std.Io,
    mode: Mode,
    /// Null targets every socket used through the installed I/O vtable.
    socket: ?std.Io.net.Socket.Handle,
    armed: std.atomic.Value(bool) = .init(false),
    calls: std.atomic.Value(usize) = .init(0),
    canceled: std.atomic.Value(bool) = .init(false),
    /// Number of encrypted 0x17 records to pass before blocking. TLS 1.3 needs
    /// one for its post-ServerHello Finished flight; TLS 1.2 application-output
    /// tests use zero, while close_notify tests still match plaintext 0x15.
    post_hello_writes_to_pass: usize = 1,
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
        if (self.armed.load(.acquire) and self.mode == .post_handshake_blocked and
            header.len >= 1 and self.shouldBlockPostHandshake(header[0]))
        {
            self.wait.wait(self.io) catch |err| {
                self.canceled.store(true, .release);
                return err;
            };
        }
        if ((self.socket != null and socket != self.socket.?) or
            !self.armed.load(.acquire))
        {
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
            .healthy, .post_handshake_blocked => {},
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

    /// TLS 1.2 exposes alerts as content type 0x15 and application data as
    /// 0x17. TLS 1.3 uses 0x17 for both its encrypted Finished flight and all
    /// later output, so the per-fixture threshold selects the target record.
    fn shouldBlockPostHandshake(self: *@This(), content_type: u8) bool {
        return switch (content_type) {
            0x15 => true,
            0x17 => self.post_hello_writes.fetchAdd(1, .monotonic) >=
                self.post_hello_writes_to_pass,
            else => false,
        };
    }
};

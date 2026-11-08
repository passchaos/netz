//! Real TCP output fixture for deadline and partial-frame regression tests.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const allocator = std.testing.allocator;

pub const BlockedOutput = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,
    rescue: ?std.Thread = null,

    pub fn init(io: std.Io, role: runtime.Role) !BlockedOutput {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer sender.close(io);
        const peer = try listener.accept(io);
        errdefer peer.close(io);
        if (comptime builtin.os.tag != .windows) {
            const buffer_size: c_int = 4096;
            try std.posix.setsockopt(sender.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.SNDBUF, std.mem.asBytes(&buffer_size));
            try std.posix.setsockopt(peer.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVBUF, std.mem.asBytes(&buffer_size));
        }
        return .{
            .connection = .{ .allocator = allocator, .io = io, .stream = sender, .role = role, .peer_enable_connect_protocol = true },
            .peer = peer,
        };
    }

    pub fn startRescue(self: *@This()) !void {
        // Close the unread peer eventually so the old unbounded path fails
        // with an assertion instead of leaving the test process hung.
        self.rescue = try std.Thread.spawn(.{}, struct {
            fn run(io: std.Io, peer: std.Io.net.Stream) void {
                std.Io.sleep(io, .fromMilliseconds(500), .awake) catch {};
                // Closing a descriptor alone does not interrupt a read that
                // already holds the socket. Wake both endpoints before close.
                peer.shutdown(io, .both) catch {};
                peer.close(io);
            }
        }.run, .{ self.connection.io, self.peer });
    }

    /// Fill both TCP queues before testing even a tiny control/FIN write.
    pub fn saturate(self: *@This()) !void {
        if (comptime builtin.os.tag == .windows) return;
        const filler = "z" ** 4096;
        for (0..3) |round| {
            while (true) {
                const rc = std.posix.system.sendto(self.connection.stream.socket.handle, filler.ptr, filler.len, std.posix.MSG.DONTWAIT | std.posix.MSG.NOSIGNAL, null, 0);
                switch (std.posix.errno(rc)) {
                    .SUCCESS, .INTR => continue,
                    .AGAIN => break,
                    else => |err| return std.posix.unexpectedErrno(err),
                }
            }
            if (round != 2) try std.Io.sleep(self.connection.io, .fromMilliseconds(20), .awake);
        }
    }

    pub fn deinit(self: *@This()) void {
        const io = self.connection.io;
        self.connection.close();
        if (self.rescue) |thread| thread.join() else self.peer.close(io);
    }
};

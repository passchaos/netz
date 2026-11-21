//! Real TCP output fixture for deadline and partial-frame regression tests.
const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("../../runtime.zig");
const tcp_saturation = @import("../../../internal/testing/tcp_saturation.zig");
const allocator = std.testing.allocator;

pub const BlockedOutput = struct {
    connection: runtime.Connection,
    peer: std.Io.net.Stream,
    rescue: ?std.Thread = null,
    stalled: ?*Stalled = null,
    stalled_vtable: ?*std.Io.VTable = null,

    /// Deterministic blocked output: `netWrite` parks until the caller's
    /// deadline cancels the concurrent write. Hosts differ in how much slack
    /// they accept past `EAGAIN`, so a real saturated socket cannot force a
    /// small control frame to sleep. Only one stalled fixture may be active at
    /// a time; `deinit` clears the slot.
    const Stalled = struct {
        var active: ?*Stalled = null;
        delegate: std.Io,

        fn netWrite(
            _: ?*anyopaque,
            _: std.Io.net.Socket.Handle,
            _: []const u8,
            _: []const []const u8,
            _: usize,
        ) std.Io.net.Stream.Writer.Error!usize {
            const self = active orelse return error.SocketUnconnected;
            std.Io.sleep(self.delegate, .fromSeconds(30), .awake) catch |err| return err;
            return error.Canceled;
        }
    };

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

    /// Real socket reads plus a write path that never completes before the
    /// caller's deadline. Use when the test only needs the bounded-write
    /// failure path, not kernel buffer pressure.
    pub fn initStalled(io: std.Io, role: runtime.Role) !BlockedOutput {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        defer listener.deinit(io);
        const sender = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer sender.close(io);
        const peer = try listener.accept(io);
        errdefer peer.close(io);

        const state = try allocator.create(Stalled);
        errdefer allocator.destroy(state);
        state.* = .{ .delegate = io };
        const vtable = try allocator.create(std.Io.VTable);
        errdefer allocator.destroy(vtable);
        vtable.* = io.vtable.*;
        vtable.netWrite = Stalled.netWrite;
        Stalled.active = state;
        return .{
            .connection = .{
                .allocator = allocator,
                .io = .{ .userdata = io.userdata, .vtable = vtable },
                .stream = sender,
                .role = role,
                .peer_enable_connect_protocol = true,
            },
            .peer = peer,
            .stalled = state,
            .stalled_vtable = vtable,
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
            tcp_saturation.saturateSendBuffer(self.connection.stream, filler) catch |err| switch (err) {
                // A host that never reports backpressure cannot exercise the
                // blocked-output contract; skip instead of hanging the fill.
                error.BufferNotSaturated => return error.SkipZigTest,
                else => return err,
            };
            if (round != 2) try std.Io.sleep(self.connection.io, .fromMilliseconds(20), .awake);
        }
    }

    pub fn deinit(self: *@This()) void {
        const io = self.connection.io;
        self.connection.close();
        if (self.rescue) |thread| thread.join() else self.peer.close(io);
        if (self.stalled) |state| {
            if (Stalled.active == state) Stalled.active = null;
            allocator.destroy(state);
        }
        if (self.stalled_vtable) |vtable| allocator.destroy(vtable);
    }
};

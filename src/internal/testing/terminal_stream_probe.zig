//! Observe actual stream EOF/reset and reject subsequent shutdown output.
const std = @import("std");
const Handle = std.Io.net.Socket.Handle;
const unused_handle = std.math.maxInt(usize);

pub const Probe = struct {
    base: std.Io = undefined,
    table: std.Io.VTable = undefined,
    tracking: std.atomic.Value(bool) = .init(false),
    terminal_count: std.atomic.Value(usize) = .init(0),
    late_writes: std.atomic.Value(usize) = .init(0),
    handles: [4]std.atomic.Value(usize) = .{ .init(unused_handle), .init(unused_handle), .init(unused_handle), .init(unused_handle) },

    // Test runners execute cases serially; spawned tasks borrow this observer
    // until their owners have joined. Every backend callback keeps its own
    // original userdata, including native application-backend callbacks.
    var active: std.atomic.Value(?*Probe) = .init(null);

    pub fn io(self: *Probe, base: std.Io) std.Io {
        self.base = base;
        self.table = base.vtable.*;
        self.table.netRead = read;
        self.table.netWrite = write;
        std.debug.assert(active.swap(self, .acq_rel) == null);
        return .{ .userdata = base.userdata, .vtable = &self.table };
    }

    pub fn deinit(self: *Probe) void {
        std.debug.assert(active.swap(null, .acq_rel) == self);
    }

    fn handleKey(handle: Handle) usize {
        return switch (@typeInfo(Handle)) {
            .pointer => @intFromPtr(handle),
            .int => @intCast(handle),
            else => @compileError("unsupported stream handle type"),
        };
    }

    fn mark(self: *Probe, handle: Handle) void {
        const key = handleKey(handle);
        if (!self.tracking.load(.acquire)) return;
        for (&self.handles) |*slot| {
            if (slot.load(.acquire) == key) return;
            if (slot.cmpxchgStrong(unused_handle, key, .acq_rel, .acquire) == null) {
                _ = self.terminal_count.fetchAdd(1, .monotonic);
                return;
            }
        }
        @panic("terminal stream observer capacity exceeded");
    }

    fn read(userdata: ?*anyopaque, handle: Handle, data: [][]u8) std.Io.net.Stream.Reader.Error!usize {
        const self = active.load(.acquire).?;
        std.debug.assert(userdata == self.base.userdata);
        const count = self.base.vtable.netRead(userdata, handle, data) catch |err| {
            if (err == error.ConnectionResetByPeer) self.mark(handle);
            return err;
        };
        if (count == 0) self.mark(handle);
        return count;
    }

    fn write(userdata: ?*anyopaque, handle: Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active.load(.acquire).?;
        const key = handleKey(handle);
        std.debug.assert(userdata == self.base.userdata);
        if (self.tracking.load(.acquire)) for (&self.handles) |*slot| {
            if (slot.load(.acquire) == key) {
                _ = self.late_writes.fetchAdd(1, .monotonic);
                return error.SocketUnconnected;
            }
        };
        return self.base.vtable.netWrite(userdata, handle, header, data, splat);
    }
};

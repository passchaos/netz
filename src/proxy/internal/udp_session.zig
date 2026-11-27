//! Bounded UDP target owners; the QUIC service loop only publishes/collects.
//! All public operations belong to one service owner. Keep receive leases
//! until encoding is complete, and stop/join before releasing the socket.
const std = @import("std");
const destination = @import("../runtime/destination.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const net = std.Io.net;
pub const Replies = @import("udp_session/replies.zig").Replies;
pub const formatHost = @import("udp_session/address.zig").formatHost;

pub const Session = struct {
    pub const receive_capacity = 8;
    pub const send_capacity = 32;
    pub const Options = struct {
        maximum_datagram_bytes: usize,
        resolve_timeout: std.Io.Duration,
        policy: acl.Policy = .{},
        policy_store: ?*reload.Reloadable = null,
        notify_context: ?*anyopaque = null,
        notify: ?*const fn (?*anyopaque) void = null,
    };
    const ReceiveSlot = struct { bytes: []u8 = &.{}, message: net.IncomingMessage = .init };
    const SendSlot = struct {
        bytes: std.ArrayList(u8) = .empty,
        host: std.ArrayList(u8) = .empty,
        target: destination.Target = undefined,
        active: bool = false,
        finished: bool = false,
        result: Completion = undefined,
    };
    pub const Completion = struct { reserved_bytes: usize, committed_bytes: usize = 0, failure: ?anyerror = null };
    pub const Packet = struct {
        owner: ?*Session,
        index: usize,
        from: net.IpAddress,
        bytes: []const u8,
        truncated: bool,
        pub fn release(self: *Packet) void {
            const owner = self.owner orelse return;
            self.owner = null;
            if (!owner.closed.load(.acquire)) owner.receive_free.putOne(owner.io, self.index) catch {};
        }
    };

    allocator: std.mem.Allocator = undefined,
    io: std.Io = undefined,
    socket: net.Socket = undefined,
    options: Options = undefined,
    receive_slots: [receive_capacity]ReceiveSlot = @splat(.{}),
    send_slots: [send_capacity]SendSlot = @splat(.{}),
    receive_free_storage: [receive_capacity]usize = undefined,
    receive_ready_storage: [receive_capacity]usize = undefined,
    send_free_storage: [send_capacity]usize = undefined,
    send_commands_storage: [send_capacity]usize = undefined,
    send_done_storage: [send_capacity]usize = undefined,
    receive_free: std.Io.Queue(usize) = undefined,
    receive_ready: std.Io.Queue(usize) = undefined,
    send_free: std.Io.Queue(usize) = undefined,
    send_commands: std.Io.Queue(usize) = undefined,
    send_done: std.Io.Queue(usize) = undefined,
    reader: ?std.Io.Future(void) = null,
    writer: ?std.Io.Future(void) = null,
    closed: std.atomic.Value(bool) = .init(false),
    ready: std.atomic.Value(bool) = .init(false),
    receive_failed: std.atomic.Value(bool) = .init(false),
    received_pending: std.atomic.Value(usize) = .init(0),
    stopped: bool = false,

    /// Keep this value at its address until deinit; the socket remains borrowed.
    pub fn init(self: *Session, allocator: std.mem.Allocator, io: std.Io, socket: net.Socket, options: Options) !void {
        if (options.maximum_datagram_bytes == 0) return error.InvalidDatagramLimit;
        self.* = .{ .allocator = allocator, .io = io, .socket = socket, .options = options };
        self.receive_free = .init(&self.receive_free_storage);
        self.receive_ready = .init(&self.receive_ready_storage);
        self.send_free = .init(&self.send_free_storage);
        self.send_commands = .init(&self.send_commands_storage);
        self.send_done = .init(&self.send_done_storage);
        for (0..receive_capacity) |index| try self.receive_free.putOne(io, index);
        for (0..send_capacity) |index| try self.send_free.putOne(io, index);
        errdefer self.deinit();
        self.reader = try io.concurrent(receiveLoop, .{self});
        self.writer = try io.concurrent(sendLoop, .{self});
    }

    pub fn enqueue(self: *Session, target: destination.Target, bytes: []const u8) !bool {
        try self.io.checkCancel();
        if (self.closed.load(.acquire)) return false;
        if (bytes.len > self.options.maximum_datagram_bytes) return error.DatagramTooLarge;
        const host = switch (target) {
            .ip => &.{},
            .domain => |domain| domain.host,
        };
        if (host.len > self.options.maximum_datagram_bytes) return error.DatagramTooLarge;
        var indices: [1]usize = undefined;
        const count = self.send_free.get(self.io, &indices, 0) catch |err| switch (err) {
            error.Closed => return false,
            else => return err,
        };
        if (count == 0) return false;
        const index = indices[0];
        const slot = &self.send_slots[index];
        errdefer self.send_free.putOne(self.io, index) catch {};
        try slot.bytes.ensureTotalCapacityPrecise(self.allocator, bytes.len);
        try slot.host.ensureTotalCapacityPrecise(self.allocator, host.len);
        slot.bytes.clearRetainingCapacity();
        slot.bytes.appendSliceAssumeCapacity(bytes);
        slot.host.clearRetainingCapacity();
        slot.host.appendSliceAssumeCapacity(host);
        slot.target = switch (target) {
            .ip => target,
            .domain => |domain| .{ .domain = .{ .host = slot.host.items, .port = domain.port } },
        };
        slot.result = .{ .reserved_bytes = bytes.len };
        slot.finished = false;
        slot.active = true;
        const queued = self.send_commands.put(self.io, &.{index}, 0) catch |err| {
            slot.active = false;
            return err;
        };
        if (queued == 0) {
            slot.active = false;
            try self.send_free.putOne(self.io, index);
            return false;
        }
        return true;
    }

    pub fn takeSent(self: *Session) ?Completion {
        if (self.stopped) {
            for (&self.send_slots) |*slot| {
                if (!slot.active) continue;
                slot.active = false;
                return if (slot.finished) slot.result else .{ .reserved_bytes = slot.bytes.items.len, .failure = error.Canceled };
            }
            return null;
        }
        var index: [1]usize = undefined;
        const count = self.send_done.get(self.io, &index, 0) catch return null;
        if (count == 0) return null;
        const slot = &self.send_slots[index[0]];
        std.debug.assert(slot.active and slot.finished);
        slot.active = false;
        const result = slot.result;
        self.send_free.putOne(self.io, index[0]) catch {};
        return result;
    }

    pub fn takeReceived(self: *Session) ?Packet {
        if (self.closed.load(.acquire)) return null;
        var index: [1]usize = undefined;
        const count = self.receive_ready.get(self.io, &index, 0) catch return null;
        if (count == 0) return null;
        const pending = self.received_pending.fetchSub(1, .acq_rel);
        std.debug.assert(pending != 0);
        const slot = &self.receive_slots[index[0]];
        return .{ .owner = self, .index = index[0], .from = slot.message.from, .bytes = slot.message.data, .truncated = slot.message.flags.trunc };
    }

    pub fn hasReceived(self: *const Session) bool {
        return !self.closed.load(.acquire) and self.received_pending.load(.acquire) != 0;
    }

    /// Return all received leases before deinit. Final send results stay collectable.
    pub fn stop(self: *Session) void {
        if (self.stopped) return;
        self.closed.store(true, .release);
        self.receive_free.close(self.io);
        self.receive_ready.close(self.io);
        self.send_free.close(self.io);
        self.send_commands.close(self.io);
        self.send_done.close(self.io);
        if (self.reader) |*future| future.cancel(self.io);
        if (self.writer) |*future| future.cancel(self.io);
        self.reader = null;
        self.writer = null;
        self.stopped = true;
    }

    pub fn deinit(self: *Session) void {
        self.stop();
        for (&self.receive_slots) |*slot| self.allocator.free(slot.bytes);
        for (&self.send_slots) |*slot| {
            slot.bytes.deinit(self.allocator);
            slot.host.deinit(self.allocator);
        }
    }

    fn notify(self: *Session) void {
        self.ready.store(true, .release);
        if (self.options.notify) |callback| callback(self.options.notify_context);
    }

    fn receiveLoop(self: *Session) void {
        while (!self.closed.load(.acquire)) {
            const index = self.receive_free.getOne(self.io) catch return;
            const slot = &self.receive_slots[index];
            if (slot.bytes.len == 0) slot.bytes = self.allocator.alloc(u8, self.options.maximum_datagram_bytes) catch {
                self.receive_failed.store(true, .release);
                self.notify();
                return;
            };
            slot.message = .init;
            const result = self.io.operate(.{ .net_receive = .{ .socket_handle = self.socket.handle, .message_buffer = (&slot.message)[0..1], .data_buffer = slot.bytes, .flags = .{} } }) catch {
                if (!self.closed.load(.acquire)) {
                    self.receive_failed.store(true, .release);
                    self.notify();
                }
                return;
            };
            if (self.closed.load(.acquire)) return;
            const err, const count = result.net_receive;
            if (count != 1) {
                _ = err;
                self.receive_failed.store(true, .release);
                self.notify();
                return;
            }
            _ = self.received_pending.fetchAdd(1, .acq_rel);
            self.receive_ready.putOne(self.io, index) catch return;
            self.notify();
        }
    }

    fn sendLoop(self: *Session) void {
        while (!self.closed.load(.acquire)) {
            const index = self.send_commands.getOne(self.io) catch return;
            const slot = &self.send_slots[index];
            var result: Completion = .{ .reserved_bytes = slot.bytes.items.len };
            if (self.closed.load(.acquire)) result.failure = error.Canceled else blk: {
                const target = switch (slot.target) {
                    .ip => |ip| ip,
                    .domain => destination.resolveTarget(self.allocator, self.io, reload.policyFor(self.options.policy, self.options.policy_store), slot.target, .udp_associate, self.options.resolve_timeout) catch |err| {
                        result.failure = err;
                        break :blk;
                    },
                };
                var message: net.OutgoingMessage = .{ .address = &target, .data_ptr = slot.bytes.items.ptr, .data_len = slot.bytes.items.len };
                const err, const count = self.io.vtable.netSend(self.io.userdata, self.socket.handle, (&message)[0..1], .{});
                if (count == 1) {
                    result.committed_bytes = @min(message.data_len, slot.bytes.items.len);
                    if (message.data_len != slot.bytes.items.len) result.failure = error.MessageOversize;
                } else result.failure = err orelse error.Unexpected;
            }
            slot.result = result;
            slot.finished = true;
            self.send_done.putOne(self.io, index) catch return;
            self.notify();
        }
    }
};

test {
    _ = @import("udp_session/address.zig");
    _ = @import("udp_session/replies.zig");
    _ = @import("udp_session/tests.zig");
}

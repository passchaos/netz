//! TCP relay queues for the shared-endpoint TUIC server.
//!
//! The endpoint pump owns every QUIC connection. TCP reads therefore run in
//! one async task per relay and publish chunks through a bounded queue; the
//! pump drains that queue without blocking. TCP writes stay on the pump and
//! use short partial-write attempts so one slow target cannot stall the other
//! connections sharing the endpoint.

const std = @import("std");
const net = std.Io.net;
const io_helpers = @import("../../internal/io.zig");

pub const Outbound = union(enum) {
    data: []u8,
    fin,
};

pub const Relay = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    tcp: net.Stream,
    stream_id: u64,
    send_offset: u64 = 0,
    last_activity_ns: i64,
    idle_timeout: std.Io.Duration,
    buffer_size: usize,
    /// One item in flight after a backpressured send.
    pending_out: ?Outbound = null,
    outbound_storage: [8]Outbound = undefined,
    outbound: std.Io.Queue(Outbound) = undefined,
    reader_future: ?std.Io.Future(void) = null,
    closed: std.atomic.Value(bool) = .init(false),
    /// The TCP reader reached EOF and queued its FIN.
    tcp_done: std.atomic.Value(bool) = .init(false),
    /// The QUIC peer sent FIN; no more stream data will arrive.
    quic_done: std.atomic.Value(bool) = .init(false),
    /// The pump sent the FIN to the QUIC peer.
    quic_fin_sent: bool = false,
    /// QUIC-to-TCP bytes that did not fit the last partial write.
    inbound: std.ArrayList(u8) = .empty,
    inbound_start: usize = 0,
    inbound_cap: usize = 256 * 1024,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        tcp: net.Stream,
        stream_id: u64,
        idle_timeout: std.Io.Duration,
        buffer_size: usize,
    ) !*Relay {
        const relay = try allocator.create(Relay);
        errdefer allocator.destroy(relay);
        relay.* = .{
            .allocator = allocator,
            .io = io,
            .tcp = tcp,
            .stream_id = stream_id,
            .last_activity_ns = nowNs(io),
            .idle_timeout = idle_timeout,
            .buffer_size = buffer_size,
        };
        relay.outbound = .init(&relay.outbound_storage);
        relay.reader_future = io.async(readerTask, .{relay});
        return relay;
    }

    pub fn deinit(self: *Relay) void {
        self.closed.store(true, .release);
        self.outbound.close(self.io);
        self.tcp.shutdown(self.io, .both) catch {};
        if (self.reader_future) |*future| {
            _ = future.await(self.io);
            self.reader_future = null;
        }
        self.tcp.close(self.io);
        if (self.pending_out) |item| self.freeOutbound(item);
        while (true) {
            var batch: [8]Outbound = undefined;
            const count = self.outbound.get(
                self.io,
                &batch,
                0,
            ) catch break;
            if (count == 0) break;
            for (batch[0..count]) |item| self.freeOutbound(item);
        }
        self.inbound.deinit(self.allocator);
        self.allocator.destroy(self);
    }

    pub fn touch(self: *Relay) void {
        self.last_activity_ns = nowNs(self.io);
    }

    pub fn idle(self: *const Relay, now: i64) bool {
        return now - self.last_activity_ns >= self.idle_timeout.nanoseconds;
    }

    pub fn queueInbound(self: *Relay, bytes: []const u8) !void {
        if (self.inbound.items.len + bytes.len > self.inbound_cap) {
            return error.RelayBufferFull;
        }
        try self.inbound.appendSlice(self.allocator, bytes);
    }

    /// Write buffered QUIC payload to TCP without blocking the endpoint pump
    /// for longer than a short scheduling quantum. Returns true when all
    /// buffered bytes were written.
    pub fn flushInbound(self: *Relay) bool {
        if (self.inbound_start == self.inbound.items.len) {
            self.inbound.clearRetainingCapacity();
            self.inbound_start = 0;
            return true;
        }
        const deadline = io_helpers.deadlineFromTimeout(
            self.io,
            .fromMilliseconds(10),
        ) catch null;
        const written = io_helpers.writeSome(
            self.io,
            self.tcp,
            self.inbound.items[self.inbound_start..],
            deadline,
        ) catch |err| switch (err) {
            error.Timeout => 0,
            else => {
                self.closed.store(true, .release);
                return false;
            },
        };
        if (written == 0) return false;
        self.inbound_start += written;
        self.touch();
        if (self.inbound_start == self.inbound.items.len) {
            self.inbound.clearRetainingCapacity();
            self.inbound_start = 0;
            return true;
        }
        if (self.inbound_start > self.inbound_cap / 2) {
            const remaining = self.inbound.items.len - self.inbound_start;
            std.mem.copyForwards(
                u8,
                self.inbound.items[0..remaining],
                self.inbound.items[self.inbound_start..],
            );
            self.inbound.items.len = remaining;
            self.inbound_start = 0;
        }
        return false;
    }

    pub fn shutdownTcpSend(self: *Relay) void {
        self.tcp.shutdown(self.io, .send) catch {};
    }

    fn freeOutbound(self: *Relay, item: Outbound) void {
        switch (item) {
            .data => |bytes| self.allocator.free(bytes),
            .fin => {},
        }
    }

    fn readerTask(self: *Relay) void {
        const allocator = self.allocator;
        const buffer = allocator.alloc(u8, self.buffer_size) catch {
            self.tcp_done.store(true, .release);
            self.outbound.putOne(self.io, .fin) catch {};
            return;
        };
        defer allocator.free(buffer);
        while (!self.closed.load(.acquire)) {
            const deadline = io_helpers.deadlineFromTimeout(
                self.io,
                self.idle_timeout,
            ) catch null;
            const count = io_helpers.readSome(
                self.io,
                self.tcp,
                buffer,
                deadline,
            ) catch break;
            if (count == 0) break;
            const chunk = allocator.dupe(u8, buffer[0..count]) catch break;
            self.outbound.putOne(self.io, .{ .data = chunk }) catch {
                allocator.free(chunk);
                break;
            };
        }
        self.tcp_done.store(true, .release);
        self.outbound.putOne(self.io, .fin) catch {};
    }
};

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
}

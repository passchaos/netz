//! TCP relay queues for shared-endpoint QUIC proxy servers.
//!
//! The endpoint pump owns every QUIC connection. TCP reads therefore run in
//! one async task per relay and publish chunks through a bounded queue; the
//! pump drains that queue without blocking. TCP writes stay on the pump and
//! use short partial-write attempts so one slow target cannot stall the other
//! connections sharing the endpoint.

const std = @import("std");
const net = std.Io.net;
const io_helpers = @import("io.zig");
const outbound_queue = @import("relay_queue/outbound.zig");

pub const Outbound = outbound_queue.Item;
pub const SendResult = outbound_queue.Result;

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
    /// Socket-visible prefix of the retained outbound DATA item.
    pending_data_start: usize = 0,
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
        self.discardOutbound();
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
        _ = self.flushInboundUpTo(std.math.maxInt(usize));
        return self.inbound_start == self.inbound.items.len;
    }

    /// Return exact TCP progress so the owner charges only committed bytes.
    pub fn flushInboundUpTo(self: *Relay, maximum_bytes: usize) usize {
        if (self.inbound_start == self.inbound.items.len) {
            self.inbound.clearRetainingCapacity();
            self.inbound_start = 0;
            return 0;
        }
        if (maximum_bytes == 0) return 0;
        const deadline = io_helpers.deadlineFromTimeout(
            self.io,
            .fromMilliseconds(10),
        ) catch null;
        const written = io_helpers.writeSome(
            self.io,
            self.tcp,
            self.inbound.items[self.inbound_start .. self.inbound_start + @min(
                maximum_bytes,
                self.inbound.items.len - self.inbound_start,
            )],
            deadline,
        ) catch |err| switch (err) {
            error.Timeout => 0,
            else => {
                self.closed.store(true, .release);
                return 0;
            },
        };
        if (written == 0) return 0;
        self.inbound_start += written;
        self.touch();
        if (self.inbound_start == self.inbound.items.len) {
            self.inbound.clearRetainingCapacity();
            self.inbound_start = 0;
            return written;
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
        return written;
    }

    pub fn shutdownTcpSend(self: *Relay) void {
        self.tcp.shutdown(self.io, .send) catch {};
    }

    /// The callback borrows each item; only this queue releases its storage.
    pub fn flushOutbound(self: *Relay, context: anytype, comptime send: anytype) void {
        outbound_queue.drain(self, context, send);
    }

    pub fn discardOutbound(self: *Relay) void {
        outbound_queue.discard(self);
    }

    pub fn freeOutbound(self: *Relay, item: Outbound) void {
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

test {
    _ = @import("relay_queue/tests.zig");
}

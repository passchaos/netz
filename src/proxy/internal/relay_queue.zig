//! TCP relay queues for shared-endpoint QUIC proxy servers.
//!
//! The endpoint pump owns every QUIC connection. TCP reads therefore run in
//! one concurrent task per relay and publish chunks through a bounded queue.
//! Target writes use a persistent owner and an immutable input loan; the pump
//! submits and collects completion while retaining sole QUIC ownership.

const std = @import("std");
const net = std.Io.net;
const io_helpers = @import("io.zig");
const outbound_queue = @import("relay_queue/outbound.zig");
const inbound_queue = @import("relay_queue/inbound.zig");

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
    input: inbound_queue.Input = .{},
    ready: std.atomic.Value(bool) = .init(false),
    notify_context: ?*anyopaque = null,
    notify: ?*const fn (?*anyopaque) void = null,
    tcp_send_shutdown: bool = false,

    pub const InputCompletion = inbound_queue.Input.Completion;
    pub const Options = struct {
        idle_timeout: std.Io.Duration,
        buffer_size: usize,
        maximum_input_bytes: usize = 256 * 1024,
        notify_context: ?*anyopaque = null,
        notify: ?*const fn (?*anyopaque) void = null,
    };

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        tcp: net.Stream,
        stream_id: u64,
        idle_timeout: std.Io.Duration,
        buffer_size: usize,
    ) !*Relay {
        return createWithOptions(allocator, io, tcp, stream_id, .{ .idle_timeout = idle_timeout, .buffer_size = buffer_size });
    }

    pub fn createWithOptions(allocator: std.mem.Allocator, io: std.Io, tcp: net.Stream, stream_id: u64, options: Options) !*Relay {
        const relay = try allocator.create(Relay);
        errdefer allocator.destroy(relay);
        relay.* = .{
            .allocator = allocator,
            .io = io,
            .tcp = tcp,
            .stream_id = stream_id,
            .last_activity_ns = nowNs(io),
            .idle_timeout = options.idle_timeout,
            .buffer_size = options.buffer_size,
            .notify_context = options.notify_context,
            .notify = options.notify,
        };
        relay.outbound = .init(&relay.outbound_storage);
        try relay.input.init(allocator, io, tcp, .{ .maximum_bytes = options.maximum_input_bytes, .notify_context = relay, .notify = notifyReady });
        errdefer relay.input.deinit();
        relay.reader_future = try io.concurrent(readerTask, .{relay});
        return relay;
    }

    pub fn deinit(self: *Relay) void {
        self.closed.store(true, .release);
        self.outbound.close(self.io);
        _ = self.stopInput();
        self.tcp.shutdown(self.io, .both) catch {};
        if (self.reader_future) |*future| {
            _ = future.await(self.io);
            self.reader_future = null;
        }
        self.tcp.close(self.io);
        self.discardOutbound();
        self.input.deinit();
        self.allocator.destroy(self);
    }

    pub fn touch(self: *Relay) void {
        self.last_activity_ns = nowNs(self.io);
    }

    pub fn idle(self: *const Relay, now: i64) bool {
        return now - self.last_activity_ns >= self.idle_timeout.nanoseconds;
    }

    pub fn queueInbound(self: *Relay, bytes: []const u8) !void {
        try self.input.append(bytes);
        self.signalReady();
    }

    pub fn pendingInboundBytes(self: *const Relay) usize {
        return self.input.pendingBytes();
    }

    pub fn readyInboundBytes(self: *const Relay) usize {
        if (self.closed.load(.acquire)) return 0;
        return self.input.readyBytes();
    }

    pub fn takeInputCompletion(self: *Relay) ?InputCompletion {
        const result = self.input.take() orelse return null;
        if (result.committed_bytes != 0) self.touch();
        if (self.input.terminal) self.closed.store(true, .release);
        return result;
    }

    pub fn submitInput(self: *Relay, maximum_bytes: usize) usize {
        if (self.closed.load(.acquire)) return 0;
        const count = self.input.submit(maximum_bytes) catch |err| {
            if (err != error.Timeout) self.closed.store(true, .release);
            return 0;
        };
        if (self.input.terminal) self.closed.store(true, .release);
        return count;
    }

    /// Nonblocking input service for owners without a shared rate bucket.
    pub fn serviceInput(self: *Relay) void {
        _ = self.takeInputCompletion();
        _ = self.submitInput(std.math.maxInt(usize));
    }

    pub fn stopInput(self: *Relay) ?InputCompletion {
        const result = self.input.stop() orelse return null;
        if (result.committed_bytes != 0) self.touch();
        return result;
    }

    pub fn inputDrained(self: *const Relay) bool {
        return self.pendingInboundBytes() == 0 and !self.input.in_flight;
    }

    /// Preserve the synchronous flush API for standalone callers.
    /// Shared endpoint pumps use serviceInput or submitInput/takeInputCompletion.
    pub fn flushInbound(self: *Relay) bool {
        _ = self.flushInboundUpTo(std.math.maxInt(usize));
        return self.inputDrained();
    }

    pub fn flushInboundUpTo(self: *Relay, maximum_bytes: usize) usize {
        const written = self.input.writeNow(maximum_bytes) catch |err| switch (err) {
            error.Timeout => 0,
            else => {
                self.closed.store(true, .release);
                return 0;
            },
        };
        if (written != 0) self.touch();
        return written;
    }

    pub fn shutdownTcpSend(self: *Relay) void {
        if (self.tcp_send_shutdown or !self.inputDrained()) return;
        self.tcp_send_shutdown = true;
        self.tcp.shutdown(self.io, .send) catch {};
    }

    fn signalReady(self: *Relay) void {
        self.ready.store(true, .release);
        if (self.notify) |notify| notify(self.notify_context);
    }

    fn notifyReady(context: ?*anyopaque) void {
        const self: *Relay = @ptrCast(@alignCast(context.?));
        self.signalReady();
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
            self.outbound.putOne(self.io, .fin) catch return;
            self.signalReady();
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
            self.signalReady();
        }
        self.tcp_done.store(true, .release);
        self.outbound.putOne(self.io, .fin) catch return;
        self.signalReady();
    }
};

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
}

test {
    _ = @import("relay_queue/tests.zig");
}

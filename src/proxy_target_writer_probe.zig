//! Fixed-binary target-write service and allocator probe; no kernel pressure.
const std = @import("std");
const netz = @import("root.zig");
const observer = @import("internal/testing/forwarded_io.zig");
const Relay = netz.proxy.internal.relay_queue.Relay;
const net = std.Io.net;
const persistent = @hasDecl(Relay, "serviceInput");

const Tracker = struct {
    inner: std.mem.Allocator,
    live: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),
    calls: std.atomic.Value(usize) = .init(0),
    const table: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = resize, .remap = remap, .free = free };
    fn allocator(self: *Tracker) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &table };
    }
    fn changed(self: *Tracker, old: usize, new: usize) void {
        const current = if (new >= old) self.live.fetchAdd(new - old, .acq_rel) + new - old else self.live.fetchSub(old - new, .acq_rel) - old + new;
        var peak = self.peak.load(.acquire);
        while (current > peak) peak = self.peak.cmpxchgWeak(peak, current, .acq_rel, .acquire) orelse break;
    }
    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *Tracker = @ptrCast(@alignCast(context));
        const result = self.inner.rawAlloc(len, alignment, ra) orelse return null;
        _ = self.calls.fetchAdd(1, .monotonic);
        self.changed(0, len);
        return result;
    }
    fn resize(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *Tracker = @ptrCast(@alignCast(context));
        if (!self.inner.rawResize(memory, alignment, len, ra)) return false;
        self.changed(memory.len, len);
        return true;
    }
    fn remap(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *Tracker = @ptrCast(@alignCast(context));
        const result = self.inner.rawRemap(memory, alignment, len, ra) orelse return null;
        self.changed(memory.len, len);
        return result;
    }
    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *Tracker = @ptrCast(@alignCast(context));
        self.inner.rawFree(memory, alignment, ra);
        self.changed(memory.len, 0);
    }
};
const Stall = struct {
    delegate: std.Io,
    calls: std.atomic.Value(usize) = .init(0),
    fn write(context: ?*anyopaque, _: net.Socket.Handle, _: []const u8, _: []const []const u8, _: usize) net.Stream.Writer.Error!usize {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        _ = self.calls.fetchAdd(1, .monotonic);
        try std.Io.sleep(self.delegate, .fromSeconds(1), .awake);
        return error.NetworkDown;
    }
};
fn now(io: std.Io) i64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}
fn drive(relay: *Relay) void {
    if (comptime persistent) relay.serviceInput() else _ = relay.flushInboundUpTo(std.math.maxInt(usize));
}
fn pending(relay: *Relay) usize {
    return if (comptime persistent) relay.pendingInboundBytes() else relay.inbound.items.len - relay.inbound_start;
}
fn collect(io: std.Io, relays: []*Relay) !void {
    if (comptime !persistent) return;
    const seen = try std.heap.c_allocator.alloc(bool, relays.len);
    defer std.heap.c_allocator.free(seen);
    @memset(seen, false);
    var remaining = relays.len;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (remaining != 0) {
        for (relays, 0..) |relay, index| {
            if (seen[index]) continue;
            const result = relay.takeInputCompletion() orelse continue;
            if (result.committed_bytes != 0) return error.UnexpectedWriteResult;
            const failure = result.failure orelse return error.UnexpectedWriteResult;
            if (failure != error.Timeout) return error.UnexpectedWriteResult;
            seen[index] = true;
            remaining -= 1;
        }
        if (remaining == 0) break;
        if (deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.CompletionTimeout;
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
}

pub fn main(init: std.process.Init) !void {
    const heap = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var count: usize = 32;
    var application = true;
    var burst = false;
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--count=")) count = try std.fmt.parseInt(usize, arg[8..], 10) else if (std.mem.eql(u8, arg, "--threaded")) application = false else if (std.mem.eql(u8, arg, "--burst")) burst = true else return error.InvalidArgument;
    }
    if (count == 0 or count > 64) return error.InvalidCount;
    var threaded = std.Io.Threaded.init(heap, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var backend: ?netz.runtime.Backend = null;
    defer if (backend) |*value| value.deinit();
    if (application) backend = try netz.runtime.Backend.initWithExecutors(heap, 1);
    const base = if (backend) |*value| value.io() else threaded.io();
    var tracker: Tracker = .{ .inner = heap };
    var stall: Stall = .{ .delegate = base };
    const io = observer.observer(&stall, .{ .netWrite = Stall.write });
    const relays = try heap.alloc(*Relay, count);
    defer heap.free(relays);
    const peers = try heap.alloc(net.Stream, count);
    defer heap.free(peers);
    var created: usize = 0;
    defer for (0..created) |i| {
        relays[i].deinit();
        peers[i].close(base);
    };
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
    defer listener.deinit(base);
    const seed = if (burst) "a" ** (16 * 1024) else "data";
    for (0..count) |i| {
        const sender = try listener.socket.address.connect(base, .{ .mode = .stream });
        const peer = listener.accept(base) catch |err| {
            sender.close(base);
            return err;
        };
        const relay = Relay.create(tracker.allocator(), io, sender, i, .fromSeconds(60), 16 * 1024) catch |err| {
            sender.close(base);
            peer.close(base);
            return err;
        };
        relays[i] = relay;
        peers[i] = peer;
        created += 1;
        try relay.queueInbound(seed);
    }
    // Warm deadline workers, then retain a second burst while targets block.
    for (relays) |relay| drive(relay);
    try collect(base, relays);
    if (burst) for (relays) |relay| try relay.queueInbound("b" ** (64 * 1024));
    const expected = seed.len + (if (burst) @as(usize, 64 * 1024) else 0);
    var samples: [5]i64 = undefined;
    var calls: [5]usize = undefined;
    for (0..5) |sample| {
        const before = stall.calls.load(.acquire);
        const start = now(base);
        for (relays) |relay| drive(relay);
        samples[sample] = now(base) - start;
        try collect(base, relays);
        calls[sample] = stall.calls.load(.acquire) - before;
        for (relays) |relay| if (pending(relay) != expected or relay.closed.load(.acquire)) return error.LostQueuedBytes;
    }
    const live = tracker.live.load(.acquire);
    const peak = tracker.peak.load(.acquire);
    const allocations = tracker.calls.load(.acquire);
    for (0..created) |i| {
        relays[i].deinit();
        peers[i].close(base);
    }
    created = 0;
    if (tracker.live.load(.acquire) != 0) return error.LiveRelayStorage;
    var ordered = samples;
    std.mem.sort(i64, &ordered, {}, std.sort.asc(i64));
    std.debug.print("{{\"persistent\":{},\"application\":{},\"count\":{d},\"burst\":{},\"budget_ns\":10000000,\"queued_per_relay\":{d},\"service_ns\":[{d},{d},{d},{d},{d}],\"calls\":[{d},{d},{d},{d},{d}],\"median_ns\":{d},\"proxy_live_bytes\":{d},\"proxy_peak_bytes\":{d},\"alloc_calls\":{d},\"zero_live_after_cleanup\":true,\"kernel_pressure\":false}}\n", .{ persistent, application, count, burst, expected, samples[0], samples[1], samples[2], samples[3], samples[4], calls[0], calls[1], calls[2], calls[3], calls[4], ordered[2], live, peak, allocations });
}

const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support").counting_allocator
    .CountingAllocator;

const send_iterations: usize = 1_000_000;
const receive_iterations: usize = 200_000;
const payload_len: usize = 513;
const fragment_bytes: usize = 17;

const ResetCode = enum {
    protocol_error,
    enhance_your_calm,
};

const WriteProgress = struct {
    committed_bytes: usize = 0,
};

const TunnelData = struct {
    data: []const u8,
    end_stream: bool = false,

    pub fn deinit(self: *TunnelData, _: std.mem.Allocator) void {
        self.* = undefined;
    }
};

const MemoryTunnel = struct {
    stream_id: u31 = 1,
    source: []const u8,
    read_offset: usize = 0,
    written_bytes: u64 = 0,
    checksum: u64 = 0,

    pub fn writeSlices(
        self: *MemoryTunnel,
        slices: []const []const u8,
        end_stream: bool,
    ) !void {
        std.debug.assert(!end_stream);
        for (slices) |slice| {
            self.written_bytes +%= slice.len;
            if (slice.len != 0) {
                self.checksum +%= slice[0];
                self.checksum +%= slice[slice.len - 1];
            }
        }
    }

    pub fn writeSlicesWithDeadline(
        self: *MemoryTunnel,
        slices: []const []const u8,
        end_stream: bool,
        progress: *WriteProgress,
        _: std.Io.Clock.Timestamp,
    ) !void {
        progress.* = .{};
        try self.writeSlices(slices, end_stream);
        for (slices) |slice| progress.committed_bytes += slice.len;
    }

    pub fn closeWrite(_: *MemoryTunnel) !void {}

    pub fn read(self: *MemoryTunnel) !TunnelData {
        const end = @min(
            self.read_offset + fragment_bytes,
            self.source.len,
        );
        const data = self.source[self.read_offset..end];
        self.read_offset = if (end == self.source.len) 0 else end;
        return .{ .data = data };
    }

    pub fn readWithDeadline(
        self: *MemoryTunnel,
        _: std.Io.Clock.Timestamp,
    ) !TunnelData {
        return self.read();
    }

    pub fn reset(_: *MemoryTunnel, _: ResetCode) !void {
        return error.UnexpectedReset;
    }
};

const Session = netz.http3.connect_udp.CapsuleSession(
    ResetCode,
    MemoryTunnel,
    WriteProgress,
);

pub fn main() !void {
    var backend = try netz.runtime.Backend.init(std.heap.smp_allocator);
    defer backend.deinit();
    const io = backend.io();
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = counting.allocator();

    var payload: [payload_len]u8 = undefined;
    for (&payload, 0..) |*byte, index| byte.* = @truncate(index);
    var sequence_storage: [payload_len + 128]u8 = undefined;
    const sequence = try buildSequence(&sequence_storage, &payload);

    var session = Session.init(
        allocator,
        io,
        .{ .source = sequence },
        .{},
    );
    defer session.deinit();
    var receive_storage: [payload_len]u8 = undefined;

    try session.send(&payload);
    _ = try session.receiveInto(&receive_storage);
    var owned_warmup = try session.receive();
    owned_warmup.deinit(allocator);

    const send_before = counting.snapshot();
    const send_started = nowNs(io);
    for (0..send_iterations) |_| {
        try session.send(&payload);
    }
    const send_elapsed = nowNs(io) -| send_started;
    const send_after = counting.snapshot();
    const send_allocations = send_after.alloc_count - send_before.alloc_count;
    if (send_allocations != 0) return error.UnexpectedAllocation;

    const into_before = counting.snapshot();
    const into_started = nowNs(io);
    var into_checksum: u64 = 0;
    for (0..receive_iterations) |_| {
        const received = try session.receiveInto(&receive_storage);
        std.mem.doNotOptimizeAway(received.payload.ptr);
        into_checksum +%= received.payload.len;
        into_checksum +%= received.payload[0];
        into_checksum +%= received.payload[received.payload.len - 1];
    }
    const into_elapsed = nowNs(io) -| into_started;
    const into_after = counting.snapshot();
    const into_allocations = into_after.alloc_count - into_before.alloc_count;
    if (into_allocations != 0) return error.UnexpectedAllocation;

    const owned_before = counting.snapshot();
    const owned_started = nowNs(io);
    var owned_checksum: u64 = 0;
    for (0..receive_iterations) |_| {
        var received = try session.receive();
        std.mem.doNotOptimizeAway(received.payload.ptr);
        owned_checksum +%= received.payload.len;
        owned_checksum +%= received.payload[0];
        owned_checksum +%= received.payload[received.payload.len - 1];
        received.deinit(allocator);
    }
    const owned_elapsed = nowNs(io) -| owned_started;
    const owned_after = counting.snapshot();
    const owned_allocations = owned_after.alloc_count -
        owned_before.alloc_count;
    const owned_frees = owned_after.free_count - owned_before.free_count;
    if (owned_allocations != receive_iterations or
        owned_frees != receive_iterations)
    {
        return error.UnexpectedAllocation;
    }

    std.debug.print(
        \\CONNECT-UDP Capsule Session benchmark
        \\  io backend: zio-std-io
        \\  payload bytes: {}, stream fragment bytes: {}
        \\  send:                 {} ns/datagram, allocations={}
        \\  caller-buffer receive:{} ns/datagram, allocations={}
        \\  owning receive:       {} ns/datagram, allocations={}
        \\  checksum: {}
        \\
    , .{
        payload.len,
        fragment_bytes,
        send_elapsed / send_iterations,
        send_allocations,
        into_elapsed / receive_iterations,
        into_allocations,
        owned_elapsed / receive_iterations,
        owned_allocations,
        session.tunnel.checksum +% into_checksum +% owned_checksum,
    });
}

fn buildSequence(
    out: []u8,
    payload: []const u8,
) ![]const u8 {
    var offset: usize = 0;
    var scratch: [payload_len + 32]u8 = undefined;
    const unknown_capsule = try netz.http3.capsule.writeInto(
        &scratch,
        0x21,
        "unknown-capsule",
    );
    append(out, &offset, unknown_capsule);

    var context_storage: [payload_len + 8]u8 = undefined;
    const unknown_context = try (netz.http3.connect_udp.ContextDatagram{
        .context_id = 2,
        .payload = "unknown-context",
    }).writeInto(&context_storage);
    const unknown_datagram = try netz.http3.capsule.writeDatagramInto(
        &scratch,
        unknown_context,
    );
    append(out, &offset, unknown_datagram);

    const context = try (netz.http3.connect_udp.ContextDatagram{
        .context_id = netz.http3.connect_udp.udp_context_id,
        .payload = payload,
    }).writeInto(&context_storage);
    const datagram = try netz.http3.capsule.writeDatagramInto(
        &scratch,
        context,
    );
    append(out, &offset, datagram);
    return out[0..offset];
}

fn append(out: []u8, offset: *usize, bytes: []const u8) void {
    @memcpy(out[offset.*..][0..bytes.len], bytes);
    offset.* += bytes.len;
}

fn nowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

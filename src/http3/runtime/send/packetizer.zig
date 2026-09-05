const std = @import("std");
const deadline_policy = @import("../../../internal/deadline.zig");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");

const net = std.Io.net;

const Range = struct { start: usize, len: usize };

/// Send an ordered HTTP/3 frame stream as MTU-sized QUIC packets.
///
/// Callers deliberately choose a STREAM payload target independently from
/// the current path MTU. In particular, the historical 1200-byte default is
/// a payload size, while a protected 1200-byte datagram must also contain the
/// short header, packet number, AEAD tag, and STREAM metadata. Keep the common
/// already-sized path allocation-free, then repacketize and split oversized
/// STREAM descriptors only when exact QUIC sizing says that it is necessary.
pub fn send(
    allocator: std.mem.Allocator,
    connection: *quic.one_rtt.Connection,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
) quic.one_rtt.Error!void {
    var backend = ConnectionBackend{ .connection = connection };
    sendWithBackend(
        allocator,
        &backend,
        frames,
        max_frames_per_packet,
    ) catch |err| {
        if (backend.visible_packet_sent and
            !connection.closing() and
            !connection.draining() and
            !connection.closed())
        {
            // The caller's logical HTTP/3 operation cannot reconstruct which
            // subset of a multi-packet HEADERS/Push/trailer sequence became
            // visible. Fail the connection closed before its transaction
            // rollback could permit different bytes at the same stream offset.
            connection.closeApplication(
                http3.ApplicationErrorCode.internal_error,
                "partial-http3-send",
            ) catch {};
        }
        return err;
    };
}

/// Reuse the same exact-size grouping and STREAM splitting with runtimes that
/// protect packets outside `one_rtt.Connection`, such as the preconfigured-key
/// HTTP/3 adapter. The backend owns packet-number and socket commit semantics.
pub fn sendWithBackend(
    allocator: std.mem.Allocator,
    backend: anytype,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
) !void {
    if (frames.len == 0) return;
    const frame_limit = @max(@as(usize, 1), max_frames_per_packet);
    if (try preflightFastPath(backend, frames, frame_limit)) {
        return sendFastPath(backend, frames, frame_limit);
    }

    var packetizer = Packetizer(@TypeOf(backend.*)).init(
        allocator,
        backend,
        frame_limit,
    );
    defer packetizer.deinit();
    for (frames) |frame| try packetizer.append(frame);
    try packetizer.finish();
}

/// Packetize cleartext development STREAM frames against the endpoint's real
/// UDP limit. A caller-provided attempt flag flips immediately before the first
/// socket call so higher layers can preserve their fail-closed retry policy.
pub fn sendEndpoint(
    allocator: std.mem.Allocator,
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    send_attempted: ?*bool,
) runtime_error.Error!void {
    return sendEndpointUntil(
        allocator,
        endpoint,
        to,
        frames,
        max_frames_per_packet,
        send_attempted,
        null,
    ) catch |err| switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => unreachable,
        else => |other| return @errorCast(other),
    };
}

pub fn sendEndpointUntil(
    allocator: std.mem.Allocator,
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    send_attempted: ?*bool,
    deadline: ?std.Io.Clock.Timestamp,
) runtime_error.ReceiveTimeoutError!void {
    var backend = EndpointBackend{
        .endpoint = endpoint,
        .to = to,
        .send_attempted = send_attempted,
        .deadline = deadline,
    };
    try sendWithBackend(
        allocator,
        &backend,
        frames,
        max_frames_per_packet,
    );
}

fn preflightFastPath(
    backend: anytype,
    frames: []const quic.Frame,
    frame_limit: usize,
) !bool {
    var packet_offset: usize = 0;
    var offset: usize = 0;
    while (offset < frames.len) : (packet_offset += 1) {
        const end = @min(frames.len, offset + frame_limit);
        if (try backend.packetLenForFramesAtOffset(
            packet_offset,
            frames[offset..end],
        ) > backend.maxDatagramSize()) return false;
        offset = end;
    }
    return true;
}

fn sendFastPath(
    backend: anytype,
    frames: []const quic.Frame,
    frame_limit: usize,
) !void {
    if (frames.len <= frame_limit) {
        try backend.sendPackets(&.{frames});
        return;
    }
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
        undefined;
    var packet_count: usize = 0;
    var offset: usize = 0;
    while (offset < frames.len) {
        const end = @min(frames.len, offset + frame_limit);
        packets[packet_count] = frames[offset..end];
        packet_count += 1;
        offset = end;
        if (packet_count == packets.len or offset == frames.len) {
            try backend.sendPackets(packets[0..packet_count]);
            packet_count = 0;
        }
    }
}

fn Packetizer(comptime Backend: type) type {
    return struct {
        const Self = @This();

        allocator: std.mem.Allocator,
        backend: *Backend,
        frame_limit: usize,
        frames: std.ArrayList(quic.Frame) = .empty,
        ranges: std.ArrayList(Range) = .empty,
        packet_start: usize = 0,

        fn init(
            allocator: std.mem.Allocator,
            backend: *Backend,
            frame_limit: usize,
        ) Self {
            return .{
                .allocator = allocator,
                .backend = backend,
                .frame_limit = frame_limit,
            };
        }

        fn deinit(self: *Self) void {
            self.ranges.deinit(self.allocator);
            self.frames.deinit(self.allocator);
            self.* = undefined;
        }

        fn currentLen(self: Self) usize {
            return self.frames.items.len - self.packet_start;
        }

        fn tryAppend(self: *Self, frame: quic.Frame) !bool {
            if (self.currentLen() == self.frame_limit) return false;
            try self.frames.append(self.allocator, frame);
            errdefer _ = self.frames.pop();
            const packet = self.frames.items[self.packet_start..];
            if (try self.backend.packetLenForFramesAtOffset(
                self.ranges.items.len,
                packet,
            ) <= self.backend.maxDatagramSize()) return true;
            _ = self.frames.pop();
            return false;
        }

        fn append(self: *Self, frame: quic.Frame) !void {
            if (frame != .stream or frame.stream.data.len == 0) {
                if (try self.tryAppend(frame)) return;
                if (self.currentLen() != 0) try self.finishPacket();
                if (!try self.tryAppend(frame)) return error.DatagramTooLarge;
                return;
            }

            const source = frame.stream;
            var consumed: usize = 0;
            while (consumed < source.data.len) {
                const remaining = source.data.len - consumed;
                if (try self.tryAppend(streamFragment(source, consumed, remaining))) {
                    return;
                }

                var low: usize = 1;
                var high: usize = remaining - 1;
                var fitting: usize = 0;
                while (low <= high) {
                    const candidate = low + (high - low) / 2;
                    if (try self.tryAppend(streamFragment(
                        source,
                        consumed,
                        candidate,
                    ))) {
                        fitting = candidate;
                        _ = self.frames.pop();
                        low = candidate + 1;
                    } else {
                        high = candidate - 1;
                    }
                }

                if (fitting == 0) {
                    if (self.currentLen() != 0) {
                        try self.finishPacket();
                        continue;
                    }
                    return error.DatagramTooLarge;
                }
                std.debug.assert(try self.tryAppend(streamFragment(
                    source,
                    consumed,
                    fitting,
                )));
                consumed += fitting;
                try self.finishPacket();
            }
        }

        fn finishPacket(self: *Self) !void {
            const len = self.currentLen();
            std.debug.assert(len != 0);
            try self.ranges.append(self.allocator, .{
                .start = self.packet_start,
                .len = len,
            });
            self.packet_start = self.frames.items.len;
        }

        fn finish(self: *Self) !void {
            if (self.currentLen() != 0) try self.finishPacket();
            var range_offset: usize = 0;
            var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
                undefined;
            while (range_offset < self.ranges.items.len) {
                const count = @min(
                    packets.len,
                    self.ranges.items.len - range_offset,
                );
                for (
                    self.ranges.items[range_offset..][0..count],
                    0..,
                ) |range, index| {
                    packets[index] = self.frames.items[range.start .. range.start + range.len];
                }
                try self.backend.sendPackets(packets[0..count]);
                range_offset += count;
            }
        }
    };
}

const ConnectionBackend = struct {
    connection: *quic.one_rtt.Connection,
    visible_packet_sent: bool = false,

    fn maxDatagramSize(self: ConnectionBackend) usize {
        return self.connection.currentSendDatagramSize();
    }

    fn packetLenForFramesAtOffset(
        self: ConnectionBackend,
        packet_offset: usize,
        frames: []const quic.Frame,
    ) quic.one_rtt.Error!usize {
        return self.connection.packetLenForFramesAtOffset(
            packet_offset,
            frames,
        );
    }

    fn sendPackets(
        self: *ConnectionBackend,
        packets: []const []const quic.Frame,
    ) quic.one_rtt.Error!void {
        var offset: usize = 0;
        while (offset < packets.len) {
            const result = self.connection.sendManyProgress(
                packets[offset..],
            ) catch |err| switch (err) {
                error.PacingLimited => {
                    try self.connection.waitForPacingAvailability();
                    continue;
                },
                else => return err,
            };
            if (result.sent_count != 0) self.visible_packet_sent = true;
            if (result.protected_count == 0) return error.MissingFrame;
            offset += result.protected_count;
            if (result.send_error) |err| return err;
            if (result.sent_count != result.protected_count) {
                return error.Unexpected;
            }
        }
    }
};

const EndpointBackend = struct {
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    send_attempted: ?*bool,
    deadline: ?std.Io.Clock.Timestamp,

    pub fn maxDatagramSize(self: EndpointBackend) usize {
        return self.endpoint.limits.max_datagram_size;
    }

    pub fn packetLenForFramesAtOffset(
        _: EndpointBackend,
        _: usize,
        frames: []const quic.Frame,
    ) runtime_error.Error!usize {
        var len: usize = 0;
        for (frames) |frame| {
            len = std.math.add(usize, len, try frame.wireLen()) catch
                return error.InvalidFrameLength;
        }
        return len;
    }

    pub fn sendPackets(
        self: *EndpointBackend,
        packets: []const []const quic.Frame,
    ) runtime_error.ReceiveTimeoutError!void {
        for (packets) |frames| {
            if (self.deadline) |deadline| {
                _ = try deadline_policy.usableAwake(
                    self.endpoint.io,
                    deadline,
                );
            }
            if (self.send_attempted) |attempted| attempted.* = true;
            try self.endpoint.sendFrames(self.to, frames);
        }
    }
};

fn streamFragment(
    source: quic.StreamFrame,
    consumed: usize,
    len: usize,
) quic.Frame {
    std.debug.assert(len != 0);
    std.debug.assert(consumed + len <= source.data.len);
    return .{ .stream = .{
        .stream_id = source.stream_id,
        .offset = source.offset + consumed,
        .fin = source.fin and consumed + len == source.data.len,
        .data = source.data[consumed .. consumed + len],
    } };
}

test "HTTP/3 packetizer preserves stream bytes FIN and MTU across batches" {
    const allocator = std.testing.allocator;
    const Backend = struct {
        const mtu: usize = 80;
        const packet_overhead: usize = 24;

        output: std.ArrayList(u8) = .empty,
        next_offset: u64 = 0,
        packet_count: usize = 0,
        batch_count: usize = 0,
        fin_count: usize = 0,

        pub fn maxDatagramSize(_: @This()) usize {
            return mtu;
        }

        pub fn packetLenForFramesAtOffset(
            _: @This(),
            _: usize,
            frames: []const quic.Frame,
        ) !usize {
            var len = packet_overhead;
            for (frames) |frame| {
                len = try std.math.add(usize, len, try frame.wireLen());
            }
            return len;
        }

        pub fn sendPackets(
            self: *@This(),
            packets: []const []const quic.Frame,
        ) !void {
            self.batch_count += 1;
            for (packets) |frames| {
                try std.testing.expect(
                    try self.packetLenForFramesAtOffset(0, frames) <= mtu,
                );
                self.packet_count += 1;
                for (frames) |frame| {
                    try std.testing.expect(frame == .stream);
                    try std.testing.expectEqual(
                        self.next_offset,
                        frame.stream.offset,
                    );
                    try self.output.appendSlice(
                        allocator,
                        frame.stream.data,
                    );
                    self.next_offset += frame.stream.data.len;
                    self.fin_count += @intFromBool(frame.stream.fin);
                }
            }
        }
    };

    var input: [8192]u8 = undefined;
    for (&input, 0..) |*byte, index| byte.* = @truncate(index);
    const source = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .data = &input,
        .fin = true,
    } }};
    var backend = Backend{};
    defer backend.output.deinit(allocator);

    try sendWithBackend(allocator, &backend, &source, 8);

    try std.testing.expect(
        backend.packet_count > quic.one_rtt.max_batch_packets,
    );
    try std.testing.expect(backend.batch_count > 1);
    try std.testing.expectEqual(@as(usize, 1), backend.fin_count);
    try std.testing.expectEqual(@as(u64, input.len), backend.next_offset);
    try std.testing.expectEqualSlices(u8, &input, backend.output.items);
}

fn checkPacketizerPlanningAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    const Backend = struct {
        sent: usize = 0,

        pub fn maxDatagramSize(_: @This()) usize {
            return 80;
        }

        pub fn packetLenForFramesAtOffset(
            _: @This(),
            _: usize,
            frames: []const quic.Frame,
        ) !usize {
            var len: usize = 24;
            for (frames) |frame| {
                len = try std.math.add(usize, len, try frame.wireLen());
            }
            return len;
        }

        pub fn sendPackets(
            self: *@This(),
            packets: []const []const quic.Frame,
        ) !void {
            self.sent += packets.len;
        }
    };

    var input: [8192]u8 = undefined;
    @memset(&input, 0xa5);
    const source = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = &input,
        .fin = true,
    } }};
    var backend = Backend{};
    sendWithBackend(allocator, &backend, &source, 8) catch |err| {
        try std.testing.expectEqual(@as(usize, 0), backend.sent);
        return err;
    };
}

test "HTTP/3 packetizer completes planning before its first send" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPacketizerPlanningAllocationFailure,
        .{},
    );
}

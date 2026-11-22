const std = @import("std");
const cancellation = @import("../../../internal/cancellation.zig");
const builtin = @import("builtin");
const deadline_policy = @import("../../../internal/deadline.zig");
const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");
const netz_runtime = @import("../../../runtime.zig");
const receive_policy = @import("policy.zig");

const Error = runtime_error.Error;
const ReceiveTimeoutError = runtime_error.ReceiveTimeoutError;
const RawDatagramBatch = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    datagrams: []quic.runtime.ReceivedBytesView,
    received_at_ns: u64 = 0,
    count: u8 = 0,
    next_index: u8 = 0,

    fn init(
        connection: *quic.one_rtt.Connection,
        max_datagrams: usize,
    ) Error!?RawDatagramBatch {
        const allocator = connection.endpoint.allocator;
        const datagram_size = connection.endpoint.receiveIntoCapacity();
        const slot_count = receive_policy.rawDatagramSlotCount(
            datagram_size,
            max_datagrams,
        );
        if (slot_count < 2) return null;
        const storage_len = std.math.mul(
            usize,
            datagram_size,
            slot_count,
        ) catch return error.OutOfMemory;
        const storage = try allocator.alloc(u8, storage_len);
        errdefer allocator.free(storage);
        return .{
            .allocator = allocator,
            .storage = storage,
            .datagrams = try allocator.alloc(
                quic.runtime.ReceivedBytesView,
                slot_count,
            ),
        };
    }

    fn deinit(self: *RawDatagramBatch) void {
        self.allocator.free(self.datagrams);
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn next(self: *RawDatagramBatch) ?quic.runtime.ReceivedBytesView {
        if (self.next_index == self.count) return null;
        const datagram = self.datagrams[self.next_index];
        self.next_index += 1;
        return datagram;
    }
};

/// Lazily drains one QUIC/GRO or independent-datagram receive batch a packet
/// at a time.
///
/// HTTP/3 stream readers intentionally observe only one packet before
/// returning control to the application. Retaining the unconsumed suffix here
/// preserves bounded DATA windows while amortizing receive and decryption.
pub const Connection = struct {
    batch: ?quic.one_rtt.ReceivedPacketBatch = null,
    raw_batch: ?RawDatagramBatch = null,
    ack_pending: bool = false,
    max_datagrams: usize = receive_policy.max_raw_datagram_batch,

    pub fn deinit(self: *Connection) void {
        if (self.batch) |*batch| batch.deinit();
        if (self.raw_batch) |*batch| batch.deinit();
        self.* = undefined;
    }

    fn visitRawDatagram(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        datagram: quic.runtime.ReceivedBytesView,
        received_at_ns: u64,
        context: anytype,
        comptime try_only: bool,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) Error!bool {
        const Context = @TypeOf(context);
        const AdapterContext = struct {
            cursor: *Connection,
            connection: *quic.one_rtt.Connection,
            context: Context,
        };
        const Adapter = struct {
            fn visit(
                adapter: *AdapterContext,
                packet: quic.one_rtt.ReceivedPacketView,
            ) Error!void {
                _ = try adapter.connection.retransmitPacketThresholdLosses(
                    quic.one_rtt.max_batch_packets,
                );
                if (try_only) {
                    _ = adapter.connection.trySendAckForPacketIfNeeded(
                        packet.packet_number,
                        packet.frames,
                    ) catch |err| {
                        cancellation.preserveIgnored(adapter.connection.endpoint.io, err);
                        adapter.cursor.ack_pending = true;
                    };
                } else {
                    _ = adapter.connection.sendAckForPacketIfNeeded(
                        packet.packet_number,
                        packet.frames,
                    ) catch |err| {
                        cancellation.preserveIgnored(adapter.connection.endpoint.io, err);
                        adapter.cursor.ack_pending = true;
                    };
                }
                try visitor(adapter.context, packet);
            }
        };
        var adapter: AdapterContext = .{
            .cursor = self,
            .connection = connection,
            .context = context,
        };
        return connection.visitReceivedDatagramAt(
            datagram,
            received_at_ns,
            &adapter,
            Adapter.visit,
        );
    }

    fn visitSingle(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        deadline: ?std.Io.Clock.Timestamp,
        context: anytype,
        comptime try_only: bool,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        const Context = @TypeOf(context);
        const AdapterContext = struct {
            cursor: *Connection,
            connection: *quic.one_rtt.Connection,
            context: Context,
        };
        const Adapter = struct {
            fn visit(
                adapter: *AdapterContext,
                packet: quic.one_rtt.ReceivedPacketView,
            ) Error!void {
                if (try_only) {
                    _ = adapter.connection.trySendAckForPacketIfNeeded(
                        packet.packet_number,
                        packet.frames,
                    ) catch |err| {
                        cancellation.preserveIgnored(adapter.connection.endpoint.io, err);
                        adapter.cursor.ack_pending = true;
                    };
                } else {
                    _ = adapter.connection.sendAckForPacketIfNeeded(
                        packet.packet_number,
                        packet.frames,
                    ) catch |err| {
                        cancellation.preserveIgnored(adapter.connection.endpoint.io, err);
                        adapter.cursor.ack_pending = true;
                    };
                }
                try visitor(adapter.context, packet);
            }
        };
        var adapter: AdapterContext = .{
            .cursor = self,
            .connection = connection,
            .context = context,
        };
        if (deadline) |absolute| {
            return connection.visitPacketServicingTimersDeadline(
                absolute,
                &adapter,
                Adapter.visit,
            );
        }
        return connection.visitPacketServicingTimers(
            &adapter,
            Adapter.visit,
        );
    }

    fn visitRetainedRawDatagram(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        context: anytype,
        comptime try_only: bool,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) Error!bool {
        const raw_batch = if (self.raw_batch) |*value| value else return false;
        while (raw_batch.next()) |datagram| {
            if (try self.visitRawDatagram(
                connection,
                datagram,
                raw_batch.received_at_ns,
                context,
                try_only,
                visitor,
            )) return true;
        }
        return false;
    }

    fn ensureRawBatch(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
    ) Error!?*RawDatagramBatch {
        if (self.raw_batch == null) {
            self.raw_batch = (try RawDatagramBatch.init(
                connection,
                self.max_datagrams,
            )) orelse return null;
        }
        return &self.raw_batch.?;
    }

    fn fillRawBatchWithDeadline(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!void {
        const raw_batch = (try self.ensureRawBatch(connection)) orelse
            return error.BufferTooShort;
        raw_batch.count = @intCast(try connection
            .receiveDatagramsIntoServicingTimersDeadline(
            raw_batch.storage,
            raw_batch.datagrams,
            deadline,
        ));
        raw_batch.next_index = 0;
        raw_batch.received_at_ns = monotonicNowNs(connection.endpoint.io);
    }

    pub fn visit(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) Error!void {
        if (self.ack_pending) {
            try connection.sendAck(0);
            self.ack_pending = false;
        }
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet_value| {
                var packet = packet_value;
                defer packet.deinit(connection.endpoint.allocator);
                return visitor(context, packetView(packet));
            }
            batch.deinit();
            self.batch = null;
        }
        if (!connection.endpoint.groReceiveEnabled()) {
            const raw_batch = (try self.ensureRawBatch(connection)) orelse {
                return self.visitSingle(
                    connection,
                    null,
                    context,
                    false,
                    visitor,
                ) catch |err| switch (err) {
                    error.Timeout, error.ConcurrencyUnavailable => unreachable,
                    else => |other| return @errorCast(other),
                };
            };
            while (true) {
                if (try self.visitRetainedRawDatagram(
                    connection,
                    context,
                    false,
                    visitor,
                )) return;
                raw_batch.count = @intCast(try connection
                    .receiveDatagramsIntoServicingTimers(
                    raw_batch.storage,
                    raw_batch.datagrams,
                ));
                raw_batch.next_index = 0;
                raw_batch.received_at_ns = monotonicNowNs(
                    connection.endpoint.io,
                );
            }
        }
        var batch = try connection.receivePacketBatchServicingTimers();
        errdefer batch.deinit();
        _ = connection.sendAckForPacketsIfNeeded(
            batch.packets[batch.next_index..],
        ) catch |err| {
            cancellation.preserveIgnored(connection.endpoint.io, err);
            self.ack_pending = true;
        };
        var packet = batch.takeNext() orelse return error.MissingStreamFrame;
        defer packet.deinit(connection.endpoint.allocator);
        self.batch = batch;
        return visitor(context, packetView(packet));
    }

    pub fn visitWithDeadline(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        // Validate before ACK emission or retained-GRO cursor advancement. An
        // expired or wrong-clock deadline is a side-effect-free operation.
        _ = try deadline_policy.usableAwake(
            connection.endpoint.io,
            deadline,
        );
        if (self.ack_pending) {
            // Outbound pacing must not block a deadline-bounded receive.
            // Keep the ACK pending for the next turn or the delayed-ACK timer.
            if (connection.trySendAck(0)) |_| {
                self.ack_pending = false;
            } else |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => {},
                else => |other| return other,
            }
        }
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet_value| {
                var packet = packet_value;
                defer packet.deinit(connection.endpoint.allocator);
                return visitor(context, packetView(packet));
            }
            batch.deinit();
            self.batch = null;
        }
        if (!connection.endpoint.groReceiveEnabled()) {
            if ((try self.ensureRawBatch(connection)) == null) {
                return self.visitSingle(
                    connection,
                    deadline,
                    context,
                    true,
                    visitor,
                );
            }
            while (true) {
                if (try self.visitRetainedRawDatagram(
                    connection,
                    context,
                    true,
                    visitor,
                )) return;
                try self.fillRawBatchWithDeadline(connection, deadline);
            }
        } else {
            return self.visitBatchWithDeadline(
                connection,
                deadline,
                context,
                visitor,
            );
        }
    }

    fn visitBatchWithDeadline(
        self: *Connection,
        connection: *quic.one_rtt.Connection,
        deadline: std.Io.Clock.Timestamp,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) (Error || quic.runtime.ReceiveTimeoutError)!void {
        var batch = try connection.receivePacketBatchServicingTimersDeadline(
            deadline,
        );
        errdefer batch.deinit();
        _ = connection.trySendAckForPacketsIfNeeded(
            batch.packets[batch.next_index..],
        ) catch |err| {
            cancellation.preserveIgnored(connection.endpoint.io, err);
            self.ack_pending = true;
        };
        var packet = batch.takeNext() orelse return error.MissingStreamFrame;
        defer packet.deinit(connection.endpoint.allocator);
        self.batch = batch;
        return visitor(context, packetView(packet));
    }
};

fn monotonicNowNs(io: std.Io) u64 {
    const timestamp = std.Io.Clock.awake.now(io).nanoseconds;
    if (timestamp <= 0) return 0;
    return std.math.cast(u64, timestamp) orelse std.math.maxInt(u64);
}

pub fn packetView(
    packet: quic.one_rtt.ReceivedPacket,
) quic.one_rtt.ReceivedPacketView {
    return .{
        .from = packet.from,
        .packet_number = packet.packet.packet_number,
        .frames = packet.frames,
        .peer_initiated_key_update = packet.peer_initiated_key_update,
    };
}

test "HTTP/3 connection cursor deadline validation preserves retained batch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x5a} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cursor-local",
        .peer_connection_id = "cursor-peer",
    });
    defer connection.deinit();

    const frames = try allocator.alloc(quic.Frame, 1);
    frames[0] = .{ .ping = {} };
    const packets = try allocator.alloc(quic.one_rtt.ReceivedPacket, 1);
    packets[0] = .{
        .from = endpoint.address(),
        .packet = .{
            .destination_connection_id = try allocator.dupe(
                u8,
                "cursor-local",
            ),
            .packet_number = 7,
            .fixed_bit = true,
            .spin_bit = false,
            .key_phase = false,
            .payload = try allocator.alloc(u8, 0),
        },
        .frames = frames,
    };
    var cursor = Connection{
        .batch = .{ .allocator = allocator, .packets = packets },
        .ack_pending = true,
    };
    defer cursor.deinit();

    const Visitor = struct {
        fn visit(count: *usize, packet: quic.one_rtt.ReceivedPacketView) Error!void {
            if (packet.packet_number != 7) return error.InvalidPacketNumber;
            count.* += 1;
        }
    };
    var visits: usize = 0;
    try std.testing.expectError(
        error.Timeout,
        cursor.visitWithDeadline(
            &connection,
            .{ .clock = .real, .raw = .zero },
            &visits,
            Visitor.visit,
        ),
    );
    try std.testing.expect(cursor.ack_pending);
    try std.testing.expectEqual(@as(usize, 0), visits);
    try std.testing.expectEqual(@as(usize, 0), cursor.batch.?.next_index);

    try std.testing.expectError(
        error.Timeout,
        cursor.visitWithDeadline(
            &connection,
            .{ .clock = .awake, .raw = .zero },
            &visits,
            Visitor.visit,
        ),
    );
    try std.testing.expect(cursor.ack_pending);
    try std.testing.expectEqual(@as(usize, 0), visits);
    try std.testing.expectEqual(@as(usize, 0), cursor.batch.?.next_index);

    cursor.ack_pending = false;
    try cursor.visitWithDeadline(
        &connection,
        .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        &visits,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 1), visits);
    try std.testing.expectEqual(@as(usize, 1), cursor.batch.?.next_index);
}

test "HTTP/3 connection cursor disables raw batching at one datagram" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        threaded.io(),
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = receive_policy.default_endpoint_max_datagram_size },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x6b} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cursor-single",
        .peer_connection_id = "cursor-peer",
    });
    defer connection.deinit();

    var cursor: Connection = .{ .max_datagrams = 1 };
    defer cursor.deinit();
    try std.testing.expect((try cursor.ensureRawBatch(&connection)) == null);
    try std.testing.expect(cursor.raw_batch == null);
}

test "HTTP/3 connection cursor batches zio UDP but applies one packet at a time" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var backend = try netz_runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = receive_policy.default_endpoint_max_datagram_size,
            .max_frames_per_datagram = 8,
            .enable_gso_send = false,
        },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_datagram_size = receive_policy.default_endpoint_max_datagram_size,
            .max_frames_per_datagram = 8,
            .enable_gso_send = false,
        },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x6a} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&receiver, .{
        .peer = sender.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "cursor-batch",
        .peer_connection_id = "cursor-peer",
        .local_endpoint = .server,
        .enable_pacing = false,
        .local_ack_eliciting_threshold = 2,
        .local_max_ack_delay_us = 25_000,
    });
    defer connection.deinit();

    const first_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = "first",
        .fin = false,
    } }};
    const second_frames = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = "second",
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &first_frames, &second_frames };
    try quic.one_rtt.sendFramesBatch(
        &sender,
        receiver.address(),
        keys,
        .{
            .destination_connection_id = "cursor-batch",
            .first_packet_number = 0,
            .packets = &packets,
        },
    );

    const VisitContext = struct {
        packet_numbers: *[2]u64,
        reject_first: bool = true,
    };
    const Visitor = struct {
        fn visit(
            context: *VisitContext,
            packet: quic.one_rtt.ReceivedPacketView,
        ) Error!void {
            const index = @as(usize, @intCast(packet.packet_number));
            if (index >= context.packet_numbers.len) {
                return error.InvalidPacketNumber;
            }
            context.packet_numbers[index] = packet.packet_number;
            if (context.reject_first) {
                context.reject_first = false;
                return error.InvalidFrame;
            }
        }
    };
    var cursor: Connection = .{};
    defer cursor.deinit();
    var packet_numbers = [_]u64{std.math.maxInt(u64)} ** 2;
    var visit_context = VisitContext{ .packet_numbers = &packet_numbers };
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .clock = .awake,
        .raw = .fromSeconds(1),
    });

    try std.testing.expectError(
        error.InvalidFrame,
        cursor.visitWithDeadline(
            &connection,
            deadline,
            &visit_context,
            Visitor.visit,
        ),
    );
    try std.testing.expectEqual(@as(u64, 0), packet_numbers[0]);
    try std.testing.expectEqual(std.math.maxInt(u64), packet_numbers[1]);
    try std.testing.expectEqual(@as(u64, 1), connection.stats().packets_received);
    try std.testing.expect(connection.ackDelayDeadline() != null);
    try std.testing.expect(cursor.raw_batch != null);
    try std.testing.expectEqual(
        @as(usize, receive_policy.max_raw_datagram_batch),
        cursor.raw_batch.?.datagrams.len,
    );
    try std.testing.expectEqual(
        @as(usize, receive_policy.raw_datagram_storage_limit),
        cursor.raw_batch.?.storage.len,
    );
    const batch_received_at_ns = cursor.raw_batch.?.received_at_ns;
    try std.testing.expect(batch_received_at_ns != 0);
    try std.testing.expectEqual(@as(usize, 1), cursor.raw_batch.?.count - cursor.raw_batch.?.next_index);
    const retained_index = cursor.raw_batch.?.next_index;
    try std.testing.expectError(
        error.Timeout,
        cursor.visitWithDeadline(
            &connection,
            .{ .clock = .real, .raw = .zero },
            &visit_context,
            Visitor.visit,
        ),
    );
    try std.testing.expectEqual(
        retained_index,
        cursor.raw_batch.?.next_index,
    );

    try cursor.visitWithDeadline(
        &connection,
        deadline,
        &visit_context,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(u64, 1), packet_numbers[1]);
    try std.testing.expectEqual(@as(u64, 2), connection.stats().packets_received);
    try std.testing.expectEqual(@as(?u64, null), connection.ackDelayDeadline());
    try std.testing.expectEqual(
        batch_received_at_ns,
        cursor.raw_batch.?.received_at_ns,
    );
    try std.testing.expectEqual(@as(usize, 0), cursor.raw_batch.?.count - cursor.raw_batch.?.next_index);
}

/// Stateless-key counterpart used by the preconfigured protected runtime.
pub const Protected = struct {
    const Batch = struct {
        allocator: std.mem.Allocator,
        packets: []quic.one_rtt.ReceivedPacket,
        next_index: usize = 0,

        fn deinit(self: *Batch) void {
            for (self.packets[self.next_index..]) |*packet| {
                packet.deinit(self.allocator);
            }
            self.allocator.free(self.packets);
            self.* = undefined;
        }

        fn takeNext(self: *Batch) ?quic.one_rtt.ReceivedPacket {
            if (self.next_index == self.packets.len) return null;
            const packet = self.packets[self.next_index];
            self.next_index += 1;
            return packet;
        }
    };

    batch: ?Batch = null,

    pub fn deinit(self: *Protected) void {
        if (self.batch) |*batch| batch.deinit();
        self.* = undefined;
    }

    pub fn take(
        self: *Protected,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
    ) Error!quic.one_rtt.ReceivedPacket {
        return self.takeUntil(
            endpoint,
            keys,
            destination_connection_id_len,
            expected_packet_number,
            max_frames,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn takeWithDeadline(
        self: *Protected,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!quic.one_rtt.ReceivedPacket {
        _ = try deadline_policy.usableAwake(endpoint.io, deadline);
        return self.takeUntil(
            endpoint,
            keys,
            destination_connection_id_len,
            expected_packet_number,
            max_frames,
            .{ .deadline = deadline },
        );
    }

    fn takeUntil(
        self: *Protected,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
        timeout: ?std.Io.Timeout,
    ) ReceiveTimeoutError!quic.one_rtt.ReceivedPacket {
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet| {
                expected_packet_number.* = packet.packet.packet_number + 1;
                return packet;
            }
            batch.deinit();
            self.batch = null;
        }

        if (!endpoint.groReceiveEnabled()) {
            var datagram = if (timeout) |bounded|
                try endpoint.receiveBytesTimeout(bounded)
            else
                try endpoint.receiveBytes();
            defer datagram.deinit(endpoint.allocator);
            const packet = try quic.one_rtt.openReceivedBytes(
                endpoint,
                datagram.from,
                datagram.bytes,
                keys,
                destination_connection_id_len,
                expected_packet_number.*,
                max_frames,
            );
            expected_packet_number.* = packet.packet.packet_number + 1;
            return packet;
        }
        var datagrams = if (timeout) |bounded|
            try endpoint.receiveBytesBatchTimeout(bounded)
        else
            try endpoint.receiveBytesBatch();
        defer datagrams.deinit(endpoint.allocator);
        const packets = try endpoint.allocator.alloc(
            quic.one_rtt.ReceivedPacket,
            datagrams.segment_count,
        );
        var completed: usize = 0;
        errdefer {
            for (packets[0..completed]) |*packet| {
                packet.deinit(endpoint.allocator);
            }
            endpoint.allocator.free(packets);
        }
        var next_expected = expected_packet_number.*;
        for (packets, 0..) |*packet, index| {
            const bytes = datagrams.datagramAt(index) orelse
                return error.InvalidPacket;
            packet.* = try quic.one_rtt.openReceivedBytes(
                endpoint,
                datagrams.from,
                bytes,
                keys,
                destination_connection_id_len,
                next_expected,
                max_frames,
            );
            next_expected = packet.packet.packet_number + 1;
            completed += 1;
        }
        var batch = Batch{
            .allocator = endpoint.allocator,
            .packets = packets,
        };
        const packet = batch.takeNext() orelse return error.MissingStreamFrame;
        expected_packet_number.* = packet.packet.packet_number + 1;
        self.batch = batch;
        return packet;
    }
};

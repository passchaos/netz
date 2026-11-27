//! Exercise the actual shared input and connection owners on both native I/O backends.
const std = @import("std");
const quic = @import("../netz.zig").quic;
const limits = @import("../runtime/limits.zig");
const tls_testing = @import("../../tls/testing.zig");
const Native = @import("../../internal/testing/deadline_send_io.zig").Native;
const native = @import("../../internal/testing/native_protocol_io.zig");
const budget = @import("service_turn.zig");
const allocator = std.testing.allocator;

fn Fixture(comptime Pump: type, comptime Connection: type, comptime config: anytype, comptime connected: anytype) type {
    return struct {
        io: std.Io,
        endpoint: quic.runtime.Endpoint,
        limiter: limits.ConnectionLimiter,
        pump: Pump,
        certificate: [65]u8,
        chain: [1][]const u8,

        fn init(self: *@This(), io: std.Io, service_io: std.Io) !void {
            self.io = io;
            const key = try tls_testing.serverKeyPair();
            self.certificate = key.public_key.toUncompressedSec1();
            self.chain = .{&self.certificate};
            var options = config;
            options.max_datagram_size = 32768;
            options.identity = .{ .certificate_chain = &self.chain, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } };
            self.endpoint = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
            errdefer self.endpoint.deinit();
            self.limiter = try limits.ConnectionLimiter.init(allocator, io, options.limits);
            errdefer self.limiter.deinit();
            self.pump = try Pump.init(allocator, service_io, &self.endpoint, options, &self.limiter, &running);
        }

        // All fixture instances run sequentially; the production pump is
        // driven explicitly rather than started on another thread.
        var running: std.atomic.Value(bool) = .init(true);

        fn deinit(self: *@This()) void {
            self.pump.deinit();
            self.limiter.deinit();
            self.endpoint.deinit();
        }

        fn add(self: *@This(), index: u8, peer: std.Io.net.IpAddress) !*Connection {
            var cid = [_]u8{0x62} ** 8;
            cid[0] = index;
            const keys = quic.protection.deriveAes128Keys([_]u8{0x53} ** 32);
            const established = try allocator.create(quic.handshake.EstablishedConnection);
            established.* = quic.handshake.establishPreconfigured(&self.endpoint, peer, .server, .{
                .local_connection_id = &cid,
                .peer_connection_id = "sender",
                .receive_keys = keys,
                .send_keys = keys,
                .one_rtt = .{ .enable_pacing = false },
            }) catch |err| {
                allocator.destroy(established);
                return err;
            };
            const handle = self.pump.shared.adoptConnection(established) catch |err| {
                established.deinit();
                allocator.destroy(established);
                return err;
            };
            connected(&self.pump, handle);
            return self.pump.by_handle.get(handle) orelse error.AdmissionFailed;
        }
    };
}

pub fn inputs(comptime Pump: type, comptime Connection: type, comptime config: anytype, comptime connected: anytype, comptime streams: anytype, comptime datagrams: anytype, comptime inbox: anytype, comptime tuic: bool) !void {
    const Case = struct {
        fn run(base: std.Io) !void {
            var clock: Native = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .delegate_io = base };
            defer clock.backend.deinit();
            var fixture: Fixture(Pump, Connection, config, connected) = undefined;
            try fixture.init(base, clock.io());
            defer fixture.deinit();
            var peer_endpoint = try quic.runtime.Endpoint.bind(allocator, fixture.io, .{ .ip4 = .loopback(0) }, .{ .max_datagram_size = 4096 });
            defer peer_endpoint.deinit();
            const conn = try fixture.add(0, peer_endpoint.address());
            if (!tuic) {
                conn.authenticated = true;
                conn.control_stream = 0;
            }

            // Queue more than one turn of protected STREAM data, including
            // FIN. The pump must keep the suffix in QUIC and resume exactly.
            const keys = quic.protection.deriveAes128Keys([_]u8{0x53} ** 32);
            var sender = try quic.one_rtt.Connection.init(&peer_endpoint, .{
                .peer = fixture.endpoint.address(),
                .local_connection_id = "sender",
                .peer_connection_id = conn.established.local_connection_id,
                .receive_keys = keys,
                .send_keys = keys,
                .enable_pacing = false,
                .max_datagram_size = 4096,
                .initial_send_max_data = 256 * 1024,
                .initial_send_max_stream_data = 256 * 1024,
            });
            defer sender.deinit();
            // This fixture qualifies input scheduling, independently of
            // congestion-control qualification in the original tests.
            sender.congestion.congestion_window = 256 * 1024;
            const id = try sender.openStream();
            try std.testing.expectEqual(@as(u64, 0), id);
            var payload: [budget.input_bytes + 4096 + 7]u8 = undefined;
            for (&payload, 0..) |*byte, i| byte.* = @intCast(i % 251);
            var offset: usize = 0;
            while (offset < payload.len) {
                const end = @min(offset + 3000, payload.len);
                try sender.send(&.{.{ .stream = .{ .stream_id = id, .offset = offset, .data = payload[offset..end], .fin = end == payload.len } }});
                var packet = try conn.established.connection.receivePacketTimeout(.{ .duration = .{ .clock = .awake, .raw = .fromSeconds(1) } });
                packet.deinit(allocator);
                offset = end;
            }
            const entry = conn.established.connection.findRecvStreamEntry(id).?;
            try std.testing.expectEqual(@as(u64, 0), entry.recv_state.read_offset);
            try streams(conn);
            try std.testing.expectEqual(@as(u64, budget.input_bytes), entry.recv_state.read_offset);
            try std.testing.expect(!entry.fin_reported);
            if (tuic) {
                try std.testing.expectEqualSlices(u8, payload[0..budget.input_bytes], conn.pending[0].input.bytes());
                try std.testing.expect(!conn.pending[0].fin);
            }
            try streams(conn);
            try std.testing.expectEqual(@as(u64, payload.len), entry.recv_state.read_offset);
            try std.testing.expect(entry.fin_reported);
            if (tuic) {
                try std.testing.expectEqualSlices(u8, &payload, conn.pending[0].input.bytes());
                try std.testing.expect(conn.pending[0].fin);
            }

            // Invalid protocol packets still consume their scheduling budget.
            // Check the untouched suffix before allowing the next turn.
            const queue = &conn.established.connection.datagram_recv_queue;
            for (0..40) |i| {
                const bytes = [_]u8{ 0xff, @intCast(i), 0xaa, 0xbb };
                try std.testing.expect((try queue.pushCopyWithinLimits(allocator, &bytes, i, 64, 256 * 1024)).accepted);
            }
            datagrams(conn);
            try std.testing.expectEqual(@as(usize, 24), queue.count());
            for (0..24) |i| {
                const index = (queue.head + i) % queue.slots.items.len;
                try std.testing.expectEqualSlices(u8, &.{ 0xff, @intCast(i + 16), 0xaa, 0xbb }, queue.slots.items[index].?.payload);
            }
            datagrams(conn);
            try std.testing.expectEqual(@as(usize, 8), queue.count());
            datagrams(conn);
            try std.testing.expectEqual(@as(usize, 0), queue.count());

            // Wider configured buffers still yield at the byte boundary,
            // while the last admitted packet remains whole.
            var wide: [24001]u8 = @splat(0xff);
            for (0..8) |i| {
                wide[1] = @intCast(i);
                try std.testing.expect((try queue.pushCopyWithinLimits(allocator, &wide, i, 64, 256 * 1024)).accepted);
            }
            datagrams(conn);
            try std.testing.expectEqual(@as(usize, 5), queue.count());
            for (0..5) |i| {
                wide[1] = @intCast(i + 3);
                const index = (queue.head + i) % queue.slots.items.len;
                try std.testing.expectEqualSlices(u8, &wide, queue.slots.items[index].?.payload);
            }
            datagrams(conn);
            try std.testing.expectEqual(@as(usize, 2), queue.count());
            datagrams(conn);
            try std.testing.expectEqual(@as(usize, 0), queue.count());

            // A producer can refill the production inbox while it is drained.
            // Expanded fixture storage makes that backlog deterministic.
            var commands: [40]@TypeOf(conn.inbox_storage[0]) = undefined;
            conn.inbox = .init(&commands);
            defer conn.inbox = .init(&conn.inbox_storage);
            for (0..40) |i| try conn.inbox.putOne(fixture.io, .{ .relay_failed = .{ .stream_id = 1000 + i } });
            conn.pending[1] = .{ .active = true, .connecting = true, .stream_id = 1039 };
            try inbox(conn);
            try std.testing.expect(conn.pending[1].active);
            var remaining: [40]@TypeOf(conn.inbox_storage[0]) = undefined;
            const count = try conn.inbox.get(fixture.io, &remaining, 0);
            try std.testing.expectEqual(@as(usize, 24), count);
            for (remaining[0..count], 16..) |command, i| {
                try std.testing.expectEqual(@as(u64, 1000 + i), command.relay_failed.stream_id);
                try conn.inbox.putOne(fixture.io, command);
            }
            try inbox(conn);
            try std.testing.expect(conn.pending[1].active);
            try inbox(conn);
            try std.testing.expect(!conn.pending[1].active);
            // Restore the storage before its stack lifetime ends.
            conn.inbox = .init(&conn.inbox_storage);
        }
    };
    try native.run(Case.run);
}

pub fn rotation(comptime Pump: type, comptime Connection: type, comptime config: anytype, comptime connected: anytype, comptime service: anytype) !void {
    const Case = struct {
        fn run(base: std.Io) !void {
            var clock: Native = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .delegate_io = base };
            defer clock.backend.deinit();
            var fixture: Fixture(Pump, Connection, config, connected) = undefined;
            try fixture.init(base, clock.io());
            defer fixture.deinit();
            for (0..33) |i| {
                const conn = try fixture.add(@intCast(i), .{ .ip4 = .loopback(1234) });
                conn.authenticated = true;
            }
            const hot = fixture.pump.connections.items[0];
            const expired = fixture.pump.connections.items[32];
            const expired_handle = expired.handle;
            expired.authenticated = false;
            expired.created_ns = -@as(i64, @intCast(fixture.pump.config.auth_timeout.nanoseconds));
            // Retiring a middle slot must not skip the last connection that
            // swapRemove moves into it, or suppress later timeout checks.
            fixture.pump.connections.items[1].closed.store(true, .release);
            for (0..40) |i| try std.testing.expect((try hot.established.connection.datagram_recv_queue.pushCopyWithinLimits(allocator, &.{ 0xff, @intCast(i) }, i, 64, 128)).accepted);
            service(&fixture.pump);
            try std.testing.expect(fixture.pump.by_handle.contains(expired_handle));
            try std.testing.expectEqual(@as(usize, 32), fixture.pump.connections.items.len);
            try std.testing.expectEqual(@as(usize, 24), hot.established.connection.datagram_recv_queue.count());
            for (0..4) |_| service(&fixture.pump);
            try std.testing.expect(!fixture.pump.by_handle.contains(expired_handle));
            try std.testing.expectEqual(@as(usize, 31), fixture.pump.connections.items.len);
            try std.testing.expectEqual(@as(usize, 0), hot.established.connection.datagram_recv_queue.count());
        }
    };
    try native.run(Case.run);
}

test "proxy service turn checks fresh time after progress and retains packet boundaries" {
    var clock: Native = .{ .backend = .init(allocator, .{ .async_limit = .nothing }) };
    defer clock.backend.deinit();
    const io = clock.io();
    var turn = budget.Turn.init(io, 16, 64);
    clock.setNow(3 * std.time.ns_per_ms);
    try std.testing.expect(turn.take(io));
    turn.consume(17);
    try std.testing.expect(!turn.take(io));
    turn = budget.Turn.init(io, 16, 64);
    try std.testing.expect(turn.take(io));
    turn.consume(100);
    try std.testing.expect(!turn.take(io));
}

test "proxy service rotation preserves the next identity after swap removal" {
    var rotation_state: budget.Rotation = .{};
    for (0..3) |i| try std.testing.expectEqual(i, rotation_state.next(4));
    rotation_state.removed(2, 4);
    try std.testing.expectEqual(@as(usize, 2), rotation_state.next(3));
    rotation_state.removed(2, 3);
    try std.testing.expectEqual(@as(usize, 0), rotation_state.next(2));
    rotation_state.removed(0, 2);
    try std.testing.expectEqual(@as(usize, 0), rotation_state.next(1));
    rotation_state.removed(0, 1);
    try std.testing.expectEqual(@as(usize, 0), rotation_state.next_index);
}

pub fn completions(comptime Pump: type, comptime Connection: type, comptime config: anytype, comptime connected: anytype, comptime service: anytype) !void {
    const Case = struct {
        fn run(base: std.Io) !void {
            var clock: Native = .{ .backend = .init(allocator, .{ .async_limit = .nothing }), .delegate_io = base };
            defer clock.backend.deinit();
            var fixture: Fixture(Pump, Connection, config, connected) = undefined;
            try fixture.init(base, clock.io());
            defer fixture.deinit();
            for (0..33) |i| _ = try fixture.add(@intCast(i), .{ .ip4 = .loopback(1234) });
            fixture.pump.ready_remaining = 33;
            service(&fixture.pump);
            try std.testing.expectEqual(@as(usize, 17), fixture.pump.ready_remaining);
            try std.testing.expectEqual(@as(usize, 16), fixture.pump.ready_rotation.next_index);
            // A closed owner still consumes its visit, without stranding
            // any later completion after the notification was consumed.
            fixture.pump.connections.items[16].closed.store(true, .release);
            service(&fixture.pump);
            try std.testing.expectEqual(@as(usize, 1), fixture.pump.ready_remaining);
            service(&fixture.pump);
            try std.testing.expectEqual(@as(usize, 0), fixture.pump.ready_remaining);
            try std.testing.expectEqual(@as(usize, 0), fixture.pump.ready_rotation.next_index);
        }
    };
    try native.run(Case.run);
}

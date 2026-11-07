//! Deterministic durable state with nonempty coverage of all snapshot sections.
const std = @import("std");
const netz = @import("netz");
const options = @import("options.zig");
const mqtt = netz.mqtt;
const expiry = std.math.maxInt(u32);
pub const monotonic = std.Io.Timestamp.zero;
pub const realtime = std.Io.Timestamp.fromNanoseconds(1_700_000_000 * std.time.ns_per_s);

pub const Verification = struct {
    sessions: usize,
    queued_messages: usize,
    snapshot_bytes: usize,
    checksum: u64,
    snapshot_crc32: u32,
    snapshot_sha256: [32]u8,
};

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    broker: mqtt.broker.Broker,
    session_count: usize,
    metadata: []u8,
    checksum: u64,

    pub fn init(allocator: std.mem.Allocator, io: std.Io, session_count: usize, metadata_bytes: usize) !Fixture {
        var broker = try mqtt.broker.Broker.init(allocator, io, .{
            .limits = .{ .max_connections = 1, .max_pending_incoming_qos2 = 1 },
            .session = .{
                .max_sessions = session_count,
                .max_queued_per_session = options.queued_per_session,
                .max_inflight_per_session = options.queued_per_session,
                .max_incoming_qos2_per_session = 1,
            },
            .retained = .{ .max_messages = 1 },
            .will = .{ .max_wills = 1 },
            .bridge_qos2 = .{ .max_entries = 1 },
        });
        errdefer broker.deinit();
        const metadata = try allocator.alloc(u8, metadata_bytes);
        errdefer allocator.free(metadata);
        for (metadata, 0..) |*byte, index| byte.* = @truncate(index *% 17 +% 3);
        const properties = [_]mqtt.Property{.{ .binary = .{ .id = .correlation_data, .value = metadata } }};
        var hash = std.hash.Wyhash.init(7);
        var first_route: u64 = 0;
        for (0..session_count) |session_index| {
            var client_buffer: [64]u8 = undefined;
            const client_id = try clientId(&client_buffer, session_index);
            const opened = try broker.sessions.open(client_id, false, expiry, monotonic);
            if (session_index == 0) first_route = opened.route_id;
            hash.update(client_id);
            for (0..options.queued_per_session) |message_index| {
                var topic_buffer: [64]u8 = undefined;
                const topic = try messageTopic(&topic_buffer, session_index, message_index);
                var payload: [options.payload_bytes]u8 = undefined;
                fillPayload(&payload, session_index, message_index);
                const result = try broker.sessions.enqueuePublish(opened.handle, topic, &payload, .{
                    .qos = .at_least_once,
                    .properties = if (metadata.len == 0) &.{} else &properties,
                    .now = monotonic,
                });
                if (result != .queued) return error.IncompleteBenchmarkFixture;
                hash.update(topic);
                hash.update(&payload);
                hash.update(metadata);
            }
            try broker.sessions.disconnect(opened.handle, null, monotonic);
        }
        _ = try broker.retained.applyPublish("bench/compat/retained", "retained", .{ .retain = true, .now = monotonic });
        var will_properties = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = expiry } }};
        const will = try broker.wills.set("bench-compat-will", .{
            .topic = "bench/compat/will",
            .payload = "will",
            .qos = .at_least_once,
            .retain = true,
            .properties = &will_properties,
        }, expiry);
        _ = try broker.wills.close(will, .ungraceful, monotonic);
        try broker.will_publishers.put(allocator, will, 77);
        _ = try broker.pending_qos2.record((@as(u64, 1) << 63) | first_route, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "bench/compat/incoming",
            .packet_id = 9,
            .payload = "incoming",
        }, monotonic);
        _ = try broker.bridge_qos2.stage(.{
            .bridge_id = [_]u8{0x5a} ** 16,
            .session_epoch = 7,
            .packet_id = 44,
        }, .{
            .dup = false,
            .qos = .exactly_once,
            .retain = false,
            .topic = "bench/compat/bridge",
            .packet_id = null,
            .payload = "bridge",
        }, monotonic);
        return .{ .allocator = allocator, .broker = broker, .session_count = session_count, .metadata = metadata, .checksum = hash.final() };
    }

    pub fn deinit(self: *Fixture) void {
        self.broker.deinit();
        self.allocator.free(self.metadata);
        self.* = undefined;
    }

    /// Standalone serialization keeps both clock inputs fixed for exact
    /// before/after byte compatibility. Combined append uses Broker's clocks.
    pub fn capture(self: *Fixture) ![]u8 {
        self.broker.state_mutex.lockUncancelable(self.broker.io);
        defer self.broker.state_mutex.unlock(self.broker.io);
        return mqtt.persistence.encodeLive(self.allocator, .{
            .retained = &self.broker.retained,
            .sessions = &self.broker.sessions,
            .wills = &self.broker.wills,
            .will_publishers = &self.broker.will_publishers,
            .pending_qos2 = &self.broker.pending_qos2,
            .bridge_qos2 = &self.broker.bridge_qos2,
        }, monotonic, realtime);
    }

    pub fn validate(self: *Fixture, encoded: []const u8, live_timestamps: bool) !Verification {
        const now = if (live_timestamps) std.Io.Clock.awake.now(self.broker.io) else monotonic;
        const real_now = if (live_timestamps) std.Io.Clock.real.now(self.broker.io) else realtime;
        var restored = try mqtt.persistence.decode(self.allocator, encoded, self.broker.options.retained, self.broker.options.session, self.broker.options.will, self.broker.options.limits.max_pending_incoming_qos2, self.broker.options.bridge_qos2, now, real_now);
        defer restored.retained.deinit();
        defer restored.sessions.deinit();
        defer restored.wills.deinit();
        defer restored.will_publishers.deinit(self.allocator);
        defer restored.pending_qos2.deinit();
        defer restored.bridge_qos2.deinit();
        const stats = restored.sessions.aggregateStats();
        if (stats.session_count != self.session_count or stats.connected_count != 0 or
            stats.disconnected_count != self.session_count or stats.queued_count != self.session_count * options.queued_per_session or
            stats.queued_payload_bytes != stats.queued_count * options.payload_bytes or stats.inflight_count != 0 or
            restored.retained.count() != 1 or restored.wills.count() != 1 or restored.will_publishers.count() != 1 or
            restored.pending_qos2.count() != 1 or restored.bridge_qos2.stats().entries != 1)
        {
            return error.RestoredBenchmarkStateMismatch;
        }
        var hash = std.hash.Wyhash.init(7);
        for (0..self.session_count) |session_index| {
            var client_buffer: [64]u8 = undefined;
            const client_id = try clientId(&client_buffer, session_index);
            const opened = try restored.sessions.open(client_id, false, expiry, now);
            if (!opened.session_present) return error.RestoredBenchmarkStateMismatch;
            hash.update(client_id);
            var output: [options.queued_per_session]mqtt.session.Transmission = undefined;
            const messages = try restored.sessions.drainInto(opened.handle, now, options.queued_per_session, &output);
            if (messages.len != options.queued_per_session) return error.RestoredBenchmarkStateMismatch;
            for (messages, 0..) |message, message_index| {
                if (message != .publish) return error.RestoredBenchmarkStateMismatch;
                const value = message.publish;
                var topic_buffer: [64]u8 = undefined;
                const topic = try messageTopic(&topic_buffer, session_index, message_index);
                var payload: [options.payload_bytes]u8 = undefined;
                fillPayload(&payload, session_index, message_index);
                if (value.qos != .at_least_once or !std.mem.eql(u8, value.topic, topic) or !std.mem.eql(u8, value.payload, &payload)) return error.RestoredBenchmarkStateMismatch;
                if (self.metadata.len == 0) {
                    if (value.properties.len != 0) return error.RestoredBenchmarkStateMismatch;
                } else if (value.properties.len != 1 or value.properties[0] != .binary or
                    value.properties[0].binary.id != .correlation_data or !std.mem.eql(u8, value.properties[0].binary.value, self.metadata))
                {
                    return error.RestoredBenchmarkStateMismatch;
                }
                hash.update(value.topic);
                hash.update(value.payload);
                hash.update(self.metadata);
                _ = try restored.sessions.handleAck(opened.handle, .puback, value.packet_id, 0);
            }
        }
        const checksum = hash.final();
        if (checksum != self.checksum) return error.RestoredBenchmarkStateMismatch;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &digest, .{});
        return .{ .sessions = stats.session_count, .queued_messages = stats.queued_count, .snapshot_bytes = encoded.len, .checksum = checksum, .snapshot_crc32 = std.hash.crc.Crc32.hash(encoded), .snapshot_sha256 = digest };
    }
};

fn clientId(buffer: []u8, index: usize) ![]const u8 {
    return std.fmt.bufPrint(buffer, "commit-bench-{d}", .{index});
}

fn messageTopic(buffer: []u8, session_index: usize, message_index: usize) ![]const u8 {
    return std.fmt.bufPrint(buffer, "bench/commit/{d}/{d}", .{ session_index, message_index });
}

fn fillPayload(payload: []u8, session_index: usize, message_index: usize) void {
    for (payload, 0..) |*byte, index| byte.* = @truncate(session_index *% 13 +% message_index *% 7 +% index);
}

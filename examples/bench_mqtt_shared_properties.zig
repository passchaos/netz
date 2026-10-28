//! Compare immutable shared metadata with independent Session ownership.
const std = @import("std");
const netz = @import("netz");
const CountingAllocator = @import("support/counting_allocator.zig").CountingAllocator;
const sessions = 64;
const messages = 256;
const samples = 7;
const Result = struct { elapsed_ns: u64, allocations: usize, live_bytes: usize, logical_bytes: usize, checksum: u64 };

pub fn main(init: std.process.Init) !void {
    var backend = try netz.runtime.Backend.init(init.gpa);
    defer backend.deinit();
    const io = backend.io();
    for ([_]bool{ false, true }) |metadata| {
        for (0..samples) |sample| {
            for ([_]bool{ sample % 2 == 0, sample % 2 != 0 }) |shared| {
                const result = try run(io, metadata, shared);
                std.debug.print("record=result benchmark=mqtt-shared-properties io=zio-std-io metadata={any} shared={any} sample={d} sessions={d} messages={d} deliveries={d} elapsed_ns={d} allocations={d} live_bytes={d} logical_bytes={d} checksum={d} teardown_live_bytes=0 complete=true\n", .{ metadata, shared, sample, sessions, messages, sessions * messages, result.elapsed_ns, result.allocations, result.live_bytes, result.logical_bytes, result.checksum });
            }
        }
    }
}

fn run(io: std.Io, metadata: bool, shared: bool) !Result {
    var counting = CountingAllocator.init(std.heap.smp_allocator);
    const allocator = counting.allocator();
    const result: Result = result: {
        var store = netz.mqtt.session.Store.init(allocator, .{ .max_sessions = sessions, .max_queued_per_session = messages });
        defer store.deinit();
        var handles: [sessions]netz.mqtt.session.Handle = undefined;
        for (&handles, 0..) |*handle, index| {
            var name: [32]u8 = undefined;
            handle.* = (try store.open(try std.fmt.bufPrint(&name, "metadata-{d}", .{index}), false, 3600, .zero)).handle;
            try store.disconnect(handle.*, null, .zero);
        }
        const correlation = [_]u8{0xa7} ** 1024;
        const trace = [_]u8{'t'} ** 512;
        var properties = [_]netz.mqtt.Property{
            .{ .utf8 = .{ .id = .content_type, .value = "application/octet-stream" } },
            .{ .utf8 = .{ .id = .response_topic, .value = "bench/response" } },
            .{ .binary = .{ .id = .correlation_data, .value = &correlation } },
            .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = &trace } },
        };
        const body = [_]u8{0x31} ** 256;
        const publish: netz.mqtt.Publish = .{ .dup = false, .qos = .at_least_once, .retain = false, .topic = "bench/metadata", .packet_id = 1, .properties = if (metadata) &properties else &.{}, .payload = &body };
        const before = counting.snapshot();
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        for (0..messages) |_| {
            if (shared) {
                const publication = try netz.mqtt.session.SharedPublication.createFromPublish(allocator, publish, 1, .zero);
                defer publication.release();
                for (handles) |handle| {
                    var changed = false;
                    _ = try store.enqueueSharedPublicationTrackingSnapshotChange(handle, publication, .{ .qos = publish.qos, .properties = publication.properties, .now = .zero }, &changed);
                    if (!changed) return error.InvalidBenchmarkState;
                }
            } else {
                for (handles) |handle| _ = try store.enqueuePublish(handle, publish.topic, publish.payload, .{ .qos = publish.qos, .properties = publish.properties, .now = .zero });
            }
        }
        const elapsed: u64 = @intCast(std.Io.Clock.awake.now(io).nanoseconds - start);
        const after = counting.snapshot();
        if (store.aggregateStats().queued_count != sessions * messages) return error.InvalidBenchmarkState;
        const logical_bytes = store.aggregateStats().owned_wire_bytes;
        var checksum: u64 = 0;
        var output: [messages]netz.mqtt.session.Transmission = undefined;
        for (handles) |handle| {
            const drained = try store.drainInto(handle, .zero, messages, &output);
            if (drained.len != messages) return error.InvalidBenchmarkState;
            for (drained) |transmission| {
                const value = transmission.publish;
                if (!std.mem.eql(u8, value.topic, publish.topic) or !std.mem.eql(u8, value.payload, publish.payload)) return error.InvalidBenchmarkState;
                if (value.properties.len != publish.properties.len) return error.InvalidBenchmarkState;
                for (value.properties, publish.properties) |actual, expected| {
                    if (!propertyEqual(actual, expected)) return error.InvalidBenchmarkState;
                }
                checksum +%= value.payload[0] + value.payload[value.payload.len - 1];
                if (metadata) checksum +%= value.properties[2].binary.value[0] + value.properties[3].utf8_pair.value.len;
                _ = try store.handleAck(handle, .puback, value.packet_id, 0);
            }
        }
        break :result .{ .elapsed_ns = elapsed, .allocations = after.alloc_count - before.alloc_count, .live_bytes = after.current_bytes - before.current_bytes, .logical_bytes = logical_bytes, .checksum = checksum };
    };
    if (counting.snapshot().current_bytes != 0) return error.BenchmarkMemoryLeak;
    return result;
}

fn propertyEqual(first: netz.mqtt.Property, second: netz.mqtt.Property) bool {
    return switch (first) {
        .utf8 => |value| second == .utf8 and value.id == second.utf8.id and std.mem.eql(u8, value.value, second.utf8.value),
        .binary => |value| second == .binary and value.id == second.binary.id and std.mem.eql(u8, value.value, second.binary.value),
        .utf8_pair => |value| second == .utf8_pair and value.id == second.utf8_pair.id and std.mem.eql(u8, value.key, second.utf8_pair.key) and std.mem.eql(u8, value.value, second.utf8_pair.value),
        else => false,
    };
}

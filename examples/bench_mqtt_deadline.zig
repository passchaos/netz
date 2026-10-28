//! Complete durable-client QoS transactions through the deadline replay path.
const std = @import("std");
const builtin = @import("builtin");
const netz = @import("netz");
const config = @import("mqtt_deadline_bench/options.zig");
const peer_mod = @import("mqtt_deadline_bench/peer.zig");
const ClientEvent = netz.mqtt.reconnect.ClientEvent;

pub fn main(init: std.process.Init) !void {
    const options = try config.parse(init);
    const allocator = std.heap.smp_allocator;
    const payload = try allocator.alloc(u8, options.payload_bytes);
    defer allocator.free(payload);
    for (payload, 0..) |*byte, index| byte.* = @truncate(index *% 37);
    var backend = try netz.runtime.Backend.init(init.gpa);
    defer backend.deinit();
    const io = backend.io();
    var server = try netz.mqtt.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 8 * 1024 * 1024 });
    defer server.deinit();
    var peer = peer_mod.Peer{ .server = &server, .options = options, .payload = payload };
    var task = try io.concurrent(peer_mod.Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var shutdown: std.Io.Event = .unset;
    var client = try netz.mqtt.reconnect.Client.init(allocator, io, server.address(), .{
        .protocol = options.protocol,
        .client_id = "bench-session-deadline",
        .limits = .{ .max_packet_size = 8 * 1024 * 1024 },
    }, .{}, &shutdown);
    defer client.deinit();
    _ = try client.connectWithDeadline(.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
    for (0..options.warmup) |_| try exchange(&client, &peer, payload, options.qos, io);
    const started = now(io);
    for (0..options.iterations) |_| try exchange(&client, &peer, payload, options.qos, io);
    const elapsed = now(io) -| started;
    const pending = try client.outgoingStats();
    if (pending.queued_count != 0 or pending.inflight_count != 0 or pending.outgoing_publish_window_used != 0) return error.InvalidBenchmarkSession;
    try client.disconnect(0);
    try task.await(io);
    if (peer.received != options.total() or peer.terminal != options.total() or !peer.disconnected or
        peer.released != (if (options.qos == .exactly_once) options.total() else 0))
    {
        return error.InvalidPeerCompletion;
    }
    std.debug.print(
        "record=result schema=1 implementation=netz protocol=mqtt transport=tcp build_mode={s} mqtt_version={d} qos={d} topic_alias={} " ++
            "client_api=reconnect-stage-flush-poll client_io=zio-std-io server_io=zio-std-io " ++
            "connections=1 window=1 validation=full-bytes+terminal deadline=single-awake-budget " ++
            "warmup={d} iterations={d} payload_bytes={d} logical_bytes={d} elapsed_ns={d} ns_per_delivery={d} " ++
            "completed_deliveries={d} session_pending=0 stats_enabled=false\n",
        .{ @tagName(builtin.mode), @intFromEnum(options.protocol), @intFromEnum(options.qos), options.protocol == .v5 and options.topic_alias, options.warmup, options.iterations, options.payload_bytes, @as(u128, options.payload_bytes) * options.iterations, elapsed, elapsed / options.iterations, options.iterations },
    );
    std.debug.print(
        "record=peer-completion schema=1 implementation=netz protocol=mqtt mqtt_version={d} qos={d} topic_alias={} " ++
            "received_messages={d} terminal_acks={d} pubrels={d} payload_bytes={d} disconnected=true\n",
        .{ @intFromEnum(options.protocol), @intFromEnum(options.qos), options.protocol == .v5 and options.topic_alias, peer.received, peer.terminal, peer.released, options.payload_bytes },
    );
}

fn exchange(client: *netz.mqtt.reconnect.Client, peer: *peer_mod.Peer, payload: []const u8, qos: netz.mqtt.QoS, io: std.Io) !void {
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    const id = try client.stagePublish(peer_mod.topic, payload, .{ .qos = qos });
    peer.expected_id.store(id, .release);
    try client.flushPendingWithDeadline(deadline);
    if (qos == .exactly_once) try acknowledgement(client, .pubrec, id, deadline);
    try acknowledgement(client, if (qos == .at_least_once) .puback else .pubcomp, id, deadline);
    if (try client.outgoingQoSState(id) != null) return error.InvalidBenchmarkSession;
}

fn acknowledgement(client: *netz.mqtt.reconnect.Client, expected: std.meta.Tag(ClientEvent), id: u16, deadline: std.Io.Clock.Timestamp) !void {
    var event = (try client.pollWithDeadline(deadline.raw, .{ .reconnect_after_transport_error = false })) orelse return error.MissingBenchmarkAck;
    defer event.deinit(client.allocator);
    if (std.meta.activeTag(event) != expected) return error.InvalidBenchmarkAck;
    const ack = switch (event) {
        .puback, .pubrec, .pubcomp => |value| value.ack,
        else => return error.InvalidBenchmarkAck,
    };
    if (ack.packet_id != id or ack.reason_code != 0 or ack.properties.len != 0) return error.InvalidBenchmarkAck;
}

fn now(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

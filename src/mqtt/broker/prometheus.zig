//! Prometheus text exposition for one coherent `Broker.stats()` snapshot.
//!
//! The output follows the OpenMetrics/Prometheus text format 0.0.4 and is
//! deterministic: metric families appear in a fixed declaration order with
//! one `# HELP` and one `# TYPE` line, followed by the sample. Monotonic
//! counters use the `_total` suffix and instantaneous values use gauges;
//! the Mosquitto EWMA load samples are gauges in events per minute with a
//! `window` label. The broker intentionally does not embed an HTTP server;
//! applications serve these bytes from their own admin endpoint.

const std = @import("std");
const broker_mod = @import("../broker.zig");

pub const Error = std.mem.Allocator.Error;

const Kind = enum { counter, gauge };

const Declaration = struct {
    name: []const u8,
    help: []const u8,
    kind: Kind,
    value: *const fn (stats: broker_mod.Stats) f64,
    labels: []const u8 = "",
};

fn integer(value: anytype) f64 {
    return @floatFromInt(value);
}

fn uptime(stats: broker_mod.Stats) f64 {
    return integer(stats.uptime_seconds);
}
fn clientsConnected(stats: broker_mod.Stats) f64 {
    return integer(stats.active_connections);
}
fn clientsMaximum(stats: broker_mod.Stats) f64 {
    return integer(stats.maximum_active_connections);
}
fn clientsDisconnected(stats: broker_mod.Stats) f64 {
    return integer(stats.connections_received -| stats.active_connections);
}
fn clientsExpired(stats: broker_mod.Stats) f64 {
    return integer(stats.expired_sessions);
}
fn clientsTotal(stats: broker_mod.Stats) f64 {
    return integer(stats.connections_received);
}
fn socketsAccepted(stats: broker_mod.Stats) f64 {
    return integer(stats.sockets_accepted);
}
fn messagesReceived(stats: broker_mod.Stats) f64 {
    return integer(stats.messages_received);
}
fn messagesSent(stats: broker_mod.Stats) f64 {
    return integer(stats.messages_sent);
}
fn bytesReceived(stats: broker_mod.Stats) f64 {
    return integer(stats.bytes_received);
}
fn bytesSent(stats: broker_mod.Stats) f64 {
    return integer(stats.bytes_sent);
}
fn publishReceived(stats: broker_mod.Stats) f64 {
    return integer(stats.publish_messages_received);
}
fn publishDropped(stats: broker_mod.Stats) f64 {
    return integer(stats.publish_messages_dropped);
}
fn publishSent(stats: broker_mod.Stats) f64 {
    return integer(stats.publish_messages_sent);
}
fn publishBytesReceived(stats: broker_mod.Stats) f64 {
    return integer(stats.publish_payload_bytes_received);
}
fn publishBytesSent(stats: broker_mod.Stats) f64 {
    return integer(stats.publish_payload_bytes_sent);
}
fn subscriptions(stats: broker_mod.Stats) f64 {
    return integer(stats.subscriptions);
}
fn sharedSubscriptions(stats: broker_mod.Stats) f64 {
    return integer(stats.shared_subscriptions);
}
fn retainedMessages(stats: broker_mod.Stats) f64 {
    return integer(stats.retained_messages);
}
fn retainedBytes(stats: broker_mod.Stats) f64 {
    return integer(stats.retained_bytes);
}
fn liveQueuedDeliveries(stats: broker_mod.Stats) f64 {
    return integer(stats.live_queued_deliveries);
}
fn sessionQueuedMessages(stats: broker_mod.Stats) f64 {
    return integer(stats.session_queued_messages);
}
fn sessionQueuedPayloadBytes(stats: broker_mod.Stats) f64 {
    return integer(stats.session_queued_payload_bytes);
}
fn sessionInflightMessages(stats: broker_mod.Stats) f64 {
    return integer(stats.session_inflight_messages);
}
fn sessionInflightPayloadBytes(stats: broker_mod.Stats) f64 {
    return integer(stats.session_inflight_payload_bytes);
}
fn pendingIncomingQos2(stats: broker_mod.Stats) f64 {
    return integer(stats.pending_incoming_qos2);
}
fn scheduledWills(stats: broker_mod.Stats) f64 {
    return integer(stats.scheduled_wills);
}
fn scheduledWillBytes(stats: broker_mod.Stats) f64 {
    return integer(stats.scheduled_will_bytes);
}
fn sessions(stats: broker_mod.Stats) f64 {
    return integer(stats.sessions);
}
fn connectedSessions(stats: broker_mod.Stats) f64 {
    return integer(stats.connected_sessions);
}
fn disconnectedSessions(stats: broker_mod.Stats) f64 {
    return integer(stats.disconnected_sessions);
}
fn sessionOwnedBytes(stats: broker_mod.Stats) f64 {
    return integer(stats.session_owned_bytes);
}

/// Fixed declaration order keeps scrapes byte-stable and makes the contract
/// testable without a live broker.
pub const declarations = [_]Declaration{
    .{
        .name = "mqtt_broker_uptime_seconds",
        .help = "Wall-clock seconds since the broker started.",
        .kind = .gauge,
        .value = uptime,
    },
    .{
        .name = "mqtt_broker_clients_connected",
        .help = "Currently connected network clients.",
        .kind = .gauge,
        .value = clientsConnected,
    },
    .{
        .name = "mqtt_broker_clients_maximum",
        .help = "High-water count of simultaneously connected clients.",
        .kind = .gauge,
        .value = clientsMaximum,
    },
    .{
        .name = "mqtt_broker_clients_disconnected",
        .help = "Connected clients that have disconnected since startup.",
        .kind = .gauge,
        .value = clientsDisconnected,
    },
    .{
        .name = "mqtt_broker_clients_expired_total",
        .help = "Sessions retired by the keep-alive or session-expiry deadline.",
        .kind = .counter,
        .value = clientsExpired,
    },
    .{
        .name = "mqtt_broker_clients_total",
        .help = "CONNECT packets admitted to the broker core.",
        .kind = .counter,
        .value = clientsTotal,
    },
    .{
        .name = "mqtt_broker_sockets_accepted_total",
        .help = "Listener transports accepted, including peers later refused.",
        .kind = .counter,
        .value = socketsAccepted,
    },
    .{
        .name = "mqtt_broker_messages_received_total",
        .help = "Complete MQTT control packets received from clients.",
        .kind = .counter,
        .value = messagesReceived,
    },
    .{
        .name = "mqtt_broker_messages_sent_total",
        .help = "Complete MQTT control packets sent to clients.",
        .kind = .counter,
        .value = messagesSent,
    },
    .{
        .name = "mqtt_broker_bytes_received_total",
        .help = "Encoded MQTT bytes received from clients.",
        .kind = .counter,
        .value = bytesReceived,
    },
    .{
        .name = "mqtt_broker_bytes_sent_total",
        .help = "Encoded MQTT bytes sent to clients.",
        .kind = .counter,
        .value = bytesSent,
    },
    .{
        .name = "mqtt_broker_publish_messages_received_total",
        .help = "PUBLISH packets accepted by the dispatch loop.",
        .kind = .counter,
        .value = publishReceived,
    },
    .{
        .name = "mqtt_broker_publish_messages_dropped_total",
        .help = "Outbound application messages that could not be queued.",
        .kind = .counter,
        .value = publishDropped,
    },
    .{
        .name = "mqtt_broker_publish_messages_sent_total",
        .help = "PUBLISH packets written to subscribers.",
        .kind = .counter,
        .value = publishSent,
    },
    .{
        .name = "mqtt_broker_publish_payload_bytes_received_total",
        .help = "Application payload bytes in accepted PUBLISH packets.",
        .kind = .counter,
        .value = publishBytesReceived,
    },
    .{
        .name = "mqtt_broker_publish_payload_bytes_sent_total",
        .help = "Application payload bytes written to subscribers.",
        .kind = .counter,
        .value = publishBytesSent,
    },
    .{
        .name = "mqtt_broker_subscriptions",
        .help = "Currently registered topic filters, including shared group leaves.",
        .kind = .gauge,
        .value = subscriptions,
    },
    .{
        .name = "mqtt_broker_shared_subscriptions",
        .help = "Distinct shared subscription groups currently registered.",
        .kind = .gauge,
        .value = sharedSubscriptions,
    },
    .{
        .name = "mqtt_broker_retained_messages",
        .help = "Currently stored retained application messages.",
        .kind = .gauge,
        .value = retainedMessages,
    },
    .{
        .name = "mqtt_broker_retained_payload_bytes",
        .help = "Payload bytes retained in the retained-message store.",
        .kind = .gauge,
        .value = retainedBytes,
    },
    .{
        .name = "mqtt_broker_live_queued_deliveries",
        .help = "Messages queued on connected client sessions.",
        .kind = .gauge,
        .value = liveQueuedDeliveries,
    },
    .{
        .name = "mqtt_broker_session_queued_messages",
        .help = "Messages queued on durable offline sessions.",
        .kind = .gauge,
        .value = sessionQueuedMessages,
    },
    .{
        .name = "mqtt_broker_session_queued_payload_bytes",
        .help = "Payload bytes queued on durable offline sessions.",
        .kind = .gauge,
        .value = sessionQueuedPayloadBytes,
    },
    .{
        .name = "mqtt_broker_session_inflight_messages",
        .help = "QoS 1/2 deliveries currently in flight.",
        .kind = .gauge,
        .value = sessionInflightMessages,
    },
    .{
        .name = "mqtt_broker_session_inflight_payload_bytes",
        .help = "Payload bytes of QoS 1/2 deliveries currently in flight.",
        .kind = .gauge,
        .value = sessionInflightPayloadBytes,
    },
    .{
        .name = "mqtt_broker_pending_incoming_qos2",
        .help = "Inbound QoS 2 transactions before PUBREL.",
        .kind = .gauge,
        .value = pendingIncomingQos2,
    },
    .{
        .name = "mqtt_broker_wills_scheduled",
        .help = "Will messages awaiting publication.",
        .kind = .gauge,
        .value = scheduledWills,
    },
    .{
        .name = "mqtt_broker_wills_payload_bytes",
        .help = "Payload bytes of will messages awaiting publication.",
        .kind = .gauge,
        .value = scheduledWillBytes,
    },
    .{
        .name = "mqtt_broker_sessions",
        .help = "Live and durable sessions currently known to the broker.",
        .kind = .gauge,
        .value = sessions,
    },
    .{
        .name = "mqtt_broker_sessions_connected",
        .help = "Sessions with an attached network connection.",
        .kind = .gauge,
        .value = connectedSessions,
    },
    .{
        .name = "mqtt_broker_sessions_disconnected",
        .help = "Durable sessions currently offline.",
        .kind = .gauge,
        .value = disconnectedSessions,
    },
    .{
        .name = "mqtt_broker_session_owned_payload_bytes",
        .help = "Payload bytes owned by durable session delivery state.",
        .kind = .gauge,
        .value = sessionOwnedBytes,
    },
};

fn rateForWindow(
    snapshot: broker_mod.LoadSnapshot,
    window: []const u8,
    field: []const u8,
) f64 {
    const rates = if (std.mem.eql(u8, window, "1m"))
        snapshot.one_minute
    else if (std.mem.eql(u8, window, "5m"))
        snapshot.five_minutes
    else
        snapshot.fifteen_minutes;
    inline for (std.meta.fields(broker_mod.LoadRates)) |rate_field| {
        if (std.mem.eql(u8, field, rate_field.name)) {
            return @field(rates, rate_field.name);
        }
    }
    unreachable;
}

const load_families = [_]struct {
    metric: []const u8,
    help: []const u8,
    field: []const u8,
}{
    .{
        .metric = "mqtt_broker_load_connections",
        .help = "Exponentially weighted connection rate per minute.",
        .field = "connections",
    },
    .{
        .metric = "mqtt_broker_load_sockets",
        .help = "Exponentially weighted accepted-socket rate per minute.",
        .field = "sockets",
    },
    .{
        .metric = "mqtt_broker_load_messages_received",
        .help = "Exponentially weighted received control-packet rate per minute.",
        .field = "messages_received",
    },
    .{
        .metric = "mqtt_broker_load_messages_sent",
        .help = "Exponentially weighted sent control-packet rate per minute.",
        .field = "messages_sent",
    },
    .{
        .metric = "mqtt_broker_load_publish_messages_dropped",
        .help = "Exponentially weighted dropped-publish rate per minute.",
        .field = "publish_messages_dropped",
    },
    .{
        .metric = "mqtt_broker_load_publish_messages_received",
        .help = "Exponentially weighted received-publish rate per minute.",
        .field = "publish_messages_received",
    },
    .{
        .metric = "mqtt_broker_load_publish_messages_sent",
        .help = "Exponentially weighted sent-publish rate per minute.",
        .field = "publish_messages_sent",
    },
    .{
        .metric = "mqtt_broker_load_bytes_received",
        .help = "Exponentially weighted received-byte rate per minute.",
        .field = "bytes_received",
    },
    .{
        .metric = "mqtt_broker_load_bytes_sent",
        .help = "Exponentially weighted sent-byte rate per minute.",
        .field = "bytes_sent",
    },
};

const windows = [_][]const u8{ "1m", "5m", "15m" };

/// Render the complete text exposition for one stats snapshot. The caller
/// owns the returned bytes; the document always ends with a newline.
pub fn render(
    allocator: std.mem.Allocator,
    stats: broker_mod.Stats,
) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    for (declarations) |declaration| {
        try out.print(allocator, "# HELP {s} {s}\n", .{
            declaration.name,
            declaration.help,
        });
        try out.print(allocator, "# TYPE {s} {s}\n", .{
            declaration.name,
            @tagName(declaration.kind),
        });
        try out.print(allocator, "{s} {d}\n", .{
            declaration.name,
            declaration.value(stats),
        });
    }

    for (load_families) |family| {
        try out.print(allocator, "# HELP {s} {s}\n", .{
            family.metric,
            family.help,
        });
        try out.print(allocator, "# TYPE {s} gauge\n", .{
            family.metric,
        });
        for (windows) |window| {
            const rate = rateForWindow(
                stats.load,
                window,
                family.field,
            );
            try out.print(allocator, "{s}{{window=\"{s}\"}} {d}\n", .{
                family.metric,
                window,
                rate,
            });
        }
    }

    return out.toOwnedSlice(allocator);
}

test "MQTT Prometheus exposition renders stable counter and gauge families" {
    const allocator = std.testing.allocator;
    const stats = broker_mod.Stats{
        .uptime_seconds = 42,
        .connections_received = 7,
        .sockets_accepted = 9,
        .active_connections = 3,
        .maximum_active_connections = 5,
        .expired_sessions = 1,
        .messages_received = 100,
        .messages_sent = 200,
        .bytes_received = 4_096,
        .bytes_sent = 8_192,
        .publish_messages_received = 10,
        .publish_payload_bytes_received = 256,
        .publish_messages_dropped = 2,
        .publish_messages_sent = 40,
        .publish_payload_bytes_sent = 1_024,
        .sessions = 6,
        .connected_sessions = 3,
        .disconnected_sessions = 3,
        .subscriptions = 11,
        .shared_subscriptions = 1,
        .retained_messages = 4,
        .retained_bytes = 80,
        .live_queued_deliveries = 5,
        .session_queued_messages = 9,
        .session_queued_payload_bytes = 220,
        .session_inflight_messages = 2,
        .session_inflight_payload_bytes = 30,
        .pending_incoming_qos2 = 1,
        .scheduled_wills = 2,
        .scheduled_will_bytes = 12,
        .session_owned_bytes = 333,
        .load = .{
            .one_minute = .{ .connections = 1.5, .messages_sent = 8 },
        },
    };

    const document = try render(allocator, stats);
    defer allocator.free(document);
    try std.testing.expect(document[document.len - 1] == '\n');

    const expected_lines = [_][]const u8{
        "# HELP mqtt_broker_uptime_seconds Wall-clock seconds since the broker started.",
        "# TYPE mqtt_broker_uptime_seconds gauge",
        "mqtt_broker_uptime_seconds 42",
        "mqtt_broker_clients_connected 3",
        "mqtt_broker_clients_maximum 5",
        "mqtt_broker_clients_disconnected 4",
        "mqtt_broker_clients_expired_total 1",
        "# TYPE mqtt_broker_clients_expired_total counter",
        "mqtt_broker_clients_total 7",
        "# TYPE mqtt_broker_sockets_accepted_total counter",
        "mqtt_broker_sockets_accepted_total 9",
        "mqtt_broker_messages_received_total 100",
        "mqtt_broker_publish_messages_dropped_total 2",
        "mqtt_broker_sessions 6",
        "mqtt_broker_sessions_disconnected 3",
        "mqtt_broker_pending_incoming_qos2 1",
        "# TYPE mqtt_broker_load_connections gauge",
        "mqtt_broker_load_connections{window=\"1m\"} 1.5",
        "mqtt_broker_load_connections{window=\"5m\"} 0",
        "mqtt_broker_load_connections{window=\"15m\"} 0",
        "# TYPE mqtt_broker_load_sockets gauge",
        "mqtt_broker_load_sockets{window=\"1m\"} 0",
        "mqtt_broker_load_sockets{window=\"5m\"} 0",
        "mqtt_broker_load_sockets{window=\"15m\"} 0",
        "mqtt_broker_load_messages_sent{window=\"1m\"} 8",
    };
    for (expected_lines) |line| {
        try std.testing.expect(
            std.mem.indexOf(u8, document, line) != null,
        );
    }
}

test "MQTT Prometheus exposition stays byte identical for one snapshot" {
    const allocator = std.testing.allocator;
    var stats: broker_mod.Stats = std.mem.zeroes(broker_mod.Stats);
    stats.active_connections = 2;
    stats.load.five_minutes.bytes_sent = 3.25;
    const first = try render(allocator, stats);
    defer allocator.free(first);
    const second = try render(allocator, stats);
    defer allocator.free(second);
    try std.testing.expectEqualStrings(first, second);
}

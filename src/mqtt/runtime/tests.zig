//! Tests moved out of the module runtime root.

const std = @import("std");
const mqtt = @import("../mod.zig");
const net = std.Io.net;
const runtime = @import("../runtime.zig");
const AcceptedClient = runtime.AcceptedClient;
const AddressResolver = runtime.AddressResolver;
const BrokerEvent = runtime.BrokerEvent;
const Client = runtime.Client;
const ConcurrentServeResult = runtime.ConcurrentServeResult;
const ConnectOptions = runtime.ConnectOptions;
const Connection = runtime.Connection;
const ConnectionCapabilities = runtime.ConnectionCapabilities;
const ConnectionLimits = runtime.ConnectionLimits;
const Error = runtime.Error;
const Limits = runtime.Limits;
const OwnedConnect = runtime.OwnedConnect;
const PacketTransport = runtime.PacketTransport;
const PendingAcceptedClient = runtime.PendingAcceptedClient;
const PendingPacketState = runtime.PendingPacketState;
const ServeErrorEvent = runtime.ServeErrorEvent;
const ServeErrorStage = runtime.ServeErrorStage;
const Server = runtime.Server;
const TrafficCounters = runtime.TrafficCounters;
const TrafficStats = runtime.TrafficStats;
const appendTopicAliasMaximumSetting = runtime.appendTopicAliasMaximumSetting;
const broker_keep_alive = runtime.broker_keep_alive;
const builtin = runtime.builtin;
const keepAliveTimeout = runtime.keepAliveTimeout;
const negotiatedOutgoingInflightLimit = runtime.negotiatedOutgoingInflightLimit;
const packet_identifiers = runtime.packet_identifiers;
const proxy_protocol = runtime.proxy_protocol;
const redirect = runtime.redirect;
const stream_io = runtime.stream_io;
const topic_alias = runtime.topic_alias;
const write_property_staging_capacity = runtime.write_property_staging_capacity;

test "MQTT Keep Alive timeout preserves half-second precision" {
    try std.testing.expect(keepAliveTimeout(0) == null);
    try std.testing.expectEqual(
        @as(i96, 1500 * std.time.ns_per_ms),
        keepAliveTimeout(1).?.raw.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 3 * std.time.ns_per_s),
        keepAliveTimeout(2).?.raw.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i96, 98_302_500 * std.time.ns_per_ms),
        keepAliveTimeout(std.math.maxInt(u16)).?.raw.nanoseconds,
    );
}

test "owned CONNECT can replace username with a policy identity" {
    const allocator = std.testing.allocator;
    var owned = OwnedConnect{
        .packet = .{
            .bytes = try allocator.alloc(u8, 0),
            .fixed = undefined,
        },
        .connect = .{
            .protocol = .v5,
            .clean_start = true,
            .keep_alive_seconds = 60,
            .client_id = "client",
            .properties = try allocator.alloc(mqtt.Property, 0),
            .username = "wire-user",
            .password = "wire-password",
        },
    };
    defer owned.deinit(allocator);
    try owned.replaceUsername(allocator, "certificate-user");
    try std.testing.expectEqualStrings(
        "certificate-user",
        owned.connect.username.?,
    );
    try std.testing.expect(owned.connect.password == null);
    try owned.replaceUsername(allocator, "replacement-user");
    try std.testing.expectEqualStrings(
        "replacement-user",
        owned.connect.username.?,
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        owned.replaceUsername(allocator, "bad\x00user"),
    );
    try std.testing.expectEqualStrings(
        "replacement-user",
        owned.connect.username.?,
    );
}

test "MQTT runtime strict UTF-8 policy covers broker input fields" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    const accepted_control = "value\xc2\x9f";
    const connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = accepted_control,
        .username = accepted_control,
        .will = .{ .topic = accepted_control, .payload = "payload" },
    };
    const subscriptions = [_]mqtt.Subscription{.{
        .topic_filter = accepted_control,
    }};
    const filters = [_][]const u8{accepted_control};
    const properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = accepted_control,
        } },
    };
    const valid_properties = [_]mqtt.Property{
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "accepted",
        } },
        .{ .binary = .{
            .id = .correlation_data,
            .value = "opaque\x00\xff",
        } },
    };

    try connection.validateIncomingConnectUtf8(connect);
    try connection.validateIncomingUtf8(accepted_control);
    try connection.validateIncomingProperties(&properties);
    try connection.validateIncomingSubscriptionsUtf8(&subscriptions);
    try connection.validateIncomingTopicFiltersUtf8(&filters);

    connection.strict_utf8 = true;
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingConnectUtf8(connect),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingUtf8(accepted_control),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingProperties(&properties),
    );
    try connection.validateIncomingProperties(&valid_properties);
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingSubscriptionsUtf8(&subscriptions),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        connection.validateIncomingTopicFiltersUtf8(&filters),
    );
}

test "MQTT runtime client and server exchange over TCP" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
                .max_outgoing_topic_aliases = 2,
                .topic_alias_maximum = 4,
                .maximum_keep_alive_seconds = 7,
                .maximum_qos = .exactly_once,
                .retain_available = false,
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("client-1", accepted.connect.connect.client_id);
            try std.testing.expectEqualStrings("status/client-1", accepted.connect.connect.will.?.topic);
            try std.testing.expectEqualStrings("offline", accepted.connect.connect.will.?.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, accepted.connect.connect.will.?.qos);
            try std.testing.expectEqualStrings("rumq", accepted.connect.connect.username.?);
            try std.testing.expectEqualStrings("mq", accepted.connect.connect.password.?);
            try std.testing.expectEqual(@as(?u16, 5), mqtt.receiveMaximum(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(?u32, 4096), mqtt.maximumPacketSize(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(?u16, 4), mqtt.topicAliasMaximum(accepted.connect.connect.properties));
            try std.testing.expectEqual(@as(u16, 2), accepted.connection.max_outgoing_inflight);
            try std.testing.expectEqual(
                @as(u16, 2),
                accepted.connection.peer_topic_alias_maximum,
            );
            try std.testing.expectEqual(@as(usize, 4096), accepted.connection.peer_max_packet_size);
            try std.testing.expectEqual(@as(u16, 7), accepted.connection.keep_alive_seconds);

            var client_auth = try accepted.connection.readAuth();
            defer client_auth.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0x19), client_auth.auth.reason_code);
            try std.testing.expectEqualStrings("SCRAM-SHA-256", client_auth.auth.properties[0].utf8.value);
            try std.testing.expectEqualStrings("client-first", client_auth.auth.properties[1].binary.value);
            try accepted.connection.writeAuth(0x18, &.{
                .{ .utf8 = .{ .id = .reason_string, .value = "continue auth" } },
            });

            var subscribe = try accepted.connection.readSubscribe();
            defer subscribe.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(usize, 2), subscribe.subscribe.subscriptions.len);
            try std.testing.expectEqualStrings("sensors/+", subscribe.subscribe.subscriptions[0].topic_filter);
            try std.testing.expectEqualStrings("alerts/#", subscribe.subscribe.subscriptions[1].topic_filter);
            const reason_codes = [_]u8{ 0x01, 0x00 };
            try accepted.connection.writeSubAck(subscribe.subscribe.packet_id, &reason_codes, &.{});

            var unsubscribe = try accepted.connection.readUnsubscribe();
            defer unsubscribe.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(usize, 2), unsubscribe.unsubscribe.topic_filters.len);
            try std.testing.expectEqualStrings("sensors/+", unsubscribe.unsubscribe.topic_filters[0]);
            try std.testing.expectEqualStrings("alerts/#", unsubscribe.unsubscribe.topic_filters[1]);
            const unsub_reasons = [_]u8{ 0x00, 0x11 };
            // A broker may deliver ordinary traffic before the correlated
            // UNSUBACK. The client must preserve that packet for its next
            // reader instead of rejecting the valid interleaving.
            try accepted.connection.publish("alerts/system", "online", .{});
            try accepted.connection.writeUnsubAck(unsubscribe.unsubscribe.packet_id, &unsub_reasons, &.{});

            var exact = try accepted.connection.readPublish();
            defer exact.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("sensors/exact", exact.publish.topic);
            try std.testing.expectEqualStrings("exactly-once", exact.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, exact.publish.qos);
            try accepted.connection.writePubRec(exact.publish.packet_id.?, 0);
            var pubrel = try accepted.connection.readPubRel();
            defer pubrel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(exact.publish.packet_id.?, pubrel.ack.packet_id);
            try accepted.connection.writePubComp(pubrel.ack.packet_id, 0);

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("sensors/temp", publish.publish.topic);
            try std.testing.expectEqualStrings("21.5", publish.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, publish.publish.qos);
            try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);

            var alias_registered = try accepted.connection.readPublish();
            defer alias_registered.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("aliased/topic", alias_registered.publish.topic);
            try std.testing.expectEqualStrings("first", alias_registered.publish.payload);
            try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(alias_registered.publish.properties));

            var alias_reused = try accepted.connection.readPublish();
            defer alias_reused.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("aliased/topic", alias_reused.publish.topic);
            try std.testing.expectEqualStrings("second", alias_reused.publish.payload);
            try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(alias_reused.publish.properties));

            try accepted.connection.readPingReq();
            try accepted.connection.writePingResp();

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var will_props = [_]mqtt.Property{.{ .four_byte = .{ .id = .will_delay_interval, .value = 1 } }};
    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "client-1",
        .will = .{
            .topic = "status/client-1",
            .payload = "offline",
            .qos = .at_least_once,
            .properties = &will_props,
        },
        .username = "rumq",
        .password = "mq",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_packet_size = 2048,
        .max_outgoing_inflight = 3,
        .receive_maximum = 5,
        .topic_alias_maximum = 4,
        .max_outgoing_topic_aliases = 3,
        .outgoing_retain = false,
    });
    defer client.close();
    try std.testing.expectEqual(@as(u16, 2), client.max_outgoing_inflight);
    try std.testing.expectEqual(@as(u16, 5), client.max_incoming_inflight);
    try std.testing.expectEqual(@as(usize, 2048), client.peer_max_packet_size);
    try std.testing.expectEqual(@as(u16, 3), client.peer_topic_alias_maximum);
    try std.testing.expectEqual(@as(u16, 7), client.keep_alive_seconds);
    try std.testing.expectEqual(mqtt.QoS.exactly_once, client.peerMaximumQoS());
    try std.testing.expect(!client.peerRetainAvailable());
    try std.testing.expect(!client.capabilities.outgoing_retain_enabled);

    try client.writeAuth(0x19, &.{
        .{ .utf8 = .{ .id = .authentication_method, .value = "SCRAM-SHA-256" } },
        .{ .binary = .{ .id = .authentication_data, .value = "client-first" } },
    });
    var auth = try client.readAuth();
    defer auth.deinit(allocator);
    try std.testing.expectEqual(@as(u8, 0x18), auth.auth.reason_code);
    try std.testing.expectEqualStrings("continue auth", auth.auth.properties[0].utf8.value);

    const subscriptions = [_]mqtt.Subscription{
        .{ .topic_filter = "sensors/+", .qos = .at_least_once },
        .{ .topic_filter = "alerts/#", .qos = .at_most_once },
    };
    var suback = try client.subscribe(&subscriptions, .{});
    defer suback.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x01, 0x00 }, suback.suback.reason_codes);

    const unsubscribe_filters = [_][]const u8{ "sensors/+", "alerts/#" };
    var unsuback = try client.unsubscribe(&unsubscribe_filters, .{});
    defer unsuback.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x11 }, unsuback.unsuback.reason_codes);

    var server_publish = try client.readPublish();
    defer server_publish.deinit(allocator);
    try std.testing.expectEqualStrings("alerts/system", server_publish.publish.topic);
    try std.testing.expectEqualStrings("online", server_publish.publish.payload);

    try client.publish("sensors/exact", "exactly-once", .{ .qos = .exactly_once });
    try client.publish("sensors/temp", "21.5", .{ .qos = .at_least_once });
    try client.publish("aliased/topic", "first", .{ .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }} });
    try client.publish("", "second", .{ .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }} });
    try client.ping();
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT exclusive traffic updates preserve wrapping counter semantics" {
    var counters: TrafficCounters = .{};
    counters.messages_received.store(std.math.maxInt(u64), .monotonic);
    counters.bytes_received.store(std.math.maxInt(u64) - 1, .monotonic);
    counters.messages_sent.store(std.math.maxInt(u64), .monotonic);
    counters.bytes_sent.store(std.math.maxInt(u64) - 2, .monotonic);

    counters.recordReceivedExclusive(2);
    counters.recordSentExclusive(3);
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 0,
            .messages_sent = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        },
        counters.stats(),
    );
}

test "MQTT deferred traffic sink flushes one exact connection delta" {
    var aggregate: TrafficCounters = .{};
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    connection.recordPacketReceived(7);
    connection.attachDeferredTrafficCounters(&aggregate);
    connection.attachDeferredTrafficCounters(&aggregate);
    connection.recordPacketReceived(11);
    connection.recordPacketSent(13);

    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 2,
            .messages_sent = 1,
            .bytes_received = 18,
            .bytes_sent = 13,
        },
        connection.trafficStats(),
    );
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 0,
            .messages_sent = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        },
        aggregate.stats(),
    );

    connection.flushDeferredTrafficCounters();
    connection.flushDeferredTrafficCounters();
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 0,
            .messages_sent = 0,
            .bytes_received = 0,
            .bytes_sent = 0,
        },
        connection.trafficStats(),
    );
    try std.testing.expectEqualDeep(
        TrafficStats{
            .messages_received = 2,
            .messages_sent = 1,
            .bytes_received = 18,
            .bytes_sent = 13,
        },
        aggregate.stats(),
    );
}

test "MQTT runtime counts complete control packets and wire bytes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);

    var counters: TrafficCounters = .{};
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, server_stream),
        .traffic_sink = &counters,
        .protocol = .v5,
    };
    defer connection.close();

    var ping_req: [mqtt.ping_packet_len]u8 = undefined;
    const request = mqtt.writePingInto(&ping_req, false);
    try stream_io.writeAllSlices(io, client_stream, &.{request});
    try connection.readPingReq();
    try connection.writePingResp();

    var ping_resp: [mqtt.ping_packet_len]u8 = undefined;
    var buffers = [_][]u8{&ping_resp};
    const received = try io.vtable.netRead(
        io.userdata,
        client_stream.socket.handle,
        &buffers,
    );
    try std.testing.expectEqual(ping_resp.len, received);
    try mqtt.validatePing(&ping_resp, true);

    const local = connection.trafficStats();
    const aggregate = counters.stats();
    try std.testing.expectEqual(@as(u64, 1), local.messages_received);
    try std.testing.expectEqual(@as(u64, 1), local.messages_sent);
    try std.testing.expectEqual(@as(u64, request.len), local.bytes_received);
    try std.testing.expectEqual(@as(u64, ping_resp.len), local.bytes_sent);
    try std.testing.expectEqual(@as(u64, 1), aggregate.messages_received);
    try std.testing.expectEqual(@as(u64, 1), aggregate.messages_sent);
    try std.testing.expectEqual(
        @as(u64, request.len),
        aggregate.bytes_received,
    );
    try std.testing.expectEqual(@as(u64, ping_resp.len), aggregate.bytes_sent);
    try std.testing.expectEqualDeep(local, aggregate);
}

test "MQTT TCP server consumes PROXY v1 before CONNECT" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_packet_size = 4096,
            .proxy_protocol = .v1,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            if (metadata.version != .v1 or metadata.command != .proxy) {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            const source = accepted.connection.remoteAddress();
            if (source != .ip4 or
                !std.mem.eql(u8, &source.ip4.bytes, &.{ 192, 0, 2, 5 }) or
                source.ip4.port != 6275)
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            if (!std.mem.eql(
                u8,
                accepted.connect.connect.client_id,
                "proxy-v1-client",
            )) {
                shared.err = error.InvalidClientId;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    try stream_io.writeAllParts(
        io,
        stream,
        "PROXY TCP4 192.0.2.5 127.0.0.1 6275 1883\r\n",
        "",
    );
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
        .protocol = .v5,
        .limits = .{ .max_packet_size = 4096 },
    };
    stream_owned = false;
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-v1-client",
        .limits = .{ .max_packet_size = 4096 },
    });
    try std.testing.expect(attempt.accepted());
    var result = try attempt.requireAccepted();
    defer result.deinit(allocator);
    try result.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT TCP PROXY v2 requires verified TLS metadata when configured" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.InvalidProperty,
        Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .proxy_v2_require_tls = true,
        }),
    );

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_packet_size = 4096,
            .proxy_protocol = .v2,
            .proxy_v2_require_tls = true,
            .proxy_v2_require_client_certificate = true,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var accepted = shared.server.accept(.{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
            defer accepted.deinit(shared.server.allocator);
            const metadata = accepted.connection.proxyMetadata() orelse {
                shared.err = error.MissingProxyMetadata;
                return;
            };
            const tls = metadata.tls orelse {
                shared.err = error.MissingProxyTls;
                return;
            };
            if (!tls.client_ssl or !tls.verified or
                !tls.client_certificate_session or
                !std.mem.eql(u8, tls.common_name.?, "device-42"))
            {
                shared.err = error.InvalidProxyMetadata;
                return;
            }
            const common_name = accepted.connection
                .authenticatedProxyCommonName() orelse {
                shared.err = error.MissingAuthenticatedProxyIdentity;
                return;
            };
            if (!std.mem.eql(u8, common_name, "device-42")) {
                shared.err = error.InvalidProxyIdentity;
                return;
            }
            var disconnect = accepted.connection.readDisconnect() catch |err| {
                shared.err = err;
                return;
            };
            disconnect.deinit(shared.server.allocator);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const address = [_]u8{
        192, 0, 2, 5, 127, 0, 0, 1, 0x18, 0x83, 0x07, 0x5b,
    };
    const ssl = [_]u8{
        0x05, 0,   0,   0,   0,   0x22, 0,   9, 'd', 'e',
        'v',  'i', 'c', 'e', '-', '4',  '2',
    };
    var proxy_header = proxy_protocol.v2_signature ++
        [_]u8{ 0x21, 0x11, 0, address.len + 3 + ssl.len } ++
        address ++ [_]u8{ 0x20, 0, ssl.len } ++ ssl;
    var empty = [_][]const u8{""};
    const remaining = try io.vtable.netWrite(
        io.userdata,
        stream.socket.handle,
        &proxy_header,
        &empty,
        0,
    );
    try std.testing.expectEqual(proxy_header.len, remaining);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, stream),
        .protocol = .v5,
        .limits = .{ .max_packet_size = 4096 },
    };
    stream_owned = false;
    var attempt = try connection.establishClient(.{
        .protocol = .v5,
        .client_id = "proxy-v2-tls",
        .limits = .{ .max_packet_size = 4096 },
    });
    try std.testing.expect(attempt.accepted());
    var accepted = try attempt.requireAccepted();
    defer accepted.deinit(allocator);
    try accepted.connection.disconnect(0);

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT runtime resolves connection acceptance policies" {
    var pending = PendingAcceptedClient{
        .connection = undefined,
        .connect = .{
            .packet = undefined,
            .connect = .{
                .protocol = .v5,
                .clean_start = true,
                .keep_alive_seconds = 0,
                .client_id = "client",
            },
        },
    };
    const clean_options = try pending.resolvedOptions(.{
        .session_present = true,
    });
    try std.testing.expect(!clean_options.session_present);
    const v5_options = try pending.resolvedOptions(.{
        .server_keep_alive_seconds = 20,
        .maximum_keep_alive_seconds = 10,
    });
    try std.testing.expectEqual(@as(u8, 0), v5_options.reason_code);
    try std.testing.expectEqual(
        @as(?u16, 10),
        v5_options.server_keep_alive_seconds,
    );

    pending.connect.connect.protocol = .v3_1_1;
    pending.connect.connect.keep_alive_seconds = 11;
    const v311_options = try pending.resolvedOptions(.{
        .session_present = true,
        .assigned_client_identifier = "must-not-leak",
        .server_keep_alive_seconds = 9,
        .maximum_keep_alive_seconds = 10,
    });
    try std.testing.expectEqual(@as(u8, 0x02), v311_options.reason_code);
    try std.testing.expect(!v311_options.session_present);
    try std.testing.expect(v311_options.assigned_client_identifier == null);
    try std.testing.expect(v311_options.server_keep_alive_seconds == null);

    pending.connect.connect.protocol = .v5;
    pending.connect.connect.keep_alive_seconds = 10;
    const boundary = try pending.resolvedOptions(.{
        .maximum_keep_alive_seconds = 10,
    });
    try std.testing.expectEqual(
        @as(?u16, null),
        boundary.server_keep_alive_seconds,
    );

    pending.connect.connect.client_id = "";
    const anonymous = try pending.resolvedOptions(.{
        .allow_zero_length_client_id = false,
    });
    try std.testing.expectEqual(@as(u8, 0x80), anonymous.reason_code);
    pending.connect.connect.client_id = "will-client";
    pending.connect.connect.will = .{
        .topic = "will/topic",
        .payload = "will",
        .qos = .at_least_once,
        .retain = false,
    };
    const v5_will = try pending.resolvedOptions(.{
        .maximum_qos = .at_most_once,
    });
    try std.testing.expectEqual(@as(u8, 0x9b), v5_will.reason_code);
    pending.connect.connect.protocol = .v3_1_1;
    const v311_will = try pending.resolvedOptions(.{
        .maximum_qos = .at_most_once,
    });
    try std.testing.expectEqual(@as(u8, 0x05), v311_will.reason_code);
    try std.testing.expectError(
        error.InvalidProperty,
        pending.resolvedOptions(.{ .maximum_keep_alive_seconds = 0 }),
    );
}

test "MQTT Connection allocates PROXY metadata on demand" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };
    const metadata = proxy_protocol.Metadata{
        .allocator = std.testing.allocator,
        .version = .v2,
        .command = .local,
        .source_unix = try std.testing.allocator.dupe(u8, "source.sock"),
    };

    try std.testing.expect(connection.proxyMetadata() == null);
    try std.testing.expectError(
        error.OutOfMemory,
        connection.attachProxyMetadata(metadata),
    );
    try std.testing.expect(connection.proxyMetadata() == null);
    try std.testing.expectEqual(proxy_protocol.Version.v2, metadata.version);
    try std.testing.expectEqualStrings("source.sock", metadata.source_unix.?);

    connection.allocator = std.testing.allocator;
    try connection.attachProxyMetadata(metadata);
    try std.testing.expectEqual(
        proxy_protocol.Version.v2,
        connection.proxyMetadata().?.version,
    );
    connection.clearProxyMetadata();
    try std.testing.expect(connection.proxyMetadata() == null);

    if (@sizeOf(usize) == 8) {
        // Event retries reuse the existing 24-byte packet ownership slot; optional
        // PROXY metadata remains a pointer instead of an inline descriptor.
        // One eight-byte atomic replaces per-read timer ownership with the
        // production Broker's shared inactivity deadline driver.
        try std.testing.expectEqual(@as(usize, 832), @sizeOf(Connection));
        try std.testing.expectEqual(
            @as(usize, 2),
            @sizeOf(ConnectionCapabilities),
        );
        try std.testing.expectEqual(
            @sizeOf(?*proxy_protocol.Metadata),
            @sizeOf(@FieldType(Connection, "proxy_metadata")),
        );
    }
}

test "MQTT Connection uses stack-first write property staging" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
    };
    defer connection.clearWritePropertyOverflow();

    var stack: [write_property_staging_capacity]mqtt.Property = undefined;
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    connection.allocator = no_alloc.allocator();
    const common = try connection.writePropertyList(&stack, stack.len);
    try std.testing.expectEqual(stack[0..].ptr, common.items.ptr);
    try std.testing.expect(connection.write_property_overflow == null);
    try std.testing.expect(!no_alloc.has_induced_failure);

    try std.testing.expectError(
        error.OutOfMemory,
        connection.writePropertyList(&stack, stack.len + 1),
    );
    try std.testing.expect(connection.write_property_overflow == null);

    connection.allocator = allocator;
    const overflow = try connection.writePropertyList(
        &stack,
        stack.len + 1,
    );
    try std.testing.expect(overflow.items.ptr != stack[0..].ptr);
    try std.testing.expectEqual(stack.len + 1, overflow.capacity);

    var warmed = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    connection.allocator = warmed.allocator();
    const reused = try connection.writePropertyList(
        &stack,
        stack.len + 1,
    );
    try std.testing.expectEqual(overflow.items.ptr, reused.items.ptr);
    try std.testing.expect(!warmed.has_induced_failure);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @as(usize, 16),
            @sizeOf(@FieldType(Connection, "write_property_overflow")),
        );
    }
}

test "MQTT Connection owns listener namespace compactly" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };

    try std.testing.expectEqualStrings("", connection.topicNamespace());
    try std.testing.expectError(
        error.OutOfMemory,
        connection.setTopicNamespace("tenant/"),
    );
    try std.testing.expectEqualStrings("", connection.topicNamespace());

    connection.allocator = std.testing.allocator;
    try connection.setTopicNamespace("tenant/");
    try std.testing.expectEqualStrings("tenant/", connection.topicNamespace());
    try std.testing.expectEqualStrings(
        "sensor",
        try connection.visibleTopic("tenant/sensor"),
    );
    try std.testing.expectError(
        error.TopicOutsideNamespace,
        connection.visibleTopic("other/sensor"),
    );

    var replacement_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = replacement_failure.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.setTopicNamespace("replacement/"),
    );
    try std.testing.expectEqualStrings("tenant/", connection.topicNamespace());
    connection.allocator = std.testing.allocator;

    const maximum_prefix = try std.testing.allocator.alloc(
        u8,
        std.math.maxInt(u16),
    );
    defer std.testing.allocator.free(maximum_prefix);
    @memset(maximum_prefix, 'a');
    try connection.setTopicNamespace(maximum_prefix);
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(u16)),
        connection.topicNamespace().len,
    );

    const oversized_prefix = try std.testing.allocator.alloc(
        u8,
        @as(usize, std.math.maxInt(u16)) + 1,
    );
    defer std.testing.allocator.free(oversized_prefix);
    @memset(oversized_prefix, 'b');
    try std.testing.expectError(
        error.InvalidTopic,
        connection.setTopicNamespace(oversized_prefix),
    );
    try std.testing.expectEqualSlices(
        u8,
        maximum_prefix,
        connection.topicNamespace(),
    );

    try connection.setTopicNamespace("");
    try std.testing.expect(connection.topic_namespace_ptr == null);
    try std.testing.expectEqual(@as(u16, 0), connection.topic_namespace_len);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @sizeOf(?[*]u8),
            @sizeOf(@FieldType(Connection, "topic_namespace_ptr")),
        );
        try std.testing.expectEqual(
            @sizeOf(u16),
            @sizeOf(@FieldType(Connection, "topic_namespace_len")),
        );
    }
}

test "MQTT Connection stores the complete optional CONNECT level" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
    };
    try std.testing.expect(connection.incomingConnectLevel() == null);

    connection.setIncomingConnectLevel(0);
    try std.testing.expectEqual(
        @as(?u8, 0),
        connection.incomingConnectLevel(),
    );
    connection.setIncomingConnectLevel(std.math.maxInt(u8));
    try std.testing.expectEqual(
        @as(?u8, std.math.maxInt(u8)),
        connection.incomingConnectLevel(),
    );

    connection.setIncomingConnectLevel(null);
    try std.testing.expect(connection.incomingConnectLevel() == null);
}

test "MQTT Connection retains only post-admission limits" {
    const configured = Limits{
        .max_packet_size = 12_345,
        .max_pending_ping_packets = 7,
        .max_pending_packet_bytes = 2_048,
        .tcp_nodelay = false,
        .proxy_protocol = .v2,
        .proxy_v2_require_tls = true,
        .proxy_v2_require_client_certificate = true,
        .proxy_header_timeout = .fromSeconds(9),
    };
    const active = ConnectionLimits.from(configured);
    try std.testing.expectEqual(
        configured.max_packet_size,
        active.max_packet_size,
    );
    try std.testing.expectEqual(
        configured.max_pending_ping_packets,
        active.max_pending_ping_packets,
    );
    try std.testing.expectEqual(configured.max_pending_packet_bytes, active.max_pending_packet_bytes);
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 24), @sizeOf(ConnectionLimits));
    }

    const connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .limits = active,
        .proxy_v2_require_client_certificate = configured.proxy_v2_require_client_certificate,
    };
    try std.testing.expect(connection.proxy_v2_require_client_certificate);
}

test "MQTT Connection stores assigned Client ID with wire length" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };
    try std.testing.expect(connection.assignedClientId() == null);
    try std.testing.expectError(
        error.OutOfMemory,
        connection.setAssignedClientId("generated-client"),
    );
    try std.testing.expect(connection.assignedClientId() == null);

    connection.allocator = std.testing.allocator;
    try connection.setAssignedClientId("generated-client");
    try std.testing.expectEqualStrings(
        "generated-client",
        connection.assignedClientId().?,
    );
    connection.clearAssignedClientId();
    try std.testing.expect(connection.assignedClientId() == null);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @sizeOf(?[*]u8),
            @sizeOf(@FieldType(Connection, "assigned_client_id_ptr")),
        );
        try std.testing.expectEqual(
            @sizeOf(u16),
            @sizeOf(@FieldType(Connection, "assigned_client_id_len")),
        );
    }
}

test "MQTT Connection allocates Topic Alias tables by direction" {
    const property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};
    var descriptor_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = descriptor_failure.allocator(),
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer connection.clearTopicAliases();

    try std.testing.expect(connection.incoming_topic_aliases == null);
    try std.testing.expect(connection.outgoing_topic_aliases == null);
    try std.testing.expectError(
        error.OutOfMemory,
        connection.prepareOutgoingTopicAliasCommit("alias/topic", &property),
    );
    try std.testing.expect(connection.outgoing_topic_aliases == null);

    var table_failure = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    connection.allocator = table_failure.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.prepareOutgoingTopicAliasCommit("alias/topic", &property),
    );
    try std.testing.expect(connection.outgoing_topic_aliases == null);

    connection.allocator = std.testing.allocator;
    try connection.prepareOutgoingTopicAliasCommit("alias/topic", &property);
    try std.testing.expectEqualStrings(
        "alias/topic",
        connection.outgoingTopicAlias(1).?,
    );
    try std.testing.expect(connection.incoming_topic_aliases == null);

    var incoming = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "incoming/topic",
        .packet_id = null,
        .properties = @constCast(&property),
        .payload = "payload",
    };
    try connection.applyIncomingTopicAlias(&incoming);
    try std.testing.expectEqualStrings(
        "incoming/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expect(connection.outgoing_topic_aliases != null);

    if (@sizeOf(usize) == 8) {
        const table_size: usize = switch (builtin.mode) {
            .Debug, .ReleaseSafe => 32,
            .ReleaseFast, .ReleaseSmall => 24,
        };
        try std.testing.expectEqual(table_size, @sizeOf(topic_alias.Table));
        try std.testing.expectEqual(
            @sizeOf(?*topic_alias.Table),
            @sizeOf(@FieldType(Connection, "incoming_topic_aliases")),
        );
        try std.testing.expectEqual(
            @sizeOf(?*topic_alias.Table),
            @sizeOf(@FieldType(Connection, "outgoing_topic_aliases")),
        );
    }
}

test "MQTT Connection allocates response waiting state on demand" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
    };

    try std.testing.expect(connection.pending_packets == null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingPacketCount());
    try std.testing.expectError(
        error.OutOfMemory,
        connection.ensurePendingPacketQueueAvailable(),
    );
    try std.testing.expect(connection.pending_packets == null);

    connection.allocator = std.testing.allocator;
    try connection.ensurePendingPacketQueueAvailable();
    try std.testing.expect(connection.pending_packets != null);
    try std.testing.expectEqual(@as(usize, 0), connection.pendingPacketCount());
    connection.clearPendingPacketState();
    try std.testing.expect(connection.pending_packets == null);

    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 96), @sizeOf(PendingPacketState));
        try std.testing.expectEqual(
            @sizeOf(?*PendingPacketState),
            @sizeOf(@FieldType(Connection, "pending_packets")),
        );
    }
}

test "MQTT client rejects Session Present after Clean Start" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            runFallible(self) catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
                var peer = PacketTransport.initTcp(
                    self.io,
                    try self.listener.accept(self.io),
                );
                defer peer.close(self.allocator);
                var packet = try peer.readPacket(self.allocator, 4096);
                defer packet.deinit(self.allocator);
                var connect = try mqtt.Connect.parse(
                    self.allocator,
                    packet.bytes,
                );
                defer connect.deinit(self.allocator);
                try std.testing.expectEqual(protocol, connect.protocol);
                try std.testing.expect(connect.clean_start);

                var invalid_connack = [_]u8{
                    0x20,
                    if (protocol == .v5) 0x03 else 0x02,
                    0x01,
                    0x00,
                    0x00,
                };
                const response_len: usize = if (protocol == .v5) 5 else 4;
                try peer.writePacket(invalid_connack[0..response_len]);
            }
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    for ([_]mqtt.ProtocolVersion{ .v3_1_1, .v5 }) |protocol| {
        try std.testing.expectError(
            error.InvalidFlags,
            Client.connectAttempt(allocator, io, listener.socket.address, .{
                .protocol = protocol,
                .client_id = "clean-client",
                .clean_start = true,
                .limits = .{ .max_packet_size = 4096 },
            }),
        );
    }

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "MQTT runtime exposes CONNACK session present" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .session_present = true,
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("resuming-client", accepted.connect.connect.client_id);
            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var result = try Client.connectWithConnAck(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "resuming-client",
        .clean_start = false,
        .limits = .{ .max_packet_size = 4096 },
    });
    defer result.deinit(allocator);
    try std.testing.expect(result.connack.connack.session_present);
    try result.connection.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT server rejects Will above its advertised Maximum QoS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            _ = shared.server.accept(.{
                .protocol = .v5,
                .maximum_qos = .at_most_once,
            }) catch |err| {
                if (err != error.InvalidQoS) shared.err = err;
                return;
            };
            shared.err = error.TestUnexpectedResult;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var attempt = try Client.connectAttempt(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "maximum-qos-will",
            .will = .{
                .topic = "will/maximum-qos",
                .payload = "blocked",
                .qos = .at_least_once,
            },
            .limits = .{ .max_packet_size = 4096 },
        },
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u8, 0x9b), attempt.connack.connack.reason_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT server rejects retained Will when retain is unavailable" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            _ = shared.server.accept(.{
                .protocol = .v5,
                .retain_available = false,
            }) catch |err| {
                if (err != error.InvalidProperty) shared.err = err;
                return;
            };
            shared.err = error.TestUnexpectedResult;
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var attempt = try Client.connectAttempt(
        allocator,
        io,
        server.address(),
        .{
            .protocol = .v5,
            .client_id = "retained-will",
            .will = .{
                .topic = "will/retain",
                .payload = "blocked",
                .retain = true,
            },
            .limits = .{ .max_packet_size = 4096 },
        },
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u8, 0x9a), attempt.connack.connack.reason_code);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT client connectAttempt exposes refused CONNACK reason" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .reason_code = 0x87, // Not authorized.
            });
            defer accepted.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("refused-client", accepted.connect.connect.client_id);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var attempt = try Client.connectAttempt(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "refused-client",
        .limits = .{ .max_packet_size = 4096 },
    });
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expect(attempt.connection == null);
    try std.testing.expectEqual(@as(u8, 0x87), attempt.connack.connack.reason_code);
    try std.testing.expectEqual(@as(usize, 0), attempt.connack.connack.properties.len);

    thread.join();
    if (shared.err) |err| return err;

    var second_server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer second_server.deinit();
    var second_shared = Shared{ .server = &second_server };
    const second_thread = try std.Thread.spawn(.{}, Shared.run, .{&second_shared});
    try std.testing.expectError(error.ConnectRefused, Client.connectWithConnAck(allocator, io, second_server.address(), .{
        .protocol = .v5,
        .client_id = "refused-client",
        .limits = .{ .max_packet_size = 4096 },
    }));
    second_thread.join();
    if (second_shared.err) |err| return err;
}

test "MQTT server reports version-aware CONNECT failures" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        listener: *net.Server,
        io: std.Io,
        allocator: std.mem.Allocator,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            for (0..9) |_| {
                const stream = self.listener.accept(self.io) catch |err| {
                    self.err = err;
                    return;
                };
                var connection = Connection{
                    .allocator = self.allocator,
                    .transport = .initTcp(self.io, stream),
                };
                var pending = connection.acceptPending(.{
                    .connect_timeout = .fromMilliseconds(500),
                }) catch {
                    connection.close();
                    continue;
                };
                pending.deinit(self.allocator);
                self.err = error.TestUnexpectedResult;
                return;
            }
        }
    };
    var shared = Shared{
        .listener = &listener,
        .io = io,
        .allocator = allocator,
    };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.writeConnectPacket(&encoded, allocator, .v5, .{
        .client_id = "unsupported-level",
    });
    const level_index = (try mqtt.FixedHeader.parse(encoded.items)).header_len +
        2 + "MQTT".len;
    const valid_v5 = try allocator.dupe(u8, encoded.items);
    defer allocator.free(valid_v5);
    const mismatched_v31 = try allocator.dupe(u8, valid_v5);
    defer allocator.free(mismatched_v31);
    mismatched_v31[level_index] = 3;
    const unsupported_v6 = try allocator.dupe(u8, valid_v5);
    defer allocator.free(unsupported_v6);
    unsupported_v6[level_index] = 6;
    const invalid_flags = try allocator.dupe(u8, valid_v5);
    defer allocator.free(invalid_flags);
    invalid_flags[0] = 0x1f;
    const cases = [_]struct { packet: []const u8, expected: ?[]const u8 }{
        .{
            .packet = mismatched_v31,
            .expected = &.{ 0x20, 0x02, 0x00, 0x01 },
        },
        .{
            .packet = unsupported_v6,
            .expected = &.{ 0x20, 0x03, 0x00, 0x84, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x0c, 0x00, 0x04, 'M',  'Q',  'T', 'T',
                0x04, 0x00, 0x00, 0x0a, 0x00, 0x00,
            },
            .expected = &.{ 0x20, 0x02, 0x00, 0x02 },
        },
        .{
            .packet = &.{
                0x10, 0x26, 0x00, 0x06, 'M',  'Q',  'I', 's', 'd', 'p',
                0x03, 0x02, 0x00, 0x0a, 0x00, 0x18, 'a', 'b', 'c', 'd',
                'e',  'f',  'g',  'h',  'i',  'j',  'k', 'l', 'm', 'n',
                'o',  'p',  'q',  'r',  's',  't',  'u', 'v', 'w', 'x',
            },
            .expected = &.{ 0x20, 0x02, 0x00, 0x02 },
        },
        .{
            .packet = invalid_flags,
            .expected = &.{ 0x20, 0x03, 0x00, 0x81, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x07, 0x00, 0x04, 'M', 'Q', 'T', 'T', 0x05,
            },
            .expected = &.{ 0x20, 0x03, 0x00, 0x81, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x15, 0x00, 0x04, 'M',  'Q',  'T',  'T',
                0x05, 0x06, 0x00, 0x0a, 0x00, 0x00, 0x01, 'p',
                0x00, 0x00, 0x01, '#',  0x00, 0x01, 'p',
            },
            .expected = &.{ 0x20, 0x03, 0x00, 0x90, 0x00 },
        },
        .{
            .packet = &.{
                0x10, 0x0d, 0x00, 0x04, 'M',  'Q',  'T',  'U',
                0x05, 0x02, 0x00, 0x0a, 0x00, 0x00, 0x00,
            },
            .expected = null,
        },
        .{
            .packet = &.{ 0x10, 0x06, 0x00, 0x04, 'M', 'Q', 'T', 'T' },
            .expected = null,
        },
    };
    const Peer = struct {
        fn run(
            peer_io: std.Io,
            peer_allocator: std.mem.Allocator,
            address: net.IpAddress,
            packet: []const u8,
            expected: ?[]const u8,
        ) !void {
            const stream = try address.connect(
                peer_io,
                .{ .mode = .stream },
            );
            defer stream.close(peer_io);
            try stream_io.writeAllSlices(peer_io, stream, &.{packet});
            var peer = PacketTransport.initTcp(peer_io, stream);
            const deadline = peer.deadlineFromNow(.fromMilliseconds(500));
            const expected_bytes = expected orelse {
                var received = peer.readPacketWithDeadline(
                    peer_allocator,
                    mqtt.ConnAck.no_properties_max_len,
                    deadline,
                ) catch |err| switch (err) {
                    error.EndOfStream,
                    error.ConnectionClosed,
                    error.SocketUnconnected,
                    error.ConnectionResetByPeer,
                    => return,
                    else => return err,
                };
                defer received.deinit(peer_allocator);
                return error.TestUnexpectedResult;
            };
            var received = try peer.readPacketWithDeadline(
                peer_allocator,
                mqtt.ConnAck.no_properties_max_len,
                deadline,
            );
            defer received.deinit(peer_allocator);
            try std.testing.expectEqualSlices(
                u8,
                expected_bytes,
                received.bytes,
            );
        }
    };
    var peer_err: ?anyerror = null;
    for (cases) |case| {
        Peer.run(
            io,
            allocator,
            listener.socket.address,
            case.packet,
            case.expected,
        ) catch |err| if (peer_err == null) {
            peer_err = err;
        };
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    if (peer_err) |err| return err;
}

test "MQTT client follows bounded Server Reference CONNACK" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var redirector = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer redirector.deinit();
    var destination = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer destination.deinit();

    const Shared = struct {
        redirector: *Server,
        destination: *Server,
        reference: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var first = try self.redirector.acceptPending(.{
                .protocol = .v5,
            });
            defer first.deinit(self.redirector.allocator);
            try first.connection.writeConnAck(.{
                .reason_code = 0x9c,
                .properties = &.{.{ .utf8 = .{
                    .id = .server_reference,
                    .value = self.reference,
                } }},
            });
            var second = try self.destination.accept(.{ .protocol = .v5 });
            defer second.deinit(self.destination.allocator);
            try std.testing.expectEqualStrings(
                "redirect-client",
                second.connect.connect.client_id,
            );
            var disconnect = try second.connection.readDisconnect();
            defer disconnect.deinit(self.destination.allocator);
        }
    };
    const reference = try std.fmt.allocPrint(
        allocator,
        "redirect-b.mqtt.resolver.test:{d}",
        .{destination.address().ip4.port},
    );
    defer allocator.free(reference);
    var shared = Shared{
        .redirector = &redirector,
        .destination = &destination,
        .reference = reference,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    const initial_uri = try std.fmt.allocPrint(
        allocator,
        "mqtt://redirect-a.mqtt.resolver.test:{d}",
        .{redirector.address().ip4.port},
    );
    defer allocator.free(initial_uri);
    const Resolver = struct {
        redirect_address: net.IpAddress,
        destination_address: net.IpAddress,
        calls: std.atomic.Value(u8) = .init(0),

        fn resolve(
            context: *anyopaque,
            resolve_allocator: std.mem.Allocator,
            _: std.Io,
            host: []const u8,
            port: u16,
            deadline: ?std.Io.Clock.Timestamp,
        ) AddressResolver.ResolveError![]net.IpAddress {
            const self: *@This() = @ptrCast(@alignCast(context));
            const address = if (std.mem.eql(
                u8,
                host,
                "redirect-a.mqtt.resolver.test",
            ))
                self.redirect_address
            else if (std.mem.eql(
                u8,
                host,
                "redirect-b.mqtt.resolver.test",
            ))
                self.destination_address
            else
                return error.UnknownHostName;
            if (address.getPort() != port or deadline == null) {
                return error.Timeout;
            }
            const addresses = try resolve_allocator.alloc(net.IpAddress, 1);
            addresses[0] = address;
            _ = self.calls.fetchAdd(1, .acq_rel);
            return addresses;
        }
    };
    var resolver = Resolver{
        .redirect_address = redirector.address(),
        .destination_address = destination.address(),
    };
    var result = try Client.connectUriFollowingRedirects(
        allocator,
        io,
        initial_uri,
        .{
            .protocol = .v5,
            .client_id = "redirect-client",
            .network_connect_timeout = .fromSeconds(3),
            .address_resolver = .{
                .context = &resolver,
                .resolve = Resolver.resolve,
            },
            .limits = .{ .max_packet_size = 4096 },
        },
        .{ .max_redirects = 1 },
    );
    defer result.deinit(allocator);
    try result.connection.disconnect(0);
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u8, 2), resolver.calls.load(.acquire));
}

test "MQTT connection enforces outgoing inflight limit before writing" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .outgoing_inflight = 1,
        .max_outgoing_inflight = 1,
    };

    try std.testing.expectError(error.InflightFull, connection.publish("limited/topic", "blocked", .{ .qos = .at_least_once }));
    try std.testing.expectEqual(@as(u16, 1), connection.outgoing_inflight);
}

test "MQTT split publish API pipelines QoS publishes up to receive maximum" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);

            var first = try accepted.connection.readPublish();
            defer first.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("pipeline/one", first.publish.topic);
            try std.testing.expectEqualStrings("one", first.publish.payload);

            var second = try accepted.connection.readPublish();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("pipeline/two", second.publish.topic);
            try std.testing.expectEqualStrings("two", second.publish.payload);

            // Delay acknowledgements until both publishes have arrived. This
            // proves the client API can actually fill the negotiated in-flight
            // window instead of waiting for each PUBACK before writing the next
            // PUBLISH, matching rumqtt's state-machine model.
            try accepted.connection.writePubAck(first.publish.packet_id.?, 0);
            try accepted.connection.writePubAck(second.publish.packet_id.?, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "pipeline-client",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_inflight = 2,
    });
    defer client.close();
    try std.testing.expectEqual(@as(u16, 2), client.max_outgoing_inflight);

    const first_id = (try client.writePublish("pipeline/one", "one", .{ .qos = .at_least_once })).?;
    const second_id = (try client.writePublish("pipeline/two", "two", .{ .qos = .at_least_once })).?;
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);
    try std.testing.expectError(error.InflightFull, client.writePublish("pipeline/three", "three", .{ .qos = .at_least_once }));

    try client.completePublishPubAck(first_id);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try client.completePublishPubAck(second_id);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT split publish API accepts out-of-order QoS1 PUBACKs" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);

            var first = try accepted.connection.readPublish();
            defer first.deinit(server_ptr.allocator);
            var second = try accepted.connection.readPublish();
            defer second.deinit(server_ptr.allocator);

            // A real broker is not required to acknowledge QoS 1 publishes in
            // send order.  Rumqtt tracks in-flight publishes by Packet
            // Identifier; the split API should likewise let callers retire the
            // ACK that actually arrived instead of forcing head-of-line order.
            try accepted.connection.writePubAck(second.publish.packet_id.?, 0);
            try accepted.connection.writePubAck(first.publish.packet_id.?, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "out-of-order-puback",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_inflight = 2,
    });
    defer client.close();

    const first_id = (try client.writePublish("ack/one", "one", .{ .qos = .at_least_once })).?;
    const second_id = (try client.writePublish("ack/two", "two", .{ .qos = .at_least_once })).?;
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    // Passing 0 means "complete whichever PUBACK arrives next".  This keeps
    // the API simple for event-loop users that read acks from the wire before
    // dispatching them to request waiters.
    try client.completePublishPubAck(0);
    try std.testing.expect(!client.packet_identifiers.contains(
        second_id,
        .outgoing_qos1,
    ));
    try std.testing.expect(client.packet_identifiers.contains(
        first_id,
        .outgoing_qos1,
    ));
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try client.completePublishPubAck(0);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT split publish API accepts out-of-order QoS2 PUBREC handshakes" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{
                .protocol = .v5,
                .max_outgoing_inflight = 2,
            });
            defer accepted.deinit(server_ptr.allocator);

            var first = try accepted.connection.readPublish();
            defer first.deinit(server_ptr.allocator);
            var second = try accepted.connection.readPublish();
            defer second.deinit(server_ptr.allocator);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, first.publish.qos);
            try std.testing.expectEqual(mqtt.QoS.exactly_once, second.publish.qos);

            try accepted.connection.writePubRec(second.publish.packet_id.?, 0);
            try accepted.connection.writePubRec(first.publish.packet_id.?, 0);

            var second_rel = try accepted.connection.readPubRel();
            defer second_rel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(second.publish.packet_id.?, second_rel.ack.packet_id);

            var first_rel = try accepted.connection.readPubRel();
            defer first_rel.deinit(server_ptr.allocator);
            try std.testing.expectEqual(first.publish.packet_id.?, first_rel.ack.packet_id);

            try accepted.connection.writePubComp(second_rel.ack.packet_id, 0);
            try accepted.connection.writePubComp(first_rel.ack.packet_id, 0);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "out-of-order-pubrec",
        .limits = .{ .max_packet_size = 4096 },
        .max_outgoing_inflight = 2,
    });
    defer client.close();

    const first_id = (try client.writePublish("qos2/one", "one", .{ .qos = .exactly_once })).?;
    const second_id = (try client.writePublish("qos2/two", "two", .{ .qos = .exactly_once })).?;
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    const second_rec = try client.completePublishPubRec(0);
    try std.testing.expectEqual(second_id, second_rec);
    try std.testing.expect(!client.packet_identifiers.contains(
        second_id,
        .outgoing_qos2,
    ));
    try std.testing.expect(client.packet_identifiers.contains(
        second_id,
        .outgoing_qos2_pubrel,
    ));
    try std.testing.expect(client.packet_identifiers.contains(
        first_id,
        .outgoing_qos2,
    ));
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    const first_rec = try client.completePublishPubRec(0);
    try std.testing.expectEqual(first_id, first_rec);
    try std.testing.expect(client.packet_identifiers.contains(
        first_id,
        .outgoing_qos2_pubrel,
    ));
    try std.testing.expectEqual(@as(u16, 2), client.outgoing_inflight);

    try client.completePublishPubComp(second_id);
    try std.testing.expectEqual(@as(u16, 1), client.outgoing_inflight);
    try client.completePublishPubComp(first_id);
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT Receive Maximum cannot raise local outgoing inflight cap" {
    try std.testing.expectEqual(@as(u16, 2), negotiatedOutgoingInflightLimit(2, 3));
    try std.testing.expectEqual(@as(u16, 2), negotiatedOutgoingInflightLimit(3, 2));
    try std.testing.expectEqual(@as(u16, 1), negotiatedOutgoingInflightLimit(1, 1));
}

test "MQTT client Receive Maximum has an independent compatibility fallback" {
    try std.testing.expectEqual(
        @as(u16, 16),
        (ConnectOptions{ .client_id = "default" }).effectiveReceiveMaximum(),
    );
    try std.testing.expectEqual(
        @as(u16, 7),
        (ConnectOptions{
            .client_id = "configured",
            .max_outgoing_inflight = 3,
            .receive_maximum = 7,
        }).effectiveReceiveMaximum(),
    );
    const properties = [_]mqtt.Property{.{ .two_byte = .{
        .id = .receive_maximum,
        .value = 11,
    } }};
    try std.testing.expectEqual(
        @as(u16, 11),
        (ConnectOptions{
            .client_id = "property",
            .max_outgoing_inflight = 3,
            .receive_maximum = 7,
            .properties = &properties,
        }).effectiveReceiveMaximum(),
    );
}

test "MQTT connection enforces negotiated maximum packet size" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_max_packet_size = 8,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);
    defer connection.write_scratch.deinit(std.testing.allocator);

    try std.testing.expectError(error.OutgoingPacketTooLarge, connection.publish("limited/topic", "payload too large", .{}));
}

test "MQTT borrowed PUBLISH preserves preflight errors and inflight state" {
    const alias_property = [_]mqtt.Property{.{
        .two_byte = .{ .id = .topic_alias, .value = 1 },
    }};
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = .{ .tcp = undefined },
        .protocol = .v5,
        .peer_max_packet_size = 8,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);
    defer connection.write_scratch.deinit(std.testing.allocator);
    defer connection.clearOutgoingTopicAliases();

    try std.testing.expectError(
        error.OutgoingPacketTooLarge,
        connection.writePublish("too/large", "payload", .{
            .qos = .at_least_once,
            .properties = &alias_property,
        }),
    );
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        connection.outgoingTopicAlias(1),
    );
    try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.packet_identifiers.count(.outgoing_qos1),
    );
    try std.testing.expect(connection.isUsable());

    try connection.prepareOutgoingTopicAliasCommit(
        "existing/topic",
        &alias_property,
    );
    connection.peer_max_packet_size = std.math.maxInt(usize);
    connection.authentication.phase = .authenticating;
    try std.testing.expectError(
        error.AuthenticationInProgress,
        connection.writePublish("auth/blocked", "payload", .{
            .qos = .at_least_once,
            .properties = &alias_property,
        }),
    );
    try std.testing.expectEqualStrings(
        "existing/topic",
        connection.outgoingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.packet_identifiers.count(.outgoing_qos1),
    );
    try std.testing.expect(connection.isUsable());
}

test "MQTT publish encoding reuses connection scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    defer connection.packet_identifiers.deinit(allocator);
    defer connection.write_scratch.deinit(allocator);

    const payload = [_]u8{0xa5} ** 1024;
    _ = try connection.writePublish("scratch/topic", &payload, .{});
    const storage = connection.write_scratch.allocatedSlice().ptr;
    const prefix_capacity = connection.write_scratch.capacity;
    try std.testing.expect(connection.write_scratch.items.len < payload.len);
    var peer = PacketTransport.initTcp(io, server_stream);
    var first = try peer.readPacket(allocator, 2048);
    defer first.deinit(allocator);
    var first_publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        first.bytes,
    );
    defer first_publish.deinit(allocator);
    try std.testing.expectEqualStrings("scratch/topic", first_publish.topic);
    try std.testing.expectEqualSlices(u8, &payload, first_publish.payload);

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    // TCP writes the retained MQTT prefix and borrowed application payload as
    // one vectored stream operation. The payload therefore does not determine
    // scratch capacity and warm sends need no allocation.
    failing.fail_index = failing.alloc_index;
    connection.allocator = failing.allocator();
    _ = try connection.writePublish("scratch/topic", &payload, .{});
    try std.testing.expectEqual(
        storage,
        connection.write_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        prefix_capacity,
        connection.write_scratch.capacity,
    );
    try std.testing.expect(connection.write_scratch.items.len < payload.len);
    try std.testing.expect(!failing.has_induced_failure);
    var second = try peer.readPacket(allocator, 2048);
    defer second.deinit(allocator);
    var second_publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        second.bytes,
    );
    defer second_publish.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &payload, second_publish.payload);
}

test "MQTT outgoing Packet Identifier allocation failure is transactional" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var connection = Connection{
        .allocator = failing.allocator(),
        .transport = undefined,
        .protocol = .v5,
        .next_packet_id = 65_535,
    };
    defer connection.packet_identifiers.deinit(failing.allocator());

    try std.testing.expectError(
        error.OutOfMemory,
        connection.reserveOutgoingPublish(.at_least_once),
    );
    try std.testing.expectEqual(@as(u16, 65_535), connection.next_packet_id);
    try std.testing.expectEqual(@as(u16, 0), connection.outgoing_inflight);
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.packet_identifiers.count(.outgoing_qos1),
    );
}

test "MQTT variable control writes reuse connection scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    defer connection.write_scratch.deinit(allocator);
    defer connection.clearWritePropertyOverflow();
    var peer = PacketTransport.initTcp(io, server_stream);

    const diagnostic_properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "diagnostic reason",
        } },
        .{ .utf8_pair = .{
            .id = .user_property,
            .key = "trace",
            .value = "control-writer",
        } },
    };
    const disconnect_properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .server_reference,
            .value = "mqtt.example.test",
        } },
    };
    const auth_properties = [_]mqtt.Property{
        .{ .utf8 = .{
            .id = .authentication_method,
            .value = "SCRAM-SHA-256",
        } },
        .{ .binary = .{
            .id = .authentication_data,
            .value = "server-final",
        } },
    };
    const suback_reasons = [_]u8{ 0x00, 0x01 };
    const unsuback_reasons = [_]u8{ 0x00, 0x11 };

    // First pass establishes the maximum output/property capacities used by
    // this sequence. Owned peer packets remain the byte-for-byte oracle for
    // the second pass, independent of codec implementation details.
    try connection.writeConnAck(.{});
    var expected_connack = try peer.readPacket(allocator, 4096);
    defer expected_connack.deinit(allocator);
    try connection.writePubAckWithProperties(
        1,
        0x80,
        &diagnostic_properties,
    );
    var expected_puback = try peer.readPacket(allocator, 4096);
    defer expected_puback.deinit(allocator);
    try connection.writeSubAck(
        2,
        &suback_reasons,
        &diagnostic_properties,
    );
    var expected_suback = try peer.readPacket(allocator, 4096);
    defer expected_suback.deinit(allocator);
    try connection.writeUnsubAck(
        3,
        &unsuback_reasons,
        &diagnostic_properties,
    );
    var expected_unsuback = try peer.readPacket(allocator, 4096);
    defer expected_unsuback.deinit(allocator);
    var expected_disconnect: std.ArrayList(u8) = .empty;
    defer expected_disconnect.deinit(allocator);
    try mqtt.Disconnect.write(&expected_disconnect, allocator, .v5, 0x9c, &disconnect_properties);
    try connection.writeAuth(0x18, &auth_properties);
    var expected_auth = try peer.readPacket(allocator, 4096);
    defer expected_auth.deinit(allocator);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try connection.writeConnAck(.{});
    try connection.writePubAckWithProperties(
        1,
        0x80,
        &diagnostic_properties,
    );
    try connection.writeSubAck(
        2,
        &suback_reasons,
        &diagnostic_properties,
    );
    try connection.writeUnsubAck(
        3,
        &unsuback_reasons,
        &diagnostic_properties,
    );
    try connection.writeAuth(0x18, &auth_properties);
    try connection.writeDisconnectWithProperties(0x9c, &disconnect_properties);
    try std.testing.expect(!failing.has_induced_failure);

    const expected_packets = [_][]const u8{
        expected_connack.bytes,
        expected_puback.bytes,
        expected_suback.bytes,
        expected_unsuback.bytes,
        expected_auth.bytes,
        expected_disconnect.items,
    };
    for (expected_packets) |expected| {
        var actual = try peer.readPacket(allocator, 4096);
        defer actual.deinit(allocator);
        try std.testing.expectEqualSlices(u8, expected, actual.bytes);
    }
}

test "MQTT runtime validates DISCONNECT state and sender direction" {
    const zero_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 0,
    } }};
    const nonzero_expiry = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 30,
    } }};

    var client = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .endpoint_role = .client,
        .connect_session_expiry = 0,
    };
    try client.validateOutgoingDisconnect(0, &zero_expiry);
    try std.testing.expectError(
        error.InvalidProperty,
        client.validateOutgoingDisconnect(0, &nonzero_expiry),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.validateOutgoingDisconnect(0x89, &.{}),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.writeDisconnectWithProperties(0x89, &.{}),
    );
    // The public writer must fail before touching the deliberately absent
    // transport or allocating/encoding packet storage.
    try std.testing.expectError(
        error.InvalidProperty,
        client.writeDisconnectWithProperties(0, &nonzero_expiry),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        client.validateIncomingDisconnect(.{
            .properties = @constCast(&zero_expiry),
        }),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.validateIncomingDisconnect(.{ .reason_code = 0x04 }),
    );

    var server = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .endpoint_role = .server,
        .connect_session_expiry = 0,
    };
    try std.testing.expectError(
        error.InvalidProperty,
        server.validateOutgoingDisconnect(0, &zero_expiry),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.validateOutgoingDisconnect(0x04, &.{}),
    );
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.writeDisconnectWithProperties(0x04, &.{}),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        server.writeDisconnectWithProperties(0, &zero_expiry),
    );
    try server.validateIncomingDisconnect(.{
        .properties = @constCast(&zero_expiry),
    });
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.validateIncomingDisconnect(.{ .reason_code = 0x89 }),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        server.validateIncomingDisconnect(.{
            .properties = @constCast(&nonzero_expiry),
        }),
    );

    client.connect_session_expiry = 10;
    server.connect_session_expiry = 10;
    try client.validateOutgoingDisconnect(0, &nonzero_expiry);
    try server.validateIncomingDisconnect(.{
        .properties = @constCast(&nonzero_expiry),
    });
}

test "MQTT runtime validates AUTH reason sender direction" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var client = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .client,
    };
    try client.validateOutgoingAuthReason(0x18);
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.writeAuth(0x00, &.{}),
    );
    try mqtt.Auth.write(&encoded, allocator, .v5, 0x19, &.{});
    try std.testing.expectError(
        error.InvalidReasonCode,
        client.parseIncomingAuth(encoded.items),
    );

    encoded.clearRetainingCapacity();
    var server = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
    };
    try server.validateOutgoingAuthReason(0x00);
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.writeAuth(0x19, &.{}),
    );
    try mqtt.Auth.write(&encoded, allocator, .v5, 0x00, &.{});
    try std.testing.expectError(
        error.InvalidReasonCode,
        server.parseIncomingAuth(encoded.items),
    );

    encoded.clearRetainingCapacity();
    try mqtt.Auth.write(&encoded, allocator, .v5, 0x18, &.{});
    var client_continue = try client.parseIncomingAuth(encoded.items);
    client_continue.deinit(allocator);
    var server_continue = try server.parseIncomingAuth(encoded.items);
    server_continue.deinit(allocator);
}

test "MQTT runtime enforces Control Packet endpoint direction before I/O" {
    var client = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .client,
    };
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writeConnAck(.{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writeSubAck(1, &.{0x00}, &.{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writeUnsubAck(1, &.{0x00}, &.{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.writePingResp(),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.validateIncomingPacketType(.subscribe),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.validateIncomingPacketType(.pingreq),
    );
    const client_incoming = try std.testing.allocator.dupe(
        u8,
        &.{ 0xc0, 0x00 },
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        client.finishReadPacket(.{
            .bytes = client_incoming,
            .fixed = try mqtt.FixedHeader.parse(client_incoming),
        }),
    );

    var server = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
    };
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.establishClient(.{ .client_id = "invalid-server-connect" }),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.subscribe(&.{.{ .topic_filter = "direction/#" }}, .{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.unsubscribe(&.{"direction/#"}, .{}),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.writePingReq(),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.validateIncomingPacketType(.connack),
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.validateIncomingPacketType(.pingresp),
    );
    const server_incoming = try std.testing.allocator.dupe(
        u8,
        &.{ 0xd0, 0x00 },
    );
    try std.testing.expectError(
        error.InvalidPacketDirection,
        server.finishReadPacket(.{
            .bytes = server_incoming,
            .fixed = try mqtt.FixedHeader.parse(server_incoming),
        }),
    );
    const malformed_server_only = try std.testing.allocator.dupe(
        u8,
        &.{ 0xd1, 0x00 },
    );
    try std.testing.expectError(
        error.InvalidFlags,
        server.finishReadPacket(.{
            .bytes = malformed_server_only,
            .fixed = try mqtt.FixedHeader.parse(malformed_server_only),
        }),
    );

    try client.validateOutgoingPacketType(.publish);
    try server.validateOutgoingPacketType(.publish);
    try client.validateIncomingPacketType(.publish);
    try server.validateIncomingPacketType(.publish);
}

test "MQTT runtime enforces incoming maximum packet size on full frame" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var sender = PacketTransport.initTcp(io, client_stream);
    var ping: std.ArrayList(u8) = .empty;
    defer ping.deinit(allocator);
    try mqtt.writePing(&ping, allocator, false);
    try sender.writePacket(ping.items);
    var transport = PacketTransport.initTcp(io, server_stream);

    // A PINGREQ has Remaining Length 0 but a total Control Packet length of 2.
    // MQTT 5's Maximum Packet Size applies to that total length, matching
    // rumqtt's outbound size check and preventing tiny limits from being
    // bypassed by packets with empty variable headers/payloads.
    try std.testing.expectError(
        error.PacketTooLarge,
        transport.readPacket(allocator, 1),
    );
}

test "MQTT runtime PING writes use fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();
    try connection.writePingResp();
    try std.testing.expect(!fail_first.has_induced_failure);

    var received: [mqtt.ping_packet_len]u8 = undefined;
    var buffers = [_][]u8{&received};
    const n = try io.vtable.netRead(
        io.userdata,
        server_stream.socket.handle,
        &buffers,
    );
    try std.testing.expectEqual(received.len, n);
    try mqtt.validatePing(&received, true);
}

test "MQTT runtime property-free acknowledgements use fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();

    // Exercise both MQTT 5 wire lengths, then MQTT 3.1's duplicate PUBREL.
    // Success omits Reason Code and Property Length, while a negative
    // acknowledgement carries the reason.
    try connection.writePubAck(0x1234, 0);
    try connection.writePubRec(0x5678, 0x80);
    try connection.writePubRel(0x9abc, 0);
    try connection.writePubComp(0xdef0, 0x92);
    connection.capabilities.peer_requested_problem_information = false;
    try connection.writePubAckWithProperties(0x2468, 0x80, &.{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "suppressed",
        } },
    });
    connection.protocol = .v3_1;
    try connection.writePubRelWithDup(0x1357, 0, true);
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{
        0x40, 0x02, 0x12, 0x34,
        0x50, 0x03, 0x56, 0x78,
        0x80, 0x62, 0x02, 0x9a,
        0xbc, 0x70, 0x03, 0xde,
        0xf0, 0x92, 0x40, 0x03,
        0x24, 0x68, 0x80, 0x6a,
        0x02, 0x13, 0x57,
    };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT runtime property-free DISCONNECT uses fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();
    try connection.disconnect(0x8d);
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{ 0xe0, 0x01, 0x8d };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT runtime property-free AUTH uses fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .capabilities = .{ .peer_requested_problem_information = false },
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();

    try connection.writeAuth(0, &.{});
    try connection.writeAuth(0x18, &.{
        .{ .utf8 = .{
            .id = .reason_string,
            .value = "suppressed",
        } },
    });
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{
        0xf0, 0x00,
        0xf0, 0x02,
        0x18, 0x00,
    };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT runtime bare CONNACK uses fixed caller storage" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer client_stream.close(io);
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
    };
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = fail_first.allocator();

    // Rejected v5 connections do not advertise negotiated capabilities; v3
    // has no CONNACK property field at all. Both forms must remain writable
    // even when the general allocator cannot provide a scratch allocation.
    try connection.writeConnAck(.{ .reason_code = 0x80 });
    connection.protocol = .v3_1_1;
    try connection.writeConnAck(.{ .reason_code = 0x05 });
    try std.testing.expect(!fail_first.has_induced_failure);

    const expected = [_]u8{
        0x20, 0x03, 0x00, 0x80,
        0x00, 0x20, 0x02, 0x00,
        0x05,
    };
    var received: [expected.len]u8 = undefined;
    var offset: usize = 0;
    while (offset < received.len) {
        var buffers = [_][]u8{received[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            server_stream.socket.handle,
            &buffers,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
    try std.testing.expectEqualSlices(u8, &expected, &received);
}

test "MQTT server applies the effective inbound QoS limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const peer = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer peer.close(io);
    const server_stream = try listener.accept(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, server_stream),
        .protocol = .v3_1_1,
    };
    defer connection.close();
    try connection.writeConnAck(.{ .max_outgoing_inflight = 1 });
    try std.testing.expectEqual(
        @as(u16, 1),
        connection.max_incoming_inflight,
    );

    connection.protocol = .v5;
    try connection.writeConnAck(.{
        .properties = &.{.{ .two_byte = .{
            .id = .receive_maximum,
            .value = 2,
        } }},
        .max_outgoing_inflight = 3,
    });
    try std.testing.expectEqual(
        @as(u16, 2),
        connection.max_incoming_inflight,
    );

    try connection.writeConnAck(.{
        .max_outgoing_inflight = std.math.maxInt(u16),
    });
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        connection.max_incoming_inflight,
    );
}

test "MQTT connection enforces incoming receive maximum" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .max_incoming_inflight = 1,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);

    const first = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/one",
        .packet_id = 10,
        .payload = "first",
    };
    _ = try connection.recordIncomingPublish(first);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    var retry = first;
    retry.dup = true;
    _ = try connection.recordIncomingPublish(retry);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    try std.testing.expectError(error.ReceiveMaximumExceeded, connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/two",
        .packet_id = 11,
        .payload = "second",
    }));

    connection.completeIncomingPublish(.puback, 10);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/two",
        .packet_id = 11,
        .payload = "second",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
}

test "MQTT incoming PUBLISH commits QoS and Topic Alias transactionally" {
    const allocator = std.testing.allocator;
    const alias_property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
        .max_incoming_inflight = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer connection.packet_identifiers.deinit(allocator);
    defer connection.clearIncomingTopicAliases();
    try (try connection.ensureIncomingTopicAliases()).put(
        allocator,
        1,
        "old/topic",
    );

    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "seed",
        .packet_id = 17,
        .payload = "seed",
    });
    var conflicting = mqtt.Publish{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "new/topic",
        .packet_id = 17,
        .properties = @constCast(&alias_property),
        .payload = "conflict",
    };
    try std.testing.expectError(
        error.InvalidPacketIdentifier,
        connection.commitIncomingPublish(&conflicting),
    );
    try std.testing.expectEqualStrings(
        "old/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    var over_limit = conflicting;
    over_limit.packet_id = 18;
    try std.testing.expectError(
        error.ReceiveMaximumExceeded,
        connection.commitIncomingPublish(&over_limit),
    );
    try std.testing.expectEqualStrings(
        "old/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    connection.completeIncomingPublish(.pubcomp, 17);
    // Keep sparse identifier capacity available so the only allocation in the
    // commit is the Topic Alias replacement after QoS registration.
    _ = try connection.packet_identifiers.add(
        allocator,
        19,
        .incoming_qos1,
    );
    try std.testing.expect(connection.packet_identifiers.remove(
        connection.allocator,
        19,
        .incoming_qos1,
    ));
    var fail_alias = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    connection.allocator = fail_alias.allocator();
    var allocation_failure = conflicting;
    allocation_failure.packet_id = 19;
    try std.testing.expectError(
        error.OutOfMemory,
        connection.commitIncomingPublish(&allocation_failure),
    );
    try std.testing.expectEqualStrings(
        "old/topic",
        connection.incomingTopicAlias(1).?,
    );
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    try std.testing.expect(!connection.packet_identifiers.contains(
        19,
        .incoming_qos1,
    ));
}

test "MQTT connection keeps QoS2 receive slot until PUBCOMP" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .max_incoming_inflight = 1,
    };
    defer connection.packet_identifiers.deinit(std.testing.allocator);

    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "receive/qos2",
        .packet_id = 20,
        .payload = "first",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
    try connection.validateIncomingPubRel(20);
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.validateIncomingPubRel(21));
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "receive/reuse",
        .packet_id = 20,
        .payload = "reuse",
    }));

    connection.completeIncomingPublish(.puback, 20);
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
    try std.testing.expectError(error.ReceiveMaximumExceeded, connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "receive/blocked",
        .packet_id = 21,
        .payload = "blocked",
    }));

    connection.completeIncomingPublish(.pubcomp, 20);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.validateIncomingPubRel(20));
    _ = try connection.recordIncomingPublish(.{
        .dup = false,
        .qos = .exactly_once,
        .retain = false,
        .topic = "receive/after-comp",
        .packet_id = 21,
        .payload = "ok",
    });
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);

    connection.completeIncomingPubRec(21, 0x10); // No matching subscribers still completes via PUBREL/PUBCOMP.
    try std.testing.expectEqual(@as(u16, 1), connection.incoming_inflight);
    try connection.validateIncomingPubRel(21);
    connection.completeIncomingPubRec(21, 0x80);
    try std.testing.expectEqual(@as(u16, 0), connection.incoming_inflight);
    try std.testing.expectError(error.InvalidPacketIdentifier, connection.validateIncomingPubRel(21));
}

test "MQTT connection enforces negotiated subscribe capabilities" {
    const exact = [_]mqtt.Subscription{.{ .topic_filter = "sensors/temp" }};
    const wildcard = [_]mqtt.Subscription{.{ .topic_filter = "sensors/+" }};
    const shared = [_]mqtt.Subscription{.{ .topic_filter = "$share/workers/sensors/temp" }};
    const sub_id = [_]mqtt.Property{.{ .varint = .{ .id = .subscription_identifier, .value = 1 } }};

    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .capabilities = .{
            .peer_wildcard_subscription_available = false,
            .peer_subscription_identifier_available = false,
            .peer_shared_subscription_available = false,
        },
    };

    try connection.validateOutgoingSubscribe(&exact, &.{});
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&wildcard, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&shared, &.{}));
    try std.testing.expectError(error.SubscriptionRefused, connection.validateOutgoingSubscribe(&exact, &sub_id));

    connection.capabilities.local_wildcard_subscription_available = false;
    connection.capabilities.local_subscription_identifier_available = false;
    connection.capabilities.local_shared_subscription_available = false;
    try connection.validateIncomingSubscribe(&exact, &.{});
    try std.testing.expectError(error.WildcardSubscriptionsNotSupported, connection.validateIncomingSubscribe(&wildcard, &.{}));
    try std.testing.expectError(error.SharedSubscriptionsNotSupported, connection.validateIncomingSubscribe(&shared, &.{}));
    try std.testing.expectError(error.SubscriptionIdentifiersNotSupported, connection.validateIncomingSubscribe(&exact, &sub_id));
}

test "MQTT connection rejects topic aliases beyond negotiated maximum" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
        .incoming_topic_alias_maximum = 1,
    };
    defer connection.clearOutgoingTopicAliases();

    try std.testing.expectError(error.InvalidProperty, connection.publish("topic", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }},
    }));
    try std.testing.expectError(error.InvalidTopic, connection.publish("", "payload", .{
        .properties = &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }},
    }));
    try connection.validateOutgoingTopicAlias("topic", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try connection.prepareOutgoingTopicAliasCommit("topic", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});
    try connection.validateOutgoingTopicAlias("", &.{.{ .two_byte = .{ .id = .topic_alias, .value = 1 } }});

    var incoming = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "topic",
        .packet_id = null,
        .properties = @constCast(&[_]mqtt.Property{.{ .two_byte = .{ .id = .topic_alias, .value = 2 } }}),
        .payload = "payload",
    };
    try std.testing.expectError(error.TopicAliasInvalid, connection.applyIncomingTopicAlias(&incoming));
}

test "MQTT connection automatically establishes and reuses outgoing aliases" {
    const allocator = std.testing.allocator;
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = 2,
    };
    defer connection.clearOutgoingTopicAliases();

    var first_properties: std.ArrayList(mqtt.Property) = .empty;
    defer first_properties.deinit(allocator);
    const first_topic = try connection.prepareAutomaticTopicAlias(
        "alias/topic",
        &first_properties,
    );
    try std.testing.expectEqualStrings("alias/topic", first_topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        first_properties.items,
    ));
    try connection.prepareOutgoingTopicAliasCommit(
        first_topic,
        first_properties.items,
    );

    var repeated_properties: std.ArrayList(mqtt.Property) = .empty;
    defer repeated_properties.deinit(allocator);
    const repeated_topic = try connection.prepareAutomaticTopicAlias(
        "alias/topic",
        &repeated_properties,
    );
    try std.testing.expectEqualStrings("", repeated_topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        repeated_properties.items,
    ));

    var second_properties: std.ArrayList(mqtt.Property) = .empty;
    defer second_properties.deinit(allocator);
    const second_topic = try connection.prepareAutomaticTopicAlias(
        "second/topic",
        &second_properties,
    );
    try std.testing.expectEqualStrings("second/topic", second_topic);
    try std.testing.expectEqual(@as(?u16, 2), mqtt.topicAlias(
        second_properties.items,
    ));
}

test "MQTT Session PUBLISH projects Topic Alias per Network Connection" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const transmission = @import("../session/mod.zig").Transmission{
        .publish = .{
            .topic = "durable/alias",
            .payload = "payload",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 7,
            .properties = &.{.{ .four_byte = .{
                .id = .message_expiry_interval,
                .value = 60,
            } }},
            .message_expiry_interval = 30,
        },
    };

    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.close();

    try connection.writeSessionTransmission(
        transmission,
        .exactly_once,
    );
    try std.testing.expect(connection.write_property_overflow == null);
    var first_packet = try peer.readPacket(allocator, 4096);
    defer first_packet.deinit(allocator);
    var first = try mqtt.Publish.parse(allocator, .v5, first_packet.bytes);
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("durable/alias", first.topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        first.properties,
    ));
    try std.testing.expectEqual(@as(?u32, 30), mqtt.messageExpiryInterval(
        first.properties,
    ));
    try std.testing.expect(connection.write_scratch.items.len <
        first_packet.bytes.len);

    // The next delivery reuses the encoded prefix, stages its small property
    // set on the stack, and needs no Topic Alias map growth, so the complete
    // write succeeds when every new allocation is rejected.
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    try connection.writeSessionTransmission(
        transmission,
        .exactly_once,
    );
    try std.testing.expect(!failing.has_induced_failure);
    try std.testing.expect(connection.write_property_overflow == null);
    var second_packet = try peer.readPacket(allocator, 4096);
    defer second_packet.deinit(allocator);
    var second = try mqtt.Publish.parse(
        allocator,
        .v5,
        second_packet.bytes,
    );
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("", second.topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        second.properties,
    ));
    try std.testing.expectEqualStrings(
        "durable/alias",
        transmission.publish.topic,
    );
    try std.testing.expect(mqtt.topicAlias(
        transmission.publish.properties,
    ) == null);

    const fresh_client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var fresh_peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer fresh_peer.close(allocator);
    var fresh = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, fresh_client_stream),
        .protocol = .v5,
        .endpoint_role = .client,
        .peer_topic_alias_maximum = 1,
    };
    defer fresh.close();
    try fresh.writeClientSessionTransmission(transmission);
    var fresh_packet = try fresh_peer.readPacket(allocator, 4096);
    defer fresh_packet.deinit(allocator);
    var fresh_publish = try mqtt.Publish.parse(
        allocator,
        .v5,
        fresh_packet.bytes,
    );
    defer fresh_publish.deinit(allocator);
    try std.testing.expectEqualStrings("durable/alias", fresh_publish.topic);
    try std.testing.expectEqual(@as(?u16, 1), mqtt.topicAlias(
        fresh_publish.properties,
    ));
}

test "MQTT Session PUBLISH falls back when alias form exceeds packet limit" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);

    const transmission = @import("../session/mod.zig").Transmission{
        .publish = .{
            .topic = "a",
            .payload = "x",
            .qos = .at_least_once,
            .retain = false,
            .dup = false,
            .packet_id = 9,
            .properties = &.{},
            .message_expiry_interval = null,
        },
    };
    var exact: std.ArrayList(u8) = .empty;
    defer exact.deinit(allocator);
    try transmission.publish.write(&exact, allocator, .v5);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .peer_topic_alias_maximum = 1,
        .peer_max_packet_size = exact.items.len,
    };
    defer connection.close();
    try (try connection.ensureOutgoingTopicAliases()).put(allocator, 1, "a");

    try connection.writeSessionTransmission(transmission, .exactly_once);
    try std.testing.expectEqual(@as(usize, 1), connection.outgoingTopicAliasCount());
    try std.testing.expectEqualStrings(
        "a",
        connection.outgoingTopicAlias(1).?,
    );
    var packet = try peer.readPacket(allocator, 4096);
    defer packet.deinit(allocator);
    var publish = try mqtt.Publish.parse(allocator, .v5, packet.bytes);
    defer publish.deinit(allocator);
    try std.testing.expectEqualStrings("a", publish.topic);
    try std.testing.expect(mqtt.topicAlias(publish.properties) == null);

    try std.testing.expectError(
        error.InvalidProperty,
        connection.writeClientSessionTransmission(.{ .publish = .{
            .topic = "must/remain/canonical",
            .payload = "x",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 10,
            .properties = &.{.{ .two_byte = .{
                .id = .topic_alias,
                .value = 1,
            } }},
            .message_expiry_interval = null,
        } }),
    );
    try std.testing.expect(connection.isUsable());
    try std.testing.expectEqual(
        @as(usize, 1),
        connection.outgoingTopicAliasCount(),
    );
}

test "MQTT Session PUBLISH alias allocation failure is pre-wire" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .client,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.close();

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        connection.writeClientSessionTransmission(.{ .publish = .{
            .topic = "allocation/failure",
            .payload = "payload",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 11,
            .properties = &.{},
            .message_expiry_interval = null,
        } }),
    );
    try std.testing.expect(connection.isUsable());
    try std.testing.expectEqual(
        @as(usize, 0),
        connection.outgoingTopicAliasCount(),
    );
    try std.testing.expectEqual(@as(usize, 0), connection.write_scratch.items.len);
    try std.testing.expectError(
        error.Timeout,
        peer.readPacketWithDeadline(
            allocator,
            4096,
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
}

test "MQTT transport write failure retires connection Topic Alias state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    const server_stream = try listener.accept(io);
    defer server_stream.close(io);

    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .peer_topic_alias_maximum = 1,
    };
    defer connection.close();
    const alias_property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = 1,
    } }};

    // A local full shutdown makes the first socket write fail deterministically.
    // Alias ownership was prepared before that attempt, but its wire outcome
    // is unknowable and therefore the connection may never use it again.
    try connection.transport.shutdown();
    const first_failed = blk: {
        _ = connection.writePublish(
            "retired/alias",
            "payload",
            .{ .properties = &alias_property },
        ) catch break :blk true;
        break :blk false;
    };
    try std.testing.expect(first_failed);
    try std.testing.expect(!connection.isUsable());
    try std.testing.expectEqualStrings(
        "retired/alias",
        connection.outgoingTopicAlias(1).?,
    );

    try std.testing.expectError(
        error.ConnectionClosed,
        connection.writePublish(
            "",
            "must not reach the wire",
            .{ .properties = &alias_property },
        ),
    );
    try std.testing.expectError(
        error.ConnectionClosed,
        connection.readPingReq(),
    );
}

test "MQTT connection supports aliases above the former fixed table" {
    const allocator = std.testing.allocator;
    const maximum_alias = std.math.maxInt(u16);
    var connection = Connection{
        .allocator = allocator,
        .transport = undefined,
        .protocol = .v5,
        .peer_topic_alias_maximum = maximum_alias,
        .incoming_topic_alias_maximum = maximum_alias,
    };
    defer connection.clearTopicAliases();

    const property = [_]mqtt.Property{.{ .two_byte = .{
        .id = .topic_alias,
        .value = maximum_alias,
    } }};
    try connection.validateOutgoingTopicAlias("large/alias", &property);
    try connection.prepareOutgoingTopicAliasCommit(
        "large/alias",
        &property,
    );
    try connection.validateOutgoingTopicAlias("", &property);

    var registered = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "incoming/large/alias",
        .packet_id = null,
        .properties = @constCast(&property),
        .payload = "first",
    };
    try connection.applyIncomingTopicAlias(&registered);
    var reused = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "",
        .packet_id = null,
        .properties = @constCast(&property),
        .payload = "second",
    };
    try connection.applyIncomingTopicAlias(&reused);
    try std.testing.expectEqualStrings("incoming/large/alias", reused.topic);
}

test "MQTT runtime advertises the configured topic alias maximum" {
    const allocator = std.testing.allocator;

    var properties: std.ArrayList(mqtt.Property) = .empty;
    defer properties.deinit(allocator);
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{}, 99);
    try std.testing.expectEqual(
        @as(?u16, 99),
        mqtt.topicAliasMaximum(properties.items),
    );

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{.{ .two_byte = .{
        .id = .topic_alias_maximum,
        .value = 8,
    } }}, 99);
    try std.testing.expectEqual(@as(usize, 0), properties.items.len);

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(
        &properties,
        allocator,
        &.{},
        std.math.maxInt(u16),
    );
    try std.testing.expectEqual(
        @as(?u16, std.math.maxInt(u16)),
        mqtt.topicAliasMaximum(properties.items),
    );

    properties.clearRetainingCapacity();
    try appendTopicAliasMaximumSetting(&properties, allocator, &.{}, 0);
    try std.testing.expectEqual(@as(usize, 0), properties.items.len);
}

test "MQTT connection enforces peer publish capabilities" {
    var connection = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .capabilities = .{
            .peer_maximum_qos = .at_most_once,
            .peer_retain_available = false,
        },
    };

    try std.testing.expectError(error.InvalidQoS, connection.publish("topic", "payload", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidProperty, connection.publish("topic", "payload", .{ .retain = true }));

    connection.capabilities.peer_retain_available = true;
    connection.capabilities.outgoing_retain_enabled = false;
    try std.testing.expectError(
        error.InvalidProperty,
        connection.publish("topic", "locally blocked", .{ .retain = true }),
    );
    try std.testing.expectError(
        error.InvalidProperty,
        connection.writeClientSessionTransmission(.{ .publish = .{
            .topic = "topic",
            .payload = "locally blocked",
            .qos = .at_most_once,
            .retain = true,
            .dup = false,
            .packet_id = 1,
            .properties = &.{},
            .message_expiry_interval = null,
        } }),
    );

    connection.capabilities.local_maximum_qos = .at_most_once;
    try std.testing.expectError(error.QoSNotSupported, connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_least_once,
        .retain = false,
        .topic = "qos/in",
        .packet_id = 7,
        .payload = "blocked",
    }));

    connection.capabilities.local_maximum_qos = .exactly_once;
    connection.capabilities.local_retain_available = false;
    try std.testing.expectError(error.RetainNotSupported, connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = true,
        .topic = "retained/in",
        .packet_id = null,
        .payload = "blocked",
    }));
    try connection.validateIncomingPublishCapabilities(.{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "normal/in",
        .packet_id = null,
        .payload = "ok",
    });
}

test "MQTT connection enforces PUBLISH subscription identifier direction" {
    const properties = [_]mqtt.Property{
        .{ .varint = .{
            .id = .subscription_identifier,
            .value = 7,
        } },
        .{ .two_byte = .{ .id = .topic_alias, .value = 1 } },
    };
    const publish_packet = mqtt.Publish{
        .dup = false,
        .qos = .at_most_once,
        .retain = false,
        .topic = "direction/topic",
        .packet_id = null,
        .properties = @constCast(&properties),
        .payload = "payload",
    };

    var server = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .server,
        .incoming_topic_alias_maximum = 1,
    };
    defer server.clearIncomingTopicAliases();
    try std.testing.expectError(
        error.InvalidProperty,
        server.validateIncomingPublishCapabilities(publish_packet),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.incomingTopicAliasCount(),
    );
    try std.testing.expectEqual(@as(u16, 0), server.incoming_inflight);
    try server.validatePublishPropertyDirection(properties[0..], .outgoing);

    var client = Connection{
        .allocator = std.testing.allocator,
        .transport = undefined,
        .protocol = .v5,
        .endpoint_role = .client,
    };
    try client.validateIncomingPublishCapabilities(publish_packet);
    try std.testing.expectError(
        error.InvalidProperty,
        client.writePublish(
            "direction/topic",
            "payload",
            .{ .properties = properties[0..] },
        ),
    );
    try std.testing.expectEqual(@as(u16, 0), client.outgoing_inflight);
    try std.testing.expectEqual(@as(usize, 0), client.write_scratch.items.len);
    try std.testing.expectError(
        error.InvalidProperty,
        client.writeClientSessionTransmission(.{ .publish = .{
            .topic = "direction/topic",
            .payload = "payload",
            .qos = .at_least_once,
            .retain = false,
            .dup = true,
            .packet_id = 1,
            .properties = properties[0..],
            .message_expiry_interval = null,
        } }),
    );
    try std.testing.expectEqual(@as(usize, 0), client.write_scratch.items.len);

    server.protocol = .v3_1_1;
    try server.validatePublishPropertyDirection(properties[0..], .incoming);
}

test "MQTT client applies configured peer publish defaults" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);

            var disconnect = try accepted.connection.readDisconnect();
            defer disconnect.deinit(server_ptr.allocator);
            try std.testing.expectEqual(@as(u8, 0), disconnect.disconnect.reason_code);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "peer-default-client",
        .limits = .{ .max_packet_size = 4096 },
        .peer_maximum_qos = .at_most_once,
        .peer_retain_available = false,
    });
    defer client.close();

    try std.testing.expectEqual(mqtt.QoS.at_most_once, client.peerMaximumQoS());
    try std.testing.expect(!client.peerRetainAvailable());
    try std.testing.expectError(error.InvalidQoS, client.publish("peer/defaults", "qos1", .{ .qos = .at_least_once }));
    try std.testing.expectError(error.InvalidProperty, client.publish("peer/defaults", "retain", .{ .retain = true }));
    try client.disconnect(0);

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT runtime surfaces negative publish acknowledgements" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var accepted = try server_ptr.accept(.{ .protocol = .v5 });
            defer accepted.deinit(server_ptr.allocator);

            var publish = try accepted.connection.readPublish();
            defer publish.deinit(server_ptr.allocator);
            try std.testing.expectEqualStrings("negative/topic", publish.publish.topic);
            try std.testing.expectEqualStrings("reject me", publish.publish.payload);
            try std.testing.expectEqual(mqtt.QoS.at_least_once, publish.publish.qos);
            try accepted.connection.writePubAckWithProperties(publish.publish.packet_id.?, 0x80, &.{
                .{ .utf8 = .{ .id = .reason_string, .value = "negative ack" } },
                .{ .utf8_pair = .{ .id = .user_property, .key = "trace", .value = "puback-negative" } },
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, server.address(), .{
        .protocol = .v5,
        .client_id = "negative-ack-client",
        .limits = .{ .max_packet_size = 4096 },
    });
    defer client.close();

    try std.testing.expectError(error.PublishRefused, client.publish("negative/topic", "reject me", .{ .qos = .at_least_once }));

    thread.join();
    if (shared.err) |err| return err;
}

test "MQTT async std.Io server handles concurrent clients" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .max_packet_size = 4096 });
    defer server.deinit();

    const Context = struct {
        pub fn handle(_: *@This(), accepted: *AcceptedClient) Error!void {
            if (std.mem.eql(u8, accepted.connect.connect.client_id, "mqtt-one")) {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(accepted.connection.allocator);
                if (!std.mem.eql(u8, publish.publish.payload, "one")) return error.UnexpectedPacket;
                try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
                return;
            }
            if (std.mem.eql(u8, accepted.connect.connect.client_id, "mqtt-two")) {
                var publish = try accepted.connection.readPublish();
                defer publish.deinit(accepted.connection.allocator);
                if (!std.mem.eql(u8, publish.publish.payload, "two")) return error.UnexpectedPacket;
                try accepted.connection.writePubAck(publish.publish.packet_id.?, 0);
                return;
            }
            return error.UnexpectedPacket;
        }
    };

    const Shared = struct {
        server: *Server,
        context: Context = .{},
        result: ?ConcurrentServeResult = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.result = shared.server.serveConcurrent(Context, &shared.context, Context.handle, 2, .{ .protocol = .v5 }) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const ClientTask = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        address: net.IpAddress,
        client_id: []const u8,
        payload: []const u8,
        err: ?anyerror = null,

        fn run(task: *@This()) void {
            runFallible(task) catch |err| {
                task.err = err;
            };
        }

        fn runFallible(task: *@This()) !void {
            var client = try Client.connect(task.allocator, task.io, task.address, .{
                .protocol = .v5,
                .client_id = task.client_id,
                .limits = .{ .max_packet_size = 4096 },
            });
            defer client.close();
            try client.publish("async/topic", task.payload, .{ .qos = .at_least_once });
        }
    };

    var clients = [_]ClientTask{
        .{ .allocator = allocator, .io = io, .address = server.address(), .client_id = "mqtt-one", .payload = "one" },
        .{ .allocator = allocator, .io = io, .address = server.address(), .client_id = "mqtt-two", .payload = "two" },
    };
    const client_one = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[0]});
    const client_two = try std.Thread.spawn(.{}, ClientTask.run, .{&clients[1]});

    client_one.join();
    client_two.join();
    server_thread.join();
    defer if (shared.result) |*result| result.deinit();

    if (clients[0].err) |err| return err;
    if (clients[1].err) |err| return err;
    if (shared.err) |err| return err;
    const result = shared.result.?;
    if (result.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), result.successCount());
}

test "MQTT broker event borrows caller storage for a complete TCP acknowledgement" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .keep_alive_seconds = 1,
    };
    defer connection.close();

    var encoded = [_]u8{ 0x40, 0x02, 0x00, 0x07 };
    try peer.writePacket(&encoded);
    var storage: [16]u8 = undefined;
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    connection.allocator = failing.allocator();
    defer connection.allocator = allocator;
    var event = try connection.readBrokerEventWithKeepAliveInto(&storage);
    defer event.deinit(failing.allocator());

    try std.testing.expect(event == .puback);
    try std.testing.expect(!event.puback.packet.owns_bytes);
    try std.testing.expectEqual(storage[0..].ptr, event.puback.packet.bytes.ptr);
    try std.testing.expectEqual(@as(u16, 7), event.puback.ack.packet_id);
    try std.testing.expect(!failing.has_induced_failure);
}

test "MQTT broker caller-output event transfers ownership and preserves output on error" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);
    const client_stream = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    var peer = PacketTransport.initTcp(io, try listener.accept(io));
    defer peer.close(allocator);
    var connection = Connection{
        .allocator = allocator,
        .transport = .initTcp(io, client_stream),
        .protocol = .v5,
        .endpoint_role = .server,
        .keep_alive_seconds = 1,
    };
    defer connection.close();

    var storage: [1]u8 = undefined;
    var event: BrokerEvent = undefined;
    var puback = [_]u8{ 0x40, 0x02, 0x00, 0x07 };
    try peer.writePacket(&puback);
    try connection.readBrokerEventWithKeepAliveIntoPrefixedOut(
        &storage,
        32,
        &event,
    );
    try std.testing.expect(event == .puback);
    try std.testing.expect(event.puback.packet.owns_bytes);
    try std.testing.expectEqual(@as(u16, 32), event.puback.packet.prefix_len);
    try std.testing.expect(event.puback.packet.prefixedAllocation() != null);
    try std.testing.expectEqual(@as(u16, 7), event.puback.ack.packet_id);
    event.deinit(allocator);

    var sentinel_bytes = [_]u8{ 0xc0, 0x00 };
    event = .{ .pingreq = .{
        .bytes = &sentinel_bytes,
        .fixed = .{
            .packet_type = .pingreq,
            .flags = 0,
            .remaining_len = 0,
            .header_len = 2,
        },
        .owns_bytes = false,
    } };
    var malformed_subscribe =
        [_]u8{ 0x82, 0x07, 0x00, 0x0f, 0x00, 0x00, 0x01, 'p', 0x40 };
    try peer.writePacket(&malformed_subscribe);
    try std.testing.expectError(
        error.MalformedSubscriptionOptions,
        connection.readBrokerEventWithKeepAliveIntoPrefixedOut(
            &storage,
            32,
            &event,
        ),
    );
    try std.testing.expect(event == .pingreq);
    try std.testing.expectEqual(sentinel_bytes[0..].ptr, event.pingreq.bytes.ptr);
    event.deinit(allocator);
}

test "MQTT serveUntil isolates CONNECT errors and reuses its worker" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_packet_size = 4096 },
    );
    defer server.deinit();

    const Observer = struct {
        io: std.Io,
        observed: std.Io.Event = .unset,
        count: std.atomic.Value(usize) = .init(0),
        stage: ServeErrorStage = .connection,

        fn observe(context_ptr: *anyopaque, event: ServeErrorEvent) void {
            const self: *@This() = @ptrCast(@alignCast(context_ptr));
            self.stage = event.stage;
            _ = self.count.fetchAdd(1, .release);
            self.observed.set(self.io);
        }
    };
    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        handled: std.atomic.Value(usize) = .init(0),

        fn handle(
            self: *@This(),
            accepted: *AcceptedClient,
        ) Error!void {
            var event = try accepted.connection.readBrokerEvent();
            defer event.deinit(accepted.connection.allocator);
            if (event != .pingreq) return error.UnexpectedPacket;
            try accepted.connection.writePingResp();
            _ = self.handled.fetchAdd(1, .release);
            if (std.mem.eql(
                u8,
                accepted.connect.connect.client_id,
                "mqtt-supervisor-stop",
            )) {
                self.shutdown.set(self.io);
            }
        }
    };
    const Shared = struct {
        server: *Server,
        shutdown: std.Io.Event = .unset,
        observer: Observer,
        context: Context,
        err: ?anyerror = null,

        fn init(server_ptr: *Server, io_value: std.Io) @This() {
            var shared: @This() = undefined;
            shared.server = server_ptr;
            shared.shutdown = .unset;
            shared.observer = .{ .io = io_value };
            shared.context = .{
                .io = io_value,
                .shutdown = &shared.shutdown,
            };
            shared.err = null;
            return shared;
        }

        fn run(self: *@This()) void {
            self.context.shutdown = &self.shutdown;
            self.server.serveUntil(
                Context,
                &self.context,
                Context.handle,
                1,
                .{ .protocol = .v5 },
                .{
                    .shutdown = &self.shutdown,
                    .error_observer = .{
                        .context = &self.observer,
                        .observe = Observer.observe,
                    },
                },
            ) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared.init(&server, io);
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.shutdown.set(io);
        server_thread.join();
    };

    const malformed = try server.address().connect(io, .{ .mode = .stream });
    const malformed_bytes = [_]u8{ 0xc0, 0x00 };
    var malformed_writer = malformed.writer(io, &.{});
    try malformed_writer.interface.writeAll(&malformed_bytes);
    malformed.close(io);
    try shared.observer.observed.wait(io);
    try std.testing.expectEqual(ServeErrorStage.accept, shared.observer.stage);

    for ([_][]const u8{ "mqtt-supervisor-one", "mqtt-supervisor-stop" }) |client_id| {
        var client = try Client.connect(
            allocator,
            io,
            server.address(),
            .{ .protocol = .v5, .client_id = client_id },
        );
        defer client.close();
        try client.ping();
    }

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(
        @as(usize, 2),
        shared.context.handled.load(.acquire),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        shared.observer.count.load(.acquire),
    );
}

test {
    _ = broker_keep_alive;
    _ = @import("receive/event_allocation_tests.zig");
    _ = @import("../reconnect/replay_deadline_tests.zig");
    _ = @import("ping_write_tests.zig");
    _ = @import("receive/alias_ownership_tests.zig");
    _ = @import("receive/alias_transport_tests.zig");
    _ = @import("../reconnect/flush_deadline_tests.zig");
    _ = @import("../reconnect/identifier_tests.zig");
    _ = @import("../reconnect/identifier_resume_tests.zig");
    _ = @import("../session/identifier_tests.zig");
    _ = @import("transport/parts_deadline_tests.zig");
    _ = @import("acknowledgement/deadline_tests.zig");
    _ = @import("acknowledgement/output_deadline_tests.zig");
    _ = @import("diagnostic/receive_deadline_tests.zig");
    _ = @import("diagnostic/reauth_deadline_tests.zig");
    _ = @import("diagnostic/connect_deadline_tests.zig");
    _ = @import("diagnostic/connect_callback_tests.zig");
    _ = @import("diagnostic/connect_retry_tests.zig");
    _ = @import("disconnect/deadline_tests.zig");
    _ = @import("acknowledgement/exchange_tests.zig");
    _ = @import("acknowledgement/control/tests.zig");
    _ = @import("acknowledgement/control/exchange_tests.zig");
    _ = @import("acknowledgement/control/qos_tests.zig");
    _ = @import("acknowledgement/identifier_tests.zig");
    _ = @import("acknowledgement/reconnect_deadline_tests.zig");
    _ = @import("acknowledgement/subscribe_tests.zig");
    _ = @import("acknowledgement/reconnect_tests.zig");
    _ = @import("acknowledgement/byte_limit_tests.zig");
    _ = @import("acknowledgement/publish_tests.zig");
    _ = @import("acknowledgement/apply_tests.zig");
    _ = @import("acknowledgement/publish_deadline_tests.zig");
    _ = @import("acceptance_tests.zig");
    _ = @import("disconnect_tests.zig");
    _ = @import("receive/termination_tests.zig");
    _ = @import("receive/event_termination_tests.zig");
}

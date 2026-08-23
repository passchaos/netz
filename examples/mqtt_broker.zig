const std = @import("std");
const netz = @import("netz");

const Config = struct {
    bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(1883) },
    connections: usize = 16,
    max_queued_deliveries: usize = 1024,
    max_session_queued_payload_bytes: usize = 0,
    max_session_inflight_payload_bytes: usize = 0,
    max_outgoing_inflight: u16 = 64,
    max_packet_size: usize = 16 * 1024 * 1024,
    max_payload_size: usize = 0,
    maximum_qos: ?netz.mqtt.QoS = null,
    retain_available: bool = true,
    topic_alias_maximum: u16 = 16,
    server_keep_alive_seconds: ?u16 = null,
    maximum_keep_alive_seconds: ?u16 = null,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
    allow_zero_length_client_id: bool = true,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    deny_publish_topic: ?[]const u8 = null,
    deny_subscribe_filter: ?[]const u8 = null,
    deny_unsubscribe_filter: ?[]const u8 = null,
    deny_delivery_topic: ?[]const u8 = null,
    upgrade_outgoing_qos: bool = false,
    queue_qos0_messages: bool = false,
    persistence_path: ?[]const u8 = null,
    autosave_interval_seconds: ?u32 = null,
    restore: bool = true,
    ignore_connection_errors: bool = false,
};

pub fn main(init: std.process.Init) !void {
    // This long-lived broker repeatedly transfers small packet/session
    // allocations between I/O workers. The SMP allocator's per-thread caches
    // retain a separate working set for every connection task; libc's shared
    // arenas keep the same workload throughput while materially reducing RSS.
    // Library users still choose the allocator passed to Broker.listen.
    const allocator = std.heap.c_allocator;
    const config = try parseArgs(init);
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const Credentials = struct {
        username: []const u8,
        password: []const u8,

        fn authorize(
            context: *anyopaque,
            connect: netz.mqtt.Connect,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const username = connect.username orelse return false;
            const password = connect.password orelse return false;
            // Length is public MQTT framing metadata; compare equal-length
            // credential bytes without leaking which field first differed.
            if (username.len != self.username.len or
                password.len != self.password.len)
            {
                return false;
            }
            const username_matches = timingSafeEqlBytes(
                username,
                self.username,
            );
            const password_matches = timingSafeEqlBytes(
                password,
                self.password,
            );
            return username_matches and password_matches;
        }
    };
    var credentials: Credentials = undefined;
    const authorization: ?netz.mqtt.broker.ConnectAuthorizationHandler =
        if (config.username) |username| .{
            .context = blk: {
                credentials = .{
                    .username = username,
                    .password = config.password.?,
                };
                break :blk &credentials;
            },
            .authorize = Credentials.authorize,
        } else null;
    const AccessPolicy = struct {
        deny_publish_topic: ?[]const u8,
        deny_subscribe_filter: ?[]const u8,
        deny_unsubscribe_filter: ?[]const u8,
        deny_delivery_topic: ?[]const u8,

        fn authorizePublish(
            context: *anyopaque,
            _: netz.mqtt.Connect,
            publish: netz.mqtt.Publish,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const denied = self.deny_publish_topic orelse return true;
            return !std.mem.eql(u8, publish.topic, denied);
        }

        fn authorizeSubscribe(
            context: *anyopaque,
            _: netz.mqtt.Connect,
            subscription: netz.mqtt.Subscription,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const denied = self.deny_subscribe_filter orelse return true;
            return !std.mem.eql(u8, subscription.topic_filter, denied);
        }

        fn authorizeUnsubscribe(
            context: *anyopaque,
            _: netz.mqtt.Connect,
            topic_filter: []const u8,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const denied = self.deny_unsubscribe_filter orelse return true;
            return !std.mem.eql(u8, topic_filter, denied);
        }

        fn authorizeDelivery(
            context: *anyopaque,
            delivery: netz.mqtt.broker.DeliveryAuthorization,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const denied = self.deny_delivery_topic orelse return true;
            return !std.mem.eql(u8, delivery.topic, denied);
        }
    };
    var access_policy = AccessPolicy{
        .deny_publish_topic = config.deny_publish_topic,
        .deny_subscribe_filter = config.deny_subscribe_filter,
        .deny_unsubscribe_filter = config.deny_unsubscribe_filter,
        .deny_delivery_topic = config.deny_delivery_topic,
    };
    const access_control: ?netz.mqtt.broker.AccessControlHandler =
        if (config.deny_publish_topic != null or
        config.deny_subscribe_filter != null or
        config.deny_unsubscribe_filter != null or
        config.deny_delivery_topic != null) .{
            .context = &access_policy,
            .authorize_publish = AccessPolicy.authorizePublish,
            .authorize_subscribe = AccessPolicy.authorizeSubscribe,
            .authorize_unsubscribe = AccessPolicy.authorizeUnsubscribe,
            .authorize_delivery = AccessPolicy.authorizeDelivery,
        } else null;

    var broker = try netz.mqtt.broker.Broker.listen(
        allocator,
        io,
        config.bind,
        .{
            .limits = .{
                .max_connections = config.connections,
                .max_queued_deliveries_per_connection = config.max_queued_deliveries,
                .max_payload_size = config.max_payload_size,
                .runtime = .{ .max_packet_size = config.max_packet_size },
            },
            .accept = .{
                .max_outgoing_inflight = config.max_outgoing_inflight,
                .maximum_qos = config.maximum_qos,
                .retain_available = config.retain_available,
                .topic_alias_maximum = config.topic_alias_maximum,
                .server_keep_alive_seconds = config.server_keep_alive_seconds,
                .maximum_keep_alive_seconds = config.maximum_keep_alive_seconds,
                .allow_zero_length_client_id = config.allow_zero_length_client_id,
                .wildcard_subscription_available = config.wildcard_subscription_available,
                .subscription_identifier_available = config.subscription_identifier_available,
                .shared_subscription_available = config.shared_subscription_available,
            },
            .upgrade_outgoing_qos = config.upgrade_outgoing_qos,
            .queue_qos0_messages = config.queue_qos0_messages,
            .connect_authorization = authorization,
            .access_control = access_control,
            .session = .{
                .max_queued_payload_bytes_per_session = config.max_session_queued_payload_bytes,
                .max_inflight_payload_bytes_per_session = config.max_session_inflight_payload_bytes,
            },
        },
    );
    defer broker.deinit();
    if (config.persistence_path) |path| {
        if (config.restore) {
            broker.restoreSnapshot(std.Io.Dir.cwd(), path) catch |err| {
                if (err != error.SnapshotNotFound) return err;
            };
        }
    }

    std.debug.print(
        "netz MQTT 3.1.1/5 broker listening on {f} for {d} clients\n",
        .{ broker.address(), config.connections },
    );
    if (config.autosave_interval_seconds) |seconds| {
        const path = config.persistence_path orelse
            return error.InvalidArgument;
        const interval = std.Io.Clock.Duration{
            .raw = .fromSeconds(seconds),
            .clock = .awake,
        };
        const Result = union(enum) {
            serve: ?anyerror,
            timer: std.Io.Cancelable!void,
        };
        var result_buffer: [2]Result = undefined;
        var select: std.Io.Select(Result) = .init(io, &result_buffer);
        defer select.cancelDiscard();
        try select.concurrent(
            .serve,
            serveBrokerResult,
            .{
                &broker,
                config.connections,
                config.ignore_connection_errors,
            },
        );
        try select.concurrent(.timer, waitAutosaveInterval, .{ io, interval });
        while (true) {
            switch (try select.await()) {
                .serve => |maybe_err| {
                    // Stop the outstanding timer before returning. Otherwise
                    // defer-based cancellation would run only after the final
                    // snapshot below and could race that quiescent write.
                    select.cancelDiscard();
                    if (maybe_err) |err| return err;
                    break;
                },
                .timer => |timer_result| {
                    try timer_result;
                    broker.saveLiveSnapshot(std.Io.Dir.cwd(), path) catch |save_err|
                        switch (save_err) {
                            // A CONNECT between Session registration and
                            // CONNACK attachment is intentionally not
                            // checkpointable. Retry at the next interval.
                            error.SnapshotBusy => {},
                            else => return save_err,
                        };
                    try select.concurrent(
                        .timer,
                        waitAutosaveInterval,
                        .{ io, interval },
                    );
                },
            }
        }
    } else {
        try serveBroker(
            &broker,
            config.connections,
            config.ignore_connection_errors,
        );
    }
    if (config.persistence_path) |path| {
        try broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }
}

fn parseArgs(
    init: std.process.Init,
) !Config {
    var config: Config = .{};
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--bind=")) {
            config.bind = try std.Io.net.IpAddress.parseLiteral(
                arg["--bind=".len..],
            );
            if (config.bind.getPort() == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--connections=",
        )) {
            config.connections = try parsePositiveUsize(
                arg["--connections=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-queued-deliveries=",
        )) {
            config.max_queued_deliveries = try parsePositiveUsize(
                arg["--max-queued-deliveries=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-outgoing-inflight=",
        )) {
            config.max_outgoing_inflight = try std.fmt.parseInt(
                u16,
                arg["--max-outgoing-inflight=".len..],
                10,
            );
            if (config.max_outgoing_inflight == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-session-queued-payload-bytes=",
        )) {
            config.max_session_queued_payload_bytes = try std.fmt.parseInt(
                usize,
                arg["--max-session-queued-payload-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-session-inflight-payload-bytes=",
        )) {
            config.max_session_inflight_payload_bytes = try std.fmt.parseInt(
                usize,
                arg["--max-session-inflight-payload-bytes=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-packet-size=",
        )) {
            config.max_packet_size = try parsePositiveUsize(
                arg["--max-packet-size=".len..],
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--max-payload-size=",
        )) {
            config.max_payload_size = try std.fmt.parseInt(
                usize,
                arg["--max-payload-size=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--maximum-qos=",
        )) {
            config.maximum_qos = switch (try std.fmt.parseInt(
                u2,
                arg["--maximum-qos=".len..],
                10,
            )) {
                0 => .at_most_once,
                1 => .at_least_once,
                2 => .exactly_once,
                else => return error.InvalidArgument,
            };
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--topic-alias-maximum=",
        )) {
            config.topic_alias_maximum = try std.fmt.parseInt(
                u16,
                arg["--topic-alias-maximum=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--server-keep-alive=",
        )) {
            config.server_keep_alive_seconds = try std.fmt.parseInt(
                u16,
                arg["--server-keep-alive=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--maximum-keep-alive=",
        )) {
            config.maximum_keep_alive_seconds = try std.fmt.parseInt(
                u16,
                arg["--maximum-keep-alive=".len..],
                10,
            );
            if (config.maximum_keep_alive_seconds.? == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.eql(u8, arg, "--no-retain")) {
            config.retain_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-wildcard-subscriptions",
        )) {
            config.wildcard_subscription_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-subscription-identifiers",
        )) {
            config.subscription_identifier_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-shared-subscriptions",
        )) {
            config.shared_subscription_available = false;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-zero-length-client-id",
        )) {
            config.allow_zero_length_client_id = false;
        } else if (std.mem.startsWith(u8, arg, "--username=")) {
            const username = arg["--username=".len..];
            if (username.len == 0 or config.username != null) {
                return error.InvalidArgument;
            }
            config.username = username;
        } else if (std.mem.startsWith(u8, arg, "--password=")) {
            const password = arg["--password=".len..];
            if (password.len == 0 or config.password != null) {
                return error.InvalidArgument;
            }
            config.password = password;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--deny-publish-topic=",
        )) {
            const topic = arg["--deny-publish-topic=".len..];
            if (topic.len == 0 or config.deny_publish_topic != null) {
                return error.InvalidArgument;
            }
            try netz.mqtt.validateTopicName(topic);
            config.deny_publish_topic = topic;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--deny-subscribe-filter=",
        )) {
            const filter = arg["--deny-subscribe-filter=".len..];
            if (filter.len == 0 or config.deny_subscribe_filter != null) {
                return error.InvalidArgument;
            }
            try netz.mqtt.validateTopicFilter(filter);
            config.deny_subscribe_filter = filter;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--deny-unsubscribe-filter=",
        )) {
            const filter = arg["--deny-unsubscribe-filter=".len..];
            if (filter.len == 0 or config.deny_unsubscribe_filter != null) {
                return error.InvalidArgument;
            }
            try netz.mqtt.validateTopicFilter(filter);
            config.deny_unsubscribe_filter = filter;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--deny-delivery-topic=",
        )) {
            const topic = arg["--deny-delivery-topic=".len..];
            if (topic.len == 0 or config.deny_delivery_topic != null) {
                return error.InvalidArgument;
            }
            try netz.mqtt.validateTopicName(topic);
            config.deny_delivery_topic = topic;
        } else if (std.mem.eql(
            u8,
            arg,
            "--upgrade-outgoing-qos",
        )) {
            config.upgrade_outgoing_qos = true;
        } else if (std.mem.eql(
            u8,
            arg,
            "--queue-qos0-messages",
        )) {
            config.queue_qos0_messages = true;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--persistence=",
        )) {
            const path = arg["--persistence=".len..];
            if (path.len == 0) return error.InvalidArgument;
            config.persistence_path = path;
        } else if (std.mem.eql(u8, arg, "--no-restore")) {
            config.restore = false;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--autosave-interval-seconds=",
        )) {
            config.autosave_interval_seconds = try std.fmt.parseInt(
                u32,
                arg["--autosave-interval-seconds=".len..],
                10,
            );
            if (config.autosave_interval_seconds.? == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.eql(u8, arg, "--ignore-connection-errors")) {
            config.ignore_connection_errors = true;
        } else {
            return error.InvalidArgument;
        }
    }
    if (config.autosave_interval_seconds != null and
        config.persistence_path == null)
    {
        return error.InvalidArgument;
    }
    if ((config.username == null) != (config.password == null)) {
        return error.InvalidArgument;
    }
    return config;
}

fn timingSafeEqlBytes(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |lhs, rhs| difference |= lhs ^ rhs;
    return difference == 0;
}

fn serveBroker(
    broker: *netz.mqtt.broker.Broker,
    connections: usize,
    ignore_connection_errors: bool,
) !void {
    if (ignore_connection_errors) {
        // Conformance/fuzz harnesses deliberately open malformed connections.
        // Serve one finite slot at a time so an expected protocol rejection
        // does not terminate the process before later valid-vector probes.
        for (0..connections) |_| broker.serve(1) catch |err| switch (err) {
            // Autosave uses this helper as a cancelable Select task. Never
            // swallow its shutdown signal while ignoring peer errors.
            error.Canceled => return err,
            else => {},
        };
    } else {
        try broker.serve(connections);
    }
}

fn serveBrokerResult(
    broker: *netz.mqtt.broker.Broker,
    connections: usize,
    ignore_connection_errors: bool,
) ?anyerror {
    serveBroker(broker, connections, ignore_connection_errors) catch |err|
        return err;
    return null;
}

fn waitAutosaveInterval(
    io: std.Io,
    interval: std.Io.Clock.Duration,
) std.Io.Cancelable!void {
    try interval.sleep(io);
}

fn parsePositiveUsize(raw: []const u8) !usize {
    const value = try std.fmt.parseInt(usize, raw, 10);
    if (value == 0) return error.InvalidArgument;
    return value;
}

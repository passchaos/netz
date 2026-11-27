const std = @import("std");
const netz = @import("netz");
const broker_config_runner = @import("mqtt_broker_config.zig");
const CountingAllocator = @import("support").counting_allocator
    .CountingAllocator;
const InteropAuthentication = @import("support").mqtt_interop_authentication.Policy;

const Config = struct {
    bind: std.Io.net.IpAddress = .{ .ip4 = .loopback(1883) },
    executors: u8 = 1,
    connections: usize = 16,
    max_queued_deliveries: usize = 1024,
    max_pending_incoming_qos2: usize = 4096,
    max_session_queued_payload_bytes: usize = 0,
    max_session_inflight_payload_bytes: usize = 0,
    max_outgoing_inflight: u16 = 64,
    strict_utf8: bool = false,
    mqtt31_session_present_extension: bool = false,
    connect_timeout_ms: ?u32 = null,
    max_packet_size: usize = 16 * 1024 * 1024,
    max_payload_size: usize = 0,
    proxy_protocol: ?netz.mqtt.proxy_protocol.Version = null,
    proxy_v2_require_tls: bool = false,
    proxy_v2_require_client_certificate: bool = false,
    proxy_header_timeout_ms: ?u32 = null,
    maximum_qos: ?netz.mqtt.QoS = null,
    retain_available: bool = true,
    topic_alias_maximum: u16 = 16,
    server_keep_alive_seconds: ?u16 = null,
    maximum_keep_alive_seconds: ?u16 = null,
    wildcard_subscription_available: bool = true,
    subscription_identifier_available: bool = true,
    shared_subscription_available: bool = true,
    allow_zero_length_client_id: bool = true,
    response_information: ?[]const u8 = null,
    connack_reason: u8 = 0,
    server_reference: ?[]const u8 = null,
    problem_reason_string: ?[]const u8 = null,
    problem_user_property: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    interop_test_authentication: bool = false,
    interop_authenticated_username_acl: bool = false,
    deny_publish_topic: ?[]const u8 = null,
    deny_subscribe_filter: ?[]const u8 = null,
    deny_unsubscribe_filter: ?[]const u8 = null,
    deny_delivery_topic: ?[]const u8 = null,
    deny_will_topic: ?[]const u8 = null,
    deny_retained_source_client_id: ?[]const u8 = null,
    check_retain_source: bool = true,
    upgrade_outgoing_qos: bool = false,
    queue_qos0_messages: bool = false,
    use_username_as_client_id: bool = false,
    persistent_session_expiry_seconds: ?u32 = null,
    system_interval_seconds: ?u32 = null,
    persistence_path: ?[]const u8 = null,
    commit_log_path: ?[]const u8 = null,
    autosave_interval_seconds: ?u32 = null,
    autosave_change_count: ?usize = null,
    restore: bool = true,
    ignore_connection_errors: bool = false,
    allocator_stats: bool = false,
    allocator_stats_qos: ?u2 = null,
    allocator_stats_session_expiry_seconds: ?u32 = null,
};

const ConfiguredErrorTrace = struct {
    var context: u8 = 0;
    var emitted: std.atomic.Value(usize) = .init(0);

    fn observe(_: *anyopaque, event: netz.mqtt.broker.ListenerErrorEvent) void {
        if (emitted.fetchAdd(1, .monotonic) >= 32) return;
        std.debug.print("MQTT listener event: listener={d} stage={s} err={s}\n", .{
            event.listener_index,
            @tagName(event.stage),
            @errorName(event.err),
        });
    }

    fn observeEnd(_: *anyopaque, event: netz.mqtt.broker.ListenerConnectionEndEvent) void {
        if (emitted.fetchAdd(1, .monotonic) >= 32) return;
        std.debug.print("MQTT connection end: listener={d} client={s} read={s} writer={s} graceful={} administrative={} keep_alive_timeout={}\n", .{
            event.listener_index,
            event.client_id,
            if (event.read_error) |err| @errorName(err) else "none",
            if (event.writer_error) |err| @errorName(err) else "none",
            event.graceful_disconnect,
            event.administrative_disconnect,
            event.keep_alive_timed_out,
        });
    }
};

pub fn main(init: std.process.Init) !void {
    // This long-lived broker repeatedly transfers small packet/session
    // allocations between I/O workers. The SMP allocator's per-thread caches
    // retain a separate working set for every connection task; libc's shared
    // arenas keep the same workload throughput while materially reducing RSS.
    // Library users still choose the allocator passed to Broker.listen.
    const base_allocator = std.heap.c_allocator;
    const config_path = try parseConfigPath(init);
    if (config_path) |path| {
        var backend = try netz.runtime.Backend.init(base_allocator);
        defer backend.deinit();
        const io = backend.io();
        broker_config_runner.run(base_allocator, io, path, .{
            .finite_test = if (init.environ_map.get(
                "NETZ_MQTT_CONFIG_FINITE_TEST",
            )) |value|
                std.mem.eql(u8, value, "1")
            else
                false,
            .error_observer = if (init.environ_map.get("NETZ_MQTT_CONFIG_TRACE_ERRORS")) |value|
                if (std.mem.eql(u8, value, "1")) .{
                    .context = &ConfiguredErrorTrace.context,
                    .observe = ConfiguredErrorTrace.observe,
                } else null
            else
                null,
            .connection_end_observer = if (init.environ_map.get("NETZ_MQTT_CONFIG_TRACE_ERRORS")) |value|
                if (std.mem.eql(u8, value, "1")) .{ .context = &ConfiguredErrorTrace.context, .observe = ConfiguredErrorTrace.observeEnd } else null
            else
                null,
        }) catch |err| switch (err) {
            error.ConfigFileNotFound => {
                std.debug.print(
                    "Error: Unable to open config file '{s}'.\n",
                    .{path},
                );
                std.process.exit(3);
            },
            else => return err,
        };
        return;
    }
    const config = try parseArgs(init);
    var backend = try netz.runtime.Backend.initWithExecutors(
        base_allocator,
        config.executors,
    );
    defer backend.deinit();
    const io = backend.io();
    var counting = CountingAllocator.init(base_allocator);
    const allocator = if (config.allocator_stats)
        counting.allocator()
    else
        base_allocator;
    var interop_authentication = InteropAuthentication{
        .allocator = allocator,
    };

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
        deny_will_topic: ?[]const u8,
        deny_retained_source_client_id: ?[]const u8,

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

        fn authorizeWill(
            context: *anyopaque,
            publication: netz.mqtt.broker.WillAuthorization,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const denied = self.deny_will_topic orelse return true;
            return !std.mem.eql(u8, publication.topic, denied);
        }

        fn authorizeRetainedSource(
            context: *anyopaque,
            publication: netz.mqtt.broker.RetainedSourceAuthorization,
        ) bool {
            const self: *@This() = @ptrCast(@alignCast(context));
            const denied = self.deny_retained_source_client_id orelse
                return true;
            return !std.mem.eql(u8, publication.client_id, denied);
        }
    };
    var access_policy = AccessPolicy{
        .deny_publish_topic = config.deny_publish_topic,
        .deny_subscribe_filter = config.deny_subscribe_filter,
        .deny_unsubscribe_filter = config.deny_unsubscribe_filter,
        .deny_delivery_topic = config.deny_delivery_topic,
        .deny_will_topic = config.deny_will_topic,
        .deny_retained_source_client_id = config.deny_retained_source_client_id,
    };
    const access_control: ?netz.mqtt.broker.AccessControlHandler =
        if (config.deny_publish_topic != null or
        config.deny_subscribe_filter != null or
        config.deny_unsubscribe_filter != null or
        config.deny_delivery_topic != null or
        config.deny_will_topic != null or
        config.deny_retained_source_client_id != null) .{
            .context = &access_policy,
            .authorize_publish = AccessPolicy.authorizePublish,
            .authorize_subscribe = AccessPolicy.authorizeSubscribe,
            .authorize_unsubscribe = AccessPolicy.authorizeUnsubscribe,
            .authorize_delivery = AccessPolicy.authorizeDelivery,
            .authorize_will = AccessPolicy.authorizeWill,
            .authorize_retained_source = AccessPolicy.authorizeRetainedSource,
        } else null;

    var problem_information: [2]netz.mqtt.Property = undefined;
    var problem_information_count: usize = 0;
    if (config.problem_reason_string) |reason| {
        problem_information[problem_information_count] = .{ .utf8 = .{
            .id = .reason_string,
            .value = reason,
        } };
        problem_information_count += 1;
    }
    if (config.problem_user_property) |value| {
        problem_information[problem_information_count] = .{
            .utf8_pair = .{
                .id = .user_property,
                .key = "diagnostic",
                .value = value,
            },
        };
        problem_information_count += 1;
    }

    var broker = try netz.mqtt.broker.Broker.listen(
        allocator,
        io,
        config.bind,
        .{
            .limits = .{
                .max_connections = config.connections,
                .max_queued_deliveries_per_connection = config.max_queued_deliveries,
                .max_pending_incoming_qos2 = config.max_pending_incoming_qos2,
                .max_payload_size = config.max_payload_size,
                .runtime = .{
                    .max_packet_size = config.max_packet_size,
                    .tcp_nodelay = true,
                    .proxy_protocol = config.proxy_protocol,
                    .proxy_v2_require_tls = config.proxy_v2_require_tls,
                    .proxy_v2_require_client_certificate = config.proxy_v2_require_client_certificate,
                    .proxy_header_timeout = if (config.proxy_header_timeout_ms) |milliseconds|
                        .fromMilliseconds(milliseconds)
                    else
                        null,
                },
            },
            .accept = .{
                .strict_utf8 = config.strict_utf8,
                .v3_1_connack_mode = if (config.mqtt31_session_present_extension)
                    .mosquitto
                else
                    .strict,
                .reason_code = config.connack_reason,
                .server_reference = config.server_reference,
                .connect_timeout = if (config.connect_timeout_ms) |milliseconds|
                    .fromMilliseconds(milliseconds)
                else
                    null,
                .max_outgoing_inflight = config.max_outgoing_inflight,
                .maximum_qos = config.maximum_qos,
                .retain_available = config.retain_available,
                .topic_alias_maximum = config.topic_alias_maximum,
                .server_keep_alive_seconds = config.server_keep_alive_seconds,
                .maximum_keep_alive_seconds = config.maximum_keep_alive_seconds,
                .allow_zero_length_client_id = config.allow_zero_length_client_id,
                .response_information = config.response_information,
                .wildcard_subscription_available = config.wildcard_subscription_available,
                .subscription_identifier_available = config.subscription_identifier_available,
                .shared_subscription_available = config.shared_subscription_available,
            },
            .upgrade_outgoing_qos = config.upgrade_outgoing_qos,
            .queue_qos0_messages = config.queue_qos0_messages,
            .check_retain_source = config.check_retain_source,
            .persistent_session_expiry_seconds = config.persistent_session_expiry_seconds,
            .system_stats_interval = if (config.system_interval_seconds) |seconds|
                .fromSeconds(seconds)
            else
                null,
            .persistent_change_autosave = if (config.autosave_change_count) |max_changes| .{
                .dir = std.Io.Dir.cwd(),
                .sub_path = config.persistence_path.?,
                .max_changes = max_changes,
            } else null,
            .connect_authorization = authorization,
            .authentication = if (config.interop_test_authentication)
                interop_authentication.handler()
            else
                null,
            .access_control = if (config.interop_authenticated_username_acl)
                interop_authentication.usernameAccessControl()
            else
                access_control,
            .problem_information = problem_information[0..problem_information_count],
            .session = .{
                .max_queued_payload_bytes_per_session = config.max_session_queued_payload_bytes,
                .max_inflight_payload_bytes_per_session = config.max_session_inflight_payload_bytes,
            },
        },
    );
    errdefer broker.deinit();
    if (config.commit_log_path) |path| {
        broker.restoreCommitLog(std.Io.Dir.cwd(), path, .{}) catch |err|
            switch (err) {
                error.CommitLogNotFound => try broker.createCommitLog(
                    std.Io.Dir.cwd(),
                    path,
                    .{},
                ),
                else => return err,
            };
    } else if (config.persistence_path) |path| {
        if (config.restore) {
            broker.restoreSnapshot(std.Io.Dir.cwd(), path) catch |err| {
                if (err != error.SnapshotNotFound) return err;
            };
        }
    }

    std.debug.print(
        "netz MQTT 3.1/3.1.1/5 broker listening on {f} for {d} clients " ++
            "server_io=zio-std-io\n",
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
                config.use_username_as_client_id,
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
            config.use_username_as_client_id,
        );
    }
    if (config.commit_log_path != null) {
        // Each protocol-visible durable transition is already fsynced by the
        // broker journal. Avoid an unrelated final snapshot format when the
        // process is configured exclusively for incremental recovery.
    } else if (config.persistence_path) |path| {
        try broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }
    broker.deinit();
    if (config.allocator_stats) {
        const stack_metrics = backend.stackMetrics();
        std.debug.print(
            "record=runtime-stack implementation=netz endpoint_role=server " ++
                "configured_maximum_bytes={d} " ++
                "configured_initial_committed_bytes={d} active_stacks={d} " ++
                "retained_stacks={d} peak_active_stacks={d} " ++
                "peak_committed_bytes_per_stack={d} " ++
                "reserved_virtual_bytes={d} complete=true\n",
            .{
                stack_metrics.configured_maximum_bytes,
                stack_metrics.configured_initial_committed_bytes,
                stack_metrics.active_stacks,
                stack_metrics.retained_stacks,
                stack_metrics.peak_active_stacks,
                stack_metrics.peak_committed_bytes_per_stack,
                stack_metrics.reserved_virtual_bytes,
            },
        );
        const snapshot = counting.snapshot();
        if (snapshot.current_bytes != 0) return error.MemoryLeak;
        std.debug.print(
            "record=allocator implementation=netz endpoint_role=server " ++
                "protocol=mqtt5 transport=tcp mode=qos{d}-fanout " ++
                "timing_usable=false allocator_scope=broker-explicit " ++
                "connection_scope=persistent client_tcp_nodelay=true " ++
                "server_tcp_nodelay=true session_expiry_seconds={d} " ++
                "configured_connections={d} alloc_count={d} " ++
                "free_count={d} resize_count={d} remap_count={d} " ++
                "total_allocated_bytes={d} total_freed_bytes={d} " ++
                "live_bytes={d} peak_live_bytes={d} " ++
                "alloc_le_64={d} alloc_le_256={d} alloc_le_1024={d} " ++
                "alloc_le_4096={d} alloc_le_16384={d} " ++
                "alloc_le_65536={d} alloc_gt_65536={d} complete=true\n",
            .{
                config.allocator_stats_qos orelse 1,
                config.allocator_stats_session_expiry_seconds orelse 0,
                config.connections,
                snapshot.alloc_count,
                snapshot.free_count,
                snapshot.resize_count,
                snapshot.remap_count,
                snapshot.total_allocated,
                snapshot.total_freed,
                snapshot.current_bytes,
                snapshot.peak_bytes,
                snapshot.alloc_buckets[0],
                snapshot.alloc_buckets[1],
                snapshot.alloc_buckets[2],
                snapshot.alloc_buckets[3],
                snapshot.alloc_buckets[4],
                snapshot.alloc_buckets[5],
                snapshot.alloc_buckets[6],
            },
        );
        for (snapshot.exact_sizes[0..snapshot.exact_size_len]) |entry| {
            if (entry.size <= 64 * 1024) continue;
            std.debug.print(
                "record=allocator-large implementation=netz " ++
                    "endpoint_role=server size_bytes={d} count={d} " ++
                    "total_bytes={d} complete=true\n",
                .{
                    entry.size,
                    entry.count,
                    entry.size *| entry.count,
                },
            );
        }
    }
}

fn parseConfigPath(init: std.process.Init) !?[]const u8 {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var path: ?[]const u8 = null;
    for (args[1..]) |arg| {
        if (!std.mem.startsWith(u8, arg, "--config=")) continue;
        if (path != null or arg.len == "--config=".len) {
            return error.InvalidArgument;
        }
        path = arg["--config=".len..];
    }
    if (path != null and args.len != 2) return error.InvalidArgument;
    return path;
}

fn parseArgs(
    init: std.process.Init,
) !Config {
    var config: Config = .{};
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--executors=")) {
            config.executors = try std.fmt.parseInt(
                u8,
                arg["--executors=".len..],
                10,
            );
            if (config.executors == 0) return error.InvalidArgument;
        } else if (std.mem.startsWith(u8, arg, "--bind=")) {
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
            "--max-pending-incoming-qos2=",
        )) {
            config.max_pending_incoming_qos2 = try parsePositiveUsize(
                arg["--max-pending-incoming-qos2=".len..],
            );
        } else if (std.mem.eql(u8, arg, "--strict-utf8")) {
            config.strict_utf8 = true;
        } else if (std.mem.eql(
            u8,
            arg,
            "--mqtt31-session-present-extension",
        )) {
            config.mqtt31_session_present_extension = true;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--connect-timeout-ms=",
        )) {
            config.connect_timeout_ms = try std.fmt.parseInt(
                u32,
                arg["--connect-timeout-ms=".len..],
                10,
            );
            if (config.connect_timeout_ms.? == 0) {
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
            "--proxy-protocol=",
        )) {
            if (config.proxy_protocol != null) {
                return error.InvalidArgument;
            }
            const value = arg["--proxy-protocol=".len..];
            config.proxy_protocol = if (std.mem.eql(u8, value, "1"))
                .v1
            else if (std.mem.eql(u8, value, "2"))
                .v2
            else
                return error.InvalidArgument;
        } else if (std.mem.eql(
            u8,
            arg,
            "--proxy-v2-require-tls",
        )) {
            config.proxy_v2_require_tls = true;
        } else if (std.mem.eql(
            u8,
            arg,
            "--proxy-v2-require-client-certificate",
        )) {
            config.proxy_v2_require_client_certificate = true;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--proxy-header-timeout-ms=",
        )) {
            config.proxy_header_timeout_ms = try std.fmt.parseInt(
                u32,
                arg["--proxy-header-timeout-ms=".len..],
                10,
            );
            if (config.proxy_header_timeout_ms.? == 0) {
                return error.InvalidArgument;
            }
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
            "--connack-reason=",
        )) {
            config.connack_reason = try std.fmt.parseInt(
                u8,
                arg["--connack-reason=".len..],
                10,
            );
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--server-reference=",
        )) {
            const reference = arg["--server-reference=".len..];
            if (reference.len == 0) return error.InvalidArgument;
            config.server_reference = reference;
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
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--response-information=",
        )) {
            const value = arg["--response-information=".len..];
            if (value.len == 0 or config.response_information != null) {
                return error.InvalidArgument;
            }
            config.response_information = value;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--problem-reason-string=",
        )) {
            const value = arg["--problem-reason-string=".len..];
            if (value.len == 0 or config.problem_reason_string != null) {
                return error.InvalidArgument;
            }
            config.problem_reason_string = value;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--problem-user-property=",
        )) {
            const value = arg["--problem-user-property=".len..];
            if (value.len == 0 or config.problem_user_property != null) {
                return error.InvalidArgument;
            }
            config.problem_user_property = value;
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
        } else if (std.mem.eql(
            u8,
            arg,
            "--interop-test-authentication",
        )) {
            config.interop_test_authentication = true;
        } else if (std.mem.eql(
            u8,
            arg,
            "--interop-authenticated-username-acl",
        )) {
            config.interop_authenticated_username_acl = true;
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
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--deny-will-topic=",
        )) {
            const topic = arg["--deny-will-topic=".len..];
            if (topic.len == 0 or config.deny_will_topic != null) {
                return error.InvalidArgument;
            }
            try netz.mqtt.validateTopicName(topic);
            config.deny_will_topic = topic;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--deny-retained-source-client-id=",
        )) {
            const client_id =
                arg["--deny-retained-source-client-id=".len..];
            if (client_id.len == 0 or
                config.deny_retained_source_client_id != null)
            {
                return error.InvalidArgument;
            }
            try netz.mqtt.validateUtf8String(client_id);
            config.deny_retained_source_client_id = client_id;
        } else if (std.mem.eql(
            u8,
            arg,
            "--no-check-retain-source",
        )) {
            config.check_retain_source = false;
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
        } else if (std.mem.eql(
            u8,
            arg,
            "--use-username-as-client-id",
        )) {
            config.use_username_as_client_id = true;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--persistent-session-expiry-seconds=",
        )) {
            config.persistent_session_expiry_seconds =
                try std.fmt.parseInt(
                    u32,
                    arg["--persistent-session-expiry-seconds=".len..],
                    10,
                );
            if (config.persistent_session_expiry_seconds.? == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--system-interval-seconds=",
        )) {
            config.system_interval_seconds = try std.fmt.parseInt(
                u32,
                arg["--system-interval-seconds=".len..],
                10,
            );
            if (config.system_interval_seconds.? == 0) {
                return error.InvalidArgument;
            }
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--persistence=",
        )) {
            const path = arg["--persistence=".len..];
            if (path.len == 0) return error.InvalidArgument;
            config.persistence_path = path;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--commit-log=",
        )) {
            const path = arg["--commit-log=".len..];
            if (path.len == 0) return error.InvalidArgument;
            config.commit_log_path = path;
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
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--autosave-change-count=",
        )) {
            config.autosave_change_count = try parsePositiveUsize(
                arg["--autosave-change-count=".len..],
            );
        } else if (std.mem.eql(u8, arg, "--ignore-connection-errors")) {
            config.ignore_connection_errors = true;
        } else if (std.mem.eql(u8, arg, "--allocator-stats")) {
            config.allocator_stats = true;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--allocator-stats-qos=",
        )) {
            const value = arg["--allocator-stats-qos=".len..];
            config.allocator_stats_qos = if (std.mem.eql(u8, value, "1"))
                1
            else if (std.mem.eql(u8, value, "2"))
                2
            else
                return error.InvalidArgument;
        } else if (std.mem.startsWith(
            u8,
            arg,
            "--allocator-stats-session-expiry-seconds=",
        )) {
            config.allocator_stats_session_expiry_seconds =
                try std.fmt.parseInt(
                    u32,
                    arg["--allocator-stats-session-expiry-seconds=".len..],
                    10,
                );
        } else {
            return error.InvalidArgument;
        }
    }
    if ((config.autosave_interval_seconds != null or
        config.autosave_change_count != null) and
        config.persistence_path == null)
    {
        return error.InvalidArgument;
    }
    if (config.commit_log_path != null and
        (config.persistence_path != null or
            config.autosave_interval_seconds != null or
            config.autosave_change_count != null or
            !config.restore))
    {
        return error.InvalidArgument;
    }
    if ((config.allocator_stats_qos != null or
        config.allocator_stats_session_expiry_seconds != null) and
        !config.allocator_stats)
    {
        return error.InvalidArgument;
    }
    if ((config.username == null) != (config.password == null)) {
        return error.InvalidArgument;
    }
    if (config.interop_authenticated_username_acl and
        (!config.interop_test_authentication or
            config.username != null or
            config.deny_publish_topic != null or
            config.deny_subscribe_filter != null or
            config.deny_unsubscribe_filter != null or
            config.deny_delivery_topic != null or
            config.deny_will_topic != null or
            config.deny_retained_source_client_id != null))
    {
        return error.InvalidArgument;
    }
    if ((config.server_reference == null) !=
        (config.connack_reason != 0x9c and config.connack_reason != 0x9d))
    {
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
    use_username_as_client_id: bool,
) !void {
    if (use_username_as_client_id) {
        const listeners = [_]netz.mqtt.broker.Listener{.{
            .source = broker.server.?.pendingSource(),
            .authorization = .{
                .use_username_as_client_id = true,
            },
            .connection_count = connections,
        }};
        try broker.serveListeners(&listeners);
        return;
    }
    if (ignore_connection_errors) {
        // Conformance/fuzz harnesses deliberately open malformed connections.
        // The finite serve call waits for every independently accepted client
        // before returning its first connection error. Ignore that aggregate
        // result while preserving concurrent clients, which packet-sequence
        // harnesses need for helper publishers. Autosave uses this helper as a
        // cancelable Select task, so never swallow its shutdown signal.
        broker.serve(connections) catch |err| switch (err) {
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
    use_username_as_client_id: bool,
) ?anyerror {
    serveBroker(
        broker,
        connections,
        ignore_connection_errors,
        use_username_as_client_id,
    ) catch |err|
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

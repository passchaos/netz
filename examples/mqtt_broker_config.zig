//! Runtime adapter for the broker example's strict Mosquitto-style config.
//!
//! Keeping listener construction here prevents the already feature-rich CLI
//! example from also owning heterogeneous transport lifetime bookkeeping.

const std = @import("std");
const builtin = @import("builtin");
const netz = @import("netz");
const reloadable_security = @import(
    "support/mqtt_reloadable_security.zig",
);
const reloadable_identity = @import(
    "support/mqtt_reloadable_identity.zig",
);
const configured_bridges = @import(
    "support/mqtt_configured_bridges.zig",
);

const mqtt = netz.mqtt;

var checkpoint_requested: std.c.sig_atomic_t = 0;
var security_reload_requested: std.c.sig_atomic_t = 0;

const CheckpointSignal = if (builtin.os.tag == .linux) struct {
    previous: std.posix.Sigaction,

    fn install() @This() {
        @atomicStore(std.c.sig_atomic_t, &checkpoint_requested, 0, .release);
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = handle },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };
        var previous: std.posix.Sigaction = undefined;
        std.posix.sigaction(.USR1, &action, &previous);
        return .{ .previous = previous };
    }

    fn deinit(self: *@This()) void {
        std.posix.sigaction(.USR1, &self.previous, null);
        @atomicStore(std.c.sig_atomic_t, &checkpoint_requested, 0, .release);
    }

    fn take() bool {
        return @atomicRmw(
            std.c.sig_atomic_t,
            &checkpoint_requested,
            .Xchg,
            0,
            .acq_rel,
        ) != 0;
    }

    fn request() void {
        @atomicStore(std.c.sig_atomic_t, &checkpoint_requested, 1, .release);
    }

    fn handle(_: std.posix.SIG) callconv(.c) void {
        // Keep the asynchronous signal path lock-free and allocation-free.
        // The std.Io supervisor consumes the flag and performs the snapshot.
        request();
    }
} else struct {
    fn install() @This() {
        return .{};
    }

    fn deinit(_: *@This()) void {}

    fn take() bool {
        return false;
    }

    fn request() void {}
};

const ReloadSignal = if (builtin.os.tag == .linux) struct {
    previous: std.posix.Sigaction,

    fn install() @This() {
        @atomicStore(
            std.c.sig_atomic_t,
            &security_reload_requested,
            0,
            .release,
        );
        const action: std.posix.Sigaction = .{
            .handler = .{ .handler = handle },
            .mask = std.posix.sigemptyset(),
            .flags = std.posix.SA.RESTART,
        };
        var previous: std.posix.Sigaction = undefined;
        std.posix.sigaction(.HUP, &action, &previous);
        return .{ .previous = previous };
    }

    fn deinit(self: *@This()) void {
        std.posix.sigaction(.HUP, &self.previous, null);
        @atomicStore(
            std.c.sig_atomic_t,
            &security_reload_requested,
            0,
            .release,
        );
    }

    fn take() bool {
        return @atomicRmw(
            std.c.sig_atomic_t,
            &security_reload_requested,
            .Xchg,
            0,
            .acq_rel,
        ) != 0;
    }

    fn handle(_: std.posix.SIG) callconv(.c) void {
        // Loading, allocation, locks, and logging remain in the supervisor.
        @atomicStore(
            std.c.sig_atomic_t,
            &security_reload_requested,
            1,
            .release,
        );
    }
} else struct {
    fn install() @This() {
        return .{};
    }

    fn deinit(_: *@This()) void {}

    fn take() bool {
        return false;
    }
};

const checkpoint_signal_poll_interval: std.Io.Clock.Duration =
    .{ .raw = .fromMilliseconds(100), .clock = .awake };

const BridgeResult = struct {
    index: usize,
    err: ?anyerror,
    expected_stop: bool,
};

pub const RunOptions = struct {
    /// Deterministic process-test lifecycle. Production config mode is a
    /// long-running supervisor and does not reinterpret listener limits as a
    /// cumulative accept count.
    finite_test: bool = false,
};

const ConfiguredServer = union(enum) {
    mqtt: mqtt.runtime.Server,
    mqtt_tls: mqtt.tls_runtime.Server,
    websockets: mqtt.websocket_runtime.Server,
    secure_websockets: mqtt.websocket_runtime.TlsServer,

    fn deinit(self: *ConfiguredServer) void {
        switch (self.*) {
            .mqtt => |*server| server.deinit(),
            .mqtt_tls => |*server| server.deinit(),
            .websockets => |*server| server.deinit(),
            .secure_websockets => |*server| server.deinit(),
        }
        self.* = undefined;
    }

    fn pendingSource(self: *ConfiguredServer) mqtt.runtime.PendingSource {
        return switch (self.*) {
            .mqtt => |*server| server.pendingSource(),
            .mqtt_tls => |*server| server.pendingSource(),
            .websockets => |*server| server.pendingSource(),
            .secure_websockets => |*server| server.pendingSource(),
        };
    }

    fn address(self: ConfiguredServer) std.Io.net.IpAddress {
        return switch (self) {
            .mqtt => |server| server.address(),
            .mqtt_tls => |server| server.address(),
            .websockets => |server| server.address(),
            .secure_websockets => |server| server.address(),
        };
    }

    fn transportName(self: ConfiguredServer) []const u8 {
        return switch (self) {
            .mqtt => "mqtt",
            .mqtt_tls => "mqtts",
            .websockets => "websockets",
            .secure_websockets => "wss",
        };
    }
};

fn openConfiguredServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: mqtt.broker_config.Config,
    configured: mqtt.broker_config.Listener,
    identity: ?mqtt.tls_runtime.ServerIdentity,
    identity_provider: ?mqtt.tls_runtime.ServerIdentityProvider,
    client_auth: ?mqtt.tls_runtime.ClientAuthPolicy,
    bind_address: std.Io.net.IpAddress,
) !ConfiguredServer {
    var listener = try netz.runtime.listenTcp(io, bind_address, .{
        .reuse_address = true,
        .ip6_only = if (bind_address == .ip6) true else null,
    });
    errdefer listener.deinit(io);

    return if (identity_provider) |provider| switch (configured.protocol) {
        .mqtt => .{ .mqtt_tls = try mqtt.tls_runtime.Server.initWithListener(
            allocator,
            io,
            listener,
            .{
                .identity = identity.?,
                .identity_provider = provider,
                .client_auth = client_auth,
                .protocol_policy = configured.tls_protocol_policy,
                .tls12_cipher_suites = if (configured.tls12_cipher_suites.len != 0)
                    configured.tls12_cipher_suites
                else
                    netz.tls.stream.default_tls12_cipher_suites,
                .alpn_protocols = &.{"mqtt"},
                .require_alpn = false,
                .limits = listenerLimits(config, configured),
                .tcp_nodelay = config.set_tcp_nodelay,
            },
        ) },
        .websockets => .{
            .secure_websockets = try mqtt.websocket_runtime.TlsServer.initWithListener(
                allocator,
                io,
                listener,
                .{
                    .identity = identity.?,
                    .identity_provider = provider,
                    .client_auth = client_auth,
                    .protocol_policy = configured.tls_protocol_policy,
                    .tls12_cipher_suites = if (configured.tls12_cipher_suites.len != 0)
                        configured.tls12_cipher_suites
                    else
                        netz.tls.stream.default_tls12_cipher_suites,
                    .allowed_origins = configured.websocket_origins.items,
                    .max_head_bytes = config.websocket_headers_size,
                    .limits = listenerLimits(config, configured),
                    .tcp_nodelay = config.set_tcp_nodelay,
                },
            ),
        },
    } else switch (configured.protocol) {
        .mqtt => .{ .mqtt = try mqtt.runtime.Server.initWithListener(
            allocator,
            io,
            listener,
            listenerLimits(config, configured),
        ) },
        .websockets => .{
            .websockets = try mqtt.websocket_runtime.Server.initWithListener(
                allocator,
                io,
                listener,
                .{
                    .limits = listenerLimits(config, configured),
                    .allowed_origins = configured.websocket_origins.items,
                    .max_head_bytes = config.websocket_headers_size,
                },
            ),
        },
    };
}

fn unavailableSocketFamily(err: anyerror) bool {
    return switch (err) {
        error.AddressFamilyUnsupported,
        error.ProtocolUnsupportedBySystem,
        error.ProtocolUnsupportedByAddressFamily,
        error.SocketModeUnsupported,
        error.OptionUnsupported,
        => true,
        else => false,
    };
}

fn listenerBindAddresses(
    configured: mqtt.broker_config.Listener,
    storage: *[2]std.Io.net.IpAddress,
) ![]const std.Io.net.IpAddress {
    if (configured.bind_interface.len != 0) {
        const resolved = try netz.runtime.resolveInterfaceAddresses(
            configured.bind_interface,
            configured.address.getPort(),
        );
        if (configured.socket_domain) |domain| {
            storage[0] = switch (domain) {
                .ipv4 => resolved.ip4 orelse
                    return error.AddressFamilyUnsupported,
                .ipv6 => resolved.ip6 orelse
                    return error.AddressFamilyUnsupported,
            };
            return storage[0..1];
        }
        var count: usize = 0;
        if (resolved.ip4) |address| {
            storage[count] = address;
            count += 1;
        }
        if (resolved.ip6) |address| {
            storage[count] = address;
            count += 1;
        }
        return storage[0..count];
    }
    if (configured.bind_all_socket_domains) {
        const port = configured.address.getPort();
        storage.* = .{
            .{ .ip4 = .unspecified(port) },
            .{ .ip6 = .unspecified(port) },
        };
        return storage;
    }
    storage[0] = configured.address;
    return storage[0..1];
}

fn listenerLimits(
    config: mqtt.broker_config.Config,
    listener: mqtt.broker_config.Listener,
) mqtt.runtime.Limits {
    return .{
        .max_packet_size = config.max_packet_size,
        .tcp_nodelay = config.set_tcp_nodelay,
        .proxy_protocol = listener.proxy_protocol,
        .proxy_v2_require_tls = listener.proxy_protocol_v2_require_tls,
        .proxy_v2_require_client_certificate = listener.proxy_protocol == .v2 and listener.require_certificate,
    };
}

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    config_path: []const u8,
    run_options: RunOptions,
) !void {
    var config = try mqtt.broker_config.load(
        allocator,
        io,
        std.Io.Dir.cwd(),
        config_path,
    );
    defer config.deinit(allocator);

    const connection_count = try config.totalMaxConnections();
    const active_connection_limit = try config.activeConnectionLimit();
    const persistence_path = if (config.persistence)
        try config.persistencePath(allocator)
    else
        null;
    defer if (persistence_path) |path| allocator.free(path);

    const security_file_count = if (config.per_listener_settings)
        config.listeners.len
    else
        1;
    const security_paths = try allocator.alloc(
        reloadable_security.Paths,
        security_file_count,
    );
    defer allocator.free(security_paths);
    for (0..security_file_count) |index| {
        security_paths[index] = if (config.per_listener_settings) .{
            .password_file = config.listeners[index].password_file,
            .acl_file = config.listeners[index].acl_file,
        } else .{
            .password_file = config.password_file,
            .acl_file = config.acl_file,
        };
    }
    const listener_ids = try allocator.alloc(u16, config.listeners.len);
    defer allocator.free(listener_ids);
    const password_authentication = try allocator.alloc(
        bool,
        config.listeners.len,
    );
    defer allocator.free(password_authentication);
    for (
        config.listeners,
        listener_ids,
        password_authentication,
    ) |listener, *id, *uses_password| {
        id.* = listener.address.getPort();
        const password_file = if (config.per_listener_settings)
            listener.password_file
        else
            config.password_file;
        uses_password.* = password_file.len != 0 and
            !listener.use_identity_as_username and
            !listener.use_subject_as_username;
    }
    var security = try reloadable_security.Security.init(
        allocator,
        io,
        std.Io.Dir.cwd(),
        security_paths,
        listener_ids,
        config.per_listener_settings,
    );
    defer security.deinit();
    try security.setPasswordAuthentication(password_authentication);
    const source_access_control = security.sourceAccessControl();
    const max_inflight_messages = config.effectiveMaxInflightMessages();
    const base_accept = mqtt.runtime.AcceptOptions{
        .protocol = .v5,
        .max_outgoing_inflight = max_inflight_messages,
        .retain_available = config.retain_available,
        .allow_zero_length_client_id = config.allow_zero_length_client_id,
    };
    var broker = try mqtt.broker.Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = active_connection_limit,
            .max_payload_size = config.message_size_limit,
            .runtime = .{ .max_packet_size = config.max_packet_size },
        },
        .max_inflight_payload_bytes_per_connection = config.max_inflight_bytes,
        .accept = base_accept,
        .upgrade_outgoing_qos = config.upgrade_outgoing_qos,
        .queue_qos0_messages = config.queue_qos0_messages,
        .check_retain_source = config.check_retain_source,
        .persistent_session_expiry_seconds = config.persistent_client_expiration_seconds,
        .retained_expiry_interval = if (config.retain_expiry_interval_seconds == 0)
            null
        else
            .fromSeconds(config.retain_expiry_interval_seconds),
        .system_stats_interval = if (config.sys_interval_seconds == 0)
            null
        else
            .fromSeconds(config.sys_interval_seconds),
        .access_control = source_access_control,
        .session = .{
            .max_sessions = config.global_max_clients,
            .max_inflight_per_session = max_inflight_messages,
            .max_inflight_payload_bytes_per_session = config.max_inflight_bytes,
            .max_queued_per_session = config.effectiveMaxQueuedMessages(),
            .max_queued_payload_bytes_per_session = config.max_queued_bytes,
        },
        .persistent_change_autosave = if (config.persistence and
            config.autosave_on_changes and
            config.autosave_interval != 0) .{
            .dir = std.Io.Dir.cwd(),
            .sub_path = persistence_path.?,
            .max_changes = config.autosave_interval,
        } else null,
    });
    defer broker.deinit();

    const bridge_commit_log_path = if (bridgesUseQoS2(config.bridges))
        try std.fmt.allocPrint(allocator, "{s}.bridge-journal", .{
            persistence_path orelse return error.BridgePersistenceRequired,
        })
    else
        null;
    defer if (bridge_commit_log_path) |path| allocator.free(path);
    if (bridge_commit_log_path) |journal_path| {
        broker.restoreCommitLog(std.Io.Dir.cwd(), journal_path, .{}) catch |err|
            switch (err) {
                error.CommitLogNotFound => {
                    if (persistence_path) |snapshot_path| {
                        broker.restoreSnapshot(
                            std.Io.Dir.cwd(),
                            snapshot_path,
                        ) catch |restore_error| {
                            if (restore_error != error.SnapshotNotFound) {
                                return restore_error;
                            }
                        };
                    }
                    try broker.createCommitLog(
                        std.Io.Dir.cwd(),
                        journal_path,
                        .{},
                    );
                },
                else => return err,
            };
    } else if (persistence_path) |path| {
        broker.restoreSnapshot(std.Io.Dir.cwd(), path) catch |err| {
            if (err != error.SnapshotNotFound) return err;
        };
    }
    var shutdown: std.Io.Event = .unset;
    var bridges = try configured_bridges.Set.init(
        allocator,
        io,
        &broker,
        config.bridges,
        &shutdown,
        persistence_path,
    );
    defer bridges.deinit();
    var checkpoint_signal = if (config.persistence)
        CheckpointSignal.install()
    else
        null;
    defer if (checkpoint_signal) |*signal| signal.deinit();
    const identity_paths = try allocator.alloc(
        reloadable_identity.Paths,
        config.listeners.len,
    );
    defer allocator.free(identity_paths);
    for (config.listeners, identity_paths) |configured, *paths| {
        paths.* = .{
            .certificate_file = configured.certfile,
            .private_key_file = configured.keyfile,
            .private_key_password_file = configured.keyfile_password_file,
            .client_ca_file = configured.cafile,
            .client_ca_path = configured.capath,
            .crl_file = configured.crlfile,
            .require_client_certificate = configured.require_certificate,
        };
    }
    var identities = try reloadable_identity.Set.init(
        allocator,
        io,
        std.Io.Dir.cwd(),
        identity_paths,
        &security.lock,
    );
    defer identities.deinit();
    const has_reloadable_files = security.hasReloadableFiles() or
        identities.hasReloadableFiles();
    var reload_signal = if (has_reloadable_files)
        ReloadSignal.install()
    else
        null;
    defer if (reload_signal) |*signal| signal.deinit();

    const maximum_server_count = std.math.mul(
        usize,
        config.listeners.len,
        2,
    ) catch return error.IntegerOverflow;
    const servers = try allocator.alloc(ConfiguredServer, maximum_server_count);
    defer allocator.free(servers);
    var initialized_servers: usize = 0;
    defer {
        while (initialized_servers != 0) {
            initialized_servers -= 1;
            servers[initialized_servers].deinit();
        }
    }
    const listeners = try allocator.alloc(
        mqtt.broker.Listener,
        maximum_server_count,
    );
    defer allocator.free(listeners);
    const endpoints = try allocator.alloc(
        mqtt.broker.ListenerEndpoint,
        maximum_server_count,
    );
    defer allocator.free(endpoints);
    const server_config_indices = try allocator.alloc(
        usize,
        maximum_server_count,
    );
    defer allocator.free(server_config_indices);
    const security_policies = try allocator.alloc(
        reloadable_security.ListenerPolicy,
        config.listeners.len,
    );
    defer allocator.free(security_policies);

    for (config.listeners, 0..) |configured, config_index| {
        var accept = base_accept;
        if (config.per_listener_settings) {
            accept.allow_zero_length_client_id =
                configured.allow_zero_length_client_id;
        }
        accept.maximum_qos = configured.maximum_qos;
        accept.maximum_keep_alive_seconds =
            configured.maximum_keep_alive_seconds;
        accept.accepted_protocol_versions =
            configured.accepted_protocol_versions;
        accept.topic_alias_maximum = configured.max_topic_alias;
        accept.max_outgoing_topic_aliases =
            configured.max_topic_alias_broker;
        security_policies[config_index] = security.listenerPolicy(
            config_index,
            configured.allow_anonymous,
        );
        const listener_access_control = security_policies[config_index]
            .accessControl();
        const authorization = mqtt.broker.ListenerAuthorization{
            .connect = if (security.hasPasswordFile(config_index) and
                !configured.use_identity_as_username and
                !configured.use_subject_as_username) .{
                .context = &security_policies[config_index],
                .authorize = reloadable_security.ListenerPolicy
                    .authorizeConnect,
            } else null,
            .access_control = listener_access_control,
            .use_username_as_client_id = configured.use_username_as_client_id,
            .use_identity_as_username = configured.use_identity_as_username,
            .use_subject_as_username = configured.use_subject_as_username,
            .retained_source_id = configured.address.getPort(),
        };
        const accept_concurrency = std.math.add(
            usize,
            @min(configured.max_connections, active_connection_limit),
            1,
        ) catch return error.IntegerOverflow;
        const namespace = try mqtt.listener_namespace.Namespace.init(
            configured.mount_point,
        );
        const identity = identities.initialIdentity(config_index);
        const identity_provider = identities.provider(config_index);
        const client_auth = identities.initialClientAuth(config_index);
        var bind_address_storage: [2]std.Io.net.IpAddress = undefined;
        const bind_addresses = try listenerBindAddresses(
            configured,
            &bind_address_storage,
        );

        const group_start = initialized_servers;
        var last_unavailable_error: ?anyerror = null;
        for (bind_addresses) |bind_address| {
            servers[initialized_servers] = openConfiguredServer(
                allocator,
                io,
                config,
                configured,
                identity,
                identity_provider,
                client_auth,
                bind_address,
            ) catch |err| {
                if (bind_addresses.len > 1 and
                    unavailableSocketFamily(err))
                {
                    last_unavailable_error = err;
                    continue;
                }
                return err;
            };
            server_config_indices[initialized_servers] = config_index;
            initialized_servers += 1;
        }
        const group_count = initialized_servers - group_start;
        if (group_count == 0) {
            return last_unavailable_error orelse
                error.AddressFamilyUnsupported;
        }
        const capacity_group = if (group_count > 1) group_start else null;
        for (group_start..initialized_servers) |server_index| {
            const group_offset = server_index - group_start;
            const finite_count = configured.max_connections / group_count +
                @intFromBool(
                    group_offset < configured.max_connections % group_count,
                );
            listeners[server_index] = .{
                .source = servers[server_index].pendingSource(),
                .namespace = namespace,
                .auto_client_id_prefix = config.autoIdPrefixForListener(
                    configured,
                ),
                .accept = accept,
                .authorization = authorization,
                .max_connections = configured.max_connections,
                .capacity_group = capacity_group,
                .connection_count = finite_count,
            };
            endpoints[server_index] = .{
                .source = listeners[server_index].source,
                .namespace = listeners[server_index].namespace,
                .auto_client_id_prefix = listeners[server_index]
                    .auto_client_id_prefix,
                .accept = listeners[server_index].accept,
                .authorization = listeners[server_index].authorization,
                .max_connections = configured.max_connections,
                .capacity_group = capacity_group,
                .accept_concurrency = accept_concurrency,
            };
        }
    }

    const active_servers = servers[0..initialized_servers];
    const active_listeners = listeners[0..initialized_servers];
    const active_endpoints = endpoints[0..initialized_servers];

    if (run_options.finite_test) {
        std.debug.print(
            "netz MQTT 3.1.1/5 broker configured {d} listeners for {d} " ++
                "clients server_io=zio-std-io\n",
            .{ config.listeners.len, connection_count },
        );
    } else {
        std.debug.print(
            "netz MQTT 3.1.1/5 broker configured {d} listeners " ++
                "global_max_connections={d} server_io=zio-std-io\n",
            .{ config.listeners.len, active_connection_limit },
        );
    }
    for (active_servers, server_config_indices[0..initialized_servers]) |
        server,
        config_index,
    | {
        const configured = config.listeners[config_index];
        std.debug.print(
            "  {s} {f} mount_point={s} max_connections={d}\n",
            .{
                server.transportName(),
                server.address(),
                if (configured.mount_point.len == 0)
                    "<global>"
                else
                    configured.mount_point,
                configured.max_connections,
            },
        );
    }
    for (config.bridges) |bridge| {
        std.debug.print(
            "  bridge {s} remote={s}:{d} addresses={d} transport={s} " ++
                "rules={d} direction={s} start_type={s}\n",
            .{
                bridge.name,
                bridge.host,
                bridge.port,
                bridge.addressCount(),
                if (bridge.usesTls()) "tls-vail" else "tcp",
                bridge.rules.len,
                if (bridge.hasOutbound() and bridge.hasInbound())
                    "both"
                else if (bridge.hasOutbound())
                    "out"
                else
                    "in",
                @tagName(bridge.start_type),
            },
        );
    }

    const service: Service = if (run_options.finite_test)
        .{ .finite = active_listeners }
    else
        .{ .continuous = .{
            .listeners = active_endpoints,
            .shutdown = &shutdown,
        } };
    if (config.persistence or has_reloadable_files or bridges.values.len != 0) {
        try serveWithManagement(
            allocator,
            &broker,
            service,
            io,
            &shutdown,
            &bridges,
            persistence_path,
            if (!config.autosave_on_changes and
                config.autosave_interval != 0)
                config.autosave_interval
            else
                null,
            if (has_reloadable_files) &security else null,
            if (has_reloadable_files) &identities else null,
        );
    } else {
        try serveConfigured(&broker, service);
    }
    bridges.disconnectLocalSources();
    if (persistence_path) |path| {
        try broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }
}

fn serveWithManagement(
    allocator: std.mem.Allocator,
    broker: *mqtt.broker.Broker,
    service: Service,
    io: std.Io,
    shutdown: *std.Io.Event,
    bridges: *configured_bridges.Set,
    persistence_path: ?[]const u8,
    interval_seconds: ?u32,
    security: ?*reloadable_security.Security,
    identities: ?*reloadable_identity.Set,
) !void {
    const Result = union(enum) {
        serve: ?anyerror,
        bridge: BridgeResult,
        bridge_failback: std.Io.Cancelable!void,
        periodic_timer: std.Io.Cancelable!void,
        signal_poll: std.Io.Cancelable!void,
    };
    const result_buffer = try allocator.alloc(Result, 4 + bridges.values.len);
    defer allocator.free(result_buffer);
    var select: std.Io.Select(Result) = .init(io, result_buffer);
    defer select.cancelDiscard();
    defer shutdown.set(io);
    try select.concurrent(.serve, serveResult, .{ broker, service });
    for (bridges.values, 0..) |_, index| {
        try select.concurrent(.bridge, bridgeResult, .{ bridges, index });
    }
    if (bridges.needsPrimaryFailback()) {
        try select.concurrent(
            .bridge_failback,
            configured_bridges.Set.runPrimaryFailback,
            .{ bridges, io, shutdown },
        );
    }
    if (interval_seconds) |seconds| {
        try select.concurrent(
            .periodic_timer,
            waitInterval,
            .{ io, std.Io.Clock.Duration{
                .raw = .fromSeconds(seconds),
                .clock = .awake,
            } },
        );
    }
    if (comptime builtin.os.tag == .linux) {
        if (persistence_path != null or security != null) {
            try select.concurrent(
                .signal_poll,
                waitInterval,
                .{ io, checkpoint_signal_poll_interval },
            );
        }
    }
    while (true) {
        switch (try select.await()) {
            .serve => |maybe_error| {
                shutdown.set(io);
                select.cancelDiscard();
                if (maybe_error) |err| return err;
                return;
            },
            .bridge => |result| {
                if (result.expected_stop) {
                    if (result.err) |err| {
                        std.debug.print(
                            "netz MQTT bridge {d} completed " ++
                                "start_type=once error={s}\n",
                            .{ result.index, @errorName(err) },
                        );
                    } else {
                        std.debug.print(
                            "netz MQTT bridge {d} completed " ++
                                "start_type=once\n",
                            .{result.index},
                        );
                    }
                    continue;
                }
                shutdown.set(io);
                select.cancelDiscard();
                if (result.err) |err| {
                    std.debug.print(
                        "netz MQTT bridge {d} stopped: error={s}\n",
                        .{ result.index, @errorName(err) },
                    );
                    return err;
                }
                return error.UnexpectedBridgeExit;
            },
            .bridge_failback => |result| {
                try result;
                return error.UnexpectedBridgeExit;
            },
            .periodic_timer => |result| {
                try result;
                broker.saveLiveSnapshot(
                    std.Io.Dir.cwd(),
                    persistence_path orelse unreachable,
                ) catch |err| switch (err) {
                    error.SnapshotBusy => {},
                    else => return err,
                };
                const seconds = interval_seconds orelse unreachable;
                try select.concurrent(
                    .periodic_timer,
                    waitInterval,
                    .{ io, std.Io.Clock.Duration{
                        .raw = .fromSeconds(seconds),
                        .clock = .awake,
                    } },
                );
            },
            .signal_poll => |result| {
                try result;
                if (CheckpointSignal.take()) {
                    broker.saveLiveSnapshot(
                        std.Io.Dir.cwd(),
                        persistence_path orelse unreachable,
                    ) catch |err| switch (err) {
                        error.SnapshotBusy => CheckpointSignal.request(),
                        else => return err,
                    };
                    if (!CheckpointSignal.take()) {
                        std.debug.print(
                            "netz MQTT persistence checkpoint completed: " ++
                                "source=SIGUSR1 server_io=zio-std-io\n",
                            .{},
                        );
                    } else {
                        // A request delivered during the completed snapshot
                        // still needs its own subsequent checkpoint.
                        CheckpointSignal.request();
                    }
                }
                if (ReloadSignal.take()) {
                    if (security) |policy| {
                        reloadSecurityAndIdentities(
                            broker,
                            policy,
                            identities orelse unreachable,
                        ) catch |err| {
                            std.debug.print(
                                "netz MQTT security reload failed: " ++
                                    "error={s} server_io=zio-std-io\n",
                                .{@errorName(err)},
                            );
                            try select.concurrent(
                                .signal_poll,
                                waitInterval,
                                .{ io, checkpoint_signal_poll_interval },
                            );
                            continue;
                        };
                        std.debug.print(
                            "netz MQTT security reload completed: " ++
                                "source=SIGHUP server_io=zio-std-io\n",
                            .{},
                        );
                    }
                }
                try select.concurrent(
                    .signal_poll,
                    waitInterval,
                    .{ io, checkpoint_signal_poll_interval },
                );
            },
        }
    }
}

fn bridgeResult(
    bridges: *configured_bridges.Set,
    index: usize,
) BridgeResult {
    const configured = bridges.configured[index];
    const bridge = &bridges.values[index];
    switch (configured.start_type) {
        .automatic => bridge.run(.{ .timeout = .fromSeconds(30) }) catch |err| {
            return .{ .index = index, .err = err, .expected_stop = false };
        },
        .lazy => bridge.runLazy(
            .{ .timeout = .fromSeconds(30) },
            configured.threshold,
            .fromSeconds(configured.idle_timeout_seconds),
        ) catch |err| {
            return .{ .index = index, .err = err, .expected_stop = false };
        },
        .once => bridge.runOnce(.{ .timeout = .fromSeconds(30) }) catch |err| {
            return .{ .index = index, .err = err, .expected_stop = true };
        },
    }
    return .{
        .index = index,
        .err = null,
        .expected_stop = configured.start_type == .once,
    };
}

fn bridgesUseQoS2(bridges: []const mqtt.broker_config.Bridge) bool {
    for (bridges) |bridge| {
        if (bridge.usesQoS2()) return true;
    }
    return false;
}

fn reloadSecurityAndIdentities(
    broker: *mqtt.broker.Broker,
    security: *reloadable_security.Security,
    identities: *reloadable_identity.Set,
) !void {
    var prepared_security = try security.prepareReload();
    defer prepared_security.deinit();
    var prepared_identities = try identities.prepareReload();
    defer prepared_identities.deinit();
    security.lock.lockUncancelable(security.io);
    var retired_security = security.swapPreparedReload(&prepared_security);
    var retired_identities = identities.swapPreparedReload(
        &prepared_identities,
    );
    security.lock.unlock(security.io);
    _ = broker.disconnectUnauthorizedConnections(.{
        .context = &retired_security,
        .still_authorized = reloadable_security.RetiredReload
            .stillAuthorizesConnection,
    });
    retired_security.deinit();
    retired_identities.deinit();
}

const Service = union(enum) {
    finite: []const mqtt.broker.Listener,
    continuous: struct {
        listeners: []const mqtt.broker.ListenerEndpoint,
        shutdown: *std.Io.Event,
    },
};

fn serveConfigured(
    broker: *mqtt.broker.Broker,
    service: Service,
) anyerror!void {
    switch (service) {
        .finite => |listeners| try broker.serveListeners(listeners),
        .continuous => |continuous| try broker.serveListenersUntil(
            continuous.listeners,
            .{ .shutdown = continuous.shutdown },
        ),
    }
}

fn serveResult(
    broker: *mqtt.broker.Broker,
    service: Service,
) ?anyerror {
    serveConfigured(broker, service) catch |err| return err;
    return null;
}

fn waitInterval(
    io: std.Io,
    interval: std.Io.Clock.Duration,
) std.Io.Cancelable!void {
    try interval.sleep(io);
}

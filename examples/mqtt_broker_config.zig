//! Runtime adapter for the broker example's strict Mosquitto-style config.
//!
//! Keeping listener construction here prevents the already feature-rich CLI
//! example from also owning heterogeneous transport lifetime bookkeeping.

const std = @import("std");
const netz = @import("netz");
const source_acl = @import("support/mqtt_source_acl.zig");

const mqtt = netz.mqtt;

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
    const password_files = try allocator.alloc(
        ?mqtt.password_file.File,
        security_file_count,
    );
    defer allocator.free(password_files);
    @memset(password_files, null);
    defer for (password_files) |*file| {
        if (file.*) |*loaded| loaded.deinit();
    };
    const acl_files = try allocator.alloc(
        ?mqtt.acl_file.File,
        security_file_count,
    );
    defer allocator.free(acl_files);
    @memset(acl_files, null);
    defer for (acl_files) |*file| {
        if (file.*) |*loaded| loaded.deinit();
    };
    for (0..security_file_count) |index| {
        const password_path = if (config.per_listener_settings)
            config.listeners[index].password_file
        else
            config.password_file;
        if (password_path.len != 0) {
            password_files[index] = try mqtt.password_file.load(
                allocator,
                io,
                std.Io.Dir.cwd(),
                password_path,
            );
        }
        const acl_path = if (config.per_listener_settings)
            config.listeners[index].acl_file
        else
            config.acl_file;
        if (acl_path.len != 0) {
            acl_files[index] = try mqtt.acl_file.load(
                allocator,
                io,
                std.Io.Dir.cwd(),
                acl_path,
            );
        }
    }
    var source_acl_policy = source_acl.Policy{
        .per_listener_settings = config.per_listener_settings,
        .listeners = config.listeners,
        .acl_files = acl_files,
    };
    const source_access_control: ?mqtt.broker.AccessControlHandler = blk: {
        for (acl_files) |maybe_file| {
            if (maybe_file != null) break :blk .{
                .context = &source_acl_policy,
                .authorize_publish = source_acl.Policy.authorizePublish,
                .authorize_subscribe = source_acl.Policy.authorizeSubscribe,
                .authorize_will = source_acl.Policy.authorizeWill,
                .authorize_retained_source = source_acl.Policy.authorizeRetainedSource,
            };
        }
        break :blk null;
    };
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
            config.autosave_on_changes) .{
            .dir = std.Io.Dir.cwd(),
            .sub_path = persistence_path.?,
            .max_changes = config.autosave_interval,
        } else null,
    });
    defer broker.deinit();

    if (persistence_path) |path| {
        broker.restoreSnapshot(std.Io.Dir.cwd(), path) catch |err| {
            if (err != error.SnapshotNotFound) return err;
        };
    }

    const identities = try allocator.alloc(
        ?netz.tls.server_identity_file.Identity,
        config.listeners.len,
    );
    defer allocator.free(identities);
    @memset(identities, null);
    defer for (identities) |*maybe_identity| {
        if (maybe_identity.*) |*identity| identity.deinit();
    };
    const client_cas = try allocator.alloc(
        ?netz.tls.client_ca_file.File,
        config.listeners.len,
    );
    defer allocator.free(client_cas);
    @memset(client_cas, null);
    defer for (client_cas) |*maybe_ca| {
        if (maybe_ca.*) |*ca| ca.deinit();
    };
    const client_crls = try allocator.alloc(
        ?netz.tls.client_crl_file.File,
        config.listeners.len,
    );
    defer allocator.free(client_crls);
    @memset(client_crls, null);
    defer for (client_crls) |*maybe_crl| {
        if (maybe_crl.*) |*crl| crl.deinit();
    };
    const client_verifiers = try allocator.alloc(
        netz.tls.trust.ClientCertificateBundleVerifier,
        config.listeners.len,
    );
    defer allocator.free(client_verifiers);
    const client_crl_verifiers = try allocator.alloc(
        netz.tls.client_crl_file.Verifier,
        config.listeners.len,
    );
    defer allocator.free(client_crl_verifiers);
    const client_auth_policies = try allocator.alloc(
        ?mqtt.tls_runtime.ClientAuthPolicy,
        config.listeners.len,
    );
    defer allocator.free(client_auth_policies);
    @memset(client_auth_policies, null);
    // Validate every credential before opening any listener. A malformed later
    // identity must not leave an earlier configured port briefly exposed.
    for (config.listeners, 0..) |configured, index| {
        if (!configured.usesTls()) continue;
        identities[index] = try netz.tls.server_identity_file.load(
            allocator,
            io,
            std.Io.Dir.cwd(),
            configured.certfile,
            configured.keyfile,
        );
        if (configured.cafile.len != 0 or configured.capath.len != 0) {
            client_cas[index] = if (configured.capath.len != 0)
                try netz.tls.client_ca_dir.loadCombined(
                    allocator,
                    io,
                    std.Io.Dir.cwd(),
                    if (configured.cafile.len != 0) configured.cafile else null,
                    configured.capath,
                )
            else
                try netz.tls.client_ca_file.load(
                    allocator,
                    io,
                    std.Io.Dir.cwd(),
                    configured.cafile,
                );
            const ca = &client_cas[index].?;
            client_verifiers[index] = ca.verifier(
                std.Io.Timestamp.now(io, .real).toSeconds(),
            );
            const verifier = if (configured.crlfile.len != 0) blk: {
                client_crls[index] = try netz.tls.client_crl_file.load(
                    allocator,
                    io,
                    std.Io.Dir.cwd(),
                    configured.crlfile,
                    ca,
                );
                client_crl_verifiers[index] = .{
                    .trust = client_verifiers[index],
                    .crls = &client_crls[index].?,
                };
                break :blk client_crl_verifiers[index].clientVerifier();
            } else client_verifiers[index].clientVerifier();
            client_auth_policies[index] = .{
                .verifier = verifier,
                .certificate_authorities = ca.authorities(),
                .requirement = if (configured.require_certificate)
                    .required
                else
                    .optional,
            };
        }
    }

    const servers = try allocator.alloc(
        ConfiguredServer,
        config.listeners.len,
    );
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
        config.listeners.len,
    );
    defer allocator.free(listeners);
    const authorizations = try allocator.alloc(
        mqtt.password_file.Authorization,
        config.listeners.len,
    );
    defer allocator.free(authorizations);
    const acl_policies = try allocator.alloc(
        mqtt.acl_file.Policy,
        config.listeners.len,
    );
    defer allocator.free(acl_policies);

    for (config.listeners, 0..) |configured, index| {
        servers[index] = if (identities[index]) |*identity|
            switch (configured.protocol) {
                .mqtt => .{ .mqtt_tls = try mqtt.tls_runtime.Server.listen(
                    allocator,
                    io,
                    configured.address,
                    .{
                        .identity = identity.serverIdentity(),
                        .client_auth = client_auth_policies[index],
                        .limits = listenerLimits(config, configured),
                        .tcp_nodelay = config.set_tcp_nodelay,
                    },
                ) },
                .websockets => .{
                    .secure_websockets = try mqtt.websocket_runtime.TlsServer.listen(
                        allocator,
                        io,
                        configured.address,
                        .{
                            .identity = identity.serverIdentity(),
                            .client_auth = client_auth_policies[index],
                            .allowed_origins = configured.websocket_origins.items,
                            .max_head_bytes = config.websocket_headers_size,
                            .limits = listenerLimits(config, configured),
                            .tcp_nodelay = config.set_tcp_nodelay,
                        },
                    ),
                },
            }
        else switch (configured.protocol) {
            .mqtt => .{ .mqtt = try mqtt.runtime.Server.listen(
                allocator,
                io,
                configured.address,
                listenerLimits(config, configured),
            ) },
            .websockets => .{
                .websockets = try mqtt.websocket_runtime.Server.listen(
                    allocator,
                    io,
                    configured.address,
                    .{
                        .limits = listenerLimits(config, configured),
                        .allowed_origins = configured.websocket_origins.items,
                        .max_head_bytes = config.websocket_headers_size,
                    },
                ),
            },
        };
        initialized_servers += 1;

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
        const security_index = if (config.per_listener_settings) index else 0;
        const listener_passwords = if (password_files[security_index]) |*file|
            file
        else
            null;
        if (listener_passwords) |file| {
            authorizations[index] = .{
                .passwords = file,
                .allow_anonymous = configured.allow_anonymous,
            };
        }
        const listener_access_control: ?mqtt.broker.ListenerAccessControlHandler =
            if (acl_files[security_index]) |*file| blk: {
                acl_policies[index] = .{ .acl = file };
                break :blk .{
                    .context = &acl_policies[index],
                    .authorize_publish = mqtt.acl_file.Policy.authorizePublish,
                    .authorize_subscribe = mqtt.acl_file.Policy.authorizeSubscribe,
                    .authorize_unsubscribe = mqtt.acl_file.Policy.authorizeUnsubscribe,
                    .authorize_delivery = mqtt.acl_file.Policy.authorizeDelivery,
                    .authorize_will = mqtt.acl_file.Policy.authorizeWill,
                };
            } else null;
        listeners[index] = .{
            .source = servers[index].pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                configured.mount_point,
            ),
            .auto_client_id_prefix = config.autoIdPrefixForListener(
                configured,
            ),
            .accept = accept,
            .authorization = .{
                .connect = if (listener_passwords != null and
                    !configured.use_identity_as_username and
                    !configured.use_subject_as_username) .{
                    .context = &authorizations[index],
                    .authorize = mqtt.password_file.Authorization.authorize,
                } else null,
                .access_control = listener_access_control,
                .use_username_as_client_id = configured.use_username_as_client_id,
                .use_identity_as_username = configured.use_identity_as_username,
                .use_subject_as_username = configured.use_subject_as_username,
                .retained_source_id = configured.address.getPort(),
            },
            .connection_count = configured.max_connections,
        };
    }

    std.debug.print(
        "netz MQTT 3.1.1/5 broker configured {d} listeners for {d} " ++
            "clients server_io=zio-std-io\n",
        .{ listeners.len, connection_count },
    );
    for (servers, config.listeners) |server, configured| {
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

    if (config.persistence and !config.autosave_on_changes) {
        try serveWithPeriodicAutosave(
            &broker,
            listeners,
            io,
            persistence_path.?,
            config.autosave_interval,
        );
    } else {
        try broker.serveListeners(listeners);
    }
    if (persistence_path) |path| {
        try broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }
}

fn serveWithPeriodicAutosave(
    broker: *mqtt.broker.Broker,
    listeners: []const mqtt.broker.Listener,
    io: std.Io,
    persistence_path: []const u8,
    interval_seconds: u32,
) !void {
    const Result = union(enum) {
        serve: ?anyerror,
        timer: std.Io.Cancelable!void,
    };
    var result_buffer: [2]Result = undefined;
    var select: std.Io.Select(Result) = .init(io, &result_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.serve, serveResult, .{ broker, listeners });
    try select.concurrent(
        .timer,
        waitInterval,
        .{ io, std.Io.Clock.Duration{
            .raw = .fromSeconds(interval_seconds),
            .clock = .awake,
        } },
    );
    while (true) {
        switch (try select.await()) {
            .serve => |maybe_error| {
                select.cancelDiscard();
                if (maybe_error) |err| return err;
                return;
            },
            .timer => |result| {
                try result;
                broker.saveLiveSnapshot(
                    std.Io.Dir.cwd(),
                    persistence_path,
                ) catch |err| switch (err) {
                    error.SnapshotBusy => {},
                    else => return err,
                };
                try select.concurrent(
                    .timer,
                    waitInterval,
                    .{ io, std.Io.Clock.Duration{
                        .raw = .fromSeconds(interval_seconds),
                        .clock = .awake,
                    } },
                );
            },
        }
    }
}

fn serveResult(
    broker: *mqtt.broker.Broker,
    listeners: []const mqtt.broker.Listener,
) ?anyerror {
    broker.serveListeners(listeners) catch |err| return err;
    return null;
}

fn waitInterval(
    io: std.Io,
    interval: std.Io.Clock.Duration,
) std.Io.Cancelable!void {
    try interval.sleep(io);
}

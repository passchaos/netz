//! Runtime adapter for the broker example's strict Mosquitto-style config.
//!
//! Keeping listener construction here prevents the already feature-rich CLI
//! example from also owning heterogeneous transport lifetime bookkeeping.

const std = @import("std");
const builtin = @import("builtin");
const netz = @import("netz");
const reloadable_security = @import("support").mqtt_reloadable_security;
const reloadable_identity = @import("support").mqtt_reloadable_identity;
const configured_bridges = @import("support").mqtt_configured_bridges;
const reload_compatibility = @import("support").mqtt_reload_compatibility;
const MemoryLimiter = @import("support").memory_limiter.MemoryLimiter;
const mqtt_pid_file = @import("support").mqtt_pid_file;
const tls_ticket_keys = @import("support").mqtt_tls_ticket_keys;

const mqtt = netz.mqtt;

var checkpoint_requested: std.c.sig_atomic_t = 0;
var config_reload_requested: std.c.sig_atomic_t = 0;

/// Publish the production example's Mosquitto-compatible `memory_limit`
/// accounting as `$SYS/broker/heap/*`. The limiter's snapshot only performs
/// atomic loads, so it is safe under the broker's state mutex.
fn heapSnapshot(context: *anyopaque) mqtt.broker.HeapSnapshot {
    const limiter: *MemoryLimiter = @ptrCast(@alignCast(context));
    const value = limiter.snapshot();
    return .{
        .current_bytes = value.current_bytes,
        .maximum_bytes = value.peak_bytes,
    };
}

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
            &config_reload_requested,
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
            &config_reload_requested,
            0,
            .release,
        );
    }

    fn take() bool {
        return @atomicRmw(
            std.c.sig_atomic_t,
            &config_reload_requested,
            .Xchg,
            0,
            .acq_rel,
        ) != 0;
    }

    fn handle(_: std.posix.SIG) callconv(.c) void {
        // Loading, allocation, locks, and logging remain in the supervisor.
        @atomicStore(
            std.c.sig_atomic_t,
            &config_reload_requested,
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

pub const RunOptions = struct {
    /// Deterministic process-test lifecycle. Production config mode is a
    /// long-running supervisor and does not reinterpret listener limits as a
    /// cumulative accept count.
    finite_test: bool = false,
    /// Borrowed throughout continuous service, including management ticks.
    error_observer: ?mqtt.broker.ListenerErrorObserver = null,
    connection_end_observer: ?mqtt.broker.ListenerConnectionEndObserver = null,
};

const AutosavePolicy = union(enum) {
    disabled,
    periodic: u32,
    changes: u32,

    fn fromConfig(config: mqtt.broker_config.Config) AutosavePolicy {
        if (!config.persistence or config.autosave_interval == 0) {
            return .disabled;
        }
        return if (config.autosave_on_changes)
            .{ .changes = config.autosave_interval }
        else
            .{ .periodic = config.autosave_interval };
    }

    fn changeThreshold(self: AutosavePolicy) ?usize {
        return switch (self) {
            .changes => |value| value,
            .disabled, .periodic => null,
        };
    }

    fn intervalSeconds(self: AutosavePolicy) u32 {
        return switch (self) {
            .disabled => 0,
            .periodic, .changes => |value| value,
        };
    }

    fn name(self: AutosavePolicy) []const u8 {
        return switch (self) {
            .disabled => "disabled",
            .periodic => "time",
            .changes => "changes",
        };
    }
};

const PreparedAutosaveReload = struct {
    allocator: std.mem.Allocator,
    persistence_path: ?[]u8,
    broker_target: mqtt.broker.PreparedChangeAutosaveTarget,
    policy: AutosavePolicy,
    snapshot_required: bool,
    staged: bool = false,
    consumed: bool = false,

    fn deinit(self: *PreparedAutosaveReload) void {
        if (!self.consumed) {
            if (self.persistence_path) |path| self.allocator.free(path);
            self.broker_target.deinit();
        }
        self.persistence_path = null;
        self.consumed = true;
    }
};

const AutosaveController = struct {
    allocator: std.mem.Allocator,
    broker: *mqtt.broker.Broker,
    io: std.Io,
    persistence_path: ?[]u8,
    policy: AutosavePolicy,
    next_periodic_ns: ?i96,

    fn init(
        allocator: std.mem.Allocator,
        broker: *mqtt.broker.Broker,
        io: std.Io,
        persistence_path: ?[]const u8,
        policy: AutosavePolicy,
    ) std.mem.Allocator.Error!AutosaveController {
        var self = AutosaveController{
            .allocator = allocator,
            .broker = broker,
            .io = io,
            .persistence_path = if (persistence_path) |path|
                try allocator.dupe(u8, path)
            else
                null,
            .policy = policy,
            .next_periodic_ns = null,
        };
        self.resetPeriodicDeadline();
        return self;
    }

    fn deinit(self: *AutosaveController) void {
        if (self.persistence_path) |path| self.allocator.free(path);
        self.* = undefined;
    }

    fn prepareReload(
        self: *AutosaveController,
        persistence_path: ?[]const u8,
        policy: AutosavePolicy,
    ) mqtt.broker.Error!PreparedAutosaveReload {
        const broker_target = try self.broker
            .preparePersistentChangeAutosaveTarget(
            if (persistence_path) |path| .{
                .dir = std.Io.Dir.cwd(),
                .sub_path = path,
                .max_changes = @max(policy.intervalSeconds(), 1),
                .enabled = policy.changeThreshold() != null,
            } else null,
        );
        errdefer {
            var target = broker_target;
            target.deinit();
        }
        const owned_path = if (persistence_path) |path|
            try self.allocator.dupe(u8, path)
        else
            null;
        return .{
            .allocator = self.allocator,
            .persistence_path = owned_path,
            .broker_target = broker_target,
            .policy = policy,
            .snapshot_required = !optionalStringEqual(
                self.persistence_path,
                persistence_path,
            ) or (policy.changeThreshold() != null and
                self.policy.changeThreshold() == null),
        };
    }

    fn stageReload(
        self: *AutosaveController,
        prepared: *PreparedAutosaveReload,
    ) mqtt.broker.Error!void {
        if (prepared.snapshot_required) if (prepared.persistence_path) |path| {
            try self.broker.saveLiveSnapshot(std.Io.Dir.cwd(), path);
        };
        prepared.staged = true;
    }

    fn commitReload(
        self: *AutosaveController,
        prepared: *PreparedAutosaveReload,
    ) void {
        std.debug.assert(prepared.staged and !prepared.consumed);
        self.broker.commitPersistentChangeAutosaveTarget(
            &prepared.broker_target,
        );
        if (self.persistence_path) |path| self.allocator.free(path);
        self.persistence_path = prepared.persistence_path;
        prepared.persistence_path = null;
        self.policy = prepared.policy;
        self.resetPeriodicDeadline();
        prepared.consumed = true;
    }

    fn tick(self: *AutosaveController) !void {
        const deadline = self.next_periodic_ns orelse return;
        const now = std.Io.Clock.awake.now(self.io).nanoseconds;
        if (now < deadline) return;
        self.resetPeriodicDeadlineFrom(now);
        self.broker.saveLiveSnapshot(
            std.Io.Dir.cwd(),
            self.persistence_path orelse unreachable,
        ) catch |err| switch (err) {
            error.SnapshotBusy => {},
            else => return err,
        };
    }

    fn noteCheckpoint(self: *AutosaveController) void {
        self.resetPeriodicDeadline();
    }

    fn saveFinalSnapshot(self: *AutosaveController) !void {
        const path = self.persistence_path orelse return;
        try self.broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }

    fn resetPeriodicDeadline(self: *AutosaveController) void {
        self.resetPeriodicDeadlineFrom(
            std.Io.Clock.awake.now(self.io).nanoseconds,
        );
    }

    fn resetPeriodicDeadlineFrom(
        self: *AutosaveController,
        now_ns: i96,
    ) void {
        self.next_periodic_ns = switch (self.policy) {
            .periodic => |seconds| now_ns +| @as(i96, seconds) *
                std.time.ns_per_s,
            .disabled, .changes => null,
        };
    }
};

const ConfiguredUnixServer = struct {
    server: mqtt.runtime.UnixServer,
    io: std.Io,
    path: []const u8,

    fn deinit(self: *ConfiguredUnixServer) void {
        self.server.deinit();
        if (std.Io.Dir.path.isAbsolute(self.path)) {
            std.Io.Dir.deleteFileAbsolute(self.io, self.path) catch {};
        } else {
            std.Io.Dir.cwd().deleteFile(self.io, self.path) catch {};
        }
        self.* = undefined;
    }
};

const ConfiguredServer = union(enum) {
    mqtt: mqtt.runtime.Server,
    mqtt_unix: ConfiguredUnixServer,
    mqtt_tls: mqtt.tls_runtime.Server,
    websockets: mqtt.websocket_runtime.Server,
    secure_websockets: mqtt.websocket_runtime.TlsServer,

    fn deinit(self: *ConfiguredServer) void {
        switch (self.*) {
            .mqtt => |*server| server.deinit(),
            .mqtt_unix => |*server| server.deinit(),
            .mqtt_tls => |*server| server.deinit(),
            .websockets => |*server| server.deinit(),
            .secure_websockets => |*server| server.deinit(),
        }
        self.* = undefined;
    }

    fn pendingSource(self: *ConfiguredServer) mqtt.runtime.PendingSource {
        return switch (self.*) {
            .mqtt => |*server| server.pendingSource(),
            .mqtt_unix => |*server| server.server.pendingSource(),
            .mqtt_tls => |*server| server.pendingSource(),
            .websockets => |*server| server.pendingSource(),
            .secure_websockets => |*server| server.pendingSource(),
        };
    }

    fn address(self: ConfiguredServer) ?std.Io.net.IpAddress {
        return switch (self) {
            .mqtt => |server| server.address(),
            .mqtt_unix => null,
            .mqtt_tls => |server| server.address(),
            .websockets => |server| server.address(),
            .secure_websockets => |server| server.address(),
        };
    }

    fn transportName(self: ConfiguredServer) []const u8 {
        return switch (self) {
            .mqtt => "mqtt",
            .mqtt_unix => "mqtt-unix",
            .mqtt_tls => "mqtts",
            .websockets => "websockets",
            .secure_websockets => "wss",
        };
    }

    fn unixPath(self: ConfiguredServer) ?[]const u8 {
        return switch (self) {
            .mqtt_unix => |server| server.path,
            else => null,
        };
    }
};

fn openConfiguredUnixServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: mqtt.broker_config.Config,
    configured: mqtt.broker_config.Listener,
) !ConfiguredServer {
    const address = try std.Io.net.UnixAddress.init(configured.unix_path);
    return .{ .mqtt_unix = .{
        .server = try mqtt.runtime.UnixServer.listen(
            allocator,
            io,
            address,
            listenerLimits(config, configured),
        ),
        .io = io,
        .path = configured.unix_path,
    } };
}

fn openConfiguredServer(
    allocator: std.mem.Allocator,
    io: std.Io,
    config: mqtt.broker_config.Config,
    configured: mqtt.broker_config.Listener,
    identity: ?mqtt.tls_runtime.ServerIdentity,
    identity_provider: ?mqtt.tls_runtime.ServerIdentityProvider,
    client_auth: ?mqtt.tls_runtime.ClientAuthPolicy,
    session_tickets: tls_ticket_keys.Policies,
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
                .tls12_session_tickets = session_tickets.tls12,
                .tls13_session_tickets = session_tickets.tls13,
                .tls12_cipher_suites = if (configured.tls12_cipher_suites.len != 0)
                    configured.tls12_cipher_suites
                else
                    netz.tls.stream.default_tls12_cipher_suites,
                .cipher_suites = if (configured.tls13_cipher_suites.len != 0)
                    configured.tls13_cipher_suites
                else
                    netz.tls.stream.default_tls13_cipher_suites,
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
                    .tls12_session_tickets = session_tickets.tls12,
                    .tls13_session_tickets = session_tickets.tls13,
                    .tls12_cipher_suites = if (configured.tls12_cipher_suites.len != 0)
                        configured.tls12_cipher_suites
                    else
                        netz.tls.stream.default_tls12_cipher_suites,
                    .cipher_suites = if (configured.tls13_cipher_suites.len != 0)
                        configured.tls13_cipher_suites
                    else
                        netz.tls.stream.default_tls13_cipher_suites,
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
    std.debug.assert(!configured.isUnix());
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

fn listenerStableId(
    listener: mqtt.broker_config.Listener,
    listener_index: usize,
) u64 {
    return if (listener.isUnix())
        (@as(u64, 1) << 63) | @as(u64, @intCast(listener_index))
    else
        listener.address.getPort();
}

fn securityPathsForConfig(
    allocator: std.mem.Allocator,
    config: *const mqtt.broker_config.Config,
) std.mem.Allocator.Error![]reloadable_security.Paths {
    const count = if (config.per_listener_settings)
        config.listeners.len
    else
        1;
    const paths = try allocator.alloc(reloadable_security.Paths, count);
    for (paths, 0..) |*entry, index| {
        entry.* = if (config.per_listener_settings) .{
            .password_file = config.listeners[index].password_file,
            .acl_file = config.listeners[index].acl_file,
        } else .{
            .password_file = config.password_file,
            .acl_file = config.acl_file,
        };
    }
    return paths;
}

fn identityPathsForConfig(
    allocator: std.mem.Allocator,
    config: *const mqtt.broker_config.Config,
) std.mem.Allocator.Error![]reloadable_identity.Paths {
    const paths = try allocator.alloc(
        reloadable_identity.Paths,
        config.listeners.len,
    );
    for (config.listeners, paths) |configured, *entry| {
        entry.* = .{
            .certificate_file = configured.certfile,
            .private_key_file = configured.keyfile,
            .private_key_password_file = configured.keyfile_password_file,
            .client_ca_file = configured.cafile,
            .client_ca_path = configured.capath,
            .crl_file = configured.crlfile,
            .require_client_certificate = configured.require_certificate,
        };
    }
    return paths;
}

pub fn run(
    base_allocator: std.mem.Allocator,
    io: std.Io,
    config_path: []const u8,
    run_options: RunOptions,
) !void {
    var memory_limiter = MemoryLimiter.init(base_allocator, 0);
    const allocator = memory_limiter.allocator();
    var config = try mqtt.broker_config.load(
        allocator,
        io,
        std.Io.Dir.cwd(),
        config_path,
    );
    defer config.deinit(allocator);
    memory_limiter.setLimit(config.memory_limit);
    var pid_file = if (config.pid_file.len == 0)
        null
    else
        try mqtt_pid_file.PidFile.acquire(
            io,
            std.Io.Dir.cwd(),
            config.pid_file,
            mqtt_pid_file.currentProcessId(),
        );
    defer if (pid_file) |*owned| owned.deinit();

    const connection_count = try config.totalMaxConnections();
    const active_connection_limit = try config.activeConnectionLimit();
    const persistence_path = if (config.persistence)
        try config.persistencePath(allocator)
    else
        null;
    defer if (persistence_path) |path| allocator.free(path);

    const security_paths = try securityPathsForConfig(allocator, &config);
    defer allocator.free(security_paths);
    const listener_ids = try allocator.alloc(u64, config.listeners.len);
    defer allocator.free(listener_ids);
    const password_authentication = try allocator.alloc(
        bool,
        config.listeners.len,
    );
    defer allocator.free(password_authentication);
    const allow_anonymous = try allocator.alloc(bool, config.listeners.len);
    defer allocator.free(allow_anonymous);
    const admission_policies = try allocator.alloc(
        mqtt.broker.ListenerAdmissionSnapshot,
        config.listeners.len,
    );
    defer allocator.free(admission_policies);
    for (
        config.listeners,
        listener_ids,
        password_authentication,
        allow_anonymous,
        admission_policies,
        0..,
    ) |listener, *id, *uses_password, *anonymous, *admission, listener_index| {
        id.* = listenerStableId(listener, listener_index);
        uses_password.* = !listener.use_identity_as_username and
            !listener.use_subject_as_username;
        anonymous.* = listener.allow_anonymous;
        admission.* = try mqtt.broker.ListenerAdmissionSnapshot
            .initWithCapabilities(
            if (config.per_listener_settings)
                listener.allow_zero_length_client_id
            else
                config.allow_zero_length_client_id,
            config.autoIdPrefixForListener(listener),
            listener.maximum_qos,
            listener.maximum_keep_alive_seconds,
            listener.max_topic_alias,
            listener.max_topic_alias_broker,
            listener.accepted_protocol_versions,
        );
        admission.retain_available = config.retain_available;
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
    try security.setAllowAnonymous(allow_anonymous);
    try security.setAdmissionPolicies(admission_policies);
    const source_access_control = security.sourceAccessControl();
    const max_inflight_messages = config.effectiveMaxInflightMessages();
    const initial_scheduling_policy = runtimeSchedulingPolicyFromConfig(
        &config,
    );
    const initial_delivery_policy = runtimeDeliveryPolicyFromConfig(&config);
    const base_accept = mqtt.runtime.AcceptOptions{
        .protocol = .v5,
        .v3_1_connack_mode = .mosquitto,
        .max_outgoing_inflight = max_inflight_messages,
        .retain_available = config.retain_available,
        .allow_zero_length_client_id = config.allow_zero_length_client_id,
    };
    var broker = try mqtt.broker.Broker.init(allocator, io, .{
        .limits = .{
            .max_connections = active_connection_limit,
            .max_payload_size = initial_delivery_policy.max_payload_size,
            .runtime = .{ .max_packet_size = config.max_packet_size },
        },
        .max_inflight_payload_bytes_per_connection = config.max_inflight_bytes,
        .heap_source = .{
            .context = &memory_limiter,
            .snapshot_fn = heapSnapshot,
        },
        .accept = base_accept,
        .client_id_prefix = config.client_id_prefixes,
        .upgrade_outgoing_qos = initial_delivery_policy.upgrade_outgoing_qos,
        .queue_qos0_messages = initial_delivery_policy.queue_qos0_messages,
        .check_retain_source = initial_delivery_policy.check_retain_source,
        .persistent_session_expiry_seconds = initial_delivery_policy.persistent_session_expiry_seconds,
        .retained_expiry_interval = initial_scheduling_policy.retained_expiry_interval,
        .system_stats_interval = initial_scheduling_policy.system_stats_interval,
        .access_control = source_access_control,
        .session = .{
            .max_sessions = config.global_max_clients,
            .max_inflight_per_session = max_inflight_messages,
            .max_inflight_payload_bytes_per_session = config.max_inflight_bytes,
            .max_queued_per_session = config.effectiveMaxQueuedMessages(),
            .max_queued_payload_bytes_per_session = config.max_queued_bytes,
        },
        .persistent_change_autosave = if (config.persistence) .{
            .dir = std.Io.Dir.cwd(),
            .sub_path = persistence_path.?,
            .max_changes = @max(config.autosave_interval, 1),
            .enabled = config.autosave_on_changes and
                config.autosave_interval != 0,
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
        persistence_path,
    );
    defer bridges.deinit();
    var checkpoint_signal = CheckpointSignal.install();
    defer checkpoint_signal.deinit();
    const identity_paths = try identityPathsForConfig(allocator, &config);
    defer allocator.free(identity_paths);
    var identities = try reloadable_identity.Set.init(
        allocator,
        io,
        std.Io.Dir.cwd(),
        identity_paths,
        &security.lock,
    );
    defer identities.deinit();
    var ticket_keyrings = try tls_ticket_keys.Set.init(
        allocator,
        io,
        config.listeners,
    );
    defer ticket_keyrings.deinit();
    const supports_config_reload = builtin.os.tag == .linux;
    var reload_signal: ?ReloadSignal = if (supports_config_reload)
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
        accept.maximum_keep_alive_seconds =
            configured.maximum_keep_alive_seconds;
        accept.topic_alias_maximum = configured.max_topic_alias;
        accept.max_outgoing_topic_aliases =
            configured.max_topic_alias_broker;
        security_policies[config_index] = security.listenerPolicy(config_index);
        const admission_policy = security_policies[config_index]
            .admissionProvider();
        const listener_access_control = security_policies[config_index]
            .accessControl();
        const authorization = mqtt.broker.ListenerAuthorization{
            .connect = if (password_authentication[config_index]) .{
                .context = &security_policies[config_index],
                .authorize = reloadable_security.ListenerPolicy
                    .authorizeConnect,
            } else null,
            .access_control = listener_access_control,
            .use_username_as_client_id = configured.use_username_as_client_id,
            .use_identity_as_username = configured.use_identity_as_username,
            .use_subject_as_username = configured.use_subject_as_username,
            .retained_source_id = listenerStableId(
                configured,
                config_index,
            ),
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
        const session_tickets = ticket_keyrings.policies(
            config_index,
            configured,
        );
        const group_start = initialized_servers;
        var last_unavailable_error: ?anyerror = null;
        if (configured.isUnix()) {
            servers[initialized_servers] = try openConfiguredUnixServer(
                allocator,
                io,
                config,
                configured,
            );
            server_config_indices[initialized_servers] = config_index;
            initialized_servers += 1;
        } else {
            var bind_address_storage: [2]std.Io.net.IpAddress = undefined;
            const bind_addresses = try listenerBindAddresses(
                configured,
                &bind_address_storage,
            );
            for (bind_addresses) |bind_address| {
                servers[initialized_servers] = openConfiguredServer(
                    allocator,
                    io,
                    config,
                    configured,
                    identity,
                    identity_provider,
                    client_auth,
                    session_tickets,
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
                .admission_policy = admission_policy,
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
                .admission_policy = listeners[server_index].admission_policy,
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
            "netz MQTT 3.1/3.1.1/5 broker configured {d} listeners for {d} " ++
                "clients server_io=zio-std-io\n",
            .{ config.listeners.len, connection_count },
        );
    } else {
        std.debug.print(
            "netz MQTT 3.1/3.1.1/5 broker configured {d} listeners " ++
                "global_max_connections={d} server_io=zio-std-io\n",
            .{ config.listeners.len, active_connection_limit },
        );
    }
    for (active_servers, server_config_indices[0..initialized_servers]) |
        server,
        config_index,
    | {
        const configured = config.listeners[config_index];
        const mount_point = if (configured.mount_point.len == 0)
            "<global>"
        else
            configured.mount_point;
        if (server.unixPath()) |path| {
            std.debug.print(
                "  {s} {s} mount_point={s} max_connections={d}\n",
                .{
                    server.transportName(),
                    path,
                    mount_point,
                    configured.max_connections,
                },
            );
        } else {
            std.debug.print(
                "  {s} {f} mount_point={s} max_connections={d}\n",
                .{
                    server.transportName(),
                    server.address().?,
                    mount_point,
                    configured.max_connections,
                },
            );
        }
    }
    for (config.bridges) |bridge| {
        std.debug.print(
            "  bridge {s} remote={s}:{d} addresses={d} transport={s} " ++
                "rules={d} direction={s} start_type={s} reload_type={s}\n",
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
                @tagName(bridge.reload_type),
            },
        );
    }

    const service: Service = if (run_options.finite_test)
        .{ .finite = active_listeners }
    else
        .{ .continuous = .{
            .listeners = active_endpoints,
            .shutdown = &shutdown,
            .error_observer = run_options.error_observer,
            .connection_end_observer = run_options.connection_end_observer,
        } };
    var autosave = try AutosaveController.init(
        allocator,
        &broker,
        io,
        persistence_path,
        AutosavePolicy.fromConfig(config),
    );
    defer autosave.deinit();
    if (config.persistence or reload_signal != null or bridges.len() != 0) {
        try serveWithManagement(
            allocator,
            &memory_limiter,
            &broker,
            service,
            io,
            config_path,
            &config,
            &shutdown,
            &bridges,
            &autosave,
            &security,
            &identities,
        );
    } else {
        try serveConfigured(&broker, service);
    }
    bridges.disconnectLocalSources();
    try autosave.saveFinalSnapshot();
}

fn serveWithManagement(
    allocator: std.mem.Allocator,
    memory_limiter: *MemoryLimiter,
    broker: *mqtt.broker.Broker,
    service: Service,
    io: std.Io,
    config_path: []const u8,
    initial_config: *const mqtt.broker_config.Config,
    shutdown: *std.Io.Event,
    bridges: *configured_bridges.Set,
    autosave: *AutosaveController,
    security: *reloadable_security.Security,
    identities: *reloadable_identity.Set,
) !void {
    const Result = union(enum) {
        serve: ?anyerror,
        bridges: ?anyerror,
        management_tick: std.Io.Cancelable!void,
    };
    const result_buffer = try allocator.alloc(Result, 3);
    defer allocator.free(result_buffer);
    var select: std.Io.Select(Result) = .init(io, result_buffer);
    defer select.cancelDiscard();
    defer shutdown.set(io);
    defer bridges.requestStop();
    try select.concurrent(.serve, serveResult, .{ broker, service });
    try select.concurrent(.bridges, bridgeSetResult, .{bridges});
    if (builtin.os.tag == .linux or
        autosave.persistence_path != null)
    {
        try select.concurrent(
            .management_tick,
            waitInterval,
            .{ io, checkpoint_signal_poll_interval },
        );
    }
    while (true) {
        switch (try select.await()) {
            .serve => |maybe_error| {
                bridges.requestStop();
                shutdown.set(io);
                select.cancelDiscard();
                if (maybe_error) |err| return err;
                return;
            },
            .bridges => |maybe_error| {
                bridges.requestStop();
                shutdown.set(io);
                select.cancelDiscard();
                if (maybe_error) |err| return err;
                return error.UnexpectedBridgeExit;
            },
            .management_tick => |result| {
                try result;
                if (CheckpointSignal.take()) {
                    if (autosave.persistence_path) |path| {
                        broker.saveLiveSnapshot(
                            std.Io.Dir.cwd(),
                            path,
                        ) catch |err| switch (err) {
                            error.SnapshotBusy => CheckpointSignal.request(),
                            else => return err,
                        };
                        if (!CheckpointSignal.take()) {
                            autosave.noteCheckpoint();
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
                    } else {
                        std.debug.print(
                            "netz MQTT persistence checkpoint ignored: " ++
                                "persistence=disabled source=SIGUSR1 " ++
                                "server_io=zio-std-io\n",
                            .{},
                        );
                    }
                }
                if (ReloadSignal.take()) {
                    switch (reloadConfiguredState(
                        allocator,
                        memory_limiter,
                        io,
                        config_path,
                        initial_config,
                        broker,
                        bridges,
                        autosave,
                        security,
                        identities,
                    )) {
                        .failure => |failure| std.debug.print(
                            "netz MQTT {s} reload failed: " ++
                                "error={s} server_io=zio-std-io\n",
                            .{
                                @tagName(failure.component),
                                @errorName(failure.err),
                            },
                        ),
                        .success => |success| {
                            if (success.security_reloaded) {
                                std.debug.print(
                                    "netz MQTT security reload completed: " ++
                                        "source=SIGHUP server_io=zio-std-io\n",
                                    .{},
                                );
                            }
                            std.debug.print(
                                "netz MQTT bridge reload staged: " ++
                                    "source=SIGHUP server_io=zio-std-io\n",
                                .{},
                            );
                            std.debug.print(
                                "netz MQTT persistence target reload " ++
                                    "completed: enabled={} source=SIGHUP " ++
                                    "server_io=zio-std-io\n",
                                .{success.persistence_enabled},
                            );
                            if (autosave.persistence_path != null) {
                                std.debug.print(
                                    "netz MQTT persistence autosave reload " ++
                                        "completed: mode={s} interval={d} " ++
                                        "source=SIGHUP server_io=zio-std-io\n",
                                    .{
                                        success.autosave_policy.name(),
                                        success.autosave_policy.intervalSeconds(),
                                    },
                                );
                            }
                            std.debug.print(
                                "netz MQTT runtime scheduling reload " ++
                                    "completed: sys_interval={d} " ++
                                    "retain_expiry_interval={d} " ++
                                    "source=SIGHUP server_io=zio-std-io\n",
                                .{
                                    intervalSeconds(
                                        success.scheduling_policy
                                            .system_stats_interval,
                                    ),
                                    intervalSeconds(
                                        success.scheduling_policy
                                            .retained_expiry_interval,
                                    ),
                                },
                            );
                            std.debug.print(
                                "netz MQTT runtime delivery reload " ++
                                    "completed: message_size_limit={d} " ++
                                    "queue_qos0_messages={} " ++
                                    "upgrade_outgoing_qos={} " ++
                                    "check_retain_source={} " ++
                                    "persistent_client_expiration={d} " ++
                                    "source=SIGHUP server_io=zio-std-io\n",
                                .{
                                    success.delivery_policy.max_payload_size,
                                    success.delivery_policy
                                        .queue_qos0_messages,
                                    success.delivery_policy
                                        .upgrade_outgoing_qos,
                                    success.delivery_policy
                                        .check_retain_source,
                                    success.delivery_policy
                                        .persistent_session_expiry_seconds orelse 0,
                                },
                            );
                            std.debug.print(
                                "netz MQTT memory limit reload " ++
                                    "completed: bytes={d} source=SIGHUP " ++
                                    "server_io=zio-std-io\n",
                                .{success.memory_limit},
                            );
                            std.debug.print(
                                "netz MQTT Client ID prefix reload " ++
                                    "completed: length={d} source=SIGHUP " ++
                                    "server_io=zio-std-io\n",
                                .{success.required_client_id_prefix_length},
                            );
                        },
                    }
                }
                try autosave.tick();
                try select.concurrent(
                    .management_tick,
                    waitInterval,
                    .{ io, checkpoint_signal_poll_interval },
                );
            },
        }
    }
}

fn bridgeSetResult(bridges: *configured_bridges.Set) ?anyerror {
    bridges.runAll() catch |err| return err;
    return null;
}

fn bridgesUseQoS2(bridges: []const mqtt.broker_config.Bridge) bool {
    for (bridges) |bridge| {
        if (bridge.usesQoS2()) return true;
    }
    return false;
}

const ReloadComponent = enum {
    configuration,
    bridge,
    persistence,
    security,
};

const ReloadOutcome = union(enum) {
    success: struct {
        security_reloaded: bool,
        autosave_policy: AutosavePolicy,
        persistence_enabled: bool,
        scheduling_policy: mqtt.broker.RuntimeSchedulingPolicy,
        delivery_policy: mqtt.broker.RuntimeDeliveryPolicy,
        memory_limit: usize,
        required_client_id_prefix_length: usize,
    },
    failure: struct {
        component: ReloadComponent,
        err: anyerror,
    },
};

fn reloadConfiguredState(
    allocator: std.mem.Allocator,
    memory_limiter: *MemoryLimiter,
    io: std.Io,
    config_path: []const u8,
    initial_config: *const mqtt.broker_config.Config,
    broker: *mqtt.broker.Broker,
    bridges: *configured_bridges.Set,
    autosave: *AutosaveController,
    security: *reloadable_security.Security,
    identities: *reloadable_identity.Set,
) ReloadOutcome {
    var reloaded_config = mqtt.broker_config.load(
        allocator,
        io,
        std.Io.Dir.cwd(),
        config_path,
    ) catch |err| return .{ .failure = .{
        .component = .configuration,
        .err = err,
    } };
    defer reloaded_config.deinit(allocator);
    validateReloadableListenerTopology(
        initial_config,
        &reloaded_config,
    ) catch |err| return .{ .failure = .{
        .component = .configuration,
        .err = err,
    } };
    reload_compatibility.validateRestartRequiredGlobals(
        initial_config,
        &reloaded_config,
    ) catch |err| return .{ .failure = .{
        .component = .configuration,
        .err = err,
    } };
    const reloaded_security_paths = securityPathsForConfig(
        allocator,
        &reloaded_config,
    ) catch |err| return .{ .failure = .{
        .component = .security,
        .err = err,
    } };
    defer allocator.free(reloaded_security_paths);
    const reloaded_identity_paths = identityPathsForConfig(
        allocator,
        &reloaded_config,
    ) catch |err| return .{ .failure = .{
        .component = .security,
        .err = err,
    } };
    defer allocator.free(reloaded_identity_paths);
    var prepared_required_client_id_prefix =
        broker.prepareRequiredClientIdPrefix(
            reloaded_config.client_id_prefixes,
        ) catch |err| return .{ .failure = .{
            .component = .configuration,
            .err = err,
        } };
    defer prepared_required_client_id_prefix.deinit();
    const reloaded_allow_anonymous = allocator.alloc(
        bool,
        reloaded_config.listeners.len,
    ) catch |err| return .{ .failure = .{
        .component = .security,
        .err = err,
    } };
    defer allocator.free(reloaded_allow_anonymous);
    const reloaded_admission_policies = allocator.alloc(
        mqtt.broker.ListenerAdmissionSnapshot,
        reloaded_config.listeners.len,
    ) catch |err| return .{ .failure = .{
        .component = .security,
        .err = err,
    } };
    defer allocator.free(reloaded_admission_policies);
    for (reloaded_config.listeners, reloaded_allow_anonymous) |
        listener,
        *enabled,
    | {
        enabled.* = listener.allow_anonymous;
    }
    for (reloaded_config.listeners, reloaded_admission_policies) |
        listener,
        *admission,
    | {
        admission.* = mqtt.broker.ListenerAdmissionSnapshot
            .initWithCapabilities(
            if (reloaded_config.per_listener_settings)
                listener.allow_zero_length_client_id
            else
                reloaded_config.allow_zero_length_client_id,
            reloaded_config.autoIdPrefixForListener(listener),
            listener.maximum_qos,
            listener.maximum_keep_alive_seconds,
            listener.max_topic_alias,
            listener.max_topic_alias_broker,
            listener.accepted_protocol_versions,
        ) catch |err| return .{ .failure = .{
            .component = .security,
            .err = err,
        } };
        admission.retain_available = reloaded_config.retain_available;
    }
    const reloaded_persistence_path = if (reloaded_config.persistence)
        reloaded_config.persistencePath(allocator) catch |err|
            return .{ .failure = .{
                .component = .persistence,
                .err = err,
            } }
    else
        null;
    defer if (reloaded_persistence_path) |path| allocator.free(path);
    const persistence_target_changed = !optionalStringEqual(
        autosave.persistence_path,
        reloaded_persistence_path,
    );
    const commit_log_enabled = broker.commitLogEnabled();
    reload_compatibility.validatePersistenceTargetReload(
        persistence_target_changed,
        commit_log_enabled,
        bridgesUseQoS2(reloaded_config.bridges),
    ) catch |err| return .{ .failure = .{
        .component = .persistence,
        .err = err,
    } };
    const reloaded_autosave = AutosavePolicy.fromConfig(reloaded_config);
    var prepared_autosave = autosave.prepareReload(
        reloaded_persistence_path,
        reloaded_autosave,
    ) catch |err| return .{ .failure = .{
        .component = .persistence,
        .err = err,
    } };
    defer prepared_autosave.deinit();
    const reloaded_scheduling_policy = runtimeSchedulingPolicyFromConfig(
        &reloaded_config,
    );
    reloaded_scheduling_policy.validate() catch |err|
        return .{ .failure = .{
            .component = .configuration,
            .err = err,
        } };
    const reloaded_delivery_policy = runtimeDeliveryPolicyFromConfig(
        &reloaded_config,
    );
    reloaded_delivery_policy.validate() catch |err|
        return .{ .failure = .{
            .component = .configuration,
            .err = err,
        } };
    var prepared_bridges = bridges.prepareReload(
        reloaded_config.bridges,
    ) catch |err| return .{ .failure = .{
        .component = .bridge,
        .err = err,
    } };
    defer prepared_bridges.deinit();

    const policy = security;
    var prepared_security = policy.prepareReloadWithPaths(
        reloaded_security_paths,
    ) catch |err|
        return .{ .failure = .{
            .component = .security,
            .err = err,
        } };
    defer prepared_security.deinit();
    const identity_set = identities;
    var prepared_identities = identity_set.prepareReloadWithPaths(
        reloaded_identity_paths,
    ) catch |err|
        return .{ .failure = .{
            .component = .security,
            .err = err,
        } };
    defer prepared_identities.deinit();
    const bridge_commit = bridges.submitPreparedReload(
        &prepared_bridges,
    ) catch |err| return .{ .failure = .{
        .component = .bridge,
        .err = err,
    } };
    autosave.stageReload(&prepared_autosave) catch |err| {
        bridge_commit.abort();
        return .{ .failure = .{
            .component = .persistence,
            .err = err,
        } };
    };

    policy.lock.lockUncancelable(policy.io);
    var retired_security = policy.swapPreparedReload(&prepared_security);
    var retired_identities = identity_set.swapPreparedReload(
        &prepared_identities,
    );
    policy.setAllowAnonymousLocked(reloaded_allow_anonymous);
    policy.setAdmissionPoliciesLocked(reloaded_admission_policies);
    policy.lock.unlock(policy.io);
    const required_client_id_prefix_length =
        prepared_required_client_id_prefix.bytes.len;
    broker.commitRequiredClientIdPrefix(
        &prepared_required_client_id_prefix,
    );
    broker.setRuntimeSchedulingPolicy(
        reloaded_scheduling_policy,
    ) catch unreachable;
    broker.setRuntimeDeliveryPolicy(
        reloaded_delivery_policy,
    ) catch unreachable;
    memory_limiter.setLimit(reloaded_config.memory_limit);
    autosave.commitReload(&prepared_autosave);
    bridge_commit.commit();
    _ = broker.disconnectUnauthorizedConnections(.{
        .context = &retired_security,
        .still_authorized = reloadable_security.RetiredReload
            .stillAuthorizesConnection,
    });
    retired_security.deinit();
    retired_identities.deinit();
    return .{ .success = .{
        .security_reloaded = true,
        .autosave_policy = reloaded_autosave,
        .persistence_enabled = reloaded_persistence_path != null,
        .scheduling_policy = reloaded_scheduling_policy,
        .delivery_policy = reloaded_delivery_policy,
        .memory_limit = reloaded_config.memory_limit,
        .required_client_id_prefix_length = required_client_id_prefix_length,
    } };
}

fn runtimeDeliveryPolicyFromConfig(
    config: *const mqtt.broker_config.Config,
) mqtt.broker.RuntimeDeliveryPolicy {
    return .{
        .max_payload_size = config.message_size_limit,
        .queue_qos0_messages = config.queue_qos0_messages,
        .upgrade_outgoing_qos = config.upgrade_outgoing_qos,
        .check_retain_source = config.check_retain_source,
        .persistent_session_expiry_seconds = config.persistent_client_expiration_seconds,
    };
}

fn runtimeSchedulingPolicyFromConfig(
    config: *const mqtt.broker_config.Config,
) mqtt.broker.RuntimeSchedulingPolicy {
    return .{
        .retained_expiry_interval = if (config.retain_expiry_interval_seconds == 0)
            null
        else
            .fromSeconds(config.retain_expiry_interval_seconds),
        .system_stats_interval = if (config.sys_interval_seconds == 0)
            null
        else
            .fromSeconds(config.sys_interval_seconds),
    };
}

fn intervalSeconds(interval: ?std.Io.Duration) u64 {
    const value = interval orelse return 0;
    return @intCast(@divExact(value.nanoseconds, std.time.ns_per_s));
}

fn optionalStringEqual(a: ?[]const u8, b: ?[]const u8) bool {
    const left = a orelse return b == null;
    const right = b orelse return false;
    return std.mem.eql(u8, left, right);
}

fn validateReloadableListenerTopology(
    initial: *const mqtt.broker_config.Config,
    candidate: *const mqtt.broker_config.Config,
) !void {
    if (initial.per_listener_settings != candidate.per_listener_settings or
        initial.listeners.len != candidate.listeners.len)
    {
        return error.ListenerConfigurationRequiresRestart;
    }
    for (initial.listeners, candidate.listeners) |before, after| {
        if (!listenerReloadCompatible(before, after)) {
            return error.ListenerConfigurationRequiresRestart;
        }
    }
}

fn listenerReloadCompatible(
    before: mqtt.broker_config.Listener,
    after: mqtt.broker_config.Listener,
) bool {
    return std.meta.eql(before.address, after.address) and
        std.mem.eql(u8, before.unix_path, after.unix_path) and
        before.bind_all_socket_domains == after.bind_all_socket_domains and
        before.socket_domain == after.socket_domain and
        std.mem.eql(u8, before.bind_interface, after.bind_interface) and
        before.protocol == after.protocol and
        before.usesTls() == after.usesTls() and
        std.mem.eql(
            std.meta.Elem(@TypeOf(before.tls13_cipher_suites)),
            before.tls13_cipher_suites,
            after.tls13_cipher_suites,
        ) and
        std.mem.eql(
            std.meta.Elem(@TypeOf(before.tls12_cipher_suites)),
            before.tls12_cipher_suites,
            after.tls12_cipher_suites,
        ) and
        std.meta.eql(before.tls_protocol_policy, after.tls_protocol_policy) and
        before.tls12_session_tickets == after.tls12_session_tickets and
        std.mem.eql(
            u8,
            before.tls12_session_ticket_server_id,
            after.tls12_session_ticket_server_id,
        ) and
        before.tls12_session_ticket_lifetime_seconds ==
            after.tls12_session_ticket_lifetime_seconds and
        before.tls13_session_tickets == after.tls13_session_tickets and
        std.mem.eql(
            u8,
            before.tls13_session_ticket_server_id,
            after.tls13_session_ticket_server_id,
        ) and
        before.tls13_session_ticket_lifetime_seconds ==
            after.tls13_session_ticket_lifetime_seconds and
        before.use_identity_as_username == after.use_identity_as_username and
        before.use_subject_as_username == after.use_subject_as_username and
        std.mem.eql(u8, before.mount_point, after.mount_point) and
        equalStringLists(
            before.websocket_origins.items,
            after.websocket_origins.items,
        ) and
        before.proxy_protocol == after.proxy_protocol and
        before.proxy_protocol_v2_require_tls ==
            after.proxy_protocol_v2_require_tls and
        before.use_username_as_client_id == after.use_username_as_client_id and
        before.max_connections == after.max_connections;
}

fn equalStringLists(before: []const []u8, after: []const []u8) bool {
    if (before.len != after.len) return false;
    for (before, after) |left, right| {
        if (!std.mem.eql(u8, left, right)) return false;
    }
    return true;
}

const Service = union(enum) {
    finite: []const mqtt.broker.Listener,
    continuous: struct {
        listeners: []const mqtt.broker.ListenerEndpoint,
        shutdown: *std.Io.Event,
        error_observer: ?mqtt.broker.ListenerErrorObserver,
        connection_end_observer: ?mqtt.broker.ListenerConnectionEndObserver,
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
            .{ .shutdown = continuous.shutdown, .error_observer = continuous.error_observer, .connection_end_observer = continuous.connection_end_observer },
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

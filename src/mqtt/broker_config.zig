//! Strict Mosquitto-style configuration for the netz MQTT broker runtime.
//!
//! This module intentionally supports a documented subset. Unknown, duplicate,
//! or misplaced directives fail closed instead of silently weakening listener
//! authentication or resource policy.

const std = @import("std");
const test_tmp = @import("../internal/test_tmp_dir.zig");
const http1 = @import("../http1/mod.zig");
const mqtt = @import("mod.zig");
const bridge_config = @import("broker_config_bridge.zig");
const broker_config_include = @import("broker_config_include.zig");
const client_id = @import("broker/client_id.zig");
pub const tls_stream = @import("../tls/mod.zig").stream;
const tls_cipher_suites = @import("../tls/cipher_suites.zig");

const net = std.Io.net;

pub const max_config_bytes: usize = 1024 * 1024;
pub const default_max_connections: usize = 16;
pub const default_global_max_clients: usize = 16_384;
pub const default_global_max_connections: usize = std.math.maxInt(u31);
pub const default_max_packet_size: usize = 2_000_000;
pub const default_max_inflight_messages: u16 =
    bridge_config.default_receive_maximum;
pub const default_max_queued_messages: usize = 1_000;
pub const default_max_topic_aliases: u16 = 10;
pub const default_websocket_headers_size: u16 = 4096;
pub const default_sys_interval_seconds: u16 = 10;
pub const maximum_retain_expiry_interval_minutes: u32 = 10_000_000;
pub const default_auto_id_prefix = "auto-";
pub const default_persistence_file = "netz-mqtt.db";
pub const default_autosave_interval: u32 = 1800;
pub const default_tls12_session_ticket_lifetime_seconds: u32 = 24 * 60 * 60;
pub const default_tls13_session_ticket_lifetime_seconds: u32 = 24 * 60 * 60;

pub const Protocol = enum { mqtt, websockets };
pub const SocketDomain = enum { ipv4, ipv6 };
pub const Bridge = bridge_config.Bridge;
pub const BridgeRule = bridge_config.Rule;
pub const BridgeEndpoint = bridge_config.Endpoint;
pub const BridgeStartType = bridge_config.StartType;
pub const BridgeReloadType = bridge_config.ReloadType;
pub const BridgeDirection = bridge_config.Direction;

pub const Listener = struct {
    address: net.IpAddress = .{ .ip4 = .loopback(0) },
    /// Non-empty only for Mosquitto's `listener 0 PATH` Unix-domain form.
    /// `address` then carries a zero-port placeholder and must not be bound.
    unix_path: []u8 = &.{},
    /// An omitted bind address without `socket_domain` requests separate
    /// IPv4 and IPv6 wildcard sockets when both families are available.
    bind_all_socket_domains: bool = false,
    socket_domain: ?SocketDomain = null,
    bind_interface: []u8 = &.{},
    protocol: Protocol = .mqtt,
    password_file: []u8 = &.{},
    acl_file: []u8 = &.{},
    certfile: []u8 = &.{},
    keyfile: []u8 = &.{},
    keyfile_password_file: []u8 = &.{},
    cafile: []u8 = &.{},
    capath: []u8 = &.{},
    crlfile: []u8 = &.{},
    tls13_cipher_suites: []tls_cipher_suites.Suite = &.{},
    tls12_cipher_suites: []tls_cipher_suites.Tls12Suite = &.{},
    tls_protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    tls12_session_tickets: bool = false,
    tls12_session_ticket_server_id: []u8 = &.{},
    tls12_session_ticket_lifetime_seconds: u32 =
        default_tls12_session_ticket_lifetime_seconds,
    tls13_session_tickets: bool = false,
    tls13_session_ticket_server_id: []u8 = &.{},
    tls13_session_ticket_lifetime_seconds: u32 =
        default_tls13_session_ticket_lifetime_seconds,
    require_certificate: bool = false,
    use_identity_as_username: bool = false,
    use_subject_as_username: bool = false,
    mount_point: []u8 = &.{},
    allow_anonymous: bool = false,
    allow_zero_length_client_id: bool = true,
    auto_id_prefix: []u8 = &.{},
    maximum_qos: ?mqtt.QoS = null,
    maximum_keep_alive_seconds: ?u16 = null,
    max_topic_alias: u16 = default_max_topic_aliases,
    max_topic_alias_broker: u16 = default_max_topic_aliases,
    accepted_protocol_versions: mqtt.AcceptedProtocolVersions = .{},
    websocket_origins: std.ArrayList([]u8) = .empty,
    proxy_protocol: ?mqtt.proxy_protocol.Version = null,
    proxy_protocol_v2_require_tls: bool = false,
    use_username_as_client_id: bool = false,
    max_connections: usize = default_max_connections,

    fn deinit(self: *Listener, allocator: std.mem.Allocator) void {
        if (self.unix_path.len != 0) allocator.free(self.unix_path);
        if (self.password_file.len != 0) allocator.free(self.password_file);
        if (self.acl_file.len != 0) allocator.free(self.acl_file);
        if (self.bind_interface.len != 0) allocator.free(self.bind_interface);
        if (self.auto_id_prefix.len != 0) allocator.free(self.auto_id_prefix);
        if (self.certfile.len != 0) allocator.free(self.certfile);
        if (self.keyfile.len != 0) allocator.free(self.keyfile);
        if (self.keyfile_password_file.len != 0) {
            allocator.free(self.keyfile_password_file);
        }
        if (self.cafile.len != 0) allocator.free(self.cafile);
        if (self.capath.len != 0) allocator.free(self.capath);
        if (self.crlfile.len != 0) allocator.free(self.crlfile);
        if (self.tls13_cipher_suites.len != 0) {
            allocator.free(self.tls13_cipher_suites);
        }
        if (self.tls12_cipher_suites.len != 0) {
            allocator.free(self.tls12_cipher_suites);
        }
        if (self.tls12_session_ticket_server_id.len != 0) {
            allocator.free(self.tls12_session_ticket_server_id);
        }
        if (self.tls13_session_ticket_server_id.len != 0) {
            allocator.free(self.tls13_session_ticket_server_id);
        }
        if (self.mount_point.len != 0) allocator.free(self.mount_point);
        for (self.websocket_origins.items) |origin| allocator.free(origin);
        self.websocket_origins.deinit(allocator);
        self.* = undefined;
    }

    pub fn usesTls(self: Listener) bool {
        return self.certfile.len != 0;
    }

    pub fn isUnix(self: Listener) bool {
        return self.unix_path.len != 0;
    }
};

pub const Config = struct {
    listeners: []Listener,
    bridges: []Bridge = &.{},
    global_max_clients: usize = default_global_max_clients,
    global_max_connections: usize = default_global_max_connections,
    per_listener_settings: bool = false,
    /// Global anonymous-admission default. An explicit
    /// `listener_allow_anonymous` on a listener takes precedence.
    allow_anonymous: bool = false,
    password_file: []u8 = &.{},
    acl_file: []u8 = &.{},
    queue_qos0_messages: bool = false,
    upgrade_outgoing_qos: bool = false,
    max_packet_size: usize = default_max_packet_size,
    message_size_limit: usize = 0,
    max_inflight_messages: u16 = default_max_inflight_messages,
    max_inflight_bytes: usize = 0,
    max_queued_messages: usize = default_max_queued_messages,
    max_queued_bytes: usize = 0,
    /// Hard limit for broker-owned heap allocations. Zero means unlimited.
    memory_limit: usize = 0,
    /// Optional process-identification file held by the configured broker.
    /// The production runner keeps an exclusive advisory lock for its lifetime.
    pid_file: []u8 = &.{},
    retain_available: bool = true,
    check_retain_source: bool = true,
    client_id_prefixes: []u8 = &.{},
    allow_zero_length_client_id: bool = true,
    auto_id_prefix: []u8 = &.{},
    persistent_client_expiration_seconds: ?u32 = null,
    retain_expiry_interval_seconds: u32 = 0,
    sys_interval_seconds: u16 = default_sys_interval_seconds,
    websocket_headers_size: u16 = default_websocket_headers_size,
    set_tcp_nodelay: bool = false,
    persistence: bool = false,
    persistence_location: []u8 = &.{},
    persistence_file: []u8 = &.{},
    autosave_interval: u32 = default_autosave_interval,
    autosave_on_changes: bool = false,

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        for (self.listeners) |*listener| listener.deinit(allocator);
        allocator.free(self.listeners);
        for (self.bridges) |*bridge| bridge.deinit(allocator);
        if (self.bridges.len != 0) allocator.free(self.bridges);
        if (self.password_file.len != 0) allocator.free(self.password_file);
        if (self.acl_file.len != 0) allocator.free(self.acl_file);
        if (self.pid_file.len != 0) allocator.free(self.pid_file);
        if (self.client_id_prefixes.len != 0) {
            allocator.free(self.client_id_prefixes);
        }
        if (self.auto_id_prefix.len != 0) allocator.free(self.auto_id_prefix);
        if (self.persistence_location.len != 0) {
            allocator.free(self.persistence_location);
        }
        if (self.persistence_file.len != 0) {
            allocator.free(self.persistence_file);
        }
        self.* = undefined;
    }

    pub fn totalMaxConnections(self: Config) error{IntegerOverflow}!usize {
        var total: usize = 0;
        for (self.listeners) |listener| {
            total = std.math.add(usize, total, listener.max_connections) catch
                return error.IntegerOverflow;
        }
        return total;
    }

    /// Bound simultaneously admitted clients without changing each
    /// listener's finite accept budget.
    pub fn activeConnectionLimit(
        self: Config,
    ) error{IntegerOverflow}!usize {
        return @min(
            try self.totalMaxConnections(),
            self.global_max_connections,
        );
    }

    /// Convert Mosquitto's zero-as-unlimited configuration value into the
    /// largest window MQTT can represent on the wire.
    pub fn effectiveMaxInflightMessages(self: Config) u16 {
        return if (self.max_inflight_messages == 0)
            std.math.maxInt(u16)
        else
            self.max_inflight_messages;
    }

    /// Convert Mosquitto's zero-as-unlimited queue count into the unbounded
    /// value understood by the Session store.
    pub fn effectiveMaxQueuedMessages(self: Config) usize {
        return if (self.max_queued_messages == 0)
            std.math.maxInt(usize)
        else
            self.max_queued_messages;
    }

    pub fn autoIdPrefixForListener(
        self: Config,
        listener: Listener,
    ) []const u8 {
        if (listener.auto_id_prefix.len != 0) {
            return listener.auto_id_prefix;
        }
        if (!self.per_listener_settings and self.auto_id_prefix.len != 0) {
            return self.auto_id_prefix;
        }
        return default_auto_id_prefix;
    }

    /// Return an owned snapshot path using Mosquitto's location/file split.
    pub fn persistencePath(
        self: Config,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        const filename = if (self.persistence_file.len == 0)
            default_persistence_file
        else
            self.persistence_file;
        if (self.persistence_location.len == 0) {
            return allocator.dupe(u8, filename);
        }
        return std.fs.path.join(allocator, &.{
            self.persistence_location,
            filename,
        });
    }
};

pub const Error = mqtt.Error || net.IpAddress.ParseLiteralError || error{
    EmptyConfig,
    MissingListener,
    DirectiveRequiresListener,
    DuplicateDirective,
    UnsupportedDirective,
    UnsupportedTlsVersion,
    InvalidDirective,
    InvalidBoolean,
    InvalidInteger,
    DuplicateListener,
    PersistenceRequired,
    AuthenticationRequired,
    TlsIdentityIncomplete,
    ClientCertificateConfigurationIncomplete,
    InvalidSessionTicketConfiguration,
    CapathUnsupportedForWebSockets,
    DirectiveRequiresBridge,
    DuplicateBridge,
    DuplicateBridgeLocalClientId,
    IntegerOverflow,
} || bridge_config.Error || std.mem.Allocator.Error;

const ListenerSeen = struct {
    address_explicit: bool = false,
    password_file: bool = false,
    acl_file: bool = false,
    protocol: bool = false,
    socket_domain: bool = false,
    bind_interface: bool = false,
    certfile: bool = false,
    keyfile: bool = false,
    keyfile_password_file: bool = false,
    cafile: bool = false,
    capath: bool = false,
    crlfile: bool = false,
    ciphers_tls13: bool = false,
    ciphers: bool = false,
    tls_version: bool = false,
    tls12_session_tickets: bool = false,
    tls12_session_ticket_server_id: bool = false,
    tls12_session_ticket_lifetime: bool = false,
    tls13_session_tickets: bool = false,
    tls13_session_ticket_server_id: bool = false,
    tls13_session_ticket_lifetime: bool = false,
    require_certificate: bool = false,
    use_identity_as_username: bool = false,
    use_subject_as_username: bool = false,
    mount_point: bool = false,
    allow_anonymous: bool = false,
    allow_zero_length_client_id: bool = false,
    auto_id_prefix: bool = false,
    maximum_qos: bool = false,
    maximum_keep_alive: bool = false,
    max_topic_alias: bool = false,
    max_topic_alias_broker: bool = false,
    accept_protocol_versions: bool = false,
    enable_proxy_protocol: bool = false,
    proxy_protocol_v2_require_tls: bool = false,
    use_username_as_client_id: bool = false,
    max_connections: bool = false,
};

const GlobalSeen = struct {
    per_listener_settings: bool = false,
    global_max_clients: bool = false,
    global_max_connections: bool = false,
    allow_anonymous: bool = false,
    queue_qos0_messages: bool = false,
    upgrade_outgoing_qos: bool = false,
    password_file: bool = false,
    acl_file: bool = false,
    max_packet_size: bool = false,
    message_size_limit: bool = false,
    max_inflight_messages: bool = false,
    max_inflight_bytes: bool = false,
    max_queued_messages: bool = false,
    max_queued_bytes: bool = false,
    memory_limit: bool = false,
    pid_file: bool = false,
    retain_available: bool = false,
    check_retain_source: bool = false,
    client_id_prefixes: bool = false,
    allow_zero_length_client_id: bool = false,
    auto_id_prefix: bool = false,
    persistent_client_expiration: bool = false,
    retain_expiry_interval: bool = false,
    sys_interval: bool = false,
    websocket_header_limit: bool = false,
    set_tcp_nodelay: bool = false,
    persistence: bool = false,
    persistence_location: bool = false,
    persistence_file: bool = false,
    autosave_interval: bool = false,
    autosave_on_changes: bool = false,
};

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
) Error!Config {
    if (source.len == 0) return error.EmptyConfig;
    if (source.len > max_config_bytes) return error.InvalidDirective;
    return parseSources(allocator, &.{.{
        .bytes = source,
        .scope = 0,
    }}, 1);
}

fn parseSources(
    allocator: std.mem.Allocator,
    sources: []const broker_config_include.Source,
    scope_count: usize,
) Error!Config {
    var listeners: std.ArrayList(Listener) = .empty;
    errdefer {
        for (listeners.items) |*listener| listener.deinit(allocator);
        listeners.deinit(allocator);
    }
    var listener_seen: std.ArrayList(ListenerSeen) = .empty;
    defer listener_seen.deinit(allocator);
    var bridge_builders: std.ArrayList(bridge_config.Builder) = .empty;
    defer {
        for (bridge_builders.items) |*builder| builder.deinit(allocator);
        bridge_builders.deinit(allocator);
    }
    var config = Config{ .listeners = &.{} };
    errdefer {
        if (config.persistence_location.len != 0) {
            allocator.free(config.persistence_location);
        }
        if (config.persistence_file.len != 0) {
            allocator.free(config.persistence_file);
        }
        if (config.password_file.len != 0) {
            allocator.free(config.password_file);
        }
        if (config.acl_file.len != 0) allocator.free(config.acl_file);
        if (config.pid_file.len != 0) allocator.free(config.pid_file);
        if (config.client_id_prefixes.len != 0) {
            allocator.free(config.client_id_prefixes);
        }
        if (config.auto_id_prefix.len != 0) {
            allocator.free(config.auto_id_prefix);
        }
    }
    var global_seen: GlobalSeen = .{};
    var security_settings_seen = false;
    const current_listener = try allocator.alloc(?usize, scope_count);
    defer allocator.free(current_listener);
    @memset(current_listener, null);
    const current_bridge = try allocator.alloc(?usize, scope_count);
    defer allocator.free(current_bridge);
    @memset(current_bridge, null);

    for (sources) |source| {
        if (source.scope >= current_listener.len) return error.InvalidDirective;
        var lines = std.mem.splitScalar(u8, source.bytes, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0 or line[0] == '#') continue;
            var words = std.mem.tokenizeAny(u8, line, " \t");
            const directive = words.next().?;

            if (std.mem.eql(u8, directive, "listener")) {
                const port_text = words.next() orelse return error.InvalidDirective;
                const port = std.fmt.parseInt(u16, port_text, 10) catch
                    return error.InvalidInteger;
                const explicit_host = words.next();
                if (words.next() != null) return error.InvalidDirective;
                if (port == 0) {
                    const unix_path = explicit_host orelse
                        return error.InvalidDirective;
                    _ = net.UnixAddress.init(unix_path) catch
                        return error.InvalidDirective;
                    try listeners.append(allocator, .{
                        .address = .{ .ip4 = .loopback(0) },
                        .unix_path = try allocator.dupe(u8, unix_path),
                    });
                    try listener_seen.append(allocator, .{
                        .address_explicit = true,
                    });
                    current_listener[source.scope] = listeners.items.len - 1;
                    continue;
                }
                const host = explicit_host orelse "0.0.0.0";
                const address = net.IpAddress.parse(host, port) catch
                    return error.InvalidDirective;
                try listeners.append(allocator, .{
                    .address = address,
                    .bind_all_socket_domains = explicit_host == null,
                });
                try listener_seen.append(allocator, .{
                    .address_explicit = explicit_host != null,
                });
                current_listener[source.scope] = listeners.items.len - 1;
                continue;
            }

            if (std.mem.eql(u8, directive, "connection")) {
                const name = try parseOne(&words);
                for (bridge_builders.items) |existing| {
                    if (std.mem.eql(u8, existing.name, name)) {
                        return error.DuplicateBridge;
                    }
                }
                var builder = try bridge_config.Builder.init(allocator, name);
                errdefer builder.deinit(allocator);
                try bridge_builders.append(allocator, builder);
                current_bridge[source.scope] = bridge_builders.items.len - 1;
                continue;
            }

            if (bridge_config.isDirective(directive)) {
                const index = current_bridge[source.scope] orelse
                    return error.DirectiveRequiresBridge;
                try bridge_builders.items[index].apply(
                    allocator,
                    directive,
                    &words,
                );
                continue;
            }

            if (std.mem.eql(u8, directive, "global_max_clients")) {
                try markOnce(&global_seen.global_max_clients);
                config.global_max_clients = try parsePositiveOrUnlimited(&words);
            } else if (std.mem.eql(
                u8,
                directive,
                "global_max_connections",
            )) {
                try markOnce(&global_seen.global_max_connections);
                config.global_max_connections =
                    try parsePositiveOrUnlimited(&words);
            } else if (std.mem.eql(u8, directive, "per_listener_settings")) {
                try markOnce(&global_seen.per_listener_settings);
                const enabled = try parseOneBool(&words);
                if (enabled and security_settings_seen) {
                    return error.InvalidDirective;
                }
                config.per_listener_settings = enabled;
            } else if (std.mem.eql(u8, directive, "queue_qos0_messages")) {
                try markOnce(&global_seen.queue_qos0_messages);
                config.queue_qos0_messages = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "upgrade_outgoing_qos")) {
                try markOnce(&global_seen.upgrade_outgoing_qos);
                config.upgrade_outgoing_qos = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "allow_anonymous")) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(&listener_seen.items[index].allow_anonymous);
                    listeners.items[index].allow_anonymous =
                        try parseOneBool(&words);
                } else {
                    try markOnce(&global_seen.allow_anonymous);
                    config.allow_anonymous = try parseOneBool(&words);
                }
            } else if (std.mem.eql(u8, directive, "password_file")) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(&listener_seen.items[index].password_file);
                    listeners.items[index].password_file =
                        try parseOneOwned(allocator, &words);
                } else {
                    try markOnce(&global_seen.password_file);
                    config.password_file = try parseOneOwned(allocator, &words);
                }
            } else if (std.mem.eql(u8, directive, "acl_file")) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(&listener_seen.items[index].acl_file);
                    listeners.items[index].acl_file =
                        try parseOneOwned(allocator, &words);
                } else {
                    try markOnce(&global_seen.acl_file);
                    config.acl_file = try parseOneOwned(allocator, &words);
                }
            } else if (std.mem.eql(
                u8,
                directive,
                "allow_zero_length_clientid",
            )) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(
                        &listener_seen.items[index].allow_zero_length_client_id,
                    );
                    listeners.items[index].allow_zero_length_client_id =
                        try parseOneBool(&words);
                } else {
                    try markOnce(&global_seen.allow_zero_length_client_id);
                    config.allow_zero_length_client_id =
                        try parseOneBool(&words);
                }
            } else if (std.mem.eql(u8, directive, "auto_id_prefix")) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(&listener_seen.items[index].auto_id_prefix);
                    listeners.items[index].auto_id_prefix =
                        try parseAutoIdPrefix(allocator, &words);
                } else {
                    try markOnce(&global_seen.auto_id_prefix);
                    config.auto_id_prefix =
                        try parseAutoIdPrefix(allocator, &words);
                }
            } else if (std.mem.eql(u8, directive, "max_packet_size")) {
                try markOnce(&global_seen.max_packet_size);
                config.max_packet_size = try parseOneInteger(u31, &words);
                if (config.max_packet_size < 20) return error.InvalidInteger;
            } else if (std.mem.eql(u8, directive, "message_size_limit")) {
                try markOnce(&global_seen.message_size_limit);
                config.message_size_limit = try parseOneInteger(u28, &words);
            } else if (std.mem.eql(u8, directive, "max_inflight_messages")) {
                try markOnce(&global_seen.max_inflight_messages);
                config.max_inflight_messages = try parseOneInteger(u16, &words);
            } else if (std.mem.eql(u8, directive, "max_inflight_bytes")) {
                try markOnce(&global_seen.max_inflight_bytes);
                config.max_inflight_bytes = try parseOneInteger(u31, &words);
            } else if (std.mem.eql(u8, directive, "max_queued_messages")) {
                try markOnce(&global_seen.max_queued_messages);
                config.max_queued_messages = try parseOneInteger(u31, &words);
            } else if (std.mem.eql(u8, directive, "max_queued_bytes")) {
                try markOnce(&global_seen.max_queued_bytes);
                config.max_queued_bytes = try parseOneInteger(u31, &words);
            } else if (std.mem.eql(u8, directive, "memory_limit")) {
                try markOnce(&global_seen.memory_limit);
                config.memory_limit = try parseOneInteger(usize, &words);
            } else if (std.mem.eql(u8, directive, "pid_file")) {
                try markOnce(&global_seen.pid_file);
                config.pid_file = try parseOneOwned(allocator, &words);
            } else if (std.mem.eql(u8, directive, "retain_available")) {
                try markOnce(&global_seen.retain_available);
                config.retain_available = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "check_retain_source")) {
                try markOnce(&global_seen.check_retain_source);
                config.check_retain_source = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "clientid_prefixes")) {
                try markOnce(&global_seen.client_id_prefixes);
                config.client_id_prefixes = try parseClientIdPrefix(
                    allocator,
                    &words,
                );
            } else if (std.mem.eql(
                u8,
                directive,
                "persistent_client_expiration",
            )) {
                try markOnce(&global_seen.persistent_client_expiration);
                config.persistent_client_expiration_seconds =
                    try parseExpiration(&words);
            } else if (std.mem.eql(
                u8,
                directive,
                "retain_expiry_interval",
            )) {
                try markOnce(&global_seen.retain_expiry_interval);
                const minutes = try parseOnePositive(u32, &words);
                if (minutes > maximum_retain_expiry_interval_minutes) {
                    return error.InvalidInteger;
                }
                config.retain_expiry_interval_seconds =
                    minutes * std.time.s_per_min;
            } else if (std.mem.eql(u8, directive, "sys_interval")) {
                try markOnce(&global_seen.sys_interval);
                config.sys_interval_seconds =
                    try parseOneInteger(u16, &words);
            } else if (std.mem.eql(
                u8,
                directive,
                "websockets_headers_size",
            )) {
                try markOnce(&global_seen.websocket_header_limit);
                config.websocket_headers_size =
                    try parseOnePositive(u16, &words);
            } else if (std.mem.eql(u8, directive, "set_tcp_nodelay")) {
                try markOnce(&global_seen.set_tcp_nodelay);
                config.set_tcp_nodelay = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "persistence") or
                std.mem.eql(u8, directive, "retained_persistence"))
            {
                try markOnce(&global_seen.persistence);
                config.persistence = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "persistence_location")) {
                try markOnce(&global_seen.persistence_location);
                config.persistence_location = try parseOneOwned(
                    allocator,
                    &words,
                );
            } else if (std.mem.eql(u8, directive, "persistence_file")) {
                try markOnce(&global_seen.persistence_file);
                config.persistence_file = try parseOneOwned(allocator, &words);
                if (std.mem.indexOfAny(
                    u8,
                    config.persistence_file,
                    "/\\",
                ) != null) {
                    return error.InvalidDirective;
                }
            } else if (std.mem.eql(u8, directive, "autosave_interval")) {
                try markOnce(&global_seen.autosave_interval);
                config.autosave_interval = try parseOneInteger(u32, &words);
            } else if (std.mem.eql(u8, directive, "autosave_on_changes")) {
                try markOnce(&global_seen.autosave_on_changes);
                config.autosave_on_changes = try parseOneBool(&words);
            } else {
                const index = current_listener[source.scope] orelse {
                    return if (isListenerDirective(directive))
                        error.DirectiveRequiresListener
                    else
                        error.UnsupportedDirective;
                };
                const listener = &listeners.items[index];
                const seen = &listener_seen.items[index];
                if (std.mem.eql(u8, directive, "protocol")) {
                    try markOnce(&seen.protocol);
                    const value = try parseOne(&words);
                    listener.protocol = if (std.mem.eql(u8, value, "mqtt"))
                        .mqtt
                    else if (std.mem.eql(u8, value, "websockets"))
                        .websockets
                    else
                        return error.InvalidDirective;
                } else if (std.mem.eql(u8, directive, "socket_domain")) {
                    if (listener.isUnix()) return error.InvalidDirective;
                    try markOnce(&seen.socket_domain);
                    const value = try parseOne(&words);
                    listener.socket_domain = if (std.mem.eql(u8, value, "ipv4"))
                        .ipv4
                    else if (std.mem.eql(u8, value, "ipv6"))
                        .ipv6
                    else
                        return error.InvalidDirective;
                    listener.bind_all_socket_domains = false;
                    const port = listener.address.getPort();
                    if (!seen.address_explicit) {
                        listener.address = switch (listener.socket_domain.?) {
                            .ipv4 => .{ .ip4 = .unspecified(port) },
                            .ipv6 => .{ .ip6 = .unspecified(port) },
                        };
                    }
                } else if (std.mem.eql(u8, directive, "bind_interface")) {
                    if (listener.isUnix()) return error.InvalidDirective;
                    try markOnce(&seen.bind_interface);
                    listener.bind_interface = try parseOneOwned(
                        allocator,
                        &words,
                    );
                    listener.bind_all_socket_domains =
                        listener.socket_domain == null;
                } else if (std.mem.eql(u8, directive, "certfile")) {
                    try markOnce(&seen.certfile);
                    listener.certfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "keyfile")) {
                    try markOnce(&seen.keyfile);
                    listener.keyfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "keyfile_password_file",
                )) {
                    try markOnce(&seen.keyfile_password_file);
                    listener.keyfile_password_file = try parseOneOwned(
                        allocator,
                        &words,
                    );
                } else if (std.mem.eql(u8, directive, "cafile")) {
                    try markOnce(&seen.cafile);
                    listener.cafile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "capath")) {
                    try markOnce(&seen.capath);
                    listener.capath = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "crlfile")) {
                    try markOnce(&seen.crlfile);
                    listener.crlfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "ciphers_tls1.3")) {
                    try markOnce(&seen.ciphers_tls13);
                    listener.tls13_cipher_suites =
                        try tls_cipher_suites.parseOpenSslList(
                            allocator,
                            try parseOne(&words),
                        );
                } else if (std.mem.eql(u8, directive, "ciphers")) {
                    try markOnce(&seen.ciphers);
                    listener.tls12_cipher_suites =
                        try tls_cipher_suites.parseOpenSslTls12List(
                            allocator,
                            try parseOne(&words),
                        );
                } else if (std.mem.eql(u8, directive, "tls_version")) {
                    try markOnce(&seen.tls_version);
                    const value = try parseOne(&words);
                    listener.tls_protocol_policy = if (std.mem.eql(
                        u8,
                        value,
                        "tlsv1.3",
                    ))
                        .tls13_only
                    else if (std.mem.eql(u8, value, "tlsv1.2-only"))
                        .tls12_only
                    else if (std.mem.eql(u8, value, "tlsv1.2"))
                        .tls12_and_tls13
                    else
                        return error.UnsupportedTlsVersion;
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "tls12_session_tickets",
                )) {
                    try markOnce(&seen.tls12_session_tickets);
                    listener.tls12_session_tickets = try parseOneBool(&words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "tls12_session_ticket_server_id",
                )) {
                    try markOnce(&seen.tls12_session_ticket_server_id);
                    listener.tls12_session_ticket_server_id =
                        try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "tls12_session_ticket_lifetime",
                )) {
                    try markOnce(&seen.tls12_session_ticket_lifetime);
                    listener.tls12_session_ticket_lifetime_seconds =
                        try parseOnePositive(u32, &words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "tls13_session_tickets",
                )) {
                    try markOnce(&seen.tls13_session_tickets);
                    listener.tls13_session_tickets = try parseOneBool(&words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "tls13_session_ticket_server_id",
                )) {
                    try markOnce(&seen.tls13_session_ticket_server_id);
                    listener.tls13_session_ticket_server_id =
                        try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "tls13_session_ticket_lifetime",
                )) {
                    try markOnce(&seen.tls13_session_ticket_lifetime);
                    listener.tls13_session_ticket_lifetime_seconds =
                        try parseOnePositive(u32, &words);
                } else if (std.mem.eql(u8, directive, "require_certificate")) {
                    try markOnce(&seen.require_certificate);
                    listener.require_certificate = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "use_identity_as_username")) {
                    security_settings_seen = true;
                    try markOnce(&seen.use_identity_as_username);
                    listener.use_identity_as_username = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "use_subject_as_username")) {
                    security_settings_seen = true;
                    try markOnce(&seen.use_subject_as_username);
                    listener.use_subject_as_username = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "mount_point")) {
                    try markOnce(&seen.mount_point);
                    const value = try parseOne(&words);
                    _ = try mqtt.listener_namespace.Namespace.init(value);
                    listener.mount_point = try allocator.dupe(u8, value);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "listener_allow_anonymous",
                )) {
                    security_settings_seen = true;
                    try markOnce(&seen.allow_anonymous);
                    listener.allow_anonymous = try parseOneBool(&words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "listener_auto_id_prefix",
                )) {
                    security_settings_seen = true;
                    try markOnce(&seen.auto_id_prefix);
                    listener.auto_id_prefix =
                        try parseAutoIdPrefix(allocator, &words);
                } else if (std.mem.eql(u8, directive, "max_qos") or
                    std.mem.eql(u8, directive, "maximum_qos"))
                {
                    try markOnce(&seen.maximum_qos);
                    listener.maximum_qos = switch (try parseOneInteger(u2, &words)) {
                        0 => .at_most_once,
                        1 => .at_least_once,
                        2 => .exactly_once,
                        else => return error.InvalidInteger,
                    };
                } else if (std.mem.eql(u8, directive, "max_keepalive")) {
                    try markOnce(&seen.maximum_keep_alive);
                    const maximum = try parseOneInteger(u16, &words);
                    listener.maximum_keep_alive_seconds = if (maximum == 0)
                        null
                    else
                        maximum;
                } else if (std.mem.eql(u8, directive, "max_topic_alias")) {
                    try markOnce(&seen.max_topic_alias);
                    listener.max_topic_alias =
                        try parseOneInteger(u16, &words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "max_topic_alias_broker",
                )) {
                    try markOnce(&seen.max_topic_alias_broker);
                    listener.max_topic_alias_broker =
                        try parseOneInteger(u16, &words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "accept_protocol_versions",
                )) {
                    try markOnce(&seen.accept_protocol_versions);
                    listener.accepted_protocol_versions =
                        try parseAcceptedProtocolVersions(&words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "websockets_origin",
                )) {
                    const origin = try parseWebsocketOrigin(allocator, &words);
                    errdefer allocator.free(origin);
                    try listener.websocket_origins.append(allocator, origin);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "enable_proxy_protocol",
                )) {
                    try markOnce(&seen.enable_proxy_protocol);
                    listener.proxy_protocol = switch (try parseOneInteger(
                        u2,
                        &words,
                    )) {
                        1 => .v1,
                        2 => .v2,
                        else => return error.InvalidInteger,
                    };
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "proxy_protocol_v2_require_tls",
                )) {
                    try markOnce(&seen.proxy_protocol_v2_require_tls);
                    listener.proxy_protocol_v2_require_tls =
                        try parseOneBool(&words);
                } else if (std.mem.eql(
                    u8,
                    directive,
                    "use_username_as_clientid",
                )) {
                    try markOnce(&seen.use_username_as_client_id);
                    listener.use_username_as_client_id = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "max_connections")) {
                    try markOnce(&seen.max_connections);
                    listener.max_connections = try parseOnePositive(usize, &words);
                } else {
                    return error.UnsupportedDirective;
                }
            }
        }
    }

    if (listeners.items.len == 0) return error.MissingListener;
    if ((global_seen.persistence_location or
        global_seen.persistence_file or
        global_seen.autosave_interval or
        global_seen.autosave_on_changes) and !config.persistence)
    {
        return error.PersistenceRequired;
    }
    for (listeners.items, 0..) |listener, index| {
        for (listeners.items[0..index]) |previous| {
            if (listener.isUnix() or previous.isUnix()) {
                if (listener.isUnix() and previous.isUnix() and
                    std.mem.eql(u8, previous.unix_path, listener.unix_path))
                {
                    return error.DuplicateListener;
                }
            } else if (previous.bind_interface.len == 0 and
                listener.bind_interface.len == 0 and
                previous.address.eql(&listener.address))
            {
                return error.DuplicateListener;
            }
        }
    }
    for (listeners.items, listener_seen.items) |*listener, seen| {
        if (!config.per_listener_settings and !seen.allow_anonymous) {
            listener.allow_anonymous = config.allow_anonymous;
        }
        if (listener.isUnix() and
            (listener.protocol != .mqtt or
                listener.usesTls() or
                listener.socket_domain != null or
                listener.bind_interface.len != 0 or
                listener.websocket_origins.items.len != 0 or
                listener.proxy_protocol != null or
                seen.proxy_protocol_v2_require_tls or
                listener.require_certificate or
                listener.use_identity_as_username or
                listener.use_subject_as_username or
                listener.cafile.len != 0 or
                listener.capath.len != 0 or
                listener.crlfile.len != 0 or
                listener.tls12_session_tickets or
                listener.tls13_session_tickets))
        {
            return error.InvalidDirective;
        }
        if (listener.bind_interface.len == 0 and
            seen.address_explicit and
            listener.socket_domain != null)
        {
            switch (listener.socket_domain.?) {
                .ipv4 => if (listener.address != .ip4)
                    return error.InvalidDirective,
                .ipv6 => if (listener.address != .ip6)
                    return error.InvalidDirective,
            }
        }
        const has_client_ca = listener.cafile.len != 0 or
            listener.capath.len != 0;
        if ((listener.certfile.len == 0) != (listener.keyfile.len == 0)) {
            return error.TlsIdentityIncomplete;
        }
        if (listener.keyfile_password_file.len != 0 and
            listener.keyfile.len == 0)
        {
            return error.TlsIdentityIncomplete;
        }
        if ((seen.tls_version or
            listener.tls13_cipher_suites.len != 0 or
            listener.tls12_cipher_suites.len != 0) and
            !listener.usesTls())
        {
            return error.TlsIdentityIncomplete;
        }
        const tls12_ticket_parameters_seen =
            seen.tls12_session_ticket_server_id or
            seen.tls12_session_ticket_lifetime;
        const tls13_ticket_parameters_seen =
            seen.tls13_session_ticket_server_id or
            seen.tls13_session_ticket_lifetime;
        const ticket_alpn_len: usize = switch (listener.protocol) {
            .mqtt => "mqtt".len,
            .websockets => "http/1.1".len,
        };
        if ((tls12_ticket_parameters_seen and
            !listener.tls12_session_tickets) or
            (listener.tls12_session_tickets and
                (!listener.usesTls() or
                    !listener.tls_protocol_policy.offersTls12() or
                    has_client_ca or
                    listener.tls12_session_ticket_server_id.len == 0 or
                    listener.tls12_session_ticket_server_id.len +
                        3 + ticket_alpn_len > 512 or
                    listener.tls12_session_ticket_lifetime_seconds >
                        @import("vail").tls.tls12_ticket.max_lifetime_seconds)))
        {
            return error.InvalidSessionTicketConfiguration;
        }
        if ((tls13_ticket_parameters_seen and
            !listener.tls13_session_tickets) or
            (listener.tls13_session_tickets and
                (!listener.usesTls() or
                    !listener.tls_protocol_policy.offersTls13() or
                    has_client_ca or
                    listener.tls13_session_ticket_server_id.len == 0 or
                    listener.tls13_session_ticket_server_id.len +
                        3 + ticket_alpn_len > 512 or
                    listener.tls13_session_ticket_lifetime_seconds >
                        @import("vail").tls.ticket.max_lifetime_seconds)))
        {
            return error.InvalidSessionTicketConfiguration;
        }
        const proxy_v2 = listener.proxy_protocol == .v2;
        if (listener.require_certificate and
            !proxy_v2 and (!has_client_ca or !listener.usesTls()))
        {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if (has_client_ca and !listener.usesTls()) {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if (listener.capath.len != 0 and listener.protocol == .websockets) {
            return error.CapathUnsupportedForWebSockets;
        }
        if (listener.websocket_origins.items.len != 0 and
            listener.protocol != .websockets)
        {
            return error.InvalidDirective;
        }
        if (proxy_v2 and
            (listener.usesTls() or listener.use_subject_as_username))
        {
            return error.InvalidDirective;
        }
        if (seen.proxy_protocol_v2_require_tls and !proxy_v2) {
            return error.InvalidDirective;
        }
        if (listener.crlfile.len != 0 and !has_client_ca) {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if ((listener.use_identity_as_username or
            listener.use_subject_as_username) and
            !listener.require_certificate)
        {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if (config.client_id_prefixes.len != 0 and
            listener.use_username_as_client_id)
        {
            return error.InvalidDirective;
        }
    }
    const candidate = Config{ .listeners = listeners.items };
    _ = try candidate.totalMaxConnections();
    config.listeners = try listeners.toOwnedSlice(allocator);
    errdefer {
        for (config.listeners) |*listener| listener.deinit(allocator);
        allocator.free(config.listeners);
        config.listeners = &.{};
    }
    if (bridge_builders.items.len != 0) {
        config.bridges = try allocator.alloc(Bridge, bridge_builders.items.len);
        var initialized_bridges: usize = 0;
        errdefer {
            for (config.bridges[0..initialized_bridges]) |*bridge| {
                bridge.deinit(allocator);
            }
            allocator.free(config.bridges);
            config.bridges = &.{};
        }
        for (bridge_builders.items, config.bridges) |*builder, *bridge| {
            bridge.* = try builder.finish(
                allocator,
                config.persistence,
                config.max_queued_messages,
                config.effectiveMaxInflightMessages(),
            );
            initialized_bridges += 1;
            if (bridge.hasOutbound()) {
                for (config.bridges[0 .. initialized_bridges - 1]) |previous| {
                    if (previous.hasOutbound() and std.mem.eql(
                        u8,
                        previous.localClientId(),
                        bridge.localClientId(),
                    )) return error.DuplicateBridgeLocalClientId;
                }
            }
        }
    }
    return config;
}

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) (Error || broker_config_include.Error || std.Io.Dir.OpenError ||
    std.Io.Dir.Iterator.Error || std.Io.Dir.StatFileError ||
    std.Io.Dir.ReadFileAllocError)!Config {
    var document = try broker_config_include.load(
        allocator,
        io,
        dir,
        sub_path,
    );
    defer document.deinit();
    return parseSources(allocator, document.sources, document.scope_count);
}

fn markOnce(flag: *bool) error{DuplicateDirective}!void {
    if (flag.*) return error.DuplicateDirective;
    flag.* = true;
}

fn isListenerDirective(value: []const u8) bool {
    return std.mem.eql(u8, value, "protocol") or
        std.mem.eql(u8, value, "socket_domain") or
        std.mem.eql(u8, value, "bind_interface") or
        std.mem.eql(u8, value, "certfile") or
        std.mem.eql(u8, value, "keyfile") or
        std.mem.eql(u8, value, "keyfile_password_file") or
        std.mem.eql(u8, value, "cafile") or
        std.mem.eql(u8, value, "capath") or
        std.mem.eql(u8, value, "crlfile") or
        std.mem.eql(u8, value, "ciphers_tls1.3") or
        std.mem.eql(u8, value, "ciphers") or
        std.mem.eql(u8, value, "tls_version") or
        std.mem.eql(u8, value, "tls12_session_tickets") or
        std.mem.eql(u8, value, "tls12_session_ticket_server_id") or
        std.mem.eql(u8, value, "tls12_session_ticket_lifetime") or
        std.mem.eql(u8, value, "tls13_session_tickets") or
        std.mem.eql(u8, value, "tls13_session_ticket_server_id") or
        std.mem.eql(u8, value, "tls13_session_ticket_lifetime") or
        std.mem.eql(u8, value, "require_certificate") or
        std.mem.eql(u8, value, "use_identity_as_username") or
        std.mem.eql(u8, value, "use_subject_as_username") or
        std.mem.eql(u8, value, "mount_point") or
        std.mem.eql(u8, value, "listener_allow_anonymous") or
        std.mem.eql(u8, value, "listener_auto_id_prefix") or
        std.mem.eql(u8, value, "max_qos") or
        std.mem.eql(u8, value, "maximum_qos") or
        std.mem.eql(u8, value, "max_keepalive") or
        std.mem.eql(u8, value, "max_topic_alias") or
        std.mem.eql(u8, value, "max_topic_alias_broker") or
        std.mem.eql(u8, value, "accept_protocol_versions") or
        std.mem.eql(u8, value, "websockets_origin") or
        std.mem.eql(u8, value, "enable_proxy_protocol") or
        std.mem.eql(u8, value, "proxy_protocol_v2_require_tls") or
        std.mem.eql(u8, value, "use_username_as_clientid") or
        std.mem.eql(u8, value, "max_connections");
}

fn parseOne(words: anytype) error{InvalidDirective}![]const u8 {
    const value = words.next() orelse return error.InvalidDirective;
    if (words.next() != null) return error.InvalidDirective;
    return value;
}

fn parseOneOwned(
    allocator: std.mem.Allocator,
    words: anytype,
) (error{InvalidDirective} || std.mem.Allocator.Error)![]u8 {
    return allocator.dupe(u8, try parseOne(words));
}

fn parseAutoIdPrefix(
    allocator: std.mem.Allocator,
    words: anytype,
) (Error || std.mem.Allocator.Error)![]u8 {
    const value = try parseOne(words);
    if (value.len > client_id.max_prefix_len) return error.InvalidDirective;
    try mqtt.validateUtf8String(value);
    return allocator.dupe(u8, value);
}

fn parseClientIdPrefix(
    allocator: std.mem.Allocator,
    words: anytype,
) (Error || std.mem.Allocator.Error)![]u8 {
    const value = try parseOne(words);
    if (value.len > std.math.maxInt(u16)) return error.InvalidDirective;
    try mqtt.validateUtf8String(value);
    return allocator.dupe(u8, value);
}

fn parseWebsocketOrigin(
    allocator: std.mem.Allocator,
    words: anytype,
) (error{InvalidDirective} || std.mem.Allocator.Error)![]u8 {
    const value = try parseOne(words);
    http1.validateHeader(.{
        .name = "Origin",
        .value = value,
    }) catch return error.InvalidDirective;
    return allocator.dupe(u8, value);
}

fn parseOneBool(words: anytype) error{ InvalidDirective, InvalidBoolean }!bool {
    const value = try parseOne(words);
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBoolean;
}

fn parseOneInteger(
    comptime T: type,
    words: anytype,
) error{ InvalidDirective, InvalidInteger }!T {
    const value = try parseOne(words);
    return std.fmt.parseInt(T, value, 10) catch error.InvalidInteger;
}

fn parseOnePositive(
    comptime T: type,
    words: anytype,
) error{ InvalidDirective, InvalidInteger }!T {
    const value = try parseOneInteger(T, words);
    if (value == 0) return error.InvalidInteger;
    return value;
}

fn parsePositiveOrUnlimited(words: anytype) error{
    InvalidDirective,
    InvalidInteger,
}!usize {
    const value = try parseOne(words);
    if (std.mem.eql(u8, value, "-1")) return std.math.maxInt(u31);
    return @intCast(try parsePositiveText(u31, value));
}

fn parsePositiveText(
    comptime T: type,
    value: []const u8,
) error{InvalidInteger}!T {
    const parsed = std.fmt.parseInt(T, value, 10) catch
        return error.InvalidInteger;
    if (parsed == 0) return error.InvalidInteger;
    return parsed;
}

fn parseAcceptedProtocolVersions(
    words: anytype,
) error{ InvalidDirective, InvalidInteger }!mqtt.AcceptedProtocolVersions {
    var result = mqtt.AcceptedProtocolVersions{
        .v3_1 = false,
        .v3_1_1 = false,
        .v5 = false,
    };
    var saw_version = false;
    while (words.next()) |word| {
        var versions = std.mem.splitScalar(u8, word, ',');
        while (versions.next()) |version| {
            if (version.len == 0) continue;
            saw_version = true;
            if (std.mem.eql(u8, version, "3")) {
                if (result.v3_1) return error.InvalidInteger;
                result.v3_1 = true;
            } else if (std.mem.eql(u8, version, "4")) {
                if (result.v3_1_1) return error.InvalidInteger;
                result.v3_1_1 = true;
            } else if (std.mem.eql(u8, version, "5")) {
                if (result.v5) return error.InvalidInteger;
                result.v5 = true;
            } else return error.InvalidInteger;
        }
    }
    if (!saw_version) return error.InvalidDirective;
    return result;
}

fn parseExpiration(
    words: anytype,
) error{ InvalidDirective, InvalidInteger }!u32 {
    const value = try parseOne(words);
    if (value.len < 2) return error.InvalidInteger;
    const multiplier: u32 = switch (value[value.len - 1]) {
        's' => 1,
        'h' => 60 * 60,
        'd' => 24 * 60 * 60,
        'w' => 7 * 24 * 60 * 60,
        'm' => 30 * 24 * 60 * 60,
        'y' => 365 * 24 * 60 * 60,
        else => return error.InvalidInteger,
    };
    const amount = std.fmt.parseInt(
        u32,
        value[0 .. value.len - 1],
        10,
    ) catch return error.InvalidInteger;
    if (amount == 0) return error.InvalidInteger;
    return std.math.mul(u32, amount, multiplier) catch
        error.InvalidInteger;
}

pub fn testBridgeConfigAllocationFailures(allocator: std.mem.Allocator) !void {
    var config = try parse(allocator,
        \\persistence true
        \\listener 1883 127.0.0.1
        \\listener_allow_anonymous true
        \\connection allocation-test
        \\addresses broker.example:2883 backup.example:3883
        \\round_robin true
        \\topic sensors/# in 1 local/ remote/
        \\topic commands/# in 2 command/ upstream/
        \\clientid allocation-bridge
        \\username user
        \\password secret
        \\bridge_cafile roots.pem
        \\bridge_capath roots.d
        \\bridge_certfile client.pem
        \\bridge_keyfile client.key
        \\bridge_keyfile_password_file client.password
        \\bridge_alpn mqtt
        \\bridge_tls_version tlsv1.3
        \\notification_topic bridge/allocation/state
    );
    defer config.deinit(allocator);
}

test {
    _ = @import("broker_config/tests.zig");
}

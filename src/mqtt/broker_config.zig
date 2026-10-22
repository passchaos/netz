//! Strict Mosquitto-style configuration for the netz MQTT broker runtime.
//!
//! This module intentionally supports a documented subset. Unknown, duplicate,
//! or misplaced directives fail closed instead of silently weakening listener
//! authentication or resource policy.

const std = @import("std");
const http1 = @import("../http1/mod.zig");
const mqtt = @import("mod.zig");
const bridge_config = @import("broker_config_bridge.zig");
const broker_config_include = @import("broker_config_include.zig");
const client_id = @import("broker/client_id.zig");
const tls_stream = @import("../tls/mod.zig").stream;
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
            } else if (std.mem.eql(u8, directive, "persistence")) {
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

test "MQTT broker config parses owned multi-listener policy" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\# strict supported subset
        \\global_max_clients 128
        \\global_max_connections 5
        \\queue_qos0_messages true
        \\upgrade_outgoing_qos true
        \\max_packet_size 2000000
        \\message_size_limit 1048576
        \\max_inflight_messages 7
        \\max_inflight_bytes 2048
        \\max_queued_messages 23
        \\max_queued_bytes 4096
        \\memory_limit 16777216
        \\pid_file run/netz-mqtt.pid
        \\retain_available false
        \\check_retain_source false
        \\allow_zero_length_clientid false
        \\auto_id_prefix assigned-
        \\persistent_client_expiration 2h
        \\retain_expiry_interval 37
        \\sys_interval 17
        \\websockets_headers_size 8192
        \\set_tcp_nodelay true
        \\password_file users.pw
        \\acl_file access.acl
        \\persistence true
        \\persistence_location state
        \\persistence_file broker.db
        \\autosave_interval 17
        \\autosave_on_changes true
        \\listener 1883 127.0.0.1
        \\listener_allow_anonymous true
        \\enable_proxy_protocol 1
        \\maximum_qos 1
        \\max_keepalive 30
        \\max_topic_alias 7
        \\max_topic_alias_broker 9
        \\accept_protocol_versions 5
        \\max_connections 4
        \\listener 8080 ::1
        \\websockets_origin https://console.example
        \\websockets_origin null
        \\protocol websockets
        \\certfile server-chain.pem
        \\keyfile server-key.pem
        \\keyfile_password_file server-key.password
        \\ciphers_tls1.3 TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384
        \\cafile client-ca.pem
        \\crlfile clients.crl
        \\require_certificate true
        \\use_identity_as_username true
        \\use_subject_as_username true
        \\mount_point tenant/
        \\listener_allow_anonymous false
        \\use_username_as_clientid true
        \\max_connections 2
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 128), config.global_max_clients);
    try std.testing.expectEqual(@as(usize, 5), config.global_max_connections);
    try std.testing.expect(config.queue_qos0_messages);
    try std.testing.expect(config.upgrade_outgoing_qos);
    try std.testing.expectEqual(@as(usize, 2_000_000), config.max_packet_size);
    try std.testing.expectEqual(@as(usize, 1_048_576), config.message_size_limit);
    try std.testing.expectEqual(@as(u16, 7), config.max_inflight_messages);
    try std.testing.expectEqual(@as(u16, 7), config.effectiveMaxInflightMessages());
    try std.testing.expectEqual(@as(usize, 2048), config.max_inflight_bytes);
    try std.testing.expectEqual(@as(usize, 23), config.max_queued_messages);
    try std.testing.expectEqual(@as(usize, 23), config.effectiveMaxQueuedMessages());
    try std.testing.expectEqual(@as(usize, 4096), config.max_queued_bytes);
    try std.testing.expectEqual(@as(usize, 16 * 1024 * 1024), config.memory_limit);
    try std.testing.expectEqualStrings("run/netz-mqtt.pid", config.pid_file);
    try std.testing.expect(!config.retain_available);
    try std.testing.expect(!config.check_retain_source);
    try std.testing.expect(!config.allow_zero_length_client_id);
    try std.testing.expectEqualStrings("assigned-", config.auto_id_prefix);
    try std.testing.expectEqual(
        @as(?u32, 2 * 60 * 60),
        config.persistent_client_expiration_seconds,
    );
    try std.testing.expectEqual(
        @as(u32, 37 * std.time.s_per_min),
        config.retain_expiry_interval_seconds,
    );
    try std.testing.expectEqual(@as(u16, 17), config.sys_interval_seconds);
    try std.testing.expectEqual(@as(u16, 8192), config.websocket_headers_size);
    try std.testing.expect(config.set_tcp_nodelay);
    try std.testing.expect(!config.per_listener_settings);
    try std.testing.expectEqualStrings("users.pw", config.password_file);
    try std.testing.expectEqualStrings("access.acl", config.acl_file);
    try std.testing.expect(config.persistence);
    try std.testing.expect(config.autosave_on_changes);
    try std.testing.expectEqual(@as(u32, 17), config.autosave_interval);
    try std.testing.expectEqual(@as(usize, 6), try config.totalMaxConnections());
    try std.testing.expectEqual(@as(usize, 5), try config.activeConnectionLimit());
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expect(config.listeners[0].protocol == .mqtt);
    try std.testing.expect(config.listeners[0].allow_anonymous);
    try std.testing.expectEqual(
        mqtt.proxy_protocol.Version.v1,
        config.listeners[0].proxy_protocol.?,
    );
    try std.testing.expect(config.listeners[0].password_file.len == 0);
    try std.testing.expect(config.listeners[0].acl_file.len == 0);
    try std.testing.expect(config.listeners[0].maximum_qos.? == .at_least_once);
    try std.testing.expectEqual(@as(?u16, 30), config.listeners[0].maximum_keep_alive_seconds);
    try std.testing.expectEqual(@as(u16, 7), config.listeners[0].max_topic_alias);
    try std.testing.expectEqual(
        @as(u16, 9),
        config.listeners[0].max_topic_alias_broker,
    );
    try std.testing.expect(!config.listeners[0].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(config.listeners[0].accepted_protocol_versions.v5);
    try std.testing.expect(config.listeners[1].protocol == .websockets);
    try std.testing.expectEqual(
        @as(usize, 2),
        config.listeners[1].websocket_origins.items.len,
    );
    try std.testing.expectEqualStrings(
        "https://console.example",
        config.listeners[1].websocket_origins.items[0],
    );
    try std.testing.expectEqualStrings(
        "null",
        config.listeners[1].websocket_origins.items[1],
    );
    try std.testing.expect(config.listeners[1].usesTls());
    try std.testing.expectEqualStrings(
        "server-chain.pem",
        config.listeners[1].certfile,
    );
    try std.testing.expectEqualStrings(
        "server-key.pem",
        config.listeners[1].keyfile,
    );
    try std.testing.expectEqualStrings(
        "server-key.password",
        config.listeners[1].keyfile_password_file,
    );
    try std.testing.expectEqualSlices(
        tls_cipher_suites.Suite,
        &.{ .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
        config.listeners[1].tls13_cipher_suites,
    );
    try std.testing.expectEqualStrings(
        "client-ca.pem",
        config.listeners[1].cafile,
    );
    try std.testing.expectEqualStrings(
        "clients.crl",
        config.listeners[1].crlfile,
    );
    try std.testing.expect(config.listeners[1].require_certificate);
    try std.testing.expect(config.listeners[1].use_identity_as_username);
    try std.testing.expect(config.listeners[1].use_subject_as_username);
    try std.testing.expectEqualStrings("tenant/", config.listeners[1].mount_point);
    try std.testing.expect(config.listeners[1].use_username_as_client_id);
    try std.testing.expectEqualStrings(
        "assigned-",
        config.autoIdPrefixForListener(config.listeners[1]),
    );
    try std.testing.expectEqual(
        default_max_topic_aliases,
        config.listeners[1].max_topic_alias,
    );
    try std.testing.expectEqual(
        default_max_topic_aliases,
        config.listeners[1].max_topic_alias_broker,
    );
    const path = try config.persistencePath(allocator);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("state/broker.db", path);
}

test "MQTT broker config owns global Client Identifier prefix policy" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "clientid_prefixes secure-\n" ++
            "listener 1883\nlistener_allow_anonymous true",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');
    try std.testing.expectEqualStrings("secure-", config.client_id_prefixes);

    try std.testing.expectError(
        error.InvalidUtf8,
        parse(
            allocator,
            "clientid_prefixes bad\x00prefix\n" ++
                "listener 1883\nlistener_allow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "clientid_prefixes first-\nclientid_prefixes second-\n" ++
                "listener 1883\nlistener_allow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "clientid_prefixes secure-\nlistener 1883\n" ++
                "listener_allow_anonymous true\nuse_username_as_clientid true",
        ),
    );
}

test "MQTT broker config owns Mosquitto Unix listener paths" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "listener 0 /tmp/netz-mqtt.sock\nlistener_allow_anonymous true",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expectEqual(@as(usize, 1), config.listeners.len);
    try std.testing.expect(config.listeners[0].isUnix());
    try std.testing.expectEqualStrings(
        "/tmp/netz-mqtt.sock",
        config.listeners[0].unix_path,
    );
    try std.testing.expectEqual(
        @as(u16, 0),
        config.listeners[0].address.getPort(),
    );
    try std.testing.expect(!config.listeners[0].bind_all_socket_domains);
}

test "MQTT broker config validates Unix listener topology" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, "listener 0\nlistener_allow_anonymous true"),
    );
    try std.testing.expectError(
        error.DuplicateListener,
        parse(allocator,
            \\listener 0 /tmp/duplicate.sock
            \\listener_allow_anonymous true
            \\listener 0 /tmp/duplicate.sock
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 0 /tmp/websocket.sock
            \\protocol websockets
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 0 /tmp/domain.sock
            \\socket_domain ipv4
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 0 /tmp/proxy.sock
            \\enable_proxy_protocol 1
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config scopes socket domains to listeners" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 1883
        \\socket_domain ipv4
        \\listener_allow_anonymous true
        \\listener 1883
        \\socket_domain ipv6
        \\listener_allow_anonymous true
        \\listener 1885 ::1
        \\socket_domain ipv6
        \\listener_allow_anonymous true
    );
    defer config.deinit(allocator);

    try std.testing.expectEqual(SocketDomain.ipv4, config.listeners[0].socket_domain.?);
    try std.testing.expect(!config.listeners[0].bind_all_socket_domains);
    try std.testing.expect(config.listeners[0].address == .ip4);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 0 },
        &config.listeners[0].address.ip4.bytes,
    );
    try std.testing.expectEqual(SocketDomain.ipv6, config.listeners[1].socket_domain.?);
    try std.testing.expect(config.listeners[1].address == .ip6);
    try std.testing.expectEqual(@as(u16, 1883), config.listeners[1].address.getPort());
    try std.testing.expectEqualSlices(
        u8,
        &([_]u8{0} ** 16),
        &config.listeners[1].address.ip6.bytes,
    );
    try std.testing.expect(config.listeners[2].address == .ip6);
    try std.testing.expect(!config.listeners[2].bind_all_socket_domains);
    try std.testing.expectEqual(@as(u8, 1), config.listeners[2].address.ip6.bytes[15]);
}

test "MQTT broker config keeps omitted socket domain dual-stack intent" {
    var config = try parse(std.testing.allocator,
        \\listener 1883
        \\listener_allow_anonymous true
        \\listener 1884 127.0.0.1
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);

    try std.testing.expect(config.listeners[0].bind_all_socket_domains);
    try std.testing.expect(!config.listeners[1].bind_all_socket_domains);
    try std.testing.expectEqual(
        @as(?SocketDomain, null),
        config.listeners[0].socket_domain,
    );
}

test "MQTT broker config owns listener interface names" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(u8,
        \\listener 1883 192.0.2.1
        \\bind_interface lo
        \\socket_domain ipv6
        \\listener_allow_anonymous true
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expectEqualStrings("lo", config.listeners[0].bind_interface);
    try std.testing.expectEqual(SocketDomain.ipv6, config.listeners[0].socket_domain.?);
    try std.testing.expect(!config.listeners[0].bind_all_socket_domains);

    var all_families = try parse(allocator,
        \\listener 1884 192.0.2.2
        \\bind_interface lo
        \\listener_allow_anonymous true
    );
    defer all_families.deinit(allocator);
    try std.testing.expect(all_families.listeners[0].bind_all_socket_domains);

    var interface_precedence = try parse(allocator,
        \\listener 1885
        \\bind_interface lo
        \\listener_allow_anonymous true
        \\listener 1885
        \\bind_interface eth0
        \\listener_allow_anonymous true
    );
    defer interface_precedence.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), interface_precedence.listeners.len);
}

test "MQTT broker config rejects invalid socket domains" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "socket_domain ipv6\nlistener 1883\n"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "bind_interface lo\nlistener 1883\n"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 1883
            \\socket_domain dual
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\socket_domain ipv4
            \\socket_domain ipv4
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\bind_interface lo
            \\bind_interface eth0
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 1883 127.0.0.1
            \\socket_domain ipv6
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 1883 ::1
            \\socket_domain ipv4
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateListener,
        parse(allocator,
            \\listener 1883 ::
            \\socket_domain ipv6
            \\listener_allow_anonymous true
            \\listener 1883
            \\socket_domain ipv6
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config parses owned inbound bridges" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(u8,
        \\persistence true
        \\listener 1883 127.0.0.1
        \\listener_allow_anonymous true
        \\connection upstream
        \\addresses broker.example:2883 backup.example:3883
        \\topic sensors/# in 1 local/ remote/
        \\topic $SYS/# in 0 "" ""
        \\cleansession false
        \\local_cleansession true
        \\bridge_protocol_version mqttv50
        \\bridge_session_expiry_interval 0xFFFFFFFF
        \\keepalive_interval 45
        \\bridge_receive_maximum 7
        \\bridge_max_topic_alias 3
        \\bridge_max_packet_size 2048
        \\bridge_outgoing_retain false
        \\bridge_attempt_unsubscribe false
        \\try_private false
        \\bridge_bind_address 127.0.0.2
        \\bridge_tcp_keepalive 30 10 5
        \\bridge_tcp_user_timeout 30000
        \\local_clientid local-edge-bridge
        \\clientid edge-bridge
        \\username bridge-user
        \\password bridge-secret
        \\restart_timeout 10 60 120
        \\bridge_cafile roots.pem
        \\bridge_capath roots.d
        \\bridge_tls_use_os_certs true
        \\bridge_certfile client-chain.pem
        \\bridge_keyfile client-key.pem
        \\bridge_keyfile_password_file client-key.password
        \\bridge_alpn mqtt
        \\bridge_ciphers_tls1.3 TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384
        \\bridge_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305
        \\bridge_require_ocsp true
        \\bridge_insecure false
        \\bridge_tls_version tlsv1.3
        \\round_robin true
        \\start_type automatic
        \\bridge_reload_type immediate
        \\notifications true
        \\notifications_local_only false
        \\notification_topic bridge/upstream/state
        \\connection backup
        \\address [::1]:3883
        \\topic backup/# in 2 mirror/ source/
        \\bridge_protocol_version mqttv31
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expectEqual(@as(usize, 2), config.bridges.len);
    const upstream = config.bridges[0];
    try std.testing.expectEqualStrings("upstream", upstream.name);
    try std.testing.expectEqualStrings("broker.example", upstream.host);
    try std.testing.expectEqual(@as(u16, 2883), upstream.port);
    try std.testing.expectEqual(@as(usize, 2), upstream.addressCount());
    try std.testing.expectEqualStrings(
        "backup.example",
        upstream.addressAt(1).host,
    );
    try std.testing.expectEqual(@as(u16, 3883), upstream.addressAt(1).port);
    try std.testing.expect(upstream.round_robin);
    try std.testing.expectEqual(
        BridgeStartType.automatic,
        upstream.start_type,
    );
    try std.testing.expectEqual(
        BridgeReloadType.immediate,
        upstream.reload_type,
    );
    try std.testing.expect(upstream.notifications);
    try std.testing.expect(!upstream.notifications_local_only);
    try std.testing.expectEqualStrings(
        "bridge/upstream/state",
        upstream.notification_topic,
    );
    try std.testing.expectEqual(mqtt.ProtocolVersion.v5, upstream.protocol);
    try std.testing.expect(!upstream.clean_session);
    try std.testing.expect(upstream.local_clean_session);
    try std.testing.expectEqual(
        std.math.maxInt(u32),
        upstream.session_expiry_interval,
    );
    try std.testing.expectEqual(@as(u16, 45), upstream.keep_alive_seconds);
    try std.testing.expectEqual(@as(u16, 7), upstream.receive_maximum);
    try std.testing.expectEqual(@as(u16, 3), upstream.max_topic_alias);
    try std.testing.expectEqual(@as(u32, 2048), upstream.max_packet_size);
    try std.testing.expect(!upstream.outgoing_retain);
    try std.testing.expect(!upstream.attempt_unsubscribe);
    try std.testing.expect(!upstream.try_private);
    try std.testing.expect(!upstream.usesPrivateBridgeMode());
    const expected_bind_address = try std.Io.net.IpAddress.parseIp4(
        "127.0.0.2",
        0,
    );
    try std.testing.expect(upstream.bind_address.?.eql(
        &expected_bind_address,
    ));
    try std.testing.expectEqual(
        mqtt.runtime.TcpKeepAlive{
            .idle_seconds = 30,
            .interval_seconds = 10,
            .probe_count = 5,
        },
        upstream.tcp_keepalive.?,
    );
    try std.testing.expectEqual(
        @as(?u32, 30_000),
        upstream.tcp_user_timeout_ms,
    );
    try std.testing.expectEqualStrings("edge-bridge", upstream.clientId());
    try std.testing.expectEqualStrings(
        "local-edge-bridge",
        upstream.localClientId(),
    );
    try std.testing.expectEqualStrings("bridge-user", upstream.remote_username);
    try std.testing.expectEqualStrings("bridge-secret", upstream.remote_password);
    try std.testing.expectEqual(@as(u16, 10), upstream.restart.base_seconds);
    try std.testing.expectEqual(@as(u16, 60), upstream.restart.cap_seconds);
    try std.testing.expect(upstream.restart.jitter);
    try std.testing.expectEqual(
        @as(u32, 120),
        upstream.restart.stable_connection_seconds,
    );
    try std.testing.expect(upstream.usesTls());
    try std.testing.expect(upstream.use_os_ca_certificates);
    try std.testing.expectEqualStrings("roots.pem", upstream.ca_file);
    try std.testing.expectEqualStrings("roots.d", upstream.ca_path);
    try std.testing.expectEqualStrings(
        "client-chain.pem",
        upstream.certificate_file,
    );
    try std.testing.expectEqualStrings(
        "client-key.pem",
        upstream.private_key_file,
    );
    try std.testing.expectEqualStrings(
        "client-key.password",
        upstream.private_key_password_file,
    );
    try std.testing.expectEqualStrings("mqtt", upstream.alpn);
    try std.testing.expectEqualSlices(
        mqtt.tls_runtime.CipherSuite,
        &.{ .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
        upstream.cipher_suites,
    );
    try std.testing.expectEqualSlices(
        mqtt.tls_runtime.Tls12CipherSuite,
        &.{
            .ecdhe_ecdsa_aes_128_gcm_sha256,
            .ecdhe_rsa_chacha20_poly1305_sha256,
        },
        upstream.tls12_cipher_suites,
    );
    try std.testing.expect(upstream.require_ocsp);
    try std.testing.expect(upstream.verify_host);
    try std.testing.expectEqual(@as(usize, 2), upstream.rules.len);
    try std.testing.expectEqualStrings(
        "remote/sensors/#",
        upstream.rules[0].filter,
    );
    try std.testing.expectEqualStrings("local/", upstream.rules[0].local_prefix);
    try std.testing.expectEqualStrings("remote/", upstream.rules[0].remote_prefix);
    try std.testing.expectEqual(mqtt.QoS.at_least_once, upstream.rules[0].qos);
    try std.testing.expectEqualStrings("$SYS/#", upstream.rules[1].filter);

    const backup = config.bridges[1];
    try std.testing.expectEqualStrings("::1", backup.host);
    try std.testing.expectEqual(@as(u16, 3883), backup.port);
    try std.testing.expectEqualStrings("backup", backup.clientId());
    try std.testing.expectEqual(mqtt.ProtocolVersion.v3_1, backup.protocol);
    try std.testing.expectEqualStrings("local.backup", backup.localClientId());
    try std.testing.expect(backup.usesQoS2());
    try std.testing.expectEqualStrings("source/backup/#", backup.rules[0].filter);
}

test "MQTT broker config applies inbound bridge defaults" {
    var config = try parse(std.testing.allocator,
        \\max_inflight_messages 9
        \\listener 1883
        \\listener_allow_anonymous true
        \\connection defaulted
        \\address localhost
        \\topic # in 0
        \\restart_timeout 20
    );
    defer config.deinit(std.testing.allocator);
    const bridge = config.bridges[0];
    try std.testing.expectEqualStrings("localhost", bridge.host);
    try std.testing.expectEqual(@as(u16, 1883), bridge.port);
    try std.testing.expectEqualStrings("defaulted", bridge.clientId());
    try std.testing.expectEqualStrings(
        "local.defaulted",
        bridge.localClientId(),
    );
    try std.testing.expectEqual(mqtt.ProtocolVersion.v3_1_1, bridge.protocol);
    try std.testing.expect(!bridge.clean_session);
    try std.testing.expect(!bridge.local_clean_session);
    try std.testing.expectEqual(@as(u16, 60), bridge.keep_alive_seconds);
    try std.testing.expectEqual(@as(u16, 9), bridge.receive_maximum);
    try std.testing.expectEqual(@as(u16, 10), bridge.max_topic_alias);
    try std.testing.expectEqual(@as(u32, 0), bridge.max_packet_size);
    try std.testing.expect(bridge.outgoing_retain);
    try std.testing.expect(bridge.attempt_unsubscribe);
    try std.testing.expect(bridge.try_private);
    try std.testing.expect(bridge.usesPrivateBridgeMode());
    try std.testing.expectEqual(
        @as(?std.Io.net.IpAddress, null),
        bridge.bind_address,
    );
    try std.testing.expectEqual(
        @as(?u32, null),
        bridge.tcp_user_timeout_ms,
    );
    try std.testing.expectEqual(
        @as(?mqtt.runtime.TcpKeepAlive, null),
        bridge.tcp_keepalive,
    );
    try std.testing.expectEqual(@as(usize, 0), bridge.cipher_suites.len);
    try std.testing.expect(!bridge.require_ocsp);
    try std.testing.expectEqual(@as(u16, 20), bridge.restart.base_seconds);
    try std.testing.expectEqual(@as(u16, 20), bridge.restart.cap_seconds);
    try std.testing.expect(!bridge.restart.jitter);
    try std.testing.expectEqual(
        @as(u32, 0),
        bridge.restart.stable_connection_seconds,
    );
    try std.testing.expectEqual(
        BridgeStartType.automatic,
        bridge.start_type,
    );
    try std.testing.expectEqual(BridgeReloadType.lazy, bridge.reload_type);
    try std.testing.expectEqualStrings("#", bridge.rules[0].filter);
    try std.testing.expect(bridge.notifications);
    try std.testing.expect(!bridge.notifications_local_only);
    const notification_topic = try bridge.notificationTopicAlloc(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(notification_topic);
    try std.testing.expectEqualStrings(
        "$SYS/broker/connection/defaulted/state",
        notification_topic,
    );

    var disabled = try parse(std.testing.allocator,
        \\listener 1884
        \\listener_allow_anonymous true
        \\connection silent
        \\address localhost
        \\topic # in 0
        \\notifications false
    );
    defer disabled.deinit(std.testing.allocator);
    try std.testing.expect(!disabled.bridges[0].notifications);

    var inherited_clean = try parse(std.testing.allocator,
        \\listener 1886
        \\listener_allow_anonymous true
        \\connection inherited-clean
        \\address localhost
        \\topic # out 0
        \\cleansession true
    );
    defer inherited_clean.deinit(std.testing.allocator);
    try std.testing.expect(inherited_clean.bridges[0].local_clean_session);

    var overridden_clean = try parse(std.testing.allocator,
        \\listener 1887
        \\listener_allow_anonymous true
        \\connection overridden-clean
        \\address localhost
        \\topic # out 0
        \\cleansession true
        \\local_cleansession false
    );
    defer overridden_clean.deinit(std.testing.allocator);
    try std.testing.expect(!overridden_clean.bridges[0].local_clean_session);

    var unlimited = try parse(std.testing.allocator,
        \\max_inflight_messages 0
        \\listener 1885
        \\listener_allow_anonymous true
        \\connection unlimited
        \\address localhost
        \\topic # in 0
    );
    defer unlimited.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        unlimited.bridges[0].receive_maximum,
    );

    var ipv6 = try parse(std.testing.allocator,
        \\listener 1886
        \\listener_allow_anonymous true
        \\connection ipv6-bind
        \\address [::1]:2883
        \\topic # out 0
        \\bridge_bind_address ::1
    );
    defer ipv6.deinit(std.testing.allocator);
    const expected_ipv6_bind = try std.Io.net.IpAddress.parseIp6("::1", 0);
    try std.testing.expect(ipv6.bridges[0].bind_address.?.eql(
        &expected_ipv6_bind,
    ));

    var timeout_boundaries = try parse(std.testing.allocator,
        \\listener 1887
        \\listener_allow_anonymous true
        \\connection timeout-zero
        \\address localhost
        \\topic zero/# in 0
        \\bridge_tcp_user_timeout 0
        \\connection timeout-max
        \\address localhost
        \\topic max/# in 0
        \\bridge_tcp_keepalive 2147483647 2147483647 2147483647
        \\bridge_tcp_user_timeout 2147483647
    );
    defer timeout_boundaries.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(?u32, 0),
        timeout_boundaries.bridges[0].tcp_user_timeout_ms,
    );
    try std.testing.expectEqual(
        @as(?u32, bridge_config.maximum_tcp_user_timeout_ms),
        timeout_boundaries.bridges[1].tcp_user_timeout_ms,
    );
    try std.testing.expectEqual(
        mqtt.runtime.TcpKeepAlive{
            .idle_seconds = bridge_config.maximum_tcp_user_timeout_ms,
            .interval_seconds = bridge_config.maximum_tcp_user_timeout_ms,
            .probe_count = bridge_config.maximum_tcp_user_timeout_ms,
        },
        timeout_boundaries.bridges[1].tcp_keepalive.?,
    );
}

test "MQTT broker config enforces MQTT 3.1 bridge Client ID length" {
    const allocator = std.testing.allocator;
    const listener = "listener 1883\nlistener_allow_anonymous true\n";
    var maximum = try parse(allocator, listener ++
        "connection maximum-v31-client\naddress localhost\n" ++
        "topic # in 0\nbridge_protocol_version mqttv31\n" ++
        "remote_clientid abcdefghijklmnopqrstuvw\n");
    defer maximum.deinit(allocator);
    try std.testing.expectEqualStrings(
        "abcdefghijklmnopqrstuvw",
        maximum.bridges[0].clientId(),
    );

    try std.testing.expectError(
        error.InvalidClientId,
        parse(allocator, listener ++
            "connection overlong-v31-client\naddress localhost\n" ++
            "topic # in 0\nbridge_protocol_version mqttv31\n" ++
            "remote_clientid abcdefghijklmnopqrstuvwx\n"),
    );
}

test "MQTT broker config rejects incomplete or unsupported bridges" {
    const allocator = std.testing.allocator;
    const listener = "listener 1883\nlistener_allow_anonymous true\n";
    try std.testing.expectError(
        error.DirectiveRequiresBridge,
        parse(allocator, listener ++ "address localhost\n"),
    );
    try std.testing.expectError(
        error.DuplicateBridge,
        parse(allocator, listener ++
            "connection duplicate\naddress localhost\ntopic # in 0\n" ++
            "connection duplicate\naddress localhost\ntopic other/# in 0\n"),
    );
    try std.testing.expectError(
        error.BridgeAddressRequired,
        parse(allocator, listener ++ "connection missing\ntopic # in 0\n"),
    );
    try std.testing.expectError(
        error.BridgeTopicRequired,
        parse(allocator, listener ++ "connection missing\naddress localhost\n"),
    );
    for ([_][]const u8{"sideways"}) |direction| {
        const source = try std.fmt.allocPrint(
            allocator,
            "{s}connection wrong-way\naddress localhost\n" ++
                "topic # {s} 1\n",
            .{ listener, direction },
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.UnsupportedBridgeDirection,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.BridgeAuthenticationIncomplete,
        parse(allocator, listener ++
            "connection auth\naddress localhost\ntopic # in 0\n" ++
            "remote_password secret\n"),
    );
    try std.testing.expectError(
        error.DuplicateBridgeFilter,
        parse(allocator, listener ++
            "connection duplicate-filter\naddress localhost\n" ++
            "topic a/# in 0\ntopic a/# in 1\n"),
    );
    try std.testing.expectError(
        error.OverlappingBridgeFilters,
        parse(allocator, listener ++
            "connection overlap\naddress localhost\n" ++
            "topic a/# in 0\ntopic a/+ in 1\n"),
    );
    try std.testing.expectError(
        error.BridgePersistenceRequired,
        parse(allocator, listener ++
            "connection qos2\naddress localhost\ntopic # in 2\n"),
    );
    try std.testing.expectError(
        error.BridgePersistentSessionRequired,
        parse(allocator, "persistence true\n" ++ listener ++
            "connection qos2\naddress localhost\ntopic # in 2\n" ++
            "cleansession true\n"),
    );
    try std.testing.expectError(
        error.BridgePersistentSessionRequired,
        parse(allocator, "persistence true\n" ++ listener ++
            "connection qos2\naddress localhost\ntopic # in 2\n" ++
            "bridge_protocol_version mqttv50\n"),
    );
    try std.testing.expectError(
        error.BridgePersistentSessionRequired,
        parse(allocator, "persistence true\n" ++ listener ++
            "connection local-clean-qos2\naddress localhost\n" ++
            "topic # out 2\nbridge_protocol_version mqttv50\n" ++
            "bridge_session_expiry_interval 60\n" ++
            "local_cleansession true\n"),
    );
    try std.testing.expectError(
        error.BridgePersistentSessionRequired,
        parse(allocator, "persistence true\n" ++ listener ++
            "connection local-clean-qos1\naddress localhost\n" ++
            "topic # out 1\nlocal_cleansession true\n"),
    );
    try std.testing.expectError(
        error.UnsupportedBridgeProtocol,
        parse(allocator, listener ++
            "connection old\naddress localhost\ntopic # in 0\n" ++
            "bridge_protocol_version mqttv32\n"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresBridge,
        parse(allocator, listener ++ "bridge_reload_type immediate\n"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, listener ++
            "connection invalid-reload\naddress localhost\ntopic # in 0\n" ++
            "bridge_reload_type delayed\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-reload\naddress localhost\ntopic # in 0\n" ++
            "bridge_reload_type lazy\nbridge_reload_type immediate\n"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, listener ++
            "connection wrong-version-property\n" ++
            "address localhost\ntopic # in 0\n" ++
            "bridge_session_expiry_interval 60\n"),
    );
    try std.testing.expectError(
        error.BridgeTlsTrustRequired,
        parse(allocator, listener ++
            "connection tls-no-trust\naddress localhost\ntopic # in 0\n" ++
            "bridge_tls_version tlsv1.3\n"),
    );
    try std.testing.expectError(
        error.BridgeTlsTrustRequired,
        parse(allocator, listener ++
            "connection cipher-no-trust\naddress localhost\ntopic # in 0\n" ++
            "bridge_ciphers_tls1.3 TLS_AES_128_GCM_SHA256\n"),
    );
    try std.testing.expectError(
        error.BridgeTlsTrustRequired,
        parse(allocator, listener ++
            "connection ocsp-no-trust\naddress localhost\ntopic # in 0\n" ++
            "bridge_require_ocsp true\n"),
    );
    for ([_][]const u8{
        "bridge_ciphers_tls1.3 DEFAULT\n",
        "bridge_ciphers_tls1.3 TLS_AES_128_GCM_SHA256:\n",
        "bridge_ciphers_tls1.3 TLS_AES_128_GCM_SHA256:" ++
            "TLS_AES_128_GCM_SHA256\n",
    }) |invalid| {
        const source = try std.fmt.allocPrint(
            allocator,
            "{s}connection invalid-cipher\naddress localhost\n" ++
                "topic # in 0\nbridge_cafile ca.pem\n{s}",
            .{ listener, invalid },
        );
        defer allocator.free(source);
        const expected = if (std.mem.eql(
            u8,
            invalid,
            "bridge_ciphers_tls1.3 TLS_AES_128_GCM_SHA256:" ++
                "TLS_AES_128_GCM_SHA256\n",
        )) error.DuplicateCipherSuite else error.UnsupportedCipherSuite;
        try std.testing.expectError(expected, parse(allocator, source));
    }
    try std.testing.expectError(
        error.BridgeTlsIdentityIncomplete,
        parse(allocator, listener ++
            "connection tls-identity\naddress localhost\ntopic # in 0\n" ++
            "bridge_cafile ca.pem\nbridge_certfile client.pem\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-capath\naddress localhost\ntopic # in 0\n" ++
            "bridge_capath roots-a\nbridge_capath roots-b\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-ciphers\naddress localhost\ntopic # in 0\n" ++
            "bridge_cafile ca.pem\n" ++
            "bridge_ciphers_tls1.3 TLS_AES_128_GCM_SHA256\n" ++
            "bridge_ciphers_tls1.3 TLS_AES_256_GCM_SHA384\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-ocsp\naddress localhost\ntopic # in 0\n" ++
            "bridge_cafile ca.pem\nbridge_require_ocsp true\n" ++
            "bridge_require_ocsp false\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-local-clean\naddress localhost\n" ++
            "topic # out 0\nlocal_cleansession true\n" ++
            "local_cleansession false\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-local-id\naddress localhost\n" ++
            "topic # out 0\nlocal_clientid one\nlocal_clientid two\n"),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, listener ++
            "connection invalid-local-clean\naddress localhost\n" ++
            "topic # out 0\nlocal_cleansession sometimes\n"),
    );
    try std.testing.expectError(
        error.DuplicateBridgeLocalClientId,
        parse(allocator, listener ++
            "connection first-local-id\naddress localhost\n" ++
            "topic first/# out 0\nlocal_clientid shared-local\n" ++
            "connection second-local-id\naddress localhost\n" ++
            "topic second/# out 0\nlocal_clientid shared-local\n"),
    );
    try std.testing.expectError(
        error.DuplicateBridgeLocalClientId,
        parse(allocator, listener ++
            "connection default-local-id\naddress localhost\n" ++
            "topic first/# out 0\nremote_clientid shared\n" ++
            "connection explicit-local-id\naddress localhost\n" ++
            "topic second/# out 0\nlocal_clientid local.shared\n"),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, listener ++
            "connection invalid-ocsp\naddress localhost\ntopic # in 0\n" ++
            "bridge_cafile ca.pem\nbridge_require_ocsp required\n"),
    );
    var insecure = try parse(allocator, listener ++
        "connection insecure\naddress localhost\ntopic # in 0\n" ++
        "bridge_cafile ca.pem\nbridge_insecure true\n");
    defer insecure.deinit(allocator);
    try std.testing.expect(!insecure.bridges[0].verify_host);
    var tls12 = try parse(allocator, listener ++
        "connection tls12\naddress localhost\ntopic # in 0\n" ++
        "bridge_cafile ca.pem\nbridge_tls_version tlsv1.2\n");
    defer tls12.deinit(allocator);
    try std.testing.expectEqual(
        @TypeOf(tls12.bridges[0].tls_protocol_policy).tls12_and_tls13,
        tls12.bridges[0].tls_protocol_policy,
    );
    var tls12_only = try parse(allocator, listener ++
        "connection tls12-only\naddress localhost\ntopic # in 0\n" ++
        "bridge_cafile ca.pem\nbridge_tls_version tlsv1.2-only\n");
    defer tls12_only.deinit(allocator);
    try std.testing.expectEqual(
        @TypeOf(tls12_only.bridges[0].tls_protocol_policy).tls12_only,
        tls12_only.bridges[0].tls_protocol_policy,
    );
    try std.testing.expectError(
        error.UnsupportedBridgeTlsVersion,
        parse(allocator, listener ++
            "connection tls11\naddress localhost\ntopic # in 0\n" ++
            "bridge_cafile ca.pem\nbridge_tls_version tlsv1.1\n"),
    );
    try std.testing.expectError(
        error.UnsupportedBridgeRestartTimeout,
        parse(allocator, listener ++
            "connection restart\naddress localhost\ntopic # in 0\n" ++
            "restart_timeout 5 30 30 30\n"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, listener ++
            "connection negative-stable\naddress localhost\ntopic # in 0\n" ++
            "restart_timeout 5 30 -1\n"),
    );
    for ([_][]const u8{
        "bridge_receive_maximum 0\n",
        "bridge_receive_maximum 65536\n",
        "bridge_max_topic_alias -1\n",
        "bridge_max_topic_alias 65536\n",
        "bridge_max_packet_size -1\n",
        "bridge_max_packet_size 4294967296\n",
        "bridge_tcp_user_timeout -1\n",
        "bridge_tcp_user_timeout 2147483648\n",
        "bridge_tcp_keepalive 0 1 1\n",
        "bridge_tcp_keepalive 1 0 1\n",
        "bridge_tcp_keepalive 1 1 0\n",
        "bridge_tcp_keepalive -1 1 1\n",
        "bridge_tcp_keepalive 2147483648 1 1\n",
    }) |invalid| {
        const source = try std.fmt.allocPrint(
            allocator,
            "{s}connection invalid-limit\naddress localhost\n" ++
                "topic # in 0\n{s}",
            .{ listener, invalid },
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, listener ++
            "connection invalid-retain\naddress localhost\n" ++
            "topic # in 0\nbridge_outgoing_retain maybe\n"),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, listener ++
            "connection invalid-unsubscribe\naddress localhost\n" ++
            "topic # out 0\nbridge_attempt_unsubscribe maybe\n"),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, listener ++
            "connection invalid-private\naddress localhost\n" ++
            "topic # out 0\ntry_private maybe\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-limit\naddress localhost\n" ++
            "topic # in 0\nbridge_receive_maximum 1\n" ++
            "bridge_receive_maximum 2\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-unsubscribe\naddress localhost\n" ++
            "topic # out 0\nbridge_attempt_unsubscribe true\n" ++
            "bridge_attempt_unsubscribe false\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-private\naddress localhost\n" ++
            "topic # out 0\ntry_private true\ntry_private false\n"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, listener ++
            "connection invalid-bind\naddress localhost\n" ++
            "topic # out 0\nbridge_bind_address localhost\n"),
    );
    try std.testing.expectError(
        error.BridgeAddressFamilyMismatch,
        parse(allocator, listener ++
            "connection mismatched-bind\naddress 127.0.0.1\n" ++
            "topic # out 0\nbridge_bind_address ::1\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-bind\naddress localhost\n" ++
            "topic # out 0\nbridge_bind_address 127.0.0.1\n" ++
            "bridge_bind_address 127.0.0.2\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-timeout\naddress localhost\n" ++
            "topic # out 0\nbridge_tcp_user_timeout 0\n" ++
            "bridge_tcp_user_timeout 1\n"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, listener ++
            "connection incomplete-keepalive\naddress localhost\n" ++
            "topic # out 0\nbridge_tcp_keepalive 1 1\n"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, listener ++
            "connection extra-keepalive\naddress localhost\n" ++
            "topic # out 0\nbridge_tcp_keepalive 1 1 1 1\n"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-keepalive\naddress localhost\n" ++
            "topic # out 0\nbridge_tcp_keepalive 1 2 3\n" ++
            "bridge_tcp_keepalive 4 5 6\n"),
    );
    try std.testing.expectError(
        error.UnsupportedBridgeStartType,
        parse(allocator, listener ++
            "connection manual\naddress localhost\ntopic # in 0\n" ++
            "start_type manual\n"),
    );
    try std.testing.expectError(
        error.BridgeNotificationsDisabled,
        parse(allocator, listener ++
            "connection notifications-off\naddress localhost\n" ++
            "topic # in 0\nnotifications false\n" ++
            "notifications_local_only true\n"),
    );
    try std.testing.expectError(
        error.InvalidTopic,
        parse(allocator, listener ++
            "connection notifications-topic\naddress localhost\n" ++
            "topic # in 0\nnotification_topic bad/+\n"),
    );
    var primary_preferred = try parse(allocator, listener ++
        "connection addresses\naddresses one.example two.example\n" ++
        "topic # in 0\n");
    defer primary_preferred.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 2),
        primary_preferred.bridges[0].addressCount(),
    );
    try std.testing.expect(!primary_preferred.bridges[0].round_robin);
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator, listener ++
            "connection duplicate-address-directive\n" ++
            "address one.example\naddresses two.example\n" ++
            "topic # in 0\n"),
    );
    for ([_][]const u8{
        "remote_clientid modern\nclientid legacy\n",
        "username legacy\nremote_username modern\n",
        "remote_username user\npassword legacy\nremote_password modern\n",
    }) |duplicate_aliases| {
        const source = try std.fmt.allocPrint(
            allocator,
            "{s}connection duplicate-bridge-alias\n" ++
                "address localhost\ntopic # in 0\n{s}",
            .{ listener, duplicate_aliases },
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.DuplicateDirective,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.DuplicateBridgeAddress,
        parse(allocator, listener ++
            "connection duplicate-address\n" ++
            "address one.example:1883 one.example\n" ++
            "topic # in 0\nround_robin true\n"),
    );
}

test "MQTT broker config accepts outbound and bidirectional mappings" {
    const allocator = std.testing.allocator;
    const listener = "listener 1883\nlistener_allow_anonymous true\n";
    var config = try parse(allocator, listener ++
        "connection outgoing\naddress localhost\n" ++
        "topic sensors/# out 1 local/ remote/\n");
    defer config.deinit(allocator);
    const bridge = config.bridges[0];
    try std.testing.expect(bridge.hasOutbound());
    try std.testing.expectEqualStrings("remote/sensors/#", bridge.rules[0].filter);
    try std.testing.expectEqualStrings("local/", bridge.rules[0].local_prefix);
    const base = try bridge.rules[0].outboundFilterAlloc(allocator);
    defer allocator.free(base);
    try std.testing.expectEqualStrings("sensors/#", base);
    var shared = try parse(allocator, listener ++
        "connection shared\naddress localhost\n" ++
        "topic $share/workers/sensors/# out 1 local/ remote/\n");
    defer shared.deinit(allocator);
    const shared_base = try shared.bridges[0].rules[0].outboundFilterAlloc(allocator);
    defer allocator.free(shared_base);
    try std.testing.expectEqualStrings("$share/workers/sensors/#", shared_base);
    var mixed = try parse(allocator, listener ++
        "connection mixed\naddress localhost\n" ++
        "topic sensors/# in 1 local/ remote/\n" ++
        "topic data/# out 1 local/ remote/\n");
    defer mixed.deinit(allocator);
    try std.testing.expect(mixed.bridges[0].hasInbound());
    try std.testing.expect(mixed.bridges[0].hasOutbound());

    var both = try parse(allocator, listener ++
        "connection bidirectional\naddress localhost\n" ++
        "bridge_protocol_version mqttv50\n" ++
        "topic sensors/# both 1 local/ remote/\n");
    defer both.deinit(allocator);
    try std.testing.expectEqual(BridgeDirection.both, both.bridges[0].rules[0].direction);
    try std.testing.expect(both.bridges[0].hasInbound());
    try std.testing.expect(both.bridges[0].hasOutbound());

    try std.testing.expectError(
        error.UnsupportedBridgeDirection,
        parse(allocator, listener ++
            "connection unsafe-both\naddress localhost\n" ++
            "topic sensors/# both 1 local/ remote/\n" ++
            "try_private false\n"),
    );
}

test "MQTT broker config validates lazy outbound lifecycle" {
    const allocator = std.testing.allocator;
    const listener = "listener 1883\nlistener_allow_anonymous true\n";
    var config = try parse(allocator, "max_queued_messages 3\n" ++ listener ++
        "connection lazy-out\naddress localhost\n" ++
        "topic sensors/# out 1\nstart_type lazy\n" ++
        "threshold 3\nidle_timeout 7\n");
    defer config.deinit(allocator);
    try std.testing.expectEqual(
        BridgeStartType.lazy,
        config.bridges[0].start_type,
    );
    try std.testing.expectEqual(@as(usize, 3), config.bridges[0].threshold);
    try std.testing.expectEqual(
        @as(u32, 7),
        config.bridges[0].idle_timeout_seconds,
    );

    try std.testing.expectError(
        error.UnsupportedBridgeStartType,
        parse(allocator, listener ++
            "connection lazy-in\naddress localhost\n" ++
            "topic sensors/# in 1\nstart_type lazy\n"),
    );
    try std.testing.expectError(
        error.BridgeLazyThresholdExceedsQueueLimit,
        parse(allocator, "max_queued_messages 2\n" ++ listener ++
            "connection unreachable\naddress localhost\n" ++
            "topic sensors/# out 1\nstart_type lazy\nthreshold 3\n"),
    );
    for ([_][]const u8{ "threshold 0\n", "idle_timeout 0\n" }) |invalid| {
        const source = try std.fmt.allocPrint(
            allocator,
            "{s}connection invalid-lazy\naddress localhost\n" ++
                "topic sensors/# out 1\nstart_type lazy\n{s}",
            .{ listener, invalid },
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(allocator, source),
        );
    }
}

test "MQTT broker config accepts decorrelated restart stable period" {
    const allocator = std.testing.allocator;
    const listener = "listener 1883\nlistener_allow_anonymous true\n";
    var config = try parse(allocator, listener ++
        "connection jittered\naddress localhost\ntopic # in 0\n" ++
        "restart_timeout 3600 7200 0\n");
    defer config.deinit(allocator);
    try std.testing.expectEqual(
        @as(u16, 3600),
        config.bridges[0].restart.base_seconds,
    );
    try std.testing.expectEqual(
        @as(u16, 7200),
        config.bridges[0].restart.cap_seconds,
    );
    try std.testing.expect(config.bridges[0].restart.jitter);
    try std.testing.expectEqual(
        @as(u32, 0),
        config.bridges[0].restart.stable_connection_seconds,
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, listener ++
            "connection excessive-cap\naddress localhost\ntopic # in 0\n" ++
            "restart_timeout 1 7201\n"),
    );
}

test "MQTT broker config bridge allocation failures leak nothing" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testBridgeConfigAllocationFailures,
        .{},
    );
}

fn testBridgeConfigAllocationFailures(allocator: std.mem.Allocator) !void {
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

test "MQTT broker config validates global client session limit" {
    const allocator = std.testing.allocator;

    var unlimited = try parse(allocator,
        \\global_max_clients -1
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer unlimited.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(u31)),
        unlimited.global_max_clients,
    );

    for ([_][]const u8{ "0", "-2", "2147483648", "invalid" }) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "global_max_clients {s}\nlistener 1883\nlistener_allow_anonymous true\n",
            .{value},
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\global_max_clients
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\global_max_clients 1
            \\global_max_clients 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config validates global connection limit" {
    const allocator = std.testing.allocator;

    var unlimited = try parse(allocator,
        \\global_max_connections -1
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer unlimited.deinit(allocator);
    try std.testing.expectEqual(
        default_global_max_connections,
        unlimited.global_max_connections,
    );
    try std.testing.expectEqual(
        default_max_connections,
        try unlimited.activeConnectionLimit(),
    );

    var omitted = try parse(allocator,
        \\listener 1884
        \\listener_allow_anonymous true
    );
    defer omitted.deinit(allocator);
    try std.testing.expectEqual(
        default_global_max_connections,
        omitted.global_max_connections,
    );

    for ([_][]const u8{ "0", "-2", "2147483648", "invalid" }) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "global_max_connections {s}\nlistener 1883\nlistener_allow_anonymous true\n",
            .{value},
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\global_max_connections
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\global_max_connections 1
            \\global_max_connections 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config owns per-listener security files" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "per_listener_settings true\n" ++
            "listener 1883 127.0.0.1\n" ++
            "password_file first.pw\nacl_file first.acl\n" ++
            "auto_id_prefix first-\n" ++
            "allow_zero_length_clientid false\n" ++
            "listener_allow_anonymous false\n" ++
            "listener 8080 127.0.0.1\nprotocol websockets\n" ++
            "password_file second.pw\nacl_file second.acl\n" ++
            "listener_auto_id_prefix second-\n" ++
            "allow_zero_length_clientid true\n" ++
            "listener_allow_anonymous false\n",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expect(config.per_listener_settings);
    try std.testing.expect(config.password_file.len == 0);
    try std.testing.expect(config.acl_file.len == 0);
    try std.testing.expectEqualStrings(
        "first.pw",
        config.listeners[0].password_file,
    );
    try std.testing.expectEqualStrings(
        "first.acl",
        config.listeners[0].acl_file,
    );
    try std.testing.expectEqualStrings(
        "second.pw",
        config.listeners[1].password_file,
    );
    try std.testing.expectEqualStrings(
        "second.acl",
        config.listeners[1].acl_file,
    );
    try std.testing.expect(!config.listeners[0].allow_zero_length_client_id);
    try std.testing.expect(config.listeners[1].allow_zero_length_client_id);
    try std.testing.expectEqualStrings(
        "first-",
        config.listeners[0].auto_id_prefix,
    );
    try std.testing.expectEqualStrings(
        "second-",
        config.listeners[1].auto_id_prefix,
    );
}

test "MQTT broker config scopes assigned Client ID prefixes" {
    const allocator = std.testing.allocator;
    var global = try parse(allocator,
        \\auto_id_prefix global-
        \\listener 1883
        \\listener_allow_anonymous true
        \\listener 1884
        \\listener_auto_id_prefix local-
        \\listener_allow_anonymous true
    );
    defer global.deinit(allocator);
    try std.testing.expectEqualStrings(
        "global-",
        global.autoIdPrefixForListener(global.listeners[0]),
    );
    try std.testing.expectEqualStrings(
        "local-",
        global.autoIdPrefixForListener(global.listeners[1]),
    );

    var isolated = try parse(allocator,
        \\per_listener_settings true
        \\listener 1885
        \\auto_id_prefix first-
        \\listener_allow_anonymous true
        \\listener 1886
        \\listener_auto_id_prefix second-
        \\listener_allow_anonymous true
    );
    defer isolated.deinit(allocator);
    try std.testing.expectEqualStrings(
        "first-",
        isolated.autoIdPrefixForListener(isolated.listeners[0]),
    );
    try std.testing.expectEqualStrings(
        "second-",
        isolated.autoIdPrefixForListener(isolated.listeners[1]),
    );

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator,
            \\per_listener_settings true
            \\auto_id_prefix missing-
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator,
            \\listener_auto_id_prefix missing-
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\listener_auto_id_prefix first-
            \\listener_auto_id_prefix second-
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\per_listener_settings true
            \\listener 1883
            \\auto_id_prefix first-
            \\listener_auto_id_prefix second-
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\auto_id_prefix first-
            \\auto_id_prefix second-
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\auto_id_prefix 123456789012345678901234567890123456789012345678901
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        parse(
            allocator,
            "listener 1883\nlistener_auto_id_prefix bad\xc0\x80prefix\n" ++
                "listener_allow_anonymous true\n",
        ),
    );
}

test "MQTT broker config scopes zero-length Client ID policy" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "per_listener_settings true\n" ++
                "allow_zero_length_clientid false\nlistener 1883",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "allow_zero_length_clientid false\n" ++
                "per_listener_settings true\n" ++
                "listener 1883\nlistener_allow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\allow_zero_length_clientid true
            \\listener 1883
            \\allow_zero_length_clientid false
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_inflight_bytes 1
            \\max_inflight_bytes 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_queued_messages 1
            \\max_queued_messages 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_queued_bytes 1
            \\max_queued_bytes 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_inflight_messages 1
            \\max_inflight_messages 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\check_retain_source true
            \\check_retain_source false
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\upgrade_outgoing_qos true
            \\upgrade_outgoing_qos false
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config keeps retained source policy global" {
    var config = try parse(std.testing.allocator,
        \\per_listener_settings true
        \\listener 1883
        \\listener_allow_anonymous true
        \\check_retain_source false
        \\listener 1884
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expect(!config.check_retain_source);
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
}

test "MQTT broker config loads include directories in Mosquitto order" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "one.d", .default_dir);
    var one = try tmp.dir.openDir(io, "one.d", .{});
    defer one.close(io);
    try one.writeFile(io, .{
        .sub_path = "b.conf",
        .data = "listener 1886\nlistener_allow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "A.conf",
        .data = "listener 1883\nlistener_allow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "a.conf",
        .data = "listener 1884\nlistener_allow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "B.conf",
        .data = "listener 1885\nlistener_allow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "ignored.txt",
        .data = "unsupported value\n",
    });
    try tmp.dir.createDir(io, "two.d", .default_dir);
    var two = try tmp.dir.openDir(io, "two.d", .{});
    defer two.close(io);
    try two.writeFile(io, .{
        .sub_path = "00.conf",
        .data = "listener 1887\nlistener_allow_anonymous true\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "listener 1882\nlistener_allow_anonymous true\n" ++
            "include_dir one.d\ninclude_dir two.d\n" ++
            "max_connections 7\n",
    });

    var config = try load(allocator, io, tmp.dir, "main.conf");
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 6), config.listeners.len);
    const expected_ports = [_]u16{ 1882, 1883, 1884, 1885, 1886, 1887 };
    for (config.listeners, expected_ports) |listener, expected_port| {
        try std.testing.expectEqual(expected_port, listener.address.getPort());
    }
    try std.testing.expectEqual(@as(usize, 7), config.listeners[0].max_connections);
    for (config.listeners[1..]) |listener| {
        try std.testing.expectEqual(
            default_max_connections,
            listener.max_connections,
        );
    }
}

test "MQTT broker config isolates included file listener scopes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "listeners.d", .default_dir);
    var included = try tmp.dir.openDir(io, "listeners.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "10-listener.conf",
        .data = "listener 1883\nlistener_allow_anonymous true\n",
    });
    try included.writeFile(io, .{
        .sub_path = "20-policy.conf",
        .data = "max_connections 2\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir listeners.d\n",
    });
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config isolates included file bridge scopes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "bridges.d", .default_dir);
    var included = try tmp.dir.openDir(io, "bridges.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "10-bridge.conf",
        .data = "connection upstream\naddress localhost\ntopic # in 0\n",
    });
    try included.writeFile(io, .{
        .sub_path = "20-policy.conf",
        .data = "restart_timeout 1\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "listener 1883\nlistener_allow_anonymous true\n" ++
            "include_dir bridges.d\n",
    });
    try std.testing.expectError(
        error.DirectiveRequiresBridge,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config rejects nested include directories" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "listeners.d", .default_dir);
    var included = try tmp.dir.openDir(io, "listeners.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "nested.conf",
        .data = "include_dir other.d\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir listeners.d\n",
    });
    try std.testing.expectError(
        error.NestedIncludeDirectory,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config rejects duplicate globals across include files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "settings.d", .default_dir);
    var included = try tmp.dir.openDir(io, "settings.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "10-first.conf",
        .data = "queue_qos0_messages true\n",
    });
    try included.writeFile(io, .{
        .sub_path = "20-second.conf",
        .data = "queue_qos0_messages false\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir settings.d\n" ++
            "listener 1883\nlistener_allow_anonymous true\n",
    });
    try std.testing.expectError(
        error.DuplicateDirective,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config fails closed for unsupported and misplaced directives" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.UnsupportedDirective,
        parse(allocator, "include_dir listeners.d\nlistener 1883"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "memory_limit -1\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "memory_limit 1024\nmemory_limit 2048\nlistener 1883",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "pid_file first.pid\npid_file second.pid\nlistener 1883",
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "mount_point tenant/\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "per_listener_settings true\npassword_file users.pw\n" ++
                "listener 1883",
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "per_listener_settings true\nacl_file access.acl\n" ++
                "listener 1883",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "password_file users.pw\nper_listener_settings true\n" ++
                "listener 1883\nlistener_allow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "listener 1883\nlistener_allow_anonymous true\n" ++
                "per_listener_settings true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "per_listener_settings true\nper_listener_settings true\n" ++
                "listener 1883\nlistener_allow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "per_listener_settings true\nlistener 1883\n" ++
                "password_file first.pw\npassword_file second.pw\n" ++
                "listener_allow_anonymous false",
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "certfile server.pem\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "keyfile_password_file secret\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "tls_version tlsv1.2\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "ciphers_tls1.3 TLS_AES_128_GCM_SHA256\nlistener 1883",
        ),
    );
    var tls12_listener = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\tls_version tlsv1.2
        \\ciphers ECDHE-ECDSA-AES128-GCM-SHA256
        \\tls12_session_tickets true
        \\tls12_session_ticket_server_id mqtt.example
        \\tls12_session_ticket_lifetime 3600
        \\listener_allow_anonymous true
    );
    defer tls12_listener.deinit(allocator);
    try std.testing.expectEqual(
        tls_stream.VersionPolicy.tls12_and_tls13,
        tls12_listener.listeners[0].tls_protocol_policy,
    );
    var tls12_only_listener = try parse(allocator,
        \\listener 8885
        \\certfile server.pem
        \\keyfile server.key
        \\tls_version tlsv1.2-only
        \\listener_allow_anonymous true
    );
    defer tls12_only_listener.deinit(allocator);
    try std.testing.expectEqual(
        tls_stream.VersionPolicy.tls12_only,
        tls12_only_listener.listeners[0].tls_protocol_policy,
    );
    try std.testing.expectEqualSlices(
        tls_cipher_suites.Tls12Suite,
        &.{.ecdhe_ecdsa_aes_128_gcm_sha256},
        tls12_listener.listeners[0].tls12_cipher_suites,
    );
    try std.testing.expect(tls12_listener.listeners[0].tls12_session_tickets);
    try std.testing.expectEqualStrings(
        "mqtt.example",
        tls12_listener.listeners[0].tls12_session_ticket_server_id,
    );
    try std.testing.expectEqual(
        @as(u32, 3600),
        tls12_listener.listeners[0].tls12_session_ticket_lifetime_seconds,
    );
    var tls13_listener = try parse(allocator,
        \\listener 8884
        \\certfile server.pem
        \\keyfile server.key
        \\tls_version tlsv1.3
        \\ciphers_tls1.3 TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256
        \\tls13_session_tickets true
        \\tls13_session_ticket_server_id mqtt.example
        \\tls13_session_ticket_lifetime 1800
        \\listener_allow_anonymous true
    );
    defer tls13_listener.deinit(allocator);
    try std.testing.expectEqual(
        tls_stream.VersionPolicy.tls13_only,
        tls13_listener.listeners[0].tls_protocol_policy,
    );
    try std.testing.expectEqualSlices(
        tls_cipher_suites.Suite,
        &.{ .aes_256_gcm_sha384, .aes_128_gcm_sha256 },
        tls13_listener.listeners[0].tls13_cipher_suites,
    );
    try std.testing.expect(tls13_listener.listeners[0].tls13_session_tickets);
    try std.testing.expectEqualStrings(
        "mqtt.example",
        tls13_listener.listeners[0].tls13_session_ticket_server_id,
    );
    try std.testing.expectEqual(
        @as(u32, 1800),
        tls13_listener.listeners[0].tls13_session_ticket_lifetime_seconds,
    );
    var tickets_disabled = try parse(allocator,
        \\listener 1883
        \\tls12_session_tickets false
        \\listener_allow_anonymous true
    );
    defer tickets_disabled.deinit(allocator);
    try std.testing.expect(
        !tickets_disabled.listeners[0].tls12_session_tickets,
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\tls12_session_tickets true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\tls13_session_tickets true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\tls13_session_tickets true
            \\tls13_session_ticket_server_id mqtt.example
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\tls13_session_tickets true
            \\tls13_session_ticket_server_id mqtt.example
            \\tls13_session_ticket_lifetime 604801
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\tls_version tlsv1.3
            \\tls12_session_tickets true
            \\tls12_session_ticket_server_id mqtt.example
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\tls12_session_tickets true
            \\tls12_session_ticket_server_id mqtt.example
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidSessionTicketConfiguration,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\tls12_session_tickets true
            \\tls12_session_ticket_server_id mqtt.example
            \\tls12_session_ticket_lifetime 604801
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.UnsupportedTlsVersion,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\tls_version tlsv1.1
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 1883
            \\ciphers_tls1.3 TLS_AES_128_GCM_SHA256
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.UnsupportedCipherSuite,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\ciphers_tls1.3 DEFAULT
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\ciphers_tls1.3 TLS_AES_128_GCM_SHA256
            \\ciphers_tls1.3 TLS_AES_256_GCM_SHA384
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\keyfile server.key
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\keyfile_password_file server-key.password
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile first.pem
            \\certfile second.pem
            \\keyfile server.key
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\retain_available true
            \\retain_available false
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\use_subject_as_username true
            \\use_subject_as_username true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "use_subject_as_username true\nlistener 8883"),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\crlfile clients.crl
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\crlfile first.crl
            \\crlfile second.crl
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\use_identity_as_username true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\use_subject_as_username true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\use_identity_as_username true
            \\use_identity_as_username true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator, "listener 1883\ncapath clients"),
    );
    try std.testing.expectError(
        error.CapathUnsupportedForWebSockets,
        parse(allocator,
            \\listener 8080
            \\protocol websockets
            \\certfile server.pem
            \\keyfile server.key
            \\capath clients
            \\listener_allow_anonymous true
        ),
    );
    var capath_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile common.pem
        \\capath clients
        \\require_certificate true
        \\listener_allow_anonymous true
    );
    defer capath_client_certificate.deinit(allocator);
    try std.testing.expectEqualStrings(
        "common.pem",
        capath_client_certificate.listeners[0].cafile,
    );
    try std.testing.expectEqualStrings(
        "clients",
        capath_client_certificate.listeners[0].capath,
    );
    try std.testing.expect(
        capath_client_certificate.listeners[0].require_certificate,
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\capath first
            \\capath second
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\require_certificate true
            \\listener_allow_anonymous true
        ),
    );
    var optional_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\require_certificate false
        \\listener_allow_anonymous true
    );
    defer optional_client_certificate.deinit(allocator);
    try std.testing.expect(
        !optional_client_certificate.listeners[0].require_certificate,
    );
    try std.testing.expectEqualStrings(
        "clients.pem",
        optional_client_certificate.listeners[0].cafile,
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile first.pem
            \\cafile second.pem
            \\require_certificate true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\require_certificate true
            \\listener_allow_anonymous true
        ),
    );
    var implicit_optional_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\listener_allow_anonymous true
    );
    defer implicit_optional_client_certificate.deinit(allocator);
    try std.testing.expect(
        !implicit_optional_client_certificate.listeners[0].require_certificate,
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\cafile clients.pem
            \\require_certificate true
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\listener_allow_anonymous true
            \\listener_allow_anonymous false
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\acl_file first.acl
            \\acl_file second.acl
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.PersistenceRequired,
        parse(allocator,
            \\listener 1883
            \\autosave_interval 5
        ),
    );
    try std.testing.expectError(
        error.PersistenceRequired,
        parse(allocator,
            \\listener 1883
            \\autosave_interval 0
        ),
    );
    var disabled_autosave = try parse(allocator,
        \\persistence true
        \\autosave_interval 0
        \\autosave_on_changes true
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer disabled_autosave.deinit(allocator);
    try std.testing.expectEqual(
        @as(u32, 0),
        disabled_autosave.autosave_interval,
    );
    try std.testing.expect(disabled_autosave.autosave_on_changes);
    try std.testing.expectError(
        error.DuplicateListener,
        parse(allocator,
            \\listener 1883 127.0.0.1
            \\listener 1883 127.0.0.1
        ),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, "listener 1883\nallow_anonymous yes"),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator,
            \\check_retain_source maybe
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_inflight_messages 65536
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_inflight_bytes 2147483648
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_inflight_bytes -1
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_messages 2147483648
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_messages -1
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_bytes 2147483648
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_bytes -1
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_qos 3"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\max_qos 1
            \\maximum_qos 0
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_topic_alias -1"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_topic_alias 65536"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_topic_alias_broker -1"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_topic_alias_broker 65536"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "max_packet_size 19\nlistener 1883"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "max_packet_size 2147483648\nlistener 1883"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "message_size_limit 268435456\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_packet_size 50
            \\max_packet_size 51
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\message_size_limit 1
            \\message_size_limit 2
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\persistence true
            \\persistence_file ../broker.db
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\password_file first.pw
            \\password_file second.pw
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\persistence true
            \\persistence_file state\\broker.db
            \\listener 1883
        ),
    );
}

test "MQTT broker config owns strings independently of source" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "persistence true\npersistence_location state\n" ++
            "persistence_file broker.db\npassword_file users.pw\n" ++
            "acl_file access.acl\n" ++
            "auto_id_prefix copied-\n" ++
            "listener 1883\n" ++
            "certfile server.pem\nkeyfile server.key\n" ++
            "cafile clients.pem\ncapath clients\n" ++
            "require_certificate true\n" ++
            "crlfile clients.crl\n" ++
            "use_identity_as_username true\n" ++
            "use_subject_as_username true\n" ++
            "mount_point tenant/\nlistener_allow_anonymous true\n",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expectEqualStrings(
        "state",
        config.persistence_location,
    );
    try std.testing.expectEqualStrings("broker.db", config.persistence_file);
    try std.testing.expectEqualStrings("users.pw", config.password_file);
    try std.testing.expectEqualStrings("access.acl", config.acl_file);
    try std.testing.expectEqualStrings("copied-", config.auto_id_prefix);
    try std.testing.expectEqualStrings("server.pem", config.listeners[0].certfile);
    try std.testing.expectEqualStrings("server.key", config.listeners[0].keyfile);
    try std.testing.expectEqualStrings("clients.pem", config.listeners[0].cafile);
    try std.testing.expectEqualStrings("clients", config.listeners[0].capath);
    try std.testing.expectEqualStrings("clients.crl", config.listeners[0].crlfile);
    try std.testing.expect(config.listeners[0].require_certificate);
    try std.testing.expect(config.listeners[0].use_identity_as_username);
    try std.testing.expect(config.listeners[0].use_subject_as_username);
    try std.testing.expectEqualStrings("tenant/", config.listeners[0].mount_point);
}

test "MQTT broker config accepts deny-all listener without credentials" {
    const allocator = std.testing.allocator;
    var config = try parse(
        allocator,
        "allow_anonymous false\nlistener 1883",
    );
    defer config.deinit(allocator);
    try std.testing.expect(!config.allow_anonymous);
    try std.testing.expect(!config.listeners[0].allow_anonymous);
    try std.testing.expectEqual(@as(usize, 0), config.password_file.len);
}

test "MQTT broker config accepts certificate identity authentication" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 8883 127.0.0.1
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\require_certificate true
        \\use_identity_as_username true
        \\listener_allow_anonymous false
        \\max_connections 1
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), config.listeners.len);
    try std.testing.expect(config.password_file.len == 0);
    try std.testing.expect(config.listeners[0].require_certificate);
    try std.testing.expect(config.listeners[0].use_identity_as_username);
}

test "MQTT broker config uses bounded packet and unlimited message defaults" {
    var config = try parse(
        std.testing.allocator,
        "listener 1883\nallow_anonymous true\n",
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(default_max_packet_size, config.max_packet_size);
    try std.testing.expectEqual(@as(usize, 0), config.message_size_limit);
    try std.testing.expectEqual(
        default_max_inflight_messages,
        config.max_inflight_messages,
    );
    try std.testing.expectEqual(
        default_max_inflight_messages,
        config.effectiveMaxInflightMessages(),
    );
    try std.testing.expectEqual(@as(usize, 0), config.max_inflight_bytes);
    try std.testing.expectEqual(
        default_max_queued_messages,
        config.max_queued_messages,
    );
    try std.testing.expectEqual(
        default_max_queued_messages,
        config.effectiveMaxQueuedMessages(),
    );
    try std.testing.expectEqual(@as(usize, 0), config.max_queued_bytes);
    try std.testing.expect(config.retain_available);
    try std.testing.expect(config.check_retain_source);
    try std.testing.expect(!config.upgrade_outgoing_qos);
    try std.testing.expect(config.allow_zero_length_client_id);
    try std.testing.expectEqualStrings(
        default_auto_id_prefix,
        config.autoIdPrefixForListener(config.listeners[0]),
    );
    try std.testing.expectEqual(
        @as(?u32, null),
        config.persistent_client_expiration_seconds,
    );
    try std.testing.expectEqual(
        @as(u32, 0),
        config.retain_expiry_interval_seconds,
    );
    try std.testing.expectEqual(
        default_sys_interval_seconds,
        config.sys_interval_seconds,
    );
    try std.testing.expectEqual(
        default_websocket_headers_size,
        config.websocket_headers_size,
    );
    try std.testing.expect(!config.set_tcp_nodelay);
    try std.testing.expect(config.allow_anonymous);
    try std.testing.expect(config.listeners[0].allow_zero_length_client_id);
    try std.testing.expectEqual(
        default_max_topic_aliases,
        config.listeners[0].max_topic_alias,
    );
    try std.testing.expectEqual(
        default_max_topic_aliases,
        config.listeners[0].max_topic_alias_broker,
    );
    try std.testing.expect(config.listeners[0].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(config.listeners[0].accepted_protocol_versions.v5);
    try std.testing.expectEqual(
        @as(?mqtt.proxy_protocol.Version, null),
        config.listeners[0].proxy_protocol,
    );

    var minimum = try parse(
        std.testing.allocator,
        "max_packet_size 20\nmessage_size_limit 268435455\n" ++
            "listener 1884\nlistener_allow_anonymous true\n",
    );
    defer minimum.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 20), minimum.max_packet_size);
    try std.testing.expectEqual(
        @as(usize, 268_435_455),
        minimum.message_size_limit,
    );
}

test "MQTT broker config resolves global and listener anonymous policy" {
    const allocator = std.testing.allocator;

    var default_deny = try parse(allocator,
        \\password_file users.pw
        \\listener 1882
    );
    defer default_deny.deinit(allocator);
    try std.testing.expect(!default_deny.allow_anonymous);
    try std.testing.expect(!default_deny.listeners[0].allow_anonymous);

    var global_after_listeners = try parse(allocator,
        \\password_file users.pw
        \\listener 1883
        \\listener_allow_anonymous false
        \\listener 1884
        \\allow_anonymous true
    );
    defer global_after_listeners.deinit(allocator);
    try std.testing.expect(global_after_listeners.allow_anonymous);
    try std.testing.expect(!global_after_listeners.listeners[0].allow_anonymous);
    try std.testing.expect(global_after_listeners.listeners[1].allow_anonymous);

    var local_override = try parse(allocator,
        \\password_file users.pw
        \\allow_anonymous false
        \\listener 1883
        \\listener_allow_anonymous true
        \\listener 1884
    );
    defer local_override.deinit(allocator);
    try std.testing.expect(!local_override.allow_anonymous);
    try std.testing.expect(local_override.listeners[0].allow_anonymous);
    try std.testing.expect(!local_override.listeners[1].allow_anonymous);

    var legacy_per_listener = try parse(allocator,
        \\per_listener_settings true
        \\listener 1883
        \\allow_anonymous true
        \\listener 1884
        \\password_file users.pw
        \\listener_allow_anonymous false
    );
    defer legacy_per_listener.deinit(allocator);
    try std.testing.expect(legacy_per_listener.listeners[0].allow_anonymous);
    try std.testing.expect(!legacy_per_listener.listeners[1].allow_anonymous);

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "listener_allow_anonymous true\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\allow_anonymous true
            \\listener 1883
            \\allow_anonymous false
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\per_listener_settings true
            \\listener 1883
            \\allow_anonymous true
            \\listener_allow_anonymous false
        ),
    );
}

test "MQTT broker config maps zero inflight messages to protocol maximum" {
    var config = try parse(std.testing.allocator,
        \\max_inflight_messages 0
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 0), config.max_inflight_messages);
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        config.effectiveMaxInflightMessages(),
    );

    var maximum = try parse(std.testing.allocator,
        \\per_listener_settings true
        \\listener 1883
        \\listener_allow_anonymous true
        \\max_inflight_messages 65535
        \\listener 1884
        \\listener_allow_anonymous true
    );
    defer maximum.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        maximum.max_inflight_messages,
    );
    try std.testing.expectEqual(@as(usize, 2), maximum.listeners.len);
}

test "MQTT broker config parses persistent client expiration units" {
    const units = [_]struct {
        value: []const u8,
        seconds: u32,
    }{
        .{ .value = "1s", .seconds = 1 },
        .{ .value = "2h", .seconds = 2 * 60 * 60 },
        .{ .value = "3d", .seconds = 3 * 24 * 60 * 60 },
        .{ .value = "4w", .seconds = 4 * 7 * 24 * 60 * 60 },
        .{ .value = "2m", .seconds = 2 * 30 * 24 * 60 * 60 },
        .{ .value = "1y", .seconds = 365 * 24 * 60 * 60 },
    };
    for (units) |case| {
        const source = try std.fmt.allocPrint(
            std.testing.allocator,
            "persistent_client_expiration {s}\nlistener 1883\n" ++
                "listener_allow_anonymous true\n",
            .{case.value},
        );
        defer std.testing.allocator.free(source);
        var config = try parse(std.testing.allocator, source);
        defer config.deinit(std.testing.allocator);
        try std.testing.expectEqual(
            @as(?u32, case.seconds),
            config.persistent_client_expiration_seconds,
        );
    }
}

test "MQTT broker config validates global system interval" {
    var disabled = try parse(std.testing.allocator,
        \\sys_interval 0
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer disabled.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 0), disabled.sys_interval_seconds);

    var maximum = try parse(std.testing.allocator,
        \\listener 1883
        \\listener_allow_anonymous true
        \\sys_interval 65535
        \\listener 1884
        \\listener_allow_anonymous true
    );
    defer maximum.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        maximum.sys_interval_seconds,
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(std.testing.allocator,
            \\sys_interval -1
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(std.testing.allocator,
            \\sys_interval 65536
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\sys_interval 1
            \\sys_interval 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config validates retained expiry scan interval" {
    var minimum = try parse(std.testing.allocator,
        \\retain_expiry_interval 1
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer minimum.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(u32, std.time.s_per_min),
        minimum.retain_expiry_interval_seconds,
    );

    var maximum = try parse(std.testing.allocator,
        \\listener 1883
        \\listener_allow_anonymous true
        \\retain_expiry_interval 10000000
    );
    defer maximum.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(u32, 10_000_000 * std.time.s_per_min),
        maximum.retain_expiry_interval_seconds,
    );

    const invalid = [_][]const u8{ "-1", "0", "10000001", "1m" };
    for (invalid) |value| {
        const source = try std.fmt.allocPrint(
            std.testing.allocator,
            "retain_expiry_interval {s}\nlistener 1883\n" ++
                "listener_allow_anonymous true\n",
            .{value},
        );
        defer std.testing.allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(std.testing.allocator, source),
        );
    }
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\retain_expiry_interval 1
            \\retain_expiry_interval 2
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config validates WebSocket header size" {
    var minimum = try parse(std.testing.allocator,
        \\websockets_headers_size 1
        \\listener 8080
        \\protocol websockets
        \\listener_allow_anonymous true
    );
    defer minimum.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 1), minimum.websocket_headers_size);

    var maximum = try parse(std.testing.allocator,
        \\listener 8080
        \\protocol websockets
        \\listener_allow_anonymous true
        \\websockets_headers_size 65535
    );
    defer maximum.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        maximum.websocket_headers_size,
    );
    for ([_][]const u8{ "-1", "0", "65536" }) |value| {
        const source = try std.fmt.allocPrint(
            std.testing.allocator,
            "websockets_headers_size {s}\nlistener 8080\n" ++
                "protocol websockets\nlistener_allow_anonymous true\n",
            .{value},
        );
        defer std.testing.allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(std.testing.allocator, source),
        );
    }
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\websockets_headers_size 4096
            \\websockets_headers_size 8192
            \\listener 8080
            \\protocol websockets
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config validates global TCP no-delay policy" {
    var enabled = try parse(std.testing.allocator,
        \\set_tcp_nodelay true
        \\listener 1883
        \\listener_allow_anonymous true
        \\listener 1884
        \\listener_allow_anonymous true
    );
    defer enabled.deinit(std.testing.allocator);
    try std.testing.expect(enabled.set_tcp_nodelay);
    try std.testing.expectEqual(@as(usize, 2), enabled.listeners.len);

    try std.testing.expectError(
        error.InvalidBoolean,
        parse(std.testing.allocator,
            \\set_tcp_nodelay yes
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\set_tcp_nodelay true
            \\set_tcp_nodelay false
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config maps zero maximum Keep Alive to unlimited" {
    var config = try parse(std.testing.allocator,
        \\listener 1883
        \\max_keepalive 0
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(?u16, null),
        config.listeners[0].maximum_keep_alive_seconds,
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(std.testing.allocator,
            \\listener 1883
            \\max_keepalive -1
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(std.testing.allocator,
            \\listener 1883
            \\max_keepalive 65536
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config rejects invalid persistent client expiration" {
    const invalid = [_][]const u8{
        "", "1", "0s", "-1s", "1S", "1x", "4294967295y",
    };
    for (invalid) |value| {
        const source = try std.fmt.allocPrint(
            std.testing.allocator,
            "persistent_client_expiration {s}\nlistener 1883\n" ++
                "listener_allow_anonymous true\n",
            .{value},
        );
        defer std.testing.allocator.free(source);
        try std.testing.expectError(
            if (value.len == 0)
                error.InvalidDirective
            else
                error.InvalidInteger,
            parse(std.testing.allocator, source),
        );
    }
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\persistent_client_expiration 1h
            \\persistent_client_expiration 2h
            \\listener 1883
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config scopes full-range Topic Alias limits per listener" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "max_topic_alias 1\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "max_topic_alias_broker 1\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\max_topic_alias 1
            \\max_topic_alias 2
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\max_topic_alias_broker 1
            \\max_topic_alias_broker 2
            \\listener_allow_anonymous true
        ),
    );
    var config = try parse(std.testing.allocator,
        \\listener 1883
        \\max_topic_alias 0
        \\max_topic_alias_broker 65535
        \\listener_allow_anonymous true
        \\listener 1884
        \\max_topic_alias 65535
        \\max_topic_alias_broker 0
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 0), config.listeners[0].max_topic_alias);
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        config.listeners[0].max_topic_alias_broker,
    );
    try std.testing.expectEqual(
        std.math.maxInt(u16),
        config.listeners[1].max_topic_alias,
    );
    try std.testing.expectEqual(
        @as(u16, 0),
        config.listeners[1].max_topic_alias_broker,
    );
}

test "MQTT broker config scopes accepted protocol versions per listener" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 1883
        \\accept_protocol_versions 5
        \\listener_allow_anonymous true
        \\listener 1884
        \\accept_protocol_versions 3, 4, 5
        \\listener_allow_anonymous true
        \\listener 1885
        \\accept_protocol_versions 4
        \\listener_allow_anonymous true
    );
    defer config.deinit(allocator);
    try std.testing.expect(!config.listeners[0].accepted_protocol_versions.v3_1);
    try std.testing.expect(!config.listeners[0].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(config.listeners[0].accepted_protocol_versions.v5);
    try std.testing.expect(config.listeners[1].accepted_protocol_versions.v3_1);
    try std.testing.expect(config.listeners[1].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(config.listeners[1].accepted_protocol_versions.v5);
    try std.testing.expect(!config.listeners[2].accepted_protocol_versions.v3_1);
    try std.testing.expect(config.listeners[2].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(!config.listeners[2].accepted_protocol_versions.v5);

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator,
            \\accept_protocol_versions 5
            \\listener 1883
        ),
    );
    const invalid = [_][]const u8{ "", "6", "3,3", "4,4", "," };
    for (invalid) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "listener 1883\naccept_protocol_versions {s}\n" ++
                "listener_allow_anonymous true\n",
            .{value},
        );
        defer allocator.free(source);
        try std.testing.expectError(
            if (value.len == 0 or std.mem.eql(u8, value, ","))
                error.InvalidDirective
            else
                error.InvalidInteger,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\accept_protocol_versions 4
            \\accept_protocol_versions 5
            \\listener_allow_anonymous true
        ),
    );
}

test "MQTT broker config validates listener PROXY protocol versions" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 1883
        \\enable_proxy_protocol 1
        \\listener_allow_anonymous true
        \\listener 8080
        \\protocol websockets
        \\enable_proxy_protocol 2
        \\listener_allow_anonymous true
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(
        mqtt.proxy_protocol.Version.v1,
        config.listeners[0].proxy_protocol.?,
    );
    try std.testing.expectEqual(
        mqtt.proxy_protocol.Version.v2,
        config.listeners[1].proxy_protocol.?,
    );

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "enable_proxy_protocol 1\nlistener 1883\n"),
    );
    for ([_][]const u8{ "0", "3", "-1" }) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "listener 1883\nenable_proxy_protocol {s}\n" ++
                "listener_allow_anonymous true\n",
            .{value},
        );
        defer allocator.free(source);
        try std.testing.expectError(
            error.InvalidInteger,
            parse(allocator, source),
        );
    }
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\enable_proxy_protocol 1
            \\enable_proxy_protocol 2
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 8883
            \\enable_proxy_protocol 2
            \\certfile server.pem
            \\keyfile server.key
            \\listener_allow_anonymous true
        ),
    );

    var proxy_tls = try parse(allocator,
        \\listener 1883
        \\enable_proxy_protocol 2
        \\proxy_protocol_v2_require_tls true
        \\require_certificate true
        \\use_identity_as_username true
        \\listener_allow_anonymous false
    );
    defer proxy_tls.deinit(allocator);
    try std.testing.expect(
        proxy_tls.listeners[0].proxy_protocol_v2_require_tls,
    );
    try std.testing.expect(proxy_tls.listeners[0].require_certificate);
    try std.testing.expect(proxy_tls.listeners[0].use_identity_as_username);

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "proxy_protocol_v2_require_tls true\nlistener 1883\n",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\enable_proxy_protocol 2
            \\proxy_protocol_v2_require_tls true
            \\proxy_protocol_v2_require_tls false
            \\listener_allow_anonymous true
        ),
    );
    for ([_][]const u8{
        \\listener 1883
        \\proxy_protocol_v2_require_tls true
        \\listener_allow_anonymous true
        ,
        \\listener 1883
        \\enable_proxy_protocol 1
        \\proxy_protocol_v2_require_tls true
        \\listener_allow_anonymous true
        ,
        \\listener 1883
        \\enable_proxy_protocol 2
        \\require_certificate true
        \\use_subject_as_username true
        \\listener_allow_anonymous false
        ,
    }) |source| {
        try std.testing.expectError(
            error.InvalidDirective,
            parse(allocator, source),
        );
    }
}

test "MQTT broker config accumulates WebSocket Origin allowlists" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "listener 8080\n" ++
            "websockets_origin https://first.example\n" ++
            "websockets_origin https://second.example:8443\n" ++
            "protocol websockets\n" ++
            "listener_allow_anonymous true\n",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');
    try std.testing.expectEqual(
        @as(usize, 2),
        config.listeners[0].websocket_origins.items.len,
    );
    try std.testing.expectEqualStrings(
        "https://first.example",
        config.listeners[0].websocket_origins.items[0],
    );
    try std.testing.expectEqualStrings(
        "https://second.example:8443",
        config.listeners[0].websocket_origins.items[1],
    );

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator,
            \\websockets_origin https://example.org
            \\listener 8080
            \\protocol websockets
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 1883
            \\websockets_origin https://example.org
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 8080
            \\protocol websockets
            \\websockets_origin
            \\listener_allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "listener 8080\nprotocol websockets\n" ++
                "websockets_origin bad\x7forigin\n" ++
                "listener_allow_anonymous true\n",
        ),
    );
}

test "MQTT broker config maps zero queued messages to unlimited" {
    var config = try parse(std.testing.allocator,
        \\max_queued_messages 0
        \\max_queued_bytes 0
        \\listener 1883
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), config.max_queued_messages);
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        config.effectiveMaxQueuedMessages(),
    );
    try std.testing.expectEqual(@as(usize, 0), config.max_queued_bytes);
}

test "MQTT broker config keeps queued limits global" {
    var config = try parse(std.testing.allocator,
        \\per_listener_settings true
        \\listener 1883
        \\listener_allow_anonymous true
        \\max_queued_messages 11
        \\max_queued_bytes 4096
        \\max_inflight_bytes 2048
        \\listener 1884
        \\listener_allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 11), config.max_queued_messages);
    try std.testing.expectEqual(@as(usize, 4096), config.max_queued_bytes);
    try std.testing.expectEqual(@as(usize, 2048), config.max_inflight_bytes);
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
}

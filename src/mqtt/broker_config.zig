//! Strict Mosquitto-style configuration for the netz MQTT broker runtime.
//!
//! This module intentionally supports a documented subset. Unknown, duplicate,
//! or misplaced directives fail closed instead of silently weakening listener
//! authentication or resource policy.

const std = @import("std");
const http1 = @import("../http1/mod.zig");
const mqtt = @import("mod.zig");
const broker_config_include = @import("broker_config_include.zig");
const client_id = @import("broker/client_id.zig");

const net = std.Io.net;

pub const max_config_bytes: usize = 1024 * 1024;
pub const default_max_connections: usize = 16;
pub const default_global_max_clients: usize = 16_384;
pub const default_global_max_connections: usize = std.math.maxInt(u31);
pub const default_max_packet_size: usize = 2_000_000;
pub const default_max_inflight_messages: u16 = 20;
pub const default_max_queued_messages: usize = 1_000;
pub const default_max_topic_aliases: u16 = 10;
pub const default_websocket_headers_size: u16 = 4096;
pub const default_sys_interval_seconds: u16 = 10;
pub const maximum_retain_expiry_interval_minutes: u32 = 10_000_000;
pub const default_auto_id_prefix = "auto-";
pub const default_persistence_file = "netz-mqtt.db";
pub const default_autosave_interval: u32 = 1800;

pub const Protocol = enum { mqtt, websockets };

pub const Listener = struct {
    address: net.IpAddress,
    protocol: Protocol = .mqtt,
    password_file: []u8 = &.{},
    acl_file: []u8 = &.{},
    certfile: []u8 = &.{},
    keyfile: []u8 = &.{},
    cafile: []u8 = &.{},
    capath: []u8 = &.{},
    crlfile: []u8 = &.{},
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
        if (self.password_file.len != 0) allocator.free(self.password_file);
        if (self.acl_file.len != 0) allocator.free(self.acl_file);
        if (self.auto_id_prefix.len != 0) allocator.free(self.auto_id_prefix);
        if (self.certfile.len != 0) allocator.free(self.certfile);
        if (self.keyfile.len != 0) allocator.free(self.keyfile);
        if (self.cafile.len != 0) allocator.free(self.cafile);
        if (self.capath.len != 0) allocator.free(self.capath);
        if (self.crlfile.len != 0) allocator.free(self.crlfile);
        if (self.mount_point.len != 0) allocator.free(self.mount_point);
        for (self.websocket_origins.items) |origin| allocator.free(origin);
        self.websocket_origins.deinit(allocator);
        self.* = undefined;
    }

    pub fn usesTls(self: Listener) bool {
        return self.certfile.len != 0;
    }
};

pub const Config = struct {
    listeners: []Listener,
    global_max_clients: usize = default_global_max_clients,
    global_max_connections: usize = default_global_max_connections,
    per_listener_settings: bool = false,
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
    retain_available: bool = true,
    check_retain_source: bool = true,
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
        if (self.password_file.len != 0) allocator.free(self.password_file);
        if (self.acl_file.len != 0) allocator.free(self.acl_file);
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
    InvalidDirective,
    InvalidBoolean,
    InvalidInteger,
    DuplicateListener,
    PersistenceRequired,
    AuthenticationRequired,
    TlsIdentityIncomplete,
    ClientCertificateConfigurationIncomplete,
    CapathUnsupportedForWebSockets,
    IntegerOverflow,
} || std.mem.Allocator.Error;

const ListenerSeen = struct {
    password_file: bool = false,
    acl_file: bool = false,
    protocol: bool = false,
    certfile: bool = false,
    keyfile: bool = false,
    cafile: bool = false,
    capath: bool = false,
    crlfile: bool = false,
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
    retain_available: bool = false,
    check_retain_source: bool = false,
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
        if (config.auto_id_prefix.len != 0) {
            allocator.free(config.auto_id_prefix);
        }
    }
    var global_seen: GlobalSeen = .{};
    var security_settings_seen = false;
    const current_listener = try allocator.alloc(?usize, scope_count);
    defer allocator.free(current_listener);
    @memset(current_listener, null);

    for (sources) |source| {
        if (source.scope >= current_listener.len) return error.InvalidDirective;
        var lines = std.mem.splitScalar(u8, source.bytes, '\n');
        while (lines.next()) |raw_line| {
            const without_comment = if (std.mem.findScalar(u8, raw_line, '#')) |i|
                raw_line[0..i]
            else
                raw_line;
            const line = std.mem.trim(u8, without_comment, " \t\r");
            if (line.len == 0) continue;
            var words = std.mem.tokenizeAny(u8, line, " \t");
            const directive = words.next().?;

            if (std.mem.eql(u8, directive, "listener")) {
                const port_text = words.next() orelse return error.InvalidDirective;
                const port = parsePort(port_text) catch return error.InvalidInteger;
                const host = words.next() orelse "0.0.0.0";
                if (words.next() != null) return error.InvalidDirective;
                const address = net.IpAddress.parse(host, port) catch
                    return error.InvalidDirective;
                for (listeners.items) |existing| {
                    if (existing.address.eql(&address)) {
                        return error.DuplicateListener;
                    }
                }
                try listeners.append(allocator, .{ .address = address });
                try listener_seen.append(allocator, .{});
                current_listener[source.scope] = listeners.items.len - 1;
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
            } else if (std.mem.eql(u8, directive, "retain_available")) {
                try markOnce(&global_seen.retain_available);
                config.retain_available = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "check_retain_source")) {
                try markOnce(&global_seen.check_retain_source);
                config.check_retain_source = try parseOneBool(&words);
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
                } else if (std.mem.eql(u8, directive, "certfile")) {
                    try markOnce(&seen.certfile);
                    listener.certfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "keyfile")) {
                    try markOnce(&seen.keyfile);
                    listener.keyfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "cafile")) {
                    try markOnce(&seen.cafile);
                    listener.cafile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "capath")) {
                    try markOnce(&seen.capath);
                    listener.capath = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "crlfile")) {
                    try markOnce(&seen.crlfile);
                    listener.crlfile = try parseOneOwned(allocator, &words);
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
                } else if (std.mem.eql(u8, directive, "allow_anonymous")) {
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
                } else if (std.mem.eql(u8, directive, "max_qos")) {
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
    for (listeners.items, listener_seen.items) |listener, seen| {
        const has_client_ca = listener.cafile.len != 0 or
            listener.capath.len != 0;
        if ((listener.certfile.len == 0) != (listener.keyfile.len == 0)) {
            return error.TlsIdentityIncomplete;
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
        const password_file = if (config.per_listener_settings)
            listener.password_file
        else
            config.password_file;
        if (!listener.allow_anonymous and password_file.len == 0 and
            !listener.use_identity_as_username and
            !listener.use_subject_as_username)
        {
            return error.AuthenticationRequired;
        }
    }
    const candidate = Config{ .listeners = listeners.items };
    _ = try candidate.totalMaxConnections();
    config.listeners = try listeners.toOwnedSlice(allocator);
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
        std.mem.eql(u8, value, "certfile") or
        std.mem.eql(u8, value, "keyfile") or
        std.mem.eql(u8, value, "cafile") or
        std.mem.eql(u8, value, "capath") or
        std.mem.eql(u8, value, "crlfile") or
        std.mem.eql(u8, value, "require_certificate") or
        std.mem.eql(u8, value, "use_identity_as_username") or
        std.mem.eql(u8, value, "use_subject_as_username") or
        std.mem.eql(u8, value, "mount_point") or
        std.mem.eql(u8, value, "allow_anonymous") or
        std.mem.eql(u8, value, "listener_auto_id_prefix") or
        std.mem.eql(u8, value, "max_qos") or
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

fn parsePort(value: []const u8) error{InvalidInteger}!u16 {
    const port = std.fmt.parseInt(u16, value, 10) catch
        return error.InvalidInteger;
    if (port == 0) return error.InvalidInteger;
    return port;
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
        .v3_1_1 = false,
        .v5 = false,
    };
    var saw_version = false;
    while (words.next()) |word| {
        var versions = std.mem.splitScalar(u8, word, ',');
        while (versions.next()) |version| {
            if (version.len == 0) continue;
            saw_version = true;
            if (std.mem.eql(u8, version, "4")) {
                if (result.v3_1_1) return error.InvalidInteger;
                result.v3_1_1 = true;
            } else if (std.mem.eql(u8, version, "5")) {
                if (result.v5) return error.InvalidInteger;
                result.v5 = true;
            } else {
                // MQTT 3.1 (level 3) is not implemented by netz. Rejecting it
                // here avoids advertising a policy the runtime cannot honor.
                return error.InvalidInteger;
            }
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
        \\allow_anonymous true
        \\enable_proxy_protocol 1
        \\max_qos 1
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
        \\cafile client-ca.pem
        \\crlfile clients.crl
        \\require_certificate true
        \\use_identity_as_username true
        \\use_subject_as_username true
        \\mount_point tenant/
        \\allow_anonymous false
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

test "MQTT broker config validates global client session limit" {
    const allocator = std.testing.allocator;

    var unlimited = try parse(allocator,
        \\global_max_clients -1
        \\listener 1883
        \\allow_anonymous true
    );
    defer unlimited.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, std.math.maxInt(u31)),
        unlimited.global_max_clients,
    );

    for ([_][]const u8{ "0", "-2", "2147483648", "invalid" }) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "global_max_clients {s}\nlistener 1883\nallow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\global_max_clients 1
            \\global_max_clients 2
            \\listener 1883
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config validates global connection limit" {
    const allocator = std.testing.allocator;

    var unlimited = try parse(allocator,
        \\global_max_connections -1
        \\listener 1883
        \\allow_anonymous true
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
        \\allow_anonymous true
    );
    defer omitted.deinit(allocator);
    try std.testing.expectEqual(
        default_global_max_connections,
        omitted.global_max_connections,
    );

    for ([_][]const u8{ "0", "-2", "2147483648", "invalid" }) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "global_max_connections {s}\nlistener 1883\nallow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\global_max_connections 1
            \\global_max_connections 2
            \\listener 1883
            \\allow_anonymous true
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
            "allow_anonymous false\n" ++
            "listener 8080 127.0.0.1\nprotocol websockets\n" ++
            "password_file second.pw\nacl_file second.acl\n" ++
            "listener_auto_id_prefix second-\n" ++
            "allow_zero_length_clientid true\n" ++
            "allow_anonymous false\n",
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
        \\allow_anonymous true
        \\listener 1884
        \\listener_auto_id_prefix local-
        \\allow_anonymous true
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
        \\allow_anonymous true
        \\listener 1886
        \\listener_auto_id_prefix second-
        \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator,
            \\listener_auto_id_prefix missing-
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\listener_auto_id_prefix first-
            \\listener_auto_id_prefix second-
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\per_listener_settings true
            \\listener 1883
            \\auto_id_prefix first-
            \\listener_auto_id_prefix second-
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\auto_id_prefix first-
            \\auto_id_prefix second-
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\auto_id_prefix 123456789012345678901234567890123456789012345678901
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidUtf8,
        parse(
            allocator,
            "listener 1883\nlistener_auto_id_prefix bad\xc0\x80prefix\n" ++
                "allow_anonymous true\n",
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
                "listener 1883\nallow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\allow_zero_length_clientid true
            \\listener 1883
            \\allow_zero_length_clientid false
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_inflight_bytes 1
            \\max_inflight_bytes 2
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_queued_messages 1
            \\max_queued_messages 2
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_queued_bytes 1
            \\max_queued_bytes 2
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\max_inflight_messages 1
            \\max_inflight_messages 2
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\check_retain_source true
            \\check_retain_source false
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\upgrade_outgoing_qos true
            \\upgrade_outgoing_qos false
            \\listener 1883
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config keeps retained source policy global" {
    var config = try parse(std.testing.allocator,
        \\per_listener_settings true
        \\listener 1883
        \\allow_anonymous true
        \\check_retain_source false
        \\listener 1884
        \\allow_anonymous true
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
        .data = "listener 1886\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "A.conf",
        .data = "listener 1883\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "a.conf",
        .data = "listener 1884\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "B.conf",
        .data = "listener 1885\nallow_anonymous true\n",
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
        .data = "listener 1887\nallow_anonymous true\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "listener 1882\nallow_anonymous true\n" ++
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
        .data = "listener 1883\nallow_anonymous true\n",
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
            "listener 1883\nallow_anonymous true\n",
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
                "listener 1883\nallow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "listener 1883\nallow_anonymous true\n" ++
                "per_listener_settings true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "per_listener_settings true\nper_listener_settings true\n" ++
                "listener 1883\nallow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "per_listener_settings true\nlistener 1883\n" ++
                "password_file first.pw\npassword_file second.pw\n" ++
                "allow_anonymous false",
        ),
    );
    try std.testing.expectError(
        error.AuthenticationRequired,
        parse(allocator, "listener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "certfile server.pem\nlistener 1883"),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\keyfile server.key
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile first.pem
            \\certfile second.pem
            \\keyfile server.key
            \\allow_anonymous true
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
            \\allow_anonymous true
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
            \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\use_identity_as_username true
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\use_subject_as_username true
            \\allow_anonymous true
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
            \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    var capath_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile common.pem
        \\capath clients
        \\require_certificate true
        \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\require_certificate true
            \\allow_anonymous true
        ),
    );
    var optional_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\require_certificate false
        \\allow_anonymous true
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
            \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    var implicit_optional_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\allow_anonymous true
            \\allow_anonymous false
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\acl_file first.acl
            \\acl_file second.acl
            \\listener 1883
            \\allow_anonymous true
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
        \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_inflight_messages 65536
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_inflight_bytes 2147483648
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_inflight_bytes -1
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_messages 2147483648
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_messages -1
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_bytes 2147483648
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator,
            \\max_queued_bytes -1
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_qos 3"),
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
            "mount_point tenant/\nallow_anonymous true\n",
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

test "MQTT broker config accepts certificate identity authentication" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 8883 127.0.0.1
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\require_certificate true
        \\use_identity_as_username true
        \\allow_anonymous false
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
            "listener 1884\nallow_anonymous true\n",
    );
    defer minimum.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 20), minimum.max_packet_size);
    try std.testing.expectEqual(
        @as(usize, 268_435_455),
        minimum.message_size_limit,
    );
}

test "MQTT broker config maps zero inflight messages to protocol maximum" {
    var config = try parse(std.testing.allocator,
        \\max_inflight_messages 0
        \\listener 1883
        \\allow_anonymous true
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
        \\allow_anonymous true
        \\max_inflight_messages 65535
        \\listener 1884
        \\allow_anonymous true
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
                "allow_anonymous true\n",
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
        \\allow_anonymous true
    );
    defer disabled.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 0), disabled.sys_interval_seconds);

    var maximum = try parse(std.testing.allocator,
        \\listener 1883
        \\allow_anonymous true
        \\sys_interval 65535
        \\listener 1884
        \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(std.testing.allocator,
            \\sys_interval 65536
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\sys_interval 1
            \\sys_interval 2
            \\listener 1883
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config validates retained expiry scan interval" {
    var minimum = try parse(std.testing.allocator,
        \\retain_expiry_interval 1
        \\listener 1883
        \\allow_anonymous true
    );
    defer minimum.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        @as(u32, std.time.s_per_min),
        minimum.retain_expiry_interval_seconds,
    );

    var maximum = try parse(std.testing.allocator,
        \\listener 1883
        \\allow_anonymous true
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
                "allow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config validates WebSocket header size" {
    var minimum = try parse(std.testing.allocator,
        \\websockets_headers_size 1
        \\listener 8080
        \\protocol websockets
        \\allow_anonymous true
    );
    defer minimum.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 1), minimum.websocket_headers_size);

    var maximum = try parse(std.testing.allocator,
        \\listener 8080
        \\protocol websockets
        \\allow_anonymous true
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
                "protocol websockets\nallow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config validates global TCP no-delay policy" {
    var enabled = try parse(std.testing.allocator,
        \\set_tcp_nodelay true
        \\listener 1883
        \\allow_anonymous true
        \\listener 1884
        \\allow_anonymous true
    );
    defer enabled.deinit(std.testing.allocator);
    try std.testing.expect(enabled.set_tcp_nodelay);
    try std.testing.expectEqual(@as(usize, 2), enabled.listeners.len);

    try std.testing.expectError(
        error.InvalidBoolean,
        parse(std.testing.allocator,
            \\set_tcp_nodelay yes
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(std.testing.allocator,
            \\set_tcp_nodelay true
            \\set_tcp_nodelay false
            \\listener 1883
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config maps zero maximum Keep Alive to unlimited" {
    var config = try parse(std.testing.allocator,
        \\listener 1883
        \\max_keepalive 0
        \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(std.testing.allocator,
            \\listener 1883
            \\max_keepalive 65536
            \\allow_anonymous true
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
                "allow_anonymous true\n",
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
            \\allow_anonymous true
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\max_topic_alias_broker 1
            \\max_topic_alias_broker 2
            \\allow_anonymous true
        ),
    );
    var config = try parse(std.testing.allocator,
        \\listener 1883
        \\max_topic_alias 0
        \\max_topic_alias_broker 65535
        \\allow_anonymous true
        \\listener 1884
        \\max_topic_alias 65535
        \\max_topic_alias_broker 0
        \\allow_anonymous true
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
        \\allow_anonymous true
        \\listener 1884
        \\accept_protocol_versions 4, 5
        \\allow_anonymous true
        \\listener 1885
        \\accept_protocol_versions 4
        \\allow_anonymous true
    );
    defer config.deinit(allocator);
    try std.testing.expect(!config.listeners[0].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(config.listeners[0].accepted_protocol_versions.v5);
    try std.testing.expect(config.listeners[1].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(config.listeners[1].accepted_protocol_versions.v5);
    try std.testing.expect(config.listeners[2].accepted_protocol_versions.v3_1_1);
    try std.testing.expect(!config.listeners[2].accepted_protocol_versions.v5);

    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator,
            \\accept_protocol_versions 5
            \\listener 1883
        ),
    );
    const invalid = [_][]const u8{ "", "3", "6", "4,4", "," };
    for (invalid) |value| {
        const source = try std.fmt.allocPrint(
            allocator,
            "listener 1883\naccept_protocol_versions {s}\n" ++
                "allow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
}

test "MQTT broker config validates listener PROXY protocol versions" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 1883
        \\enable_proxy_protocol 1
        \\allow_anonymous true
        \\listener 8080
        \\protocol websockets
        \\enable_proxy_protocol 2
        \\allow_anonymous true
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
                "allow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 8883
            \\enable_proxy_protocol 2
            \\certfile server.pem
            \\keyfile server.key
            \\allow_anonymous true
        ),
    );

    var proxy_tls = try parse(allocator,
        \\listener 1883
        \\enable_proxy_protocol 2
        \\proxy_protocol_v2_require_tls true
        \\require_certificate true
        \\use_identity_as_username true
        \\allow_anonymous false
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
            \\allow_anonymous true
        ),
    );
    for ([_][]const u8{
        \\listener 1883
        \\proxy_protocol_v2_require_tls true
        \\allow_anonymous true
        ,
        \\listener 1883
        \\enable_proxy_protocol 1
        \\proxy_protocol_v2_require_tls true
        \\allow_anonymous true
        ,
        \\listener 1883
        \\enable_proxy_protocol 2
        \\require_certificate true
        \\use_subject_as_username true
        \\allow_anonymous false
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
            "allow_anonymous true\n",
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
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\listener 8080
            \\protocol websockets
            \\websockets_origin
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "listener 8080\nprotocol websockets\n" ++
                "websockets_origin bad\x7forigin\n" ++
                "allow_anonymous true\n",
        ),
    );
}

test "MQTT broker config maps zero queued messages to unlimited" {
    var config = try parse(std.testing.allocator,
        \\max_queued_messages 0
        \\max_queued_bytes 0
        \\listener 1883
        \\allow_anonymous true
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
        \\allow_anonymous true
        \\max_queued_messages 11
        \\max_queued_bytes 4096
        \\max_inflight_bytes 2048
        \\listener 1884
        \\allow_anonymous true
    );
    defer config.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 11), config.max_queued_messages);
    try std.testing.expectEqual(@as(usize, 4096), config.max_queued_bytes);
    try std.testing.expectEqual(@as(usize, 2048), config.max_inflight_bytes);
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
}

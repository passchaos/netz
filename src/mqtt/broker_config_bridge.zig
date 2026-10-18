//! Owned Mosquitto-style bridge configuration.
//!
//! The top-level broker parser owns scope selection. This module keeps the
//! bridge grammar, validation, and allocation lifecycle out of the already
//! large listener configuration module.

const std = @import("std");
const mqtt = @import("mod.zig");
const rule_helpers = @import("bridge/rules.zig");
const socket_options = @import("../internal/socket_options.zig");
const tls_cipher_suites = @import("../tls/cipher_suites.zig");
const tls_stream = @import("../tls/mod.zig").stream;

const net = std.Io.net;

pub const default_port: u16 = 1883;
pub const default_keep_alive_seconds: u16 = 60;
pub const default_restart_base_seconds: u16 = 5;
pub const default_restart_cap_seconds: u16 = 30;
pub const default_lazy_idle_timeout_seconds: u32 = 60;
pub const default_lazy_threshold: usize = 10;
pub const default_receive_maximum: u16 = 20;
pub const default_max_topic_alias: u16 = 10;
pub const maximum_restart_seconds: u16 = 3600;
pub const maximum_restart_cap_seconds: u16 = 7200;
pub const maximum_host_bytes: usize = 255;
/// Mosquitto parses bridge_tcp_user_timeout into a non-negative C `int`.
pub const maximum_tcp_user_timeout_ms: u32 = std.math.maxInt(i32);

pub const Error = mqtt.Error || tls_cipher_suites.Error ||
    std.mem.Allocator.Error || error{
    DuplicateDirective,
    InvalidDirective,
    InvalidBoolean,
    InvalidInteger,
    BridgeAddressRequired,
    BridgeTopicRequired,
    BridgeAuthenticationIncomplete,
    BridgePersistenceRequired,
    BridgePersistentSessionRequired,
    BridgeTlsIdentityIncomplete,
    BridgeTlsTrustRequired,
    BridgeNotificationsDisabled,
    BridgeLazyThresholdExceedsQueueLimit,
    BridgeAddressFamilyMismatch,
    DuplicateBridgeAddress,
    DuplicateBridgeFilter,
    OverlappingBridgeFilters,
    UnsupportedBridgeDirection,
    UnsupportedBridgeProtocol,
    UnsupportedBridgeRestartTimeout,
    UnsupportedBridgeStartType,
    UnsupportedBridgeTlsVersion,
    /// Retained for source compatibility; explicit hostname opt-out is now
    /// represented by `Bridge.verify_host = false`.
    InsecureBridgeTlsUnsupported,
};

pub const RestartPolicy = struct {
    base_seconds: u16 = default_restart_base_seconds,
    cap_seconds: u16 = default_restart_cap_seconds,
    jitter: bool = true,
    stable_connection_seconds: u32 = 0,
};

pub const StartType = enum {
    automatic,
    lazy,
    once,
};

pub const ReloadType = enum {
    lazy,
    immediate,
};

pub const Rule = struct {
    /// Effective filter sent to the remote broker, including remote_prefix.
    filter: []u8,
    qos: mqtt.QoS,
    local_prefix: []u8 = &.{},
    remote_prefix: []u8 = &.{},
    direction: Direction = .in,

    /// Allocate the unprefixed outbound filter, preserving a shared-subscription
    /// wrapper around its unprefixed inner Topic Filter.
    pub fn outboundFilterAlloc(self: Rule, allocator: std.mem.Allocator) Error![]u8 {
        try mqtt.validateTopicFilter(self.filter);
        const inner = rule_helpers.effectiveFilter(self.filter);
        if (!std.mem.startsWith(u8, inner, self.remote_prefix)) return error.InvalidSubscription;
        const base = inner[self.remote_prefix.len..];
        if (!std.mem.startsWith(u8, self.filter, "$share/")) return allocator.dupe(u8, base);
        return std.mem.concat(allocator, u8, &.{ self.filter[0 .. self.filter.len - inner.len], base });
    }

    fn deinit(self: *Rule, allocator: std.mem.Allocator) void {
        allocator.free(self.filter);
        if (self.local_prefix.len != 0) allocator.free(self.local_prefix);
        if (self.remote_prefix.len != 0) allocator.free(self.remote_prefix);
        self.* = undefined;
    }
};

pub const Direction = enum { in, out, both };

pub const Endpoint = struct {
    host: []const u8,
    port: u16,

    fn deinit(self: *Endpoint, allocator: std.mem.Allocator) void {
        allocator.free(@constCast(self.host));
        self.* = undefined;
    }
};

pub const Bridge = struct {
    name: []u8,
    host: []u8,
    port: u16 = default_port,
    secondary_addresses: []Endpoint = &.{},
    rules: []Rule,
    protocol: mqtt.ProtocolVersion = .v3_1_1,
    clean_session: bool = false,
    local_clean_session: bool = false,
    session_expiry_interval: u32 = 0,
    keep_alive_seconds: u16 = default_keep_alive_seconds,
    receive_maximum: u16 = default_receive_maximum,
    max_topic_alias: u16 = default_max_topic_alias,
    max_packet_size: u32 = 0,
    outgoing_retain: bool = true,
    attempt_unsubscribe: bool = true,
    try_private: bool = true,
    bind_address: ?net.IpAddress = null,
    tcp_keepalive: ?socket_options.TcpKeepAlive = null,
    tcp_user_timeout_ms: ?u32 = null,
    local_client_id: []u8 = &.{},
    remote_client_id: []u8 = &.{},
    remote_username: []u8 = &.{},
    remote_password: []u8 = &.{},
    ca_file: []u8 = &.{},
    ca_path: []u8 = &.{},
    use_os_ca_certificates: bool = false,
    certificate_file: []u8 = &.{},
    private_key_file: []u8 = &.{},
    private_key_password_file: []u8 = &.{},
    alpn: []u8 = &.{},
    cipher_suites: []tls_cipher_suites.Suite = &.{},
    tls12_cipher_suites: []tls_cipher_suites.Tls12Suite = &.{},
    tls_protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    require_ocsp: bool = false,
    /// Verify the configured bridge host against the server certificate.
    /// `bridge_insecure true` disables only this identity match.
    verify_host: bool = true,
    round_robin: bool = false,
    start_type: StartType = .automatic,
    reload_type: ReloadType = .lazy,
    idle_timeout_seconds: u32 = default_lazy_idle_timeout_seconds,
    threshold: usize = default_lazy_threshold,
    notifications: bool = true,
    notifications_local_only: bool = false,
    notification_topic: []u8 = &.{},
    restart: RestartPolicy = .{},

    /// Deep-copy a validated bridge configuration for a runtime owner. This
    /// keeps connector callbacks and reconnect state independent from the
    /// parser document, which is required before bridge configurations can be
    /// staged and atomically replaced on reload.
    pub fn clone(
        self: Bridge,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Bridge {
        var copy = self;
        copy.name = &.{};
        copy.host = &.{};
        copy.secondary_addresses = &.{};
        copy.rules = &.{};
        copy.local_client_id = &.{};
        copy.remote_client_id = &.{};
        copy.remote_username = &.{};
        copy.remote_password = &.{};
        copy.ca_file = &.{};
        copy.ca_path = &.{};
        copy.certificate_file = &.{};
        copy.private_key_file = &.{};
        copy.private_key_password_file = &.{};
        copy.alpn = &.{};
        copy.cipher_suites = &.{};
        copy.tls12_cipher_suites = &.{};
        copy.notification_topic = &.{};
        errdefer copy.deinit(allocator);

        copy.name = try allocator.dupe(u8, self.name);
        copy.host = try allocator.dupe(u8, self.host);
        copy.secondary_addresses = try cloneEndpoints(
            allocator,
            self.secondary_addresses,
        );
        copy.rules = try cloneRules(allocator, self.rules);
        copy.local_client_id = try cloneBytes(allocator, self.local_client_id);
        copy.remote_client_id = try cloneBytes(allocator, self.remote_client_id);
        copy.remote_username = try cloneBytes(allocator, self.remote_username);
        copy.remote_password = try cloneBytes(allocator, self.remote_password);
        copy.ca_file = try cloneBytes(allocator, self.ca_file);
        copy.ca_path = try cloneBytes(allocator, self.ca_path);
        copy.certificate_file = try cloneBytes(allocator, self.certificate_file);
        copy.private_key_file = try cloneBytes(allocator, self.private_key_file);
        copy.private_key_password_file = try cloneBytes(
            allocator,
            self.private_key_password_file,
        );
        copy.alpn = try cloneBytes(allocator, self.alpn);
        copy.cipher_suites = try cloneSlice(
            tls_cipher_suites.Suite,
            allocator,
            self.cipher_suites,
        );
        copy.tls12_cipher_suites = try cloneSlice(
            tls_cipher_suites.Tls12Suite,
            allocator,
            self.tls12_cipher_suites,
        );
        copy.notification_topic = try cloneBytes(
            allocator,
            self.notification_topic,
        );
        return copy;
    }

    pub fn deinit(self: *Bridge, allocator: std.mem.Allocator) void {
        for (self.rules) |*rule| rule.deinit(allocator);
        allocator.free(self.rules);
        if (self.remote_password.len != 0) {
            std.crypto.secureZero(u8, self.remote_password);
            allocator.free(self.remote_password);
        }
        if (self.remote_username.len != 0) allocator.free(self.remote_username);
        if (self.local_client_id.len != 0) allocator.free(self.local_client_id);
        if (self.remote_client_id.len != 0) allocator.free(self.remote_client_id);
        if (self.ca_file.len != 0) allocator.free(self.ca_file);
        if (self.ca_path.len != 0) allocator.free(self.ca_path);
        if (self.certificate_file.len != 0) allocator.free(self.certificate_file);
        if (self.private_key_file.len != 0) allocator.free(self.private_key_file);
        if (self.private_key_password_file.len != 0) {
            allocator.free(self.private_key_password_file);
        }
        if (self.alpn.len != 0) allocator.free(self.alpn);
        if (self.cipher_suites.len != 0) allocator.free(self.cipher_suites);
        if (self.tls12_cipher_suites.len != 0) {
            allocator.free(self.tls12_cipher_suites);
        }
        if (self.notification_topic.len != 0) {
            allocator.free(self.notification_topic);
        }
        for (self.secondary_addresses) |*endpoint| endpoint.deinit(allocator);
        if (self.secondary_addresses.len != 0) {
            allocator.free(self.secondary_addresses);
        }
        allocator.free(self.host);
        allocator.free(self.name);
        self.* = undefined;
    }

    pub fn clientId(self: Bridge) []const u8 {
        return if (self.remote_client_id.len != 0)
            self.remote_client_id
        else
            self.name;
    }

    pub fn localClientId(self: Bridge) []const u8 {
        return if (self.local_client_id.len != 0)
            self.local_client_id
        else
            self.name;
    }

    pub fn usesQoS2(self: Bridge) bool {
        for (self.rules) |rule| {
            if (rule.qos == .exactly_once) return true;
        }
        return false;
    }

    pub fn usesOutboundQoS2(self: Bridge) bool {
        for (self.rules) |rule| {
            if (rule.direction != .in and rule.qos == .exactly_once) {
                return true;
            }
        }
        return false;
    }

    pub fn hasOutbound(self: Bridge) bool {
        for (self.rules) |rule| if (rule.direction != .in) return true;
        return false;
    }

    pub fn hasInbound(self: Bridge) bool {
        for (self.rules) |rule| if (rule.direction != .out) return true;
        return false;
    }

    pub fn usesTls(self: Bridge) bool {
        return self.ca_file.len != 0 or self.ca_path.len != 0 or
            self.use_os_ca_certificates or self.cipher_suites.len != 0 or
            self.require_ocsp;
    }

    pub fn usesPrivateBridgeMode(self: Bridge) bool {
        return self.protocol.isLegacy() and self.try_private;
    }

    /// A bidirectional legacy bridge cannot safely fall back to an ordinary
    /// MQTT client connection: MQTT 3.1 and 3.1.1 have no subscription-level
    /// No Local or Retain As Published bits. Mosquitto's private bridge marker
    /// is therefore required to prevent loops and preserve retained state.
    pub fn requiresPrivateBridgeMode(self: Bridge) bool {
        return self.usesPrivateBridgeMode() and
            self.hasInbound() and self.hasOutbound();
    }

    pub fn addressCount(self: Bridge) usize {
        return 1 + self.secondary_addresses.len;
    }

    pub fn addressAt(self: Bridge, index: usize) Endpoint {
        if (index == 0) return .{ .host = self.host, .port = self.port };
        return self.secondary_addresses[index - 1];
    }

    pub fn notificationTopicAlloc(
        self: Bridge,
        allocator: std.mem.Allocator,
    ) Error![]u8 {
        if (self.notification_topic.len != 0) {
            return allocator.dupe(u8, self.notification_topic);
        }
        const topic = try std.fmt.allocPrint(
            allocator,
            "$SYS/broker/connection/{s}/state",
            .{self.clientId()},
        );
        errdefer allocator.free(topic);
        try mqtt.validateTopicName(topic);
        return topic;
    }
};

fn cloneBytes(
    allocator: std.mem.Allocator,
    value: []const u8,
) std.mem.Allocator.Error![]u8 {
    return if (value.len == 0) &.{} else allocator.dupe(u8, value);
}

fn cloneSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    value: []const T,
) std.mem.Allocator.Error![]T {
    return if (value.len == 0) &.{} else allocator.dupe(T, value);
}

fn cloneEndpoints(
    allocator: std.mem.Allocator,
    endpoints: []const Endpoint,
) std.mem.Allocator.Error![]Endpoint {
    if (endpoints.len == 0) return &.{};
    const copies = try allocator.alloc(Endpoint, endpoints.len);
    var initialized: usize = 0;
    errdefer {
        while (initialized != 0) {
            initialized -= 1;
            copies[initialized].deinit(allocator);
        }
        allocator.free(copies);
    }
    for (endpoints, copies) |source, *copy| {
        copy.* = .{
            .host = try allocator.dupe(u8, source.host),
            .port = source.port,
        };
        initialized += 1;
    }
    return copies;
}

fn cloneRules(
    allocator: std.mem.Allocator,
    rules: []const Rule,
) std.mem.Allocator.Error![]Rule {
    if (rules.len == 0) return &.{};
    const copies = try allocator.alloc(Rule, rules.len);
    var initialized: usize = 0;
    errdefer {
        while (initialized != 0) {
            initialized -= 1;
            copies[initialized].deinit(allocator);
        }
        allocator.free(copies);
    }
    for (rules, copies) |source, *copy| {
        copy.* = try cloneRule(allocator, source);
        initialized += 1;
    }
    return copies;
}

fn cloneRule(
    allocator: std.mem.Allocator,
    source: Rule,
) std.mem.Allocator.Error!Rule {
    const filter = try allocator.dupe(u8, source.filter);
    errdefer allocator.free(filter);
    const local_prefix = try cloneBytes(allocator, source.local_prefix);
    errdefer if (local_prefix.len != 0) allocator.free(local_prefix);
    const remote_prefix = try cloneBytes(allocator, source.remote_prefix);
    return .{
        .filter = filter,
        .qos = source.qos,
        .local_prefix = local_prefix,
        .remote_prefix = remote_prefix,
        .direction = source.direction,
    };
}

const Seen = struct {
    address: bool = false,
    clean_session: bool = false,
    local_clean_session: bool = false,
    bridge_protocol_version: bool = false,
    bridge_session_expiry_interval: bool = false,
    keepalive_interval: bool = false,
    bridge_receive_maximum: bool = false,
    bridge_max_topic_alias: bool = false,
    bridge_max_packet_size: bool = false,
    bridge_outgoing_retain: bool = false,
    bridge_attempt_unsubscribe: bool = false,
    try_private: bool = false,
    bridge_bind_address: bool = false,
    bridge_tcp_keepalive: bool = false,
    bridge_tcp_user_timeout: bool = false,
    local_client_id: bool = false,
    remote_client_id: bool = false,
    remote_username: bool = false,
    remote_password: bool = false,
    restart_timeout: bool = false,
    bridge_cafile: bool = false,
    bridge_capath: bool = false,
    bridge_tls_use_os_certs: bool = false,
    bridge_certfile: bool = false,
    bridge_keyfile: bool = false,
    bridge_keyfile_password_file: bool = false,
    bridge_alpn: bool = false,
    bridge_ciphers_tls13: bool = false,
    bridge_ciphers: bool = false,
    bridge_require_ocsp: bool = false,
    bridge_insecure: bool = false,
    bridge_tls_version: bool = false,
    round_robin: bool = false,
    start_type: bool = false,
    bridge_reload_type: bool = false,
    idle_timeout: bool = false,
    threshold: bool = false,
    notifications: bool = false,
    notifications_local_only: bool = false,
    notification_topic: bool = false,
};

pub const Builder = struct {
    name: []u8,
    host: []u8 = &.{},
    port: u16 = default_port,
    secondary_addresses: std.ArrayList(Endpoint) = .empty,
    rules: std.ArrayList(Rule) = .empty,
    protocol: mqtt.ProtocolVersion = .v3_1_1,
    clean_session: bool = false,
    local_clean_session: ?bool = null,
    session_expiry_interval: u32 = 0,
    keep_alive_seconds: u16 = default_keep_alive_seconds,
    receive_maximum: ?u16 = null,
    max_topic_alias: u16 = default_max_topic_alias,
    max_packet_size: u32 = 0,
    outgoing_retain: bool = true,
    attempt_unsubscribe: bool = true,
    try_private: bool = true,
    bind_address: ?net.IpAddress = null,
    tcp_keepalive: ?socket_options.TcpKeepAlive = null,
    tcp_user_timeout_ms: ?u32 = null,
    local_client_id: []u8 = &.{},
    remote_client_id: []u8 = &.{},
    remote_username: []u8 = &.{},
    remote_password: []u8 = &.{},
    ca_file: []u8 = &.{},
    ca_path: []u8 = &.{},
    use_os_ca_certificates: bool = false,
    certificate_file: []u8 = &.{},
    private_key_file: []u8 = &.{},
    private_key_password_file: []u8 = &.{},
    alpn: []u8 = &.{},
    cipher_suites: []tls_cipher_suites.Suite = &.{},
    tls12_cipher_suites: []tls_cipher_suites.Tls12Suite = &.{},
    tls_protocol_policy: tls_stream.VersionPolicy = .tls12_and_tls13,
    require_ocsp: bool = false,
    verify_host: bool = true,
    round_robin: bool = false,
    start_type: StartType = .automatic,
    reload_type: ReloadType = .lazy,
    idle_timeout_seconds: u32 = default_lazy_idle_timeout_seconds,
    threshold: usize = default_lazy_threshold,
    notifications: bool = true,
    notifications_local_only: bool = false,
    notification_topic: []u8 = &.{},
    restart: RestartPolicy = .{},
    seen: Seen = .{},
    moved: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        name: []const u8,
    ) Error!Builder {
        if (name.len == 0 or name.len > std.math.maxInt(u16)) {
            return error.InvalidDirective;
        }
        try mqtt.validateUtf8String(name);
        return .{ .name = try allocator.dupe(u8, name) };
    }

    pub fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        if (self.moved) return;
        for (self.rules.items) |*rule| rule.deinit(allocator);
        self.rules.deinit(allocator);
        if (self.remote_password.len != 0) {
            std.crypto.secureZero(u8, self.remote_password);
            allocator.free(self.remote_password);
        }
        if (self.remote_username.len != 0) allocator.free(self.remote_username);
        if (self.local_client_id.len != 0) allocator.free(self.local_client_id);
        if (self.remote_client_id.len != 0) allocator.free(self.remote_client_id);
        if (self.ca_file.len != 0) allocator.free(self.ca_file);
        if (self.ca_path.len != 0) allocator.free(self.ca_path);
        if (self.certificate_file.len != 0) allocator.free(self.certificate_file);
        if (self.private_key_file.len != 0) allocator.free(self.private_key_file);
        if (self.private_key_password_file.len != 0) {
            allocator.free(self.private_key_password_file);
        }
        if (self.alpn.len != 0) allocator.free(self.alpn);
        if (self.cipher_suites.len != 0) allocator.free(self.cipher_suites);
        if (self.tls12_cipher_suites.len != 0) {
            allocator.free(self.tls12_cipher_suites);
        }
        if (self.notification_topic.len != 0) {
            allocator.free(self.notification_topic);
        }
        for (self.secondary_addresses.items) |*endpoint| {
            endpoint.deinit(allocator);
        }
        self.secondary_addresses.deinit(allocator);
        if (self.host.len != 0) allocator.free(self.host);
        allocator.free(self.name);
        self.* = undefined;
    }

    fn clientId(self: Builder) []const u8 {
        return if (self.remote_client_id.len != 0)
            self.remote_client_id
        else
            self.name;
    }

    pub fn apply(
        self: *Builder,
        allocator: std.mem.Allocator,
        directive: []const u8,
        words: anytype,
    ) Error!void {
        if (std.mem.eql(u8, directive, "address")) {
            try markOnce(&self.seen.address);
            try self.parseAddresses(allocator, words);
        } else if (std.mem.eql(u8, directive, "topic")) {
            try self.appendRule(allocator, words);
        } else if (std.mem.eql(u8, directive, "cleansession")) {
            try markOnce(&self.seen.clean_session);
            self.clean_session = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "local_cleansession")) {
            try markOnce(&self.seen.local_clean_session);
            self.local_clean_session = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "bridge_protocol_version")) {
            try markOnce(&self.seen.bridge_protocol_version);
            const value = try parseOne(words);
            self.protocol = if (std.mem.eql(u8, value, "mqttv31"))
                .v3_1
            else if (std.mem.eql(u8, value, "mqttv311"))
                .v3_1_1
            else if (std.mem.eql(u8, value, "mqttv50"))
                .v5
            else
                return error.UnsupportedBridgeProtocol;
        } else if (std.mem.eql(
            u8,
            directive,
            "bridge_session_expiry_interval",
        )) {
            try markOnce(&self.seen.bridge_session_expiry_interval);
            const value = try parseOne(words);
            self.session_expiry_interval = std.fmt.parseInt(
                u32,
                value,
                0,
            ) catch return error.InvalidInteger;
        } else if (std.mem.eql(u8, directive, "keepalive_interval")) {
            try markOnce(&self.seen.keepalive_interval);
            self.keep_alive_seconds = try parsePositive(u16, words);
        } else if (std.mem.eql(u8, directive, "bridge_receive_maximum")) {
            try markOnce(&self.seen.bridge_receive_maximum);
            self.receive_maximum = try parsePositive(u16, words);
        } else if (std.mem.eql(u8, directive, "bridge_max_topic_alias")) {
            try markOnce(&self.seen.bridge_max_topic_alias);
            self.max_topic_alias = try parseOneInteger(u16, words);
        } else if (std.mem.eql(u8, directive, "bridge_max_packet_size")) {
            try markOnce(&self.seen.bridge_max_packet_size);
            self.max_packet_size = try parseOneInteger(u32, words);
        } else if (std.mem.eql(u8, directive, "bridge_outgoing_retain")) {
            try markOnce(&self.seen.bridge_outgoing_retain);
            self.outgoing_retain = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "bridge_attempt_unsubscribe")) {
            try markOnce(&self.seen.bridge_attempt_unsubscribe);
            self.attempt_unsubscribe = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "try_private")) {
            try markOnce(&self.seen.try_private);
            self.try_private = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "bridge_bind_address")) {
            try markOnce(&self.seen.bridge_bind_address);
            self.bind_address = net.IpAddress.parse(
                try parseOne(words),
                0,
            ) catch return error.InvalidDirective;
        } else if (std.mem.eql(u8, directive, "bridge_tcp_keepalive")) {
            try markOnce(&self.seen.bridge_tcp_keepalive);
            self.tcp_keepalive = .{
                .idle_seconds = try parsePositiveCInt(words),
                .interval_seconds = try parsePositiveCInt(words),
                .probe_count = try parsePositiveCInt(words),
            };
            if (words.next() != null) return error.InvalidDirective;
        } else if (std.mem.eql(u8, directive, "bridge_tcp_user_timeout")) {
            try markOnce(&self.seen.bridge_tcp_user_timeout);
            const milliseconds = try parseOneInteger(u32, words);
            if (milliseconds > maximum_tcp_user_timeout_ms) {
                return error.InvalidInteger;
            }
            self.tcp_user_timeout_ms = milliseconds;
        } else if (std.mem.eql(u8, directive, "local_clientid")) {
            try markOnce(&self.seen.local_client_id);
            self.local_client_id = try parseOwnedUtf8(allocator, words);
        } else if (std.mem.eql(u8, directive, "remote_clientid")) {
            try markOnce(&self.seen.remote_client_id);
            self.remote_client_id = try parseOwnedUtf8(allocator, words);
        } else if (std.mem.eql(u8, directive, "remote_username")) {
            try markOnce(&self.seen.remote_username);
            self.remote_username = try parseOwnedUtf8(allocator, words);
        } else if (std.mem.eql(u8, directive, "remote_password")) {
            try markOnce(&self.seen.remote_password);
            self.remote_password = try parseOwnedUtf8(allocator, words);
        } else if (std.mem.eql(u8, directive, "restart_timeout")) {
            try markOnce(&self.seen.restart_timeout);
            self.restart = try parseRestartTimeout(words);
        } else if (std.mem.eql(u8, directive, "bridge_cafile")) {
            try markOnce(&self.seen.bridge_cafile);
            self.ca_file = try parseOwnedNonEmpty(allocator, words);
        } else if (std.mem.eql(u8, directive, "bridge_capath")) {
            try markOnce(&self.seen.bridge_capath);
            self.ca_path = try parseOwnedNonEmpty(allocator, words);
        } else if (std.mem.eql(
            u8,
            directive,
            "bridge_tls_use_os_certs",
        )) {
            try markOnce(&self.seen.bridge_tls_use_os_certs);
            self.use_os_ca_certificates = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "bridge_certfile")) {
            try markOnce(&self.seen.bridge_certfile);
            self.certificate_file = try parseOwnedNonEmpty(allocator, words);
        } else if (std.mem.eql(u8, directive, "bridge_keyfile")) {
            try markOnce(&self.seen.bridge_keyfile);
            self.private_key_file = try parseOwnedNonEmpty(allocator, words);
        } else if (std.mem.eql(
            u8,
            directive,
            "bridge_keyfile_password_file",
        )) {
            try markOnce(&self.seen.bridge_keyfile_password_file);
            self.private_key_password_file = try parseOwnedNonEmpty(
                allocator,
                words,
            );
        } else if (std.mem.eql(u8, directive, "bridge_alpn")) {
            try markOnce(&self.seen.bridge_alpn);
            self.alpn = try parseOwnedUtf8(allocator, words);
            if (self.alpn.len > std.math.maxInt(u8)) {
                return error.InvalidDirective;
            }
        } else if (std.mem.eql(u8, directive, "bridge_ciphers_tls1.3")) {
            try markOnce(&self.seen.bridge_ciphers_tls13);
            self.cipher_suites = try tls_cipher_suites.parseOpenSslList(
                allocator,
                try parseOne(words),
            );
        } else if (std.mem.eql(u8, directive, "bridge_ciphers")) {
            try markOnce(&self.seen.bridge_ciphers);
            self.tls12_cipher_suites = try tls_cipher_suites.parseOpenSslTls12List(
                allocator,
                try parseOne(words),
            );
        } else if (std.mem.eql(u8, directive, "bridge_require_ocsp")) {
            try markOnce(&self.seen.bridge_require_ocsp);
            self.require_ocsp = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "bridge_insecure")) {
            try markOnce(&self.seen.bridge_insecure);
            self.verify_host = !(try parseOneBool(words));
        } else if (std.mem.eql(u8, directive, "bridge_tls_version")) {
            try markOnce(&self.seen.bridge_tls_version);
            const value = try parseOne(words);
            self.tls_protocol_policy = if (std.mem.eql(u8, value, "tlsv1.3"))
                .tls13_only
            else if (std.mem.eql(u8, value, "tlsv1.2-only"))
                .tls12_only
            else if (std.mem.eql(u8, value, "tlsv1.2"))
                .tls12_and_tls13
            else
                return error.UnsupportedBridgeTlsVersion;
        } else if (std.mem.eql(u8, directive, "round_robin")) {
            try markOnce(&self.seen.round_robin);
            self.round_robin = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "start_type")) {
            try markOnce(&self.seen.start_type);
            const value = try parseOne(words);
            self.start_type = if (std.mem.eql(u8, value, "automatic"))
                .automatic
            else if (std.mem.eql(u8, value, "lazy"))
                .lazy
            else if (std.mem.eql(u8, value, "once"))
                .once
            else
                return error.UnsupportedBridgeStartType;
        } else if (std.mem.eql(u8, directive, "bridge_reload_type")) {
            try markOnce(&self.seen.bridge_reload_type);
            const value = try parseOne(words);
            self.reload_type = if (std.mem.eql(u8, value, "lazy"))
                .lazy
            else if (std.mem.eql(u8, value, "immediate"))
                .immediate
            else
                return error.InvalidDirective;
        } else if (std.mem.eql(u8, directive, "idle_timeout")) {
            try markOnce(&self.seen.idle_timeout);
            self.idle_timeout_seconds = try parsePositive(u32, words);
        } else if (std.mem.eql(u8, directive, "threshold")) {
            try markOnce(&self.seen.threshold);
            self.threshold = try parsePositive(u31, words);
        } else if (std.mem.eql(u8, directive, "notifications")) {
            try markOnce(&self.seen.notifications);
            self.notifications = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "notifications_local_only")) {
            try markOnce(&self.seen.notifications_local_only);
            self.notifications_local_only = try parseOneBool(words);
        } else if (std.mem.eql(u8, directive, "notification_topic")) {
            try markOnce(&self.seen.notification_topic);
            const topic = try parseOne(words);
            try mqtt.validateTopicName(topic);
            self.notification_topic = try allocator.dupe(u8, topic);
        } else {
            return error.InvalidDirective;
        }
    }

    pub fn finish(
        self: *Builder,
        allocator: std.mem.Allocator,
        persistence: bool,
        max_queued_messages: usize,
        inherited_receive_maximum: u16,
    ) Error!Bridge {
        if (!self.seen.address) return error.BridgeAddressRequired;
        if (self.rules.items.len == 0) return error.BridgeTopicRequired;
        try mqtt.validateClientIdentifier(
            self.protocol,
            self.clientId(),
            self.clean_session,
        );
        if (self.bind_address) |local_address| {
            try validateEndpointFamily(self.host, local_address);
            for (self.secondary_addresses.items) |endpoint| {
                try validateEndpointFamily(endpoint.host, local_address);
            }
        }
        if (self.remote_password.len != 0 and self.remote_username.len == 0) {
            return error.BridgeAuthenticationIncomplete;
        }
        if (self.local_client_id.len == 0) {
            const prefix = "local.";
            const local_id_len = std.math.add(
                usize,
                prefix.len,
                self.clientId().len,
            ) catch return error.InvalidDirective;
            if (local_id_len > std.math.maxInt(u16)) {
                return error.InvalidDirective;
            }
            self.local_client_id = try std.mem.concat(
                allocator,
                u8,
                &.{ prefix, self.clientId() },
            );
        }
        if (self.seen.bridge_session_expiry_interval and
            self.protocol != .v5)
        {
            return error.InvalidDirective;
        }
        if ((self.certificate_file.len == 0) !=
            (self.private_key_file.len == 0))
        {
            return error.BridgeTlsIdentityIncomplete;
        }
        if (self.private_key_password_file.len != 0 and
            self.private_key_file.len == 0)
        {
            return error.BridgeTlsIdentityIncomplete;
        }
        const tls_option_configured = self.certificate_file.len != 0 or
            self.alpn.len != 0 or self.cipher_suites.len != 0 or
            self.tls12_cipher_suites.len != 0 or
            self.seen.bridge_require_ocsp or
            self.seen.bridge_insecure or
            self.seen.bridge_tls_version;
        if (tls_option_configured and
            self.ca_file.len == 0 and self.ca_path.len == 0 and
            !self.use_os_ca_certificates)
        {
            return error.BridgeTlsTrustRequired;
        }
        if (!self.notifications and
            (self.notifications_local_only or
                self.notification_topic.len != 0))
        {
            return error.BridgeNotificationsDisabled;
        }
        if (self.notifications and self.notification_topic.len == 0) {
            const default_topic_len = std.math.add(
                usize,
                "$SYS/broker/connection//state".len,
                self.clientId().len,
            ) catch return error.InvalidTopic;
            if (default_topic_len > std.math.maxInt(u16) or
                mqtt.hasWildcards(self.clientId()))
            {
                return error.InvalidTopic;
            }
        }
        var uses_qos2 = false;
        var has_inbound = false;
        var has_outbound = false;
        var uses_persistent_outbound_qos = false;
        for (self.rules.items) |rule| {
            uses_qos2 = uses_qos2 or rule.qos == .exactly_once;
            has_inbound = has_inbound or rule.direction != .out;
            has_outbound = has_outbound or rule.direction != .in;
            uses_persistent_outbound_qos = uses_persistent_outbound_qos or
                (rule.direction != .in and rule.qos != .at_most_once);
        }
        if (self.start_type == .lazy and !has_outbound) {
            return error.UnsupportedBridgeStartType;
        }
        if (self.start_type == .lazy and max_queued_messages != 0 and
            self.threshold > max_queued_messages)
        {
            return error.BridgeLazyThresholdExceedsQueueLimit;
        }
        if (uses_qos2) {
            if (!persistence) return error.BridgePersistenceRequired;
            if (self.clean_session or
                (self.protocol == .v5 and self.session_expiry_interval == 0))
            {
                return error.BridgePersistentSessionRequired;
            }
        }
        if (uses_persistent_outbound_qos and
            (self.local_clean_session orelse self.clean_session))
        {
            return error.BridgePersistentSessionRequired;
        }
        if (has_outbound and has_inbound and
            self.protocol.isLegacy() and !self.try_private)
        {
            return error.UnsupportedBridgeDirection;
        }
        const owned_rules = try self.rules.toOwnedSlice(allocator);
        errdefer {
            for (owned_rules) |*rule| rule.deinit(allocator);
            allocator.free(owned_rules);
        }
        const owned_secondary_addresses = try self.secondary_addresses
            .toOwnedSlice(allocator);
        const result = Bridge{
            .name = self.name,
            .host = self.host,
            .port = self.port,
            .secondary_addresses = owned_secondary_addresses,
            .rules = owned_rules,
            .protocol = self.protocol,
            .clean_session = self.clean_session,
            .local_clean_session = self.local_clean_session orelse
                self.clean_session,
            .session_expiry_interval = self.session_expiry_interval,
            .keep_alive_seconds = self.keep_alive_seconds,
            .receive_maximum = self.receive_maximum orelse
                inherited_receive_maximum,
            .max_topic_alias = self.max_topic_alias,
            .max_packet_size = self.max_packet_size,
            .outgoing_retain = self.outgoing_retain,
            .attempt_unsubscribe = self.attempt_unsubscribe,
            .try_private = self.try_private,
            .bind_address = self.bind_address,
            .tcp_keepalive = self.tcp_keepalive,
            .tcp_user_timeout_ms = self.tcp_user_timeout_ms,
            .local_client_id = self.local_client_id,
            .remote_client_id = self.remote_client_id,
            .remote_username = self.remote_username,
            .remote_password = self.remote_password,
            .ca_file = self.ca_file,
            .ca_path = self.ca_path,
            .use_os_ca_certificates = self.use_os_ca_certificates,
            .certificate_file = self.certificate_file,
            .private_key_file = self.private_key_file,
            .private_key_password_file = self.private_key_password_file,
            .alpn = self.alpn,
            .cipher_suites = self.cipher_suites,
            .tls12_cipher_suites = self.tls12_cipher_suites,
            .tls_protocol_policy = self.tls_protocol_policy,
            .require_ocsp = self.require_ocsp,
            .verify_host = self.verify_host,
            .round_robin = self.round_robin,
            .start_type = self.start_type,
            .reload_type = self.reload_type,
            .idle_timeout_seconds = self.idle_timeout_seconds,
            .threshold = self.threshold,
            .notifications = self.notifications,
            .notifications_local_only = self.notifications_local_only,
            .notification_topic = self.notification_topic,
            .restart = self.restart,
        };
        self.moved = true;
        return result;
    }

    fn parseAddresses(
        self: *Builder,
        allocator: std.mem.Allocator,
        words: anytype,
    ) Error!void {
        var count: usize = 0;
        while (words.next()) |value| {
            const endpoint = try parseEndpoint(value);
            if (self.hasEndpoint(endpoint)) return error.DuplicateBridgeAddress;
            const host = try allocator.dupe(u8, endpoint.host);
            if (count == 0) {
                self.host = host;
                self.port = endpoint.port;
            } else {
                errdefer allocator.free(host);
                try self.secondary_addresses.append(allocator, .{
                    .host = host,
                    .port = endpoint.port,
                });
            }
            count += 1;
        }
        if (count == 0) return error.InvalidDirective;
    }

    fn hasEndpoint(self: *const Builder, endpoint: Endpoint) bool {
        if (self.host.len != 0 and self.port == endpoint.port and
            std.mem.eql(u8, self.host, endpoint.host)) return true;
        for (self.secondary_addresses.items) |existing| {
            if (existing.port == endpoint.port and
                std.mem.eql(u8, existing.host, endpoint.host)) return true;
        }
        return false;
    }

    fn appendRule(
        self: *Builder,
        allocator: std.mem.Allocator,
        words: anytype,
    ) Error!void {
        const topic = words.next() orelse return error.InvalidDirective;
        const direction_text = words.next() orelse
            return error.UnsupportedBridgeDirection;
        const direction = std.meta.stringToEnum(Direction, direction_text) orelse return error.UnsupportedBridgeDirection;
        const qos = switch (try parseInteger(u2, words.next() orelse
            return error.InvalidDirective)) {
            0 => mqtt.QoS.at_most_once,
            1 => mqtt.QoS.at_least_once,
            2 => mqtt.QoS.exactly_once,
            else => return error.InvalidInteger,
        };
        const local_prefix_text = normalizeEmpty(words.next() orelse "");
        const remote_prefix_text = normalizeEmpty(words.next() orelse "");
        if (words.next() != null) return error.InvalidDirective;
        try validatePrefix(local_prefix_text);
        try validatePrefix(remote_prefix_text);
        const filter = try effectiveFilterAlloc(
            allocator,
            topic,
            remote_prefix_text,
        );
        errdefer allocator.free(filter);
        const local_prefix = try duplicateNonEmpty(allocator, local_prefix_text);
        errdefer if (local_prefix.len != 0) allocator.free(local_prefix);
        const remote_prefix = try duplicateNonEmpty(
            allocator,
            remote_prefix_text,
        );
        errdefer if (remote_prefix.len != 0) allocator.free(remote_prefix);
        const candidate = Rule{
            .filter = filter,
            .qos = qos,
            .local_prefix = local_prefix,
            .remote_prefix = remote_prefix,
            .direction = direction,
        };
        const candidate_outbound_filter = if (direction != .in)
            try candidate.outboundFilterAlloc(allocator)
        else
            null;
        defer if (candidate_outbound_filter) |value| allocator.free(value);
        for (self.rules.items) |previous| {
            if (directionsShareInbound(previous.direction, direction) and
                rule_helpers.filtersOverlap(previous.filter, filter))
            {
                return if (std.mem.eql(u8, previous.filter, filter))
                    error.DuplicateBridgeFilter
                else
                    error.OverlappingBridgeFilters;
            }
            if (directionsShareOutbound(previous.direction, direction)) {
                const previous_filter = try previous.outboundFilterAlloc(
                    allocator,
                );
                defer allocator.free(previous_filter);
                if (rule_helpers.filtersOverlap(
                    previous_filter,
                    candidate_outbound_filter.?,
                )) {
                    return if (std.mem.eql(
                        u8,
                        previous_filter,
                        candidate_outbound_filter.?,
                    ))
                        error.DuplicateBridgeFilter
                    else
                        error.OverlappingBridgeFilters;
                }
            }
        }
        try self.rules.append(allocator, .{
            .filter = filter,
            .qos = qos,
            .local_prefix = local_prefix,
            .remote_prefix = remote_prefix,
            .direction = direction,
        });
    }
};

fn directionsShareInbound(left: Direction, right: Direction) bool {
    return left != .out and right != .out;
}

fn directionsShareOutbound(left: Direction, right: Direction) bool {
    return left != .in and right != .in;
}

pub fn isDirective(value: []const u8) bool {
    return std.mem.eql(u8, value, "address") or
        std.mem.eql(u8, value, "topic") or
        std.mem.eql(u8, value, "cleansession") or
        std.mem.eql(u8, value, "local_cleansession") or
        std.mem.eql(u8, value, "bridge_protocol_version") or
        std.mem.eql(u8, value, "bridge_session_expiry_interval") or
        std.mem.eql(u8, value, "keepalive_interval") or
        std.mem.eql(u8, value, "bridge_receive_maximum") or
        std.mem.eql(u8, value, "bridge_max_topic_alias") or
        std.mem.eql(u8, value, "bridge_max_packet_size") or
        std.mem.eql(u8, value, "bridge_outgoing_retain") or
        std.mem.eql(u8, value, "bridge_attempt_unsubscribe") or
        std.mem.eql(u8, value, "try_private") or
        std.mem.eql(u8, value, "bridge_bind_address") or
        std.mem.eql(u8, value, "bridge_tcp_keepalive") or
        std.mem.eql(u8, value, "bridge_tcp_user_timeout") or
        std.mem.eql(u8, value, "local_clientid") or
        std.mem.eql(u8, value, "remote_clientid") or
        std.mem.eql(u8, value, "remote_username") or
        std.mem.eql(u8, value, "remote_password") or
        std.mem.eql(u8, value, "restart_timeout") or
        std.mem.eql(u8, value, "bridge_cafile") or
        std.mem.eql(u8, value, "bridge_capath") or
        std.mem.eql(u8, value, "bridge_tls_use_os_certs") or
        std.mem.eql(u8, value, "bridge_certfile") or
        std.mem.eql(u8, value, "bridge_keyfile") or
        std.mem.eql(u8, value, "bridge_keyfile_password_file") or
        std.mem.eql(u8, value, "bridge_alpn") or
        std.mem.eql(u8, value, "bridge_ciphers_tls1.3") or
        std.mem.eql(u8, value, "bridge_ciphers") or
        std.mem.eql(u8, value, "bridge_require_ocsp") or
        std.mem.eql(u8, value, "bridge_insecure") or
        std.mem.eql(u8, value, "bridge_tls_version") or
        std.mem.eql(u8, value, "round_robin") or
        std.mem.eql(u8, value, "start_type") or
        std.mem.eql(u8, value, "bridge_reload_type") or
        std.mem.eql(u8, value, "idle_timeout") or
        std.mem.eql(u8, value, "threshold") or
        std.mem.eql(u8, value, "notifications") or
        std.mem.eql(u8, value, "notifications_local_only") or
        std.mem.eql(u8, value, "notification_topic");
}

fn parseEndpoint(value: []const u8) Error!Endpoint {
    if (value.len == 0) return error.InvalidDirective;
    if (value[0] == '[') {
        const close = std.mem.indexOfScalar(u8, value, ']') orelse
            return error.InvalidDirective;
        if (close == 1 or close + 2 > value.len or value[close + 1] != ':') {
            return error.InvalidDirective;
        }
        if (std.mem.indexOfScalar(u8, value[close + 2 ..], ':') != null) {
            return error.InvalidDirective;
        }
        const host = value[1..close];
        _ = std.Io.net.IpAddress.parseIp6(host, 0) catch
            return error.InvalidDirective;
        return .{
            .host = host,
            .port = try parsePort(value[close + 2 ..]),
        };
    }
    const first_colon = std.mem.indexOfScalar(u8, value, ':');
    if (first_colon) |colon| {
        if (colon == 0 or colon + 1 == value.len or
            std.mem.indexOfScalar(u8, value[colon + 1 ..], ':') != null)
        {
            return error.InvalidDirective;
        }
        const host = value[0..colon];
        try validateHost(host);
        return .{
            .host = host,
            .port = try parsePort(value[colon + 1 ..]),
        };
    }
    try validateHost(value);
    return .{ .host = value, .port = default_port };
}

fn validateEndpointFamily(
    host: []const u8,
    local_address: net.IpAddress,
) Error!void {
    const remote = net.IpAddress.parse(host, 0) catch return;
    if (std.meta.activeTag(remote) != std.meta.activeTag(local_address)) {
        return error.BridgeAddressFamilyMismatch;
    }
}

fn validateHost(value: []const u8) Error!void {
    if (value.len == 0 or value.len > maximum_host_bytes or
        std.mem.indexOfAny(u8, value, "/[]") != null)
    {
        return error.InvalidDirective;
    }
    try mqtt.validateUtf8String(value);
}

fn parsePort(value: []const u8) Error!u16 {
    const port = try parseInteger(u16, value);
    if (port == 0) return error.InvalidInteger;
    return port;
}

fn parseRestartTimeout(words: anytype) Error!RestartPolicy {
    const base = try parseRestartSeconds(words.next() orelse
        return error.InvalidDirective);
    const cap_text = words.next();
    const cap = if (cap_text) |value|
        try parseRestartCapSeconds(value)
    else
        base;
    const stable_connection_seconds = if (words.next()) |value|
        try parseInteger(u32, value)
    else
        0;
    if (words.next() != null) return error.UnsupportedBridgeRestartTimeout;
    if (cap < base) return error.InvalidInteger;
    return .{
        .base_seconds = base,
        .cap_seconds = cap,
        .jitter = cap_text != null,
        .stable_connection_seconds = stable_connection_seconds,
    };
}

fn parseRestartSeconds(value: []const u8) Error!u16 {
    const seconds = try parseInteger(u16, value);
    if (seconds == 0 or seconds > maximum_restart_seconds) {
        return error.InvalidInteger;
    }
    return seconds;
}

fn parseRestartCapSeconds(value: []const u8) Error!u16 {
    const seconds = try parseInteger(u16, value);
    if (seconds == 0 or seconds > maximum_restart_cap_seconds) {
        return error.InvalidInteger;
    }
    return seconds;
}

fn effectiveFilterAlloc(
    allocator: std.mem.Allocator,
    topic: []const u8,
    remote_prefix: []const u8,
) Error![]u8 {
    try mqtt.validateTopicFilter(topic);
    if (remote_prefix.len == 0) return allocator.dupe(u8, topic);
    if (!std.mem.startsWith(u8, topic, "$share/")) {
        return concatFilter(allocator, remote_prefix, topic);
    }
    const rest = topic["$share/".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse
        return error.InvalidSubscription;
    const wrapper_len = "$share/".len + slash + 1;
    const wrapper = topic[0..wrapper_len];
    const inner = rest[slash + 1 ..];
    const prefixed_inner = try concatFilter(allocator, remote_prefix, inner);
    defer allocator.free(prefixed_inner);
    const result = try std.mem.concat(allocator, u8, &.{ wrapper, prefixed_inner });
    errdefer allocator.free(result);
    try mqtt.validateTopicFilter(result);
    return result;
}

fn concatFilter(
    allocator: std.mem.Allocator,
    prefix: []const u8,
    filter: []const u8,
) Error![]u8 {
    const len = std.math.add(usize, prefix.len, filter.len) catch
        return error.InvalidSubscription;
    if (len > std.math.maxInt(u16)) return error.InvalidSubscription;
    const result = try std.mem.concat(allocator, u8, &.{ prefix, filter });
    errdefer allocator.free(result);
    try mqtt.validateTopicFilter(result);
    return result;
}

fn validatePrefix(prefix: []const u8) Error!void {
    if (prefix.len == 0) return;
    if (prefix.len >= std.math.maxInt(u16)) return error.InvalidTopic;
    try mqtt.validateUtf8String(prefix);
    if (mqtt.hasWildcards(prefix)) return error.InvalidTopic;
}

fn normalizeEmpty(value: []const u8) []const u8 {
    return if (std.mem.eql(u8, value, "\"\"")) "" else value;
}

fn duplicateNonEmpty(
    allocator: std.mem.Allocator,
    value: []const u8,
) std.mem.Allocator.Error![]u8 {
    return if (value.len == 0) &.{} else allocator.dupe(u8, value);
}

fn parseOwnedUtf8(
    allocator: std.mem.Allocator,
    words: anytype,
) Error![]u8 {
    const value = try parseOne(words);
    if (value.len == 0 or value.len > std.math.maxInt(u16)) {
        return error.InvalidDirective;
    }
    try mqtt.validateUtf8String(value);
    return allocator.dupe(u8, value);
}

fn parseOwnedNonEmpty(
    allocator: std.mem.Allocator,
    words: anytype,
) Error![]u8 {
    const value = try parseOne(words);
    if (value.len == 0) return error.InvalidDirective;
    return allocator.dupe(u8, value);
}

fn parseOne(words: anytype) Error![]const u8 {
    const value = words.next() orelse return error.InvalidDirective;
    if (words.next() != null) return error.InvalidDirective;
    return value;
}

fn parseOneBool(words: anytype) Error!bool {
    const value = try parseOne(words);
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBoolean;
}

fn parsePositive(comptime T: type, words: anytype) Error!T {
    const value = try parseOne(words);
    const parsed = try parseInteger(T, value);
    if (parsed == 0) return error.InvalidInteger;
    return parsed;
}

fn parsePositiveCInt(words: anytype) Error!u32 {
    const value = try parseInteger(u32, words.next() orelse
        return error.InvalidDirective);
    if (value == 0 or value > std.math.maxInt(i32)) {
        return error.InvalidInteger;
    }
    return value;
}

fn testBridgeClone(allocator: std.mem.Allocator) !void {
    var name = "primary".*;
    var host = "broker.example".*;
    var secondary_host = "backup.example".*;
    var filter = "remote/sensors/#".*;
    var local_prefix = "local/".*;
    var remote_prefix = "remote/".*;
    var username = "bridge-user".*;
    var password = "bridge-secret".*;
    var ca_file = "ca.pem".*;
    var notification_topic = "bridge/state".*;
    var suites = [_]tls_cipher_suites.Suite{
        .aes_256_gcm_sha384,
        .aes_128_gcm_sha256,
    };
    var tls12_suites = [_]tls_cipher_suites.Tls12Suite{
        .ecdhe_ecdsa_aes_128_gcm_sha256,
    };
    const endpoints = [_]Endpoint{.{
        .host = &secondary_host,
        .port = 2883,
    }};
    const rules = [_]Rule{.{
        .filter = &filter,
        .qos = .at_least_once,
        .local_prefix = &local_prefix,
        .remote_prefix = &remote_prefix,
        .direction = .both,
    }};
    const source = Bridge{
        .name = &name,
        .host = &host,
        .secondary_addresses = @constCast(&endpoints),
        .rules = @constCast(&rules),
        .remote_username = &username,
        .remote_password = &password,
        .ca_file = &ca_file,
        .cipher_suites = &suites,
        .tls12_cipher_suites = &tls12_suites,
        .notification_topic = &notification_topic,
    };
    var copy = try source.clone(allocator);
    defer copy.deinit(allocator);

    @memset(&name, 'x');
    @memset(&host, 'x');
    @memset(&secondary_host, 'x');
    @memset(&filter, 'x');
    @memset(&local_prefix, 'x');
    @memset(&remote_prefix, 'x');
    @memset(&username, 'x');
    @memset(&password, 'x');
    @memset(&ca_file, 'x');
    @memset(&notification_topic, 'x');
    suites[0] = .aes_128_ccm_sha256;
    tls12_suites[0] = .ecdhe_rsa_aes_256_gcm_sha384;

    try std.testing.expectEqualStrings("primary", copy.name);
    try std.testing.expectEqualStrings("broker.example", copy.host);
    try std.testing.expectEqualStrings(
        "backup.example",
        copy.secondary_addresses[0].host,
    );
    try std.testing.expectEqualStrings("remote/sensors/#", copy.rules[0].filter);
    try std.testing.expectEqualStrings("local/", copy.rules[0].local_prefix);
    try std.testing.expectEqualStrings("remote/", copy.rules[0].remote_prefix);
    try std.testing.expectEqualStrings("bridge-user", copy.remote_username);
    try std.testing.expectEqualStrings("bridge-secret", copy.remote_password);
    try std.testing.expectEqualStrings("ca.pem", copy.ca_file);
    try std.testing.expectEqualStrings("bridge/state", copy.notification_topic);
    try std.testing.expectEqual(
        tls_cipher_suites.Suite.aes_256_gcm_sha384,
        copy.cipher_suites[0],
    );
    try std.testing.expectEqual(
        tls_cipher_suites.Tls12Suite.ecdhe_ecdsa_aes_128_gcm_sha256,
        copy.tls12_cipher_suites[0],
    );
}

test "MQTT bridge configuration clone owns all nested state" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        testBridgeClone,
        .{},
    );
}

fn parseOneInteger(comptime T: type, words: anytype) Error!T {
    return parseInteger(T, try parseOne(words));
}

fn parseInteger(comptime T: type, value: []const u8) Error!T {
    return std.fmt.parseInt(T, value, 10) catch error.InvalidInteger;
}

fn markOnce(flag: *bool) Error!void {
    if (flag.*) return error.DuplicateDirective;
    flag.* = true;
}

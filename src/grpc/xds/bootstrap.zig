//! Bounded gRPC xDS bootstrap JSON parsing and node metadata encoding.
const std = @import("std");
const ads = @import("ads.zig");
pub const Error = std.mem.Allocator.Error || error{
    InvalidBootstrap,
    BootstrapLimitExceeded,
    InvalidServerUri,
    UnsupportedBootstrapCreds,
    UnsupportedBootstrapFeature,
    InvalidBootstrapNode,
};

pub const Limits = struct {
    max_bytes: usize = 1024 * 1024,
    max_servers: usize = 16,
    max_authorities: usize = 64,
    max_providers: usize = 256,
    max_creds: usize = 8,
    max_features: usize = 16,
    max_text_bytes: usize = 4096,
    max_metadata_bytes: usize = 64 * 1024,
    max_metadata_depth: u8 = 16,
    max_metadata_entries: usize = 1024,
};

pub const Scheme = enum { http, https };
pub const Target = struct { scheme: Scheme, host: []const u8, port: u16 };
pub const TlsConfig = struct {
    ca_certificate_file: []const u8 = "",
    certificate_file: []const u8 = "",
    private_key_file: []const u8 = "",
    /// Optional file_watcher provider names.
    root_certificate_provider: []const u8 = "",
    identity_certificate_provider: []const u8 = "",
    /// File refresh period. Zero disables scheduled refresh; the gRPC default
    /// is ten minutes.
    refresh_interval: std.Io.Duration = .fromSeconds(600),
};
pub const CertificateProvider = struct {
    name: []const u8,
    plugin_name: []const u8,
    certificate_file: []const u8 = "",
    private_key_file: []const u8 = "",
    ca_certificate_file: []const u8 = "",
    refresh_interval: std.Io.Duration = .fromSeconds(600),
};
pub const Creds = struct { type: []const u8, config_json: ?[]const u8 = null, tls: ?TlsConfig = null };

pub const Server = struct {
    uri: []const u8,
    target: Target,
    channel_creds: []Creds,
    server_features: []const []const u8,
    ignore_resource_deletion: bool = false,
    fail_on_data_errors: bool = false,
    resource_timer_is_transient_error: bool = false,
    trusted_xds_server: bool = false,

    pub fn hasInsecureCreds(self: Server) bool {
        for (self.channel_creds) |creds| if (std.mem.eql(u8, creds.type, "insecure")) return true;
        return false;
    }
    pub fn hasTlsCreds(self: Server) bool {
        for (self.channel_creds) |creds| if (std.mem.eql(u8, creds.type, "tls")) return true;
        return false;
    }
    pub fn tlsConfig(self: Server) ?TlsConfig {
        for (self.channel_creds) |creds| if (creds.tls) |config| return config;
        return null;
    }
};

pub const Locality = struct { region: []const u8 = "", zone: []const u8 = "", sub_zone: []const u8 = "" };

pub const Node = struct {
    id: []const u8 = "",
    cluster: []const u8 = "",
    locality: ?Locality = null,
    /// Serialized google.protobuf.Struct for the ADS Node.
    metadata: ?[]const u8 = null,
    metadata_json: ?[]const u8 = null,
};

pub const Authority = struct {
    name: []const u8,
    servers: []Server,
    client_listener_resource_name_template: []const u8 = "",
    fallback_on_reachability_only: bool = false,
};

pub const Bootstrap = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize) = .init(1),
    servers: []Server,
    node: ?Node = null,
    authorities: []Authority = &.{},
    certificate_providers: []CertificateProvider = &.{},
    client_default_listener_resource_name_template: []const u8 = "",
    server_listener_resource_name_template: []const u8 = "",

    pub fn retain(self: *Bootstrap) *Bootstrap {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }

    /// Release one owner; retained discovery sources keep the arena alive.
    pub fn deinit(self: *Bootstrap) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.arena.deinit();
        self.allocator.destroy(self);
    }

    pub fn adsNode(self: *const Bootstrap) ?ads.codec.Node {
        const node = self.node orelse return null;
        return .{
            .id = node.id,
            .cluster = node.cluster,
            .metadata = node.metadata,
            .locality = if (node.locality) |value| .{ .region = value.region, .zone = value.zone, .sub_zone = value.sub_zone } else null,
        };
    }

    pub fn firstInsecureServer(self: *const Bootstrap) ?*const Server {
        for (self.servers) |*server| {
            if (server.target.scheme == .http and server.hasInsecureCreds()) return server;
        }
        return null;
    }

    pub fn authority(self: *const Bootstrap, name: []const u8) ?*const Authority {
        for (self.authorities) |*value| if (std.mem.eql(u8, value.name, name)) return value;
        return null;
    }

    pub fn certificateProvider(self: *const Bootstrap, name: []const u8) ?*const CertificateProvider {
        for (self.certificate_providers) |*value| if (std.mem.eql(u8, value.name, name)) return value;
        return null;
    }
};

fn jsonObject(value: std.json.Value) Error!std.json.ObjectMap {
    if (value != .object) return error.InvalidBootstrap;
    return value.object;
}

fn jsonArray(value: std.json.Value) Error!std.json.Array {
    if (value != .array) return error.InvalidBootstrap;
    return value.array;
}

fn text(value: std.json.Value, limits: Limits) Error![]const u8 {
    if (value != .string) return error.InvalidBootstrap;
    const string = value.string;
    if (string.len > limits.max_text_bytes or !std.unicode.utf8ValidateSlice(string)) return error.InvalidBootstrap;
    return string;
}

fn optionalText(object: std.json.ObjectMap, key: []const u8, limits: Limits) Error![]const u8 {
    const value = object.get(key) orelse return "";
    return text(value, limits);
}

fn optionalBool(object: std.json.ObjectMap, key: []const u8) Error!bool {
    const value = object.get(key) orelse return false;
    if (value != .bool) return error.InvalidBootstrap;
    return value.bool;
}

fn parseTarget(uri: []const u8, limits: Limits) Error!Target {
    var scheme: Scheme = .http;
    var rest = uri;
    if (std.mem.startsWith(u8, uri, "http://")) {
        rest = uri["http://".len..];
    } else if (std.mem.startsWith(u8, uri, "https://")) {
        scheme = .https;
        rest = uri["https://".len..];
    } else return error.InvalidServerUri;
    if (rest.len == 0 or rest.len > limits.max_text_bytes) return error.InvalidServerUri;
    if (std.mem.indexOfAny(u8, rest, "/?#@") != null) return error.InvalidServerUri;
    var host: []const u8 = undefined;
    var port_text: []const u8 = "";
    if (rest[0] == '[') {
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return error.InvalidServerUri;
        host = rest[1..close];
        if (close + 1 < rest.len) {
            if (rest[close + 1] != ':') return error.InvalidServerUri;
            port_text = rest[close + 2 ..];
        }
    } else if (std.mem.lastIndexOfScalar(u8, rest, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, rest[0..colon], ':') != null) return error.InvalidServerUri;
        host = rest[0..colon];
        port_text = rest[colon + 1 ..];
    } else {
        host = rest;
    }
    if (host.len == 0 or host.len > limits.max_text_bytes) return error.InvalidServerUri;
    const port: u16 = if (port_text.len == 0)
        (if (scheme == .http) 80 else 443)
    else
        std.fmt.parseInt(u16, port_text, 10) catch return error.InvalidServerUri;
    if (port == 0) return error.InvalidServerUri;
    return .{ .scheme = scheme, .host = host, .port = port };
}

/// Parse the gRPC bootstrap duration form: seconds with an optional `s`
/// suffix and up to nine fractional digits, for example `"1s"` or `"1.25s"`.
fn parseDuration(value: std.json.Value, limits: Limits) Error!std.Io.Duration {
    const raw = try text(value, limits);
    if (raw.len < 2 or raw[raw.len - 1] != 's') return error.InvalidBootstrap;
    const body = raw[0 .. raw.len - 1];
    if (body.len == 0) return error.InvalidBootstrap;
    var seconds_text = body;
    var nanos: u64 = 0;
    if (std.mem.indexOfScalar(u8, body, '.')) |dot| {
        seconds_text = body[0..dot];
        const fraction = body[dot + 1 ..];
        if (fraction.len == 0 or fraction.len > 9) return error.InvalidBootstrap;
        for (fraction) |c| if (!std.ascii.isDigit(c)) return error.InvalidBootstrap;
        nanos = std.fmt.parseInt(u64, fraction, 10) catch return error.InvalidBootstrap;
        var index = fraction.len;
        while (index < 9) : (index += 1) nanos *= 10;
    }
    if (seconds_text.len == 0) return error.InvalidBootstrap;
    for (seconds_text) |c| if (!std.ascii.isDigit(c)) return error.InvalidBootstrap;
    const seconds = std.fmt.parseInt(u64, seconds_text, 10) catch return error.InvalidBootstrap;
    if (seconds > 315576000000) return error.InvalidBootstrap;
    const total: i96 = @as(i96, @intCast(seconds)) * std.time.ns_per_s + @as(i96, @intCast(nanos));
    return .fromNanoseconds(total);
}

fn parseTlsConfig(object: std.json.ObjectMap, limits: Limits) Error!TlsConfig {
    const config: TlsConfig = .{
        .ca_certificate_file = try optionalText(object, "ca_certificate_file", limits),
        .certificate_file = try optionalText(object, "certificate_file", limits),
        .private_key_file = try optionalText(object, "private_key_file", limits),
        .root_certificate_provider = try optionalText(object, "root_certificate_provider", limits),
        .identity_certificate_provider = try optionalText(object, "identity_certificate_provider", limits),
        .refresh_interval = if (object.get("refresh_interval")) |value| try parseDuration(value, limits) else .fromSeconds(600),
    };
    if ((config.certificate_file.len == 0) != (config.private_key_file.len == 0)) return error.InvalidBootstrap;
    if (config.root_certificate_provider.len != 0 and config.ca_certificate_file.len != 0) return error.InvalidBootstrap;
    if (config.identity_certificate_provider.len != 0 and (config.certificate_file.len != 0 or config.private_key_file.len != 0)) return error.InvalidBootstrap;
    return config;
}

fn parseCreds(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error![]Creds {
    const items = (try jsonArray(value)).items;
    if (items.len == 0 or items.len > limits.max_creds) return error.InvalidBootstrap;
    const result = try arena.alloc(Creds, items.len);
    for (items, result) |item, *creds| {
        const object = try jsonObject(item);
        const type_value = object.get("type") orelse return error.InvalidBootstrap;
        const type_name = try text(type_value, limits);
        if (type_name.len == 0) return error.InvalidBootstrap;
        const config = object.get("config");
        if (config) |raw| if (raw != .object) return error.InvalidBootstrap;
        const config_json: ?[]const u8 = if (config) |raw| try std.json.Stringify.valueAlloc(arena, raw, .{}) else null;
        const tls: ?TlsConfig = if (std.mem.eql(u8, type_name, "tls")) if (config) |raw| try parseTlsConfig(raw.object, limits) else TlsConfig{} else null;
        creds.* = .{ .type = type_name, .config_json = config_json, .tls = tls };
    }
    return result;
}

fn parseFeatures(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error![]const []const u8 {
    const items = (try jsonArray(value)).items;
    if (items.len > limits.max_features) return error.BootstrapLimitExceeded;
    const result = try arena.alloc([]const u8, items.len);
    for (items, result) |item, *feature| feature.* = try text(item, limits);
    return result;
}

fn parseServer(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error!Server {
    const object = try jsonObject(value);
    const uri_value = object.get("server_uri") orelse return error.InvalidBootstrap;
    const uri = try text(uri_value, limits);
    const target = try parseTarget(uri, limits);
    const creds_value = object.get("channel_creds") orelse return error.InvalidBootstrap;
    const creds = try parseCreds(arena, creds_value, limits);
    var has_known = false;
    for (creds) |entry| if (std.mem.eql(u8, entry.type, "insecure") or std.mem.eql(u8, entry.type, "tls") or std.mem.eql(u8, entry.type, "google_default") or std.mem.eql(u8, entry.type, "xds")) {
        has_known = true;
    };
    if (!has_known) return error.UnsupportedBootstrapCreds;
    const features: []const []const u8 = if (object.get("server_features")) |raw| try parseFeatures(arena, raw, limits) else &.{};
    var result: Server = .{ .uri = uri, .target = target, .channel_creds = creds, .server_features = features };
    for (features) |feature| {
        if (std.mem.eql(u8, feature, "ignore_resource_deletion")) result.ignore_resource_deletion = true;
        if (std.mem.eql(u8, feature, "fail_on_data_errors")) result.fail_on_data_errors = true;
        if (std.mem.eql(u8, feature, "resource_timer_is_transient_error")) result.resource_timer_is_transient_error = true;
        if (std.mem.eql(u8, feature, "trusted_xds_server")) result.trusted_xds_server = true;
    }
    return result;
}

fn parseServers(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error![]Server {
    const items = (try jsonArray(value)).items;
    if (items.len == 0 or items.len > limits.max_servers) return error.InvalidBootstrap;
    const result = try arena.alloc(Server, items.len);
    for (items, result) |item, *server| server.* = try parseServer(arena, item, limits);
    return result;
}

fn encodeStruct(arena: std.mem.Allocator, out: *std.ArrayList(u8), value: std.json.Value, limits: Limits, depth: u8, entries: *usize) Error!void {
    if (depth > limits.max_metadata_depth) return error.BootstrapLimitExceeded;
    const object = try jsonObject(value);
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        entries.* += 1;
        if (entries.* > limits.max_metadata_entries) return error.BootstrapLimitExceeded;
        const key = entry.key_ptr.*;
        if (!std.unicode.utf8ValidateSlice(key) or key.len > limits.max_text_bytes) return error.InvalidBootstrap;
        var map_entry: std.ArrayList(u8) = .empty;
        try appendBytes(&map_entry, arena, 1, key, limits);
        var value_message: std.ArrayList(u8) = .empty;
        try encodeValue(arena, &value_message, entry.value_ptr.*, limits, depth + 1, entries);
        try appendBytes(&map_entry, arena, 2, value_message.items, limits);
        try appendBytes(out, arena, 1, map_entry.items, limits);
    }
}

fn encodeValue(arena: std.mem.Allocator, out: *std.ArrayList(u8), value: std.json.Value, limits: Limits, depth: u8, entries: *usize) Error!void {
    if (depth > limits.max_metadata_depth) return error.BootstrapLimitExceeded;
    switch (value) {
        .null => try appendVarint(out, arena, 1, 0, limits),
        .bool => |raw| try appendVarint(out, arena, 4, @intFromBool(raw), limits),
        .integer => |raw| try appendFixed64(out, arena, 2, @bitCast(@as(f64, @floatFromInt(raw))), limits),
        .float => |raw| try appendFixed64(out, arena, 2, @bitCast(raw), limits),
        .number_string => |raw| {
            const parsed = std.fmt.parseFloat(f64, raw) catch return error.InvalidBootstrap;
            try appendFixed64(out, arena, 2, @bitCast(parsed), limits);
        },
        .string => |raw| {
            if (!std.unicode.utf8ValidateSlice(raw) or raw.len > limits.max_text_bytes) return error.InvalidBootstrap;
            try appendBytes(out, arena, 3, raw, limits);
        },
        .array => |raw| {
            var list: std.ArrayList(u8) = .empty;
            for (raw.items) |item| {
                entries.* += 1;
                if (entries.* > limits.max_metadata_entries) return error.BootstrapLimitExceeded;
                var element: std.ArrayList(u8) = .empty;
                try encodeValue(arena, &element, item, limits, depth + 1, entries);
                try appendBytes(&list, arena, 1, element.items, limits);
            }
            try appendBytes(out, arena, 6, list.items, limits);
        },
        .object => {
            var nested: std.ArrayList(u8) = .empty;
            try encodeStruct(arena, &nested, value, limits, depth + 1, entries);
            try appendBytes(out, arena, 5, nested.items, limits);
        },
    }
}

fn appendVarint(out: *std.ArrayList(u8), arena: std.mem.Allocator, field: u32, value: u64, limits: Limits) Error!void {
    try appendRaw(out, arena, @as(u64, field) * 8, limits);
    try appendRaw(out, arena, value, limits);
}

fn appendBytes(out: *std.ArrayList(u8), arena: std.mem.Allocator, field: u32, bytes: []const u8, limits: Limits) Error!void {
    try appendRaw(out, arena, @as(u64, field) * 8 + 2, limits);
    try appendRaw(out, arena, bytes.len, limits);
    try out.appendSlice(arena, bytes);
    if (out.items.len > limits.max_metadata_bytes) return error.BootstrapLimitExceeded;
}

fn appendFixed64(out: *std.ArrayList(u8), arena: std.mem.Allocator, field: u32, bits: u64, limits: Limits) Error!void {
    try appendRaw(out, arena, @as(u64, field) * 8 + 1, limits);
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, bits, .little);
    try out.appendSlice(arena, &raw);
    if (out.items.len > limits.max_metadata_bytes) return error.BootstrapLimitExceeded;
}

fn appendRaw(out: *std.ArrayList(u8), arena: std.mem.Allocator, value: u64, limits: Limits) Error!void {
    var remaining = value;
    while (remaining >= 128) : (remaining >>= 7) try out.append(arena, @as(u8, @truncate(remaining)) | 0x80);
    try out.append(arena, @intCast(remaining));
    if (out.items.len > limits.max_metadata_bytes) return error.BootstrapLimitExceeded;
}

fn parseNode(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error!Node {
    const object = try jsonObject(value);
    var node: Node = .{};
    node.id = try optionalText(object, "id", limits);
    if (node.id.len == 0) return error.InvalidBootstrapNode;
    node.cluster = try optionalText(object, "cluster", limits);
    if (object.get("locality")) |raw| {
        const local = try jsonObject(raw);
        node.locality = .{
            .region = try optionalText(local, "region", limits),
            .zone = try optionalText(local, "zone", limits),
            .sub_zone = try optionalText(local, "sub_zone", limits),
        };
    }
    if (object.get("metadata")) |raw| {
        if (raw != .object) return error.InvalidBootstrap;
        var encoded: std.ArrayList(u8) = .empty;
        var entries: usize = 0;
        try encodeStruct(arena, &encoded, raw, limits, 0, &entries);
        node.metadata = encoded.items;
        node.metadata_json = try std.json.Stringify.valueAlloc(arena, raw, .{});
    }
    return node;
}

fn parseAuthorities(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error![]Authority {
    const object = try jsonObject(value);
    if (object.count() > limits.max_authorities) return error.BootstrapLimitExceeded;
    const result = try arena.alloc(Authority, object.count());
    var iterator = object.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        const name = entry.key_ptr.*;
        if (name.len == 0 or name.len > limits.max_text_bytes or !std.unicode.utf8ValidateSlice(name)) return error.InvalidBootstrap;
        const body = try jsonObject(entry.value_ptr.*);
        const servers: []Server = if (body.get("xds_servers")) |raw| try parseServers(arena, raw, limits) else &.{};
        const template = try optionalText(body, "client_listener_resource_name_template", limits);
        if (template.len != 0) {
            const prefix = try std.fmt.allocPrint(arena, "xdstp://{s}/", .{name});
            if (!std.mem.startsWith(u8, template, prefix)) return error.InvalidBootstrap;
        }
        result[index] = .{
            .name = name,
            .servers = servers,
            .client_listener_resource_name_template = template,
            .fallback_on_reachability_only = try optionalBool(body, "fallback_on_reachability_only"),
        };
    }
    return result;
}

fn parseCertificateProviders(arena: std.mem.Allocator, value: std.json.Value, limits: Limits) Error![]CertificateProvider {
    const object = try jsonObject(value);
    if (object.count() > limits.max_providers) return error.BootstrapLimitExceeded;
    const result = try arena.alloc(CertificateProvider, object.count());
    var iterator = object.iterator();
    var index: usize = 0;
    while (iterator.next()) |entry| : (index += 1) {
        const name = entry.key_ptr.*;
        if (name.len == 0 or name.len > limits.max_text_bytes or !std.unicode.utf8ValidateSlice(name)) return error.InvalidBootstrap;
        const body = try jsonObject(entry.value_ptr.*);
        const plugin = try optionalText(body, "plugin_name", limits);
        if (plugin.len == 0) return error.InvalidBootstrap;
        if (!std.mem.eql(u8, plugin, "file_watcher")) return error.UnsupportedBootstrapFeature;
        var config: CertificateProvider = .{ .name = name, .plugin_name = plugin };
        if (body.get("config")) |raw| {
            const config_object = try jsonObject(raw);
            config.certificate_file = try optionalText(config_object, "certificate_file", limits);
            config.private_key_file = try optionalText(config_object, "private_key_file", limits);
            config.ca_certificate_file = try optionalText(config_object, "ca_certificate_file", limits);
            config.refresh_interval = if (config_object.get("refresh_interval")) |duration| try parseDuration(duration, limits) else .fromSeconds(600);
            if ((config.certificate_file.len == 0) != (config.private_key_file.len == 0)) return error.InvalidBootstrap;
            if (config.certificate_file.len == 0 and config.ca_certificate_file.len == 0) return error.InvalidBootstrap;
        } else return error.InvalidBootstrap;
        result[index] = config;
    }
    return result;
}

fn validateProviderReferences(servers: []const Server, providers: []const CertificateProvider) Error!void {
    for (servers) |server| {
        const tls = server.tlsConfig() orelse continue;
        if (tls.root_certificate_provider.len != 0) {
            const found = for (providers) |provider| {
                if (std.mem.eql(u8, provider.name, tls.root_certificate_provider)) break provider;
            } else return error.InvalidBootstrap;
            if (found.ca_certificate_file.len == 0) return error.InvalidBootstrap;
        }
        if (tls.identity_certificate_provider.len != 0) {
            const found = for (providers) |provider| {
                if (std.mem.eql(u8, provider.name, tls.identity_certificate_provider)) break provider;
            } else return error.InvalidBootstrap;
            if (found.certificate_file.len == 0 or found.private_key_file.len == 0) return error.InvalidBootstrap;
        }
    }
}

pub fn parse(gpa: std.mem.Allocator, json_text: []const u8, limits: Limits) Error!*Bootstrap {
    if (json_text.len > limits.max_bytes) return error.BootstrapLimitExceeded;
    const self = try gpa.create(Bootstrap);
    self.* = .{ .allocator = gpa, .arena = .init(gpa), .servers = &.{} };
    errdefer self.deinit();
    const arena = self.arena.allocator();
    const root = std.json.parseFromSliceLeaky(std.json.Value, arena, json_text, .{
        .max_value_len = limits.max_bytes,
        .allocate = .alloc_always,
        .duplicate_field_behavior = .@"error",
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidBootstrap,
    };
    if (root != .object) return error.InvalidBootstrap;
    const object = root.object;
    const servers_value = object.get("xds_servers") orelse return error.InvalidBootstrap;
    self.servers = try parseServers(arena, servers_value, limits);
    if (object.get("node")) |value| self.node = try parseNode(arena, value, limits);
    if (object.get("authorities")) |value| self.authorities = try parseAuthorities(arena, value, limits);
    if (object.get("certificate_providers")) |value| self.certificate_providers = try parseCertificateProviders(arena, value, limits);
    self.client_default_listener_resource_name_template = try optionalText(object, "client_default_listener_resource_name_template", limits);
    self.server_listener_resource_name_template = try optionalText(object, "server_listener_resource_name_template", limits);
    try validateProviderReferences(self.servers, self.certificate_providers);
    for (self.authorities) |authority| try validateProviderReferences(authority.servers, self.certificate_providers);
    if (object.get("allowed_grpc_services")) |value| {
        if (value != .object) return error.InvalidBootstrap;
        if (value.object.count() != 0) return error.UnsupportedBootstrapFeature;
    }
    return self;
}

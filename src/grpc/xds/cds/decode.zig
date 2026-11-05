//! Owned EDS-backed Envoy v3 Cluster data used by the application resolver.
const std = @import("std");
const pb = @import("protobuf.zig");
const policy = @import("policy.zig");
const tls_material = @import("../tls_material.zig");
pub const type_url = "type.googleapis.com/envoy.config.cluster.v3.Cluster";
pub const Error = pb.Error;
pub const Limits = struct { max_bytes: usize = 8 * 1024 * 1024, max_text_bytes: usize = 4096, max_thresholds: usize = 256, max_policies: usize = 32, max_endpoints: usize = 65536, max_aggregate_clusters: usize = 256, allow_sds: bool = false };
/// `aggregate` is a netz-internal discovery kind selected by the CDS
/// `envoy.clusters.aggregate` custom cluster extension; it has no Envoy enum
/// wire value of its own.
pub const Discovery = enum(u32) { static = 0, strict_dns = 1, logical_dns = 2, eds = 3, aggregate = 4, _ };
pub const HostEndpoint = struct {
    host: []const u8,
    port: u16,
    priority: u32 = 0,
    endpoint_weight: u32 = 1,
    locality_weight: u32 = 1,
    region: []const u8 = "",
    zone: []const u8 = "",
    sub_zone: []const u8 = "",
};
/// CDS `lrs_report_endpoint_metrics` entries (field 57) that select which
/// ORCA endpoint metrics are propagated into LRS locality reports. Envoy
/// propagates nothing unless a cluster opts in, so the defaults are all false.
pub const LrsPropagation = struct {
    cpu_utilization: bool = false,
    memory_utilization: bool = false,
    application_utilization: bool = false,
    named_metrics_all: bool = false,
    named_metrics: []const []const u8 = &.{},
};
pub const Http2Limits = struct {
    header_table_size: ?u32 = null,
    max_concurrent_streams: ?u32 = null,
    initial_window_size: ?u32 = null,
    initial_connection_window_size: ?u32 = null,
};
/// Secret Discovery Service references from an `UpstreamTlsContext`.
/// Inline certificate/validation material and SDS references for the same
/// aspect are mutually exclusive.
pub const TlsSds = struct {
    certificate: ?[]const u8 = null,
    validation: ?[]const u8 = null,
};
pub const Cluster = struct {
    name: []const u8,
    eds_service_name: []const u8,
    discovery: Discovery = .eds,
    /// Raw inline `ClusterLoadAssignment` for STATIC/DNS clusters.
    inline_assignment: []const u8 = "",
    /// Flattened DNS endpoints, retaining priority/locality identity.
    host_endpoints: []const HostEndpoint = &.{},
    tls: ?tls_material.Config = null,
    /// SDS references resolved by the runtime controller. When present, the
    /// referenced secrets must be available before endpoints are published.
    tls_sds: ?TlsSds = null,
    http2_limits: ?Http2Limits = null,
    max_concurrent_requests: u32 = 1024,
    lrs_propagation: LrsPropagation = .{},
    /// Ordered leaf cluster names for an `envoy.clusters.aggregate` cluster.
    aggregate_clusters: []const []const u8 = &.{},
    policy: policy.Result,
    pub fn isEds(self: Cluster) bool {
        return self.discovery == .eds;
    }
    pub fn isDns(self: Cluster) bool {
        return self.discovery == .strict_dns or self.discovery == .logical_dns;
    }
    /// LOGICAL_DNS resolves once when the resource is applied; STRICT_DNS keeps
    /// re-resolution requests enabled after a connection failure.
    pub fn isLogicalDns(self: Cluster) bool {
        return self.discovery == .logical_dns;
    }
    pub fn isAggregate(self: Cluster) bool {
        return self.discovery == .aggregate;
    }
    pub fn edsName(self: Cluster) []const u8 {
        if (!self.isEds()) return "";
        return if (self.eds_service_name.len != 0) self.eds_service_name else self.name;
    }
};
pub const Owned = struct {
    wire: []const u8 = "",
    arena: std.heap.ArenaAllocator,
    value: Cluster,
    pub fn deinit(self: *Owned) void {
        self.arena.deinit();
        self.* = undefined;
    }
};
fn eds(bytes: []const u8, text_limit: usize) Error![]const u8 {
    var reader: pb.Reader = .{ .bytes = bytes };
    var source: ?[]const u8 = null;
    var service: []const u8 = "";
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) source = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) service = try pb.text(&reader, text_limit) else try reader.skip(field);
    }
    _ = @import("../config_source.zig").decode(source orelse return error.InvalidCdsResource) catch |err| return switch (err) {
        error.InvalidConfigSource => error.InvalidCdsResource,
        error.UnsupportedConfigSource => error.UnsupportedCdsFeature,
        else => @errorCast(err),
    };
    return service;
}
const Socket = struct { host: []const u8, port: u16 };

const DnsParser = struct {
    arena: std.mem.Allocator,
    limits: Limits,
    count: usize = 0,

    fn text(self: DnsParser, reader: *pb.Reader) Error![]const u8 {
        const value = try reader.string();
        if (value.len > self.limits.max_text_bytes) return error.CdsLimitExceeded;
        return value;
    }
    fn u32Value(_: DnsParser, reader: *pb.Reader) Error!u32 {
        const value = try reader.varint();
        if (value > std.math.maxInt(u32)) return error.InvalidCdsResource;
        return @intCast(value);
    }
    fn wrapper(self: DnsParser, bytes: []const u8) Error!u32 {
        var value: u32 = 0;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 0) value = try self.u32Value(&reader) else try reader.skip(field);
        }
        return value;
    }
    fn socket(self: DnsParser, bytes: []const u8) Error!Socket {
        var host: []const u8 = "";
        var port: ?u32 = null;
        var protocol: u32 = 0;
        var resolver: []const u8 = "";
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 0) protocol = try self.u32Value(&reader) else if (field.number == 2 and field.wire_type == 2) host = try self.text(&reader) else if (field.number == 3 and field.wire_type == 0) port = try self.u32Value(&reader) else if (field.number == 4 and field.wire_type == 2) resolver = try self.text(&reader) else try reader.skip(field);
        }
        if (protocol != 0 or resolver.len != 0) return error.UnsupportedCdsFeature;
        const value = port orelse return error.InvalidCdsResource;
        if (value == 0 or value > 65535 or host.len == 0) return error.InvalidCdsResource;
        return .{ .host = host, .port = @intCast(value) };
    }
    fn address(self: DnsParser, bytes: []const u8) Error!Socket {
        var socket_bytes: ?[]const u8 = null;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) socket_bytes = try reader.bytesValue() else if ((field.number == 2 or field.number == 3) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
        }
        return self.socket(socket_bytes orelse return error.InvalidCdsResource);
    }
    fn endpoint(self: DnsParser, bytes: []const u8) Error!Socket {
        var address_bytes: ?[]const u8 = null;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) address_bytes = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 2) {
                _ = try self.text(&reader);
            } else if (field.number == 4 and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
        }
        return self.address(address_bytes orelse return error.InvalidCdsResource);
    }
    fn lbEndpoint(self: *DnsParser, bytes: []const u8) Error!?HostEndpoint {
        var endpoint_bytes: ?[]const u8 = null;
        var weight_bytes: ?[]const u8 = null;
        var health: u32 = 0;
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) endpoint_bytes = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 0) health = try self.u32Value(&reader) else if (field.number == 4 and field.wire_type == 2) weight_bytes = try reader.bytesValue() else try reader.skip(field);
        }
        if (health != 0 and health != 1 and health != 3) return null;
        const weight = if (weight_bytes) |raw| try self.wrapper(raw) else 1;
        if (weight == 0) return error.InvalidCdsResource;
        if (self.count >= self.limits.max_endpoints) return error.CdsLimitExceeded;
        self.count += 1;
        const socket_value = try self.endpoint(endpoint_bytes orelse return error.InvalidCdsResource);
        return .{ .host = socket_value.host, .port = socket_value.port, .endpoint_weight = weight };
    }
    fn locality(self: *DnsParser, bytes: []const u8, out: *std.ArrayList(HostEndpoint)) Error!void {
        var locality_bytes: ?[]const u8 = null;
        var weight: u32 = 1;
        var priority: u32 = 0;
        var endpoint_bytes: std.ArrayList([]const u8) = .empty;
        defer endpoint_bytes.deinit(self.arena);
        var reader: pb.Reader = .{ .bytes = bytes };
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) locality_bytes = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 2) weight = try self.wrapper(try reader.bytesValue()) else if (field.number == 5 and field.wire_type == 0) priority = try self.u32Value(&reader) else if (field.number == 2 and field.wire_type == 2) {
                try endpoint_bytes.append(self.arena, try reader.bytesValue());
            } else if ((field.number == 7 or field.number == 8) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
        }
        if (weight == 0) return error.InvalidCdsResource;
        var region: []const u8 = "";
        var zone: []const u8 = "";
        var sub_zone: []const u8 = "";
        if (locality_bytes) |raw| {
            var location: pb.Reader = .{ .bytes = raw };
            while (try location.next()) |field| {
                if (field.number == 1 and field.wire_type == 2) region = try self.text(&location) else if (field.number == 2 and field.wire_type == 2) zone = try self.text(&location) else if (field.number == 3 and field.wire_type == 2) sub_zone = try self.text(&location) else try location.skip(field);
            }
        }
        for (endpoint_bytes.items) |raw| {
            const value = (try self.lbEndpoint(raw)) orelse continue;
            try out.append(self.arena, .{ .host = value.host, .port = value.port, .priority = priority, .endpoint_weight = value.endpoint_weight, .locality_weight = weight, .region = region, .zone = zone, .sub_zone = sub_zone });
        }
    }
};

fn onePerLocality(arena: std.mem.Allocator, hosts: []const HostEndpoint) Error![]const HostEndpoint {
    var selected: std.ArrayList(HostEndpoint) = .empty;
    for (hosts) |host| {
        var duplicate = false;
        for (selected.items) |existing| {
            if (existing.priority == host.priority and std.mem.eql(u8, existing.region, host.region) and std.mem.eql(u8, existing.zone, host.zone) and std.mem.eql(u8, existing.sub_zone, host.sub_zone)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) try selected.append(arena, host);
    }
    return selected.toOwnedSlice(arena);
}

fn dnsAssignment(arena: std.mem.Allocator, bytes: []const u8, name: []const u8, limits: Limits) Error![]const HostEndpoint {
    var parser = DnsParser{ .arena = arena, .limits = limits };
    var endpoints: std.ArrayList(HostEndpoint) = .empty;
    var cluster_name: []const u8 = "";
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) cluster_name = try parser.text(&reader) else if (field.number == 2 and field.wire_type == 2) {
            try parser.locality(try reader.bytesValue(), &endpoints);
        } else try reader.skip(field);
    }
    if (!std.mem.eql(u8, cluster_name, name)) return error.InvalidCdsResource;
    return endpoints.toOwnedSlice(arena);
}

fn circuit(bytes: []const u8, limit: usize) Error!u32 {
    var reader: pb.Reader = .{ .bytes = bytes };
    var count: usize = 0;
    var selected: ?u32 = null;
    while (try reader.next()) |field| {
        if (field.number != 1 or field.wire_type != 2) {
            try reader.skip(field);
            continue;
        }
        if (count >= limit) return error.CdsLimitExceeded;
        count += 1;
        var threshold: pb.Reader = .{ .bytes = try reader.bytesValue() };
        var priority: u32 = 0;
        var maximum: ?[]const u8 = null;
        while (try threshold.next()) |value| {
            if (value.number == 1 and value.wire_type == 0) priority = try pb.u32Value(&threshold) else if (value.number == 4 and value.wire_type == 2) maximum = try threshold.bytesValue() else try threshold.skip(value);
        }
        const raw = if (maximum) |value| try pb.wrapper(value) else 1024;
        if (raw > std.math.maxInt(u32)) return error.InvalidCdsResource;
        // DEFAULT selection does not excuse malformed nested wire data in a
        // HIGH or later threshold: the whole resource must decode first.
        if (priority != 0 or selected != null) continue;
        selected = @intCast(raw);
    }
    return selected orelse 1024;
}
fn dataSource(bytes: []const u8, limits: Limits) Error![]const u8 {
    var inline_bytes: ?[]const u8 = null;
    var inline_string: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) inline_bytes = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) {
            const value = try pb.text(&reader, limits.max_text_bytes);
            inline_string = value;
        } else if ((field.number == 3 or field.number == 4) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    return inline_bytes orelse inline_string orelse error.InvalidCdsResource;
}

fn tlsCertificate(bytes: []const u8, limits: Limits) Error!struct { chain: []const u8, key: []const u8 } {
    var chain: ?[]const u8 = null;
    var key: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) chain = try dataSource(try reader.bytesValue(), limits) else if (field.number == 2 and field.wire_type == 2) key = try dataSource(try reader.bytesValue(), limits) else if ((field.number == 3 or field.number == 4) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    return .{ .chain = chain orelse return error.InvalidCdsResource, .key = key orelse return error.InvalidCdsResource };
}

const Validation = struct {
    trusted_ca: []const u8,
    san_matchers: []const tls_material.SanMatcher,
};

fn sanMatcher(bytes: []const u8, limits: Limits) Error!tls_material.SanMatcher {
    var kind: ?tls_material.SanMatch = null;
    var value: []const u8 = "";
    var ignore_case = false;
    var count: usize = 0;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            value = try pb.text(&reader, limits.max_text_bytes);
            kind = .exact;
            count += 1;
        } else if (field.number == 2 and field.wire_type == 2) {
            value = try pb.text(&reader, limits.max_text_bytes);
            kind = .prefix;
            count += 1;
        } else if (field.number == 3 and field.wire_type == 2) {
            value = try pb.text(&reader, limits.max_text_bytes);
            kind = .suffix;
            count += 1;
        } else if (field.number == 7 and field.wire_type == 2) {
            value = try pb.text(&reader, limits.max_text_bytes);
            kind = .contains;
            count += 1;
        } else if ((field.number == 5 or field.number == 8) and field.wire_type == 2) return error.UnsupportedCdsFeature else if (field.number == 6 and field.wire_type == 0) {
            ignore_case = (try pb.u32Value(&reader)) != 0;
        } else try reader.skip(field);
    }
    if (count != 1) return error.InvalidCdsResource;
    return .{ .kind = kind.?, .value = value, .ignore_case = ignore_case };
}

fn validationContext(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Validation {
    var trusted_ca: ?[]const u8 = null;
    var matchers: std.ArrayList(tls_material.SanMatcher) = .empty;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) trusted_ca = try dataSource(try reader.bytesValue(), limits) else if (field.number == 2 and field.wire_type == 2) {
            try matchers.append(arena, try sanMatcher(try reader.bytesValue(), limits));
        } else if (field.number >= 3 and field.number <= 10) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    return .{ .trusted_ca = trusted_ca orelse return error.InvalidCdsResource, .san_matchers = try matchers.toOwnedSlice(arena) };
}

const TlsParams = struct {
    version_policy: tls_material.VersionPolicy,
    tls12_cipher_suites: []const tls_material.Tls12CipherSuite,
};

fn cipherSuite(name: []const u8) ?tls_material.Tls12CipherSuite {
    const map = std.StaticStringMap(tls_material.Tls12CipherSuite).initComptime(.{
        .{ "ECDHE-ECDSA-AES128-GCM-SHA256", .ecdhe_ecdsa_aes_128_gcm_sha256 },
        .{ "ECDHE-ECDSA-AES256-GCM-SHA384", .ecdhe_ecdsa_aes_256_gcm_sha384 },
        .{ "ECDHE-RSA-AES128-GCM-SHA256", .ecdhe_rsa_aes_128_gcm_sha256 },
        .{ "ECDHE-RSA-AES256-GCM-SHA384", .ecdhe_rsa_aes_256_gcm_sha384 },
        .{ "ECDHE-ECDSA-CHACHA20-POLY1305", .ecdhe_ecdsa_chacha20_poly1305_sha256 },
        .{ "ECDHE-RSA-CHACHA20-POLY1305", .ecdhe_rsa_chacha20_poly1305_sha256 },
    });
    return map.get(name);
}

fn tlsParameters(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!TlsParams {
    var minimum: ?u32 = null;
    var maximum: ?u32 = null;
    var suites: std.ArrayList(tls_material.Tls12CipherSuite) = .empty;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) minimum = try pb.u32Value(&reader) else if (field.number == 2 and field.wire_type == 0) maximum = try pb.u32Value(&reader) else if (field.number == 3 and field.wire_type == 2) {
            const name = try pb.text(&reader, limits.max_text_bytes);
            try suites.append(arena, cipherSuite(name) orelse return error.UnsupportedCdsFeature);
        } else if (field.number == 4 and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    // Envoy TlsProtocol: AUTO=0, TLSv1_0=1, TLSv1_1=2, TLSv1_2=3, TLSv1_3=4.
    const min = if (minimum) |value| if (value == 0) @as(u32, 3) else value else 3;
    const max = if (maximum) |value| if (value == 0) @as(u32, 4) else value else 4;
    if (min < 3 or max < 3 or min > max or max > 4) return if (min < 3 or max < 3) error.UnsupportedCdsFeature else error.InvalidCdsResource;
    const version_policy: tls_material.VersionPolicy = if (max == 3) .tls12_only else if (min == 4) .tls13_only else .tls12_and_tls13;
    return .{ .version_policy = version_policy, .tls12_cipher_suites = try suites.toOwnedSlice(arena) };
}

const CommonTls = struct {
    config: tls_material.Config = .{},
    sds: TlsSds = .{},
};

const TlsResult = struct {
    config: tls_material.Config,
    sds: ?TlsSds,
};

/// Decode an `SdsSecretConfig`. The source defaults to the ADS stream and any
/// explicit non-ADS source is rejected.
fn sdsSecretConfig(bytes: []const u8, limits: Limits) Error![]const u8 {
    var name: []const u8 = "";
    var source: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            name = try pb.text(&reader, limits.max_text_bytes);
        } else if (field.number == 2 and field.wire_type == 2) {
            source = try reader.bytesValue();
        } else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidCdsResource;
    if (source) |value| {
        const kind = @import("../config_source.zig").decode(value) catch |err| return switch (err) {
            error.UnsupportedConfigSource => error.UnsupportedCdsFeature,
            else => error.InvalidCdsResource,
        };
        if (kind != .ads) return error.UnsupportedCdsFeature;
    }
    return name;
}

fn commonTlsContext(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!CommonTls {
    var result = CommonTls{};
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            const params = try tlsParameters(arena, try reader.bytesValue(), limits);
            result.config.version_policy = params.version_policy;
            result.config.tls12_cipher_suites = params.tls12_cipher_suites;
        } else if (field.number == 2 and field.wire_type == 2) {
            if (result.config.certificate_chain.len != 0 or result.sds.certificate != null) return error.UnsupportedCdsFeature;
            const certificate = try tlsCertificate(try reader.bytesValue(), limits);
            result.config.certificate_chain = certificate.chain;
            result.config.private_key = certificate.key;
        } else if (field.number == 3 and field.wire_type == 2) {
            if (result.config.trusted_ca.len != 0 or result.sds.validation != null) return error.UnsupportedCdsFeature;
            const validation = try validationContext(arena, try reader.bytesValue(), limits);
            result.config.trusted_ca = validation.trusted_ca;
            result.config.san_matchers = validation.san_matchers;
        } else if (field.number == 4 and field.wire_type == 2) {
            _ = try reader.bytesValue();
        } else if (field.number == 6 and field.wire_type == 2) {
            if (result.config.certificate_chain.len != 0 or result.sds.certificate != null) return error.UnsupportedCdsFeature;
            result.sds.certificate = try sdsSecretConfig(try reader.bytesValue(), limits);
        } else if (field.number == 7 and field.wire_type == 2) {
            if (result.config.trusted_ca.len != 0 or result.sds.validation != null) return error.UnsupportedCdsFeature;
            result.sds.validation = try sdsSecretConfig(try reader.bytesValue(), limits);
        } else if (field.number >= 5 and field.number <= 15 and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    return result;
}

fn upstreamTlsContext(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!TlsResult {
    var result: tls_material.Config = .{};
    var sds = TlsSds{};
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            const common = try commonTlsContext(arena, try reader.bytesValue(), limits);
            result.trusted_ca = common.config.trusted_ca;
            result.certificate_chain = common.config.certificate_chain;
            result.private_key = common.config.private_key;
            result.version_policy = common.config.version_policy;
            result.tls12_cipher_suites = common.config.tls12_cipher_suites;
            result.san_matchers = common.config.san_matchers;
            sds = common.sds;
        } else if (field.number == 2 and field.wire_type == 2) {
            const value = try pb.text(&reader, 255);
            result.server_name = value;
        } else if (field.number == 3 and field.wire_type == 0) {
            if (try pb.u32Value(&reader) != 0) return error.UnsupportedCdsFeature;
        } else try reader.skip(field);
    }
    return .{
        .config = result,
        .sds = if (sds.certificate != null or sds.validation != null) sds else null,
    };
}

fn transportSocket(arena: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!TlsResult {
    var name: []const u8 = "";
    var typed: ?[]const u8 = null;
    var reader: pb.Reader = .{ .bytes = bytes };
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limits.max_text_bytes) else if (field.number == 3 and field.wire_type == 2) typed = try reader.bytesValue() else try reader.skip(field);
    }
    if (!std.mem.eql(u8, name, "envoy.transport_sockets.tls")) return error.UnsupportedCdsFeature;
    var any_type_url: []const u8 = "";
    var value: ?[]const u8 = null;
    var any: pb.Reader = .{ .bytes = typed orelse return error.InvalidCdsResource };
    while (try any.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) any_type_url = try any.string() else if (field.number == 2 and field.wire_type == 2) value = try any.bytesValue() else try any.skip(field);
    }
    if (!std.mem.eql(u8, any_type_url, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext")) return error.UnsupportedCdsFeature;
    return upstreamTlsContext(arena, value orelse return error.InvalidCdsResource, limits);
}

/// Parse `Cluster.CustomClusterType` (CDS field 38) for the aggregate cluster
/// extension. Any other custom cluster type remains unsupported.
fn aggregateCluster(
    arena: std.mem.Allocator,
    raw: []const u8,
    limits: Limits,
) Error![]const []const u8 {
    var custom: pb.Reader = .{ .bytes = raw };
    var extension_name: []const u8 = "";
    var typed_config: ?[]const u8 = null;
    while (try custom.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            extension_name = try pb.text(&custom, limits.max_text_bytes);
        } else if (field.number == 2 and field.wire_type == 2) {
            typed_config = try custom.bytesValue();
        } else try custom.skip(field);
    }
    if (!std.mem.eql(u8, extension_name, "envoy.clusters.aggregate")) {
        return error.UnsupportedCdsFeature;
    }
    const any = typed_config orelse return error.InvalidCdsResource;
    var any_reader: pb.Reader = .{ .bytes = any };
    var any_type_url: []const u8 = "";
    var value: ?[]const u8 = null;
    while (try any_reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            any_type_url = try pb.text(&any_reader, limits.max_text_bytes);
        } else if (field.number == 2 and field.wire_type == 2) {
            value = try any_reader.bytesValue();
        } else try any_reader.skip(field);
    }
    if (!std.mem.eql(
        u8,
        any_type_url,
        "type.googleapis.com/envoy.extensions.clusters.aggregate.v3.ClusterConfig",
    )) return error.UnsupportedCdsFeature;

    var config_reader: pb.Reader = .{
        .bytes = value orelse return error.InvalidCdsResource,
    };
    var clusters: std.ArrayList([]const u8) = .empty;
    while (try config_reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            const leaf = try pb.text(&config_reader, limits.max_text_bytes);
            if (leaf.len == 0) return error.InvalidCdsResource;
            if (clusters.items.len >= limits.max_aggregate_clusters) {
                return error.CdsLimitExceeded;
            }
            try clusters.append(arena, leaf);
        } else try config_reader.skip(field);
    }
    if (clusters.items.len == 0) return error.InvalidCdsResource;
    return clusters.toOwnedSlice(arena);
}

fn durationValue(bytes: []const u8) Error!std.Io.Duration {
    var reader: pb.Reader = .{ .bytes = bytes };
    var seconds: u64 = 0;
    var nanos: u32 = 0;
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 0) {
            seconds = try reader.varint();
        } else if (field.number == 2 and field.wire_type == 0) {
            const raw = try reader.varint();
            if (raw >= std.time.ns_per_s) return error.InvalidCdsResource;
            nanos = @intCast(raw);
        } else try reader.skip(field);
    }
    const whole = std.math.mul(u64, seconds, std.time.ns_per_s) catch
        return error.InvalidCdsResource;
    const total = std.math.add(u64, whole, nanos) catch
        return error.InvalidCdsResource;
    if (total > std.math.maxInt(i64)) return error.InvalidCdsResource;
    return .fromNanoseconds(@intCast(total));
}

fn u32Wrapper(bytes: []const u8) Error!u32 {
    const value = try pb.wrapper(bytes);
    if (value > std.math.maxInt(u32)) return error.InvalidCdsResource;
    return @intCast(value);
}

const http_protocol_options_type =
    "type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions";

fn typedConfigValue(
    bytes: []const u8,
    expected_type: []const u8,
) Error!?[]const u8 {
    var reader: pb.Reader = .{ .bytes = bytes };
    var any_bytes: ?[]const u8 = null;
    while (try reader.next()) |field| {
        if (field.number == 2 and field.wire_type == 2) {
            any_bytes = try reader.bytesValue();
        } else try reader.skip(field);
    }
    var any: pb.Reader = .{ .bytes = any_bytes orelse
        return error.InvalidCdsResource };
    var type_url_value: []const u8 = "";
    var value: ?[]const u8 = null;
    while (try any.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) {
            type_url_value = try any.string();
        } else if (field.number == 2 and field.wire_type == 2) {
            value = try any.bytesValue();
        } else try any.skip(field);
    }
    if (!std.mem.eql(u8, type_url_value, expected_type)) return null;
    return value orelse error.InvalidCdsResource;
}

fn http2Limits(bytes: []const u8) Error!Http2Limits {
    var reader: pb.Reader = .{ .bytes = bytes };
    var result: Http2Limits = .{};
    while (try reader.next()) |field| {
        switch (field.number) {
            2 => {
                var nested: pb.Reader = .{ .bytes = try reader.bytesValue() };
                while (try nested.next()) |inner| {
                    switch (inner.number) {
                        1 => result.header_table_size = try u32Wrapper(try nested.bytesValue()),
                        2 => result.max_concurrent_streams = try u32Wrapper(try nested.bytesValue()),
                        3 => result.initial_window_size = try u32Wrapper(try nested.bytesValue()),
                        4 => result.initial_connection_window_size = try u32Wrapper(try nested.bytesValue()),
                        else => try nested.skip(inner),
                    }
                }
            },
            // HTTP/1, HTTP/3 and automatic/downstream protocol selection are
            // not valid for a gRPC H2 upstream.
            1, 3, 4, 5, 6 => return error.UnsupportedCdsFeature,
            else => try reader.skip(field),
        }
    }
    if (result.initial_window_size) |value| {
        if (value > std.math.maxInt(i31)) return error.InvalidCdsResource;
    }
    if (result.initial_connection_window_size) |value| {
        if (value > std.math.maxInt(i31)) return error.InvalidCdsResource;
    }
    return result;
}

fn formatDuration(
    allocator: std.mem.Allocator,
    value: std.Io.Duration,
) Error![]const u8 {
    const raw = value.nanoseconds;
    if (raw < 0) return error.InvalidCdsResource;
    const total: u64 = @intCast(raw);
    const seconds = total / std.time.ns_per_s;
    const fraction = total % std.time.ns_per_s;
    if (fraction == 0) {
        return std.fmt.allocPrint(allocator, "{d}s", .{seconds});
    }
    var digits: [9]u8 = undefined;
    _ = std.fmt.bufPrint(&digits, "{d:0>9}", .{fraction}) catch
        return error.InvalidCdsResource;
    var end: usize = digits.len;
    while (end != 0 and digits[end - 1] == '0') end -= 1;
    return std.fmt.allocPrint(
        allocator,
        "{d}.{s}s",
        .{ seconds, digits[0..end] },
    );
}

fn appendJsonField(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime format: []const u8,
    args: anytype,
) Error!void {
    if (out.items.len != 0) try out.append(allocator, ',');
    const piece = try std.fmt.allocPrint(allocator, format, args);
    try out.appendSlice(allocator, piece);
}

/// Project Envoy's Cluster.outlier_detection onto gRPC's
/// `outlier_detection_experimental` policy. Consecutive-5xx and local-origin
/// controls have no gRPC counterpart and fail closed when enabled.
fn outlierConfig(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) Error![]const u8 {
    _ = limits;
    var reader: pb.Reader = .{ .bytes = bytes };
    var interval: ?std.Io.Duration = null;
    var base_ejection_time: ?std.Io.Duration = null;
    var max_ejection_time: ?std.Io.Duration = null;
    var max_ejection_percent: u32 = 10;
    var enforcing_success_rate: u32 = 100;
    var minimum_hosts: u32 = 5;
    var request_volume: u32 = 100;
    var stdev_factor: u32 = 1900;
    var failure_threshold: u32 = 85;
    var enforcing_failure: u32 = 0;
    var failure_minimum_hosts: u32 = 5;
    var failure_request_volume: u32 = 50;
    var failure_present = false;
    while (try reader.next()) |field| {
        switch (field.number) {
            1, 5, 10, 11, 13, 14, 15, 18 => {
                if (try u32Wrapper(try reader.bytesValue()) != 0) {
                    return error.UnsupportedCdsFeature;
                }
            },
            2 => interval = try durationValue(try reader.bytesValue()),
            3 => base_ejection_time = try durationValue(try reader.bytesValue()),
            4 => max_ejection_percent = try u32Wrapper(try reader.bytesValue()),
            6 => enforcing_success_rate = try u32Wrapper(try reader.bytesValue()),
            7 => minimum_hosts = try u32Wrapper(try reader.bytesValue()),
            8 => request_volume = try u32Wrapper(try reader.bytesValue()),
            9 => stdev_factor = try u32Wrapper(try reader.bytesValue()),
            12 => {
                if (try reader.varint() != 0) return error.UnsupportedCdsFeature;
            },
            16 => {
                failure_threshold = try u32Wrapper(try reader.bytesValue());
                failure_present = true;
            },
            17 => {
                enforcing_failure = try u32Wrapper(try reader.bytesValue());
                failure_present = true;
            },
            19 => {
                failure_minimum_hosts = try u32Wrapper(try reader.bytesValue());
                failure_present = true;
            },
            20 => {
                failure_request_volume = try u32Wrapper(try reader.bytesValue());
                failure_present = true;
            },
            21 => max_ejection_time = try durationValue(try reader.bytesValue()),
            22 => {
                const jitter = try durationValue(try reader.bytesValue());
                if (jitter.nanoseconds != 0) return error.UnsupportedCdsFeature;
            },
            23, 25 => {
                if ((try pb.wrapper(try reader.bytesValue())) != 0) {
                    return error.UnsupportedCdsFeature;
                }
            },
            24 => return error.UnsupportedCdsFeature,
            else => try reader.skip(field),
        }
    }
    if (max_ejection_percent > 100 or enforcing_success_rate > 100 or
        enforcing_failure > 100 or failure_threshold > 100)
    {
        return error.InvalidCdsResource;
    }
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (interval) |value| {
        try appendJsonField(
            &out,
            allocator,
            "\"interval\":\"{s}\"",
            .{try formatDuration(allocator, value)},
        );
    }
    if (base_ejection_time) |value| {
        try appendJsonField(
            &out,
            allocator,
            "\"baseEjectionTime\":\"{s}\"",
            .{try formatDuration(allocator, value)},
        );
    }
    if (max_ejection_time) |value| {
        try appendJsonField(
            &out,
            allocator,
            "\"maxEjectionTime\":\"{s}\"",
            .{try formatDuration(allocator, value)},
        );
    }
    try appendJsonField(
        &out,
        allocator,
        "\"maxEjectionPercent\":{d}",
        .{max_ejection_percent},
    );
    try appendJsonField(
        &out,
        allocator,
        "\"successRateEjection\":{{\"stdevFactor\":{d},\"enforcementPercentage\":{d},\"minimumHosts\":{d},\"requestVolume\":{d}}}",
        .{ stdev_factor, enforcing_success_rate, minimum_hosts, request_volume },
    );
    if (failure_present and enforcing_failure > 0) {
        try appendJsonField(
            &out,
            allocator,
            "\"failurePercentageEjection\":{{\"threshold\":{d},\"enforcementPercentage\":{d},\"minimumHosts\":{d},\"requestVolume\":{d}}}",
            .{
                failure_threshold,
                enforcing_failure,
                failure_minimum_hosts,
                failure_request_volume,
            },
        );
    }
    return out.toOwnedSlice(allocator);
}

pub fn decode(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) Error!Owned {
    if (bytes.len > limits.max_bytes) return error.CdsLimitExceeded;
    var result = Owned{ .arena = .init(gpa), .value = undefined };
    errdefer result.deinit();
    const arena = result.arena.allocator();
    const image = try arena.dupe(u8, bytes);
    result.wire = image;
    var reader: pb.Reader = .{ .bytes = image };
    var name: []const u8 = "";
    var kind: u32 = 0;
    var config: ?[]const u8 = null;
    var assignment: ?[]const u8 = null;
    var transport: ?[]const u8 = null;
    var lb: u32 = 0;
    var ring_config: ?[]const u8 = null;
    var typed_policy: ?[]const u8 = null;
    var breaker: ?[]const u8 = null;
    var outlier: ?[]const u8 = null;
    var http2: ?Http2Limits = null;
    var lrs_cpu: bool = false;
    var lrs_memory: bool = false;
    var lrs_application: bool = false;
    var lrs_named_all: bool = false;
    var lrs_named: std.ArrayList([]const u8) = .empty;
    var aggregate_clusters: []const []const u8 = &.{};
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limits.max_text_bytes) else if (field.number == 2 and field.wire_type == 0) kind = try pb.u32Value(&reader) else if (field.number == 38 and field.wire_type == 2) {
            aggregate_clusters = try aggregateCluster(
                arena,
                try reader.bytesValue(),
                limits,
            );
            kind = @intFromEnum(Discovery.aggregate);
        } else if (field.number == 3 and field.wire_type == 2) config = try reader.bytesValue() else if (field.number == 24 and field.wire_type == 2) transport = try reader.bytesValue() else if (field.number == 33 and field.wire_type == 2) assignment = try reader.bytesValue() else if (field.number == 6 and field.wire_type == 0) lb = try pb.u32Value(&reader) else if (field.number == 23 and field.wire_type == 2) ring_config = try reader.bytesValue() else if (field.number == 41 and field.wire_type == 2) typed_policy = try reader.bytesValue() else if (field.number == 10 and field.wire_type == 2) breaker = try reader.bytesValue() else if (field.number == 19 and field.wire_type == 2) outlier = try reader.bytesValue() else if (field.number == 48 and field.wire_type == 2) {
            const value = (try typedConfigValue(
                try reader.bytesValue(),
                http_protocol_options_type,
            )) orelse return error.UnsupportedCdsFeature;
            http2 = try http2Limits(value);
        } else if (field.number == 57 and field.wire_type == 2) {
            // Repeated string selecting ORCA metric propagation. Unknown
            // entries are ignored so forward-compatible control planes can add
            // selectors without failing the whole cluster.
            const value = try pb.text(&reader, limits.max_text_bytes);
            if (std.mem.eql(u8, value, "cpu_utilization")) {
                lrs_cpu = true;
            } else if (std.mem.eql(u8, value, "mem_utilization")) {
                lrs_memory = true;
            } else if (std.mem.eql(u8, value, "application_utilization")) {
                lrs_application = true;
            } else if (std.mem.eql(u8, value, "named_metrics.*")) {
                lrs_named_all = true;
            } else if (std.mem.startsWith(u8, value, "named_metrics.")) {
                const metric = value["named_metrics.".len..];
                if (metric.len != 0) try lrs_named.append(arena, metric);
            }
        } else if ((field.number == 43 or field.number == 42) and field.wire_type == 2) return error.UnsupportedCdsFeature else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidCdsResource;
    const discovery: Discovery = @enumFromInt(kind);
    // `aggregate` has no Envoy wire enum value; it is selected only by the
    // custom cluster extension above. A raw kind 4 is still unsupported.
    if (discovery == .aggregate and aggregate_clusters.len == 0) {
        return error.UnsupportedCdsFeature;
    }
    var service: []const u8 = "";
    var inline_assignment: []const u8 = "";
    var host_endpoints: []const HostEndpoint = &.{};
    switch (discovery) {
        .eds => {
            service = try eds(config orelse return error.InvalidCdsResource, limits.max_text_bytes);
            if (std.mem.startsWith(u8, name, "xdstp:") and service.len == 0) return error.InvalidCdsResource;
        },
        .static => {
            const raw = assignment orelse return error.InvalidCdsResource;
            var checked = @import("../eds/decode.zig").decode(arena, raw, .{ .max_bytes = limits.max_bytes }) catch |err| return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                else => error.InvalidCdsResource,
            };
            defer checked.deinit();
            if (!std.mem.eql(u8, checked.value.cluster_name, name)) return error.InvalidCdsResource;
            inline_assignment = raw;
        },
        .strict_dns, .logical_dns => {
            const raw = assignment orelse return error.InvalidCdsResource;
            host_endpoints = try dnsAssignment(arena, raw, name, limits);
            if (discovery == .logical_dns) host_endpoints = try onePerLocality(arena, host_endpoints);
            inline_assignment = raw;
        },
        .aggregate => {},
        else => return error.UnsupportedCdsFeature,
    }
    const tls_result = if (transport) |raw| try transportSocket(arena, raw, limits) else null;
    const tls: ?tls_material.Config = if (tls_result) |value| value.config else null;
    const tls_sds: ?TlsSds = if (tls_result) |value| value.sds else null;
    if (tls_sds != null and !limits.allow_sds) return error.UnsupportedCdsFeature;
    const lrs_propagation: LrsPropagation = .{
        .cpu_utilization = lrs_cpu,
        .memory_utilization = lrs_memory,
        .application_utilization = lrs_application,
        .named_metrics_all = lrs_named_all,
        .named_metrics = try lrs_named.toOwnedSlice(arena),
    };
    var cluster_policy = if (typed_policy) |raw|
        try policy.typed(arena, raw, limits.max_policies, limits.max_text_bytes, 0)
    else
        try policy.legacy(arena, lb, ring_config);
    if (outlier) |raw| {
        const outlier_json = try outlierConfig(arena, raw, limits);
        cluster_policy.child_json = try std.fmt.allocPrint(
            arena,
            "[{{\"outlier_detection_experimental\":{{\"childPolicy\":{s},{s}}}}}]",
            .{ cluster_policy.child_json, outlier_json },
        );
    }
    result.value = .{ .name = name, .eds_service_name = service, .discovery = discovery, .inline_assignment = inline_assignment, .host_endpoints = host_endpoints, .tls = tls, .tls_sds = tls_sds, .http2_limits = http2, .max_concurrent_requests = if (breaker) |raw| try circuit(raw, limits.max_thresholds) else 1024, .lrs_propagation = lrs_propagation, .aggregate_clusters = aggregate_clusters, .policy = cluster_policy };
    // Converted policies must satisfy the same configuration parser/runtime
    // contract as direct callers, including complete range validation.
    const json = try std.fmt.allocPrint(arena, "{{\"loadBalancingConfig\":{s}}}", .{result.value.policy.child_json});
    var checked = @import("../../service_config.zig").ServiceConfig.parse(arena, json) catch |err| return if (err == error.OutOfMemory) error.OutOfMemory else error.InvalidCdsResource;
    checked.deinit();
    return result;
}

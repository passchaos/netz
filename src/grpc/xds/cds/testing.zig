//! Small wire fixtures; interop uses the independent official Envoy schemas.
const std = @import("std");
pub const Builder = struct {
    allocator: std.mem.Allocator,
    data: std.ArrayList(u8) = .empty,
    pub fn deinit(self: *Builder) void {
        self.data.deinit(self.allocator);
    }
    fn integer(self: *Builder, raw: u64) !void {
        var value = raw;
        while (value >= 128) : (value >>= 7) try self.data.append(self.allocator, @as(u8, @truncate(value)) | 0x80);
        try self.data.append(self.allocator, @intCast(value));
    }
    pub fn number(self: *Builder, field: u32, value: u64) !void {
        try self.integer(@as(u64, field) * 8);
        try self.integer(value);
    }
    pub fn bytes(self: *Builder, field: u32, value: []const u8) !void {
        try self.integer(@as(u64, field) * 8 + 2);
        try self.integer(value.len);
        try self.data.appendSlice(self.allocator, value);
    }
    pub fn wrapper(self: *Builder, field: u32, value: u64) !void {
        var nested = Builder{ .allocator = self.allocator };
        defer nested.deinit();
        try nested.number(1, value);
        try self.bytes(field, nested.data.items);
    }
};
pub fn cluster(gpa: std.mem.Allocator, name: []const u8, service: []const u8, extra: []const u8) ![]u8 {
    var builder = Builder{ .allocator = gpa };
    errdefer builder.deinit();
    try builder.bytes(1, name);
    try builder.number(2, 3);
    var config = Builder{ .allocator = gpa };
    defer config.deinit();
    try config.bytes(1, "\x1a\x00"); // ConfigSource.ads
    try config.bytes(2, service);
    try builder.bytes(3, config.data.items);
    try builder.data.appendSlice(gpa, extra);
    return builder.data.toOwnedSlice(gpa);
}
pub const Host = struct { host: []const u8, port: u16 };
pub fn assignment(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16) ![]u8 {
    return assignmentHosts(gpa, name, &.{.{ .host = host, .port = port }});
}
pub fn assignmentHosts(gpa: std.mem.Allocator, name: []const u8, hosts: []const Host) ![]u8 {
    var locality = Builder{ .allocator = gpa };
    defer locality.deinit();
    try locality.bytes(1, "");
    try locality.wrapper(3, 1);
    for (hosts) |host| {
        var socket = Builder{ .allocator = gpa };
        defer socket.deinit();
        try socket.bytes(2, host.host);
        try socket.number(3, host.port);
        var address = Builder{ .allocator = gpa };
        defer address.deinit();
        try address.bytes(1, socket.data.items);
        var endpoint = Builder{ .allocator = gpa };
        defer endpoint.deinit();
        try endpoint.bytes(1, address.data.items);
        var lb = Builder{ .allocator = gpa };
        defer lb.deinit();
        try lb.bytes(1, endpoint.data.items);
        try locality.bytes(2, lb.data.items);
    }
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, name);
    try out.bytes(2, locality.data.items);
    return out.data.toOwnedSlice(gpa);
}
pub fn staticCluster(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16) ![]u8 {
    return discoveryCluster(gpa, name, host, port, 0);
}
pub fn staticClusterTls(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16, tls: []const u8) ![]u8 {
    const assign = try assignment(gpa, name, host, port);
    defer gpa.free(assign);
    var builder = Builder{ .allocator = gpa };
    errdefer builder.deinit();
    try builder.bytes(1, name);
    try builder.number(2, 0);
    try builder.bytes(33, assign);
    try builder.bytes(24, tls);
    return builder.data.toOwnedSlice(gpa);
}
pub fn upstreamTls(gpa: std.mem.Allocator, trusted_ca: []const u8, sni: []const u8) ![]u8 {
    return upstreamTlsWithVersions(gpa, trusted_ca, sni, null);
}
pub const Versions = struct { min: u32, max: u32 };
pub const SanSpec = struct { kind: enum { exact, prefix, suffix, contains }, value: []const u8 };
pub fn upstreamTlsWithVersions(gpa: std.mem.Allocator, trusted_ca: []const u8, sni: []const u8, versions: ?Versions) ![]u8 {
    return buildUpstreamTls(gpa, trusted_ca, sni, versions, &.{}, &.{});
}
pub fn upstreamTlsWithCiphers(gpa: std.mem.Allocator, trusted_ca: []const u8, sni: []const u8, ciphers: []const []const u8) ![]u8 {
    return buildUpstreamTls(gpa, trusted_ca, sni, null, ciphers, &.{});
}
pub fn upstreamTlsWithSans(gpa: std.mem.Allocator, trusted_ca: []const u8, sni: []const u8, sans: []const SanSpec) ![]u8 {
    return buildUpstreamTls(gpa, trusted_ca, sni, null, &.{}, sans);
}
fn buildUpstreamTls(gpa: std.mem.Allocator, trusted_ca: []const u8, sni: []const u8, versions: ?Versions, ciphers: []const []const u8, sans: []const SanSpec) ![]u8 {
    var trusted = Builder{ .allocator = gpa };
    defer trusted.deinit();
    try trusted.bytes(2, trusted_ca);
    var validation = Builder{ .allocator = gpa };
    defer validation.deinit();
    try validation.bytes(1, trusted.data.items);
    for (sans) |san| {
        var matcher = Builder{ .allocator = gpa };
        defer matcher.deinit();
        try matcher.bytes(switch (san.kind) {
            .exact => 1,
            .prefix => 2,
            .suffix => 3,
            .contains => 7,
        }, san.value);
        try validation.bytes(2, matcher.data.items);
    }
    var common = Builder{ .allocator = gpa };
    defer common.deinit();
    if (versions != null or ciphers.len != 0) {
        var params = Builder{ .allocator = gpa };
        defer params.deinit();
        if (versions) |value| {
            try params.number(1, value.min);
            try params.number(2, value.max);
        }
        for (ciphers) |name| try params.bytes(3, name);
        try common.bytes(1, params.data.items);
    }
    try common.bytes(3, validation.data.items);
    var context = Builder{ .allocator = gpa };
    defer context.deinit();
    try context.bytes(1, common.data.items);
    if (sni.len != 0) try context.bytes(2, sni);
    var any = Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext");
    try any.bytes(2, context.data.items);
    var socket = Builder{ .allocator = gpa };
    errdefer socket.deinit();
    try socket.bytes(1, "envoy.transport_sockets.tls");
    try socket.bytes(3, any.data.items);
    return socket.data.toOwnedSlice(gpa);
}
fn tlsSocket(gpa: std.mem.Allocator, context: []const u8) ![]u8 {
    var any = Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext");
    try any.bytes(2, context);
    var socket = Builder{ .allocator = gpa };
    errdefer socket.deinit();
    try socket.bytes(1, "envoy.transport_sockets.tls");
    try socket.bytes(3, any.data.items);
    return socket.data.toOwnedSlice(gpa);
}

pub fn sdsSecretConfig(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, name);
    // ConfigSource.ads (field 3) selects the enclosing ADS stream.
    try out.bytes(2, "\x1a\x00");
    return out.data.toOwnedSlice(gpa);
}

pub fn upstreamTlsSds(
    gpa: std.mem.Allocator,
    sni: []const u8,
    certificate: ?[]const u8,
    validation: ?[]const u8,
) ![]u8 {
    var common = Builder{ .allocator = gpa };
    defer common.deinit();
    if (certificate) |name| {
        const config = try sdsSecretConfig(gpa, name);
        defer gpa.free(config);
        try common.bytes(6, config);
    }
    if (validation) |name| {
        const config = try sdsSecretConfig(gpa, name);
        defer gpa.free(config);
        try common.bytes(7, config);
    }
    var context = Builder{ .allocator = gpa };
    defer context.deinit();
    try context.bytes(1, common.data.items);
    if (sni.len != 0) try context.bytes(2, sni);
    return tlsSocket(gpa, context.data.items);
}

pub fn dnsCluster(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16, kind: u32) ![]u8 {
    return discoveryCluster(gpa, name, host, port, kind);
}
pub fn dnsClusterHosts(gpa: std.mem.Allocator, name: []const u8, kind: u32, hosts: []const Host) ![]u8 {
    const assign = try assignmentHosts(gpa, name, hosts);
    defer gpa.free(assign);
    return discoveryClusterBytes(gpa, name, kind, assign);
}
fn discoveryCluster(gpa: std.mem.Allocator, name: []const u8, host: []const u8, port: u16, kind: u32) ![]u8 {
    const assign = try assignment(gpa, name, host, port);
    defer gpa.free(assign);
    return discoveryClusterBytes(gpa, name, kind, assign);
}
fn discoveryClusterBytes(gpa: std.mem.Allocator, name: []const u8, kind: u32, assign: []const u8) ![]u8 {
    var builder = Builder{ .allocator = gpa };
    errdefer builder.deinit();
    try builder.bytes(1, name);
    try builder.number(2, kind);
    try builder.bytes(33, assign);
    return builder.data.toOwnedSlice(gpa);
}
pub fn typed(gpa: std.mem.Allocator, type_url: []const u8, payload: []const u8) ![]u8 {
    var any = Builder{ .allocator = gpa };
    defer any.deinit();
    try any.bytes(1, type_url);
    try any.bytes(2, payload);
    var extension = Builder{ .allocator = gpa };
    defer extension.deinit();
    try extension.bytes(2, any.data.items);
    var policy = Builder{ .allocator = gpa };
    defer policy.deinit();
    try policy.bytes(4, extension.data.items);
    var out = Builder{ .allocator = gpa };
    errdefer out.deinit();
    try out.bytes(1, policy.data.items);
    return out.data.toOwnedSlice(gpa);
}

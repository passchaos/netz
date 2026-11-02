//! Small protobuf fixture builder; external conformance uses official schemas.
const std = @import("std");
const resource = @import("decode.zig");
pub const Endpoint = struct { host: []const u8 = "127.0.0.1", port: u16, health: u32 = 1, weight: ?u32 = null, extra_port: ?u16 = null, protocol: u32 = 0 };
pub const Locality = struct { region: []const u8, zone: []const u8 = "", priority: u32 = 0, weight: ?u32 = 1, endpoints: []const Endpoint };
fn integer(out: *std.ArrayList(u8), gpa: std.mem.Allocator, raw: u64) !void {
    var value = raw;
    while (value >= 128) : (value >>= 7) try out.append(gpa, @as(u8, @truncate(value)) | 0x80);
    try out.append(gpa, @intCast(value));
}
fn bytes(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, value: []const u8) !void {
    try integer(out, gpa, @as(u64, field) * 8 + 2);
    try integer(out, gpa, value.len);
    try out.appendSlice(gpa, value);
}
fn number(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, value: u32) !void {
    try integer(out, gpa, @as(u64, field) * 8);
    try integer(out, gpa, value);
}
fn weight(out: *std.ArrayList(u8), gpa: std.mem.Allocator, field: u32, value: u32) !void {
    var wrapper: std.ArrayList(u8) = .empty;
    defer wrapper.deinit(gpa);
    try number(&wrapper, gpa, 1, value);
    try bytes(out, gpa, field, wrapper.items);
}
fn address(gpa: std.mem.Allocator, value: Endpoint, port: u16) ![]u8 {
    var socket: std.ArrayList(u8) = .empty;
    defer socket.deinit(gpa);
    try number(&socket, gpa, 1, value.protocol);
    try bytes(&socket, gpa, 2, value.host);
    try number(&socket, gpa, 3, port);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try bytes(&out, gpa, 1, socket.items);
    return out.toOwnedSlice(gpa);
}
pub fn encode(gpa: std.mem.Allocator, cluster: []const u8, localities: []const Locality, drop: ?resource.Drop) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try bytes(&out, gpa, 1, cluster);
    for (localities) |value| {
        var local: std.ArrayList(u8) = .empty;
        defer local.deinit(gpa);
        var identity: std.ArrayList(u8) = .empty;
        defer identity.deinit(gpa);
        try bytes(&identity, gpa, 1, value.region);
        try bytes(&identity, gpa, 2, value.zone);
        try bytes(&local, gpa, 1, identity.items);
        if (value.weight) |w| try weight(&local, gpa, 3, w);
        try number(&local, gpa, 5, value.priority);
        for (value.endpoints) |endpoint| {
            var lb: std.ArrayList(u8) = .empty;
            defer lb.deinit(gpa);
            var ep: std.ArrayList(u8) = .empty;
            defer ep.deinit(gpa);
            const main = try address(gpa, endpoint, endpoint.port);
            defer gpa.free(main);
            try bytes(&ep, gpa, 1, main);
            if (endpoint.extra_port) |port| {
                var extra: std.ArrayList(u8) = .empty;
                defer extra.deinit(gpa);
                const addr = try address(gpa, endpoint, port);
                defer gpa.free(addr);
                try bytes(&extra, gpa, 1, addr);
                try bytes(&ep, gpa, 4, extra.items);
            }
            try bytes(&lb, gpa, 1, ep.items);
            try number(&lb, gpa, 2, endpoint.health);
            if (endpoint.weight) |w| try weight(&lb, gpa, 4, w);
            try bytes(&local, gpa, 2, lb.items);
        }
        try bytes(&out, gpa, 2, local.items);
    }
    if (drop) |value| {
        var policy: std.ArrayList(u8) = .empty;
        defer policy.deinit(gpa);
        var overload: std.ArrayList(u8) = .empty;
        defer overload.deinit(gpa);
        var fraction: std.ArrayList(u8) = .empty;
        defer fraction.deinit(gpa);
        try bytes(&overload, gpa, 1, value.category);
        try number(&fraction, gpa, 1, value.requests_per_million);
        try number(&fraction, gpa, 2, 2);
        try bytes(&overload, gpa, 2, fraction.items);
        try bytes(&policy, gpa, 2, overload.items);
        try bytes(&out, gpa, 4, policy.items);
    }
    return out.toOwnedSlice(gpa);
}

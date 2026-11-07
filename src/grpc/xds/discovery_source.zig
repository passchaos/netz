//! Immutable, retained provenance for bootstrap-managed discovery streams.
const std = @import("std");
const bootstrap = @import("bootstrap.zig");
const ads = @import("ads.zig");
const streaming = @import("../stream/runtime.zig");
const request_inputs = @import("../channel/shared/request_inputs.zig");
pub const Error = ads.codec.Error || error{UnsupportedDiscoveryRequest};
const lrs_feature = "envoy.lrs.supports_send_all_clusters";

pub const Source = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize) = .init(1),
    bootstrap: *bootstrap.Bootstrap,
    server: bootstrap.Server,
    node: ads.codec.Node,
    node_bytes: []const u8,
    lrs_node: ads.codec.Node,
    request: streaming.RequestOptions,
    /// Fixed-size identity of the bounded value encoding, never pointer identities.
    key: []const u8,

    pub fn create(gpa: std.mem.Allocator, configuration: *bootstrap.Bootstrap, server: bootstrap.Server, node: ads.codec.Node, request: streaming.RequestOptions) Error!*Source {
        // Managed discovery owns its method path and transport authority.
        if (request.fault_policy != null or request.xds_path_rewrite != null or request.xds_host_rewrite != null or request.xds_auto_host_rewrite) return error.UnsupportedDiscoveryRequest;
        const self = try gpa.create(Source);
        self.* = .{ .allocator = gpa, .arena = .init(gpa), .bootstrap = configuration.retain(), .server = server, .node = undefined, .node_bytes = "", .lrs_node = undefined, .request = request, .key = "" };
        errdefer self.release();
        const arena = self.arena.allocator();
        self.server = try copyValue(arena, server);
        self.node = try copyValue(arena, node);
        self.node_bytes = try ads.codec.encodeNode(arena, self.node);
        self.lrs_node = self.node;
        const supports_all = for (self.node.client_features) |feature| {
            if (std.mem.eql(u8, feature, lrs_feature)) break true;
        } else false;
        if (!supports_all) {
            const features = try arena.alloc([]const u8, self.node.client_features.len + 1);
            @memcpy(features[0..self.node.client_features.len], self.node.client_features);
            features[self.node.client_features.len] = lrs_feature;
            self.lrs_node.client_features = features;
        }
        // Materialize request-header policies and own all request slices.
        self.request = (try request_inputs.clone(arena, request)).options;
        var key = Key{ .allocator = arena };
        try key.encode(self.server);
        if (self.server.tlsConfig()) |tls| {
            try key.encode(if (tls.root_certificate_provider.len != 0) configuration.certificateProvider(tls.root_certificate_provider) else null);
            try key.encode(if (tls.identity_certificate_provider.len != 0) configuration.certificateProvider(tls.identity_certificate_provider) else null);
        }
        try key.encode(self.node_bytes);
        try key.encode(self.request);
        const encoded_key = try key.bytes.toOwnedSlice(arena);
        const fingerprint = try arena.create([32]u8);
        std.crypto.hash.sha2.Sha256.hash(encoded_key, fingerprint, .{});
        self.key = fingerprint;
        return self;
    }
    pub fn retain(self: *Source) *Source {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }
    pub fn release(self: *Source) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.arena.deinit();
        self.bootstrap.deinit();
        self.allocator.destroy(self);
    }
};

fn copyValue(arena: std.mem.Allocator, value: anytype) std.mem.Allocator.Error!@TypeOf(value) {
    const T = @TypeOf(value);
    switch (@typeInfo(T)) {
        .pointer => |info| {
            if (info.size != .slice) @compileError("Discovery copies cannot borrow object pointers");
            if (info.child == u8) return arena.dupe(u8, value);
            const values = try arena.alloc(info.child, value.len);
            for (value, values) |child, *owned| owned.* = try copyValue(arena, child);
            return values;
        },
        .optional => return if (value) |child| try copyValue(arena, child) else null,
        .@"struct" => |info| {
            var result = value;
            inline for (info.fields) |field| @field(result, field.name) = try copyValue(arena, @field(value, field.name));
            return result;
        },
        else => return value,
    }
}

/// Fixed-width little-endian integers, length-prefixed byte strings and
/// schema-ordered fields make equality independent of allocation addresses.
const Key = struct {
    allocator: std.mem.Allocator,
    bytes: std.ArrayList(u8) = .empty,
    fn append(self: *Key, bytes: []const u8) Error!void {
        const limit = (bootstrap.Limits{}).max_bytes;
        if (bytes.len > limit - self.bytes.items.len) return error.DiscoveryLimitExceeded;
        try self.bytes.appendSlice(self.allocator, bytes);
    }
    fn encode(self: *Key, value: anytype) Error!void {
        const T = @TypeOf(value);
        switch (@typeInfo(T)) {
            .int => |info| {
                var bytes: [16]u8 = undefined;
                const number: u128 = if (info.signedness == .signed) @bitCast(@as(i128, value)) else @intCast(value);
                std.mem.writeInt(u128, &bytes, number, .little);
                try self.append(&bytes);
            },
            .bool => try self.append(&.{@intFromBool(value)}),
            .@"enum" => try self.encode(@intFromEnum(value)),
            .optional => {
                try self.append(&.{@intFromBool(value != null)});
                if (value) |child| try self.encode(child);
            },
            .pointer => |info| switch (info.size) {
                .slice => {
                    try self.encode(@as(u64, @intCast(value.len)));
                    if (info.child == u8) try self.append(value) else for (value) |child| try self.encode(child);
                },
                .one => try self.encode(value.*),
                else => @compileError("Discovery key cannot contain unbounded pointers"),
            },
            .@"struct" => |info| inline for (info.fields) |field| {
                // URI spelling is redundant with the normalized target.
                if (comptime T == bootstrap.Server and std.mem.eql(u8, field.name, "uri")) continue;
                if (comptime T == streaming.RequestOptions and (std.mem.eql(u8, field.name, "fault_policy") or std.mem.eql(u8, field.name, "xds_path_rewrite") or std.mem.eql(u8, field.name, "xds_host_rewrite"))) continue;
                try self.encode(@field(value, field.name));
            },
            else => @compileError("Unsupported discovery key value"),
        }
    }
};

test "discovery source retains bootstrap and copies caller node and request" {
    const gpa = std.testing.allocator;
    const configuration = try bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://xds.test:80\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .{});
    var caller_owns_configuration = true;
    defer if (caller_owns_configuration) configuration.deinit();
    const source = blk: {
        var caller = std.heap.ArenaAllocator.init(gpa);
        defer caller.deinit();
        const arena = caller.allocator();
        break :blk try Source.create(gpa, configuration, configuration.servers[0], .{
            .id = try arena.dupe(u8, "node"),
            .cluster = try arena.dupe(u8, "cluster"),
            .metadata = try arena.dupe(u8, ""),
            .locality = .{ .zone = try arena.dupe(u8, "zone") },
            .user_agent_name = try arena.dupe(u8, "agent"),
            .user_agent_version = try arena.dupe(u8, "version"),
            .client_features = &.{try arena.dupe(u8, "feature")},
        }, .{ .path = try arena.dupe(u8, "/discovery"), .metadata = &.{.{ .name = try arena.dupe(u8, "x-key"), .value = try arena.dupe(u8, "value") }} });
    };
    defer source.release();
    configuration.deinit();
    caller_owns_configuration = false;
    try std.testing.expectEqual(@as(usize, 1), configuration.refs.load(.acquire));
    try std.testing.expectEqualStrings("xds.test", source.server.target.host);
    try std.testing.expectEqualStrings("zone", source.node.locality.?.zone);
    try std.testing.expectEqualStrings("version", source.node.user_agent_version);
    try std.testing.expectEqualStrings("feature", source.node.client_features[0]);
    try std.testing.expectEqualStrings("value", source.request.metadata[0].value);
    try std.testing.expectEqualStrings(lrs_feature, source.lrs_node.client_features[1]);
    try std.testing.expect(source.retain() == source);
    source.release();
}

test "discovery source equivalent rebind keys and allocation cleanup" {
    const Scenario = struct {
        fn run(gpa: std.mem.Allocator) !void {
            const json = "{\"xds_servers\":[{\"server_uri\":\"http://xds.test\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}";
            const first = try bootstrap.parse(gpa, json, .{});
            defer first.deinit();
            const second = try bootstrap.parse(gpa, json, .{});
            defer second.deinit();
            const a = try Source.create(gpa, first, first.servers[0], .{ .id = "node" }, .{ .path = "/ads", .authority = "xds.test", .binary_metadata = &.{.{ .name = "key-bin", .value = "\xff" }} });
            defer a.release();
            const b = try Source.create(gpa, second, second.servers[0], .{ .id = "node" }, a.request);
            defer b.release();
            try std.testing.expectEqualSlices(u8, a.key, b.key);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Scenario.run, .{});
}

test "discovery source rejects application route rewriting" {
    const gpa = std.testing.allocator;
    const configuration = try bootstrap.parse(gpa, "{\"xds_servers\":[{\"server_uri\":\"http://xds.test\",\"channel_creds\":[{\"type\":\"insecure\"}]}]}", .{});
    defer configuration.deinit();
    const requests = [_]streaming.RequestOptions{
        .{ .path = "/ads", .xds_auto_host_rewrite = true },
        .{ .path = "/ads", .xds_path_rewrite = .{ .prefix = .{ .matched = 1, .replacement = "/rewritten/" } } },
    };
    for (requests) |request| try std.testing.expectError(error.UnsupportedDiscoveryRequest, Source.create(gpa, configuration, configuration.servers[0], .{ .id = "node" }, request));
    try std.testing.expectEqual(@as(usize, 1), configuration.refs.load(.acquire));
}

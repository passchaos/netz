//! Bounded owned RDS v3 resource; matching and action parsing stay cohesive.
const std = @import("std");
const model = @import("model.zig");
const pb = @import("protobuf.zig");
const routing = @import("../routing/mod.zig");
const Parser = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    limits: model.Limits,
    routes: usize = 0,
    domains: usize = 0,
    regex_instructions: usize = 0,
    cluster_entries: usize = 0,
    pub fn noteCluster(self: *Parser) pb.Error!void {
        if (self.cluster_entries >= self.limits.max_cluster_entries) return error.RdsLimitExceeded;
        self.cluster_entries += 1;
    }
    pub fn regex(self: *Parser, bytes: []const u8) pb.Error!routing.string.Match {
        var reader = pb.Reader{ .bytes = bytes };
        var pattern: []const u8 = "";
        while (try reader.next()) |field| {
            if (field.number == 2 and field.wire_type == 2) pattern = try pb.text(&reader, self.limits.max_text_bytes) else try reader.skip(field);
        }
        const matcher = routing.string.Match.compileRegex(self.allocator, pattern, self.limits.regex) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.RegexLimitExceeded => error.RdsLimitExceeded,
            else => error.InvalidRdsResource,
        };
        self.regex_instructions = std.math.add(usize, self.regex_instructions, matcher.safe_regex.instructions.len) catch return error.RdsLimitExceeded;
        if (self.regex_instructions > self.limits.max_total_regex_instructions) return error.RdsLimitExceeded;
        if (self.arena.queryCapacity() > self.limits.max_storage_bytes) return error.RdsLimitExceeded;
        return matcher;
    }
    fn route(self: *Parser, bytes: []const u8, inherited: ?@import("../../call.zig").RetryPolicy) pb.Error!?model.Route {
        if (self.routes >= self.limits.max_routes) return error.RdsLimitExceeded;
        self.routes += 1;
        var reader = pb.Reader{ .bytes = bytes };
        var raw_match: ?[]const u8 = null;
        var raw_action: ?[]const u8 = null;
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) raw_match = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) raw_action = try reader.bytesValue() else if ((field.number == 3 or field.number == 7 or field.number == 17 or field.number == 18 or field.number == 19) and field.wire_type == 2) {
                _ = try reader.bytesValue();
                raw_action = null;
            } else if (field.number == 13 and field.wire_type == 2) return error.UnsupportedRdsFeature else try reader.skip(field);
        }
        const match = (try @import("match.zig").decode(self, raw_match orelse return error.InvalidRdsResource)) orelse return null;
        var action: @FieldType(model.Route, "action") = .inappropriate;
        if (raw_action) |raw| {
            var forward = (try @import("action.zig").decode(self, raw)) orelse return null;
            if (!forward.retry_present) forward.retry_policy = inherited;
            action = .{ .forward = forward };
        }
        return .{ .path = match.path, .headers = match.headers, .fraction_per_million = match.fraction, .action = action };
    }
    fn virtualHost(self: *Parser, bytes: []const u8) pb.Error!model.VirtualHost {
        var reader = pb.Reader{ .bytes = bytes };
        var domains: std.ArrayList([]const u8) = .empty;
        defer domains.deinit(self.allocator);
        var routes: std.ArrayList([]const u8) = .empty;
        defer routes.deinit(self.allocator);
        var retry: ?@import("../../call.zig").RetryPolicy = null;
        while (try reader.next()) |field| {
            if (field.number == 2 and field.wire_type == 2) {
                if (self.domains >= self.limits.max_domains) return error.RdsLimitExceeded;
                self.domains += 1;
                const value = try pb.text(&reader, self.limits.max_text_bytes);
                if (routing.domain.kind(value) == null) return error.InvalidRdsResource;
                try domains.append(self.allocator, value);
            } else if (field.number == 3 and field.wire_type == 2) {
                if (routes.items.len >= self.limits.max_routes) return error.RdsLimitExceeded;
                try routes.append(self.allocator, try reader.bytesValue());
            } else if (field.number == 16 and field.wire_type == 2) retry = try @import("retry.zig").parse(self.allocator, try reader.bytesValue(), self.limits.max_text_bytes) else if (field.number == 15 and field.wire_type == 2) return error.UnsupportedRdsFeature else try reader.skip(field);
        }
        if (domains.items.len == 0) return error.InvalidRdsResource;
        var values: std.ArrayList(model.Route) = .empty;
        defer values.deinit(self.allocator);
        for (routes.items) |raw| {
            if (try self.route(raw, retry)) |value| try values.append(self.allocator, value);
            if (self.arena.queryCapacity() > self.limits.max_storage_bytes) return error.RdsLimitExceeded;
        }
        return .{ .domains = try domains.toOwnedSlice(self.allocator), .routes = try values.toOwnedSlice(self.allocator) };
    }
};
pub fn decode(gpa: std.mem.Allocator, bytes: []const u8, limits: model.Limits) model.Error!model.Owned {
    if (bytes.len > limits.max_bytes) return error.RdsLimitExceeded;
    var owned = model.Owned{ .arena = .init(gpa), .value = undefined };
    errdefer owned.deinit();
    const allocator = owned.arena.allocator();
    const image = try allocator.dupe(u8, bytes);
    owned.wire = image;
    var parser = Parser{ .allocator = allocator, .arena = &owned.arena, .limits = limits };
    var reader = pb.Reader{ .bytes = image };
    var name: []const u8 = "";
    var hosts: std.ArrayList(model.VirtualHost) = .empty;
    defer hosts.deinit(allocator);
    while (try reader.next()) |field| {
        if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, limits.max_text_bytes) else if (field.number == 2 and field.wire_type == 2) {
            if (hosts.items.len >= limits.max_virtual_hosts) return error.RdsLimitExceeded;
            try hosts.append(allocator, try parser.virtualHost(try reader.bytesValue()));
        } else if ((field.number == 12 or field.number == 13) and field.wire_type == 2) return error.UnsupportedRdsFeature else try reader.skip(field);
    }
    if (name.len == 0) return error.InvalidRdsResource;
    if (owned.arena.queryCapacity() > limits.max_storage_bytes) return error.RdsLimitExceeded;
    owned.value = .{ .name = name, .virtual_hosts = try hosts.toOwnedSlice(allocator) };
    return owned;
}

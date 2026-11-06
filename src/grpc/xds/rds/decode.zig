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
    fn parseAny(self: *Parser, bytes: []const u8) pb.Error!struct { type_name: []const u8, value: []const u8 } {
        var reader = pb.Reader{ .bytes = bytes };
        var url: []const u8 = "";
        var value: []const u8 = "";
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) url = try pb.text(&reader, self.limits.max_text_bytes) else if (field.number == 2 and field.wire_type == 2) value = try reader.bytesValue() else try reader.skip(field);
        }
        const offset = std.mem.lastIndexOfScalar(u8, url, '/') orelse return error.InvalidRdsResource;
        if (offset + 1 == url.len) return error.InvalidRdsResource;
        return .{ .type_name = url[offset + 1 ..], .value = value };
    }
    fn overrideKind(type_name: []const u8) ?model.OverrideKind {
        if (std.mem.eql(u8, type_name, "envoy.extensions.filters.http.rbac.v3.RBACPerRoute")) return .rbac;
        if (std.mem.eql(u8, type_name, "envoy.extensions.filters.http.fault.v3.HTTPFault")) return .fault;
        return null;
    }
    fn rbacPerRoute(self: *Parser, bytes: []const u8) pb.Error!model.Override {
        _ = self;
        var reader = pb.Reader{ .bytes = bytes };
        var policy: ?[]const u8 = null;
        while (try reader.next()) |field| {
            if (field.number == 2 and field.wire_type == 2) policy = try reader.bytesValue() else try reader.skip(field);
        }
        return if (policy) |value|
            .{ .kind = .rbac, .config = value }
        else
            .{ .kind = .rbac, .disabled = true };
    }
    fn overrideAny(self: *Parser, bytes: []const u8) pb.Error!?model.Override {
        const parsed = try self.parseAny(bytes);
        if (std.mem.eql(u8, parsed.type_name, "envoy.config.route.v3.FilterConfig")) {
            var reader = pb.Reader{ .bytes = parsed.value };
            var inner: ?[]const u8 = null;
            var disabled = false;
            while (try reader.next()) |field| {
                if (field.number == 1 and field.wire_type == 2) inner = try reader.bytesValue() else if (field.number == 3 and field.wire_type == 0) disabled = (try reader.varint()) != 0 else try reader.skip(field);
            }
            if (disabled) {
                if (inner) |value| {
                    const nested = try self.parseAny(value);
                    return .{ .kind = overrideKind(nested.type_name), .disabled = true };
                }
                return .{ .disabled = true };
            }
            const value = inner orelse return error.InvalidRdsResource;
            const nested = try self.parseAny(value);
            if (overrideKind(nested.type_name) == .rbac) return try self.rbacPerRoute(nested.value);
            if (overrideKind(nested.type_name) == .fault) return .{ .kind = .fault, .config = nested.value };
            return null;
        }
        if (overrideKind(parsed.type_name) == .rbac) return try self.rbacPerRoute(parsed.value);
        if (overrideKind(parsed.type_name) == .fault) return .{ .kind = .fault, .config = parsed.value };
        return null;
    }
    fn overrideEntry(self: *Parser, bytes: []const u8) pb.Error!?model.Override {
        var reader = pb.Reader{ .bytes = bytes };
        var name: []const u8 = "";
        var any: ?[]const u8 = null;
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) name = try pb.text(&reader, self.limits.max_text_bytes) else if (field.number == 2 and field.wire_type == 2) any = try reader.bytesValue() else try reader.skip(field);
        }
        if (name.len == 0 or any == null) return error.InvalidRdsResource;
        var value = (try self.overrideAny(any.?)) orelse return null;
        value.name = name;
        return value;
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
    fn headerNameValid(name: []const u8) bool {
        if (name.len == 0 or name[0] == ':') return false;
        if (std.mem.endsWith(u8, name, "-bin")) return false;
        if (std.ascii.eqlIgnoreCase(name, "content-type") or
            std.ascii.eqlIgnoreCase(name, "te") or
            std.ascii.startsWithIgnoreCase(name, "grpc-"))
        {
            return false;
        }
        for (name) |byte| {
            if ((byte >= 'a' and byte <= 'z') or
                (byte >= '0' and byte <= '9') or
                byte == '_' or byte == '-' or byte == '.')
            {
                continue;
            }
            return false;
        }
        return true;
    }
    fn headerValueValid(value: []const u8) bool {
        for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
        return true;
    }
    fn headerMutation(
        self: *Parser,
        bytes: []const u8,
    ) pb.Error!?@import("../../call.zig").HeaderMutation {
        var reader = pb.Reader{ .bytes = bytes };
        var key: []const u8 = "";
        var value: ?[]const u8 = null;
        var raw_value: ?[]const u8 = null;
        var append: ?bool = null;
        var append_action: ?u64 = null;
        var keep_empty = false;
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) {
                var nested = pb.Reader{ .bytes = try reader.bytesValue() };
                while (try nested.next()) |entry| {
                    if (entry.number == 1 and entry.wire_type == 2) {
                        key = try pb.text(&nested, self.limits.max_text_bytes);
                    } else if (entry.number == 2 and entry.wire_type == 2) {
                        value = try pb.text(&nested, self.limits.max_text_bytes);
                    } else if (entry.number == 3 and entry.wire_type == 2) {
                        raw_value = try nested.bytesValue();
                    } else try nested.skip(entry);
                }
            } else if (field.number == 2 and field.wire_type == 2) {
                append = (try pb.wrapper(try reader.bytesValue())) != 0;
            } else if (field.number == 3 and field.wire_type == 0) {
                append_action = try reader.varint();
            } else if (field.number == 4 and field.wire_type == 0) {
                keep_empty = (try reader.varint()) != 0;
            } else try reader.skip(field);
        }
        if (!headerNameValid(key)) return error.InvalidRdsResource;
        if (value != null and raw_value != null) return error.InvalidRdsResource;
        const header_value = raw_value orelse value orelse "";
        if (!headerValueValid(header_value)) return error.InvalidRdsResource;
        if (header_value.len == 0 and !keep_empty) return null;
        if (std.mem.indexOfScalar(u8, header_value, '%') != null) {
            return error.UnsupportedRdsFeature;
        }
        const action: @import("../../call.zig").HeaderMutationAction = if (append_action) |raw| switch (raw) {
            0 => .append,
            1 => .add_if_absent,
            2 => .overwrite,
            3 => .overwrite_if_exists,
            else => return error.InvalidRdsResource,
        } else if (append) |enabled|
            if (enabled) .append else .overwrite
        else
            .append;
        return .{ .name = key, .value = header_value, .action = action };
    }
    fn route(self: *Parser, bytes: []const u8, inherited: ?@import("../../call.zig").RetryPolicy) pb.Error!?model.Route {
        if (self.routes >= self.limits.max_routes) return error.RdsLimitExceeded;
        self.routes += 1;
        var reader = pb.Reader{ .bytes = bytes };
        var raw_match: ?[]const u8 = null;
        var raw_action: ?[]const u8 = null;
        var headers_to_add: std.ArrayList(@import("../../call.zig").HeaderMutation) = .empty;
        defer headers_to_add.deinit(self.allocator);
        var headers_to_remove: std.ArrayList([]const u8) = .empty;
        defer headers_to_remove.deinit(self.allocator);
        var response_headers_to_add: std.ArrayList(@import("../../call.zig").HeaderMutation) = .empty;
        defer response_headers_to_add.deinit(self.allocator);
        var response_headers_to_remove: std.ArrayList([]const u8) = .empty;
        defer response_headers_to_remove.deinit(self.allocator);
        var overrides: std.ArrayList(model.Override) = .empty;
        defer overrides.deinit(self.allocator);
        while (try reader.next()) |field| {
            if (field.number == 1 and field.wire_type == 2) raw_match = try reader.bytesValue() else if (field.number == 2 and field.wire_type == 2) raw_action = try reader.bytesValue() else if ((field.number == 3 or field.number == 7 or field.number == 17 or field.number == 18 or field.number == 19) and field.wire_type == 2) {
                _ = try reader.bytesValue();
                raw_action = null;
            } else if (field.number == 9 and field.wire_type == 2) {
                if (headers_to_add.items.len >= self.limits.max_headers_per_route) {
                    return error.RdsLimitExceeded;
                }
                if (try self.headerMutation(try reader.bytesValue())) |mutation| {
                    try headers_to_add.append(self.allocator, mutation);
                }
            } else if (field.number == 12 and field.wire_type == 2) {
                if (headers_to_remove.items.len >= self.limits.max_headers_per_route) {
                    return error.RdsLimitExceeded;
                }
                const name = try pb.text(&reader, self.limits.max_text_bytes);
                if (!headerNameValid(name)) return error.InvalidRdsResource;
                try headers_to_remove.append(self.allocator, name);
            } else if (field.number == 10 and field.wire_type == 2) {
                if (response_headers_to_add.items.len >= self.limits.max_headers_per_route) {
                    return error.RdsLimitExceeded;
                }
                if (try self.headerMutation(try reader.bytesValue())) |mutation| {
                    try response_headers_to_add.append(self.allocator, mutation);
                }
            } else if (field.number == 11 and field.wire_type == 2) {
                if (response_headers_to_remove.items.len >= self.limits.max_headers_per_route) {
                    return error.RdsLimitExceeded;
                }
                const name = try pb.text(&reader, self.limits.max_text_bytes);
                if (!headerNameValid(name)) return error.InvalidRdsResource;
                try response_headers_to_remove.append(self.allocator, name);
            } else if (field.number == 13 and field.wire_type == 2) {
                if (overrides.items.len >= self.limits.max_overrides) return error.RdsLimitExceeded;
                if (try self.overrideEntry(try reader.bytesValue())) |entry| try overrides.append(self.allocator, entry);
            } else try reader.skip(field);
        }
        const match = (try @import("match.zig").decode(self, raw_match orelse return error.InvalidRdsResource)) orelse return null;
        var action: @FieldType(model.Route, "action") = .inappropriate;
        if (raw_action) |raw| {
            var forward = (try @import("action.zig").decode(self, raw, match.path)) orelse return null;
            if (!forward.retry_present) forward.retry_policy = inherited;
            action = .{ .forward = forward };
        }
        return .{
            .path = match.path,
            .headers = match.headers,
            .fraction_per_million = match.fraction,
            .action = action,
            .request_headers_to_add = try headers_to_add.toOwnedSlice(self.allocator),
            .request_headers_to_remove = try headers_to_remove.toOwnedSlice(self.allocator),
            .response_headers_to_add = try response_headers_to_add.toOwnedSlice(self.allocator),
            .response_headers_to_remove = try response_headers_to_remove.toOwnedSlice(self.allocator),
            .overrides = try overrides.toOwnedSlice(self.allocator),
        };
    }
    fn virtualHost(self: *Parser, bytes: []const u8) pb.Error!model.VirtualHost {
        var reader = pb.Reader{ .bytes = bytes };
        var domains: std.ArrayList([]const u8) = .empty;
        defer domains.deinit(self.allocator);
        var routes: std.ArrayList([]const u8) = .empty;
        defer routes.deinit(self.allocator);
        var retry: ?@import("../../call.zig").RetryPolicy = null;
        var overrides: std.ArrayList(model.Override) = .empty;
        defer overrides.deinit(self.allocator);
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
            } else if (field.number == 16 and field.wire_type == 2) retry = try @import("retry.zig").parse(self.allocator, try reader.bytesValue(), self.limits.max_text_bytes) else if (field.number == 15 and field.wire_type == 2) {
                if (overrides.items.len >= self.limits.max_overrides) return error.RdsLimitExceeded;
                if (try self.overrideEntry(try reader.bytesValue())) |entry| try overrides.append(self.allocator, entry);
            } else try reader.skip(field);
        }
        if (domains.items.len == 0) return error.InvalidRdsResource;
        var values: std.ArrayList(model.Route) = .empty;
        defer values.deinit(self.allocator);
        for (routes.items) |raw| {
            if (try self.route(raw, retry)) |value| try values.append(self.allocator, value);
            if (self.arena.queryCapacity() > self.limits.max_storage_bytes) return error.RdsLimitExceeded;
        }
        return .{
            .domains = try domains.toOwnedSlice(self.allocator),
            .routes = try values.toOwnedSlice(self.allocator),
            .overrides = try overrides.toOwnedSlice(self.allocator),
        };
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

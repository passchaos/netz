//! Owned CORS response fields, usable with either HTTP/1 or HTTP/2 adapters.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const policy_mod = @import("policy.zig");

pub const Headers = struct {
    allocator: std.mem.Allocator,
    fields: []http2.Hpack.HeaderField,
    values: []u8,

    pub fn init(allocator: std.mem.Allocator, policy: policy_mod.Policy, decision: policy_mod.Decision) !Headers {
        try policy.validate();
        const allowed = decision.kind == .allowed or decision.kind == .preflight;
        const preflight = decision.kind == .preflight;
        const names = if (preflight) policy.allowed_headers else policy.exposed_headers;
        var joined_len: usize = 0;
        if (allowed) for (names, 0..) |name, index| {
            joined_len = std.math.add(usize, joined_len, name.len + @as(usize, if (index == 0) 0 else 2)) catch return error.InvalidCorsPolicy;
        };
        var age_buffer: [10]u8 = undefined;
        const age = if (preflight and policy.max_age_seconds != 0)
            std.fmt.bufPrint(&age_buffer, "{d}", .{policy.max_age_seconds}) catch unreachable
        else
            "";
        const origin = if (allowed) decision.origin orelse return error.InvalidCorsRequest else "";
        const values_len = std.math.add(usize, std.math.add(usize, origin.len, joined_len) catch return error.InvalidCorsPolicy, age.len) catch return error.InvalidCorsPolicy;
        const fields_len: usize = 1 + if (!allowed) @as(usize, 0) else 1 + @as(usize, @intFromBool(policy.allow_credentials)) + @as(usize, @intFromBool(joined_len != 0)) + @as(usize, @intFromBool(preflight)) + @as(usize, @intFromBool(age.len != 0));
        const fields = try allocator.alloc(http2.Hpack.HeaderField, fields_len);
        errdefer allocator.free(fields);
        const values = try allocator.alloc(u8, values_len);
        errdefer allocator.free(values);
        var count: usize = 0;
        fields[count] = .{ .name = "vary", .value = if (preflight) "Origin, Access-Control-Request-Method, Access-Control-Request-Headers" else "Origin" };
        count += 1;
        if (allowed) {
            @memcpy(values[0..origin.len], origin);
            fields[count] = .{ .name = "access-control-allow-origin", .value = values[0..origin.len] };
            count += 1;
            if (policy.allow_credentials) {
                fields[count] = .{ .name = "access-control-allow-credentials", .value = "true" };
                count += 1;
            }
            if (preflight) {
                fields[count] = .{ .name = "access-control-allow-methods", .value = "POST" };
                count += 1;
            }
            var offset = origin.len;
            for (names, 0..) |name, index| {
                if (index != 0) {
                    @memcpy(values[offset..][0..2], ", ");
                    offset += 2;
                }
                @memcpy(values[offset..][0..name.len], name);
                offset += name.len;
            }
            if (joined_len != 0) {
                fields[count] = .{ .name = if (preflight) "access-control-allow-headers" else "access-control-expose-headers", .value = values[origin.len..offset] };
                count += 1;
            }
            if (age.len != 0) {
                @memcpy(values[offset..][0..age.len], age);
                fields[count] = .{ .name = "access-control-max-age", .value = values[offset..][0..age.len] };
                count += 1;
            }
        }
        std.debug.assert(count == fields_len);
        return .{ .allocator = allocator, .fields = fields, .values = values };
    }

    pub fn deinit(self: *Headers) void {
        self.allocator.free(self.fields);
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

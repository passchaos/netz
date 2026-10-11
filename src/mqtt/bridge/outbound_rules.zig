//! Owned disjoint subscription rules shared by outbound source kinds.
const std = @import("std");
const mqtt = @import("../mod.zig");
const rule_helpers = @import("rules.zig");
const outbound = @import("outbound_engine.zig");
const Rule = outbound.Rule;
const Error = outbound.Error;

pub const OwnedRule = struct {
    value: Rule,
    source_filter: []u8,

    pub fn deinit(self: *OwnedRule, allocator: std.mem.Allocator) void {
        allocator.free(self.source_filter);
        allocator.free(self.value.remote_prefix);
        allocator.free(self.value.local_prefix);
        allocator.free(self.value.filter);
        self.* = undefined;
    }
};

pub const OwnedRules = struct {
    values: []OwnedRule,

    pub fn init(
        allocator: std.mem.Allocator,
        source: []const Rule,
    ) Error!OwnedRules {
        if (source.len == 0) return error.NoBridgeRules;
        const values = try allocator.alloc(OwnedRule, source.len);
        var initialized: usize = 0;
        errdefer {
            for (values[0..initialized]) |*value| value.deinit(allocator);
            allocator.free(values);
        }
        for (source, values) |rule, *owned| {
            try rule.validate();
            const filter = try allocator.dupe(u8, rule.filter);
            errdefer allocator.free(filter);
            const local_prefix = try allocator.dupe(u8, rule.local_prefix);
            errdefer allocator.free(local_prefix);
            const remote_prefix = try allocator.dupe(u8, rule.remote_prefix);
            errdefer allocator.free(remote_prefix);
            const value = Rule{
                .filter = filter,
                .qos = rule.qos,
                .local_prefix = local_prefix,
                .remote_prefix = remote_prefix,
            };
            const source_filter = try value.sourceFilterAlloc(allocator);
            errdefer allocator.free(source_filter);
            owned.* = .{
                .value = value,
                .source_filter = source_filter,
            };
            for (values[0..initialized]) |previous| {
                if (std.mem.eql(
                    u8,
                    previous.source_filter,
                    source_filter,
                )) {
                    return error.DuplicateBridgeFilter;
                }
                if (rule_helpers.filtersOverlap(
                    previous.source_filter,
                    source_filter,
                )) {
                    return error.OverlappingBridgeFilters;
                }
            }
            initialized += 1;
        }
        return .{ .values = values };
    }

    pub fn deinit(self: *OwnedRules, allocator: std.mem.Allocator) void {
        for (self.values) |*value| value.deinit(allocator);
        allocator.free(self.values);
        self.* = undefined;
    }
};

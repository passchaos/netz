//! Actual per-resource acceptance and withdrawals for one typed cache transaction.
const std = @import("std");
const Controller = @import("controller.zig").Controller;
const delta = @import("../ads/delta.zig");
const Plan = @import("plan.zig").Plan;

pub const Changes = struct {
    allocator: std.mem.Allocator,
    accepted: std.ArrayList([]const u8) = .empty,
    withdrawn: std.ArrayList([]const u8) = .empty,
    pub fn deinit(self: *Changes) void {
        self.accepted.deinit(self.allocator);
        self.withdrawn.deinit(self.allocator);
    }
    pub fn accept(self: *Changes, name: []const u8) std.mem.Allocator.Error!void {
        for (self.accepted.items) |previous| if (std.mem.eql(u8, previous, name)) return;
        try self.accepted.append(self.allocator, name);
    }
    pub fn withdraw(self: *Changes, name: []const u8) std.mem.Allocator.Error!void {
        for (self.withdrawn.items) |previous| if (std.mem.eql(u8, previous, name)) return;
        try self.withdrawn.append(self.allocator, name);
    }
    pub fn storageBytes(self: *const Changes) @import("errors.zig").PublishError!usize {
        const capacity = std.math.add(usize, self.accepted.capacity, self.withdrawn.capacity) catch return error.XdsLimitExceeded;
        return std.math.mul(usize, capacity, @sizeOf([]const u8)) catch return error.XdsLimitExceeded;
    }
    pub fn prepare(self: *Changes, client: *delta.Client, update: delta.Update, plan: *Plan) @import("errors.zig").PublishError!delta.subscriptions.PreparedVersions {
        const url = update.response.value.type_url;
        const names = if (std.mem.eql(u8, url, @import("../cds.zig").type_url))
            try plan.cdsNames()
        else if (std.mem.eql(u8, url, @import("../eds.zig").type_url))
            try plan.edsNames()
        else
            try plan.sdsNames();
        defer plan.allocator.free(names);
        return client.prepareAppliedVersions(update, self.accepted.items, self.withdrawn.items, names);
    }
    pub fn commit(self: *const Changes, client: *delta.Client, update: delta.Update, versions: *delta.subscriptions.PreparedVersions) void {
        const now_ns: i128 = @intCast(std.Io.Timestamp.now(client.sender.state.io, .real).toNanoseconds());
        versions.commitAt(update.response.value, self.accepted.items, now_ns);
    }
};

/// Version backing storage remains live beside the target candidate. Reserve
/// its bytes from the publication budget, then restore the caller's limit.
pub const Budget = struct {
    controller: *Controller,
    previous: usize,
    pub fn reserve(controller: *Controller, versions: *const delta.subscriptions.PreparedVersions, changes: *const Changes) @import("errors.zig").PublishError!Budget {
        const bytes = std.math.add(usize, try versions.storageBytes(), try changes.storageBytes()) catch return error.XdsLimitExceeded;
        const previous = controller.options.limits.max_storage_bytes;
        if (bytes > previous) return error.XdsLimitExceeded;
        controller.options.limits.max_storage_bytes = previous - bytes;
        return .{ .controller = controller, .previous = previous };
    }
    pub fn deinit(self: Budget) void {
        self.controller.options.limits.max_storage_bytes = self.previous;
    }
};

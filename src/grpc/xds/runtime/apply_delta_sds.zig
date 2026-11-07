//! Delta SDS resources staged in the supplying authority's secret cache.
const std = @import("std");
const ctl = @import("controller.zig");
const sds = @import("../sds.zig");
const delta = @import("../ads/delta.zig");
const shared = @import("../../channel/shared.zig");
const Plan = @import("plan.zig").Plan;
const SecretPlan = @import("apply_sds.zig").SecretPlan;
const version_patch = @import("delta_versions.zig");

pub fn apply(self: *ctl.Controller, client: *delta.Client, update: delta.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) ctl.Error!u64 {
    if (self.latest == null) return error.XdsNotStarted;
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    const io = client.sender.state.io;
    const response = update.response.value;
    var secrets = try SecretPlan.init(self);
    defer secrets.deinit();
    var storage: usize = 0;
    var invalid: std.ArrayList([]const u8) = .empty;
    defer invalid.deinit(self.allocator);
    var first_error: ?sds.Error = null;
    var versions_changed = version_patch.Changes{ .allocator = self.allocator };
    defer versions_changed.deinit();
    for (response.resources) |raw| {
        const any = raw.resource orelse continue;
        var value = sds.decode(self.allocator, any.value, self.options.limits.sds) catch |err| {
            if (err == error.OutOfMemory) return err;
            if (!self.options.fail_on_data_errors) return err;
            if (raw.name.len == 0) return err;
            if (!self.inResponseScope(raw.name)) continue;
            try invalid.append(self.allocator, raw.name);
            try versions_changed.withdraw(raw.name);
            if (first_error == null) first_error = err;
            continue;
        };
        if (!std.mem.eql(u8, value.value.name, raw.name)) {
            value.deinit();
            return error.InvalidDiscoveryMessage;
        }
        if (!self.inResponseScope(raw.name)) {
            value.deinit();
            continue;
        }
        const ttl = delta.codec.ttlDeadline(io, raw.ttl) catch |err| {
            value.deinit();
            return err;
        };
        const pointer = self.allocator.create(ctl.CachedSecret) catch |err| {
            value.deinit();
            return err;
        };
        pointer.* = .{ .owned = value, .deadline = ttl };
        try secrets.put(pointer);
        try versions_changed.accept(raw.name);
        storage = std.math.add(usize, storage, value.arena.queryCapacity()) catch return error.XdsLimitExceeded;
        if (storage > self.options.limits.max_storage_bytes) return error.XdsLimitExceeded;
    }
    std.mem.sort(*ctl.CachedSecret, secrets.decoded.items, {}, struct {
        fn less(_: void, a: *ctl.CachedSecret, b: *ctl.CachedSecret) bool {
            return std.mem.order(u8, a.owned.value.name, b.owned.value.name) == .lt;
        }
    }.less);
    if (secrets.decoded.items.len > 1) for (secrets.decoded.items[1..], 0..) |value, i| {
        if (std.mem.eql(u8, value.owned.value.name, secrets.decoded.items[i].owned.value.name)) return error.DuplicateSdsResource;
    };
    // Timer changes are staged too: a later invalid heartbeat or failed
    // endpoint publication cannot refresh part of the accepted cache.
    for (response.resources) |raw| {
        if (raw.resource != null or !self.inResponseScope(raw.name)) continue;
        const cached = secrets.secrets.get(raw.name) orelse continue;
        try secrets.refresh(cached, try delta.codec.ttlDeadline(io, raw.ttl));
        try versions_changed.accept(raw.name);
    }
    for (response.removed) |name| {
        if (self.inResponseScope(name)) {
            secrets.remove(name);
            try versions_changed.withdraw(name);
        }
    }
    for (invalid.items) |name| secrets.remove(name);
    var plan = try Plan.create(self, null);
    defer plan.deinit();
    const changed = try secrets.stageClusters(&plan, io);
    var versions = try versions_changed.prepare(client, update, &plan);
    defer versions.deinit();
    const budget = try version_patch.Budget.reserve(self, &versions, &versions_changed);
    defer budget.deinit();
    const revision = if (changed)
        try self.publishDelta(client, &plan, self.latest.?, false, destination, deadline)
    else
        try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    secrets.commit();
    versions_changed.commit(client, update, &versions);
    if (first_error) |err| return err;
    return revision;
}

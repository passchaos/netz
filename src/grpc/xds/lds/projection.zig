//! Immutable HCM timeout, RBAC and fault-injection projection.
const std = @import("std");
const rds = @import("../rds.zig");
const rbac = @import("rbac.zig");
const fault = @import("../../fault.zig");
const routing = @import("../routing/mod.zig");
const selector = @import("../../channel/call_selector.zig");
const service = @import("../../service_config.zig");

const RbacOverride = union(enum) {
    inherit,
    disabled,
    policy: *rbac.Policy,
};
const FaultOverride = union(enum) {
    inherit,
    disabled,
    policy: *fault.Policy,
};
const Compiled = struct {
    rbac: RbacOverride = .inherit,
    fault: FaultOverride = .inherit,
};

pub const Projection = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    source: *rds.Snapshot,
    /// A dynamic listener still awaits an accepted RDS image.
    pending: bool = false,
    /// Borrowed from the retained source snapshot for managed watch retention.
    remote_rds: ?[]const u8 = null,
    maximum: ?std.Io.Duration,
    arena: std.heap.ArenaAllocator,
    rbac: ?*rbac.Policy = null,
    fault: ?fault.Policy = null,
    vhost_overrides: []Compiled = &.{},
    route_overrides: [][]Compiled = &.{},
    pub fn create(
        gpa: std.mem.Allocator,
        source: *rds.Snapshot,
        maximum: ?std.Io.Duration,
        rbac_config: ?[]const u8,
        fault_config: ?[]const u8,
        rbac_name: ?[]const u8,
        fault_name: ?[]const u8,
    ) (std.mem.Allocator.Error || rbac.Error || fault.Error)!*Projection {
        const self = try gpa.create(Projection);
        errdefer gpa.destroy(self);
        source.retain();
        errdefer source.release();
        self.* = .{
            .allocator = gpa,
            .source = source,
            .maximum = maximum,
            .arena = .init(gpa),
        };
        errdefer self.arena.deinit();
        if (rbac_config) |bytes| {
            const policy = try self.arena.allocator().create(rbac.Policy);
            policy.* = try rbac.decode(self.arena.allocator(), bytes, .{});
            self.rbac = policy;
        }
        if (fault_config) |bytes| {
            self.fault = try fault.decode(self.arena.allocator(), bytes, .{});
        }
        try self.compileOverrides(rbac_name orelse "", fault_name orelse "");
        return self;
    }
    fn compileOverrides(self: *Projection, rbac_name: []const u8, fault_name: []const u8) !void {
        const hosts = self.source.resource.value.virtual_hosts;
        if (hosts.len == 0) return;
        const arena = self.arena.allocator();
        self.vhost_overrides = try arena.alloc(Compiled, hosts.len);
        self.route_overrides = try arena.alloc([]Compiled, hosts.len);
        for (hosts, 0..) |host, host_index| {
            var compiled = Compiled{};
            for (host.overrides) |entry| {
                try self.applyOverride(&compiled, entry, rbac_name, fault_name);
            }
            self.vhost_overrides[host_index] = compiled;
            const routes = try arena.alloc(Compiled, host.routes.len);
            for (host.routes, 0..) |route, route_index| {
                var route_compiled = Compiled{};
                for (route.overrides) |entry| {
                    try self.applyOverride(&route_compiled, entry, rbac_name, fault_name);
                }
                routes[route_index] = route_compiled;
            }
            self.route_overrides[host_index] = routes;
        }
    }
    fn applyOverride(self: *Projection, compiled: *Compiled, entry: rds.resource.Override, rbac_name: []const u8, fault_name: []const u8) !void {
        if (entry.name.len == 0) return;
        if (rbac_name.len != 0 and std.mem.eql(u8, entry.name, rbac_name)) {
            if (entry.disabled) {
                compiled.rbac = .disabled;
            } else if (entry.kind != null and entry.kind.? == .rbac) {
                if (entry.config.len == 0) {
                    compiled.rbac = .disabled;
                } else {
                    const policy = try self.arena.allocator().create(rbac.Policy);
                    policy.* = try rbac.decode(self.arena.allocator(), entry.config, .{});
                    compiled.rbac = .{ .policy = policy };
                }
            }
        }
        if (fault_name.len != 0 and std.mem.eql(u8, entry.name, fault_name)) {
            if (entry.disabled) {
                compiled.fault = .disabled;
            } else if (entry.kind != null and entry.kind.? == .fault) {
                if (entry.config.len == 0) {
                    compiled.fault = .disabled;
                } else {
                    const policy = try self.arena.allocator().create(fault.Policy);
                    policy.* = try fault.decode(self.arena.allocator(), entry.config, .{});
                    compiled.fault = .{ .policy = policy };
                }
            }
        }
    }
    fn rbacFor(self: *Projection, selection: rds.Selection) ?*rbac.Policy {
        if (selection.virtual_host < self.route_overrides.len and
            selection.route < self.route_overrides[selection.virtual_host].len)
        {
            switch (self.route_overrides[selection.virtual_host][selection.route].rbac) {
                .inherit => {},
                .disabled => return null,
                .policy => |policy| return policy,
            }
        }
        if (selection.virtual_host < self.vhost_overrides.len) {
            switch (self.vhost_overrides[selection.virtual_host].rbac) {
                .inherit => {},
                .disabled => return null,
                .policy => |policy| return policy,
            }
        }
        return self.rbac;
    }
    fn faultFor(self: *Projection, selection: rds.Selection) ?*fault.Policy {
        if (selection.virtual_host < self.route_overrides.len and
            selection.route < self.route_overrides[selection.virtual_host].len)
        {
            switch (self.route_overrides[selection.virtual_host][selection.route].fault) {
                .inherit => {},
                .disabled => return null,
                .policy => |policy| return policy,
            }
        }
        if (selection.virtual_host < self.vhost_overrides.len) {
            switch (self.vhost_overrides[selection.virtual_host].fault) {
                .inherit => {},
                .disabled => return null,
                .policy => |policy| return policy,
            }
        }
        return self.faultPolicy();
    }
    fn faultPolicy(self: *Projection) ?*fault.Policy {
        return if (self.fault) |*policy| policy else null;
    }
    pub fn retain(self: *Projection) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Projection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.source.release();
        self.arena.deinit();
        self.allocator.destroy(self);
    }
    fn view(self: *Projection) rds.Snapshot {
        // Copy only immutable data, never the concurrently modified atomic
        // reference counter. This borrowed view is used only for resolution.
        var snapshot = rds.Snapshot{ .allocator = self.source.allocator, .resource = self.source.resource, .authority = self.source.authority, .virtual_host = self.source.virtual_host, .required_clusters = self.source.required_clusters, .options = self.source.options };
        snapshot.options.default_max_stream_duration = self.maximum;
        return snapshot;
    }
    fn requestFor(self: *Projection, options: anytype) routing.header.Request {
        return .{
            .path = options.path,
            .authority = options.authority orelse self.source.authority,
            .scheme = options.scheme,
            .metadata = options.metadata,
            .max_header_bytes = self.source.options.max_header_bytes,
        };
    }
    fn authorize(self: *Projection, active: selector.Context, request: routing.header.Request, selection: rds.Selection) selector.Error!void {
        const policy = self.rbacFor(selection) orelse return;
        const allowed = rbac.evaluate(policy, active.allocator, request) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.PermissionDenied,
        };
        if (!allowed) return error.PermissionDenied;
    }
    fn select(self: *Projection, active: selector.Context, options: anytype) selector.Error!rds.Selection {
        var seed: u64 = undefined;
        active.io.random(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        return self.view().selectWith(active.allocator, self.requestFor(options), active.channel_id, prng.random());
    }
    fn retainContext(context: *anyopaque) void {
        const self: *Projection = @ptrCast(@alignCast(context));
        self.retain();
    }
    fn releaseContext(context: *anyopaque) void {
        const self: *Projection = @ptrCast(@alignCast(context));
        self.release();
    }
    fn unary(context: *anyopaque, active: selector.Context, base: service.ResolvedUnary) selector.Error!service.ResolvedUnary {
        const self: *Projection = @ptrCast(@alignCast(context));
        const selection = try self.select(active, base.options);
        try self.authorize(active, self.requestFor(base.options), selection);
        var resolved = try rds.Snapshot.applyUnary(active, base, selection);
        resolved.options.fault_policy = self.faultFor(selection);
        return resolved;
    }
    fn streaming(context: *anyopaque, active: selector.Context, base: service.ResolvedStreaming) selector.Error!service.ResolvedStreaming {
        const self: *Projection = @ptrCast(@alignCast(context));
        const selection = try self.select(active, base.options);
        try self.authorize(active, self.requestFor(base.options), selection);
        var resolved = try rds.Snapshot.applyStreaming(base, selection);
        resolved.options.fault_policy = self.faultFor(selection);
        return resolved;
    }
    pub fn descriptor(self: *Projection) selector.Selector {
        return .{ .context = self, .retain_fn = retainContext, .release_fn = releaseContext, .unary_fn = unary, .streaming_fn = streaming, .required_clusters = self.source.required_clusters };
    }
    pub fn publishWithDeadline(self: *Projection, destination: @import("../../channel/shared.zig").SharedChannel, deadline: std.Io.Clock.Timestamp) @import("../../channel/shared.zig").Error!u64 {
        return destination.updateWithDeadline(.{ .call_selector = .{ .replace = self.descriptor() } }, deadline);
    }
};

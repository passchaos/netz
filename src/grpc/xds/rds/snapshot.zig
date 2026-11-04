//! Reference-owned route selector, held by immutable channel config generations.
const std = @import("std");
const model = @import("model.zig");
const routing = @import("../routing/mod.zig");
const selector = @import("../../channel/call_selector.zig");
const service = @import("../../service_config.zig");
const wire = @import("../../wire.zig");
pub const Error = model.Error || selector.Error || error{InvalidRdsOptions};
pub const Options = struct { authority: []const u8, max_header_bytes: usize = 65536, default_max_stream_duration: ?std.Io.Duration = null };
pub const Selection = struct {
    cluster: []const u8,
    hash: u64,
    duration: ?std.Io.Duration,
    retry: ?@import("../../call.zig").RetryPolicy,
    path_rewrite: ?@import("../../call.zig").PathRewrite = null,
    authority: ?[]const u8 = null,
};
fn firstHeader(request: routing.header.Request, name: []const u8) ?[]const u8 {
    if (std.ascii.eqlIgnoreCase(name, ":authority")) return request.authority;
    if (std.ascii.eqlIgnoreCase(name, ":path")) return request.path;
    if (std.ascii.eqlIgnoreCase(name, ":method")) return "POST";
    if (std.ascii.eqlIgnoreCase(name, ":scheme")) return request.scheme;
    if (std.mem.endsWith(u8, name, "-bin")) return null;
    for (request.metadata) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, name)) return field.value;
    }
    return null;
}
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    resource: model.Owned,
    authority: []const u8,
    virtual_host: ?usize,
    required_clusters: []const []const u8,
    options: Options,
    pub fn create(gpa: std.mem.Allocator, bytes: []const u8, bounds: model.Limits, options: Options) Error!*Snapshot {
        if (options.authority.len == 0 or options.max_header_bytes == 0) return error.InvalidRdsOptions;
        if (options.authority.len > bounds.max_text_bytes or !std.unicode.utf8ValidateSlice(options.authority)) return error.InvalidRdsOptions;
        if (options.default_max_stream_duration) |duration| if (duration.nanoseconds < 0) return error.InvalidRdsOptions;
        var owned = try @import("decode.zig").decode(gpa, bytes, bounds);
        errdefer owned.deinit();
        return takeResource(gpa, &owned, bounds, options);
    }
    /// Consume a previously decoded resource only on successful construction.
    /// LDS inline route configs avoid compiling the same RDS image twice.
    pub fn takeResource(gpa: std.mem.Allocator, owned: *model.Owned, bounds: model.Limits, options: Options) Error!*Snapshot {
        if (options.authority.len == 0 or options.max_header_bytes == 0) return error.InvalidRdsOptions;
        if (options.authority.len > bounds.max_text_bytes or !std.unicode.utf8ValidateSlice(options.authority)) return error.InvalidRdsOptions;
        if (options.default_max_stream_duration) |duration| if (duration.nanoseconds < 0) return error.InvalidRdsOptions;
        const arena = owned.arena.allocator();
        const authority = try arena.dupe(u8, options.authority);
        const host = routing.domain.select(owned.value.virtual_hosts, authority);
        var clusters: std.ArrayList([]const u8) = .empty;
        if (host) |index| for (owned.value.virtual_hosts[index].routes) |route| {
            if (route.action != .forward) continue;
            for (route.action.forward.clusters) |cluster| try clusters.append(arena, cluster.key);
        };
        std.mem.sort([]const u8, clusters.items, {}, struct {
            fn less(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.less);
        var count: usize = 0;
        for (clusters.items) |key| {
            if (count != 0 and std.mem.eql(u8, clusters.items[count - 1], key)) continue;
            if (count >= bounds.max_referenced_clusters) return error.RdsLimitExceeded;
            clusters.items[count] = key;
            count += 1;
        }
        const keys = clusters.items[0..count];
        if (owned.arena.queryCapacity() > bounds.max_storage_bytes) return error.RdsLimitExceeded;
        const self = try gpa.create(Snapshot);
        self.* = .{ .allocator = gpa, .resource = owned.*, .authority = authority, .virtual_host = host, .required_clusters = keys, .options = options };
        self.options.authority = authority;
        owned.* = undefined;
        return self;
    }
    pub fn retain(self: *Snapshot) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Snapshot) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.resource.deinit();
        self.allocator.destroy(self);
    }
    pub fn selectWith(self: *const Snapshot, gpa: std.mem.Allocator, request: routing.header.Request, channel_id: u64, random: std.Random) selector.Error!Selection {
        if (request.budget) |budget| try budget.check();
        if (request.path.len > request.max_header_bytes or request.authority.len > request.max_header_bytes) return error.RouteMetadataLimitExceeded;
        const host = self.virtual_host orelse return error.NoMatchingRoute;
        for (self.resource.value.virtual_hosts[host].routes) |route| {
            if (!try route.path.matchesWithBudget(gpa, request.path, request.budget)) continue;
            var match = true;
            for (route.headers) |header| if (!try header.matches(gpa, request)) {
                match = false;
                break;
            };
            if (!match) continue;
            if (route.fraction_per_million) |fraction| if (random.uintLessThan(u32, 1000000) >= fraction) continue;
            if (route.action != .forward) return error.InvalidRouteAction;
            const forward = route.action.forward;
            var path_rewrite: ?@import("../../call.zig").PathRewrite = null;
            if (forward.path_rewrite) |rewrite| {
                path_rewrite = switch (rewrite) {
                    .prefix => |replacement| switch (route.path) {
                        .prefix => |literal| .{ .prefix = .{
                            .matched = literal.text.len,
                            .replacement = replacement,
                        } },
                        else => .{ .whole = replacement },
                    },
                    .whole => |value| .{ .whole = value },
                };
                if (path_rewrite.?.outputLen(request.path.len) > request.max_header_bytes) {
                    return error.RouteMetadataLimitExceeded;
                }
            }
            var authority: ?[]const u8 = null;
            if (forward.host_rewrite) |rewrite| switch (rewrite) {
                .literal => |value| authority = value,
                .header => |name| authority = firstHeader(request, name),
            };
            if (authority) |value| {
                if (value.len > request.max_header_bytes) {
                    return error.RouteMetadataLimitExceeded;
                }
            }
            var key = random.uintLessThan(u32, forward.total_weight);
            const cluster = for (forward.clusters) |candidate| {
                if (key < candidate.weight) break candidate.key;
                key -= candidate.weight;
            } else unreachable;
            var hash: ?u64 = null;
            for (forward.hash_policies) |policy| {
                const next: ?u64 = switch (policy.kind) {
                    .channel_id => channel_id,
                    .header => |name| blk: {
                        var header = try request.header(gpa, name);
                        defer header.deinit();
                        break :blk if (header.value) |value| std.hash.XxHash64.hash(0, value) else null;
                    },
                };
                if (next) |value| hash = (if (hash) |previous| std.math.rotl(u64, previous, 1) else @as(u64, 0)) ^ value;
                if (policy.terminal and hash != null) break;
            }
            return .{
                .cluster = cluster,
                .hash = hash orelse random.int(u64),
                .duration = forward.max_stream_duration orelse self.options.default_max_stream_duration,
                .retry = forward.retry_policy,
                .path_rewrite = path_rewrite,
                .authority = authority,
            };
        }
        return error.NoMatchingRoute;
    }
    fn selectRandom(self: *const Snapshot, context: selector.Context, options: anytype) selector.Error!Selection {
        var seed: u64 = undefined;
        context.io.random(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        return self.selectWith(context.allocator, .{ .path = options.path, .authority = options.authority orelse self.authority, .scheme = options.scheme, .metadata = options.metadata, .max_header_bytes = self.options.max_header_bytes, .budget = .{ .io = context.io, .deadline = context.deadline } }, context.channel_id, prng.random());
    }
    fn apply(options: anytype, selection: Selection) selector.Error!@TypeOf(options) {
        var selected = options;
        selected.xds_cluster = selection.cluster;
        selected.request_hash = selection.hash;
        selected.xds_path_rewrite = selection.path_rewrite;
        if (selection.authority) |authority| selected.authority = authority;
        if (selection.duration) |limit| if (limit.nanoseconds > 0) {
            const duration: std.Io.Duration = if (options.timeout) |timeout| .fromNanoseconds(@min(timeout.duration().nanoseconds, limit.nanoseconds)) else limit;
            selected.timeout = try wire.Timeout.fromDuration(duration);
        };
        return selected;
    }
    pub fn resolveUnary(self: *Snapshot, context: selector.Context, base: service.ResolvedUnary) selector.Error!service.ResolvedUnary {
        const selection = try self.selectRandom(context, base.options);
        var resolved = base;
        resolved.options = try apply(base.options, selection);
        resolved.retry_policy = selection.retry;
        if (resolved.retry_policy) |*retry| if (context.service_config) |config| {
            retry.throttler = config.retry_throttler;
        };
        resolved.hedging_policy = null;
        return resolved;
    }
    pub fn resolveStreaming(self: *Snapshot, context: selector.Context, base: service.ResolvedStreaming) selector.Error!service.ResolvedStreaming {
        const selection = try self.selectRandom(context, base.options);
        var resolved = base;
        resolved.options = try apply(base.options, selection);
        resolved.hedging_policy = null;
        return resolved;
    }
    fn retainContext(context: *anyopaque) void {
        const self: *Snapshot = @ptrCast(@alignCast(context));
        self.retain();
    }
    fn releaseContext(context: *anyopaque) void {
        const self: *Snapshot = @ptrCast(@alignCast(context));
        self.release();
    }
    fn unaryContext(pointer: *anyopaque, context: selector.Context, base: service.ResolvedUnary) selector.Error!service.ResolvedUnary {
        const self: *Snapshot = @ptrCast(@alignCast(pointer));
        return self.resolveUnary(context, base);
    }
    fn streamContext(pointer: *anyopaque, context: selector.Context, base: service.ResolvedStreaming) selector.Error!service.ResolvedStreaming {
        const self: *Snapshot = @ptrCast(@alignCast(pointer));
        return self.resolveStreaming(context, base);
    }
    pub fn descriptor(self: *Snapshot) selector.Selector {
        return .{ .context = self, .retain_fn = retainContext, .release_fn = releaseContext, .unary_fn = unaryContext, .streaming_fn = streamContext, .required_clusters = self.required_clusters };
    }
    pub fn publishWithDeadline(self: *Snapshot, destination: @import("../../channel/shared.zig").SharedChannel, deadline: std.Io.Clock.Timestamp) (Error || @import("../../channel/shared.zig").Error)!u64 {
        return destination.updateWithDeadline(.{ .call_selector = .{ .replace = self.descriptor() } }, deadline);
    }
};

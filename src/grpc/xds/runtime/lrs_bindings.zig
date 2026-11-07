//! Stage independent source-pinned LRS owners before publishing discovery.
const std = @import("std");
const Source = @import("../discovery_source.zig").Source;
const Plane = @import("../control_plane.zig").ControlPlane;
const lrs = @import("../lrs.zig");
const shared = @import("../../channel/shared.zig");
const Selection = @import("../../channel/shared/lrs_stats.zig").Selection;
const Options = @import("options.zig").AutomaticLrsOptions;
pub const Error = @import("../control_plane.zig").Error || lrs.RunnerError || error{XdsLimitExceeded};

pub const Binding = struct {
    allocator: std.mem.Allocator,
    source: *Source,
    data: shared.SharedChannel,
    plane: *Plane,
    runner: *lrs.Runner,

    fn create(gpa: std.mem.Allocator, io: std.Io, source: *Source, data: shared.SharedChannel, options: Options) Error!*Binding {
        const self = try gpa.create(Binding);
        errdefer gpa.destroy(self);
        const plane = try Plane.init(gpa, io, source.bootstrap, .{ .node = source.node, .pinned_server = source.server });
        errdefer plane.deinit();
        var sender = plane.sender();
        defer sender.deinit();
        var reporter = options.reporter;
        reporter.source_key = source.key;
        const runner = try lrs.Runner.create(gpa, io, sender, plane, data, .{
            .client = .{ .node = source.lrs_node, .request = source.request },
            .reporter = reporter,
            .poll_interval = options.poll_interval,
            .connect_timeout = options.connect_timeout,
            .stop_when_idle = true,
        });
        errdefer runner.deinit();
        try runner.prepareStart();
        data.state.retain();
        self.* = .{ .allocator = gpa, .source = source.retain(), .data = data, .plane = plane, .runner = runner };
        return self;
    }

    fn deinit(self: *Binding) void {
        self.runner.deinit();
        self.plane.deinit();
        self.source.release();
        self.data.state.release();
        self.allocator.destroy(self);
    }
};

pub const Bindings = struct {
    items: std.ArrayList(*Binding) = .empty,

    pub fn deinit(self: *Bindings, gpa: std.mem.Allocator) void {
        for (self.items.items) |binding| binding.deinit();
        self.items.deinit(gpa);
    }

    fn clean(self: *Bindings) void {
        var index: usize = 0;
        while (index < self.items.items.len) {
            if (self.items.items[index].runner.finished.load(.acquire)) self.items.orderedRemove(index).deinit() else index += 1;
        }
    }

    pub fn prepare(self: *Bindings, gpa: std.mem.Allocator, io: std.Io, data: shared.SharedChannel, selection: ?*Selection, options: Options, limit: usize) Error!Prepared {
        self.clean();
        var staged: Prepared = .{ .allocator = gpa, .owner = self };
        errdefer staged.deinit();
        if (selection) |selected| for (selected.identities) |identity| {
            const source = identity.source orelse continue;
            staged.has_sources = true;
            try staged.pinned.ensureUnusedCapacity(gpa, 1);
            const known = for (self.items.items) |binding| {
                if (std.mem.eql(u8, binding.source.key, source.key) and binding.runner.pinPublication()) {
                    staged.pinned.appendAssumeCapacity(binding.runner);
                    break true;
                }
            } else for (staged.items.items) |binding| {
                if (std.mem.eql(u8, binding.source.key, source.key)) break true;
            } else false;
            if (known) continue;
            self.clean();
            if (self.items.items.len + staged.items.items.len >= limit) return error.XdsLimitExceeded;
            try staged.items.ensureUnusedCapacity(gpa, 1);
            staged.items.appendAssumeCapacity(try Binding.create(gpa, io, source, data, options));
        };
        try self.items.ensureUnusedCapacity(gpa, staged.items.items.len);
        return staged;
    }
};

pub const Prepared = struct {
    allocator: std.mem.Allocator,
    owner: *Bindings,
    items: std.ArrayList(*Binding) = .empty,
    pinned: std.ArrayList(*lrs.Runner) = .empty,
    has_sources: bool = false,

    pub fn deinit(self: *Prepared) void {
        for (self.pinned.items) |runner| runner.unpinPublication();
        self.pinned.deinit(self.allocator);
        for (self.items.items) |binding| binding.deinit();
        self.items.deinit(self.allocator);
    }

    pub fn storageBytes(self: *const Prepared) usize {
        var bytes: usize = 0;
        for (self.owner.items.items) |binding| bytes +|= binding.source.arena.queryCapacity();
        for (self.items.items) |binding| bytes +|= binding.source.arena.queryCapacity();
        return bytes;
    }

    /// Task admission already succeeded. Activation follows the target commit.
    pub fn commit(self: *Prepared) void {
        for (self.items.items) |binding| {
            self.owner.items.appendAssumeCapacity(binding);
            binding.runner.activate();
        }
        self.items.clearRetainingCapacity();
        for (self.pinned.items) |runner| runner.unpinPublication();
        self.pinned.clearRetainingCapacity();
    }
};

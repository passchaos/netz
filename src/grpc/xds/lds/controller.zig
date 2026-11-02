//! Serialized client listener/RDS state; publication commits before ACK output.
const std = @import("std");
const model = @import("model.zig");
const ads = @import("../ads.zig");
const rds = @import("../rds.zig");
const shared = @import("../../channel/shared.zig");
pub const Error = model.Error || ads.Error || rds.Error || shared.Error || error{ InvalidLdsOptions, WrongLdsResource, DuplicateLdsResource };
pub const Options = struct { listener_name: []const u8, authority: []const u8, max_header_bytes: usize = 65536, limits: model.Limits = .{} };
pub const Controller = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    options: Options,
    listener: ?model.Owned = null,
    routes: ?*rds.Snapshot = null,
    pub fn init(gpa: std.mem.Allocator, options: Options) Error!Controller {
        if (options.listener_name.len == 0 or options.listener_name.len > options.limits.max_text_bytes or !std.unicode.utf8ValidateSlice(options.listener_name) or options.authority.len == 0 or options.authority.len > options.limits.rds.max_text_bytes or !std.unicode.utf8ValidateSlice(options.authority) or options.max_header_bytes == 0) return error.InvalidLdsOptions;
        var self = Controller{ .allocator = gpa, .arena = .init(gpa), .options = options };
        errdefer self.deinit();
        self.options.listener_name = try self.arena.allocator().dupe(u8, options.listener_name);
        self.options.authority = try self.arena.allocator().dupe(u8, options.authority);
        return self;
    }
    pub fn deinit(self: *Controller) void {
        if (self.listener) |*value| value.deinit();
        if (self.routes) |snapshot| snapshot.release();
        self.arena.deinit();
        self.* = undefined;
    }
    pub fn subscribe(self: *Controller, client: *ads.Client) Error!void {
        try client.setSubscription(model.type_url, &.{self.options.listener_name});
    }
    pub fn routeOptions(self: *const Controller) rds.Options {
        return .{ .authority = self.options.authority, .max_header_bytes = self.options.max_header_bytes };
    }
    pub fn empty(self: *Controller, name: []const u8) Error!*rds.Snapshot {
        var writer: std.Io.Writer.Allocating = .init(self.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var length = name.len;
        while (length >= 128) : (length >>= 7) writer.writer.writeByte(@as(u8, @truncate(length)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(length)) catch return error.OutOfMemory;
        writer.writer.writeAll(name) catch return error.OutOfMemory;
        return rds.Snapshot.create(self.allocator, writer.written(), self.options.limits.rds, self.routeOptions());
    }
    pub fn takeInline(self: *Controller, candidate: *model.Owned) Error!*rds.Snapshot {
        var resource = candidate.inline_rds orelse return error.InvalidLdsResource;
        candidate.inline_rds = null;
        return rds.Snapshot.takeResource(self.allocator, &resource, self.options.limits.rds, self.routeOptions()) catch |err| {
            resource.deinit();
            return err;
        };
    }
    pub fn applyWithDeadline(self: *Controller, client: *ads.Client, update: ads.Update, destination: shared.SharedChannel, deadline: std.Io.Clock.Timestamp) Error!u64 {
        _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
        try client.validateUpdate(update);
        const url = update.response.value.type_url;
        const revision = if (std.mem.eql(u8, url, model.type_url))
            try @import("apply_listener.zig").apply(self, client, update, destination, deadline)
        else if (std.mem.eql(u8, url, rds.type_url))
            try @import("apply_routes.zig").apply(self, update, destination, deadline)
        else
            return error.WrongLdsResource;
        try client.acceptAppliedUpdate(update);
        _ = try client.flushWithDeadline(deadline);
        return revision;
    }
};

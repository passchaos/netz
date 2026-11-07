//! Prepare named subscriptions through a managed router or the raw ADS client.
const std = @import("std");
const ads = @import("../ads.zig");
const delta = @import("../ads/delta.zig");
const Error = @import("errors.zig").PublishError;
pub const Watch = ads.subscriptions.Subscription;

pub const Transaction = struct {
    context: *anyopaque,
    commit_fn: *const fn (*anyopaque) void,
    deinit_fn: *const fn (*anyopaque) void,
    pub fn commit(self: *Transaction) void {
        self.commit_fn(self.context);
    }
    pub fn deinit(self: *Transaction) void {
        self.deinit_fn(self.context);
    }
};

pub const Router = struct {
    context: *anyopaque,
    prepare_fn: *const fn (*anyopaque, []const Watch, std.Io.Clock.Timestamp) Error!Transaction,
    pub fn prepare(self: Router, watches: []const Watch, deadline: std.Io.Clock.Timestamp) Error!Transaction {
        return self.prepare_fn(self.context, watches, deadline);
    }
};

pub const Prepared = union(enum) {
    sotw: ads.subscriptions.Prepared,
    delta: delta.subscriptions.Prepared,
    routed: Transaction,
    pub fn commit(self: *Prepared) void {
        switch (self.*) {
            inline else => |*value| value.commit(),
        }
    }
    pub fn deinit(self: *Prepared) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
    }
};

pub fn prepare(client: anytype, router: ?Router, type_url: []const u8, names: []const []const u8, deadline: std.Io.Clock.Timestamp) Error!Prepared {
    if (router) |managed| return .{ .routed = try managed.prepare(&.{.{ .type_url = type_url, .names = names }}, deadline) };
    if (@TypeOf(client) == *ads.Client) return .{ .sotw = try client.subscriptions.prepare(type_url, names) };
    return .{ .delta = try client.subscriptions.prepare(type_url, names) };
}

//! Authority-scoped clients and transactional global dependency watch sets.
const std = @import("std");
const bootstrap = @import("../../bootstrap.zig");
const plane = @import("../../control_plane.zig");
const resource = @import("../../resource_name.zig");
const ads = @import("../../ads.zig");
const delta = @import("../../ads/delta.zig");
const discovery = @import("../discovery.zig");
const owned = @import("names.zig");
const session_mod = @import("session.zig");
const Error = @import("../errors.zig").PublishError;
pub const Mode = session_mod.Mode;
pub const Options = struct { control_plane: plane.Options = .{}, max_sessions: usize = 257 };

pub fn Registry(comptime mode: Mode) type {
    return struct {
        const Self = @This();
        pub const Session = session_mod.Session(mode);
        const Batch = if (mode == .sotw) ads.subscriptions.Batch else delta.subscriptions.Batch;
        const Subscription = if (mode == .sotw) ads.subscriptions.Subscription else delta.subscriptions.Subscription;
        const Applied = struct { session: *Session, batch: Batch };
        const Patch = struct { index: ?usize, value: ?owned.Names };
        allocator: std.mem.Allocator,
        io: std.Io,
        bootstrap: *bootstrap.Bootstrap,
        options: Options,
        sessions: std.ArrayList(*Session) = .empty,
        desired: std.ArrayList(owned.Names) = .empty,
        pending_types: usize = 0,
        preparing: ?*Prepared = null,

        pub fn init(gpa: std.mem.Allocator, io: std.Io, configuration: *bootstrap.Bootstrap, options: Options) Self {
            return .{ .allocator = gpa, .io = io, .bootstrap = configuration.retain(), .options = options };
        }

        pub fn deinit(self: *Self) void {
            for (self.sessions.items) |session| session.release();
            self.sessions.deinit(self.allocator);
            for (self.desired.items) |*names| names.deinit();
            self.desired.deinit(self.allocator);
            self.bootstrap.deinit();
        }

        pub fn forName(self: *Self, name: []const u8) Error!*Session {
            const parsed = try resource.parse(name);
            const authority = if (parsed.authority) |encoded| try resource.decodeAuthority(self.allocator, encoded) else null;
            defer if (authority) |value| self.allocator.free(value);
            return self.forAuthority(authority orelse "");
        }

        pub fn forAuthority(self: *Self, authority: []const u8) Error!*Session {
            for (self.sessions.items) |session| if (std.mem.eql(u8, session.authority, authority)) return session;
            if (authority.len != 0 and self.bootstrap.authority(authority) == null) return error.InvalidControlPlaneOptions;
            if (self.sessions.items.len >= self.options.max_sessions) return error.XdsLimitExceeded;
            try self.sessions.ensureUnusedCapacity(self.allocator, 1);
            const session = try Session.create(self.allocator, self.io, self.bootstrap, authority, self.options.control_plane);
            session.provisional = self.preparing != null;
            self.sessions.appendAssumeCapacity(session);
            return session;
        }

        pub fn active(self: *const Self, session: *const Session) bool {
            for (self.desired.items) |names| for (names.values) |name| {
                if (owned.belongs(name, session.authority)) return true;
            };
            return false;
        }

        pub fn flush(self: *Self, deadline: std.Io.Clock.Timestamp) Error!void {
            for (self.sessions.items) |session| {
                if (session.client.stream != null) _ = try session.client.flushWithDeadline(deadline);
                if (!self.active(session)) {
                    if (session.pending) |value| if (value) |event_value| {
                        var event = event_value;
                        event.deinit();
                    } else |_| {};
                    session.pending = null;
                    session.client.disconnect();
                }
            }
        }

        pub fn router(self: *Self) discovery.Router {
            return .{ .context = self, .prepare_fn = prepareOpaque };
        }

        fn typeIndex(self: *Self, url: []const u8) ?usize {
            for (self.desired.items, 0..) |names, index| if (std.mem.eql(u8, names.type_url, url)) return index;
            return null;
        }

        fn prepareOpaque(context: *anyopaque, watches: []const discovery.Watch, deadline: std.Io.Clock.Timestamp) Error!discovery.Transaction {
            const self: *Self = @ptrCast(@alignCast(context));
            _ = try @import("../../../../internal/deadline.zig").usableAwake(self.io, deadline);
            const prepared = try self.allocator.create(Prepared);
            prepared.* = .{ .owner = self };
            errdefer prepared.destroy();
            const previous_preparation = self.preparing;
            self.preparing = prepared;
            defer self.preparing = previous_preparation;
            try prepared.patches.ensureTotalCapacity(self.allocator, watches.len);
            for (watches, 0..) |watch, index| {
                for (watches[0..index]) |previous| if (std.mem.eql(u8, previous.type_url, watch.type_url)) return error.InvalidDiscoveryMessage;
                for (watch.names) |name| {
                    const parsed = try resource.parse(name);
                    if (parsed.type_url) |url| if (!std.mem.eql(u8, url, resource.shortType(watch.type_url))) return error.InvalidXdsResourceName;
                    _ = try self.forName(name);
                }
                const names = try owned.Names.create(self.allocator, watch.type_url, watch.names);
                const target = self.typeIndex(watch.type_url);
                prepared.patches.appendAssumeCapacity(.{ .index = target, .value = names });
                if (target == null) {
                    self.pending_types += 1;
                    prepared.new_types += 1;
                }
            }
            try self.desired.ensureUnusedCapacity(self.allocator, self.pending_types);
            for (self.sessions.items) |session| try prepared.forSession(session);
            return .{ .context = prepared, .commit_fn = Prepared.commitOpaque, .deinit_fn = Prepared.deinitOpaque };
        }

        const Prepared = struct {
            owner: *Self,
            patches: std.ArrayList(Patch) = .empty,
            batches: std.ArrayList(Applied) = .empty,
            new_types: usize = 0,

            fn forSession(self: *Prepared, session: *Session) Error!void {
                const gpa = self.owner.allocator;
                var requests: std.ArrayList(Subscription) = .empty;
                defer {
                    for (requests.items) |request| gpa.free(request.names);
                    requests.deinit(gpa);
                }
                for (self.patches.items) |patch| {
                    const names = patch.value.?;
                    const part = try names.partition(gpa, session.authority);
                    if (part.len == 0 and (mode == .sotw or session.client.subscriptions.find(names.type_url) == null)) {
                        gpa.free(part);
                        continue;
                    }
                    requests.append(gpa, .{ .type_url = names.type_url, .names = part }) catch |err| {
                        gpa.free(part);
                        return err;
                    };
                }
                if (requests.items.len == 0) return;
                try self.batches.ensureUnusedCapacity(gpa, 1);
                const batch = try session.client.subscriptions.prepareMany(requests.items);
                session.pending_prepares += 1;
                self.batches.appendAssumeCapacity(.{ .session = session, .batch = batch });
            }

            fn commitOpaque(context: *anyopaque) void {
                const self: *Prepared = @ptrCast(@alignCast(context));
                for (self.batches.items) |*applied| {
                    applied.batch.commit();
                    applied.session.provisional = false;
                }
                for (self.patches.items) |*patch| {
                    if (patch.index) |index| {
                        const old = self.owner.desired.items[index];
                        self.owner.desired.items[index] = patch.value.?;
                        patch.value = old;
                    } else {
                        self.owner.desired.appendAssumeCapacity(patch.value.?);
                        patch.value = null;
                    }
                }
                self.owner.pending_types -= self.new_types;
                self.new_types = 0;
            }

            fn deinitOpaque(context: *anyopaque) void {
                const self: *Prepared = @ptrCast(@alignCast(context));
                self.destroy();
            }

            fn destroy(self: *Prepared) void {
                const gpa = self.owner.allocator;
                self.owner.pending_types -= self.new_types;
                for (self.batches.items) |*applied| {
                    applied.batch.deinit();
                    std.debug.assert(applied.session.pending_prepares != 0);
                    applied.session.pending_prepares -= 1;
                }
                self.batches.deinit(gpa);
                for (self.patches.items) |*patch| if (patch.value) |*names| names.deinit();
                self.patches.deinit(gpa);
                self.owner.removeProvisional();
                gpa.destroy(self);
            }
        };

        fn removeProvisional(self: *Self) void {
            var index: usize = 0;
            while (index < self.sessions.items.len) {
                const session = self.sessions.items[index];
                if (session.provisional and session.pending_prepares == 0 and !self.active(session)) {
                    _ = self.sessions.orderedRemove(index);
                    session.release(); // Emitted Event references keep any retained owner alive.
                } else index += 1;
            }
        }
    };
}

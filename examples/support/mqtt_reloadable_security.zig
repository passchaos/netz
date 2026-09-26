//! Atomic password/ACL file reload for the Mosquitto-style broker example.
//!
//! Paths and listener topology remain fixed for the process lifetime. A reload
//! parses every configured file into a detached set before one write-locked
//! swap. Callbacks hold the read lock through password verification or ACL
//! evaluation, so the previous set is destroyed only after all readers leave.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const Paths = struct {
    password_file: []const u8 = &.{},
    acl_file: []const u8 = &.{},
};

const FileSet = struct {
    passwords: []?mqtt.password_file.File,
    acls: []?mqtt.acl_file.File,

    fn load(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: []const Paths,
    ) !FileSet {
        const passwords = try allocator.alloc(
            ?mqtt.password_file.File,
            paths.len,
        );
        errdefer allocator.free(passwords);
        @memset(passwords, null);
        var password_count: usize = 0;
        errdefer {
            for (passwords[0..password_count]) |*maybe_file| {
                if (maybe_file.*) |*file| file.deinit();
            }
        }
        const acls = try allocator.alloc(?mqtt.acl_file.File, paths.len);
        errdefer allocator.free(acls);
        @memset(acls, null);
        var acl_count: usize = 0;
        errdefer {
            for (acls[0..acl_count]) |*maybe_file| {
                if (maybe_file.*) |*file| file.deinit();
            }
        }

        for (paths, 0..) |entry, index| {
            if (entry.password_file.len != 0) {
                passwords[index] = try mqtt.password_file.load(
                    allocator,
                    io,
                    dir,
                    entry.password_file,
                );
            }
            password_count = index + 1;
            if (entry.acl_file.len != 0) {
                acls[index] = try mqtt.acl_file.load(
                    allocator,
                    io,
                    dir,
                    entry.acl_file,
                );
            }
            acl_count = index + 1;
        }
        return .{ .passwords = passwords, .acls = acls };
    }

    fn deinit(self: *FileSet, allocator: std.mem.Allocator) void {
        for (self.passwords) |*maybe_file| {
            if (maybe_file.*) |*file| file.deinit();
        }
        allocator.free(self.passwords);
        for (self.acls) |*maybe_file| {
            if (maybe_file.*) |*file| file.deinit();
        }
        allocator.free(self.acls);
        self.* = undefined;
    }
};

pub const Security = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    paths: []const Paths,
    listener_ids: []const u16,
    per_listener_settings: bool,
    files: FileSet,
    lock: std.Io.RwLock = .init,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        paths: []const Paths,
        listener_ids: []const u16,
        per_listener_settings: bool,
    ) !Security {
        if (paths.len == 0 or listener_ids.len == 0 or
            (per_listener_settings and paths.len != listener_ids.len) or
            (!per_listener_settings and paths.len != 1))
        {
            return error.InvalidSecurityLayout;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .dir = dir,
            .paths = paths,
            .listener_ids = listener_ids,
            .per_listener_settings = per_listener_settings,
            .files = try FileSet.load(allocator, io, dir, paths),
        };
    }

    pub fn deinit(self: *Security) void {
        self.files.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn reload(self: *Security) !void {
        var replacement = try FileSet.load(
            self.allocator,
            self.io,
            self.dir,
            self.paths,
        );
        self.lock.lockUncancelable(self.io);
        var previous = self.files;
        self.files = replacement;
        replacement = undefined;
        self.lock.unlock(self.io);
        previous.deinit(self.allocator);
    }

    pub fn hasReloadableFiles(self: *const Security) bool {
        for (self.paths) |entry| {
            if (entry.password_file.len != 0 or entry.acl_file.len != 0) {
                return true;
            }
        }
        return false;
    }

    pub fn hasPasswordFile(self: *const Security, listener_index: usize) bool {
        return self.paths[self.securityIndex(listener_index)].password_file.len != 0;
    }

    pub fn hasAclFile(self: *const Security, listener_index: usize) bool {
        return self.paths[self.securityIndex(listener_index)].acl_file.len != 0;
    }

    pub fn hasAnyAclFile(self: *const Security) bool {
        for (self.paths) |entry| if (entry.acl_file.len != 0) return true;
        return false;
    }

    pub fn listenerPolicy(
        self: *Security,
        listener_index: usize,
        allow_anonymous: bool,
    ) ListenerPolicy {
        return .{
            .security = self,
            .listener_index = listener_index,
            .allow_anonymous = allow_anonymous,
        };
    }

    pub fn sourceAccessControl(
        self: *Security,
    ) ?mqtt.broker.AccessControlHandler {
        if (!self.hasAnyAclFile()) return null;
        return .{
            .context = self,
            .authorize_publish = allowSourcePublish,
            .authorize_subscribe = allowSourceSubscribe,
            .authorize_will = authorizeSourceWill,
            .authorize_retained_source = authorizeRetainedSource,
        };
    }

    fn securityIndex(self: *const Security, listener_index: usize) usize {
        std.debug.assert(listener_index < self.listener_ids.len);
        return if (self.per_listener_settings) listener_index else 0;
    }

    fn aclAllows(
        self: *Security,
        listener_index: usize,
        operation: mqtt.acl_file.Operation,
        identity: mqtt.acl_file.Identity,
        topic: []const u8,
    ) bool {
        self.lock.lockSharedUncancelable(self.io);
        defer self.lock.unlockShared(self.io);
        const file = self.files.acls[
            self.securityIndex(listener_index)
        ] orelse return true;
        return file.allows(operation, identity, topic);
    }

    fn sourceAclAllows(
        self: *Security,
        listener_id: ?u64,
        identity: mqtt.acl_file.Identity,
        topic: []const u8,
    ) bool {
        self.lock.lockSharedUncancelable(self.io);
        defer self.lock.unlockShared(self.io);
        const index = if (!self.per_listener_settings)
            0
        else blk: {
            const id = listener_id orelse return false;
            var found: ?usize = null;
            for (self.listener_ids, 0..) |candidate, candidate_index| {
                if (candidate != id) continue;
                if (found != null) return false;
                found = candidate_index;
            }
            break :blk found orelse return false;
        };
        const file = self.files.acls[index] orelse return true;
        return file.allows(.write, identity, topic);
    }

    fn allowSourcePublish(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Publish,
    ) bool {
        return true;
    }

    fn allowSourceSubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Subscription,
    ) bool {
        return true;
    }

    fn authorizeSourceWill(
        context: *anyopaque,
        publication: mqtt.broker.WillAuthorization,
    ) bool {
        const self: *Security = @ptrCast(@alignCast(context));
        return self.sourceAclAllows(
            publication.listener_id,
            .{
                .client_id = publication.client_id,
                .username = publication.username,
            },
            publication.topic,
        );
    }

    fn authorizeRetainedSource(
        context: *anyopaque,
        publication: mqtt.broker.RetainedSourceAuthorization,
    ) bool {
        const self: *Security = @ptrCast(@alignCast(context));
        return self.sourceAclAllows(
            publication.listener_id,
            .{
                .client_id = publication.client_id,
                .username = publication.username,
            },
            publication.topic,
        );
    }
};

pub const ListenerPolicy = struct {
    security: *Security,
    listener_index: usize,
    allow_anonymous: bool,

    pub fn authorizeConnect(context: *anyopaque, connect: mqtt.Connect) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        self.security.lock.lockSharedUncancelable(self.security.io);
        defer self.security.lock.unlockShared(self.security.io);
        const maybe_file = &self.security.files.passwords[
            self.security.securityIndex(self.listener_index)
        ];
        const file = if (maybe_file.*) |*value|
            value
        else
            return self.allow_anonymous;
        const username = connect.username orelse return self.allow_anonymous;
        const password = connect.password orelse return false;
        return file.verify(username, password);
    }

    pub fn accessControl(
        self: *ListenerPolicy,
    ) ?mqtt.broker.ListenerAccessControlHandler {
        if (!self.security.hasAclFile(self.listener_index)) return null;
        return .{
            .context = self,
            .authorize_publish = authorizePublish,
            .authorize_subscribe = authorizeSubscribe,
            .authorize_unsubscribe = authorizeUnsubscribe,
            .authorize_delivery = authorizeDelivery,
            .authorize_will = authorizeWill,
        };
    }

    fn authorizePublish(
        context: *anyopaque,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        return self.security.aclAllows(
            self.listener_index,
            .write,
            identityForConnect(connect),
            publish.topic,
        );
    }

    fn authorizeSubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Subscription,
    ) bool {
        return true;
    }

    fn authorizeUnsubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: []const u8,
    ) bool {
        return true;
    }

    fn authorizeDelivery(
        context: *anyopaque,
        delivery: mqtt.broker.DeliveryAuthorization,
    ) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        return self.security.aclAllows(
            self.listener_index,
            .read,
            .{
                .client_id = delivery.client_id,
                .username = delivery.username,
            },
            delivery.topic,
        );
    }

    fn authorizeWill(
        context: *anyopaque,
        connect: mqtt.Connect,
        will: mqtt.LastWill,
    ) bool {
        const self: *ListenerPolicy = @ptrCast(@alignCast(context));
        return self.security.aclAllows(
            self.listener_index,
            .write,
            identityForConnect(connect),
            will.topic,
        );
    }
};

fn identityForConnect(connect: mqtt.Connect) mqtt.acl_file.Identity {
    return .{ .client_id = connect.client_id, .username = connect.username };
}

const password_hash = "$7$1000$MDEyMzQ1Njc4OWFi$" ++
    "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+" ++
    "KMfRf9YJT//3a9+kZTXUdA==";

test "reloadable MQTT security swaps atomically and rolls back failure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "old:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "acl",
        .data = "user old\ntopic write before/#\n",
    });
    const paths = [_]Paths{.{
        .password_file = "passwords",
        .acl_file = "acl",
    }};
    const listener_ids = [_]u16{1883};
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        false,
    );
    defer security.deinit();
    var policy = security.listenerPolicy(0, false);
    var connect = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = "client",
        .username = "old",
        .password = "password",
    };
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    try std.testing.expect(ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "before/value",
            .packet_id = null,
            .payload = "value",
        },
    ));
    const source_access = security.sourceAccessControl().?;
    try std.testing.expect(source_access.authorize_retained_source.?(
        source_access.context,
        .{
            .client_id = "client",
            .username = "old",
            .listener_id = null,
            .topic = "before/value",
            .payload = "value",
            .qos = .at_most_once,
            .retain = true,
            .properties = &.{},
        },
    ));
    try std.testing.expect(!source_access.authorize_retained_source.?(
        source_access.context,
        .{
            .client_id = "client",
            .username = "old",
            .listener_id = 1883,
            .topic = "after/value",
            .payload = "value",
            .qos = .at_most_once,
            .retain = true,
            .properties = &.{},
        },
    ));

    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "new:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "acl",
        .data = "user old\ntopic write after/#\n" ++
            "user new\ntopic write after/#\n",
    });
    try security.reload();
    try std.testing.expect(!ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "new";
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "old";
    try std.testing.expect(!ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "before/value",
            .packet_id = null,
            .payload = "value",
        },
    ));
    try std.testing.expect(ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "after/value",
            .packet_id = null,
            .payload = "value",
        },
    ));

    try tmp.dir.writeFile(io, .{
        .sub_path = "passwords",
        .data = "third:" ++ password_hash ++ "\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "acl",
        .data = "unsupported entry\n",
    });
    try std.testing.expectError(error.InvalidDirective, security.reload());
    connect.username = "new";
    try std.testing.expect(ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "third";
    try std.testing.expect(!ListenerPolicy.authorizeConnect(&policy, connect));
    connect.username = "old";
    try std.testing.expect(ListenerPolicy.authorizePublish(
        &policy,
        connect,
        .{
            .dup = false,
            .qos = .at_most_once,
            .retain = false,
            .topic = "after/value",
            .packet_id = null,
            .payload = "value",
        },
    ));
    try std.testing.expect(source_access.authorize_retained_source.?(
        source_access.context,
        .{
            .client_id = "client",
            .username = "old",
            .listener_id = 1883,
            .topic = "after/value",
            .payload = "value",
            .qos = .at_most_once,
            .retain = true,
            .properties = &.{},
        },
    ));
}

test "reloadable MQTT security selects unique retained source listener" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "first.acl",
        .data = "user writer\ntopic write first/#\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "second.acl",
        .data = "user writer\ntopic write second/#\n",
    });
    const paths = [_]Paths{
        .{ .acl_file = "first.acl" },
        .{ .acl_file = "second.acl" },
    };
    const listener_ids = [_]u16{ 1883, 1884 };
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        true,
    );
    defer security.deinit();
    const access = security.sourceAccessControl().?;
    try std.testing.expect(authorizeRetained(&access, 1883, "first/value"));
    try std.testing.expect(!authorizeRetained(&access, 1884, "first/value"));
    try std.testing.expect(!authorizeRetained(&access, null, "first/value"));
}

test "reloadable MQTT security rejects ambiguous retained source listener" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{
        .sub_path = "first.acl",
        .data = "user writer\ntopic write allowed/#\n",
    });
    const paths = [_]Paths{
        .{ .acl_file = "first.acl" },
        .{},
    };
    const listener_ids = [_]u16{ 1883, 1883 };
    var security = try Security.init(
        allocator,
        io,
        tmp.dir,
        &paths,
        &listener_ids,
        true,
    );
    defer security.deinit();
    const access = security.sourceAccessControl().?;
    try std.testing.expect(!authorizeRetained(
        &access,
        1883,
        "allowed/value",
    ));
}

fn authorizeRetained(
    access: *const mqtt.broker.AccessControlHandler,
    listener_id: ?u64,
    topic: []const u8,
) bool {
    return access.authorize_retained_source.?(access.context, .{
        .client_id = "publisher",
        .username = "writer",
        .listener_id = listener_id,
        .topic = topic,
        .payload = "value",
        .qos = .at_most_once,
        .retain = true,
        .properties = &.{},
    });
}

//! Retained-source ACL dispatch for the Mosquitto-style broker example.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const Policy = struct {
    per_listener_settings: bool,
    listeners: []const mqtt.broker_config.Listener,
    acl_files: []const ?mqtt.acl_file.File,

    fn allowsWrite(
        self: *const Policy,
        client_id: []const u8,
        username: ?[]const u8,
        listener_id: ?u64,
        topic: []const u8,
    ) bool {
        if (self.acl_files.len == 0 or
            (self.per_listener_settings and
                self.acl_files.len != self.listeners.len))
        {
            return false;
        }
        const file = if (!self.per_listener_settings)
            self.acl_files[0] orelse return true
        else blk: {
            const id = listener_id orelse return false;
            var source_index: ?usize = null;
            for (self.listeners, 0..) |listener, index| {
                if (listener.address.getPort() != id) continue;
                if (source_index != null) return false;
                source_index = index;
            }
            break :blk self.acl_files[source_index orelse return false] orelse
                return true;
        };
        return file.allows(.write, .{
            .client_id = client_id,
            .username = username,
        }, topic);
    }

    pub fn authorizePublish(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Publish,
    ) bool {
        return true;
    }

    pub fn authorizeSubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Subscription,
    ) bool {
        return true;
    }

    pub fn authorizeWill(
        context: *anyopaque,
        publication: mqtt.broker.WillAuthorization,
    ) bool {
        const self: *const Policy = @ptrCast(@alignCast(context));
        return self.allowsWrite(
            publication.client_id,
            publication.username,
            publication.listener_id,
            publication.topic,
        );
    }

    pub fn authorizeRetainedSource(
        context: *anyopaque,
        publication: mqtt.broker.RetainedSourceAuthorization,
    ) bool {
        const self: *const Policy = @ptrCast(@alignCast(context));
        return self.allowsWrite(
            publication.client_id,
            publication.username,
            publication.listener_id,
            publication.topic,
        );
    }
};

test "retained source ACL selects the unique originating listener" {
    var first = try mqtt.acl_file.parse(
        std.testing.allocator,
        "user writer\ntopic write first/#\n",
    );
    defer first.deinit();
    var second = try mqtt.acl_file.parse(
        std.testing.allocator,
        "user writer\ntopic write second/#\n",
    );
    defer second.deinit();
    const listeners = [_]mqtt.broker_config.Listener{
        .{ .address = .{ .ip4 = .loopback(1883) } },
        .{ .address = .{ .ip4 = .loopback(1884) } },
    };
    const files = [_]?mqtt.acl_file.File{ first, second };
    var policy = Policy{
        .per_listener_settings = true,
        .listeners = &listeners,
        .acl_files = &files,
    };
    try std.testing.expect(authorizeRetained(
        &policy,
        1883,
        "first/value",
    ));
    try std.testing.expect(!authorizeRetained(
        &policy,
        1884,
        "first/value",
    ));
    try std.testing.expect(!authorizeRetained(
        &policy,
        null,
        "first/value",
    ));
}

test "global retained source ACL ignores listener identity" {
    var acl = try mqtt.acl_file.parse(
        std.testing.allocator,
        "user writer\ntopic write global/#\n",
    );
    defer acl.deinit();
    const listeners = [_]mqtt.broker_config.Listener{
        .{ .address = .{ .ip4 = .loopback(1883) } },
    };
    const files = [_]?mqtt.acl_file.File{acl};
    var policy = Policy{
        .per_listener_settings = false,
        .listeners = &listeners,
        .acl_files = &files,
    };
    try std.testing.expect(authorizeRetained(
        &policy,
        null,
        "global/value",
    ));
}

test "retained source ACL rejects ambiguous listener identity" {
    var acl = try mqtt.acl_file.parse(
        std.testing.allocator,
        "user writer\ntopic write allowed/#\n",
    );
    defer acl.deinit();
    const listeners = [_]mqtt.broker_config.Listener{
        .{ .address = .{ .ip4 = .loopback(1883) } },
        .{ .address = .{ .ip6 = .loopback(1883) } },
    };
    const files = [_]?mqtt.acl_file.File{ acl, null };
    var policy = Policy{
        .per_listener_settings = true,
        .listeners = &listeners,
        .acl_files = &files,
    };
    try std.testing.expect(!authorizeRetained(
        &policy,
        1883,
        "allowed/value",
    ));
}

fn authorizeRetained(
    policy: *Policy,
    listener_id: ?u64,
    topic: []const u8,
) bool {
    return Policy.authorizeRetainedSource(policy, .{
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

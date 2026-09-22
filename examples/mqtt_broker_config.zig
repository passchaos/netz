//! Runtime adapter for the broker example's strict Mosquitto-style config.
//!
//! Keeping listener construction here prevents the already feature-rich CLI
//! example from also owning heterogeneous transport lifetime bookkeeping.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

const ConfiguredServer = union(enum) {
    mqtt: mqtt.runtime.Server,
    websockets: mqtt.websocket_runtime.Server,

    fn deinit(self: *ConfiguredServer) void {
        switch (self.*) {
            .mqtt => |*server| server.deinit(),
            .websockets => |*server| server.deinit(),
        }
        self.* = undefined;
    }

    fn pendingSource(self: *ConfiguredServer) mqtt.runtime.PendingSource {
        return switch (self.*) {
            .mqtt => |*server| server.pendingSource(),
            .websockets => |*server| server.pendingSource(),
        };
    }

    fn address(self: ConfiguredServer) std.Io.net.IpAddress {
        return switch (self) {
            .mqtt => |server| server.address(),
            .websockets => |server| server.address(),
        };
    }
};

pub fn run(
    allocator: std.mem.Allocator,
    io: std.Io,
    config_path: []const u8,
) !void {
    var config = try mqtt.broker_config.load(
        allocator,
        io,
        std.Io.Dir.cwd(),
        config_path,
    );
    defer config.deinit(allocator);

    var passwords: ?mqtt.password_file.File = if (config.password_file.len != 0)
        try mqtt.password_file.load(
            allocator,
            io,
            std.Io.Dir.cwd(),
            config.password_file,
        )
    else
        null;
    defer if (passwords) |*file| file.deinit();
    var acl: ?mqtt.acl_file.File = if (config.acl_file.len != 0)
        try mqtt.acl_file.load(
            allocator,
            io,
            std.Io.Dir.cwd(),
            config.acl_file,
        )
    else
        null;
    defer if (acl) |*file| file.deinit();
    var acl_policy: mqtt.acl_file.Policy = undefined;
    const access_control: ?mqtt.broker.ListenerAccessControlHandler =
        if (acl) |*file| blk: {
            acl_policy = .{ .acl = file };
            break :blk .{
                .context = &acl_policy,
                .authorize_publish = mqtt.acl_file.Policy.authorizePublish,
                .authorize_subscribe = mqtt.acl_file.Policy.authorizeSubscribe,
                .authorize_unsubscribe = mqtt.acl_file.Policy.authorizeUnsubscribe,
                .authorize_delivery = mqtt.acl_file.Policy.authorizeDelivery,
                .authorize_will = mqtt.acl_file.Policy.authorizeWill,
            };
        } else null;

    const connection_count = try config.totalMaxConnections();
    const persistence_path = if (config.persistence)
        try config.persistencePath(allocator)
    else
        null;
    defer if (persistence_path) |path| allocator.free(path);

    const base_accept = mqtt.runtime.AcceptOptions{
        .protocol = .v5,
        .max_outgoing_inflight = 64,
    };
    var broker = try mqtt.broker.Broker.init(allocator, io, .{
        .limits = .{ .max_connections = connection_count },
        .accept = base_accept,
        .queue_qos0_messages = config.queue_qos0_messages,
        .persistent_change_autosave = if (config.persistence and
            config.autosave_on_changes) .{
            .dir = std.Io.Dir.cwd(),
            .sub_path = persistence_path.?,
            .max_changes = config.autosave_interval,
        } else null,
    });
    defer broker.deinit();

    if (persistence_path) |path| {
        broker.restoreSnapshot(std.Io.Dir.cwd(), path) catch |err| {
            if (err != error.SnapshotNotFound) return err;
        };
    }

    const servers = try allocator.alloc(
        ConfiguredServer,
        config.listeners.len,
    );
    defer allocator.free(servers);
    var initialized_servers: usize = 0;
    defer {
        while (initialized_servers != 0) {
            initialized_servers -= 1;
            servers[initialized_servers].deinit();
        }
    }
    const listeners = try allocator.alloc(
        mqtt.broker.Listener,
        config.listeners.len,
    );
    defer allocator.free(listeners);
    const authorizations = try allocator.alloc(
        mqtt.password_file.Authorization,
        config.listeners.len,
    );
    defer allocator.free(authorizations);

    for (config.listeners, 0..) |configured, index| {
        servers[index] = switch (configured.protocol) {
            .mqtt => .{ .mqtt = try mqtt.runtime.Server.listen(
                allocator,
                io,
                configured.address,
                .{},
            ) },
            .websockets => .{
                .websockets = try mqtt.websocket_runtime.Server.listen(
                    allocator,
                    io,
                    configured.address,
                    .{},
                ),
            },
        };
        initialized_servers += 1;

        var accept = base_accept;
        accept.maximum_qos = configured.maximum_qos;
        accept.maximum_keep_alive_seconds =
            configured.maximum_keep_alive_seconds;
        if (passwords) |*file| {
            authorizations[index] = .{
                .passwords = file,
                .allow_anonymous = configured.allow_anonymous,
            };
        }
        listeners[index] = .{
            .source = servers[index].pendingSource(),
            .namespace = try mqtt.listener_namespace.Namespace.init(
                configured.mount_point,
            ),
            .accept = accept,
            .authorization = .{
                .connect = if (passwords != null) .{
                    .context = &authorizations[index],
                    .authorize = mqtt.password_file.Authorization.authorize,
                } else null,
                .access_control = access_control,
                .use_username_as_client_id = configured.use_username_as_client_id,
            },
            .connection_count = configured.max_connections,
        };
    }

    std.debug.print(
        "netz MQTT 3.1.1/5 broker configured {d} listeners for {d} " ++
            "clients server_io=zio-std-io\n",
        .{ listeners.len, connection_count },
    );
    for (servers, config.listeners) |server, configured| {
        std.debug.print(
            "  {s} {f} mount_point={s} max_connections={d}\n",
            .{
                @tagName(configured.protocol),
                server.address(),
                if (configured.mount_point.len == 0)
                    "<global>"
                else
                    configured.mount_point,
                configured.max_connections,
            },
        );
    }

    if (config.persistence and !config.autosave_on_changes) {
        try serveWithPeriodicAutosave(
            &broker,
            listeners,
            io,
            persistence_path.?,
            config.autosave_interval,
        );
    } else {
        try broker.serveListeners(listeners);
    }
    if (persistence_path) |path| {
        try broker.saveSnapshot(std.Io.Dir.cwd(), path);
    }
}

fn serveWithPeriodicAutosave(
    broker: *mqtt.broker.Broker,
    listeners: []const mqtt.broker.Listener,
    io: std.Io,
    persistence_path: []const u8,
    interval_seconds: u32,
) !void {
    const Result = union(enum) {
        serve: ?anyerror,
        timer: std.Io.Cancelable!void,
    };
    var result_buffer: [2]Result = undefined;
    var select: std.Io.Select(Result) = .init(io, &result_buffer);
    defer select.cancelDiscard();
    try select.concurrent(.serve, serveResult, .{ broker, listeners });
    try select.concurrent(
        .timer,
        waitInterval,
        .{ io, std.Io.Clock.Duration{
            .raw = .fromSeconds(interval_seconds),
            .clock = .awake,
        } },
    );
    while (true) {
        switch (try select.await()) {
            .serve => |maybe_error| {
                select.cancelDiscard();
                if (maybe_error) |err| return err;
                return;
            },
            .timer => |result| {
                try result;
                broker.saveLiveSnapshot(
                    std.Io.Dir.cwd(),
                    persistence_path,
                ) catch |err| switch (err) {
                    error.SnapshotBusy => {},
                    else => return err,
                };
                try select.concurrent(
                    .timer,
                    waitInterval,
                    .{ io, std.Io.Clock.Duration{
                        .raw = .fromSeconds(interval_seconds),
                        .clock = .awake,
                    } },
                );
            },
        }
    }
}

fn serveResult(
    broker: *mqtt.broker.Broker,
    listeners: []const mqtt.broker.Listener,
) ?anyerror {
    broker.serveListeners(listeners) catch |err| return err;
    return null;
}

fn waitInterval(
    io: std.Io,
    interval: std.Io.Clock.Duration,
) std.Io.Cancelable!void {
    try interval.sleep(io);
}

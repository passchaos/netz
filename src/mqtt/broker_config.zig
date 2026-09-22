//! Strict Mosquitto-style configuration for the netz MQTT broker runtime.
//!
//! This module intentionally supports a documented subset. Unknown, duplicate,
//! or misplaced directives fail closed instead of silently weakening listener
//! authentication or resource policy.

const std = @import("std");
const mqtt = @import("mod.zig");

const net = std.Io.net;

pub const max_config_bytes: usize = 1024 * 1024;
pub const default_max_connections: usize = 16;
pub const default_persistence_file = "netz-mqtt.db";
pub const default_autosave_interval: u32 = 1800;

pub const Protocol = enum { mqtt, websockets };

pub const Listener = struct {
    address: net.IpAddress,
    protocol: Protocol = .mqtt,
    mount_point: []u8 = &.{},
    allow_anonymous: bool = false,
    maximum_qos: ?mqtt.QoS = null,
    maximum_keep_alive_seconds: ?u16 = null,
    use_username_as_client_id: bool = false,
    max_connections: usize = default_max_connections,

    fn deinit(self: *Listener, allocator: std.mem.Allocator) void {
        if (self.mount_point.len != 0) allocator.free(self.mount_point);
        self.* = undefined;
    }
};

pub const Config = struct {
    listeners: []Listener,
    password_file: []u8 = &.{},
    acl_file: []u8 = &.{},
    queue_qos0_messages: bool = false,
    persistence: bool = false,
    persistence_location: []u8 = &.{},
    persistence_file: []u8 = &.{},
    autosave_interval: u32 = default_autosave_interval,
    autosave_on_changes: bool = false,

    pub fn deinit(self: *Config, allocator: std.mem.Allocator) void {
        for (self.listeners) |*listener| listener.deinit(allocator);
        allocator.free(self.listeners);
        if (self.password_file.len != 0) allocator.free(self.password_file);
        if (self.acl_file.len != 0) allocator.free(self.acl_file);
        if (self.persistence_location.len != 0) {
            allocator.free(self.persistence_location);
        }
        if (self.persistence_file.len != 0) {
            allocator.free(self.persistence_file);
        }
        self.* = undefined;
    }

    pub fn totalMaxConnections(self: Config) error{IntegerOverflow}!usize {
        var total: usize = 0;
        for (self.listeners) |listener| {
            total = std.math.add(usize, total, listener.max_connections) catch
                return error.IntegerOverflow;
        }
        return total;
    }

    /// Return an owned snapshot path using Mosquitto's location/file split.
    pub fn persistencePath(
        self: Config,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error![]u8 {
        const filename = if (self.persistence_file.len == 0)
            default_persistence_file
        else
            self.persistence_file;
        if (self.persistence_location.len == 0) {
            return allocator.dupe(u8, filename);
        }
        return std.fs.path.join(allocator, &.{
            self.persistence_location,
            filename,
        });
    }
};

pub const Error = mqtt.Error || net.IpAddress.ParseLiteralError || error{
    EmptyConfig,
    MissingListener,
    DirectiveRequiresListener,
    DuplicateDirective,
    UnsupportedDirective,
    InvalidDirective,
    InvalidBoolean,
    InvalidInteger,
    DuplicateListener,
    PersistenceRequired,
    AuthenticationRequired,
    IntegerOverflow,
} || std.mem.Allocator.Error;

const ListenerSeen = struct {
    protocol: bool = false,
    mount_point: bool = false,
    allow_anonymous: bool = false,
    maximum_qos: bool = false,
    maximum_keep_alive: bool = false,
    use_username_as_client_id: bool = false,
    max_connections: bool = false,
};

const GlobalSeen = struct {
    queue_qos0_messages: bool = false,
    password_file: bool = false,
    acl_file: bool = false,
    persistence: bool = false,
    persistence_location: bool = false,
    persistence_file: bool = false,
    autosave_interval: bool = false,
    autosave_on_changes: bool = false,
};

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
) Error!Config {
    if (source.len == 0) return error.EmptyConfig;
    if (source.len > max_config_bytes) return error.InvalidDirective;

    var listeners: std.ArrayList(Listener) = .empty;
    errdefer {
        for (listeners.items) |*listener| listener.deinit(allocator);
        listeners.deinit(allocator);
    }
    var listener_seen: std.ArrayList(ListenerSeen) = .empty;
    defer listener_seen.deinit(allocator);
    var config = Config{ .listeners = &.{} };
    errdefer {
        if (config.persistence_location.len != 0) {
            allocator.free(config.persistence_location);
        }
        if (config.persistence_file.len != 0) {
            allocator.free(config.persistence_file);
        }
        if (config.password_file.len != 0) {
            allocator.free(config.password_file);
        }
        if (config.acl_file.len != 0) allocator.free(config.acl_file);
    }
    var global_seen: GlobalSeen = .{};

    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |raw_line| {
        const without_comment = if (std.mem.findScalar(u8, raw_line, '#')) |i|
            raw_line[0..i]
        else
            raw_line;
        const line = std.mem.trim(u8, without_comment, " \t\r");
        if (line.len == 0) continue;
        var words = std.mem.tokenizeAny(u8, line, " \t");
        const directive = words.next().?;

        if (std.mem.eql(u8, directive, "listener")) {
            const port_text = words.next() orelse return error.InvalidDirective;
            const port = parsePort(port_text) catch return error.InvalidInteger;
            const host = words.next() orelse "0.0.0.0";
            if (words.next() != null) return error.InvalidDirective;
            const address = net.IpAddress.parse(host, port) catch
                return error.InvalidDirective;
            for (listeners.items) |existing| {
                if (existing.address.eql(&address)) {
                    return error.DuplicateListener;
                }
            }
            try listeners.append(allocator, .{ .address = address });
            try listener_seen.append(allocator, .{});
            continue;
        }

        if (std.mem.eql(u8, directive, "queue_qos0_messages")) {
            try markOnce(&global_seen.queue_qos0_messages);
            config.queue_qos0_messages = try parseOneBool(&words);
        } else if (std.mem.eql(u8, directive, "password_file")) {
            try markOnce(&global_seen.password_file);
            config.password_file = try parseOneOwned(allocator, &words);
        } else if (std.mem.eql(u8, directive, "acl_file")) {
            try markOnce(&global_seen.acl_file);
            config.acl_file = try parseOneOwned(allocator, &words);
        } else if (std.mem.eql(u8, directive, "persistence")) {
            try markOnce(&global_seen.persistence);
            config.persistence = try parseOneBool(&words);
        } else if (std.mem.eql(u8, directive, "persistence_location")) {
            try markOnce(&global_seen.persistence_location);
            config.persistence_location = try parseOneOwned(
                allocator,
                &words,
            );
        } else if (std.mem.eql(u8, directive, "persistence_file")) {
            try markOnce(&global_seen.persistence_file);
            config.persistence_file = try parseOneOwned(allocator, &words);
            if (std.mem.indexOfAny(
                u8,
                config.persistence_file,
                "/\\",
            ) != null) {
                return error.InvalidDirective;
            }
        } else if (std.mem.eql(u8, directive, "autosave_interval")) {
            try markOnce(&global_seen.autosave_interval);
            config.autosave_interval = try parseOnePositive(u32, &words);
        } else if (std.mem.eql(u8, directive, "autosave_on_changes")) {
            try markOnce(&global_seen.autosave_on_changes);
            config.autosave_on_changes = try parseOneBool(&words);
        } else {
            if (listeners.items.len == 0) {
                return if (isListenerDirective(directive))
                    error.DirectiveRequiresListener
                else
                    error.UnsupportedDirective;
            }
            const index = listeners.items.len - 1;
            const listener = &listeners.items[index];
            const seen = &listener_seen.items[index];
            if (std.mem.eql(u8, directive, "protocol")) {
                try markOnce(&seen.protocol);
                const value = try parseOne(&words);
                listener.protocol = if (std.mem.eql(u8, value, "mqtt"))
                    .mqtt
                else if (std.mem.eql(u8, value, "websockets"))
                    .websockets
                else
                    return error.InvalidDirective;
            } else if (std.mem.eql(u8, directive, "mount_point")) {
                try markOnce(&seen.mount_point);
                const value = try parseOne(&words);
                _ = try mqtt.listener_namespace.Namespace.init(value);
                listener.mount_point = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, directive, "allow_anonymous")) {
                try markOnce(&seen.allow_anonymous);
                listener.allow_anonymous = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "max_qos")) {
                try markOnce(&seen.maximum_qos);
                listener.maximum_qos = switch (try parseOneInteger(u2, &words)) {
                    0 => .at_most_once,
                    1 => .at_least_once,
                    2 => .exactly_once,
                    else => return error.InvalidInteger,
                };
            } else if (std.mem.eql(u8, directive, "max_keepalive")) {
                try markOnce(&seen.maximum_keep_alive);
                listener.maximum_keep_alive_seconds =
                    try parseOnePositive(u16, &words);
            } else if (std.mem.eql(
                u8,
                directive,
                "use_username_as_clientid",
            )) {
                try markOnce(&seen.use_username_as_client_id);
                listener.use_username_as_client_id = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "max_connections")) {
                try markOnce(&seen.max_connections);
                listener.max_connections = try parseOnePositive(usize, &words);
            } else {
                return error.UnsupportedDirective;
            }
        }
    }

    if (listeners.items.len == 0) return error.MissingListener;
    if ((global_seen.persistence_location or
        global_seen.persistence_file or
        global_seen.autosave_interval or
        global_seen.autosave_on_changes) and !config.persistence)
    {
        return error.PersistenceRequired;
    }
    for (listeners.items) |listener| {
        if (!listener.allow_anonymous and config.password_file.len == 0) {
            return error.AuthenticationRequired;
        }
    }
    const candidate = Config{ .listeners = listeners.items };
    _ = try candidate.totalMaxConnections();
    config.listeners = try listeners.toOwnedSlice(allocator);
    return config;
}

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) (Error || std.Io.Dir.ReadFileAllocError)!Config {
    const source = try dir.readFileAlloc(
        io,
        sub_path,
        allocator,
        .limited(max_config_bytes + 1),
    );
    defer allocator.free(source);
    if (source.len > max_config_bytes) return error.InvalidDirective;
    return parse(allocator, source);
}

fn markOnce(flag: *bool) error{DuplicateDirective}!void {
    if (flag.*) return error.DuplicateDirective;
    flag.* = true;
}

fn isListenerDirective(value: []const u8) bool {
    return std.mem.eql(u8, value, "protocol") or
        std.mem.eql(u8, value, "mount_point") or
        std.mem.eql(u8, value, "allow_anonymous") or
        std.mem.eql(u8, value, "max_qos") or
        std.mem.eql(u8, value, "max_keepalive") or
        std.mem.eql(u8, value, "use_username_as_clientid") or
        std.mem.eql(u8, value, "max_connections");
}

fn parsePort(value: []const u8) error{InvalidInteger}!u16 {
    const port = std.fmt.parseInt(u16, value, 10) catch
        return error.InvalidInteger;
    if (port == 0) return error.InvalidInteger;
    return port;
}

fn parseOne(words: anytype) error{InvalidDirective}![]const u8 {
    const value = words.next() orelse return error.InvalidDirective;
    if (words.next() != null) return error.InvalidDirective;
    return value;
}

fn parseOneOwned(
    allocator: std.mem.Allocator,
    words: anytype,
) (error{InvalidDirective} || std.mem.Allocator.Error)![]u8 {
    return allocator.dupe(u8, try parseOne(words));
}

fn parseOneBool(words: anytype) error{ InvalidDirective, InvalidBoolean }!bool {
    const value = try parseOne(words);
    if (std.mem.eql(u8, value, "true")) return true;
    if (std.mem.eql(u8, value, "false")) return false;
    return error.InvalidBoolean;
}

fn parseOneInteger(
    comptime T: type,
    words: anytype,
) error{ InvalidDirective, InvalidInteger }!T {
    const value = try parseOne(words);
    return std.fmt.parseInt(T, value, 10) catch error.InvalidInteger;
}

fn parseOnePositive(
    comptime T: type,
    words: anytype,
) error{ InvalidDirective, InvalidInteger }!T {
    const value = try parseOneInteger(T, words);
    if (value == 0) return error.InvalidInteger;
    return value;
}

test "MQTT broker config parses owned multi-listener policy" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\# strict supported subset
        \\queue_qos0_messages true
        \\password_file users.pw
        \\acl_file access.acl
        \\persistence true
        \\persistence_location state
        \\persistence_file broker.db
        \\autosave_interval 17
        \\autosave_on_changes true
        \\listener 1883 127.0.0.1
        \\allow_anonymous true
        \\max_qos 1
        \\max_keepalive 30
        \\max_connections 4
        \\listener 8080 ::1
        \\protocol websockets
        \\mount_point tenant/
        \\allow_anonymous false
        \\use_username_as_clientid true
        \\max_connections 2
    );
    defer config.deinit(allocator);
    try std.testing.expect(config.queue_qos0_messages);
    try std.testing.expectEqualStrings("users.pw", config.password_file);
    try std.testing.expectEqualStrings("access.acl", config.acl_file);
    try std.testing.expect(config.persistence);
    try std.testing.expect(config.autosave_on_changes);
    try std.testing.expectEqual(@as(u32, 17), config.autosave_interval);
    try std.testing.expectEqual(@as(usize, 6), try config.totalMaxConnections());
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expect(config.listeners[0].protocol == .mqtt);
    try std.testing.expect(config.listeners[0].allow_anonymous);
    try std.testing.expect(config.listeners[0].maximum_qos.? == .at_least_once);
    try std.testing.expectEqual(@as(?u16, 30), config.listeners[0].maximum_keep_alive_seconds);
    try std.testing.expect(config.listeners[1].protocol == .websockets);
    try std.testing.expectEqualStrings("tenant/", config.listeners[1].mount_point);
    try std.testing.expect(config.listeners[1].use_username_as_client_id);
    const path = try config.persistencePath(allocator);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("state/broker.db", path);
}

test "MQTT broker config fails closed for unsupported and misplaced directives" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "mount_point tenant/\nlistener 1883"),
    );
    try std.testing.expectError(
        error.AuthenticationRequired,
        parse(allocator, "listener 1883"),
    );
    try std.testing.expectError(
        error.UnsupportedDirective,
        parse(allocator, "listener 1883\ncertfile server.pem"),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 1883
            \\allow_anonymous true
            \\allow_anonymous false
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\acl_file first.acl
            \\acl_file second.acl
            \\listener 1883
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.PersistenceRequired,
        parse(allocator,
            \\listener 1883
            \\autosave_interval 5
        ),
    );
    try std.testing.expectError(
        error.DuplicateListener,
        parse(allocator,
            \\listener 1883 127.0.0.1
            \\listener 1883 127.0.0.1
        ),
    );
    try std.testing.expectError(
        error.InvalidBoolean,
        parse(allocator, "listener 1883\nallow_anonymous yes"),
    );
    try std.testing.expectError(
        error.InvalidInteger,
        parse(allocator, "listener 1883\nmax_qos 3"),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\persistence true
            \\persistence_file ../broker.db
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\password_file first.pw
            \\password_file second.pw
            \\listener 1883
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator,
            \\persistence true
            \\persistence_file state\\broker.db
            \\listener 1883
        ),
    );
}

test "MQTT broker config owns strings independently of source" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "persistence true\npersistence_location state\n" ++
            "persistence_file broker.db\npassword_file users.pw\n" ++
            "acl_file access.acl\n" ++
            "listener 1883\n" ++
            "mount_point tenant/\nallow_anonymous true\n",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expectEqualStrings(
        "state",
        config.persistence_location,
    );
    try std.testing.expectEqualStrings("broker.db", config.persistence_file);
    try std.testing.expectEqualStrings("users.pw", config.password_file);
    try std.testing.expectEqualStrings("access.acl", config.acl_file);
    try std.testing.expectEqualStrings("tenant/", config.listeners[0].mount_point);
}

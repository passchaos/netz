//! Strict Mosquitto-style configuration for the netz MQTT broker runtime.
//!
//! This module intentionally supports a documented subset. Unknown, duplicate,
//! or misplaced directives fail closed instead of silently weakening listener
//! authentication or resource policy.

const std = @import("std");
const mqtt = @import("mod.zig");
const broker_config_include = @import("broker_config_include.zig");

const net = std.Io.net;

pub const max_config_bytes: usize = 1024 * 1024;
pub const default_max_connections: usize = 16;
pub const default_persistence_file = "netz-mqtt.db";
pub const default_autosave_interval: u32 = 1800;

pub const Protocol = enum { mqtt, websockets };

pub const Listener = struct {
    address: net.IpAddress,
    protocol: Protocol = .mqtt,
    password_file: []u8 = &.{},
    acl_file: []u8 = &.{},
    certfile: []u8 = &.{},
    keyfile: []u8 = &.{},
    cafile: []u8 = &.{},
    capath: []u8 = &.{},
    crlfile: []u8 = &.{},
    require_certificate: bool = false,
    use_identity_as_username: bool = false,
    use_subject_as_username: bool = false,
    mount_point: []u8 = &.{},
    allow_anonymous: bool = false,
    maximum_qos: ?mqtt.QoS = null,
    maximum_keep_alive_seconds: ?u16 = null,
    use_username_as_client_id: bool = false,
    max_connections: usize = default_max_connections,

    fn deinit(self: *Listener, allocator: std.mem.Allocator) void {
        if (self.password_file.len != 0) allocator.free(self.password_file);
        if (self.acl_file.len != 0) allocator.free(self.acl_file);
        if (self.certfile.len != 0) allocator.free(self.certfile);
        if (self.keyfile.len != 0) allocator.free(self.keyfile);
        if (self.cafile.len != 0) allocator.free(self.cafile);
        if (self.capath.len != 0) allocator.free(self.capath);
        if (self.crlfile.len != 0) allocator.free(self.crlfile);
        if (self.mount_point.len != 0) allocator.free(self.mount_point);
        self.* = undefined;
    }

    pub fn usesTls(self: Listener) bool {
        return self.certfile.len != 0;
    }
};

pub const Config = struct {
    listeners: []Listener,
    per_listener_settings: bool = false,
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
    TlsIdentityIncomplete,
    ClientCertificateConfigurationIncomplete,
    CapathUnsupportedForWebSockets,
    IntegerOverflow,
} || std.mem.Allocator.Error;

const ListenerSeen = struct {
    password_file: bool = false,
    acl_file: bool = false,
    protocol: bool = false,
    certfile: bool = false,
    keyfile: bool = false,
    cafile: bool = false,
    capath: bool = false,
    crlfile: bool = false,
    require_certificate: bool = false,
    use_identity_as_username: bool = false,
    use_subject_as_username: bool = false,
    mount_point: bool = false,
    allow_anonymous: bool = false,
    maximum_qos: bool = false,
    maximum_keep_alive: bool = false,
    use_username_as_client_id: bool = false,
    max_connections: bool = false,
};

const GlobalSeen = struct {
    per_listener_settings: bool = false,
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
    return parseSources(allocator, &.{.{
        .bytes = source,
        .scope = 0,
    }}, 1);
}

fn parseSources(
    allocator: std.mem.Allocator,
    sources: []const broker_config_include.Source,
    scope_count: usize,
) Error!Config {
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
    var security_settings_seen = false;
    const current_listener = try allocator.alloc(?usize, scope_count);
    defer allocator.free(current_listener);
    @memset(current_listener, null);

    for (sources) |source| {
        if (source.scope >= current_listener.len) return error.InvalidDirective;
        var lines = std.mem.splitScalar(u8, source.bytes, '\n');
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
                current_listener[source.scope] = listeners.items.len - 1;
                continue;
            }

            if (std.mem.eql(u8, directive, "per_listener_settings")) {
                try markOnce(&global_seen.per_listener_settings);
                const enabled = try parseOneBool(&words);
                if (enabled and security_settings_seen) {
                    return error.InvalidDirective;
                }
                config.per_listener_settings = enabled;
            } else if (std.mem.eql(u8, directive, "queue_qos0_messages")) {
                try markOnce(&global_seen.queue_qos0_messages);
                config.queue_qos0_messages = try parseOneBool(&words);
            } else if (std.mem.eql(u8, directive, "password_file")) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(&listener_seen.items[index].password_file);
                    listeners.items[index].password_file =
                        try parseOneOwned(allocator, &words);
                } else {
                    try markOnce(&global_seen.password_file);
                    config.password_file = try parseOneOwned(allocator, &words);
                }
            } else if (std.mem.eql(u8, directive, "acl_file")) {
                security_settings_seen = true;
                if (config.per_listener_settings) {
                    const index = current_listener[source.scope] orelse
                        return error.DirectiveRequiresListener;
                    try markOnce(&listener_seen.items[index].acl_file);
                    listeners.items[index].acl_file =
                        try parseOneOwned(allocator, &words);
                } else {
                    try markOnce(&global_seen.acl_file);
                    config.acl_file = try parseOneOwned(allocator, &words);
                }
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
                const index = current_listener[source.scope] orelse {
                    return if (isListenerDirective(directive))
                        error.DirectiveRequiresListener
                    else
                        error.UnsupportedDirective;
                };
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
                } else if (std.mem.eql(u8, directive, "certfile")) {
                    try markOnce(&seen.certfile);
                    listener.certfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "keyfile")) {
                    try markOnce(&seen.keyfile);
                    listener.keyfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "cafile")) {
                    try markOnce(&seen.cafile);
                    listener.cafile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "capath")) {
                    try markOnce(&seen.capath);
                    listener.capath = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "crlfile")) {
                    try markOnce(&seen.crlfile);
                    listener.crlfile = try parseOneOwned(allocator, &words);
                } else if (std.mem.eql(u8, directive, "require_certificate")) {
                    try markOnce(&seen.require_certificate);
                    listener.require_certificate = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "use_identity_as_username")) {
                    security_settings_seen = true;
                    try markOnce(&seen.use_identity_as_username);
                    listener.use_identity_as_username = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "use_subject_as_username")) {
                    security_settings_seen = true;
                    try markOnce(&seen.use_subject_as_username);
                    listener.use_subject_as_username = try parseOneBool(&words);
                } else if (std.mem.eql(u8, directive, "mount_point")) {
                    try markOnce(&seen.mount_point);
                    const value = try parseOne(&words);
                    _ = try mqtt.listener_namespace.Namespace.init(value);
                    listener.mount_point = try allocator.dupe(u8, value);
                } else if (std.mem.eql(u8, directive, "allow_anonymous")) {
                    security_settings_seen = true;
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
        const has_client_ca = listener.cafile.len != 0 or
            listener.capath.len != 0;
        if ((listener.certfile.len == 0) != (listener.keyfile.len == 0)) {
            return error.TlsIdentityIncomplete;
        }
        if (listener.require_certificate and
            (!has_client_ca or !listener.usesTls()))
        {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if (has_client_ca and !listener.usesTls()) {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if (listener.capath.len != 0 and listener.protocol == .websockets) {
            return error.CapathUnsupportedForWebSockets;
        }
        if (listener.crlfile.len != 0 and !has_client_ca) {
            return error.ClientCertificateConfigurationIncomplete;
        }
        if ((listener.use_identity_as_username or
            listener.use_subject_as_username) and
            !listener.require_certificate)
        {
            return error.ClientCertificateConfigurationIncomplete;
        }
        const password_file = if (config.per_listener_settings)
            listener.password_file
        else
            config.password_file;
        if (!listener.allow_anonymous and password_file.len == 0 and
            !listener.use_identity_as_username and
            !listener.use_subject_as_username)
        {
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
) (Error || broker_config_include.Error || std.Io.Dir.OpenError ||
    std.Io.Dir.Iterator.Error || std.Io.Dir.StatFileError ||
    std.Io.Dir.ReadFileAllocError)!Config {
    var document = try broker_config_include.load(
        allocator,
        io,
        dir,
        sub_path,
    );
    defer document.deinit();
    return parseSources(allocator, document.sources, document.scope_count);
}

fn markOnce(flag: *bool) error{DuplicateDirective}!void {
    if (flag.*) return error.DuplicateDirective;
    flag.* = true;
}

fn isListenerDirective(value: []const u8) bool {
    return std.mem.eql(u8, value, "protocol") or
        std.mem.eql(u8, value, "certfile") or
        std.mem.eql(u8, value, "keyfile") or
        std.mem.eql(u8, value, "cafile") or
        std.mem.eql(u8, value, "capath") or
        std.mem.eql(u8, value, "crlfile") or
        std.mem.eql(u8, value, "require_certificate") or
        std.mem.eql(u8, value, "use_identity_as_username") or
        std.mem.eql(u8, value, "use_subject_as_username") or
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
        \\certfile server-chain.pem
        \\keyfile server-key.pem
        \\cafile client-ca.pem
        \\crlfile clients.crl
        \\require_certificate true
        \\use_identity_as_username true
        \\use_subject_as_username true
        \\mount_point tenant/
        \\allow_anonymous false
        \\use_username_as_clientid true
        \\max_connections 2
    );
    defer config.deinit(allocator);
    try std.testing.expect(config.queue_qos0_messages);
    try std.testing.expect(!config.per_listener_settings);
    try std.testing.expectEqualStrings("users.pw", config.password_file);
    try std.testing.expectEqualStrings("access.acl", config.acl_file);
    try std.testing.expect(config.persistence);
    try std.testing.expect(config.autosave_on_changes);
    try std.testing.expectEqual(@as(u32, 17), config.autosave_interval);
    try std.testing.expectEqual(@as(usize, 6), try config.totalMaxConnections());
    try std.testing.expectEqual(@as(usize, 2), config.listeners.len);
    try std.testing.expect(config.listeners[0].protocol == .mqtt);
    try std.testing.expect(config.listeners[0].allow_anonymous);
    try std.testing.expect(config.listeners[0].password_file.len == 0);
    try std.testing.expect(config.listeners[0].acl_file.len == 0);
    try std.testing.expect(config.listeners[0].maximum_qos.? == .at_least_once);
    try std.testing.expectEqual(@as(?u16, 30), config.listeners[0].maximum_keep_alive_seconds);
    try std.testing.expect(config.listeners[1].protocol == .websockets);
    try std.testing.expect(config.listeners[1].usesTls());
    try std.testing.expectEqualStrings(
        "server-chain.pem",
        config.listeners[1].certfile,
    );
    try std.testing.expectEqualStrings(
        "server-key.pem",
        config.listeners[1].keyfile,
    );
    try std.testing.expectEqualStrings(
        "client-ca.pem",
        config.listeners[1].cafile,
    );
    try std.testing.expectEqualStrings(
        "clients.crl",
        config.listeners[1].crlfile,
    );
    try std.testing.expect(config.listeners[1].require_certificate);
    try std.testing.expect(config.listeners[1].use_identity_as_username);
    try std.testing.expect(config.listeners[1].use_subject_as_username);
    try std.testing.expectEqualStrings("tenant/", config.listeners[1].mount_point);
    try std.testing.expect(config.listeners[1].use_username_as_client_id);
    const path = try config.persistencePath(allocator);
    defer allocator.free(path);
    try std.testing.expectEqualStrings("state/broker.db", path);
}

test "MQTT broker config owns per-listener security files" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "per_listener_settings true\n" ++
            "listener 1883 127.0.0.1\n" ++
            "password_file first.pw\nacl_file first.acl\n" ++
            "allow_anonymous false\n" ++
            "listener 8080 127.0.0.1\nprotocol websockets\n" ++
            "password_file second.pw\nacl_file second.acl\n" ++
            "allow_anonymous false\n",
    );
    defer allocator.free(source);
    var config = try parse(allocator, source);
    defer config.deinit(allocator);
    @memset(source, 'x');

    try std.testing.expect(config.per_listener_settings);
    try std.testing.expect(config.password_file.len == 0);
    try std.testing.expect(config.acl_file.len == 0);
    try std.testing.expectEqualStrings(
        "first.pw",
        config.listeners[0].password_file,
    );
    try std.testing.expectEqualStrings(
        "first.acl",
        config.listeners[0].acl_file,
    );
    try std.testing.expectEqualStrings(
        "second.pw",
        config.listeners[1].password_file,
    );
    try std.testing.expectEqualStrings(
        "second.acl",
        config.listeners[1].acl_file,
    );
}

test "MQTT broker config loads include directories in Mosquitto order" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "one.d", .default_dir);
    var one = try tmp.dir.openDir(io, "one.d", .{});
    defer one.close(io);
    try one.writeFile(io, .{
        .sub_path = "b.conf",
        .data = "listener 1886\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "A.conf",
        .data = "listener 1883\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "a.conf",
        .data = "listener 1884\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "B.conf",
        .data = "listener 1885\nallow_anonymous true\n",
    });
    try one.writeFile(io, .{
        .sub_path = "ignored.txt",
        .data = "unsupported value\n",
    });
    try tmp.dir.createDir(io, "two.d", .default_dir);
    var two = try tmp.dir.openDir(io, "two.d", .{});
    defer two.close(io);
    try two.writeFile(io, .{
        .sub_path = "00.conf",
        .data = "listener 1887\nallow_anonymous true\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "listener 1882\nallow_anonymous true\n" ++
            "include_dir one.d\ninclude_dir two.d\n" ++
            "max_connections 7\n",
    });

    var config = try load(allocator, io, tmp.dir, "main.conf");
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 6), config.listeners.len);
    const expected_ports = [_]u16{ 1882, 1883, 1884, 1885, 1886, 1887 };
    for (config.listeners, expected_ports) |listener, expected_port| {
        try std.testing.expectEqual(expected_port, listener.address.getPort());
    }
    try std.testing.expectEqual(@as(usize, 7), config.listeners[0].max_connections);
    for (config.listeners[1..]) |listener| {
        try std.testing.expectEqual(
            default_max_connections,
            listener.max_connections,
        );
    }
}

test "MQTT broker config isolates included file listener scopes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "listeners.d", .default_dir);
    var included = try tmp.dir.openDir(io, "listeners.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "10-listener.conf",
        .data = "listener 1883\nallow_anonymous true\n",
    });
    try included.writeFile(io, .{
        .sub_path = "20-policy.conf",
        .data = "max_connections 2\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir listeners.d\n",
    });
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config rejects nested include directories" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "listeners.d", .default_dir);
    var included = try tmp.dir.openDir(io, "listeners.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "nested.conf",
        .data = "include_dir other.d\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir listeners.d\n",
    });
    try std.testing.expectError(
        error.NestedIncludeDirectory,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config rejects duplicate globals across include files" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "settings.d", .default_dir);
    var included = try tmp.dir.openDir(io, "settings.d", .{});
    defer included.close(io);
    try included.writeFile(io, .{
        .sub_path = "10-first.conf",
        .data = "queue_qos0_messages true\n",
    });
    try included.writeFile(io, .{
        .sub_path = "20-second.conf",
        .data = "queue_qos0_messages false\n",
    });
    try tmp.dir.writeFile(io, .{
        .sub_path = "main.conf",
        .data = "include_dir settings.d\n" ++
            "listener 1883\nallow_anonymous true\n",
    });
    try std.testing.expectError(
        error.DuplicateDirective,
        load(allocator, io, tmp.dir, "main.conf"),
    );
}

test "MQTT broker config fails closed for unsupported and misplaced directives" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.UnsupportedDirective,
        parse(allocator, "include_dir listeners.d\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "mount_point tenant/\nlistener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "per_listener_settings true\npassword_file users.pw\n" ++
                "listener 1883",
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(
            allocator,
            "per_listener_settings true\nacl_file access.acl\n" ++
                "listener 1883",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "password_file users.pw\nper_listener_settings true\n" ++
                "listener 1883\nallow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.InvalidDirective,
        parse(
            allocator,
            "listener 1883\nallow_anonymous true\n" ++
                "per_listener_settings true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "per_listener_settings true\nper_listener_settings true\n" ++
                "listener 1883\nallow_anonymous true",
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(
            allocator,
            "per_listener_settings true\nlistener 1883\n" ++
                "password_file first.pw\npassword_file second.pw\n" ++
                "allow_anonymous false",
        ),
    );
    try std.testing.expectError(
        error.AuthenticationRequired,
        parse(allocator, "listener 1883"),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "certfile server.pem\nlistener 1883"),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.TlsIdentityIncomplete,
        parse(allocator,
            \\listener 8883
            \\keyfile server.key
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile first.pem
            \\certfile second.pem
            \\keyfile server.key
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\use_subject_as_username true
            \\use_subject_as_username true
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DirectiveRequiresListener,
        parse(allocator, "use_subject_as_username true\nlistener 8883"),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\crlfile clients.crl
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\crlfile first.crl
            \\crlfile second.crl
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\use_identity_as_username true
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\use_subject_as_username true
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\use_identity_as_username true
            \\use_identity_as_username true
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator, "listener 1883\ncapath clients"),
    );
    try std.testing.expectError(
        error.CapathUnsupportedForWebSockets,
        parse(allocator,
            \\listener 8080
            \\protocol websockets
            \\certfile server.pem
            \\keyfile server.key
            \\capath clients
            \\allow_anonymous true
        ),
    );
    var capath_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile common.pem
        \\capath clients
        \\require_certificate true
        \\allow_anonymous true
    );
    defer capath_client_certificate.deinit(allocator);
    try std.testing.expectEqualStrings(
        "common.pem",
        capath_client_certificate.listeners[0].cafile,
    );
    try std.testing.expectEqualStrings(
        "clients",
        capath_client_certificate.listeners[0].capath,
    );
    try std.testing.expect(
        capath_client_certificate.listeners[0].require_certificate,
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\capath first
            \\capath second
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\require_certificate true
            \\allow_anonymous true
        ),
    );
    var optional_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\require_certificate false
        \\allow_anonymous true
    );
    defer optional_client_certificate.deinit(allocator);
    try std.testing.expect(
        !optional_client_certificate.listeners[0].require_certificate,
    );
    try std.testing.expectEqualStrings(
        "clients.pem",
        optional_client_certificate.listeners[0].cafile,
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile first.pem
            \\cafile second.pem
            \\require_certificate true
            \\allow_anonymous true
        ),
    );
    try std.testing.expectError(
        error.DuplicateDirective,
        parse(allocator,
            \\listener 8883
            \\certfile server.pem
            \\keyfile server.key
            \\cafile clients.pem
            \\require_certificate true
            \\require_certificate true
            \\allow_anonymous true
        ),
    );
    var implicit_optional_client_certificate = try parse(allocator,
        \\listener 8883
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\allow_anonymous true
    );
    defer implicit_optional_client_certificate.deinit(allocator);
    try std.testing.expect(
        !implicit_optional_client_certificate.listeners[0].require_certificate,
    );
    try std.testing.expectError(
        error.ClientCertificateConfigurationIncomplete,
        parse(allocator,
            \\listener 8883
            \\cafile clients.pem
            \\require_certificate true
            \\allow_anonymous true
        ),
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
            "certfile server.pem\nkeyfile server.key\n" ++
            "cafile clients.pem\ncapath clients\n" ++
            "require_certificate true\n" ++
            "crlfile clients.crl\n" ++
            "use_identity_as_username true\n" ++
            "use_subject_as_username true\n" ++
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
    try std.testing.expectEqualStrings("server.pem", config.listeners[0].certfile);
    try std.testing.expectEqualStrings("server.key", config.listeners[0].keyfile);
    try std.testing.expectEqualStrings("clients.pem", config.listeners[0].cafile);
    try std.testing.expectEqualStrings("clients", config.listeners[0].capath);
    try std.testing.expectEqualStrings("clients.crl", config.listeners[0].crlfile);
    try std.testing.expect(config.listeners[0].require_certificate);
    try std.testing.expect(config.listeners[0].use_identity_as_username);
    try std.testing.expect(config.listeners[0].use_subject_as_username);
    try std.testing.expectEqualStrings("tenant/", config.listeners[0].mount_point);
}

test "MQTT broker config accepts certificate identity authentication" {
    const allocator = std.testing.allocator;
    var config = try parse(allocator,
        \\listener 8883 127.0.0.1
        \\certfile server.pem
        \\keyfile server.key
        \\cafile clients.pem
        \\require_certificate true
        \\use_identity_as_username true
        \\allow_anonymous false
        \\max_connections 1
    );
    defer config.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), config.listeners.len);
    try std.testing.expect(config.password_file.len == 0);
    try std.testing.expect(config.listeners[0].require_certificate);
    try std.testing.expect(config.listeners[0].use_identity_as_username);
}

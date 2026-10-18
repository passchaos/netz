//! Strict Mosquitto ACL-file parsing and authorization.
//!
//! The supported grammar is `user <name>`, followed by `topic` rules scoped
//! to that user, plus global `pattern` rules. Topic rules before the first user
//! apply only to anonymous clients. Explicit deny rules take precedence over
//! grants, and an unmatched operation is denied.

const std = @import("std");
const mqtt = @import("mod.zig");

pub const max_file_bytes: usize = 1024 * 1024;
pub const max_rules: usize = 16_384;

pub const Error = mqtt.Error || std.mem.Allocator.Error || error{
    TooManyRules,
    InvalidDirective,
    InvalidAccess,
    InvalidPattern,
};

pub const Operation = enum { read, write };
pub const Access = enum { deny, read, write, readwrite };

const Rule = struct {
    username: ?[]const u8,
    filter: []const u8,
    access: Access,
    pattern: bool,
};

pub const Identity = struct {
    client_id: []const u8,
    username: ?[]const u8,
};

pub const File = struct {
    allocator: std.mem.Allocator,
    source: []u8,
    rules: []Rule,
    has_patterns: bool,

    pub fn deinit(self: *File) void {
        self.allocator.free(self.rules);
        self.allocator.free(self.source);
        self.* = undefined;
    }

    pub fn ruleCount(self: File) usize {
        return self.rules.len;
    }

    pub fn allows(
        self: File,
        operation: Operation,
        identity: Identity,
        topic: []const u8,
    ) bool {
        if (decision(self.rules, operation, identity, topic, false)) |allowed| {
            return allowed;
        }
        if (!self.has_patterns) return false;
        // Match Mosquitto's injection guard: identity wildcards deny pattern
        // evaluation, but do not override an already-matched user rule.
        if (containsPatternWildcard(identity.client_id) or
            if (identity.username) |username|
                containsPatternWildcard(username)
            else
                false)
        {
            return false;
        }
        return decision(self.rules, operation, identity, topic, true) orelse
            false;
    }
};

pub const Policy = struct {
    acl: *const File,

    pub fn authorizePublish(
        context: *anyopaque,
        connect: mqtt.Connect,
        publish: mqtt.Publish,
    ) bool {
        const self: *const Policy = @ptrCast(@alignCast(context));
        return self.acl.allows(.write, identityForConnect(connect), publish.topic);
    }

    /// Mosquitto's ACL-file plugin admits subscriptions and applies read rules
    /// to each concrete retained/live/durable delivery.
    pub fn authorizeSubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: mqtt.Subscription,
    ) bool {
        return true;
    }

    pub fn authorizeUnsubscribe(
        _: *anyopaque,
        _: mqtt.Connect,
        _: []const u8,
    ) bool {
        return true;
    }

    pub fn authorizeDelivery(
        context: *anyopaque,
        delivery: mqtt.broker.DeliveryAuthorization,
    ) bool {
        const self: *const Policy = @ptrCast(@alignCast(context));
        return self.acl.allows(.read, .{
            .client_id = delivery.client_id,
            .username = delivery.username,
        }, delivery.topic);
    }

    pub fn authorizeWill(
        context: *anyopaque,
        connect: mqtt.Connect,
        will: mqtt.LastWill,
    ) bool {
        const self: *const Policy = @ptrCast(@alignCast(context));
        return self.acl.allows(.write, identityForConnect(connect), will.topic);
    }

    pub fn authorizeRetainedSource(
        context: *anyopaque,
        publication: mqtt.broker.RetainedSourceAuthorization,
    ) bool {
        const self: *const Policy = @ptrCast(@alignCast(context));
        return self.acl.allows(.write, .{
            .client_id = publication.client_id,
            .username = publication.username,
        }, publication.topic);
    }
};

pub fn parse(allocator: std.mem.Allocator, source: []const u8) Error!File {
    if (source.len > max_file_bytes) return error.InvalidDirective;
    const owned_source = try allocator.dupe(u8, source);
    errdefer allocator.free(owned_source);
    var rules: std.ArrayList(Rule) = .empty;
    defer rules.deinit(allocator);
    var current_user: ?[]const u8 = null;
    var has_patterns = false;

    var lines = std.mem.splitScalar(u8, owned_source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const first = splitWord(line);
        if (std.mem.eql(u8, first.word, "user")) {
            if (first.rest.len == 0 or
                first.rest.len > std.math.maxInt(u16))
            {
                return error.InvalidDirective;
            }
            try mqtt.validateUtf8String(first.rest);
            current_user = first.rest;
            continue;
        }
        const pattern = if (std.mem.eql(u8, first.word, "topic"))
            false
        else if (std.mem.eql(u8, first.word, "pattern"))
            true
        else
            return error.InvalidDirective;
        if (first.rest.len == 0) return error.InvalidDirective;
        const second = splitWord(first.rest);
        const access: Access = if (second.rest.len == 0)
            .readwrite
        else
            parseAccess(second.word) orelse return error.InvalidAccess;
        const filter = if (second.rest.len == 0) second.word else second.rest;
        if (filter.len == 0) return error.InvalidDirective;
        try mqtt.validateTopicFilter(filter);
        if (pattern and !validPattern(filter)) return error.InvalidPattern;
        if (rules.items.len == max_rules) return error.TooManyRules;
        try rules.append(allocator, .{
            .username = if (pattern) null else current_user,
            .filter = filter,
            .access = access,
            .pattern = pattern,
        });
        has_patterns = has_patterns or pattern;
    }
    return .{
        .allocator = allocator,
        .source = owned_source,
        .rules = try rules.toOwnedSlice(allocator),
        .has_patterns = has_patterns,
    };
}

pub fn load(
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
) (Error || std.Io.Dir.ReadFileAllocError)!File {
    const source = try dir.readFileAlloc(
        io,
        sub_path,
        allocator,
        .limited(max_file_bytes + 1),
    );
    defer allocator.free(source);
    if (source.len > max_file_bytes) return error.InvalidDirective;
    return parse(allocator, source);
}

fn identityForConnect(connect: mqtt.Connect) Identity {
    return .{ .client_id = connect.client_id, .username = connect.username };
}

fn splitWord(value: []const u8) struct {
    word: []const u8,
    rest: []const u8,
} {
    const end = std.mem.indexOfAny(u8, value, " \t") orelse value.len;
    return .{
        .word = value[0..end],
        .rest = std.mem.trim(u8, value[end..], " \t"),
    };
}

fn parseAccess(value: []const u8) ?Access {
    inline for (std.meta.fields(Access)) |field| {
        if (std.mem.eql(u8, value, field.name)) {
            return @enumFromInt(field.value);
        }
    }
    return null;
}

fn validPattern(filter: []const u8) bool {
    var found = false;
    var levels = std.mem.splitScalar(u8, filter, '/');
    while (levels.next()) |level| {
        if (std.mem.indexOfScalar(u8, level, '%') != null) {
            if (!std.mem.eql(u8, level, "%c") and
                !std.mem.eql(u8, level, "%u"))
            {
                return false;
            }
            found = true;
        }
    }
    return found;
}

fn containsPatternWildcard(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "+#") != null;
}

fn grants(access: Access, operation: Operation) bool {
    return switch (access) {
        .deny => false,
        .read => operation == .read,
        .write => operation == .write,
        .readwrite => true,
    };
}

fn decision(
    rules: []const Rule,
    operation: Operation,
    identity: Identity,
    topic: []const u8,
    pattern: bool,
) ?bool {
    for (rules) |rule| {
        if (rule.pattern != pattern or rule.access != .deny or
            !scopeMatches(rule, identity))
        {
            continue;
        }
        if (topicMatchesRule(rule, identity, topic)) return false;
    }
    for (rules) |rule| {
        if (rule.pattern != pattern or rule.access == .deny or
            !grants(rule.access, operation) or !scopeMatches(rule, identity))
        {
            continue;
        }
        if (topicMatchesRule(rule, identity, topic)) return true;
    }
    return null;
}

fn scopeMatches(rule: Rule, identity: Identity) bool {
    if (rule.pattern) return true;
    if (rule.username) |expected| {
        const username = identity.username orelse return false;
        return std.mem.eql(u8, username, expected);
    }
    return identity.username == null;
}

fn topicMatchesRule(rule: Rule, identity: Identity, topic: []const u8) bool {
    if (topic.len == 0) return false;
    if (topic[0] == '$' and rule.filter[0] != '$') return false;
    var filter_levels = std.mem.splitScalar(u8, rule.filter, '/');
    var topic_levels = std.mem.splitScalar(u8, topic, '/');
    while (filter_levels.next()) |filter_level| {
        if (std.mem.eql(u8, filter_level, "#")) return true;
        const topic_level = topic_levels.next() orelse return false;
        if (std.mem.eql(u8, filter_level, "+")) continue;
        if (rule.pattern and std.mem.eql(u8, filter_level, "%c")) {
            if (!std.mem.eql(u8, topic_level, identity.client_id)) return false;
            continue;
        }
        if (rule.pattern and std.mem.eql(u8, filter_level, "%u")) {
            const username = identity.username orelse return false;
            if (!std.mem.eql(u8, topic_level, username)) return false;
            continue;
        }
        if (!std.mem.eql(u8, filter_level, topic_level)) return false;
    }
    return topic_levels.next() == null;
}

test "MQTT ACL file applies anonymous user and pattern rules" {
    var acl = try parse(std.testing.allocator,
        \\topic read public/#
        \\topic deny public/private
        \\user alice
        \\topic write devices/alice/#
        \\topic readwrite shared/+
        \\pattern write clients/%c
        \\pattern read users/%u/#
    );
    defer acl.deinit();
    try std.testing.expectEqual(@as(usize, 6), acl.ruleCount());
    try std.testing.expect(acl.allows(.read, .{
        .client_id = "anon",
        .username = null,
    }, "public/status"));
    try std.testing.expect(!acl.allows(.read, .{
        .client_id = "anon",
        .username = null,
    }, "public/private"));
    const alice = Identity{ .client_id = "device-7", .username = "alice" };
    try std.testing.expect(acl.allows(.write, alice, "devices/alice/value"));
    try std.testing.expect(!acl.allows(.read, alice, "devices/alice/value"));
    try std.testing.expect(acl.allows(.read, alice, "shared/value"));
    try std.testing.expect(acl.allows(.write, alice, "clients/device-7"));
    try std.testing.expect(acl.allows(.read, alice, "users/alice/value"));
    try std.testing.expect(!acl.allows(.read, alice, "public/status"));
    try std.testing.expect(acl.allows(.write, .{
        .client_id = "danger+#",
        .username = "alice",
    }, "devices/alice/value"));
    try std.testing.expect(!acl.allows(.write, .{
        .client_id = "danger+#",
        .username = "alice",
    }, "clients/danger+#"));
}

test "MQTT ACL file treats an access-name topic as the default form" {
    var acl = try parse(std.testing.allocator, "topic read\n");
    defer acl.deinit();
    const anonymous = Identity{ .client_id = "anon", .username = null };
    try std.testing.expect(acl.allows(.read, anonymous, "read"));
    try std.testing.expect(acl.allows(.write, anonymous, "read"));
}

test "MQTT ACL file accepts empty rules as default deny" {
    var acl = try parse(std.testing.allocator, "\n# no grants\r\n\t\n");
    defer acl.deinit();
    try std.testing.expectEqual(@as(usize, 0), acl.ruleCount());
    const anonymous = Identity{ .client_id = "anon", .username = null };
    try std.testing.expect(!acl.allows(.read, anonymous, "empty/value"));
    try std.testing.expect(!acl.allows(.write, anonymous, "empty/value"));
    const named = Identity{ .client_id = "named", .username = "user" };
    try std.testing.expect(!acl.allows(.read, named, "empty/value"));
    try std.testing.expect(!acl.allows(.write, named, "empty/value"));
}

test "MQTT ACL file owns rule storage" {
    const allocator = std.testing.allocator;
    const source = try allocator.dupe(
        u8,
        "user alice\ntopic read sensors/#\n",
    );
    defer allocator.free(source);
    var acl = try parse(allocator, source);
    defer acl.deinit();
    @memset(source, 'x');
    try std.testing.expect(acl.allows(.read, .{
        .client_id = "reader",
        .username = "alice",
    }, "sensors/value"));
}

test "MQTT ACL file fails closed" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidDirective,
        parse(allocator, "include other.acl\n"),
    );
    try std.testing.expectError(
        error.InvalidAccess,
        parse(allocator, "topic execute sensors/#\n"),
    );
    try std.testing.expectError(
        error.InvalidPattern,
        parse(allocator, "pattern read users/prefix-%u/#\n"),
    );
    try std.testing.expectError(
        error.InvalidSubscription,
        parse(allocator, "topic read broken/#/tail\n"),
    );
    try std.testing.expectError(
        error.InvalidPattern,
        parse(allocator, "pattern read public/#\n"),
    );
}

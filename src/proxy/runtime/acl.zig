//! Ordered destination ACL for proxy servers.
//!
//! Rules are evaluated in order and the first matching rule decides the
//! request. The default action is deny so a server that has not been given an
//! explicit allow list cannot become an open proxy. IP rules are evaluated
//! against resolved destination addresses; domain rules are evaluated against
//! the untrusted textual authority.

const std = @import("std");

const net = std.Io.net;

pub const Action = enum { allow, deny };

pub const Command = enum {
    connect,
    bind,
    udp_associate,
};

pub const CommandSet = struct {
    bits: u8 = 0,

    pub const all: CommandSet = .{ .bits = 0b111 };
    pub const none: CommandSet = .{ .bits = 0 };

    pub fn only(command: Command) CommandSet {
        return .{ .bits = @as(u8, 1) << @intFromEnum(command) };
    }

    pub fn with(self: CommandSet, command: Command) CommandSet {
        return .{ .bits = self.bits | only(command).bits };
    }

    pub fn contains(self: CommandSet, command: Command) bool {
        return (self.bits & only(command).bits) != 0;
    }
};

pub const PortRange = struct {
    min: u16 = 0,
    max: u16 = 65535,

    pub fn contains(self: PortRange, port: u16) bool {
        return port >= self.min and port <= self.max;
    }
};

pub const Family = enum { ip4, ip6 };

pub const IpCidr = struct {
    family: Family,
    network: [16]u8,
    prefix: u8,

    pub const ParseError = error{ InvalidCidr, UnsupportedAddressFamily };

    pub fn parse(text: []const u8) ParseError!IpCidr {
        const slash = std.mem.findScalar(u8, text, '/');
        const address_text = if (slash) |index| text[0..index] else text;
        const prefix_text: ?[]const u8 = if (slash) |index|
            text[index + 1 ..]
        else
            null;
        if (address_text.len == 0) return error.InvalidCidr;

        const address = net.IpAddress.parse(address_text, 0) catch
            return error.InvalidCidr;
        return switch (address) {
            .ip4 => |ip4| blk: {
                const prefix: u8 = if (prefix_text) |value|
                    std.fmt.parseInt(u8, value, 10) catch
                        return error.InvalidCidr
                else
                    32;
                if (prefix > 32) return error.InvalidCidr;
                var network = [_]u8{0} ** 16;
                @memcpy(network[0..4], &ip4.bytes);
                maskBytes(&network, prefix);
                break :blk .{
                    .family = .ip4,
                    .network = network,
                    .prefix = prefix,
                };
            },
            .ip6 => |ip6| blk: {
                const prefix: u8 = if (prefix_text) |value|
                    std.fmt.parseInt(u8, value, 10) catch
                        return error.InvalidCidr
                else
                    128;
                if (prefix > 128) return error.InvalidCidr;
                var network = ip6.bytes;
                maskBytes(&network, prefix);
                break :blk .{
                    .family = .ip6,
                    .network = network,
                    .prefix = prefix,
                };
            },
        };
    }

    pub fn matches(self: IpCidr, address: net.IpAddress) bool {
        return switch (address) {
            .ip4 => |ip4| blk: {
                if (self.family != .ip4) break :blk false;
                var bytes = [_]u8{0} ** 16;
                @memcpy(bytes[0..4], &ip4.bytes);
                maskBytes(&bytes, self.prefix);
                break :blk std.mem.eql(u8, bytes[0..4], self.network[0..4]);
            },
            .ip6 => |ip6| blk: {
                if (self.family != .ip6) break :blk false;
                var bytes = ip6.bytes;
                maskBytes(&bytes, self.prefix);
                break :blk std.mem.eql(u8, &bytes, &self.network);
            },
        };
    }
};

fn maskBytes(bytes: *[16]u8, prefix: u8) void {
    var remaining = prefix;
    for (bytes, 0..) |*byte, index| {
        if (remaining >= 8) {
            remaining -= 8;
            continue;
        }
        if (remaining == 0) {
            byte.* = 0;
        } else {
            byte.* &= @as(u8, 0xff) << @intCast(8 - remaining);
            remaining = 0;
        }
        _ = index;
    }
}

pub const DomainMatch = struct {
    pattern: []const u8,
    mode: Mode,

    pub const Mode = enum { exact, suffix };

    pub const ParseError = error{InvalidDomainPattern};

    pub fn parse(text: []const u8) ParseError!DomainMatch {
        if (text.len == 0) return error.InvalidDomainPattern;
        if (std.mem.startsWith(u8, text, "*.")) {
            if (text.len == 2) return error.InvalidDomainPattern;
            return .{ .pattern = text[2..], .mode = .suffix };
        }
        if (text[0] == '.') {
            if (text.len == 1) return error.InvalidDomainPattern;
            return .{ .pattern = text[1..], .mode = .suffix };
        }
        return .{ .pattern = text, .mode = .exact };
    }

    pub fn matches(self: DomainMatch, host: []const u8) bool {
        return switch (self.mode) {
            .exact => std.ascii.eqlIgnoreCase(self.pattern, host),
            .suffix => blk: {
                if (host.len < self.pattern.len) break :blk false;
                const tail = host[host.len - self.pattern.len ..];
                if (!std.ascii.eqlIgnoreCase(self.pattern, tail)) break :blk false;
                if (host.len == self.pattern.len) break :blk true;
                break :blk host[host.len - self.pattern.len - 1] == '.';
            },
        };
    }
};

pub const Matcher = union(enum) {
    any,
    ip: IpCidr,
    domain: DomainMatch,
};

pub const Rule = struct {
    action: Action,
    matcher: Matcher = .any,
    ports: PortRange = .{},
    commands: CommandSet = .all,

    pub fn matchesIp(
        self: Rule,
        address: net.IpAddress,
        port: u16,
        command: Command,
    ) bool {
        if (!self.ports.contains(port) or !self.commands.contains(command)) {
            return false;
        }
        return switch (self.matcher) {
            .any => true,
            .ip => |cidr| cidr.matches(address),
            .domain => false,
        };
    }

    pub fn matchesDomain(
        self: Rule,
        host: []const u8,
        port: u16,
        command: Command,
    ) bool {
        if (!self.ports.contains(port) or !self.commands.contains(command)) {
            return false;
        }
        return switch (self.matcher) {
            .any => true,
            .ip => false,
            .domain => |domain| domain.matches(host),
        };
    }
};

pub const Policy = struct {
    rules: []const Rule = &.{},
    default_action: Action = .deny,

    /// First-match decision for a textual destination, or null when no domain
    /// or catch-all rule matched.
    pub fn evaluateDomain(
        self: Policy,
        host: []const u8,
        port: u16,
        command: Command,
    ) ?Action {
        for (self.rules) |rule| {
            if (rule.matchesDomain(host, port, command)) return rule.action;
        }
        return null;
    }

    /// First-match decision for a resolved destination address, or null when
    /// no IP or catch-all rule matched.
    pub fn evaluateIp(
        self: Policy,
        address: net.IpAddress,
        port: u16,
        command: Command,
    ) ?Action {
        for (self.rules) |rule| {
            if (rule.matchesIp(address, port, command)) return rule.action;
        }
        return null;
    }

    pub fn decideIp(
        self: Policy,
        address: net.IpAddress,
        port: u16,
        command: Command,
    ) Action {
        return self.evaluateIp(address, port, command) orelse
            self.default_action;
    }

    pub fn decideDomain(
        self: Policy,
        host: []const u8,
        port: u16,
        command: Command,
    ) Action {
        return self.evaluateDomain(host, port, command) orelse
            self.default_action;
    }
};

pub const ValidationError = error{
    InvalidCidr,
    UnsupportedAddressFamily,
    InvalidDomainPattern,
};

/// Parse a textual matcher (`*`, `0.0.0.0/8`, `*.example.com`).
pub fn parseMatcher(text: []const u8) ValidationError!Matcher {
    if (std.mem.eql(u8, text, "*")) return .any;
    if (std.mem.findScalar(u8, text, '/') != null) {
        return .{ .ip = try IpCidr.parse(text) };
    }
    if (std.mem.startsWith(u8, text, "*.") or
        std.mem.startsWith(u8, text, "."))
    {
        return .{ .domain = try DomainMatch.parse(text) };
    }
    if (net.IpAddress.parse(text, 0)) |_| {
        return .{ .ip = try IpCidr.parse(text) };
    } else |_| {}
    return .{ .domain = try DomainMatch.parse(text) };
}

test "ACL defaults to deny" {
    const policy = Policy{};
    const loopback = net.IpAddress{ .ip4 = .{
        .bytes = .{ 127, 0, 0, 1 },
        .port = 80,
    } };
    try std.testing.expectEqual(
        Action.deny,
        policy.decideIp(loopback, 80, .connect),
    );
    try std.testing.expectEqual(
        Action.deny,
        policy.decideDomain("example.com", 80, .connect),
    );
}

test "ACL evaluates CIDR ports commands and first-match order" {
    const rules = [_]Rule{
        .{
            .action = .allow,
            .matcher = .{ .ip = try IpCidr.parse("10.0.0.0/8") },
            .ports = .{ .min = 80, .max = 443 },
            .commands = CommandSet.only(.connect),
        },
        .{
            .action = .deny,
            .matcher = .{ .ip = try IpCidr.parse("10.0.0.0/8") },
        },
        .{
            .action = .deny,
            .matcher = .{ .ip = try IpCidr.parse("0.0.0.0/0") },
        },
    };
    const policy = Policy{ .rules = &rules };
    const private = net.IpAddress{ .ip4 = .{
        .bytes = .{ 10, 1, 2, 3 },
        .port = 0,
    } };
    const public = net.IpAddress{ .ip4 = .{
        .bytes = .{ 192, 0, 2, 1 },
        .port = 0,
    } };

    try std.testing.expectEqual(
        Action.allow,
        policy.decideIp(private, 80, .connect),
    );
    try std.testing.expectEqual(
        Action.deny,
        policy.decideIp(private, 22, .connect),
    );
    try std.testing.expectEqual(
        Action.deny,
        policy.decideIp(private, 80, .bind),
    );
    try std.testing.expectEqual(
        Action.deny,
        policy.decideIp(public, 80, .connect),
    );
}

test "ACL matches IPv6 CIDRs" {
    const rules = [_]Rule{.{
        .action = .allow,
        .matcher = .{ .ip = try IpCidr.parse("2001:db8::/32") },
        .commands = CommandSet.only(.connect),
    }};
    const policy = Policy{ .rules = &rules };
    const inside = net.IpAddress{ .ip6 = .{
        .bytes = .{
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
            0,    0,    0,    0,    0, 0, 0, 1,
        },
        .port = 0,
        .flow = 0,
        .interface = .none,
    } };
    const outside = net.IpAddress{ .ip6 = .{
        .bytes = .{
            0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0,
            0,    0,    0,    0,    0, 0, 0, 1,
        },
        .port = 0,
        .flow = 0,
        .interface = .none,
    } };
    try std.testing.expectEqual(Action.allow, policy.decideIp(inside, 443, .connect));
    try std.testing.expectEqual(Action.deny, policy.decideIp(outside, 443, .connect));
}

test "ACL domain matchers are case-insensitive and bounded" {
    const exact = try DomainMatch.parse("example.com");
    try std.testing.expect(exact.matches("example.com"));
    try std.testing.expect(exact.matches("EXAMPLE.COM"));
    try std.testing.expect(!exact.matches("evil.example.com"));

    const suffix = try DomainMatch.parse("*.example.com");
    try std.testing.expect(suffix.matches("api.example.com"));
    try std.testing.expect(suffix.matches("example.com"));
    try std.testing.expect(!suffix.matches("notexample.com"));
    try std.testing.expect(!suffix.matches("example.com.evil"));

    const rules = [_]Rule{
        .{
            .action = .deny,
            .matcher = .{ .domain = try DomainMatch.parse("*.internal") },
        },
        .{
            .action = .allow,
            .matcher = .any,
        },
    };
    const policy = Policy{ .rules = &rules };
    try std.testing.expectEqual(
        Action.deny,
        policy.decideDomain("db.internal", 443, .connect),
    );
    try std.testing.expectEqual(
        Action.allow,
        policy.decideDomain("origin.example", 443, .connect),
    );
}

test "matcher parsing rejects malformed CIDRs" {
    try std.testing.expectError(error.InvalidCidr, parseMatcher("10.0.0.0/33"));
    try std.testing.expectError(error.InvalidCidr, parseMatcher("::/129"));
    try std.testing.expectError(error.InvalidCidr, parseMatcher("not-an-ip/8"));
    const matcher = try parseMatcher("192.0.2.0/24");
    try std.testing.expectEqual(Family.ip4, matcher.ip.family);
    try std.testing.expectEqual(@as(u8, 24), matcher.ip.prefix);
}

//! SOCKS authentication policy and RFC 1929 credential verification.

const std = @import("std");
const codec = @import("codec.zig");

pub const max_username_len: usize = 255;
pub const max_password_len: usize = 255;

pub const Error = error{
    InvalidCredentials,
};

pub const Entry = struct {
    username: []const u8,
    password: []const u8,
};

/// Caller-owned authentication callback. Implementations must be thread-safe
/// when the server accepts concurrently.
pub const Authenticator = struct {
    context: *anyopaque,
    verify: *const fn (
        context: *anyopaque,
        username: []const u8,
        password: []const u8,
    ) bool,

    pub fn verifyCredentials(
        self: Authenticator,
        username: []const u8,
        password: []const u8,
    ) bool {
        if (!validField(username) or !validField(password)) return false;
        return self.verify(self.context, username, password);
    }
};

/// Bounded in-memory credential table.
pub const Static = struct {
    entries: []const Entry,

    pub fn init(entries: []const Entry) Error!Static {
        for (entries) |entry| {
            if (!validField(entry.username) or !validField(entry.password)) {
                return error.InvalidCredentials;
            }
        }
        return .{ .entries = entries };
    }

    pub fn authenticator(self: *const Static) Authenticator {
        return .{
            .context = @ptrCast(@constCast(self)),
            .verify = verifyEntryTable,
        };
    }

    pub fn verify(self: *const Static, username: []const u8, password: []const u8) bool {
        if (!validField(username) or !validField(password)) return false;
        return verifyEntryTable(@ptrCast(@constCast(self)), username, password);
    }
};

fn verifyEntryTable(
    context: *anyopaque,
    username: []const u8,
    password: []const u8,
) bool {
    const table: *const Static = @ptrCast(@alignCast(context));
    var matched = false;
    for (table.entries) |entry| {
        // Visit every entry and both fields so a matching username does not
        // create a shorter observable path than a mismatching one.
        const username_match = timingSafeEql(username, entry.username);
        const password_match = timingSafeEql(password, entry.password);
        matched = matched or (username_match and password_match);
    }
    return matched;
}

fn timingSafeEql(a: []const u8, b: []const u8) bool {
    // Length is treated as public metadata. Once lengths agree, every byte
    // is visited without a data-dependent early exit.
    if (a.len != b.len) return false;
    var difference: u8 = 0;
    for (a, b) |lhs, rhs| difference |= lhs ^ rhs;
    return difference == 0;
}

fn validField(value: []const u8) bool {
    return value.len > 0 and value.len <= 255;
}

pub const Policy = struct {
    /// Anonymous access is opt-in. When false and no authenticator is
    /// configured, every SOCKS5 connection is rejected.
    allow_anonymous: bool = false,
    authenticator: ?Authenticator = null,

    pub fn requiresAuthentication(self: Policy) bool {
        return self.authenticator != null;
    }
};

pub const Selection = enum {
    none,
    username_password,
    reject,
};

/// Choose one offered method without permitting an authentication downgrade.
/// A configured authenticator wins whenever the client offers it.
pub fn selectMethod(methods: []const u8, policy: Policy) Selection {
    const offers_username_password = std.mem.indexOfScalar(
        u8,
        methods,
        @intFromEnum(codec.Method.username_password),
    ) != null;
    const offers_none = std.mem.indexOfScalar(
        u8,
        methods,
        @intFromEnum(codec.Method.none),
    ) != null;

    if (policy.authenticator != null and offers_username_password) {
        return .username_password;
    }
    if (policy.allow_anonymous and offers_none) return .none;
    return .reject;
}

test "static credentials verify without early exit behavior" {
    const entries = [_]Entry{
        .{ .username = "alice", .password = "correct horse" },
        .{ .username = "bob", .password = "battery staple" },
    };
    const table = try Static.init(&entries);
    try std.testing.expect(table.verify("alice", "correct horse"));
    try std.testing.expect(table.verify("bob", "battery staple"));
    try std.testing.expect(!table.verify("alice", "wrong"));
    try std.testing.expect(!table.verify("carol", "correct horse"));
    try std.testing.expect(!table.verify("alice", ""));
    try std.testing.expect(!table.verify("", "correct horse"));
}

test "static credentials reject out-of-range entries" {
    const empty = [_]Entry{.{ .username = "", .password = "x" }};
    try std.testing.expectError(error.InvalidCredentials, Static.init(&empty));
    var long_name: [256]u8 = @splat('a');
    const too_long = [_]Entry{.{ .username = &long_name, .password = "x" }};
    try std.testing.expectError(error.InvalidCredentials, Static.init(&too_long));
}

test "method selection prevents anonymous downgrade" {
    const methods_offer_both = [_]u8{ 0x00, 0x02 };
    const methods_offer_none = [_]u8{0x00};
    const methods_offer_auth = [_]u8{0x02};
    const methods_offer_unknown = [_]u8{0x80};

    var table = try Static.init(&[_]Entry{
        .{ .username = "user", .password = "secret" },
    });
    const auth = table.authenticator();
    const required = Policy{ .authenticator = auth, .allow_anonymous = false };

    try std.testing.expectEqual(
        Selection.username_password,
        selectMethod(&methods_offer_both, required),
    );
    try std.testing.expectEqual(
        Selection.reject,
        selectMethod(&methods_offer_none, required),
    );
    try std.testing.expectEqual(
        Selection.username_password,
        selectMethod(&methods_offer_auth, required),
    );

    const anonymous = Policy{ .allow_anonymous = true };
    try std.testing.expectEqual(
        Selection.none,
        selectMethod(&methods_offer_both, anonymous),
    );
    try std.testing.expectEqual(
        Selection.none,
        selectMethod(&methods_offer_none, anonymous),
    );
    try std.testing.expectEqual(
        Selection.reject,
        selectMethod(&methods_offer_unknown, anonymous),
    );

    const closed = Policy{ .allow_anonymous = false };
    try std.testing.expectEqual(
        Selection.reject,
        selectMethod(&methods_offer_none, closed),
    );
    try std.testing.expectEqual(
        Selection.reject,
        selectMethod(&methods_offer_auth, closed),
    );
}

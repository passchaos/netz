//! Strict reader and verifier for Mosquitto password files.
//!
//! Only hashed credentials are accepted. Current Argon2id entries, `$7$`
//! PBKDF2-SHA512 entries, and legacy `$6$` salted SHA-512 entries are decoded
//! at load time. Malformed, duplicate, plaintext, or excessively expensive
//! entries fail closed before a listener is opened.

const std = @import("std");
const mqtt = @import("mod.zig");

pub const max_file_bytes: usize = 1024 * 1024;
pub const max_users: usize = 4096;
pub const max_pbkdf2_iterations: u32 = 1_000_000;
pub const max_argon2_memory_kib: u32 = 64 * 1024;
pub const max_argon2_time_cost: u32 = 4;
pub const max_argon2_parallelism: u24 = 4;

const digest_length = std.crypto.hash.sha2.Sha512.digest_length;
const max_salt_length = 64;

pub const Error = mqtt.Error || std.mem.Allocator.Error || error{
    EmptyPasswordFile,
    TooManyUsers,
    DuplicateUser,
    InvalidEntry,
    UnsupportedHash,
    InvalidHash,
    ExpensiveHash,
};

const Decoded = struct {
    salt: [max_salt_length]u8 = [_]u8{0} ** max_salt_length,
    salt_len: u8,
    hash: [digest_length]u8 = [_]u8{0} ** digest_length,
    hash_len: u8,
};

comptime {
    if (digest_length != 64 or max_salt_length > std.math.maxInt(u8)) {
        @compileError("password-file storage widths need updating");
    }
}

const Sha512 = struct {
    decoded: Decoded,
};

const Pbkdf2Sha512 = struct {
    iterations: u32,
    decoded: Decoded,
};

const Argon2id = struct {
    memory_kib: u32,
    time_cost: u32,
    parallelism: u24,
    decoded: Decoded,
};

const Hash = union(enum) {
    sha512: Sha512,
    pbkdf2_sha512: Pbkdf2Sha512,
    argon2id: Argon2id,
};

const Entry = struct {
    username: []const u8,
    hash: Hash,
};

pub const File = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []u8,
    entries: []Entry,
    index: std.StringHashMapUnmanaged(usize),
    verify_mutex: std.Io.Mutex = .init,

    pub fn deinit(self: *File) void {
        self.index.deinit(self.allocator);
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(self.entries));
        self.allocator.free(self.entries);
        std.crypto.secureZero(u8, self.source);
        self.allocator.free(self.source);
        self.* = undefined;
    }

    pub fn userCount(self: File) usize {
        return self.entries.len;
    }

    /// Return whether `other` contains the same parsed credential for one
    /// username. This compares the algorithm, work factors, salt, and digest;
    /// comments, ordering, and unrelated users do not force a live client to
    /// reconnect after an atomic password-file reload.
    pub fn sameCredential(
        self: *const File,
        other: *const File,
        username: []const u8,
    ) bool {
        const left = self.index.get(username) orelse return false;
        const right = other.index.get(username) orelse return false;
        return std.meta.eql(
            self.entries[left].hash,
            other.entries[right].hash,
        );
    }

    /// Verify one complete MQTT username/password pair. Unknown usernames,
    /// missing passwords, and internal KDF failures all return false. Expensive
    /// password computations are serialized so concurrent CONNECT attempts
    /// cannot multiply the configured memory cost.
    pub fn verify(
        self: *File,
        username: []const u8,
        password: []const u8,
    ) bool {
        if (std.mem.findScalar(u8, password, 0) != null) return false;
        const entry_index = self.index.get(username) orelse return false;
        self.verify_mutex.lockUncancelable(self.io);
        defer self.verify_mutex.unlock(self.io);
        return verifyHash(
            self.allocator,
            self.io,
            self.entries[entry_index].hash,
            password,
        );
    }
};

/// Listener-local Mosquitto authentication policy. Anonymous clients are
/// admitted only when configured. A client that presents a username must
/// provide a matching password even on an anonymous-capable listener.
pub const Authorization = struct {
    passwords: *File,
    allow_anonymous: bool,

    pub fn authorize(context: *anyopaque, connect: mqtt.Connect) bool {
        const self: *Authorization = @ptrCast(@alignCast(context));
        const username = connect.username orelse return self.allow_anonymous;
        const password = connect.password orelse return false;
        return self.passwords.verify(username, password);
    }
};

pub fn parse(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: []const u8,
) Error!File {
    if (source.len == 0) return error.EmptyPasswordFile;
    if (source.len > max_file_bytes) return error.InvalidEntry;
    const owned_source = try allocator.dupe(u8, source);
    errdefer {
        std.crypto.secureZero(u8, owned_source);
        allocator.free(owned_source);
    }
    var entries: std.ArrayList(Entry) = .empty;
    defer {
        std.crypto.secureZero(u8, std.mem.sliceAsBytes(entries.items));
        entries.deinit(allocator);
    }
    var index: std.StringHashMapUnmanaged(usize) = .empty;
    errdefer index.deinit(allocator);

    var lines = std.mem.splitScalar(u8, owned_source, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const separator = std.mem.findScalar(u8, line, ':') orelse
            return error.InvalidEntry;
        if (std.mem.findScalar(u8, line[separator + 1 ..], ':') != null) {
            return error.InvalidEntry;
        }
        const username = std.mem.trim(u8, line[0..separator], " \t");
        const encoded = std.mem.trim(u8, line[separator + 1 ..], " \t");
        if (username.len == 0 or username.len > std.math.maxInt(u16) or
            encoded.len == 0 or encoded.len > std.math.maxInt(u16))
        {
            return error.InvalidEntry;
        }
        try mqtt.validateUtf8String(username);
        if (index.contains(username)) return error.DuplicateUser;
        if (entries.items.len == max_users) return error.TooManyUsers;
        const hash = try parseHash(encoded);
        const entry_index = entries.items.len;
        try entries.append(allocator, .{
            .username = username,
            .hash = hash,
        });
        try index.put(allocator, username, entry_index);
    }
    if (entries.items.len == 0) return error.EmptyPasswordFile;
    return .{
        .allocator = allocator,
        .io = io,
        .source = owned_source,
        .entries = try entries.toOwnedSlice(allocator),
        .index = index,
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
    defer {
        std.crypto.secureZero(u8, source);
        allocator.free(source);
    }
    if (source.len > max_file_bytes) return error.InvalidEntry;
    return parse(allocator, io, source);
}

fn parseHash(encoded: []const u8) Error!Hash {
    if (std.mem.startsWith(u8, encoded, "$7$")) {
        var fields = std.mem.splitScalar(u8, encoded[3..], '$');
        const iterations_text = fields.next() orelse return error.InvalidHash;
        const salt_text = fields.next() orelse return error.InvalidHash;
        const hash_text = fields.next() orelse return error.InvalidHash;
        if (fields.next() != null) return error.InvalidHash;
        const iterations = std.fmt.parseInt(
            u32,
            iterations_text,
            10,
        ) catch return error.InvalidHash;
        if (iterations == 0) return error.InvalidHash;
        if (iterations > max_pbkdf2_iterations) return error.ExpensiveHash;
        return .{ .pbkdf2_sha512 = .{
            .iterations = iterations,
            .decoded = try decodeSaltAndHash(salt_text, hash_text, true),
        } };
    }
    if (std.mem.startsWith(u8, encoded, "$6$")) {
        var fields = std.mem.splitScalar(u8, encoded[3..], '$');
        const salt_text = fields.next() orelse return error.InvalidHash;
        const hash_text = fields.next() orelse return error.InvalidHash;
        if (fields.next() != null) return error.InvalidHash;
        return .{ .sha512 = .{
            .decoded = try decodeSaltAndHash(salt_text, hash_text, true),
        } };
    }
    if (std.mem.startsWith(u8, encoded, "$argon2id$")) {
        return .{ .argon2id = try parseArgon2id(encoded) };
    }
    return error.UnsupportedHash;
}

fn parseArgon2id(encoded: []const u8) Error!Argon2id {
    var fields = std.mem.splitScalar(u8, encoded, '$');
    if ((fields.next() orelse return error.InvalidHash).len != 0 or
        !std.mem.eql(u8, fields.next() orelse return error.InvalidHash, "argon2id") or
        !std.mem.eql(u8, fields.next() orelse return error.InvalidHash, "v=19"))
    {
        return error.InvalidHash;
    }
    const parameters = fields.next() orelse return error.InvalidHash;
    const salt_text = fields.next() orelse return error.InvalidHash;
    const hash_text = fields.next() orelse return error.InvalidHash;
    if (fields.next() != null) return error.InvalidHash;

    var memory_kib: ?u32 = null;
    var time_cost: ?u32 = null;
    var parallelism: ?u24 = null;
    var values = std.mem.splitScalar(u8, parameters, ',');
    while (values.next()) |value| {
        const separator = std.mem.findScalar(u8, value, '=') orelse
            return error.InvalidHash;
        const name = value[0..separator];
        const number = value[separator + 1 ..];
        if (std.mem.eql(u8, name, "m")) {
            if (memory_kib != null) return error.InvalidHash;
            memory_kib = std.fmt.parseInt(u32, number, 10) catch
                return error.InvalidHash;
        } else if (std.mem.eql(u8, name, "t")) {
            if (time_cost != null) return error.InvalidHash;
            time_cost = std.fmt.parseInt(u32, number, 10) catch
                return error.InvalidHash;
        } else if (std.mem.eql(u8, name, "p")) {
            if (parallelism != null) return error.InvalidHash;
            parallelism = std.fmt.parseInt(u24, number, 10) catch
                return error.InvalidHash;
        } else {
            return error.InvalidHash;
        }
    }
    const m = memory_kib orelse return error.InvalidHash;
    const t = time_cost orelse return error.InvalidHash;
    const p = parallelism orelse return error.InvalidHash;
    if (m < 8 or t == 0 or p == 0 or m / 8 < p) return error.InvalidHash;
    if (m > max_argon2_memory_kib or t > max_argon2_time_cost or
        p > max_argon2_parallelism)
    {
        return error.ExpensiveHash;
    }
    return .{
        .memory_kib = m,
        .time_cost = t,
        .parallelism = p,
        .decoded = try decodeSaltAndHash(salt_text, hash_text, false),
    };
}

fn decodeSaltAndHash(
    salt_text: []const u8,
    hash_text: []const u8,
    padded: bool,
) Error!Decoded {
    const decoder = if (padded)
        std.base64.standard.Decoder
    else
        std.base64.standard_no_pad.Decoder;
    const salt_len = decoder.calcSizeForSlice(salt_text) catch
        return error.InvalidHash;
    const hash_len = decoder.calcSizeForSlice(hash_text) catch
        return error.InvalidHash;
    if (padded) {
        if ((salt_len != 12 and salt_len != max_salt_length) or
            hash_len != digest_length)
        {
            return error.InvalidHash;
        }
    } else {
        if (salt_len < 8 or salt_len > max_salt_length or
            hash_len < 4 or hash_len > digest_length)
        {
            return error.InvalidHash;
        }
    }
    var result = Decoded{
        .salt_len = @intCast(salt_len),
        .hash_len = @intCast(hash_len),
    };
    decoder.decode(result.salt[0..salt_len], salt_text) catch
        return error.InvalidHash;
    decoder.decode(result.hash[0..hash_len], hash_text) catch
        return error.InvalidHash;
    return result;
}

fn verifyHash(
    allocator: std.mem.Allocator,
    io: std.Io,
    hash: Hash,
    password: []const u8,
) bool {
    var computed = [_]u8{0} ** digest_length;
    defer std.crypto.secureZero(u8, &computed);
    const decoded = switch (hash) {
        .sha512 => |value| blk: {
            var hasher = std.crypto.hash.sha2.Sha512.init(.{});
            hasher.update(password);
            hasher.update(value.decoded.salt[0..value.decoded.salt_len]);
            hasher.final(&computed);
            break :blk value.decoded;
        },
        .pbkdf2_sha512 => |value| blk: {
            std.crypto.pwhash.pbkdf2(
                &computed,
                password,
                value.decoded.salt[0..value.decoded.salt_len],
                value.iterations,
                std.crypto.auth.hmac.sha2.HmacSha512,
            ) catch return false;
            break :blk value.decoded;
        },
        .argon2id => |value| blk: {
            std.crypto.pwhash.argon2.kdf(
                allocator,
                computed[0..value.decoded.hash_len],
                password,
                value.decoded.salt[0..value.decoded.salt_len],
                .{
                    .t = value.time_cost,
                    .m = value.memory_kib,
                    .p = value.parallelism,
                },
                .argon2id,
                io,
            ) catch return false;
            break :blk value.decoded;
        },
    };
    return std.crypto.timing_safe.eql(
        [digest_length]u8,
        computed,
        decoded.hash,
    );
}

fn expectPassword(
    source: []const u8,
    username: []const u8,
) !void {
    var passwords = try parse(std.testing.allocator, std.testing.io, source);
    defer passwords.deinit();
    try std.testing.expect(passwords.verify(username, "password"));
    try std.testing.expect(!passwords.verify(username, "wrong"));
    try std.testing.expect(!passwords.verify("unknown", "password"));
}

test "MQTT password file verifies Mosquitto legacy SHA-512" {
    try expectPassword(
        "legacy:$6$MDEyMzQ1Njc4OWFi$" ++
            "QQ3PWSJ3IyGPP66YMDh3aUdVyS29efC2oPtFLnz5O/EXQO4dovrApaaZv32acQ3b0Lt02H8GBYcsYpkBYYcERg==\n",
        "legacy",
    );
}

test "MQTT password file verifies Mosquitto PBKDF2-SHA512" {
    try expectPassword(
        "pbkdf2:$7$1000$MDEyMzQ1Njc4OWFi$" ++
            "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+KMfRf9YJT//3a9+kZTXUdA==\n",
        "pbkdf2",
    );
}

test "MQTT password file verifies Mosquitto Argon2id" {
    try expectPassword(
        "argon:$argon2id$v=19$m=32,t=2,p=1$" ++
            "MDEyMzQ1Njc4OWFiY2RlZg$hoITHlJQ9BQSDFM3EJP0xeU50GBsmMtcLnThmLoiluM\n",
        "argon",
    );
}

test "MQTT password file compares one parsed credential across reloads" {
    const allocator = std.testing.allocator;
    const hash = "$7$1000$MDEyMzQ1Njc4OWFi$" ++
        "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+" ++
        "KMfRf9YJT//3a9+kZTXUdA==";
    const changed = "$6$MDEyMzQ1Njc4OWFi$" ++
        "QQ3PWSJ3IyGPP66YMDh3aUdVyS29efC2oPtFLnz5O/EXQO4dovrApaaZv32acQ3b" ++
        "0Lt02H8GBYcsYpkBYYcERg==";
    var first = try parse(
        allocator,
        std.testing.io,
        "# first ordering\nuser:" ++ hash ++ "\nother:" ++ changed ++ "\n",
    );
    defer first.deinit();
    var second = try parse(
        allocator,
        std.testing.io,
        "other:" ++ changed ++ "\n# reordered\nuser:" ++ hash ++ "\n",
    );
    defer second.deinit();
    var replacement = try parse(
        allocator,
        std.testing.io,
        "user:" ++ changed ++ "\n",
    );
    defer replacement.deinit();

    try std.testing.expect(first.sameCredential(&second, "user"));
    try std.testing.expect(first.sameCredential(&second, "other"));
    try std.testing.expect(!first.sameCredential(&second, "missing"));
    try std.testing.expect(!first.sameCredential(&replacement, "user"));
    try std.testing.expect(!first.sameCredential(&replacement, "other"));
}

test "MQTT password file fails closed and owns its input" {
    const allocator = std.testing.allocator;
    const hash = "$7$1000$MDEyMzQ1Njc4OWFi$" ++
        "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+" ++
        "KMfRf9YJT//3a9+kZTXUdA==";
    const source = try std.fmt.allocPrint(allocator, "user:{s}\n", .{hash});
    defer allocator.free(source);
    var passwords = try parse(allocator, std.testing.io, source);
    defer passwords.deinit();
    @memset(source, 'x');
    try std.testing.expect(passwords.verify("user", "password"));
    try std.testing.expect(!passwords.verify("user", "pass\x00word"));

    try std.testing.expectError(
        error.UnsupportedHash,
        parse(allocator, std.testing.io, "user:plaintext\n"),
    );
    try std.testing.expectError(
        error.DuplicateUser,
        parse(allocator, std.testing.io,
            \\user:$6$MDEyMzQ1Njc4OWFi$QQ3PWSJ3IyGPP66YMDh3aUdVyS29efC2oPtFLnz5O/EXQO4dovrApaaZv32acQ3b0Lt02H8GBYcsYpkBYYcERg==
            \\user:$6$MDEyMzQ1Njc4OWFi$QQ3PWSJ3IyGPP66YMDh3aUdVyS29efC2oPtFLnz5O/EXQO4dovrApaaZv32acQ3b0Lt02H8GBYcsYpkBYYcERg==
        ),
    );
    try std.testing.expectError(
        error.ExpensiveHash,
        parse(
            allocator,
            std.testing.io,
            "user:$argon2id$v=19$m=65537,t=1,p=1$" ++
                "MDEyMzQ1Njc4OWFiY2RlZg$hoITHlJQ9BQSDFM3EJP0xeU50GBsmMtcLnThmLoiluM\n",
        ),
    );
    try std.testing.expectError(
        error.ExpensiveHash,
        parse(
            allocator,
            std.testing.io,
            "user:$7$1000001$MDEyMzQ1Njc4OWFi$" ++
                "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+" ++
                "KMfRf9YJT//3a9+kZTXUdA==\n",
        ),
    );
}

test "MQTT password-file authorization preserves anonymous policy" {
    const allocator = std.testing.allocator;
    const source = "user:$7$1000$MDEyMzQ1Njc4OWFi$" ++
        "c9YpKMKKFXo4iKjCHWgIKvbTAC0Q4UwNh03D5+1WeU4qgE0EqSKzvYKJitoqJI1+" ++
        "KMfRf9YJT//3a9+kZTXUdA==\n";
    var passwords = try parse(allocator, std.testing.io, source);
    defer passwords.deinit();
    var policy = Authorization{
        .passwords = &passwords,
        .allow_anonymous = true,
    };
    const anonymous = mqtt.Connect{
        .protocol = .v5,
        .clean_start = true,
        .keep_alive_seconds = 60,
        .client_id = "anonymous",
    };
    try std.testing.expect(Authorization.authorize(&policy, anonymous));
    var supplied = anonymous;
    supplied.username = "user";
    try std.testing.expect(!Authorization.authorize(&policy, supplied));
    supplied.password = "wrong";
    try std.testing.expect(!Authorization.authorize(&policy, supplied));
    supplied.password = "password";
    try std.testing.expect(Authorization.authorize(&policy, supplied));
    policy.allow_anonymous = false;
    try std.testing.expect(!Authorization.authorize(&policy, anonymous));
}

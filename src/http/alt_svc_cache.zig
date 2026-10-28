//! Thread-safe HTTP/3 Alt-Svc cache and failure backoff.
//!
//! Entries are keyed by the authenticated origin, not by the alternative
//! authority. A response advertisement refreshes one HTTP/3 alternative for
//! that origin; `clear`, `ma=0`, or a replacement field without HTTP/3 removes
//! it. Repeated advertisements of the same target preserve failure backoff so
//! a broken QUIC path cannot be retried on every TCP response.

const std = @import("std");
const Guard = @import("../internal/mutex_guard.zig").Guard;
const http3 = @import("../http3/mod.zig");

pub const Error = std.mem.Allocator.Error || error{
    InvalidCacheOptions,
    InvalidHeader,
    InvalidOrigin,
    IntegerOverflow,
};

pub const Config = struct {
    max_entries: usize = 128,
    /// RFC 7838 default when `ma` is absent.
    default_max_age_seconds: u64 = 86_400,
    /// Optional deployment cap for peer-provided `ma` values.
    max_max_age_seconds: ?u64 = null,
    failure_backoff_initial: std.Io.Duration = .fromSeconds(1),
    failure_backoff_max: std.Io.Duration = .fromSeconds(300),
};

pub const UpdateResult = enum {
    unchanged,
    stored,
    removed,
};

pub const Alternative = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    alpn: []u8,
    connect_host: []u8,
    origin_host: []u8,
    port: u16,
    expires_at_ms: u64,
    failure_count: u8,

    pub fn deinit(self: *Alternative) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    pub fn target(self: *const Alternative) http3.AltSvcTarget {
        return .{
            .alpn = self.alpn,
            .connect_host = self.connect_host,
            .origin_host = self.origin_host,
            .port = self.port,
            .max_age = null,
        };
    }
};

pub const Stats = struct {
    entries: usize,
    hits: u64,
    misses: u64,
    backoff_suppressed: u64,
    stored: u64,
    removed: u64,
    evicted: u64,
    expired: u64,
    failures: u64,

    pub fn hitRate(self: Stats) f64 {
        const total = self.hits + self.misses + self.backoff_suppressed;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(self.hits)) /
            @as(f64, @floatFromInt(total));
    }
};

const IndexKey = struct {
    scheme: []const u8,
    host: []const u8,
    port: u16,
};

const IndexContext = struct {
    pub fn hash(_: @This(), key: IndexKey) u64 {
        var hasher = std.hash.Wyhash.init(0);
        updateLower(&hasher, key.scheme);
        hasher.update(&.{0});
        updateLower(&hasher, key.host);
        std.hash.autoHash(&hasher, key.port);
        return hasher.final();
    }

    pub fn eql(_: @This(), lhs: IndexKey, rhs: IndexKey) bool {
        return lhs.port == rhs.port and
            std.ascii.eqlIgnoreCase(lhs.scheme, rhs.scheme) and
            std.ascii.eqlIgnoreCase(lhs.host, rhs.host);
    }

    fn updateLower(hasher: *std.hash.Wyhash, value: []const u8) void {
        var storage: [64]u8 = undefined;
        var offset: usize = 0;
        while (offset < value.len) {
            const len = @min(storage.len, value.len - offset);
            for (value[offset..][0..len], storage[0..len]) |byte, *out| {
                out.* = std.ascii.toLower(byte);
            }
            hasher.update(storage[0..len]);
            offset += len;
        }
    }
};

const Index = std.HashMapUnmanaged(
    IndexKey,
    usize,
    IndexContext,
    std.hash_map.default_max_load_percentage,
);

const Entry = struct {
    storage: []u8,
    origin: http3.Origin,
    alpn: []u8,
    connect_host: []u8,
    origin_host: []u8,
    port: u16,
    expires_at_ms: u64,
    retry_at_ms: u64 = 0,
    failure_count: u8 = 0,
    last_used: u64,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        allocator.free(self.storage);
        self.* = undefined;
    }

    fn sameTarget(self: Entry, target: http3.AltSvcTarget) bool {
        return self.port == target.port and
            std.mem.eql(u8, self.alpn, target.alpn) and
            std.ascii.eqlIgnoreCase(self.connect_host, target.connect_host) and
            std.ascii.eqlIgnoreCase(self.origin_host, target.origin_host);
    }
};

pub const Cache = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    mutex: std.Io.Mutex = .init,
    entries: std.ArrayList(Entry) = .empty,
    index: Index = .empty,
    access_clock: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    backoff_suppressed: u64 = 0,
    total_stored: u64 = 0,
    total_removed: u64 = 0,
    total_evicted: u64 = 0,
    total_expired: u64 = 0,
    total_failures: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        config: Config,
    ) Error!Cache {
        if (config.default_max_age_seconds == 0 or
            config.failure_backoff_initial.nanoseconds <= 0 or
            config.failure_backoff_max.nanoseconds <= 0 or
            config.failure_backoff_initial.nanoseconds >
                config.failure_backoff_max.nanoseconds)
        {
            return error.InvalidCacheOptions;
        }
        if (config.max_max_age_seconds) |maximum| {
            if (maximum == 0) return error.InvalidCacheOptions;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
        };
    }

    pub fn deinit(self: *Cache) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.index.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn clear(self: *Cache) void {
        self.clearBefore(null) catch unreachable;
    }

    pub fn clearBefore(self: *Cache, deadline: ?std.Io.Clock.Timestamp) (std.Io.Cancelable || error{Timeout})!void {
        var guard = try Guard.initBefore(&self.mutex, self.io, deadline);
        defer guard.unlock();
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.clearRetainingCapacity();
        self.index.clearRetainingCapacity();
    }

    pub fn updateFromHeaders(
        self: *Cache,
        origin: http3.Origin,
        headers: anytype,
    ) Error!UpdateResult {
        return self.updateFromHeadersAt(
            origin,
            headers,
            nowMilliseconds(self.io),
        );
    }

    pub fn updateFromHeadersAt(
        self: *Cache,
        origin: http3.Origin,
        headers: anytype,
        now_ms: u64,
    ) Error!UpdateResult {
        try validateOrigin(origin);
        const selection = try selectTarget(origin, headers);
        switch (selection) {
            .absent => return .unchanged,
            .remove => return if (self.removeAtOrigin(origin))
                .removed
            else
                .unchanged,
            .target => |target| {
                const advertised_age = target.max_age orelse
                    self.config.default_max_age_seconds;
                const max_age = if (self.config.max_max_age_seconds) |maximum|
                    @min(advertised_age, maximum)
                else
                    advertised_age;
                if (max_age == 0) {
                    return if (self.removeAtOrigin(origin))
                        .removed
                    else
                        .unchanged;
                }
                if (self.config.max_entries == 0) return .unchanged;
                var entry = try makeEntry(
                    self.allocator,
                    origin,
                    target,
                    saturatingDeadlineSeconds(now_ms, max_age),
                );
                var entry_owned = true;
                defer if (entry_owned) entry.deinit(self.allocator);

                self.mutex.lockUncancelable(self.io);
                defer self.mutex.unlock(self.io);
                _ = self.pruneExpiredLocked(now_ms);
                if (self.index.get(indexKey(origin))) |index| {
                    var previous = &self.entries.items[index];
                    if (previous.sameTarget(target)) {
                        entry.failure_count = previous.failure_count;
                        entry.retry_at_ms = previous.retry_at_ms;
                    }
                    entry.last_used = self.nextAccess();
                    var removed = previous.*;
                    previous.* = entry;
                    entry_owned = false;
                    const stored_key = self.index.getKeyPtr(indexKey(origin)).?;
                    stored_key.* = indexKey(
                        self.entries.items[index].origin,
                    );
                    removed.deinit(self.allocator);
                    self.total_stored +|= 1;
                    return .stored;
                }
                if (self.entries.items.len < self.config.max_entries) {
                    try self.entries.ensureUnusedCapacity(self.allocator, 1);
                    try self.index.ensureUnusedCapacity(self.allocator, 1);
                } else {
                    var evicted = self.removeAtLocked(self.oldestIndex());
                    evicted.deinit(self.allocator);
                    self.total_evicted +|= 1;
                }
                entry.last_used = self.nextAccess();
                const new_index = self.entries.items.len;
                self.entries.appendAssumeCapacity(entry);
                entry_owned = false;
                self.index.putAssumeCapacityNoClobber(
                    indexKey(self.entries.items[new_index].origin),
                    new_index,
                );
                self.total_stored +|= 1;
                return .stored;
            },
        }
    }

    pub fn lookup(
        self: *Cache,
        origin: http3.Origin,
    ) Error!?Alternative {
        return self.lookupAt(origin, nowMilliseconds(self.io));
    }

    pub fn lookupAt(
        self: *Cache,
        origin: http3.Origin,
        now_ms: u64,
    ) Error!?Alternative {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(now_ms);
        const index = self.index.get(indexKey(origin)) orelse {
            self.misses +|= 1;
            return null;
        };
        var entry = &self.entries.items[index];
        if (now_ms < entry.retry_at_ms) {
            self.backoff_suppressed +|= 1;
            return null;
        }
        const total_len = try totalLength(&.{
            entry.alpn,
            entry.connect_host,
            entry.origin_host,
        });
        const storage = try self.allocator.alloc(u8, total_len);
        errdefer self.allocator.free(storage);
        var offset: usize = 0;
        const alpn = copyPart(storage, &offset, entry.alpn, false);
        const connect_host = copyPart(
            storage,
            &offset,
            entry.connect_host,
            false,
        );
        const origin_host = copyPart(
            storage,
            &offset,
            entry.origin_host,
            false,
        );
        entry.last_used = self.nextAccess();
        self.hits +|= 1;
        return .{
            .allocator = self.allocator,
            .storage = storage,
            .alpn = alpn,
            .connect_host = connect_host,
            .origin_host = origin_host,
            .port = entry.port,
            .expires_at_ms = entry.expires_at_ms,
            .failure_count = entry.failure_count,
        };
    }

    pub fn recordFailure(self: *Cache, origin: http3.Origin) bool {
        return self.recordFailureAt(origin, nowMilliseconds(self.io));
    }

    pub fn recordFailureAt(
        self: *Cache,
        origin: http3.Origin,
        now_ms: u64,
    ) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(now_ms);
        const index = self.index.get(indexKey(origin)) orelse return false;
        var entry = &self.entries.items[index];
        entry.failure_count +|= 1;
        entry.retry_at_ms = saturatingAdd(
            now_ms,
            self.failureBackoffMilliseconds(entry.failure_count),
        );
        entry.last_used = self.nextAccess();
        self.total_failures +|= 1;
        return true;
    }

    pub fn recordSuccess(self: *Cache, origin: http3.Origin) bool {
        return self.recordSuccessAt(origin, nowMilliseconds(self.io));
    }

    pub fn recordSuccessAt(
        self: *Cache,
        origin: http3.Origin,
        now_ms: u64,
    ) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(now_ms);
        const index = self.index.get(indexKey(origin)) orelse return false;
        var entry = &self.entries.items[index];
        entry.failure_count = 0;
        entry.retry_at_ms = 0;
        entry.last_used = self.nextAccess();
        return true;
    }

    pub fn remove(self: *Cache, origin: http3.Origin) bool {
        return self.removeAtOrigin(origin);
    }

    pub fn count(self: *Cache) usize {
        return self.countAt(nowMilliseconds(self.io));
    }

    pub fn countAt(self: *Cache, now_ms: u64) usize {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(now_ms);
        return self.entries.items.len;
    }

    pub fn stats(self: *Cache) Stats {
        return self.statsAt(nowMilliseconds(self.io));
    }

    pub fn statsAt(self: *Cache, now_ms: u64) Stats {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        _ = self.pruneExpiredLocked(now_ms);
        return .{
            .entries = self.entries.items.len,
            .hits = self.hits,
            .misses = self.misses,
            .backoff_suppressed = self.backoff_suppressed,
            .stored = self.total_stored,
            .removed = self.total_removed,
            .evicted = self.total_evicted,
            .expired = self.total_expired,
            .failures = self.total_failures,
        };
    }

    fn removeAtOrigin(self: *Cache, origin: http3.Origin) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const index = self.index.get(indexKey(origin)) orelse return false;
        var removed = self.removeAtLocked(index);
        removed.deinit(self.allocator);
        self.total_removed +|= 1;
        return true;
    }

    fn pruneExpiredLocked(self: *Cache, now_ms: u64) usize {
        var removed_count: usize = 0;
        var index: usize = 0;
        while (index < self.entries.items.len) {
            if (now_ms < self.entries.items[index].expires_at_ms) {
                index += 1;
                continue;
            }
            var expired = self.removeAtLocked(index);
            expired.deinit(self.allocator);
            removed_count += 1;
        }
        self.total_expired +|= removed_count;
        return removed_count;
    }

    fn removeAtLocked(self: *Cache, index: usize) Entry {
        const old_len = self.entries.items.len;
        const removed_key = indexKey(self.entries.items[index].origin);
        std.debug.assert(self.index.remove(removed_key));
        const removed = self.entries.swapRemove(index);
        if (index != old_len - 1) {
            const moved_key = indexKey(self.entries.items[index].origin);
            self.index.getPtr(moved_key).?.* = index;
        }
        return removed;
    }

    fn oldestIndex(self: *const Cache) usize {
        std.debug.assert(self.entries.items.len != 0);
        var oldest: usize = 0;
        for (self.entries.items[1..], 1..) |entry, index| {
            if (entry.last_used < self.entries.items[oldest].last_used) {
                oldest = index;
            }
        }
        return oldest;
    }

    fn nextAccess(self: *Cache) u64 {
        const value = self.access_clock;
        self.access_clock +%= 1;
        return value;
    }

    fn failureBackoffMilliseconds(self: *const Cache, failures: u8) u64 {
        const initial = durationMillisecondsCeil(
            self.config.failure_backoff_initial,
        );
        const maximum = durationMillisecondsCeil(
            self.config.failure_backoff_max,
        );
        var delay = initial;
        var remaining = failures -| 1;
        while (remaining != 0 and delay < maximum) : (remaining -= 1) {
            delay = @min(maximum, saturatingAdd(delay, delay));
        }
        return delay;
    }
};

const Selection = union(enum) {
    absent,
    remove,
    target: http3.AltSvcTarget,
};

fn selectTarget(origin: http3.Origin, headers: anytype) Error!Selection {
    var saw_header = false;
    var saw_non_clear = false;
    var saw_clear = false;
    var selected: ?http3.AltSvcTarget = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "alt-svc")) continue;
        saw_header = true;
        const value = std.mem.trim(u8, header.value, " \t");
        if (std.ascii.eqlIgnoreCase(value, "clear")) {
            if (saw_non_clear) return error.InvalidHeader;
            saw_clear = true;
            continue;
        }
        if (saw_clear) return error.InvalidHeader;
        saw_non_clear = true;
        if (selected == null) {
            const endpoint = (try parseFirstHttp3(value)) orelse continue;
            selected = try altSvcTarget(origin.host, endpoint, origin.port);
        } else {
            // Still validate later HTTP/3 alternatives transactionally.
            _ = try parseFirstHttp3(value);
        }
    }
    if (!saw_header) return .absent;
    if (saw_clear or selected == null) return .remove;
    return .{ .target = selected.? };
}

fn parseFirstHttp3(value: []const u8) Error!?http3.AltSvcEndpoint {
    return http3.firstHttp3AltSvc(value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidHeader,
    };
}

fn altSvcTarget(
    origin_host: []const u8,
    endpoint: http3.AltSvcEndpoint,
    default_port: u16,
) Error!http3.AltSvcTarget {
    return http3.altSvcTarget(
        origin_host,
        endpoint,
        default_port,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidHeader,
    };
}

fn makeEntry(
    allocator: std.mem.Allocator,
    origin: http3.Origin,
    target: http3.AltSvcTarget,
    expires_at_ms: u64,
) Error!Entry {
    const total_len = try totalLength(&.{
        origin.scheme,
        origin.host,
        target.alpn,
        target.connect_host,
        target.origin_host,
    });
    const storage = try allocator.alloc(u8, total_len);
    errdefer allocator.free(storage);
    var offset: usize = 0;
    const scheme = copyPart(storage, &offset, origin.scheme, true);
    const host = copyPart(storage, &offset, origin.host, true);
    const alpn = copyPart(storage, &offset, target.alpn, false);
    const connect_host = copyPart(
        storage,
        &offset,
        target.connect_host,
        true,
    );
    const origin_host = copyPart(
        storage,
        &offset,
        target.origin_host,
        true,
    );
    return .{
        .storage = storage,
        .origin = .{
            .scheme = scheme,
            .host = host,
            .port = origin.port,
        },
        .alpn = alpn,
        .connect_host = connect_host,
        .origin_host = origin_host,
        .port = target.port,
        .expires_at_ms = expires_at_ms,
        .last_used = 0,
    };
}

fn validateOrigin(origin: http3.Origin) Error!void {
    if (!std.ascii.eqlIgnoreCase(origin.scheme, "https") or
        origin.host.len == 0 or origin.port == 0)
    {
        return error.InvalidOrigin;
    }
    for (origin.host) |byte| {
        if (byte <= 0x20 or byte >= 0x7f or
            byte == '"' or byte == ',' or byte == ';' or byte == '/' or
            byte == '[' or byte == ']')
        {
            return error.InvalidOrigin;
        }
    }
}

fn totalLength(parts: []const []const u8) Error!usize {
    var total: usize = 0;
    for (parts) |part| {
        total = std.math.add(usize, total, part.len) catch
            return error.IntegerOverflow;
    }
    return total;
}

fn copyPart(
    storage: []u8,
    offset: *usize,
    value: []const u8,
    lowercase: bool,
) []u8 {
    const out = storage[offset.*..][0..value.len];
    if (lowercase) {
        for (value, out) |byte, *target| {
            target.* = std.ascii.toLower(byte);
        }
    } else {
        @memcpy(out, value);
    }
    offset.* += value.len;
    return out;
}

fn indexKey(origin: http3.Origin) IndexKey {
    return .{
        .scheme = origin.scheme,
        .host = origin.host,
        .port = origin.port,
    };
}

fn saturatingDeadlineSeconds(now_ms: u64, seconds: u64) u64 {
    return saturatingAdd(now_ms, std.math.mul(u64, seconds, 1000) catch
        std.math.maxInt(u64));
}

fn saturatingAdd(lhs: u64, rhs: u64) u64 {
    return std.math.add(u64, lhs, rhs) catch std.math.maxInt(u64);
}

fn durationMillisecondsCeil(duration: std.Io.Duration) u64 {
    const ns: u128 = @intCast(duration.nanoseconds);
    const milliseconds = (ns + std.time.ns_per_ms - 1) / std.time.ns_per_ms;
    return @intCast(@min(milliseconds, std.math.maxInt(u64)));
}

fn nowMilliseconds(io: std.Io) u64 {
    return @intCast(@max(0, std.Io.Clock.awake.now(io).toMilliseconds()));
}

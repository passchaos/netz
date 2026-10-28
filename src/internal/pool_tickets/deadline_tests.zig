const std = @import("std");
const tls = @import("../../tls/stream/mod.zig");
const cache_mod = @import("../../tls/stream/client_ticket_cache.zig");
const setup = @import("setup.zig");

fn ticket12(allocator: std.mem.Allocator, now: u64) !tls.Tls12SessionTicket {
    return tls.Tls12SessionTicket.init(allocator, "ticket-12", &.{}, .ecdhe_ecdsa_aes_128_gcm_sha256, [_]u8{0x42} ** 48, "ticket.test", "h2", now, 3600);
}

fn ticket13(allocator: std.mem.Allocator, now: u64) !tls.Tls13SessionTicket {
    const identity = try allocator.dupe(u8, "ticket-13");
    errdefer allocator.free(identity);
    const name = try allocator.dupe(u8, "ticket.test");
    errdefer allocator.free(name);
    const alpn = try allocator.dupe(u8, "h2");
    return .{
        .allocator = allocator,
        .identity = identity,
        .psk = .fromSha256([_]u8{0x43} ** 32),
        .suite = .aes_128_gcm_sha256,
        .server_name = name,
        .alpn = alpn,
        .age_add = 7,
        .received_at_ms = now,
        .lifetime_seconds = 3600,
        .max_early_data_size = null,
        .application_settings_codepoint = null,
        .local_application_settings = null,
        .peer_application_settings = null,
    };
}

const Connection = struct {
    version: tls.Protocol,
    pending12: ?tls.Tls12SessionTicket = null,
    pending13: ?tls.Tls13SessionTicket = null,
    takes: usize = 0,
    pub fn negotiatedTlsProtocol(self: *const @This()) ?tls.Protocol {
        return self.version;
    }
    pub fn negotiatedAlpn(_: *const @This()) ?[]const u8 {
        return "h2";
    }
    pub fn wasTlsSessionResumed(_: *const @This()) ?bool {
        return false;
    }
    pub fn takeTls12SessionTicket(self: *@This()) ?tls.Tls12SessionTicket {
        self.takes += 1;
        const ticket = self.pending12;
        self.pending12 = null;
        return ticket;
    }
    pub fn takeTls13SessionTicket(self: *@This()) tls.Error!?tls.Tls13SessionTicket {
        self.takes += 1;
        const ticket = self.pending13;
        self.pending13 = null;
        return ticket;
    }
    fn deinit(self: *@This()) void {
        if (self.pending12) |*ticket| ticket.deinit();
        if (self.pending13) |*ticket| ticket.deinit();
    }
};

const Gate = struct {
    base: std.Io,
    canceled: bool,
    var active: ?*Gate = null;
    fn wait(userdata: ?*anyopaque, pointer: *const u32, expected: u32, timeout: std.Io.Timeout) std.Io.Cancelable!void {
        const self = active.?;
        if (self.canceled) return error.Canceled;
        return self.base.vtable.futexWait(userdata, pointer, expected, timeout);
    }
};

test "TLS setup ticket invalidation preserves the old cache entry until bounded admission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ tls.Protocol.tls12, tls.Protocol.tls13 }) |version| {
        inline for (.{ false, true }) |exact_alpn| {
            const Cache = if (version == .tls12) cache_mod.Cache else cache_mod.Tls13Cache;
            var cache = Cache.init(std.testing.allocator, base, 2);
            defer cache.deinit();
            const now: u64 = if (version == .tls12) @intCast(std.Io.Clock.real.now(base).toSeconds()) else @intCast(@divFloor(std.Io.Clock.real.now(base).nanoseconds, std.time.ns_per_ms));
            cache.store("ticket.test", 443, if (version == .tls12) try ticket12(std.testing.allocator, now) else try ticket13(std.testing.allocator, now), now);
            var connection = Connection{ .version = version };
            var gate = Gate{ .base = base, .canceled = true };
            var table = base.vtable.*;
            table.futexWait = Gate.wait;
            Gate.active = &gate;
            defer Gate.active = null;
            const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
            cache.mutex.lockUncancelable(base);
            var locked = true;
            defer if (locked) cache.mutex.unlock(base);
            const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
            if (version == .tls12) try std.testing.expectError(error.Canceled, setup.remember12(&cache, &connection, "ticket.test", 443, exact_alpn, io, deadline)) else try std.testing.expectError(error.Canceled, setup.remember13(&cache, &connection, "ticket.test", 443, exact_alpn, true, io, deadline));
            try std.testing.expectEqual(@as(usize, 1), cache.entries.items.len);
            try std.testing.expectEqual(@as(usize, 0), connection.takes);
            cache.mutex.unlock(base);
            locked = false;
            if (version == .tls12) try setup.remember12(&cache, &connection, "ticket.test", 443, exact_alpn, base, deadline) else try std.testing.expect(!try setup.remember13(&cache, &connection, "ticket.test", 443, exact_alpn, true, base, deadline));
            try std.testing.expectEqual(@as(usize, 0), cache.count());
            try std.testing.expectEqual(@as(usize, 1), connection.takes);
        }
    }
}

test "TLS setup ticket storage waits before transfer and resumes with the same owned ticket" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ tls.Protocol.tls12, tls.Protocol.tls13 }) |version| {
        inline for (.{ false, true }) |exact_alpn| {
            inline for (.{ false, true }) |canceled| {
                const Cache = if (version == .tls12) cache_mod.Cache else cache_mod.Tls13Cache;
                var cache = Cache.init(std.testing.allocator, base, 2);
                defer cache.deinit();
                var connection = Connection{ .version = version };
                if (version == .tls12) connection.pending12 = try ticket12(std.testing.allocator, @intCast(std.Io.Clock.real.now(base).toSeconds())) else connection.pending13 = try ticket13(std.testing.allocator, @intCast(@divFloor(std.Io.Clock.real.now(base).nanoseconds, std.time.ns_per_ms)));
                defer connection.deinit();
                const identity = if (version == .tls12) connection.pending12.?.ticket_storage.ptr else connection.pending13.?.identity.ptr;
                var gate = Gate{ .base = base, .canceled = canceled };
                var table = base.vtable.*;
                table.futexWait = Gate.wait;
                Gate.active = &gate;
                defer Gate.active = null;
                const io: std.Io = .{ .userdata = base.userdata, .vtable = &table };
                cache.mutex.lockUncancelable(base);
                var locked = true;
                defer if (locked) cache.mutex.unlock(base);
                const deadline = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) });
                const expected = if (canceled) error.Canceled else error.Timeout;
                if (version == .tls12) {
                    try std.testing.expectError(expected, setup.remember12(&cache, &connection, "ticket.test", 443, exact_alpn, io, deadline));
                } else {
                    try std.testing.expectError(expected, setup.remember13(&cache, &connection, "ticket.test", 443, exact_alpn, true, io, deadline));
                }
                try std.testing.expect(!cache.mutex.tryLock());
                try std.testing.expectEqual(@as(usize, 0), connection.takes);
                try std.testing.expect(identity == if (version == .tls12) connection.pending12.?.ticket_storage.ptr else connection.pending13.?.identity.ptr);
                cache.mutex.unlock(base);
                locked = false;
                const next = std.Io.Clock.Timestamp.fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) });
                if (version == .tls12) try setup.remember12(&cache, &connection, "ticket.test", 443, exact_alpn, base, next) else try std.testing.expect(try setup.remember13(&cache, &connection, "ticket.test", 443, exact_alpn, true, base, next));
                try std.testing.expectEqual(@as(usize, 1), connection.takes);
                try std.testing.expectEqual(@as(usize, 1), cache.count());
                const now: u64 = if (version == .tls12) @intCast(std.Io.Clock.real.now(base).toSeconds()) else @intCast(@divFloor(std.Io.Clock.real.now(base).nanoseconds, std.time.ns_per_ms));
                var cloned = (try cache.cloneForAlpnBefore("ticket.test", 443, "h2", now, next)).?;
                defer cloned.deinit();
                try std.testing.expectEqualStrings(if (version == .tls12) "ticket-12" else "ticket-13", if (version == .tls12) cloned.ticket() else cloned.identity);
            }
        }
    }
}

const SlowAllocator = struct {
    base: std.mem.Allocator,
    var time_ns: i96 = 1000;
    fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        return .fromNanoseconds(time_ns);
    }
    fn alloc(pointer: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(pointer));
        const memory = self.base.rawAlloc(len, alignment, ret) orelse return null;
        time_ns = 1003;
        return memory;
    }
    fn free(pointer: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const self: *@This() = @ptrCast(@alignCast(pointer));
        self.base.rawFree(bytes, alignment, ret);
    }
    const vtable: std.mem.Allocator.VTable = .{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free };
};

test "TLS setup ticket clone allocation cannot renew deadline or mutate cached ownership" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const base = threaded.io();
    inline for (.{ false, true }) |tls13| {
        inline for (.{ false, true }) |exact_alpn| {
            const Cache = if (tls13) cache_mod.Tls13Cache else cache_mod.Cache;
            var cache = Cache.init(std.testing.allocator, base, 2);
            defer cache.deinit();
            cache.store("ticket.test", 443, if (tls13) try ticket13(std.testing.allocator, 100_000) else try ticket12(std.testing.allocator, 100), if (tls13) 100_000 else 100);
            const access = cache.access_clock;
            var slow = SlowAllocator{ .base = std.testing.allocator };
            var table = base.vtable.*;
            table.now = SlowAllocator.now;
            cache.io = .{ .userdata = base.userdata, .vtable = &table };
            cache.allocator = .{ .ptr = &slow, .vtable = &SlowAllocator.vtable };
            defer {
                cache.io = base;
                cache.allocator = std.testing.allocator;
            }
            SlowAllocator.time_ns = 1000;
            const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .fromNanoseconds(1003) };
            if (exact_alpn) try std.testing.expectError(error.Timeout, cache.cloneForAlpnBefore("ticket.test", 443, "h2", if (tls13) 100_000 else 100, deadline)) else try std.testing.expectError(error.Timeout, cache.cloneForBefore("ticket.test", 443, if (tls13) 100_000 else 100, deadline));
            try std.testing.expectEqual(access, cache.access_clock);
            try std.testing.expect(cache.mutex.tryLock());
            cache.mutex.unlock(base);
            cache.io = base;
            cache.allocator = std.testing.allocator;
            var retry = (try cache.cloneFor("ticket.test", 443, if (tls13) 100_000 else 100)).?;
            defer retry.deinit();
            try std.testing.expectEqualStrings(if (tls13) "ticket-13" else "ticket-12", if (tls13) retry.identity else retry.ticket());
        }
    }
}

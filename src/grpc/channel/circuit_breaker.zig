//! Shared xDS cluster/EDS circuit budget with independently owned active permits.
const std = @import("std");
pub const Error = std.mem.Allocator.Error || error{InvalidCircuitBreaker};
pub const Options = struct {
    cluster: []const u8,
    eds_service_name: []const u8 = "",
    max_concurrent_requests: u32 = 1024,
};
pub const Stats = struct { active: u32 = 0, admitted: u64 = 0, rejected: u64 = 0 };
// This process-wide registry must outlive every application Io backend.
// The static threaded facade is used solely for native futex locking; it
// allocates no threads or runtime resources.
var registry_io: std.Io.Threaded = .init_single_threaded;
var registry_mutex: std.Io.Mutex = .init;
var registry_head: ?*Counter = null;
// A shared key can outlive the first channel allocator as well as its Io.
const registry_allocator = if (@import("builtin").is_test) std.testing.allocator else std.heap.smp_allocator;
const Counter = struct {
    allocator: std.mem.Allocator,
    cluster: []u8,
    eds_service_name: []u8,
    next: ?*Counter,
    refs: std.atomic.Value(usize) = .init(1),
    active: std.atomic.Value(u32) = .init(0),
    admitted: std.atomic.Value(u64) = .init(0),
    rejected: std.atomic.Value(u64) = .init(0),
    fn create(gpa: std.mem.Allocator, options: Options, next: ?*Counter) Error!*Counter {
        const cluster = try gpa.dupe(u8, options.cluster);
        errdefer gpa.free(cluster);
        const eds = try gpa.dupe(u8, options.eds_service_name);
        errdefer gpa.free(eds);
        const counter = try gpa.create(Counter);
        counter.* = .{ .allocator = gpa, .cluster = cluster, .eds_service_name = eds, .next = next };
        return counter;
    }
    fn retain(self: *Counter) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    fn tryRetain(self: *Counter) bool {
        var refs = self.refs.load(.acquire);
        while (refs != 0) {
            refs = self.refs.cmpxchgWeak(refs, refs + 1, .acq_rel, .acquire) orelse return true;
        }
        return false;
    }
    fn release(self: *Counter) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        registry_mutex.lockUncancelable(registry_io.io());
        var link = &registry_head;
        while (link.*) |counter| {
            if (counter == self) {
                link.* = self.next;
                break;
            }
            link = &counter.next;
        }
        registry_mutex.unlock(registry_io.io());
        std.debug.assert(self.active.load(.acquire) == 0);
        self.allocator.free(self.cluster);
        self.allocator.free(self.eds_service_name);
        self.allocator.destroy(self);
    }
};
pub const Permit = struct {
    counter: ?*Counter,
    secondary: ?*Counter = null,
    /// One owning value; copying a permit does not acquire another request.
    pub fn release(self: *Permit) void {
        if (self.secondary) |extra| {
            self.secondary = null;
            std.debug.assert(extra.active.fetchSub(1, .acq_rel) != 0);
            extra.release();
        }
        const counter = self.counter orelse return;
        self.counter = null;
        std.debug.assert(counter.active.fetchSub(1, .acq_rel) != 0);
        counter.release();
    }
};
/// Combine channel and cluster constraints; identical identities reserve once
/// under the stricter limit. Independent budgets are released as one permit.
pub fn acquirePair(first: ?Policy, second: ?Policy) ?Permit {
    if (first == null) return if (second) |policy| policy.acquire() else null;
    if (second == null) return first.?.acquire();
    if (first.?.counter == second.?.counter) {
        var policy = first.?;
        policy.maximum = @min(policy.maximum, second.?.maximum);
        return policy.acquire();
    }
    var permit = first.?.acquire() orelse return null;
    var extra = second.?.acquire() orelse {
        permit.release();
        return null;
    };
    permit.secondary = extra.counter;
    extra.counter = null;
    return permit;
}
pub const Policy = struct {
    counter: *Counter,
    maximum: u32,
    pub fn init(options: Options) Error!Policy {
        if (options.cluster.len == 0 or options.cluster.len > 4096 or options.eds_service_name.len > 4096 or !std.unicode.utf8ValidateSlice(options.cluster) or !std.unicode.utf8ValidateSlice(options.eds_service_name)) return error.InvalidCircuitBreaker;
        registry_mutex.lockUncancelable(registry_io.io());
        defer registry_mutex.unlock(registry_io.io());
        var cursor = registry_head;
        while (cursor) |counter| : (cursor = counter.next) {
            if (std.mem.eql(u8, counter.cluster, options.cluster) and std.mem.eql(u8, counter.eds_service_name, options.eds_service_name) and counter.tryRetain()) return .{ .counter = counter, .maximum = options.max_concurrent_requests };
        }
        const counter = try Counter.create(registry_allocator, options, registry_head);
        registry_head = counter;
        return .{ .counter = counter, .maximum = options.max_concurrent_requests };
    }
    pub fn clone(self: Policy) Policy {
        self.counter.retain();
        return self;
    }
    pub fn deinit(self: *Policy) void {
        self.counter.release();
        self.* = undefined;
    }
    pub fn saturated(self: Policy) bool {
        return self.counter.active.load(.acquire) >= self.maximum;
    }
    pub fn recordRejection(self: Policy) void {
        _ = self.counter.rejected.fetchAdd(1, .monotonic);
    }
    /// Claim only once a transport owner can admit the RPC. Unlike a separate
    /// check/increment, CAS also keeps concurrent endpoint owners within cap.
    pub fn acquire(self: Policy) ?Permit {
        var active = self.counter.active.load(.acquire);
        while (true) {
            if (active >= self.maximum) {
                self.recordRejection();
                return null;
            }
            active = self.counter.active.cmpxchgWeak(active, active + 1, .acq_rel, .acquire) orelse {
                self.counter.retain();
                _ = self.counter.admitted.fetchAdd(1, .monotonic);
                return .{ .counter = self.counter };
            };
        }
    }
    pub fn stats(self: Policy) Stats {
        return .{ .active = self.counter.active.load(.acquire), .admitted = self.counter.admitted.load(.acquire), .rejected = self.counter.rejected.load(.acquire) };
    }
};

test "gRPC circuit breaker shares identity and keeps permits through limit replacement" {
    var first = try Policy.init(.{ .cluster = "first", .eds_service_name = "eds", .max_concurrent_requests = 1 });
    var first_live = true;
    defer if (first_live) first.deinit();
    var second = try Policy.init(.{ .cluster = "first", .eds_service_name = "eds", .max_concurrent_requests = 1 });
    defer second.deinit();
    var independent = try Policy.init(.{ .cluster = "first", .eds_service_name = "other", .max_concurrent_requests = 1 });
    defer independent.deinit();
    var permit = first.acquire().?;
    defer permit.release();
    try std.testing.expect(second.acquire() == null);
    var other = independent.acquire().?;
    defer other.release();
    first.deinit();
    first_live = false;
    try std.testing.expectEqual(@as(u32, 1), second.stats().active);
    var raised = second.clone();
    defer raised.deinit();
    raised.maximum = 2;
    var extra = raised.acquire().?;
    defer extra.release();
    try std.testing.expectEqual(@as(u32, 2), second.stats().active);
    permit.release();
    extra.release();
    try std.testing.expectEqual(@as(u32, 0), second.stats().active);
    var resumed = second.acquire().?;
    resumed.release();
}

test "gRPC circuit breaker registry construction rolls back allocation failures" {
    const Harness = struct {
        fn run(gpa: std.mem.Allocator) !void {
            const counter = try Counter.create(gpa, .{ .cluster = "allocation-sweep", .eds_service_name = "eds" }, null);
            var policy = Policy{ .counter = counter, .maximum = 1024 };
            defer policy.deinit();
            var permit = policy.acquire().?;
            defer permit.release();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Harness.run, .{});
    try std.testing.expectError(error.InvalidCircuitBreaker, Policy.init(.{ .cluster = "" }));
}

test "gRPC circuit breaker combined budgets reserve once for a shared identity and roll back partial reservations" {
    var first = try Policy.init(.{ .cluster = "combined", .max_concurrent_requests = 2 });
    defer first.deinit();
    var same = first.clone();
    defer same.deinit();
    same.maximum = 1;
    var permit = acquirePair(first, same).?;
    try std.testing.expectEqual(@as(u32, 1), first.stats().active);
    try std.testing.expect(acquirePair(first, same) == null);
    permit.release();
    var second = try Policy.init(.{ .cluster = "other-combined", .max_concurrent_requests = 1 });
    defer second.deinit();
    var pair = acquirePair(first, second).?;
    try std.testing.expectEqual(@as(u32, 1), first.stats().active);
    try std.testing.expectEqual(@as(u32, 1), second.stats().active);
    try std.testing.expect(acquirePair(first, second) == null);
    try std.testing.expectEqual(@as(u32, 1), first.stats().active);
    pair.release();
    pair.release();
    try std.testing.expectEqual(@as(u32, 0), first.stats().active);
    try std.testing.expectEqual(@as(u32, 0), second.stats().active);
}

test "gRPC circuit breaker atomic permits enforce the cap across racing owners" {
    var policy = try Policy.init(.{ .cluster = "racing-owners", .max_concurrent_requests = 2 });
    defer policy.deinit();
    const Context = struct {
        policy: Policy,
        maximum_seen: std.atomic.Value(u32) = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
        fn run(self: *@This()) void {
            for (0..200) |_| {
                var permit = self.policy.acquire() orelse {
                    std.Thread.yield() catch {};
                    continue;
                };
                const active = self.policy.stats().active;
                if (active > self.policy.maximum) self.failed.store(true, .release);
                var old = self.maximum_seen.load(.acquire);
                while (active > old) old = self.maximum_seen.cmpxchgWeak(old, active, .acq_rel, .acquire) orelse break;
                std.Thread.yield() catch {};
                permit.release();
            }
        }
    };
    var context = Context{ .policy = policy };
    var threads: [8]std.Thread = undefined;
    var count: usize = 0;
    defer for (threads[0..count]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Context.run, .{&context});
        count += 1;
    }
    for (threads) |thread| thread.join();
    count = 0;
    try std.testing.expect(!context.failed.load(.acquire));
    try std.testing.expect(context.maximum_seen.load(.acquire) > 0);
    try std.testing.expectEqual(@as(u32, 0), policy.stats().active);
}

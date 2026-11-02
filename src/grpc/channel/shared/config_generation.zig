//! Reference-counted immutable service-config generation.
//!
//! Dynamic config publication swaps one pointer under the SharedChannel lock;
//! in-flight method resolution retains the prior generation until it finishes.
const std = @import("std");
const service_config = @import("../../service_config.zig");
const Storage = @import("config_storage.zig").Storage;
const Selector = @import("../call_selector.zig").Selector;

pub const Generation = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    storage: *Storage,
    /// Borrowed immutable views; only `storage` destroys this arena/text.
    config: service_config.ServiceConfig,
    json: ?[]u8 = null,
    call_selector: ?Selector = null,
    retired_next: ?*Generation = null,

    pub fn create(
        allocator: std.mem.Allocator,
        config: service_config.ServiceConfig,
    ) std.mem.Allocator.Error!*Generation {
        const generation = try allocator.create(Generation);
        errdefer allocator.destroy(generation);
        const storage = try Storage.create(allocator, config, null);
        generation.* = .{ .allocator = allocator, .storage = storage, .config = storage.config };
        return generation;
    }

    pub fn retain(self: *Generation) *Generation {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }
    pub fn createWithJson(allocator: std.mem.Allocator, config: service_config.ServiceConfig, json: []const u8) std.mem.Allocator.Error!*Generation {
        const generation = try allocator.create(Generation);
        errdefer allocator.destroy(generation);
        const storage = try Storage.create(allocator, config, json);
        generation.* = .{ .allocator = allocator, .storage = storage, .config = storage.config, .json = storage.json };
        return generation;
    }
    pub fn withSelector(allocator: std.mem.Allocator, old: ?*Generation, selected: ?Selector) service_config.Error!*Generation {
        const generation = if (old) |previous| blk: {
            const value = try allocator.create(Generation);
            const storage = previous.storage.retain();
            value.* = .{ .allocator = allocator, .storage = storage, .config = storage.config, .json = storage.json };
            break :blk value;
        } else blk: {
            var parsed = try service_config.ServiceConfig.parse(allocator, "{}");
            errdefer parsed.deinit();
            break :blk try createWithJson(allocator, parsed, "{}");
        };
        generation.call_selector = if (selected) |value| value.retain() else null;
        return generation;
    }
    pub fn sameServiceConfig(a: ?*Generation, b: ?*Generation) bool {
        if (a) |left| return if (b) |right| left.storage == right.storage else false;
        return b == null;
    }

    pub fn release(self: *Generation) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const allocator = self.allocator;
        if (self.call_selector) |selected| selected.release();
        self.storage.release();
        self.* = undefined;
        allocator.destroy(self);
    }
};

/// Publication is serialized by State's mutex. The short reader epoch only
/// protects the load/retain pair; each caller then owns an independent ref.
pub const Publication = struct {
    current: std.atomic.Value(?*Generation),
    readers: std.atomic.Value(usize) = .init(0),
    retired: ?*Generation = null,

    pub fn init(generation: ?*Generation) Publication {
        return .{ .current = .init(generation) };
    }
    pub fn load(self: *const Publication, comptime order: std.builtin.AtomicOrder) ?*Generation {
        return self.current.load(order);
    }
    pub fn retain(self: *Publication) ?*Generation {
        _ = self.readers.fetchAdd(1, .seq_cst);
        const generation = self.current.load(.seq_cst);
        if (generation) |config| _ = config.retain();
        _ = self.readers.fetchSub(1, .seq_cst);
        return generation;
    }
    pub fn publish(self: *Publication, generation: ?*Generation) void {
        if (self.current.swap(generation, .seq_cst)) |old| {
            if (old == generation) old.release() else {
                old.retired_next = self.retired;
                self.retired = old;
            }
        }
        self.reclaim();
    }
    pub fn reclaim(self: *Publication) void {
        // `retired` is only mutated under the State mutex, so the common
        // steady-state path avoids an atomic reader-epoch load.
        if (self.retired == null) return;
        if (self.readers.load(.seq_cst) != 0) return;
        while (self.retired) |old| {
            self.retired = old.retired_next;
            old.retired_next = null;
            old.release();
        }
    }
    pub fn deinit(self: *Publication) void {
        std.debug.assert(self.readers.load(.seq_cst) == 0);
        self.reclaim();
        if (self.current.load(.acquire)) |generation| generation.release();
    }
};

test "gRPC shared config generation retains immutable arena ownership" {
    var config = try service_config.ServiceConfig.parse(
        std.testing.allocator,
        "{}",
    );
    const generation = try Generation.create(std.testing.allocator, config);
    config = undefined;
    _ = generation.retain();
    generation.release();
    generation.release();
}

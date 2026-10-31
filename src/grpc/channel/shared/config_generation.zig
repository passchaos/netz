//! Reference-counted immutable service-config generation.
//!
//! Dynamic config publication swaps one pointer under the SharedChannel lock;
//! in-flight method resolution retains the prior generation until it finishes.
const std = @import("std");
const service_config = @import("../../service_config.zig");

pub const Generation = struct {
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    config: service_config.ServiceConfig,
    json: ?[]u8 = null,
    retired_next: ?*Generation = null,

    pub fn create(
        allocator: std.mem.Allocator,
        config: service_config.ServiceConfig,
    ) std.mem.Allocator.Error!*Generation {
        const generation = try allocator.create(Generation);
        generation.* = .{ .allocator = allocator, .config = config };
        return generation;
    }

    pub fn retain(self: *Generation) *Generation {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }
    pub fn createWithJson(allocator: std.mem.Allocator, config: service_config.ServiceConfig, json: []const u8) std.mem.Allocator.Error!*Generation {
        const text = try allocator.dupe(u8, json);
        errdefer allocator.free(text);
        const generation = try create(allocator, config);
        generation.json = text;
        return generation;
    }

    pub fn release(self: *Generation) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const allocator = self.allocator;
        self.config.deinit();
        if (self.json) |json| allocator.free(json);
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

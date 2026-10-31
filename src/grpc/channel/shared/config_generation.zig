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

    pub fn release(self: *Generation) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const allocator = self.allocator;
        self.config.deinit();
        self.* = undefined;
        allocator.destroy(self);
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

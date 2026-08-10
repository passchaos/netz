const std = @import("std");

/// Runtime backend selection for netz examples and applications.
///
/// Protocol modules consume only `std.Io`; backend construction belongs here so
/// HTTP/WebSocket/etc. do not need Linux- or kqueue-specific branches.  Zig
/// 0.16 exposes `std.Io.Evented` (io_uring on Linux, kqueue/dispatch on other
/// supported targets), but the backend is still incomplete in some released
/// stdlib builds.  `initAuto` therefore attempts Evented when it is known to be
/// compilable for the pinned toolchain and otherwise falls back to Threaded.
pub const BackendPreference = enum {
    /// Prefer std.Io.Evented when the current Zig stdlib/target supports it,
    /// otherwise use std.Io.Threaded.
    evented_then_threaded,
    /// Force the portable threaded backend.
    threaded,
};

pub const BackendKind = enum {
    evented,
    threaded,
};

pub const Backend = if (canCompileEventedBackend()) EventedCapableBackend else ThreadedOnlyBackend;

const ThreadedOnlyBackend = struct {
    allocator: std.mem.Allocator,
    kind: BackendKind,
    threaded: std.Io.Threaded,

    pub fn initAuto(allocator: std.mem.Allocator, preference: BackendPreference) !ThreadedOnlyBackend {
        _ = preference;
        return initThreaded(allocator);
    }

    pub fn initThreaded(allocator: std.mem.Allocator) !ThreadedOnlyBackend {
        return .{
            .allocator = allocator,
            .kind = .threaded,
            .threaded = std.Io.Threaded.init(allocator, .{}),
        };
    }

    pub fn io(self: *ThreadedOnlyBackend) std.Io {
        return self.threaded.io();
    }

    pub fn deinit(self: *ThreadedOnlyBackend) void {
        self.threaded.deinit();
        self.* = undefined;
    }
};

const EventedCapableBackend = struct {
    allocator: std.mem.Allocator,
    kind: BackendKind,
    storage: union(BackendKind) {
        evented: std.Io.Evented,
        threaded: std.Io.Threaded,
    },

    pub fn initAuto(allocator: std.mem.Allocator, preference: BackendPreference) !EventedCapableBackend {
        if (preference == .evented_then_threaded) {
            var evented: std.Io.Evented = undefined;
            if (evented.init(allocator, .{})) |_| {
                return .{
                    .allocator = allocator,
                    .kind = .evented,
                    .storage = .{ .evented = evented },
                };
            } else |_| {}
        }
        return initThreaded(allocator);
    }

    pub fn initThreaded(allocator: std.mem.Allocator) !EventedCapableBackend {
        return .{
            .allocator = allocator,
            .kind = .threaded,
            .storage = .{ .threaded = std.Io.Threaded.init(allocator, .{}) },
        };
    }

    pub fn io(self: *EventedCapableBackend) std.Io {
        return switch (self.storage) {
            .evented => |*evented| evented.io(),
            .threaded => |*threaded| threaded.io(),
        };
    }

    pub fn deinit(self: *EventedCapableBackend) void {
        switch (self.storage) {
            .evented => |*evented| evented.deinit(),
            .threaded => |*threaded| threaded.deinit(),
        }
        self.* = undefined;
    }
};

/// Zig 0.16's Evented backends currently fail to compile in this pinned
/// toolchain on supported host targets: Linux io_uring misses stdlib error-set
/// cases, while the macOS dispatch backend trips a stdlib allocator assertion
/// during generic test builds. Keep this gate explicit so applications can use
/// `Backend.initAuto(.evented_then_threaded)` without pulling a broken backend
/// into generic protocol builds. When the pinned Zig stdlib is fixed, flipping
/// target branches to `true` enables Evented without changing protocol code.
fn canCompileEventedBackend() bool {
    if (std.Io.Evented == void) return false;
    return switch (@import("builtin").os.tag) {
        .linux => false,
        .macos => false,
        else => false,
    };
}

test "runtime backend auto falls back when Evented is unavailable" {
    var backend = try Backend.initAuto(std.testing.allocator, .evented_then_threaded);
    defer backend.deinit();
    _ = backend.io();
    if (!canCompileEventedBackend()) {
        try std.testing.expectEqual(BackendKind.threaded, backend.kind);
    }
}

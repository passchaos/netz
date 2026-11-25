const std = @import("std");
const owned = @import("owned_result_deadline.zig");
const Probe = @import("testing/trust_completion.zig").Probe;
const Mode = @import("testing/trust_completion.zig").Mode;

const Value = struct {
    bytes: []u8,
    destroyed: *usize,
    pub fn deinit(self: *@This()) void {
        std.testing.allocator.free(self.bytes);
        self.destroyed.* += 1;
    }
};

fn interrupt(probe: *Probe) void {
    switch (probe.mode) {
        .ordinary => {},
        .expired => probe.now_ns = 3000,
        .canceled => probe.cancel_pending = true,
    }
}

test "owned deadline completion transfers timely success and destroys interrupted success once" {
    inline for (std.meta.tags(Mode)) |mode| {
        var probe: Probe = .{ .mode = mode };
        var destroyed: usize = 0;
        const result: error{SourceFailed}!Value = .{ .bytes = try std.testing.allocator.alloc(u8, 16), .destroyed = &destroyed };
        interrupt(&probe);
        const completed = owned.complete(probe.io(), probe.deadline(), result);
        if (mode == .ordinary) {
            var value = try completed;
            try std.testing.expectEqual(@as(usize, 0), destroyed);
            value.deinit();
        } else {
            try std.testing.expectError(if (mode == .expired) error.Timeout else error.Canceled, completed);
        }
        try std.testing.expectEqual(@as(usize, 1), destroyed);
    }
}

test "owned deadline completion preserves only timely source failures" {
    inline for (std.meta.tags(Mode)) |mode| {
        var probe: Probe = .{ .mode = mode };
        const result: error{SourceFailed}!Value = error.SourceFailed;
        interrupt(&probe);
        try std.testing.expectError(switch (mode) {
            .ordinary => error.SourceFailed,
            .expired => error.Timeout,
            .canceled => error.Canceled,
        }, owned.complete(probe.io(), probe.deadline(), result));
    }
}

test "owned deadline admission preserves cancellation and expiry before work" {
    const Work = struct {
        fn run() error{SourceFailed}!Value {
            return error.SourceFailed;
        }
    };
    inline for (std.meta.tags(Mode)) |mode| {
        var probe: Probe = .{ .mode = mode };
        try std.testing.expectError(switch (mode) {
            .ordinary => error.ConcurrencyUnavailable,
            .expired => error.Timeout,
            .canceled => error.Canceled,
        }, owned.before(probe.io(), probe.deadline(), Work.run, .{}));
        try std.testing.expectEqual(@as(usize, 1), probe.admissions);
    }
}

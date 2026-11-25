const std = @import("std");
const loading = @import("trust_loading.zig");
const Store = @import("vail").x509.trust.SystemStore;
const support = @import("../internal/testing/trust_completion.zig");

fn admission(mode: support.Mode) !void {
    var probe: support.Probe = .{ .mode = mode };
    const Loader = struct {
        fn run() error{}!Store {
            return Store.initEmpty(std.testing.allocator);
        }
    };
    try std.testing.expectError(switch (mode) {
        .ordinary => error.ConcurrencyUnavailable,
        .expired => error.Timeout,
        .canceled => error.Canceled,
    }, loading.before(probe.io(), probe.deadline(), Loader.run, .{}));
    try std.testing.expectEqual(@as(usize, 1), probe.admissions);
    try std.testing.expectEqual(@as(usize, 0), probe.allocations);
}

test "TLS trust completion preserves admission failure within budget" {
    try admission(.ordinary);
}
test "TLS trust completion expired admission failure returns Timeout" {
    try admission(.expired);
}
test "TLS trust completion canceled admission failure returns Canceled" {
    try admission(.canceled);
}

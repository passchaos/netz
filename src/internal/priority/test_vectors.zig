//! Shared protocol tests for structured Priority Dictionary semantics.
pub const Case = struct {
    field: []const u8,
    urgency: u3 = 3,
    incremental: bool = false,
};

pub const dictionaries = [_]Case{
    .{ .field = "custom=\"noise, i, tail\", u=2", .urgency = 2 },
    .{ .field = "custom=(\"noise, i, tail\" ?1);p=\"u=0\", u=2", .urgency = 2 },
    .{ .field = "u=1;note=\"noise, i, tail\"", .urgency = 1 },
    .{ .field = "u=0, u=9, i, i=token" },
    .{ .field = "u=1, i, u=(0), i=(?1)" },
    .{ .field = "u=01, i=?1", .urgency = 1, .incremental = true },
    .{ .field = "u=-0", .urgency = 0 },
    .{ .field = "u=000000000000007", .urgency = 7 },
    .{ .field = "u=01,\ti=?1", .urgency = 1, .incremental = true },
};

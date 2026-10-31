//! gRFC A48 power-of-N least-request endpoint selection.
//!
//! Callers provide an indexed candidate set plus readiness and outstanding
//! request accessors. Sampling intentionally permits duplicates, matching the
//! Envoy and gRPC policy rather than silently changing its probability model.

const std = @import("std");

pub const Config = struct {
    pub const default_choice_count: u8 = 2;
    pub const max_choice_count: u8 = 10;

    choice_count: u8 = default_choice_count,
};

pub fn exactUniqueCount(items: anytype) usize {
    var count: usize = 0;
    for (items, 0..) |_, index| {
        if (!isExactDuplicate(items, index)) count += 1;
    }
    return count;
}

pub fn isExactDuplicate(items: anytype, index: usize) bool {
    for (items[0..index]) |prior| {
        if (std.meta.eql(prior, items[index])) return true;
    }
    return false;
}

pub fn pickIndex(
    context: anytype,
    candidate_count: usize,
    config: Config,
    seed: u64,
    comptime available: anytype,
    comptime outstanding: anytype,
) ?usize {
    var available_count: usize = 0;
    for (0..candidate_count) |index| {
        if (available(context, index)) available_count += 1;
    }
    if (available_count == 0) return null;

    var prng = std.Random.DefaultPrng.init(seed);
    const random = prng.random();
    var selected: ?usize = null;
    var selected_outstanding: usize = 0;
    for (0..config.choice_count) |_| {
        var ordinal = random.uintLessThan(usize, available_count);
        const sampled = for (0..candidate_count) |index| {
            if (!available(context, index)) continue;
            if (ordinal == 0) break index;
            ordinal -= 1;
        } else unreachable;
        const sampled_outstanding = outstanding(context, sampled);
        if (selected == null or sampled_outstanding < selected_outstanding) {
            selected = sampled;
            selected_outstanding = sampled_outstanding;
        }
    }
    return selected;
}

test "gRPC least request samples ready candidates with bounded choices" {
    const Candidate = struct {
        ready: bool,
        active: usize,
    };
    const Access = struct {
        fn available(items: []const Candidate, index: usize) bool {
            return items[index].ready;
        }
        fn outstanding(items: []const Candidate, index: usize) usize {
            return items[index].active;
        }
    };
    const candidates = [_]Candidate{
        .{ .ready = false, .active = 0 },
        .{ .ready = true, .active = 9 },
        .{ .ready = true, .active = 1 },
    };

    var selected_low = false;
    var selected_high = false;
    for (0..256) |seed| {
        const picked = pickIndex(
            &candidates,
            candidates.len,
            .{ .choice_count = 2 },
            seed,
            Access.available,
            Access.outstanding,
        ).?;
        try std.testing.expect(picked != 0);
        selected_high = selected_high or picked == 1;
        selected_low = selected_low or picked == 2;
    }
    // Duplicate samples are permitted, so both endpoints remain reachable;
    // the lower-load endpoint must nevertheless win most two-choice picks.
    try std.testing.expect(selected_high);
    try std.testing.expect(selected_low);

    var low_picks: usize = 0;
    for (0..4096) |seed| {
        low_picks += @intFromBool(pickIndex(
            &candidates,
            candidates.len,
            .{ .choice_count = 2 },
            seed,
            Access.available,
            Access.outstanding,
        ).? == 2);
    }
    try std.testing.expect(low_picks > 2800);
    try std.testing.expect(low_picks < 3300);
}

test "gRPC least request returns null without a ready candidate" {
    const Access = struct {
        fn available(_: void, _: usize) bool {
            return false;
        }
        fn outstanding(_: void, _: usize) usize {
            unreachable;
        }
    };
    try std.testing.expectEqual(
        @as(?usize, null),
        pickIndex(
            {},
            3,
            .{},
            0,
            Access.available,
            Access.outstanding,
        ),
    );
}

test "gRPC least request ignores exact duplicate resolved endpoints" {
    const Endpoint = struct {
        address: u16,
        authority: []const u8,
    };
    const endpoints = [_]Endpoint{
        .{ .address = 1, .authority = "a" },
        .{ .address = 1, .authority = "a" },
        .{ .address = 1, .authority = "b" },
        .{ .address = 2, .authority = "a" },
    };
    try std.testing.expect(!isExactDuplicate(&endpoints, 0));
    try std.testing.expect(isExactDuplicate(&endpoints, 1));
    try std.testing.expect(!isExactDuplicate(&endpoints, 2));
    try std.testing.expect(!isExactDuplicate(&endpoints, 3));
    try std.testing.expectEqual(
        @as(usize, 3),
        exactUniqueCount(&endpoints),
    );
}

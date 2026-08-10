const std = @import("std");
const quic = @import("../mod.zig");
const resumption = @import("mod.zig");

test "resumption cache deep-copies inputs and returns owned sessions" {
    var cache = try resumption.Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    var server_id = [_]u8{ 'a', '.', 't' };
    var ticket_bytes = [_]u8{ 1, 2, 3, 4 };
    try cache.store(ticket(
        &server_id,
        "h3",
        &ticket_bytes,
        1000,
        100,
        resumption.cache.quic_early_data_size,
        0x11,
    ));
    @memset(&server_id, 'x');
    @memset(&ticket_bytes, 0xff);

    var session = (try cache.acquire("a.t", "h3", 1001)).?;
    defer session.deinit();
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, session.ticket);
    try std.testing.expectEqual(@as(u8, 0x11), session.psk[0]);

    // Returned bytes survive replacement and eviction because no cache-owned
    // pointers escape.
    try cache.store(ticket(
        "a.t",
        "h3",
        "replacement",
        1002,
        100,
        null,
        0x22,
    ));
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, session.ticket);
}

test "resumption cache isolates origins and ALPNs" {
    var cache = try resumption.Cache.init(std.testing.allocator, 4);
    defer cache.deinit();
    try cache.store(ticket("example:443", "h3", "one", 1, 100, null, 1));
    try cache.store(ticket("example:443", "hq", "two", 2, 100, null, 2));
    try cache.store(ticket("other:443", "h3", "three", 3, 100, null, 3));

    var h3 = (try cache.acquire("example:443", "h3", 4)).?;
    defer h3.deinit();
    try std.testing.expectEqualStrings("one", h3.ticket);
    var hq = (try cache.acquire("example:443", "hq", 4)).?;
    defer hq.deinit();
    try std.testing.expectEqualStrings("two", hq.ticket);
    try std.testing.expect((try cache.acquire("missing", "h3", 4)) == null);
}

test "resumption cache uses LRU eviction and protects active leases" {
    var cache = try resumption.Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    try cache.store(ticket(
        "a",
        "h3",
        "a-ticket",
        1,
        100,
        resumption.cache.quic_early_data_size,
        1,
    ));
    try cache.store(ticket("b", "h3", "b-ticket", 2, 100, null, 2));

    // Touch a; inserting c must evict b, the least recently used entry.
    var touched = (try cache.acquire("a", "h3", 3)).?;
    touched.deinit();
    try cache.store(ticket("c", "h3", "c-ticket", 3, 100, null, 3));
    try std.testing.expect((try cache.acquire("b", "h3", 3)) == null);

    var lease = (try cache.beginEarlyData("a", "h3", 4)).?;
    defer lease.deinit();
    // Replacement cannot invalidate the active lease.
    try std.testing.expectError(
        error.CacheBusy,
        cache.store(ticket("a", "h3", "replace", 4, 100, null, 4)),
    );
    try std.testing.expectEqualStrings("a-ticket", lease.session.ticket);
    try cache.releaseEarlyData(&lease);
}

test "resumption early-data lease is exclusive and one shot after consume" {
    var cache = try resumption.Cache.init(std.testing.allocator, 1);
    defer cache.deinit();
    try cache.store(ticket(
        "example",
        "h3",
        "ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        0xaa,
    ));
    var lease = (try cache.beginEarlyData("example", "h3", 1010)).?;
    defer lease.deinit();
    try std.testing.expect((try cache.beginEarlyData("example", "h3", 1010)) == null);
    try std.testing.expectEqual(
        @as(u32, 19 +% 10),
        lease.session.obfuscatedTicketAge(1019),
    );
    try cache.consumeEarlyData(&lease);
    try std.testing.expect((try cache.beginEarlyData("example", "h3", 1020)) == null);
    try std.testing.expectError(
        error.LeaseAlreadyFinished,
        cache.releaseEarlyData(&lease),
    );

    // A newer ticket for the same origin can authorize a new attempt.
    try cache.store(ticket(
        "example",
        "h3",
        "new-ticket",
        1021,
        100,
        resumption.cache.quic_early_data_size,
        0xbb,
    ));
    var next = (try cache.beginEarlyData("example", "h3", 1022)).?;
    defer next.deinit();
    try cache.releaseEarlyData(&next);
    // A reservation released before wire use can be acquired again.
    var retry = (try cache.beginEarlyData("example", "h3", 1023)).?;
    defer retry.deinit();
    try cache.consumeEarlyData(&retry);
}

test "resumption cache stats expose lease and early-data state" {
    var cache = try resumption.Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    try cache.store(ticket(
        "early",
        "h3",
        "early-ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        0x11,
    ));
    try cache.store(ticket("resume", "h3", "resume-ticket", 1000, 100, null, 0x22));

    const initial = cache.stats();
    try std.testing.expectEqual(@as(usize, 2), initial.entries);
    try std.testing.expectEqual(@as(usize, 2), initial.capacity);
    try std.testing.expectEqual(@as(usize, 0), initial.active_early_data_leases);
    try std.testing.expectEqual(@as(usize, 0), initial.consumed_early_data_tickets);
    try std.testing.expectEqual(@as(usize, 1), initial.reusable_early_data_tickets);

    var lease = (try cache.beginEarlyData("early", "h3", 1001)).?;
    defer lease.deinit();
    const leased = cache.getStats();
    try std.testing.expectEqual(@as(usize, 1), leased.active_early_data_leases);
    try std.testing.expectEqual(@as(usize, 0), leased.reusable_early_data_tickets);

    try cache.consumeEarlyData(&lease);
    const consumed = cache.stats();
    try std.testing.expectEqual(@as(usize, 0), consumed.active_early_data_leases);
    try std.testing.expectEqual(@as(usize, 1), consumed.consumed_early_data_tickets);
    try std.testing.expectEqual(@as(usize, 0), consumed.reusable_early_data_tickets);
}

test "resumption cache expires tickets and validates lifetime" {
    var cache = try resumption.Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    try cache.store(ticket("valid", "h3", "ticket", 1000, 1, null, 1));
    var at_expiry = (try cache.acquire("valid", "h3", 2000)).?;
    at_expiry.deinit();
    // Strictly after the lifetime is expired; exactly at expiry remains usable
    // as in TLS ticket lifetime arithmetic.
    try std.testing.expect((try cache.acquire("valid", "h3", 2001)) == null);
    try std.testing.expectEqual(@as(usize, 1), cache.pruneExpired(2001));
    try std.testing.expectEqual(@as(usize, 0), cache.count());

    try std.testing.expectError(
        error.InvalidTicketLifetime,
        cache.store(ticket("bad", "h3", "ticket", 0, 0, null, 1)),
    );
    try std.testing.expectError(
        error.InvalidTicketLifetime,
        cache.store(ticket(
            "bad",
            "h3",
            "ticket",
            0,
            resumption.cache.max_ticket_lifetime_seconds + 1,
            null,
            1,
        )),
    );
    try std.testing.expectError(
        error.InvalidEarlyDataSize,
        cache.store(ticket("bad", "h3", "ticket", 0, 10, 1024, 1)),
    );
}

test "resumption lease deinit releases unused reservations" {
    var cache = try resumption.Cache.init(std.testing.allocator, 1);
    defer cache.deinit();
    try cache.store(ticket(
        "example",
        "h3",
        "ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        1,
    ));
    {
        var lease = (try cache.beginEarlyData("example", "h3", 1001)).?;
        lease.deinit();
    }
    var reacquired = (try cache.beginEarlyData("example", "h3", 1002)).?;
    defer reacquired.deinit();
    try cache.releaseEarlyData(&reacquired);
}

test "resumption cache will not evict active leases" {
    var cache = try resumption.Cache.init(std.testing.allocator, 1);
    defer cache.deinit();
    try cache.store(ticket(
        "leased",
        "h3",
        "ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        1,
    ));
    var lease = (try cache.beginEarlyData("leased", "h3", 1001)).?;
    defer lease.deinit();
    try std.testing.expectError(
        error.CacheBusy,
        cache.store(ticket("new", "h3", "new", 1001, 100, null, 2)),
    );
    try std.testing.expectEqual(@as(usize, 0), cache.pruneExpired(200_000));
    try std.testing.expectEqual(@as(usize, 1), cache.count());
}

test "resumption lease IDs do not collide after counter wrap" {
    var cache = try resumption.Cache.init(std.testing.allocator, 2);
    defer cache.deinit();
    try cache.store(ticket(
        "a",
        "h3",
        "a-ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        1,
    ));
    try cache.store(ticket(
        "b",
        "h3",
        "b-ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        2,
    ));
    var first = (try cache.beginEarlyData("a", "h3", 1001)).?;
    defer first.deinit();
    try std.testing.expectEqual(@as(u64, 1), first.lease_id);
    cache.next_lease_id = 1;
    var second = (try cache.beginEarlyData("b", "h3", 1001)).?;
    defer second.deinit();
    try std.testing.expectEqual(@as(u64, 2), second.lease_id);
    try cache.releaseEarlyData(&first);
    try cache.releaseEarlyData(&second);
}

fn checkResumptionCacheAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var cache = try resumption.Cache.init(allocator, 2);
    defer cache.deinit();
    try cache.store(ticket(
        "example",
        "h3",
        "ticket",
        1000,
        100,
        resumption.cache.quic_early_data_size,
        1,
    ));
    var lease = (try cache.beginEarlyData("example", "h3", 1001)).?;
    defer lease.deinit();
    try cache.releaseEarlyData(&lease);
    var session = (try cache.acquire("example", "h3", 1002)).?;
    defer session.deinit();
    try std.testing.expectEqualStrings("ticket", session.ticket);
}

test "resumption cache is transactional under every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkResumptionCacheAllocationFailure,
        .{},
    );
}

fn ticket(
    server_id: []const u8,
    alpn: []const u8,
    ticket_data: []const u8,
    issued_at_ms: u64,
    lifetime_seconds: u32,
    max_early_data_size: ?u32,
    psk_byte: u8,
) resumption.Ticket {
    return .{
        .server_id = server_id,
        .alpn = alpn,
        .ticket = ticket_data,
        .psk = [_]u8{psk_byte} ** 32,
        .issued_at_ms = issued_at_ms,
        .lifetime_seconds = lifetime_seconds,
        .age_add = 10,
        .max_early_data_size = max_early_data_size,
        .transport_parameters = .fromTransportParameters(
            quic.practical_transport_parameters,
        ),
    };
}

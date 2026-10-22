const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const connect_datagram = @import("../../datagram.zig");
const Registry = connect_datagram.Registry;
const ReceiveIntoTarget = connect_datagram.ReceiveIntoTarget;
const Owned = connect_datagram.Owned;
const Terminal = connect_datagram.Terminal;

test "HTTP/3 CONNECT datagram association detaches explicitly" {
    var registry = Registry.init(std.testing.allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    try std.testing.expect(registry.contains(0));
    try std.testing.expect(!registry.streamDetached(0));
    try std.testing.expect(!registry.hasDetachedStreams());
    try registry.markStreamDetached(0);
    try std.testing.expect(registry.streamDetached(0));
    try std.testing.expect(registry.hasDetachedStreams());
    try std.testing.expectError(
        error.UnexpectedStream,
        registry.markStreamDetached(4),
    );
}

test "HTTP/3 CONNECT datagram registry demultiplexes and bounds FIFO queues" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 8,
    });
    defer registry.deinit();
    try registry.register(0);
    try registry.register(4);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{ .quarter_stream_id = 1, .payload = "other" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "first" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "two" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 0, .payload = "new" }).write(&encoded, allocator);
    try registry.route(encoded.items);

    var other = (try registry.poll(4)).?;
    defer other.deinit(allocator);
    try std.testing.expectEqualStrings("other", other.payload);
    // The item cap evicts "first" before retaining the newer payloads.
    var first = (try registry.poll(0)).?;
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("two", first.payload);
    var second = (try registry.poll(0)).?;
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("new", second.payload);
    try std.testing.expectEqual(@as(?Owned, null), try registry.poll(0));

    encoded.clearRetainingCapacity();
    try (http3.Datagram{ .quarter_stream_id = 2, .payload = "unknown" }).write(&encoded, allocator);
    try registry.route(encoded.items);
    try std.testing.expectError(error.UnexpectedStream, registry.poll(8));
    try std.testing.expectError(error.UnexpectedStream, registry.register(2));
}

test "HTTP/3 CONNECT datagram caller buffer preserves queue semantics" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);
    try registry.register(4);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "direct",
    }).write(&encoded, allocator);
    var direct_storage: [6]u8 = undefined;
    var direct = ReceiveIntoTarget.init(0, &direct_storage);
    {
        var no_alloc = std.testing.FailingAllocator.init(
            allocator,
            .{ .fail_index = 0 },
        );
        registry.allocator = no_alloc.allocator();
        defer registry.allocator = allocator;
        try registry.routeInto(encoded.items, &direct);
        try std.testing.expect(!no_alloc.has_induced_failure);
    }
    try std.testing.expectEqualStrings("direct", (try direct.finish()).?);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));

    encoded.clearRetainingCapacity();
    try (http3.Datagram{
        .quarter_stream_id = 1,
        .payload = "other",
    }).write(&encoded, allocator);
    var unmatched = ReceiveIntoTarget.init(0, &direct_storage);
    try registry.routeInto(encoded.items, &unmatched);
    try std.testing.expect((try unmatched.finish()) == null);
    try std.testing.expectEqual(@as(usize, 1), try registry.queuedCount(4));

    encoded.clearRetainingCapacity();
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "too-large",
    }).write(&encoded, allocator);
    var short_storage: [2]u8 = undefined;
    var short = ReceiveIntoTarget.init(0, &short_storage);
    try registry.routeInto(encoded.items, &short);
    try std.testing.expectError(error.BufferTooShort, short.finish());
    try std.testing.expectEqual(@as(usize, 1), try registry.queuedCount(0));
    try std.testing.expectError(
        error.BufferTooShort,
        registry.pollInto(0, &short_storage),
    );
    try std.testing.expectEqual(@as(usize, 1), try registry.queuedCount(0));
    var retry_storage: [9]u8 = undefined;
    try std.testing.expectEqualStrings(
        "too-large",
        (try registry.pollInto(0, &retry_storage)).?,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
}

test "HTTP/3 CONNECT datagram registry isolates unknown associations" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 2,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 2,
        .payload = "unknown",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));

    // A Quarter Stream ID whose reconstruction would exceed u62 is malformed.
    encoded.clearRetainingCapacity();
    try quic.varint.encode(
        &encoded,
        allocator,
        http3.Datagram.max_quarter_stream_id + 1,
    );
    try encoded.appendSlice(allocator, "overflow");
    try std.testing.expectError(error.InvalidFrame, registry.route(encoded.items));
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
}

test "HTTP/3 CONNECT datagram batch uses stable exact backing storage" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    const payloads = [_][]const u8{ "one", &.{}, "three" };
    const batch = try registry.encodeBatch(0, &payloads);
    try std.testing.expectEqual(payloads.len, batch.datagrams.len);
    try std.testing.expectEqual(
        payloads[0].len + payloads[1].len + payloads[2].len + payloads.len,
        batch.storage.len,
    );
    for (batch.datagrams, payloads) |encoded, expected| {
        const datagram = try http3.Datagram.parse(encoded);
        try std.testing.expectEqual(@as(u64, 0), datagram.quarter_stream_id);
        try std.testing.expectEqualStrings(expected, datagram.payload);
        try std.testing.expect(@intFromPtr(encoded.ptr) >=
            @intFromPtr(batch.storage.ptr));
        try std.testing.expect(@intFromPtr(encoded.ptr) + encoded.len <=
            @intFromPtr(batch.storage.ptr) + batch.storage.len);
    }

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    registry.allocator = failing.allocator();
    const reused = try registry.encodeBatch(0, &payloads);
    registry.allocator = allocator;
    try std.testing.expectEqual(batch.storage.ptr, reused.storage.ptr);
    try std.testing.expectEqual(batch.datagrams.ptr, reused.datagrams.ptr);
    for (reused.datagrams, payloads) |encoded, expected| {
        const datagram = try http3.Datagram.parse(encoded);
        try std.testing.expectEqualStrings(expected, datagram.payload);
    }
}

test "HTTP/3 CONNECT datagram queue allocation failure is transactional" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 1,
        .max_queued_bytes_per_association = 32,
    });
    defer registry.deinit();
    try registry.register(0);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "retained",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    registry.allocator = failing.allocator();
    encoded.clearRetainingCapacity();
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "replacement",
    }).write(&encoded, allocator);
    try std.testing.expectError(error.OutOfMemory, registry.route(encoded.items));
    registry.allocator = allocator;

    var retained = (try registry.poll(0)).?;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("retained", retained.payload);
}

test "HTTP/3 CONNECT datagram terminal state drains payloads first" {
    const allocator = std.testing.allocator;
    var registry = Registry.init(allocator, .{
        .max_associations = 1,
        .max_queued_per_association = 2,
        .max_queued_bytes_per_association = 64,
    });
    defer registry.deinit();
    try registry.register(0);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "before reset",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);
    registry.markTerminal(0, .{ .peer_reset = 0x10c });

    // Late datagrams for a closed receive side are silently dropped.
    encoded.clearRetainingCapacity();
    try (http3.Datagram{
        .quarter_stream_id = 0,
        .payload = "after reset",
    }).write(&encoded, allocator);
    try registry.route(encoded.items);

    try std.testing.expectEqual(@as(?Terminal, null), try registry.drainedTerminal(0));
    var retained = (try registry.poll(0)).?;
    defer retained.deinit(allocator);
    try std.testing.expectEqualStrings("before reset", retained.payload);
    try std.testing.expectEqualDeep(
        Terminal{ .peer_reset = 0x10c },
        (try registry.drainedTerminal(0)).?,
    );
    // Terminal observation is stable until the higher-level association is
    // explicitly retired, which lets its opposite stream direction finish.
    try std.testing.expectEqualDeep(
        Terminal{ .peer_reset = 0x10c },
        (try registry.drainedTerminal(0)).?,
    );
    try std.testing.expectEqual(@as(usize, 0), try registry.queuedCount(0));
}

//! Local executor faults retain exactly one encrypted record transaction.
const std = @import("std");
const fixture = @import("testing/record_fixture.zig");
const support = @import("../../internal/testing/write_interruption.zig");
const record_io = @import("record_io.zig");
const allocator = std.testing.allocator;
const Resume = enum { replay, explicit, extend };

test "TLS bounded write interruptions preserve ciphertext and authenticated sequence" {
    inline for ([_]bool{ false, true }) |old| {
        try exercise(old, .before_write, 0, false, .replay);
        for ([_]support.Stage{ .after_prefix, .after_prefix_timer_rejected }) |stage| {
            for ([_]usize{ 1, 6, 12 }) |prefix| try exercise(old, stage, prefix, false, .replay);
            try exercise(old, stage, record_io.max_record_len, true, .replay);
        }
        try exercise(old, .after_prefix, 6, false, .explicit);
        try exercise(old, .before_write, 0, false, .extend);
    }
}

fn exercise(comptime old: bool, stage: support.Stage, prefix: usize, comptime cross_record: bool, resume_mode: Resume) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var probe = support.Probe{ .delegate = base, .stage = stage, .prefix_len = prefix };
    support.Probe.active = &probe;
    var vtable = base.vtable.*;
    vtable.groupConcurrent = support.Probe.groupConcurrent;
    vtable.netWrite = support.Probe.netWrite;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{});
    defer listener.deinit(base);
    const socket = try listener.socket.address.connect(base, .{ .mode = .stream });
    defer socket.close(base);
    const peer = try listener.accept(base);
    defer peer.close(base);
    var sender = try fixture.stream(old, 0x22, 0x11);
    defer sender.deinit();
    var receiver = try fixture.stream(old, 0x11, 0x22);
    defer receiver.deinit();
    const payload: []const u8 = if (cross_record) &([_]u8{'a'} ** (record_io.max_plaintext_len + 32)) else "one exact record";
    const first_plaintext = if (cross_record) record_io.max_plaintext_len else 0;
    const first_ciphertext = if (cross_record) record_io.max_plaintext_len + (if (old) @as(usize, 29) else @as(usize, 22)) else prefix;
    const records = if (cross_record) @as(u64, 2) else @as(u64, 1);
    var committed: usize = 99;
    try std.testing.expectError(error.ConcurrencyUnavailable, sender.writeAllWithDeadline(io, socket, payload, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expectEqual(first_plaintext, committed);
    try std.testing.expectEqual(first_ciphertext, probe.written);
    try std.testing.expectEqual(if (cross_record) @as(usize, 0) else prefix, sender.pending_write_offset);
    try std.testing.expectEqual(records, if (old) sender.write_traffic.next_sequence_number else sender.write_sequence);
    try std.testing.expect(!sender.failed);
    const encoded_len = sender.pending_write_len;
    probe.armed = false;
    const pending_bytes = payload[first_plaintext..];
    const extension: []const u8 = if (resume_mode == .extend) "/extra" else "";
    const relocated = try allocator.alloc(u8, pending_bytes.len + extension.len);
    defer allocator.free(relocated);
    @memcpy(relocated[0..pending_bytes.len], pending_bytes);
    @memcpy(relocated[pending_bytes.len..], extension);
    relocated[0] ^= 1;
    const before_mutation = probe.written;
    try std.testing.expectError(error.WriteInProgress, sender.writeAllWithDeadline(io, socket, relocated, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expectEqual(before_mutation, probe.written);
    try std.testing.expectEqual(@as(usize, 0), committed);
    relocated[0] ^= 1;
    for ([_][]const u8{ "", pending_bytes[0..1], "different pending record with enough bytes" }) |mismatch| {
        const before = probe.written;
        try std.testing.expectError(error.WriteInProgress, sender.writeAllWithDeadline(io, socket, mismatch, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
        try std.testing.expectEqual(@as(usize, 0), committed);
        try std.testing.expectEqual(before, probe.written);
        try std.testing.expectEqual(encoded_len, sender.pending_write_len);
        try std.testing.expect(!sender.failed);
    }
    if (resume_mode == .explicit) {
        try sender.finishPendingWrite(io, socket, &committed);
    } else {
        try sender.writeAllWithDeadline(io, socket, relocated, &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    }
    try std.testing.expectEqual(payload.len - first_plaintext + extension.len, committed);
    const extra_record_len = if (resume_mode == .extend) extension.len + (if (old) @as(usize, 29) else @as(usize, 22)) else 0;
    try std.testing.expectEqual(encoded_len + (if (cross_record) first_ciphertext else 0) + extra_record_len, probe.written);
    try std.testing.expectEqual(@as(usize, 0), sender.pending_write_len);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &sender.pending_plaintext_fingerprint.digest);
    const completed_records = records + @as(u64, if (resume_mode == .extend) 1 else 0);
    try std.testing.expectEqual(completed_records, if (old) sender.write_traffic.next_sequence_number else sender.write_sequence);
    var out: [record_io.max_plaintext_len + 32]u8 = undefined;
    var count: usize = 0;
    while (count < payload.len + extension.len) count += try receiver.readWithDeadline(base, peer, out[count .. payload.len + extension.len], .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings(payload, out[0..payload.len]);
    try std.testing.expectEqualStrings(extension, out[payload.len..count]);
    try sender.writeAllWithDeadline(io, socket, "following", &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    const next = try receiver.readWithDeadline(base, peer, &out, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings("following", out[0..next]);
    try std.testing.expectEqual(completed_records + 1, if (old) sender.write_traffic.next_sequence_number else sender.write_sequence);
}

test "TLS bounded write failure keeps real network errors terminal" {
    const Failure = struct {
        var writes: usize = 0;
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            writes += 1;
            return error.NetworkDown;
        }
    };
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    var vtable = base.vtable.*;
    vtable.netWrite = Failure.write;
    const io: std.Io = .{ .userdata = base.userdata, .vtable = &vtable };
    const socket: std.Io.net.Stream = .{ .socket = .{ .handle = 0, .address = .{ .ip4 = .loopback(0) } } };
    inline for ([_]bool{ false, true }) |old| {
        var sender = try fixture.stream(old, 0x22, 0x11);
        defer sender.deinit();
        Failure.writes = 0;
        var committed: usize = 99;
        try std.testing.expectError(error.NetworkDown, sender.writeAllWithDeadline(io, socket, "payload", &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
        try std.testing.expectEqual(@as(usize, 0), committed);
        try std.testing.expect(sender.failed);
        try std.testing.expectError(error.ConnectionClosed, sender.writeAllWithDeadline(io, socket, "payload", &committed, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
        try std.testing.expectEqual(@as(usize, 1), Failure.writes);
    }
}

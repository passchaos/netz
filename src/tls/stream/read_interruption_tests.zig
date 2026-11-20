//! Executor admission failure cannot invalidate an incomplete TLS record.
const std = @import("std");
const fixture = @import("testing/record_fixture.zig");
const record_io = @import("record_io.zig");
const allocator = std.testing.allocator;

const support = @import("../../internal/testing/read_interruption.zig");
const Fault = support.Fault;
const Probe = support.InterruptedIo;

fn seal(comptime old: bool, sender: anytype, output: []u8, payload: []const u8) !usize {
    if (old) return sender.write_traffic.seal(23, payload, output);
    const len = try sender.write_keys.seal(sender.write_sequence, 23, payload, output);
    sender.write_sequence += 1;
    return len;
}

test "TLS bounded read interruptions retain partial TLS12 and TLS13 ciphertext without losing record sequence" {
    inline for ([_]bool{ false, true }) |old| {
        for (std.enums.values(Fault)) |fault| {
            for ([_]usize{ 1, 6, 12 }) |cut| try exercise(old, fault, cut);
        }
    }
}

fn exercise(comptime old: bool, fault: Fault, cut: usize) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    Probe.delegate = base;
    defer Probe.next = null;
    var vtable = base.vtable.*;
    vtable.batchAwaitConcurrent = Probe.awaitConcurrent;
    vtable.groupConcurrent = Probe.groupConcurrent;
    vtable.futexWait = Probe.futexWait;
    const io = std.Io{ .userdata = base.userdata, .vtable = &vtable };
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(base, .{ .reuse_address = true });
    defer listener.deinit(base);
    const socket = try listener.socket.address.connect(base, .{ .mode = .stream });
    defer socket.close(base);
    const peer = try listener.accept(base);
    defer peer.close(base);
    var sender = try fixture.stream(old, 0x22, 0x11);
    defer sender.deinit();
    var receiver = try fixture.stream(old, 0x11, 0x22);
    defer receiver.deinit();
    var encoded: [record_io.max_record_len]u8 = undefined;
    const len = try seal(old, &sender, &encoded, "accepted record");
    var writer = socket.writer(base, &.{});
    try writer.interface.writeAll(encoded[0..cut]);
    var output: [64]u8 = undefined;
    try std.testing.expectError(error.Timeout, receiver.readWithDeadline(io, peer, &output, .fromNow(base, .{ .clock = .awake, .raw = .fromMilliseconds(10) })));
    try std.testing.expectEqual(cut, receiver.record_reader.encoded_len);
    Probe.next = fault;
    const expected = if (fault == .executor) error.ConcurrencyUnavailable else error.Canceled;
    try std.testing.expectError(expected, receiver.readWithDeadline(io, peer, &output, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) })));
    try std.testing.expect(!receiver.failed);
    try std.testing.expectEqual(cut, receiver.record_reader.encoded_len);
    try std.testing.expectEqual(@as(u64, 0), if (old) receiver.read_traffic.next_sequence_number else receiver.read_sequence);
    try writer.interface.writeAll(encoded[cut..len]);
    const count = try receiver.readWithDeadline(io, peer, &output, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings("accepted record", output[0..count]);
    try std.testing.expectEqual(@as(usize, 0), receiver.record_reader.encoded_len);
    try std.testing.expectEqual(@as(u64, 1), if (old) receiver.read_traffic.next_sequence_number else receiver.read_sequence);
    const next = try seal(old, &sender, &encoded, "next record");
    try writer.interface.writeAll(encoded[0..next]);
    const next_count = try receiver.readWithDeadline(io, peer, &output, .fromNow(base, .{ .clock = .awake, .raw = .fromSeconds(1) }));
    try std.testing.expectEqualStrings("next record", output[0..next_count]);
    try std.testing.expectEqual(@as(u64, 2), if (old) receiver.read_traffic.next_sequence_number else receiver.read_sequence);
}

//! Joined socket submission for development and preconfigured-key DATAGRAMs.
const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const bounded = @import("../../../internal/progress_deadline.zig");
const codec = @import("codec.zig");

const net = std.Io.net;
pub const Error = quic.one_rtt.Error || quic.runtime.ReceiveTimeoutError;
const protected_packet_capacity = codec.stack_capacity + 64;

pub fn frames(endpoint: *quic.runtime.Endpoint, to: net.IpAddress, value: []const quic.Frame, deadline: ?std.Io.Clock.Timestamp) Error!void {
    if (deadline) |until| return bounded.runVoid(endpoint.io, until, quic.runtime.Endpoint.sendFrames, .{ endpoint, to, value });
    return endpoint.sendFrames(to, value);
}

pub fn developmentBatch(endpoint: *quic.runtime.Endpoint, to: net.IpAddress, datagrams: []const []const u8, committed: *usize, deadline: ?std.Io.Clock.Timestamp) Error!void {
    committed.* = 0;
    var wait_error: ?bounded.BudgetError = null;
    const result = if (deadline) |until| result: {
        const outcome = bounded.before(endpoint.io, until, quic.runtime.Endpoint.sendManyBytesProgress, .{ endpoint, to, datagrams });
        wait_error = outcome.wait_error;
        break :result try (outcome.result orelse return wait_error orelse error.Unexpected);
    } else try endpoint.sendManyBytesProgress(to, datagrams);
    committed.* = result.sent_count;
    if (bounded.batchError(result, datagrams.len, wait_error)) |err| return err;
}

pub fn protectedBatch(endpoint: *quic.runtime.Endpoint, to: net.IpAddress, keys: quic.protection.PacketProtectionKeys, options: quic.one_rtt.BatchSendOptions, payload: []u8, packets: []u8, packet_number: *u64, committed: *usize, deadline: ?std.Io.Clock.Timestamp) Error!void {
    committed.* = 0;
    var wait_error: ?bounded.BudgetError = null;
    const result = if (deadline) |until| result: {
        const outcome = bounded.before(endpoint.io, until, quic.one_rtt.sendFramesBatchIntoProgress, .{ endpoint, to, keys, options, payload, packets });
        wait_error = outcome.wait_error;
        break :result try (outcome.result orelse return wait_error orelse error.Unexpected);
    } else try quic.one_rtt.sendFramesBatchIntoProgress(endpoint, to, keys, options, payload, packets);
    // Every protected packet consumes its nonce, including an unsent suffix.
    packet_number.* += @intCast(result.protected_count);
    committed.* = result.sent_count;
    if (bounded.batchError(result, options.packets.len, wait_error)) |err| return err;
}

pub fn protectedOne(endpoint: *quic.runtime.Endpoint, to: net.IpAddress, keys: quic.protection.PacketProtectionKeys, options: quic.one_rtt.SendOptions, packet_number: *u64, deadline: ?std.Io.Clock.Timestamp) Error!void {
    if (deadline) |until| return bounded.runVoid(endpoint.io, until, sendProtectedOne, .{ endpoint, to, keys, options, packet_number });
    return sendProtectedOne(endpoint, to, keys, options, packet_number);
}

fn sendProtectedOne(endpoint: *quic.runtime.Endpoint, to: net.IpAddress, keys: quic.protection.PacketProtectionKeys, options: quic.one_rtt.SendOptions, packet_number: *u64) Error!void {
    const sizes = try quic.one_rtt.framePacketStorageSizes(options);
    if (sizes.packet <= protected_packet_capacity) {
        var storage: [protected_packet_capacity]u8 = undefined;
        const packet = try quic.one_rtt.sealFramesInto(keys, options, &storage);
        packet_number.* += 1;
        try endpoint.sendBytes(to, packet);
    } else {
        const storage = try endpoint.allocator.alloc(u8, sizes.packet);
        defer endpoint.allocator.free(storage);
        const packet = try quic.one_rtt.sealFramesInto(keys, options, storage);
        packet_number.* += 1;
        try endpoint.sendBytes(to, packet);
    }
}

//! Charge session data when QUIC observes highest offsets, before application
//! consumption or transport retirement can hide gaps and RESET Final Size.

const webtransport = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const std = @import("std");

pub fn account(registry: *webtransport.StreamRegistry, stream: *webtransport.StreamState, stats: quic.one_rtt.RecvStreamStats) webtransport.Error!void {
    const flow = registry.flow orelse return;
    const previous = stream.receive_accounted_offset;
    const highest = if (stats.reset) |reset| reset.final_size else stats.highest_received_offset;
    const result = if (stats.reset != null)
        flow.accountReset(previous, highest, stream.receive_header_len)
    else
        flow.accountReceived(previous, highest, stream.receive_header_len);
    result catch |err| {
        registry.flow_violation = true;
        return err;
    };
    stream.receive_accounted_offset = @max(previous, highest);
}

pub fn observe(connection: *const quic.one_rtt.Connection, registry: *webtransport.StreamRegistry, stream: *webtransport.StreamState) webtransport.Error!void {
    if (registry.flow == null) return;
    const stats = connection.recvStreamStats(stream.stream_id) orelse return;
    try account(registry, stream, stats);
}

pub fn observeAll(connection: *const quic.one_rtt.Connection, registry: *webtransport.StreamRegistry) webtransport.Error!void {
    if (registry.flow == null) return;
    for (registry.registered()) |*stream| try observe(connection, registry, stream);
}

pub fn consume(registry: *webtransport.StreamRegistry, stream: *webtransport.StreamState, bytes: u64) void {
    const flow = registry.flow orelse return;
    std.debug.assert(bytes <= (stream.receive_accounted_offset -| stream.receive_header_len) - stream.receive_credited_data);
    stream.receive_credited_data += bytes;
    flow.consumed_data += bytes;
    std.debug.assert(flow.consumed_data <= flow.received.data);
}

pub fn consumeAbandoned(registry: *webtransport.StreamRegistry, stream: *webtransport.StreamState) void {
    if (registry.flow == null) return;
    consume(registry, stream, (stream.receive_accounted_offset -| stream.receive_header_len) - stream.receive_credited_data);
}

test {
    _ = @import("receive/tests.zig");
}

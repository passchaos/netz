const std = @import("std");
const webtransport = @import("../../../mod.zig");
const grant = @import("../grant.zig");
const Pair = @import("../../session_control/test_support/handshake_pair.zig").Pair;
const ObservedBatchSend = @import("../../../../quic/one_rtt/tests/observed_batch_send.zig").ObservedBatchSend;

test "WebTransport flow combined grants commit all limits in one socket submission" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    const conn = pair.connection(.server);
    const flow = pair.server.streams.flow.?;
    const snapshot = flow.*;
    const updates = [_]webtransport.Capsule{
        .{ .max_data = snapshot.receive_limit.data + 1 },
        .{ .max_streams_bidi = snapshot.receive_limit.bidi + 1 },
        .{ .max_streams_uni = snapshot.receive_limit.uni + 1 },
    };
    const original_io = conn.endpoint.io;
    var observed = ObservedBatchSend{ .delegate = original_io, .fail_on_call = 1 };
    conn.endpoint.io = observed.io();
    defer conn.endpoint.io = original_io;
    try std.testing.expectError(error.NetworkDown, grant.sendMany(&pair.server.control, &pair.server.h3, &pair.server.streams, &updates));
    try std.testing.expectEqualDeep(snapshot, flow.*);
    observed.fail_on_call = null;
    try grant.sendMany(&pair.server.control, &pair.server.h3, &pair.server.streams, &updates);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    try std.testing.expectEqual(@as(usize, 1), observed.last_message_count);
    try std.testing.expectEqual(snapshot.receive_limit.data + 1, flow.receive_limit.data);
    try std.testing.expectEqual(snapshot.receive_limit.bidi + 1, flow.receive_limit.bidi);
    try std.testing.expectEqual(snapshot.receive_limit.uni + 1, flow.receive_limit.uni);

    const accepted = flow.*;
    try std.testing.expectError(error.InvalidSessionState, grant.sendMany(&pair.server.control, &pair.server.h3, &pair.server.streams, &.{
        .{ .max_data = accepted.receive_limit.data + 1 },
        .{ .max_data = accepted.receive_limit.data + 2 },
    }));
    try std.testing.expectEqualDeep(accepted, flow.*);
    try std.testing.expectEqual(@as(usize, 2), observed.calls);
    // std.Io reports a complete single datagram as success even if an error
    // accompanies that complete prefix; advertised credit must match the wire.
    observed.fail_after_prefix = 1;
    try grant.sendMany(&pair.server.control, &pair.server.h3, &pair.server.streams, &.{.{ .max_data = accepted.receive_limit.data + 1 }});
    try std.testing.expectEqual(accepted.receive_limit.data + 1, flow.receive_limit.data);
}

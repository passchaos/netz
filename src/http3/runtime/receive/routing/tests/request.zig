const std = @import("std");
const http3 = @import("../../../../mod.zig");
const quic = @import("../../../../../quic/mod.zig");
const request_routing = @import("../request.zig");
const qpack_state = @import("../../../qpack/state.zig");
const buffered_request = @import("../../../stream/buffered/request.zig");
const stream_lifecycle = @import("../../../stream/lifecycle.zig");
const streaming_set = @import("../../../stream/set.zig");

const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const RequestStreamSet = buffered_request.Set;
const ServerRequestLifecycle = stream_lifecycle.Server;
const StreamingRequestSet = streaming_set.Set;

test "HTTP/3 server request priorities move into active lifecycle" {
    const allocator = std.testing.allocator;
    var control = try http3.ControlState.init(.{
        .max_priority_updates = 2,
    });
    defer control.deinit(allocator);
    control.settings.received = true;
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1, .incremental = true },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
    try request_routing.serverRequestReceived(
        &control,
        &lifecycle,
        0,
        .{ .urgency = 6 },
    );
    try std.testing.expectEqual(@as(u3, 1), lifecycle.priority(0).urgency);
    try std.testing.expect(lifecycle.priority(0).incremental);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
    try request_routing.serverRequestReceived(
        &control,
        &lifecycle,
        4,
        .{ .urgency = 5 },
    );
    request_routing.finishServerRequest(&control, &lifecycle, 4);
    try std.testing.expect(lifecycle.contains(0));
    try std.testing.expect(!lifecycle.contains(4));

    encoded.clearRetainingCapacity();
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 4 },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
    request_routing.reconcileServerRequestPriorities(&control, &lifecycle);
    try std.testing.expectEqual(@as(u3, 4), lifecycle.priority(0).urgency);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);

    request_routing.finishServerRequest(&control, &lifecycle, 0);
    try std.testing.expect(!lifecycle.contains(0));

    encoded.clearRetainingCapacity();
    try http3.writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 7 },
    );
    try control.applyFrame(allocator, try http3.Frame.parse(encoded.items));
    control.discardRetiredPriorityUpdates(allocator);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
}

test "HTTP/3 request router handles duplicate reset idempotently" {
    const allocator = std.testing.allocator;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(443) };
    const code = http3.ApplicationErrorCode.request_cancelled;
    const frames = [_]quic.Frame{.{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = code,
        .final_size = 0,
    } }};

    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    var qpack_decode = QpackDecodeState.init(allocator, 0, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 2);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(
        allocator,
        2,
        1024,
        .{},
        .request,
    );
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();
    try request_routing.serverRequestReceived(
        &control,
        &lifecycle,
        0,
        .{},
    );

    const first = (try request_routing.applyServerRequestPacketFrames(
        from,
        &frames,
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 1 },
        &.{},
        null,
        null,
    )) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqual(@as(usize, 1), streaming.resetCount());
    try std.testing.expect(!lifecycle.contains(0));

    try std.testing.expect((try request_routing.applyServerRequestPacketFrames(
        from,
        &frames,
        allocator,
        &control,
        &qpack_decode,
        &qpack_encode,
        0,
        &buffered,
        &streaming,
        &lifecycle,
        .{ .static_limit = 1 },
        &.{},
        null,
        null,
    )) == null);
    try std.testing.expectEqual(@as(usize, 1), streaming.resetCount());
    const queued = streaming.takeFirstReset() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), queued.stream_id);
    try std.testing.expectEqual(code, queued.application_error_code);
}

test "HTTP/3 request router enforces blocked budget across buffered and streaming sets" {
    const allocator = std.testing.allocator;
    const from: std.Io.net.IpAddress = .{ .ip4 = .loopback(443) };
    var control: http3.ControlState = .{};
    defer control.deinit(allocator);
    control.settings.local = .{
        .qpack_max_table_capacity = 256,
        .qpack_blocked_streams = 1,
    };
    var qpack_decode = QpackDecodeState.init(allocator, 256, 1024);
    defer qpack_decode.deinit();
    var qpack_encode = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        1024,
    );
    defer qpack_encode.deinit();
    var buffered = RequestStreamSet.init(allocator, 1024, 2);
    defer buffered.deinit();
    var streaming = StreamingRequestSet.init(
        allocator,
        2,
        1024,
        control.settings.local,
        .request,
    );
    defer streaming.deinit();
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "request");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/blocked" },
        .{ .name = "x-blocked", .value = "request" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message, allocator);
    try buffered.insert(from, .{
        .stream_id = 0,
        .data = message.items,
        .fin = true,
    });
    _ = try streaming.activateRequest(&buffered, 0);

    try std.testing.expectError(
        error.QpackDecompressionFailed,
        request_routing.applyServerRequestPacketFrames(
            from,
            &.{.{ .stream = .{
                .stream_id = 4,
                .data = message.items,
                .fin = true,
            } }},
            allocator,
            &control,
            &qpack_decode,
            &qpack_encode,
            1,
            &buffered,
            &streaming,
            &lifecycle,
            .{ .static_limit = 2 },
            &.{},
            null,
            null,
        ),
    );
    try std.testing.expect(streaming.find(0) != null);
    try std.testing.expect(buffered.contains(4));
}

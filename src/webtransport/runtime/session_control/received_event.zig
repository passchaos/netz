//! Protected H3 Session events must observe control-only packets as well as
//! CONNECT DATA. One packet of progress per turn preserves GOAWAY visibility
//! and leaves other Sessions' application events in their owning readers.
const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const reader_mod = @import("../protected_session_control.zig");
const control_mod = @import("../session_control.zig");
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn receive(h3: anytype, reader: *reader_mod.Reader, session_id: u62, deadline: ?std.Io.Clock.Timestamp) (reader_mod.Error || http3.runtime.ReceiveTimeoutError)!control_mod.Event {
    const H3 = @typeInfo(@TypeOf(h3)).pointer.child;
    const server = @hasDecl(H3, "pollRequestEventFor");
    const endpoint = if (server) &h3.quic_server.endpoint else &h3.quic_client.endpoint;
    const allocator = endpoint.allocator;
    var buffer: [reader_mod.buffer_capacity]u8 = undefined;
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(endpoint.io, absolute);
        reader.control.observeGoAway(h3.control.peer_goaway_id);
        if (try reader.pollPending()) |event| return event;
        // The targeted H3 response API consumes RESET metadata before
        // returning RequestCancelled/RequestRejected. Keep the exact code
        // across that transaction rather than mapping its generic error.
        const reset_code: ?u64 = if (server) null else h3.response_streams.resetFor(session_id);
        if (reset_code != null and !reader.control.state.closed) reader.control.state.close(0);
        var event = (if (server)
            try h3.pollRequestEventFor(session_id)
        else
            h3.pollResponseEvent(session_id) catch |err| {
                if (reset_code) |code| {
                    if (err == error.RequestCancelled or err == error.RequestRejected) return reader.control.resetCapsulePayload(code) orelse error.InvalidSessionState;
                }
                return err;
            }) orelse {
            if (deadline) |absolute| try h3.pollControlWithDeadline(absolute) else try h3.pollControl();
            continue;
        };
        defer event.deinit(allocator);
        const message = if (server) switch (event) {
            .reset => |reset| return reader.control.resetCapsulePayload(reset.application_error_code) orelse error.InvalidSessionState,
            .message => |value| value.value,
        } else event;
        switch (message) {
            .finished => return (try reader.finish()) orelse error.InvalidSessionState,
            .data_available => {
                const count = if (server) try h3.readRequestData(session_id, &buffer) else try h3.readResponseData(session_id, &buffer);
                if (try reader.consume(buffer[0..count])) |ready| return ready;
            },
            else => return error.InvalidSessionState,
        }
    }
}

test "WebTransport protected control deadline preserves an unreported GOAWAY advisory" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var h3: http3.runtime.ProtectedClient = undefined;
    h3.quic_client.endpoint.allocator = std.testing.allocator;
    h3.quic_client.endpoint.io = threaded.io();
    h3.control = .{ .peer_goaway_id = 0 };
    var reader = reader_mod.Reader.init(try control_mod.Control.init(std.testing.allocator, .init(0)));
    defer reader.deinit();
    try std.testing.expectError(error.Timeout, receive(&h3, &reader, 0, .{ .clock = .awake, .raw = .zero }));
    try std.testing.expect(!reader.control.peer_drain_reported and !reader.control.pending_draining);
    try std.testing.expect(!reader.control.state.draining);
    const event = try receive(&h3, &reader, 0, null);
    try std.testing.expect(event == .draining);
    try std.testing.expect(reader.control.peer_drain_reported);
}

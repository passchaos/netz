const quic = @import("../../../quic/mod.zig");
const runtime_error = @import("../error.zig");

pub fn close(
    endpoint: *quic.runtime.Endpoint,
    peer: @import("std").Io.net.IpAddress,
    err: anyerror,
) void {
    const policy = runtime_error.protocolClose(err) orelse return;
    endpoint.sendFrames(peer, &.{.{ .application_close = .{
        .error_code = policy.code,
        .reason_phrase = policy.reason,
    } }}) catch {};
}

/// Connection failure owns all development client state, including extension
/// streams. Reinitialize the containers so later deinit remains valid, without
/// allocating while reporting the original peer error.
pub fn clearClient(client: anytype) void {
    const allocator = client.quic_client.endpoint.allocator;
    const limits = client.limits;
    client.request_unusable = true;
    client.response_streams.deinit();
    client.response_streams = .init(
        allocator,
        limits.max_stream_buffer,
        limits.max_concurrent_request_streams,
    );
    client.streaming_responses.deinit();
    client.streaming_responses = .initWithInformationalLimit(
        allocator,
        limits.max_concurrent_request_streams,
        limits.max_stream_buffer,
        limits.max_informational_responses,
        .{ .enable_connect_protocol = true },
        .response,
    );
    client.request_lifecycle.deinit();
    client.request_lifecycle = .init(allocator, limits.max_concurrent_request_streams);
    client.outbound_bodies.deinit();
    client.outbound_bodies = .init(allocator, limits.max_concurrent_request_streams);
    client.qpack_decode.deinit();
    client.qpack_decode = .init(allocator, 0, limits.max_stream_buffer);
    client.qpack_encode.deinit();
    client.qpack_encode = .init(allocator, 0, limits.max_stream_buffer);
    client.stream_send_scratch.reset();
    client.development_streams.clear();
    client.development_stream_sends.clear();
    client.runtime_datagrams.clear();
}

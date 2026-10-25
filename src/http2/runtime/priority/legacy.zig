//! Keep frame structure checks while ignoring deprecated priority semantics.
const http2 = @import("../../mod.zig");

pub fn ignored(connection: anytype) bool {
    // A server must honor the client's first SETTINGS flag even when its
    // own configuration still permits RFC 7540 priority signals.
    return connection.limits.no_rfc7540_priorities or
        (connection.role == .server and connection.peer_no_rfc7540_priorities);
}

pub fn parseHeaders(connection: anytype, frame: http2.Frame) http2.Error!http2.HeadersPayload {
    return if (ignored(connection)) http2.HeadersPayload.parseIgnoringPriority(frame) else http2.HeadersPayload.parse(frame);
}

pub fn validateFrame(connection: anytype, frame: http2.Frame) http2.Error!void {
    if (ignored(connection)) {
        if (frame.header.frame_type != .priority) return error.InvalidFrameSize;
        if (frame.header.stream_id == 0) return error.InvalidStreamId;
        _ = try http2.Priority.parse(frame.payload);
    } else _ = try http2.PriorityPayload.parse(frame);
}

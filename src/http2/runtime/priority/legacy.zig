//! Validate deprecated PRIORITY frame structure while ignoring priority
//! semantics. RFC 9218 priority is handled separately.
const http2 = @import("../../mod.zig");

pub fn parseHeaders(_: anytype, frame: http2.Frame) http2.Error!http2.HeadersPayload {
    return http2.HeadersPayload.parseIgnoringPriority(frame);
}

pub fn validateFrame(_: anytype, frame: http2.Frame) http2.Error!void {
    if (frame.header.frame_type != .priority) return error.InvalidFrameSize;
    if (frame.header.stream_id == 0) return error.InvalidStreamId;
    if (frame.payload.len != 5) return error.InvalidFrameSize;
}

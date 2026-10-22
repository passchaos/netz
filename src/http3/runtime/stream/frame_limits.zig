//! Early resource preflight for HTTP/3 frames whose payload must be buffered
//! whole before QPACK decoding.

const std = @import("std");
const http3 = @import("../../mod.zig");

pub const Kind = enum { request, response };

pub fn validateFieldSectionHeader(
    header: http3.Frame.Header,
    max_stream_buffer: usize,
) http3.Error!void {
    if (header.frame_type != http3.FrameType.headers and
        header.frame_type != http3.FrameType.push_promise)
    {
        return;
    }
    if (try header.totalLength() > max_stream_buffer) {
        return error.ExcessiveLoad;
    }
}

/// Scan the leading contiguous frame sequence until a semantic boundary. An
/// incomplete type or length remains retryable; once a field-section header is
/// complete, callers can reject it without accumulating the remaining payload.
pub fn validateAvailableFieldSection(
    available: []const u8,
    max_stream_buffer: usize,
    kind: Kind,
) http3.Error!void {
    var offset: usize = 0;
    while (offset < available.len) {
        const header = http3.Frame.parseHeader(
            available[offset..],
        ) catch |err| switch (err) {
            error.BufferTooShort => return,
            else => return err,
        };
        switch (header.frame_type) {
            http3.FrameType.headers => {
                try validateFieldSectionHeader(
                    header,
                    max_stream_buffer -| offset,
                );
                return;
            },
            http3.FrameType.push_promise => {
                if (kind == .request) return;
                try validateFieldSectionHeader(
                    header,
                    max_stream_buffer -| offset,
                );
            },
            http3.FrameType.data => return,
            else => if (http3.messageStreamForbiddenFrame(
                header.frame_type,
            )) return,
        }
        const frame_length = try header.totalLength();
        if (frame_length > available.len - offset) return;
        offset += frame_length;
    }
}

test "HTTP/3 field section frame preflight uses exact buffer ownership" {
    try validateFieldSectionHeader(.{
        .frame_type = http3.FrameType.headers,
        .payload_length = 62,
        .header_length = 2,
    }, 64);
    try std.testing.expectError(
        error.ExcessiveLoad,
        validateFieldSectionHeader(.{
            .frame_type = http3.FrameType.headers,
            .payload_length = 63,
            .header_length = 2,
        }, 64),
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        validateFieldSectionHeader(.{
            .frame_type = http3.FrameType.push_promise,
            .payload_length = 63,
            .header_length = 2,
        }, 64),
    );
    // DATA is consumed incrementally and does not need to fit as one frame.
    try validateFieldSectionHeader(.{
        .frame_type = http3.FrameType.data,
        .payload_length = std.math.maxInt(usize),
        .header_length = 2,
    }, 64);

    try validateAvailableFieldSection(&.{0x01}, 64, .request);
    try validateAvailableFieldSection(&.{ 0x01, 62 }, 64, .request);
    try std.testing.expectError(
        error.ExcessiveLoad,
        validateAvailableFieldSection(&.{ 0x01, 63 }, 64, .request),
    );
    // A complete ignorable extension before HEADERS also occupies aggregate
    // stream storage and reduces the remaining exact capacity.
    try validateAvailableFieldSection(
        &.{ 0x21, 0x01, 0xaa, 0x01, 59 },
        64,
        .request,
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        validateAvailableFieldSection(
            &.{ 0x21, 0x01, 0xaa, 0x01, 60 },
            64,
            .request,
        ),
    );

    // A request-side PUSH_PROMISE remains a semantic H3_FRAME_UNEXPECTED;
    // this resource preflight must not replace that error with ExcessiveLoad.
    try validateAvailableFieldSection(&.{ 0x05, 63 }, 64, .request);
    try std.testing.expectError(
        error.ExcessiveLoad,
        validateAvailableFieldSection(&.{ 0x05, 63 }, 64, .response),
    );
}

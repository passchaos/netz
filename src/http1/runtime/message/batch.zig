const std = @import("std");
const http1 = @import("../../mod.zig");
const framing = @import("framing.zig");

/// Remove chunk framing from a previously validated request batch and compact
/// the untouched pipelined suffix. Returned heads and bodies borrow `inbuf`;
/// the caller must keep them alive only until its next read or prefix removal.
pub fn compactValidatedRequests(
    inbuf: *std.ArrayList(u8),
    heads: []http1.RequestHead,
    header_storage: []http1.Header,
    bodies: [][]const u8,
    options: http1.ParseOptions,
    wire_consumed: usize,
    max_head_bytes: usize,
    max_body_bytes: usize,
) usize {
    var read_offset: usize = 0;
    var write_offset: usize = 0;
    for (heads, bodies, 0..) |*head, *body, index| {
        const headers = header_storage[index * options.max_headers ..][0..options.max_headers];
        const source_head = http1.parseRequestHead(
            inbuf.items[read_offset..],
            headers,
            options,
        ) catch unreachable;
        const source_body_start = read_offset + source_head.head_len;
        const chunked_layout = if (source_head.body_framing == .chunked)
            framing.chunkedBodyLayout(
                inbuf.items[source_body_start..],
                max_head_bytes,
                max_body_bytes,
            ) catch unreachable
        else
            null;
        const body_len: usize = switch (source_head.body_framing) {
            .none => 0,
            .content_length => source_head.content_length.?,
            .chunked => chunked_layout.?.decoded_len,
            .close_delimited => unreachable,
        };
        const source_wire_len = if (source_head.body_framing == .chunked)
            chunked_layout.?.wire_len
        else
            body_len;

        @memmove(
            inbuf.items[write_offset..][0..source_head.head_len],
            inbuf.items[read_offset..source_body_start],
        );
        const destination_body_start = write_offset + source_head.head_len;
        if (source_head.body_framing == .chunked) {
            framing.copyChunkedPayloadForwards(
                inbuf.items[source_body_start..],
                inbuf.items[destination_body_start .. destination_body_start + body_len],
            );
        } else if (body_len != 0) {
            @memmove(
                inbuf.items[destination_body_start .. destination_body_start + body_len],
                inbuf.items[source_body_start..][0..body_len],
            );
        }

        head.* = http1.parseRequestHead(
            inbuf.items[write_offset..],
            headers,
            options,
        ) catch unreachable;
        body.* = inbuf.items[destination_body_start .. destination_body_start + body_len];
        read_offset += source_head.head_len + source_wire_len;
        write_offset = destination_body_start + body_len;
    }

    std.debug.assert(read_offset == wire_consumed);
    const suffix = inbuf.items[wire_consumed..];
    @memmove(inbuf.items[write_offset..][0..suffix.len], suffix);
    inbuf.items.len -= wire_consumed - write_offset;
    return write_offset;
}

test "HTTP/1 chunked batch compaction preserves aliased input and suffix" {
    const allocator = std.testing.allocator;
    const first =
        "POST /one HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "2\r\nab\r\n1\r\nc\r\n0\r\n\r\n";
    const second =
        "POST /two HTTP/1.1\r\nHost: example\r\n" ++
        "Transfer-Encoding: chunked\r\n\r\n" ++
        "1\r\nd\r\n0\r\n\r\n";
    const suffix = "GET /next HTTP/1.1\r\nHost: example\r\n\r\n";
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(allocator);
    try inbuf.appendSlice(allocator, first ++ second ++ suffix);
    const original_pointer = inbuf.items.ptr;

    var heads: [2]http1.RequestHead = undefined;
    var headers: [8]http1.Header = undefined;
    var bodies: [2][]const u8 = undefined;
    const consumed = compactValidatedRequests(
        &inbuf,
        &heads,
        &headers,
        &bodies,
        .{ .max_headers = 4 },
        first.len + second.len,
        1024,
        3,
    );

    try std.testing.expectEqual(original_pointer, inbuf.items.ptr);
    try std.testing.expectEqualStrings("abc", bodies[0]);
    try std.testing.expectEqualStrings("d", bodies[1]);
    try std.testing.expectEqualStrings("/one", heads[0].target);
    try std.testing.expectEqualStrings("/two", heads[1].target);
    try std.testing.expectEqualStrings(
        suffix,
        inbuf.items[consumed..],
    );
}

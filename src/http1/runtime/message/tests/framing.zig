const std = @import("std");
const http1 = @import("../../../mod.zig");
const framing = @import("../framing.zig");

test "HTTP/1 message framing rejects ambiguous head framing" {
    const conflicting = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!";
    try std.testing.expectError(
        error.ConflictingContentLength,
        targetLength(conflicting, 1024, 1024, null),
    );

    const coalesced = "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\n\r\nhello";
    try std.testing.expectEqual(
        coalesced.len,
        try targetLength(coalesced, 1024, 1024, null),
    );

    const signed_length = "HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello";
    try std.testing.expectError(
        error.InvalidContentLength,
        targetLength(signed_length, 1024, 1024, null),
    );

    const stacked_te = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        stacked_te.len,
        try targetLength(stacked_te, 1024, 1024, null),
    );

    const non_final_chunked = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n";
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        targetLength(non_final_chunked, 1024, 1024, null),
    );

    const signed_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n+5\r\nhello\r\n0\r\n\r\n";
    try std.testing.expectError(
        error.InvalidChunk,
        targetLength(signed_chunk, 1024, 1024, null),
    );
}

test "HTTP/1 message framing recognizes quoted transfer parameters without phantom codings" {
    const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: custom; note=\"a,chunked,z\", chunked\r\n\r\n";
    const body = "2\r\nok\r\n0\r\n\r\n";
    try std.testing.expectEqual((head ++ body).len, try targetLength(head ++ body, 1024, 2, .GET));
    try std.testing.expectEqual(framing.TransferEncodingState.non_chunked, try framing.transferEncodingState("HTTP/1.1 200 OK\r\nTransfer-Encoding: custom; note=\"a,chunked\""));
    const split = "POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: custom; note=\"a,chunked,z\"\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectEqual((split ++ body).len, try targetLength(split ++ body, 1024, 2, null));
}

test "HTTP/1 message framing validates transfer parameters before reading a body" {
    for ([_][]const u8{
        "chunked; x=yes",
        "gzip; note=\"unterminated, chunked",
        "custom; note=bad value, chunked",
        "custom; flag, chunked",
        "gzi(p, chunked",
    }) |value| {
        var head: [256]u8 = undefined;
        const bytes = try std.fmt.bufPrint(&head, "HTTP/1.1 200 OK\r\nTransfer-Encoding: {s}", .{value});
        try std.testing.expectError(error.InvalidTransferEncoding, framing.transferEncodingState(bytes));
    }
}

test "HTTP/1 message framing counts decoded chunk payload only" {
    const head = "POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n";
    const exact = head ++ "2;ignored=yes\r\nab\r\n3  \r\ncde\r\n0\r\n\r\n";
    try std.testing.expectEqual(
        exact.len,
        try targetLength(exact, 1024, 5, null),
    );

    const empty = head ++ "0\r\n\r\n";
    try std.testing.expectEqual(
        empty.len,
        try targetLength(empty, 1024, 0, null),
    );

    try std.testing.expectError(
        error.BodyTooLarge,
        targetLength(head ++ "6\r\n", 1024, 5, null),
    );
}

test "HTTP/1 message framing rejects malformed chunk extensions" {
    const head = "POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n";
    try std.testing.expectError(
        error.InvalidChunk,
        targetLength(
            head ++ "1;name=bad value\r\nx\r\n0\r\n\r\n",
            1024,
            1,
            null,
        ),
    );
}

test "HTTP/1 message framing bounds chunk extensions and trailers independently" {
    const head = "POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n";
    const trailer_fields = "Digest: abc\r\n\r\n";
    const trailer = "0\r\nDigest: abc\r\n\r\n";
    try std.testing.expectEqual(
        (head ++ trailer).len,
        try targetLength(
            head ++ trailer,
            trailer_fields.len,
            0,
            null,
        ),
    );
    try std.testing.expectError(
        error.HeadersTooLarge,
        targetLength(
            head ++ trailer,
            trailer_fields.len - 1,
            0,
            null,
        ),
    );

    var incomplete: std.ArrayList(u8) = .empty;
    defer incomplete.deinit(std.testing.allocator);
    try incomplete.appendSlice(std.testing.allocator, head ++ "1;");
    try incomplete.appendNTimes(
        std.testing.allocator,
        'a',
        http1.max_chunk_extension_bytes + 30,
    );
    try std.testing.expectError(
        error.ChunkExtensionTooLarge,
        targetLength(incomplete.items, 1024, 1, null),
    );

    var complete: std.ArrayList(u8) = .empty;
    defer complete.deinit(std.testing.allocator);
    try complete.appendSlice(std.testing.allocator, head ++ "1");
    try complete.appendNTimes(
        std.testing.allocator,
        ' ',
        http1.max_chunk_size_line_bytes - 1,
    );
    try complete.appendSlice(std.testing.allocator, "\r\nx\r\n0\r\n\r\n");
    try std.testing.expectError(
        error.ChunkExtensionTooLarge,
        targetLength(complete.items, 1024, 1, null),
    );
}

test "HTTP/1 aggregate framing bounds cumulative chunk wire overhead" {
    const head = "POST / HTTP/1.1\r\nHost: example\r\nTransfer-Encoding: chunked\r\n\r\n";
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try encoded.appendSlice(std.testing.allocator, head);
    for (0..2) |_| {
        try encoded.append(std.testing.allocator, '1');
        try encoded.appendNTimes(
            std.testing.allocator,
            ' ',
            http1.max_chunk_size_line_bytes - 2,
        );
        try encoded.appendSlice(std.testing.allocator, "\r\nx\r\n");
    }
    try encoded.appendSlice(std.testing.allocator, "0\r\n\r\n");

    try std.testing.expectError(
        error.BodyTooLarge,
        targetLength(encoded.items, 64, 2, null),
    );
}

test "HTTP/1 message framing enforces exact head limits" {
    const exact = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    try std.testing.expectEqual(
        @as(?usize, exact.len - 4),
        try framing.findHeadEndWithinLimit(exact, exact.len),
    );
    try std.testing.expectError(
        error.HeadersTooLarge,
        framing.findHeadEndWithinLimit(exact, exact.len - 1),
    );

    const incomplete = "GET / HTTP/1.1\r\nHost: example";
    try std.testing.expectEqual(
        @as(?usize, null),
        try framing.findHeadEndWithinLimit(incomplete, incomplete.len + 1),
    );
    try std.testing.expectError(
        error.HeadersTooLarge,
        framing.findHeadEndWithinLimit(incomplete, incomplete.len),
    );
}

test "HTTP/1 message framing applies method response semantics" {
    const ok = "HTTP/1.1 200 OK\r\n";
    try std.testing.expect(framing.responseHeadForbidsBody(ok, .HEAD));
    try std.testing.expect(framing.responseHeadForbidsBody(ok, .CONNECT));
    try std.testing.expect(!framing.responseHeadForbidsBody(ok, .GET));
    try std.testing.expect(framing.responseHeadForbidsBody(
        "HTTP/1.1 204 No Content\r\n",
        null,
    ));
    try std.testing.expect(!framing.informationalResponseToSkip(101));
    try std.testing.expect(framing.informationalResponseToSkip(103));
}

test "HTTP/1 message framing validates automatic continue eligibility" {
    try std.testing.expect(framing.requestShouldSendContinue(
        "POST / HTTP/1.1\r\nHost: example\r\nExpect: 100-continue\r\nContent-Length: 1",
    ));
    try std.testing.expect(!framing.requestShouldSendContinue(
        "POST / HTTP/1.0\r\nHost: example\r\nExpect: 100-continue\r\nContent-Length: 1",
    ));
    try std.testing.expect(!framing.requestShouldSendContinue(
        "POST / HTTP/1.1\r\nHost: example\r\nExpect: other\r\nContent-Length: 1",
    ));
    try std.testing.expect(!framing.requestShouldSendContinue(
        "GET / HTTP/1.1\r\nHost: example\r\nExpect: 100-continue",
    ));
    try std.testing.expect(framing.requestShouldSendContinue(
        "POST / HTTP/1.1\r\nHost: example\r\nExpect: 100-continue\r\nTransfer-Encoding: custom; note=\"a,chunked,z\", chunked",
    ));
    try std.testing.expect(!framing.requestShouldSendContinue(
        "POST / HTTP/1.1\r\nHost: example\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked; x=yes",
    ));
}

fn targetLength(
    bytes: []const u8,
    max_head_bytes: usize,
    max_body_bytes: usize,
    request_method: ?http1.Method,
) framing.Error!usize {
    const head_end = std.mem.indexOf(u8, bytes, "\r\n\r\n").?;
    return framing.messageTargetLength(
        bytes,
        head_end,
        max_head_bytes,
        max_body_bytes,
        request_method,
    );
}

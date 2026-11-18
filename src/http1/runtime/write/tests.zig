const std = @import("std");
const write_root = @import("../write.zig");

const http1 = @import("../../mod.zig");

const BatchScratch = write_root.BatchScratch;
const ResponseOptions = write_root.ResponseOptions;
const Scratch = write_root.Scratch;
const StreamingChunkScratch = write_root.StreamingChunkScratch;
const StreamingFraming = write_root.StreamingFraming;
const StreamingRequestOptions = write_root.StreamingRequestOptions;
const TrailerScratch = write_root.TrailerScratch;
const TrailerValueScratch = write_root.TrailerValueScratch;
const chunk_header_buffer_len = write_root.chunk_header_buffer_len;
const content_length_buffer_len = write_root.content_length_buffer_len;
const freeStackFirstHeaderBuffer = write_root.freeStackFirstHeaderBuffer;
const header_staging_capacity = write_root.header_staging_capacity;
const prepareRequest = write_root.prepareRequest;
const prepareResponse = write_root.prepareResponse;
const prepareResponseParts = write_root.prepareResponseParts;
const prepareStreamingRequest = write_root.prepareStreamingRequest;
const prepareStreamingResponse = write_root.prepareStreamingResponse;
const stackFirstHeaderBuffer = write_root.stackFirstHeaderBuffer;
const streaming = write_root.streaming;
const trailer_value_staging_capacity = write_root.trailer_value_staging_capacity;

test "HTTP/1 streaming framing honors explicit Trailer declarations" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const request = try prepareStreamingRequest(
        allocator,
        .{
            .method = .POST,
            .host = "localhost",
            .headers = &.{
                .{ .name = "Transfer-Encoding", .value = "chunked" },
                .{ .name = "Trailer", .value = "Digest, X-Complete" },
            },
        },
        &scratch,
    );
    try std.testing.expectEqual(
        StreamingFraming.chunked,
        request.framing,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        scratch.trailerHeaders().len,
    );

    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .headers = &.{
                    .{ .name = "Transfer-Encoding", .value = "chunked" },
                    .{ .name = "Trailer", .value = "Digest" },
                },
                .trailer_names = &.{"X-Complete"},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .trailer_names = &.{"Connection"},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingResponse(
            allocator,
            .{
                .trailer_names = &.{"Upgrade"},
                .request_accepts_trailers = true,
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareStreamingResponse(
            allocator,
            .{ .trailer_names = &.{"Digest"} },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareResponse(allocator, .{
            .body = "ok",
            .trailers = &.{.{
                .name = "Digest",
                .value = "sha-256=demo",
            }},
        }, &scratch),
    );
    const response = try prepareStreamingResponse(
        allocator,
        .{
            .headers = &.{.{
                .name = "Trailer",
                .value = "Digest",
            }},
            .request_accepts_trailers = true,
        },
        &scratch,
    );
    try std.testing.expectEqual(
        StreamingFraming.chunked,
        response.framing,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            response.head,
            "Transfer-Encoding: chunked\r\n",
        ) != null,
    );

    const head_response = try prepareStreamingResponse(
        allocator,
        .{
            .request_method = .HEAD,
            .headers = &.{.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            }},
        },
        &scratch,
    );
    try std.testing.expectEqual(
        StreamingFraming.suppressed,
        head_response.framing,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            head_response.head,
            "Transfer-Encoding: chunked\r\n",
        ) != null,
    );
}

test "HTTP/1 aggregate framing honors explicit Trailer declarations" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const request = try prepareRequest(
        allocator,
        .{
            .method = .POST,
            .host = "localhost",
            .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
            .body = "ok",
            .trailers = &.{.{
                .name = "Digest",
                .value = "sha-256=request",
            }},
        },
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 0), request.body.len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.endsWith(
        u8,
        request.header,
        "2\r\nok\r\n0\r\nDigest: sha-256=request\r\n\r\n",
    ));

    try std.testing.expectError(
        error.InvalidTrailer,
        prepareRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
                .trailers = &.{.{ .name = "X-Other", .value = "value" }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTrailer,
        prepareRequest(
            allocator,
            .{
                .method = .POST,
                .host = "localhost",
                .headers = &.{.{
                    .name = "Trailer",
                    .value = "Content-Length",
                }},
            },
            &scratch,
        ),
    );

    const response = try prepareResponse(
        allocator,
        .{
            .headers = &.{.{ .name = "Trailer", .value = "Digest" }},
            .body = "ok",
            .trailers = &.{.{
                .name = "Digest",
                .value = "sha-256=response",
            }},
            .request_accepts_trailers = true,
        },
        &scratch,
    );
    try std.testing.expectEqual(@as(usize, 0), response.body.len);
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.header,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.endsWith(
        u8,
        response.header,
        "2\r\nok\r\n0\r\nDigest: sha-256=response\r\n\r\n",
    ));

    try std.testing.expectError(
        error.InvalidTrailer,
        prepareResponse(
            allocator,
            .{
                .headers = &.{
                    .{ .name = "Transfer-Encoding", .value = "chunked" },
                    .{ .name = "Trailer", .value = "Digest" },
                },
                .trailers = &.{.{ .name = "X-Other", .value = "value" }},
                .request_accepts_trailers = true,
            },
            &scratch,
        ),
    );
}

test "HTTP/1 runtime request writer normalizes TE connection semantics" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const request = try prepareRequest(
        allocator,
        .{
            .host = "localhost",
            .headers = &.{.{ .name = "TE", .value = "trailers" }},
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "TE: trailers\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Connection: TE\r\n",
    ) != null);

    const streaming_request = try prepareStreamingRequest(
        allocator,
        .{
            .host = "localhost",
            .body_length = 0,
            .headers = &.{.{ .name = "TE", .value = "trailers" }},
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_request.head,
        "Connection: TE\r\n",
    ) != null);

    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{ .name = "TE", .value = "chunked" }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareResponse(
            allocator,
            .{ .headers = &.{.{ .name = "TE", .value = "trailers" }} },
            &scratch,
        ),
    );
}

test "HTTP/1 runtime writers reject unsafe Connection options" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidConnection,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{
                    .{ .name = "Connection", .value = "Content-Length" },
                    .{ .name = "Content-Length", .value = "0" },
                },
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidConnection,
        prepareStreamingRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close, bad option",
                }},
                .body_length = 0,
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidConnection,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{
                    .name = "Upgrade",
                    .value = "websocket",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidResponse,
        prepareResponse(
            allocator,
            .{ .status = 101, .reason = "Switching Protocols" },
            &scratch,
        ),
    );

    const switching = try prepareResponse(
        allocator,
        .{
            .status = 101,
            .reason = "Switching Protocols",
            .headers = &.{
                .{ .name = "Connection", .value = "Upgrade" },
                .{ .name = "Upgrade", .value = "websocket" },
            },
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        switching.header,
        "Connection: Upgrade\r\nUpgrade: websocket\r\n",
    ) != null);
}

test "HTTP/1 response writers enforce empty 205 content" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareResponse(allocator, .{
            .status = 205,
            .reason = "Reset Content",
            .body = "forbidden",
        }, &scratch),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        prepareResponse(allocator, .{
            .status = 205,
            .reason = "Reset Content",
            .headers = &.{.{
                .name = "Content-Length",
                .value = "1",
            }},
        }, &scratch),
    );

    const fixed = try prepareResponse(allocator, .{
        .status = 205,
        .reason = "Reset Content",
    }, &scratch);
    try std.testing.expectEqualStrings("", fixed.body);
    try std.testing.expect(std.mem.indexOf(
        u8,
        fixed.header,
        "Content-Length: 0\r\n",
    ) != null);

    const chunked = try prepareResponse(allocator, .{
        .status = 205,
        .reason = "Reset Content",
        .headers = &.{.{
            .name = "Transfer-Encoding",
            .value = "chunked",
        }},
    }, &scratch);
    try std.testing.expectEqualStrings("", chunked.body);
    try std.testing.expect(std.mem.endsWith(
        u8,
        chunked.header,
        "\r\n0\r\n\r\n",
    ));

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareResponseParts(allocator, &.{
            .{ .body = "valid prefix" },
            .{ .status = 205, .body = "forbidden" },
        }, &scratch),
    );

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareStreamingResponse(allocator, .{
            .status = 205,
            .body_length = 1,
        }, &scratch),
    );
    const reset_streaming = try prepareStreamingResponse(allocator, .{
        .status = 205,
        .headers = &.{.{
            .name = "Transfer-Encoding",
            .value = "chunked",
        }},
    }, &scratch);
    try std.testing.expectEqual(
        StreamingFraming.chunked,
        reset_streaming.framing,
    );
    try std.testing.expectEqual(
        @as(?usize, 0),
        reset_streaming.expected_length,
    );
}

test "HTTP/1 304 response writers preserve metadata transfer coding" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);
    const headers = [_]http1.Header{
        .{ .name = "Content-Length", .value = "123" },
        .{ .name = "Transfer-Encoding", .value = "gzip, chunked" },
    };

    const aggregate = try prepareResponse(allocator, .{
        .status = 304,
        .reason = "Not Modified",
        .headers = &headers,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        aggregate.header,
        "Transfer-Encoding: gzip, chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        aggregate.header,
        "Content-Length:",
    ) == null);
    try std.testing.expect(std.mem.endsWith(u8, aggregate.header, "\r\n\r\n"));
    try std.testing.expect(!std.mem.endsWith(
        u8,
        aggregate.header,
        "\r\n0\r\n\r\n",
    ));
    try std.testing.expectEqualStrings("", aggregate.body);

    const streaming_head = try prepareStreamingResponse(allocator, .{
        .status = 304,
        .reason = "Not Modified",
        .headers = &headers,
    }, &scratch);
    try std.testing.expectEqual(
        StreamingFraming.suppressed,
        streaming_head.framing,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_head.head,
        "Transfer-Encoding: gzip, chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_head.head,
        "Content-Length:",
    ) == null);
    try std.testing.expect(std.mem.endsWith(
        u8,
        streaming_head.head,
        "\r\n\r\n",
    ));
}

test "HTTP/1 request writers enforce empty TRACE content" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidContentLength,
        prepareRequest(
            allocator,
            .{ .method = .TRACE, .host = "localhost", .body = "body" },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidTransferEncoding,
        prepareRequest(
            allocator,
            .{
                .method = .TRACE,
                .host = "localhost",
                .headers = &.{.{
                    .name = "Transfer-Encoding",
                    .value = "chunked",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        prepareStreamingRequest(
            allocator,
            .{
                .method = .TRACE,
                .host = "localhost",
                .body_length = 1,
            },
            &scratch,
        ),
    );

    const request = try prepareStreamingRequest(
        allocator,
        .{
            .method = .TRACE,
            .host = "localhost",
        },
        &scratch,
    );
    try std.testing.expectEqual(StreamingFraming{ .fixed = 0 }, request.framing);
    try std.testing.expect(
        std.mem.indexOf(u8, request.head, "Transfer-Encoding:") == null,
    );
}

test "HTTP/1 request writers validate 100-continue expectations" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    try std.testing.expectError(
        error.InvalidExpectation,
        prepareRequest(
            allocator,
            .{
                .host = "localhost",
                .headers = &.{.{
                    .name = "Expect",
                    .value = "100-continue",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidExpectation,
        prepareStreamingRequest(
            allocator,
            .{
                .host = "localhost",
                .body_length = 0,
                .headers = &.{.{
                    .name = "Expect",
                    .value = "100-continue",
                }},
            },
            &scratch,
        ),
    );
    try std.testing.expectError(
        error.InvalidExpectation,
        prepareResponse(
            allocator,
            .{ .headers = &.{.{
                .name = "Expect",
                .value = "100-continue",
            }} },
            &scratch,
        ),
    );

    const request = try prepareStreamingRequest(
        allocator,
        .{
            .host = "localhost",
            .headers = &.{.{
                .name = "Expect",
                .value = "100-continue",
            }},
        },
        &scratch,
    );
    try std.testing.expectEqual(StreamingFraming.chunked, request.framing);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.head,
        "Expect: 100-continue\r\n",
    ) != null);

    const extension = try prepareRequest(
        allocator,
        .{
            .host = "localhost",
            .headers = &.{.{
                .name = "Expect",
                .value = "custom=value; mode=fast",
            }},
        },
        &scratch,
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        extension.header,
        "Expect: custom=value; mode=fast\r\n",
    ) != null);
}

test "HTTP/1 runtime response writers preserve an empty reason separator" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const aggregate = try prepareResponse(allocator, .{
        .status = 204,
        .reason = "",
    }, &scratch);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 204 \r\n\r\n",
        aggregate.header,
    );

    const streaming_head = try prepareStreamingResponse(allocator, .{
        .status = 204,
        .reason = "",
    }, &scratch);
    try std.testing.expectEqualStrings(
        "HTTP/1.1 204 \r\n\r\n",
        streaming_head.head,
    );
    try std.testing.expectEqual(
        StreamingFraming.suppressed,
        streaming_head.framing,
    );
}

test "HTTP/1 writer preserves or title-cases request and response fields" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const preserved = try prepareRequest(allocator, .{
        .host = "example.com",
        .headers = &.{.{ .name = "x-TRACE-id", .value = "one" }},
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        preserved.header,
        "x-TRACE-id: one\r\n",
    ) != null);

    const request = try prepareRequest(allocator, .{
        .host = "example.com",
        .headers = &.{.{ .name = "x-TRACE-id", .value = "one" }},
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "X-Trace-Id: one\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Host: example.com\r\n",
    ) != null);

    const response = try prepareResponse(allocator, .{
        .headers = &.{.{ .name = "cOnTeNt-TyPe", .value = "text/plain" }},
        .body = "ok",
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        response.header,
        "Content-Type: text/plain\r\n",
    ) != null);
}

test "HTTP/1 duplicate trailers encode as separate runtime field lines" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);

    const message = try prepareResponse(allocator, .{
        .headers = &.{.{
            .name = "transfer-encoding",
            .value = "chunked",
        }},
        .body = "ok",
        .trailers = &.{
            .{ .name = "x-checkSUM", .value = "one" },
            .{ .name = "X-CHECKsum", .value = "two" },
        },
        .request_accepts_trailers = true,
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        message.header,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        message.header,
        "0\r\nX-Checksum: one\r\nX-Checksum: two\r\n\r\n",
    ) != null);

    const streaming_head = try prepareStreamingResponse(allocator, .{
        .headers = &.{.{
            .name = "transfer-encoding",
            .value = "chunked",
        }},
        .trailer_names = &.{"x-checksum"},
        .request_accepts_trailers = true,
        .header_name_casing = .title_case,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_head.head,
        "Transfer-Encoding: chunked\r\n",
    ) != null);
    const end = try streaming.prepareEndWithCasing(
        allocator,
        &.{
            .{ .name = "x-checkSUM", .value = "one" },
            .{ .name = "X-CHECKsum", .value = "two" },
        },
        &scratch,
        streaming_head.header_name_casing,
    );
    try std.testing.expectEqualStrings(
        "0\r\nX-Checksum: one\r\nX-Checksum: two\r\n\r\n",
        end,
    );
}

test "HTTP/1 streaming terminator rejects malformed trailers before encoding" {
    const allocator = std.testing.allocator;
    var scratch: Scratch = .{};
    defer scratch.deinit(allocator);
    try scratch.encoded.appendSlice(allocator, "stale");

    try std.testing.expectError(
        error.MalformedHeader,
        streaming.prepareEnd(
            allocator,
            &.{.{
                .name = "X-Trace",
                .value = "ok\r\nInjected: yes",
            }},
            &scratch,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), scratch.encoded.items.len);
}

test "HTTP/1 write scratch allocates batch state lazily" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 72), @sizeOf(BatchScratch));
        try std.testing.expectEqual(@as(usize, 48), @sizeOf(Scratch));
        try std.testing.expectEqual(
            @as(usize, 20),
            content_length_buffer_len,
        );
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Scratch, "batch")),
        );
    }

    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    try std.testing.expect(scratch.batch == null);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        scratch.batchScratch(failing.allocator()),
    );
    try std.testing.expect(scratch.batch == null);

    const batch = try scratch.batchScratch(allocator);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectEqual(
        @intFromPtr(batch),
        @intFromPtr(try scratch.batchScratch(no_alloc.allocator())),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    var failing_vectors = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        batch.prepareVectors(failing_vectors.allocator(), 4),
    );
    try std.testing.expectEqual(@as(usize, 0), batch.vectors.items.len);

    const vectors = try batch.prepareVectors(allocator, 4);
    try std.testing.expectEqual(@as(usize, 4), vectors.descriptors.len);
    try std.testing.expectEqual(@as(usize, 4), vectors.parts.len);

    var warmed_vectors = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    _ = try batch.prepareVectors(warmed_vectors.allocator(), 4);
    try std.testing.expect(!warmed_vectors.has_induced_failure);

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    var counted_scratch = Scratch{};
    defer counted_scratch.deinit(tracked);
    const counted = try counted_scratch.batchScratch(tracked);
    _ = try counted.prepareVectors(tracked, 4);
    try std.testing.expectEqual(@as(usize, 2), tracking.allocations);
}

test "HTTP/1 request preparation uses stack-first header descriptors" {
    var tracking = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = tracking.allocator();
    var scratch = Scratch{};
    defer scratch.deinit(allocator);

    const request = try prepareRequest(allocator, .{
        .method = .POST,
        .host = "example.test",
        .headers = &.{.{ .name = "X-Test", .value = "value" }},
        .body = "body",
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Host: example.test\r\n",
    ) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Content-Length: 4\r\n",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
    try std.testing.expectEqual(@as(usize, 0), tracking.resize_index);

    const allocations = tracking.allocations;
    const streaming_request = try prepareStreamingRequest(allocator, .{
        .method = .POST,
        .host = "example.test",
        .headers = &.{.{ .name = "X-Test", .value = "value" }},
        .body_length = 4,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        streaming_request.head,
        "Content-Length: 4\r\n",
    ) != null);
    try std.testing.expectEqual(
        allocations,
        tracking.allocations,
    );
}

test "HTTP/1 header staging uses stack and one exact overflow allocation" {
    const allocator = std.testing.allocator;
    var stack: [header_staging_capacity]http1.Header = undefined;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    const common = try stackFirstHeaderBuffer(
        no_alloc.allocator(),
        &stack,
        stack.len,
    );
    defer freeStackFirstHeaderBuffer(
        no_alloc.allocator(),
        &stack,
        common,
    );
    try std.testing.expectEqual(stack[0..].ptr, common.ptr);
    try std.testing.expect(!no_alloc.has_induced_failure);

    try std.testing.expectError(
        error.OutOfMemory,
        stackFirstHeaderBuffer(
            no_alloc.allocator(),
            &stack,
            stack.len + 1,
        ),
    );
    try std.testing.expect(no_alloc.has_induced_failure);

    const overflow = try stackFirstHeaderBuffer(
        allocator,
        &stack,
        stack.len + 1,
    );
    defer freeStackFirstHeaderBuffer(allocator, &stack, overflow);
    try std.testing.expect(overflow.ptr != stack[0..].ptr);
    try std.testing.expectEqual(stack.len + 1, overflow.len);

    var input: [header_staging_capacity - 3]http1.Header = undefined;
    for (&input) |*header| {
        header.* = .{ .name = "X-Test", .value = "value" };
    }
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    var scratch = Scratch{};
    defer scratch.deinit(tracked);
    const request = try prepareRequest(tracked, .{
        .host = "example.test",
        .headers = &input,
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "X-Test: value\r\n",
    ) != null);
    // The exact descriptor fallback is already released when the encoded head
    // is returned; only Scratch's encoded-byte allocation remains live.
    try std.testing.expectEqual(
        tracking.deallocations + 1,
        tracking.allocations,
    );
}

test "HTTP/1 Content-Length staging fits the largest usize" {
    const allocator = std.testing.allocator;
    var scratch = Scratch{};
    defer scratch.deinit(allocator);

    const request = try prepareStreamingRequest(allocator, .{
        .method = .POST,
        .host = "example.test",
        .body_length = std.math.maxInt(usize),
    }, &scratch);
    const prefix = "Content-Length: ";
    const start = (std.mem.indexOf(u8, request.head, prefix) orelse
        return error.TestUnexpectedResult) + prefix.len;
    const end = std.mem.indexOfPos(u8, request.head, start, "\r\n") orelse
        return error.TestUnexpectedResult;
    const rendered = request.head[start..end];
    try std.testing.expectEqual(content_length_buffer_len, rendered.len);
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        try std.fmt.parseInt(usize, rendered, 10),
    );
}

test "HTTP/1 write scratch allocates multi-chunk state lazily" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(
            @as(usize, 24),
            @sizeOf(StreamingChunkScratch),
        );
        try std.testing.expectEqual(@as(usize, 18), chunk_header_buffer_len);
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Scratch, "streaming_chunks")),
        );
    }

    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    try std.testing.expect(scratch.streaming_chunks == null);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        scratch.streamingChunkScratch(failing.allocator()),
    );
    try std.testing.expect(scratch.streaming_chunks == null);

    const chunks = try scratch.streamingChunkScratch(allocator);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectEqual(
        @intFromPtr(chunks),
        @intFromPtr(try scratch.streamingChunkScratch(no_alloc.allocator())),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);

    var failing_storage = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        chunks.prepare(failing_storage.allocator(), 2),
    );
    try std.testing.expectEqual(@as(usize, 0), chunks.storage.items.len);

    const buffers = try chunks.prepare(allocator, 2);
    try std.testing.expectEqual(
        @as(usize, 2 * chunk_header_buffer_len),
        buffers.descriptors.len,
    );
    try std.testing.expectEqual(@as(usize, 6), buffers.parts.len);

    var warmed = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    _ = try chunks.prepare(warmed.allocator(), 2);
    try std.testing.expect(!warmed.has_induced_failure);

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    var counted_scratch = Scratch{};
    defer counted_scratch.deinit(tracked);
    const counted = try counted_scratch.streamingChunkScratch(tracked);
    _ = try counted.prepare(tracked, 2);
    try std.testing.expectEqual(@as(usize, 2), tracking.allocations);

    var max_header: [chunk_header_buffer_len]u8 = undefined;
    const rendered = try std.fmt.bufPrint(
        &max_header,
        "{x}\r\n",
        .{std.math.maxInt(usize)},
    );
    try std.testing.expectEqual(chunk_header_buffer_len, rendered.len);
}

test "HTTP/1 write scratch allocates trailer state only when requested" {
    const allocator = std.testing.allocator;
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 24), @sizeOf(TrailerScratch));
        try std.testing.expectEqual(
            @as(usize, 8),
            @sizeOf(@FieldType(Scratch, "trailers")),
        );
    }

    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    _ = try prepareRequest(allocator, .{
        .host = "localhost",
    }, &scratch);
    try std.testing.expect(scratch.trailers == null);

    const complete = try prepareRequest(allocator, .{
        .method = .POST,
        .host = "localhost",
        .body = "body",
        .trailers = &.{.{ .name = "Digest", .value = "sha-256=value" }},
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        complete.header,
        "Trailer: Digest\r\n",
    ) != null);
    try std.testing.expect(scratch.trailers == null);

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        scratch.trailerScratch(failing.allocator()),
    );
    try std.testing.expect(scratch.trailers == null);

    const trailer_scratch = try scratch.trailerScratch(allocator);
    var failing_storage = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        trailer_scratch.prepare(
            failing_storage.allocator(),
            &.{.{ .name = "Trailer", .value = "Digest" }},
            &.{},
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        scratch.trailerHeaders().len,
    );

    const options = StreamingRequestOptions{
        .method = .POST,
        .host = "localhost",
        .headers = &.{.{
            .name = "Transfer-Encoding",
            .value = "chunked",
        }},
        .trailer_names = &.{"Digest"},
    };
    const prepared = try prepareStreamingRequest(allocator, options, &scratch);
    try std.testing.expectEqual(StreamingFraming.chunked, prepared.framing);
    try std.testing.expectEqual(@as(usize, 1), scratch.trailerHeaders().len);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const warmed = try prepareStreamingRequest(
        no_alloc.allocator(),
        options,
        &scratch,
    );
    try std.testing.expectEqual(StreamingFraming.chunked, warmed.framing);
    try std.testing.expect(!no_alloc.has_induced_failure);

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    var counted_scratch = Scratch{};
    defer counted_scratch.deinit(tracked);
    const counted = try counted_scratch.trailerScratch(tracked);
    _ = try counted.prepare(
        tracked,
        &.{.{ .name = "Trailer", .value = "Digest" }},
        &.{},
    );
    try std.testing.expectEqual(@as(usize, 2), tracking.allocations);
}

test "HTTP/1 Trailer value staging uses stack and exact fallback" {
    const allocator = std.testing.allocator;
    var value: TrailerValueScratch = .{};
    defer value.deinit(allocator);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const common = try value.render(no_alloc.allocator(), &.{
        .{ .name = "Digest", .value = "one" },
        .{ .name = "digest", .value = "two" },
        .{ .name = "X-Complete", .value = "yes" },
    });
    try std.testing.expectEqualStrings("Digest, X-Complete", common);
    try std.testing.expect(!no_alloc.has_induced_failure);

    var long_name: [trailer_value_staging_capacity + 1]u8 = undefined;
    @memset(&long_name, 'x');
    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    var failed_value: TrailerValueScratch = .{};
    try std.testing.expectError(
        error.OutOfMemory,
        failed_value.render(failing.allocator(), &.{.{
            .name = &long_name,
            .value = "value",
        }}),
    );
    try std.testing.expect(failed_value.heap == null);

    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var overflow_value: TrailerValueScratch = .{};
    const overflow = try overflow_value.render(
        tracking.allocator(),
        &.{.{ .name = &long_name, .value = "value" }},
    );
    try std.testing.expectEqualStrings(&long_name, overflow);
    try std.testing.expectEqual(@as(usize, 1), tracking.allocations);
    overflow_value.deinit(tracking.allocator());
    try std.testing.expectEqual(@as(usize, 1), tracking.deallocations);
}

test "HTTP/1 complete trailers need no persistent trailer scratch" {
    var tracking = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    const allocator = tracking.allocator();
    var scratch = Scratch{};
    defer scratch.deinit(allocator);

    const request = try prepareRequest(allocator, .{
        .method = .POST,
        .host = "example.test",
        .body = "body",
        .trailers = &.{.{ .name = "Digest", .value = "sha-256=value" }},
    }, &scratch);
    try std.testing.expect(std.mem.indexOf(
        u8,
        request.header,
        "Trailer: Digest\r\n",
    ) != null);
    try std.testing.expect(scratch.trailers == null);
    try std.testing.expectEqual(
        tracking.deallocations + 1,
        tracking.allocations,
    );
}

test "HTTP/1 warmed response batch reuses lazy scratch" {
    const allocator = std.testing.allocator;
    var scratch = Scratch{};
    defer scratch.deinit(allocator);
    const responses = [_]ResponseOptions{
        .{ .body = "one" },
        .{ .body = "two" },
    };
    _ = try prepareResponseParts(allocator, &responses, &scratch);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
    });
    const parts = try prepareResponseParts(
        no_alloc.allocator(),
        &responses,
        &scratch,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 4), parts.len);
}

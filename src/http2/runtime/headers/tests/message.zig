const std = @import("std");
const http2 = @import("../../../mod.zig");
const headers = @import("../message.zig");

test "HTTP/2 response DATA length checks overruns and final short bodies before delivery" {
    const checked = headers.checkedResponseBodyLength;
    try std.testing.expectEqual(@as(usize, 2), try checked(3, 0, 2, 10, true, false));
    try std.testing.expectEqual(@as(usize, 3), try checked(3, 2, 1, 10, true, true));
    try std.testing.expectEqual(@as(usize, 3), try checked(3, 3, 0, 10, true, true));
    try std.testing.expectError(error.InvalidContentLength, checked(1, 0, 2, 10, true, false));
    try std.testing.expectError(error.InvalidContentLength, checked(3, 1, 1, 10, true, true));
    try std.testing.expectError(error.InvalidContentLength, checked(3, 2, 0, 10, true, true));
    try std.testing.expectError(error.InvalidContentLength, checked(0, 0, 1, 10, true, false));
    // Representation metadata on HEAD/304 does not describe DATA content.
    try std.testing.expectEqual(@as(usize, 0), try checked(123, 0, 0, 0, false, true));
    try std.testing.expectError(error.InvalidContentLength, checked(123, 0, 1, 10, false, false));
    try std.testing.expectEqual(@as(usize, 2), try checked(null, 1, 1, 2, true, true));
    try std.testing.expectError(error.MessageTooLarge, checked(null, 1, 2, 2, true, false));
    const max = std.math.maxInt(usize);
    try std.testing.expectEqual(max, try checked(null, max - 1, 1, max, true, true));
    try std.testing.expectError(error.MessageTooLarge, checked(null, max, 1, max, true, false));
}

test "HTTP/2 message headers validate request targets and pseudo ordering" {
    const valid = [_]http2.Hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/items?q=1" },
        .{ .name = "host", .value = "example.test" },
    };
    try headers.validateHeaderBlock(&valid, .request);
    const lookup = try headers.requestHeaderLookup(&valid);
    try std.testing.expectEqualStrings(
        "example.test",
        lookup.requestAuthority().?,
    );

    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = "accept", .value = "*/*" },
            .{ .name = ":path", .value = "/late" },
            .{ .name = ":scheme", .value = "https" },
        }, .request),
    );
    try std.testing.expectError(
        error.MissingPseudoHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
        }, .request),
    );
}

test "HTTP/2 message headers validate CONNECT authority and body semantics" {
    try headers.validateHeaderBlock(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "[2001:db8::1]:443" },
    }, .request);
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":authority", .value = "example.test" },
        }, .request),
    );

    const head = headers.responseSemanticsFromMethod("HEAD", false);
    try std.testing.expect(headers.responseForbidsBody(200, "HEAD", false));
    try std.testing.expectError(
        error.InvalidContentLength,
        headers.validateResponseBodyForRequestSemantics(
            200,
            head,
            &.{},
            &.{},
            &.{.{ .name = "x-trailer", .value = "bad" }},
        ),
    );

    const connect = headers.responseSemanticsFromMethod("CONNECT", false);
    try std.testing.expectError(
        error.InvalidContentLength,
        headers.validateResponseBodyForRequestSemantics(
            200,
            connect,
            &.{},
            "tunnel-bytes",
            &.{},
        ),
    );
}

test "HTTP/2 message headers parse duplicate content length atomically" {
    try std.testing.expectEqual(
        @as(?usize, 5),
        try headers.contentLength(&.{
            .{ .name = "content-length", .value = "5, 5" },
            .{ .name = "content-length", .value = "5" },
        }),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        headers.contentLength(&.{
            .{ .name = "content-length", .value = "5" },
            .{ .name = "content-length", .value = "6" },
        }),
    );
}

test "HTTP/2 message headers enforce uncompressed list size" {
    const fields = [_]http2.Hpack.HeaderField{.{
        .name = "x",
        .value = "value",
    }};
    try headers.validateHeaderListSize(&fields, 38);
    try std.testing.expectError(
        error.MessageTooLarge,
        headers.validateHeaderListSize(&fields, 37),
    );
}

test "HTTP/2 message headers reject connection-specific fields and invalid trailers" {
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/bad-te" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "te", .value = "gzip" },
        }, .request),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/bad-transfer-encoding" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "transfer-encoding", .value = "chunked" },
        }, .request),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/connection" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = "connection", .value = "keep-alive" },
        }, .request),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "te", .value = "trailers" },
        }, .response),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "connection", .value = "x-hop" },
        }, .response),
    );

    const TrailerCase = struct {
        name: []const u8,
        value: []const u8,
    };
    inline for ([_]TrailerCase{
        .{ .name = "te", .value = "trailers" },
        .{ .name = "content-length", .value = "5" },
        .{ .name = "content-type", .value = "text/plain" },
    }) |field| {
        try std.testing.expectError(
            error.InvalidHeader,
            headers.validateHeaderBlock(
                &.{.{ .name = field.name, .value = field.value }},
                .request_trailers,
            ),
        );
    }
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{.{ .name = "set-cookie", .value = "a=b" }}, .response_trailers),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/bad-value" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = "x-bad", .value = "ok\r\ninjected: yes" },
        }, .request),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "x-bad", .value = "bad\x7fvalue" },
        }, .response),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        headers.validateDeclaredRequestLength(&.{.{ .name = "content-length", .value = "5" }}, "pong".len),
    );
}

test "HTTP/2 message headers enforce RFC 8470 Early-Data placement" {
    // Recipients treat invalid or repeated request fields as equivalent to 1.
    try headers.validateHeaderBlock(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/forwarded" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "early-data", .value = "invalid" },
        .{ .name = "early-data", .value = "1" },
    }, .request);

    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":status", .value = "200" },
            .{ .name = "early-data", .value = "1" },
        }, .response),
    );
    inline for (.{
        headers.HeaderBlockKind.request_trailers,
        headers.HeaderBlockKind.response_trailers,
    }) |kind| {
        try std.testing.expectError(
            error.InvalidHeader,
            headers.validateHeaderBlock(&.{.{
                .name = "early-data",
                .value = "1",
            }}, kind),
        );
    }
}

test "HTTP/2 message headers validate methods request targets and authorities" {
    try std.testing.expectError(
        error.MissingPseudoHeader,
        headers.validateHeaderBlock(&.{.{ .name = ":method", .value = "CONNECT" }}, .request),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "CONNECT" },
            .{ .name = ":authority", .value = "example.com:443" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
        }, .request),
    );
    try headers.validateHeaderBlock(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "[2001:db8::1]:443" },
    }, .request);
    inline for (.{ "example.com", "example.com:65536" }) |authority| {
        try std.testing.expectError(
            error.InvalidHeader,
            headers.validateHeaderBlock(&.{
                .{ .name = ":method", .value = "CONNECT" },
                .{ .name = ":authority", .value = authority },
            }, .request),
        );
    }
    try std.testing.expectError(
        error.MissingPseudoHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "connect" },
            .{ .name = ":authority", .value = "example.com:443" },
        }, .request),
    );
    try headers.validateHeaderBlock(&.{
        .{ .name = ":method", .value = "connect" },
        .{ .name = ":path", .value = "/ordinary-extension-method" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    }, .request);

    const RequestTargetCase = struct {
        method: []const u8,
        path: []const u8,
        scheme: []const u8,
        authority: ?[]const u8 = null,
    };
    inline for ([_]RequestTargetCase{
        .{ .method = "options", .path = "*", .scheme = "https", .authority = null },
        .{ .method = "", .path = "/", .scheme = "https", .authority = null },
        .{ .method = "GET /", .path = "/", .scheme = "https", .authority = null },
        .{ .method = "GET", .path = "", .scheme = "https", .authority = null },
        .{ .method = "GET", .path = "relative", .scheme = "https", .authority = null },
        .{ .method = "GET", .path = "?q=1", .scheme = "https", .authority = null },
        .{ .method = "GET", .path = "/resource#fragment", .scheme = "https", .authority = null },
        .{ .method = "GET", .path = "/invalid-scheme", .scheme = "https://", .authority = null },
        .{ .method = "GET", .path = "/invalid-authority", .scheme = "https", .authority = "user@example.com" },
        .{ .method = "GET", .path = "/invalid-port", .scheme = "https", .authority = "example.com:65536" },
    }) |case| {
        const with_authority = [_]http2.Hpack.HeaderField{
            .{ .name = ":method", .value = case.method },
            .{ .name = ":path", .value = case.path },
            .{ .name = ":scheme", .value = case.scheme },
            .{ .name = ":authority", .value = case.authority orelse "example.com" },
        };
        const fields = if (case.authority != null) with_authority[0..] else with_authority[0..3];
        try std.testing.expectError(error.InvalidHeader, headers.validateHeaderBlock(fields, .request));
    }

    try headers.validateHeaderBlock(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/?q=1" },
        .{ .name = ":scheme", .value = "https" },
    }, .request);
    try headers.validateHeaderBlock(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/matching-authorities" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "EXAMPLE.com:443" },
        .{ .name = "host", .value = "example.COM:443" },
    }, .request);
    try std.testing.expectError(
        error.InvalidHeader,
        headers.validateHeaderBlock(&.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/mismatched-authorities" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "origin.example" },
            .{ .name = "host", .value = "proxy.example" },
        }, .request),
    );
}

test "HTTP/2 message headers validate names status and lookup fields" {
    inline for (.{ "bad:name", ":bad:name" }) |name| {
        try std.testing.expectError(
            error.InvalidHeader,
            headers.validateHeaderBlock(&.{
                .{ .name = ":method", .value = "GET" },
                .{ .name = ":path", .value = "/bad-name" },
                .{ .name = ":scheme", .value = "https" },
                .{ .name = name, .value = "value" },
            }, .request),
        );
    }

    inline for (.{ "20x", "099", "101" }) |status| {
        try std.testing.expectError(
            error.InvalidStatus,
            headers.validateHeaderBlock(&.{.{ .name = ":status", .value = status }}, .response),
        );
    }

    const response_lookup = try headers.responseHeaderLookup(&.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "content-length", .value = "0, 0" },
    });
    try std.testing.expectEqualStrings("204", response_lookup.status.?);
    try std.testing.expectEqual(@as(?usize, 0), response_lookup.content_length);

    const host_lookup = try headers.requestHeaderLookup(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/host-only" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "host", .value = "example.com" },
    });
    try std.testing.expectEqualStrings("GET", host_lookup.method.?);
    try std.testing.expectEqualStrings("/host-only", host_lookup.path.?);
    try std.testing.expectEqualStrings("https", host_lookup.scheme.?);
    try std.testing.expectEqualStrings("example.com", host_lookup.requestAuthority().?);

    const lookup_with_length = try headers.requestHeaderLookup(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/lookup" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "content-length", .value = "5, 5" },
        .{ .name = "priority", .value = "u=1" },
    });
    try std.testing.expectEqual(@as(?usize, 5), lookup_with_length.content_length);
    try std.testing.expectEqualStrings("u=1", lookup_with_length.priority.?);

    try std.testing.expect(headers.responseForbidsBody(200, "HEAD", false));
    try std.testing.expect(!headers.responseForbidsBody(200, "head", false));
    try std.testing.expect(headers.responseForbidsBody(200, "CONNECT", false));
    try std.testing.expect(!headers.responseForbidsBody(200, "connect", false));
}

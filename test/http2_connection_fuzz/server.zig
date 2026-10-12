const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const http2 = netz.http2;
const runtime = http2.runtime;

pub fn State(comptime Server: type, comptime tls: bool) type {
    return struct {
        server: *Server,
        allocator: std.mem.Allocator,
        input: []const u8,
        summary: model.Summary = .{},
        err: ?anyerror = null,

        pub fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const sequence = self.input[0..@min(
                self.input.len,
                model.max_operations,
            )];
            var index: usize = 0;
            while (index < sequence.len) {
                var last_stream_id: u31 = 0;
                var connection = try self.server.acceptWithTimeout(
                    model.timeout,
                );
                var connection_open = true;
                defer if (connection_open) connection.close();
                if (tls) try validateTls(&connection);
                var connection_key_updates: u64 = 0;
                while (index < sequence.len) : (index += 1) {
                    const operation = sequence[index];
                    switch (model.kind(operation)) {
                        0, 1, 2 => last_stream_id = try completeRequest(
                            &connection,
                            operation,
                            index,
                        ),
                        3 => last_stream_id = try streamResponse(
                            &connection,
                            operation,
                            index,
                        ),
                        4 => last_stream_id = try responseBatch(
                            &connection,
                            operation,
                            index,
                        ),
                        5 => {
                            const expected = pingPayload(operation, index);
                            try std.testing.expectEqual(
                                expected,
                                try connection.readPingWithTimeout(
                                    model.timeout,
                                ),
                            );
                        },
                        6 => last_stream_id = try expectCancellation(
                            &connection,
                            operation,
                            index,
                        ),
                        7 => {
                            try connection.sendGoAway(
                                last_stream_id,
                                .no_error,
                                "fuzz-rotate",
                            );
                            self.summary.goaways += 1;
                            index += 1;
                            break;
                        },
                    }
                    if (tls and model.requestsKeyUpdate(operation)) {
                        connection_key_updates += 1;
                        self.summary.key_updates += 1;
                        try validateKeyUpdates(
                            &connection,
                            connection_key_updates,
                        );
                    }
                }
                connection.close();
                connection_open = false;
            }
        }
    };
}

fn validateTls(connection: *runtime.Connection) !void {
    try std.testing.expectEqualStrings(
        "h2",
        connection.negotiatedAlpn() orelse return error.InvalidAlpn,
    );
    try std.testing.expectEqual(
        netz.tls.stream.NegotiatedCipherSuite.aes_128_gcm_sha256,
        connection.negotiatedCipherSuite().?,
    );
    try std.testing.expectEqual(
        netz.tls.stream.TranscriptHash.sha256,
        connection.negotiatedTranscriptHash().?,
    );
}

fn validateKeyUpdates(
    connection: *runtime.Connection,
    expected: u64,
) !void {
    const counts = connection.keyUpdateCounts() orelse
        return error.MissingTlsState;
    try std.testing.expectEqual(expected, counts.sent);
    try std.testing.expectEqual(expected, counts.received);
    try std.testing.expect(!counts.awaiting_peer_response);
}

fn completeRequest(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
) !u31 {
    var request = try connection.readRequestWithTimeout(model.timeout);
    defer request.deinit(std.testing.allocator);
    try validateRequest(request, operation, index, "");
    const response = model.Bytes.response(operation, index);
    try connection.writeResponse(request.stream_id, .{
        .body = &response.value,
        .request_method = request.method,
    });
    return request.stream_id;
}

fn streamResponse(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
) !u31 {
    var request = try connection.readRequestWithTimeout(model.timeout);
    defer request.deinit(std.testing.allocator);
    try validateRequest(request, operation, index, "");
    const response = model.Bytes.response(operation, index);
    var writer = try connection.startResponse(request.stream_id, .{
        .headers = &.{.{ .name = "content-length", .value = "3" }},
        .request_method = request.method,
    });
    defer writer.deinit();
    try writer.write(response.value[0..1]);
    try writer.finishData(response.value[1..]);
    return request.stream_id;
}

fn responseBatch(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
) !u31 {
    var first = try connection.readRequestWithTimeout(model.timeout);
    defer first.deinit(std.testing.allocator);
    var second = try connection.readRequestWithTimeout(model.timeout);
    defer second.deinit(std.testing.allocator);
    try validateRequest(first, operation, index, "/a");
    try validateRequest(second, operation, index, "/b");
    const first_body = model.Bytes.response(operation, index);
    const second_body = [_]u8{
        first_body.value[0],
        first_body.value[1],
        first_body.value[2] ^ 0xff,
    };
    // Reverse response order to exercise stream correlation independently of
    // wire arrival order.
    try connection.writeResponse(second.stream_id, .{ .body = &second_body });
    try connection.writeResponse(first.stream_id, .{ .body = &first_body.value });
    return @max(first.stream_id, second.stream_id);
}

fn expectCancellation(
    connection: *runtime.Connection,
    operation: u8,
    index: usize,
) !u31 {
    var request = try connection.readRequestWithTimeout(model.timeout);
    defer request.deinit(std.testing.allocator);
    try validateRequest(request, operation, index, "");
    var reset = try connection.readResetStreamWithTimeout(model.timeout);
    defer reset.deinit(std.testing.allocator);
    try std.testing.expectEqual(request.stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(http2.ErrorCode.cancel, reset.reset.error_code);
    return request.stream_id;
}

fn validateRequest(
    request: runtime.OwnedRequest,
    operation: u8,
    index: usize,
    suffix: []const u8,
) !void {
    var path_storage: [40]u8 = undefined;
    try std.testing.expectEqualStrings(
        try model.pathBuffer(&path_storage, operation, index, suffix),
        request.path,
    );
    try std.testing.expectEqualStrings(
        if (model.kind(operation) == 0 or model.kind(operation) == 3 or
            model.kind(operation) == 4 or model.kind(operation) == 6)
            "GET"
        else
            "POST",
        request.method,
    );
    if (model.kind(operation) == 1 or model.kind(operation) == 2) {
        const expected = model.Bytes.request(operation, index);
        try std.testing.expectEqualSlices(u8, &expected.value, request.body);
    } else {
        try std.testing.expectEqual(@as(usize, 0), request.body.len);
    }
    if (model.kind(operation) == 1) {
        try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
        try std.testing.expectEqualStrings(
            "complete",
            request.trailers[0].value,
        );
    }
}

pub fn pingPayload(operation: u8, index: usize) [8]u8 {
    return .{ operation, @intCast(index), 1, 2, 3, 4, 5, 6 };
}

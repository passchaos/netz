const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const http1 = netz.http1;
const runtime = http1.runtime;

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
            var connections: usize = 0;
            while (connections == 0 or index < sequence.len) {
                var connection = try self.server.acceptWithTimeout(
                    model.timeout,
                );
                var connection_open = true;
                defer if (connection_open) connection.close();
                if (tls) try validateTls(&connection);
                var connection_key_updates: u64 = 0;
                connections += 1;
                while (index < sequence.len) : (index += 1) {
                    const operation = sequence[index];
                    var request = try connection.readRequestWithTimeout(
                        .{},
                        model.timeout,
                    );
                    defer request.deinit(self.allocator);
                    try validateRequest(request.request, operation, index);
                    try writeResponse(
                        &connection,
                        request.request,
                        operation,
                        index,
                    );
                    self.summary.requests += 1;
                    if (tls and model.requestsKeyUpdate(operation)) {
                        connection_key_updates += 1;
                        self.summary.key_updates += 1;
                        try validateKeyUpdates(
                            &connection,
                            connection_key_updates,
                        );
                    }
                    if (model.closesConnection(operation)) {
                        self.summary.server_closes += 1;
                        index += 1;
                        break;
                    }
                }
                connection.close();
                connection_open = false;
            }
        }
    };
}

fn validateTls(connection: *runtime.Connection) !void {
    try std.testing.expectEqual(
        netz.tls.stream.CipherSuite.aes_128_gcm_sha256,
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

fn validateRequest(
    request: http1.Request,
    operation: u8,
    index: usize,
) !void {
    var target_storage: [32]u8 = undefined;
    try std.testing.expectEqualStrings(
        try model.targetBuffer(&target_storage, operation, index),
        request.target,
    );
    try std.testing.expectEqual(model.method(operation), request.method);
    if (model.requestHasBody(operation)) {
        const expected = model.Bytes.request(operation, index);
        try std.testing.expectEqualSlices(
            u8,
            &expected.value,
            request.body,
        );
    } else {
        try std.testing.expectEqual(@as(usize, 0), request.body.len);
    }
    switch (model.kind(operation)) {
        2 => try std.testing.expectEqual(
            http1.BodyFraming.content_length,
            request.body_framing,
        ),
        3 => {
            try std.testing.expectEqual(
                http1.BodyFraming.chunked,
                request.body_framing,
            );
            try std.testing.expectEqual(@as(usize, 1), request.trailers.len);
            try std.testing.expectEqualStrings(
                "X-Request-Digest",
                request.trailers[0].name,
            );
            try std.testing.expectEqualStrings(
                "complete",
                request.trailers[0].value,
            );
        },
        7 => try std.testing.expect(!request.keepAlive()),
        else => {},
    }
}

fn writeResponse(
    connection: *runtime.Connection,
    request: http1.Request,
    operation: u8,
    index: usize,
) !void {
    const response = model.Bytes.response(operation, index);
    switch (model.kind(operation)) {
        4 => {
            var writer = try connection.startResponse(.{
                .body_length = response.value.len,
                .request_method = request.method,
            });
            defer writer.deinit();
            try writer.write(response.value[0..1]);
            try writer.writeChunks(&.{
                response.value[1..2],
                &.{},
                response.value[2..],
            });
            try writer.finish();
        },
        5 => {
            var writer = try connection.startResponse(.{
                .headers = &.{.{
                    .name = "Connection",
                    .value = "close",
                }},
                .trailer_names = &.{"X-Response-Digest"},
                .request_accepts_trailers = request.acceptsTrailers(),
                .request_method = request.method,
            });
            defer writer.deinit();
            try writer.writeChunks(&.{
                response.value[0..1],
                response.value[1..],
            });
            try writer.finishTrailers(&.{.{
                .name = "X-Response-Digest",
                .value = "complete",
            }});
        },
        6 => try connection.writeResponse(.{
            .body = &response.value,
            .request_method = request.method,
        }),
        7 => try connection.writeResponse(.{
            .headers = &.{.{
                .name = "Connection",
                .value = "close",
            }},
            .body = &response.value,
            .request_method = request.method,
        }),
        else => try connection.writeResponse(.{
            .body = &response.value,
            .request_method = request.method,
        }),
    }
}

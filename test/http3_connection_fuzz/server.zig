const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const http3 = netz.http3;
const runtime = http3.runtime;

pub const State = struct {
    server: *runtime.HandshakeServer,
    allocator: std.mem.Allocator,
    input: []const u8,
    err: ?anyerror = null,

    pub fn run(self: *@This()) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *@This()) !void {
        var session = try self.server.acceptWithTimeout(model.timeout);
        defer session.deinit();
        var next_stream_id: u62 = 0;
        var shutdown_started = false;
        for (self.input, 0..) |operation, index| {
            switch (model.kind(operation)) {
                0, 1, 2, 6 => {
                    var request = try session.receiveRequestWithTimeout(
                        model.timeout,
                    );
                    defer request.deinit(self.allocator);
                    try validateRequest(request, operation, index, "");
                    const body = model.Bytes.response(operation, index);
                    try session.sendResponseWithTimeout(
                        request.stream_id,
                        .{
                            .status = 200,
                            .body = &body.value,
                            .request_method = request.request.method,
                        },
                        model.timeout,
                    );
                    next_stream_id += 4;
                },
                3 => {
                    var request = try session.receiveRequestWithTimeout(
                        model.timeout,
                    );
                    defer request.deinit(self.allocator);
                    try validateRequest(request, operation, index, "");
                    const body = model.Bytes.response(operation, index);
                    try session.startResponseWithTimeout(
                        request.stream_id,
                        .{
                            .status = 200,
                            .headers = &.{.{
                                .name = "content-length",
                                .value = "3",
                            }},
                            .request_method = request.request.method,
                        },
                        body.value.len,
                        model.timeout,
                    );
                    var progress: runtime.BodyWriteProgress = .{};
                    try session.sendResponseBodyPartsPacedWithTimeout(
                        request.stream_id,
                        &.{ body.value[0..1], &.{}, body.value[1..] },
                        false,
                        &progress,
                        model.timeout,
                    );
                    try session.finishResponseTrailersPacedWithTimeout(
                        request.stream_id,
                        &.{.{ .name = "x-response-state", .value = "complete" }},
                        model.timeout,
                    );
                    next_stream_id += 4;
                },
                4 => {
                    var first = try session.receiveRequestWithTimeout(
                        model.timeout,
                    );
                    defer first.deinit(self.allocator);
                    var second = try session.receiveRequestWithTimeout(
                        model.timeout,
                    );
                    defer second.deinit(self.allocator);
                    try validateRequest(first, operation, index, "/a");
                    try validateRequest(second, operation, index, "/b");
                    const first_body = model.Bytes.response(operation, index);
                    const second_body = [_]u8{
                        first_body.value[0],
                        first_body.value[1],
                        first_body.value[2] ^ 0xff,
                    };
                    try session.sendResponseWithTimeout(second.stream_id, .{
                        .status = 200,
                        .body = &second_body,
                    }, model.timeout);
                    try session.sendResponseWithTimeout(first.stream_id, .{
                        .status = 200,
                        .body = &first_body.value,
                    }, model.timeout);
                    next_stream_id += 8;
                },
                5 => {
                    while (true) {
                        var event = try session.receiveRequestEventWithTimeout(
                            model.timeout,
                        );
                        defer event.deinit(self.allocator);
                        switch (event) {
                            .reset => |reset| {
                                try std.testing.expectEqual(
                                    next_stream_id,
                                    reset.stream_id,
                                );
                                try std.testing.expectEqual(
                                    @as(u64, http3.ApplicationErrorCode.request_cancelled),
                                    reset.application_error_code,
                                );
                                break;
                            },
                            .message => |message| switch (message.value) {
                                .data_available => {
                                    var scratch: [16]u8 = undefined;
                                    _ = try session.readRequestData(
                                        message.stream_id,
                                        &scratch,
                                    );
                                },
                                .head, .trailers, .finished, .push_promise => {},
                            },
                        }
                    }
                    next_stream_id += 4;
                },
                7 => {
                    try session.initiateShutdownWithTimeout(model.timeout);
                    try session.completeShutdownWithTimeout(model.timeout);
                    shutdown_started = true;
                    break;
                },
            }
        }
        if (!shutdown_started) {
            try session.initiateShutdownWithTimeout(model.timeout);
            try session.completeShutdownWithTimeout(model.timeout);
        }
    }
};

fn validateRequest(
    request: runtime.OwnedHandshakeRequest,
    operation: u8,
    index: usize,
    suffix: []const u8,
) !void {
    var path_storage: [40]u8 = undefined;
    try std.testing.expectEqualStrings(
        try model.pathBuffer(&path_storage, operation, index, suffix),
        request.request.path,
    );
    const kind = model.kind(operation);
    try std.testing.expectEqualStrings(
        if (kind == 1 or kind == 2) "POST" else if (kind == 6) "HEAD" else "GET",
        request.request.method,
    );
    if (kind == 1 or kind == 2) {
        const expected = model.Bytes.request(operation, index);
        try std.testing.expectEqualSlices(
            u8,
            &expected.value,
            request.request.body,
        );
    } else {
        try std.testing.expectEqual(@as(usize, 0), request.request.body.len);
    }
    if (kind == 1 or kind == 2) {
        try std.testing.expectEqual(@as(usize, 1), request.request.trailers.len);
        try std.testing.expectEqualStrings(
            "complete",
            request.request.trailers[0].value,
        );
    }
}

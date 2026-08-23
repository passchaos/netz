const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const runtime = @import("../runtime.zig");

const Observation = struct {
    statuses: [2]u16 = undefined,
    headers_valid: bool = true,
    count: usize = 0,

    fn observe(
        context_ptr: *anyopaque,
        response: http3.InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context_ptr));
        if (self.count >= self.statuses.len) {
            self.headers_valid = false;
            return;
        }
        const expected_name = if (response.status == 103)
            "link"
        else
            "x-progress";
        const expected_value = if (response.status == 103)
            "</runtime.css>"
        else
            "half";
        self.headers_valid = self.headers_valid and std.mem.eql(
            u8,
            findHeader(response.headers, expected_name) orelse "",
            expected_value,
        );
        self.statuses[self.count] = response.status;
        self.count += 1;
    }
};

fn findHeader(
    headers: []const http3.Qpack.HeaderField,
    name: []const u8,
) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
}

test "HTTP/3 incremental response reader bounds informational heads" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);

    try http3.writeResponseSequence(
        &bytes,
        allocator,
        &.{
            .{ .status = 103 },
            .{ .status = 102 },
            .{ .status = 103 },
        },
        .{ .status = 204 },
    );
    var reader = runtime.StreamingMessageReader
        .initResponseWithInformationalLimit(allocator, 0, 512, .{}, 2);
    defer reader.deinit();
    try reader.insert(.{
        .stream_id = 0,
        .data = bytes.items,
        .fin = true,
    });
    for ([_]u16{ 103, 102 }) |expected| {
        var event = (try reader.next(table)) orelse
            return error.TestUnexpectedResult;
        defer event.deinit(allocator);
        try std.testing.expect(event == .head);
        try std.testing.expectEqual(expected, event.head.response.status);
    }
    try std.testing.expectError(
        error.TooManyInformationalResponses,
        reader.next(table),
    );
}

test "HTTP/3 protected client observes and bounds informational responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0x61, 0x62, 0x63, 0x64 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x81} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x91} ** quic.protection.secret_len,
    );
    var server = try runtime.ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.ProtectedServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |scenario| {
                var request = try self.server.receiveRequest();
                defer request.deinit(self.server.quic_server.endpoint.allocator);
                const informational = if (scenario == 0)
                    &[_]http3.InformationalResponse{
                        .{
                            .status = 103,
                            .headers = &.{.{
                                .name = "link",
                                .value = "</runtime.css>",
                            }},
                        },
                        .{
                            .status = 102,
                            .headers = &.{.{
                                .name = "x-progress",
                                .value = "half",
                            }},
                        },
                    }
                else
                    &[_]http3.InformationalResponse{
                        .{ .status = 103 },
                        .{ .status = 102 },
                        .{ .status = 103 },
                    };
                try self.server.sendResponseWithInformational(
                    request.from,
                    request.stream_id,
                    informational,
                    .{ .status = 200, .body = "final" },
                );
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try runtime.ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_informational_responses = 2,
        },
    );
    defer client.deinit();

    var observation: Observation = .{};
    var response = try client.requestWithInformational(.{
        .method = "GET",
        .path = "/informational",
        .authority = "localhost",
    }, .{
        .context = &observation,
        .on_response = Observation.observe,
    });
    defer response.deinit(allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        observation.statuses[0..observation.count],
    );
    try std.testing.expect(observation.headers_valid);
    try std.testing.expectEqualStrings("final", response.response.body);

    try std.testing.expectError(
        error.TooManyInformationalResponses,
        client.request(.{
            .method = "GET",
            .path = "/informational-over-limit",
            .authority = "localhost",
        }),
    );

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

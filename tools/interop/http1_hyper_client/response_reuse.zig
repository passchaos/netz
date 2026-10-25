//! Independently verify Hyper's EOF response boundaries over TCP and TLS.
const std = @import("std");
const http1 = @import("netz").http1;
const runtime = http1.runtime;

pub fn exercise(allocator: std.mem.Allocator, io: std.Io, port: u16, tls_options: ?runtime.VailTlsClientOptions) !void {
    const limits = runtime.Limits{ .response_head_timeout = .fromSeconds(5), .max_body_bytes = 4096 };
    for ([_]bool{ false, true }) |streaming| {
        var client = if (tls_options) |options|
            try runtime.Client.connectVailTlsHost(allocator, io, "localhost", port, limits, options)
        else
            try runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(port) }, limits);
        defer client.close();
        const request = runtime.RequestOptions{ .target = "/eof", .host = "localhost", .version = .http_1_0, .headers = &.{.{ .name = "Connection", .value = "keep-alive" }} };
        if (streaming) {
            const Sink = struct {
                body: std.ArrayList(u8) = .empty,
                heads: usize = 0,

                fn begin(self: *@This(), head: runtime.StreamingResponseHead) !void {
                    try std.testing.expectEqual(http1.BodyFraming.close_delimited, head.body_framing);
                    try std.testing.expect(!head.keepAlive());
                    try std.testing.expect(head.must_close);
                    self.heads += 1;
                }

                fn consume(self: *@This(), bytes: []const u8) !void {
                    try self.body.appendSlice(std.heap.c_allocator, bytes);
                }
            };
            var sink: Sink = .{};
            defer sink.body.deinit(std.heap.c_allocator);
            var response = try client.requestStreamingWithOptionsAndHead(request, .{}, null, &sink, Sink.begin, Sink.consume);
            defer response.deinit(allocator);
            try std.testing.expectEqual(@as(usize, 1), sink.heads);
            try std.testing.expect(!response.keepAlive());
            try std.testing.expect(response.must_close);
            try std.testing.expectEqualStrings("hyper-eof", sink.body.items);
        } else {
            var response = try client.requestWithTimeout(request, .fromSeconds(5));
            defer response.deinit(allocator);
            try std.testing.expectEqual(http1.BodyFraming.close_delimited, response.response.body_framing);
            try std.testing.expect(!response.response.keepAlive());
            try std.testing.expect(response.response.must_close);
            try std.testing.expectEqualStrings("hyper-eof", response.response.body);
        }
        try std.testing.expect(!client.isReusable());
        try std.testing.expectError(error.ConnectionUnusable, client.requestWithTimeout(request, .fromSeconds(5)));
    }
    std.debug.print("netz HTTP/1 client verified Hyper EOF response metadata: transport={s} aggregate=true streaming=true reusable=false\n", .{if (tls_options != null) "tls" else "cleartext"});
}

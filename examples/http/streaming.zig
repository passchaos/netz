//! Stream request and response bodies incrementally over HTTP/1.1.
//!
//! The server consumes each request chunk as it arrives and writes a chunked
//! response while the upload is still in flight. The client writes its body in
//! pieces and consumes response chunks through a callback, so neither side
//! aggregates the complete message.

const std = @import("std");
const netz = @import("netz");

const chunk_bytes = 16 * 1024;
const chunk_count = 8;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .max_head_bytes = 8 * 1024,
            .max_body_bytes = chunk_bytes * chunk_count,
        },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.Server,
        received: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            const Sink = struct {
                total: usize = 0,

                fn consume(context: *@This(), bytes: []const u8) !void {
                    context.total += bytes.len;
                    std.debug.print("server chunk: {d} bytes\n", .{bytes.len});
                }
            };
            var sink = Sink{};
            var request = try connection.readRequestStreaming(
                &sink,
                Sink.consume,
            );
            defer request.deinit(self.server.allocator);
            self.received = sink.total;

            // A null body length selects chunked framing, so the response head
            // is visible before the first response chunk is produced.
            var response = try connection.startResponse(.{
                .status = 200,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body_length = null,
                .request_method = request.method,
            });
            defer response.deinit();
            try response.write("streamed ");
            try response.write("response ");
            try response.write("chunks\n");
            try response.finish();
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    var client = try netz.http1.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{},
    );
    defer client.close();

    const host = try std.fmt.allocPrint(
        allocator,
        "127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(host);

    var request = try client.startRequest(.{
        .method = .POST,
        .target = "/stream",
        .host = host,
        // No length is known up front, so the request body uses chunked
        // framing and every write becomes an independent HTTP/1 chunk.
        .body_length = null,
    });
    defer request.deinit();

    var chunk: [chunk_bytes]u8 = undefined;
    @memset(&chunk, 's');
    for (0..chunk_count) |index| {
        chunk[0] = @intCast('0' + (index % 10));
        try request.write(&chunk);
    }
    try request.finish();

    const Sink = struct {
        total: usize = 0,

        fn consume(context: *@This(), bytes: []const u8) !void {
            context.total += bytes.len;
            std.debug.print("client chunk: {d} bytes\n", .{bytes.len});
        }
    };
    var sink = Sink{};
    var response = try request.readResponseStreaming(&sink, Sink.consume);
    defer response.deinit(allocator);

    server_task.await(io);
    if (task.err) |err| return err;

    std.debug.print(
        "server received {d} bytes, client received {d} bytes\n",
        .{ task.received, sink.total },
    );
}

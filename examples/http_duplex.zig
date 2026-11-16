//! Stream a request body and response through the unified duplex handle.
//!
//! The same `netz.http.RequestHandle` shape serves HTTP/1, HTTP/2, and HTTP/3;
//! this example uses one cleartext HTTP/1 connection and shows incremental
//! body writes, callback-scoped response chunks, and trailers.

const std = @import("std");
const netz = @import("netz");

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
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            std.debug.print("server received body: {s}\n", .{
                request.request.body,
            });

            var response = try connection.startResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body_length = null,
                .trailer_names = &.{"x-checksum"},
                .request_accepts_trailers = true,
                .request_method = .POST,
            });
            try response.write("streamed-");
            try response.write("response");
            try response.finishTrailers(&.{
                .{ .name = "x-checksum", .value = "1" },
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/upload",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{});
    defer client.deinit();
    var connection = try client.connectUri(uri);
    defer connection.close();

    var body_reader = std.Io.Reader.fixed("netz");
    var handle = try connection.startRequest("/upload", .{
        .method = "POST",
        .headers = &.{.{ .name = "te", .value = "trailers" }},
        // No length is known up front, so HTTP/1 uses chunked framing.
        .body_length = .unknown,
    });
    defer handle.deinit();

    try handle.writeBody("hello ");
    try handle.writeBodyFromReader(&body_reader);
    try handle.finishBody();

    var sink = PrintSink{};
    const head = try handle.readResponse(sink.sink());
    std.debug.print(
        "client received {d} with {d} header(s), {d} body bytes, {d} trailer(s)\n",
        .{ head.status, head.headers.len, sink.body_bytes, sink.trailer_count },
    );

    server_task.await(io);
    if (task.err) |err| return err;
}

const PrintSink = struct {
    body_bytes: usize = 0,
    trailer_count: usize = 0,

    fn sink(self: *PrintSink) netz.http.ResponseSink {
        return .{
            .context = self,
            .begin = begin,
            .data = data,
            .end = end,
        };
    }

    fn begin(_: *anyopaque, head: netz.http.ResponseHead) !void {
        std.debug.print("response {d} via {t}\n", .{
            head.status,
            head.protocol,
        });
    }

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *PrintSink = @ptrCast(@alignCast(context));
        self.body_bytes += bytes.len;
        std.debug.print("chunk: {s}\n", .{bytes});
    }

    fn end(
        context: *anyopaque,
        trailers: []const netz.http.DuplexHeader,
    ) !void {
        const self: *PrintSink = @ptrCast(@alignCast(context));
        self.trailer_count = trailers.len;
        for (trailers) |trailer| {
            std.debug.print("trailer: {s}={s}\n", .{
                trailer.name,
                trailer.value,
            });
        }
    }
};

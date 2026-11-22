//! Stream a response above the default body cap.
//!
//! `http1_limits.max_body_bytes` bounds the received body for both buffered
//! responses and `RequestHandle` streaming (16 MiB by default). This example
//! raises the cap explicitly, then streams 20 MiB through a sink that hashes
//! every chunk without retaining the complete response.

const std = @import("std");
const netz = @import("netz");

const chunk_len = 64 * 1024;
const chunk_count = 320; // 20 MiB, above the default 16 MiB buffered cap.

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

            // A null body length selects chunked framing; the server never
            // materializes the complete body.
            var response = try connection.startResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "application/octet-stream",
                }},
                .body_length = null,
                .request_method = request.request.method,
            });
            var chunk: [chunk_len]u8 = undefined;
            for (0..chunk_count) |index| {
                @memset(&chunk, 'a' + @as(u8, @intCast(index % 26)));
                try response.write(&chunk);
            }
            try response.finish();
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/large",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
        // The default is 16 MiB; the cap applies to streamed bodies too.
        .http1_limits = .{ .max_body_bytes = 24 * 1024 * 1024 },
    });
    defer client.deinit();
    var connection = try client.connectUri(uri);
    defer connection.close();
    var handle = try connection.startRequest("/large", .{ .method = "GET" });
    defer handle.deinit();
    try handle.finishBody();

    var sink = HashSink{};
    const head = try handle.readResponse(sink.sink());
    if (head.status != 200) return error.UnexpectedStatus;
    const expected = chunk_len * chunk_count;
    if (sink.bytes != expected) return error.UnexpectedBodyLength;
    std.debug.print(
        "streamed {d} bytes (cap raised to 24 MiB) sha256={x}\n",
        .{ sink.bytes, sink.hasher.finalResult() },
    );

    server_task.await(io);
    if (task.err) |err| return err;
}

const HashSink = struct {
    hasher: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    bytes: usize = 0,

    fn sink(self: *HashSink) netz.http.ResponseSink {
        return .{
            .context = self,
            .begin = begin,
            .data = data,
            .end = end,
        };
    }

    fn begin(_: *anyopaque, head: netz.http.ResponseHead) !void {
        if (head.status != 200) return error.UnexpectedStatus;
    }

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *HashSink = @ptrCast(@alignCast(context));
        self.hasher.update(bytes);
        self.bytes += bytes.len;
    }

    fn end(_: *anyopaque, trailers: []const netz.http.DuplexHeader) !void {
        _ = trailers;
    }
};

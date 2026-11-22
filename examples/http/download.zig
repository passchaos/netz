//! Streaming download with the unified duplex handle.
//!
//! Mirrors `curl -o` / the `reqwest` download example: the server streams a
//! chunked body, and the client writes each callback chunk to a file without
//! buffering the complete response.

const std = @import("std");
const netz = @import("netz");

const download_path = "netz-download-example.bin";
const chunk_len = 1024;
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

            // A null body length selects chunked framing for HTTP/1.1.
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
                @memset(&chunk, 'a' + @as(u8, @intCast(index)));
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
        "http://127.0.0.1:{d}/download",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var file = try std.Io.Dir.cwd().createFile(io, download_path, .{
        .truncate = true,
    });
    defer file.close(io);
    defer std.Io.Dir.cwd().deleteFile(io, download_path) catch {};

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();
    var connection = try client.connectUri(uri);
    defer connection.close();
    var handle = try connection.startRequest("/download", .{
        .method = "GET",
    });
    defer handle.deinit();
    // The duplex handle streams one exchange: finish the (empty) request body
    // before reading the streaming response.
    try handle.finishBody();

    var sink = DownloadSink{ .file = file, .io = io };
    const head = try handle.readResponse(sink.sink());
    std.debug.print(
        "downloaded {d} bytes via {t}, status {d}\n",
        .{ sink.bytes, head.protocol, head.status },
    );
    if (sink.bytes != chunk_len * chunk_count) return error.UnexpectedBodyLength;

    server_task.await(io);
    if (task.err) |err| return err;
}

const DownloadSink = struct {
    file: std.Io.File,
    io: std.Io,
    bytes: usize = 0,

    fn sink(self: *DownloadSink) netz.http.ResponseSink {
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
        const self: *DownloadSink = @ptrCast(@alignCast(context));
        try self.file.writeStreamingAll(self.io, bytes);
        self.bytes += bytes.len;
    }

    fn end(
        _: *anyopaque,
        trailers: []const netz.http.DuplexHeader,
    ) !void {
        _ = trailers;
    }
};

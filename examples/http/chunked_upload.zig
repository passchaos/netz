//! Chunked upload and download with HTTP/1.1 trailers.
//!
//! The client sends an unknown-length body as independent chunks and announces
//! a trailing checksum. The server consumes the upload incrementally, echoes
//! the same chunks as a chunked download, and finishes with its own checksum
//! trailer. Neither side buffers the complete body.

const std = @import("std");
const netz = @import("netz");

const chunk_bytes = 8 * 1024;
const chunk_count = 16;

const UploadSink = struct {
    total: usize = 0,
    checksum: u32 = 0,

    fn consume(self: *UploadSink, bytes: []const u8) !void {
        self.total += bytes.len;
        for (bytes) |byte| self.checksum +%= byte;
    }
};

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
        upload_checksum: u32 = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();

            var sink = UploadSink{};
            var request = try connection.readRequestStreaming(
                &sink,
                UploadSink.consume,
            );
            defer request.deinit(self.server.allocator);
            self.received = sink.total;
            self.upload_checksum = sink.checksum;

            std.debug.print(
                "server received {d} bytes in {d} chunk(s), checksum {d}\n",
                .{ sink.total, chunk_count, sink.checksum },
            );
            if (request.trailers.len != 0) {
                for (request.trailers) |trailer| {
                    std.debug.print("server upload trailer: {s}={s}\n", .{
                        trailer.name,
                        trailer.value,
                    });
                }
            }

            // Echo a chunked download and finish with the checksum of the
            // bytes actually written by the server.
            var response = try connection.startResponse(.{
                .status = 200,
                .headers = &.{.{
                    .name = "content-type",
                    .value = "application/octet-stream",
                }},
                .body_length = null,
                .trailer_names = &.{"x-checksum"},
                .request_accepts_trailers = request.acceptsTrailers(),
                .request_method = request.method,
            });
            defer response.deinit();

            var download_checksum: u32 = 0;
            var chunk: [chunk_bytes]u8 = undefined;
            @memset(&chunk, 'd');
            for (0..chunk_count) |index| {
                chunk[0] = @intCast('0' + (index % 10));
                for (chunk) |byte| download_checksum +%= byte;
                try response.write(&chunk);
            }
            var checksum_buffer: [16]u8 = undefined;
            const checksum_text = try std.fmt.bufPrint(
                &checksum_buffer,
                "{d}",
                .{download_checksum},
            );
            try response.finishTrailers(&.{
                .{ .name = "x-checksum", .value = checksum_text },
            });
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

    var checksum: u32 = 0;
    var chunk: [chunk_bytes]u8 = undefined;
    @memset(&chunk, 'u');
    for (0..chunk_count) |index| {
        chunk[0] = @intCast('0' + (index % 10));
        for (chunk) |byte| checksum +%= byte;
    }
    var checksum_buffer: [16]u8 = undefined;
    const checksum_text = try std.fmt.bufPrint(
        &checksum_buffer,
        "{d}",
        .{checksum},
    );

    var request = try client.startRequest(.{
        .method = .POST,
        .target = "/chunked",
        .host = host,
        .headers = &.{.{
            .name = "te",
            .value = "trailers",
        }},
        .body_length = null,
        .trailer_names = &.{"x-upload-checksum"},
    });
    defer request.deinit();

    for (0..chunk_count) |index| {
        chunk[0] = @intCast('0' + (index % 10));
        try request.write(&chunk);
    }
    try request.finishTrailers(&.{
        .{ .name = "x-upload-checksum", .value = checksum_text },
    });

    const DownloadSink = struct {
        total: usize = 0,
        checksum: u32 = 0,

        fn consume(self: *@This(), bytes: []const u8) !void {
            self.total += bytes.len;
            for (bytes) |byte| self.checksum +%= byte;
        }
    };
    var sink = DownloadSink{};
    var response = try request.readResponseStreaming(&sink, DownloadSink.consume);
    defer response.deinit(allocator);

    server_task.await(io);
    if (task.err) |err| return err;

    std.debug.print(
        "client received {d} bytes, upload checksum {d}, download checksum {d}\n",
        .{ sink.total, task.upload_checksum, sink.checksum },
    );
    for (response.trailers) |trailer| {
        std.debug.print("client download trailer: {s}={s}\n", .{
            trailer.name,
            trailer.value,
        });
    }
}

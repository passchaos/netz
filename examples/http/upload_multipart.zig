//! Multipart form upload with the unified client and HTTP/1 server parser.
//!
//! Mirrors `curl -F`: stream slice and reader parts into one
//! `multipart/form-data` body, send it with the generated Content-Type, and
//! parse the same wire form on the server with bounded limits.

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
        .{ .max_head_bytes = 4096, .max_body_bytes = 64 * 1024 },
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

            const content_type = request.request.header("content-type") orelse
                return error.MissingContentType;
            var parsed = try netz.http.multipart.parse(
                self.server.allocator,
                request.request.body,
                content_type,
                .{},
            );
            defer parsed.deinit();

            var title: []const u8 = "(missing)";
            var filename: []const u8 = "(none)";
            var file_body: []const u8 = "(missing)";
            var streamed: []const u8 = "(missing)";
            for (parsed.parts) |part| {
                if (std.mem.eql(u8, part.name, "title")) {
                    title = part.body;
                } else if (std.mem.eql(u8, part.name, "file")) {
                    filename = part.filename orelse "(unnamed)";
                    file_body = part.body;
                } else if (std.mem.eql(u8, part.name, "stream")) {
                    streamed = part.body;
                }
            }
            var storage: [512]u8 = undefined;
            const body = try std.fmt.bufPrint(
                &storage,
                "parts={d} title={s} filename={s} file={s} stream={s}",
                .{
                    parsed.parts.len,
                    title,
                    filename,
                    file_body,
                    streamed,
                },
            );
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = body,
                .request_method = request.request.method,
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

    const boundary = "netz-example-boundary-7d1f";
    var body_output: std.Io.Writer.Allocating = .init(allocator);
    defer body_output.deinit();
    var streamed_reader = std.Io.Reader.fixed("streamed from a reader");
    try netz.http.multipart.write(&body_output.writer, boundary, &.{
        .{
            .name = "title",
            .body = .{ .slice = "netz upload" },
        },
        .{
            .name = "file",
            .filename = "hello.txt",
            .content_type = "text/plain",
            .body = .{ .slice = "hello from multipart" },
        },
        .{
            .name = "stream",
            .body = .{ .reader = &streamed_reader },
        },
    });
    var content_type_storage: [128]u8 = undefined;
    const content_type = try netz.http.multipart.contentType(
        &content_type_storage,
        boundary,
    );

    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{
            .method = "POST",
            .headers = &.{.{ .name = "content-type", .value = content_type }},
            .body = body_output.written(),
        },
        .fromSeconds(5),
    );
    defer response.deinit();
    if (response.status() != 200) return error.UnexpectedStatus;
    std.debug.print("multipart response: {s}\n", .{response.body()});

    server_task.await(io);
    if (task.err) |err| return err;
}

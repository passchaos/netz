//! Stream a request body from a Reader (`curl -T` / reqwest body stream).
//!
//! The unified client reads the source under the request deadline and writes
//! fixed-length framing because the source length is known. The server keeps
//! its body cap explicit and reports the exact received size.

const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const payload = "netz-streaming-upload-" ** 2048;

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = payload.len },
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
            var storage: [128]u8 = undefined;
            const body = try std.fmt.bufPrint(
                &storage,
                "received {d} bytes",
                .{request.request.body.len},
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

    var reader = std.Io.Reader.fixed(payload);
    var client = try netz.http.Client.init(allocator, io, .{
        .protocol_policy = .http1_only,
    });
    defer client.deinit();
    var response = try client.requestUriWithTimeout(
        uri,
        .{
            .method = "POST",
            .headers = &.{.{
                .name = "content-type",
                .value = "application/octet-stream",
            }},
            .body_source = .{ .reader = .{
                .reader = &reader,
                .length = payload.len,
            } },
        },
        .fromSeconds(10),
    );
    defer response.deinit();
    std.debug.print("uploaded {d} bytes -> {d}: {s}\n", .{
        payload.len,
        response.status(),
        response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
}

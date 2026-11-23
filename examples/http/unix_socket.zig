//! HTTP over a Unix domain socket, mirroring `curl --unix-socket`.
//!
//! Local sidecars (Docker, containerd, supervisors, language toolchains)
//! commonly expose HTTP on a Unix socket. The same HTTP/1 parser and writer run
//! unchanged; only the transport address differs.

const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    if (comptime @import("builtin").os.tag == .windows) {
        std.debug.print("Unix sockets are unavailable on Windows\n", .{});
        return;
    }

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    const stamp = std.Io.Clock.real.now(io).nanoseconds;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(
        &path_buffer,
        "/tmp/netz-http-unix-{d}.sock",
        .{stamp},
    );
    const address = try std.Io.net.UnixAddress.init(path);

    var server = try netz.http1.runtime.UnixServer.listen(
        allocator,
        io,
        address,
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer {
        server.deinit();
        std.Io.Dir.deleteFileAbsolute(io, path) catch {};
    }

    const ServerTask = struct {
        server: *netz.http1.runtime.UnixServer,
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
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "text/plain",
                }},
                .body = "hello over a Unix socket",
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    var client = try netz.http1.runtime.Client.connectUnix(
        allocator,
        io,
        address,
        "localhost",
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try client.request(.{ .target = "/unix" });
    defer response.deinit(allocator);
    std.debug.print("Unix HTTP/1.1 {d}: {s}\n", .{
        response.response.status,
        response.response.body,
    });

    server_task.await(io);
    if (task.err) |err| return err;
}

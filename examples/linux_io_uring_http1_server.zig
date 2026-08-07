const builtin = @import("builtin");
const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    if (comptime builtin.os.tag != .linux) {
        std.debug.print("linux io_uring HTTP/1 server example is only available on Linux\n", .{});
        return;
    }

    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var ring = std.os.linux.IoUring.init(16, 0) catch |err| switch (err) {
        error.PermissionDenied, error.SystemOutdated => {
            std.debug.print("io_uring unavailable on this kernel/container: {s}\n", .{@errorName(err)});
            return;
        },
        else => |e| return e,
    };
    defer ring.deinit();

    var server = try netz.http1.runtime.LinuxIoUringServer.listen(
        allocator,
        &ring,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
        .{ .reuse_address = true },
    );
    defer server.deinit();

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const Shared = struct {
        server: *netz.http1.runtime.LinuxIoUringServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.http1.runtime.LinuxIoUringServer) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            std.debug.print("io_uring HTTP/1 server accepted {s} {s}\n", .{
                request.request.method.string(),
                request.request.target,
            });

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "hello from io_uring server",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/uring-server-example", .{server.address.ip4.port});
    defer allocator.free(uri);
    var response = try netz.http1.runtime.Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    std.debug.print("threaded HTTP/1 client received {d}: {s}\n", .{ response.response.status, response.response.body });
}

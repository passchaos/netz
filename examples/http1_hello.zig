const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.initAuto(allocator, .evented_then_threaded);
    defer backend.deinit();
    const io = backend.io();
    std.debug.print("std.Io backend: {t}\n", .{backend.kind});

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http1.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.http1.runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest(.{});
            defer request.deinit(server_ptr.allocator);
            std.debug.print("HTTP/1 server received {s} {s}\n", .{
                request.request.method.string(),
                request.request.target,
            });

            try connection.writeResponse(.{
                .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
                .body = "hello from netz HTTP/1.1",
                .request_method = request.request.method,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    // Like hyper's simple client example, build an absolute URI and let the
    // runtime derive Host/authority and the TCP endpoint.  Literal addresses
    // such as 127.0.0.1 and bracketed IPv6 authorities both work.
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/hello?name=netz", .{server.address().ip4.port});
    defer allocator.free(uri);

    var response = try netz.http1.runtime.Client.requestUri(allocator, io, uri, .{}, .{
        .max_head_bytes = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    std.debug.print("HTTP/1 client received {d}: {s}\n", .{ response.response.status, response.response.body });
}

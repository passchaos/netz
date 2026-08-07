const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Zig 0.16 exposes std.Io.Uring on Linux, but its std.Io networking
    // vtable currently marks listen/connect/read/write as unavailable.  These
    // protocol runtimes accept any std.Io backend, so this can switch to Uring
    // once Zig wires networking into that backend; today Threaded is the
    // portable backend that can actually drive TCP.
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const Shared = struct {
        server: *netz.http2.runtime.Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *netz.http2.runtime.Server) !void {
            var connection = try server_ptr.accept();
            defer connection.close();

            var request = try connection.readRequest();
            defer request.deinit(server_ptr.allocator);
            std.debug.print("HTTP/2 server received {s} {s} over scheme {s}\n", .{
                request.method,
                request.path,
                request.scheme,
            });

            try connection.writeResponse(request.stream_id, .{
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "hello from netz h2c",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    // This is HTTP/2 prior knowledge (h2c), similar in spirit to hyper's
    // conn::http2 handshake examples: the URI drives :authority and :scheme.
    const uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/h2?example=1", .{server.address().ip4.port});
    defer allocator.free(uri);

    var response = try netz.http2.runtime.Client.requestUri(allocator, io, uri, .{}, .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    std.debug.print("HTTP/2 client received {d}: {s}\n", .{ response.status, response.body });
}

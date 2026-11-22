//! Managed HTTP/1.1 serve loop with graceful shutdown.
//!
//! `Server.serveUntil` is the production accept loop: it bounds concurrent
//! connections and requests per connection, applies accept/connection error
//! policies, and stops when the caller sets the shutdown event. The handler
//! returns the response instead of writing it directly.

const std = @import("std");
const netz = @import("netz");

const HandlerContext = struct {
    requests: usize = 0,
};

fn handle(
    context: *HandlerContext,
    request: netz.http1.Request,
) netz.http1.runtime.Error!netz.http1.runtime.ResponseOptions {
    context.requests += 1;
    // The loop writes the response after the handler returns, so the body
    // must outlive this call. Use static text or context-owned storage.
    const body = if (std.mem.eql(u8, request.target, "/status"))
        "managed serve loop is healthy"
    else
        "hello from serveUntil";
    return .{
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = body,
        .request_method = request.method,
    };
}

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

    var shutdown: std.Io.Event = .unset;
    var context = HandlerContext{};

    const ServeTask = struct {
        server: *netz.http1.runtime.Server,
        context: *HandlerContext,
        shutdown: *std.Io.Event,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.server.serveUntil(
                HandlerContext,
                self.context,
                handle,
                8,
                16,
                .{ .shutdown = self.shutdown },
            ) catch |err| {
                self.err = err;
            };
        }
    };

    var task = ServeTask{
        .server = &server,
        .context = &context,
        .shutdown = &shutdown,
    };
    var server_task = io.async(ServeTask.run, .{&task});
    defer server_task.cancel(io);

    const base_uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}",
        .{server.address().ip4.port},
    );
    defer allocator.free(base_uri);

    var pool = try netz.http.Pool.init(allocator, io, .{
        .client = .{ .protocol_policy = .http1_only },
        .max_connections = 2,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
    });
    defer pool.deinit();

    for ([_][]const u8{ "/hello", "/status" }) |target| {
        const uri = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ base_uri, target },
        );
        defer allocator.free(uri);
        var response = try pool.requestUriWithTimeout(
            uri,
            .{ .method = "GET" },
            .fromSeconds(5),
        );
        defer response.deinit();
        std.debug.print("{s} -> {d}: {s}\n", .{
            target,
            response.status(),
            response.body(),
        });
    }

    // Graceful shutdown: the managed loop stops accepting, cancels pending
    // reads, and returns once the bounded connection tasks finish.
    shutdown.set(io);
    server_task.await(io);
    if (task.err) |err| return err;
    std.debug.print("server stopped after {d} request(s)\n", .{
        context.requests,
    });
}

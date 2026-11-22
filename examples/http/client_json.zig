//! JSON request and response bodies with the unified client.
//!
//! Mirrors the `reqwest` JSON example: send `application/json`, parse the
//! typed response, and keep the body limits explicit.

const std = @import("std");
const netz = @import("netz");

const Incoming = struct {
    name: []const u8,
    count: i64,
};

const Reply = struct {
    greeting: []const u8,
    doubled: i64,
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

            const parsed = try std.json.parseFromSlice(
                Incoming,
                self.server.allocator,
                request.request.body,
                .{},
            );
            defer parsed.deinit();

            var storage: [128]u8 = undefined;
            const greeting = try std.fmt.bufPrint(
                &storage,
                "hello {s}",
                .{parsed.value.name},
            );
            var output: std.Io.Writer.Allocating = .init(self.server.allocator);
            defer output.deinit();
            var json: std.json.Stringify = .{
                .writer = &output.writer,
                .options = .{},
            };
            try json.write(Reply{
                .greeting = greeting,
                .doubled = parsed.value.count * 2,
            });
            try connection.writeResponse(.{
                .headers = &.{.{
                    .name = "content-type",
                    .value = "application/json",
                }},
                .body = output.written(),
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/echo",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var body_output: std.Io.Writer.Allocating = .init(allocator);
    defer body_output.deinit();
    var body_json: std.json.Stringify = .{
        .writer = &body_output.writer,
        .options = .{},
    };
    try body_json.write(Incoming{ .name = "netz", .count = 21 });

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
                .value = "application/json",
            }},
            .body = body_output.written(),
        },
        .fromSeconds(5),
    );
    defer response.deinit();
    if (response.status() != 200) return error.UnexpectedStatus;

    const parsed = try std.json.parseFromSlice(
        Reply,
        allocator,
        response.body(),
        .{},
    );
    defer parsed.deinit();
    std.debug.print("JSON reply: {s}, doubled={d}\n", .{
        parsed.value.greeting,
        parsed.value.doubled,
    });

    server_task.await(io);
    if (task.err) |err| return err;
}

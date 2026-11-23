//! Per-request timeouts and absolute deadlines, mirroring reqwest's
//! `.timeout()` and curl's `--max-time`.
//!
//! One slow origin answers after 200 ms. The first client gives up after
//! 50 ms and receives `error.Timeout`; the second uses a 2 s absolute deadline
//! and completes. The budget covers DNS/TCP, TLS, request write and the
//! complete response, not just the connect.

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
        .{ .max_head_bytes = 4096, .max_body_bytes = 4096 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.Server,
        answered: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            // Two one-shot clients: the impatient one and the patient one.
            for (0..2) |_| {
                var connection = try self.server.accept();
                defer connection.close();
                var request = try connection.readRequest(.{});
                defer request.deinit(self.server.allocator);
                // Slow origin. The impatient client has already timed out and
                // closed, so a write failure here is expected and ignored.
                try std.Io.sleep(
                    self.server.io,
                    .fromMilliseconds(200),
                    .awake,
                );
                connection.writeResponse(.{
                    .headers = &.{.{
                        .name = "content-type",
                        .value = "text/plain",
                    }},
                    .body = "slow but successful",
                    .request_method = request.request.method,
                }) catch {};
                self.answered += 1;
            }
        }
    };

    var task = ServerTask{ .server = &server };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/slow",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    // reqwest `.timeout(Duration::from_millis(50))`: the origin needs 200 ms.
    var impatient = try netz.http.Client.init(allocator, io, .{});
    defer impatient.deinit();
    if (impatient.requestUriWithTimeout(
        uri,
        .{ .method = "GET" },
        .fromMilliseconds(50),
    )) |response_value| {
        var response = response_value;
        response.deinit();
        return error.ExpectedTimeout;
    } else |err| switch (err) {
        error.Timeout => std.debug.print(
            "50 ms timeout: error.Timeout (expected)\n",
            .{},
        ),
        else => return err,
    }

    // curl --max-time 2: one absolute deadline for the complete exchange.
    var patient = try netz.http.Client.init(allocator, io, .{});
    defer patient.deinit();
    var response = try patient.requestUriWithDeadline(
        uri,
        .{ .method = "GET" },
        .fromNow(io, .{ .raw = .fromSeconds(2), .clock = .awake }),
    );
    defer response.deinit();
    std.debug.print("2 s deadline: {t} {d}: {s}\n", .{
        response.protocol(),
        response.status(),
        response.body(),
    });

    server_task.await(io);
    if (task.err) |err| return err;
    if (task.answered != 2) return error.UnexpectedResponseCount;
}

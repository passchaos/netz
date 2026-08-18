const std = @import("std");
const netz = @import("netz");

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
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
            var call = try netz.grpc.parseUnaryRequest(
                server_ptr.allocator,
                &request,
                4096,
            );
            defer call.deinit();
            std.debug.print(
                "gRPC server received {s}/{s}: {x}\n",
                .{ call.service, call.method, call.message.payload },
            );
            try netz.grpc.writeUnaryResponse(
                &connection,
                server_ptr.allocator,
                call.stream_id,
                .{ .message = "\x0a\x04netz" },
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.close();
    var response = try netz.grpc.unaryCall(
        &client,
        allocator,
        .{
            .path = "/demo.Echo/Unary",
            .authority = "localhost",
            // Opaque protobuf bytes: field 1, string "zig".
            .message = "\x0a\x03zig",
            .timeout = try .init(1, .second),
        },
    );
    defer response.deinit();

    thread.join();
    if (shared.err) |err| return err;
    std.debug.print(
        "gRPC client received status={t} message={x}\n",
        .{ response.status, response.message.?.payload },
    );
}

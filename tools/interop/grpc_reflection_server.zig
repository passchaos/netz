//! One-shot h2c reflection server for the upstream gRPC `grpc_cli` gate.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const descriptor_set = try std.Io.Dir.cwd().readFileAlloc(
        io,
        args[2],
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(descriptor_set);
    var registry = netz.grpc.reflection.Registry.init(allocator, io);
    defer registry.deinit();
    _ = try registry.addFileDescriptorSet(descriptor_set);
    try registry.addService("grpc.reflection.v1.ServerReflection");
    try registry.addService("grpc.reflection.v1alpha.ServerReflection");

    var server = try netz.grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_frame_payload = 64 * 1024,
            .max_body_bytes = 4 * 1024 * 1024,
            .handshake_timeout = .fromSeconds(5),
        },
        4 * 1024 * 1024,
    );
    defer server.deinit();
    std.debug.print(
        "netz gRPC reflection server ready: port={d} " ++
            "client_io=grpc-cpp-posix-event-engine server_io=zio-std-io\n",
        .{port},
    );

    var connection = try server.accept();
    defer connection.deinit();
    var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(10));
    defer stream.deinit();
    try connection.serveReflection(&registry, &stream);
    std.debug.print(
        "netz gRPC reflection server completed " ++
            "client_io=grpc-cpp-posix-event-engine server_io=zio-std-io\n",
        .{},
    );
}

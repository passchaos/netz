const std = @import("std");
const zio = @import("zio");

/// Runtime backend for netz examples and applications.
///
/// zio owns scheduling and platform I/O while protocol modules consume only
/// its standard `std.Io` interface. No zio or operating-system-specific type
/// crosses into HTTP, WebSocket, QUIC, or the other protocol APIs.
pub const BackendKind = enum { zio };

pub const Backend = struct {
    allocator: std.mem.Allocator,
    kind: BackendKind = .zio,
    runtime: *anyopaque,

    /// Initialize the supported asynchronous backend. Protocol callers receive
    /// a `std.Io`; zio remains an implementation detail of this owner.
    pub fn init(allocator: std.mem.Allocator) !Backend {
        return initZio(allocator);
    }

    /// Explicit spelling for applications that want to document the backend.
    pub fn initZio(allocator: std.mem.Allocator) !Backend {
        const runtime = try zio.Runtime.init(allocator, .{});
        return .{
            .allocator = allocator,
            .runtime = @ptrCast(runtime),
        };
    }

    pub fn io(self: *Backend) std.Io {
        return zioRuntime(self.runtime).io();
    }

    pub fn deinit(self: *Backend) void {
        zioRuntime(self.runtime).deinit();
        self.* = undefined;
    }

    fn zioRuntime(runtime: *anyopaque) *zio.Runtime {
        return @ptrCast(@alignCast(runtime));
    }
};

test "runtime backend initializes zio behind std.Io" {
    var backend = try Backend.init(std.testing.allocator);
    defer backend.deinit();

    try std.testing.expectEqual(BackendKind.zio, backend.kind);
    const io = backend.io();
    try std.testing.expect(io.userdata != null);
}

test "runtime backend zio std.Io TCP round trip" {
    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const io = backend.io();

    var server = try std.Io.net.IpAddress.listen(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .reuse_address = true },
    );
    defer server.deinit(io);

    const Echo = struct {
        fn run(
            echo_io: std.Io,
            listener: *std.Io.net.Server,
            result: *anyerror!void,
        ) void {
            result.* = runFallible(echo_io, listener);
        }

        fn runFallible(
            echo_io: std.Io,
            listener: *std.Io.net.Server,
        ) !void {
            const peer = try listener.accept(echo_io);
            defer peer.close(echo_io);

            var read_buffer: [16]u8 = undefined;
            var reader = peer.reader(echo_io, &read_buffer);
            var payload: [4]u8 = undefined;
            const received = try reader.interface.readSliceShort(&payload);

            var write_buffer: [16]u8 = undefined;
            var writer = peer.writer(echo_io, &write_buffer);
            try writer.interface.writeAll(payload[0..received]);
            try writer.interface.flush();
            try peer.shutdown(echo_io, .send);
        }
    };

    var echo_result: anyerror!void = {};
    var echo = io.async(Echo.run, .{ io, &server, &echo_result });
    defer echo.cancel(io);

    const client = try std.Io.net.IpAddress.connect(
        &server.socket.address,
        io,
        .{ .mode = .stream },
    );
    defer client.close(io);

    var write_buffer: [16]u8 = undefined;
    var writer = client.writer(io, &write_buffer);
    try writer.interface.writeAll("ping");
    try writer.interface.flush();
    try client.shutdown(io, .send);

    var read_buffer: [16]u8 = undefined;
    var reader = client.reader(io, &read_buffer);
    var payload: [4]u8 = undefined;
    const received = try reader.interface.readSliceShort(&payload);
    try std.testing.expectEqualStrings("ping", payload[0..received]);

    echo.await(io);
    try echo_result;
}

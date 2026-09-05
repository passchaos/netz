const std = @import("std");
const zio = @import("zio");

/// Runtime backend selection for netz examples and applications.
///
/// Protocol modules consume only `std.Io`. Backend construction belongs here
/// so HTTP, WebSocket, QUIC, and the other protocol implementations do not
/// depend on zio or expose operating-system-specific event-loop APIs.
pub const BackendPreference = enum {
    /// Prefer zio's complete `std.Io` implementation and fall back to the
    /// standard threaded implementation if zio cannot initialize.
    zio_then_threaded,
    /// Compatibility spelling retained for applications written before zio
    /// replaced the incomplete Zig 0.16 `std.Io.Evented` backend.
    evented_then_threaded,
    /// Force the portable standard threaded backend.
    threaded,
};

pub const BackendKind = enum {
    zio,
    threaded,
};

pub const Backend = struct {
    allocator: std.mem.Allocator,
    kind: BackendKind,
    storage: union(BackendKind) {
        zio: *anyopaque,
        threaded: std.Io.Threaded,
    },

    /// Select a backend without exposing its implementation to protocol code.
    /// The legacy `.evented_then_threaded` preference is an alias for
    /// `.zio_then_threaded`.
    pub fn initAuto(
        allocator: std.mem.Allocator,
        preference: BackendPreference,
    ) !Backend {
        return switch (preference) {
            .zio_then_threaded, .evented_then_threaded => initZio(allocator) catch initThreaded(allocator),
            .threaded => initThreaded(allocator),
        };
    }

    /// Force zio and report initialization failure instead of falling back.
    pub fn initZio(allocator: std.mem.Allocator) !Backend {
        const runtime = try zio.Runtime.init(allocator, .{});
        return .{
            .allocator = allocator,
            .kind = .zio,
            .storage = .{ .zio = @ptrCast(runtime) },
        };
    }

    /// Force Zig's portable threaded `std.Io` implementation.
    pub fn initThreaded(allocator: std.mem.Allocator) !Backend {
        return .{
            .allocator = allocator,
            .kind = .threaded,
            .storage = .{
                .threaded = std.Io.Threaded.init(allocator, .{}),
            },
        };
    }

    pub fn io(self: *Backend) std.Io {
        return switch (self.storage) {
            .zio => |runtime| zioRuntime(runtime).io(),
            .threaded => |*threaded| threaded.io(),
        };
    }

    pub fn deinit(self: *Backend) void {
        switch (self.storage) {
            .zio => |runtime| zioRuntime(runtime).deinit(),
            .threaded => |*threaded| threaded.deinit(),
        }
        self.* = undefined;
    }

    fn zioRuntime(runtime: *anyopaque) *zio.Runtime {
        return @ptrCast(@alignCast(runtime));
    }
};

test "runtime backend initializes zio behind std.Io" {
    var backend = try Backend.initZio(std.testing.allocator);
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

test "runtime backend can force Threaded" {
    var backend = try Backend.initAuto(std.testing.allocator, .threaded);
    defer backend.deinit();

    try std.testing.expectEqual(BackendKind.threaded, backend.kind);
    _ = backend.io();
}

test "legacy Evented preference selects zio or safe fallback" {
    var backend = try Backend.initAuto(
        std.testing.allocator,
        .evented_then_threaded,
    );
    defer backend.deinit();

    _ = backend.io();
    try std.testing.expect(backend.kind == .zio or backend.kind == .threaded);
}

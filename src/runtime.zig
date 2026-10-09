const std = @import("std");
const builtin = @import("builtin");
const zio = @import("zio");

/// Runtime backend for netz examples and applications.
///
/// zio owns scheduling and platform I/O while protocol modules consume only
/// its standard `std.Io` interface. No zio or operating-system-specific type
/// crosses into HTTP, WebSocket, QUIC, or the other protocol APIs.
pub const BackendKind = enum { zio };

/// Return the zio event-loop's awake-clock snapshot when `io` belongs to the
/// task currently running on that loop. Foreign `std.Io` implementations and
/// calls outside a matching runtime retain their ordinary clock semantics.
pub fn cachedAwakeNow(io: std.Io) std.Io.Timestamp {
    return zio.cachedAwakeNow(io);
}

/// Clock-tagged form for composing an awake-clock deadline.
pub fn cachedAwakeTimestamp(io: std.Io) std.Io.Clock.Timestamp {
    return .{
        .raw = cachedAwakeNow(io),
        .clock = .awake,
    };
}

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

test "runtime cached awake timestamp follows zio event-loop scans" {
    var backend = try Backend.init(std.testing.allocator);
    defer backend.deinit();
    const io = backend.io();

    const before = cachedAwakeNow(io);
    zio.os.time.sleep(.fromMilliseconds(2));
    try std.testing.expectEqual(before.nanoseconds, cachedAwakeNow(io).nanoseconds);
    const tagged = cachedAwakeTimestamp(io);
    try std.testing.expectEqual(std.Io.Clock.awake, tagged.clock);
    try std.testing.expectEqual(before.nanoseconds, tagged.raw.nanoseconds);

    try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    try std.testing.expect(cachedAwakeNow(io).nanoseconds > before.nanoseconds);
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

test "runtime backend zio std.Io drains queued UDP datagrams in one batch" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;

    var backend = try Backend.initZio(std.testing.allocator);
    defer backend.deinit();
    const io = backend.io();

    var sender = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer sender.close(io);
    var receiver = try std.Io.net.IpAddress.bind(
        &.{ .ip4 = .loopback(0) },
        io,
        .{ .mode = .dgram },
    );
    defer receiver.close(io);

    const expected = [_][]const u8{ "one", "two", "three", "four" };
    for (expected) |payload| {
        try sender.send(io, &receiver.address, payload);
    }

    var messages: [expected.len]std.Io.net.IncomingMessage =
        @splat(.init);
    var storage: [expected.len * 16]u8 = undefined;
    const receive_error, const count = receiver.receiveManyTimeout(
        io,
        &messages,
        &storage,
        .{},
        .{ .duration = .{
            .clock = .awake,
            .raw = .fromSeconds(1),
        } },
    );
    try std.testing.expectEqual(null, receive_error);
    try std.testing.expectEqual(expected.len, count);
    for (messages[0..count], expected) |message, payload| {
        try std.testing.expectEqualStrings(payload, message.data);
        try std.testing.expect(message.from.eql(&sender.address));
    }
}

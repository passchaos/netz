//! Deadline-aware TCP reads for MQTT broker Keep Alive enforcement.
//!
//! An ordinary Control Packet gets one deadline. Large packet bodies mirror
//! Mosquitto's bounded progress exception: the deadline is renewed only while
//! more than 1,000 bytes remain, so a useful transfer can continue but a peer
//! cannot retain broker resources by trickling a small packet indefinitely.

const std = @import("std");
const builtin = @import("builtin");

const net = std.Io.net;

const progress_threshold: usize = 1000;

pub const Error = error{ConnectionClosed} ||
    net.Stream.Reader.Error ||
    std.Io.Operation.FileReadStreaming.UnendingError ||
    std.Io.Operation.NetReceive.Error ||
    std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

pub const Reader = struct {
    io: std.Io,
    stream: net.Stream,
    timeout: ?std.Io.Clock.Duration,
    deadline: std.Io.Clock.Timestamp,

    pub fn init(
        io: std.Io,
        stream: net.Stream,
        timeout: ?std.Io.Clock.Duration,
    ) Reader {
        if (timeout) |value| {
            std.debug.assert(value.raw.nanoseconds > 0);
            return .{
                .io = io,
                .stream = stream,
                .timeout = value,
                .deadline = .fromNow(io, value),
            };
        }
        return .{
            .io = io,
            .stream = stream,
            .timeout = null,
            .deadline = undefined,
        };
    }

    /// Fill `buffer`, preserving one deadline unless a large body progresses.
    pub fn readExact(
        self: *Reader,
        buffer: []u8,
        renew_large_progress: bool,
    ) Error!void {
        var offset: usize = 0;
        if (self.timeout) |timeout| {
            if (renew_large_progress and buffer.len > progress_threshold) {
                self.deadline = .fromNow(self.io, timeout);
            }
        }
        while (offset < buffer.len) {
            const count = if (self.timeout != null)
                try self.readSomeTimeout(buffer[offset..])
            else
                try self.readSome(buffer[offset..]);
            offset += count;
            if (self.timeout) |timeout| {
                if (renew_large_progress and
                    buffer.len - offset > progress_threshold)
                {
                    self.deadline = .fromNow(self.io, timeout);
                }
            }
        }
    }

    fn readSome(
        self: Reader,
        buffer: []u8,
    ) Error!usize {
        var bufs = [_][]u8{buffer};
        const count = try self.io.vtable.netRead(
            self.io.userdata,
            self.stream.socket.handle,
            &bufs,
        );
        if (count == 0) return error.ConnectionClosed;
        return count;
    }

    fn readSomeTimeout(
        self: Reader,
        buffer: []u8,
    ) Error!usize {
        if (builtin.os.tag == .windows) {
            // Windows socket handles are not interchangeable with File
            // handles, so use the network operation that Threaded lowers to
            // AFD. POSIX uses file_read_streaming below to avoid asking
            // recvmsg for a meaningless source address on connected TCP.
            var incoming: net.IncomingMessage = .init;
            const maybe_err, const count = (try self.io.operateTimeout(
                .{ .net_receive = .{
                    .socket_handle = self.stream.socket.handle,
                    .message_buffer = (&incoming)[0..1],
                    .data_buffer = buffer,
                    .flags = .{},
                } },
                .{ .deadline = self.deadline },
            )).net_receive;
            if (maybe_err) |err| return err;
            std.debug.assert(count == 1);
            if (incoming.data.len == 0) return error.ConnectionClosed;
            return incoming.data.len;
        }

        var bufs = [_][]u8{buffer};
        const result = try self.io.operateTimeout(
            .{ .file_read_streaming = .{
                .file = .{
                    .handle = self.stream.socket.handle,
                    .flags = .{ .nonblocking = false },
                },
                .data = &bufs,
            } },
            .{ .deadline = self.deadline },
        );
        const count = result.file_read_streaming catch |err| switch (err) {
            error.EndOfStream => return error.ConnectionClosed,
            else => return @errorCast(err),
        };
        if (count == 0) return error.ConnectionClosed;
        return count;
    }
};

test "Keep Alive reader renews only for large packet progress" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        reading: std.atomic.Value(bool) = .init(false),
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.runFallible() catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            const socket = try shared.listener.accept(shared.io);
            defer socket.close(shared.io);
            var reader = Reader.init(
                shared.io,
                socket,
                .{
                    .raw = .fromMilliseconds(400),
                    .clock = .awake,
                },
            );
            shared.reading.store(true, .release);
            var header: [3]u8 = undefined;
            try reader.readExact(&header, false);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 0x30, 0xea, 0x07 },
                &header,
            );
            var body: [1002]u8 = undefined;
            try reader.readExact(&body, true);

            var idle_reader = Reader.init(
                shared.io,
                socket,
                .{
                    .raw = .fromMilliseconds(100),
                    .clock = .awake,
                },
            );
            var small_packet: [2]u8 = undefined;
            try std.testing.expectError(
                error.Timeout,
                idle_reader.readExact(&small_packet, false),
            );
        }
    };
    var shared = Shared{
        .io = io,
        .listener = &listener,
    };
    const server_thread = try std.Thread.spawn(
        .{},
        Shared.run,
        .{&shared},
    );

    const socket = try listener.socket.address.connect(
        io,
        .{ .mode = .stream },
    );
    defer socket.close(io);
    while (!shared.reading.load(.acquire)) {
        try std.Io.sleep(io, .fromMilliseconds(1), .awake);
    }
    // Header completion reveals a body above the progress threshold and
    // renews the deadline. Total transfer time still exceeds the original
    // 400 ms budget.
    try std.Io.sleep(io, .fromMilliseconds(200), .awake);
    try writeAll(io, socket, &.{ 0x30, 0xea, 0x07 });
    try std.Io.sleep(io, .fromMilliseconds(200), .awake);
    try writeAll(io, socket, &.{ 0, 0 });
    try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    var body_tail: [1000]u8 = @splat(0);
    try writeAll(io, socket, &body_tail);

    // A small partial packet receives no progress exception.
    try std.Io.sleep(io, .fromMilliseconds(30), .awake);
    try writeAll(io, socket, &.{0xc0});

    server_thread.join();
    if (shared.err) |err| return err;
}

fn writeAll(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
) net.Stream.Writer.Error!void {
    var written: usize = 0;
    while (written < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[written..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        written += count;
    }
}

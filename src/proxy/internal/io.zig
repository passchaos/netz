//! Bounded, deadline-aware stream I/O shared by proxy protocol servers.
//!
//! The helpers here deliberately keep ownership with the caller: every buffer
//! is caller-provided and every returned slice borrows that buffer. A
//! `BufferedReader` never reads past its configured storage, so protocol
//! parsers cannot be turned into unbounded memory sinks by a hostile peer.

const std = @import("std");
const builtin = @import("builtin");

const net = std.Io.net;

pub const ReadError = net.Stream.Reader.Error ||
    std.Io.Operation.FileReadStreaming.UnendingError ||
    std.Io.Operation.NetReceive.Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError || error{EndOfStream};

pub const WriteError = net.Stream.Writer.Error || std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

pub const BufferError = error{
    BufferTooSmall,
    TooLong,
    EndOfStream,
};

/// Convert an optional relative timeout into one absolute awake-clock
/// timestamp. A non-positive timeout is rejected instead of being treated as
/// an unlimited budget.
pub fn deadlineFromTimeout(
    io: std.Io,
    timeout: ?std.Io.Duration,
) std.Io.Timeout.Error!?std.Io.Clock.Timestamp {
    const duration = timeout orelse return null;
    if (duration.nanoseconds <= 0) return error.Timeout;
    return .fromNow(io, .{ .raw = duration, .clock = .awake });
}

/// Reject an already expired caller-owned deadline before doing any I/O.
pub fn usableDeadline(
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
) std.Io.Timeout.Error!std.Io.Clock.Timestamp {
    if (deadline.clock != .awake or
        deadline.durationFromNow(io).raw.nanoseconds <= 0)
    {
        return error.Timeout;
    }
    return deadline;
}

pub fn readSome(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: ?std.Io.Clock.Timestamp,
) ReadError!usize {
    if (deadline) |absolute| {
        return readSomeWithDeadline(io, stream, buffer, absolute);
    }
    var parts = [_][]u8{buffer};
    return io.vtable.netRead(
        io.userdata,
        stream.socket.handle,
        &parts,
    );
}

pub fn writeAll(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
    deadline: ?std.Io.Clock.Timestamp,
) WriteError!void {
    if (deadline) |absolute| {
        var committed: usize = 0;
        while (committed < bytes.len) {
            committed += try writeSomeWithDeadline(
                io,
                stream,
                bytes[committed..],
                absolute,
            );
        }
        return;
    }

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

/// Streaming reader over one connected TCP stream with a fixed storage budget.
pub const BufferedReader = struct {
    io: std.Io,
    stream: net.Stream,
    storage: []u8,
    start: usize = 0,
    end: usize = 0,
    deadline: ?std.Io.Clock.Timestamp,

    pub fn init(
        io: std.Io,
        stream: net.Stream,
        storage: []u8,
        deadline: ?std.Io.Clock.Timestamp,
    ) BufferedReader {
        return .{
            .io = io,
            .stream = stream,
            .storage = storage,
            .deadline = deadline,
        };
    }

    /// Bytes read but not yet consumed. These must be forwarded before
    /// switching the stream to raw relay mode.
    pub fn buffered(self: *const BufferedReader) []const u8 {
        return self.storage[self.start..self.end];
    }

    pub fn consume(self: *BufferedReader, count: usize) void {
        std.debug.assert(count <= self.end - self.start);
        self.start += count;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
    }

    fn fill(self: *BufferedReader) ReadError!void {
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        } else if (self.end == self.storage.len) {
            const unread = self.end - self.start;
            std.mem.copyForwards(
                u8,
                self.storage[0..unread],
                self.storage[self.start..self.end],
            );
            self.start = 0;
            self.end = unread;
        }
        const count = try readSome(
            self.io,
            self.stream,
            self.storage[self.end..],
            self.deadline,
        );
        if (count == 0) return error.EndOfStream;
        self.end += count;
    }

    pub fn readByte(self: *BufferedReader) ReadError!u8 {
        if (self.start == self.end) try self.fill();
        const value = self.storage[self.start];
        self.start += 1;
        if (self.start == self.end) {
            self.start = 0;
            self.end = 0;
        }
        return value;
    }

    pub fn readExact(self: *BufferedReader, output: []u8) ReadError!void {
        var offset: usize = 0;
        while (offset < output.len) {
            if (self.start == self.end) try self.fill();
            const available = self.end - self.start;
            const take = @min(available, output.len - offset);
            @memcpy(output[offset..][0..take], self.storage[self.start..][0..take]);
            self.start += take;
            offset += take;
            if (self.start == self.end) {
                self.start = 0;
                self.end = 0;
            }
        }
    }

    /// Read a NUL-terminated field into `output`. The returned slice excludes
    /// the terminator and borrows `output`.
    pub fn readUntilNull(
        self: *BufferedReader,
        output: []u8,
    ) (ReadError || BufferError)![]const u8 {
        var offset: usize = 0;
        while (true) {
            const byte = try self.readByte();
            if (byte == 0) return output[0..offset];
            if (offset == output.len) return error.TooLong;
            output[offset] = byte;
            offset += 1;
        }
    }

    pub fn readPeekByte(self: *BufferedReader) ReadError!u8 {
        if (self.start == self.end) try self.fill();
        return self.storage[self.start];
    }
};

fn readSomeWithDeadline(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
    deadline: std.Io.Clock.Timestamp,
) ReadError!usize {
    if (builtin.os.tag == .windows) {
        var incoming: net.IncomingMessage = .init;
        const maybe_err, const message_count = (try io.operateTimeout(
            .{ .net_receive = .{
                .socket_handle = stream.socket.handle,
                .message_buffer = (&incoming)[0..1],
                .data_buffer = buffer,
                .flags = .{},
            } },
            .{ .deadline = deadline },
        )).net_receive;
        if (maybe_err) |err| return err;
        std.debug.assert(message_count == 1);
        return incoming.data.len;
    }

    var buffers = [_][]u8{buffer};
    const result = try io.operateTimeout(
        .{ .file_read_streaming = .{
            .file = .{
                .handle = stream.socket.handle,
                .flags = .{ .nonblocking = false },
            },
            .data = &buffers,
        } },
        .{ .deadline = deadline },
    );
    return result.file_read_streaming catch |err| switch (err) {
        error.EndOfStream => 0,
        else => return @errorCast(err),
    };
}

fn writeSomeWithDeadline(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
    deadline: std.Io.Clock.Timestamp,
) WriteError!usize {
    if (bytes.len == 0) return 0;
    if (deadline.durationFromNow(io).raw.nanoseconds <= 0) {
        return error.Timeout;
    }

    const Task = struct {
        io: std.Io,
        stream: net.Stream,
        bytes: []const u8,
        result: ?WriteError!usize = null,

        fn write(self: *@This()) void {
            const count = self.io.vtable.netWrite(
                self.io.userdata,
                self.stream.socket.handle,
                self.bytes,
                &.{""},
                0,
            ) catch |err| {
                self.result = err;
                return;
            };
            self.result = if (count == 0) error.SocketUnconnected else count;
        }

        fn waitUntil(
            task_io: std.Io,
            task_deadline: std.Io.Clock.Timestamp,
        ) std.Io.Cancelable!void {
            try task_deadline.wait(task_io);
        }
    };

    const Wake = union(enum) { write: void, timeout: std.Io.Cancelable!void };
    var task = Task{
        .io = io,
        .stream = stream,
        .bytes = bytes,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(io, &wake_storage);
    defer select.cancelDiscard();
    try select.concurrent(.write, Task.write, .{&task});
    select.concurrent(.timeout, Task.waitUntil, .{ io, deadline }) catch |err| {
        select.cancelDiscard();
        if (task.result) |result| {
            if (result) |count| return count else |_| {}
        }
        return err;
    };
    const wake = select.await() catch |err| {
        select.cancelDiscard();
        if (task.result) |result| {
            if (result) |count| return count else |_| {}
        }
        return err;
    };
    switch (wake) {
        .write => {
            const result = task.result orelse error.SocketUnconnected;
            return result;
        },
        .timeout => |result| {
            select.cancelDiscard();
            if (task.result) |write_result| {
                if (write_result) |count| return count else |_| {}
            }
            result catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            };
            return error.Timeout;
        },
    }
}

test "buffered reader preserves unread bytes across exact reads" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try writeAll(self.io, stream, "abcdef", null);
        }
    };

    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    defer thread.join();

    const stream = try (net.IpAddress{ .ip4 = .loopback(listener.socket.address.ip4.port) })
        .connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var storage: [8]u8 = undefined;
    var reader = BufferedReader.init(io, stream, &storage, null);
    var first: [3]u8 = undefined;
    try reader.readExact(&first);
    try std.testing.expectEqualStrings("abc", &first);
    try std.testing.expectEqualStrings("def", reader.buffered());
    var rest: [3]u8 = undefined;
    try reader.readExact(&rest);
    try std.testing.expectEqualStrings("def", &rest);
}

test "buffered reader bounds a NUL-terminated field" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
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
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            try writeAll(self.io, stream, "toolong\x00tail", null);
        }
    };

    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    defer thread.join();

    const stream = try (net.IpAddress{ .ip4 = .loopback(listener.socket.address.ip4.port) })
        .connect(io, .{ .mode = .stream });
    defer stream.close(io);

    var storage: [16]u8 = undefined;
    var reader = BufferedReader.init(io, stream, &storage, null);
    var field: [4]u8 = undefined;
    try std.testing.expectError(
        error.TooLong,
        reader.readUntilNull(&field),
    );
}

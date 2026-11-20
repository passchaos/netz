//! One retained Reader chunk per request; blocking source I/O stays off the
//! connection frame owner so sibling streams can keep making progress.
const std = @import("std");

pub const Reader = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    source: *std.Io.Reader,
    owner_wake: *std.Io.Event,
    buffer: []u8,
    mutex: std.Io.Mutex = .init,
    consumed: std.Io.Event = .unset,
    future: std.Io.Future(void) = undefined,
    future_active: bool = false,
    state: State = .pending,
    offset: usize = 0,

    const State = union(enum) {
        pending,
        data: usize,
        eof,
        failure: std.Io.Reader.Error,
    };

    pub const Available = union(enum) {
        pending,
        data: []const u8,
        eof,
        failure: std.Io.Reader.Error,
    };

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        source: *std.Io.Reader,
        owner_wake: *std.Io.Event,
        quantum: usize,
    ) !*Reader {
        const self = try allocator.create(Reader);
        errdefer allocator.destroy(self);
        const buffer = try allocator.alloc(u8, @min(quantum, 16 * 1024));
        errdefer allocator.free(buffer);
        self.* = .{
            .allocator = allocator,
            .io = io,
            .source = source,
            .owner_wake = owner_wake,
            .buffer = buffer,
        };
        return self;
    }

    pub fn start(self: *Reader) !void {
        self.future = try self.io.concurrent(run, .{self});
        self.future_active = true;
    }

    pub fn deinit(self: *Reader) void {
        // Join before either the Reader, driver wake or request command can
        // leave scope. Sources doing I/O must cooperate with cancellation.
        if (self.future_active) self.future.cancel(self.io);
        self.allocator.free(self.buffer);
        self.allocator.destroy(self);
    }

    pub fn available(self: *Reader) Available {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        return switch (self.state) {
            .pending => .pending,
            .data => |len| .{ .data = self.buffer[self.offset..len] },
            .eof => .eof,
            .failure => |err| .{ .failure = err },
        };
    }

    /// Release only the socket-committed prefix; the retained suffix remains
    /// stable through partial flow-control writes and the next owner turn.
    pub fn consume(self: *Reader, count: usize) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        std.debug.assert(self.state == .data);
        std.debug.assert(count <= self.state.data - self.offset);
        self.offset += count;
        if (self.offset == self.state.data) {
            self.offset = 0;
            self.state = .pending;
            self.consumed.set(self.io);
        }
    }

    fn publish(self: *Reader, state: State) void {
        self.mutex.lockUncancelable(self.io);
        self.state = state;
        self.mutex.unlock(self.io);
        self.owner_wake.set(self.io);
    }

    fn run(self: *Reader) void {
        while (true) {
            const count = @import("../../client/reader_io.zig").readBefore(self.io, self.source, self.buffer, null) catch {
                self.publish(.{ .failure = error.ReadFailed });
                return;
            };
            if (count == 0) {
                self.publish(.eof);
                return;
            }
            self.publish(.{ .data = count });
            self.consumed.wait(self.io) catch return;
            self.consumed.reset();
        }
    }
};

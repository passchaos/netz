const std = @import("std");
const test_socket = @import("../../../internal/test_socket.zig");
const output = @import("output.zig");

const Tls = struct {
    calls: usize = 0,
    bytes: [64]u8 = undefined,
    written: usize = 0,
    deadline: ?std.Io.Clock.Timestamp = null,
};
const Transport = union(enum) {
    tcp: struct { io: std.Io, stream: std.Io.net.Stream },
    tls_client: *Tls,
    tls_server: *Tls,

    pub fn writeAllWithDeadline(self: Transport, bytes: []const u8, committed: *usize, deadline: std.Io.Clock.Timestamp) !void {
        const connection = switch (self) {
            .tls_client, .tls_server => |connection| connection,
            .tcp => unreachable,
        };
        connection.calls += 1;
        @memcpy(connection.bytes[0..bytes.len], bytes);
        connection.written = bytes.len;
        connection.deadline = deadline;
        committed.* = bytes.len;
    }
};
const Observer = struct {
    var active: *Observer = undefined;
    bytes: [64]u8 = undefined,
    written: usize = 0,
    calls: usize = 0,
    header: []const u8,
    payload: []const u8,
    borrowed: bool = false,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        self.calls += 1;
        self.borrowed = header.ptr == self.header.ptr and data[0].ptr == self.payload.ptr;
        @memcpy(self.bytes[0..header.len], header);
        var count = header.len;
        for (data[0 .. data.len - 1]) |part| {
            @memcpy(self.bytes[count..][0..part.len], part);
            count += part.len;
        }
        self.written = count;
        return count;
    }
};

test "HTTP/2 transport deadline scatter output borrows TCP slices without allocation" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const delegate = threaded.io();
    var observer = Observer{ .header = "HEAD", .payload = "body" };
    Observer.active = &observer;
    var vtable = delegate.vtable.*;
    vtable.netWrite = Observer.write;
    const io = std.Io{ .userdata = delegate.userdata, .vtable = &vtable };
    const transport = Transport{ .tcp = .{ .io = io, .stream = test_socket.stream() } };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var batch: std.ArrayList(u8) = .empty;
    defer batch.deinit(std.testing.allocator);
    var submitted = false;
    try output.writeAllSlicesWithDeadline(failing.allocator(), transport, &.{ observer.header, observer.payload, "TAIL" }, &batch, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) }), &submitted);
    try std.testing.expect(submitted and observer.borrowed);
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expectEqualStrings("HEADbodyTAIL", observer.bytes[0..observer.written]);
    try std.testing.expectEqual(@as(usize, 0), batch.capacity);
}

test "HTTP/2 transport deadline scatter output retains one contiguous TLS transaction" {
    var batch: std.ArrayList(u8) = .empty;
    defer batch.deinit(std.testing.allocator);
    const deadline = std.Io.Clock.Timestamp{ .clock = .awake, .raw = .zero };
    inline for (.{ .tls_client, .tls_server }) |tag| {
        var connection: Tls = .{};
        const transport = @unionInit(Transport, @tagName(tag), &connection);
        var submitted = false;
        try output.writeAllSlicesWithDeadline(std.testing.allocator, transport, &.{ "HEAD", "", "body", "TAIL" }, &batch, deadline, &submitted);
        try std.testing.expect(submitted);
        try std.testing.expectEqual(@as(usize, 1), connection.calls);
        try std.testing.expectEqualStrings("HEADbodyTAIL", connection.bytes[0..connection.written]);
        try std.testing.expectEqual(deadline, connection.deadline.?);
    }
}

test "HTTP/2 transport deadline scatter TLS allocation failure never submits output" {
    var batch: std.ArrayList(u8) = .empty;
    var connection: Tls = .{};
    const transport = Transport{ .tls_client = &connection };
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var submitted = true;
    try std.testing.expectError(error.OutOfMemory, output.writeAllSlicesWithDeadline(failing.allocator(), transport, &.{ "HEAD", "body" }, &batch, .{ .clock = .awake, .raw = .zero }, &submitted));
    try std.testing.expect(!submitted);
    try std.testing.expectEqual(@as(usize, 0), connection.calls);
    try std.testing.expectEqual(@as(usize, 0), batch.capacity);
}

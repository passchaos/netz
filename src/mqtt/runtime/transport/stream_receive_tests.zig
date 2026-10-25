//! Packet cursors survive every accepted read before a local interruption.
const std = @import("std");

pub fn cursor(comptime Reader: type, comptime State: type, comptime PacketError: type) !void {
    const Source = struct {
        io: std.Io,
        bytes: []const u8,
        cut: usize,
        offset: usize = 0,
        fault: ?anyerror,

        pub fn read(self: *@This(), out: []u8) PacketError!usize {
            if (self.offset == self.cut) {
                if (self.fault) |err| {
                    self.fault = null;
                    return @errorCast(err);
                }
            }
            const end = if (self.offset < self.cut) self.cut else self.bytes.len;
            const count = @min(out.len, end - self.offset);
            @memcpy(out[0..count], self.bytes[self.offset..][0..count]);
            self.offset += count;
            return count;
        }

        pub fn readWithDeadline(self: *@This(), out: []u8, _: std.Io.Clock.Timestamp) PacketError!usize {
            return self.read(out);
        }
    };
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const bytes = "\x30\x0a\x00\x01xpayload";
    for ([_]anyerror{ error.Canceled, error.ConcurrencyUnavailable }) |fault| {
        var source: Source = .{ .io = threaded.io(), .bytes = bytes, .cut = 7, .fault = fault };
        var transport = struct { connection: *Source, packet_state: State = .{} }{ .connection = &source };
        defer transport.packet_state.deinit(std.testing.allocator);
        try std.testing.expectError(fault, Reader.read(std.testing.allocator, &transport, 64, null, null, 0));
        try std.testing.expectEqual(source.cut, transport.packet_state.packet_read);
        var packet = try Reader.read(std.testing.allocator, &transport, 64, null, null, 0);
        defer packet.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(bytes, packet.bytes);
    }
    for ([_]u16{ 0, 32 }) |prefix_len| {
        var source: Source = .{ .io = threaded.io(), .bytes = bytes, .cut = bytes.len, .fault = null };
        var transport = struct { connection: *Source, packet_state: State = .{} }{ .connection = &source };
        defer transport.packet_state.deinit(std.testing.allocator);
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, Reader.read(failing.allocator(), &transport, 64, null, null, prefix_len));
        try std.testing.expectEqual(@as(usize, 2), source.offset);
        try std.testing.expectEqual(@as(usize, 2), transport.packet_state.header_len);
        var packet = try Reader.read(std.testing.allocator, &transport, 64, null, null, prefix_len);
        defer packet.deinit(std.testing.allocator);
        try std.testing.expectEqualStrings(bytes, packet.bytes);
        try std.testing.expectEqual(prefix_len, packet.prefix_len);
    }
}

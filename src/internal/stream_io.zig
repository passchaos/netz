const std = @import("std");

const net = std.Io.net;

/// Write two borrowed slices as one logical stream write.
///
/// Zig 0.16's `netWrite` reserves the final `data` item as a splat pattern.
/// Therefore the payload must be followed by an empty pattern item; passing
/// `&.{payload}` with `splat = 0` silently omits the payload from that syscall.
/// Keeping this subtle contract in one helper prevents framed protocols from
/// regressing to separate header/payload sends and triggering delayed ACKs.
pub fn writeAllParts(
    io: std.Io,
    stream: net.Stream,
    header: []const u8,
    payload: []const u8,
) net.Stream.Writer.Error!void {
    return writeAllSlices(io, stream, &.{ header, payload });
}

/// Write borrowed slices in order without first concatenating them.
///
/// Up to fifteen remaining slices are offered per call; a backend may consume
/// fewer (Zig 0.16 Threaded uses eight iovecs), in which case this helper
/// resumes at the exact slice boundary. Empty slices are skipped and short
/// writes never replay bytes.
pub fn writeAllSlices(
    io: std.Io,
    stream: net.Stream,
    parts: []const []const u8,
) net.Stream.Writer.Error!void {
    var part_index: usize = 0;
    var part_offset: usize = 0;
    while (true) {
        while (part_index < parts.len and
            part_offset == parts[part_index].len)
        {
            part_index += 1;
            part_offset = 0;
        }
        if (part_index == parts.len) return;

        // The final data entry is reserved by std.Io as the splat pattern.
        // Keep one slot empty and fill preceding slots with subsequent slices.
        var data: [16][]const u8 = undefined;
        var data_len: usize = 0;
        var next_index = part_index + 1;
        while (next_index < parts.len and data_len + 1 < data.len) : (next_index += 1) {
            if (parts[next_index].len == 0) continue;
            data[data_len] = parts[next_index];
            data_len += 1;
        }
        data[data_len] = "";
        data_len += 1;

        var remaining = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            parts[part_index][part_offset..],
            data[0..data_len],
            0,
        );
        if (remaining == 0) return error.SocketUnconnected;

        while (remaining != 0) {
            const available = parts[part_index].len - part_offset;
            if (remaining < available) {
                part_offset += remaining;
                break;
            }
            remaining -= available;
            part_index += 1;
            part_offset = 0;
            while (part_index < parts.len and parts[part_index].len == 0) {
                part_index += 1;
            }
            if (part_index == parts.len) {
                std.debug.assert(remaining == 0);
                return;
            }
        }
    }
}

test "stream vector write includes all slices in the first netWrite" {
    const Observer = struct {
        bytes: [64]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,
        max_per_call: usize = std.math.maxInt(usize),

        fn netWrite(
            userdata: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            splat: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            var written: usize = 0;
            written += self.append(
                header[0..@min(header.len, self.max_per_call)],
            );
            if (data.len != 0) {
                for (data[0 .. data.len - 1]) |bytes| {
                    if (written == self.max_per_call) break;
                    const remaining = self.max_per_call - written;
                    written += self.append(
                        bytes[0..@min(bytes.len, remaining)],
                    );
                }
                for (0..splat) |_| {
                    if (written == self.max_per_call) break;
                    const pattern = data[data.len - 1];
                    const remaining = self.max_per_call - written;
                    written += self.append(
                        pattern[0..@min(pattern.len, remaining)],
                    );
                }
            }
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            const count = @min(bytes.len, self.bytes.len - self.len);
            @memcpy(self.bytes[self.len..][0..count], bytes[0..count]);
            self.len += count;
            return count;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = Observer.netWrite;
    var observer: Observer = .{};
    const io = std.Io{ .userdata = &observer, .vtable = &vtable };

    try writeAllSlices(
        io,
        undefined,
        &.{ "header", "", "payload", "-tail" },
    );
    try std.testing.expectEqual(@as(usize, 1), observer.calls);
    try std.testing.expectEqualStrings(
        "headerpayload-tail",
        observer.bytes[0..observer.len],
    );
}

test "stream vector write advances correctly after partial writes" {
    const Observer = struct {
        bytes: [64]u8 = undefined,
        len: usize = 0,
        calls: usize = 0,

        fn netWrite(
            userdata: ?*anyopaque,
            _: net.Socket.Handle,
            header: []const u8,
            data: []const []const u8,
            _: usize,
        ) net.Stream.Writer.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            var remaining: usize = 3;
            var written: usize = 0;
            const header_count = @min(header.len, remaining);
            written += self.append(header[0..header_count]);
            remaining -= header_count;
            if (data.len != 0) {
                for (data[0 .. data.len - 1]) |bytes| {
                    if (remaining == 0) break;
                    const count = @min(bytes.len, remaining);
                    written += self.append(bytes[0..count]);
                    remaining -= count;
                }
            }
            return written;
        }

        fn append(self: *@This(), bytes: []const u8) usize {
            @memcpy(self.bytes[self.len..][0..bytes.len], bytes);
            self.len += bytes.len;
            return bytes.len;
        }
    };

    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var vtable = threaded.io().vtable.*;
    vtable.netWrite = Observer.netWrite;
    var observer: Observer = .{};
    const io = std.Io{ .userdata = &observer, .vtable = &vtable };

    try writeAllSlices(
        io,
        undefined,
        &.{ "head", "body", "-tail" },
    );
    try std.testing.expect(observer.calls > 1);
    try std.testing.expectEqualStrings(
        "headbody-tail",
        observer.bytes[0..observer.len],
    );
}

const std = @import("std");
const runtime = @import("../../http1/runtime.zig");
const Reader = @import("../../http1/runtime/body_reader.zig").Reader(runtime.Error);
const metadata = @import("response_tests.zig");

test "HTTP content decoding keeps HTTP1 streaming metadata and pipeline boundaries" {
    const raw =
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 123\r\n\r\n" ++
        "HTTP/1.1 304 Not Modified\r\nContent-Encoding: gzip\r\nContent-Length: 123\r\n\r\n" ++
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n";
    const Source = struct {
        offset: usize = 0,

        fn readSome(context: ?*anyopaque, output: []u8) runtime.Error!usize {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            const count = @min(output.len, raw.len - self.offset);
            @memcpy(output[0..count], raw[self.offset..][0..count]);
            self.offset += count;
            return count;
        }
    };
    const Consumer = struct {
        metadata_only: bool,

        fn begin(self: *@This(), head: Reader.ResponseHead) !void {
            try std.testing.expectEqual(!self.metadata_only, head.body_allowed);
            if (self.metadata_only) {
                try metadata.expectEmptyStream(head);
            } else {
                var decoder = try head.streamContentDecoder(std.testing.allocator, .{
                    .max_encoded_bytes = 1024,
                    .max_decoded_bytes = 1024,
                });
                defer decoder.deinit();
                try std.testing.expectError(error.InvalidContentEncoding, decoder.finish(&.{}));
            }
        }

        fn consume(_: *@This(), bytes: []const u8) !void {
            try std.testing.expectEqual(@as(usize, 0), bytes.len);
        }
    };
    var inbuf: std.ArrayList(u8) = .empty;
    defer inbuf.deinit(std.testing.allocator);
    var source: Source = .{};
    var reader = Reader{
        .allocator = std.testing.allocator,
        .context = &source,
        .read_some = Source.readSome,
        .inbuf = &inbuf,
        .limits = .{ .max_head_bytes = 4096, .max_body_bytes = 1 },
        .options = .{},
    };
    for (0..3) |index| {
        var consumer = Consumer{ .metadata_only = index < 2 };
        var response = try reader.readResponse(if (index == 0) .HEAD else .GET, &consumer, Consumer.begin, Consumer.consume);
        defer response.deinit(std.testing.allocator);
        try std.testing.expectEqual(index >= 2, response.body_allowed);
        try std.testing.expectEqual(@as(usize, 0), response.body_bytes);
    }
    try std.testing.expectEqual(raw.len, source.offset);
}

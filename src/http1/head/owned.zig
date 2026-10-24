//! Owned field descriptors and folded values; start-line strings borrow input.
const std = @import("std");
const http1 = @import("../mod.zig");

fn Owned(comptime Head: type) type {
    return struct {
        head: Head,
        header_storage: []http1.Header,
        value_storage: [][]u8,

        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            for (self.value_storage) |value| allocator.free(value);
            allocator.free(self.value_storage);
            allocator.free(self.header_storage);
            self.* = undefined;
        }

        pub fn takeValues(self: *@This()) [][]u8 {
            const values = self.value_storage;
            self.value_storage = &.{};
            return values;
        }
    };
}

pub fn Parser(comptime Context: type) type {
    return struct {
        pub const Request = Owned(http1.RequestHead);
        pub const Response = Owned(http1.ResponseHead);

        pub fn request(allocator: std.mem.Allocator, bytes: []const u8, options: http1.ParseOptions) http1.Error!Request {
            var fields = try Context.parseFields(allocator, bytes, options, .request);
            errdefer Context.deinitFields(&fields, allocator);
            const head = try Context.finishRequest(fields.start_line, fields.storage.headers, fields.head_len, options);
            return .{ .head = head, .header_storage = fields.storage.headers, .value_storage = fields.storage.value_storage };
        }

        pub fn response(allocator: std.mem.Allocator, bytes: []const u8, options: http1.ParseOptions, context: http1.ResponseContext) http1.Error!Response {
            var fields = try Context.parseFields(allocator, bytes, options, .response);
            errdefer Context.deinitFields(&fields, allocator);
            const head = try Context.finishResponse(fields.start_line, fields.storage.headers, fields.head_len, context);
            return .{ .head = head, .header_storage = fields.storage.headers, .value_storage = fields.storage.value_storage };
        }
    };
}

test {
    _ = @import("tests.zig");
}

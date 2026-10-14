//! Stack-first mapping from unified headers into protocol-native fields.

const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");
const types = @import("types.zig");

pub const max_stack_headers: usize = 32;
pub const max_stack_trailers: usize = 16;

pub const Http1Headers = struct {
    items: []const http1.Header,
    owned: ?[]http1.Header = null,

    pub fn deinit(self: *Http1Headers, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
        self.* = undefined;
    }
};

pub fn mapHttp1(
    allocator: std.mem.Allocator,
    headers: []const types.Header,
    stack: []http1.Header,
) std.mem.Allocator.Error!Http1Headers {
    const out = if (headers.len <= stack.len)
        stack[0..headers.len]
    else
        try allocator.alloc(http1.Header, headers.len);
    for (headers, out) |header, *mapped| {
        mapped.* = .{ .name = header.name, .value = header.value };
    }
    return .{
        .items = out,
        .owned = if (headers.len <= stack.len) null else out,
    };
}

pub const Http2Headers = struct {
    items: []const http2.Hpack.HeaderField,
    owned: ?[]http2.Hpack.HeaderField = null,

    pub fn deinit(self: *Http2Headers, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
        self.* = undefined;
    }
};

pub fn mapHttp2(
    allocator: std.mem.Allocator,
    headers: []const types.Header,
    stack: []http2.Hpack.HeaderField,
) std.mem.Allocator.Error!Http2Headers {
    const out = if (headers.len <= stack.len)
        stack[0..headers.len]
    else
        try allocator.alloc(http2.Hpack.HeaderField, headers.len);
    for (headers, out) |header, *mapped| {
        mapped.* = .{
            .name = header.name,
            .value = header.value,
            .never_index = header.never_indexed,
        };
    }
    return .{
        .items = out,
        .owned = if (headers.len <= stack.len) null else out,
    };
}

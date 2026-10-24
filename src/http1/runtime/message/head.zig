//! Body boundaries derived from the same parsed head exposed to applications.
const std = @import("std");
const http1 = @import("../../mod.zig");
const framing = @import("framing.zig");

pub const Plan = struct {
    head_len: usize,
    body_framing: http1.BodyFraming,
    content_length: ?usize,
    send_continue: bool = false,

    pub fn validateBodyLimit(self: Plan, max_body_bytes: usize) framing.Error!void {
        if (self.body_framing == .content_length and (self.content_length orelse return error.InvalidContentLength) > max_body_bytes) return error.BodyTooLarge;
    }

    pub fn targetLength(self: Plan, bytes: []const u8, max_head_bytes: usize, max_body_bytes: usize) framing.Error!usize {
        if (self.head_len > bytes.len) return error.BufferTooShort;
        return switch (self.body_framing) {
            .none, .close_delimited => self.head_len,
            .content_length => blk: {
                const len = self.content_length orelse return error.InvalidContentLength;
                if (len > max_body_bytes) return error.BodyTooLarge;
                break :blk std.math.add(usize, self.head_len, len) catch error.ContentLengthOverflow;
            },
            .chunked => std.math.add(usize, self.head_len, (try framing.chunkedBodyLayout(bytes[self.head_len..], max_head_bytes, max_body_bytes)).wire_len) catch error.BodyTooLarge,
        };
    }
};

pub fn inspect(allocator: std.mem.Allocator, bytes: []const u8, options: http1.ParseOptions, request_method: ?http1.Method, is_request: bool) http1.Error!Plan {
    // The owning runtime can accept obs-fold without imposing that capability
    // on allocation-free borrowed-head APIs. Strict heads retain their stack
    // descriptors and do not allocate while selecting the message boundary.
    if (options.allow_obs_fold) {
        if (is_request) {
            var owned = try http1.parseOwnedRequestHead(allocator, bytes, options);
            defer owned.deinit(allocator);
            return fromRequest(owned.head);
        }
        var owned = try http1.parseOwnedResponseHead(allocator, bytes, options, .{ .request_method = request_method });
        defer owned.deinit(allocator);
        return fromResponse(owned.head);
    }
    var stack: [128]http1.Header = undefined;
    const headers = if (options.max_headers <= stack.len) stack[0..options.max_headers] else try allocator.alloc(http1.Header, options.max_headers);
    defer if (headers.ptr != stack[0..].ptr) allocator.free(headers);
    return if (is_request)
        fromRequest(try http1.parseRequestHead(bytes, headers, options))
    else
        fromResponse(try http1.parseResponseHead(bytes, headers, options, .{ .request_method = request_method }));
}

fn fromRequest(head: http1.RequestHead) Plan {
    return .{ .head_len = head.head_len, .body_framing = head.body_framing, .content_length = head.content_length, .send_continue = shouldContinue(head) };
}

fn fromResponse(head: http1.ResponseHead) Plan {
    return .{ .head_len = head.head_len, .body_framing = head.body_framing, .content_length = head.content_length };
}

pub fn shouldContinue(head: anytype) bool {
    if (head.version != .http_1_1) return false;
    if (head.body_framing != .chunked and (head.content_length orelse 0) == 0) return false;
    var found = false;
    for (head.headers) |header| {
        if (!header.eqlName("expect")) continue;
        if (found or !std.ascii.eqlIgnoreCase(header.value, "100-continue")) return false;
        found = true;
    }
    return found;
}

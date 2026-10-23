//! Receive HTTP/1 Upgrade heads and rejection entities under one deadline.
//! A successful response transfers coalesced bytes to WebSocket framing;
//! a rejection retains the complete bounded HTTP entity and trailers.

const std = @import("std");
const http1 = @import("../../../http1/mod.zig");
const framing = @import("../../../http1/runtime/message/framing.zig");
const storage = @import("storage.zig");
const Limits = @import("../common.zig").Limits;

pub const Head = struct {
    head: []u8,
    extra: []u8,

    pub fn deinit(self: *Head, allocator: std.mem.Allocator) void {
        allocator.free(self.head);
        allocator.free(self.extra);
        self.* = undefined;
    }
};

pub const ResponseBytes = struct {
    bytes: []u8,
    /// Bytes following a successful 101 head belong to WebSocket framing.
    /// Rejection responses instead consume their complete HTTP body here.
    extra: ?[]u8,
};

pub fn Reader(comptime Context: type) type {
    return struct {
        const Transport = Context.TransportType;
        const Error = Context.ErrorType;

        pub fn readResponseBytes(
            allocator: std.mem.Allocator,
            transport: Transport,
            head: *Head,
            limits: Limits,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!ResponseBytes {
            var header_stack: [storage.stack_capacity]http1.Header =
                undefined;
            const header_storage = try storage.acquire(
                http1.Header,
                allocator,
                &header_stack,
                limits.max_response_headers,
            );
            defer storage.release(
                http1.Header,
                allocator,
                &header_stack,
                header_storage,
            );
            const parsed_head = try http1.parseResponseHead(
                head.head,
                header_storage,
                .{ .max_headers = limits.max_response_headers },
                .{ .request_method = .GET },
            );
            if (parsed_head.status == 101) {
                const result: ResponseBytes = .{
                    .bytes = head.head,
                    .extra = head.extra,
                };
                head.* = undefined;
                return result;
            }

            var bytes: std.ArrayList(u8) = .empty;
            errdefer bytes.deinit(allocator);
            try bytes.ensureTotalCapacity(
                allocator,
                std.math.add(usize, head.head.len, head.extra.len) catch
                    return error.BodyTooLarge,
            );
            bytes.appendSliceAssumeCapacity(head.head);
            bytes.appendSliceAssumeCapacity(head.extra);
            const body_start = head.head.len;

            var scratch: [4096]u8 = undefined;
            if (framing.responseHeadUsesCloseDelimitedBody(
                head.head[0 .. head.head.len - 4],
                .GET,
            )) {
                if (bytes.items.len - body_start > limits.max_rejection_body_bytes) {
                    return error.BodyTooLarge;
                }
                while (true) {
                    const count = if (deadline) |absolute|
                        try Context.readWithDeadline(transport, &scratch, absolute)
                    else
                        try Context.read(transport, &scratch);
                    if (count == 0) break;
                    const body_len = std.math.add(
                        usize,
                        bytes.items.len - body_start,
                        count,
                    ) catch return error.BodyTooLarge;
                    if (body_len > limits.max_rejection_body_bytes) {
                        return error.BodyTooLarge;
                    }
                    try bytes.appendSlice(allocator, scratch[0..count]);
                }
                return .{ .bytes = try bytes.toOwnedSlice(allocator), .extra = null };
            }

            const target_len = while (true) {
                const len = framing.messageTargetLength(
                    bytes.items,
                    head.head.len - 4,
                    limits.max_head_bytes,
                    limits.max_rejection_body_bytes,
                    .GET,
                ) catch |err| switch (err) {
                    error.BufferTooShort => {
                        const count = if (deadline) |absolute|
                            try Context.readWithDeadline(transport, scratch[0..1], absolute)
                        else
                            try Context.read(transport, scratch[0..1]);
                        if (count == 0) return error.ConnectionClosed;
                        try bytes.appendSlice(allocator, scratch[0..count]);
                        continue;
                    },
                    else => |other| return other,
                };
                break len;
            };
            try bytes.ensureTotalCapacity(allocator, target_len);
            while (bytes.items.len < target_len) {
                const count = if (deadline) |absolute|
                    try Context.readWithDeadline(
                        transport,
                        scratch[0..@min(scratch.len, target_len - bytes.items.len)],
                        absolute,
                    )
                else
                    try Context.read(
                        transport,
                        scratch[0..@min(scratch.len, target_len - bytes.items.len)],
                    );
                if (count == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..count]);
            }
            // Rejected connections are closed, so any bytes beyond this response are
            // intentionally discarded rather than exposed as ambiguous pipeline data.
            bytes.items.len = target_len;
            return .{ .bytes = try bytes.toOwnedSlice(allocator), .extra = null };
        }

        pub fn readHead(
            allocator: std.mem.Allocator,
            transport: Transport,
            max_head_bytes: usize,
            deadline: ?std.Io.Clock.Timestamp,
        ) Error!Head {
            return readHeadWithInitial(
                allocator,
                transport,
                max_head_bytes,
                deadline,
                &.{},
            );
        }

        pub fn readHeadWithInitial(
            allocator: std.mem.Allocator,
            transport: Transport,
            max_head_bytes: usize,
            deadline: ?std.Io.Clock.Timestamp,
            initial: []const u8,
        ) Error!Head {
            var bytes: std.ArrayList(u8) = .empty;
            defer bytes.deinit(allocator);
            try bytes.appendSlice(allocator, initial);
            var scratch: [4096]u8 = undefined;
            while (true) {
                if (try findHeadEndWithinLimit(bytes.items, max_head_bytes)) |head_end| {
                    const split = head_end + 4;
                    const head = try allocator.dupe(u8, bytes.items[0..split]);
                    errdefer allocator.free(head);
                    return .{
                        .head = head,
                        .extra = try allocator.dupe(u8, bytes.items[split..]),
                    };
                }
                const read_buf = scratch[0..@min(scratch.len, max_head_bytes - bytes.items.len)];
                const n = if (deadline) |absolute|
                    try Context.readWithDeadline(transport, read_buf, absolute)
                else
                    try Context.read(transport, read_buf);
                if (n == 0) return error.ConnectionClosed;
                try bytes.appendSlice(allocator, scratch[0..n]);
            }
        }
    };
}

pub fn findHeadEndWithinLimit(bytes: []const u8, max_head_bytes: usize) error{HeadersTooLarge}!?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) return error.HeadersTooLarge;
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

test "WebSocket HTTP upgrade reader enforces header byte limit at delimiter" {
    const exact = "GET /chat HTTP/1.1\r\nHost: example\r\n\r\n";
    try std.testing.expectEqual(@as(?usize, exact.len - 4), try findHeadEndWithinLimit(exact, exact.len));
    try std.testing.expectError(error.HeadersTooLarge, findHeadEndWithinLimit(exact, exact.len - 1));

    const incomplete = "GET /chat HTTP/1.1\r\nHost: example";
    try std.testing.expectEqual(@as(?usize, null), try findHeadEndWithinLimit(incomplete, incomplete.len + 1));
    try std.testing.expectError(error.HeadersTooLarge, findHeadEndWithinLimit(incomplete, incomplete.len));
}

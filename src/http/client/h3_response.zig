//! Owned H3 response collection shared by direct and pooled clients.
const std = @import("std");
const http3 = @import("../../http3/mod.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const client = @import("types.zig");
const duplex = @import("duplex.zig");

/// Clone decoded QPACK fields so they outlive the stream handle. Each field
/// owns its name and value allocation, matching `Qpack.freeDecodedFields`.
fn cloneH3Fields(
    allocator: std.mem.Allocator,
    fields: anytype,
) std.mem.Allocator.Error![]http3.Qpack.HeaderField {
    const owned = try allocator.alloc(http3.Qpack.HeaderField, fields.len);
    var initialized: usize = 0;
    errdefer {
        for (owned[0..initialized]) |field| {
            if (field.name_storage) |storage| allocator.free(storage);
            if (field.value_storage) |storage| allocator.free(storage);
        }
        allocator.free(owned);
    }
    for (fields, owned) |source, *target| {
        const name = try allocator.dupe(u8, source.name);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, source.value);
        target.* = .{
            .name = name,
            .value = value,
            .never_indexed = source.never_indexed,
            .name_storage = name,
            .value_storage = value,
        };
        initialized += 1;
    }
    return owned;
}

pub const Collector = struct {
    allocator: std.mem.Allocator,
    status: u16 = 0,
    headers: []http3.Qpack.HeaderField = &.{},
    trailers: []http3.Qpack.HeaderField = &.{},
    body: std.ArrayList(u8) = .empty,
    body_allowed: bool = true,
    consumed: usize = 0,
    qpack_section_acknowledgments: usize = 0,
    finished: bool = false,

    pub fn responseSink(self: *Collector) duplex.ResponseSink {
        return .{ .context = self, .begin = beginUnified, .data = data, .end = endUnified };
    }

    fn beginUnified(context: *anyopaque, head: duplex.ResponseHead) !void {
        const self: *Collector = @ptrCast(@alignCast(context));
        if (self.status != 0) return error.UnexpectedFrame;
        self.status = head.status;
        self.headers = try cloneH3Fields(self.allocator, head.headers);
    }

    fn endUnified(context: *anyopaque, fields: []const duplex.Header) !void {
        const self: *Collector = @ptrCast(@alignCast(context));
        if (self.finished) return error.UnexpectedFrame;
        self.trailers = try cloneH3Fields(self.allocator, fields);
        self.finished = true;
    }

    pub fn sink(self: *Collector) http3_runtime.StreamCallbackSink {
        return .{
            .context = self,
            .begin = begin,
            .data = data,
            .end = end,
        };
    }

    fn begin(
        context: *anyopaque,
        head: http3.DecodedResponseHead,
    ) !void {
        const self: *Collector = @ptrCast(@alignCast(context));
        if (self.status != 0) return error.UnexpectedFrame;
        self.status = head.status;
        self.body_allowed = head.body_allowed;
        self.consumed = head.consumed;
        self.qpack_section_acknowledgments =
            head.qpack_section_acknowledgments;
        self.headers = try cloneH3Fields(self.allocator, head.headers);
    }

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *Collector = @ptrCast(@alignCast(context));
        try self.body.appendSlice(self.allocator, bytes);
    }

    fn end(
        context: *anyopaque,
        trailers: []const http3.Qpack.HeaderField,
    ) !void {
        const self: *Collector = @ptrCast(@alignCast(context));
        if (self.finished) return error.UnexpectedFrame;
        self.trailers = try cloneH3Fields(self.allocator, trailers);
        self.finished = true;
    }

    pub fn deinit(self: *Collector) void {
        http3.Qpack.freeDecodedFields(self.allocator, self.headers);
        http3.Qpack.freeDecodedFields(self.allocator, self.trailers);
        self.body.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn intoResponse(
        self: *Collector,
        allocator: std.mem.Allocator,
    ) !client.OwnedResponse {
        if (!self.finished or self.status == 0) {
            return error.UnexpectedFrame;
        }
        const body = try self.body.toOwnedSlice(allocator);
        errdefer allocator.free(body);
        const stream_bytes = try allocator.alloc(u8, 0);
        errdefer allocator.free(stream_bytes);
        const headers = self.headers;
        self.headers = &.{};
        const trailers = self.trailers;
        self.trailers = &.{};
        return .{
            .allocator = allocator,
            .value = .{ .http3 = .{
                .stream_bytes = stream_bytes,
                .response = .{
                    .status = self.status,
                    .headers = headers,
                    .trailers = trailers,
                    .body = body,
                    .body_storage = body,
                    .body_allowed = self.body_allowed,
                    .consumed = self.consumed,
                    .qpack_section_acknowledgments = self.qpack_section_acknowledgments,
                },
            } },
        };
    }
};

//! Connection-owned pushed responses, decoded in HTTP/2 wire order.

const std = @import("std");
const http2 = @import("../../mod.zig");
const message = @import("../headers/message.zig");

pub const Error = message.Error || error{ InvalidFrame, UnexpectedFrame, StreamReset, PushNotReady, PushBufferFull, MessageTooLarge, TooManyInformationalResponses };

pub const Limits = struct {
    max_bytes: usize,
    max_body_bytes: usize,
    max_informational_responses: usize,
};

pub const Response = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body: []u8,
    trailers: []http2.Hpack.HeaderField,
    body_allowed: bool,
    trailers_only: bool,
};

pub const Entry = struct {
    stream_id: u31,
    head_request: bool,
    headers: ?[]http2.Hpack.HeaderField = null,
    trailers: []http2.Hpack.HeaderField = &.{},
    body: std.ArrayList(u8) = .empty,
    status: ?u16 = null,
    content_length: ?usize = null,
    body_allowed: bool = true,
    informational_count: usize = 0,
    retained_bytes: usize = 0,
    finished: bool = false,
    failure: ?Error = null,
    trailers_only: bool = false,
    started: bool = false,

    fn clear(self: *Entry, allocator: std.mem.Allocator) void {
        if (self.headers) |headers| freeHeaders(allocator, headers);
        freeHeaders(allocator, self.trailers);
        self.body.deinit(allocator);
        self.headers = null;
        self.trailers = &.{};
        self.body = .empty;
    }
};

pub const Store = struct {
    entries: std.ArrayList(Entry) = .empty,
    index: std.AutoHashMapUnmanaged(u31, usize) = .empty,
    retained_bytes: usize = 0,

    pub fn deinit(self: *Store, allocator: std.mem.Allocator) void {
        for (self.entries.items) |*entry| entry.clear(allocator);
        self.entries.deinit(allocator);
        self.index.deinit(allocator);
        self.* = .{};
    }

    pub fn reserve(self: *Store, allocator: std.mem.Allocator, stream_id: u31, head_request: bool) std.mem.Allocator.Error!void {
        const slot = try self.index.getOrPut(allocator, stream_id);
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.index.remove(stream_id);
        try self.entries.append(allocator, .{ .stream_id = stream_id, .head_request = head_request });
        slot.value_ptr.* = self.entries.items.len - 1;
    }

    pub fn get(self: *Store, stream_id: u31) ?*Entry {
        return &self.entries.items[self.index.get(stream_id) orelse return null];
    }

    pub fn remove(self: *Store, allocator: std.mem.Allocator, stream_id: u31) void {
        const slot = self.index.fetchRemove(stream_id) orelse return;
        var entry = self.entries.swapRemove(slot.value);
        self.retained_bytes -= entry.retained_bytes;
        entry.clear(allocator);
        if (slot.value < self.entries.items.len) {
            const moved = self.entries.items[slot.value].stream_id;
            self.index.getPtr(moved).?.* = slot.value;
        }
    }

    /// Consume an already decoded field section, including on error. Its
    /// strings remain independent of later HPACK dynamic-table mutations.
    pub fn headers(self: *Store, allocator: std.mem.Allocator, stream_id: u31, fields: []http2.Hpack.HeaderField, end_stream: bool, limits: Limits) Error!void {
        var fields_owned = true;
        defer if (fields_owned) freeHeaders(allocator, fields);
        const entry = self.get(stream_id) orelse return error.UnexpectedFrame;
        if (entry.finished) return error.UnexpectedFrame;
        if (entry.headers != null) {
            if (!end_stream or !entry.body_allowed) return error.UnexpectedFrame;
            try message.validateHeaderBlock(fields, .response_trailers);
            try message.validateResponseContentLength(entry.content_length, entry.body.items.len, entry.body_allowed);
            try self.charge(entry, headerBytes(fields), limits.max_bytes);
            entry.trailers = fields;
            fields_owned = false;
            entry.finished = true;
            return;
        }
        try message.validateHeaderBlock(fields, .response);
        const lookup = try message.responseHeaderLookup(fields);
        const text = lookup.status orelse return error.MissingPseudoHeader;
        const status = std.fmt.parseInt(u16, text, 10) catch return error.InvalidStatus;
        if (message.informationalResponseToSkip(status)) {
            if (end_stream or lookup.content_length != null) return error.InvalidContentLength;
            if (entry.informational_count >= limits.max_informational_responses) return error.TooManyInformationalResponses;
            entry.informational_count += 1;
            return;
        }
        const body_allowed = !message.responseForbidsBody(status, if (entry.head_request) "HEAD" else "GET", false);
        if ((message.statusIsInformational(status) or status == 204) and lookup.content_length != null) return error.InvalidContentLength;
        if (body_allowed and (lookup.content_length orelse 0) > limits.max_body_bytes) return error.MessageTooLarge;
        if (end_stream) try message.validateResponseContentLength(lookup.content_length, 0, body_allowed);
        try self.charge(entry, headerBytes(fields), limits.max_bytes);
        entry.headers = fields;
        fields_owned = false;
        entry.status = status;
        entry.content_length = lookup.content_length;
        entry.body_allowed = body_allowed;
        entry.finished = end_stream;
        entry.trailers_only = end_stream;
    }

    pub fn data(self: *Store, allocator: std.mem.Allocator, stream_id: u31, bytes: []const u8, end_stream: bool, limits: Limits) Error!void {
        const entry = self.get(stream_id) orelse return error.UnexpectedFrame;
        if (entry.finished or entry.headers == null) return error.UnexpectedFrame;
        _ = try message.checkedResponseBodyLength(entry.content_length, entry.body.items.len, bytes.len, limits.max_body_bytes, entry.body_allowed, end_stream);
        try self.checkCharge(bytes.len, limits.max_bytes);
        try entry.body.appendSlice(allocator, bytes);
        self.retained_bytes += bytes.len;
        entry.retained_bytes += bytes.len;
        entry.finished = end_stream;
    }

    /// A later reset must not erase an already completed response. For an
    /// unfinished response, retain its first error until its owner consumes it.
    pub fn fail(self: *Store, allocator: std.mem.Allocator, stream_id: u31, err: Error) void {
        const entry = self.get(stream_id) orelse return;
        if (entry.finished) return;
        self.retained_bytes -= entry.retained_bytes;
        entry.retained_bytes = 0;
        entry.clear(allocator);
        entry.failure = err;
        entry.finished = true;
    }

    /// Ownership transfers only after body compaction succeeds, so allocation
    /// failure while taking a ready response leaves it available for retry.
    pub fn take(self: *Store, allocator: std.mem.Allocator, stream_id: u31) Error!Response {
        const entry = self.get(stream_id) orelse return error.UnexpectedFrame;
        if (!entry.finished) return error.PushNotReady;
        if (entry.failure) |err| return err;
        const body = try entry.body.toOwnedSlice(allocator);
        const response = Response{
            .headers = entry.headers.?,
            .status = entry.status.?,
            .body = body,
            .trailers = entry.trailers,
            .body_allowed = entry.body_allowed,
            .trailers_only = entry.trailers_only,
        };
        self.retained_bytes -= entry.retained_bytes;
        entry.retained_bytes = 0;
        entry.headers = null;
        entry.trailers = &.{};
        return response;
    }

    fn charge(self: *Store, entry: *Entry, bytes: usize, maximum: usize) Error!void {
        try self.checkCharge(bytes, maximum);
        self.retained_bytes += bytes;
        entry.retained_bytes += bytes;
    }

    fn checkCharge(self: *const Store, bytes: usize, maximum: usize) Error!void {
        if (bytes > maximum -| self.retained_bytes) return error.PushBufferFull;
    }
};

fn headerBytes(fields: []const http2.Hpack.HeaderField) usize {
    var bytes: usize = 0;
    for (fields) |field| bytes +|= 32 +| field.name.len +| field.value.len;
    return bytes;
}

fn freeHeaders(allocator: std.mem.Allocator, fields: []http2.Hpack.HeaderField) void {
    if (fields.len != 0 and fields[0].block_storage != null) {
        http2.Hpack.freeOwnedFields(allocator, fields);
        return;
    }
    for (fields) |field| {
        allocator.free(field.name);
        allocator.free(field.value);
    }
    allocator.free(fields);
}

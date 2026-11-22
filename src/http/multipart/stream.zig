//! Bounded streaming `multipart/form-data` parser.
//!
//! The parser reads from a caller-owned `std.Io.Reader` and delivers each part
//! through callbacks. It keeps only a bounded window for boundary detection;
//! part bodies are never buffered in full.

const std = @import("std");
const boundary_rules = @import("boundary.zig");
const content_type = @import("content_type.zig");
const parser = @import("parser.zig");

pub const Header = parser.Header;

pub const StreamOptions = struct {
    max_parts: usize = 64,
    max_headers_per_part: usize = 32,
    max_header_bytes: usize = 8 * 1024,
    max_part_bytes: usize = 16 * 1024 * 1024,
    max_total_bytes: usize = 64 * 1024 * 1024,
    max_name_bytes: usize = 255,
    max_filename_bytes: usize = 255,
    max_preamble_bytes: usize = 64 * 1024,
    allow_nested: bool = false,
    /// Rolling window used for boundary detection. Bodies are emitted in
    /// chunks no larger than this value.
    buffer_bytes: usize = 64 * 1024,
};

const hard_max_parts = 1024;
const hard_max_headers_per_part = 128;
const hard_max_buffer_bytes = 1024 * 1024;
const hard_max_header_bytes = 1024 * 1024;
const hard_max_preamble_bytes = 1024 * 1024;

pub const PartHead = struct {
    allocator: std.mem.Allocator,
    headers: []Header,
    header_storage: []u8,
    disposition_storage: []u8,
    name: []const u8,
    filename: ?[]const u8,
    content_type: ?[]const u8,

    pub fn deinit(self: *PartHead) void {
        self.allocator.free(self.headers);
        self.allocator.free(self.header_storage);
        self.allocator.free(self.disposition_storage);
        self.* = undefined;
    }
};

pub const Handler = struct {
    context: *anyopaque,
    begin: *const fn (context: *anyopaque, head: PartHead) anyerror!void,
    data: *const fn (context: *anyopaque, bytes: []const u8) anyerror!void,
    end: *const fn (context: *anyopaque) anyerror!void,
};

pub fn parseStream(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    content_type_value: []const u8,
    options: StreamOptions,
    handler: Handler,
) !void {
    var boundary_buffer: [boundary_rules.max_len]u8 = undefined;
    const boundary = content_type.boundaryInto(
        &boundary_buffer,
        content_type_value,
    ) catch |err| switch (err) {
        error.InvalidContentType => return error.InvalidContentType,
        error.MissingBoundary => return error.MissingBoundary,
        error.DuplicateBoundary => return error.DuplicateBoundary,
        error.InvalidBoundary => return error.InvalidBoundary,
        error.BufferTooSmall => return error.BufferTooSmall,
    };
    return parseStreamWithBoundary(
        allocator,
        reader,
        boundary,
        options,
        handler,
    );
}

pub fn parseStreamWithBoundary(
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    boundary: []const u8,
    options: StreamOptions,
    handler: Handler,
) !void {
    try validateOptions(boundary, options);
    var stream = StreamParser{
        .allocator = allocator,
        .reader = reader,
        .boundary = boundary,
        .options = options,
        .handler = handler,
    };
    defer stream.deinit();
    try stream.run();
}

fn validateOptions(boundary: []const u8, options: StreamOptions) !void {
    boundary_rules.validate(boundary) catch return error.InvalidBoundary;
    if (options.max_parts == 0 or options.max_parts > hard_max_parts) {
        return error.TooManyParts;
    }
    if (options.max_headers_per_part == 0 or
        options.max_headers_per_part > hard_max_headers_per_part)
    {
        return error.TooManyHeaders;
    }
    if (options.buffer_bytes == 0 or
        options.buffer_bytes > hard_max_buffer_bytes)
    {
        return error.BufferTooSmall;
    }
    if (options.max_header_bytes > hard_max_header_bytes or
        options.max_preamble_bytes > hard_max_preamble_bytes)
    {
        return error.BufferTooSmall;
    }
}

const State = enum {
    initial,
    headers,
    body,
    done,
};

const StreamParser = struct {
    allocator: std.mem.Allocator,
    reader: *std.Io.Reader,
    boundary: []const u8,
    options: StreamOptions,
    handler: Handler,
    buffer: std.ArrayList(u8) = .empty,
    state: State = .initial,
    total_read: usize = 0,
    part_count: usize = 0,
    part_body_bytes: usize = 0,
    current_head: ?PartHead = null,

    fn deinit(self: *StreamParser) void {
        if (self.current_head) |*head| head.deinit();
        self.buffer.deinit(self.allocator);
    }

    fn run(self: *StreamParser) !void {
        while (true) {
            switch (self.state) {
                .initial => try self.findInitialBoundary(),
                .headers => try self.parseHeaders(),
                .body => try self.streamBody(),
                .done => return,
            }
        }
    }

    fn findInitialBoundary(self: *StreamParser) !void {
        var delimiter_buffer: [2 + boundary_rules.max_len]u8 = undefined;
        delimiter_buffer[0] = '-';
        delimiter_buffer[1] = '-';
        @memcpy(delimiter_buffer[2..][0..self.boundary.len], self.boundary);
        const delimiter = delimiter_buffer[0 .. 2 + self.boundary.len];

        while (true) {
            if (std.mem.indexOfPos(
                u8,
                self.buffer.items,
                0,
                delimiter,
            )) |position| {
                const valid_prefix = position == 0 or
                    (position >= 2 and std.mem.eql(
                        u8,
                        self.buffer.items[position - 2 .. position],
                        "\r\n",
                    ));
                if (valid_prefix) {
                    if (position > self.options.max_preamble_bytes) {
                        return error.MissingInitialBoundary;
                    }
                    self.consume(position);
                    const suffix = delimiter.len;
                    if (self.buffer.items.len < suffix + 2) {
                        if (!try self.readMore()) {
                            return error.TruncatedBody;
                        }
                        continue;
                    }
                    if (std.mem.eql(
                        u8,
                        self.buffer.items[suffix..][0..2],
                        "\r\n",
                    )) {
                        self.consume(suffix + 2);
                        self.state = .headers;
                        return;
                    }
                    if (std.mem.eql(
                        u8,
                        self.buffer.items[suffix..][0..2],
                        "--",
                    )) {
                        self.consume(suffix + 2);
                        self.state = .done;
                        return;
                    }
                    return error.MissingInitialBoundary;
                }
            }
            if (self.buffer.items.len >
                self.options.max_preamble_bytes + delimiter.len)
            {
                return error.MissingInitialBoundary;
            }
            if (!try self.readMore()) return error.MissingInitialBoundary;
        }
    }

    fn parseHeaders(self: *StreamParser) !void {
        if (self.part_count == self.options.max_parts) {
            return error.TooManyParts;
        }
        const header_end = while (true) {
            if (std.mem.indexOfPos(
                u8,
                self.buffer.items,
                0,
                "\r\n\r\n",
            )) |position| break position;
            if (self.buffer.items.len >
                self.options.max_header_bytes + 4)
            {
                return error.HeaderTooLarge;
            }
            if (!try self.readMore()) return error.TruncatedBody;
        };
        if (header_end > self.options.max_header_bytes) {
            return error.HeaderTooLarge;
        }

        var head = try self.buildHead(self.buffer.items[0..header_end]);
        errdefer head.deinit();
        try self.handler.begin(self.handler.context, head);
        self.current_head = head;
        self.consume(header_end + 4);
        self.part_body_bytes = 0;
        self.part_count += 1;
        self.state = .body;
    }

    fn buildHead(self: *StreamParser, block: []const u8) !PartHead {
        const header_storage = try self.allocator.dupe(u8, block);
        errdefer self.allocator.free(header_storage);
        var headers: std.ArrayList(Header) = .empty;
        errdefer headers.deinit(self.allocator);
        const parsed = try parser.parseHeaderLines(
            self.allocator,
            &headers,
            header_storage,
            self.options.max_headers_per_part,
        );
        const disposition_value = parsed.disposition orelse
            return error.MissingContentDisposition;
        var disposition_storage: std.ArrayList(u8) = .empty;
        errdefer disposition_storage.deinit(self.allocator);
        const names = try parser.parseDispositionInto(
            self.allocator,
            &disposition_storage,
            disposition_value,
            self.options.max_name_bytes,
            self.options.max_filename_bytes,
        );
        if (parsed.content_type) |value| {
            if (!self.options.allow_nested and
                std.ascii.startsWithIgnoreCase(value, "multipart/"))
            {
                return error.UnsupportedNestedMultipart;
            }
        }
        const owned_headers = try headers.toOwnedSlice(self.allocator);
        const owned_disposition = try disposition_storage.toOwnedSlice(
            self.allocator,
        );
        return .{
            .allocator = self.allocator,
            .headers = owned_headers,
            .header_storage = header_storage,
            .disposition_storage = owned_disposition,
            .name = owned_disposition[names.name_start..][0..names.name_len],
            .filename = if (names.has_filename)
                owned_disposition[names.filename_start..][0..names.filename_len]
            else
                null,
            .content_type = parsed.content_type,
        };
    }

    fn streamBody(self: *StreamParser) !void {
        var delimiter_buffer: [4 + boundary_rules.max_len]u8 = undefined;
        delimiter_buffer[0] = '\r';
        delimiter_buffer[1] = '\n';
        delimiter_buffer[2] = '-';
        delimiter_buffer[3] = '-';
        @memcpy(
            delimiter_buffer[4..][0..self.boundary.len],
            self.boundary,
        );
        const delimiter = delimiter_buffer[0 .. 4 + self.boundary.len];

        while (true) {
            if (std.mem.indexOfPos(
                u8,
                self.buffer.items,
                0,
                delimiter,
            )) |position| {
                const suffix = position + delimiter.len;
                if (self.buffer.items.len < suffix + 2) {
                    if (!try self.readMore()) return error.TruncatedBody;
                    continue;
                }
                const marker = self.buffer.items[suffix..][0..2];
                const final = std.mem.eql(u8, marker, "--");
                if (final or std.mem.eql(u8, marker, "\r\n")) {
                    try self.emit(self.buffer.items[0..position]);
                    self.consume(position);
                    self.consume(delimiter.len + 2);
                    try self.endPart();
                    if (final) {
                        self.state = .done;
                    } else {
                        self.state = .headers;
                    }
                    return;
                }
                // A boundary-like byte sequence in the body. Preserve the
                // first byte and keep searching.
                try self.emit(self.buffer.items[0..1]);
                self.consume(1);
                continue;
            }

            const keep = delimiter.len - 1;
            if (self.buffer.items.len > keep) {
                const emit_len = self.buffer.items.len - keep;
                try self.emit(self.buffer.items[0..emit_len]);
                self.consume(emit_len);
            }
            if (!try self.readMore()) return error.TruncatedBody;
        }
    }

    fn emit(self: *StreamParser, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        if (self.part_body_bytes + bytes.len > self.options.max_part_bytes) {
            return error.PartTooLarge;
        }
        self.part_body_bytes += bytes.len;
        try self.handler.data(self.handler.context, bytes);
    }

    fn endPart(self: *StreamParser) !void {
        try self.handler.end(self.handler.context);
        if (self.current_head) |*head| {
            head.deinit();
            self.current_head = null;
        }
    }

    fn bufferLimit(self: *const StreamParser) usize {
        return switch (self.state) {
            .initial => @max(
                self.options.buffer_bytes,
                self.options.max_preamble_bytes + 2 + self.boundary.len,
            ),
            .headers => @max(
                self.options.buffer_bytes,
                self.options.max_header_bytes + 4,
            ),
            .body, .done => self.options.buffer_bytes,
        };
    }

    fn readMore(self: *StreamParser) !bool {
        const limit_buffer = self.bufferLimit();
        if (self.buffer.items.len >= limit_buffer) return false;
        const available = limit_buffer - self.buffer.items.len;
        var chunk: [16 * 1024]u8 = undefined;
        const limit = @min(available, chunk.len);
        const read = try self.reader.readSliceShort(chunk[0..limit]);
        if (read == 0) return false;
        if (self.total_read + read > self.options.max_total_bytes) {
            return error.BodyTooLarge;
        }
        self.total_read += read;
        try self.buffer.appendSlice(self.allocator, chunk[0..read]);
        return true;
    }

    fn consume(self: *StreamParser, count: usize) void {
        if (count == 0) return;
        const remaining = self.buffer.items.len - count;
        std.mem.copyForwards(
            u8,
            self.buffer.items[0..remaining],
            self.buffer.items[count..],
        );
        self.buffer.shrinkRetainingCapacity(remaining);
    }
};

const Collector = struct {
    allocator: std.mem.Allocator,
    parts: std.ArrayList(CollectedPart) = .empty,
    current: ?CollectedPart = null,

    const CollectedPart = struct {
        name: []u8,
        filename: ?[]u8,
        content_type: ?[]u8,
        body: std.ArrayList(u8),
    };

    fn begin(context: *anyopaque, head: PartHead) anyerror!void {
        const self: *Collector = @ptrCast(@alignCast(context));
        var part = CollectedPart{
            .name = try self.allocator.dupe(u8, head.name),
            .filename = null,
            .content_type = null,
            .body = .empty,
        };
        errdefer {
            self.allocator.free(part.name);
            if (part.filename) |value| self.allocator.free(value);
            if (part.content_type) |value| self.allocator.free(value);
            part.body.deinit(self.allocator);
        }
        if (head.filename) |filename| {
            part.filename = try self.allocator.dupe(u8, filename);
        }
        if (head.content_type) |value| {
            part.content_type = try self.allocator.dupe(u8, value);
        }
        self.current = part;
    }

    fn data(context: *anyopaque, bytes: []const u8) anyerror!void {
        const self: *Collector = @ptrCast(@alignCast(context));
        try self.current.?.body.appendSlice(self.allocator, bytes);
    }

    fn end(context: *anyopaque) anyerror!void {
        const self: *Collector = @ptrCast(@alignCast(context));
        try self.parts.append(self.allocator, self.current.?);
        self.current = null;
    }

    fn deinit(self: *Collector) void {
        if (self.current) |*part| {
            self.allocator.free(part.name);
            if (part.filename) |value| self.allocator.free(value);
            if (part.content_type) |value| self.allocator.free(value);
            part.body.deinit(self.allocator);
        }
        for (self.parts.items) |*part| {
            self.allocator.free(part.name);
            if (part.filename) |value| self.allocator.free(value);
            if (part.content_type) |value| self.allocator.free(value);
            part.body.deinit(self.allocator);
        }
        self.parts.deinit(self.allocator);
    }
};

test "stream parser handles boundaries split across reads" {
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"field\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"upload\"; " ++
        "filename=\"a.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "hello\r\n" ++
        "--b--\r\n";
    var reader = std.Io.Reader.fixed(body);
    var collector = Collector{ .allocator = std.testing.allocator };
    defer collector.deinit();

    try parseStreamWithBoundary(
        std.testing.allocator,
        &reader,
        "b",
        .{ .buffer_bytes = 8 },
        .{
            .context = &collector,
            .begin = Collector.begin,
            .data = Collector.data,
            .end = Collector.end,
        },
    );

    try std.testing.expectEqual(@as(usize, 2), collector.parts.items.len);
    try std.testing.expectEqualStrings(
        "field",
        collector.parts.items[0].name,
    );
    try std.testing.expectEqualStrings(
        "value",
        collector.parts.items[0].body.items,
    );
    try std.testing.expectEqualStrings(
        "upload",
        collector.parts.items[1].name,
    );
    try std.testing.expectEqualStrings(
        "a.txt",
        collector.parts.items[1].filename.?,
    );
    try std.testing.expectEqualStrings(
        "text/plain",
        collector.parts.items[1].content_type.?,
    );
    try std.testing.expectEqualStrings(
        "hello",
        collector.parts.items[1].body.items,
    );
}

test "stream parser emits large bodies without buffering them whole" {
    const allocator = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);
    try body.appendSlice(
        allocator,
        "--b\r\nContent-Disposition: form-data; name=\"data\"\r\n\r\n",
    );
    for (0..4096) |index| {
        try body.append(allocator, @intCast('a' + index % 26));
    }
    try body.appendSlice(allocator, "\r\n--b--\r\n");

    var reader = std.Io.Reader.fixed(body.items);
    var collector = Collector{ .allocator = allocator };
    defer collector.deinit();
    try parseStreamWithBoundary(
        allocator,
        &reader,
        "b",
        .{ .buffer_bytes = 16 },
        .{
            .context = &collector,
            .begin = Collector.begin,
            .data = Collector.data,
            .end = Collector.end,
        },
    );

    try std.testing.expectEqual(@as(usize, 1), collector.parts.items.len);
    try std.testing.expectEqual(
        @as(usize, 4096),
        collector.parts.items[0].body.items.len,
    );
    for (collector.parts.items[0].body.items, 0..) |byte, index| {
        try std.testing.expectEqual(
            @as(u8, @intCast('a' + index % 26)),
            byte,
        );
    }
}

test "stream parser preserves boundary-like body bytes and rejects truncation" {
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"data\"\r\n" ++
        "\r\n" ++
        "a\r\n--bXb\r\n" ++
        "--b--\r\n";
    var reader = std.Io.Reader.fixed(body);
    var collector = Collector{ .allocator = std.testing.allocator };
    defer collector.deinit();
    try parseStreamWithBoundary(
        std.testing.allocator,
        &reader,
        "b",
        .{ .buffer_bytes = 7 },
        .{
            .context = &collector,
            .begin = Collector.begin,
            .data = Collector.data,
            .end = Collector.end,
        },
    );
    try std.testing.expectEqualStrings(
        "a\r\n--bXb",
        collector.parts.items[0].body.items,
    );

    const truncated =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"data\"\r\n" ++
        "\r\n" ++
        "value";
    var truncated_reader = std.Io.Reader.fixed(truncated);
    var truncated_collector = Collector{
        .allocator = std.testing.allocator,
    };
    defer truncated_collector.deinit();
    try std.testing.expectError(
        error.TruncatedBody,
        parseStreamWithBoundary(
            std.testing.allocator,
            &truncated_reader,
            "b",
            .{ .buffer_bytes = 8 },
            .{
                .context = &truncated_collector,
                .begin = Collector.begin,
                .data = Collector.data,
                .end = Collector.end,
            },
        ),
    );
}

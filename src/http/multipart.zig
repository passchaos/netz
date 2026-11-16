//! Bounded, streaming `multipart/form-data` encoding (RFC 7578).
//!
//! The writer never buffers a part body. A part can be a slice or a
//! caller-owned `std.Io.Reader`; large files therefore stay in caller storage
//! and flow directly to the HTTP body writer.

const std = @import("std");

pub const max_boundary_len = 70;
pub const max_part_header_bytes = 8 * 1024;

pub const Error = std.Io.Writer.Error ||
    std.Io.Reader.StreamRemainingError ||
    error{
        BufferTooSmall,
        InvalidBoundary,
        InvalidPartName,
        InvalidFilename,
        InvalidHeaderName,
        InvalidHeaderValue,
        InvalidState,
        UnfinishedPart,
        AlreadyFinished,
        Overflow,
        PartHeaderTooLarge,
        EndOfStream,
    };

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Body = union(enum) {
    slice: []const u8,
    reader: *std.Io.Reader,
};

pub const PartOptions = struct {
    filename: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    headers: []const Header = &.{},
};

pub const Part = struct {
    name: []const u8,
    filename: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    headers: []const Header = &.{},
    body: Body,
};

pub fn validateBoundary(boundary: []const u8) Error!void {
    if (boundary.len == 0 or boundary.len > max_boundary_len) {
        return error.InvalidBoundary;
    }
    for (boundary) |byte| {
        if (byte < 0x21 or byte > 0x7e or byte == '"' or byte == '\\') {
            return error.InvalidBoundary;
        }
    }
}

fn isTokenChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
}

fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.InvalidHeaderName;
    for (name) |byte| {
        if (!isTokenChar(byte)) return error.InvalidHeaderName;
    }
}

fn validateHeaderValue(value: []const u8) Error!void {
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) {
            return error.InvalidHeaderValue;
        }
    }
}

fn validateDispositionValue(
    value: []const u8,
    comptime error_value: Error,
) Error!void {
    for (value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0) {
            return error_value;
        }
    }
}

fn quotedLen(value: []const u8) usize {
    var total: usize = 0;
    for (value) |byte| {
        total += if (byte == '"' or byte == '\\') 2 else 1;
    }
    return total;
}

fn writeQuoted(writer: *std.Io.Writer, value: []const u8) Error!void {
    for (value) |byte| {
        if (byte == '"' or byte == '\\') {
            try writer.writeByte('\\');
        }
        try writer.writeByte(byte);
    }
}

fn validatePart(
    name: []const u8,
    options: PartOptions,
) Error!void {
    try validateDispositionValue(name, error.InvalidPartName);
    if (options.filename) |filename| {
        try validateDispositionValue(filename, error.InvalidFilename);
    }
    if (options.content_type) |content_type| {
        try validateHeaderValue(content_type);
    }
    for (options.headers) |header| {
        try validateHeaderName(header.name);
        try validateHeaderValue(header.value);
    }
}

fn writePartPrefix(
    writer: *std.Io.Writer,
    boundary: []const u8,
    name: []const u8,
    options: PartOptions,
) Error!void {
    try validatePart(name, options);

    try writer.writeAll("--");
    try writer.writeAll(boundary);
    try writer.writeAll("\r\n");
    try writer.writeAll("Content-Disposition: form-data; name=\"");
    try writeQuoted(writer, name);
    if (options.filename) |filename| {
        try writer.writeAll("\"; filename=\"");
        try writeQuoted(writer, filename);
    }
    try writer.writeAll("\"\r\n");
    if (options.content_type) |content_type| {
        try writer.writeAll("Content-Type: ");
        try writer.writeAll(content_type);
        try writer.writeAll("\r\n");
    }
    for (options.headers) |header| {
        try writer.writeAll(header.name);
        try writer.writeAll(": ");
        try writer.writeAll(header.value);
        try writer.writeAll("\r\n");
    }
    try writer.writeAll("\r\n");
}

fn partPrefixLen(
    boundary: []const u8,
    name: []const u8,
    options: PartOptions,
) Error!usize {
    var total: usize = 0;
    total = try std.math.add(usize, total, 2 + boundary.len + 2);
    total = try std.math.add(usize, total, "Content-Disposition: form-data; name=\"".len);
    total = try std.math.add(usize, total, quotedLen(name));
    if (options.filename) |filename| {
        total = try std.math.add(usize, total, "\"; filename=\"".len);
        total = try std.math.add(usize, total, quotedLen(filename));
    }
    total = try std.math.add(usize, total, "\"\r\n".len);
    if (options.content_type) |content_type| {
        total = try std.math.add(usize, total, "Content-Type: ".len);
        total = try std.math.add(usize, total, content_type.len);
        total = try std.math.add(usize, total, 2);
    }
    for (options.headers) |header| {
        total = try std.math.add(usize, total, header.name.len);
        total = try std.math.add(usize, total, 2);
        total = try std.math.add(usize, total, header.value.len);
        total = try std.math.add(usize, total, 2);
    }
    total = try std.math.add(usize, total, 2);
    return total;
}

/// Exact body length, or null when any part is reader-backed.
pub fn contentLength(
    boundary: []const u8,
    parts: []const Part,
) Error!?usize {
    try validateBoundary(boundary);
    var total: usize = 0;
    for (parts) |part| {
        const options: PartOptions = .{
            .filename = part.filename,
            .content_type = part.content_type,
            .headers = part.headers,
        };
        try validatePart(part.name, options);
        total = try std.math.add(
            usize,
            total,
            try partPrefixLen(boundary, part.name, options),
        );
        switch (part.body) {
            .slice => |body| {
                total = try std.math.add(usize, total, body.len);
            },
            .reader => return null,
        }
        total = try std.math.add(usize, total, 2);
    }
    total = try std.math.add(usize, total, 2 + boundary.len + 4);
    return total;
}

/// Write every part and the final boundary.
pub fn write(
    writer: *std.Io.Writer,
    boundary: []const u8,
    parts: []const Part,
) Error!void {
    var multipart_writer = try Writer.init(writer, boundary);
    for (parts) |part| {
        try multipart_writer.beginPart(part.name, .{
            .filename = part.filename,
            .content_type = part.content_type,
            .headers = part.headers,
        });
        switch (part.body) {
            .slice => |body| try multipart_writer.writeBody(body),
            .reader => |reader| try multipart_writer.writeBodyFromReader(reader),
        }
        try multipart_writer.endPart();
    }
    try multipart_writer.finish();
}

/// Stateful streaming writer for callers that cannot enumerate all parts up
/// front.
pub const Writer = struct {
    writer: *std.Io.Writer,
    boundary: []const u8,
    state: State = .idle,

    const State = enum {
        idle,
        part,
        finished,
    };

    pub fn init(writer: *std.Io.Writer, boundary: []const u8) Error!Writer {
        try validateBoundary(boundary);
        return .{ .writer = writer, .boundary = boundary };
    }

    pub fn beginPart(
        self: *Writer,
        name: []const u8,
        options: PartOptions,
    ) Error!void {
        if (self.state != .idle) return error.InvalidState;
        try writePartPrefix(self.writer, self.boundary, name, options);
        self.state = .part;
    }

    pub fn writeBody(self: *Writer, bytes: []const u8) Error!void {
        if (self.state != .part) return error.InvalidState;
        try self.writer.writeAll(bytes);
    }

    pub fn writeBodyFromReader(
        self: *Writer,
        reader: *std.Io.Reader,
    ) Error!void {
        if (self.state != .part) return error.InvalidState;
        _ = try reader.streamRemaining(self.writer);
    }

    pub fn endPart(self: *Writer) Error!void {
        if (self.state != .part) return error.InvalidState;
        try self.writer.writeAll("\r\n");
        self.state = .idle;
    }

    pub fn finish(self: *Writer) Error!void {
        switch (self.state) {
            .part => return error.UnfinishedPart,
            .finished => return error.AlreadyFinished,
            .idle => {},
        }
        try self.writer.writeAll("--");
        try self.writer.writeAll(self.boundary);
        try self.writer.writeAll("--\r\n");
        self.state = .finished;
    }
};

/// Pull-based multipart body reader. It yields exactly the same bytes as
/// `write` and can be passed directly as `netz.http.BodySource.reader`.
pub const Reader = struct {
    reader: std.Io.Reader,
    boundary: []const u8,
    parts: []const Part,
    part_index: usize = 0,
    phase: Phase = .prefix,
    prefix_buf: [max_part_header_bytes]u8 = undefined,
    prefix_len: usize = 0,
    prefix_pos: usize = 0,
    body_reader: ?*std.Io.Reader = null,
    slice_body: []const u8 = &.{},
    slice_offset: usize = 0,
    body_kind: BodyKind = .none,
    err: ?anyerror = null,

    const BodyKind = enum {
        none,
        slice,
        reader,
    };

    const Phase = enum {
        prefix,
        body,
        suffix,
        final,
        done,
    };

    const vtable: std.Io.Reader.VTable = .{ .stream = stream };

    pub fn init(parts: []const Part, boundary: []const u8) Error!Reader {
        try validateBoundary(boundary);
        for (parts) |part| {
            try validatePart(part.name, .{
                .filename = part.filename,
                .content_type = part.content_type,
                .headers = part.headers,
            });
            const prefix_len = try partPrefixLen(boundary, part.name, .{
                .filename = part.filename,
                .content_type = part.content_type,
                .headers = part.headers,
            });
            if (prefix_len > max_part_header_bytes) {
                return error.PartHeaderTooLarge;
            }
        }
        return .{
            .reader = .{
                .vtable = &vtable,
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
            .boundary = boundary,
            .parts = parts,
        };
    }

    pub fn takeError(self: *Reader) ?anyerror {
        return self.err;
    }

    fn stream(
        r: *std.Io.Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) std.Io.Reader.StreamError!usize {
        const self: *Reader = @alignCast(@fieldParentPtr("reader", r));
        return self.fill(w, limit) catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            else => {
                self.err = err;
                return error.ReadFailed;
            },
        };
    }

    fn fill(
        self: *Reader,
        w: *std.Io.Writer,
        limit: std.Io.Limit,
    ) Error!usize {
        var remaining = @intFromEnum(limit);
        var written: usize = 0;
        while (true) {
            if (remaining == 0) return written;
            switch (self.phase) {
                .done => return if (written == 0) error.EndOfStream else written,
                .prefix => {
                    if (self.prefix_len == 0) {
                        if (self.part_index == self.parts.len) {
                            try self.setFinalPrefix();
                            self.phase = .final;
                            continue;
                        }
                        try self.setPartPrefix();
                    }
                    const count = @min(
                        remaining,
                        self.prefix_len - self.prefix_pos,
                    );
                    try w.writeAll(
                        self.prefix_buf[self.prefix_pos..][0..count],
                    );
                    self.prefix_pos += count;
                    written += count;
                    remaining -= count;
                    if (self.prefix_pos < self.prefix_len) return written;
                    self.prefix_len = 0;
                    self.prefix_pos = 0;
                    self.startBody() catch |err| return err;
                    self.phase = .body;
                },
                .body => {
                    switch (self.body_kind) {
                        .none => return error.InvalidState,
                        .slice => {
                            const remaining_slice =
                                self.slice_body[self.slice_offset..];
                            if (remaining_slice.len == 0) {
                                try self.setPrefixLiteral("\r\n");
                                self.phase = .suffix;
                                continue;
                            }
                            const count = @min(
                                remaining,
                                remaining_slice.len,
                            );
                            try w.writeAll(remaining_slice[0..count]);
                            self.slice_offset += count;
                            written += count;
                            remaining -= count;
                        },
                        .reader => {
                            const body_reader = self.body_reader orelse
                                return error.InvalidState;
                            const count = body_reader.stream(
                                w,
                                .limited(remaining),
                            ) catch |err| switch (err) {
                                error.EndOfStream => {
                                    try self.setPrefixLiteral("\r\n");
                                    self.phase = .suffix;
                                    continue;
                                },
                                else => return err,
                            };
                            if (count == 0) return written;
                            written += count;
                            remaining -= count;
                        },
                    }
                },
                .suffix => {
                    const count = @min(
                        remaining,
                        self.prefix_len - self.prefix_pos,
                    );
                    try w.writeAll(
                        self.prefix_buf[self.prefix_pos..][0..count],
                    );
                    self.prefix_pos += count;
                    written += count;
                    remaining -= count;
                    if (self.prefix_pos < self.prefix_len) return written;
                    self.prefix_len = 0;
                    self.prefix_pos = 0;
                    self.part_index += 1;
                    self.phase = .prefix;
                },
                .final => {
                    const count = @min(
                        remaining,
                        self.prefix_len - self.prefix_pos,
                    );
                    try w.writeAll(
                        self.prefix_buf[self.prefix_pos..][0..count],
                    );
                    self.prefix_pos += count;
                    written += count;
                    remaining -= count;
                    if (self.prefix_pos < self.prefix_len) return written;
                    self.phase = .done;
                },
            }
        }
    }

    fn setPartPrefix(self: *Reader) Error!void {
        const part = self.parts[self.part_index];
        var writer = std.Io.Writer.fixed(&self.prefix_buf);
        try writePartPrefix(
            &writer,
            self.boundary,
            part.name,
            .{
                .filename = part.filename,
                .content_type = part.content_type,
                .headers = part.headers,
            },
        );
        self.prefix_len = writer.end;
        self.prefix_pos = 0;
    }

    fn setFinalPrefix(self: *Reader) Error!void {
        var writer = std.Io.Writer.fixed(&self.prefix_buf);
        try writer.writeAll("--");
        try writer.writeAll(self.boundary);
        try writer.writeAll("--\r\n");
        self.prefix_len = writer.end;
        self.prefix_pos = 0;
    }

    fn setPrefixLiteral(self: *Reader, literal: []const u8) Error!void {
        if (literal.len > self.prefix_buf.len) return error.PartHeaderTooLarge;
        @memcpy(self.prefix_buf[0..literal.len], literal);
        self.prefix_len = literal.len;
        self.prefix_pos = 0;
    }

    fn startBody(self: *Reader) Error!void {
        const part = self.parts[self.part_index];
        switch (part.body) {
            .slice => |slice| {
                self.slice_body = slice;
                self.slice_offset = 0;
                self.body_kind = .slice;
            },
            .reader => |reader| {
                self.body_reader = reader;
                self.body_kind = .reader;
            },
        }
    }
};

/// Render a `Content-Type` header value with a quoted boundary.
pub fn contentType(out: []u8, boundary: []const u8) Error![]const u8 {
    try validateBoundary(boundary);
    const prefix = "multipart/form-data; boundary=\"";
    const suffix = "\"";
    const required = prefix.len + boundary.len + suffix.len;
    if (out.len < required) return error.BufferTooSmall;
    @memcpy(out[0..prefix.len], prefix);
    @memcpy(out[prefix.len .. prefix.len + boundary.len], boundary);
    @memcpy(out[prefix.len + boundary.len .. required], suffix);
    return out[0..required];
}

/// Generate a deterministic boundary from caller-provided entropy.
pub fn formatBoundary(
    out: []u8,
    entropy: [16]u8,
) Error![]const u8 {
    const hex = std.fmt.bytesToHex(entropy, .lower);
    const boundary = std.fmt.bufPrint(
        out,
        "----netz-{s}",
        .{&hex},
    ) catch return error.BufferTooSmall;
    try validateBoundary(boundary);
    return boundary;
}

test "multipart writer emits fields and a file part" {
    var storage: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const boundary = "----netz-test";

    const parts = [_]Part{
        .{
            .name = "name",
            .body = .{ .slice = "value" },
        },
        .{
            .name = "upload",
            .filename = "a.txt",
            .content_type = "text/plain",
            .body = .{ .slice = "hello" },
        },
    };

    try write(&writer, boundary, &parts);
    const expected =
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"name\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "hello\r\n" ++
        "--" ++ boundary ++ "--\r\n";
    try std.testing.expectEqualStrings(expected, writer.buffered());
    try std.testing.expectEqual(
        expected.len,
        (try contentLength(boundary, &parts)).?,
    );
}

test "multipart writer streams a reader body" {
    var storage: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    var reader = std.Io.Reader.fixed("streamed");
    const boundary = "----netz-reader";

    const parts = [_]Part{.{
        .name = "file",
        .filename = "a.bin",
        .body = .{ .reader = &reader },
    }};

    try write(&writer, boundary, &parts);
    try std.testing.expect(std.mem.endsWith(u8, writer.buffered(), "streamed\r\n--" ++ boundary ++ "--\r\n"));
    try std.testing.expectEqual(
        @as(?usize, null),
        try contentLength(boundary, &parts),
    );
}

test "multipart writer quotes names and rejects injection" {
    var storage: [256]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const boundary = "----netz-quote";

    try write(&writer, boundary, &.{.{
        .name = "a\"b\\c",
        .body = .{ .slice = "" },
    }});
    try std.testing.expect(std.mem.indexOf(
        u8,
        writer.buffered(),
        "name=\"a\\\"b\\\\c\"",
    ) != null);

    try std.testing.expectError(
        error.InvalidPartName,
        write(&writer, boundary, &.{.{
            .name = "bad\r\nname",
            .body = .{ .slice = "" },
        }}),
    );
    try std.testing.expectError(
        error.InvalidBoundary,
        validateBoundary("bad\r\nboundary"),
    );
}

test "multipart reader yields the same bytes as the writer" {
    var storage: [1024]u8 = undefined;
    var writer = std.Io.Writer.fixed(&storage);
    const boundary = "----netz-reader-compare";
    const parts = [_]Part{
        .{ .name = "name", .body = .{ .slice = "value" } },
        .{
            .name = "upload",
            .filename = "a.txt",
            .content_type = "text/plain",
            .body = .{ .slice = "hello" },
        },
    };

    try write(&writer, boundary, &parts);
    var reader = try Reader.init(&parts, boundary);
    const bytes = try reader.reader.allocRemaining(
        std.testing.allocator,
        .limited(1024),
    );
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings(writer.buffered(), bytes);
    try std.testing.expect(reader.takeError() == null);
}

test "multipart reader streams a reader body" {
    var body_reader = std.Io.Reader.fixed("streamed");
    const boundary = "----netz-reader-stream";
    const parts = [_]Part{.{
        .name = "file",
        .filename = "a.bin",
        .body = .{ .reader = &body_reader },
    }};

    var reader = try Reader.init(&parts, boundary);
    const bytes = try reader.reader.allocRemaining(
        std.testing.allocator,
        .limited(1024),
    );
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(std.mem.endsWith(
        u8,
        bytes,
        "streamed\r\n--" ++ boundary ++ "--\r\n",
    ));
}

test "multipart content type and boundary helpers are bounded" {
    var storage: [128]u8 = undefined;
    const boundary = try formatBoundary(&storage, [_]u8{0xab} ** 16);
    try std.testing.expectEqualStrings(
        "----netz-abababababababababababababababab",
        boundary,
    );

    var header: [96]u8 = undefined;
    try std.testing.expectEqualStrings(
        "multipart/form-data; boundary=\"----netz-abababababababababababababababab\"",
        try contentType(&header, boundary),
    );

    var tiny: [4]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        contentType(&tiny, boundary),
    );
}

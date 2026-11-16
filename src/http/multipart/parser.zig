//! Bounded `multipart/form-data` parsing (RFC 7578).
//!
//! The parser borrows part bodies from the input slice and owns only the
//! `Part`/`Header` arrays plus unescaped disposition values. It never writes
//! to the filesystem and enforces explicit part/header/body limits.

const std = @import("std");
const boundary_rules = @import("boundary.zig");
const content_type = @import("content_type.zig");

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const Part = struct {
    headers: []const Header,
    name: []const u8,
    filename: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    body: []const u8,
};

pub const ParseOptions = struct {
    max_parts: usize = 64,
    max_headers_per_part: usize = 32,
    max_header_bytes: usize = 8 * 1024,
    max_part_bytes: usize = 16 * 1024 * 1024,
    max_total_bytes: usize = 64 * 1024 * 1024,
    max_name_bytes: usize = 255,
    max_filename_bytes: usize = 255,
    max_preamble_bytes: usize = 64 * 1024,
    max_epilogue_bytes: usize = 64 * 1024,
    allow_nested: bool = false,
};

const hard_max_parts = 1024;
const hard_max_headers_per_part = 128;
const hard_max_disposition_bytes = 64 * 1024;

pub const Error = std.mem.Allocator.Error || error{
    InvalidContentType,
    MissingBoundary,
    DuplicateBoundary,
    InvalidBoundary,
    BufferTooSmall,
    MissingInitialBoundary,
    TruncatedBody,
    MalformedHeader,
    HeaderTooLarge,
    TooManyHeaders,
    TooManyParts,
    PartTooLarge,
    BodyTooLarge,
    MissingContentDisposition,
    InvalidContentDisposition,
    MissingName,
    DuplicateName,
    DuplicateFilename,
    NameTooLong,
    FilenameTooLong,
    UnsupportedNestedMultipart,
    UnsupportedParameter,
    InvalidHeaderName,
};

pub const Parsed = struct {
    allocator: std.mem.Allocator,
    parts: []Part,
    headers: []Header,
    parts_allocation: []Part,
    headers_allocation: []Header,
    disposition_allocation: []u8,

    pub fn deinit(self: *Parsed) void {
        self.allocator.free(self.parts_allocation);
        self.allocator.free(self.headers_allocation);
        self.allocator.free(self.disposition_allocation);
        self.* = undefined;
    }
};

/// Parse a `multipart/form-data` body using its Content-Type header value.
pub fn parseAlloc(
    allocator: std.mem.Allocator,
    body: []const u8,
    content_type_value: []const u8,
    options: ParseOptions,
) Error!Parsed {
    if (body.len > options.max_total_bytes) return error.BodyTooLarge;
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
    return parseWithBoundary(allocator, body, boundary, options);
}

/// Parse a body when the boundary is already known.
pub fn parseWithBoundary(
    allocator: std.mem.Allocator,
    body: []const u8,
    boundary: []const u8,
    options: ParseOptions,
) Error!Parsed {
    if (body.len > options.max_total_bytes) return error.BodyTooLarge;
    boundary_rules.validate(boundary) catch return error.InvalidBoundary;
    if (options.max_parts == 0 or options.max_parts > hard_max_parts) {
        return error.TooManyParts;
    }
    if (options.max_headers_per_part == 0 or
        options.max_headers_per_part > hard_max_headers_per_part)
    {
        return error.TooManyHeaders;
    }
    if (options.max_name_bytes > hard_max_disposition_bytes or
        options.max_filename_bytes > hard_max_disposition_bytes)
    {
        return error.NameTooLong;
    }

    const parts_allocation = try allocator.alloc(Part, options.max_parts);
    errdefer allocator.free(parts_allocation);
    const header_capacity = std.math.mul(
        usize,
        options.max_parts,
        options.max_headers_per_part,
    ) catch return error.TooManyHeaders;
    const headers_allocation = try allocator.alloc(Header, header_capacity);
    errdefer allocator.free(headers_allocation);
    const disposition_capacity = std.math.mul(
        usize,
        options.max_parts,
        options.max_name_bytes + options.max_filename_bytes + 2,
    ) catch return error.NameTooLong;
    const disposition_allocation = try allocator.alloc(
        u8,
        disposition_capacity,
    );
    errdefer allocator.free(disposition_allocation);

    var parser = Parser{
        .body = body,
        .boundary = boundary,
        .options = options,
        .parts = parts_allocation,
        .headers = headers_allocation,
        .disposition = disposition_allocation,
    };
    try parser.run();

    return .{
        .allocator = allocator,
        .parts = parts_allocation[0..parser.part_count],
        .headers = headers_allocation[0..parser.header_count],
        .parts_allocation = parts_allocation,
        .headers_allocation = headers_allocation,
        .disposition_allocation = disposition_allocation,
    };
}

const Parser = struct {
    body: []const u8,
    boundary: []const u8,
    options: ParseOptions,
    pos: usize = 0,
    parts: []Part,
    part_count: usize = 0,
    headers: []Header,
    header_count: usize = 0,
    disposition: []u8,
    disposition_count: usize = 0,

    fn run(self: *Parser) Error!void {
        try self.findInitialBoundary();
        while (!self.finished()) {
            try self.parsePart();
        }
    }

    fn finished(self: *const Parser) bool {
        return self.pos == std.math.maxInt(usize);
    }

    fn markFinished(self: *Parser) void {
        self.pos = std.math.maxInt(usize);
    }

    fn initialDelimiter(self: *const Parser, out: []u8) []const u8 {
        out[0] = '-';
        out[1] = '-';
        @memcpy(out[2..][0..self.boundary.len], self.boundary);
        return out[0 .. 2 + self.boundary.len];
    }

    fn findInitialBoundary(self: *Parser) Error!void {
        var delimiter_buffer: [2 + boundary_rules.max_len]u8 = undefined;
        const delimiter_slice = self.initialDelimiter(&delimiter_buffer);
        var search_from: usize = 0;
        while (std.mem.indexOfPos(
            u8,
            self.body,
            search_from,
            delimiter_slice,
        )) |position| {
            const valid_prefix = position == 0 or
                std.mem.eql(
                    u8,
                    self.body[position - 2 .. position],
                    "\r\n",
                );
            if (!valid_prefix) {
                search_from = position + 1;
                continue;
            }
            if (position > self.options.max_preamble_bytes) {
                return error.MissingInitialBoundary;
            }
            const suffix = position + delimiter_slice.len;
            if (suffix + 2 > self.body.len) return error.TruncatedBody;
            if (std.mem.eql(u8, self.body[suffix..][0..2], "\r\n")) {
                self.pos = suffix + 2;
                return;
            }
            if (std.mem.eql(u8, self.body[suffix..][0..2], "--")) {
                self.pos = suffix + 2;
                self.markFinished();
                return;
            }
            search_from = position + 1;
        }
        return error.MissingInitialBoundary;
    }

    fn parsePart(self: *Parser) Error!void {
        if (self.part_count == self.options.max_parts) {
            return error.TooManyParts;
        }
        const header_limit = std.math.add(
            usize,
            self.pos,
            self.options.max_header_bytes,
        ) catch return error.HeaderTooLarge;
        const header_end = std.mem.indexOfPos(
            u8,
            self.body,
            self.pos,
            "\r\n\r\n",
        ) orelse return error.HeaderTooLarge;
        if (header_end > header_limit) return error.HeaderTooLarge;

        const header_start = self.header_count;
        var disposition_value: ?[]const u8 = null;
        var content_type_value: ?[]const u8 = null;
        var line_start = self.pos;
        while (line_start < header_end) {
            const line_end = std.mem.indexOfPos(
                u8,
                self.body,
                line_start,
                "\r\n",
            ) orelse return error.MalformedHeader;
            if (line_end > header_end) return error.MalformedHeader;
            if (line_end == line_start) break;
            if (self.body[line_start] == ' ' or
                self.body[line_start] == '\t')
            {
                return error.MalformedHeader;
            }
            const colon = std.mem.indexOfScalarPos(
                u8,
                self.body,
                line_start,
                ':',
            ) orelse return error.MalformedHeader;
            if (colon >= line_end) return error.MalformedHeader;
            const name = self.body[line_start..colon];
            if (!validHeaderName(name)) return error.InvalidHeaderName;
            const value = std.mem.trim(
                u8,
                self.body[colon + 1 .. line_end],
                " \t",
            );
            if (self.header_count - header_start >=
                self.options.max_headers_per_part)
            {
                return error.TooManyHeaders;
            }
            if (self.header_count == self.headers.len) {
                return error.TooManyHeaders;
            }
            self.headers[self.header_count] = .{
                .name = name,
                .value = value,
            };
            self.header_count += 1;
            if (std.ascii.eqlIgnoreCase(name, "content-disposition")) {
                if (disposition_value != null) {
                    return error.MalformedHeader;
                }
                disposition_value = value;
            } else if (std.ascii.eqlIgnoreCase(name, "content-type")) {
                if (content_type_value != null) {
                    return error.MalformedHeader;
                }
                content_type_value = value;
            }
            line_start = line_end + 2;
        }

        const disposition = disposition_value orelse
            return error.MissingContentDisposition;
        const names = try self.parseDisposition(disposition);

        if (content_type_value) |value| {
            if (!self.options.allow_nested and
                std.ascii.startsWithIgnoreCase(value, "multipart/"))
            {
                return error.UnsupportedNestedMultipart;
            }
        }

        const body_start = header_end + 4;
        const part = try self.findPartBody(body_start);
        self.parts[self.part_count] = .{
            .headers = self.headers[header_start..self.header_count],
            .name = names.name,
            .filename = names.filename,
            .content_type = content_type_value,
            .body = part.body,
        };
        self.part_count += 1;

        if (part.final) {
            const epilogue_len = self.body.len - part.next;
            if (epilogue_len > self.options.max_epilogue_bytes) {
                return error.TruncatedBody;
            }
            self.markFinished();
        } else {
            self.pos = part.next;
        }
    }

    const PartBody = struct {
        body: []const u8,
        next: usize,
        final: bool,
    };

    fn findPartBody(self: *Parser, body_start: usize) Error!PartBody {
        var delimiter_buffer: [4 + boundary_rules.max_len]u8 = undefined;
        delimiter_buffer[0] = '\r';
        delimiter_buffer[1] = '\n';
        delimiter_buffer[2] = '-';
        delimiter_buffer[3] = '-';
        @memcpy(
            delimiter_buffer[4..][0..self.boundary.len],
            self.boundary,
        );
        const delimiter_slice = delimiter_buffer[0 .. 4 + self.boundary.len];

        var search_from = body_start;
        while (std.mem.indexOfPos(
            u8,
            self.body,
            search_from,
            delimiter_slice,
        )) |position| {
            const suffix = position + delimiter_slice.len;
            if (suffix + 2 > self.body.len) return error.TruncatedBody;
            const marker = self.body[suffix..][0..2];
            if (std.mem.eql(u8, marker, "\r\n")) {
                const body = self.body[body_start..position];
                if (body.len > self.options.max_part_bytes) {
                    return error.PartTooLarge;
                }
                return .{
                    .body = body,
                    .next = suffix + 2,
                    .final = false,
                };
            }
            if (std.mem.eql(u8, marker, "--")) {
                const body = self.body[body_start..position];
                if (body.len > self.options.max_part_bytes) {
                    return error.PartTooLarge;
                }
                return .{
                    .body = body,
                    .next = suffix + 2,
                    .final = true,
                };
            }
            search_from = position + 1;
        }
        return error.TruncatedBody;
    }

    const DispositionNames = struct {
        name: []const u8,
        filename: ?[]const u8,
    };

    fn parseDisposition(
        self: *Parser,
        value: []const u8,
    ) Error!DispositionNames {
        var index: usize = 0;
        skipOws(value, &index);
        const type_start = index;
        while (index < value.len and
            value[index] != ';' and
            value[index] != ' ' and
            value[index] != '\t')
        {
            index += 1;
        }
        if (!std.ascii.eqlIgnoreCase(
            value[type_start..index],
            "form-data",
        )) {
            return error.InvalidContentDisposition;
        }

        var name: ?[]const u8 = null;
        var filename: ?[]const u8 = null;
        while (index < value.len) {
            skipOws(value, &index);
            if (index == value.len) break;
            if (value[index] == ';') {
                index += 1;
                skipOws(value, &index);
            }
            if (index == value.len) break;

            const param_start = index;
            while (index < value.len and isTokenChar(value[index])) {
                index += 1;
            }
            if (index == param_start) {
                return error.InvalidContentDisposition;
            }
            const param_name = value[param_start..index];
            skipOws(value, &index);
            if (index == value.len or value[index] != '=') {
                return error.InvalidContentDisposition;
            }
            index += 1;
            skipOws(value, &index);
            if (index == value.len) return error.InvalidContentDisposition;

            const is_name = std.ascii.eqlIgnoreCase(param_name, "name");
            const is_filename = std.ascii.eqlIgnoreCase(
                param_name,
                "filename",
            );
            if (!is_name and !is_filename) {
                if (std.mem.endsWith(u8, param_name, "*")) {
                    return error.UnsupportedParameter;
                }
                try skipValue(value, &index);
                continue;
            }

            const decoded = try self.parseDispositionValue(value, &index);
            if (is_name) {
                if (name != null) return error.DuplicateName;
                if (decoded.len > self.options.max_name_bytes) {
                    return error.NameTooLong;
                }
                name = decoded;
            } else {
                if (filename != null) return error.DuplicateFilename;
                if (decoded.len > self.options.max_filename_bytes) {
                    return error.FilenameTooLong;
                }
                filename = decoded;
            }
        }

        return .{
            .name = name orelse return error.MissingName,
            .filename = filename,
        };
    }

    fn parseDispositionValue(
        self: *Parser,
        value: []const u8,
        index: *usize,
    ) Error![]const u8 {
        if (value[index.*] == '"') {
            index.* += 1;
            const start = self.disposition_count;
            while (index.* < value.len and value[index.*] != '"') {
                if (value[index.*] == '\\') {
                    index.* += 1;
                    if (index.* == value.len) {
                        return error.InvalidContentDisposition;
                    }
                }
                if (self.disposition_count == self.disposition.len) {
                    return error.NameTooLong;
                }
                self.disposition[self.disposition_count] = value[index.*];
                self.disposition_count += 1;
                index.* += 1;
            }
            if (index.* == value.len or value[index.*] != '"') {
                return error.InvalidContentDisposition;
            }
            index.* += 1;
            return self.disposition[start..self.disposition_count];
        }
        const start = index.*;
        while (index.* < value.len and
            value[index.*] != ';' and
            value[index.*] != ' ' and
            value[index.*] != '\t')
        {
            index.* += 1;
        }
        if (start == index.*) return error.InvalidContentDisposition;
        return value[start..index.*];
    }
};

fn skipOws(input: []const u8, index: *usize) void {
    while (index.* < input.len and
        (input[index.*] == ' ' or input[index.*] == '\t'))
    {
        index.* += 1;
    }
}

fn skipValue(input: []const u8, index: *usize) Error!void {
    if (index.* == input.len) return error.InvalidContentDisposition;
    if (input[index.*] == '"') {
        index.* += 1;
        while (index.* < input.len and input[index.*] != '"') {
            if (input[index.*] == '\\') {
                index.* += 1;
                if (index.* == input.len) {
                    return error.InvalidContentDisposition;
                }
            }
            index.* += 1;
        }
        if (index.* == input.len) return error.InvalidContentDisposition;
        index.* += 1;
        return;
    }
    while (index.* < input.len and
        input[index.*] != ';' and
        input[index.*] != ' ' and
        input[index.*] != '\t')
    {
        index.* += 1;
    }
}

fn isTokenChar(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
            else => false,
        };
}

fn validHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!isTokenChar(byte)) return false;
    }
    return true;
}

test "multipart parser extracts fields and files" {
    const allocator = std.testing.allocator;
    const boundary = "----netz-parse";
    const body =
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"field\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "hello\r\n" ++
        "--" ++ boundary ++ "--\r\n";

    var parsed = try parseAlloc(
        allocator,
        body,
        "multipart/form-data; boundary=\"" ++ boundary ++ "\"",
        .{},
    );
    defer parsed.deinit();

    try std.testing.expectEqual(@as(usize, 2), parsed.parts.len);
    try std.testing.expectEqualStrings("field", parsed.parts[0].name);
    try std.testing.expectEqualStrings("value", parsed.parts[0].body);
    try std.testing.expectEqualStrings("upload", parsed.parts[1].name);
    try std.testing.expectEqualStrings("a.txt", parsed.parts[1].filename.?);
    try std.testing.expectEqualStrings(
        "text/plain",
        parsed.parts[1].content_type.?,
    );
    try std.testing.expectEqualStrings("hello", parsed.parts[1].body);
}

test "multipart parser handles preamble and boundary-like body bytes" {
    const allocator = std.testing.allocator;
    const boundary = "----netz-preamble";
    const body =
        "preamble\r\n" ++
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"data\"\r\n" ++
        "\r\n" ++
        "before\r\n--" ++ boundary ++ "xafter\r\n" ++
        "--" ++ boundary ++ "--\r\n" ++
        "epilogue";

    var parsed = try parseWithBoundary(
        allocator,
        body,
        boundary,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.parts.len);
    try std.testing.expectEqualStrings(
        "before\r\n--" ++ boundary ++ "xafter",
        parsed.parts[0].body,
    );
}

test "multipart parser rejects malformed and oversized input" {
    const allocator = std.testing.allocator;
    const boundary = "----netz-reject";
    const missing_final =
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"a\"\r\n" ++
        "\r\n" ++
        "value";
    try std.testing.expectError(
        error.TruncatedBody,
        parseWithBoundary(allocator, missing_final, boundary, .{}),
    );

    const missing_name =
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--" ++ boundary ++ "--\r\n";
    try std.testing.expectError(
        error.MissingName,
        parseWithBoundary(allocator, missing_name, boundary, .{}),
    );

    const obs_fold =
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data;\r\n name=\"a\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--" ++ boundary ++ "--\r\n";
    try std.testing.expectError(
        error.MalformedHeader,
        parseWithBoundary(allocator, obs_fold, boundary, .{}),
    );

    const too_large =
        "--" ++ boundary ++ "\r\n" ++
        "Content-Disposition: form-data; name=\"a\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--" ++ boundary ++ "--\r\n";
    try std.testing.expectError(
        error.PartTooLarge,
        parseWithBoundary(allocator, too_large, boundary, .{
            .max_part_bytes = 1,
        }),
    );
}

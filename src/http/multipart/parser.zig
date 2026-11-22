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
const hard_max_total_disposition_bytes = 4 * 1024 * 1024;

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
    UnsupportedCharset,
    InvalidExtendedValue,
    DispositionTooLarge,
    InvalidHeaderName,
};

pub const Parsed = struct {
    allocator: std.mem.Allocator,
    parts: []Part,
    headers: []Header,
    disposition: []u8,

    pub fn deinit(self: *Parsed) void {
        self.allocator.free(self.parts);
        self.allocator.free(self.headers);
        self.allocator.free(self.disposition);
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

    var parser = Parser{
        .allocator = allocator,
        .body = body,
        .boundary = boundary,
        .options = options,
    };
    defer parser.deinit();
    try parser.run();

    const parts = try allocator.alloc(Part, parser.parts.items.len);
    errdefer allocator.free(parts);
    const headers = try parser.headers.toOwnedSlice(allocator);
    errdefer allocator.free(headers);
    const disposition = try parser.disposition.toOwnedSlice(allocator);
    errdefer allocator.free(disposition);

    for (parser.parts.items, parts) |draft, *part| {
        part.* = .{
            .headers = headers[draft.header_start..][0..draft.header_count],
            .name = disposition[draft.name_start..][0..draft.name_len],
            .filename = if (draft.has_filename)
                disposition[draft.filename_start..][0..draft.filename_len]
            else
                null,
            .content_type = draft.content_type,
            .body = draft.body,
        };
    }

    return .{
        .allocator = allocator,
        .parts = parts,
        .headers = headers,
        .disposition = disposition,
    };
}

const PartDraft = struct {
    header_start: usize,
    header_count: usize,
    name_start: usize,
    name_len: usize,
    filename_start: usize = 0,
    filename_len: usize = 0,
    has_filename: bool = false,
    content_type: ?[]const u8,
    body: []const u8,
};

const Parser = struct {
    allocator: std.mem.Allocator,
    body: []const u8,
    boundary: []const u8,
    options: ParseOptions,
    pos: usize = 0,
    parts: std.ArrayList(PartDraft) = .empty,
    headers: std.ArrayList(Header) = .empty,
    disposition: std.ArrayList(u8) = .empty,

    fn deinit(self: *Parser) void {
        self.parts.deinit(self.allocator);
        self.headers.deinit(self.allocator);
        self.disposition.deinit(self.allocator);
    }

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
                (position >= 2 and std.mem.eql(
                    u8,
                    self.body[position - 2 .. position],
                    "\r\n",
                ));
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
        if (self.parts.items.len == self.options.max_parts) {
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

        const header_start = self.headers.items.len;
        const parsed_headers = try parseHeaderLines(
            self.allocator,
            &self.headers,
            self.body[self.pos..header_end],
            self.options.max_headers_per_part,
        );
        const disposition = parsed_headers.disposition orelse
            return error.MissingContentDisposition;
        const names = try parseDispositionInto(
            self.allocator,
            &self.disposition,
            disposition,
            self.options.max_name_bytes,
            self.options.max_filename_bytes,
        );
        const content_type_value = parsed_headers.content_type;

        if (content_type_value) |value| {
            if (!self.options.allow_nested and
                std.ascii.startsWithIgnoreCase(value, "multipart/"))
            {
                return error.UnsupportedNestedMultipart;
            }
        }

        const body_start = header_end + 4;
        const part = try self.findPartBody(body_start);
        try self.parts.append(self.allocator, .{
            .header_start = header_start,
            .header_count = self.headers.items.len - header_start,
            .name_start = names.name_start,
            .name_len = names.name_len,
            .filename_start = names.filename_start,
            .filename_len = names.filename_len,
            .has_filename = names.has_filename,
            .content_type = content_type_value,
            .body = part.body,
        });

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
};

const DispositionParser = struct {
    allocator: std.mem.Allocator,
    disposition: *std.ArrayList(u8),
    max_name_bytes: usize,
    max_filename_bytes: usize,

    const Names = struct {
        name_start: usize,
        name_len: usize,
        filename_start: usize = 0,
        filename_len: usize = 0,
        has_filename: bool = false,
    };

    const ValueRange = struct {
        start: usize,
        len: usize,
    };

    fn parse(
        self: *DispositionParser,
        value: []const u8,
    ) Error!Names {
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

        var name: ?ValueRange = null;
        var filename: ?ValueRange = null;
        var filename_extended: ?ValueRange = null;
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
            const is_filename_extended = std.ascii.eqlIgnoreCase(
                param_name,
                "filename*",
            );
            if (is_filename_extended) {
                if (filename_extended != null) {
                    return error.DuplicateFilename;
                }
                var scratch: std.ArrayList(u8) = .empty;
                defer scratch.deinit(self.allocator);
                const raw = try parseExtendedRaw(
                    self.allocator,
                    &scratch,
                    value,
                    &index,
                );
                const decoded = try self.decodeExtendedValue(raw);
                if (decoded.len > self.max_filename_bytes) {
                    return error.FilenameTooLong;
                }
                filename_extended = decoded;
                continue;
            }
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
                if (decoded.len > self.max_name_bytes) {
                    return error.NameTooLong;
                }
                name = decoded;
            } else {
                if (filename != null) return error.DuplicateFilename;
                if (decoded.len > self.max_filename_bytes) {
                    return error.FilenameTooLong;
                }
                filename = decoded;
            }
        }

        const chosen_name = name orelse return error.MissingName;
        const chosen_filename = filename_extended orelse filename;
        return .{
            .name_start = chosen_name.start,
            .name_len = chosen_name.len,
            .filename_start = if (chosen_filename) |item| item.start else 0,
            .filename_len = if (chosen_filename) |item| item.len else 0,
            .has_filename = chosen_filename != null,
        };
    }

    fn decodeExtendedValue(
        self: *DispositionParser,
        raw: []const u8,
    ) Error!ValueRange {
        const first_quote = std.mem.indexOfScalar(u8, raw, '\'') orelse
            return error.InvalidExtendedValue;
        const rest = raw[first_quote + 1 ..];
        const second_relative = std.mem.indexOfScalar(u8, rest, '\'') orelse
            return error.InvalidExtendedValue;
        const second_quote = first_quote + 1 + second_relative;
        const charset = raw[0..first_quote];
        const latin1 = std.ascii.eqlIgnoreCase(charset, "ISO-8859-1");
        if (!latin1 and !std.ascii.eqlIgnoreCase(charset, "UTF-8")) {
            return error.UnsupportedCharset;
        }
        const encoded = raw[second_quote + 1 ..];
        const start = self.disposition.items.len;
        var cursor: usize = 0;
        while (cursor < encoded.len) {
            if (encoded[cursor] == '%') {
                if (cursor + 2 >= encoded.len) {
                    return error.InvalidExtendedValue;
                }
                const high = hexValue(encoded[cursor + 1]) orelse
                    return error.InvalidExtendedValue;
                const low = hexValue(encoded[cursor + 2]) orelse
                    return error.InvalidExtendedValue;
                if (self.disposition.items.len ==
                    hard_max_total_disposition_bytes)
                {
                    return error.DispositionTooLarge;
                }
                try self.disposition.append(
                    self.allocator,
                    (high << 4) | low,
                );
                cursor += 3;
                continue;
            }
            if (self.disposition.items.len ==
                hard_max_total_disposition_bytes)
            {
                return error.DispositionTooLarge;
            }
            try self.disposition.append(
                self.allocator,
                encoded[cursor],
            );
            cursor += 1;
        }
        const len = self.disposition.items.len - start;
        const result = self.disposition.items[start..];
        if (!latin1 and !std.unicode.utf8ValidateSlice(result)) {
            return error.InvalidExtendedValue;
        }
        return .{ .start = start, .len = len };
    }

    fn parseDispositionValue(
        self: *DispositionParser,
        value: []const u8,
        index: *usize,
    ) Error!ValueRange {
        if (value[index.*] == '"') {
            index.* += 1;
            const start = self.disposition.items.len;
            while (index.* < value.len and value[index.*] != '"') {
                if (value[index.*] == '\\') {
                    index.* += 1;
                    if (index.* == value.len) {
                        return error.InvalidContentDisposition;
                    }
                }
                if (self.disposition.items.len ==
                    hard_max_total_disposition_bytes)
                {
                    return error.DispositionTooLarge;
                }
                try self.disposition.append(
                    self.allocator,
                    value[index.*],
                );
                index.* += 1;
            }
            if (index.* == value.len or value[index.*] != '"') {
                return error.InvalidContentDisposition;
            }
            index.* += 1;
            return .{
                .start = start,
                .len = self.disposition.items.len - start,
            };
        }
        const input_start = index.*;
        while (index.* < value.len and
            value[index.*] != ';' and
            value[index.*] != ' ' and
            value[index.*] != '\t')
        {
            index.* += 1;
        }
        if (input_start == index.*) return error.InvalidContentDisposition;
        const slice = value[input_start..index.*];
        if (self.disposition.items.len + slice.len >
            hard_max_total_disposition_bytes)
        {
            return error.DispositionTooLarge;
        }
        const start = self.disposition.items.len;
        try self.disposition.appendSlice(
            self.allocator,
            slice,
        );
        return .{
            .start = start,
            .len = index.* - input_start,
        };
    }
};

pub const DispositionNames = DispositionParser.Names;

pub fn parseDispositionInto(
    allocator: std.mem.Allocator,
    disposition: *std.ArrayList(u8),
    value: []const u8,
    max_name_bytes: usize,
    max_filename_bytes: usize,
) Error!DispositionNames {
    var parser = DispositionParser{
        .allocator = allocator,
        .disposition = disposition,
        .max_name_bytes = max_name_bytes,
        .max_filename_bytes = max_filename_bytes,
    };
    return parser.parse(value);
}

fn skipOws(input: []const u8, index: *usize) void {
    while (index.* < input.len and
        (input[index.*] == ' ' or input[index.*] == '\t'))
    {
        index.* += 1;
    }
}

fn parseExtendedRaw(
    allocator: std.mem.Allocator,
    scratch: *std.ArrayList(u8),
    value: []const u8,
    index: *usize,
) Error![]const u8 {
    if (index.* == value.len) return error.InvalidExtendedValue;
    if (value[index.*] == '"') {
        index.* += 1;
        while (index.* < value.len and value[index.*] != '"') {
            if (value[index.*] == '\\') {
                index.* += 1;
                if (index.* == value.len) {
                    return error.InvalidExtendedValue;
                }
            }
            try scratch.append(allocator, value[index.*]);
            index.* += 1;
        }
        if (index.* == value.len or value[index.*] != '"') {
            return error.InvalidExtendedValue;
        }
        index.* += 1;
        return scratch.items;
    }
    const start = index.*;
    while (index.* < value.len and
        value[index.*] != ';' and
        value[index.*] != ' ' and
        value[index.*] != '\t')
    {
        index.* += 1;
    }
    if (start == index.*) return error.InvalidExtendedValue;
    return value[start..index.*];
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
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

pub const HeaderParseResult = struct {
    disposition: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
};

pub fn parseHeaderLines(
    allocator: std.mem.Allocator,
    headers: *std.ArrayList(Header),
    block: []const u8,
    max_headers: usize,
) Error!HeaderParseResult {
    const start_count = headers.items.len;
    var result: HeaderParseResult = .{};
    var line_start: usize = 0;
    while (line_start < block.len) {
        const line_end = std.mem.indexOfPos(
            u8,
            block,
            line_start,
            "\r\n",
        ) orelse block.len;
        if (line_end == line_start) return error.MalformedHeader;
        if (block[line_start] == ' ' or block[line_start] == '\t') {
            return error.MalformedHeader;
        }
        const colon = std.mem.indexOfScalarPos(
            u8,
            block,
            line_start,
            ':',
        ) orelse return error.MalformedHeader;
        if (colon >= line_end) return error.MalformedHeader;
        const name = block[line_start..colon];
        if (!validHeaderName(name)) return error.InvalidHeaderName;
        const value = std.mem.trim(
            u8,
            block[colon + 1 .. line_end],
            " \t",
        );
        if (headers.items.len - start_count >= max_headers) {
            return error.TooManyHeaders;
        }
        try headers.append(allocator, .{ .name = name, .value = value });
        if (std.ascii.eqlIgnoreCase(name, "content-disposition")) {
            if (result.disposition != null) return error.MalformedHeader;
            result.disposition = value;
        } else if (std.ascii.eqlIgnoreCase(name, "content-type")) {
            if (result.content_type != null) return error.MalformedHeader;
            result.content_type = value;
        }
        line_start = line_end + 2;
    }
    return result;
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

test "multipart parser decodes RFC 5987 filename*" {
    const allocator = std.testing.allocator;
    const body =
        "--b\r\n" ++
        "Content-Disposition: form-data; name=\"upload\"; " ++
        "filename*=UTF-8''%E4%B8%AD%E6%96%87.txt\r\n" ++
        "\r\n" ++
        "x\r\n" ++
        "--b--\r\n";

    var parsed = try parseWithBoundary(allocator, body, "b", .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("upload", parsed.parts[0].name);
    try std.testing.expectEqualStrings("中文.txt", parsed.parts[0].filename.?);
}

test "multipart parser prefers filename* and validates extended values" {
    const allocator = std.testing.allocator;
    const boundary = "b";

    const preferred = try std.fmt.allocPrint(
        allocator,
        "--b\r\nContent-Disposition: {s}\r\n\r\nx\r\n--b--\r\n",
        .{
            "form-data; name=\"upload\"; filename=\"fallback.txt\"; " ++
                "filename*=UTF-8''real.txt",
        },
    );
    defer allocator.free(preferred);
    var parsed = try parseWithBoundary(
        allocator,
        preferred,
        boundary,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqualStrings(
        "real.txt",
        parsed.parts[0].filename.?,
    );

    const latin1 = try std.fmt.allocPrint(
        allocator,
        "--b\r\nContent-Disposition: {s}\r\n\r\nx\r\n--b--\r\n",
        .{
            "form-data; name=\"upload\"; " ++
                "filename*=ISO-8859-1''caf%E9.txt",
        },
    );
    defer allocator.free(latin1);
    var parsed_latin1 = try parseWithBoundary(
        allocator,
        latin1,
        boundary,
        .{},
    );
    defer parsed_latin1.deinit();
    try std.testing.expectEqualSlices(
        u8,
        "caf\xe9.txt",
        parsed_latin1.parts[0].filename.?,
    );

    const quoted = try std.fmt.allocPrint(
        allocator,
        "--b\r\nContent-Disposition: {s}\r\n\r\nx\r\n--b--\r\n",
        .{
            "form-data; name=\"upload\"; " ++
                "filename*=\"UTF-8''%E4%B8%AD%E6%96%87.txt\"",
        },
    );
    defer allocator.free(quoted);
    var parsed_quoted = try parseWithBoundary(
        allocator,
        quoted,
        boundary,
        .{},
    );
    defer parsed_quoted.deinit();
    try std.testing.expectEqualStrings(
        "中文.txt",
        parsed_quoted.parts[0].filename.?,
    );

    const invalid = try std.fmt.allocPrint(
        allocator,
        "--b\r\nContent-Disposition: {s}\r\n\r\nx\r\n--b--\r\n",
        .{
            "form-data; name=\"upload\"; filename*=UTF-8''%ZZ",
        },
    );
    defer allocator.free(invalid);
    try std.testing.expectError(
        error.InvalidExtendedValue,
        parseWithBoundary(allocator, invalid, boundary, .{}),
    );

    const unsupported = try std.fmt.allocPrint(
        allocator,
        "--b\r\nContent-Disposition: {s}\r\n\r\nx\r\n--b--\r\n",
        .{
            "form-data; name=\"upload\"; filename*=KOI8-R''x",
        },
    );
    defer allocator.free(unsupported);
    try std.testing.expectError(
        error.UnsupportedCharset,
        parseWithBoundary(allocator, unsupported, boundary, .{}),
    );
}

test "multipart parser accepts a curl-shaped form" {
    const allocator = std.testing.allocator;
    const boundary = "------------------------7u3Vb6xOMj4YLWeQhjKRTV";
    const body =
        "--------------------------7u3Vb6xOMj4YLWeQhjKRTV\r\n" ++
        "Content-Disposition: form-data; name=\"field\"\r\n" ++
        "\r\n" ++
        "value\r\n" ++
        "--------------------------7u3Vb6xOMj4YLWeQhjKRTV\r\n" ++
        "Content-Disposition: form-data; name=\"upload\"; filename=\"a.txt\"\r\n" ++
        "Content-Type: text/plain\r\n" ++
        "\r\n" ++
        "hello\r\n" ++
        "--------------------------7u3Vb6xOMj4YLWeQhjKRTV--\r\n";

    var parsed = try parseAlloc(
        allocator,
        body,
        "multipart/form-data; boundary=" ++ boundary,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 2), parsed.parts.len);
    try std.testing.expectEqualStrings("field", parsed.parts[0].name);
    try std.testing.expectEqualStrings("value", parsed.parts[0].body);
    try std.testing.expectEqualStrings("upload", parsed.parts[1].name);
    try std.testing.expectEqualStrings("a.txt", parsed.parts[1].filename.?);
    try std.testing.expectEqualStrings("hello", parsed.parts[1].body);
}

test "multipart parser keeps slices valid across storage growth" {
    const allocator = std.testing.allocator;
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(allocator);

    for (0..8) |index| {
        const part = try std.fmt.allocPrint(
            allocator,
            "--b\r\n" ++
                "Content-Disposition: form-data; name=\"p{d}\"; " ++
                "filename=\"f{d}.txt\"\r\n" ++
                "Content-Type: text/plain\r\n" ++
                "X-Index: {d}\r\n" ++
                "X-Part: value\r\n" ++
                "\r\n" ++
                "body-{d}\r\n",
            .{ index, index, index, index },
        );
        defer allocator.free(part);
        try body.appendSlice(allocator, part);
    }
    try body.appendSlice(allocator, "--b--\r\n");

    var parsed = try parseWithBoundary(
        allocator,
        body.items,
        "b",
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 8), parsed.parts.len);

    for (parsed.parts, 0..) |part, index| {
        const expected_name = try std.fmt.allocPrint(
            allocator,
            "p{d}",
            .{index},
        );
        defer allocator.free(expected_name);
        const expected_filename = try std.fmt.allocPrint(
            allocator,
            "f{d}.txt",
            .{index},
        );
        defer allocator.free(expected_filename);
        const expected_body = try std.fmt.allocPrint(
            allocator,
            "body-{d}",
            .{index},
        );
        defer allocator.free(expected_body);
        const expected_index = try std.fmt.allocPrint(
            allocator,
            "{d}",
            .{index},
        );
        defer allocator.free(expected_index);

        try std.testing.expectEqualStrings(expected_name, part.name);
        try std.testing.expectEqualStrings(
            expected_filename,
            part.filename.?,
        );
        try std.testing.expectEqualStrings(expected_body, part.body);
        try std.testing.expectEqual(@as(usize, 4), part.headers.len);
        try std.testing.expectEqualStrings(
            "X-Index",
            part.headers[2].name,
        );
        try std.testing.expectEqualStrings(
            expected_index,
            part.headers[2].value,
        );
    }
}

//! Bounded Envoy URI-template path matching and rewriting.
//!
//! The matcher supports the operators documented by Envoy's URI template
//! extensions: `*` (one segment), `**` (zero or more segments, last only),
//! `{name}`/`{name=*}` (one captured segment), `{name=**}` (captured suffix),
//! `{name=videos/*}` (captured multi-segment pattern) and variables embedded in
//! a segment such as `{file}.vtt`. Matching is anchored to the complete path
//! with query and fragment removed.
const std = @import("std");

pub const Error = std.mem.Allocator.Error || error{
    InvalidTemplate,
    TemplateLimitExceeded,
};
pub const Limits = struct {
    max_bytes: usize = 256,
    max_segments: usize = 64,
    max_variables: usize = 32,
    max_steps: usize = 65536,
};

const max_captures = 32;

pub const Captures = struct {
    names: [max_captures][]const u8 = undefined,
    values: [max_captures][]const u8 = undefined,
    len: usize = 0,

    pub fn reset(self: *Captures) void {
        self.len = 0;
    }

    pub fn get(self: *const Captures, name: []const u8) ?[]const u8 {
        var index: usize = 0;
        while (index < self.len) : (index += 1) {
            if (std.mem.eql(u8, self.names[index], name)) {
                return self.values[index];
            }
        }
        return null;
    }

    fn add(self: *Captures, name: []const u8, value: []const u8) Error!void {
        if (self.len >= self.names.len) return error.TemplateLimitExceeded;
        self.names[self.len] = name;
        self.values[self.len] = value;
        self.len += 1;
    }
};

const Segment = union(enum) {
    literal: []const u8,
    single: ?[]const u8,
    multi: ?[]const u8,
    pattern: struct { name: []const u8, parts: []const Segment },
    embedded: struct { name: []const u8, prefix: []const u8, suffix: []const u8 },
};

pub const Match = struct {
    parts: []const Segment,
    variables: []const []const u8,
    limits: Limits,

    pub fn compile(
        allocator: std.mem.Allocator,
        template: []const u8,
        limits: Limits,
    ) Error!Match {
        if (template.len == 0 or template.len > limits.max_bytes) {
            return error.TemplateLimitExceeded;
        }
        if (template[0] != '/') return error.InvalidTemplate;
        var variables: std.ArrayList([]const u8) = .empty;
        errdefer variables.deinit(allocator);
        var parts: std.ArrayList(Segment) = .empty;
        errdefer parts.deinit(allocator);
        try parseParts(
            allocator,
            template[1..],
            &parts,
            &variables,
            limits,
            true,
        );
        if (parts.items.len > limits.max_segments) {
            return error.TemplateLimitExceeded;
        }
        return .{
            .parts = try parts.toOwnedSlice(allocator),
            .variables = try variables.toOwnedSlice(allocator),
            .limits = limits,
        };
    }

    pub fn match(
        self: *const Match,
        path: []const u8,
        captures: *Captures,
    ) Error!bool {
        captures.reset();
        const end = std.mem.indexOfAny(u8, path, "?#") orelse path.len;
        const value = path[0..end];
        if (value.len == 0 or value[0] != '/') return false;
        var segments: [64]PathSegment = undefined;
        const count = splitPath(value, &segments);
        if (count == null) return error.TemplateLimitExceeded;
        var steps: usize = 0;
        const matched = try matchParts(
            self.parts,
            0,
            value,
            segments[0..count.?],
            0,
            captures,
            &steps,
            self.limits.max_steps,
        );
        return matched == count.?;
    }
};

const PathSegment = struct { text: []const u8, start: usize, end: usize };

fn splitPath(path: []const u8, out: *[64]PathSegment) ?usize {
    if (path.len <= 1) return 0;
    var count: usize = 0;
    var start: usize = 1; // account for the leading '/'
    var index: usize = 1;
    while (true) {
        if (index == path.len or path[index] == '/') {
            if (count == out.len) return null;
            out[count] = .{
                .text = path[start..index],
                .start = start,
                .end = index,
            };
            count += 1;
            if (index == path.len) break;
            start = index + 1;
        }
        index += 1;
    }
    return count;
}

fn parseParts(
    allocator: std.mem.Allocator,
    template: []const u8,
    parts: *std.ArrayList(Segment),
    variables: *std.ArrayList([]const u8),
    limits: Limits,
    allow_named: bool,
) Error!void {
    var start: usize = 0;
    var depth: usize = 0;
    var index: usize = 0;
    while (index <= template.len) : (index += 1) {
        const at_end = index == template.len;
        const byte = if (at_end) 0 else template[index];
        if (!at_end) {
            if (byte == '{') {
                depth += 1;
                continue;
            }
            if (byte == '}') {
                if (depth == 0) return error.InvalidTemplate;
                depth -= 1;
                continue;
            }
            if (byte != '/' or depth != 0) continue;
        }
        if (depth != 0) return error.InvalidTemplate;
        const segment = template[start..index];
        if (segment.len != 0) {
            try parseSegment(allocator, segment, parts, variables, limits, allow_named);
        }
        start = index + 1;
    }
    if (parts.items.len != 0 and parts.items[parts.items.len - 1] == .multi) {
        // `**` and `{name=**}` are only valid as the final operator.
    } else {
        for (parts.items, 0..) |part, part_index| {
            if (part == .multi and part_index + 1 != parts.items.len) {
                return error.InvalidTemplate;
            }
        }
    }
}

fn parseSegment(
    allocator: std.mem.Allocator,
    segment: []const u8,
    parts: *std.ArrayList(Segment),
    variables: *std.ArrayList([]const u8),
    limits: Limits,
    allow_named: bool,
) Error!void {
    if (std.mem.eql(u8, segment, "*")) {
        try parts.append(allocator, .{ .single = null });
        return;
    }
    if (std.mem.eql(u8, segment, "**")) {
        try parts.append(allocator, .{ .multi = null });
        return;
    }
    if (segment[0] == '{' and segment[segment.len - 1] == '}') {
        if (!allow_named) return error.InvalidTemplate;
        const inner = segment[1 .. segment.len - 1];
        const equals = std.mem.indexOfScalar(u8, inner, '=');
        const name = if (equals) |at| inner[0..at] else inner;
        const pattern = if (equals) |at| inner[at + 1 ..] else "*";
        if (!validName(name)) return error.InvalidTemplate;
        try appendVariable(allocator, variables, name, limits);
        if (std.mem.eql(u8, pattern, "*")) {
            try parts.append(allocator, .{ .single = name });
        } else if (std.mem.eql(u8, pattern, "**")) {
            try parts.append(allocator, .{ .multi = name });
        } else if (std.mem.indexOfScalar(u8, pattern, '/') != null) {
            var nested: std.ArrayList(Segment) = .empty;
            defer nested.deinit(allocator);
            var nested_variables: std.ArrayList([]const u8) = .empty;
            defer nested_variables.deinit(allocator);
            try parseParts(
                allocator,
                pattern,
                &nested,
                &nested_variables,
                limits,
                false,
            );
            try parts.append(allocator, .{ .pattern = .{
                .name = name,
                .parts = try nested.toOwnedSlice(allocator),
            } });
        } else {
            try parts.append(allocator, .{ .embedded = .{
                .name = name,
                .prefix = pattern,
                .suffix = "",
            } });
        }
        return;
    }
    const open = std.mem.indexOfScalar(u8, segment, '{') orelse {
        try parts.append(allocator, .{ .literal = segment });
        return;
    };
    const close = std.mem.indexOfScalarPos(u8, segment, open, '}') orelse {
        return error.InvalidTemplate;
    };
    if (std.mem.indexOfScalarPos(u8, segment, close + 1, '{') != null or
        std.mem.indexOfScalarPos(u8, segment, close + 1, '}') != null)
    {
        return error.InvalidTemplate;
    }
    const name = segment[open + 1 .. close];
    if (!validName(name)) return error.InvalidTemplate;
    try appendVariable(allocator, variables, name, limits);
    try parts.append(allocator, .{ .embedded = .{
        .name = name,
        .prefix = segment[0..open],
        .suffix = segment[close + 1 ..],
    } });
}

fn appendVariable(
    allocator: std.mem.Allocator,
    variables: *std.ArrayList([]const u8),
    name: []const u8,
    limits: Limits,
) Error!void {
    if (variables.items.len >= limits.max_variables) {
        return error.TemplateLimitExceeded;
    }
    for (variables.items) |existing| {
        if (std.mem.eql(u8, existing, name)) return error.InvalidTemplate;
    }
    try variables.append(allocator, name);
}

fn validName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    return true;
}

fn matchParts(
    parts: []const Segment,
    part_index: usize,
    path: []const u8,
    segments: []const PathSegment,
    segment_index: usize,
    captures: *Captures,
    steps: *usize,
    max_steps: usize,
) Error!?usize {
    steps.* += 1;
    if (steps.* > max_steps) return error.TemplateLimitExceeded;
    if (part_index == parts.len) return segment_index;
    const part = parts[part_index];
    switch (part) {
        .literal => |literal| {
            if (segment_index >= segments.len or
                !std.mem.eql(u8, segments[segment_index].text, literal))
            {
                return null;
            }
            return matchParts(
                parts,
                part_index + 1,
                path,
                segments,
                segment_index + 1,
                captures,
                steps,
                max_steps,
            );
        },
        .single => |name| {
            if (segment_index >= segments.len) return null;
            if (name) |capture| {
                try captures.add(capture, segments[segment_index].text);
            }
            return matchParts(
                parts,
                part_index + 1,
                path,
                segments,
                segment_index + 1,
                captures,
                steps,
                max_steps,
            );
        },
        .multi => |name| {
            // The compiler enforces that a multi segment is last.
            if (name) |capture| {
                const value = if (segment_index == segments.len)
                    ""
                else
                    path[segments[segment_index].start..segments[segments.len - 1].end];
                try captures.add(capture, value);
            }
            return segments.len;
        },
        .pattern => |pattern| {
            const saved = captures.len;
            const end = try matchParts(
                pattern.parts,
                0,
                path,
                segments,
                segment_index,
                captures,
                steps,
                max_steps,
            ) orelse {
                captures.len = saved;
                return null;
            };
            const value = if (end == segment_index)
                ""
            else
                path[segments[segment_index].start..segments[end - 1].end];
            captures.len = saved;
            try captures.add(pattern.name, value);
            return matchParts(
                parts,
                part_index + 1,
                path,
                segments,
                end,
                captures,
                steps,
                max_steps,
            );
        },
        .embedded => |embedded| {
            if (segment_index >= segments.len) return null;
            const text = segments[segment_index].text;
            if (text.len < embedded.prefix.len + embedded.suffix.len) return null;
            if (!std.mem.startsWith(u8, text, embedded.prefix) or
                !std.mem.endsWith(u8, text, embedded.suffix))
            {
                return null;
            }
            const end = text.len - embedded.suffix.len;
            try captures.add(embedded.name, text[embedded.prefix.len..end]);
            return matchParts(
                parts,
                part_index + 1,
                path,
                segments,
                segment_index + 1,
                captures,
                steps,
                max_steps,
            );
        },
    }
}

pub const Rewrite = struct {
    parts: []const Part,
    limits: Limits,

    const Part = union(enum) {
        literal: []const u8,
        variable: []const u8,
    };

    pub fn compile(
        allocator: std.mem.Allocator,
        template: []const u8,
        match_variables: []const []const u8,
        limits: Limits,
    ) Error!Rewrite {
        if (template.len == 0 or template.len > limits.max_bytes) {
            return error.TemplateLimitExceeded;
        }
        var parts: std.ArrayList(Part) = .empty;
        errdefer parts.deinit(allocator);
        var start: usize = 0;
        var index: usize = 0;
        while (index < template.len) {
            if (template[index] != '{') {
                index += 1;
                continue;
            }
            if (index > start) {
                try parts.append(allocator, .{ .literal = template[start..index] });
            }
            const close = std.mem.indexOfScalarPos(u8, template, index, '}') orelse {
                return error.InvalidTemplate;
            };
            const name = template[index + 1 .. close];
            if (!validName(name) or !containsVariable(match_variables, name)) {
                return error.InvalidTemplate;
            }
            try parts.append(allocator, .{ .variable = name });
            index = close + 1;
            start = index;
        }
        if (start < template.len) {
            try parts.append(allocator, .{ .literal = template[start..] });
        }
        return .{ .parts = try parts.toOwnedSlice(allocator), .limits = limits };
    }

    pub fn outputLen(self: *const Rewrite, captures: *const Captures) Error!usize {
        var total: usize = 0;
        for (self.parts) |part| switch (part) {
            .literal => |literal| total = std.math.add(usize, total, literal.len) catch return error.TemplateLimitExceeded,
            .variable => |name| {
                const value = captures.get(name) orelse "";
                total = std.math.add(usize, total, value.len) catch return error.TemplateLimitExceeded;
            },
        };
        return total;
    }

    pub fn write(
        self: *const Rewrite,
        captures: *const Captures,
        output: []u8,
    ) Error![]const u8 {
        var offset: usize = 0;
        for (self.parts) |part| switch (part) {
            .literal => |literal| {
                if (literal.len > output.len - offset) {
                    return error.TemplateLimitExceeded;
                }
                @memcpy(output[offset..][0..literal.len], literal);
                offset += literal.len;
            },
            .variable => |name| {
                const value = captures.get(name) orelse "";
                if (value.len > output.len - offset) {
                    return error.TemplateLimitExceeded;
                }
                @memcpy(output[offset..][0..value.len], value);
                offset += value.len;
            },
        };
        return output[0..offset];
    }
};

fn containsVariable(variables: []const []const u8, name: []const u8) bool {
    for (variables) |variable| if (std.mem.eql(u8, variable, name)) return true;
    return false;
}

test {
    _ = @import("template_tests.zig");
}

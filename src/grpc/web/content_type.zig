//! gRPC-Web media types and HTTP Accept response negotiation.

const std = @import("std");
const http2 = @import("../../http2/mod.zig");

pub const Error = error{ InvalidWebContentType, InvalidWebAccept, NoAcceptableWebContentType };

/// gRPC-Web payload codec: protobuf is opaque bytes here, matching gRPC.
pub const Format = enum {
    proto,
    json,
};

/// Whether the entity uses the base64 text wire (`application/grpc-web-text`).
pub const ContentType = struct {
    format: Format,
    text: bool,

    /// Canonical response media type. gRPC-Web clients accept any type that
    /// begins with `application/grpc-web`; proto binary keeps the unsuffixed
    /// form Envoy returns for an unsuffixed request.
    pub fn canonical(self: ContentType) []const u8 {
        if (self.text) {
            return switch (self.format) {
                .proto => "application/grpc-web-text",
                .json => "application/grpc-web-text+json",
            };
        }
        return switch (self.format) {
            .proto => "application/grpc-web",
            .json => "application/grpc-web+json",
        };
    }
};

const media = "application/grpc-web";

/// Classify a gRPC-Web request content type. Unknown parameters after a
/// semicolon are ignored, matching the HTTP content-type grammar. Plain
/// `application/grpc` is rejected so the gRPC and gRPC-Web paths cannot be
/// confused by shared server dispatch.
pub fn parseContentType(raw: []const u8) Error!ContentType {
    var value = std.mem.trim(u8, raw, " \t");
    if (std.mem.indexOfScalar(u8, value, ';')) |semicolon| {
        value = std.mem.trim(u8, value[0..semicolon], " \t");
    }
    if (value.len < media.len or
        !std.ascii.eqlIgnoreCase(value[0..media.len], media))
    {
        return error.InvalidWebContentType;
    }
    const rest = value[media.len..];
    if (rest.len == 0) {
        return .{ .format = .proto, .text = false };
    }
    if (std.ascii.eqlIgnoreCase(rest, "+proto")) {
        return .{ .format = .proto, .text = false };
    }
    if (std.ascii.eqlIgnoreCase(rest, "+json")) {
        return .{ .format = .json, .text = false };
    }
    // The text forms replace the separator with "-text".
    if (rest.len < "-text".len or
        !std.ascii.eqlIgnoreCase(rest[0.."-text".len], "-text"))
    {
        return error.InvalidWebContentType;
    }
    const text_rest = rest["-text".len..];
    if (text_rest.len == 0) {
        return .{ .format = .proto, .text = true };
    }
    if (std.ascii.eqlIgnoreCase(text_rest, "+proto")) {
        return .{ .format = .proto, .text = true };
    }
    if (std.ascii.eqlIgnoreCase(text_rest, "+json")) {
        return .{ .format = .json, .text = true };
    }
    return error.InvalidWebContentType;
}

const Preference = struct {
    specificity: ?u2 = null,
    quality: u16 = 0,

    fn update(self: *Preference, specificity: u2, quality: u16) void {
        if (self.specificity == null or specificity > self.specificity.? or
            (specificity == self.specificity.? and quality > self.quality))
        {
            self.* = .{ .specificity = specificity, .quality = quality };
        }
    }
};

/// Request encoding and response encoding are independent. Absent Accept
/// retains the request wire; otherwise honor quality and media specificity
/// across repeated fields. The payload format remains that of the request.
pub fn negotiateResponseContentType(request: ContentType, headers: []const http2.Hpack.HeaderField) Error!ContentType {
    var preferences = [_]Preference{ .{}, .{} }; // binary, text
    var accept_seen = false;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "accept")) continue;
        accept_seen = true;
        var ranges = Elements{ .input = header.value, .separator = ',' };
        while (ranges.next()) |range| {
            var params = Elements{ .input = range, .separator = ';' };
            const name = std.mem.trim(u8, params.next() orelse continue, " \t");
            var specificities: [2]?u2 = .{ null, null };
            if (std.mem.eql(u8, name, "*/*") or std.ascii.eqlIgnoreCase(name, "application/*")) {
                const specificity: u2 = if (name[0] == '*') 0 else 1;
                specificities = .{ specificity, specificity };
            } else {
                const parsed = parseContentType(name) catch continue;
                if (parsed.format != request.format) continue;
                specificities[@intFromBool(parsed.text)] = 2;
            }
            var quality: u16 = 1000;
            var quality_seen = false;
            while (params.next()) |param| {
                const equals = std.mem.indexOfScalar(u8, param, '=') orelse continue;
                if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, param[0..equals], " \t"), "q")) continue;
                if (quality_seen) return error.InvalidWebAccept;
                quality_seen = true;
                quality = try parseQuality(std.mem.trim(u8, param[equals + 1 ..], " \t"));
            }
            for (&preferences, specificities) |*preference, specificity| {
                if (specificity) |value| preference.update(value, quality);
            }
        }
    }
    if (!accept_seen) return request;
    if (preferences[0].quality == 0 and preferences[1].quality == 0) {
        return error.NoAcceptableWebContentType;
    }
    return .{
        .format = request.format,
        .text = if (preferences[0].quality == preferences[1].quality)
            request.text
        else
            preferences[1].quality > preferences[0].quality,
    };
}

fn parseQuality(value: []const u8) Error!u16 {
    if (value.len == 0 or (value[0] != '0' and value[0] != '1')) return error.InvalidWebAccept;
    if (value.len == 1) return if (value[0] == '1') 1000 else 0;
    if (value[1] != '.' or value.len > 5) return error.InvalidWebAccept;
    var result: u16 = 0;
    var place: u16 = 100;
    for (value[2..]) |digit| {
        if (digit < '0' or digit > '9' or (value[0] == '1' and digit != '0')) return error.InvalidWebAccept;
        result += @as(u16, digit - '0') * place;
        place /= 10;
    }
    return if (value[0] == '1') 1000 else result;
}

// Quoted extension parameters can contain commas or semicolons. Preserve
// those bytes when splitting a combined Accept field and its parameters.
const Elements = struct {
    input: []const u8,
    separator: u8,
    offset: usize = 0,

    fn next(self: *Elements) ?[]const u8 {
        if (self.offset >= self.input.len) return null;
        const start = self.offset;
        var quoted = false;
        var escaped = false;
        while (self.offset < self.input.len) : (self.offset += 1) {
            const byte = self.input[self.offset];
            if (escaped) {
                escaped = false;
            } else if (quoted and byte == '\\') {
                escaped = true;
            } else if (byte == '"') {
                quoted = !quoted;
            } else if (!quoted and byte == self.separator) {
                const end = self.offset;
                self.offset += 1;
                return self.input[start..end];
            }
        }
        return self.input[start..];
    }
};

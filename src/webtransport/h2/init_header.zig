//! Per-Session WebTransport-Init Dictionary credit, merged with SETTINGS.
const std = @import("std");
const sf = @import("../../internal/structured_field.zig");
const model = @import("state.zig");
pub const Error = error{InvalidWebTransportInit};

/// Per-session stream-data credit advertised by the sender of a
/// WebTransport-Init field. Names are relative to that sender.
pub const InitialStreamDataLimits = struct {
    uni: u64 = 0,
    bidi_local: u64 = 0,
    bidi_remote: u64 = 0,

    fn validate(self: InitialStreamDataLimits) Error!void {
        if (self.uni > 999999999999999 or self.bidi_local > 999999999999999 or self.bidi_remote > 999999999999999) return error.InvalidWebTransportInit;
    }
};

pub fn parse(headers: anytype, baseline: model.Limits) Error!model.Limits {
    var out = baseline;
    var parsed: struct {
        uni: ?u64 = null,
        bidi_local: ?u64 = null,
        bidi_remote: ?u64 = null,
    } = .{};
    var matching_lines: usize = 0;
    var saw_empty_line = false;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "webtransport-init")) continue;
        matching_lines += 1;
        var cursor: usize = 0;
        const text = header.value;
        sf.skipOptionalWhitespace(text, &cursor);
        if (cursor == text.len) {
            saw_empty_line = true;
            continue;
        }
        while (cursor < text.len) {
            const start = cursor;
            if (!(text[cursor] >= 'a' and text[cursor] <= 'z') and text[cursor] != '*') return error.InvalidWebTransportInit;
            cursor += 1;
            while (cursor < text.len and (std.ascii.isLower(text[cursor]) or std.ascii.isDigit(text[cursor]) or std.mem.indexOfScalar(u8, "_.*-", text[cursor]) != null)) cursor += 1;
            const key = text[start..cursor];
            const target: ?*?u64 = if (std.mem.eql(u8, key, "u")) &parsed.uni else if (std.mem.eql(u8, key, "bl")) &parsed.bidi_local else if (std.mem.eql(u8, key, "br")) &parsed.bidi_remote else null;
            if (cursor < text.len and text[cursor] == '=') {
                cursor += 1;
                const item_start = cursor;
                sf.consumeMember8941(text, &cursor) catch return error.InvalidWebTransportInit;
                if (target) |field| {
                    var end = item_start;
                    if (end < text.len and text[end] == '-') return error.InvalidWebTransportInit;
                    while (end < text.len and std.ascii.isDigit(text[end])) end += 1;
                    if (end == item_start or end - item_start > 15 or (end < text.len and text[end] != ';' and text[end] != ',' and text[end] != ' ' and text[end] != '\t')) return error.InvalidWebTransportInit;
                    const number = std.fmt.parseInt(u64, text[item_start..end], 10) catch return error.InvalidWebTransportInit;
                    field.* = number;
                }
            } else {
                if (target != null) return error.InvalidWebTransportInit;
                sf.consumeParameters8941(text, &cursor) catch return error.InvalidWebTransportInit;
            }
            sf.skipOptionalWhitespace(text, &cursor);
            if (cursor == text.len) break;
            if (text[cursor] != ',') return error.InvalidWebTransportInit;
            cursor += 1;
            sf.skipOptionalWhitespace(text, &cursor);
            if (cursor == text.len) return error.InvalidWebTransportInit;
        }
    }
    // Multiple HTTP field lines are combined with commas before Structured
    // Field parsing. An empty member is therefore valid only when it is the
    // sole field line. RFC 8941 dictionaries retain the last duplicate key.
    if (matching_lines > 1 and saw_empty_line) return error.InvalidWebTransportInit;
    if (parsed.uni) |value| out.uni_data = @max(out.uni_data, value);
    if (parsed.bidi_local) |value| out.bidi_local_data = @max(out.bidi_local_data, value);
    if (parsed.bidi_remote) |value| out.bidi_remote_data = @max(out.bidi_remote_data, value);
    return out;
}

pub fn fromSettings(settings: @import("../../http2/mod.zig").WebTransportSettings) model.Limits {
    return .{ .data = settings.max_data, .bidi = settings.max_streams_bidi, .uni = settings.max_streams_uni, .uni_data = settings.max_stream_data_uni, .bidi_local_data = settings.max_stream_data_bidi_local, .bidi_remote_data = settings.max_stream_data_bidi_remote };
}

pub fn writeInto(output: []u8, limits: InitialStreamDataLimits) (Error || error{BufferTooShort})![]u8 {
    // RFC 8941 Integers have at most fifteen decimal digits.
    try limits.validate();
    return std.fmt.bufPrint(output, "u={d}, bl={d}, br={d}", .{ limits.uni, limits.bidi_local, limits.bidi_remote }) catch error.BufferTooShort;
}

//! RFC 6265 cookie-date parsing.
//!
//! Cookie expiry deliberately accepts the historical delimiter/token grammar
//! rather than only IMF-fixdate. Invalid dates are ignored by the caller, as
//! required for an unrecognized Expires attribute.

const std = @import("std");

pub fn parse(value: []const u8) ?i64 {
    var second: ?u8 = null;
    var minute: ?u8 = null;
    var hour: ?u8 = null;
    var day: ?u8 = null;
    var month: ?u8 = null;
    var year: ?u16 = null;

    var tokens = Tokens{ .value = value };
    while (tokens.next()) |token| {
        if (hour == null) {
            if (parseTime(token)) |time| {
                hour = time.hour;
                minute = time.minute;
                second = time.second;
                continue;
            }
        }
        if (day == null) {
            if (parseDigits(token, 1, 2)) |number| {
                day = @intCast(number);
                continue;
            }
        }
        if (month == null) {
            if (parseMonth(token)) |number| {
                month = number;
                continue;
            }
        }
        if (year == null) {
            if (parseDigits(token, 2, 4)) |number| {
                year = @intCast(number);
                continue;
            }
        }
    }

    const resolved_day = day orelse return null;
    const resolved_month = month orelse return null;
    var resolved_year = year orelse return null;
    const resolved_hour = hour orelse return null;
    const resolved_minute = minute orelse return null;
    const resolved_second = second orelse return null;

    if (resolved_year >= 70 and resolved_year <= 99) {
        resolved_year += 1900;
    } else if (resolved_year <= 69) {
        resolved_year += 2000;
    }
    if (resolved_year < 1601 or
        resolved_month == 0 or resolved_month > 12 or
        resolved_day == 0 or
        resolved_day > daysInMonth(resolved_year, resolved_month) or
        resolved_hour > 23 or resolved_minute > 59 or resolved_second > 59)
    {
        return null;
    }

    return daysFromCivil(
        resolved_year,
        resolved_month,
        resolved_day,
    ) * std.time.s_per_day +
        @as(i64, resolved_hour) * std.time.s_per_hour +
        @as(i64, resolved_minute) * std.time.s_per_min +
        resolved_second;
}

const Tokens = struct {
    value: []const u8,
    index: usize = 0,

    fn next(self: *Tokens) ?[]const u8 {
        while (self.index < self.value.len and
            isDelimiter(self.value[self.index]))
        {
            self.index += 1;
        }
        if (self.index == self.value.len) return null;
        const start = self.index;
        while (self.index < self.value.len and
            !isDelimiter(self.value[self.index]))
        {
            self.index += 1;
        }
        return self.value[start..self.index];
    }
};

fn isDelimiter(byte: u8) bool {
    return byte == '\t' or
        (byte >= 0x20 and byte <= 0x2f) or
        (byte >= 0x3b and byte <= 0x40) or
        (byte >= 0x5b and byte <= 0x60) or
        (byte >= 0x7b and byte <= 0x7e);
}

fn parseTime(token: []const u8) ?struct {
    hour: u8,
    minute: u8,
    second: u8,
} {
    var parts = std.mem.splitScalar(u8, token, ':');
    const hour = parseDigits(parts.next() orelse return null, 1, 2) orelse
        return null;
    const minute = parseDigits(parts.next() orelse return null, 1, 2) orelse
        return null;
    const second = parseDigits(parts.next() orelse return null, 1, 2) orelse
        return null;
    if (parts.next() != null) return null;
    return .{
        .hour = @intCast(hour),
        .minute = @intCast(minute),
        .second = @intCast(second),
    };
}

fn parseDigits(token: []const u8, minimum: usize, maximum: usize) ?u16 {
    if (token.len < minimum or token.len > maximum) return null;
    var result: u16 = 0;
    for (token) |byte| {
        if (!std.ascii.isDigit(byte)) return null;
        result = result * 10 + (byte - '0');
    }
    return result;
}

fn parseMonth(token: []const u8) ?u8 {
    if (token.len < 3) return null;
    const months = [_][]const u8{
        "jan", "feb", "mar", "apr", "may", "jun",
        "jul", "aug", "sep", "oct", "nov", "dec",
    };
    for (months, 1..) |month, number| {
        if (std.ascii.eqlIgnoreCase(token[0..3], month)) {
            return @intCast(number);
        }
    }
    return null;
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => 0,
    };
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

/// Howard Hinnant's civil calendar conversion, shifted to the Unix epoch.
fn daysFromCivil(year: u16, month: u8, day: u8) i64 {
    var adjusted_year: i64 = year;
    adjusted_year -= @intFromBool(month <= 2);
    const era = @divFloor(adjusted_year, 400);
    const year_of_era = adjusted_year - era * 400;
    const adjusted_month: i64 = @as(i64, month) +
        (if (month > 2) @as(i64, -3) else 9);
    const day_of_year = @divFloor(153 * adjusted_month + 2, 5) + day - 1;
    const day_of_era = year_of_era * 365 + @divFloor(year_of_era, 4) -
        @divFloor(year_of_era, 100) + day_of_year;
    return era * 146_097 + day_of_era - 719_468;
}

test "cookie date accepts RFC historical formats" {
    try std.testing.expectEqual(
        @as(?i64, 784_111_777),
        parse("Sun, 06 Nov 1994 08:49:37 GMT"),
    );
    try std.testing.expectEqual(
        @as(?i64, 784_111_777),
        parse("Sunday, 06-Nov-94 08:49:37 GMT"),
    );
    try std.testing.expectEqual(
        @as(?i64, 784_111_777),
        parse("Sun Nov  6 08:49:37 1994"),
    );
}

test "cookie date validates calendar and lower year bound" {
    try std.testing.expect(parse("Thu, 29 Feb 2024 00:00:00 GMT") != null);
    try std.testing.expect(parse("Wed, 29 Feb 2023 00:00:00 GMT") == null);
    try std.testing.expect(parse("Sun, 06 Nov 1600 08:49:37 GMT") == null);
    try std.testing.expect(parse("Sun, 06 Nope 1994 08:49:37 GMT") == null);
    try std.testing.expect(parse("Sun, 06 Nov 1994 24:00:00 GMT") == null);
}

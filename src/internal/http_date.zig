const std = @import("std");
const netz_runtime = @import("../runtime.zig");

/// Length of an IMF-fixdate value such as
/// `Sun, 06 Nov 1994 08:49:37 GMT`.
pub const value_len: usize = 29;

const earliest_unix_second: i64 = 0;
const latest_unix_second: i64 = 253_402_300_799;

/// A wall-clock read is at most this stale. HTTP dates have one-second
/// resolution, and the loop's cached awake clock lets a burst of responses
/// share one `clock_gettime`.
const real_clock_refresh_ns: i64 = 1_000_000;

const Cache = struct {
    unix_second: u64 = 0,
    value: [value_len]u8 = "Thu, 01 Jan 1970 00:00:00 GMT".*,
    valid: bool = false,
    sampled_at_awake_ns: i64 = 0,
    sample_valid: bool = false,
};

threadlocal var cache: Cache = .{};

/// Return the current HTTP-date in IMF-fixdate form.
///
/// The returned pointer borrows thread-local storage. It remains valid until a
/// later call to `valueNow` on the same thread observes a different wall-clock
/// second and overwrites the cached bytes. Callers should consume or copy it
/// synchronously rather than retaining it. No allocation is performed.
///
/// The wall clock is sampled at most once per millisecond per thread, timed
/// against the runtime's cached awake clock when available. A date can
/// therefore trail the wall clock by under a millisecond, far inside its
/// one-second resolution.
pub fn valueNow(io: std.Io) *const [value_len]u8 {
    const awake_ns: i64 = std.math.cast(
        i64,
        netz_runtime.cachedAwakeNow(io).nanoseconds,
    ) orelse 0;
    if (cache.valid and cache.sample_valid and awake_ns > 0 and
        awake_ns >= cache.sampled_at_awake_ns and
        awake_ns - cache.sampled_at_awake_ns < real_clock_refresh_ns)
    {
        return &cache.value;
    }
    const seconds = std.Io.Timestamp.now(io, .real).toSeconds();
    cache.sampled_at_awake_ns = awake_ns;
    cache.sample_valid = awake_ns > 0;
    return valueAtUnixSecond(seconds);
}

fn valueAtUnixSecond(raw_unix_second: i64) *const [value_len]u8 {
    const unix_second = clampUnixSecond(raw_unix_second);
    if (!cache.valid or cache.unix_second != unix_second) {
        cache.value = formatUnixSecond(unix_second);
        cache.unix_second = unix_second;
        cache.valid = true;
    }
    return &cache.value;
}

fn clampUnixSecond(unix_second: i64) u64 {
    return @intCast(std.math.clamp(
        unix_second,
        earliest_unix_second,
        latest_unix_second,
    ));
}

fn formatUnixSecond(unix_second: u64) [value_len]u8 {
    const epoch_seconds = std.time.epoch.EpochSeconds{
        .secs = unix_second,
    };
    const epoch_day = epoch_seconds.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch_seconds.getDaySeconds();

    const weekdays = [_]*const [3]u8{
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat",
    };
    const months = [_]*const [3]u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };

    var value = "Thu, 01 Jan 1970 00:00:00 GMT".*;
    const weekday_index: usize = @intCast(
        (epoch_day.day + 4) % weekdays.len,
    );
    @memcpy(value[0..3], weekdays[weekday_index]);
    writeTwoDigits(value[5..7], month_day.day_index + 1);
    @memcpy(
        value[8..11],
        months[@intFromEnum(month_day.month) - 1],
    );
    writeFourDigits(value[12..16], year_day.year);
    writeTwoDigits(value[17..19], day_seconds.getHoursIntoDay());
    writeTwoDigits(value[20..22], day_seconds.getMinutesIntoHour());
    writeTwoDigits(value[23..25], day_seconds.getSecondsIntoMinute());
    return value;
}

fn writeTwoDigits(destination: *[2]u8, value: anytype) void {
    const number: u8 = @intCast(value);
    destination[0] = '0' + number / 10;
    destination[1] = '0' + number % 10;
}

fn writeFourDigits(destination: *[4]u8, value: anytype) void {
    const number: u16 = @intCast(value);
    destination[0] = '0' + @as(u8, @intCast(number / 1000));
    destination[1] = '0' + @as(u8, @intCast(number / 100 % 10));
    destination[2] = '0' + @as(u8, @intCast(number / 10 % 10));
    destination[3] = '0' + @as(u8, @intCast(number % 10));
}

test "HTTP date renders IMF-fixdate calendar boundaries" {
    try std.testing.expectEqualStrings(
        "Thu, 01 Jan 1970 00:00:00 GMT",
        &formatUnixSecond(0),
    );
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        &formatUnixSecond(784_111_777),
    );
    try std.testing.expectEqualStrings(
        "Tue, 29 Feb 2000 00:00:00 GMT",
        &formatUnixSecond(951_782_400),
    );
    try std.testing.expectEqualStrings(
        "Fri, 31 Dec 9999 23:59:59 GMT",
        &formatUnixSecond(latest_unix_second),
    );
}

test "HTTP date changes exactly at a second boundary" {
    try std.testing.expectEqualStrings(
        "Thu, 01 Jan 1970 23:59:59 GMT",
        &formatUnixSecond(86_399),
    );
    try std.testing.expectEqualStrings(
        "Fri, 02 Jan 1970 00:00:00 GMT",
        &formatUnixSecond(86_400),
    );
}

test "HTTP date reuses the cached value within one second" {
    cache = .{};
    defer cache = .{};

    const first = valueAtUnixSecond(784_111_777);
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:37 GMT",
        first,
    );
    // A same-second lookup must not render again. Mutating the private cache
    // makes that observable without depending on wall-clock timing.
    cache.value[0] = 'X';
    const reused = valueAtUnixSecond(784_111_777);
    try std.testing.expectEqual(@as(u8, 'X'), reused[0]);

    const refreshed = valueAtUnixSecond(784_111_778);
    try std.testing.expectEqualStrings(
        "Sun, 06 Nov 1994 08:49:38 GMT",
        refreshed,
    );
}

test "HTTP date clamps unsupported wall-clock years" {
    cache = .{};
    defer cache = .{};
    try std.testing.expectEqualStrings(
        "Thu, 01 Jan 1970 00:00:00 GMT",
        valueAtUnixSecond(-1),
    );
    try std.testing.expectEqualStrings(
        "Fri, 31 Dec 9999 23:59:59 GMT",
        valueAtUnixSecond(std.math.maxInt(i64)),
    );
}

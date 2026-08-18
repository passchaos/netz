//! Versioned binary record helpers shared by MQTT persistence sections.

const std = @import("std");
const mqtt = @import("../mod.zig");
const wire = @import("../../internal/wire.zig");

pub const Error = mqtt.Error || wire.Error || error{
    CorruptSnapshot,
    SnapshotLimitExceeded,
    UnsupportedSnapshotVersion,
} || std.mem.Allocator.Error;

pub const max_blob_bytes: usize = 64 * 1024 * 1024;

pub fn appendInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: T,
) Error!void {
    wire.appendInt(out, allocator, T, value, .big) catch |err|
        return @errorCast(err);
}

pub fn appendBool(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: bool,
) Error!void {
    try out.append(allocator, @intFromBool(value));
}

pub fn appendOptionalInt(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    comptime T: type,
    value: ?T,
) Error!void {
    try appendBool(out, allocator, value != null);
    if (value) |present| try appendInt(out, allocator, T, present);
}

pub fn appendBlob(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    bytes: []const u8,
) Error!void {
    if (bytes.len > max_blob_bytes) return error.SnapshotLimitExceeded;
    try appendInt(out, allocator, u32, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

pub fn appendProperties(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    properties: []const mqtt.Property,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try mqtt.writeProperties(&encoded, allocator, properties);
    try appendBlob(out, allocator, encoded.items);
}

pub const Cursor = struct {
    inner: wire.Cursor,

    pub fn init(bytes: []const u8) Cursor {
        return .{ .inner = .init(bytes) };
    }

    pub fn eof(self: Cursor) bool {
        return self.inner.eof();
    }

    pub fn readInt(
        self: *Cursor,
        comptime T: type,
    ) Error!T {
        return self.inner.readInt(T, .big) catch
            return error.CorruptSnapshot;
    }

    pub fn readBool(self: *Cursor) Error!bool {
        return switch (try self.readInt(u8)) {
            0 => false,
            1 => true,
            else => error.CorruptSnapshot,
        };
    }

    pub fn readOptionalInt(
        self: *Cursor,
        comptime T: type,
    ) Error!?T {
        return if (try self.readBool())
            try self.readInt(T)
        else
            null;
    }

    pub fn readBlob(self: *Cursor) Error![]const u8 {
        const len = try self.readInt(u32);
        if (len > max_blob_bytes) return error.SnapshotLimitExceeded;
        return self.inner.readSlice(len) catch
            return error.CorruptSnapshot;
    }

    pub fn readProperties(
        self: *Cursor,
        allocator: std.mem.Allocator,
    ) Error![]mqtt.Property {
        const encoded = try self.readBlob();
        var cursor = wire.Cursor.init(encoded);
        const properties = mqtt.parseProperties(
            allocator,
            &cursor,
        ) catch |err| return @errorCast(err);
        errdefer allocator.free(properties);
        if (!cursor.eof()) return error.CorruptSnapshot;
        return properties;
    }

    pub fn finish(self: Cursor) Error!void {
        if (!self.eof()) return error.CorruptSnapshot;
    }
};

pub fn qosFromByte(value: u8) Error!mqtt.QoS {
    return std.enums.fromInt(mqtt.QoS, value) orelse
        error.CorruptSnapshot;
}

pub fn elapsedDowntimeNs(
    saved_realtime_ns: i64,
    restore_realtime_ns: i64,
) i96 {
    return @max(
        @as(i96, restore_realtime_ns) -
            @as(i96, saved_realtime_ns),
        0,
    );
}

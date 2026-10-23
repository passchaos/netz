//! Will checkpoint records and restoration validation.
//! Missing Will Delay means zero; absent Message Expiry remains distinct from
//! an explicit zero expiry. Keep owned properties in their original form.

const std = @import("std");
const mqtt = @import("../mod.zig");
const will = @import("mod.zig");
const persistence = @import("../persistence/codec.zig");

pub fn write(
    self: *will.Scheduler,
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    now: std.Io.Timestamp,
    publishers: *const will.PublisherMap,
    include_connected: bool,
) (will.Error || persistence.Error)!void {
    var snapshot_count: u32 = 0;
    for (self.entries.items) |maybe_entry| {
        const entry = maybe_entry orelse continue;
        if (entry.state == .due or
            (entry.state == .connected and !include_connected) or
            (entry.state == .scheduled and entry.heap_index == null))
        {
            return error.SnapshotBusy;
        }
        snapshot_count = std.math.add(
            u32,
            snapshot_count,
            1,
        ) catch return error.SnapshotLimitExceeded;
    }
    try persistence.appendInt(out, allocator, u32, snapshot_count);
    for (self.entries.items, 0..) |maybe_entry, index| {
        const entry = maybe_entry orelse continue;
        const handle = will.Handle{
            .index = index,
            .generation = entry.generation,
        };
        const publisher_id = publishers.get(handle) orelse
            return error.CorruptSnapshot;
        try persistence.appendBlob(out, allocator, entry.client_id);
        try persistence.appendBool(
            out,
            allocator,
            entry.source_username != null,
        );
        if (entry.source_username) |value| {
            try persistence.appendBlob(out, allocator, value);
        }
        try persistence.appendOptionalInt(
            out,
            allocator,
            u64,
            entry.source_listener_id,
        );
        try persistence.appendBlob(out, allocator, entry.topic);
        try persistence.appendBlob(out, allocator, entry.payload);
        try persistence.appendInt(
            out,
            allocator,
            u8,
            @intFromEnum(entry.qos),
        );
        try persistence.appendBool(out, allocator, entry.retain);
        try persistence.appendProperties(
            out,
            allocator,
            entry.properties,
        );
        try persistence.appendInt(
            out,
            allocator,
            u32,
            entry.will_delay_interval,
        );
        try persistence.appendOptionalInt(
            out,
            allocator,
            u32,
            entry.message_expiry_interval,
        );
        try persistence.appendInt(
            out,
            allocator,
            u32,
            entry.session_expiry_interval,
        );
        try persistence.appendInt(
            out,
            allocator,
            u64,
            @intCast(if (entry.state == .connected)
                @as(i96, effectiveDelay(
                    entry.will_delay_interval,
                    entry.session_expiry_interval,
                )) * std.time.ns_per_s
            else
                @max(entry.deadline_ns - now.nanoseconds, 0)),
        );
        try persistence.appendOptionalInt(
            out,
            allocator,
            u64,
            publisher_id,
        );
    }
}

pub fn restore(
    self: *will.Scheduler,
    cursor: *persistence.Cursor,
    restore_now: std.Io.Timestamp,
    downtime_ns: i96,
    restored_publishers: *will.PublisherMap,
) (will.Error || persistence.Error)!void {
    const snapshot_count = try cursor.readInt(u32);
    if (snapshot_count > self.options.max_wills) {
        return error.WillLimitExceeded;
    }
    const map_capacity = std.math.cast(
        u32,
        self.options.max_wills,
    ) orelse return error.WillLimitExceeded;
    try restored_publishers.ensureTotalCapacity(
        self.allocator,
        map_capacity,
    );
    for (0..snapshot_count) |_| {
        const client_id = try cursor.readBlob();
        const source_username = if (try cursor.readBool())
            try cursor.readBlob()
        else
            null;
        const source_listener_id = try cursor.readOptionalInt(u64);
        const topic = try cursor.readBlob();
        const payload = try cursor.readBlob();
        const qos = try persistence.qosFromByte(
            try cursor.readInt(u8),
        );
        const retain = try cursor.readBool();
        const properties = try cursor.readProperties(self.allocator);
        defer self.allocator.free(properties);
        const will_delay_interval = try cursor.readInt(u32);
        const message_expiry_interval =
            try cursor.readOptionalInt(u32);
        const session_expiry_interval = try cursor.readInt(u32);
        const saved_remaining_ns = try cursor.readInt(u64);
        const maximum_delay_ns = @as(u64, effectiveDelay(
            will_delay_interval,
            session_expiry_interval,
        )) * std.time.ns_per_s;
        if (saved_remaining_ns > maximum_delay_ns) {
            return error.CorruptSnapshot;
        }
        const remaining_ns = saved_remaining_ns -|
            @as(u64, @intCast(@min(
                @max(downtime_ns, 0),
                std.math.maxInt(u64),
            )));
        const publisher_id = try cursor.readOptionalInt(u64);
        if (self.client_index.contains(client_id) or
            (mqtt.willDelayInterval(properties) orelse 0) !=
                will_delay_interval or
            mqtt.messageExpiryInterval(properties) !=
                message_expiry_interval)
        {
            return error.CorruptSnapshot;
        }
        const handle = try self.setWithSource(
            client_id,
            .{
                .topic = topic,
                .payload = payload,
                .qos = qos,
                .retain = retain,
                .properties = properties,
            },
            source_username,
            source_listener_id,
            session_expiry_interval,
        );
        const entry = &self.entries.items[handle.index].?;
        entry.state = .scheduled;
        entry.deadline_ns = std.math.add(
            i96,
            restore_now.nanoseconds,
            remaining_ns,
        ) catch std.math.maxInt(i96);
        self.heap.appendAssumeCapacity(self, handle.index);
        restored_publishers.putAssumeCapacityNoClobber(
            handle,
            publisher_id,
        );
    }
}

fn effectiveDelay(will_delay: u32, session_expiry: u32) u32 {
    return @min(will_delay, session_expiry);
}

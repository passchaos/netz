//! Apply a complete validated EDS response before advancing its ADS version.
const std = @import("std");
const ads = @import("../ads.zig");
const resource = @import("decode.zig");
const target = @import("target.zig");
const shared = @import("../../channel/shared.zig");
pub const Error = target.Error || ads.Error || error{ WrongEdsResource, DuplicateEdsResource };

pub fn publishWithDeadline(client: *ads.Client, update: ads.Update, resource_name: []const u8, destination: shared.SharedChannel, options: target.Options, limits: resource.Limits, deadline: std.Io.Clock.Timestamp) Error!u64 {
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    try client.validateUpdate(update);
    if (!std.mem.eql(u8, update.response.value.type_url, resource.type_url)) return error.WrongEdsResource;
    var candidates: std.ArrayList(*target.Snapshot) = .empty;
    defer {
        for (candidates.items) |snapshot| snapshot.release();
        candidates.deinit(client.allocator);
    }
    var selected: ?*target.Snapshot = null;
    for (update.response.value.resources) |value| {
        const snapshot = try target.Snapshot.create(client.allocator, value.value, limits, options);
        errdefer snapshot.release();
        const name = snapshot.resource.value.cluster_name;
        for (candidates.items) |previous| if (std.mem.eql(u8, previous.resource.value.cluster_name, name)) return error.DuplicateEdsResource;
        try candidates.append(client.allocator, snapshot);
        if (std.mem.eql(u8, name, resource_name)) selected = snapshot;
    }
    if (selected == null) {
        // SotW omission removes the requested assignment. Create an empty
        // typed resource using only its cluster_name protobuf field.
        var writer: std.Io.Writer.Allocating = .init(client.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var len = resource_name.len;
        while (len >= 128) : (len >>= 7) writer.writer.writeByte(@as(u8, @truncate(len)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(len)) catch return error.OutOfMemory;
        writer.writer.writeAll(resource_name) catch return error.OutOfMemory;
        const empty = try target.Snapshot.create(client.allocator, writer.written(), limits, options);
        errdefer empty.release();
        try candidates.append(client.allocator, empty);
        selected = empty;
    }
    const revision = try selected.?.publishWithDeadline(destination, deadline);
    // Publication is authoritative even if the remaining ACK budget expires.
    // This mutation allocates nothing after prior validation under one caller.
    try client.acceptAppliedUpdate(update);
    _ = try client.flushWithDeadline(deadline);
    return revision;
}

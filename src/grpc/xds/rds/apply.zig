//! Complete resource validation precedes selector publication and ADS acceptance.
const std = @import("std");
const ads = @import("../ads.zig");
const model = @import("model.zig");
const target = @import("snapshot.zig");
const shared = @import("../../channel/shared.zig");
pub const Error = target.Error || shared.Error || ads.Error || error{ WrongRdsResource, DuplicateRdsResource };
pub fn publishWithDeadline(client: *ads.Client, update: ads.Update, name: []const u8, destination: shared.SharedChannel, options: target.Options, limits: model.Limits, deadline: std.Io.Clock.Timestamp) Error!u64 {
    _ = try @import("../../../internal/deadline.zig").usableAwake(client.sender.state.io, deadline);
    try client.validateUpdate(update);
    if (!std.mem.eql(u8, update.response.value.type_url, model.type_url)) return error.WrongRdsResource;
    var candidates: std.ArrayList(*target.Snapshot) = .empty;
    defer {
        for (candidates.items) |snapshot| snapshot.release();
        candidates.deinit(client.allocator);
    }
    var selected: ?*target.Snapshot = null;
    var storage_bytes: usize = 0;
    for (update.response.value.resources) |raw| {
        const snapshot = try target.Snapshot.create(client.allocator, raw.value, limits, options);
        errdefer snapshot.release();
        storage_bytes = std.math.add(usize, storage_bytes, snapshot.resource.arena.queryCapacity()) catch return error.RdsLimitExceeded;
        if (storage_bytes > limits.max_storage_bytes) return error.RdsLimitExceeded;
        try candidates.append(client.allocator, snapshot);
        if (std.mem.eql(u8, name, snapshot.resource.value.name)) selected = snapshot;
    }
    const names = try client.allocator.dupe(*target.Snapshot, candidates.items);
    defer client.allocator.free(names);
    std.mem.sort(*target.Snapshot, names, {}, struct {
        fn less(_: void, a: *target.Snapshot, b: *target.Snapshot) bool {
            return std.mem.order(u8, a.resource.value.name, b.resource.value.name) == .lt;
        }
    }.less);
    if (names.len > 1) for (names[1..], 0..) |value, index| if (std.mem.eql(u8, value.resource.value.name, names[index].resource.value.name)) return error.DuplicateRdsResource;
    if (selected == null) {
        var writer: std.Io.Writer.Allocating = .init(client.allocator);
        defer writer.deinit();
        writer.writer.writeByte(10) catch return error.OutOfMemory;
        var length = name.len;
        while (length >= 128) : (length >>= 7) writer.writer.writeByte(@as(u8, @truncate(length)) | 0x80) catch return error.OutOfMemory;
        writer.writer.writeByte(@intCast(length)) catch return error.OutOfMemory;
        writer.writer.writeAll(name) catch return error.OutOfMemory;
        const empty = try target.Snapshot.create(client.allocator, writer.written(), limits, options);
        errdefer empty.release();
        storage_bytes = std.math.add(usize, storage_bytes, empty.resource.arena.queryCapacity()) catch return error.RdsLimitExceeded;
        if (storage_bytes > limits.max_storage_bytes) return error.RdsLimitExceeded;
        try candidates.append(client.allocator, empty);
        selected = empty;
    }
    const revision = try selected.?.publishWithDeadline(destination, deadline);
    try client.acceptAppliedUpdate(update);
    _ = try client.flushWithDeadline(deadline);
    return revision;
}

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
    // RDS/EDS SotW responses may contain only changed resources. Omission
    // leaves the accepted target/selector intact, including initial discovery.
    const revision = if (selected) |snapshot|
        try snapshot.publishWithDeadline(destination, deadline)
    else
        try @import("../publication.zig").unchangedRevisionWithDeadline(destination, deadline);
    try client.acceptAppliedUpdate(update);
    _ = try client.flushWithDeadline(deadline);
    return revision;
}

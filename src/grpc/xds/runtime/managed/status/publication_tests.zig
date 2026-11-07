//! A publisher failure cannot accept an identical resource at a new version.
const std = @import("std");
const grpc = @import("../../../../mod.zig");
const managed = @import("../../managed.zig");
const ads = @import("../../../ads.zig");
const delta = @import("../../../ads/delta.zig");
const Projection = @import("../../../lds/projection.zig").Projection;
const Error = @import("../../errors.zig").PublishError;
const t = @import("testing.zig");
const gpa = t.gpa;
const Failed = struct {
    fn sotw(_: *anyopaque, _: *ads.Client, _: *Projection, _: grpc.SharedChannel, _: std.Io.Clock.Timestamp) Error!u64 {
        return error.AdsNotConnected;
    }
    fn deltaMode(_: *anyopaque, _: *delta.Client, _: *Projection, _: grpc.SharedChannel, _: std.Io.Clock.Timestamp) Error!u64 {
        return error.AdsNotConnected;
    }
};
fn publication(comptime mode: managed.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    var h = try t.Harness(mode).initWithDataErrors(threaded.io(), true);
    defer h.deinit();
    try h.graph();
    const before = try h.snapshot("");
    defer gpa.free(before);
    const revision = h.data.configurationRevision();
    const generation = h.facade.controller.resource_commit_generation;
    const listener = try t.lds_fixture.encode(gpa, .{ .name = t.names.listener, .route_name = t.names.routes });
    defer gpa.free(listener);
    var event = try h.event(.{ .url = t.lds.type_url, .name = t.names.listener, .version = "l2", .bytes = listener });
    defer event.deinit();
    if (mode == .sotw) {
        const previous = h.facade.controller.listener.?.options.publisher;
        defer h.facade.controller.listener.?.options.publisher = previous;
        h.facade.controller.listener.?.options.publisher = .{ .context = h.facade.controller, .publish_fn = Failed.sotw };
        try std.testing.expectError(error.AdsNotConnected, h.facade.applyWithDeadline(&event, t.names.deadline(h.io)));
    } else {
        const previous = h.facade.controller.listener.?.options.delta_publisher;
        defer h.facade.controller.listener.?.options.delta_publisher = previous;
        h.facade.controller.listener.?.options.delta_publisher = .{ .context = h.facade.controller, .publish_fn = Failed.deltaMode };
        try std.testing.expectError(error.AdsNotConnected, h.facade.applyWithDeadline(&event, t.names.deadline(h.io)));
    }
    try std.testing.expectEqual(generation, h.facade.controller.resource_commit_generation);
    try std.testing.expectEqual(revision, h.data.configurationRevision());
    const after = try h.snapshot("");
    defer gpa.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    const dump = try t.decode(after);
    defer dump.deinit();
    try std.testing.expectEqualStrings("l1", dump.find(t.lds.type_url, t.names.listener).?.version);
    try event.session.client.validateUpdate((try event.result).update);
}
test "gRPC federated CSDS SotW publisher failure preserves identical resource history" {
    try publication(.sotw);
}
test "gRPC federated CSDS delta publisher failure preserves identical resource history" {
    try publication(.delta);
}

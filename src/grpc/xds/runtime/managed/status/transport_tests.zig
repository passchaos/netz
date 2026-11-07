//! FetchClientStatus exposes the complete managed inventory over real HTTP/2.
const std = @import("std");
const grpc = @import("../../../../mod.zig");
const managed = @import("../../managed.zig");
const service = @import("../../../csds_service.zig");
const t = @import("testing.zig");
const gpa = t.gpa;

fn transport(comptime mode: managed.Mode) !void {
    var threaded = std.Io.Threaded.init(gpa, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var h = try t.Harness(mode).init(io);
    defer h.deinit();
    try h.graph();
    const invalid = try t.cds_fixture.cluster(gpa, t.names.cluster_a, t.names.endpoint_a, "\xd2\x02\x02\x1a\x00");
    defer gpa.free(invalid);
    var rejected = try h.event(.{ .url = t.cds.type_url, .name = t.names.cluster_a, .version = "bad-a", .bytes = invalid });
    defer rejected.deinit();
    try std.testing.expectError(error.UnsupportedCdsFeature, h.facade.applyWithDeadline(&rejected, t.names.deadline(io)));
    try std.testing.expectError(error.AdsNotConnected, h.facade.rejectWithDeadline(&rejected, "invalid source A", t.names.deadline(io)));
    var server = try grpc.runtime.Server.listen(gpa, io, .{ .ip4 = .loopback(0) }, .{ .max_frame_payload = 4096, .max_body_bytes = 16384 }, 1024);
    defer server.deinit();
    const Peer = struct {
        fn run(listener: *grpc.runtime.Server, discovery: *managed.Managed(mode)) !void {
            var connection = try listener.acceptWithTimeout(.fromSeconds(5));
            defer connection.deinit();
            for (0..3) |_| {
                var request = try connection.readUnaryWithTimeout(.fromSeconds(5));
                defer request.deinit();
                if (!try service.respondManagedFetch(&connection, &request, discovery, gpa, "")) {
                    try connection.writeUnary(request.request.stream_id, .{ .message = "other" });
                }
            }
        }
    };
    var peer = io.async(Peer.run, .{ &server, h.facade });
    defer _ = peer.cancel(io) catch {};
    var client = try grpc.runtime.Client.connect(gpa, io, server.address(), .{ .max_frame_payload = 4096, .max_body_bytes = 16384 });
    defer client.deinit();
    for ([_][]const u8{ "", "\x18\x01" }, 0..) |body, index| {
        var response = try client.unary(.{ .path = service.fetch_path, .authority = "localhost", .message = body, .timeout = .{ .value = 5, .unit = .second } });
        defer response.deinit();
        try std.testing.expectEqual(grpc.Status.ok, response.status);
        const dump = try t.decode(response.message.?.payload);
        defer dump.deinit();
        try std.testing.expectEqual(@as(usize, 6), dump.resources.len);
        try std.testing.expectEqualStrings("grpc", dump.scope);
        const a = dump.find(t.cds.type_url, t.names.cluster_a) orelse return error.MissingSourceA;
        const b = dump.find(t.cds.type_url, t.names.cluster_b) orelse return error.MissingSourceB;
        try std.testing.expectEqualStrings("ca1", a.version);
        try std.testing.expectEqualStrings("cb1", b.version);
        try std.testing.expectEqual(@import("../../../csds.zig").ClientStatus.nacked, a.status);
        try std.testing.expectEqual(@import("../../../csds.zig").ClientStatus.acked, b.status);
        try std.testing.expectEqualStrings("bad-a", a.error_state.?.version_info);
        try std.testing.expectEqualStrings("invalid source A", a.error_state.?.details);
        try std.testing.expect(a.error_state.?.last_update_attempt != null);
        try std.testing.expect(b.error_state == null);
        for (dump.resources) |resource| {
            try std.testing.expectEqual(index == 0, resource.wire.len != 0);
            try std.testing.expect(resource.last_updated_seconds != null);
        }
    }
    var other = try client.unary(.{ .path = "/demo.Service/Other", .authority = "localhost", .message = "", .timeout = .{ .value = 5, .unit = .second } });
    defer other.deinit();
    try std.testing.expectEqualStrings("other", other.message.?.payload);
    try peer.await(io);
}

test "gRPC federated CSDS SotW FetchClientStatus serves both authorities and NACKs" {
    try transport(.sotw);
}
test "gRPC federated CSDS delta FetchClientStatus serves both authorities and NACKs" {
    try transport(.delta);
}

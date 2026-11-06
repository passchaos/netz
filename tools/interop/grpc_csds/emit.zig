//! Emit one CSDS ClientStatusResponse for the independent proto gate.
const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const resources = [_]netz.grpc.xds.csds.Resource{
        .{
            .type_url = "type.googleapis.com/envoy.config.listener.v3.Listener",
            .name = "frontend",
            .version = "v1",
            .wire = "\x0a\x08frontend",
            .status = .acked,
        },
        .{
            .type_url = "type.googleapis.com/envoy.config.cluster.v3.Cluster",
            .name = "a",
            .version = "v2",
            .wire = "\x0a\x01a",
            .status = .acked,
        },
        .{
            .type_url = "type.googleapis.com/envoy.config.endpoint.v3.ClusterLoadAssignment",
            .name = "eds-a",
            .status = .requested,
        },
    };
    const encoded = try netz.grpc.xds.csds.encodeResponse(allocator, &resources, .{
        .node = "\x0a\x06node-1",
    });
    defer allocator.free(encoded);
    const base64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(encoded.len));
    defer allocator.free(base64);
    _ = std.base64.standard.Encoder.encode(base64, encoded);
    std.debug.print("{s}\n", .{base64});
}

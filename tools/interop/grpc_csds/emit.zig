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
            .last_updated_seconds = 1760000000,
            .last_updated_nanos = 123456789,
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

    // A request with exclude_resource_contents=true keeps metadata but drops
    // the resource wire bytes.
    const request = try netz.grpc.xds.csds.decodeRequest("\x18\x01");
    const excluded = try netz.grpc.xds.csds.encodeResponse(allocator, &resources, .{
        .node = "\x0a\x06node-1",
        .exclude_resource_contents = request.exclude_resource_contents,
    });
    defer allocator.free(excluded);
    const excluded_base64 = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(excluded.len));
    defer allocator.free(excluded_base64);
    _ = std.base64.standard.Encoder.encode(excluded_base64, excluded);
    std.debug.print("{s}\n", .{excluded_base64});
}

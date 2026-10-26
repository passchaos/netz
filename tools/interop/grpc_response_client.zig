//! Native client for the independent HTTP/2 response-policy peer.
const std = @import("std");
const netz = @import("netz");

const Probe = struct { path: []const u8, status: u8, messages: usize, payload: []const u8, details: bool = false };
const Collector = struct {
    probe: Probe,
    count: usize = 0,
    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        try std.testing.expectEqualStrings(self.probe.payload, message.payload);
        self.count += 1;
    }
};
fn check(response: anytype, probe: Probe, count: usize) !void {
    try std.testing.expectEqual(probe.status, @intFromEnum(response.status));
    try std.testing.expectEqual(probe.messages, count);
    try std.testing.expectEqual(probe.details, response.status_details != null);
    if (probe.details) try std.testing.expectEqualSlices(u8, "\x08\x07", response.status_details.?.bytes);
    try std.testing.expect(response.reset == null);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    const manifest = try std.Io.Dir.cwd().readFileAlloc(io, args[2], allocator, .limited(64 * 1024));
    defer allocator.free(manifest);
    var probes = try std.json.parseFromSlice([]const Probe, allocator, manifest, .{});
    defer probes.deinit();
    var client = try netz.grpc.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(port) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.deinit();
    for (probes.value) |probe| {
        var response = try client.unary(.{ .path = probe.path, .message = "", .timeout = .{ .value = 5, .unit = .second } });
        defer response.deinit();
        try check(response, probe, @intFromBool(response.message != null));
        if (response.message) |message| try std.testing.expectEqualStrings(probe.payload, message.payload);
    }
    for (probes.value) |probe| {
        var stream = try client.startStreaming(.{ .path = probe.path, .timeout = .{ .value = 5, .unit = .second } });
        defer stream.deinit();
        try stream.writeMessage("");
        var collector: Collector = .{ .probe = probe };
        var response = try stream.finishAndRead(&collector, Collector.consume);
        defer response.deinit();
        try check(response, probe, collector.count);
    }
    for (probes.value) |probe| {
        var stream = try client.startDuplex(.{ .path = probe.path, .timeout = .{ .value = 5, .unit = .second } });
        defer stream.deinit();
        try std.testing.expectEqual(netz.grpc.DuplexWriteResult.complete, try stream.writeMessage(""));
        try std.testing.expectEqual(netz.grpc.DuplexWriteResult.complete, try stream.finishRequest());
        var collector: Collector = .{ .probe = probe };
        while (true) {
            var event = try stream.readResponseEvent(&collector, Collector.consume);
            defer event.deinit(allocator);
            if (event == .terminal) {
                try check(event.terminal, probe, collector.count);
                break;
            }
        }
    }
    std.debug.print("netz gRPC response policy complete io=zio-std-io cases={d} shapes=unary+streaming+duplex reuse=true\n", .{probes.value.len});
}

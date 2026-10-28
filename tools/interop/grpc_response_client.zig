//! Native client for the independent HTTP/2 response-policy peer.
const std = @import("std");
const netz = @import("netz");

const Probe = struct { path: []const u8, status: u8, messages: usize, payload: []const u8, details: bool = false, authority: ?[]const u8 = null, host: ?[]const u8 = null, request_payload: []const u8 = "", unary_only: bool = false, status_message: ?[]const u8 = null, shared_probe: bool = false, read_delay_ms: u32 = 0 };
const Collector = struct {
    probe: Probe,
    count: usize = 0,
    fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
        try std.testing.expectEqualStrings(self.probe.payload, message.payload);
        self.count += 1;
    }
};
fn requestHeaders(probe: Probe, storage: *[1]netz.http2.Hpack.HeaderField) []const netz.http2.Hpack.HeaderField {
    if (probe.host) |host| {
        storage[0] = .{ .name = "host", .value = host };
        return storage;
    }
    return &.{};
}

fn check(response: anytype, probe: Probe, count: usize) !void {
    try std.testing.expectEqual(probe.status, @intFromEnum(response.status));
    try std.testing.expectEqual(probe.messages, count);
    try std.testing.expectEqual(probe.details, response.status_details != null);
    if (probe.details) try std.testing.expectEqualSlices(u8, "\x08\x07", response.status_details.?.bytes);
    try std.testing.expect(response.reset == null);
    if (probe.status_message) |expected| try std.testing.expectEqualStrings(expected, response.status_message);
}

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    const manifest = try std.Io.Dir.cwd().readFileAlloc(io, args[2], allocator, .limited(256 * 1024));
    defer allocator.free(manifest);
    var probes = try std.json.parseFromSlice([]const Probe, allocator, manifest, .{});
    defer probes.deinit();
    var client = try netz.grpc.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(port) }, .{ .max_frame_payload = 4096, .max_body_bytes = 4096 });
    defer client.deinit();
    for (probes.value) |probe| {
        var storage: [1]netz.http2.Hpack.HeaderField = undefined;
        const metadata = requestHeaders(probe, &storage);
        var response = try client.unary(.{ .path = probe.path, .authority = probe.authority, .metadata = metadata, .message = probe.request_payload, .timeout = .{ .value = 5, .unit = .second } });
        defer response.deinit();
        try check(response, probe, @intFromBool(response.message != null));
        if (response.message) |message| try std.testing.expectEqualStrings(probe.payload, message.payload);
        if (probe.unary_only) try std.testing.expectEqualStrings("yes", netz.grpc.call.headerValue(response.transport.?.trailers, "x-early").?);
    }
    for (probes.value) |probe| {
        if (probe.unary_only) continue;
        var storage: [1]netz.http2.Hpack.HeaderField = undefined;
        const metadata = requestHeaders(probe, &storage);
        var stream = try client.startStreaming(.{ .path = probe.path, .authority = probe.authority, .metadata = metadata, .timeout = .{ .value = 5, .unit = .second } });
        defer stream.deinit();
        try stream.writeMessage("");
        var collector: Collector = .{ .probe = probe };
        var response = try stream.finishAndRead(&collector, Collector.consume);
        defer response.deinit();
        try check(response, probe, collector.count);
    }
    for (probes.value) |probe| {
        if (probe.unary_only) continue;
        var storage: [1]netz.http2.Hpack.HeaderField = undefined;
        const metadata = requestHeaders(probe, &storage);
        var stream = try client.startDuplex(.{ .path = probe.path, .authority = probe.authority, .metadata = metadata, .timeout = .{ .value = 5, .unit = .second } });
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
    var channel = try netz.grpc.SharedChannel.init(allocator, io, .{
        .cleartext_ip = .{
            .address = .{ .ip4 = .loopback(port) },
            .limits = .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        },
    }, .{});
    defer channel.deinit();
    var sender = channel.sender();
    defer sender.deinit();
    var shared_count: usize = 0;
    for (probes.value) |probe| {
        if (!probe.shared_probe) continue;
        var storage: [1]netz.http2.Hpack.HeaderField = undefined;
        const metadata = requestHeaders(probe, &storage);
        var rpc = try sender.startDuplex(.{
            .path = probe.path,
            .authority = probe.authority,
            .metadata = metadata,
            .timeout = .{ .value = 500, .unit = .millisecond },
            .wait_for_ready = true,
        });
        defer rpc.deinit();
        var writer = rpc.writer();
        defer writer.deinit();
        var reader = rpc.reader();
        defer reader.deinit();
        try writer.writeFinalMessage(probe.request_payload);
        try std.Io.sleep(io, .fromMilliseconds(probe.read_delay_ms), .awake);
        try std.testing.expect(rpc.call.deadline.?.durationFromNow(io).raw.nanoseconds <= 0);
        var collector: Collector = .{ .probe = probe };
        while (true) {
            var event = try reader.next();
            defer event.deinit(allocator);
            switch (event) {
                .message => |message| {
                    try std.testing.expectEqualStrings(probe.payload, message.payload);
                    collector.count += 1;
                },
                .terminal => |response| {
                    try check(response, probe, collector.count);
                    break;
                },
                else => {},
            }
        }
        shared_count += 1;
    }
    std.debug.print("netz gRPC response policy complete io=zio-std-io cases={d} shared={d} shapes=unary+streaming+duplex+shared reuse=true\n", .{ probes.value.len, shared_count });
}

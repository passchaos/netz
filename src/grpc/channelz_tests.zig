//! Focused Channelz registry, pagination and wire-codec regressions.
const std = @import("std");
const channelz = @import("channelz.zig");
const pb = @import("protobuf.zig");
const runtime = @import("runtime.zig");
const wire = @import("wire.zig");
const gpa = std.testing.allocator;

const DecodedChannel = struct {
    id: i64,
    name: []const u8,
    target: []const u8,
    state: u32,
    started: i64,
    succeeded: i64,
    failed: i64,
    last_call_started: ?Timestamp,
};

const DecodedServer = struct {
    id: i64,
    name: []const u8,
    started: i64,
    succeeded: i64,
    failed: i64,
    last_call_started: ?Timestamp,
};

const Timestamp = struct { seconds: i64, nanos: u32 };

const Dump = struct {
    channels: []DecodedChannel = &.{},
    servers: []DecodedServer = &.{},
    end: bool = false,
    single_channel: ?DecodedChannel = null,
    single_server: ?DecodedServer = null,

    fn deinit(self: Dump) void {
        if (self.channels.len != 0) gpa.free(self.channels);
        if (self.servers.len != 0) gpa.free(self.servers);
    }
};

fn decodeTopChannels(bytes: []const u8) !Dump {
    var reader = pb.Reader{ .bytes = bytes };
    var values: std.ArrayList(DecodedChannel) = .empty;
    errdefer values.deinit(gpa);
    var result = Dump{};
    while (try reader.next()) |field| switch (field.number) {
        1 => try values.append(gpa, try decodeChannel(try reader.bytesValue())),
        2 => result.end = (try reader.varint()) != 0,
        else => try reader.skip(field),
    };
    result.channels = try values.toOwnedSlice(gpa);
    return result;
}

fn decodeServers(bytes: []const u8) !Dump {
    var reader = pb.Reader{ .bytes = bytes };
    var values: std.ArrayList(DecodedServer) = .empty;
    errdefer values.deinit(gpa);
    var result = Dump{};
    while (try reader.next()) |field| switch (field.number) {
        1 => try values.append(gpa, try decodeServer(try reader.bytesValue())),
        2 => result.end = (try reader.varint()) != 0,
        else => try reader.skip(field),
    };
    result.servers = try values.toOwnedSlice(gpa);
    return result;
}

fn decodeChannelResponse(bytes: []const u8) !Dump {
    var reader = pb.Reader{ .bytes = bytes };
    var result = Dump{};
    while (try reader.next()) |field| switch (field.number) {
        1 => result.single_channel = try decodeChannel(try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return result;
}

fn decodeServerResponse(bytes: []const u8) !Dump {
    var reader = pb.Reader{ .bytes = bytes };
    var result = Dump{};
    while (try reader.next()) |field| switch (field.number) {
        1 => result.single_server = try decodeServer(try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return result;
}

fn decodeChannel(bytes: []const u8) !DecodedChannel {
    var reader = pb.Reader{ .bytes = bytes };
    var value = DecodedChannel{
        .id = 0,
        .name = "",
        .target = "",
        .state = 0,
        .started = 0,
        .succeeded = 0,
        .failed = 0,
        .last_call_started = null,
    };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            var ref = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try ref.next()) |item| switch (item.number) {
                1 => value.id = @bitCast(try ref.varint()),
                2 => value.name = try ref.string(),
                else => try ref.skip(item),
            };
        },
        2 => {
            var data = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try data.next()) |item| switch (item.number) {
                1 => {
                    var state = pb.Reader{ .bytes = try data.bytesValue() };
                    while (try state.next()) |entry| switch (entry.number) {
                        1 => value.state = @intCast(try state.varint()),
                        else => try state.skip(entry),
                    };
                },
                2 => value.target = try data.string(),
                4 => value.started = @bitCast(try data.varint()),
                5 => value.succeeded = @bitCast(try data.varint()),
                6 => value.failed = @bitCast(try data.varint()),
                7 => value.last_call_started = try decodeTimestamp(try data.bytesValue()),
                else => try data.skip(item),
            };
        },
        else => try reader.skip(field),
    };
    return value;
}

fn decodeServer(bytes: []const u8) !DecodedServer {
    var reader = pb.Reader{ .bytes = bytes };
    var value = DecodedServer{
        .id = 0,
        .name = "",
        .started = 0,
        .succeeded = 0,
        .failed = 0,
        .last_call_started = null,
    };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            var ref = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try ref.next()) |item| switch (item.number) {
                5 => value.id = @bitCast(try ref.varint()),
                6 => value.name = try ref.string(),
                else => try ref.skip(item),
            };
        },
        2 => {
            var data = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try data.next()) |item| switch (item.number) {
                2 => value.started = @bitCast(try data.varint()),
                3 => value.succeeded = @bitCast(try data.varint()),
                4 => value.failed = @bitCast(try data.varint()),
                5 => value.last_call_started = try decodeTimestamp(try data.bytesValue()),
                else => try data.skip(item),
            };
        },
        else => try reader.skip(field),
    };
    return value;
}

fn decodeTimestamp(bytes: []const u8) !Timestamp {
    var reader = pb.Reader{ .bytes = bytes };
    var value = Timestamp{ .seconds = 0, .nanos = 0 };
    while (try reader.next()) |field| switch (field.number) {
        1 => value.seconds = @bitCast(try reader.varint()),
        2 => value.nanos = @intCast(try reader.varint()),
        else => try reader.skip(field),
    };
    return value;
}

fn putVarint(out: *std.ArrayList(u8), value: u64) !void {
    var remaining = value;
    while (remaining >= 0x80) {
        try out.append(gpa, @as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try out.append(gpa, @truncate(remaining));
}

fn putVarintField(out: *std.ArrayList(u8), number: u32, value: u64) !void {
    try putVarint(out, (@as(u64, number) << 3));
    try putVarint(out, value);
}

fn pageRequest(start: i64, max_results: i64) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    if (start != 0) try putVarintField(&out, 1, @bitCast(start));
    if (max_results != 0) try putVarintField(&out, 2, @bitCast(max_results));
    return out.toOwnedSlice(gpa);
}

fn idRequest(field_number: u32, id: i64) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try putVarintField(&out, field_number, @bitCast(id));
    return out.toOwnedSlice(gpa);
}

test "Channelz top-channel pagination preserves ids, metadata and counters" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var registry = channelz.Registry.init(gpa, threaded.io());
    defer registry.deinit();

    const a = try registry.addChannel("a", "dns:///a.example");
    a.setState(.ready);
    a.callStarted();
    a.callSucceeded();
    const b = try registry.addChannel("b", "dns:///b.example");
    b.callStarted();
    b.callFailed();
    _ = try registry.addChannel("c", "dns:///c.example");

    const first_request = try pageRequest(0, 2);
    defer gpa.free(first_request);
    const first_bytes = (try registry.handle(gpa, channelz.get_top_channels_path, first_request)).?;
    defer gpa.free(first_bytes);
    const first = try decodeTopChannels(first_bytes);
    defer first.deinit();
    try std.testing.expectEqual(@as(usize, 2), first.channels.len);
    try std.testing.expect(!first.end);
    try std.testing.expectEqual(@as(i64, 1), first.channels[0].id);
    try std.testing.expectEqualStrings("a", first.channels[0].name);
    try std.testing.expectEqualStrings("dns:///a.example", first.channels[0].target);
    try std.testing.expectEqual(@intFromEnum(channelz.ConnectivityState.ready), first.channels[0].state);
    try std.testing.expectEqual(@as(i64, 1), first.channels[0].started);
    try std.testing.expectEqual(@as(i64, 1), first.channels[0].succeeded);
    try std.testing.expectEqual(@as(i64, 0), first.channels[0].failed);
    try std.testing.expect(first.channels[0].last_call_started != null);
    try std.testing.expectEqual(@as(i64, 2), first.channels[1].id);
    try std.testing.expectEqual(@as(i64, 1), first.channels[1].failed);

    const second_request = try pageRequest(3, 2);
    defer gpa.free(second_request);
    const second_bytes = (try registry.handle(gpa, channelz.get_top_channels_path, second_request)).?;
    defer gpa.free(second_bytes);
    const second = try decodeTopChannels(second_bytes);
    defer second.deinit();
    try std.testing.expectEqual(@as(usize, 1), second.channels.len);
    try std.testing.expectEqual(@as(i64, 3), second.channels[0].id);
    try std.testing.expect(second.end);

    const channel_request = try idRequest(1, 2);
    defer gpa.free(channel_request);
    const channel_bytes = (try registry.handle(gpa, channelz.get_channel_path, channel_request)).?;
    defer gpa.free(channel_bytes);
    const channel = try decodeChannelResponse(channel_bytes);
    try std.testing.expectEqual(@as(i64, 2), channel.single_channel.?.id);
    try std.testing.expectEqualStrings("b", channel.single_channel.?.name);
}

test "Channelz server pages and single lookups expose call counters" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var registry = channelz.Registry.init(gpa, threaded.io());
    defer registry.deinit();

    const first = try registry.addServer("first");
    first.callStarted();
    first.callSucceeded();
    const second = try registry.addServer("second");
    second.callStarted();
    second.callFailed();

    const request = try pageRequest(0, 0);
    defer gpa.free(request);
    const bytes = (try registry.handle(gpa, channelz.get_servers_path, request)).?;
    defer gpa.free(bytes);
    const dump = try decodeServers(bytes);
    defer dump.deinit();
    try std.testing.expectEqual(@as(usize, 2), dump.servers.len);
    try std.testing.expect(dump.end);
    try std.testing.expectEqual(@as(i64, 1), dump.servers[0].id);
    try std.testing.expectEqualStrings("first", dump.servers[0].name);
    try std.testing.expectEqual(@as(i64, 1), dump.servers[0].succeeded);
    try std.testing.expectEqual(@as(i64, 2), dump.servers[1].id);
    try std.testing.expectEqual(@as(i64, 1), dump.servers[1].failed);

    const server_request = try idRequest(1, 2);
    defer gpa.free(server_request);
    const server_bytes = (try registry.handle(gpa, channelz.get_server_path, server_request)).?;
    defer gpa.free(server_bytes);
    const server = try decodeServerResponse(server_bytes);
    try std.testing.expectEqual(@as(i64, 2), server.single_server.?.id);
    try std.testing.expectEqualStrings("second", server.single_server.?.name);
    try std.testing.expectEqual(@as(i64, 1), server.single_server.?.failed);

    const sockets_request = try idRequest(1, 1);
    defer gpa.free(sockets_request);
    const sockets_bytes = (try registry.handle(gpa, channelz.get_server_sockets_path, sockets_request)).?;
    defer gpa.free(sockets_bytes);
    var sockets = try channelz.decodeServerSockets(gpa, sockets_bytes);
    defer sockets.deinit();
    try std.testing.expectEqual(@as(usize, 0), sockets.sockets.len);
    try std.testing.expect(sockets.end);
}

test "Channelz encodes Unix and opaque socket addresses" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var registry = channelz.Registry.init(gpa, threaded.io());
    defer registry.deinit();
    const server = try registry.addServer("uds-server");
    const socket = try registry.addSocket(
        "uds",
        .{ .uds = "/tmp/channelz.sock" },
        .{ .other = "opaque-peer" },
    );
    socket.streamStarted();
    socket.streamFailed();
    socket.messageReceived();
    try server.addListenSocket(socket);

    const page_request = try channelz.encodeServerSocketsRequest(gpa, server.id, 0, 0);
    defer gpa.free(page_request);
    const page_bytes = (try registry.handle(gpa, channelz.get_server_sockets_path, page_request)).?;
    defer gpa.free(page_bytes);
    var page = try channelz.decodeServerSockets(gpa, page_bytes);
    defer page.deinit();
    try std.testing.expectEqual(@as(usize, 1), page.sockets.len);
    try std.testing.expectEqualStrings("uds", page.sockets[0].name);
    try std.testing.expect(page.end);

    const socket_request = try channelz.encodeIdRequest(gpa, socket.id);
    defer gpa.free(socket_request);
    const socket_bytes = (try registry.handle(gpa, channelz.get_socket_path, socket_request)).?;
    defer gpa.free(socket_bytes);
    var decoded = try channelz.decodeSocketResponse(gpa, socket_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualStrings("uds", decoded.value.name);
    try std.testing.expectEqual(@as(i64, 1), decoded.value.data.streams_started);
    try std.testing.expectEqual(@as(i64, 1), decoded.value.data.streams_failed);
    try std.testing.expectEqual(@as(i64, 1), decoded.value.data.messages_received);
    try std.testing.expectEqualStrings("/tmp/channelz.sock", decoded.value.local.?.uds);
    try std.testing.expectEqualStrings("opaque-peer", decoded.value.remote.?.other);
}

test "Channelz rejects unknown methods, unknown ids and invalid pages" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    var registry = channelz.Registry.init(gpa, threaded.io());
    defer registry.deinit();
    const channel = try registry.addChannel("only", "dns:///only.example");

    try std.testing.expect((try registry.handle(gpa, "/other.Service/Call", "")) == null);
    try std.testing.expectError(error.Unimplemented, registry.handle(gpa, "/grpc.channelz.v1.Channelz/Unknown", ""));
    try std.testing.expectError(error.NotFound, registry.handle(gpa, channelz.get_channel_path, &.{ 0x08, 0x7f }));
    try std.testing.expectError(error.NotFound, registry.handle(gpa, channelz.get_subchannel_path, &.{ 0x08, 0x01 }));
    try std.testing.expectError(error.NotFound, registry.handle(gpa, channelz.get_socket_path, &.{ 0x08, 0x01 }));
    try std.testing.expectError(error.InvalidRequest, registry.handle(gpa, channelz.get_top_channels_path, &.{ 0x10, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01 }));

    try std.testing.expect(registry.removeChannel(channel));
    try std.testing.expectError(error.NotFound, registry.handle(gpa, channelz.get_channel_path, &.{ 0x08, 0x01 }));
}

test "Channelz serve dispatches real unary gRPC requests and statuses" {
    var threaded = std.Io.Threaded.init(gpa, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var registry = channelz.Registry.init(gpa, io);
    defer registry.deinit();
    const channel = try registry.addChannel("frontend", "dns:///frontend.example");
    channel.setState(.ready);
    channel.callStarted();
    channel.callSucceeded();
    const server_info = try registry.addServer("backend");
    server_info.callStarted();
    server_info.callSucceeded();

    var server = try runtime.Server.listen(
        gpa,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
        1024,
    );
    defer server.deinit();
    const listen = try registry.addSocket(
        "listen",
        .{ .tcpip = server.address() },
        null,
    );
    listen.streamStarted();
    listen.streamSucceeded();
    listen.messageSent();
    try server_info.addListenSocket(listen);

    const Shared = struct {
        server: *runtime.Server,
        registry: *channelz.Registry,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.deinit();
            for (0..10) |_| {
                var request = connection.readUnary() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit();
                const handled = channelz.serve(self.registry, &connection, &request) catch |err| {
                    self.err = err;
                    return;
                };
                if (!handled) {
                    self.err = error.TestUnexpectedResult;
                    return;
                }
            }
        }
    };
    var shared = Shared{ .server = &server, .registry = &registry };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    var client = try runtime.Client.connect(
        gpa,
        io,
        server.address(),
        .{ .max_frame_payload = 4096, .max_body_bytes = 4096 },
    );
    defer client.deinit();

    const page_request = try pageRequest(0, 0);
    defer gpa.free(page_request);
    var page = try client.unary(.{
        .path = channelz.get_top_channels_path,
        .authority = "localhost",
        .message = page_request,
    });
    defer page.deinit();
    try std.testing.expectEqual(wire.Status.ok, page.status);
    const dump = try decodeTopChannels(page.message.?.payload);
    defer dump.deinit();
    try std.testing.expectEqual(@as(usize, 1), dump.channels.len);
    try std.testing.expectEqualStrings("frontend", dump.channels[0].name);
    try std.testing.expectEqual(@intFromEnum(channelz.ConnectivityState.ready), dump.channels[0].state);

    const missing_request = try idRequest(1, 999);
    defer gpa.free(missing_request);
    var missing = try client.unary(.{
        .path = channelz.get_channel_path,
        .authority = "localhost",
        .message = missing_request,
    });
    defer missing.deinit();
    try std.testing.expectEqual(wire.Status.not_found, missing.status);

    var admin = channelz.Client{ .allocator = gpa, .connection = &client };
    var top = try admin.getTopChannels(0, 0);
    defer top.deinit();
    try std.testing.expectEqual(@as(usize, 1), top.channels.len);
    try std.testing.expectEqualStrings("frontend", top.channels[0].name);
    try std.testing.expectEqual(
        channelz.ConnectivityState.ready,
        top.channels[0].data.state,
    );
    try std.testing.expectEqual(@as(i64, 1), top.channels[0].data.calls_started);

    var servers = try admin.getServers(0, 0);
    defer servers.deinit();
    try std.testing.expectEqual(@as(usize, 1), servers.servers.len);
    try std.testing.expectEqualStrings("backend", servers.servers[0].name);
    try std.testing.expectEqual(@as(i64, 1), servers.servers[0].data.calls_succeeded);

    var server_value = try admin.getServer(1);
    defer server_value.deinit();
    try std.testing.expectEqualStrings("backend", server_value.value.name);

    var channel_value = try admin.getChannel(1);
    defer channel_value.deinit();
    try std.testing.expectEqualStrings("frontend", channel_value.value.name);

    var sockets = try admin.getServerSockets(1, 0, 0);
    defer sockets.deinit();
    try std.testing.expectEqual(@as(usize, 1), sockets.sockets.len);
    try std.testing.expectEqualStrings("listen", sockets.sockets[0].name);
    try std.testing.expect(sockets.end);

    var socket_value = try admin.getSocket(1);
    defer socket_value.deinit();
    try std.testing.expectEqualStrings("listen", socket_value.value.name);
    try std.testing.expectEqual(@as(i64, 1), socket_value.value.data.streams_started);
    try std.testing.expect(socket_value.value.local != null);

    try std.testing.expectError(error.NotFound, admin.getChannel(999));
    try std.testing.expectError(error.NotFound, admin.getSocket(999));

    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

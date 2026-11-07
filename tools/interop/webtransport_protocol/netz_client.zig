//! One H3 connection preserves sibling sessions across scoped WT_ALPN_ERROR.
const std = @import("std");
const netz = @import("netz");
const fixture = @import("fixture.zig");
const wt = netz.webtransport;
const endpoint = struct {
    const Client = wt.runtime.EndpointClient;
    const Session = wt.runtime.EndpointClientSession;
};
const allocator = fixture.allocator;

fn datagram(client: *endpoint.Client, session: *endpoint.Session, payload: []const u8, io: std.Io) !void {
    const until = fixture.deadline(io);
    try session.sendDatagramWithDeadline(client, payload, until);
    var buffer: [256]u8 = undefined;
    var event = try client.receiveWithDeadline(session.id(), &buffer, until);
    defer event.deinit(allocator);
    if (event != .datagram) return error.SiblingDataLeak;
    try std.testing.expectEqualStrings(payload, event.datagram.payload);
}

fn accepted(client: *endpoint.Client, authority: []const u8, comptime path: []const u8, comptime values: []const []const u8, expected: []const u8, expected_wire: []const u8, io: std.Io) !*endpoint.Session {
    const session = try client.openSessionWithDeadline(.{ .authority = authority, .path = path, .origin = "", .application_protocols = .{ .values = values, .required = true } }, fixture.deadline(io));
    const selected = session.applicationProtocol() orelse return error.MissingSelection;
    try std.testing.expect(selected.eql(expected));
    try std.testing.expectEqualStrings(expected_wire, session.responseHeader("wt-protocol").?);
    var decoded: [128]u8 = undefined;
    try fixture.report("WT_PROTOCOL_NETZ_CLIENT_CASE ", .{ .path = path, .session_id = session.id().value, .selected = try selected.decodeInto(&decoded), .selected_wire = session.responseHeader("wt-protocol").? });
    return session;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const dcid = [_]u8{ 0x77, 0x74, 0x70, 0x72, 0x6f, 0x74, 1, 1 };
    const cid = [_]u8{ 0x77, 0x74, 0x70, 0x72, 0x6f, 0x74, 1, 2 };
    var client = try endpoint.Client.connectWithDeadline(allocator, io, .{ .ip4 = .loopback(0) }, .{ .ip4 = .loopback(port) }, .{
        .max_sessions = 8,
        .limits = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 128 } },
        .h3 = .{ .handshake = .{ .original_destination_connection_id = &dcid, .local_connection_id = &cid, .max_crypto_buffer = 64 * 1024 }, .session = .{ .max_stream_buffer = 64 * 1024, .max_stream_frame_data = 1200 } },
    }, fixture.deadline(io));
    defer client.deinit();
    const authority = try std.fmt.allocPrint(allocator, "localhost:{d}", .{port});
    defer allocator.free(authority);
    const sibling = try accepted(&client, authority, "/ordered", &.{ "p2", "p1" }, "p2", "\"p2\"", io);
    try std.testing.expectEqual(@as(u62, 0), sibling.id().value);
    try datagram(&client, sibling, "before-errors", io);
    for ([_][]const u8{ "/missing", "/unoffered" }, [_][]const u8{ "after-missing", "after-unoffered" }, 0..) |path, payload, index| {
        const id: u62 = @intCast(4 + index * 4);
        try std.testing.expectError(error.ApplicationProtocolNegotiationFailed, client.openSessionWithDeadline(.{
            .authority = authority,
            .path = path,
            .origin = "",
            .application_protocols = .{ .values = &.{"p1"}, .required = true },
        }, fixture.deadline(io)));
        try std.testing.expectEqual(@as(usize, 1), client.sessionCount());
        try std.testing.expect(!client.h3.established.connection.closed());
        try std.testing.expectEqual(wt.ApplicationErrorCode.alpn_error, client.h3.established.connection.sendStreamStats(id).?.reset.?.application_error_code);
        try datagram(&client, sibling, payload, io);
        try fixture.report("WT_PROTOCOL_NETZ_CLIENT_REJECTION ", .{ .path = path, .stream_id = id, .reset_code = wt.ApplicationErrorCode.alpn_error, .sibling_session_count = client.sessionCount(), .connection_alive = true });
    }
    const escaped = try accepted(&client, authority, "/escaped", &.{ fixture.escaped, "p1" }, fixture.escaped, fixture.escaped_selected, io);
    try datagram(&client, escaped, "escaped-live", io);
    const stream = try sibling.openBidirectionalStream(&client);
    var committed: usize = 0;
    const until = fixture.deadline(io);
    try sibling.sendStreamWithDeadline(&client, stream, "sibling-stream", true, &committed, until);
    var buffer: [256]u8 = undefined;
    var length: usize = 0;
    while (true) {
        var event = try client.receiveWithDeadline(sibling.id(), &buffer, until);
        defer event.deinit(allocator);
        if (event != .stream or event.stream != .data) return error.SiblingDataLeak;
        const data = event.stream.data;
        try std.testing.expectEqual(stream, data.stream_id);
        try std.testing.expect(data.bytes <= "sibling-stream".len - length);
        try std.testing.expectEqualStrings("sibling-stream"[length..][0..data.bytes], buffer[0..data.bytes]);
        length += data.bytes;
        if (data.fin) break;
    }
    try std.testing.expectEqual(@as(usize, "sibling-stream".len), length);
    const reused = try accepted(&client, authority, "/reuse", &.{"p1"}, "p1", "\"p1\"", io);
    try datagram(&client, reused, "new-session-live", io);
    try std.testing.expectEqual(@as(usize, 3), client.sessionCount());
    try fixture.report("WT_PROTOCOL_NETZ_CLIENT_RESULT ", .{ .status = "passed", .scoped_alpn_resets = @as(usize, 2), .existing_sibling_preserved = true, .optimistic_streams_not_delivered = true, .new_session_after_errors = true, .connection_count = @as(usize, 1), .application_datagrams = @as(usize, 5), .application_streams = @as(usize, 1) });
    try client.closeConnection(0, "protocol gate complete");
}

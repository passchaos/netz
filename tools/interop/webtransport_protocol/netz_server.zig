//! Reference semantic client tests the production server's protocol policy.
const std = @import("std");
const netz = @import("netz");
const fixture = @import("fixture.zig");
const allocator = fixture.allocator;
const wt = netz.webtransport;

fn echoStream(session: *wt.runtime.AcceptedHandshakeSession, expected: []const u8, until: std.Io.Clock.Timestamp) !void {
    var buffer: [256]u8 = undefined;
    var received: usize = 0;
    var id: ?u62 = null;
    while (true) {
        const event = try session.readStreamWithDeadline(&buffer, until);
        if (event != .data) return error.UnexpectedStreamEvent;
        const data = event.data;
        if (id) |known| try std.testing.expectEqual(known, data.stream_id) else id = data.stream_id;
        try std.testing.expect(data.direction == .bidirectional and !data.locally_initiated);
        try std.testing.expect(data.bytes <= expected.len - received);
        try std.testing.expectEqualStrings(expected[received..][0..data.bytes], buffer[0..data.bytes]);
        received += data.bytes;
        if (data.fin) break;
    }
    try std.testing.expectEqual(expected.len, received);
    var committed: usize = 0;
    try session.sendStreamWithDeadline(id.?, expected, true, &committed, until);
    try std.testing.expectEqual(expected.len, committed);
    try session.waitForStreamRecoveryIdleWithDeadline(id.?, until);
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3) return error.InvalidArguments;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const identity = try fixture.Identity.load(io, args[1], args[2]);
    defer identity.deinit();
    const cid = [_]u8{ 0x77, 0x74, 0x70, 0x72, 0x6f, 0x74, 0, 1 };
    var server = try wt.runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .application_protocols = .{ .values = &.{ "p1", "p2", fixture.escaped }, .required = true },
        .http3 = .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 128 } },
    }, .{
        .handshake = .{ .local_connection_id = &cid, .max_crypto_buffer = 64 * 1024, .identity = .{
            .certificate_chain = &.{identity.certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = identity.key } },
        } },
        .session = .{ .max_stream_buffer = 64 * 1024, .max_stream_frame_data = 1200 },
    });
    defer server.deinit();
    std.debug.print("WT_PROTOCOL_NETZ_PORT={d}\n", .{server.address().getPort()});
    for ([_][]const u8{ "ordered", "escaped", "required-no-overlap" }) |name| {
        const until = fixture.deadline(io);
        var pending = try server.receiveSessionRequestWithDeadline(until);
        var pending_owned = true;
        defer if (pending_owned) pending.deinit();
        const path = try std.fmt.allocPrint(allocator, "/{s}", .{name});
        defer allocator.free(path);
        try std.testing.expectEqualStrings(path, pending.path());
        const wire = fixture.header(pending.headers(), "wt-available-protocols") orelse return error.MissingOffer;
        if (std.mem.eql(u8, name, "required-no-overlap")) {
            try std.testing.expectEqualStrings("\"absent\"", wire);
            try std.testing.expectError(error.NoCommonApplicationProtocol, pending.accept());
            try std.testing.expect(pending.h3.established.connection.sendStreamStats(pending.session_id.value) == null);
            var rejected = try pending.reject(406, &.{});
            pending_owned = false;
            defer rejected.deinit();
            try rejected.h3.waitForStreamRecoveryIdleWithDeadline(rejected.session_id.value, until);
            try fixture.report("WT_PROTOCOL_NETZ_SERVER_CASE ", .{ .name = name, .status = @as(u16, 406), .required_no_overlap = true, .application_streams = @as(usize, 0), .application_datagrams = @as(usize, 0) });
            continue;
        }
        const expected = if (std.mem.eql(u8, name, "ordered")) "p2" else fixture.escaped;
        const expected_wire = if (std.mem.eql(u8, name, "ordered")) "\"p2\", \"p1\"" else fixture.escaped_available;
        try std.testing.expectEqualStrings(expected_wire, wire);
        var offered = pending.offeredApplicationProtocols().?.iterator();
        try std.testing.expect(offered.next().?.eql(expected));
        try std.testing.expect(offered.next().?.eql("p1"));
        try std.testing.expect(offered.next() == null);
        var session = try pending.accept();
        pending_owned = false;
        defer session.deinit();
        const selected = session.applicationProtocol() orelse return error.MissingSelection;
        try std.testing.expect(selected.eql(expected));
        var decoded: [128]u8 = undefined;
        const value = try selected.decodeInto(&decoded);
        const payload = try std.fmt.allocPrint(allocator, "semantic-datagram-{s}", .{name});
        defer allocator.free(payload);
        var datagram = try session.receiveDatagramWithDeadline(until);
        defer datagram.deinit(allocator);
        try std.testing.expectEqualStrings(payload, datagram.datagram.payload);
        try session.sendDatagramWithDeadline(payload, until);
        const stream_payload = try std.fmt.allocPrint(allocator, "semantic-stream-{s}", .{name});
        defer allocator.free(stream_payload);
        try echoStream(&session, stream_payload, until);
        try fixture.report("WT_PROTOCOL_NETZ_SERVER_CASE ", .{ .name = name, .available_wire = wire, .selected = value, .status = @as(u16, 200), .application_streams = @as(usize, 1), .application_datagrams = @as(usize, 1) });
    }
    try fixture.report("WT_PROTOCOL_NETZ_SERVER_RESULT ", .{ .status = "passed", .ordered_overlap = true, .escaped_identifiers = true, .required_rejection_before_application_io = true, .accepted = @as(usize, 2), .rejected = @as(usize, 1) });
}

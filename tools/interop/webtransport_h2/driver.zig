//! Production API driver for an independent Python draft-15 peer.
const std = @import("std");
const netz = @import("netz");
const wt = netz.webtransport.h2;
const http2 = netz.http2.runtime;
const credit: netz.http2.WebTransportSettings = .{
    .enabled = true,
    .max_data = 64,
    .max_stream_data_uni = 16,
    .max_stream_data_bidi_local = 24,
    .max_stream_data_bidi_remote = 32,
    .max_streams_uni = 8,
    .max_streams_bidi = 8,
};
const init_credit: wt.init_header.InitialStreamDataLimits = .{
    .uni = 96,
    .bidi_local = 100,
    .bidi_remote = 104,
};

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(8), .clock = .awake });
}

fn next(session: *wt.Session, until: std.Io.Clock.Timestamp) !wt.state.Event {
    while (true) {
        const event = try session.receiveWithDeadline(until);
        if (event != .progress) return event;
    }
}

fn exchange(session: *wt.Session, until: std.Io.Clock.Timestamp) !void {
    try std.testing.expectEqualStrings("interop", session.selected_protocol.?);
    try std.testing.expectEqual(@as(u64, 128), session.state.send_limit.uni_data);
    try std.testing.expectEqual(@as(u64, 132), session.state.send_limit.bidi_local_data);
    try std.testing.expectEqual(@as(u64, 136), session.state.send_limit.bidi_remote_data);
    try std.testing.expectEqual(@as(u64, 96), session.state.receive_limit.uni_data);
    try std.testing.expectEqual(@as(u64, 100), session.state.receive_limit.bidi_local_data);
    try std.testing.expectEqual(@as(u64, 104), session.state.receive_limit.bidi_remote_data);

    const local_bidi = try session.openStream(.bidirectional);
    try session.sendStreamWithDeadline(local_bidi, "", false, until);
    // Neither initial session nor stream credit allows this write. The peer
    // grants both while an unrelated DATAGRAM must remain owned for receive.
    const body = [_]u8{'x'} ** 200;
    try session.sendStreamWithDeadline(local_bidi, &body, true, until);
    try std.testing.expectEqualStrings("while-blocked", (try next(session, until)).datagram);
    const reply = (try next(session, until)).stream;
    try std.testing.expectEqual(local_bidi, reply.id);
    try std.testing.expect(reply.fin);
    try std.testing.expectEqualStrings("reply", reply.data);
    try session.consume(local_bidi, reply.data.len);
    try session.retireStream(local_bidi);

    try session.sendDatagramWithDeadline("ping", until);
    try std.testing.expectEqualStrings("pong", (try next(session, until)).datagram);
    const reset_id = try session.openStream(.unidirectional);
    try session.sendStreamWithDeadline(reset_id, "prefix", false, until);
    try session.resetStreamWithDeadline(reset_id, 42, until);
    const stop_id = try session.openStream(.unidirectional);
    try session.sendStreamWithDeadline(stop_id, "", false, until);
    const stopped = (try next(session, until)).stopped;
    try std.testing.expectEqual(stop_id, stopped.id);
    try std.testing.expectEqual(@as(u32, 0xffffffff), stopped.code);
    try session.resetStreamWithDeadline(stop_id, stopped.code, until);

    try session.grantDataWithDeadline(4096, until);
    try session.grantStreamsWithDeadline(.bidirectional, 16, until);
    try session.grantStreamsWithDeadline(.unidirectional, 16, until);
    const peer_uni = (try next(session, until)).stream;
    try std.testing.expect(peer_uni.fin);
    try std.testing.expect(peer_uni.id & 3 == (@as(u62, @intFromEnum(session.state.role)) ^ 3));
    try std.testing.expectEqualStrings("peer-uni", peer_uni.data);
    try session.consume(peer_uni.id, peer_uni.data.len);
    try session.retireStream(peer_uni.id);
    const peer_bidi = (try next(session, until)).stream;
    try std.testing.expect(peer_bidi.fin);
    try std.testing.expectEqualStrings("peer-bidi", peer_bidi.data);
    try session.sendStreamWithDeadline(peer_bidi.id, "local-reply", true, until);
    try session.consume(peer_bidi.id, peer_bidi.data.len);
    try session.retireStream(peer_bidi.id);
    try session.drainWithDeadline(until);
    try std.testing.expect((try next(session, until)) == .draining);
    const closed = (try next(session, until)).closed;
    try std.testing.expectEqual(@as(u32, 17), closed.code);
    try std.testing.expectEqualStrings("done \xe2\x9c\x93", closed.reason);
}

fn invalidReset(session: *wt.Session, until: std.Io.Clock.Timestamp) !void {
    const received = (try next(session, until)).stream;
    try std.testing.expectEqualStrings("abc", received.data);
    // Three bytes were delivered, but the peer RESET says two.
    try std.testing.expectError(error.StreamStateError, session.receiveWithDeadline(until));
}

fn reuse(session: *wt.Session, until: std.Io.Clock.Timestamp) !void {
    try session.sendDatagramWithDeadline("after-error", until);
    try std.testing.expectEqualStrings("still-healthy", (try next(session, until)).datagram);
    const closed = (try next(session, until)).closed;
    try std.testing.expectEqual(@as(u32, 18), closed.code);
}

fn nextEndpoint(client: anytype, handle: anytype, until: std.Io.Clock.Timestamp) !wt.endpoint_client.Event {
    while (true) {
        var event = try client.receiveWithDeadline(handle, until);
        if (event.value != .progress) return event;
        event.deinit();
    }
}

fn reuseEndpoint(client: wt.EndpointClient, until: std.Io.Clock.Timestamp) !void {
    var dropped = try client.connectAttemptWithDeadline(.{
        .path = "/drop",
        .authority = "origin.internal",
        .protocols = .{ .values = &.{ "interop", "other" }, .required = true },
        .initial_receive_stream_data = init_credit,
    }, until);
    var dropped_owned = true;
    defer if (dropped_owned) dropped.deinit();
    try std.testing.expect(dropped.accepted());
    const prior = dropped.accepted_session.?.handle;
    dropped.deinit();
    dropped_owned = false;
    var attempt = try client.connectAttemptWithDeadline(.{
        .path = "/reuse",
        .authority = "origin.internal",
        .protocols = .{ .values = &.{ "interop", "other" }, .required = true },
        .initial_receive_stream_data = init_credit,
    }, until);
    var owned = true;
    defer if (owned) attempt.deinit();
    var accepted = try attempt.requireAccepted();
    owned = false;
    defer accepted.deinit();
    try std.testing.expectEqual(@as(u16, 200), accepted.status);
    try std.testing.expectEqualStrings("interop", accepted.selected_protocol.?);
    try std.testing.expectEqual(prior.index, accepted.handle.index);
    try std.testing.expect(prior.generation != accepted.handle.generation);
    try client.sendDatagramWithDeadline(accepted.handle, "after-error", until);
    var reply = try nextEndpoint(client, accepted.handle, until);
    defer reply.deinit();
    try std.testing.expectEqualStrings("still-healthy", reply.value.datagram);
    var closed = try nextEndpoint(client, accepted.handle, until);
    defer closed.deinit();
    try std.testing.expectEqual(@as(u32, 18), closed.value.closed.code);
    std.debug.print("WebTransport HTTP2 EndpointClient dropped cleanup passed: canceled=1 slot_reused=true\n", .{});
    std.debug.print("WebTransport HTTP2 EndpointClient queue passed: connect+datagram+receive owned_results=true reuse_after_error=true\n", .{});
}

fn reuseServerEndpoint(server: wt.EndpointServer, until: std.Io.Clock.Timestamp) !void {
    var dropped = try server.receiveRequestWithDeadline(until);
    var dropped_owned = true;
    defer if (dropped_owned) dropped.deinit();
    try std.testing.expectEqualStrings("/drop-pending", dropped.path());
    const prior = dropped.data.handle;
    dropped.deinit();
    dropped_owned = false;
    var request = try server.receiveRequestWithDeadline(until);
    var request_owned = true;
    defer if (request_owned) request.deinit();
    try std.testing.expectEqualStrings("/reuse", request.path());
    try std.testing.expectEqual(prior.index, request.data.handle.index);
    try std.testing.expect(prior.generation != request.data.handle.generation);
    var accepted = try request.acceptWithDeadline(.{
        .protocols = .{ .values = &.{"interop"}, .required = true },
        .initial_receive_stream_data = init_credit,
    }, until);
    request_owned = false;
    defer accepted.deinit();
    try std.testing.expectEqualStrings("interop", accepted.selected_protocol.?);
    try server.sendDatagramWithDeadline(accepted.handle, "after-error", until);
    var reply = try nextEndpoint(server, accepted.handle, until);
    defer reply.deinit();
    try std.testing.expectEqualStrings("still-healthy", reply.value.datagram);
    var closed = try nextEndpoint(server, accepted.handle, until);
    defer closed.deinit();
    try std.testing.expectEqual(@as(u32, 18), closed.value.closed.code);
    std.debug.print("WebTransport HTTP2 EndpointServer pending cleanup passed: canceled=1 slot_reused=true queue=true\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 6) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[2], 10);
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const until = deadline(io);
    if (std.mem.eql(u8, args[1], "client")) {
        var ca: std.crypto.Certificate.Bundle = .empty;
        defer ca.deinit(allocator);
        try ca.addCertsFromFilePathAbsolute(allocator, io, std.Io.Clock.real.now(io), args[3]);
        var ca_lock: std.Io.RwLock = .init;
        var connection = try http2.Client.connectTlsAddressWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            "origin.internal",
            "origin.internal",
            .{ .enable_connect_protocol = true, .webtransport = credit },
            .{ .ca_bundle = .{ .bundle = &ca, .lock = &ca_lock }, .protocol_policy = .tls13_only },
            until,
        );
        var connection_owned = true;
        defer if (connection_owned) connection.close();
        var rejection = try wt.runtime.connectAttemptWithDeadline(allocator, &connection, .{
            .path = "/reject",
            .authority = "origin.internal",
        }, until);
        defer rejection.deinit();
        try std.testing.expectEqual(@as(u16, 429), rejection.status());
        try std.testing.expectEqualStrings("retry", rejection.body());
        try std.testing.expectEqualStrings("1", rejection.trailers()[0].value);
        for ([_][]const u8{ "/interop", "/bad-reset" }, 0..) |path, index| {
            var session = try wt.runtime.connectWithDeadline(allocator, &connection, .{
                .path = path,
                .authority = "origin.internal",
                .protocols = .{ .values = &.{ "interop", "other" }, .required = true },
                .initial_receive_stream_data = init_credit,
            }, until);
            defer session.deinit();
            switch (index) {
                0 => try exchange(&session, until),
                1 => try invalidReset(&session, until),
                else => unreachable,
            }
        }
        connection_owned = false;
        var endpoint = try wt.EndpointClient.initWithDeadline(allocator, connection, .{ .max_sessions = 1 }, until);
        defer endpoint.deinit();
        try reuseEndpoint(endpoint, until);
    } else if (std.mem.eql(u8, args[1], "server")) {
        var identity = try netz.tls.server_identity_file.load(allocator, io, .cwd(), args[4], args[5]);
        defer identity.deinit();
        var server = try http2.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(port) }, .{
            .identity = identity.serverIdentity(),
            .protocol_policy = .tls13_only,
            .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
        });
        defer server.deinit();
        std.debug.print("READY {d}\n", .{server.address().getPort()});
        var connection = try server.acceptWithDeadline(until);
        var connection_owned = true;
        defer if (connection_owned) connection.close();
        var rejected = try wt.runtime.readRequestWithDeadline(&connection, until);
        defer rejected.deinit(allocator);
        try std.testing.expectEqualStrings("/reject", rejected.request.path);
        try rejected.rejectWithDeadline(&connection, .{
            .status = 429,
            .body = "retry",
            .trailers = &.{.{ .name = "x-retry", .value = "1" }},
        }, until);
        for ([_][]const u8{ "/interop", "/bad-reset" }, 0..) |path, index| {
            var pending = try wt.runtime.readRequestWithDeadline(&connection, until);
            defer pending.deinit(allocator);
            try std.testing.expectEqualStrings(path, pending.request.path);
            var session = try wt.runtime.acceptWithDeadline(allocator, &connection, pending, .{
                .protocols = .{ .values = &.{"interop"}, .required = true },
                .initial_receive_stream_data = init_credit,
            }, until);
            defer session.deinit();
            switch (index) {
                0 => try exchange(&session, until),
                1 => try invalidReset(&session, until),
                else => unreachable,
            }
        }
        connection_owned = false;
        var endpoint = try wt.EndpointServer.initWithDeadline(allocator, connection, .{ .max_sessions = 1, .max_pending_sessions = 1 }, until);
        defer endpoint.deinit();
        try reuseServerEndpoint(endpoint, until);
    } else if (std.mem.eql(u8, args[1], "listener")) {
        var identity = try netz.tls.server_identity_file.load(allocator, io, .cwd(), args[4], args[5]);
        defer identity.deinit();
        const raw = try http2.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(port) }, .{
            .identity = identity.serverIdentity(),
            .protocol_policy = .tls13_only,
            .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
        });
        var listener = try wt.EndpointListener.initTlsServer(allocator, raw, .{ .max_connections = 1, .max_pending_requests = 1, .accept_workers = 1, .endpoint = .{ .max_sessions = 1, .max_pending_sessions = 1 } });
        defer listener.deinit();
        std.debug.print("READY {d}\n", .{listener.address().getPort()});
        var pending = try listener.receiveRequestWithDeadline(until);
        var pending_owned = true;
        defer if (pending_owned) pending.deinit();
        try std.testing.expectEqualStrings("/listener", pending.path());
        var accepted = try pending.acceptWithDeadline(.{ .protocols = .{ .values = &.{"interop"}, .required = true }, .initial_receive_stream_data = init_credit }, until);
        pending_owned = false;
        defer accepted.deinit();
        try std.testing.expectEqualStrings("interop", accepted.applicationProtocol().?);
        var incoming = try nextEndpoint(listener, accepted.handle, until);
        defer incoming.deinit();
        try std.testing.expectEqualStrings("listener-stream", incoming.value.stream.data);
        try std.testing.expect(incoming.value.stream.fin);
        const id = incoming.value.stream.id;
        try listener.sendStreamWithDeadline(accepted.handle, id, "listener-stream-reply", true, until);
        try listener.consumeWithDeadline(accepted.handle, id, incoming.value.stream.data.len, until);
        try listener.retireStreamWithDeadline(accepted.handle, id, until);
        var datagram = try nextEndpoint(listener, accepted.handle, until);
        defer datagram.deinit();
        try std.testing.expectEqualStrings("listener-ping", datagram.value.datagram);
        try listener.sendDatagramWithDeadline(accepted.handle, "listener-pong", until);
        try listener.closeWithDeadline(accepted.handle, 19, "", until);
        std.debug.print("WebTransport HTTP2 EndpointListener passed: accepted=true stream=true datagram=true close=19\n", .{});
        return;
    } else return error.InvalidArgument;
    std.debug.print("WebTransport HTTP2 {s} passed: rejected=429 streams=4 flow_control=true reset=42 reliable_size=6 stop=4294967295 drain=true close=17 invalid_reset=StreamStateError reuse_after_error=true client_io=zio-std-io\n", .{args[1]});
}

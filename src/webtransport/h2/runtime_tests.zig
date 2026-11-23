const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const wt = @import("mod.zig");
const tls = @import("../../tls/testing.zig");
const allocator = std.testing.allocator;
const credit: http2.WebTransportSettings = .{ .enabled = true, .max_data = 8192, .max_stream_data_uni = 2048, .max_stream_data_bidi_local = 2048, .max_stream_data_bidi_remote = 2048, .max_streams_uni = 8, .max_streams_bidi = 8 };
fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(3), .clock = .awake });
}
fn next(session: *wt.Session) !wt.state.Event {
    while (true) {
        const event = try session.receiveWithTimeout(.fromSeconds(3));
        if (event != .progress) return event;
    }
}

test "WebTransport HTTP2 TLS runtime exchanges virtual streams datagrams reset STOP and close" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    var server = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
        .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
    });
    defer server.deinit();
    const Peer = struct {
        server: *http2.runtime.TlsServer,
        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var pending = try wt.runtime.readRequestWithTimeout(&connection, .fromSeconds(3));
            defer pending.deinit(allocator);
            var session = try wt.runtime.acceptWithTimeout(allocator, &connection, pending, .{
                .protocols = .{ .values = &.{"echo"}, .required = true },
                .headers = &.{.{ .name = "x-session", .value = "accepted" }},
                .initial_receive_stream_data = .{ .uni = 4096, .bidi_local = 4100, .bidi_remote = 4200 },
            }, .fromSeconds(3));
            defer session.deinit();
            try std.testing.expectEqualStrings("echo", session.applicationProtocol().?);
            try std.testing.expectEqual(@as(u64, 3096), session.state.send_limit.uni_data);
            try std.testing.expectEqual(@as(u64, 4096), session.state.receive_limit.uni_data);
            const stream = (try next(&session)).stream;
            try std.testing.expectEqualStrings("hello", stream.data);
            const bidi = stream.id;
            try session.sendStreamSlicesWithTimeout(bidi, &.{ "rep", "ly" }, true, .fromSeconds(3));
            try session.consume(bidi, 5);
            try session.retireStream(bidi);
            const datagram = try next(&session);
            try std.testing.expectEqualStrings("ping", datagram.datagram);
            try session.sendDatagramWithTimeout("pong", .fromSeconds(3));
            const data = (try next(&session)).stream;
            try std.testing.expectEqualStrings("prefix", data.data);
            const uni = data.id;
            const reset = (try next(&session)).reset;
            try std.testing.expectEqual(uni, reset.id);
            try std.testing.expectEqual(@as(u32, 42), reset.code);
            try session.consume(uni, 6);
            try session.retireStream(uni);
            const stopped_stream = (try next(&session)).stream;
            try session.stopSendingWithTimeout(stopped_stream.id, 71, .fromSeconds(3));
            const stopped_reset = (try next(&session)).reset;
            try std.testing.expectEqual(@as(u32, 71), stopped_reset.code);
            try session.retireStream(stopped_stream.id);
            const drained = try next(&session);
            try std.testing.expect(drained == .draining);
            const closed = (try next(&session)).closed;
            try std.testing.expectEqual(@as(u32, 17), closed.code);
            try std.testing.expectEqualStrings("done", closed.reason);
        }
    };
    var peer = Peer{ .server = &server };
    var task = io.async(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", .{ .enable_connect_protocol = true, .webtransport = credit }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .fromSeconds(3));
    defer connection.close();
    var session = try wt.runtime.connectWithTimeout(allocator, &connection, .{
        .path = "/echo",
        .authority = "localhost",
        .protocols = .{ .values = &.{ "echo", "other" }, .required = true },
        .initial_receive_stream_data = .{ .uni = 3096, .bidi_local = 3100, .bidi_remote = 3200 },
    }, .fromSeconds(3));
    defer session.deinit();
    try std.testing.expectEqualStrings("echo", session.applicationProtocol().?);
    try std.testing.expectEqual(@as(?u16, 200), session.responseStatus());
    try std.testing.expectEqualStrings("accepted", session.responseHeader("x-session").?);
    try std.testing.expectEqual(@as(u64, 4096), session.state.send_limit.uni_data);
    try std.testing.expectEqual(@as(u64, 3096), session.state.receive_limit.uni_data);
    try std.testing.expect(!session.unreliableDelivery());
    const bidi = try session.openStream(.bidirectional);
    try session.sendStreamSlicesWithTimeout(bidi, &.{ "hel", "lo" }, true, .fromSeconds(3));
    const reply = (try next(&session)).stream;
    try std.testing.expectEqualStrings("reply", reply.data);
    try session.consume(bidi, 5);
    try session.retireStream(bidi);
    try session.sendDatagramWithTimeout("ping", .fromSeconds(3));
    try std.testing.expectEqualStrings("pong", (try next(&session)).datagram);
    const uni = try session.openStream(.unidirectional);
    try session.sendStreamWithDeadline(uni, "prefix", false, deadline(io));
    try session.resetStreamWithTimeout(uni, 42, .fromSeconds(3));
    const stopped = try session.openStream(.unidirectional);
    try session.sendStreamWithDeadline(stopped, "", false, deadline(io));
    const stop = (try next(&session)).stopped;
    try std.testing.expectEqual(stopped, stop.id);
    try session.resetStreamWithDeadline(stopped, stop.code, deadline(io));
    try session.drainWithTimeout(.fromSeconds(3));
    try session.closeWithTimeout(17, "done", .fromSeconds(3));
    const close = try next(&session);
    try std.testing.expect(close == .closed);
    try task.await(io);
}

test "WebTransport HTTP2 Init dictionary merges known integers and ignores valid unknown members" {
    const Header = http2.Hpack.HeaderField;
    const parsed = try wt.init_header.parse(&[_]Header{.{ .name = "webtransport-init", .value = "u=256, bl=32;p, br=64, extension=(1 \"two\");x=?1" }}, .{ .uni_data = 512, .bidi_local_data = 16 });
    try std.testing.expectEqual(@as(u64, 512), parsed.uni_data);
    try std.testing.expectEqual(@as(u64, 32), parsed.bidi_local_data);
    try std.testing.expectEqual(@as(u64, 64), parsed.bidi_remote_data);
    const combined = try wt.init_header.parse(&[_]Header{
        .{ .name = "WebTransport-Init", .value = "u=300, bl=31" },
        .{ .name = "webtransport-init", .value = "u=40, br=63" },
    }, .{ .uni_data = 10, .bidi_local_data = 32, .bidi_remote_data = 64 });
    try std.testing.expectEqual(@as(u64, 40), combined.uni_data);
    try std.testing.expectEqual(@as(u64, 32), combined.bidi_local_data);
    try std.testing.expectEqual(@as(u64, 64), combined.bidi_remote_data);
    for ([_][]const u8{ "u", "u=-1", "u=1.5", "u=?1", "u=(1)", "bl=\"3\"", "u=1234567890123456", "extension=(1,two)", "extension=@1", "extension;x=@1", "u=1," }) |value| {
        try std.testing.expectError(error.InvalidWebTransportInit, wt.init_header.parse(&[_]Header{.{ .name = "webtransport-init", .value = value }}, .{}));
    }
    try std.testing.expectError(error.InvalidWebTransportInit, wt.init_header.parse(&[_]Header{
        .{ .name = "webtransport-init", .value = "" },
        .{ .name = "webtransport-init", .value = "u=1" },
    }, .{}));
    var output: [64]u8 = undefined;
    try std.testing.expectEqualStrings("u=1, bl=2, br=3", try wt.init_header.writeInto(&output, .{ .uni = 1, .bidi_local = 2, .bidi_remote = 3 }));
    try std.testing.expectError(error.InvalidWebTransportInit, wt.init_header.writeInto(&output, .{ .uni = 1000000000000000 }));
}

test "WebTransport HTTP2 TLS send waits for credit and retains unrelated datagrams" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    var limited = credit;
    limited.max_data = 3;
    limited.max_stream_data_uni = 3;
    var server = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
        .limits = .{ .enable_connect_protocol = true, .webtransport = limited },
    });
    defer server.deinit();
    const Peer = struct {
        server: *http2.runtime.TlsServer,
        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var pending = try wt.runtime.readRequestWithDeadline(&connection, deadline(connection.io));
            defer pending.deinit(allocator);
            var session = try wt.runtime.acceptWithDeadline(allocator, &connection, pending, .{}, deadline(connection.io));
            defer session.deinit();
            const first = (try next(&session)).stream;
            try std.testing.expectEqualStrings("abc", first.data);
            try session.sendDatagramWithDeadline("queued-before-credit", deadline(connection.io));
            try session.grantDataWithTimeout(20, .fromSeconds(3));
            try session.grantStreamDataWithTimeout(first.id, 20, .fromSeconds(3));
            const second = (try next(&session)).stream;
            try std.testing.expectEqualStrings("def", second.data);
            try std.testing.expect(second.fin);
            _ = try next(&session);
        }
    };
    var peer = Peer{ .server = &server };
    var task = io.async(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", .{ .enable_connect_protocol = true, .webtransport = credit }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .fromSeconds(3));
    defer connection.close();
    var session = try wt.runtime.connectWithTimeout(allocator, &connection, .{ .path = "/credit", .authority = "localhost" }, .fromSeconds(3));
    defer session.deinit();
    const id = try session.openStream(.unidirectional);
    try session.sendStreamWithDeadline(id, "abc", false, deadline(io));
    try session.sendStreamWithDeadline(id, "def", true, deadline(io));
    const queued = try next(&session);
    try std.testing.expectEqualStrings("queued-before-credit", queued.datagram);
    try session.closeWithDeadline(0, "", deadline(io));
    _ = try next(&session);
    try task.await(io);
}

test "WebTransport HTTP2 invalid CONNECT and Init reject only their streams" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    var server = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
        .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
    });
    defer server.deinit();
    const Peer = struct {
        server: *http2.runtime.TlsServer,
        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            try std.testing.expectError(error.InvalidConnect, wt.runtime.readRequestWithTimeout(&connection, .fromSeconds(3)));
            var rejected = try wt.runtime.readRequestWithTimeout(&connection, .fromSeconds(3));
            defer rejected.deinit(allocator);
            try rejected.rejectWithTimeout(&connection, .{
                .status = 429,
                .headers = &.{.{ .name = "retry-after", .value = "7" }},
                .body = "try later",
                .trailers = &.{.{ .name = "x-rejection", .value = "complete" }},
            }, .fromSeconds(3));
            var malformed = try wt.runtime.readRequestWithTimeout(&connection, .fromSeconds(3));
            defer malformed.deinit(allocator);
            try std.testing.expectError(error.InvalidWebTransportInit, wt.runtime.acceptWithTimeout(allocator, &connection, malformed, .{}, .fromSeconds(3)));
            var pending = try wt.runtime.readRequestWithTimeout(&connection, .fromSeconds(3));
            defer pending.deinit(allocator);
            var session = try wt.runtime.acceptWithTimeout(allocator, &connection, pending, .{ .headers = &.{.{ .name = "x-sibling", .value = "healthy" }} }, .fromSeconds(3));
            defer session.deinit();
            const closed = (try session.receiveWithTimeout(.fromSeconds(3))).closed;
            try std.testing.expectEqual(@as(u32, 5), closed.code);
            try std.testing.expectEqualStrings("healthy sibling", closed.reason);
        }
    };
    var peer = Peer{ .server = &server };
    var task = io.async(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", .{ .enable_connect_protocol = true, .webtransport = credit }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .fromSeconds(3));
    defer connection.close();
    var invalid_connect = try connection.openExtendedConnectAttemptWithTimeout(.{
        .method = "CONNECT",
        .protocol = "webtransport",
        .scheme = "http",
        .authority = "localhost",
        .path = "/bad-scheme",
    }, .fromSeconds(3));
    defer invalid_connect.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 400), invalid_connect.status);
    try std.testing.expect(!invalid_connect.accepted());
    var rejected = try wt.runtime.connectAttemptWithTimeout(allocator, &connection, .{ .path = "/policy", .authority = "localhost" }, .fromSeconds(3));
    defer rejected.deinit();
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqual(@as(u16, 429), rejected.status());
    try std.testing.expectEqualStrings("7", rejected.responseHeader("retry-after").?);
    try std.testing.expectEqualStrings("try later", rejected.body());
    try std.testing.expectEqual(@as(usize, 1), rejected.trailers().len);
    try std.testing.expectEqualStrings("x-rejection", rejected.trailers()[0].name);
    try std.testing.expectEqualStrings("complete", rejected.trailers()[0].value);
    try std.testing.expectError(error.SessionRejected, rejected.requireAccepted());
    var invalid_init = try connection.openExtendedConnectAttemptWithTimeout(.{
        .method = "CONNECT",
        .protocol = "webtransport",
        .scheme = "https",
        .authority = "localhost",
        .path = "/bad-init",
        .headers = &.{.{ .name = "webtransport-init", .value = "u=?1" }},
    }, .fromSeconds(3));
    defer invalid_init.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 400), invalid_init.status);
    try std.testing.expect(!invalid_init.accepted());
    var accepted = try wt.runtime.connectAttemptWithTimeout(allocator, &connection, .{ .path = "/healthy", .authority = "localhost" }, .fromSeconds(3));
    var accepted_owned = true;
    defer if (accepted_owned) accepted.deinit();
    try std.testing.expect(accepted.accepted());
    try std.testing.expectEqual(@as(u16, 200), accepted.status());
    try std.testing.expectEqualStrings("healthy", accepted.responseHeader("x-sibling").?);
    try std.testing.expectEqual(@as(usize, 0), accepted.body().len);
    try std.testing.expectEqual(@as(usize, 0), accepted.trailers().len);
    var session = try accepted.requireAccepted();
    accepted_owned = false;
    defer session.deinit();
    try std.testing.expectEqualStrings("healthy", session.responseHeader("x-sibling").?);
    try session.closeWithTimeout(5, "healthy sibling", .fromSeconds(3));
    try std.testing.expect((try session.receiveWithTimeout(.fromSeconds(3))) == .closed);
    try task.await(io);
}

test "WebTransport HTTP2 duplex Sessions route rejection and sibling capsules" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls.certificate_base64);
    const key = try tls.serverKeyPair();
    var server = try http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
        .protocol_policy = .tls13_only,
        .limits = .{ .enable_connect_protocol = true, .webtransport = credit },
    });
    defer server.deinit();
    const Peer = struct {
        server: *http2.runtime.TlsServer,

        fn start(stream: *http2.runtime.ServerDuplexStream, status: u16, headers: []const http2.Hpack.HeaderField, before: std.Io.Clock.Timestamp) !void {
            try std.testing.expectEqualStrings("CONNECT", stream.method);
            try std.testing.expectEqualStrings("webtransport", stream.protocol.?);
            try stream.startResponseWithDeadline(.{ .status = status, .headers = headers, .request_method = "CONNECT", .extended_connect = true }, before);
        }

        fn readDatagram(stream: *http2.runtime.ServerDuplexStream, expected: []const u8, before: std.Io.Clock.Timestamp) !void {
            while (true) {
                var event = try stream.readRequestEventWithDeadline(before);
                defer event.deinit(allocator);
                switch (event) {
                    .data => |data| {
                        const parsed = try wt.Capsule.parse(data.data);
                        try std.testing.expectEqual(data.data.len, parsed.consumed);
                        try std.testing.expectEqualStrings(expected, parsed.capsule.datagram);
                        return;
                    },
                    .finished => return error.TestUnexpectedResult,
                    .trailers, .reset => return error.TestUnexpectedResult,
                }
            }
        }

        fn readClose(stream: *http2.runtime.ServerDuplexStream, expected_code: u32, expected_reason: []const u8, before: std.Io.Clock.Timestamp) !void {
            while (true) {
                var event = try stream.readRequestEventWithDeadline(before);
                defer event.deinit(allocator);
                switch (event) {
                    .data => |data| {
                        const parsed = try wt.Capsule.parse(data.data);
                        try std.testing.expectEqual(data.data.len, parsed.consumed);
                        try std.testing.expectEqual(expected_code, parsed.capsule.close_session.code);
                        try std.testing.expectEqualStrings(expected_reason, parsed.capsule.close_session.reason);
                        return;
                    },
                    .finished => return error.TestUnexpectedResult,
                    .trailers, .reset => return error.TestUnexpectedResult,
                }
            }
        }

        fn writeCapsule(stream: *http2.runtime.ServerDuplexStream, capsule: wt.Capsule, before: std.Io.Clock.Timestamp) !void {
            var storage: [256]u8 = undefined;
            const bytes = try capsule.writeInto(&storage);
            const result = try stream.writeResponseWithDeadline(bytes, before);
            try std.testing.expectEqual(bytes.len, result.written);
        }

        fn run(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(3));
            defer connection.close();
            var rejected = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer rejected.deinit();
            try start(&rejected, 429, &.{
                .{ .name = "content-length", .value = "5" },
                .{ .name = "retry-after", .value = "9" },
            }, deadline(connection.io));
            _ = try rejected.writeResponseWithDeadline("later", deadline(connection.io));
            try rejected.finishResponseTrailersWithDeadline(&.{.{ .name = "x-rejected", .value = "complete" }}, deadline(connection.io));
            try std.testing.expect((try rejected.drainRequestAfterResponseWithDeadline(deadline(connection.io))) == .finished);

            var a = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer a.deinit();
            try std.testing.expectEqualStrings("/a", a.path);
            try start(&a, 200, &.{.{ .name = "x-session", .value = "a" }}, deadline(connection.io));
            var b = try connection.acceptDuplexRequestWithDeadline(deadline(connection.io));
            defer b.deinit();
            try std.testing.expectEqualStrings("/b", b.path);
            try start(&b, 200, &.{.{ .name = "x-session", .value = "b" }}, deadline(connection.io));

            try readDatagram(&a, "to-a", deadline(connection.io));
            try readDatagram(&b, "to-b", deadline(connection.io));
            try writeCapsule(&b, .{ .datagram = "from-b" }, deadline(connection.io));
            try writeCapsule(&a, .{ .datagram = "from-a" }, deadline(connection.io));

            try readClose(&a, 1, "a", deadline(connection.io));
            try std.testing.expect((try a.readRequestEventWithDeadline(deadline(connection.io))) == .finished);
            _ = try a.finishResponseWithDeadline(deadline(connection.io));
            try readClose(&b, 2, "b", deadline(connection.io));
            try std.testing.expect((try b.readRequestEventWithDeadline(deadline(connection.io))) == .finished);
            _ = try b.finishResponseWithDeadline(deadline(connection.io));
        }
    };
    var peer = Peer{ .server = &server };
    var task = io.async(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var connection = try http2.runtime.Client.connectTlsAddressWithTimeout(allocator, io, server.address(), "localhost", "localhost", .{ .enable_connect_protocol = true, .webtransport = credit }, .{
        .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
        .protocol_policy = .tls13_only,
    }, .fromSeconds(3));
    defer connection.close();

    var rejected = try wt.runtime.connectDuplexAttemptWithTimeout(allocator, &connection, .{ .path = "/reject", .authority = "localhost" }, .fromSeconds(3));
    defer rejected.deinit();
    try std.testing.expect(!rejected.accepted());
    try std.testing.expectEqual(@as(u16, 429), rejected.status());
    try std.testing.expectEqualStrings("9", rejected.responseHeader("retry-after").?);
    try std.testing.expectEqualStrings("later", rejected.body());
    try std.testing.expectEqualStrings("complete", rejected.trailers()[0].value);

    var a = try wt.runtime.connectDuplexWithTimeout(allocator, &connection, .{ .path = "/a", .authority = "localhost" }, .fromSeconds(3));
    defer a.deinit();
    var b = try wt.runtime.connectDuplexWithTimeout(allocator, &connection, .{ .path = "/b", .authority = "localhost" }, .fromSeconds(3));
    defer b.deinit();
    try std.testing.expect(a.multiplexed());
    try std.testing.expect(b.multiplexed());
    try std.testing.expectEqualStrings("a", a.responseHeader("x-session").?);
    try std.testing.expectEqualStrings("b", b.responseHeader("x-session").?);
    try b.sendDatagramWithTimeout("to-b", .fromSeconds(3));
    try a.sendDatagramWithTimeout("to-a", .fromSeconds(3));
    try std.testing.expectEqualStrings("from-a", (try next(&a)).datagram);
    try std.testing.expectEqualStrings("from-b", (try next(&b)).datagram);
    try a.closeWithTimeout(1, "a", .fromSeconds(3));
    try b.closeWithTimeout(2, "b", .fromSeconds(3));
    try std.testing.expect((try next(&a)) == .closed);
    try std.testing.expect((try next(&b)) == .closed);
    try task.await(io);
}

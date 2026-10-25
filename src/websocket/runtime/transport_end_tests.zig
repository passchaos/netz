//! TLS EOF and truncated records retire WebSocket state without a wire Close.
const std = @import("std");
const runtime = @import("../runtime.zig");
const tls_testing = @import("../../tls/testing.zig");
const stream_io = @import("../../internal/stream_io.zig");

const Mode = enum { frame, message, caller_buffer, ping, close };
const Fault = enum { eof, header, payload, bad_mac, close_notify };
const Backend = enum { vail_tls13, vail_tls12, standard_tls13 };

test "WSS unexpected EOF retires fragmented receive state" {
    try exercise(.message, .eof, .vail_tls13, false);
}

test "WSS fatal TLS input retires every receive API and both client backends" {
    for (std.enums.values(Mode)) |mode| {
        for (std.enums.values(Fault)) |fault| {
            for (std.enums.values(Backend)) |backend| try exercise(mode, fault, backend, false);
        }
    }
}

test "WSS server TLS truncation retires fragmented message ownership" {
    for ([_]Mode{ .frame, .message, .caller_buffer }) |mode| {
        for (std.enums.values(Fault)) |fault| {
            for ([_]Backend{ .vail_tls12, .vail_tls13 }) |backend| try exercise(mode, fault, backend, true);
        }
    }
}

fn sendFault(connection: *runtime.Connection, fault: Fault) !void {
    try runtime.testing.writeFrame(connection, .text, "partial", false);
    switch (fault) {
        .eof => {},
        .header => try stream_io.writeAllSlices(connection.io, connection.stream, &.{&.{0x17}}),
        .payload => try stream_io.writeAllSlices(connection.io, connection.stream, &.{&.{ 0x17, 0x03, 0x03, 0x00, 0x20, 0x00 }}),
        .bad_mac => try stream_io.writeAllSlices(connection.io, connection.stream, &.{&(.{ 0x17, 0x03, 0x03, 0x00, 0x21 } ++ .{0} ** 33)}),
        .close_notify => {
            if (connection.tls_server_conn) |tls| try tls.sendCloseNotify() else if (connection.tls_vail_conn) |tls| try tls.sendCloseNotify() else unreachable;
        },
    }
    try connection.stream.shutdown(connection.io, .send);
}

fn expectEnd(connection: anytype, mode: Mode, expected: anyerror) !void {
    switch (mode) {
        .frame => {
            var first = try connection.receiveFrameWithTimeout(.fromSeconds(2));
            defer first.deinit(connection.allocator);
            try std.testing.expectEqualStrings("partial", first.payload);
            try std.testing.expect(!first.header.fin);
            try std.testing.expectError(expected, connection.receiveFrameWithTimeout(.fromSeconds(2)));
        },
        .message => try std.testing.expectError(expected, connection.receiveMessageWithTimeout(.fromSeconds(2))),
        .caller_buffer => {
            var output: [64]u8 = undefined;
            try std.testing.expectError(expected, connection.receiveMessageIntoWithTimeout(&output, .fromSeconds(2)));
        },
        .ping => {
            var event = try connection.pingWithTimeout("probe", .fromSeconds(2));
            defer event.deinit(connection.allocator);
            try std.testing.expect(event == .application);
            try std.testing.expectError(expected, connection.continuePingWithTimeout("probe", .fromSeconds(2)));
        },
        .close => {
            var event = try connection.closeWithTimeout(.{ .code = .normal_closure }, .fromSeconds(2));
            defer event.deinit(connection.allocator);
            try std.testing.expect(event == .application);
            try std.testing.expectError(expected, connection.continueCloseWithTimeout(.fromSeconds(2)));
        },
    }
    try std.testing.expect(runtime.testing.receiveStorageReleased(connection));
    try std.testing.expect(runtime.testing.outboundStorageReleased(connection));
    try std.testing.expect(runtime.testing.writeAborted(connection));
    try std.testing.expectEqual(mode == .close, connection.close_sent.load(.acquire));
    try std.testing.expect(!connection.close_received.load(.acquire));
    try std.testing.expectError(error.ConnectionClosed, connection.sendText("late"));
    try std.testing.expectError(error.ConnectionClosed, connection.sendPing("late"));
    try std.testing.expectError(error.ConnectionClosed, connection.receiveMessageWithTimeout(.fromSeconds(2)));
}

fn expectedError(fault: Fault, backend: Backend, server_receiver: bool) anyerror {
    if (fault == .close_notify) return error.ConnectionClosed;
    if (!server_receiver and backend == .standard_tls13) return switch (fault) {
        .eof, .header, .payload => error.TlsConnectionTruncated,
        .bad_mac => error.TlsBadRecordMac,
        .close_notify => unreachable,
    };
    return switch (fault) {
        .eof => error.UnexpectedEof,
        .header, .payload => error.TruncatedRecord,
        .bad_mac => error.AuthenticationFailed,
        .close_notify => unreachable,
    };
}

fn exercise(mode: Mode, fault: Fault, backend: Backend, server_receiver: bool) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .identity = .{ .certificate_chain = &.{&certificate_der}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } } },
        .cipher_suites = &.{.aes_128_gcm_sha256},
        .protocol_policy = if (backend == .vail_tls12) .tls12_only else .tls13_only,
        .limits = .{ .max_message_bytes = 64 },
    });
    defer server.deinit();
    const Peer = struct {
        server: *runtime.TlsServer,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        mode: Mode,
        fault: Fault,
        expected: anyerror,
        receiver: bool,

        fn run(self: *@This()) void {
            self.serve() catch |err| {
                self.err = err;
            };
        }

        fn serve(self: *@This()) !void {
            var connection = try self.server.accept(.{});
            defer connection.close();
            if (self.receiver) {
                try expectEnd(&connection, self.mode, self.expected);
                return;
            }
            try sendFault(&connection, self.fault);
            try self.release.waitTimeout(self.server.io, .{ .duration = .{ .raw = .fromSeconds(3), .clock = .awake } });
        }
    };
    var peer = Peer{ .server = &server, .mode = mode, .fault = fault, .expected = expectedError(fault, backend, server_receiver), .receiver = server_receiver };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    defer peer.release.set(io);
    var client = try runtime.Client.connectTlsHost(allocator, io, "localhost", server.address().ip4.port, .{
        .host = "localhost",
        .vail_tls = if (backend != .standard_tls13) .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() }, .protocol_policy = if (backend == .vail_tls12) .tls12_only else .tls13_only } else null,
        .limits = .{ .max_message_bytes = 64 },
    }, .{ .verify_host = false });
    defer client.close();
    if (server_receiver) try sendFault(&client, fault) else try expectEnd(&client, mode, peer.expected);
    peer.release.set(io);
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

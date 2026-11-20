//! Public pooled and exclusive H3 streaming shapes retain the same fields,
//! informational ordering and exactly-once callback contract.
const std = @import("std");
const http = @import("../mod.zig");
const h1 = @import("../../http1/runtime.zig");
const h3 = @import("../../http3/runtime.zig");
const protocol = @import("../../http3/mod.zig");
const tls_testing = @import("../../tls/testing.zig");
const allocator = std.testing.allocator;
const field_count = 40;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

const Sink = struct {
    body: std.ArrayList(u8) = .empty,
    informational_count: usize = 0,
    begin_count: usize = 0,
    end_count: usize = 0,
    order: [8]u8 = undefined,
    order_len: usize = 0,

    fn append(self: *Sink, event: u8) void {
        if (self.order_len < self.order.len) self.order[self.order_len] = event;
        self.order_len += 1;
    }

    fn responseSink(self: *Sink) http.ResponseSink {
        return .{ .context = self, .begin = begin, .data = data, .end = end, .informational = informational };
    }

    fn assertFields(fields: []const http.Header) !void {
        var count: usize = 0;
        for (fields) |field| if (std.mem.startsWith(u8, field.name, "x-response-")) {
            try std.testing.expectEqualStrings("v", field.value);
            try std.testing.expect(field.never_indexed);
            count += 1;
        };
        try std.testing.expectEqual(@as(usize, field_count), count);
    }

    fn informational(context: *anyopaque, head: http.ResponseHead) void {
        const self: *Sink = @ptrCast(@alignCast(context));
        self.append('I');
        self.informational_count += 1;
        // The enclosing assertions check every callback; preserve a failed
        // observation as an impossible count rather than aborting a void hook.
        if (head.status != 103 or head.protocol != .http3) self.informational_count += 100;
        assertFields(head.headers) catch {
            self.informational_count += 100;
        };
    }

    fn begin(context: *anyopaque, head: http.ResponseHead) !void {
        const self: *Sink = @ptrCast(@alignCast(context));
        self.append('B');
        self.begin_count += 1;
        try std.testing.expectEqual(@as(u16, 200), head.status);
        try assertFields(head.headers);
    }

    fn data(context: *anyopaque, bytes: []const u8) !void {
        const self: *Sink = @ptrCast(@alignCast(context));
        self.append('D');
        try self.body.appendSlice(allocator, bytes);
    }

    fn end(context: *anyopaque, fields: []const http.Header) !void {
        const self: *Sink = @ptrCast(@alignCast(context));
        self.append('E');
        self.end_count += 1;
        try assertFields(fields);
    }
};

fn receiveStreamingUpload(session: *h3.HandshakeServerSession, io: std.Io, expected: []const u8) !u62 {
    var stream_id: ?u62 = null;
    var offset: usize = 0;
    var saw_trailers = false;
    var buffer: [16 * 1024]u8 = undefined;
    while (true) {
        var event = try session.receiveRequestEventWithDeadline(deadline(io));
        defer event.deinit(allocator);
        if (event != .message) return error.TestUnexpectedResult;
        const message = event.message;
        if (stream_id) |id| try std.testing.expectEqual(id, message.stream_id) else stream_id = message.stream_id;
        switch (message.value) {
            .head => |head| try std.testing.expect(head == .request),
            .data_available => {
                const count = try session.readRequestData(message.stream_id, &buffer);
                try std.testing.expect(count <= expected.len - offset);
                try std.testing.expectEqualSlices(u8, expected[offset..][0..count], buffer[0..count]);
                offset += count;
            },
            .trailers => |trailers| {
                try std.testing.expectEqual(@as(usize, field_count), trailers.fields.len);
                for (trailers.fields) |field| {
                    try std.testing.expect(field.never_indexed);
                    try std.testing.expectEqualStrings("done", field.value);
                }
                saw_trailers = true;
            },
            .finished => {
                try std.testing.expectEqual(expected.len, offset);
                try std.testing.expect(saw_trailers);
                return stream_id.?;
            },
            .push_promise => return error.TestUnexpectedResult,
        }
    }
}

fn exercise(comptime shared_endpoint: bool) !void {
    return exerciseWithDeadlines(shared_endpoint, false);
}

fn exerciseWithDeadlines(comptime shared_endpoint: bool, comptime timed: bool) !void {
    const upload: []const u8 = if (timed) "u" ** (128 * 1024 + 3) else "upload";
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    const identity: @FieldType(h1.TlsListenOptions, "identity") = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } };
    var tcp = try h1.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{ .identity = identity, .alpn_protocols = &.{"http/1.1"} });
    defer tcp.deinit();
    const limits: h3.Limits = .{ .quic = .{ .max_datagram_size = 4096 } };
    var udp = try h3.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, limits, .{
        .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } } },
    });
    defer udp.deinit();
    const alt_svc = try std.fmt.allocPrint(allocator, "h3=\":{d}\"; ma=60", .{udp.address().getPort()});
    defer allocator.free(alt_svc);
    var release: std.Io.Event = .unset;
    const TcpWorker = struct {
        fn run(server: *h1.TlsServer, advertisement: []const u8, done: *std.Io.Event) !void {
            var connection = try server.acceptWithTimeout(.fromSeconds(5));
            defer connection.close();
            var request = try connection.readRequestWithDeadline(.{}, deadline(server.io));
            defer request.deinit(allocator);
            try connection.writeResponse(.{ .headers = &.{.{ .name = "alt-svc", .value = advertisement }}, .body = "discovery", .request_method = request.request.method });
            try done.wait(server.io);
        }
    };
    const UdpWorker = struct {
        fn run(server: *h3.HandshakeServer, worker_io: std.Io, done: *std.Io.Event, expected: []const u8) !void {
            var session = try server.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var names: [field_count][24]u8 = undefined;
            var fields: [field_count]protocol.Qpack.HeaderField = undefined;
            for (&names, &fields, 0..) |*name, *field, index| field.* = .{ .name = try std.fmt.bufPrint(name, "x-response-{d}", .{index}), .value = "v", .never_indexed = true };
            for (0..2) |_| {
                const stream_id = if (timed) try receiveStreamingUpload(&session, worker_io, expected) else blk: {
                    var request = try session.receiveRequestWithDeadline(deadline(worker_io));
                    defer request.deinit(allocator);
                    try std.testing.expectEqualStrings(expected, request.request.body);
                    try std.testing.expectEqual(@as(usize, field_count), request.request.trailers.len);
                    for (request.request.trailers) |field| {
                        try std.testing.expect(field.never_indexed);
                        try std.testing.expectEqualStrings("done", field.value);
                    }
                    break :blk request.stream_id;
                };
                try session.sendInformationalResponse(stream_id, .{ .status = 103, .headers = &fields });
                try session.startResponse(stream_id, .{ .status = 200, .headers = &fields }, 4);
                try session.sendResponseBodyPaced(stream_id, "body", false);
                try session.finishResponseTrailersPaced(stream_id, &fields);
            }
            try done.wait(worker_io);
        }
    };
    var tcp_task = try io.concurrent(TcpWorker.run, .{ &tcp, alt_svc, &release });
    defer _ = tcp_task.cancel(io) catch {};
    var udp_task = try io.concurrent(UdpWorker.run, .{ &udp, io, &release, upload });
    defer _ = udp_task.cancel(io) catch {};
    defer release.set(io);
    var pool = try http.Pool.init(allocator, io, .{
        .max_total_connections = 2,
        .client = .{ .tls = .{ .server_verifier = .{ .pinned_ecdsa_p256_public_key = public_key } } },
        .http3 = .{ .limits = limits, .shared_endpoint = shared_endpoint, .max_connections = 1, .handshake = .{ .handshake = .{ .original_destination_connection_id = &.{}, .local_connection_id = &.{}, .server_auth = .{ .pinned_ecdsa_p256_public_key = public_key } } } },
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(allocator, "https://localhost:{d}/stream", .{tcp.address().getPort()});
    defer allocator.free(uri);
    var discovery = try pool.requestUriWithDeadline(uri, .{}, deadline(io));
    defer discovery.deinit();
    var names: [field_count][24]u8 = undefined;
    var trailers: [field_count]http.Header = undefined;
    for (&names, &trailers, 0..) |*name, *field, index| field.* = .{ .name = try std.fmt.bufPrint(name, "x-upload-{d}", .{index}), .value = "done", .never_indexed = true };
    for (0..2) |index| {
        var handle = try pool.startRequestWithDeadline(uri, .{ .method = "POST", .body_length = .unknown }, deadline(io));
        defer handle.deinit();
        try std.testing.expectEqual(http.Protocol.http3, handle.protocol());
        if (timed) {
            var progress: http.UploadProgress = .{};
            if (index == 0) {
                try handle.writeBodyWithDeadline(upload, &progress, deadline(io));
                try std.testing.expectEqual(upload.len, progress.accepted_bytes);
            } else {
                var source = @import("reader_gate.zig").Gate{ .io = io, .bytes = upload, .prefix_len = 3 };
                try std.testing.expectError(error.Timeout, handle.writeBodyFromReaderWithTimeout(&source.reader, &progress, .fromMilliseconds(30)));
                try std.testing.expect(source.canceled and source.finished);
                try std.testing.expectEqual(source.prefix_len, progress.accepted_bytes);
                source.release.set(io);
                try handle.writeBodyFromReaderWithDeadline(&source.reader, &progress, deadline(io));
                try std.testing.expectEqual(upload.len - source.prefix_len, progress.accepted_bytes);
            }
            try handle.finishTrailersWithDeadline(&trailers, &progress, deadline(io));
            try std.testing.expect(progress.end_accepted);
            try std.testing.expectError(error.RequestBodyFinished, handle.writeBodyWithDeadline("later", &progress, deadline(io)));
        } else {
            try handle.writeBody(upload);
            try handle.finishTrailers(&trailers);
        }
        var sink = Sink{};
        defer sink.body.deinit(allocator);
        const head = try handle.readResponseWithDeadline(sink.responseSink(), deadline(io));
        try Sink.assertFields(head.headers);
        _ = try handle.readResponseWithDeadline(sink.responseSink(), deadline(io));
        try std.testing.expectEqual(@as(usize, 1), sink.informational_count);
        try std.testing.expectEqual(@as(usize, 1), sink.begin_count);
        try std.testing.expectEqual(@as(usize, 1), sink.end_count);
        try std.testing.expectEqualStrings("body", sink.body.items);
        try std.testing.expectEqual(@as(u8, 'I'), sink.order[0]);
        try std.testing.expectEqual(@as(u8, 'B'), sink.order[1]);
        try std.testing.expectEqual(@as(u8, 'E'), sink.order[sink.order_len - 1]);
    }
    release.set(io);
    try tcp_task.await(io);
    try udp_task.await(io);
    try std.testing.expectEqual(@as(usize, 1), pool.http3ConnectionCount());
}

test "unified HTTP pooled H3 fields and interim callbacks share endpoint" {
    try exercise(true);
}

test "unified HTTP pooled H3 fields and interim callbacks use exclusive endpoint" {
    try exercise(false);
}

test "unified HTTP streaming deadlines accept oversized pooled H3 uploads on both endpoints" {
    try exerciseWithDeadlines(true, true);
    try exerciseWithDeadlines(false, true);
}

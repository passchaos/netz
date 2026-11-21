//! Independent interim heads and compound streaming responses share the same
//! ordered H3 stream and final-response lifetime.
const std = @import("std");
const h3 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const tls_testing = @import("../../../tls/testing.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

const Observer = struct {
    statuses: [4]u16 = undefined,
    count: usize = 0,
    fn observe(context: *anyopaque, head: h3.InformationalResponseHead) void {
        const self: *Observer = @ptrCast(@alignCast(context));
        if (self.count < self.statuses.len) self.statuses[self.count] = head.status;
        self.count += 1;
    }
};

fn field(headers: []const h3.Qpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| if (std.mem.eql(u8, header.name, name)) return header.value;
    return null;
}

test "HTTP/3 concurrent informational 304 head preserves representation length" {
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    const response: h3.Response = .{ .status = 304 };
    const framing = try response.writeStreamingHead(&bytes, allocator, .{}, 4);
    try std.testing.expect(!framing.body_allowed);
    try std.testing.expectEqual(@as(?usize, 0), framing.expected_length);
    var decoded = try h3.decodeResponse(allocator, bytes.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 304), decoded.status);
    try std.testing.expectEqualStrings("4", field(decoded.headers, "content-length").?);
    try std.testing.expectEqualStrings("", decoded.body);
    bytes.clearRetainingCapacity();
    try std.testing.expectError(error.InvalidContentLength, (h3.Response{ .status = 304, .body = "body" }).writeStreamingHead(&bytes, allocator, .{}, 4));
    try std.testing.expectError(error.InvalidContentLength, (h3.Response{ .status = 204 }).writeStreamingHead(&bytes, allocator, .{}, 4));
    try std.testing.expectError(error.InvalidContentLength, (h3.Response{ .status = 205 }).writeStreamingHead(&bytes, allocator, .{}, 4));
    try std.testing.expectEqual(@as(usize, 0), bytes.items.len);
}

test "HTTP/3 concurrent informational development sends retain ordered offsets" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const limits: runtime.Limits = .{ .quic = .{ .max_datagram_size = 4096 }, .max_stream_frame_data = 128 };
    var server = try runtime.Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, limits);
    defer server.deinit();
    var shutdown: std.Io.Event = .unset;
    const Context = struct { io: std.Io, shutdown: *std.Io.Event };
    var context = Context{ .io = io, .shutdown = &shutdown };
    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.Server.ConcurrentStream) !void {
            try std.testing.expectError(error.Timeout, stream.writeInformationalResponseWithDeadline(102, &.{}, .{ .raw = .zero, .clock = .awake }));
            try stream.writeInformationalResponseWithDeadline(103, &.{}, deadline(ctx.io));
            try stream.startResponseWithBodyAndInformational(.{ .status = 200 }, null, "alpha", false, &.{.{ .status = 102 }});
            try stream.writeData("beta", false);
            try std.testing.expectError(
                error.Timeout,
                stream.finishWithTrailersWithTimeout(&.{}, .zero),
            );
            try stream.finishWithTrailersWithTimeout(
                &.{.{ .name = "x-finished", .value = "done" }},
                .fromSeconds(1),
            );
        }
    };
    const Worker = struct {
        fn run(listener: *runtime.Server, ctx: *Context) !void {
            const summary = try listener.serveConcurrentStreams(Context, ctx, Handler.run, .{ .max_streams = 2, .shutdown = ctx.shutdown });
            try std.testing.expectEqual(@as(usize, 2), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, &context });
    defer _ = serving.cancel(io) catch {};
    var client = try runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), limits);
    defer client.deinit();
    for (0..2) |_| {
        var observer = Observer{};
        var response = try client.requestWithInformationalAndDeadline(.{ .method = "GET", .path = "/stream", .authority = "localhost" }, .{ .context = &observer, .on_response = Observer.observe }, deadline(io));
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(usize, 2), observer.count);
        try std.testing.expectEqual(@as(u16, 103), observer.statuses[0]);
        try std.testing.expectEqual(@as(u16, 102), observer.statuses[1]);
        try std.testing.expectEqualStrings("alphabeta", response.response.body);
        try std.testing.expectEqualStrings("done", field(response.response.trailers, "x-finished").?);
    }
    shutdown.set(io);
    try serving.await(io);
}

test "HTTP/3 concurrent informational prefix survives failed literal head preflight" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{ .max_datagram_size = 4096 } };
    var server = try runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, limits, .{
        .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } },
    });
    defer server.deinit();
    const large = [_]u8{'Z'} ** 5000;
    const Worker = struct {
        fn run(listener: *runtime.HandshakeServer, worker_io: std.Io) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            var warm = try session.receiveRequestWithDeadline(deadline(worker_io));
            defer warm.deinit(allocator);
            try session.sendResponse(warm.stream_id, .{ .status = 200, .body = "warm", .request_method = warm.request.method });
            var request = try session.receiveRequestWithDeadline(deadline(worker_io));
            defer request.deinit(allocator);
            try session.sendInformationalResponse(request.stream_id, .{ .status = 103 });
            const response: h3.Response = .{ .status = 200, .headers = &.{.{ .name = "x-large", .value = &large }} };
            try std.testing.expectError(error.DatagramTooLarge, session.tryStartResponse(request.stream_id, response, 4, false));
            try session.startResponse(request.stream_id, response, 4);
            try session.sendResponseBodyPaced(request.stream_id, "body", true);
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, io });
    defer _ = serving.cancel(io) catch {};
    var client = try runtime.HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), limits, .{
        .handshake = .{ .original_destination_connection_id = &.{ 9, 8, 7, 6, 5, 4, 3, 2 }, .local_connection_id = &.{ 2, 3, 4, 5, 6, 7, 8, 9 }, .server_name = "localhost", .server_auth = .{ .pinned_ecdsa_p256_public_key = public_key } },
    });
    defer client.deinit();
    var warm = try client.requestWithDeadline(.{ .method = "GET", .path = "/warm", .authority = "localhost" }, deadline(io));
    defer warm.deinit(allocator);
    var observer = Observer{};
    var response = try client.requestWithInformationalAndDeadline(.{ .method = "GET", .path = "/stream", .authority = "localhost" }, .{ .context = &observer, .on_response = Observer.observe }, deadline(io));
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), observer.count);
    try std.testing.expectEqual(@as(u16, 103), observer.statuses[0]);
    try std.testing.expectEqualStrings(&large, field(response.response.headers, "x-large").?);
    try std.testing.expectEqualStrings("body", response.response.body);
    try serving.await(io);
}

test "HTTP/3 concurrent informational responses compose with bodies and trailers" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const public_key = key.public_key.toUncompressedSec1();
    const limits: runtime.Limits = .{ .quic = .{ .max_datagram_size = 4096 } };
    var server = try runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, limits, .{
        .handshake = .{ .local_connection_id = &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, .identity = .{
            .certificate_chain = &.{&certificate},
            .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
        } },
    });
    defer server.deinit();
    var shutdown: std.Io.Event = .unset;
    const Context = struct {
        io: std.Io,
        shutdown: *std.Io.Event,
        body: [9000]u8 = [_]u8{'Z'} ** 9000,
    };
    var context = Context{ .io = io, .shutdown = &shutdown };
    const Handler = struct {
        fn run(ctx: *Context, stream: *runtime.HandshakeServerSession.ConcurrentStream) !void {
            const path = stream.head().path;
            errdefer |err| std.debug.print("H3 informational handler {s}: {s}\n", .{ path, @errorName(err) });
            const info: h3.InformationalResponse = .{ .status = 103, .headers = &.{.{ .name = "link", .value = "</style.css>; rel=preload" }} };
            const trailers: []const h3.Qpack.HeaderField = &.{.{ .name = "x-finished", .value = "done" }};
            if (std.mem.eql(u8, path, "/split")) {
                try std.testing.expectError(error.Timeout, stream.writeInformationalResponseWithDeadline(102, &.{}, .{ .raw = .zero, .clock = .awake }));
                try stream.writeInformationalResponse(100, &.{});
                try stream.writeInformationalResponseWithDeadline(info.status, info.headers, deadline(ctx.io));
                try stream.startResponse(.{ .status = 200 }, null);
                try std.testing.expectError(error.UnexpectedFrame, stream.writeInformationalResponse(103, &.{}));
                try stream.writeData("alpha", false);
                try stream.writeData("beta", false);
                try stream.finishWithTrailers(trailers);
            } else if (std.mem.eql(u8, path, "/combined")) {
                try stream.startResponseWithBodyAndInformational(.{ .status = 200 }, null, "alpha", false, &.{info});
                try stream.writeData("beta", false);
                try stream.finishWithTrailers(trailers);
            } else if (std.mem.eql(u8, path, "/buffered") or std.mem.eql(u8, path, "/large")) {
                var names: [24][24]u8 = undefined;
                var headers: [24]h3.Qpack.HeaderField = undefined;
                for (&names, &headers, 0..) |*name, *header, index| header.* = .{ .name = try std.fmt.bufPrint(name, "x-field-{d}", .{index}), .value = "v" };
                if (std.mem.eql(u8, path, "/buffered")) {
                    try stream.startResponseWithBodyAndInformational(.{ .status = 200, .headers = &headers, .trailers = trailers }, ctx.body.len, &ctx.body, true, &.{info});
                } else {
                    try stream.writeInformationalResponse(info.status, info.headers);
                    try stream.startResponseWithBody(.{ .status = 200, .headers = &headers }, ctx.body.len, &ctx.body, true);
                }
            } else if (std.mem.eql(u8, path, "/literal")) {
                try stream.writeInformationalResponse(info.status, info.headers);
                try stream.startResponseWithBody(.{ .status = 200 }, 4, "body", true);
            } else if (std.mem.eql(u8, path, "/head")) {
                // The owner derives HEAD from the request; no caller method
                // annotation is needed, and the interim head must still arrive.
                try stream.startResponseWithBodyAndInformational(.{ .status = 200 }, 4, "body", true, &.{info});
            } else if (std.mem.eql(u8, path, "/no-content")) {
                try stream.startResponseWithBodyAndInformational(.{ .status = 204 }, 0, "", true, &.{info});
            } else if (std.mem.eql(u8, path, "/not-modified")) {
                try stream.startResponseWithBodyAndInformational(.{ .status = 304 }, 4, "", true, &.{info});
            } else if (std.mem.eql(u8, path, "/empty-trailers")) {
                try stream.startResponseWithBodyAndInformational(.{ .status = 200, .trailers = trailers }, 0, "", true, &.{info});
            } else {
                try std.testing.expectEqualStrings("/preflight", path);
                try std.testing.expectError(error.InvalidStatus, stream.startResponseWithBodyAndInformational(.{ .status = 200 }, 1, "x", true, &.{ info, .{ .status = 200 } }));
                try stream.startResponseWithBodyAndInformational(.{ .status = 200 }, 1, "x", true, &.{info});
            }
        }
    };
    const Worker = struct {
        fn run(listener: *runtime.HandshakeServer, ctx: *Context) !void {
            var session = try listener.acceptWithTimeout(.fromSeconds(5));
            defer session.deinit();
            const summary = try session.serveConcurrentStreams(Context, ctx, Handler.run, .{ .max_streams = 2, .shutdown = ctx.shutdown });
            try std.testing.expectEqual(@as(usize, 10), summary.completed);
            try std.testing.expectEqual(@as(usize, 0), summary.failed);
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, &context });
    defer _ = serving.cancel(io) catch {};
    var client = try runtime.HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), limits, .{
        .handshake = .{ .original_destination_connection_id = &.{ 9, 8, 7, 6, 5, 4, 3, 2 }, .local_connection_id = &.{ 2, 3, 4, 5, 6, 7, 8, 9 }, .server_name = "localhost", .server_auth = .{ .pinned_ecdsa_p256_public_key = public_key } },
    });
    defer client.deinit();
    const paths = [_][]const u8{ "/split", "/combined", "/buffered", "/large", "/literal", "/head", "/preflight", "/no-content", "/not-modified", "/empty-trailers" };
    for (paths, 0..) |path, index| {
        var observer = Observer{};
        var response = client.requestWithInformationalAndDeadline(.{ .method = if (index == 5) "HEAD" else "GET", .path = path, .authority = "localhost" }, .{ .context = &observer, .on_response = Observer.observe }, deadline(io)) catch |err| {
            std.debug.print("H3 informational client {s}: {s}\n", .{ path, @errorName(err) });
            return err;
        };
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, if (index == 7) 204 else if (index == 8) 304 else 200), response.response.status);
        try std.testing.expectEqual(@as(usize, if (index == 0) 2 else 1), observer.count);
        try std.testing.expectEqual(@as(u16, 103), observer.statuses[observer.count - 1]);
        if (index < 2) {
            try std.testing.expectEqualStrings("alphabeta", response.response.body);
            try std.testing.expectEqualStrings("done", field(response.response.trailers, "x-finished").?);
        } else if (index < 4) {
            try std.testing.expectEqualStrings(&context.body, response.response.body);
            try std.testing.expectEqualStrings("v", field(response.response.headers, "x-field-23").?);
            try std.testing.expectEqualStrings("9000", field(response.response.headers, "content-length").?);
            if (index == 2) try std.testing.expectEqualStrings("done", field(response.response.trailers, "x-finished").?);
        } else if (index == 4) {
            try std.testing.expectEqualStrings("body", response.response.body);
        } else if (index == 5) {
            try std.testing.expectEqualStrings("", response.response.body);
            try std.testing.expectEqualStrings("4", field(response.response.headers, "content-length").?);
        } else if (index == 6) {
            try std.testing.expectEqualStrings("x", response.response.body);
        } else {
            try std.testing.expectEqualStrings("", response.response.body);
            if (index == 7) try std.testing.expect(field(response.response.headers, "content-length") == null);
            if (index == 8) try std.testing.expectEqualStrings("4", field(response.response.headers, "content-length").?);
            if (index == 9) try std.testing.expectEqualStrings("done", field(response.response.trailers, "x-finished").?);
        }
    }
    shutdown.set(io);
    try serving.await(io);
}

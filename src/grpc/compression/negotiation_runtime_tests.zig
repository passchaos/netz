//! Real RPC output follows the most recent accepted-encoding field.
const std = @import("std");
const grpc = @import("../mod.zig");
const http2 = @import("../../http2/mod.zig");
const allocator = std.testing.allocator;
const payload = "compressible response " ** 64;
const Mode = enum { unary, server_stream, client_stream, duplex, web };
const Case = struct { first: []const u8, last: []const u8, response: grpc.CompressionAlgorithm, compressed: bool };
const cases = [_]Case{
    .{ .first = "gzip", .last = "deflate", .response = .gzip, .compressed = false },
    .{ .first = "deflate", .last = "gzip", .response = .gzip, .compressed = true },
    .{ .first = "gzip", .last = "unknown", .response = .gzip, .compressed = false },
    .{ .first = "gzip", .last = "unknown, deflate", .response = .deflate, .compressed = true },
    .{ .first = "gzip,deflate", .last = "", .response = .gzip, .compressed = false },
};

const Collector = struct {
    count: usize = 0,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        try std.testing.expectEqualStrings("input", message.payload);
        self.count += 1;
    }
};

fn serve(connection: *grpc.runtime.ServerConnection, mode: Mode, row: Case) !void {
    switch (mode) {
        .unary => {
            var request = try connection.readUnaryWithTimeout(.fromSeconds(2));
            defer request.deinit();
            try connection.writeUnary(request.request.stream_id, .{ .message = payload, .compression = row.response, .request_accepted_encodings = request.request.accepted_encodings });
        },
        .server_stream, .client_stream => {
            var collector: Collector = .{};
            var request = try connection.readStreamingWithTimeout(.fromSeconds(2), &collector, Collector.consume);
            defer request.deinit();
            try std.testing.expectEqual(@as(usize, if (mode == .client_stream) 2 else 1), collector.count);
            if (mode == .client_stream) {
                try connection.writeUnary(request.transport.stream_id, .{ .message = payload, .compression = row.response, .request_accepted_encodings = request.accepted_encodings });
            } else {
                var writer = try grpc.startStreamingResponse(&connection.connection, allocator, request.transport.stream_id, .{ .compression = row.response, .request_accepted_encodings = request.accepted_encodings });
                defer writer.deinit();
                try writer.writeMessage(payload);
                try writer.writeMessage(payload);
                try writer.finishOk();
            }
        },
        .duplex => {
            var stream = try connection.acceptDuplexWithTimeout(.fromSeconds(2));
            defer stream.deinit();
            var collector: Collector = .{};
            while (true) {
                var event = try stream.readRequestEventWithTimeout(.fromSeconds(2), &collector, Collector.consume);
                defer event.deinit();
                if (event == .finished) break;
                if (event == .reset) return error.UnexpectedReset;
            }
            try std.testing.expectEqual(@as(usize, 2), collector.count);
            try stream.startResponse(.{ .compression = row.response, .request_accepted_encodings = stream.accepted_encodings });
            try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(payload));
            try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try stream.writeMessage(payload));
            try stream.finishOk();
        },
        .web => {
            var request = try connection.readUnaryWebWithTimeout(.fromSeconds(2));
            defer request.deinit();
            try connection.writeUnaryWeb(request.request.stream_id, .{ .message = payload, .compression = row.response, .request_accepted_encodings = request.request.accepted_encodings }, request.content_type);
        },
    }
}

fn exercise(mode: Mode) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server = try grpc.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{}, 4096);
    defer server.deinit();
    const Peer = struct {
        server: *grpc.runtime.Server,
        mode: Mode,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }
        fn runFallible(self: *@This()) !void {
            var connection = try self.server.acceptWithTimeout(.fromSeconds(2));
            defer connection.deinit();
            for (cases) |row| try serve(&connection, self.mode, row);
        }
    };
    var peer: Peer = .{ .server = &server, .mode = mode };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    var client = try http2.runtime.Client.connect(allocator, io, server.address(), .{});
    defer client.close();
    var framed: std.ArrayList(u8) = .empty;
    defer framed.deinit(allocator);
    try grpc.writeMessage(&framed, allocator, "input", false);
    if (mode == .client_stream or mode == .duplex) try grpc.writeMessage(&framed, allocator, "input", false);
    for (cases) |row| {
        const fields = [_]http2.Hpack.HeaderField{
            .{ .name = "te", .value = "trailers" },
            .{ .name = "content-type", .value = if (mode == .web) "application/grpc-web+proto" else "application/grpc" },
            .{ .name = "grpc-accept-encoding", .value = row.first },
            .{ .name = "grpc-accept-encoding", .value = row.last },
        };
        var response = try client.requestWithTimeout(.{ .method = "POST", .path = "/fixture.Compression/Call", .authority = "localhost", .headers = if (mode == .web) fields[1..] else &fields, .body = framed.items }, .fromSeconds(2));
        defer response.deinit(allocator);
        const encoding = grpc.call.headerValue(response.headers, "grpc-encoding");
        if (row.compressed) try std.testing.expectEqualStrings(row.response.name(), encoding.?) else try std.testing.expect(encoding == null);
        var messages = grpc.MessageIterator.init(response.body, 4096);
        const count: usize = if (mode == .server_stream or mode == .duplex) 2 else 1;
        for (0..count) |_| {
            const message = (try messages.next()).?;
            try std.testing.expectEqual(row.compressed, message.compressed);
            var decoded = try grpc.decompressMessageAlloc(allocator, if (row.compressed) row.response else .identity, message.payload, 4096);
            defer decoded.deinit(allocator);
            try std.testing.expectEqualStrings(payload, decoded.bytes);
        }
        if (mode == .web) {
            try std.testing.expectEqual(@as(u8, 0x80), response.body[messages.offset]);
        } else {
            try std.testing.expectEqual(@as(?grpc.Message, null), try messages.next());
            try std.testing.expectEqualStrings("0", grpc.call.headerValue(response.trailers, "grpc-status").?);
        }
    }
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

test "gRPC compression negotiation follows the last field across RPC shapes and Web" {
    for (std.enums.values(Mode)) |mode| try exercise(mode);
}

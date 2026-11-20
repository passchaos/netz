//! Timed HTTP/1 output preserves framing ownership and body-byte accounting.
const std = @import("std");
const runtime = @import("../runtime.zig");
const backend_mod = @import("../../runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io, milliseconds: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
}

const Pair = struct {
    client: std.Io.net.Stream,
    peer: std.Io.net.Stream,
    fn open(io: std.Io) !Pair {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
        defer listener.deinit(io);
        const client = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer client.close(io);
        return .{ .client = client, .peer = try listener.accept(io) };
    }
};

fn exchange(io: std.Io, strategy: runtime.WriteStrategy) !void {
    const pair = try Pair.open(io);
    var client = runtime.Client{ .io = io, .allocator = allocator, .stream = pair.client, .limits = .{ .write_strategy = strategy } };
    defer client.close();
    var server = runtime.Connection{ .io = io, .allocator = allocator, .stream = pair.peer, .limits = .{ .write_strategy = strategy } };
    defer server.close();
    const Peer = struct {
        fn run(connection: *runtime.Connection) !void {
            var saved: ?runtime.ResponseWriter = null;
            for (0..3) |round| {
                var request = try connection.readRequestWithDeadline(.{}, deadline(connection.io, 2000));
                defer request.deinit(allocator);
                try std.testing.expectEqualStrings("zabcdef", request.request.body);
                try std.testing.expectEqualStrings("yes", request.request.trailers[0].value);
                if (round == 2) {
                    try connection.writeResponseWithTimeout(.{ .body = "reply", .trailers = &.{.{ .name = "x-final", .value = "done" }}, .request_accepts_trailers = request.request.acceptsTrailers() }, .fromSeconds(2));
                    continue;
                }
                var response = try connection.startResponseWithDeadline(.{ .body_length = null, .trailer_names = &.{"x-final"}, .request_accepts_trailers = request.request.acceptsTrailers() }, deadline(connection.io, 2000));
                defer response.deinit();
                try response.writeChunksWithDeadline(&.{ "re", "", "ply" }, deadline(connection.io, 2000));
                try std.testing.expectEqual(@as(usize, 5), response.committedBytes());
                try response.finishTrailersWithTimeout(&.{.{ .name = "x-final", .value = "done" }}, .fromSeconds(2));
                if (saved) |value| try std.testing.expectEqual(@as(usize, 5), value.committedBytes());
                saved = response;
            }
        }
    };
    var peer = try io.concurrent(Peer.run, .{&server});
    defer _ = peer.cancel(io) catch {};
    var saved: ?runtime.RequestWriter = null;
    for (0..3) |_| {
        var writer = try client.startRequestWithTimeout(.{ .method = .POST, .target = "/upload", .host = "localhost", .body_length = null, .trailer_names = &.{"x-end"}, .headers = &.{.{ .name = "te", .value = "trailers" }} }, .fromSeconds(2));
        defer writer.deinit();
        try writer.writeWithTimeout("z", .fromSeconds(2));
        try writer.writeChunksWithDeadline(&.{ "ab", "", "cdef" }, deadline(io, 2000));
        try std.testing.expectEqual(@as(usize, 7), writer.committedBytes());
        try writer.finishTrailersWithDeadline(&.{.{ .name = "x-end", .value = "yes" }}, deadline(io, 2000));
        var response = try writer.readResponseWithDeadline(deadline(io, 2000));
        defer response.deinit(allocator);
        try std.testing.expectEqualStrings("reply", response.response.body);
        try std.testing.expectEqualStrings("done", response.response.trailers[0].value);
        if (saved) |value| try std.testing.expectEqual(@as(usize, 7), value.committedBytes());
        saved = writer;
    }
    try peer.await(io);
}

test "HTTP/1 streaming deadlines compose request and response chunks trailers and reuse" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    for (std.enums.values(runtime.WriteStrategy)) |strategy| try exchange(threaded.io(), strategy);
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    for (std.enums.values(runtime.WriteStrategy)) |strategy| try exchange(backend.io(), strategy);
}

const Probe = struct {
    var active: *Probe = undefined;
    delegate: std.Io,
    armed: bool = false,
    remaining: usize = 0,
    calls: usize = 0,
    captured: [64]u8 = undefined,
    captured_len: usize = 0,
    never: std.Io.Event = .unset,

    fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, data: []const []const u8, splat: usize) std.Io.net.Stream.Writer.Error!usize {
        const self = active;
        std.debug.assert(splat == 0);
        self.calls += 1;
        var total = header.len;
        for (data[0 .. data.len - 1]) |part| total += part.len;
        if (!self.armed) return total;
        if (self.remaining == 0) {
            try self.never.wait(self.delegate);
            return error.Unexpected;
        }
        const count = @min(total, self.remaining);
        var left = count;
        const first = @min(header.len, left);
        @memcpy(self.captured[self.captured_len..][0..first], header[0..first]);
        self.captured_len += first;
        left -= first;
        for (data[0 .. data.len - 1]) |part| {
            const n = @min(part.len, left);
            @memcpy(self.captured[self.captured_len..][0..n], part[0..n]);
            self.captured_len += n;
            left -= n;
            if (left == 0) break;
        }
        self.remaining -= count;
        return count;
    }

    fn io(self: *Probe, table: *std.Io.VTable) std.Io {
        active = self;
        table.* = self.delegate.vtable.*;
        table.netWrite = write;
        return .{ .userdata = self.delegate.userdata, .vtable = table };
    }
};

fn partial(comptime request: bool, strategy: runtime.WriteStrategy, mode: enum { fixed, chunk, chunks }) !void {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const pair = try Pair.open(base);
    defer pair.peer.close(base);
    var probe = Probe{ .delegate = base };
    var table: std.Io.VTable = undefined;
    const io = probe.io(&table);
    var owner = if (request)
        runtime.Client{ .io = io, .allocator = allocator, .stream = pair.client, .limits = .{ .write_strategy = strategy } }
    else
        runtime.Connection{ .io = io, .allocator = allocator, .stream = pair.client, .limits = .{ .write_strategy = strategy } };
    defer owner.close();
    const length: ?usize = if (mode == .fixed) 7 else null;
    var writer = if (request)
        try owner.startRequestWithDeadline(.{ .method = .POST, .target = "/partial", .host = "localhost", .body_length = length }, deadline(io, 2000))
    else
        try owner.startResponseWithDeadline(.{ .body_length = length }, deadline(io, 2000));
    defer writer.deinit();
    try writer.write("z");
    probe.armed = true;
    probe.remaining = switch (mode) {
        .fixed => 2,
        .chunk => 5,
        .chunks => 12,
    };
    const result = if (mode == .chunks)
        writer.writeChunksWithDeadline(&.{ "ab", "cdef" }, deadline(io, 30))
    else
        writer.writeWithDeadline("abcdef", deadline(io, 30));
    try std.testing.expectError(error.Timeout, result);
    try std.testing.expectEqual(@as(usize, if (mode == .chunks) 5 else 3), writer.committedBytes());
    const wire = switch (mode) {
        .fixed => "ab",
        .chunk => "6\r\nab",
        .chunks => "2\r\nab\r\n4\r\ncd",
    };
    try std.testing.expectEqualStrings(wire, probe.captured[0..probe.captured_len]);
    try std.testing.expectEqual(runtime.body_writer.State.Phase.unusable, owner.writer_state.phase);
    try std.testing.expectError(error.InvalidWriterState, writer.write("retry"));
}

test "HTTP/1 streaming deadlines retain exact body progress after partial timed output" {
    inline for ([_]bool{ false, true }) |request| {
        for (std.enums.values(runtime.WriteStrategy)) |strategy| {
            inline for (.{ .fixed, .chunk, .chunks }) |mode| try partial(request, strategy, mode);
        }
    }
}

test "HTTP/1 streaming deadlines reject expired setup writes finish and continue without I/O" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const base = threaded.io();
    const pair = try Pair.open(base);
    defer pair.peer.close(base);
    var probe = Probe{ .delegate = base };
    var table: std.Io.VTable = undefined;
    const io = probe.io(&table);
    var client = runtime.Client{ .io = io, .allocator = allocator, .stream = pair.client };
    defer client.close();
    const expired: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = .zero };
    const options: runtime.StreamingRequestOptions = .{ .method = .POST, .target = "/expired", .host = "localhost", .body_length = null, .headers = &.{.{ .name = "expect", .value = "100-continue" }} };
    try std.testing.expectError(error.Timeout, client.startRequestWithDeadline(options, expired));
    try std.testing.expectEqual(@as(usize, 0), probe.calls);
    try std.testing.expectEqual(runtime.body_writer.State.Phase.idle, client.writer_state.phase);
    var writer = try client.startRequestWithDeadline(options, deadline(io, 2000));
    defer writer.deinit();
    const calls = probe.calls;
    try std.testing.expectError(error.Timeout, writer.writeWithDeadline("body", expired));
    try std.testing.expectError(error.Timeout, writer.writeChunksWithDeadline(&.{"body"}, expired));
    try std.testing.expectError(error.Timeout, writer.finishWithDeadline(expired));
    try std.testing.expectError(error.Timeout, writer.finishTrailersWithDeadline(&.{}, expired));
    try std.testing.expectError(error.Timeout, writer.waitForContinueWithDeadline(expired));
    try std.testing.expectEqual(calls, probe.calls);
    try std.testing.expectEqual(runtime.body_writer.State.Phase.writing, client.writer_state.phase);
    try std.testing.expect(!client.writer_state.expect_continue_received);
    try std.testing.expect(client.response_deadline == null);
}

test "HTTP/1 streaming deadlines bound the body of an early final response while waiting for Continue" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const pair = try Pair.open(io);
    defer pair.peer.close(io);
    var client = runtime.Client{ .io = io, .allocator = allocator, .stream = pair.client };
    defer client.close();
    const Peer = struct {
        io: std.Io,
        stream: std.Io.net.Stream,
        sent: std.Io.Event = .unset,
        never: std.Io.Event = .unset,
        fn run(self: *@This()) !void {
            var buffer: [512]u8 = undefined;
            var reader = self.stream.reader(self.io, &buffer);
            while (true) {
                const line = try reader.interface.takeDelimiterInclusive('\n');
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            try runtime.stream_io.writeAllSlices(self.io, self.stream, &.{"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"});
            self.sent.set(self.io);
            try self.never.wait(self.io);
        }
    };
    var peer = Peer{ .io = io, .stream = pair.peer };
    var task = try io.concurrent(Peer.run, .{&peer});
    defer _ = task.cancel(io) catch {};
    var writer = try client.startRequestWithDeadline(.{ .method = .POST, .target = "/reject", .host = "localhost", .body_length = 5, .headers = &.{.{ .name = "expect", .value = "100-continue" }} }, deadline(io, 2000));
    defer writer.deinit();
    try peer.sent.wait(io);
    try std.testing.expectError(error.Timeout, writer.waitForContinueWithDeadline(deadline(io, 30)));
    try std.testing.expectEqual(runtime.body_writer.State.Phase.unusable, client.writer_state.phase);
    try std.testing.expect(client.response_deadline == null);
}

test "HTTP/1 streaming deadlines preserve Continue observation and retry after pre-expiry" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    const pair = try Pair.open(io);
    defer pair.peer.close(io);
    var client = runtime.Client{ .io = io, .allocator = allocator, .stream = pair.client };
    defer client.close();
    const Peer = struct {
        fn run(task_io: std.Io, stream: std.Io.net.Stream) !void {
            var buffer: [512]u8 = undefined;
            var reader = stream.reader(task_io, &buffer);
            while (true) {
                const line = try reader.interface.takeDelimiterInclusive('\n');
                if (std.mem.eql(u8, line, "\r\n")) break;
            }
            try runtime.stream_io.writeAllSlices(task_io, stream, &.{"HTTP/1.1 103 Early Hints\r\nx-hint: before-continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n"});
            var body: [4]u8 = undefined;
            try reader.interface.readSliceAll(&body);
            try std.testing.expectEqualStrings("body", &body);
            try runtime.stream_io.writeAllSlices(task_io, stream, &.{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"});
        }
    };
    var peer = try io.concurrent(Peer.run, .{ io, pair.peer });
    defer _ = peer.cancel(io) catch {};
    var writer = try client.startRequestWithDeadline(.{ .method = .POST, .target = "/continue", .host = "localhost", .body_length = 4, .headers = &.{.{ .name = "expect", .value = "100-continue" }} }, deadline(io, 2000));
    defer writer.deinit();
    try std.testing.expectError(error.Timeout, writer.waitForContinueWithDeadline(.{ .clock = .awake, .raw = .zero }));
    const Observations = struct {
        statuses: [2]u16 = undefined,
        count: usize = 0,
        fn observe(context: *anyopaque, head: runtime.InformationalResponseHead) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.statuses[self.count] = head.status;
            self.count += 1;
        }
    };
    var observations: Observations = .{};
    const continued = try writer.waitForContinueWithInformationalAndTimeout(.{ .context = &observations, .on_response = Observations.observe }, .fromSeconds(2));
    try std.testing.expect(continued == .proceed);
    try std.testing.expectEqualSlices(u16, &.{ 103, 100 }, observations.statuses[0..observations.count]);
    try writer.writeWithDeadline("body", deadline(io, 2000));
    try writer.finishWithDeadline(deadline(io, 2000));
    var response = try writer.readResponseWithDeadline(deadline(io, 2000));
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("ok", response.response.body);
    try peer.await(io);
}

test "HTTP/1 streaming deadlines cover native TLS12 native TLS13 and standard TLS13" {
    const tls_testing = @import("../../tls/testing.zig");
    const Mode = enum { native12, native13, standard13 };
    for (std.enums.values(Mode)) |mode| {
        var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
        defer threaded.deinit();
        const io = threaded.io();
        var certificate: [tls_testing.certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
        const key = try tls_testing.serverKeyPair();
        var server = try runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{
            .identity = .{ .certificate_chain = &.{&certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } } },
            .protocol_policy = if (mode == .native12) .tls12_only else .tls13_only,
        });
        defer server.deinit();
        const Peer = struct {
            fn run(listener: *runtime.TlsServer, task_io: std.Io) !void {
                var connection = try listener.acceptWithDeadline(deadline(task_io, 3000));
                defer connection.close();
                for (0..2) |_| {
                    var request = try connection.readRequestWithDeadline(.{}, deadline(task_io, 3000));
                    defer request.deinit(allocator);
                    try std.testing.expectEqualStrings("upload", request.request.body);
                    var writer = try connection.startResponseWithDeadline(.{
                        .trailer_names = &.{"x-finished"},
                        .request_accepts_trailers = request.request.acceptsTrailers(),
                    }, deadline(task_io, 3000));
                    defer writer.deinit();
                    try writer.writeChunksWithDeadline(&.{ "TLS", " response" }, deadline(task_io, 3000));
                    try writer.finishTrailersWithDeadline(&.{.{ .name = "x-finished", .value = "yes" }}, deadline(task_io, 3000));
                    try std.testing.expectEqual(@as(usize, 12), writer.committedBytes());
                }
            }
        };
        var peer = try io.concurrent(Peer.run, .{ &server, io });
        defer _ = peer.cancel(io) catch {};
        var client = if (mode == .standard13)
            try runtime.Client.connectTlsAddressWithDeadline(allocator, io, server.address(), "localhost", "localhost", .{}, .{ .verify_host = false }, deadline(io, 3000))
        else
            try runtime.Client.connectVailTlsAddressWithDeadline(allocator, io, server.address(), "localhost", .{}, .{
                .protocol_policy = if (mode == .native12) .tls12_only else .tls13_only,
                .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            }, deadline(io, 3000));
        defer client.close();
        for (0..2) |_| {
            var writer = try client.startRequestWithDeadline(.{ .method = .POST, .target = "/tls-upload", .headers = &.{.{ .name = "te", .value = "trailers" }} }, deadline(io, 3000));
            defer writer.deinit();
            try writer.writeChunksWithDeadline(&.{ "up", "load" }, deadline(io, 3000));
            try writer.finishWithDeadline(deadline(io, 3000));
            try std.testing.expectEqual(@as(usize, 6), writer.committedBytes());
            var response = try writer.readResponseWithDeadline(deadline(io, 3000));
            defer response.deinit(allocator);
            try std.testing.expectEqualStrings("TLS response", response.response.body);
            try std.testing.expectEqualStrings("yes", response.response.trailers[0].value);
        }
        try peer.await(io);
    }
}

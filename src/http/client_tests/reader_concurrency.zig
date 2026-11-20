//! Source I/O and cancellation must not stop the H2 frame owner.
const std = @import("std");
const http = @import("../mod.zig");
const runtime = @import("../../http2/runtime.zig");
const backend_mod = @import("../../runtime.zig");
const allocator = std.testing.allocator;

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}

const GatedReader = struct {
    reader: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    io: std.Io,
    started: std.Io.Event = .unset,
    gate: std.Io.Event = .unset,
    canceled: bool = false,
    prefix_len: usize = 0,
    offset: usize = 0,

    fn stream(reader: *std.Io.Reader, writer: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *GatedReader = @fieldParentPtr("reader", reader);
        self.started.set(self.io);
        const body = "reader-body";
        if (self.offset == body.len) return error.EndOfStream;
        const available = if (self.offset < self.prefix_len) self.prefix_len - self.offset else blk: {
            self.gate.wait(self.io) catch {
                self.canceled = true;
                return error.ReadFailed;
            };
            break :blk body.len - self.offset;
        };
        const count = try writer.write(body[self.offset..][0..limit.minInt(available)]);
        self.offset += count;
        return count;
    }
};

fn exercise(io: std.Io, comptime cancel_reader: bool) !void {
    var source = GatedReader{ .io = io, .prefix_len = if (cancel_reader) 0 else 3 };
    var shutdown: std.Io.Event = .unset;
    var server = try runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(0) }, .{});
    defer server.deinit();
    const Context = struct {
        source: *GatedReader,
        shutdown: *std.Io.Event,
        head_received: std.Io.Event = .unset,
        prefix_received: std.Io.Event = .unset,
        accepts: usize = 0,
    };
    var context = Context{ .source = &source, .shutdown = &shutdown };
    const Handler = struct {
        fn run(ctx: *Context, request: *runtime.Connection.ConcurrentStream) anyerror!void {
            const io_value = ctx.source.io;
            if (std.mem.eql(u8, request.head().path, "/held")) {
                ctx.head_received.set(io_value);
                var body: [64]u8 = undefined;
                var length: usize = 0;
                while (request.nextBody(body[length..], deadline(io_value)) catch |err| {
                    if (cancel_reader) return;
                    return err;
                }) |count| {
                    length += count;
                    if (length >= ctx.source.prefix_len) ctx.prefix_received.set(io_value);
                }
                if (cancel_reader) return error.TestUnexpectedResult;
                try std.testing.expectEqualStrings("reader-body", body[0..length]);
                try request.startResponse(.{ .status = 200 });
                try request.writeData("held-complete", true);
            } else {
                try request.startResponse(.{ .status = 200 });
                try request.writeData("probe-complete", true);
                // The blocked source cannot advance until a later sibling
                // was serviced over this exact connection.
                if (!cancel_reader) ctx.source.gate.set(io_value);
            }
        }
    };
    const Worker = struct {
        fn run(listener: *runtime.Server, ctx: *Context) !void {
            var connection = try listener.acceptWithDeadline(deadline(listener.io));
            defer connection.close();
            ctx.accepts += 1;
            const summary = try connection.serveConcurrentStreams(Context, ctx, Handler.run, .{
                .max_streams = 2,
                .shutdown = ctx.shutdown,
            });
            try std.testing.expectEqual(@as(usize, 3), summary.accepted);
        }
    };
    var serving = try io.concurrent(Worker.run, .{ &server, &context });
    defer _ = serving.cancel(io) catch {};
    var pool = try http.Pool.init(allocator, io, .{
        .max_connections = 1,
        .max_idle_connections = 1,
        .max_idle_per_origin = 1,
        .client = .{ .cleartext_protocol = .http2_prior_knowledge },
    });
    defer pool.deinit();
    const held_uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/held", .{server.address().getPort()});
    defer allocator.free(held_uri);
    const probe_uri = try std.fmt.allocPrint(allocator, "http://127.0.0.1:{d}/probe", .{server.address().getPort()});
    defer allocator.free(probe_uri);
    const Request = struct {
        fn run(owner: *http.Pool, uri: []const u8, reader: *std.Io.Reader) !http.OwnedResponse {
            return owner.requestUri(uri, .{ .method = "POST", .body_source = .{ .reader = .{ .reader = reader } } });
        }
    };
    var held = try io.concurrent(Request.run, .{ &pool, held_uri, &source.reader });
    var held_done = false;
    defer if (!held_done) if (held.cancel(io)) |value| {
        var response = value;
        response.deinit();
    } else |_| {};
    try source.started.waitTimeout(io, .{ .deadline = deadline(io) });
    try context.head_received.waitTimeout(io, .{ .deadline = deadline(io) });
    if (!cancel_reader) try context.prefix_received.waitTimeout(io, .{ .deadline = deadline(io) });
    var probe = try pool.requestUriWithDeadline(probe_uri, .{}, deadline(io));
    defer probe.deinit();
    try std.testing.expectEqualStrings("probe-complete", probe.body());
    if (cancel_reader) {
        try std.testing.expectError(error.Canceled, held.cancel(io));
        held_done = true;
        // Cancellation joins the producer before the borrowed Reader can go.
        try std.testing.expect(source.canceled);
        try std.testing.expectEqual(@as(usize, 0), source.offset);
    } else {
        var response = try held.await(io);
        held_done = true;
        defer response.deinit();
        try std.testing.expectEqualStrings("held-complete", response.body());
    }
    var later = try pool.requestUriWithDeadline(probe_uri, .{}, deadline(io));
    defer later.deinit();
    try std.testing.expectEqualStrings("probe-complete", later.body());
    shutdown.set(io);
    try serving.await(io);
    try std.testing.expectEqual(@as(usize, 1), context.accepts);
}

test "unified HTTP pooled H2 blocked Reader permits late siblings" {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    try exercise(threaded.io(), false);
}

test "unified HTTP pooled H2 cancels a blocked Reader and preserves reuse" {
    var backend = try backend_mod.Backend.initZio(allocator);
    defer backend.deinit();
    try exercise(backend.io(), true);
}

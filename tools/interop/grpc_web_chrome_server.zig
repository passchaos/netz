//! Production HTTP/1.1 adapter exercised by the official browser gRPC-Web SDK.
const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 3 and args.len != 5 and args.len != 6) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.initZio(allocator);
    defer backend.deinit();
    const io = backend.io();
    if (args.len >= 5) {
        const certificate = try std.Io.Dir.cwd().readFileAlloc(io, args[3], allocator, .limited(16 * 1024));
        defer allocator.free(certificate);
        const scalar = try std.Io.Dir.cwd().readFileAlloc(io, args[4], allocator, .limited(33));
        defer allocator.free(scalar);
        if (scalar.len != 32) return error.InvalidArgument;
        const Key = std.crypto.sign.ecdsa.EcdsaP256Sha256;
        const key = try Key.KeyPair.fromSecretKey(try Key.SecretKey.fromBytes(scalar[0..32].*));
        if (args.len == 6) {
            if (!std.mem.eql(u8, args[5], "--http2")) return error.InvalidArgument;
            var server = try netz.http2.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(port) }, .{ .identity = .{
                .certificate_chain = &.{certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            } });
            defer server.deinit();
            try run(&server, args[2], io, "https", true);
        } else {
            var server = try netz.http1.runtime.TlsServer.listen(allocator, io, .{ .ip4 = .loopback(port) }, .{ .identity = .{
                .certificate_chain = &.{certificate},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key } },
            } });
            defer server.deinit();
            try run(&server, args[2], io, "https", false);
        }
    } else {
        var server = try netz.http1.runtime.Server.listen(allocator, io, .{ .ip4 = .loopback(port) }, .{});
        defer server.deinit();
        try run(&server, args[2], io, "http", false);
    }
}

const Context = struct {
    io: std.Io,
    options: netz.grpc.web.http1.Options,
    group: std.Io.Group = .init,
    done: std.Io.Event = .unset,
    ack: std.Io.Event = .unset,
    stopping: std.atomic.Value(bool) = .init(false),
    rpc_count: std.atomic.Value(u32) = .init(0),
    preflight_count: std.atomic.Value(u32) = .init(0),
    rejected_count: std.atomic.Value(u32) = .init(0),
    failure_mutex: std.Io.Mutex = .init,
    failure: ?anyerror = null,

    fn stop(self: *Context) void {
        self.stopping.store(true, .release);
        self.done.set(self.io);
    }
    fn fail(self: *Context, err: anyerror) void {
        if (self.stopping.load(.acquire)) return;
        self.failure_mutex.lockUncancelable(self.io);
        if (self.failure == null) self.failure = err;
        self.failure_mutex.unlock(self.io);
        self.stop();
    }
    fn serve(self: *Context, value: netz.http1.runtime.Connection) std.Io.Cancelable!void {
        var connection = value;
        defer connection.close();
        self.serveConnection(&connection, netz.grpc.web.http1) catch |err| {
            const idle_tls_close = err == error.UnexpectedEof and connection.inbuf.items.len == 0;
            if (!idle_tls_close and err != error.Canceled and err != error.ConnectionUnusable and err != error.ConnectionClosed) self.fail(err);
        };
    }
    fn serveHttp2(self: *Context, value: netz.http2.runtime.Connection) std.Io.Cancelable!void {
        var connection = value;
        defer connection.close();
        self.serveConnection(&connection, netz.grpc.web.http2) catch |err| {
            if (err != error.Canceled and err != error.ConnectionClosed and err != error.UnexpectedEof and err != error.ConnectionGoAway) self.fail(err);
        };
    }
    fn serveConnection(self: *Context, connection: anytype, comptime Adapter: type) !void {
        while (!self.stopping.load(.acquire)) {
            const event = try Adapter.readRequest(connection, self.options);
            if (event == .handled) {
                if (event.handled.status == 204) _ = self.preflight_count.fetchAdd(1, .monotonic);
                if (event.handled.status == 403) _ = self.rejected_count.fetchAdd(1, .monotonic);
                continue;
            }
            var request = event.request;
            defer request.deinit();
            if (!std.mem.eql(u8, try netz.grpc.parseBearerToken(request.request.headers), "grpc-web-test")) return error.UnexpectedAuthorization;
            _ = self.rpc_count.fetchAdd(1, .monotonic);
            if (std.mem.eql(u8, request.request.method, "Stream")) {
                var stream = try request.startServerStream(.{ .initial_metadata = &.{.{ .name = "x-initial", .value = "visible" }} });
                defer stream.deinit();
                try stream.writeMessage("a" ** 32768);
                try self.ack.waitTimeout(self.io, .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } });
                try stream.writeMessage("second");
                try stream.finish(.{ .status = .ok, .trailing_metadata = &.{.{ .name = "x-terminal", .value = "done" }} });
            } else if (std.mem.eql(u8, request.request.method, "Denied")) {
                try request.writeUnary(.{ .status = .unauthenticated, .status_message = "bad token", .trailers_only = true });
            } else {
                try request.writeUnary(.{ .message = request.request.message.payload, .initial_metadata = &.{.{ .name = "x-initial", .value = "visible" }} });
                if (std.mem.eql(u8, request.request.method, "Ack")) self.ack.set(self.io);
                if (std.mem.eql(u8, request.request.method, "Finish")) self.stop();
            }
        }
    }
};

fn run(server: anytype, origin: []const u8, io: std.Io, scheme: []const u8, comptime http2_mode: bool) !void {
    var context: Context = .{ .io = io, .options = .{ .cors_policy = .{
        .allowed_origins = &.{origin},
        .allow_credentials = true,
        .exposed_headers = &.{ "grpc-status", "grpc-message", "grpc-encoding", "x-initial" },
    } } };
    defer context.group.cancel(io);
    const Acceptor = struct {
        fn accept(ctx: *Context, listener: @TypeOf(server)) std.Io.Cancelable!void {
            while (!ctx.stopping.load(.acquire)) {
                var connection = listener.accept() catch |err| {
                    if (http2_mode and (err == error.UnexpectedEof or err == error.ConnectionClosed or err == error.SocketUnconnected or err == error.ConnectionResetByPeer or err == error.TruncatedRecord)) continue;
                    if (err != error.Canceled) ctx.fail(err);
                    return;
                };
                ctx.group.concurrent(ctx.io, if (http2_mode) Context.serveHttp2 else Context.serve, .{ ctx, connection }) catch |err| {
                    connection.close();
                    ctx.fail(err);
                    return;
                };
            }
        }
    };
    try context.group.concurrent(io, Acceptor.accept, .{ &context, server });
    std.debug.print("gRPC-Web browser listening port={d} scheme={s} io=zio-std-io protocol={s}\n", .{ server.address().ip4.port, scheme, if (http2_mode) "h2" else "http/1.1" });
    try context.done.waitTimeout(io, .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } });
    context.group.cancel(io);
    if (context.failure) |err| return err;
    const rpc = context.rpc_count.load(.acquire);
    const preflight = context.preflight_count.load(.acquire);
    const rejected = context.rejected_count.load(.acquire);
    if (rpc != 6 or preflight == 0 or rejected == 0) return error.IncompleteBrowserGate;
    std.debug.print("gRPC-Web browser complete rpc={d} preflight={d} rejected={d} io=zio-std-io\n", .{ rpc, preflight, rejected });
}

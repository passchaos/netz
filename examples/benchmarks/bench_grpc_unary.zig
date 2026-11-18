const std = @import("std");
const netz = @import("netz");

const Options = struct {
    payload_bytes: usize = 262144,
    warmup: usize = 20,
    iterations: usize = 200,
    cached_allocator: bool = false,
    shared: bool = false,
    validate: bool = true,
    /// Server responses use the prefix-reserved owned buffer. Pass
    /// --borrowed-response for the staged borrowed path.
    owned_response: bool = true,
    /// Client requests serialize into prefix-reserved storage. Pass
    /// --owned-request for that path instead of the staged borrowed request.
    owned_request: bool = false,
};

fn parse(init: std.process.Init) !Options {
    var options: Options = .{};
    var args = try std.process.Args.Iterator.initAllocator(
        init.minimal.args,
        std.heap.smp_allocator,
    );
    defer args.deinit();
    _ = args.next();
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--cached-allocator")) {
            options.cached_allocator = true;
        } else if (std.mem.eql(u8, arg, "--shared")) {
            options.shared = true;
        } else if (std.mem.eql(u8, arg, "--no-validate")) {
            options.validate = false;
        } else if (std.mem.eql(u8, arg, "--borrowed-response")) {
            options.owned_response = false;
        } else if (std.mem.eql(u8, arg, "--owned-request")) {
            options.owned_request = true;
        } else if (std.mem.startsWith(u8, arg, "--payload=")) {
            options.payload_bytes = try std.fmt.parseInt(
                usize,
                arg["--payload=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--warmup=")) {
            options.warmup = try std.fmt.parseInt(
                usize,
                arg["--warmup=".len..],
                10,
            );
        } else if (std.mem.startsWith(u8, arg, "--iterations=")) {
            options.iterations = try std.fmt.parseInt(
                usize,
                arg["--iterations=".len..],
                10,
            );
        } else return error.InvalidArgument;
    }
    if (options.payload_bytes > 16 * 1024 * 1024 - 8 or
        options.iterations == 0)
    {
        return error.InvalidArgument;
    }
    return options;
}

pub fn main(init: std.process.Init) !void {
    const options = try parse(init);
    var cache: netz.alloc.BlockCache = undefined;
    var cache_live = false;
    defer if (cache_live) cache.deinit();
    const backing = if (options.cached_allocator) blk: {
        cache = .init(std.heap.smp_allocator, .{});
        cache_live = true;
        break :blk cache.allocator();
    } else std.heap.smp_allocator;

    const request = try backing.alloc(u8, options.payload_bytes);
    defer backing.free(request);
    const response = try backing.alloc(u8, options.payload_bytes);
    defer backing.free(response);
    @memset(request, 'a');
    @memset(response, 'b');
    var request_message: ?netz.grpc.OwnedRequestMessage = null;
    defer if (request_message) |*message| message.deinit();
    if (options.owned_request) {
        request_message = try netz.grpc.OwnedRequestMessage.init(
            backing,
            options.payload_bytes,
        );
        @memcpy(request_message.?.payload(), request);
    }
    // The server reuses one prefix-reserved response buffer for every call.
    var response_message = try netz.grpc.OwnedResponseMessage.init(
        backing,
        options.payload_bytes,
    );
    defer response_message.deinit();
    @memcpy(response_message.payload(), response);

    var backend = try netz.runtime.Backend.init(backing);
    defer backend.deinit();
    const io = backend.io();
    const limits: netz.http2.runtime.Limits = .{
        .max_body_bytes = options.payload_bytes + 16,
        .max_frame_payload = 16 * 1024,
    };
    var server = try netz.http2.runtime.Server.listen(
        backing,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    var peer = Peer{
        .server = &server,
        .allocator = backing,
        .response = response,
        .message = response_message,
        .owned_response = options.owned_response,
        .calls = options.warmup + options.iterations,
    };
    var peer_result: anyerror!void = {};
    var peer_task = io.async(Peer.run, .{ &peer, &peer_result });
    defer peer_task.cancel(io);

    var elapsed: u64 = undefined;
    if (options.shared) {
        var channel = try netz.grpc.SharedChannel.init(
            backing,
            io,
            .{ .cleartext_ip = .{
                .address = server.address(),
                .limits = limits,
            } },
            .{},
        );
        defer channel.deinit();
        var sender = channel.sender();
        defer sender.deinit();
        for (0..options.warmup) |_| {
            try sharedExchange(
                sender,
                request,
                response,
                options.validate,
                if (request_message) |*message| message else null,
            );
        }
        const started = now(io);
        for (0..options.iterations) |_| {
            try sharedExchange(
                sender,
                request,
                response,
                options.validate,
                if (request_message) |*message| message else null,
            );
        }
        elapsed = now(io) -| started;
    } else {
        var client = try netz.http2.runtime.Client.connect(
            backing,
            io,
            server.address(),
            limits,
        );
        defer client.close();
        for (0..options.warmup) |_| {
            try exchange(
                &client,
                backing,
                request,
                response,
                options.validate,
                if (request_message) |*message| message else null,
            );
        }
        const started = now(io);
        for (0..options.iterations) |_| {
            try exchange(
                &client,
                backing,
                request,
                response,
                options.validate,
                if (request_message) |*message| message else null,
            );
        }
        elapsed = now(io) -| started;
    }

    peer_task.await(io);
    try peer_result;
    if (peer.calls_seen != options.warmup + options.iterations) {
        return error.InvalidPeerCompletion;
    }
    if (options.cached_allocator) {
        std.debug.print(
            "record=cache schema=1 hits={d} misses={d} cached_bytes={d}\n",
            .{ cache.hitCount(), cache.missCount(), cache.cached_bytes },
        );
    }
    std.debug.print(
        "record=result schema=2 implementation=netz protocol=grpc transport=h2c " ++
            "client_api={s} request_storage={s} allocator={s} warmup={d} iterations={d} " ++
            "payload_bytes={d} validation={s} elapsed_ns={d} ns_per_roundtrip={d} " ++
            "roundtrips_per_second={d} complete=true\n",
        .{
            if (options.shared) "shared-unary" else "ordinary-unary",
            if (options.owned_request) "owned" else "staged",
            if (options.cached_allocator) "cached" else "smp",
            options.warmup,
            options.iterations,
            options.payload_bytes,
            if (options.validate) "full-bytes" else "length-only",
            elapsed,
            elapsed / options.iterations,
            if (elapsed == 0) 0 else @as(u128, options.iterations) * std.time.ns_per_s / elapsed,
        },
    );
}

fn exchange(
    connection: *netz.http2.runtime.Connection,
    allocator: std.mem.Allocator,
    request: []const u8,
    response: []const u8,
    validate: bool,
    owned_request: ?*netz.grpc.OwnedRequestMessage,
) !void {
    var result = try netz.grpc.unaryCall(connection, allocator, .{
        .path = "/bench.Echo/Unary",
        .authority = "localhost",
        .message = if (owned_request == null) request else "",
        .owned_message = owned_request,
    });
    defer result.deinit();
    try validateUnary(result, response, validate);
}

fn sharedExchange(
    sender: netz.grpc.SharedChannelSender,
    request: []const u8,
    response: []const u8,
    validate: bool,
    owned_request: ?*netz.grpc.OwnedRequestMessage,
) !void {
    var result = try sender.unary(.{
        .path = "/bench.Echo/Unary",
        .authority = "localhost",
        .message = if (owned_request == null) request else "",
        .owned_message = owned_request,
    });
    defer result.deinit();
    try validateUnary(result, response, validate);
}

fn validateUnary(result: netz.grpc.UnaryResponse, response: []const u8, validate: bool) !void {
    if (result.status != .ok) return error.UnexpectedStatus;
    const payload = result.message orelse return error.MissingResponse;
    if (validate) {
        if (!std.mem.eql(u8, payload.payload, response)) {
            return error.InvalidResponse;
        }
    } else if (payload.payload.len != response.len) {
        return error.InvalidResponse;
    }
}

const Peer = struct {
    server: *netz.http2.runtime.Server,
    allocator: std.mem.Allocator,
    response: []const u8,
    /// One prefix-reserved buffer serves every response; the writer borrows it.
    message: netz.grpc.OwnedResponseMessage,
    owned_response: bool,
    calls: usize,
    calls_seen: usize = 0,

    fn run(self: *Peer, result: *anyerror!void) void {
        result.* = self.runFallible();
    }

    fn runFallible(self: *Peer) !void {
        var connection = try self.server.accept();
        defer connection.close();
        while (self.calls_seen < self.calls) : (self.calls_seen += 1) {
            var request = try connection.readRequest();
            defer request.deinit(self.allocator);
            var call = try netz.grpc.parseUnaryRequest(
                self.allocator,
                &request,
                self.response.len + 8,
            );
            defer call.deinit();
            // Guard the request path: an empty or truncated request would make
            // request-storage comparisons meaningless.
            if (call.message.payload.len != self.response.len or
                (call.message.payload.len != 0 and call.message.payload[0] != 'a'))
            {
                return error.InvalidGrpcRequest;
            }
            try netz.grpc.writeUnaryResponse(
                &connection,
                self.allocator,
                call.stream_id,
                if (self.owned_response)
                    .{ .owned_message = &self.message }
                else
                    .{ .message = self.response },
            );
        }
    }
};

fn now(io: std.Io) u64 {
    return @intCast(std.Io.Clock.awake.now(io).nanoseconds);
}

const std = @import("std");
const netz = @import("netz");
const grpc_pb = @import("grpc_pb");

const generated = grpc_pb.demo.binding;
const Event = generated.Event;
const Pipe = generated.services.Pipe;

const RequestStream = struct {
    items: []const Event,
    index: usize = 0,

    pub fn next(self: *@This()) !?Event {
        if (self.index == self.items.len) return null;
        defer self.index += 1;
        return self.items[self.index];
    }
};

const ResponseSink = struct {
    allocator: std.mem.Allocator,
    items: std.ArrayList(Event) = .empty,

    fn deinit(self: *ResponseSink) void {
        for (self.items.items) |*item| item.deinit(self.allocator);
        self.items.deinit(self.allocator);
    }

    pub fn append(
        self: *ResponseSink,
        allocator: std.mem.Allocator,
        item: Event,
    ) !void {
        try self.items.append(allocator, try item.cloneOwned(allocator));
    }
};

const PipeImpl = struct {
    pub fn Get(
        _: *@This(),
        allocator: std.mem.Allocator,
        request: Event,
    ) !Event {
        if (request.id < 0) return error.RejectedByApplication;
        var response = try request.cloneOwned(allocator);
        response.id += 100;
        return response;
    }

    pub fn Upload(
        _: *@This(),
        _: std.mem.Allocator,
        requests: anytype,
    ) !Event {
        var response = Event.init();
        response.note = "upload";
        while (try requests.next()) |request| response.id += request.id;
        return response;
    }

    pub fn Watch(
        _: *@This(),
        allocator: std.mem.Allocator,
        request: Event,
        responses: anytype,
    ) !void {
        for (1..3) |delta| {
            var response = Event.init();
            response.id = request.id + @as(i32, @intCast(delta));
            response.note = "watch";
            try responses.append(allocator, response);
        }
    }

    pub fn Chat(
        _: *@This(),
        allocator: std.mem.Allocator,
        requests: anytype,
        responses: anytype,
    ) !void {
        while (try requests.next()) |request| {
            var response = Event.init();
            response.id = request.id + 10;
            response.note = "chat";
            try responses.append(allocator, response);
        }
    }
};

const ServerState = struct {
    server: *netz.grpc.runtime.Server,
    err: ?anyerror = null,

    fn run(self: *ServerState) void {
        self.runFallible() catch |err| {
            self.err = err;
        };
    }

    fn runFallible(self: *ServerState) !void {
        var connection = try self.server.accept();
        defer connection.deinit();
        var implementation = PipeImpl{};
        const Handler = Pipe.Handler(PipeImpl);
        var handler = Handler.init(&implementation);
        const Transport = netz.grpc.pbz.ServerTransport(Pipe, Handler);
        var transport = try Transport.init(&connection, &handler, .{
            .package = grpc_pb.proto_package,
            .handler_error_status = .invalid_argument,
        });
        for (0..8) |index| {
            const expected: netz.grpc.Status = if (index == 4 or index == 5)
                .invalid_argument
            else if (index == 6)
                .deadline_exceeded
            else
                .ok;
            try std.testing.expectEqual(expected, try transport.serveOne());
        }
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var server = try netz.grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 128, .max_body_bytes = 4096 },
        4096,
    );
    defer server.deinit();
    var server_state = ServerState{ .server = &server };
    var server_future = io.async(ServerState.run, .{
        &server_state,
    });
    defer server_future.cancel(io);

    var client = try netz.grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 128, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    var service_config = try netz.grpc.ServiceConfig.parse(allocator,
        \\{"methodConfig": [{"name": [{"service": "demo.binding.Pipe"}],
        \\ "timeout": "2s", "maxRequestMessageBytes": 4096,
        \\ "maxResponseMessageBytes": "4096"}]}
    );
    defer service_config.deinit();
    const Transport = netz.grpc.pbz.ClientTransport(Pipe);
    const GeneratedClient = Pipe.Client(Transport);
    var generated_client = GeneratedClient.init(try Transport.init(&client, .{
        .package = grpc_pb.proto_package,
        .authority = "localhost",
        .service_config = &service_config,
    }));
    defer generated_client.transport.deinit();

    var unary_request = Event.init();
    unary_request.id = 7;
    unary_request.note = "unary";
    var unary_response = try generated_client.Get(allocator, unary_request);
    defer unary_response.deinit(allocator);
    try std.testing.expectEqual(@as(i32, 107), unary_response.id);

    var upload_items = [_]Event{ Event.init(), Event.init(), Event.init() };
    upload_items[0].id = 1;
    upload_items[1].id = 2;
    upload_items[2].id = 3;
    var upload_stream = RequestStream{ .items = &upload_items };
    var upload_response = try generated_client.Upload(
        allocator,
        &upload_stream,
    );
    defer upload_response.deinit(allocator);
    try std.testing.expectEqual(@as(i32, 6), upload_response.id);

    var watch_request = Event.init();
    watch_request.id = 20;
    var watch = ResponseSink{ .allocator = allocator };
    defer watch.deinit();
    try generated_client.Watch(allocator, watch_request, &watch);
    try std.testing.expectEqual(@as(usize, 2), watch.items.items.len);
    try std.testing.expectEqual(@as(i32, 21), watch.items.items[0].id);
    try std.testing.expectEqual(@as(i32, 22), watch.items.items[1].id);

    var chat_items = [_]Event{ Event.init(), Event.init() };
    chat_items[0].id = 31;
    chat_items[1].id = 41;
    var chat_stream = RequestStream{ .items = &chat_items };
    var chat = ResponseSink{ .allocator = allocator };
    defer chat.deinit();
    try generated_client.Chat(allocator, &chat_stream, &chat);
    try std.testing.expectEqual(@as(usize, 2), chat.items.items.len);
    try std.testing.expectEqual(@as(i32, 41), chat.items.items[0].id);
    try std.testing.expectEqual(@as(i32, 51), chat.items.items[1].id);

    var rejected_request = Event.init();
    rejected_request.id = -1;
    try std.testing.expectError(
        error.RpcFailed,
        generated_client.Get(allocator, rejected_request),
    );
    try std.testing.expectEqual(
        netz.grpc.Status.invalid_argument,
        generated_client.transport.lastStatus().?,
    );
    const borrowed_failure = generated_client.transport.lastFailure().?;
    try std.testing.expectEqual(
        netz.grpc.Status.invalid_argument,
        borrowed_failure.status,
    );
    try std.testing.expectEqualStrings(
        "generated handler failed",
        borrowed_failure.status_message,
    );
    try std.testing.expectEqual(@as(?u16, 200), borrowed_failure.http_status);
    try std.testing.expect(borrowed_failure.reset == null);
    var owned_failure = generated_client.transport.takeFailure().?;
    defer owned_failure.deinit();
    try std.testing.expect(generated_client.transport.lastFailure() == null);

    var malformed = try client.unary(.{
        .path = "/demo.binding.Pipe/Get",
        .authority = "localhost",
        .message = &.{ 0x12, 0x02, 'x' },
    });
    defer malformed.deinit();
    try std.testing.expectEqual(
        netz.grpc.Status.invalid_argument,
        malformed.status,
    );
    try std.testing.expectEqualStrings(
        "could not parse request",
        malformed.status_message,
    );

    var deadline_writer = try client.connection.startRequest(.{
        .method = "POST",
        .path = "/demo.binding.Pipe/Get",
        .authority = "localhost",
        .headers = &.{
            .{ .name = "content-type", .value = "application/grpc+proto" },
            .{ .name = "te", .value = "trailers" },
            .{ .name = "grpc-timeout", .value = "50m" },
        },
    });
    var deadline_stream = try deadline_writer.beginDuplex();
    var deadline_stream_live = true;
    defer if (deadline_stream_live) deadline_stream.deinit();
    var deadline_event = try deadline_stream.readResponseEventWithTimeout(
        .fromSeconds(2),
    );
    defer deadline_event.deinit(allocator);
    try std.testing.expect(deadline_event == .head);
    try std.testing.expectEqual(
        @as(u16, 200),
        deadline_event.head.status,
    );
    try std.testing.expectEqualStrings(
        "4",
        netz.http2.runtime.testing.findHeader(
            deadline_event.head.headers,
            "grpc-status",
        ).?,
    );
    var deadline_finished = try deadline_stream.readResponseEventWithTimeout(
        .fromSeconds(2),
    );
    defer deadline_finished.deinit(allocator);
    try std.testing.expect(deadline_finished == .finished);
    deadline_stream.deinit();
    deadline_stream_live = false;

    unary_request.id = 8;
    var recovered = try generated_client.Get(allocator, unary_request);
    defer recovered.deinit(allocator);
    try std.testing.expectEqual(@as(i32, 108), recovered.id);
    try std.testing.expectEqual(
        netz.grpc.Status.ok,
        generated_client.transport.lastStatus().?,
    );
    try std.testing.expect(generated_client.transport.lastFailure() == null);

    server_future.await(io);
    if (server_state.err) |err| return err;
    _ = init;
    std.debug.print(
        "pbz generated gRPC client/handler interoperated: unary=true client_stream=true server_stream=true bidi=true error_status=true client_io=zio-std-io server_io=zio-std-io\n",
        .{},
    );
}

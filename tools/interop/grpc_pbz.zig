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
        try serveUnary(&connection);
        try serveClientStream(&connection);
        try serveServerStream(&connection);
        try serveBidi(&connection);
    }

    fn serveUnary(connection: *netz.grpc.runtime.ServerConnection) !void {
        var request = try connection.readUnary();
        defer request.deinit();
        try std.testing.expectEqualStrings(
            "/demo.binding.Pipe/Get",
            request.request.path,
        );
        var decoded = try Event.decodeOwned(
            connection.connection.allocator,
            request.request.message.payload,
        );
        defer decoded.deinit(connection.connection.allocator);
        decoded.id += 100;
        const response = try decoded.encode(connection.connection.allocator);
        defer connection.connection.allocator.free(response);
        try connection.writeUnary(request.request.stream_id, .{
            .message = response,
        });
    }

    fn serveClientStream(
        connection: *netz.grpc.runtime.ServerConnection,
    ) !void {
        const Collector = struct {
            allocator: std.mem.Allocator,
            total: i32 = 0,

            fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
                var decoded = try Event.decodeOwned(
                    self.allocator,
                    message.payload,
                );
                defer decoded.deinit(self.allocator);
                self.total += decoded.id;
            }
        };
        var collector = Collector{
            .allocator = connection.connection.allocator,
        };
        var request = try connection.readStreaming(&collector, Collector.consume);
        defer request.deinit();
        try std.testing.expectEqualStrings(
            "/demo.binding.Pipe/Upload",
            request.path,
        );
        var response_message = Event.init();
        response_message.id = collector.total;
        response_message.note = "upload";
        const encoded = try response_message.encode(
            connection.connection.allocator,
        );
        defer connection.connection.allocator.free(encoded);
        var response = try connection.startStreamingResponse(
            request.transport.stream_id,
            .{ .request_accepted_encodings = request.accepted_encodings },
        );
        defer response.deinit();
        try response.writeMessage(encoded);
        try response.finishOk();
    }

    fn serveServerStream(
        connection: *netz.grpc.runtime.ServerConnection,
    ) !void {
        var request = try connection.readUnary();
        defer request.deinit();
        try std.testing.expectEqualStrings(
            "/demo.binding.Pipe/Watch",
            request.request.path,
        );
        var decoded = try Event.decodeOwned(
            connection.connection.allocator,
            request.request.message.payload,
        );
        defer decoded.deinit(connection.connection.allocator);
        var response = try connection.startStreamingResponse(
            request.request.stream_id,
            .{ .request_accepted_encodings = request.request.accepted_encodings },
        );
        defer response.deinit();
        for (1..3) |delta| {
            var item = Event.init();
            item.id = decoded.id + @as(i32, @intCast(delta));
            item.note = "watch";
            const encoded = try item.encode(connection.connection.allocator);
            defer connection.connection.allocator.free(encoded);
            try response.writeMessage(encoded);
        }
        try response.finishOk();
    }

    fn serveBidi(connection: *netz.grpc.runtime.ServerConnection) !void {
        const Collector = struct {
            allocator: std.mem.Allocator,
            ids: [4]i32 = undefined,
            len: usize = 0,

            fn consume(self: *@This(), message: netz.grpc.StreamingMessage) !void {
                var decoded = try Event.decodeOwned(
                    self.allocator,
                    message.payload,
                );
                defer decoded.deinit(self.allocator);
                self.ids[self.len] = decoded.id;
                self.len += 1;
            }
        };
        var collector = Collector{
            .allocator = connection.connection.allocator,
        };
        var request = try connection.readStreaming(&collector, Collector.consume);
        defer request.deinit();
        try std.testing.expectEqualStrings(
            "/demo.binding.Pipe/Chat",
            request.path,
        );
        var response = try connection.startStreamingResponse(
            request.transport.stream_id,
            .{ .request_accepted_encodings = request.accepted_encodings },
        );
        defer response.deinit();
        for (collector.ids[0..collector.len]) |id| {
            var item = Event.init();
            item.id = id + 10;
            item.note = "chat";
            const encoded = try item.encode(connection.connection.allocator);
            defer connection.connection.allocator.free(encoded);
            try response.writeMessage(encoded);
        }
        try response.finishOk();
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try netz.grpc.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_frame_payload = 128, .max_body_bytes = 4096 },
        4096,
    );
    defer server.deinit();
    var server_state = ServerState{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, ServerState.run, .{
        &server_state,
    });

    var client = try netz.grpc.runtime.Client.connect(
        allocator,
        io,
        server.address(),
        .{ .max_frame_payload = 128, .max_body_bytes = 4096 },
    );
    defer client.deinit();
    const Transport = netz.grpc.pbz.ClientTransport(Pipe);
    const GeneratedClient = Pipe.Client(Transport);
    var generated_client = GeneratedClient.init(try Transport.init(&client, .{
        .package = grpc_pb.proto_package,
        .authority = "localhost",
        .timeout = try netz.grpc.Timeout.init(2, .second),
    }));

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

    server_thread.join();
    if (server_state.err) |err| return err;
    _ = init;
    std.debug.print(
        "pbz generated gRPC client interoperated: unary=true client_stream=true server_stream=true bidi=true\n",
        .{},
    );
}

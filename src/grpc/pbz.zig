//! Transport adapters for `pbz` generated service clients and handlers.
//!
//! This module intentionally does not import pbz. Generated messages are used
//! through their public `encode` and `decodeOwned` methods, keeping protobuf an
//! optional application dependency while providing the exact transport shape
//! emitted by `protoc-gen-pbz`.

const std = @import("std");
const http2 = @import("../http2/mod.zig");
const grpc_call = @import("call.zig");
const compression = @import("compression.zig");
const metadata = @import("metadata.zig");
const runtime = @import("runtime.zig");
const service_config = @import("service_config.zig");
const stream = @import("stream/mod.zig");
const wire = @import("wire.zig");

pub const Error = error{
    InvalidServiceName,
    InvalidTransportOptions,
    InvalidMethodShape,
    InvalidRequestPayload,
    UnknownMethod,
    RpcFailed,
};

pub const ClientOptions = struct {
    package: []const u8 = "",
    authority: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    compression: compression.Algorithm = .identity,
    compression_level: u4 = 6,
    accepted_encodings: compression.AlgorithmSet = .supported,
    timeout: ?wire.Timeout = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
    binary_metadata: []const metadata.BinaryMetadata = &.{},
    max_message_size: usize = 16 * 1024 * 1024,
    retry_policy: ?grpc_call.RetryPolicy = null,
    service_config: ?*service_config.ServiceConfig = null,
};

pub const ServerOptions = struct {
    package: []const u8 = "",
    compression: compression.Algorithm = .identity,
    compression_level: u4 = 6,
    accepted_encodings: compression.AlgorithmSet = .supported,
    max_message_size: usize = 16 * 1024 * 1024,
    handler_error_status: wire.Status = .internal,
    handler_error_message: ?[]const u8 = "generated handler failed",
};

pub const RpcFailure = struct {
    allocator: std.mem.Allocator,
    status: wire.Status,
    status_message: []u8,
    reset: ?http2.ResetStreamPayload = null,
    http_status: ?u16 = null,

    pub fn deinit(self: *RpcFailure) void {
        self.allocator.free(self.status_message);
        self.* = undefined;
    }
};

/// Adapter accepted directly by a generated `Service.Client(Transport)`.
///
/// A streaming response sink implements `append(allocator, message)`. The
/// generated method's `output_type_ref` selects the decoder, and the decoded
/// message is borrowed for that call, matching pbz's generated Handler sink
/// convention. After `RpcFailed`, `lastStatus()` exposes the terminal gRPC
/// status without coupling generated method signatures to netz response types.
pub fn ClientTransport(comptime Service: type) type {
    validateServiceType(Service);
    return struct {
        client: *runtime.Client,
        options: ClientOptions,
        last_status: ?wire.Status = null,
        last_failure: ?RpcFailure = null,

        const Self = @This();

        pub fn init(
            client: *runtime.Client,
            options: ClientOptions,
        ) Error!Self {
            if (options.retry_policy != null and
                options.service_config != null)
            {
                return error.InvalidTransportOptions;
            }
            try validateQualifiedName(options.package, true);
            try validateIdentifier(Service.name);
            return .{ .client = client, .options = options };
        }

        pub fn deinit(self: *Self) void {
            self.clearFailure();
            self.* = undefined;
        }

        pub fn call(
            self: *Self,
            allocator: std.mem.Allocator,
            service_name: []const u8,
            method_name: []const u8,
            request_payload: []const u8,
        ) ![]u8 {
            self.beginCall();
            try self.requireMethod(service_name, method_name, false, false);
            const path = try self.methodPathAlloc(allocator, method_name);
            defer allocator.free(path);
            var response = if (self.options.retry_policy) |policy|
                try self.client.unaryWithRetry(
                    self.unaryOptions(path, request_payload),
                    policy,
                )
            else if (self.options.service_config) |config|
                try self.client.unaryWithServiceConfig(
                    self.unaryOptions(path, request_payload),
                    config,
                )
            else
                try self.client.unary(
                    self.unaryOptions(path, request_payload),
                );
            defer response.deinit();
            self.last_status = response.status;
            if (response.status != .ok) {
                try self.recordUnaryFailure(&response);
                return error.RpcFailed;
            }
            return allocator.dupe(
                u8,
                (response.message orelse return error.InvalidMethodShape)
                    .payload,
            );
        }

        pub fn callClientStream(
            self: *Self,
            allocator: std.mem.Allocator,
            service_name: []const u8,
            method_name: []const u8,
            requests: anytype,
        ) ![]u8 {
            self.beginCall();
            try self.requireMethod(service_name, method_name, true, false);
            const path = try self.methodPathAlloc(allocator, method_name);
            defer allocator.free(path);
            var writer = try self.client.startStreaming(
                self.streamingOptions(path),
            );
            defer writer.deinit();
            var output = SingleResponse.init(allocator);
            errdefer output.deinit();
            while (try requests.next()) |request| {
                const payload = try request.encode(allocator);
                defer allocator.free(payload);
                if (try writer.writeMessageOrReadResponse(
                    payload,
                    &output,
                    SingleResponse.consume,
                )) |response_value| {
                    var response = response_value;
                    defer response.deinit();
                    return self.finishSingleResponse(&response, &output);
                }
            }
            var response = try writer.finishAndRead(
                &output,
                SingleResponse.consume,
            );
            defer response.deinit();
            return self.finishSingleResponse(&response, &output);
        }

        pub fn callServerStream(
            self: *Self,
            allocator: std.mem.Allocator,
            service_name: []const u8,
            method_name: []const u8,
            request_payload: []const u8,
            responses: anytype,
        ) !void {
            self.beginCall();
            try self.requireService(service_name);
            inline for (@typeInfo(Service).@"struct".decls) |decl| {
                const candidate = @field(Service, decl.name);
                if (comptime !isMethodType(candidate)) continue;
                if (std.mem.eql(u8, method_name, candidate.name)) {
                    if (candidate.client_streaming or
                        !candidate.server_streaming)
                    {
                        return error.InvalidMethodShape;
                    }
                    return self.callServerStreamMethod(
                        candidate,
                        allocator,
                        method_name,
                        request_payload,
                        responses,
                    );
                }
            }
            return error.UnknownMethod;
        }

        fn callServerStreamMethod(
            self: *Self,
            comptime Method: type,
            allocator: std.mem.Allocator,
            method_name: []const u8,
            request_payload: []const u8,
            responses: anytype,
        ) !void {
            const path = try self.methodPathAlloc(allocator, method_name);
            defer allocator.free(path);
            var rpc = try self.client.startDuplex(self.streamingOptions(path));
            defer rpc.deinit();
            var collector = ResponseSink(
                @TypeOf(responses),
                Method.output_type_ref,
            ).init(
                allocator,
                responses,
            );
            if (try self.sendRequestAndDrain(
                &rpc,
                request_payload,
                &collector,
                true,
            )) {
                return self.requireOkStatus();
            }
            try self.finishResponseStream(&rpc, &collector);
        }

        pub fn callBidiStream(
            self: *Self,
            allocator: std.mem.Allocator,
            service_name: []const u8,
            method_name: []const u8,
            requests: anytype,
            responses: anytype,
        ) !void {
            self.beginCall();
            try self.requireService(service_name);
            inline for (@typeInfo(Service).@"struct".decls) |decl| {
                const candidate = @field(Service, decl.name);
                if (comptime !isMethodType(candidate)) continue;
                if (std.mem.eql(u8, method_name, candidate.name)) {
                    if (!candidate.client_streaming or
                        !candidate.server_streaming)
                    {
                        return error.InvalidMethodShape;
                    }
                    return self.callBidiStreamMethod(
                        candidate,
                        allocator,
                        method_name,
                        requests,
                        responses,
                    );
                }
            }
            return error.UnknownMethod;
        }

        fn callBidiStreamMethod(
            self: *Self,
            comptime Method: type,
            allocator: std.mem.Allocator,
            method_name: []const u8,
            requests: anytype,
            responses: anytype,
        ) !void {
            const path = try self.methodPathAlloc(allocator, method_name);
            defer allocator.free(path);
            var rpc = try self.client.startDuplex(self.streamingOptions(path));
            defer rpc.deinit();
            var collector = ResponseSink(
                @TypeOf(responses),
                Method.output_type_ref,
            ).init(
                allocator,
                responses,
            );
            while (try requests.next()) |request| {
                const payload = try request.encode(allocator);
                defer allocator.free(payload);
                if (try self.sendRequestAndDrain(
                    &rpc,
                    payload,
                    &collector,
                    false,
                )) {
                    return self.requireOkStatus();
                }
            }
            var result = try rpc.finishRequest();
            while (result == .peer_event) {
                if (try self.consumeResponseEvent(&rpc, &collector)) return;
                result = try rpc.finishRequest();
            }
            try self.finishResponseStream(&rpc, &collector);
        }

        fn sendRequestAndDrain(
            self: *Self,
            rpc: *stream.ClientDuplex,
            payload: []const u8,
            collector: anytype,
            final: bool,
        ) !bool {
            var result = if (final)
                try rpc.writeFinalMessage(payload)
            else
                try rpc.writeMessage(payload);
            while (result == .peer_event) {
                if (try self.consumeResponseEvent(rpc, collector)) {
                    return true;
                }
                result = try rpc.resumeMessage();
            }
            return false;
        }

        fn finishResponseStream(
            self: *Self,
            rpc: *stream.ClientDuplex,
            collector: anytype,
        ) !void {
            while (!try self.consumeResponseEvent(rpc, collector)) {}
            try self.requireOkStatus();
        }

        fn consumeResponseEvent(
            self: *Self,
            rpc: *stream.ClientDuplex,
            collector: anytype,
        ) !bool {
            var event = try rpc.readResponseEvent(
                collector,
                @TypeOf(collector.*).consume,
            );
            defer event.deinit(self.client.connection.allocator);
            switch (event) {
                .terminal => |terminal| {
                    self.last_status = terminal.status;
                    if (terminal.status != .ok) {
                        try self.recordDuplexFailure(&terminal);
                    }
                    return true;
                },
                .informational, .initial_metadata, .messages => return false,
            }
        }

        fn finishSingleResponse(
            self: *Self,
            response: *stream.Response,
            output: *SingleResponse,
        ) ![]u8 {
            self.last_status = response.status;
            if (response.status != .ok) {
                try self.recordStreamingFailure(response);
                return error.RpcFailed;
            }
            return output.take() orelse error.InvalidMethodShape;
        }

        pub fn lastStatus(self: Self) ?wire.Status {
            return self.last_status;
        }

        /// Borrow the most recent typed RPC failure until the next call,
        /// `takeFailure`, or `deinit`.
        pub fn lastFailure(self: *const Self) ?*const RpcFailure {
            return if (self.last_failure) |*failure| failure else null;
        }

        /// Transfer ownership of the most recent failure to the caller.
        pub fn takeFailure(self: *Self) ?RpcFailure {
            const failure = self.last_failure;
            self.last_failure = null;
            return failure;
        }

        fn requireOkStatus(self: Self) Error!void {
            if ((self.last_status orelse return error.InvalidMethodShape) !=
                .ok) return error.RpcFailed;
        }

        fn beginCall(self: *Self) void {
            self.last_status = null;
            self.clearFailure();
        }

        fn clearFailure(self: *Self) void {
            if (self.last_failure) |*failure| failure.deinit();
            self.last_failure = null;
        }

        fn recordUnaryFailure(
            self: *Self,
            response: *const grpc_call.UnaryResponse,
        ) !void {
            self.last_failure = .{
                .allocator = self.client.connection.allocator,
                .status = response.status,
                .status_message = try self.client.connection.allocator.dupe(
                    u8,
                    response.status_message,
                ),
                .reset = response.reset,
                .http_status = if (response.transport) |transport|
                    transport.status
                else
                    null,
            };
        }

        fn recordStreamingFailure(
            self: *Self,
            response: *const stream.Response,
        ) !void {
            self.last_failure = .{
                .allocator = self.client.connection.allocator,
                .status = response.status,
                .status_message = try self.client.connection.allocator.dupe(
                    u8,
                    response.status_message,
                ),
                .reset = response.reset,
                .http_status = if (response.transport) |transport|
                    transport.status
                else
                    null,
            };
        }

        fn recordDuplexFailure(
            self: *Self,
            response: *const stream.DuplexResponse,
        ) !void {
            self.last_failure = .{
                .allocator = self.client.connection.allocator,
                .status = response.status,
                .status_message = try self.client.connection.allocator.dupe(
                    u8,
                    response.status_message,
                ),
                .reset = response.reset,
                .http_status = if (response.head) |head| head.status else null,
            };
        }

        fn unaryOptions(
            self: Self,
            path: []const u8,
            payload: []const u8,
        ) grpc_call.UnaryCallOptions {
            return .{
                .path = path,
                .authority = self.options.authority,
                .scheme = self.options.scheme,
                .message = payload,
                .compression = self.options.compression,
                .compression_level = self.options.compression_level,
                .accepted_encodings = self.options.accepted_encodings,
                .timeout = self.options.timeout,
                .metadata = self.options.metadata,
                .binary_metadata = self.options.binary_metadata,
                .max_message_size = self.options.max_message_size,
            };
        }

        fn streamingOptions(self: Self, path: []const u8) stream.RequestOptions {
            return .{
                .path = path,
                .authority = self.options.authority,
                .scheme = self.options.scheme,
                .compression = self.options.compression,
                .compression_level = self.options.compression_level,
                .accepted_encodings = self.options.accepted_encodings,
                .timeout = self.options.timeout,
                .metadata = self.options.metadata,
                .binary_metadata = self.options.binary_metadata,
                .max_message_size = self.options.max_message_size,
            };
        }

        fn methodPathAlloc(
            self: Self,
            allocator: std.mem.Allocator,
            method_name: []const u8,
        ) ![]u8 {
            if (self.options.package.len == 0) {
                return std.fmt.allocPrint(
                    allocator,
                    "/{s}/{s}",
                    .{ Service.name, method_name },
                );
            }
            return std.fmt.allocPrint(
                allocator,
                "/{s}.{s}/{s}",
                .{ self.options.package, Service.name, method_name },
            );
        }

        fn requireMethod(
            self: Self,
            service_name: []const u8,
            method_name: []const u8,
            client_streaming: bool,
            server_streaming: bool,
        ) Error!void {
            try self.requireService(service_name);
            inline for (@typeInfo(Service).@"struct".decls) |decl| {
                const candidate = @field(Service, decl.name);
                if (comptime !isMethodType(candidate)) continue;
                if (std.mem.eql(u8, method_name, candidate.name)) {
                    if (candidate.client_streaming != client_streaming or
                        candidate.server_streaming != server_streaming)
                    {
                        return error.InvalidMethodShape;
                    }
                    return;
                }
            }
            return error.UnknownMethod;
        }

        fn requireService(
            self: Self,
            service_name: []const u8,
        ) Error!void {
            _ = self;
            if (!std.mem.eql(u8, service_name, Service.name)) {
                return error.InvalidServiceName;
            }
        }
    };
}

/// Dispatch one accepted RPC to a `protoc-gen-pbz` generated Handler.
///
/// Request iterators decode owned generated messages lazily. Response sinks
/// encode generated messages immediately and keep the same `ServerDuplex` as
/// the sole HTTP/2 frame reader while flow control exposes peer events.
pub fn ServerTransport(comptime Service: type, comptime Handler: type) type {
    validateServiceType(Service);
    return struct {
        connection: *runtime.ServerConnection,
        handler: *Handler,
        options: ServerOptions,

        const Self = @This();

        pub fn init(
            connection: *runtime.ServerConnection,
            handler: *Handler,
            options: ServerOptions,
        ) Error!Self {
            try validateQualifiedName(options.package, true);
            try validateIdentifier(Service.name);
            if (options.handler_error_status == .ok) {
                return error.InvalidTransportOptions;
            }
            return .{
                .connection = connection,
                .handler = handler,
                .options = options,
            };
        }

        pub fn serveOne(self: *Self) !wire.Status {
            var rpc = try self.connection.acceptDuplex();
            defer rpc.deinit();
            if (!matchesService(
                rpc.service,
                self.options.package,
                Service.name,
            )) {
                try rpc.finish(.unimplemented, "unknown service", &.{}, &.{});
                return .unimplemented;
            }
            inline for (@typeInfo(Service).@"struct".decls) |decl| {
                const Method = @field(Service, decl.name);
                if (comptime !isMethodType(Method)) continue;
                if (std.mem.eql(u8, rpc.method, Method.name)) {
                    return self.serveMethod(Method, &rpc);
                }
            }
            try rpc.finish(.unimplemented, "unknown method", &.{}, &.{});
            return .unimplemented;
        }

        fn serveMethod(
            self: *Self,
            comptime Method: type,
            rpc: *stream.ServerDuplex,
        ) !wire.Status {
            var requests = ServerRequestIterator(
                Method.input_type_ref,
            ).init(self.connection.connection.allocator, rpc);
            defer requests.deinit();
            var responses = ServerResponseSink(
                Method.output_type_ref,
                @TypeOf(&requests),
            ).init(
                self.connection.connection.allocator,
                rpc,
                &requests,
                self.responseOptions(rpc),
                !Method.server_streaming,
            );

            if (!Method.client_streaming and !Method.server_streaming) {
                const request = requests.single() catch |err|
                    return self.finishRequestError(rpc, err);
                var response = @call(
                    .auto,
                    @field(Handler, Method.name),
                    .{
                        self.handler.*,
                        self.connection.connection.allocator,
                        request,
                    },
                ) catch |err| return self.finishDispatchError(
                    rpc,
                    &requests,
                    err,
                );
                defer response.deinit(self.connection.connection.allocator);
                try responses.append(
                    self.connection.connection.allocator,
                    response,
                );
            } else if (Method.client_streaming and
                !Method.server_streaming)
            {
                var response = @call(
                    .auto,
                    @field(Handler, Method.name),
                    .{
                        self.handler.*,
                        self.connection.connection.allocator,
                        &requests,
                    },
                ) catch |err| return self.finishDispatchError(
                    rpc,
                    &requests,
                    err,
                );
                defer response.deinit(self.connection.connection.allocator);
                try responses.append(
                    self.connection.connection.allocator,
                    response,
                );
            } else if (!Method.client_streaming and
                Method.server_streaming)
            {
                const request = requests.single() catch |err|
                    return self.finishRequestError(rpc, err);
                @call(
                    .auto,
                    @field(Handler, Method.name),
                    .{
                        self.handler.*,
                        self.connection.connection.allocator,
                        request,
                        &responses,
                    },
                ) catch |err| return self.finishDispatchError(
                    rpc,
                    &requests,
                    err,
                );
            } else {
                @call(
                    .auto,
                    @field(Handler, Method.name),
                    .{
                        self.handler.*,
                        self.connection.connection.allocator,
                        &requests,
                        &responses,
                    },
                ) catch |err| return self.finishDispatchError(
                    rpc,
                    &requests,
                    err,
                );
            }
            try responses.finish();
            return .ok;
        }

        fn finishHandlerError(
            self: Self,
            rpc: *stream.ServerDuplex,
            _: anyerror,
        ) !wire.Status {
            try rpc.finish(
                self.options.handler_error_status,
                self.options.handler_error_message,
                &.{},
                &.{},
            );
            return self.options.handler_error_status;
        }

        fn finishDispatchError(
            self: Self,
            rpc: *stream.ServerDuplex,
            requests: anytype,
            err: anyerror,
        ) !wire.Status {
            if (requests.invalid_payload or err == error.InvalidRequestPayload) {
                return self.finishRequestError(rpc, err);
            }
            return self.finishHandlerError(rpc, err);
        }

        fn finishRequestError(
            self: Self,
            rpc: *stream.ServerDuplex,
            _: anyerror,
        ) !wire.Status {
            _ = self;
            try rpc.finish(
                .invalid_argument,
                "could not parse request",
                &.{},
                &.{},
            );
            return .invalid_argument;
        }

        fn responseOptions(
            self: Self,
            rpc: *const stream.ServerDuplex,
        ) stream.ResponseOptions {
            return .{
                .compression = self.options.compression,
                .compression_level = self.options.compression_level,
                .request_accepted_encodings = rpc.accepted_encodings,
                .accepted_encodings = self.options.accepted_encodings,
                .max_message_size = self.options.max_message_size,
            };
        }
    };
}

const SingleResponse = struct {
    allocator: std.mem.Allocator,
    payload: ?[]u8 = null,

    fn init(allocator: std.mem.Allocator) SingleResponse {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *SingleResponse) void {
        if (self.payload) |payload| self.allocator.free(payload);
        self.* = undefined;
    }

    fn consume(self: *SingleResponse, message: stream.DecodedMessage) !void {
        if (self.payload != null) return error.InvalidMethodShape;
        self.payload = try self.allocator.dupe(u8, message.payload);
    }

    fn take(self: *SingleResponse) ?[]u8 {
        const payload = self.payload;
        self.payload = null;
        return payload;
    }
};

fn ResponseSink(comptime SinkPointer: type, comptime Message: type) type {
    return struct {
        allocator: std.mem.Allocator,
        sink: SinkPointer,

        fn init(
            allocator: std.mem.Allocator,
            sink: SinkPointer,
        ) @This() {
            return .{ .allocator = allocator, .sink = sink };
        }

        fn consume(
            self: *@This(),
            message: stream.DecodedMessage,
        ) !void {
            var decoded = try Message.decodeOwned(
                self.allocator,
                message.payload,
            );
            defer decoded.deinit(self.allocator);
            try self.sink.append(self.allocator, decoded);
        }
    };
}

fn ServerRequestIterator(comptime Message: type) type {
    return struct {
        allocator: std.mem.Allocator,
        rpc: *stream.ServerDuplex,
        messages: std.ArrayList(Message) = .empty,
        next_index: usize = 0,
        released_index: usize = 0,
        finished: bool = false,
        invalid_payload: bool = false,

        fn init(
            allocator: std.mem.Allocator,
            rpc: *stream.ServerDuplex,
        ) @This() {
            return .{ .allocator = allocator, .rpc = rpc };
        }

        fn deinit(self: *@This()) void {
            for (self.messages.items[self.released_index..]) |*message| {
                message.deinit(self.allocator);
            }
            self.messages.deinit(self.allocator);
        }

        pub fn next(self: *@This()) !?Message {
            if (self.invalid_payload) return error.InvalidRequestPayload;
            while (self.released_index < self.next_index) {
                self.messages.items[self.released_index].deinit(
                    self.allocator,
                );
                self.released_index += 1;
            }
            if (self.released_index == self.messages.items.len) {
                self.messages.clearRetainingCapacity();
                self.next_index = 0;
                self.released_index = 0;
            }
            while (self.next_index == self.messages.items.len and
                !self.finished)
            {
                try self.pump();
            }
            if (self.invalid_payload) return error.InvalidRequestPayload;
            if (self.next_index == self.messages.items.len) return null;
            defer self.next_index += 1;
            return self.messages.items[self.next_index];
        }

        fn single(self: *@This()) !Message {
            while (!self.finished) try self.pump();
            if (self.invalid_payload) return error.InvalidRequestPayload;
            if (self.messages.items.len != 1) {
                return error.InvalidRequestPayload;
            }
            self.next_index = 1;
            return self.messages.items[0];
        }

        fn pump(self: *@This()) !void {
            var event = try self.rpc.readRequestEvent(
                self,
                @This().consume,
            );
            defer event.deinit();
            switch (event) {
                .messages => {},
                .finished => self.finished = true,
                .reset => return error.RpcFailed,
            }
        }

        fn consume(
            self: *@This(),
            message: stream.DecodedMessage,
        ) !void {
            if (self.invalid_payload) return;
            const decoded = Message.decodeOwned(
                self.allocator,
                message.payload,
            ) catch |err| {
                if (err == error.OutOfMemory) return err;
                self.invalid_payload = true;
                return;
            };
            self.messages.append(self.allocator, decoded) catch |err| {
                var owned = decoded;
                owned.deinit(self.allocator);
                return err;
            };
        }
    };
}

fn ServerResponseSink(comptime Message: type, comptime Requests: type) type {
    return struct {
        allocator: std.mem.Allocator,
        rpc: *stream.ServerDuplex,
        requests: Requests,
        options: stream.ResponseOptions,
        require_one: bool,
        count: usize = 0,
        started: bool = false,
        finished: bool = false,

        fn init(
            allocator: std.mem.Allocator,
            rpc: *stream.ServerDuplex,
            requests: Requests,
            options: stream.ResponseOptions,
            require_one: bool,
        ) @This() {
            return .{
                .allocator = allocator,
                .rpc = rpc,
                .requests = requests,
                .options = options,
                .require_one = require_one,
            };
        }

        pub fn append(
            self: *@This(),
            allocator: std.mem.Allocator,
            message: Message,
        ) !void {
            _ = allocator;
            if (self.finished) {
                return error.InvalidMethodShape;
            }
            if (self.require_one and self.count != 0) {
                return error.InvalidMethodShape;
            }
            if (!self.started) {
                try self.rpc.startResponse(self.options);
                self.started = true;
            }
            const payload = try message.encode(self.allocator);
            defer self.allocator.free(payload);
            var result = try self.rpc.writeMessage(payload);
            while (result == .peer_event) {
                try self.requests.pump();
                result = try self.rpc.resumeMessage();
            }
            self.count += 1;
        }

        fn finish(self: *@This()) !void {
            if (self.finished) return error.InvalidMethodShape;
            if (self.require_one and self.count != 1) {
                return error.InvalidMethodShape;
            }
            try self.rpc.finishOk();
            self.finished = true;
        }
    };
}

fn isMethodType(comptime candidate: anytype) bool {
    return @TypeOf(candidate) == type and
        @hasDecl(candidate, "name") and
        @hasDecl(candidate, "input_type_ref") and
        @hasDecl(candidate, "output_type_ref") and
        @hasDecl(candidate, "client_streaming") and
        @hasDecl(candidate, "server_streaming");
}

fn validateServiceType(comptime Service: type) void {
    if (!@hasDecl(Service, "name")) {
        @compileError("pbz service metadata must declare name");
    }
}

fn matchesService(
    actual: []const u8,
    package: []const u8,
    service: []const u8,
) bool {
    if (package.len == 0) return std.mem.eql(u8, actual, service);
    return actual.len == package.len + 1 + service.len and
        std.mem.startsWith(u8, actual, package) and
        actual[package.len] == '.' and
        std.mem.eql(u8, actual[package.len + 1 ..], service);
}

fn validateQualifiedName(name: []const u8, allow_empty: bool) Error!void {
    if (name.len == 0) {
        if (allow_empty) return;
        return error.InvalidServiceName;
    }
    var parts = std.mem.splitScalar(u8, name, '.');
    while (parts.next()) |part| try validateIdentifier(part);
}

fn validateIdentifier(name: []const u8) Error!void {
    if (name.len == 0 or
        !(std.ascii.isAlphabetic(name[0]) or name[0] == '_'))
    {
        return error.InvalidServiceName;
    }
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
            return error.InvalidServiceName;
        }
    }
}

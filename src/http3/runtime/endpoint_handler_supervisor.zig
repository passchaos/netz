//! Bounded application-handler tasks for the shared HTTP/3 endpoint server.
//!
//! The endpoint loop remains the sole QUIC/QPACK owner. It assembles request
//! events into owned values, workers run only application code, and owned
//! responses return through a bounded completion queue for nonblocking send.

const std = @import("std");
const http3 = @import("../mod.zig");
const content_coding = @import("../../http/content_coding.zig");
const early_data = @import("../../http/early_data.zig");
const quic = @import("../../quic/mod.zig");

pub const ErrorStage = enum { connection, handler, response };

pub const ErrorPolicy = enum { continue_serving, stop };

pub const ErrorEvent = struct {
    stage: ErrorStage,
    err: anyerror,
    connection_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null,
    stream_id: ?u62 = null,
};

pub const ErrorObserver = struct {
    context: *anyopaque,
    observe: *const fn (context: *anyopaque, event: ErrorEvent) void,
};

pub const Options = struct {
    shutdown: *std.Io.Event,
    supported_versions: []const u32,
    max_handler_tasks: usize = 64,
    max_pending_requests: usize = 256,
    max_request_body_bytes: usize = 1024 * 1024,
    /// Stop after this many responses have reached the UDP socket. Zero keeps
    /// serving until `shutdown` is set.
    stop_after_responses: usize = 0,
    /// Backs response copies made by concurrent handler workers. Allocation
    /// and later endpoint-thread deallocation must both be thread-safe.
    response_allocator: std.mem.Allocator = std.heap.smp_allocator,
    poll_interval: std.Io.Clock.Duration = .{
        .clock = .awake,
        .raw = .fromMilliseconds(5),
    },
    error_policy: ErrorPolicy = .continue_serving,
    error_observer: ?ErrorObserver = null,
};

const RequestKey = struct {
    connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
    stream_id: u62,
};

pub const OwnedRequest = struct {
    connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
    from: std.Io.net.IpAddress,
    stream_id: u62,
    /// True when accepted TLS 0-RTT STREAM data contributed to this request.
    /// Handlers can return 425 or apply application-specific replay defenses.
    was_early_data: bool = false,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    headers: []http3.Qpack.HeaderField,
    body: []const u8,
    body_storage: ?[]u8 = null,
    trailers: []http3.Qpack.HeaderField = &.{},

    /// Whether the current QUIC hop used accepted 0-RTT or an earlier gateway
    /// marked this request with RFC 8470 Early-Data.
    pub fn mightHaveBeenEarly(self: OwnedRequest) bool {
        return self.was_early_data or
            early_data.requestMightHaveBeenEarly(self.headers);
    }

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        http3.Qpack.freeDecodedFields(allocator, self.headers);
        http3.Qpack.freeDecodedFields(allocator, self.trailers);
        if (self.body_storage) |body| allocator.free(body);
        self.* = undefined;
    }

    pub fn contentEncoding(
        self: OwnedRequest,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    pub fn decodeContentAlloc(
        self: OwnedRequest,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return content_coding.decodeHeadersAlloc(
            allocator,
            self.headers,
            self.body,
            max_output_len,
        );
    }

    pub fn decodeContentInto(
        self: OwnedRequest,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return (try self.contentEncoding()).decodeInto(
            self.body,
            out,
            scratch,
        );
    }
};

const Collector = struct {
    from: std.Io.net.IpAddress,
    was_early_data: bool,
    head: http3.DecodedRequestHead,
    body: std.ArrayList(u8) = .empty,
    trailers: []http3.Qpack.HeaderField = &.{},
    finished: bool = false,

    fn deinit(self: *Collector, allocator: std.mem.Allocator) void {
        self.head.deinit(allocator);
        self.body.deinit(allocator);
        if (self.trailers.len != 0) {
            http3.Qpack.freeDecodedFields(allocator, self.trailers);
        }
        self.* = undefined;
    }

    fn takeRequest(
        self: *Collector,
        allocator: std.mem.Allocator,
        connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
        stream_id: u62,
    ) std.mem.Allocator.Error!OwnedRequest {
        const from = self.from;
        const was_early_data = self.was_early_data;
        const body_storage: ?[]u8 = if (self.body.items.len == 0) blk: {
            self.body.deinit(allocator);
            break :blk null;
        } else try self.body.toOwnedSlice(allocator);
        const head = self.head;
        const trailers = self.trailers;
        self.head.headers = &.{};
        self.trailers = &.{};
        self.* = undefined;
        return .{
            .connection_handle = connection_handle,
            .from = from,
            .stream_id = stream_id,
            .was_early_data = was_early_data,
            .method = head.method,
            .path = head.path,
            .scheme = head.scheme,
            .authority = head.authority,
            .headers = head.headers,
            .trailers = trailers,
            .body = if (body_storage) |body| body else &.{},
            .body_storage = body_storage,
        };
    }
};

const OwnedResponse = struct {
    arena: std.heap.ArenaAllocator,
    value: http3.Response,

    fn clone(
        backing_allocator: std.mem.Allocator,
        response: http3.Response,
    ) std.mem.Allocator.Error!OwnedResponse {
        var arena = std.heap.ArenaAllocator.init(backing_allocator);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        const headers = try cloneFields(allocator, response.headers);
        const body = try allocator.dupe(u8, response.body);
        const trailers = try cloneFields(allocator, response.trailers);
        const request_method = if (response.request_method) |method|
            try allocator.dupe(u8, method)
        else
            null;
        return .{
            .arena = arena,
            .value = .{
                .status = response.status,
                .headers = headers,
                .body = body,
                .trailers = trailers,
                .request_method = request_method,
                .extended_connect = response.extended_connect,
            },
        };
    }

    fn deinit(self: *OwnedResponse) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn cloneFields(
    allocator: std.mem.Allocator,
    fields: []const http3.Qpack.HeaderField,
) std.mem.Allocator.Error![]http3.Qpack.HeaderField {
    const cloned = try allocator.alloc(http3.Qpack.HeaderField, fields.len);
    for (fields, cloned) |source, *target| {
        target.* = .{
            .name = try allocator.dupe(u8, source.name),
            .value = try allocator.dupe(u8, source.value),
            .never_indexed = source.never_indexed,
        };
    }
    return cloned;
}

fn requestHasProtocol(headers: []const http3.Qpack.HeaderField) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
}

fn normalizeHandlerResponse(
    response: *http3.Response,
    request: anytype,
) bool {
    const invalid_final = response.status >= 100 and response.status < 200;
    if (invalid_final) response.* = .{ .status = 500 };
    if (response.request_method == null) {
        response.request_method = request.method;
    }
    response.extended_connect = requestHasProtocol(request.headers);
    return invalid_final;
}

pub fn serveUntil(
    comptime Runtime: type,
    endpoint: *Runtime.EndpointServer,
    comptime HandlerContext: type,
    context: *HandlerContext,
    comptime handler: *const fn (
        *HandlerContext,
        *const OwnedRequest,
    ) Runtime.Error!http3.Response,
    options: Options,
) anyerror!void {
    const Supervisor = State(Runtime, HandlerContext, handler);
    var supervisor = try Supervisor.init(endpoint, context, options);
    defer supervisor.deinit();
    try supervisor.run();
}

fn State(
    comptime Runtime: type,
    comptime HandlerContext: type,
    comptime handler: *const fn (
        *HandlerContext,
        *const OwnedRequest,
    ) Runtime.Error!http3.Response,
) type {
    return struct {
        const Self = @This();

        const Completion = struct {
            key: RequestKey,
            result: union(enum) {
                response: struct {
                    value: OwnedResponse,
                    invalid_final: bool,
                },
                failure: struct {
                    stage: ErrorStage,
                    err: anyerror,
                },
                consumed,
            },

            fn deinit(self: *Completion) void {
                switch (self.result) {
                    .response => |*response| response.value.deinit(),
                    .failure => {},
                    .consumed => {},
                }
                self.* = undefined;
            }
        };

        const PendingResponse = struct {
            key: RequestKey,
            request: *OwnedRequest,
            response: OwnedResponse,
            invalid_final: bool,
            phase: enum { head, body, trailers } = .head,
            body_offset: usize = 0,

            fn deinit(self: *PendingResponse, allocator: std.mem.Allocator) void {
                self.request.deinit(allocator);
                allocator.destroy(self.request);
                self.response.deinit();
                self.* = undefined;
            }
        };

        const WorkerContext = struct {
            io: std.Io,
            response_allocator: std.mem.Allocator,
            handler_context: *HandlerContext,
            completions: *std.Io.Queue(Completion),
        };

        const Task = struct {
            worker: *WorkerContext,
            key: RequestKey,
            request: *const OwnedRequest,

            fn run(task: Task) std.Io.Cancelable!void {
                const result: Completion = result: {
                    var response = handler(
                        task.worker.handler_context,
                        task.request,
                    ) catch |err| break :result .{
                        .key = task.key,
                        .result = .{ .failure = .{
                            .stage = .handler,
                            .err = err,
                        } },
                    };
                    const invalid_final = normalizeHandlerResponse(
                        &response,
                        task.request.*,
                    );
                    const owned_response = OwnedResponse.clone(
                        task.worker.response_allocator,
                        response,
                    ) catch |err| break :result .{
                        .key = task.key,
                        .result = .{ .failure = .{
                            .stage = .response,
                            .err = err,
                        } },
                    };
                    break :result .{
                        .key = task.key,
                        .result = .{ .response = .{
                            .value = owned_response,
                            .invalid_final = invalid_final,
                        } },
                    };
                };
                task.worker.completions.putOneUncancelable(
                    task.worker.io,
                    result,
                ) catch unreachable;
            }
        };

        endpoint: *Runtime.EndpointServer,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options,
        workers: std.Io.Group = .init,
        worker_context: *WorkerContext,
        active_workers: usize = 0,
        completion_storage: []Completion,
        completions: *std.Io.Queue(Completion),
        collectors: std.AutoHashMapUnmanaged(RequestKey, Collector) = .empty,
        active_requests: std.AutoHashMapUnmanaged(RequestKey, *OwnedRequest) =
            .empty,
        responses: std.ArrayList(PendingResponse) = .empty,
        rejected: std.AutoHashMapUnmanaged(RequestKey, void) = .empty,
        abandoned: std.AutoHashMapUnmanaged(RequestKey, void) = .empty,
        rejected_keys: std.ArrayList(RequestKey) = .empty,
        served_requests: usize = 0,
        force_transport_progress: bool = false,

        fn init(
            endpoint: *Runtime.EndpointServer,
            context: *HandlerContext,
            options: Options,
        ) !Self {
            if (options.supported_versions.len == 0 or
                options.max_handler_tasks == 0 or
                options.max_pending_requests == 0 or
                options.max_pending_requests > std.math.maxInt(u32) or
                options.poll_interval.raw.nanoseconds <= 0)
            {
                return error.InvalidServeOptions;
            }
            const pending_capacity: u32 = @intCast(
                options.max_pending_requests,
            );
            const allocator = endpoint.allocator;
            const storage = try allocator.alloc(
                Completion,
                options.max_handler_tasks,
            );
            errdefer allocator.free(storage);
            const completions = try allocator.create(std.Io.Queue(Completion));
            errdefer allocator.destroy(completions);
            completions.* = .init(storage);
            const worker_context = try allocator.create(WorkerContext);
            errdefer allocator.destroy(worker_context);
            worker_context.* = .{
                .io = endpoint.server.quic_server.endpoint.io,
                .response_allocator = options.response_allocator,
                .handler_context = context,
                .completions = completions,
            };
            var supervisor: Self = .{
                .endpoint = endpoint,
                .allocator = allocator,
                .io = endpoint.server.quic_server.endpoint.io,
                .options = options,
                .worker_context = worker_context,
                .completion_storage = storage,
                .completions = completions,
            };
            errdefer supervisor.deinit();
            try supervisor.collectors.ensureTotalCapacity(
                allocator,
                pending_capacity,
            );
            try supervisor.active_requests.ensureTotalCapacity(
                allocator,
                pending_capacity,
            );
            try supervisor.responses.ensureTotalCapacity(
                allocator,
                options.max_pending_requests,
            );
            try supervisor.rejected.ensureTotalCapacity(
                allocator,
                pending_capacity,
            );
            try supervisor.abandoned.ensureTotalCapacity(
                allocator,
                pending_capacity,
            );
            try supervisor.rejected_keys.ensureTotalCapacity(
                allocator,
                options.max_pending_requests,
            );
            return supervisor;
        }

        fn deinit(self: *Self) void {
            self.workers.cancel(self.io);
            while (self.pollCompletion()) |completion_value| {
                var completion = completion_value;
                completion.deinit();
            }
            self.completions.close(self.io);
            var collector_iterator = self.collectors.valueIterator();
            while (collector_iterator.next()) |collector| {
                collector.deinit(self.allocator);
            }
            self.collectors.deinit(self.allocator);
            var active_iterator = self.active_requests.valueIterator();
            while (active_iterator.next()) |request| {
                request.*.deinit(self.allocator);
                self.allocator.destroy(request.*);
            }
            self.active_requests.deinit(self.allocator);
            for (self.responses.items) |*response| {
                response.deinit(self.allocator);
            }
            self.responses.deinit(self.allocator);
            self.rejected.deinit(self.allocator);
            self.abandoned.deinit(self.allocator);
            self.rejected_keys.deinit(self.allocator);
            self.allocator.destroy(self.worker_context);
            self.allocator.destroy(self.completions);
            self.allocator.free(self.completion_storage);
            self.* = undefined;
        }

        fn run(self: *Self) !void {
            while (!self.options.shutdown.isSet()) {
                try self.drainCompletions();
                try self.dispatchReadyRequests();
                try self.flushResponses();
                try self.flushRejected();
                if (self.options.stop_after_responses != 0 and
                    self.served_requests >= self.options.stop_after_responses and
                    self.active_workers == 0 and
                    self.active_requests.count() == 0 and
                    self.collectors.count() == 0 and
                    self.responses.items.len == 0 and
                    self.rejected.count() == 0)
                {
                    return;
                }

                const force_transport_progress = self.force_transport_progress;
                self.force_transport_progress = false;
                const event_value = (if (force_transport_progress)
                    self.endpoint.receiveTransportProgressOnce(
                        self.options.supported_versions,
                        self.options.poll_interval,
                    )
                else
                    self.endpoint.receiveOnce(
                        self.options.supported_versions,
                        self.options.poll_interval,
                    )) catch |err| {
                    if (err == error.Canceled and
                        self.options.shutdown.isSet()) return;
                    if (try self.report(.connection, err, null)) return err;
                    continue;
                } orelse continue;
                var event = event_value;
                defer event.deinit(self.allocator);
                switch (event) {
                    .connected, .unrouted => {},
                    .handshake_failed => |failure| {
                        if (try self.report(
                            .connection,
                            failure.err,
                            null,
                        )) return failure.err;
                    },
                    .closed => |closed| self.dropConnection(closed.handle),
                    .request => |*request_event| try self.consumeRequestEvent(
                        request_event.connection_handle,
                        &request_event.request,
                    ),
                }
            }
        }

        fn consumeRequestEvent(
            self: *Self,
            connection_handle: quic.endpoint_dispatcher.ConnectionHandle,
            event: *Runtime.StreamingRequestEvent,
        ) !void {
            const stream_id = switch (event.*) {
                .reset => |reset| reset.stream_id,
                .message => |message| message.stream_id,
            };
            const key: RequestKey = .{
                .connection_handle = connection_handle,
                .stream_id = stream_id,
            };
            if (event.* == .reset) {
                self.removeCollector(key);
                self.removeResponseFor(key);
                if (self.active_requests.contains(key)) {
                    try self.abandoned.put(self.allocator, key, {});
                }
                _ = self.rejected.remove(key);
                return;
            }
            const message = &event.message;
            const session = self.endpoint.session(connection_handle) orelse
                return error.UnknownConnectionHandle;
            if (self.rejected.contains(key)) {
                switch (message.value) {
                    .data_available => {
                        if ((try session.skipRequestDataOnce(stream_id)) == null) {
                            self.force_transport_progress = true;
                        }
                    },
                    .finished, .trailers => {},
                    .head, .push_promise => return error.UnexpectedFrame,
                }
                try self.endpoint.dispatcher.refreshConnectionTimer(
                    connection_handle,
                );
                return;
            }
            switch (message.value) {
                .head => |head| switch (head) {
                    .response => return error.UnexpectedFrame,
                    .request => |request_head| {
                        if (requestHasProtocol(request_head.headers)) {
                            try self.reject(key, session);
                            return;
                        }
                        const pending_responses = self.collectors.count() +|
                            self.active_workers +| self.responses.items.len +|
                            @as(usize, 0);
                        const pending = pending_responses +|
                            self.rejected.count();
                        const response_budget_full =
                            self.options.stop_after_responses != 0 and
                            self.served_requests +| pending_responses >=
                                self.options.stop_after_responses;
                        if (pending >= self.options.max_pending_requests or
                            response_budget_full)
                        {
                            try self.reject(key, session);
                            return;
                        }
                        if (request_head.content_length) |length| {
                            if (length > self.options.max_request_body_bytes) {
                                try self.reject(key, session);
                                return;
                            }
                        }
                        const slot = try self.collectors.getOrPut(
                            self.allocator,
                            key,
                        );
                        if (slot.found_existing) return error.UnexpectedFrame;
                        slot.value_ptr.* = .{
                            .from = message.from,
                            .was_early_data = message.was_early_data,
                            .head = request_head,
                        };
                        message.value = .data_available;
                    },
                },
                .data_available => {
                    const collector = self.collectors.getPtr(key) orelse
                        return error.UnexpectedFrame;
                    const available = try session.availableRequestData(stream_id);
                    if (available > self.options.max_request_body_bytes -|
                        collector.body.items.len)
                    {
                        self.removeCollector(key);
                        try self.reject(key, session);
                        return;
                    }
                    if (available == 0) return;
                    const previous = collector.body.items.len;
                    const destination = try collector.body.addManyAsSlice(
                        self.allocator,
                        available,
                    );
                    const count = session.readRequestDataOnce(
                        stream_id,
                        destination,
                    ) catch |err| {
                        collector.body.items.len = previous;
                        return err;
                    } orelse {
                        collector.body.items.len = previous;
                        self.force_transport_progress = true;
                        return;
                    };
                    collector.body.items.len = previous + count;
                },
                .trailers => |trailers| {
                    const collector = self.collectors.getPtr(key) orelse
                        return error.UnexpectedFrame;
                    if (collector.trailers.len != 0) return error.UnexpectedFrame;
                    collector.trailers = trailers.fields;
                    message.value = .data_available;
                },
                .finished => {
                    const collector = self.collectors.getPtr(key) orelse
                        return error.UnexpectedFrame;
                    collector.finished = true;
                },
                .push_promise => return error.UnexpectedFrame,
            }
            try self.endpoint.dispatcher.refreshConnectionTimer(
                connection_handle,
            );
        }

        fn dispatchReadyRequests(self: *Self) !void {
            while (self.active_workers < self.options.max_handler_tasks) {
                var ready_key: ?RequestKey = null;
                var iterator = self.collectors.iterator();
                while (iterator.next()) |entry| {
                    if (entry.value_ptr.finished) {
                        ready_key = entry.key_ptr.*;
                        break;
                    }
                }
                const key = ready_key orelse return;
                const removed = self.collectors.fetchRemove(key).?;
                var collector = removed.value;
                const request_value = collector.takeRequest(
                    self.allocator,
                    key.connection_handle,
                    key.stream_id,
                ) catch |err| {
                    collector.deinit(self.allocator);
                    return err;
                };
                const request = self.allocator.create(OwnedRequest) catch |err| {
                    var owned = request_value;
                    owned.deinit(self.allocator);
                    return err;
                };
                request.* = request_value;
                self.active_requests.put(
                    self.allocator,
                    key,
                    request,
                ) catch |err| {
                    request.deinit(self.allocator);
                    self.allocator.destroy(request);
                    return err;
                };
                const task: Task = .{
                    .worker = self.worker_context,
                    .key = key,
                    .request = request,
                };
                self.workers.concurrent(
                    self.io,
                    Task.run,
                    .{task},
                ) catch |err| {
                    _ = self.active_requests.remove(key);
                    request.deinit(self.allocator);
                    self.allocator.destroy(request);
                    return err;
                };
                self.active_workers += 1;
            }
        }

        fn drainCompletions(self: *Self) !void {
            while (self.pollCompletion()) |completion_value| {
                var completion = completion_value;
                defer completion.deinit();
                if (self.abandoned.remove(completion.key)) {
                    const request = (self.active_requests.fetchRemove(
                        completion.key,
                    ) orelse return error.UnexpectedStream).value;
                    request.deinit(self.allocator);
                    self.allocator.destroy(request);
                    continue;
                }
                switch (completion.result) {
                    .response => |response| {
                        const request = self.active_requests.get(
                            completion.key,
                        ) orelse return error.UnexpectedStream;
                        try self.responses.append(self.allocator, .{
                            .key = completion.key,
                            .request = request,
                            .response = response.value,
                            .invalid_final = response.invalid_final,
                        });
                        _ = self.active_requests.remove(completion.key);
                        completion.result = .consumed;
                    },
                    .failure => |failure| {
                        const request = (self.active_requests.fetchRemove(
                            completion.key,
                        ) orelse return error.UnexpectedStream).value;
                        request.deinit(self.allocator);
                        self.allocator.destroy(request);
                        if (self.endpoint.session(
                            completion.key.connection_handle,
                        )) |session| {
                            self.reject(completion.key, session) catch |err| {
                                self.retireConnection(
                                    completion.key.connection_handle,
                                );
                                if (try self.report(
                                    .response,
                                    err,
                                    completion.key,
                                )) return err;
                            };
                        }
                        if (try self.report(
                            failure.stage,
                            failure.err,
                            completion.key,
                        )) return failure.err;
                    },
                    .consumed => unreachable,
                }
            }
        }

        fn pollCompletion(self: *Self) ?Completion {
            var values: [1]Completion = undefined;
            const count = self.completions.get(self.io, &values, 0) catch
                return null;
            if (count == 0) return null;
            std.debug.assert(self.active_workers != 0);
            self.active_workers -= 1;
            return values[0];
        }

        fn flushResponses(self: *Self) !void {
            var index: usize = 0;
            while (index < self.responses.items.len) {
                const pending = &self.responses.items[index];
                const session = self.endpoint.session(
                    pending.key.connection_handle,
                ) orelse {
                    self.removeResponse(index);
                    continue;
                };
                const complete = self.tryFlushResponse(session, pending) catch |err|
                    switch (err) {
                        error.PacingLimited,
                        error.CongestionLimited,
                        error.FlowControlBlocked,
                        => {
                            self.force_transport_progress = true;
                            index += 1;
                            continue;
                        },
                        else => {
                            const key = pending.key;
                            self.removeResponse(index);
                            self.reject(key, session) catch |reject_err| {
                                self.retireConnection(key.connection_handle);
                                if (try self.report(
                                    .response,
                                    reject_err,
                                    key,
                                )) return reject_err;
                            };
                            if (try self.report(.response, err, key)) return err;
                            continue;
                        },
                    };
                try self.endpoint.dispatcher.refreshConnectionTimer(
                    pending.key.connection_handle,
                );
                if (!complete) {
                    index += 1;
                    continue;
                }
                const invalid_final = pending.invalid_final;
                const key = pending.key;
                self.removeResponse(index);
                self.served_requests += 1;
                if (invalid_final and try self.report(
                    .handler,
                    error.InvalidStatus,
                    key,
                )) return error.InvalidStatus;
            }
        }

        fn tryFlushResponse(
            self: *Self,
            session: *Runtime.HandshakeServerSession,
            pending: *PendingResponse,
        ) Runtime.Error!bool {
            _ = self;
            const response = pending.response.value;
            switch (pending.phase) {
                .head => {
                    try response.validateBodySemantics();
                    try session.tryStartResponse(
                        pending.key.stream_id,
                        .{
                            .status = response.status,
                            .headers = response.headers,
                            .request_method = response.request_method,
                            .extended_connect = response.extended_connect,
                        },
                        response.body.len,
                        response.trailers.len != 0,
                    );
                    if (response.suppressesBody() or
                        (response.body.len == 0 and
                            response.trailers.len == 0)) return true;
                    pending.phase = if (response.body.len == 0)
                        .trailers
                    else
                        .body;
                },
                .body => {
                    const count = @min(
                        response.body.len - pending.body_offset,
                        session.options.paced_body_chunk_bytes,
                    );
                    const end = pending.body_offset + count;
                    try session.trySendResponseBody(
                        pending.key.stream_id,
                        response.body[pending.body_offset..end],
                        end == response.body.len and
                            response.trailers.len == 0,
                    );
                    pending.body_offset = end;
                    if (end != response.body.len) return false;
                    if (response.trailers.len == 0) return true;
                    pending.phase = .trailers;
                },
                .trailers => {
                    try session.tryFinishResponseTrailers(
                        pending.key.stream_id,
                        response.trailers,
                    );
                    return true;
                },
            }
            return false;
        }

        fn reject(
            self: *Self,
            key: RequestKey,
            session: *Runtime.HandshakeServerSession,
        ) !void {
            session.tryCancelRequest(
                key.stream_id,
                http3.ApplicationErrorCode.request_rejected,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => {
                    try self.rejected.put(self.allocator, key, {});
                    self.force_transport_progress = true;
                    return;
                },
                else => return err,
            };
            _ = self.rejected.remove(key);
            try self.endpoint.dispatcher.refreshConnectionTimer(
                key.connection_handle,
            );
        }

        fn flushRejected(self: *Self) !void {
            self.rejected_keys.clearRetainingCapacity();
            try self.rejected_keys.ensureTotalCapacity(
                self.allocator,
                self.rejected.count(),
            );
            var iterator = self.rejected.keyIterator();
            while (iterator.next()) |key| {
                self.rejected_keys.appendAssumeCapacity(key.*);
            }
            for (self.rejected_keys.items) |key| {
                const session = self.endpoint.session(
                    key.connection_handle,
                ) orelse {
                    _ = self.rejected.remove(key);
                    continue;
                };
                self.reject(key, session) catch |err| switch (err) {
                    error.PacingLimited,
                    error.CongestionLimited,
                    error.FlowControlBlocked,
                    => {},
                    else => {
                        _ = self.rejected.remove(key);
                        if (try self.report(.response, err, key)) return err;
                    },
                };
            }
        }

        fn removeCollector(self: *Self, key: RequestKey) void {
            var removed = self.collectors.fetchRemove(key) orelse return;
            removed.value.deinit(self.allocator);
        }

        fn removeResponse(self: *Self, index: usize) void {
            var removed = self.responses.swapRemove(index);
            removed.deinit(self.allocator);
        }

        fn removeResponseFor(self: *Self, key: RequestKey) void {
            for (self.responses.items, 0..) |response, index| {
                if (response.key.connection_handle == key.connection_handle and
                    response.key.stream_id == key.stream_id)
                {
                    self.removeResponse(index);
                    return;
                }
            }
        }

        fn dropConnection(
            self: *Self,
            handle: quic.endpoint_dispatcher.ConnectionHandle,
        ) void {
            while (true) {
                var found: ?RequestKey = null;
                var iterator = self.collectors.keyIterator();
                while (iterator.next()) |key| {
                    if (key.connection_handle == handle) {
                        found = key.*;
                        break;
                    }
                }
                self.removeCollector(found orelse break);
            }
            while (true) {
                var found: ?RequestKey = null;
                var iterator = self.rejected.keyIterator();
                while (iterator.next()) |key| {
                    if (key.connection_handle == handle) {
                        found = key.*;
                        break;
                    }
                }
                _ = self.rejected.remove(found orelse break);
            }
            var active_iterator = self.active_requests.keyIterator();
            while (active_iterator.next()) |key| {
                if (key.connection_handle == handle) {
                    self.abandoned.put(self.allocator, key.*, {}) catch {};
                }
            }
            var response_index: usize = 0;
            while (response_index < self.responses.items.len) {
                if (self.responses.items[response_index]
                    .key.connection_handle == handle)
                {
                    self.removeResponse(response_index);
                } else response_index += 1;
            }
        }

        fn retireConnection(
            self: *Self,
            handle: quic.endpoint_dispatcher.ConnectionHandle,
        ) void {
            _ = self.endpoint.removeConnection(handle);
            self.dropConnection(handle);
        }

        fn report(
            self: *Self,
            stage: ErrorStage,
            err: anyerror,
            key: ?RequestKey,
        ) !bool {
            if (self.options.error_observer) |observer| {
                observer.observe(observer.context, .{
                    .stage = stage,
                    .err = err,
                    .connection_handle = if (key) |value|
                        value.connection_handle
                    else
                        null,
                    .stream_id = if (key) |value| value.stream_id else null,
                });
            }
            return self.options.error_policy == .stop;
        }
    };
}

test "HTTP/3 endpoint handler collector preserves early-data provenance" {
    var collector = Collector{
        .from = .{ .ip4 = .loopback(443) },
        .was_early_data = true,
        .head = .{
            .method = "GET",
            .path = "/early",
            .scheme = "https",
            .authority = "localhost",
            .headers = &.{},
            .content_length = null,
            .body_allowed = true,
            .consumed = 0,
            .qpack_section_acknowledgments = 0,
        },
    };
    const request = try collector.takeRequest(std.testing.allocator, 7, 0);
    try std.testing.expect(request.was_early_data);
    try std.testing.expectEqual(@as(usize, 7), request.connection_handle);
    try std.testing.expectEqual(@as(u62, 0), request.stream_id);
}

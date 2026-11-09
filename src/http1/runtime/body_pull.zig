//! Pull-style HTTP/1 request-body reader driven by the existing push parser.
const std = @import("std");
const http1 = @import("../mod.zig");
const body_reader = @import("body_reader.zig");

pub fn Reader(comptime ConnectionType: type, comptime RuntimeError: type) type {
    const Streaming = body_reader.Reader(RuntimeError);
    return struct {
        const Self = @This();

        pub const Head = struct {
            allocator: std.mem.Allocator,
            method: http1.Method,
            target: []u8,
            version: http1.Version,
            headers: []http1.Header,
            storage: []u8,
            body_framing: http1.BodyFraming,
            content_length: ?usize,
            must_close: bool,
            /// False when `target` and `headers` borrow an owned request that
            /// outlives this value; `deinit` then releases nothing.
            owned: bool = true,

            fn copy(allocator: std.mem.Allocator, request_head: Streaming.RequestHead) !Head {
                var storage_bytes: usize = request_head.target.len;
                for (request_head.headers) |field| storage_bytes += field.name.len + field.value.len;
                const storage = try allocator.alloc(u8, storage_bytes);
                errdefer allocator.free(storage);
                const headers = try allocator.alloc(http1.Header, request_head.headers.len);
                errdefer allocator.free(headers);
                var offset: usize = 0;
                const target = storage[offset..][0..request_head.target.len];
                @memcpy(target, request_head.target);
                offset += request_head.target.len;
                for (request_head.headers, headers) |field, *copy_field| {
                    const name = storage[offset..][0..field.name.len];
                    @memcpy(name, field.name);
                    offset += field.name.len;
                    const value = storage[offset..][0..field.value.len];
                    @memcpy(value, field.value);
                    offset += field.value.len;
                    copy_field.* = .{ .name = name, .value = value };
                }
                return .{ .allocator = allocator, .method = request_head.method, .target = target, .version = request_head.version, .headers = headers, .storage = storage, .body_framing = request_head.body_framing, .content_length = request_head.content_length, .must_close = request_head.must_close };
            }

            /// Borrow the head slices from an owned request instead of copying
            /// them. The request must outlive every use of this value.
            pub fn borrow(
                allocator: std.mem.Allocator,
                request: *const Streaming.Request,
                content_length: ?usize,
            ) Head {
                return .{
                    .allocator = allocator,
                    .method = request.method,
                    .target = @constCast(request.target),
                    .version = request.version,
                    .headers = @constCast(request.headers),
                    .storage = &.{},
                    .body_framing = request.body_framing,
                    .content_length = content_length,
                    .must_close = request.must_close,
                    .owned = false,
                };
            }

            pub fn deinit(self: *Head) void {
                if (self.owned) {
                    self.allocator.free(self.headers);
                    self.allocator.free(self.storage);
                }
                self.* = undefined;
            }
            pub fn header(self: Head, name: []const u8) ?[]const u8 {
                for (self.headers) |field| if (field.eqlName(name)) return field.value;
                return null;
            }
            pub fn keepAlive(self: Head) bool {
                return !self.must_close and http1.headersKeepAlive(self.version, self.headers);
            }
            pub fn acceptsTrailers(self: Head) bool {
                return http1.requestAcceptsTrailers(self.version, self.headers);
            }
            /// Content-decoding chain for the encoded body chunks returned by
            /// `next`. The caller drives `step`/`finish` with output buffers.
            pub fn streamContentDecoder(self: Head, allocator: std.mem.Allocator, options: http1.content_coding.StreamOptions) http1.content_coding.Error!http1.content_coding.StreamDecoder {
                const request_head: Streaming.RequestHead = .{
                    .method = self.method,
                    .target = self.target,
                    .version = self.version,
                    .headers = self.headers,
                    .body_framing = self.body_framing,
                    .content_length = self.content_length,
                    .must_close = self.must_close,
                };
                return request_head.streamContentDecoder(allocator, options);
            }
        };

        allocator: std.mem.Allocator,
        io: std.Io,
        connection: *ConnectionType,
        options: http1.ParseOptions,
        max_buffered_bytes: usize,
        mutex: std.Io.Mutex = .init,
        cond: std.Io.Condition = .init,
        chunks: std.ArrayList([]u8) = .empty,
        buffered_bytes: usize = 0,
        head_value: ?Head = null,
        failure: ?anyerror = null,
        canceled: bool = false,
        finished: bool = false,
        request: ?Streaming.Request = null,
        current: ?[]u8 = null,
        current_offset: usize = 0,
        producer: ?std.Io.Future(anyerror!void) = null,

        pub fn init(allocator: std.mem.Allocator, connection: *ConnectionType, options: http1.ParseOptions, max_buffered_bytes: usize) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .io = connection.io,
                .connection = connection,
                .options = options,
                .max_buffered_bytes = @max(max_buffered_bytes, 1),
            };
            self.producer = self.io.async(Self.produce, .{self});
            return self;
        }

        /// Build an already-complete reader for a request that has no body.
        /// The caller has consumed the head from the connection buffer and
        /// owns `head_value` and `request`; the reader releases both.
        pub fn initCompleted(
            allocator: std.mem.Allocator,
            connection: *ConnectionType,
            options: http1.ParseOptions,
            head_value: Head,
            request: Streaming.Request,
        ) !*Self {
            const self = try allocator.create(Self);
            self.* = .{
                .allocator = allocator,
                .io = connection.io,
                .connection = connection,
                .options = options,
                .max_buffered_bytes = 1,
                .head_value = head_value,
                .finished = true,
                .request = request,
            };
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            self.canceled = true;
            self.cond.broadcast(self.io);
            self.mutex.unlock(self.io);
            if (self.producer) |*producer| {
                _ = producer.cancel(self.io) catch {};
                _ = producer.await(self.io) catch {};
            }
            if (!self.finished) self.connection.close();
            if (self.current) |chunk| self.allocator.free(chunk);
            for (self.chunks.items) |chunk| self.allocator.free(chunk);
            self.chunks.deinit(self.allocator);
            if (self.head_value) |*value| value.deinit();
            if (self.request) |*request| request.deinit(self.allocator);
            self.allocator.destroy(self);
        }

        /// Wait for the parsed request head. The returned value remains valid
        /// until `deinit`.
        pub fn head(self: *Self) !*const Head {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (self.head_value == null and self.failure == null and !self.finished) {
                try self.cond.wait(self.io, &self.mutex);
            }
            if (self.head_value) |*value| return value;
            if (self.failure) |err| return err;
            return error.ConnectionClosed;
        }

        /// Return the next body chunk. The slice is borrowed until the next
        /// `next` call or `deinit`; the caller must consume it before calling
        /// again. Returns null after the body is complete.
        pub fn next(self: *Self) !?[]const u8 {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (true) {
                if (self.current) |chunk| {
                    if (self.current_offset < chunk.len) {
                        const result = chunk[self.current_offset..];
                        self.current_offset = chunk.len;
                        return result;
                    }
                    self.allocator.free(chunk);
                    self.current = null;
                    self.current_offset = 0;
                }
                if (self.chunks.items.len != 0) {
                    self.current = self.chunks.orderedRemove(0);
                    self.buffered_bytes -= self.current.?.len;
                    self.cond.signal(self.io);
                    continue;
                }
                if (self.failure) |err| return err;
                if (self.finished) return null;
                try self.cond.wait(self.io, &self.mutex);
            }
        }

        /// Take the completed request metadata. `next` must have returned null
        /// (or `requestReady` must be true); calling early returns
        /// `error.RequestNotComplete` instead of blocking behind a full queue.
        pub fn takeRequest(self: *Self) !Streaming.Request {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.failure) |err| return err;
            if (!self.finished) return error.RequestNotComplete;
            const request = self.request orelse return error.ConnectionClosed;
            self.request = null;
            return request;
        }

        /// True once the producer has completed the body and stored the request
        /// metadata. Body chunks may still be pending; `next` drains them.
        pub fn requestReady(self: *Self) bool {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.finished;
        }

        fn produce(self: *Self) anyerror!void {
            const request = self.connection.readRequestStreamingWithOptionsAndHead(self.options, self, Self.begin, Self.consume) catch |err| {
                self.fail(err);
                return err;
            };
            self.complete(request);
        }

        fn begin(self: *Self, request_head: Streaming.RequestHead) anyerror!void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            if (self.canceled) return error.Canceled;
            self.head_value = try Head.copy(self.allocator, request_head);
            self.cond.broadcast(self.io);
        }

        fn consume(self: *Self, bytes: []const u8) anyerror!void {
            if (bytes.len == 0) return;
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            while (self.buffered_bytes >= self.max_buffered_bytes and !self.canceled) {
                try self.cond.wait(self.io, &self.mutex);
            }
            if (self.canceled) return error.Canceled;
            const copy = try self.allocator.dupe(u8, bytes);
            errdefer self.allocator.free(copy);
            try self.chunks.append(self.allocator, copy);
            self.buffered_bytes += copy.len;
            self.cond.signal(self.io);
        }

        fn complete(self: *Self, request: Streaming.Request) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.request = request;
            self.finished = true;
            self.cond.broadcast(self.io);
        }

        fn fail(self: *Self, err: anyerror) void {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            self.failure = err;
            self.finished = true;
            self.cond.broadcast(self.io);
        }
    };
}

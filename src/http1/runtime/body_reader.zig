const std = @import("std");
const http1 = @import("../mod.zig");
const chunk_size = @import("../chunk_size.zig");

const direct_body_read_bytes: usize = 64 * 1024;
// Four 16-KiB chunks fit in one read for the common streaming shape while the
// persistent per-connection allocation remains bounded and reusable.
const buffered_read_ahead_bytes: usize = 64 * 1024;

pub fn Reader(comptime RuntimeError: type) type {
    return struct {
        allocator: std.mem.Allocator,
        context: ?*anyopaque,
        read_some: *const fn (
            context: ?*anyopaque,
            buffer: []u8,
        ) RuntimeError!usize,
        read_head_some: ?*const fn (
            context: ?*anyopaque,
            buffer: []u8,
        ) RuntimeError!usize = null,
        before_request_body: ?*const fn (
            context: ?*anyopaque,
            head: []const u8,
        ) RuntimeError!void = null,
        /// Typed counterpart for protocol decisions based on accepted fields.
        before_request_head: ?*const fn (
            context: ?*anyopaque,
            head: http1.RequestHead,
        ) RuntimeError!void = null,
        informational_context: ?*anyopaque = null,
        informational_responses_seen: ?*usize = null,
        on_informational: ?*const fn (
            context: *anyopaque,
            response: http1.InformationalResponseHead,
        ) void = null,
        inbuf: *std.ArrayList(u8),
        offset: usize = 0,
        limits: Limits,
        options: http1.ParseOptions,

        const Self = @This();

        pub const Limits = struct {
            max_head_bytes: usize,
            max_body_bytes: usize,
            max_informational_responses: usize = 16,
        };

        pub const Request = struct {
            head_bytes: []u8,
            method: http1.Method,
            target: []const u8,
            version: http1.Version,
            headers: []http1.Header,
            body_framing: http1.BodyFraming,
            body_bytes: usize,
            must_close: bool = false,
            header_value_storage: [][]u8 = &.{},
            trailers: []http1.Header = &.{},
            trailer_bytes: ?[]u8 = null,
            trailer_value_storage: [][]u8 = &.{},

            pub fn deinit(
                self: *Request,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.headers);
                for (self.header_value_storage) |value| allocator.free(value);
                allocator.free(self.header_value_storage);
                for (self.trailer_value_storage) |value| allocator.free(value);
                allocator.free(self.trailer_value_storage);
                allocator.free(self.trailers);
                if (self.trailer_bytes) |bytes| allocator.free(bytes);
                allocator.free(self.head_bytes);
                self.* = undefined;
            }

            pub fn header(
                self: Request,
                name: []const u8,
            ) ?[]const u8 {
                for (self.headers) |field| {
                    if (field.eqlName(name)) return field.value;
                }
                return null;
            }

            pub fn keepAlive(self: Request) bool {
                return !self.must_close and http1.headersKeepAlive(
                    self.version,
                    self.headers,
                );
            }

            pub fn acceptsTrailers(self: Request) bool {
                return http1.requestAcceptsTrailers(
                    self.version,
                    self.headers,
                );
            }
        };

        pub const Response = struct {
            head_bytes: []u8,
            version: http1.Version,
            status: u16,
            reason: []const u8,
            headers: []http1.Header,
            body_framing: http1.BodyFraming,
            body_bytes: usize,
            body_allowed: bool = true,
            must_close: bool = false,
            header_value_storage: [][]u8 = &.{},
            trailers: []http1.Header = &.{},
            trailer_bytes: ?[]u8 = null,
            trailer_value_storage: [][]u8 = &.{},

            pub fn deinit(
                self: *Response,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.headers);
                for (self.header_value_storage) |value| allocator.free(value);
                allocator.free(self.header_value_storage);
                for (self.trailer_value_storage) |value| allocator.free(value);
                allocator.free(self.trailer_value_storage);
                allocator.free(self.trailers);
                if (self.trailer_bytes) |bytes| allocator.free(bytes);
                allocator.free(self.head_bytes);
                self.* = undefined;
            }

            pub fn header(
                self: Response,
                name: []const u8,
            ) ?[]const u8 {
                for (self.headers) |field| {
                    if (field.eqlName(name)) return field.value;
                }
                return null;
            }

            pub fn keepAlive(self: Response) bool {
                return @import("../response_framing.zig").keepAlive(self);
            }
        };

        pub const RequestHead = struct {
            method: http1.Method,
            target: []const u8,
            version: http1.Version,
            headers: []const http1.Header,
            body_framing: http1.BodyFraming,
            content_length: ?usize,
            must_close: bool = false,

            pub fn header(
                self: RequestHead,
                name: []const u8,
            ) ?[]const u8 {
                for (self.headers) |field| {
                    if (field.eqlName(name)) return field.value;
                }
                return null;
            }

            pub fn keepAlive(self: RequestHead) bool {
                return !self.must_close and http1.headersKeepAlive(
                    self.version,
                    self.headers,
                );
            }

            pub fn acceptsTrailers(self: RequestHead) bool {
                return http1.requestAcceptsTrailers(
                    self.version,
                    self.headers,
                );
            }

            pub fn streamContentDecoder(
                self: RequestHead,
                allocator: std.mem.Allocator,
                options: http1.content_coding.StreamOptions,
            ) http1.content_coding.Error!http1.content_coding.StreamDecoder {
                return (try http1.content_coding.parseHeaders(self.headers))
                    .streamDecoder(allocator, options);
            }
        };

        pub const ResponseHead = struct {
            version: http1.Version,
            status: u16,
            reason: []const u8,
            headers: []const http1.Header,
            body_framing: http1.BodyFraming,
            content_length: ?usize,
            body_allowed: bool = true,
            must_close: bool = false,

            pub fn header(
                self: ResponseHead,
                name: []const u8,
            ) ?[]const u8 {
                for (self.headers) |field| {
                    if (field.eqlName(name)) return field.value;
                }
                return null;
            }

            pub fn keepAlive(self: ResponseHead) bool {
                return @import("../response_framing.zig").keepAlive(self);
            }

            pub fn streamContentDecoder(
                self: ResponseHead,
                allocator: std.mem.Allocator,
                options: http1.content_coding.StreamOptions,
            ) http1.content_coding.Error!http1.content_coding.StreamDecoder {
                return (try http1.content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed))
                    .streamDecoder(allocator, options);
            }
        };

        const Trailers = struct {
            bytes: ?[]u8 = null,
            headers: []http1.Header = &.{},
            value_storage: [][]u8 = &.{},

            fn deinit(
                self: *Trailers,
                allocator: std.mem.Allocator,
            ) void {
                for (self.value_storage) |value| allocator.free(value);
                allocator.free(self.value_storage);
                allocator.free(self.headers);
                if (self.bytes) |bytes| allocator.free(bytes);
                self.* = undefined;
            }
        };

        const BodyResult = struct {
            body_bytes: usize = 0,
            trailers: Trailers = .{},
        };

        /// Read a request head and deliver its body as borrowed callback slices.
        pub fn readRequest(
            self: *Self,
            callback_context: anytype,
            comptime begin: anytype,
            comptime consume: anytype,
        ) !Request {
            const head_bytes = try self.readHeadBytes();
            errdefer self.allocator.free(head_bytes);
            var owned_head: ?http1.OwnedRequestHead = null;
            defer if (owned_head) |*owned| owned.deinit(self.allocator);
            var headers_stack: [128]http1.Header = undefined;
            const headers = if (self.options.allow_obs_fold)
                headers_stack[0..0]
            else if (self.options.max_headers <=
                headers_stack.len)
                headers_stack[0..self.options.max_headers]
            else
                try self.allocator.alloc(
                    http1.Header,
                    self.options.max_headers,
                );
            defer if (headers.ptr != headers_stack[0..].ptr) {
                self.allocator.free(headers);
            };
            const head = if (self.options.allow_obs_fold) blk: {
                owned_head = try http1.parseOwnedRequestHead(self.allocator, head_bytes, self.options);
                break :blk owned_head.?.head;
            } else try http1.parseRequestHead(
                head_bytes,
                headers,
                self.options,
            );
            try self.validateKnownBodyLength(
                head.body_framing,
                head.content_length,
            );
            if (self.before_request_head) |before| {
                try before(self.context, head);
            }
            if (self.before_request_body) |before| {
                try before(self.context, head_bytes);
            }

            begin(callback_context, RequestHead{
                .method = head.method,
                .target = head.target,
                .version = head.version,
                .headers = head.headers,
                .body_framing = head.body_framing,
                .content_length = head.content_length,
                .must_close = head.must_close,
            }) catch |err| {
                return err;
            };
            const body = try self.readBody(
                head.body_framing,
                head.content_length,
                callback_context,
                consume,
            );
            var body_owned = true;
            errdefer if (body_owned) {
                var cleanup = body.trailers;
                cleanup.deinit(self.allocator);
            };
            const owned_headers = try self.allocator.dupe(
                http1.Header,
                head.headers,
            );
            errdefer self.allocator.free(owned_headers);
            self.commit();
            body_owned = false;
            return .{
                .head_bytes = head_bytes,
                .method = head.method,
                .target = head.target,
                .version = head.version,
                .headers = owned_headers,
                .body_framing = head.body_framing,
                .body_bytes = body.body_bytes,
                .must_close = head.must_close,
                .trailers = body.trailers.headers,
                .header_value_storage = if (owned_head) |*owned| owned.takeValues() else &.{},
                .trailer_bytes = body.trailers.bytes,
                .trailer_value_storage = body.trailers.value_storage,
            };
        }

        /// Read one final response, skipping valid informational responses.
        pub fn readResponse(
            self: *Self,
            request_method: http1.Method,
            callback_context: anytype,
            comptime begin: anytype,
            comptime consume: anytype,
        ) !Response {
            var local_informational_count: usize = 0;
            const informational_count = self.informational_responses_seen orelse
                &local_informational_count;
            while (true) {
                const head_bytes = try self.readHeadBytes();
                var head_needs_free = true;
                defer if (head_needs_free) self.allocator.free(head_bytes);
                var owned_head: ?http1.OwnedResponseHead = null;
                defer if (owned_head) |*owned| owned.deinit(self.allocator);
                var headers_stack: [128]http1.Header = undefined;
                const headers = if (self.options.allow_obs_fold)
                    headers_stack[0..0]
                else if (self.options.max_headers <=
                    headers_stack.len)
                    headers_stack[0..self.options.max_headers]
                else
                    try self.allocator.alloc(
                        http1.Header,
                        self.options.max_headers,
                    );
                defer if (headers.ptr != headers_stack[0..].ptr) {
                    self.allocator.free(headers);
                };
                var head = if (self.options.allow_obs_fold) blk: {
                    owned_head = try http1.parseOwnedResponseHead(self.allocator, head_bytes, self.options, .{ .request_method = request_method });
                    break :blk owned_head.?.head;
                } else try http1.parseResponseHead(
                    head_bytes,
                    headers,
                    self.options,
                    .{ .request_method = request_method },
                );
                if (head.status >= 100 and head.status < 200 and
                    head.status != 101)
                {
                    // Informational responses terminate at the head. Reject
                    // body framing before continuing so bytes cannot be
                    // reinterpreted as another status line.
                    try http1.validateResponseBodyForStatus(
                        head.status,
                        head.headers,
                        &.{},
                        &.{},
                    );
                    informational_count.* += 1;
                    if (informational_count.* >
                        self.limits.max_informational_responses)
                    {
                        return error.TooManyInformationalResponses;
                    }
                    if (self.on_informational) |observe| {
                        observe(
                            self.informational_context.?,
                            .{
                                .version = head.version,
                                .status = head.status,
                                .reason = head.reason,
                                .headers = head.headers,
                            },
                        );
                    }
                    self.allocator.free(head_bytes);
                    head_needs_free = false;
                    continue;
                }
                if (head.body_framing == .chunked or
                    head.body_framing == .close_delimited)
                {
                    head.headers = stripHeader(
                        head.headers,
                        "content-length",
                    );
                }
                try self.validateKnownBodyLength(
                    head.body_framing,
                    head.content_length,
                );

                begin(callback_context, ResponseHead{
                    .version = head.version,
                    .status = head.status,
                    .reason = head.reason,
                    .headers = head.headers,
                    .body_framing = head.body_framing,
                    .content_length = head.content_length,
                    .body_allowed = head.body_allowed,
                    .must_close = head.must_close,
                }) catch |err| {
                    return err;
                };
                const body = try self.readBody(
                    head.body_framing,
                    head.content_length,
                    callback_context,
                    consume,
                );
                var body_owned = true;
                errdefer if (body_owned) {
                    var cleanup = body.trailers;
                    cleanup.deinit(self.allocator);
                };
                const owned_headers = try self.allocator.dupe(
                    http1.Header,
                    head.headers,
                );
                errdefer self.allocator.free(owned_headers);
                self.commit();
                head_needs_free = false;
                body_owned = false;
                return .{
                    .head_bytes = head_bytes,
                    .version = head.version,
                    .status = head.status,
                    .reason = head.reason,
                    .headers = owned_headers,
                    .body_framing = head.body_framing,
                    .body_bytes = body.body_bytes,
                    .body_allowed = head.body_allowed,
                    .must_close = head.must_close,
                    .trailers = body.trailers.headers,
                    .header_value_storage = if (owned_head) |*owned| owned.takeValues() else &.{},
                    .trailer_bytes = body.trailers.bytes,
                    .trailer_value_storage = body.trailers.value_storage,
                };
            }
        }

        fn readHeadBytes(self: *Self) RuntimeError![]u8 {
            self.compact();
            var head_end = try findHeadEnd(
                self.buffered(),
                self.limits.max_head_bytes,
            );
            while (head_end == null) {
                try self.readHeadMore(self.limits.max_head_bytes);
                head_end = try findHeadEnd(
                    self.buffered(),
                    self.limits.max_head_bytes,
                );
            }
            const len = head_end.? + 4;
            const bytes = try self.allocator.dupe(
                u8,
                self.buffered()[0..len],
            );
            self.consumePrefix(len);
            return bytes;
        }

        fn readHeadMore(
            self: *Self,
            max_buffer_bytes: usize,
        ) RuntimeError!void {
            return self.readMoreWith(
                max_buffer_bytes,
                self.read_head_some orelse self.read_some,
            );
        }

        fn readBody(
            self: *Self,
            framing: http1.BodyFraming,
            content_length: ?usize,
            callback_context: anytype,
            comptime consume: anytype,
        ) !BodyResult {
            return switch (framing) {
                .none => .{},
                .content_length => self.readFixed(
                    content_length orelse return error.InvalidContentLength,
                    callback_context,
                    consume,
                ),
                .chunked => self.readChunked(
                    callback_context,
                    consume,
                ),
                .close_delimited => self.readCloseDelimited(
                    callback_context,
                    consume,
                ),
            };
        }

        fn validateKnownBodyLength(
            self: Self,
            framing: http1.BodyFraming,
            content_length: ?usize,
        ) RuntimeError!void {
            if (framing != .content_length) return;
            if ((content_length orelse return error.InvalidContentLength) >
                self.limits.max_body_bytes)
            {
                return error.BodyTooLarge;
            }
        }

        fn readFixed(
            self: *Self,
            length: usize,
            callback_context: anytype,
            comptime consume: anytype,
        ) !BodyResult {
            if (length > self.limits.max_body_bytes) {
                return error.BodyTooLarge;
            }
            var remaining = length;
            var direct_buffer: [direct_body_read_bytes]u8 = undefined;
            while (remaining != 0) {
                if (self.buffered().len == 0) {
                    // Once Content-Length establishes the exact boundary, read
                    // directly into callback scratch. Appending to `inbuf`
                    // would add a full-body memory copy and cannot discover a
                    // pipeline suffix because this read is capped at remaining.
                    const count = try self.read_some(
                        self.context,
                        direct_buffer[0..@min(
                            direct_buffer.len,
                            remaining,
                        )],
                    );
                    if (count == 0) return error.ConnectionClosed;
                    consume(
                        callback_context,
                        direct_buffer[0..count],
                    ) catch |err| return err;
                    remaining -= count;
                    continue;
                }
                const available = self.buffered();
                const count = @min(remaining, available.len);
                if (count == 0) return error.ConnectionClosed;
                consume(
                    callback_context,
                    available[0..count],
                ) catch |err| return err;
                self.consumePrefix(count);
                remaining -= count;
            }
            return .{ .body_bytes = length };
        }

        fn readCloseDelimited(
            self: *Self,
            callback_context: anytype,
            comptime consume: anytype,
        ) !BodyResult {
            var total: usize = 0;
            var scratch: [16 * 1024]u8 = undefined;
            while (true) {
                const available = self.buffered();
                if (available.len != 0) {
                    total = try addBodyBytes(
                        total,
                        available.len,
                        self.limits.max_body_bytes,
                    );
                    consume(
                        callback_context,
                        available,
                    ) catch |err| return err;
                    self.consumePrefix(available.len);
                }
                self.compact();
                const count = try self.read_some(
                    self.context,
                    &scratch,
                );
                if (count == 0) break;
                total = try addBodyBytes(
                    total,
                    count,
                    self.limits.max_body_bytes,
                );
                consume(
                    callback_context,
                    scratch[0..count],
                ) catch |err| return err;
            }
            return .{ .body_bytes = total };
        }

        fn readChunked(
            self: *Self,
            callback_context: anytype,
            comptime consume: anytype,
        ) !BodyResult {
            var total: usize = 0;
            var metadata: chunk_size.State = .{};
            while (true) {
                const size = try self.readChunkSize(&metadata);
                if (size == 0) {
                    const trailers = try self.readTrailers();
                    return .{
                        .body_bytes = total,
                        .trailers = trailers,
                    };
                }
                total = try addBodyBytes(
                    total,
                    size,
                    self.limits.max_body_bytes,
                );
                var remaining = size;
                while (remaining != 0) {
                    if (self.buffered().len == 0) {
                        // Chunked framing has an explicit terminator and this
                        // reader owns a persistent inbuf, so it is safe to read
                        // beyond the current payload into later chunks or the
                        // next pipelined head. A bounded read-ahead amortizes
                        // size/data/CRLF parsing over one socket read while
                        // callbacks still receive each chunk incrementally.
                        try self.readMore(buffered_read_ahead_bytes);
                    }
                    const available = self.buffered();
                    const count = @min(
                        remaining,
                        available.len,
                    );
                    consume(
                        callback_context,
                        available[0..count],
                    ) catch |err| return err;
                    self.consumePrefix(count);
                    remaining -= count;
                }
                try self.requireBytes(2);
                if (!std.mem.eql(
                    u8,
                    self.buffered()[0..2],
                    "\r\n",
                )) return error.InvalidChunk;
                self.consumePrefix(2);
            }
        }

        fn readTrailers(self: *Self) RuntimeError!Trailers {
            try self.requireBytes(2);
            if (std.mem.startsWith(
                u8,
                self.buffered(),
                "\r\n",
            )) {
                self.consumePrefix(2);
                return .{};
            }

            var trailer_end = try findHeadEnd(
                self.buffered(),
                self.limits.max_head_bytes,
            );
            while (trailer_end == null) {
                try self.readMore(self.limits.max_head_bytes);
                trailer_end = try findHeadEnd(
                    self.buffered(),
                    self.limits.max_head_bytes,
                );
            }
            const len = trailer_end.? + 4;
            const bytes = try self.allocator.dupe(
                u8,
                self.buffered()[0..len],
            );
            errdefer self.allocator.free(bytes);
            self.consumePrefix(len);

            var trailers = try parseTrailerBlock(
                self.allocator,
                bytes,
                self.options,
            );
            errdefer trailers.deinit(self.allocator);
            try http1.validateTrailers(trailers.headers);
            return .{
                .bytes = bytes,
                .headers = trailers.headers,
                .value_storage = trailers.value_storage,
            };
        }

        fn readChunkSize(self: *Self, metadata: *chunk_size.State) RuntimeError!usize {
            while (true) {
                if (std.mem.indexOf(u8, self.buffered(), "\r\n")) |end| {
                    const size = metadata.feed(self.buffered()[0..end]) catch |err| switch (err) {
                        error.ChunkSizeOverheadTooLarge => return error.BodyTooLarge,
                        else => |other| return @errorCast(other),
                    };
                    self.consumePrefix(end + 2);
                    return size;
                }
                try chunk_size.validateIncomplete(self.buffered());
                // Reserve both delimiter bytes even when CR and LF split.
                try self.readMore(http1.max_chunk_size_line_bytes + 1);
            }
        }

        fn requireBytes(
            self: *Self,
            count: usize,
        ) RuntimeError!void {
            while (self.buffered().len < count) {
                try self.readMore(count);
            }
        }

        fn readMore(
            self: *Self,
            max_buffer_bytes: usize,
        ) RuntimeError!void {
            return self.readMoreWith(max_buffer_bytes, self.read_some);
        }

        fn readMoreWith(
            self: *Self,
            max_buffer_bytes: usize,
            read_some: *const fn (
                context: ?*anyopaque,
                buffer: []u8,
            ) RuntimeError!usize,
        ) RuntimeError!void {
            self.compact();
            if (self.inbuf.items.len >= max_buffer_bytes) {
                return error.BodyTooLarge;
            }
            const original_len = self.inbuf.items.len;
            const destination = try self.inbuf.addManyAsSlice(
                self.allocator,
                @min(
                    buffered_read_ahead_bytes,
                    max_buffer_bytes - original_len,
                ),
            );
            const count = read_some(
                self.context,
                destination,
            ) catch |err| {
                self.inbuf.shrinkRetainingCapacity(original_len);
                return err;
            };
            self.inbuf.shrinkRetainingCapacity(original_len + count);
            if (count == 0) return error.ConnectionClosed;
        }

        fn buffered(self: Self) []u8 {
            return self.inbuf.items[self.offset..];
        }

        fn consumePrefix(self: *Self, len: usize) void {
            std.debug.assert(len <= self.buffered().len);
            self.offset += len;
        }

        fn compact(self: *Self) void {
            if (self.offset == 0) return;
            const remaining = self.buffered();
            if (remaining.len != 0) {
                @memmove(
                    self.inbuf.items[0..remaining.len],
                    remaining,
                );
            }
            self.inbuf.shrinkRetainingCapacity(remaining.len);
            self.offset = 0;
        }

        fn commit(self: *Self) void {
            self.compact();
        }
    };
}

fn findHeadEnd(
    bytes: []const u8,
    max_head_bytes: usize,
) !?usize {
    if (std.mem.indexOf(u8, bytes, "\r\n\r\n")) |head_end| {
        if (head_end + 4 > max_head_bytes) {
            return error.HeadersTooLarge;
        }
        return head_end;
    }
    if (bytes.len >= max_head_bytes) return error.HeadersTooLarge;
    return null;
}

fn parseTrailerBlock(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
) !http1.ParsedTrailerFields {
    const block_end = bytes.len - 4;
    if (options.allow_obs_fold) {
        const parsed = try http1.parseTrailerFields(
            allocator,
            bytes[0..block_end],
            options,
        );
        return .{
            .headers = parsed.headers,
            .value_storage = parsed.value_storage,
        };
    }
    var count: usize = 0;
    var lines = std.mem.splitSequence(
        u8,
        bytes[0..block_end],
        "\r\n",
    );
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            return error.MalformedHeader;
        }
        if (count >= options.max_headers) return error.TooManyHeaders;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.MalformedHeader;
        try http1.validateHeaderName(line[0..colon]);
        try http1.validateHeaderValue(
            std.mem.trim(u8, line[colon + 1 ..], " \t"),
        );
        count += 1;
    }
    if (count == 0) return .{};

    const headers = try allocator.alloc(http1.Header, count);
    errdefer allocator.free(headers);
    lines = std.mem.splitSequence(
        u8,
        bytes[0..block_end],
        "\r\n",
    );
    var index: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':').?;
        headers[index] = .{
            .name = line[0..colon],
            .value = std.mem.trim(
                u8,
                line[colon + 1 ..],
                " \t",
            ),
        };
        index += 1;
    }
    return .{ .headers = headers };
}

fn addBodyBytes(
    current: usize,
    additional: usize,
    maximum: usize,
) !usize {
    const total = std.math.add(
        usize,
        current,
        additional,
    ) catch return error.BodyTooLarge;
    if (total > maximum) return error.BodyTooLarge;
    return total;
}

fn stripHeader(
    headers: []http1.Header,
    name: []const u8,
) []http1.Header {
    var kept: usize = 0;
    for (headers) |header| {
        if (header.eqlName(name)) continue;
        headers[kept] = header;
        kept += 1;
    }
    return headers[0..kept];
}

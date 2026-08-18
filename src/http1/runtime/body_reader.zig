const std = @import("std");
const http1 = @import("../mod.zig");

pub fn Reader(comptime RuntimeError: type) type {
    return struct {
        allocator: std.mem.Allocator,
        context: ?*anyopaque,
        read_some: *const fn (
            context: ?*anyopaque,
            buffer: []u8,
        ) RuntimeError!usize,
        before_request_body: ?*const fn (
            context: ?*anyopaque,
            head: []const u8,
        ) RuntimeError!void = null,
        inbuf: *std.ArrayList(u8),
        offset: usize = 0,
        limits: Limits,
        options: http1.ParseOptions,

        const Self = @This();

        pub const Limits = struct {
            max_head_bytes: usize,
            max_body_bytes: usize,
        };

        pub const Request = struct {
            head_bytes: []u8,
            method: http1.Method,
            target: []const u8,
            version: http1.Version,
            headers: []http1.Header,
            body_framing: http1.BodyFraming,
            body_bytes: usize,
            trailers: []http1.Header = &.{},
            trailer_bytes: ?[]u8 = null,

            pub fn deinit(
                self: *Request,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.headers);
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
                return messageKeepAlive(
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
            trailers: []http1.Header = &.{},
            trailer_bytes: ?[]u8 = null,

            pub fn deinit(
                self: *Response,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.headers);
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
                return messageKeepAlive(
                    self.version,
                    self.headers,
                );
            }
        };

        pub const RequestHead = struct {
            method: http1.Method,
            target: []const u8,
            version: http1.Version,
            headers: []const http1.Header,
            body_framing: http1.BodyFraming,
            content_length: ?usize,
        };

        pub const ResponseHead = struct {
            version: http1.Version,
            status: u16,
            reason: []const u8,
            headers: []const http1.Header,
            body_framing: http1.BodyFraming,
            content_length: ?usize,
        };

        const Trailers = struct {
            bytes: ?[]u8 = null,
            headers: []http1.Header = &.{},

            fn deinit(
                self: *Trailers,
                allocator: std.mem.Allocator,
            ) void {
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
            var headers_stack: [128]http1.Header = undefined;
            const headers = if (self.options.max_headers <=
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
            var head = try http1.parseRequestHead(
                head_bytes,
                headers,
                self.options,
            );
            if (head.body_framing == .chunked) {
                head.headers = stripHeader(
                    head.headers,
                    "content-length",
                );
            }
            try self.validateKnownBodyLength(
                head.body_framing,
                head.content_length,
            );
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
                .trailers = body.trailers.headers,
                .trailer_bytes = body.trailers.bytes,
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
            while (true) {
                const head_bytes = try self.readHeadBytes();
                var head_needs_free = true;
                defer if (head_needs_free) self.allocator.free(head_bytes);
                var headers_stack: [128]http1.Header = undefined;
                const headers = if (self.options.max_headers <=
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
                var head = try http1.parseResponseHead(
                    head_bytes,
                    headers,
                    self.options,
                    .{ .request_method = request_method },
                );
                if (head.status >= 100 and head.status < 200 and
                    head.status != 101)
                {
                    // Informational responses terminate at the head. Reject a
                    // declared length before skipping to the final response so
                    // those bytes cannot be reinterpreted as another status line.
                    if (head.content_length != null) {
                        return error.InvalidContentLength;
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
                    .trailers = body.trailers.headers,
                    .trailer_bytes = body.trailers.bytes,
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
                try self.readMore(self.limits.max_head_bytes);
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
            while (remaining != 0) {
                if (self.buffered().len == 0) {
                    try self.readMore(std.math.maxInt(usize));
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
            var extension_bytes: usize = 0;
            while (true) {
                const size = try self.readChunkSize(
                    &extension_bytes,
                    http1.max_chunk_extension_bytes + 32,
                );
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
                        try self.readMore(std.math.maxInt(usize));
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

            const headers = try parseTrailerBlock(
                self.allocator,
                bytes,
                self.options,
            );
            errdefer self.allocator.free(headers);
            try http1.validateTrailers(headers);
            return .{ .bytes = bytes, .headers = headers };
        }

        fn readChunkSize(
            self: *Self,
            extension_bytes: *usize,
            max_bytes: usize,
        ) RuntimeError!usize {
            while (true) {
                if (std.mem.indexOf(
                    u8,
                    self.buffered(),
                    "\r\n",
                )) |end| {
                    const line = self.buffered()[0..end];
                    const semi = std.mem.indexOfScalar(
                        u8,
                        line,
                        ';',
                    ) orelse line.len;
                    if (semi != line.len) {
                        extension_bytes.* = std.math.add(
                            usize,
                            extension_bytes.*,
                            line.len - semi,
                        ) catch return error.ChunkExtensionTooLarge;
                        if (extension_bytes.* >
                            http1.max_chunk_extension_bytes)
                        {
                            return error.ChunkExtensionTooLarge;
                        }
                    }
                    const size = try http1.parseChunkSize(
                        try chunkSizePart(line[0..semi]),
                    );
                    self.consumePrefix(end + 2);
                    return size;
                }
                if (self.buffered().len >= max_bytes) {
                    return error.ChunkExtensionTooLarge;
                }
                try self.readMore(max_bytes);
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
            self.compact();
            if (self.inbuf.items.len >= max_buffer_bytes) {
                return error.BodyTooLarge;
            }
            var scratch: [16 * 1024]u8 = undefined;
            const count = try self.read_some(
                self.context,
                scratch[0..@min(
                    scratch.len,
                    max_buffer_bytes - self.inbuf.items.len,
                )],
            );
            if (count == 0) return error.ConnectionClosed;
            try self.inbuf.appendSlice(
                self.allocator,
                scratch[0..count],
            );
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

fn chunkSizePart(raw_size: []const u8) ![]const u8 {
    if (raw_size.len == 0) return error.InvalidChunk;
    var end: usize = 0;
    while (end < raw_size.len and
        std.ascii.isHex(raw_size[end])) : (end += 1)
    {}
    if (end == 0) return error.InvalidChunk;
    for (raw_size[end..]) |byte| {
        switch (byte) {
            ' ', '\t' => {},
            else => return error.InvalidChunk,
        }
    }
    return raw_size[0..end];
}

fn parseTrailerBlock(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
) ![]http1.Header {
    const block_end = bytes.len - 4;
    var count: usize = 0;
    var lines = std.mem.splitSequence(
        u8,
        bytes[0..block_end],
        "\r\n",
    );
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            // Streaming metadata intentionally has the same strict ownership
            // model as borrowed heads. obs-fold would require per-value owned
            // allocations and remains rejected here.
            _ = options.allow_obs_fold;
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
    if (count == 0) return @constCast(&[_]http1.Header{});

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
    return headers;
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

fn messageKeepAlive(
    version: http1.Version,
    headers: []const http1.Header,
) bool {
    for (headers) |header| {
        if (!header.eqlName("connection")) continue;
        var values = std.mem.splitScalar(u8, header.value, ',');
        while (values.next()) |raw| {
            const value = std.mem.trim(u8, raw, " \t");
            if (std.ascii.eqlIgnoreCase(value, "close")) return false;
            if (std.ascii.eqlIgnoreCase(value, "keep-alive")) return true;
        }
    }
    return version == .http_1_1;
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

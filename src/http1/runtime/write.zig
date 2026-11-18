const std = @import("std");
const http1 = @import("../mod.zig");
const wire = @import("../../internal/wire.zig");

pub const Error = http1.Error || error{InvalidResponse};

/// Controls only the spelling of emitted HTTP/1 field names. Header lookup and
/// validation remain case-insensitive, and `.preserve` retains today's exact
/// caller-provided bytes.
pub const HeaderNameCasing = enum {
    preserve,
    title_case,
};

pub const RequestOptions = struct {
    method: http1.Method = .GET,
    target: []const u8 = "/",
    version: http1.Version = .http_1_1,
    /// Optional authority used to synthesize Host when the caller did not
    /// provide one explicitly. HTTP/1.1 requires Host on origin-form requests;
    /// keeping it here avoids forcing every caller to construct the field.
    host: ?[]const u8 = null,
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
    header_name_casing: HeaderNameCasing = .preserve,
};

pub const ResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    body: []const u8 = &.{},
    trailers: []const http1.Header = &.{},
    /// True only when the associated HTTP/1.1 request contained a
    /// TE: trailers token. Response trailer fields are rejected otherwise.
    request_accepts_trailers: bool = false,
    header_name_casing: HeaderNameCasing = .preserve,
    /// Optional method of the request this response answers. HEAD and
    /// successful CONNECT have method-specific body framing rules that cannot
    /// be inferred from status and headers alone.
    request_method: ?http1.Method = null,
};

pub const StreamingRequestOptions = struct {
    method: http1.Method = .POST,
    target: []const u8 = "/",
    version: http1.Version = .http_1_1,
    host: ?[]const u8 = null,
    headers: []const http1.Header = &.{},
    /// Exact body size when known. A null size selects chunked framing for
    /// body-capable HTTP/1.1 methods unless Content-Length already fixes it.
    body_length: ?usize = null,
    /// Trailer field names announced in the initial Trailer header. Values are
    /// supplied later to `finishTrailers`; repeated names are announced once.
    trailer_names: []const []const u8 = &.{},
    header_name_casing: HeaderNameCasing = .preserve,
};

pub const StreamingResponseOptions = struct {
    version: http1.Version = .http_1_1,
    status: u16 = 200,
    reason: []const u8 = "OK",
    headers: []const http1.Header = &.{},
    /// Exact body size when known. A null size selects chunked framing for an
    /// ordinary HTTP/1.1 response.
    body_length: ?usize = null,
    trailer_names: []const []const u8 = &.{},
    /// True only when the associated HTTP/1.1 request contained a
    /// TE: trailers token. Announced response trailers are rejected
    /// otherwise.
    request_accepts_trailers: bool = false,
    header_name_casing: HeaderNameCasing = .preserve,
    request_method: ?http1.Method = null,
};

pub const StreamingFraming = union(enum) {
    fixed: usize,
    chunked,
    suppressed,
};

pub const StreamingHead = struct {
    head: []const u8,
    framing: StreamingFraming,
    /// An HTTP/1 writer owns the connection until it finishes. Even after a
    /// syntactically complete body, Connection: close and successful CONNECT
    /// prevent that connection from returning to the reusable state.
    reusable_after_finish: bool,
    /// Optional exact length enforced even when trailers force chunked wire
    /// framing.
    expected_length: ?usize,
    /// Captured from the start options so a later streaming terminator uses
    /// the same field-name policy as its request or response head.
    header_name_casing: HeaderNameCasing,
};

/// Reusable encoder storage owned by a persistent runtime connection.
///
/// Single non-chunked messages keep the application body outside `encoded`,
/// allowing the transport to use vectored I/O. A response batch is different:
/// it must be fully materialized before the first socket write so validation of
/// a later response cannot expose a valid prefix on the wire.
const BatchPart = union(enum) {
    encoded: struct { start: usize, len: usize },
    borrowed: []const u8,
};

const BatchVectors = struct {
    descriptors: []BatchPart,
    parts: [][]const u8,
};

pub const BatchScratch = struct {
    /// Independent contiguous transport staging. This cannot share `encoded`:
    /// prepared message heads may still borrow that storage while a
    /// connection-level flatten policy copies all parts.
    flattened: std.ArrayList(u8) = .empty,
    encoded: std.ArrayList(u8) = .empty,
    vectors: std.ArrayList(usize) = .empty,

    fn reset(self: *BatchScratch) void {
        self.encoded.clearRetainingCapacity();
        self.vectors.clearRetainingCapacity();
    }

    pub fn prepareVectors(
        self: *BatchScratch,
        allocator: std.mem.Allocator,
        part_capacity: usize,
    ) Error!BatchVectors {
        const descriptor_bytes = std.math.mul(
            usize,
            part_capacity,
            @sizeOf(BatchPart),
        ) catch return error.ContentLengthOverflow;
        _ = std.math.add(
            usize,
            descriptor_bytes,
            @alignOf([]const u8) - 1,
        ) catch return error.ContentLengthOverflow;
        const parts_offset = std.mem.alignForward(
            usize,
            descriptor_bytes,
            @alignOf([]const u8),
        );
        const parts_bytes = std.math.mul(
            usize,
            part_capacity,
            @sizeOf([]const u8),
        ) catch return error.ContentLengthOverflow;
        const total_bytes = std.math.add(
            usize,
            parts_offset,
            parts_bytes,
        ) catch return error.ContentLengthOverflow;
        const word_count = std.math.divCeil(
            usize,
            total_bytes,
            @sizeOf(usize),
        ) catch return error.ContentLengthOverflow;
        try self.vectors.resize(allocator, word_count);

        const bytes = std.mem.sliceAsBytes(self.vectors.items);
        const descriptor_storage: []align(@alignOf(BatchPart)) u8 =
            @alignCast(bytes[0..descriptor_bytes]);
        const parts_storage: []align(@alignOf([]const u8)) u8 =
            @alignCast(bytes[parts_offset..][0..parts_bytes]);
        return .{
            .descriptors = std.mem.bytesAsSlice(
                BatchPart,
                descriptor_storage,
            ),
            .parts = std.mem.bytesAsSlice(
                []const u8,
                parts_storage,
            ),
        };
    }

    pub fn deinit(self: *BatchScratch, allocator: std.mem.Allocator) void {
        self.flattened.deinit(allocator);
        self.encoded.deinit(allocator);
        self.vectors.deinit(allocator);
        self.* = undefined;
    }
};

pub const TrailerScratch = struct {
    /// The first word stores the logical header count. Aligned descriptors and
    /// their copied names follow in the same allocation.
    storage: std.ArrayList(usize) = .empty,

    fn reset(self: *TrailerScratch) void {
        self.storage.clearRetainingCapacity();
    }

    pub fn prepare(
        self: *TrailerScratch,
        allocator: std.mem.Allocator,
        initial_headers: []const http1.Header,
        names: []const []const u8,
    ) Error![]const http1.Header {
        self.reset();
        var candidate_count: usize = names.len;
        var name_storage_len: usize = 0;
        for (initial_headers) |header| {
            if (!header.eqlName("trailer")) continue;
            var values = std.mem.splitScalar(u8, header.value, ',');
            while (values.next()) |raw_name| {
                const name = std.mem.trim(u8, raw_name, " \t");
                candidate_count = std.math.add(
                    usize,
                    candidate_count,
                    1,
                ) catch return error.InvalidTrailer;
                name_storage_len = std.math.add(
                    usize,
                    name_storage_len,
                    name.len,
                ) catch return error.InvalidTrailer;
            }
        }
        for (names) |name| {
            name_storage_len = std.math.add(
                usize,
                name_storage_len,
                name.len,
            ) catch return error.InvalidTrailer;
        }

        const headers_offset = std.mem.alignForward(
            usize,
            @sizeOf(usize),
            @alignOf(http1.Header),
        );
        const header_bytes = std.math.mul(
            usize,
            candidate_count,
            @sizeOf(http1.Header),
        ) catch return error.InvalidTrailer;
        const names_offset = std.math.add(
            usize,
            headers_offset,
            header_bytes,
        ) catch return error.InvalidTrailer;
        const total_bytes = std.math.add(
            usize,
            names_offset,
            name_storage_len,
        ) catch return error.InvalidTrailer;
        const word_count = std.math.divCeil(
            usize,
            total_bytes,
            @sizeOf(usize),
        ) catch return error.InvalidTrailer;
        try self.storage.resize(allocator, word_count);
        self.storage.items[0] = 0;

        const bytes = std.mem.sliceAsBytes(self.storage.items);
        const header_storage: []align(@alignOf(http1.Header)) u8 = @alignCast(
            bytes[headers_offset..][0..header_bytes],
        );
        var headers = std.ArrayList(http1.Header).initBuffer(
            std.mem.bytesAsSlice(http1.Header, header_storage),
        );
        var name_storage = std.ArrayList(u8).initBuffer(
            bytes[names_offset..][0..name_storage_len],
        );

        var explicit_trailer_header = false;
        for (initial_headers) |header| {
            if (!header.eqlName("trailer")) continue;
            explicit_trailer_header = true;
            var values = std.mem.splitScalar(u8, header.value, ',');
            while (values.next()) |raw_name| {
                try appendTrailerName(
                    &headers,
                    &name_storage,
                    std.mem.trim(u8, raw_name, " \t"),
                );
            }
        }
        for (names) |name| {
            if (explicit_trailer_header) {
                if (!headerNamePresent(headers.items, name)) {
                    return error.InvalidTrailer;
                }
            } else {
                try appendTrailerName(&headers, &name_storage, name);
            }
        }
        try http1.validateTrailers(headers.items);
        self.storage.items[0] = headers.items.len;
        return headers.items;
    }

    fn headerItems(self: *const TrailerScratch) []const http1.Header {
        if (self.storage.items.len == 0) return &.{};
        const header_count = self.storage.items[0];
        const header_bytes = header_count * @sizeOf(http1.Header);
        const bytes = std.mem.sliceAsBytes(self.storage.items);
        const header_storage: []align(@alignOf(http1.Header)) const u8 =
            @alignCast(bytes[trailer_headers_offset..][0..header_bytes]);
        return std.mem.bytesAsSlice(http1.Header, header_storage);
    }

    pub fn deinit(self: *TrailerScratch, allocator: std.mem.Allocator) void {
        self.storage.deinit(allocator);
        self.* = undefined;
    }
};

const trailer_headers_offset = std.mem.alignForward(
    usize,
    @sizeOf(usize),
    @alignOf(http1.Header),
);

pub const trailer_value_staging_capacity = 256;

pub const TrailerValueScratch = struct {
    stack: [trailer_value_staging_capacity]u8 = undefined,
    heap: ?[]u8 = null,

    pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
        if (self.heap) |bytes| allocator.free(bytes);
        self.* = undefined;
    }
    pub fn render(
        self: *@This(),
        allocator: std.mem.Allocator,
        trailers: []const http1.Header,
    ) Error![]const u8 {
        std.debug.assert(self.heap == null);
        var rendered_len: usize = 0;
        var unique_count: usize = 0;
        for (trailers, 0..) |trailer, index| {
            var duplicate = false;
            for (trailers[0..index]) |prior| {
                if (trailer.eqlName(prior.name)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            if (unique_count != 0) {
                rendered_len = std.math.add(
                    usize,
                    rendered_len,
                    2,
                ) catch return error.InvalidTrailer;
            }
            rendered_len = std.math.add(
                usize,
                rendered_len,
                trailer.name.len,
            ) catch return error.InvalidTrailer;
            unique_count += 1;
        }

        const output = if (rendered_len <= self.stack.len)
            self.stack[0..rendered_len]
        else blk: {
            const heap = try allocator.alloc(u8, rendered_len);
            self.heap = heap;
            break :blk heap;
        };
        var offset: usize = 0;
        for (trailers, 0..) |trailer, index| {
            var duplicate = false;
            for (trailers[0..index]) |prior| {
                if (trailer.eqlName(prior.name)) {
                    duplicate = true;
                    break;
                }
            }
            if (duplicate) continue;
            if (offset != 0) {
                @memcpy(output[offset..][0..2], ", ");
                offset += 2;
            }
            @memcpy(output[offset..][0..trailer.name.len], trailer.name);
            offset += trailer.name.len;
        }
        return output[0..offset];
    }
};

pub const chunk_header_buffer_len = std.fmt.count(
    "{x}\r\n",
    .{std.math.maxInt(usize)},
);

pub const StreamingChunkBuffers = struct {
    descriptors: []u8,
    parts: [][]const u8,
};

pub const StreamingChunkScratch = struct {
    /// Chunk-size text and slice descriptors share one pointer-aligned backing
    /// allocation. The two views are rebuilt after every resize.
    storage: std.ArrayList(usize) = .empty,

    fn reset(self: *StreamingChunkScratch) void {
        self.storage.clearRetainingCapacity();
    }

    pub fn prepare(
        self: *StreamingChunkScratch,
        allocator: std.mem.Allocator,
        chunk_count: usize,
    ) Error!StreamingChunkBuffers {
        const descriptor_bytes = std.math.mul(
            usize,
            chunk_count,
            chunk_header_buffer_len,
        ) catch return error.ContentLengthOverflow;
        _ = std.math.add(
            usize,
            descriptor_bytes,
            @alignOf([]const u8) - 1,
        ) catch return error.ContentLengthOverflow;
        const parts_offset = std.mem.alignForward(
            usize,
            descriptor_bytes,
            @alignOf([]const u8),
        );
        const part_count = std.math.mul(
            usize,
            chunk_count,
            3,
        ) catch return error.ContentLengthOverflow;
        const parts_bytes = std.math.mul(
            usize,
            part_count,
            @sizeOf([]const u8),
        ) catch return error.ContentLengthOverflow;
        const total_bytes = std.math.add(
            usize,
            parts_offset,
            parts_bytes,
        ) catch return error.ContentLengthOverflow;
        const word_count = std.math.divCeil(
            usize,
            total_bytes,
            @sizeOf(usize),
        ) catch return error.ContentLengthOverflow;
        try self.storage.resize(allocator, word_count);

        const bytes = std.mem.sliceAsBytes(self.storage.items);
        const parts_storage: []align(@alignOf([]const u8)) u8 = @alignCast(
            bytes[parts_offset..][0..parts_bytes],
        );
        return .{
            .descriptors = bytes[0..descriptor_bytes],
            .parts = std.mem.bytesAsSlice(
                []const u8,
                parts_storage,
            ),
        };
    }

    pub fn deinit(
        self: *StreamingChunkScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.storage.deinit(allocator);
        self.* = undefined;
    }
};

pub const content_length_buffer_len = std.fmt.count(
    "{d}",
    .{std.math.maxInt(usize)},
);

pub const Scratch = struct {
    encoded: std.ArrayList(u8) = .empty,
    batch: ?*BatchScratch = null,
    trailers: ?*TrailerScratch = null,
    streaming_chunks: ?*StreamingChunkScratch = null,

    fn reset(self: *Scratch) void {
        self.encoded.clearRetainingCapacity();
        if (self.trailers) |trailers| trailers.reset();
        if (self.streaming_chunks) |chunks| chunks.reset();
    }

    pub fn deinit(self: *Scratch, allocator: std.mem.Allocator) void {
        self.encoded.deinit(allocator);
        if (self.batch) |batch| {
            batch.deinit(allocator);
            allocator.destroy(batch);
        }
        if (self.trailers) |trailers| {
            trailers.deinit(allocator);
            allocator.destroy(trailers);
        }
        if (self.streaming_chunks) |chunks| {
            chunks.deinit(allocator);
            allocator.destroy(chunks);
        }
        self.* = undefined;
    }
    pub fn batchScratch(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*BatchScratch {
        if (self.batch) |batch| return batch;
        const batch = try allocator.create(BatchScratch);
        batch.* = .{};
        self.batch = batch;
        return batch;
    }

    pub fn flattenedBuffer(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*std.ArrayList(u8) {
        return &(try self.batchScratch(allocator)).flattened;
    }
    pub fn trailerScratch(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*TrailerScratch {
        if (self.trailers) |trailers| return trailers;
        const trailers = try allocator.create(TrailerScratch);
        trailers.* = .{};
        self.trailers = trailers;
        return trailers;
    }

    pub fn trailerHeaders(self: *const Scratch) []const http1.Header {
        const trailers = self.trailers orelse return &.{};
        return trailers.headerItems();
    }

    pub fn streamingChunkScratch(
        self: *Scratch,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!*StreamingChunkScratch {
        if (self.streaming_chunks) |chunks| return chunks;
        const chunks = try allocator.create(StreamingChunkScratch);
        chunks.* = .{};
        self.streaming_chunks = chunks;
        return chunks;
    }
};

pub const header_staging_capacity = 16;

/// Keep ordinary outgoing header sets entirely on the caller's stack. Larger
/// sets retain full support through one exact temporary allocation.
pub fn stackFirstHeaderBuffer(
    allocator: std.mem.Allocator,
    stack: []http1.Header,
    required: usize,
) std.mem.Allocator.Error![]http1.Header {
    if (required <= stack.len) return stack[0..required];
    return allocator.alloc(http1.Header, required);
}

pub fn freeStackFirstHeaderBuffer(
    allocator: std.mem.Allocator,
    stack: []http1.Header,
    buffer: []http1.Header,
) void {
    if (buffer.ptr != stack.ptr) allocator.free(buffer);
}

pub const MessageParts = struct {
    header: []const u8,
    body: []const u8,
};

/// Validate and encode only a request head for an incremental body writer.
pub fn prepareStreamingRequest(
    allocator: std.mem.Allocator,
    options: StreamingRequestOptions,
    scratch: *Scratch,
) Error!StreamingHead {
    scratch.reset();
    var headers_stack: [header_staging_capacity]http1.Header = undefined;
    const headers_buffer = try stackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        std.math.add(usize, options.headers.len, 4) catch
            return error.OutOfMemory,
    );
    defer freeStackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        headers_buffer,
    );
    var headers = std.ArrayList(http1.Header).initBuffer(headers_buffer);
    try http1.validateRequestTargetForMethod(options.method, options.target);
    if (options.method == .CONNECT) {
        // CONNECT changes the meaning of all subsequent bytes after its
        // response. Keep that lifecycle on the dedicated tunnel API.
        return error.InvalidContentLength;
    }

    const target_authority = http1.absoluteFormAuthority(options.target);
    appendRequestHeadersWithHost(
        &headers,
        options.headers,
        options.host orelse target_authority,
    );
    appendRequiredTeConnectionOption(&headers);
    try http1.validateConnectionHeadersForWrite(
        options.version,
        headers.items,
    );
    try http1.validateRequestTeForWrite(
        options.version,
        headers.items,
    );
    try http1.validateHostHeaderBlock(
        options.version,
        headers.items,
    );
    if (target_authority) |authority| {
        const host = wire.findHeader(
            headers.items,
            "host",
        ) orelse return error.InvalidHost;
        if (!std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, host, " \t"),
            authority,
        )) return error.InvalidHost;
    }

    try http1.validateOutgoingRequestFramingForMethod(
        options.method,
        headers.items,
        options.body_length,
        options.trailer_names.len != 0,
    );

    const trailers_requested = hasHeader(
        headers.items,
        "trailer",
    ) or options.trailer_names.len != 0;
    const trailer_headers: []const http1.Header = if (trailers_requested) blk: {
        const trailers = try scratch.trailerScratch(allocator);
        break :blk try trailers.prepare(
            allocator,
            headers.items,
            options.trailer_names,
        );
    } else &.{};
    const explicit_chunked = try chunkedWriteFraming(
        headers.items,
        trailer_headers,
    );
    if (trailers_requested and !explicit_chunked) {
        return error.InvalidTrailer;
    }
    const declared_length = try http1.contentLength(
        headers.items,
    );
    const use_chunked = explicit_chunked or
        (declared_length == null and options.body_length == null and
            requestUnknownLengthUsesChunked(options.method));
    const fixed_length: usize = if (use_chunked)
        0
    else if (options.body_length) |length|
        length
    else
        declared_length orelse 0;
    if (!use_chunked) {
        if (declared_length) |declared| {
            if (options.body_length) |length| {
                if (declared != length) return error.InvalidContentLength;
            }
        }
    }
    const expected_length = if (use_chunked)
        options.body_length
    else
        fixed_length;
    try http1.validateRequestExpectForWrite(
        options.version,
        headers.items,
        if (use_chunked)
            options.body_length == null or options.body_length.? != 0
        else
            fixed_length != 0,
    );

    var content_length: [content_length_buffer_len]u8 = undefined;
    var trailer_value: TrailerValueScratch = .{};
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeadersInPlace(
        &headers,
        allocator,
        fixed_length,
        trailer_headers,
        use_chunked,
        shouldDefaultRequestContentLength(
            options.method,
            fixed_length,
            trailer_headers,
        ),
        &content_length,
        &trailer_value,
        null,
    );
    try encodeRequestHead(allocator, options, headers.items, scratch);
    return .{
        .head = scratch.encoded.items,
        .framing = if (use_chunked)
            .chunked
        else
            .{ .fixed = fixed_length },
        .reusable_after_finish = http1.headersKeepAlive(
            options.version,
            headers.items,
        ),
        .expected_length = expected_length,
        .header_name_casing = options.header_name_casing,
    };
}

/// Validate and encode only a response head for an incremental body writer.
pub fn prepareStreamingResponse(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    scratch: *Scratch,
) Error!StreamingHead {
    return prepareStreamingResponseWithDefaultDate(
        allocator,
        options,
        null,
        scratch,
    );
}

fn prepareStreamingResponseWithDefaultDate(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!StreamingHead {
    scratch.reset();
    var headers_stack: [header_staging_capacity]http1.Header = undefined;
    const headers_buffer = try stackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        std.math.add(usize, options.headers.len, 3) catch
            return error.OutOfMemory,
    );
    defer freeStackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        headers_buffer,
    );
    var headers = std.ArrayList(http1.Header).initBuffer(headers_buffer);
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try http1.validateConnectionHeadersForWrite(
        options.version,
        options.headers,
    );
    try http1.validateResponseTeForWrite(options.headers);
    try http1.validateResponseUpgradeForWrite(
        options.status,
        options.headers,
    );
    const trailers_requested = hasHeader(options.headers, "trailer") or
        options.trailer_names.len != 0;
    const trailer_headers: []const http1.Header = if (trailers_requested) blk: {
        const trailers = try scratch.trailerScratch(allocator);
        break :blk try trailers.prepare(
            allocator,
            options.headers,
            options.trailer_names,
        );
    } else &.{};
    try http1.validateOutgoingResponseBodyForStatus(
        options.status,
        options.headers,
        &.{},
        trailer_headers,
    );

    const suppress_body = responseWriteSuppressesBody(
        options.status,
        options.request_method,
    );
    const explicit_chunked = try chunkedWriteFraming(
        options.headers,
        trailer_headers,
    );
    if (trailers_requested and !options.request_accepts_trailers) {
        return error.InvalidTrailer;
    }
    if (trailers_requested and !explicit_chunked) {
        return error.InvalidTrailer;
    }
    const head_response = if (options.request_method) |method|
        method == .HEAD
    else
        false;
    const metadata_only_transfer_encoding =
        (head_response or options.status == 304) and explicit_chunked;
    if (suppress_body and explicit_chunked and
        !metadata_only_transfer_encoding)
    {
        return error.InvalidTransferEncoding;
    }
    if (head_response and trailers_requested) return error.InvalidTrailer;
    const declared_length = try http1.contentLength(options.headers);
    const content_forbidden = options.status == 205;
    if (content_forbidden and (options.body_length orelse 0) != 0) {
        return error.InvalidContentLength;
    }
    if (content_forbidden and (declared_length orelse 0) != 0) {
        return error.InvalidContentLength;
    }
    const use_chunked = !suppress_body and
        (explicit_chunked or
            (declared_length == null and options.body_length == null and
                !content_forbidden));
    // A HEAD response may describe the transfer coding a corresponding GET
    // would use, but no chunk terminator follows the head. Preserve an
    // explicitly supplied coding while still returning suppressed framing.
    const header_uses_chunked = use_chunked or
        metadata_only_transfer_encoding;
    if (options.request_method != null and
        options.request_method.? == .CONNECT and
        options.status >= 200 and options.status < 300)
    {
        if (declared_length != null) return error.InvalidContentLength;
        if ((options.body_length orelse 0) != 0) {
            return error.InvalidContentLength;
        }
    }
    if (!use_chunked and !suppress_body) {
        if (declared_length) |declared| {
            if (options.body_length) |length| {
                if (declared != length) return error.InvalidContentLength;
            }
        }
    }
    if (suppress_body and
        options.request_method != null and
        options.request_method.? == .HEAD)
    {
        if (declared_length) |declared| {
            if (options.body_length) |length| {
                if (declared != length) return error.InvalidContentLength;
            }
        }
    } else if (suppress_body and
        http1.statusCodeForbidsBody(options.status) and
        (options.body_length orelse 0) != 0)
    {
        return error.InvalidContentLength;
    }

    const fixed_length: usize = if (use_chunked or suppress_body)
        0
    else
        options.body_length orelse declared_length orelse 0;
    var content_length: [content_length_buffer_len]u8 = undefined;
    var trailer_value: TrailerValueScratch = .{};
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeaders(
        &headers,
        allocator,
        options.headers,
        if (suppress_body)
            options.body_length orelse 0
        else
            fixed_length,
        trailer_headers,
        header_uses_chunked,
        responseShouldDefaultContentLength(
            options.status,
            options.request_method,
        ),
        &content_length,
        &trailer_value,
        if (responseStatusIsFinal(options.status)) default_date else null,
    );
    try encodeStreamingResponseHead(
        allocator,
        options,
        headers.items,
        scratch,
    );

    const successful_connect = options.request_method != null and
        options.request_method.? == .CONNECT and
        options.status >= 200 and options.status < 300;
    return .{
        .head = scratch.encoded.items,
        .framing = if (suppress_body)
            .suppressed
        else if (use_chunked)
            .chunked
        else
            .{ .fixed = fixed_length },
        .reusable_after_finish = !successful_connect and
            http1.headersKeepAlive(options.version, options.headers),
        .expected_length = if (suppress_body or content_forbidden)
            0
        else if (use_chunked)
            options.body_length
        else
            fixed_length,
        .header_name_casing = options.header_name_casing,
    };
}

/// Validate and encode a request, borrowing an unframed body when possible.
pub fn prepareRequest(
    allocator: std.mem.Allocator,
    options: RequestOptions,
    scratch: *Scratch,
) Error!MessageParts {
    scratch.reset();
    var headers_stack: [header_staging_capacity]http1.Header = undefined;
    const headers_buffer = try stackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        std.math.add(usize, options.headers.len, 4) catch
            return error.OutOfMemory,
    );
    defer freeStackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        headers_buffer,
    );
    var headers = std.ArrayList(http1.Header).initBuffer(headers_buffer);
    try http1.validateRequestTargetForMethod(options.method, options.target);
    const target_authority = if (options.method == .CONNECT)
        options.target
    else
        http1.absoluteFormAuthority(options.target);
    const synthesized_host = options.host orelse target_authority;
    appendRequestHeadersWithHost(
        &headers,
        options.headers,
        synthesized_host,
    );
    appendRequiredTeConnectionOption(&headers);
    try http1.validateConnectionHeadersForWrite(
        options.version,
        headers.items,
    );
    try http1.validateRequestTeForWrite(
        options.version,
        headers.items,
    );
    try http1.validateHostHeaderBlock(
        options.version,
        headers.items,
    );
    if (target_authority) |authority| {
        const host = wire.findHeader(
            headers.items,
            "host",
        ) orelse return error.InvalidHost;
        if (!std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, host, " \t"),
            authority,
        )) {
            return error.InvalidHost;
        }
    }
    try http1.validateOutgoingRequestBodyForMethod(
        options.method,
        headers.items,
        options.body,
        options.trailers,
    );
    try http1.validateTrailerDeclarations(
        headers.items,
        options.trailers,
    );
    const use_chunked = try chunkedWriteFraming(
        headers.items,
        options.trailers,
    );
    try validateDeclaredRequestBodyLength(
        headers.items,
        options.body.len,
        use_chunked,
    );
    try http1.validateRequestExpectForWrite(
        options.version,
        headers.items,
        options.body.len != 0,
    );

    var content_length: [content_length_buffer_len]u8 = undefined;
    var trailer_value: TrailerValueScratch = .{};
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeadersInPlace(
        &headers,
        allocator,
        options.body.len,
        options.trailers,
        use_chunked,
        shouldDefaultRequestContentLength(
            options.method,
            options.body.len,
            options.trailers,
        ),
        &content_length,
        &trailer_value,
        null,
    );

    try encodeRequestHead(allocator, options, headers.items, scratch);
    if (use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunked(
            &scratch.encoded,
            allocator,
            &chunks,
            options.trailers,
            options.header_name_casing,
        );
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    return .{ .header = scratch.encoded.items, .body = options.body };
}

/// Validate and encode a response, borrowing an unframed body when possible.
pub fn prepareResponse(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    scratch: *Scratch,
) Error!MessageParts {
    return prepareResponseWithDefaultDate(
        allocator,
        options,
        null,
        scratch,
    );
}

/// Runtime-only response preparation with an optional generated Date value.
/// The pure codec entry point above intentionally remains deterministic.
pub fn prepareServerResponse(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!MessageParts {
    return prepareResponseWithDefaultDate(
        allocator,
        options,
        if (responseStatusIsFinal(options.status)) default_date else null,
        scratch,
    );
}

fn prepareResponseWithDefaultDate(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!MessageParts {
    scratch.reset();
    const framing = try prepareResponseFramingAndHead(
        allocator,
        options,
        default_date,
        scratch,
    );

    if (framing.suppress_body) {
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    if (framing.use_chunked) {
        const chunks = [_][]const u8{options.body};
        try encodeChunked(
            &scratch.encoded,
            allocator,
            &chunks,
            options.trailers,
            options.header_name_casing,
        );
        return .{ .header = scratch.encoded.items, .body = &.{} };
    }
    return .{ .header = scratch.encoded.items, .body = options.body };
}

/// Validate a complete response pipeline and prepare borrowed write slices.
///
/// Heads and chunked messages are retained in `batch.encoded`; ordinary
/// fixed bodies remain borrowed. Descriptors use offsets while encoded storage
/// grows, then resolve to stable slices only after every response validates.
pub fn prepareResponseParts(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    scratch: *Scratch,
) Error![]const []const u8 {
    return prepareResponsePartsWithDefaultDate(
        allocator,
        responses,
        null,
        scratch,
    );
}

/// Runtime-only batch preparation with one cached Date value shared by every
/// final response that does not already provide the field.
pub fn prepareServerResponseParts(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error![]const []const u8 {
    // `default_date` may borrow a thread-local cache. Every encoded head is
    // copied into Scratch before this function returns, so callers can refresh
    // that cache immediately after the synchronous preparation completes.
    return prepareResponsePartsWithDefaultDate(
        allocator,
        responses,
        default_date,
        scratch,
    );
}

fn prepareResponsePartsWithDefaultDate(
    allocator: std.mem.Allocator,
    responses: []const ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error![]const []const u8 {
    const batch = try scratch.batchScratch(allocator);
    batch.reset();
    const part_capacity = std.math.mul(
        usize,
        responses.len,
        2,
    ) catch return error.ContentLengthOverflow;
    const buffers = try batch.prepareVectors(
        allocator,
        part_capacity,
    );
    var part_descriptors = std.ArrayList(BatchPart).initBuffer(
        buffers.descriptors,
    );
    var parts = std.ArrayList([]const u8).initBuffer(buffers.parts);
    for (responses) |response| {
        scratch.encoded.clearRetainingCapacity();

        const framing = try prepareResponseFramingAndHead(
            allocator,
            response,
            if (responseStatusIsFinal(response.status))
                default_date
            else
                null,
            scratch,
        );
        const head_start = batch.encoded.items.len;
        try batch.encoded.appendSlice(
            allocator,
            scratch.encoded.items,
        );
        part_descriptors.appendAssumeCapacity(.{
            .encoded = .{
                .start = head_start,
                .len = scratch.encoded.items.len,
            },
        });
        if (!framing.suppress_body) {
            if (framing.use_chunked) {
                scratch.encoded.clearRetainingCapacity();
                const chunks = [_][]const u8{response.body};
                try encodeChunked(
                    &scratch.encoded,
                    allocator,
                    &chunks,
                    response.trailers,
                    response.header_name_casing,
                );
                const chunk_start = batch.encoded.items.len;
                try batch.encoded.appendSlice(
                    allocator,
                    scratch.encoded.items,
                );
                part_descriptors.appendAssumeCapacity(.{
                    .encoded = .{
                        .start = chunk_start,
                        .len = scratch.encoded.items.len,
                    },
                });
            } else {
                part_descriptors.appendAssumeCapacity(.{
                    .borrowed = response.body,
                });
            }
        }
    }
    for (part_descriptors.items) |descriptor| {
        parts.appendAssumeCapacity(switch (descriptor) {
            .encoded => |range| batch.encoded.items[range.start .. range.start + range.len],
            .borrowed => |body| body,
        });
    }
    return parts.items;
}

const ResponseFraming = struct {
    use_chunked: bool,
    suppress_body: bool,
};

fn prepareResponseFramingAndHead(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    default_date: ?[]const u8,
    scratch: *Scratch,
) Error!ResponseFraming {
    try http1.validateStatusCode(options.status);
    try http1.validateReasonPhrase(options.reason);
    try http1.validateConnectionHeadersForWrite(
        options.version,
        options.headers,
    );
    try http1.validateResponseTeForWrite(options.headers);
    try http1.validateResponseExpectForWrite(options.headers);
    try http1.validateResponseUpgradeForWrite(
        options.status,
        options.headers,
    );
    try http1.validateOutgoingResponseBodyForStatus(
        options.status,
        options.headers,
        options.body,
        options.trailers,
    );
    try http1.validateTrailerDeclarations(
        options.headers,
        options.trailers,
    );
    if ((options.trailers.len != 0 or
        hasHeader(options.headers, "trailer")) and
        !options.request_accepts_trailers)
    {
        return error.InvalidTrailer;
    }
    const use_chunked = try chunkedWriteFraming(
        options.headers,
        options.trailers,
    );
    try validateDeclaredResponseBodyLength(
        options.status,
        options.request_method,
        options.headers,
        options.body.len,
        options.trailers.len,
        use_chunked,
    );
    const suppress_body = responseWriteSuppressesBody(
        options.status,
        options.request_method,
    );
    var headers_stack: [header_staging_capacity]http1.Header = undefined;
    const headers_buffer = try stackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        std.math.add(usize, options.headers.len, 3) catch
            return error.OutOfMemory,
    );
    defer freeStackFirstHeaderBuffer(
        allocator,
        &headers_stack,
        headers_buffer,
    );
    var headers = std.ArrayList(http1.Header).initBuffer(headers_buffer);
    var content_length: [content_length_buffer_len]u8 = undefined;
    var trailer_value: TrailerValueScratch = .{};
    defer trailer_value.deinit(allocator);
    try appendDefaultedHeaders(
        &headers,
        allocator,
        options.headers,
        options.body.len,
        options.trailers,
        use_chunked,
        responseShouldDefaultContentLength(
            options.status,
            options.request_method,
        ),
        &content_length,
        &trailer_value,
        default_date,
    );
    try encodeResponseHead(allocator, options, headers.items, scratch);
    return .{
        .use_chunked = use_chunked,
        .suppress_body = suppress_body,
    };
}

fn encodeResponseHead(
    allocator: std.mem.Allocator,
    options: ResponseOptions,
    headers: []const http1.Header,
    scratch: *Scratch,
) Error!void {
    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.append(allocator, ' ');
    try appendDecimal(encoded, allocator, options.status);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.reason);
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(
        encoded,
        allocator,
        headers,
        options.header_name_casing,
    );
    try encoded.appendSlice(allocator, "\r\n");
}

fn encodeRequestHead(
    allocator: std.mem.Allocator,
    options: anytype,
    headers: []const http1.Header,
    scratch: *Scratch,
) Error!void {
    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.method.string());
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.target);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(
        encoded,
        allocator,
        headers,
        options.header_name_casing,
    );
    try encoded.appendSlice(allocator, "\r\n");
}

fn encodeStreamingResponseHead(
    allocator: std.mem.Allocator,
    options: StreamingResponseOptions,
    headers: []const http1.Header,
    scratch: *Scratch,
) Error!void {
    const encoded = &scratch.encoded;
    try encoded.appendSlice(allocator, options.version.string());
    try encoded.append(allocator, ' ');
    try appendDecimal(encoded, allocator, options.status);
    try encoded.append(allocator, ' ');
    try encoded.appendSlice(allocator, options.reason);
    try encoded.appendSlice(allocator, "\r\n");
    try writeHeaderLines(
        encoded,
        allocator,
        headers,
        options.header_name_casing,
    );
    try encoded.appendSlice(allocator, "\r\n");
}

fn appendRequestHeadersWithHost(
    list: *std.ArrayList(http1.Header),
    headers: []const http1.Header,
    host: ?[]const u8,
) void {
    var has_host = false;
    for (headers) |header| {
        if (header.eqlName("host")) has_host = true;
        list.appendAssumeCapacity(header);
    }
    if (!has_host) {
        if (host) |value| {
            list.appendAssumeCapacity(.{ .name = "Host", .value = value });
        }
    }
}

fn appendRequiredTeConnectionOption(
    headers: *std.ArrayList(http1.Header),
) void {
    if (!hasHeader(headers.items, "te") or
        wire.anyHeaderContainsToken(headers.items, "connection", "te"))
    {
        return;
    }
    headers.appendAssumeCapacity(.{ .name = "Connection", .value = "TE" });
}

fn appendTrailerName(
    headers: *std.ArrayList(http1.Header),
    storage: *std.ArrayList(u8),
    name: []const u8,
) Error!void {
    try http1.validateHeaderName(name);
    if (headerNamePresent(headers.items, name)) return;
    const start = storage.items.len;
    storage.appendSliceAssumeCapacity(name);
    headers.appendAssumeCapacity(.{
        .name = storage.items[start..],
        .value = "",
    });
}

fn headerNamePresent(
    headers: []const http1.Header,
    name: []const u8,
) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

fn hasHeader(headers: []const http1.Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

const DefaultedHeaderPresence = struct {
    content_length: bool = false,
    transfer_encoding: bool = false,
    trailer: bool = false,
    date: bool = false,

    fn observe(self: *@This(), header: http1.Header) void {
        if (header.eqlName("content-length")) self.content_length = true;
        if (header.eqlName("transfer-encoding")) {
            self.transfer_encoding = true;
        }
        if (header.eqlName("trailer")) self.trailer = true;
        if (header.eqlName("date")) self.date = true;
    }
};

fn appendMissingDefaultedHeadersAssumeCapacity(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    body_len: usize,
    trailers: []const http1.Header,
    use_chunked: bool,
    add_default_content_length: bool,
    len_buf: *[content_length_buffer_len]u8,
    trailer_value: *TrailerValueScratch,
    default_date: ?[]const u8,
    presence: DefaultedHeaderPresence,
) Error!void {
    if (use_chunked) {
        if (!presence.transfer_encoding) {
            list.appendAssumeCapacity(.{
                .name = "Transfer-Encoding",
                .value = "chunked",
            });
        }
        if (trailers.len != 0 and !presence.trailer) {
            list.appendAssumeCapacity(.{
                .name = "Trailer",
                .value = try trailer_value.render(allocator, trailers),
            });
        }
    } else if (add_default_content_length and !presence.content_length) {
        const rendered = std.fmt.bufPrint(
            len_buf,
            "{}",
            .{body_len},
        ) catch unreachable;
        list.appendAssumeCapacity(.{
            .name = "Content-Length",
            .value = rendered,
        });
    }
    if (default_date) |value| {
        if (!presence.date) {
            list.appendAssumeCapacity(.{ .name = "Date", .value = value });
        }
    }
}

fn appendDefaultedHeaders(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    body_len: usize,
    trailers: []const http1.Header,
    use_chunked: bool,
    add_default_content_length: bool,
    len_buf: *[content_length_buffer_len]u8,
    trailer_value: *TrailerValueScratch,
    default_date: ?[]const u8,
) Error!void {
    if (!use_chunked and trailers.len != 0) return error.InvalidTrailer;
    var presence: DefaultedHeaderPresence = .{};
    for (headers) |header| {
        presence.observe(header);
        if (use_chunked and header.eqlName("content-length")) continue;
        list.appendAssumeCapacity(header);
    }
    return appendMissingDefaultedHeadersAssumeCapacity(
        list,
        allocator,
        body_len,
        trailers,
        use_chunked,
        add_default_content_length,
        len_buf,
        trailer_value,
        default_date,
        presence,
    );
}

fn appendDefaultedHeadersInPlace(
    list: *std.ArrayList(http1.Header),
    allocator: std.mem.Allocator,
    body_len: usize,
    trailers: []const http1.Header,
    use_chunked: bool,
    add_default_content_length: bool,
    len_buf: *[content_length_buffer_len]u8,
    trailer_value: *TrailerValueScratch,
    default_date: ?[]const u8,
) Error!void {
    // Request validation has finished, so the normalized descriptor list can
    // become the final output list without retaining and copying a second one.
    if (!use_chunked and trailers.len != 0) return error.InvalidTrailer;
    var presence: DefaultedHeaderPresence = .{};
    var retained: usize = 0;
    for (list.items) |header| {
        presence.observe(header);
        if (use_chunked and header.eqlName("content-length")) continue;
        list.items[retained] = header;
        retained += 1;
    }
    list.items.len = retained;
    return appendMissingDefaultedHeadersAssumeCapacity(
        list,
        allocator,
        body_len,
        trailers,
        use_chunked,
        add_default_content_length,
        len_buf,
        trailer_value,
        default_date,
        presence,
    );
}

fn responseStatusIsFinal(status: u16) bool {
    return status == 101 or status >= 200;
}

fn shouldDefaultRequestContentLength(
    method: http1.Method,
    body_len: usize,
    trailers: []const http1.Header,
) bool {
    if (body_len != 0 or trailers.len != 0) return true;
    return switch (method) {
        .GET, .HEAD, .CONNECT => false,
        else => true,
    };
}

fn requestUnknownLengthUsesChunked(method: http1.Method) bool {
    return switch (method) {
        // Match Hyper's conservative default: these methods usually carry no
        // entity, but callers can still opt in with body_length or an explicit
        // Transfer-Encoding header.
        .GET, .HEAD, .CONNECT, .TRACE => false,
        else => true,
    };
}

fn validateDeclaredRequestBodyLength(
    headers: []const http1.Header,
    body_len: usize,
    use_chunked: bool,
) Error!void {
    if (use_chunked) return;
    if (try http1.contentLength(headers)) |len| {
        // Sending a different length would desynchronize the peer and corrupt
        // the next message on a persistent connection.
        if (len != body_len) return error.InvalidContentLength;
    }
}

fn validateDeclaredResponseBodyLength(
    status: u16,
    request_method: ?http1.Method,
    headers: []const http1.Header,
    body_len: usize,
    trailers_len: usize,
    use_chunked: bool,
) Error!void {
    if (request_method) |method| {
        if (method == .CONNECT and status >= 200 and status < 300) {
            if (use_chunked) return error.InvalidTransferEncoding;
            // A successful CONNECT switches to tunnel bytes immediately after
            // the head, so even Content-Length: 0 is ambiguous to middleware.
            if (body_len != 0 or
                (try http1.contentLength(headers)) != null)
            {
                return error.InvalidContentLength;
            }
            return;
        }
        if (method == .HEAD) {
            if (trailers_len != 0) return error.InvalidTrailer;
            if (try http1.contentLength(headers)) |len| {
                if (body_len != 0 and len != body_len) {
                    return error.InvalidContentLength;
                }
            }
            return;
        }
    }
    if (use_chunked or status == 304) return;
    if (try http1.contentLength(headers)) |len| {
        if (len != body_len) return error.InvalidContentLength;
    }
}

fn responseWriteSuppressesBody(
    status: u16,
    request_method: ?http1.Method,
) bool {
    if (http1.statusCodeForbidsBody(status)) return true;
    if (request_method) |method| {
        if (method == .HEAD) return true;
        if (method == .CONNECT and status >= 200 and status < 300) {
            return true;
        }
    }
    return false;
}

fn responseShouldDefaultContentLength(
    status: u16,
    request_method: ?http1.Method,
) bool {
    if (http1.statusCodeForbidsBody(status)) return false;
    if (request_method) |method| {
        // The bytes after a successful CONNECT head are tunnel data, not an
        // HTTP body. Avoid synthesizing framing that intermediaries may reject.
        if (method == .CONNECT and status >= 200 and status < 300) {
            return false;
        }
    }
    return true;
}

fn chunkedWriteFraming(
    headers: []const http1.Header,
    trailers: []const http1.Header,
) Error!bool {
    var has_transfer_encoding = false;
    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) {
            has_transfer_encoding = true;
            break;
        }
    }
    if (has_transfer_encoding) {
        // This runtime only knows how to emit chunked transfer coding. Never
        // put a raw body under a caller-provided unsupported coding.
        if ((try http1.bodyFraming(headers)) != .chunked) {
            return error.InvalidTransferEncoding;
        }
        return true;
    }
    if (trailers.len == 0 and !hasHeader(headers, "trailer")) return false;
    return true;
}

fn appendDecimal(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    value: anytype,
) Error!void {
    var tmp: [32]u8 = undefined;
    const rendered = std.fmt.bufPrint(
        &tmp,
        "{}",
        .{value},
    ) catch return error.InvalidResponse;
    try list.appendSlice(allocator, rendered);
}

fn appendHeaderNameAssumeCapacity(
    list: *std.ArrayList(u8),
    name: []const u8,
    casing: HeaderNameCasing,
) void {
    switch (casing) {
        .preserve => list.appendSliceAssumeCapacity(name),
        .title_case => {
            var capitalize = true;
            for (name) |byte| {
                list.appendAssumeCapacity(if (capitalize)
                    std.ascii.toUpper(byte)
                else
                    std.ascii.toLower(byte));
                capitalize = byte == '-';
            }
        },
    }
}

fn writeHeaderLines(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    headers: []const http1.Header,
    casing: HeaderNameCasing,
) Error!void {
    var rendered_len: usize = 0;
    for (headers) |header| {
        try http1.validateHeader(header);
        rendered_len = std.math.add(
            usize,
            rendered_len,
            header.name.len,
        ) catch return error.InvalidResponse;
        rendered_len = std.math.add(
            usize,
            rendered_len,
            2,
        ) catch return error.InvalidResponse;
        rendered_len = std.math.add(
            usize,
            rendered_len,
            header.value.len,
        ) catch return error.InvalidResponse;
        rendered_len = std.math.add(
            usize,
            rendered_len,
            2,
        ) catch return error.InvalidResponse;
    }
    try list.ensureUnusedCapacity(allocator, rendered_len);
    for (headers) |header| {
        appendHeaderNameAssumeCapacity(list, header.name, casing);
        list.appendSliceAssumeCapacity(": ");
        list.appendSliceAssumeCapacity(header.value);
        list.appendSliceAssumeCapacity("\r\n");
    }
}

fn encodeChunked(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    chunks: []const []const u8,
    trailers: []const http1.Header,
    casing: HeaderNameCasing,
) Error!void {
    try http1.validateTrailers(trailers);
    for (chunks) |chunk| {
        // A zero-length chunk is the terminator. Empty payload slices therefore
        // emit no DATA, leaving one terminator after all chunks and trailers.
        if (chunk.len == 0) continue;
        var tmp: [chunk_header_buffer_len]u8 = undefined;
        const rendered = std.fmt.bufPrint(
            &tmp,
            "{x}\r\n",
            .{chunk.len},
        ) catch return error.InvalidResponse;
        try list.appendSlice(allocator, rendered);
        try list.appendSlice(allocator, chunk);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "0\r\n");
    try writeHeaderLines(list, allocator, trailers, casing);
    try list.appendSlice(allocator, "\r\n");
}

/// Runtime-facing namespace for the stateful body writer.
///
/// Keeping the head/framing helpers behind this narrow surface prevents the
/// complete-message encoder's scratch details from becoming public API.
pub const streaming = struct {
    pub const RequestOptions = StreamingRequestOptions;
    pub const ResponseOptions = StreamingResponseOptions;
    pub const Framing = StreamingFraming;
    pub const Head = StreamingHead;

    pub fn prepareRequest(
        allocator: std.mem.Allocator,
        options: StreamingRequestOptions,
        scratch: *Scratch,
    ) Error!Head {
        return prepareStreamingRequest(allocator, options, scratch);
    }

    pub fn prepareResponse(
        allocator: std.mem.Allocator,
        options: StreamingResponseOptions,
        scratch: *Scratch,
    ) Error!Head {
        return prepareStreamingResponse(allocator, options, scratch);
    }

    /// Runtime-only streaming response preparation with an optional generated
    /// Date value. The Date slice is consumed while encoding the returned head.
    pub fn prepareServerResponse(
        allocator: std.mem.Allocator,
        options: StreamingResponseOptions,
        default_date: ?[]const u8,
        scratch: *Scratch,
    ) Error!Head {
        // The returned head owns the rendered field bytes in Scratch rather
        // than borrowing `default_date`.
        return prepareStreamingResponseWithDefaultDate(
            allocator,
            options,
            default_date,
            scratch,
        );
    }

    /// Encode the unique terminating chunk and ordered trailer field lines.
    ///
    /// This runs before any transport write, so malformed trailers and
    /// allocation failures cannot expose a partial terminator on the wire.
    pub fn prepareEnd(
        allocator: std.mem.Allocator,
        trailers: []const http1.Header,
        scratch: *Scratch,
    ) Error![]const u8 {
        return prepareEndWithCasing(
            allocator,
            trailers,
            scratch,
            .preserve,
        );
    }

    pub fn prepareEndWithCasing(
        allocator: std.mem.Allocator,
        trailers: []const http1.Header,
        scratch: *Scratch,
        casing: HeaderNameCasing,
    ) Error![]const u8 {
        scratch.encoded.clearRetainingCapacity();
        try http1.validateTrailers(trailers);
        try scratch.encoded.appendSlice(allocator, "0\r\n");
        try writeHeaderLines(
            &scratch.encoded,
            allocator,
            trailers,
            casing,
        );
        try scratch.encoded.appendSlice(allocator, "\r\n");
        return scratch.encoded.items;
    }
};

test {
    _ = @import("write/tests.zig");
}

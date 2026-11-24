//! HTTP/2 request, response, and batch message types.

const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");

const Error = runtime.Error;
const Connection = runtime.Connection;
const freeHeaders = runtime.freeHeaders;
const content_coding = @import("../../http/content_coding.zig");
const content_digest = @import("../../http/digest.zig");

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    path: []const u8 = "/",
    /// Optional request URI scheme for the `:scheme` pseudo-header.  When
    /// omitted, the runtime uses the connection's transport-derived default
    /// (`http` for the h2c helpers in this module, `https` for generic callers).
    scheme: ?[]const u8 = null,
    /// RFC 8441 extended CONNECT `:protocol` pseudo-header.  Sending it
    /// requires the peer to advertise SETTINGS_ENABLE_CONNECT_PROTOCOL = 1.
    protocol: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    /// Optional RFC 9218 end-to-end Priority request field. The runtime emits
    /// it as a normal lowercase header; callers can later reprioritize the
    /// response with `sendPriorityUpdate`.
    priority: ?http2.ExtensiblePriority = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
};

pub const StreamingRequestOptions = struct {
    method: []const u8 = "POST",
    path: []const u8 = "/",
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    priority: ?http2.ExtensiblePriority = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    /// Exact request body size. When null, the request is length-unbounded and
    /// ends only through RequestWriter FIN or trailers.
    body_length: ?usize = null,
};

pub const ResponseOptions = struct {
    status: u16 = 200,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
    /// Optional request method for method-specific response semantics.  HEAD
    /// and successful traditional CONNECT responses do not carry HTTP response
    /// bodies even when representation headers such as Content-Length are
    /// present; server helpers fill this automatically when they own the
    /// request/response loop.
    request_method: ?[]const u8 = null,
    extended_connect: bool = false,
};

pub const StreamingResponseOptions = struct {
    status: u16 = 200,
    headers: []const http2.Hpack.HeaderField = &.{},
    /// Optional request method when the response is not started directly from
    /// a request reader. It controls HEAD and CONNECT body semantics.
    request_method: ?[]const u8 = null,
    extended_connect: bool = false,
};

pub const StreamResponseSemantics = struct {
    stream_id: u31,
    head: bool = false,
    traditional_connect: bool = false,
    extended_connect: bool = false,
    priority: http2.ExtensiblePriority = .{},
};

pub fn uriTargetAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const path_value = uriComponentBytes(uri.path);
    const path = if (path_value.len == 0) "/" else path_value;
    if (uri.query) |query| {
        return try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, uriComponentBytes(query) });
    }
    return try allocator.dupe(u8, path);
}

fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

pub const OwnedRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8 = null,
    body: []u8,
    trailers: []http2.Hpack.HeaderField = &.{},
    priority: http2.ExtensiblePriority = .{},
    /// Peer socket address captured for server-accepted TCP requests. Null
    /// when the caller did not construct this from an accepted connection.
    from: ?std.Io.net.IpAddress = null,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        allocator.free(self.body);
        self.* = undefined;
    }

    pub fn contentEncoding(
        self: OwnedRequest,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    /// Decode Content-Encoding layers without mutating HPACK-owned metadata or
    /// the encoded request body.
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

pub const PendingRequest = union(enum) {
    ready: OwnedRequest,
    reset: u31,

    pub fn streamId(self: PendingRequest) u31 {
        return switch (self) {
            .ready => |request| request.stream_id,
            .reset => |stream_id| stream_id,
        };
    }

    pub fn deinit(self: *PendingRequest, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .ready => |*request| request.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

pub const StreamingRequest = struct {
    stream_id: u31,
    headers: []http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8 = null,
    body_bytes: usize,
    trailers: []http2.Hpack.HeaderField = &.{},
    priority: http2.ExtensiblePriority = .{},
    /// Socket address recorded for this request's transport. Accepted server
    /// connections record the remote peer; client-created connections record
    /// the local endpoint.
    from: ?std.Io.net.IpAddress = null,

    pub fn deinit(
        self: *StreamingRequest,
        allocator: std.mem.Allocator,
    ) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        self.* = undefined;
    }
};

/// Validated request metadata delivered before streaming DATA.
pub const StreamingRequestHead = struct {
    stream_id: u31,
    headers: []const http2.Hpack.HeaderField,
    method: []const u8,
    path: []const u8,
    scheme: []const u8,
    authority: ?[]const u8,
    protocol: ?[]const u8 = null,
    /// Socket address recorded for this request's transport. Accepted server
    /// connections record the remote peer; client-created connections record
    /// the local endpoint.
    from: ?std.Io.net.IpAddress = null,

    pub fn streamContentDecoder(
        self: StreamingRequestHead,
        allocator: std.mem.Allocator,
        options: content_coding.StreamOptions,
    ) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.parseHeaders(self.headers)).streamDecoder(
            allocator,
            options,
        );
    }

    pub fn fromOwned(request: OwnedRequest) StreamingRequestHead {
        return .{
            .stream_id = request.stream_id,
            .headers = request.headers,
            .method = request.method,
            .path = request.path,
            .scheme = request.scheme,
            .authority = request.authority,
            .protocol = request.protocol,
            .from = request.from,
        };
    }
};

pub fn streamingRequestFromOwned(request: OwnedRequest) StreamingRequest {
    return .{
        .stream_id = request.stream_id,
        .headers = request.headers,
        .method = request.method,
        .path = request.path,
        .scheme = request.scheme,
        .authority = request.authority,
        .protocol = request.protocol,
        .body_bytes = request.body.len,
        .from = request.from,
        .trailers = request.trailers,
        .priority = request.priority,
    };
}

pub const OwnedResponse = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body: []u8,
    /// False when originating-request semantics suppress representation data.
    body_allowed: bool = true,
    trailers: []http2.Hpack.HeaderField = &.{},
    /// The final response head carried END_STREAM, so no DATA or trailing
    /// HEADERS could have committed an upper-layer response.
    trailers_only: bool = false,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        allocator.free(self.body);
        self.* = undefined;
    }

    /// Validate actual message content, including content-coded bytes, against
    /// every enabled Content-Digest in headers and trailers.
    pub fn verifyContentDigest(self: OwnedResponse, policy: content_digest.Policy) content_digest.Error!content_digest.Result {
        return content_digest.verifyContent(self.body, self.headers, self.trailers, policy);
    }

    pub fn contentEncoding(
        self: OwnedResponse,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    /// Decode Content-Encoding layers without mutating wire headers or body.
    pub fn decodeContentAlloc(
        self: OwnedResponse,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).decodeAlloc(
            allocator,
            self.body,
            max_output_len,
        );
    }

    pub fn decodeContentInto(
        self: OwnedResponse,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).decodeInto(
            self.body,
            out,
            scratch,
        );
    }
};

pub const RedirectedResponse = struct {
    allocator: std.mem.Allocator,
    response: OwnedResponse,
    final_uri: []u8,
    redirect_count: usize,

    pub fn deinit(self: *RedirectedResponse) void {
        const allocator = self.allocator;
        self.response.deinit(allocator);
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    pub fn takeResponse(self: *RedirectedResponse) OwnedResponse {
        const response = self.response;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return response;
    }
};

pub const StreamingResponse = struct {
    headers: []http2.Hpack.HeaderField,
    status: u16,
    body_bytes: usize,
    trailers: []http2.Hpack.HeaderField = &.{},

    pub fn deinit(
        self: *StreamingResponse,
        allocator: std.mem.Allocator,
    ) void {
        freeHeaders(allocator, self.headers);
        freeHeaders(allocator, self.trailers);
        self.* = undefined;
    }
};

/// Final (non-informational) response metadata delivered before DATA.
pub const StreamingResponseHead = struct {
    headers: []const http2.Hpack.HeaderField,
    status: u16,
    body_allowed: bool = true,

    pub fn streamContentDecoder(
        self: StreamingResponseHead,
        allocator: std.mem.Allocator,
        options: content_coding.StreamOptions,
    ) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).streamDecoder(
            allocator,
            options,
        );
    }
};

pub const InformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        response: StreamingResponseHead,
    ) void,
};

/// Observes an informational response from a multiplexed request batch.
/// `response.headers` borrow connection decoder storage and are valid only for
/// the callback. The request index is stable even when peer frames are ordered
/// differently from the input array; `stream_id` provides wire-level identity.
pub const BatchInformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        request_index: usize,
        stream_id: u31,
        response: StreamingResponseHead,
    ) void,
};

/// One terminal result from a request batch whose members carry independent
/// deadlines. Successful response ownership transfers to the observer. An
/// error applies only to `request_index` unless the connection itself failed,
/// in which case every unfinished member receives that connection error.
pub const BatchOwnedResponseResult = union(enum) {
    response: OwnedResponse,
    err: anyerror,
};

pub const BatchOwnedResponseObserver = struct {
    context: *anyopaque,
    on_result: *const fn (
        context: *anyopaque,
        request_index: usize,
        result: BatchOwnedResponseResult,
    ) void,
};

/// One terminal result from a callback-streaming request batch whose members
/// carry independent deadlines. Headers and trailers are owned by a successful
/// response; response DATA has already been delivered to `on_data`.
pub const BatchStreamingResponseResult = union(enum) {
    response: StreamingResponse,
    err: anyerror,
};

/// Streams independently-deadlined response bodies without aggregating DATA.
/// `on_head` and `on_data` run under the connection's borrowed-reader guard and
/// must not re-enter the same connection. Either callback may reject only its
/// own stream; the exact callback error is then delivered through `on_result`.
pub const BatchStreamingResponseObserver = struct {
    context: *anyopaque,
    on_head: ?*const fn (
        context: *anyopaque,
        request_index: usize,
        response: StreamingResponseHead,
    ) anyerror!void = null,
    on_data: *const fn (
        context: *anyopaque,
        request_index: usize,
        data: []const u8,
    ) anyerror!void,
    on_result: *const fn (
        context: *anyopaque,
        request_index: usize,
        result: BatchStreamingResponseResult,
    ) void,
};

/// Cross-task wake source for independently-deadlined request batches.
/// `take_canceled` consumes one request's cancellation bit. `acknowledge`
/// resets `event` only after checking for cancellations that raced the scan.
/// Both callbacks run on the sole connection reader.
pub const BatchCancellationObserver = struct {
    event: *std.Io.Event,
    context: *anyopaque,
    take_canceled: *const fn (
        context: *anyopaque,
        request_index: usize,
    ) bool,
    acknowledge: *const fn (context: *anyopaque) void,
};

pub fn countInformationalResponse(
    count: *usize,
    limit: usize,
) Error!void {
    count.* = std.math.add(usize, count.*, 1) catch
        return error.TooManyInformationalResponses;
    if (count.* > limit) return error.TooManyInformationalResponses;
}

pub fn notifyInformationalResponse(
    connection: *Connection,
    observer: ?InformationalObserver,
    response: StreamingResponseHead,
    count: *usize,
    limit: usize,
) Error!void {
    try countInformationalResponse(count, limit);
    if (observer) |value| {
        try connection.beginBorrowedReadCallback();
        defer connection.endBorrowedReadCallback();
        value.on_response(value.context, response);
    }
}

fn notifyBatchInformationalResponse(
    connection: *Connection,
    observer: ?BatchInformationalObserver,
    request_index: usize,
    stream_id: u31,
    response: StreamingResponseHead,
    count: *usize,
    limit: usize,
) Error!void {
    try countInformationalResponse(count, limit);
    if (observer) |value| {
        try connection.beginBorrowedReadCallback();
        defer connection.endBorrowedReadCallback();
        value.on_response(
            value.context,
            request_index,
            stream_id,
            response,
        );
    }
}

pub fn ignoreStreamingRequestHead(
    context: anytype,
    head: StreamingRequestHead,
) !void {
    _ = context;
    _ = head;
}

pub fn ignoreStreamingResponseHead(
    context: anytype,
    head: StreamingResponseHead,
) !void {
    _ = context;
    _ = head;
}

const content_digest = @import("../http/digest.zig");
const std = @import("std");
const wire = @import("../internal/wire.zig");
const http_method = @import("../internal/http_method.zig");
const early_data = @import("../http/early_data.zig");
const field_value = @import("../http/field_value.zig");
const chunk_size = @import("chunk_size.zig");
const response_framing = @import("response_framing.zig");
pub const content_coding = @import("../http/content_coding.zig");

pub const runtime = @import("runtime.zig");
pub const client_pool = @import("client_pool.zig");
/// HTTP/1 reuses the shared wire header descriptor without canonicalizing field
/// names. Parsed `Header.name` slices therefore preserve the exact on-wire
/// spelling, while `header()`, `findHeader()`, and `eqlName()` still treat names
/// case-insensitively.
pub const Header = wire.Header;

/// CRLF line iterator used by the HTTP/1 head and trailer parsers. Searching
/// for the first CR and checking the next byte avoids the generic substring
/// search in `std.mem.splitSequence` for every field line while preserving the
/// exact split-on-CRLF semantics.
pub const LineIterator = struct {
    bytes: []const u8,
    index: usize = 0,

    pub fn init(bytes: []const u8) LineIterator {
        return .{ .bytes = bytes };
    }

    pub fn next(self: *LineIterator) ?[]const u8 {
        if (self.index >= self.bytes.len) return null;
        const start = self.index;
        var search = start;
        while (std.mem.indexOfScalarPos(u8, self.bytes, search, '\r')) |cr| {
            if (cr + 1 < self.bytes.len and self.bytes[cr + 1] == '\n') {
                self.index = cr + 2;
                return self.bytes[start..cr];
            }
            search = cr + 1;
        }
        self.index = self.bytes.len;
        return self.bytes[start..];
    }
};

test {
    _ = @import("runtime/client_pool_tests.zig");
    _ = @import("client_pool/admission_tests.zig");
    _ = @import("head/body_framing_tests.zig");
    _ = @import("chunk_size_tests.zig");
}

pub const Error = wire.Error || error{
    BufferTooShort,
    TooManyHeaders,
    MalformedStartLine,
    UriTooLong,
    MalformedHeader,
    InvalidMethod,
    InvalidVersion,
    InvalidResponse,
    InvalidStatus,
    InvalidChunk,
    InvalidHost,
    InvalidContentLength,
    ConflictingContentLength,
    InvalidTransferEncoding,
    InvalidConnection,
    InvalidExpectation,
    InvalidTrailer,
    ChunkSizeOverflow,
    ChunkExtensionTooLarge,
    ContentLengthOverflow,
    RenderBufferTooSmall,
} || std.mem.Allocator.Error;

pub const MethodTag = enum {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
    QUERY,

    extension,

    pub fn string(self: MethodTag) []const u8 {
        return switch (self) {
            .extension => unreachable,
            else => @tagName(self),
        };
    }

    pub fn safe(self: MethodTag) bool {
        return self != .extension and http_method.isSafe(self.string());
    }

    pub fn idempotent(self: MethodTag) bool {
        return self != .extension and
            http_method.isIdempotent(self.string());
    }
};

/// A case-sensitive HTTP method.
///
/// Extension values borrow their input. This keeps request parsing and writing
/// allocation-free while accepting the complete RFC 9110 `method = token`
/// grammar instead of restricting HTTP/1 to a fixed registry snapshot.
pub const Method = union(MethodTag) {
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    CONNECT,
    OPTIONS,
    TRACE,
    PATCH,
    QUERY,
    extension: []const u8,

    pub fn parse(bytes: []const u8) Error!Method {
        // Dispatch on the fixed length and first byte first. Request lines
        // overwhelmingly carry registered methods, and this avoids up to nine
        // full slice comparisons for every parsed start line.
        switch (bytes.len) {
            3 => {
                if (bytes[0] == 'G' and std.mem.eql(u8, bytes, "GET")) return .GET;
                if (bytes[0] == 'P' and std.mem.eql(u8, bytes, "PUT")) return .PUT;
            },
            4 => {
                if (bytes[0] == 'H' and std.mem.eql(u8, bytes, "HEAD")) return .HEAD;
                if (bytes[0] == 'P' and std.mem.eql(u8, bytes, "POST")) return .POST;
            },
            5 => {
                if (bytes[0] == 'P' and std.mem.eql(u8, bytes, "PATCH")) return .PATCH;
                if (bytes[0] == 'T' and std.mem.eql(u8, bytes, "TRACE")) return .TRACE;
                if (bytes[0] == 'Q' and std.mem.eql(u8, bytes, "QUERY")) return .QUERY;
            },
            6 => {
                if (bytes[0] == 'D' and std.mem.eql(u8, bytes, "DELETE")) return .DELETE;
            },
            7 => {
                if (bytes[0] == 'C' and std.mem.eql(u8, bytes, "CONNECT")) return .CONNECT;
                if (bytes[0] == 'O' and std.mem.eql(u8, bytes, "OPTIONS")) return .OPTIONS;
            },
            else => {},
        }
        try validateBytes(bytes);
        return .{ .extension = bytes };
    }

    pub fn string(self: Method) []const u8 {
        return switch (self) {
            .GET => "GET",
            .HEAD => "HEAD",
            .POST => "POST",
            .PUT => "PUT",
            .DELETE => "DELETE",
            .CONNECT => "CONNECT",
            .OPTIONS => "OPTIONS",
            .TRACE => "TRACE",
            .PATCH => "PATCH",
            .QUERY => "QUERY",
            .extension => |bytes| bytes,
        };
    }

    pub fn validate(self: Method) Error!void {
        switch (self) {
            .extension => |bytes| {
                try validateBytes(bytes);
                if (isStandard(bytes)) return error.InvalidMethod;
            },
            else => {},
        }
    }

    fn validateBytes(bytes: []const u8) Error!void {
        if (!http_method.isToken(bytes)) return error.InvalidMethod;
    }

    fn isStandard(bytes: []const u8) bool {
        inline for (.{
            "GET",     "HEAD",    "POST",  "PUT",   "DELETE",
            "CONNECT", "OPTIONS", "TRACE", "PATCH", "QUERY",
        }) |standard| {
            if (std.mem.eql(u8, bytes, standard)) return true;
        }
        return false;
    }

    pub fn safe(self: Method) bool {
        return std.meta.activeTag(self).safe();
    }

    pub fn idempotent(self: Method) bool {
        return std.meta.activeTag(self).idempotent();
    }
};

pub const Version = enum {
    http_1_1,

    pub fn parse(bytes: []const u8) Error!Version {
        if (std.mem.eql(u8, bytes, "HTTP/1.1")) return .http_1_1;
        return error.InvalidVersion;
    }

    pub fn string(self: Version) []const u8 {
        return switch (self) {
            .http_1_1 => "HTTP/1.1",
        };
    }
};

pub const ParseOptions = struct {
    max_headers: usize = 100,
    /// Maximum request-target bytes. Pure parsing remains unlimited unless a
    /// caller such as the connection-owning server supplies a policy.
    max_request_target_bytes: usize = std.math.maxInt(usize),
    allow_obs_fold: bool = false,
    /// Compatibility switch matching Hyper's HTTP/1 server builder. Strict
    /// parsing remains the default because accepting a different request-line
    /// grammar at intermediaries can create routing ambiguity.
    allow_multiple_spaces_in_request_line_delimiters: bool = false,
    /// Client-side compatibility switch for non-conforming response fields
    /// such as `Name : value`. Requests and trailers remain strict even when
    /// this is enabled, matching Hyper's direction-specific policy.
    allow_spaces_after_header_name_in_responses: bool = false,
    /// Ignore malformed request header lines that do not contain NUL or a
    /// bare carriage return. This is intentionally opt-in and mirrors Hyper's
    /// compatibility mode for peers with unrelated broken extension fields.
    ignore_invalid_headers_in_requests: bool = false,
    /// Response-side counterpart to `ignore_invalid_headers_in_requests`.
    ignore_invalid_headers_in_responses: bool = false,
};

pub const ResponseContext = struct {
    request_method: ?Method = null,
};

/// Borrowed HTTP/1 request head parsed without allocation.
pub const RequestHead = struct {
    method: Method,
    target: []const u8,
    version: Version,
    headers: []Header,
    body_framing: BodyFraming,
    content_length: ?usize,
    head_len: usize,
    /// Transfer-Encoding takes framing precedence over Content-Length, but a
    /// request carrying both is an HTTP request-smuggling hazard. The message
    /// remains parseable as chunked while its connection becomes one-shot.
    must_close: bool = false,

    pub fn header(self: RequestHead, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn keepAlive(self: RequestHead) bool {
        return !self.must_close and
            headersKeepAlive(self.version, self.headers);
    }

    pub fn acceptsTrailers(self: RequestHead) bool {
        return requestAcceptsTrailers(self.version, self.headers);
    }

    pub fn streamContentDecoder(
        self: RequestHead,
        allocator: std.mem.Allocator,
        options: content_coding.StreamOptions,
    ) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.parseHeaders(self.headers)).streamDecoder(
            allocator,
            options,
        );
    }

    /// Total bytes for a pipelined message when its body boundary is known from
    /// the head. Chunked bodies require parsing chunks and return null.
    pub fn messageLength(self: RequestHead) Error!?usize {
        return switch (self.body_framing) {
            .none => self.head_len,
            .content_length => std.math.add(usize, self.head_len, self.content_length.?) catch error.ContentLengthOverflow,
            .chunked, .close_delimited => null,
        };
    }
};

/// Borrowed HTTP/1 response head parsed without allocation.
pub const ResponseHead = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
    body_framing: BodyFraming,
    content_length: ?usize,
    head_len: usize,
    /// Originating-request semantics permit response representation bytes.
    body_allowed: bool = true,
    /// True when safe message framing requires retiring the connection even
    /// after a complete response body has been consumed.
    must_close: bool = false,

    pub fn header(self: ResponseHead, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn streamContentDecoder(
        self: ResponseHead,
        allocator: std.mem.Allocator,
        options: content_coding.StreamOptions,
    ) content_coding.Error!content_coding.StreamDecoder {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).streamDecoder(
            allocator,
            options,
        );
    }

    pub fn messageLength(self: ResponseHead) Error!?usize {
        return switch (self.body_framing) {
            .none => self.head_len,
            .content_length => std.math.add(usize, self.head_len, self.content_length.?) catch error.ContentLengthOverflow,
            .chunked, .close_delimited => null,
        };
    }

    pub fn keepAlive(self: ResponseHead) bool {
        return response_framing.keepAlive(self);
    }
};

/// Borrowed metadata for a bodyless informational response. Runtime observer
/// callbacks may inspect these slices only until the callback returns.
pub const InformationalResponseHead = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,

    pub fn header(
        self: InformationalResponseHead,
        name: []const u8,
    ) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }
};

pub const max_chunk_extension_bytes: usize = 16 * 1024;
/// Exclusive upper bound for a complete chunk-size line before its CRLF.
/// The fixed allowance covers the hexadecimal size and optional whitespace;
/// the remainder bounds extensions. Keeping one shared bound prevents a peer
/// from bypassing the streaming limit by delivering an oversized line and its
/// terminator in the same transport read.
pub const max_chunk_size_line_bytes: usize = max_chunk_extension_bytes + 32;

pub const BodyFraming = enum {
    /// No message body framing was present in the parsed bytes.
    none,
    /// The body is delimited by Content-Length and points into the caller buffer.
    content_length,
    /// The parser decoded RFC 9112 chunked transfer coding into owned storage.
    chunked,
    /// Runtime-only response body framing: no length/coding was declared and
    /// EOF delimited the body bytes.
    close_delimited,
};

pub const Request = struct {
    method: Method,
    target: []const u8,
    version: Version,
    headers: []Header,
    body: []const u8,
    body_framing: BodyFraming = .none,
    trailers: []Header = &.{},
    body_storage: ?[]u8 = null,
    header_value_storage: [][]u8 = &.{},
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,
    /// True when safe message framing requires retiring the connection even
    /// if its Connection fields would otherwise permit persistence.
    must_close: bool = false,
    /// Peer socket address captured for server-accepted TCP requests. Null
    /// for client-created requests and transports without an IP peer.
    from: ?std.Io.net.IpAddress = null,

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        if (self.body_storage) |body| allocator.free(body);
        freeHeaderValueStorage(allocator, self.header_value_storage);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.headers);
        allocator.free(self.trailers);
        self.* = undefined;
    }

    pub fn header(self: Request, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    pub fn contentEncoding(
        self: Request,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    /// Decode Content-Encoding layers without mutating the request body.
    pub fn decodeContentAlloc(
        self: Request,
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
        self: Request,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return (try self.contentEncoding()).decodeInto(
            self.body,
            out,
            scratch,
        );
    }

    pub fn keepAlive(self: Request) bool {
        return !self.must_close and
            headersKeepAlive(self.version, self.headers);
    }

    pub fn acceptsTrailers(self: Request) bool {
        return requestAcceptsTrailers(self.version, self.headers);
    }

    pub fn upgradeProtocol(self: Request) ?[]const u8 {
        if (!wire.anyHeaderContainsToken(
            self.headers,
            "connection",
            "upgrade",
        )) return null;
        const upgrade = self.header("upgrade") orelse return null;
        return wire.trimOws(upgrade);
    }
};

/// Apply HTTP/1 persistence defaults after combining every repeated
/// Connection field. `close` has precedence regardless of field order.
pub fn headersKeepAlive(
    version: Version,
    headers: []const Header,
) bool {
    if (wire.anyHeaderContainsToken(
        headers,
        "connection",
        "close",
    )) return false;
    if (wire.anyHeaderContainsToken(
        headers,
        "connection",
        "keep-alive",
    )) return true;
    return version == .http_1_1;
}

/// Whether a request explicitly permits response trailer fields.
///
/// Netz enforces RFC 9110 section 6.5.1's recommendation that an HTTP/1.1
/// server not emit trailer fields unless the request's TE field advertises
/// trailers. Repeated TE fields are treated as one logical list.
pub fn requestAcceptsTrailers(
    version: Version,
    headers: []const Header,
) bool {
    if (version != .http_1_1) return false;
    const state = parseTeHeaders(headers) catch return false;
    return state.accepts_trailers and
        (connectionOptionPresent(headers, "te") catch false);
}

fn hasHeaderNamed(headers: []const Header, name: []const u8) bool {
    for (headers) |header| {
        if (header.eqlName(name)) return true;
    }
    return false;
}

/// Filter descriptors in caller-owned storage without touching the wire
/// bytes. This lets the borrowed request-head API expose Hyper's TE-over-CL
/// normalization without allocating.
fn stripHeaderInPlace(headers: []Header, name: []const u8) []Header {
    var kept: usize = 0;
    for (headers) |header| {
        if (header.eqlName(name)) continue;
        headers[kept] = header;
        kept += 1;
    }
    return headers[0..kept];
}

pub const Response = struct {
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []Header,
    body: []const u8,
    body_framing: BodyFraming = .none,
    /// False for HEAD, successful CONNECT and status-suppressed bodies.
    body_allowed: bool = true,
    trailers: []Header = &.{},
    body_storage: ?[]u8 = null,
    header_value_storage: [][]u8 = &.{},
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,
    /// True when EOF framing, mixed TE/CL or a protocol switch ends HTTP
    /// persistence. A successful CONNECT/Upgrade may still hand the byte
    /// stream to the selected protocol through the runtime's tunnel APIs.
    must_close: bool = false,

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        if (self.body_storage) |body| allocator.free(body);
        freeHeaderValueStorage(allocator, self.header_value_storage);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.headers);
        allocator.free(self.trailers);
        self.* = undefined;
    }

    pub fn header(self: Response, name: []const u8) ?[]const u8 {
        return wire.findHeader(self.headers, name);
    }

    /// Validate actual message content, including content-coded bytes, against
    /// every enabled Content-Digest in headers and trailers.
    pub fn verifyContentDigest(self: Response, policy: content_digest.Policy) content_digest.Error!content_digest.Result {
        return content_digest.verifyContent(self.body, self.headers, self.trailers, policy);
    }

    pub fn contentEncoding(
        self: Response,
    ) content_coding.Error!content_coding.Chain {
        return content_coding.parseHeaders(self.headers);
    }

    /// Decode Content-Encoding layers in reverse application order while
    /// bounding every materialized layer. The response remains unchanged.
    pub fn decodeContentAlloc(
        self: Response,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).decodeAlloc(
            allocator,
            self.body,
            max_output_len,
        );
    }

    /// Caller-buffer counterpart to `decodeContentAlloc`. For stacked
    /// encodings, `scratch` holds intermediate representation bytes.
    pub fn decodeContentInto(
        self: Response,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return (try content_coding.responseDecodingChain(self.headers, self.status, self.body_allowed)).decodeInto(
            self.body,
            out,
            scratch,
        );
    }

    pub fn keepAlive(self: Response) bool {
        return response_framing.keepAlive(self);
    }

    /// Return the selected protocol from a valid 101 Switching Protocols
    /// response. Both Connection and Upgrade are required so callers cannot
    /// mistake an arbitrary informational response for a protocol handoff.
    pub fn upgradeProtocol(self: Response) ?[]const u8 {
        if (self.status != 101) return null;
        if (!wire.anyHeaderContainsToken(
            self.headers,
            "connection",
            "upgrade",
        )) return null;
        const upgrade = self.header("upgrade") orelse return null;
        const protocol = wire.trimOws(upgrade);
        return if (protocol.len == 0) null else protocol;
    }
};

/// Parse a strict request head into caller-provided header storage.
///
/// Returned strings borrow `bytes`; `header_storage` is only used for the
/// lightweight name/value descriptors. Obsolete folding is intentionally
/// rejected because unfolding requires owned value storage.
pub fn parseRequestHead(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
) Error!RequestHead {
    const parsed = try parseHeadLines(bytes, header_storage, options, .{
        .ignore_invalid = options.ignore_invalid_headers_in_requests,
    });
    return finishRequestHead(parsed, options);
}

fn finishRequestHead(parsed: BorrowedHead, options: ParseOptions) Error!RequestHead {
    const request_line = try parseRequestLine(
        parsed.start_line,
        options.allow_multiple_spaces_in_request_line_delimiters,
    );
    if (request_line.target.len > options.max_request_target_bytes) {
        return error.UriTooLong;
    }
    const method = try Method.parse(request_line.method);
    try validateRequestTargetForMethod(method, request_line.target);
    const version = try Version.parse(request_line.version);
    try normalizeParsedRequestHostParts(
        method,
        version,
        request_line.target,
        parsed.headers,
    );
    const framing = try requestFraming(parsed.headers);
    const exposed_headers = if (framing.body == .chunked)
        stripHeaderInPlace(parsed.headers, "content-length")
    else
        parsed.headers;
    return .{
        .method = method,
        .target = request_line.target,
        .version = version,
        .headers = exposed_headers,
        .body_framing = framing.body,
        .content_length = framing.content_length,
        .head_len = parsed.head_len,
        .must_close = framing.must_close,
    };
}

pub fn parseResponseHead(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
    context: ResponseContext,
) Error!ResponseHead {
    const parsed = try parseHeadLines(
        bytes,
        header_storage,
        options,
        .{
            .allow_spaces_before_colon = options.allow_spaces_after_header_name_in_responses,
            .ignore_invalid = options.ignore_invalid_headers_in_responses,
        },
    );
    return finishResponseHead(parsed, context);
}

fn finishResponseHead(parsed: BorrowedHead, context: ResponseContext) Error!ResponseHead {
    const status_line = try parseStatusLine(parsed.start_line);
    const version = try Version.parse(status_line.version);
    const status = try parseStatusCode(status_line.status_code);
    try validateReasonPhrase(status_line.reason);
    const metadata = try response_framing.inspect(status, context.request_method, parsed.headers);
    early_data.validateForbiddenFields(parsed.headers) catch
        return error.InvalidResponse;
    const declared_content_length = try metadata.contentLength(parsed.headers);
    const framing: BodyFraming = if (!metadata.body_allowed) .none else switch (bodyFraming(parsed.headers) catch |err| switch (err) {
        error.InvalidTransferEncoding => if (try responseTransferEncodingIsCloseDelimited(parsed.headers))
            .close_delimited
        else
            return error.InvalidTransferEncoding,
        else => |e| return e,
    }) {
        // Response messages without an explicit body delimiter are bounded by
        // connection close.  Reporting this as `none` would let pipeline-aware
        // callers treat the head as a complete response and misclassify the
        // body bytes as the next message.
        .none => .close_delimited,
        else => |value| value,
    };
    const exposed_headers = if (metadata.has_transfer_encoding)
        stripHeaderInPlace(parsed.headers, "content-length")
    else
        parsed.headers;
    return .{
        .version = version,
        .status = status,
        .reason = status_line.reason,
        .headers = exposed_headers,
        .body_framing = framing,
        .body_allowed = metadata.body_allowed,
        .content_length = declared_content_length,
        .head_len = parsed.head_len,
        .must_close = metadata.mustClose(framing),
    };
}

const OwnedHeadParser = @import("head/owned.zig").Parser(struct {
    pub const parseFields = parseOwnedHeadFields;
    pub fn deinitFields(fields: *OwnedHeadFields, allocator: std.mem.Allocator) void {
        fields.storage.deinit(allocator);
    }
    pub fn finishRequest(start_line: []const u8, headers: []Header, head_len: usize, options: ParseOptions) Error!RequestHead {
        return finishRequestHead(.{ .start_line = start_line, .headers = headers, .head_len = head_len }, options);
    }
    pub fn finishResponse(start_line: []const u8, headers: []Header, head_len: usize, context: ResponseContext) Error!ResponseHead {
        return finishResponseHead(.{ .start_line = start_line, .headers = headers, .head_len = head_len }, context);
    }
});
pub const OwnedRequestHead = OwnedHeadParser.Request;
pub const OwnedResponseHead = OwnedHeadParser.Response;
/// Parse head metadata with owned descriptors and optional unfolded values.
/// Input bytes need only contain a complete head; no body is required.
pub const parseOwnedRequestHead = OwnedHeadParser.request;
pub const parseOwnedResponseHead = OwnedHeadParser.response;

const OwnedHeadFields = struct { start_line: []const u8, head_len: usize, storage: ParsedHeaders };
fn parseOwnedHeadFields(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions, kind: enum { request, response }) Error!OwnedHeadFields {
    const end = findHeadEnd(bytes) orelse return error.BufferTooShort;
    var lines = LineIterator.init(bytes[0..end]);
    const start_line = lines.next() orelse return error.MalformedStartLine;
    const fields = try parseHeaderLines(allocator, &lines, options, .{
        .allow_spaces_before_colon = kind == .response and options.allow_spaces_after_header_name_in_responses,
        .ignore_invalid = if (kind == .response) options.ignore_invalid_headers_in_responses else options.ignore_invalid_headers_in_requests,
    });
    return .{ .start_line = start_line, .head_len = end + 4, .storage = fields };
}

const BorrowedHead = struct {
    start_line: []const u8,
    headers: []Header,
    head_len: usize,
};

const HeaderParsePolicy = struct {
    allow_spaces_before_colon: bool = false,
    ignore_invalid: bool = false,
};

fn parseHeadLines(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
    policy: HeaderParsePolicy,
) Error!BorrowedHead {
    // Walk CRLF-delimited lines once and stop at the empty line. The previous
    // implementation first scanned the complete head for CRLFCRLF and then
    // rescanned every line; pipelined runtimes already provide a complete
    // buffer, so the double pass was pure overhead in the parse hot path.
    const first_line_end = std.mem.indexOf(u8, bytes, "\r\n") orelse
        return error.BufferTooShort;
    const start_line = bytes[0..first_line_end];

    if (!policy.allow_spaces_before_colon and !policy.ignore_invalid) {
        return parseStrictHeadLines(
            bytes,
            header_storage,
            options,
            start_line,
            first_line_end + 2,
        );
    }

    return parseCompatibleHeadLines(
        bytes,
        header_storage,
        options,
        policy,
        start_line,
        first_line_end + 2,
    );
}

pub fn parseCompatibleHeadLines(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
    policy: HeaderParsePolicy,
    start_line: []const u8,
    initial_pos: usize,
) Error!BorrowedHead {
    var count: usize = 0;
    var pos = initial_pos;
    while (true) {
        const line_end_rel = std.mem.indexOf(
            u8,
            bytes[pos..],
            "\r\n",
        ) orelse return error.BufferTooShort;
        if (line_end_rel == 0) {
            return .{
                .start_line = start_line,
                .headers = header_storage[0..count],
                .head_len = pos + 2,
            };
        }
        const line = bytes[pos .. pos + line_end_rel];
        if (line[0] == ' ' or line[0] == '\t') {
            // Even when allocating parse allows obs-fold, this borrowed API
            // cannot expose a contiguous unfolded value without copying.
            _ = options.allow_obs_fold;
            if (!policy.ignore_invalid or hasFatalInvalidHeaderByte(line)) {
                return error.MalformedHeader;
            }
            pos += line_end_rel + 2;
            continue;
        }
        const header = parseHeaderLine(
            line,
            policy.allow_spaces_before_colon,
        ) catch |err| {
            if (!policy.ignore_invalid or
                hasFatalInvalidHeaderByte(line))
            {
                return err;
            }
            pos += line_end_rel + 2;
            continue;
        };
        if (count >= options.max_headers or count >= header_storage.len) {
            return error.TooManyHeaders;
        }
        header_storage[count] = header;
        count += 1;
        pos += line_end_rel + 2;
        if (pos > bytes.len) return error.BufferTooShort;
    }
}

/// Single-pass field parser for the default strict borrowed-head policy. The
/// compatibility paths still use complete line slices because they may
/// skip malformed fields; strict parsing can validate name, value, and CRLF in
/// one traversal without weakening incomplete-input classification.
pub fn parseStrictHeadLines(
    bytes: []const u8,
    header_storage: []Header,
    options: ParseOptions,
    start_line: []const u8,
    initial_pos: usize,
) Error!BorrowedHead {
    var count: usize = 0;
    var pos = initial_pos;
    while (true) {
        if (pos >= bytes.len) return error.BufferTooShort;
        if (bytes[pos] == '\r') {
            if (pos + 1 >= bytes.len) return error.BufferTooShort;
            if (bytes[pos + 1] == '\n') {
                return .{
                    .start_line = start_line,
                    .headers = header_storage[0..count],
                    .head_len = pos + 2,
                };
            }
        }
        if (bytes[pos] == ' ' or bytes[pos] == '\t') {
            // Borrowed values cannot expose unfolded storage. Even when the
            // allocating parser accepts obs-fold, the strict borrowed API has
            // always rejected it after the physical line became complete.
            _ = options.allow_obs_fold;
            return rejectCompleteHeaderLine(bytes, pos + 1);
        }

        const name_start = pos;
        while (true) : (pos += 1) {
            if (pos >= bytes.len) return error.BufferTooShort;
            const byte = bytes[pos];
            if (byte == ':') break;
            if (byte == '\r') {
                if (pos + 1 >= bytes.len) return error.BufferTooShort;
                if (bytes[pos + 1] == '\n') {
                    return error.MalformedHeader;
                }
            }
            if (!validHeaderNameByte(byte)) {
                return rejectCompleteHeaderLine(bytes, pos + 1);
            }
        }
        if (pos == name_start) {
            return rejectCompleteHeaderLine(bytes, pos + 1);
        }
        const name = bytes[name_start..pos];
        pos += 1;
        while (pos < bytes.len and
            (bytes[pos] == ' ' or bytes[pos] == '\t'))
        {
            pos += 1;
        }

        const value_start = pos;
        var value_end = value_start;
        while (true) : (pos += 1) {
            if (pos >= bytes.len) return error.BufferTooShort;
            const byte = bytes[pos];
            if (byte == '\r') {
                if (pos + 1 >= bytes.len) return error.BufferTooShort;
                if (bytes[pos + 1] != '\n') {
                    return rejectCompleteHeaderLine(bytes, pos + 1);
                }
                break;
            }
            if (field_value.invalidByte(byte)) {
                return rejectCompleteHeaderLine(bytes, pos + 1);
            }
            if (byte != ' ' and byte != '\t') value_end = pos + 1;
        }

        if (count >= options.max_headers or count >= header_storage.len) {
            return error.TooManyHeaders;
        }
        header_storage[count] = .{
            .name = name,
            .value = bytes[value_start..value_end],
        };
        count += 1;
        pos += 2;
    }
}

/// Locate the end of an HTTP/1 head. Searching for the first CR and then
/// checking the following bytes avoids the generic multi-byte substring
/// search on every request while preserving the exact first-match semantics.
fn findHeadEnd(bytes: []const u8) ?usize {
    var start: usize = 0;
    while (std.mem.indexOfScalarPos(u8, bytes, start, '\r')) |index| {
        if (index + 4 <= bytes.len and
            bytes[index + 1] == '\n' and
            bytes[index + 2] == '\r' and
            bytes[index + 3] == '\n')
        {
            return index;
        }
        start = index + 1;
    }
    return null;
}

fn rejectCompleteHeaderLine(
    bytes: []const u8,
    scan_start: usize,
) Error {
    if (scan_start >= bytes.len or
        std.mem.indexOf(u8, bytes[scan_start..], "\r\n") == null)
    {
        return error.BufferTooShort;
    }
    return error.MalformedHeader;
}

/// Parse one complete request with strict Host cardinality and syntax before
/// allocating or decoding its body. Absolute-form and CONNECT targets replace
/// the exposed Host value with their authoritative request-target authority.
pub fn parseRequest(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!Request {
    const head_end = findHeadEnd(bytes) orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    var lines = LineIterator.init(head);
    const request_line = lines.next() orelse return error.MalformedStartLine;

    const request_parts = try parseRequestLine(
        request_line,
        options.allow_multiple_spaces_in_request_line_delimiters,
    );
    if (request_parts.target.len > options.max_request_target_bytes) {
        return error.UriTooLong;
    }
    const method = try Method.parse(request_parts.method);
    try validateRequestTargetForMethod(method, request_parts.target);
    const version = try Version.parse(request_parts.version);

    var parsed_headers = try parseHeaderLines(
        allocator,
        &lines,
        options,
        .{ .ignore_invalid = options.ignore_invalid_headers_in_requests },
    );
    errdefer parsed_headers.deinit(allocator);
    try normalizeParsedRequestHostParts(
        method,
        version,
        request_parts.target,
        parsed_headers.headers,
    );
    const consumed_head = head_end + 4;
    const framing = try requestFraming(parsed_headers.headers);
    const parsed_body = try parseBodyWithFraming(
        allocator,
        bytes,
        consumed_head,
        options,
        framing.body,
        framing.content_length,
    );
    errdefer parsed_body.deinit(allocator);
    if (parsed_body.framing == .chunked or parsed_body.framing == .close_delimited) {
        try parsed_headers.stripContentLength(allocator);
    }
    early_data.validateForbiddenFields(parsed_body.trailers) catch
        return error.InvalidTrailer;

    return .{
        .method = method,
        .target = request_parts.target,
        .version = version,
        .headers = parsed_headers.headers,
        .body = parsed_body.body,
        .body_framing = parsed_body.framing,
        .trailers = parsed_body.trailers,
        .body_storage = parsed_body.body_storage,
        .header_value_storage = parsed_headers.value_storage,
        .trailer_value_storage = parsed_body.trailer_value_storage,
        .consumed = parsed_body.consumed,
        .must_close = framing.must_close,
    };
}

/// Validate a complete request head with the allocating parser's exact
/// compatibility policy, without requiring any body bytes. Servers use this
/// before emitting 100 Continue so a malformed request cannot receive an
/// interim success response merely because its Host/Expect/length fields look
/// plausible to a lightweight framing scan.
pub fn validateRequestHead(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ParseOptions,
) Error!void {
    const head_end = findHeadEnd(bytes) orelse
        return error.BufferTooShort;
    var lines = LineIterator.init(bytes[0..head_end]);
    const request_line = lines.next() orelse return error.MalformedStartLine;
    const parts = try parseRequestLine(
        request_line,
        options.allow_multiple_spaces_in_request_line_delimiters,
    );
    if (parts.target.len > options.max_request_target_bytes) {
        return error.UriTooLong;
    }
    const method = try Method.parse(parts.method);
    try validateRequestTargetForMethod(method, parts.target);
    const version = try Version.parse(parts.version);
    var parsed = try parseHeaderLines(
        allocator,
        &lines,
        options,
        .{ .ignore_invalid = options.ignore_invalid_headers_in_requests },
    );
    defer parsed.deinit(allocator);
    try normalizeParsedRequestHostParts(
        method,
        version,
        parts.target,
        parsed.headers,
    );
    _ = try requestFraming(parsed.headers);
}

/// Parse a complete response image. For an EOF-delimited entity, bytes must
/// include the complete body through transport EOF; parseResponseHead exposes
/// that framing without treating a partial image as a complete entity.
pub fn parseResponse(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!Response {
    return parseResponseWithContext(allocator, bytes, options, .{});
}

pub fn parseResponseForRequest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ParseOptions,
    request_method: Method,
) Error!Response {
    return parseResponseWithContext(allocator, bytes, options, .{ .request_method = request_method });
}

pub fn parseResponseWithContext(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ParseOptions,
    context: ResponseContext,
) Error!Response {
    const head_end = findHeadEnd(bytes) orelse return error.BufferTooShort;
    const head = bytes[0..head_end];
    var lines = LineIterator.init(head);
    const status_line = lines.next() orelse return error.MalformedStartLine;

    const status_parts = try parseStatusLine(status_line);
    const version = try Version.parse(status_parts.version);
    const status = try parseStatusCode(status_parts.status_code);
    try validateReasonPhrase(status_parts.reason);

    var parsed_headers = try parseHeaderLines(
        allocator,
        &lines,
        options,
        .{
            .allow_spaces_before_colon = options.allow_spaces_after_header_name_in_responses,
            .ignore_invalid = options.ignore_invalid_headers_in_responses,
        },
    );
    errdefer parsed_headers.deinit(allocator);
    const metadata = try response_framing.inspect(status, context.request_method, parsed_headers.headers);
    early_data.validateForbiddenFields(parsed_headers.headers) catch
        return error.InvalidResponse;
    const consumed_head = head_end + 4;
    const parsed_body = if (!metadata.body_allowed)
        ParsedBody{
            .framing = .none,
            .body = bytes[consumed_head..consumed_head],
            .consumed = consumed_head,
        }
    else
        try parseResponseBody(allocator, bytes, consumed_head, parsed_headers.headers, options);
    errdefer parsed_body.deinit(allocator);
    if (metadata.has_transfer_encoding) {
        try parsed_headers.stripContentLength(allocator);
    }
    early_data.validateForbiddenFields(parsed_body.trailers) catch
        return error.InvalidTrailer;

    return .{
        .version = version,
        .status = status,
        .reason = status_parts.reason,
        .headers = parsed_headers.headers,
        .body = parsed_body.body,
        .body_framing = parsed_body.framing,
        .body_allowed = metadata.body_allowed,
        .trailers = parsed_body.trailers,
        .body_storage = parsed_body.body_storage,
        .header_value_storage = parsed_headers.value_storage,
        .trailer_value_storage = parsed_body.trailer_value_storage,
        .consumed = parsed_body.consumed,
        .must_close = metadata.mustClose(parsed_body.framing),
    };
}

const ParsedHeaders = struct {
    headers: []Header,
    value_storage: [][]u8 = &.{},

    pub fn deinit(self: *ParsedHeaders, allocator: std.mem.Allocator) void {
        freeHeaderValueStorage(allocator, self.value_storage);
        allocator.free(self.headers);
        self.* = undefined;
    }

    fn stripContentLength(self: *ParsedHeaders, allocator: std.mem.Allocator) Error!void {
        var kept: usize = 0;
        var removed = false;
        for (self.headers) |header| {
            if (header.eqlName("content-length")) {
                removed = true;
                continue;
            }
            self.headers[kept] = header;
            kept += 1;
        }
        if (!removed) return;
        const stripped = try allocator.realloc(self.headers, kept);
        self.headers = stripped;
    }
};

fn parseHeaderLines(
    allocator: std.mem.Allocator,
    lines: *LineIterator,
    options: ParseOptions,
    policy: HeaderParsePolicy,
) Error!ParsedHeaders {
    if (!options.allow_obs_fold) {
        return parseHeaderLinesNoFold(
            allocator,
            lines.*,
            options,
            policy,
        );
    }

    return FoldedHeaders.parse(allocator, lines, options, policy);
}

const FoldedHeaders = @import("head/folded.zig").Parser(struct {
    pub const PolicyType = HeaderParsePolicy;
    pub const ResultType = ParsedHeaders;
    pub const parseLine = parseHeaderLine;
    pub const validateValue = validateHeaderValue;
    pub const fatal = hasFatalInvalidHeaderByte;
});

/// Owned result of parsing a CRLF-delimited trailer field block.
pub const ParsedTrailerFields = struct {
    headers: []Header = &.{},
    value_storage: [][]u8 = &.{},

    pub fn deinit(
        self: *ParsedTrailerFields,
        allocator: std.mem.Allocator,
    ) void {
        freeHeaderValueStorage(allocator, self.value_storage);
        allocator.free(self.headers);
        self.* = undefined;
    }
};

/// Parse an owned CRLF-delimited trailer field block using the same syntax and
/// obs-fold policy as request/response heads. Trailer-specific forbidden field
/// names remain validated by the caller after parsing.
pub fn parseTrailerFields(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: ParseOptions,
) Error!ParsedTrailerFields {
    var lines = LineIterator.init(bytes);
    const parsed = try parseHeaderLines(allocator, &lines, options, .{});
    return .{
        .headers = parsed.headers,
        .value_storage = parsed.value_storage,
    };
}

/// Validate a trailer field block without retaining its fields. This is used
/// by borrowed aggregate paths that must enforce the same syntax, count, and
/// forbidden-name policy without allocating descriptor or unfolded-value
/// storage.
pub fn validateTrailerFields(
    bytes: []const u8,
    options: ParseOptions,
) Error!void {
    var count: usize = 0;
    var lines = LineIterator.init(bytes);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            if (!options.allow_obs_fold or count == 0) {
                return error.MalformedHeader;
            }
            const continuation = wire.trimOws(line);
            try validateHeaderValue(continuation);
            continue;
        }
        const trailer = try parseHeaderLine(line, false);
        if (count >= options.max_headers) return error.TooManyHeaders;
        if (!validTrailerFieldName(trailer.name)) {
            return error.InvalidTrailer;
        }
        count += 1;
    }
}

pub fn parseHeaderLinesNoFold(
    allocator: std.mem.Allocator,
    lines: LineIterator,
    options: ParseOptions,
    policy: HeaderParsePolicy,
) Error!ParsedHeaders {
    // Preserve the first validation pass for the common small header set.
    // Larger sets still count exactly before allocating and filling their
    // result, avoiding geometric temporary storage on attacker-sized input.
    var common_headers: [16]Header = undefined;
    var scan = lines;
    var count: usize = 0;
    while (scan.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') {
            if (policy.ignore_invalid and
                !hasFatalInvalidHeaderByte(line))
            {
                continue;
            }
            return error.MalformedHeader;
        }
        const header = parseHeaderLine(
            line,
            policy.allow_spaces_before_colon,
        ) catch |err| {
            if (!policy.ignore_invalid or
                hasFatalInvalidHeaderByte(line))
            {
                return err;
            }
            continue;
        };
        if (count >= options.max_headers) return error.TooManyHeaders;
        if (count < common_headers.len) common_headers[count] = header;
        count += 1;
    }

    if (count == 0) {
        return .{
            .headers = @constCast(&[_]Header{}),
            .value_storage = @constCast(&[_][]u8{}),
        };
    }

    const headers = try allocator.alloc(Header, count);
    errdefer allocator.free(headers);
    if (count <= common_headers.len) {
        @memcpy(headers, common_headers[0..count]);
        return .{
            .headers = headers,
            .value_storage = @constCast(&[_][]u8{}),
        };
    }
    var fill = lines;
    var index: usize = 0;
    while (fill.next()) |line| {
        if (line.len == 0) continue;
        if (line[0] == ' ' or line[0] == '\t') continue;
        const header = parseHeaderLine(
            line,
            policy.allow_spaces_before_colon,
        ) catch continue;
        headers[index] = header;
        index += 1;
    }
    return .{
        .headers = headers,
        .value_storage = @constCast(&[_][]u8{}),
    };
}

const RequestLineParts = struct {
    method: []const u8,
    target: []const u8,
    version: []const u8,
};

const StatusLineParts = struct {
    version: []const u8,
    status_code: []const u8,
    reason: []const u8,
};

fn parseStatusLine(line: []const u8) Error!StatusLineParts {
    const version_end = std.mem.indexOfScalar(u8, line, ' ') orelse
        return error.MalformedStartLine;
    const status_start = version_end + 1;
    const status_end = std.mem.indexOfScalarPos(
        u8,
        line,
        status_start,
        ' ',
    ) orelse return error.MalformedStartLine;
    return .{
        .version = line[0..version_end],
        .status_code = line[status_start..status_end],
        .reason = line[status_end + 1 ..],
    };
}

fn parseRequestLine(
    line: []const u8,
    allow_multiple_spaces: bool,
) Error!RequestLineParts {
    if (!allow_multiple_spaces) {
        // The strict grammar is three non-empty fields separated by exactly
        // one SP. Locate the two delimiters with the SIMD scalar search
        // instead of walking every byte, then reject any extra separator.
        const first_space = std.mem.indexOfScalar(u8, line, ' ') orelse
            return error.MalformedStartLine;
        if (first_space == 0) return error.MalformedStartLine;
        const target_start = first_space + 1;
        const second_space = std.mem.indexOfScalarPos(
            u8,
            line,
            target_start,
            ' ',
        ) orelse return error.MalformedStartLine;
        if (second_space == target_start) return error.MalformedStartLine;
        const version_start = second_space + 1;
        if (version_start == line.len) return error.MalformedStartLine;
        if (std.mem.indexOfScalarPos(u8, line, version_start, ' ') != null) {
            return error.MalformedStartLine;
        }
        return .{
            .method = line[0..first_space],
            .target = line[target_start..second_space],
            .version = line[version_start..],
        };
    }

    var fields: [3][]const u8 = undefined;
    var field_count: usize = 0;
    var cursor: usize = 0;
    while (cursor < line.len) {
        const start = cursor;
        while (cursor < line.len and line[cursor] != ' ') : (cursor += 1) {}
        if (field_count == fields.len) return error.MalformedStartLine;
        fields[field_count] = line[start..cursor];
        field_count += 1;
        if (cursor == line.len) break;

        const delimiter_start = cursor;
        while (cursor < line.len and line[cursor] == ' ') : (cursor += 1) {}
        if (!allow_multiple_spaces and cursor - delimiter_start != 1) {
            return error.MalformedStartLine;
        }
        if (cursor == line.len) return error.MalformedStartLine;
    }
    if (field_count != fields.len) return error.MalformedStartLine;
    return .{
        .method = fields[0],
        .target = fields[1],
        .version = fields[2],
    };
}

inline fn parseHeaderLine(
    line: []const u8,
    allow_spaces_before_colon: bool,
) Error!Header {
    var colon: usize = 0;
    var name_end: usize = 0;
    if (allow_spaces_before_colon) {
        colon = std.mem.indexOfScalar(u8, line, ':') orelse
            return error.MalformedHeader;
        name_end = colon;
        while (name_end != 0 and
            (line[name_end - 1] == ' ' or line[name_end - 1] == '\t'))
        {
            name_end -= 1;
        }
        try validateHeaderName(line[0..name_end]);
    } else {
        while (colon < line.len and line[colon] != ':') : (colon += 1) {
            if (!validHeaderNameByte(line[colon])) {
                return error.MalformedHeader;
            }
        }
        if (colon == 0 or colon == line.len) return error.MalformedHeader;
        name_end = colon;
    }
    const name = line[0..name_end];
    var value_start = colon + 1;
    while (value_start < line.len and
        (line[value_start] == ' ' or line[value_start] == '\t'))
    {
        value_start += 1;
    }
    var value_end = value_start;
    for (line[value_start..], value_start..) |byte, index| {
        if (field_value.invalidByte(byte)) {
            return error.MalformedHeader;
        }
        if (byte != ' ' and byte != '\t') value_end = index + 1;
    }
    const value = line[value_start..value_end];
    return .{ .name = name, .value = value };
}

fn hasFatalInvalidHeaderByte(line: []const u8) bool {
    // httparse deliberately refuses to recover from NUL and bare CR because
    // they can change the line boundary seen by another HTTP implementation.
    return std.mem.indexOfScalar(u8, line, 0) != null or
        std.mem.indexOfScalar(u8, line, '\r') != null or
        std.mem.indexOfScalar(u8, line, '\n') != null;
}

const ParsedBody = struct {
    framing: BodyFraming,
    body: []const u8,
    body_storage: ?[]u8 = null,
    trailers: []Header = &.{},
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,

    fn deinit(self: ParsedBody, allocator: std.mem.Allocator) void {
        if (self.body_storage) |body| allocator.free(body);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.trailers);
    }
};

fn parseBody(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    body_start: usize,
    headers: []const Header,
    options: ParseOptions,
) Error!ParsedBody {
    const framing = try bodyFraming(headers);
    return parseBodyWithFraming(
        allocator,
        bytes,
        body_start,
        options,
        framing,
        if (framing == .content_length)
            (try contentLength(headers)).?
        else
            null,
    );
}

fn parseBodyWithFraming(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    body_start: usize,
    options: ParseOptions,
    framing: BodyFraming,
    declared_content_length: ?usize,
) Error!ParsedBody {
    return switch (framing) {
        .none => .{
            .framing = .none,
            .body = bytes[body_start..body_start],
            .consumed = body_start,
        },
        .content_length => blk: {
            const len = declared_content_length.?;
            const end = std.math.add(usize, body_start, len) catch return error.ContentLengthOverflow;
            if (bytes.len < end) return error.BufferTooShort;
            break :blk .{
                .framing = .content_length,
                .body = bytes[body_start..end],
                .consumed = end,
            };
        },
        .chunked => blk: {
            var decoded = try decodeChunked(allocator, bytes[body_start..], options);
            errdefer decoded.deinit(allocator);
            break :blk .{
                .framing = .chunked,
                .body = decoded.body,
                .body_storage = decoded.body,
                .trailers = decoded.trailers,
                .trailer_value_storage = decoded.trailer_value_storage,
                .consumed = body_start + decoded.consumed,
            };
        },
        .close_delimited => unreachable,
    };
}

fn parseResponseBody(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    body_start: usize,
    headers: []const Header,
    options: ParseOptions,
) Error!ParsedBody {
    const body: ParsedBody = parseBody(allocator, bytes, body_start, headers, options) catch |err| switch (err) {
        error.InvalidTransferEncoding => blk: {
            if (!try responseTransferEncodingIsCloseDelimited(headers)) return error.InvalidTransferEncoding;
            break :blk .{
                .framing = .close_delimited,
                .body = bytes[body_start..],
                .consumed = bytes.len,
            };
        },
        else => |e| return e,
    };
    if (body.framing == .none) return .{
        .framing = .close_delimited,
        .body = bytes[body_start..],
        .consumed = bytes.len,
    };
    return body;
}

pub fn bodyFraming(headers: []const Header) Error!BodyFraming {
    if (try transferEncodingFraming(headers)) |framing| return framing;
    if ((try contentLength(headers)) != null) return .content_length;
    return .none;
}

const RequestFraming = struct {
    body: BodyFraming,
    content_length: ?usize,
    must_close: bool,
};

fn requestFraming(headers: []const Header) Error!RequestFraming {
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var final_is_chunked = false;
    var saw_content_length = false;
    var content_length: ?usize = null;
    var content_length_error: ?Error = null;

    for (headers) |header| {
        if (header.eqlName("transfer-encoding")) {
            saw_transfer_encoding = true;
            try updateTransferEncodingFraming(
                header.value,
                &saw_chunked,
                &final_is_chunked,
            );
            continue;
        }
        if (!header.eqlName("content-length")) continue;
        saw_content_length = true;
        if (content_length_error != null) continue;
        content_length = parseContentLengthFieldValue(
            header.value,
            content_length,
        ) catch |err| {
            content_length_error = err;
            continue;
        };
    }

    if (saw_transfer_encoding) {
        if (!saw_chunked or !final_is_chunked) {
            return error.InvalidTransferEncoding;
        }
        return .{
            .body = .chunked,
            .content_length = null,
            .must_close = saw_content_length,
        };
    }
    if (content_length_error) |err| return err;
    return .{
        .body = if (content_length != null) .content_length else .none,
        .content_length = content_length,
        .must_close = false,
    };
}

pub fn contentLength(headers: []const Header) Error!?usize {
    var found: ?usize = null;
    for (headers) |header| {
        if (!header.eqlName("content-length")) continue;
        found = try parseContentLengthFieldValue(header.value, found);
    }
    return found;
}

fn parseContentLengthFieldValue(value: []const u8, previous: ?usize) Error!?usize {
    var found = previous;
    // HTTP field coalescing can turn repeated Content-Length fields into a
    // comma-separated list.  The message is only unambiguous when every decimal
    // value is byte-for-byte equivalent after OWS trimming.
    var parts = std.mem.splitScalar(u8, value, ',');
    while (parts.next()) |raw_part| {
        const part = wire.trimOws(raw_part);
        if (part.len == 0) return error.InvalidContentLength;
        for (part) |byte| {
            // Be stricter than std.fmt.parseInt: HTTP Content-Length is the
            // `1*DIGIT` grammar, so a leading '+' must be rejected instead of
            // being accepted by some numeric parsers and rejected by others.
            if (!std.ascii.isDigit(byte)) return error.InvalidContentLength;
        }
        const parsed = std.fmt.parseInt(usize, part, 10) catch |err| switch (err) {
            error.InvalidCharacter => return error.InvalidContentLength,
            error.Overflow => return error.ContentLengthOverflow,
        };
        if (found) |existing| {
            if (existing != parsed) return error.ConflictingContentLength;
        } else {
            found = parsed;
        }
    }
    return found;
}

fn transferEncodingFraming(headers: []const Header) Error!?BodyFraming {
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var final_is_chunked = false;

    for (headers) |header| {
        if (!header.eqlName("transfer-encoding")) continue;
        saw_transfer_encoding = true;
        try updateTransferEncodingFraming(
            header.value,
            &saw_chunked,
            &final_is_chunked,
        );
    }

    if (!saw_transfer_encoding) return null;
    if (!saw_chunked or !final_is_chunked) return error.InvalidTransferEncoding;
    return .chunked;
}

fn updateTransferEncodingFraming(
    value: []const u8,
    saw_chunked: *bool,
    final_is_chunked: *bool,
) Error!void {
    var state: @import("transfer_encoding.zig").State = .{ .saw_chunked = saw_chunked.*, .final_is_chunked = final_is_chunked.* };
    try state.feed(value);
    saw_chunked.* = state.saw_chunked;
    final_is_chunked.* = state.final_is_chunked;
}

const TransferCodingIterator = @import("transfer_encoding.zig").Iterator;
const skipTransferOws = @import("transfer_encoding.zig").skipOws;

fn consumeQuotedString(
    value: []const u8,
    pos: *usize,
    comptime invalid: Error,
) Error!void {
    std.debug.assert(pos.* < value.len and value[pos.*] == '"');
    pos.* += 1;
    while (pos.* < value.len) {
        const byte = value[pos.*];
        pos.* += 1;
        if (byte == '"') return;
        if (byte == '\\') {
            if (pos.* == value.len) return invalid;
            const escaped = value[pos.*];
            if (!(escaped == '\t' or
                (escaped >= 0x20 and escaped <= 0x7e) or
                escaped >= 0x80))
            {
                return invalid;
            }
            pos.* += 1;
            continue;
        }
        if (!(byte == '\t' or
            byte == ' ' or
            byte == 0x21 or
            (byte >= 0x23 and byte <= 0x5b) or
            (byte >= 0x5d and byte <= 0x7e) or
            byte >= 0x80))
        {
            return invalid;
        }
    }
    return invalid;
}

pub fn responseTransferEncodingIsCloseDelimited(headers: []const Header) Error!bool {
    var saw_transfer_encoding = false;
    var saw_chunked = false;
    var final_is_chunked = false;
    for (headers) |header| {
        if (!header.eqlName("transfer-encoding")) continue;
        saw_transfer_encoding = true;
        try updateTransferEncodingFraming(
            header.value,
            &saw_chunked,
            &final_is_chunked,
        );
    }
    return saw_transfer_encoding and !final_is_chunked;
}

pub fn statusCodeForbidsBody(status: u16) bool {
    return (status >= 100 and status < 200) or status == 204 or status == 304;
}

const TeHeaderState = struct {
    present: bool = false,
    accepts_trailers: bool = false,
};

fn parseTeHeaders(headers: []const Header) Error!TeHeaderState {
    var state: TeHeaderState = .{};
    for (headers) |header| {
        if (!header.eqlName("te")) continue;
        state.present = true;
        if (wire.trimOws(header.value).len == 0) continue;
        var codings = TransferCodingIterator{ .value = header.value };
        while (try codings.next()) |coding| {
            if (std.ascii.eqlIgnoreCase(coding.name, "chunked")) {
                return error.InvalidTransferEncoding;
            }
            if (std.ascii.eqlIgnoreCase(coding.name, "trailers")) {
                if (coding.has_parameters) {
                    return error.InvalidTransferEncoding;
                }
                state.accepts_trailers = true;
            }
        }
    }
    return state;
}

fn connectionOptionPresent(
    headers: []const Header,
    expected: []const u8,
) Error!bool {
    var found = false;
    for (headers) |header| {
        if (!header.eqlName("connection")) continue;
        var options = std.mem.splitScalar(u8, header.value, ',');
        while (options.next()) |raw_option| {
            const option = wire.trimOws(raw_option);
            validateHeaderName(option) catch {
                return error.InvalidConnection;
            };
            if (std.ascii.eqlIgnoreCase(option, expected)) found = true;
        }
    }
    return found;
}

/// Validate the HTTP/1 request-only TE field before serialization. RFC 9112
/// reserves `chunked` as always acceptable and RFC 9110 requires the hop-by-hop
/// field to be named by a Connection option.
pub fn validateRequestTeForWrite(
    version: Version,
    headers: []const Header,
) Error!void {
    const state = try parseTeHeaders(headers);
    if (!state.present) return;
    if (version != .http_1_1) return error.InvalidTransferEncoding;
    if (!try connectionOptionPresent(headers, "te")) {
        return error.InvalidTransferEncoding;
    }
}

fn validateUpgradeValue(value: []const u8) Error!void {
    var protocols = std.mem.splitScalar(u8, value, ',');
    while (protocols.next()) |raw_protocol| {
        const protocol = wire.trimOws(raw_protocol);
        const slash = std.mem.indexOfScalar(u8, protocol, '/');
        if (slash) |index| {
            if (index == 0 or index + 1 == protocol.len or
                std.mem.indexOfScalar(u8, protocol[index + 1 ..], '/') != null)
            {
                return error.InvalidConnection;
            }
            validateHeaderName(protocol[0..index]) catch {
                return error.InvalidConnection;
            };
            validateHeaderName(protocol[index + 1 ..]) catch {
                return error.InvalidConnection;
            };
        } else {
            validateHeaderName(protocol) catch {
                return error.InvalidConnection;
            };
        }
    }
}

fn connectionOptionIsCritical(option: []const u8) bool {
    return std.ascii.eqlIgnoreCase(option, "connection") or
        std.ascii.eqlIgnoreCase(option, "content-length") or
        std.ascii.eqlIgnoreCase(option, "host") or
        std.ascii.eqlIgnoreCase(option, "trailer") or
        std.ascii.eqlIgnoreCase(option, "transfer-encoding");
}

/// Validate sender-side Connection options and Upgrade coupling. Routing and
/// message-framing fields cannot become hop-by-hop because an intermediary
/// removing them would cause the next recipient to interpret different bytes.
pub fn validateConnectionHeadersForWrite(
    version: Version,
    headers: []const Header,
) Error!void {
    var has_upgrade_option = false;
    var has_upgrade = false;
    for (headers) |header| {
        if (header.eqlName("upgrade")) {
            has_upgrade = true;
            try validateUpgradeValue(header.value);
            continue;
        }
        if (!header.eqlName("connection")) continue;
        var options = std.mem.splitScalar(u8, header.value, ',');
        while (options.next()) |raw_option| {
            const option = wire.trimOws(raw_option);
            validateHeaderName(option) catch {
                return error.InvalidConnection;
            };
            if (connectionOptionIsCritical(option)) {
                return error.InvalidConnection;
            }
            if (std.ascii.eqlIgnoreCase(option, "upgrade")) {
                has_upgrade_option = true;
            }
        }
    }
    if (has_upgrade and
        (version != .http_1_1 or !has_upgrade_option))
    {
        return error.InvalidConnection;
    }
}

/// A 101 response only has meaning when it selects a protocol through Upgrade.
pub fn validateResponseUpgradeForWrite(
    status: u16,
    headers: []const Header,
) Error!void {
    if (status == 101 and !hasHeaderNamed(headers, "upgrade")) {
        return error.InvalidResponse;
    }
}

/// TE advertises request-side response capabilities and is never a response
/// field, regardless of HTTP/1.x version.
pub fn validateResponseTeForWrite(headers: []const Header) Error!void {
    if (hasHeaderNamed(headers, "te")) {
        return error.InvalidTransferEncoding;
    }
}

const ExpectHeaderState = struct {
    present: bool = false,
    member_count: usize = 0,
    continue_count: usize = 0,
};

fn consumeExpectTokenOrQuoted(
    value: []const u8,
    pos: *usize,
) Error!void {
    if (pos.* == value.len) return error.InvalidExpectation;
    if (value[pos.*] == '"') {
        consumeQuotedString(value, pos, error.InvalidExpectation) catch {
            return error.InvalidExpectation;
        };
        return;
    }
    const start = pos.*;
    while (pos.* < value.len and validHeaderNameByte(value[pos.*])) {
        pos.* += 1;
    }
    if (pos.* == start) return error.InvalidExpectation;
}

fn parseExpectHeaders(headers: []const Header) Error!ExpectHeaderState {
    var state: ExpectHeaderState = .{};
    for (headers) |header| {
        if (!header.eqlName("expect")) continue;
        state.present = true;
        var pos: usize = 0;
        while (true) {
            skipTransferOws(header.value, &pos);
            const name_start = pos;
            while (pos < header.value.len and
                validHeaderNameByte(header.value[pos]))
            {
                pos += 1;
            }
            if (pos == name_start) return error.InvalidExpectation;
            const name = header.value[name_start..pos];
            state.member_count = std.math.add(
                usize,
                state.member_count,
                1,
            ) catch return error.InvalidExpectation;
            skipTransferOws(header.value, &pos);

            var has_value_or_parameters = false;
            if (pos < header.value.len and header.value[pos] == '=') {
                has_value_or_parameters = true;
                pos += 1;
                skipTransferOws(header.value, &pos);
                try consumeExpectTokenOrQuoted(header.value, &pos);
                skipTransferOws(header.value, &pos);
                while (pos < header.value.len and header.value[pos] == ';') {
                    pos += 1;
                    skipTransferOws(header.value, &pos);
                    const parameter_start = pos;
                    while (pos < header.value.len and
                        validHeaderNameByte(header.value[pos]))
                    {
                        pos += 1;
                    }
                    if (pos == parameter_start) {
                        return error.InvalidExpectation;
                    }
                    skipTransferOws(header.value, &pos);
                    if (pos == header.value.len or header.value[pos] != '=') {
                        return error.InvalidExpectation;
                    }
                    pos += 1;
                    skipTransferOws(header.value, &pos);
                    try consumeExpectTokenOrQuoted(header.value, &pos);
                    skipTransferOws(header.value, &pos);
                }
            }

            if (std.ascii.eqlIgnoreCase(name, "100-continue")) {
                if (has_value_or_parameters) {
                    return error.InvalidExpectation;
                }
                state.continue_count = std.math.add(
                    usize,
                    state.continue_count,
                    1,
                ) catch return error.InvalidExpectation;
            }
            if (pos == header.value.len) break;
            if (header.value[pos] != ',') {
                return error.InvalidExpectation;
            }
            pos += 1;
        }
    }
    return state;
}

/// Validate the only standardized expectation that affects the HTTP/1 write
/// state machine. Unknown but well-formed extension expectations remain
/// available for applications and can receive a 417 response from the peer.
pub fn validateRequestExpectForWrite(
    version: Version,
    headers: []const Header,
    has_content: bool,
) Error!void {
    const state = try parseExpectHeaders(headers);
    if (state.continue_count == 0) return;
    if (state.continue_count != 1 or state.member_count != 1 or
        version != .http_1_1 or !has_content)
    {
        return error.InvalidExpectation;
    }
}

pub fn validateResponseExpectForWrite(headers: []const Header) Error!void {
    if (hasHeaderNamed(headers, "expect")) {
        return error.InvalidExpectation;
    }
}

pub fn validateResponseBodyForStatus(status: u16, headers: []const Header, body: []const u8, trailers: []const Header) Error!void {
    try validateStatusCode(status);
    if (!statusCodeForbidsBody(status)) return;
    if (body.len != 0 or trailers.len != 0) return error.InvalidContentLength;
    const declared_content_length = try contentLength(headers);
    if (status != 304) {
        for (headers) |header| {
            if (header.eqlName("transfer-encoding")) {
                return error.InvalidTransferEncoding;
            }
        }
    }
    // A 304 may carry Content-Length or Transfer-Encoding to describe the
    // selected representation. 1xx and 204 permit neither field.
    if (status != 304 and declared_content_length != null) return error.InvalidContentLength;
}

pub fn validateOutgoingResponseBodyForStatus(status: u16, headers: []const Header, body: []const u8, trailers: []const Header) Error!void {
    try validateResponseBodyForStatus(status, headers, body, trailers);
    // RFC 9110 Section 15.3.6 forbids a server from generating content in a
    // 205 response. Unlike 1xx/204/304, however, RFC 9112 does not make 205
    // intrinsically bodyless for message framing. Keep this sender-only check
    // separate so recipients still consume a peer's framed content.
    if (status != 205) return;
    if (body.len != 0) return error.InvalidContentLength;
    if (try contentLength(headers)) |declared| {
        if (declared != 0) return error.InvalidContentLength;
    }
}

/// CONNECT request content has no generally defined semantics. RFC 9110
/// therefore forbids both length delimiters and transfer codings instead of
/// allowing even an apparently empty framed body onto a persistent connection.
pub fn validateOutgoingRequestBodyForMethod(
    method: Method,
    headers: []const Header,
    body: []const u8,
    trailers: []const Header,
) Error!void {
    try validateOutgoingRequestFramingForMethod(
        method,
        headers,
        body.len,
        trailers.len != 0,
    );
}

/// Validate request-method constraints when only the prospective body length
/// is known. A null length is safe for TRACE because its streaming writer is
/// fixed to zero and will reject later body bytes.
pub fn validateOutgoingRequestFramingForMethod(
    method: Method,
    headers: []const Header,
    body_length: ?usize,
    has_trailers: bool,
) Error!void {
    switch (method) {
        .CONNECT => {
            if ((try contentLength(headers)) != null) {
                return error.InvalidContentLength;
            }
            if (hasHeaderNamed(headers, "transfer-encoding")) {
                return error.InvalidTransferEncoding;
            }
            if (hasHeaderNamed(headers, "trailer") or has_trailers) {
                return error.InvalidTrailer;
            }
            if ((body_length orelse 0) != 0) {
                return error.InvalidContentLength;
            }
        },
        .TRACE => {
            if (hasHeaderNamed(headers, "transfer-encoding")) {
                return error.InvalidTransferEncoding;
            }
            if (hasHeaderNamed(headers, "trailer") or has_trailers) {
                return error.InvalidTrailer;
            }
            if (try contentLength(headers)) |declared| {
                if (declared != 0) return error.InvalidContentLength;
            }
            if ((body_length orelse 0) != 0) {
                return error.InvalidContentLength;
            }
        },
        else => {},
    }
}

const responseForbidsBody = response_framing.forbidsBody;

pub fn writeRequest(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    method: Method,
    target: []const u8,
    version: Version,
    headers: []const Header,
    body: []const u8,
) !void {
    try validateRequestForWrite(method, target, version, headers, body);
    try list.ensureUnusedCapacity(allocator, try requestWireLen(method, target, version, headers, body));
    try list.appendSlice(allocator, method.string());
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, target);
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, version.string());
    try list.appendSlice(allocator, "\r\n");
    try writeHeaders(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

pub fn writeRequestChecked(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    method: Method,
    target: []const u8,
    version: Version,
    headers: []const Header,
    body: []const u8,
) Error!void {
    try validateRequestForWrite(method, target, version, headers, body);
    try list.ensureUnusedCapacity(allocator, try requestWireLen(method, target, version, headers, body));
    try list.appendSlice(allocator, method.string());
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, target);
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, version.string());
    try list.appendSlice(allocator, "\r\n");
    try writeHeadersChecked(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

fn validateRequestForWrite(
    method: Method,
    target: []const u8,
    version: Version,
    headers: []const Header,
    body: []const u8,
) Error!void {
    try validateRequestTargetForMethod(method, target);
    early_data.validateOutboundRequestHeaders(headers) catch
        return error.MalformedHeader;
    try validateConnectionHeadersForWrite(version, headers);
    try validateRequestTeForWrite(version, headers);
    try validateRequestHostParts(method, version, target, headers);
    try validateOutgoingRequestBodyForMethod(
        method,
        headers,
        body,
        &.{},
    );
    const framing = try requestFraming(headers);
    if (framing.must_close) return error.InvalidContentLength;
    const has_trailer_declaration = hasHeaderNamed(headers, "trailer");
    try validateTrailerDeclarations(headers, &.{});
    if (has_trailer_declaration and framing.body != .chunked) {
        return error.InvalidTrailer;
    }
    const has_content = switch (framing.body) {
        .none => blk: {
            if (body.len != 0) return error.InvalidContentLength;
            break :blk false;
        },
        .content_length => blk: {
            if (framing.content_length.? != body.len) {
                return error.InvalidContentLength;
            }
            break :blk body.len != 0;
        },
        // This low-level serializer accepts an already transfer-coded body.
        // Callers that have unencoded chunks should use the runtime writer or
        // `encodeChunked` first.
        .chunked => (try validateChunkedBodyForWrite(body, headers)) != 0,
        .close_delimited => unreachable,
    };
    try validateRequestExpectForWrite(version, headers, has_content);
}

fn requestWireLen(method: Method, target: []const u8, version: Version, headers: []const Header, body: []const u8) Error!usize {
    var len = method.string().len;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, target.len) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, version.string().len) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, try headerBlockWireLen(headers)) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    return std.math.add(usize, len, body.len) catch return error.RenderBufferTooSmall;
}

pub fn writeResponse(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,
    body: []const u8,
) !void {
    try validateResponseForWrite(version, status, reason, headers, body);
    try list.ensureUnusedCapacity(allocator, try responseWireLen(version, status, reason, headers, body));
    try list.appendSlice(allocator, version.string());
    try list.append(allocator, ' ');
    try appendDecimal(list, allocator, status);
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, reason);
    try list.appendSlice(allocator, "\r\n");
    try writeHeaders(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

pub fn writeResponseChecked(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,
    body: []const u8,
) Error!void {
    try validateResponseForWrite(version, status, reason, headers, body);
    try list.ensureUnusedCapacity(allocator, try responseWireLen(version, status, reason, headers, body));
    try list.appendSlice(allocator, version.string());
    try list.append(allocator, ' ');
    try appendDecimalChecked(list, allocator, status);
    try list.append(allocator, ' ');
    try list.appendSlice(allocator, reason);
    try list.appendSlice(allocator, "\r\n");
    try writeHeadersChecked(list, allocator, headers);
    try list.appendSlice(allocator, "\r\n");
    try list.appendSlice(allocator, body);
}

fn validateResponseForWrite(
    version: Version,
    status: u16,
    reason: []const u8,
    headers: []const Header,
    body: []const u8,
) Error!void {
    try validateReasonPhrase(reason);
    try validateStatusCode(status);
    try validateConnectionHeadersForWrite(version, headers);
    try validateResponseTeForWrite(headers);
    try validateResponseExpectForWrite(headers);
    try validateResponseUpgradeForWrite(status, headers);
    early_data.validateForbiddenFields(headers) catch
        return error.InvalidResponse;
    try validateOutgoingResponseBodyForStatus(status, headers, body, &.{});
    const has_transfer_encoding = hasHeaderNamed(
        headers,
        "transfer-encoding",
    );
    const has_trailer_declaration = hasHeaderNamed(headers, "trailer");
    try validateTrailerDeclarations(headers, &.{});
    const declared_content_length = try contentLength(headers);
    if (has_transfer_encoding) {
        const close_delimited = try responseTransferEncodingIsCloseDelimited(
            headers,
        );
        if (declared_content_length != null) {
            return error.InvalidContentLength;
        }
        if (has_trailer_declaration and close_delimited) {
            return error.InvalidTrailer;
        }
        // An empty representation can be metadata for a HEAD response (and a
        // 304 is already constrained to empty above). For an emitted body,
        // however, a final chunked coding must contain exactly one complete
        // chunked wire body so no suffix can be interpreted as another message.
        if (!close_delimited and body.len != 0) {
            _ = try validateChunkedBodyForWrite(body, headers);
        }
    } else {
        if (has_trailer_declaration) return error.InvalidTrailer;
        if (body.len == 0) return;
        if (declared_content_length) |declared| {
            if (declared != body.len) return error.InvalidContentLength;
        }
    }
}

fn responseWireLen(version: Version, status: u16, reason: []const u8, headers: []const Header, body: []const u8) Error!usize {
    var len = version.string().len;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, decimalDigitLen(status)) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 1) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, reason.len) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, try headerBlockWireLen(headers)) catch return error.RenderBufferTooSmall;
    len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    return std.math.add(usize, len, body.len) catch return error.RenderBufferTooSmall;
}

fn decimalDigitLen(value: u16) usize {
    if (value >= 1000) return 4;
    if (value >= 100) return 3;
    if (value >= 10) return 2;
    return 1;
}

fn writeHeaders(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) !void {
    try writeHeadersDirect(list, allocator, headers);
}

fn writeHeadersChecked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) Error!void {
    try writeHeadersDirect(list, allocator, headers);
}

fn writeHeadersDirect(list: *std.ArrayList(u8), allocator: std.mem.Allocator, headers: []const Header) Error!void {
    const len = try headerBlockWireLen(headers);

    const start = list.items.len;
    try list.ensureUnusedCapacity(allocator, len);
    list.items.len = start + len;
    var pos = start;
    for (headers) |header| {
        @memcpy(list.items[pos..][0..header.name.len], header.name);
        pos += header.name.len;
        @memcpy(list.items[pos..][0..2], ": ");
        pos += 2;
        @memcpy(list.items[pos..][0..header.value.len], header.value);
        pos += header.value.len;
        @memcpy(list.items[pos..][0..2], "\r\n");
        pos += 2;
    }
}

fn headerBlockWireLen(headers: []const Header) Error!usize {
    var len: usize = 0;
    for (headers) |header| {
        try validateHeader(header);
        len = std.math.add(usize, len, header.name.len) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, header.value.len) catch return error.RenderBufferTooSmall;
        len = std.math.add(usize, len, 2) catch return error.RenderBufferTooSmall;
    }
    return len;
}

fn appendDecimal(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) !void {
    var tmp: [32]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&tmp, "{}", .{value});
    try list.appendSlice(allocator, rendered);
}

fn appendDecimalChecked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: anytype) Error!void {
    var tmp: [32]u8 = undefined;
    const rendered = std.fmt.bufPrint(&tmp, "{}", .{value}) catch return error.RenderBufferTooSmall;
    try list.appendSlice(allocator, rendered);
}

pub fn validateHeader(header: Header) Error!void {
    try validateHeaderName(header.name);
    try validateHeaderValue(header.value);
}

pub fn validateRequestTarget(target: []const u8) Error!void {
    if (target.len == 0) return error.MalformedStartLine;
    for (target) |byte| {
        // The request target is a single start-line token.  Rejecting SP/HTAB
        // and all control bytes prevents request-smuggling/start-line injection
        // while still allowing UTF-8/opaque octets that many origin-form paths
        // carry in practice.  URI fragments are never sent in HTTP requests;
        // clients such as hyper strip them before serialization, so reject raw
        // '#' here to avoid origin/proxy disagreement.
        if (byte <= 0x20 or byte == 0x7f or byte == '#') return error.MalformedStartLine;
    }
}

pub fn validateRequestTargetForMethod(method: Method, target: []const u8) Error!void {
    try method.validate();
    switch (method) {
        .CONNECT => try validateConnectTarget(target),
        .OPTIONS => {
            try validateRequestTarget(target);
            if (std.mem.eql(u8, target, "*")) return;
            try validateOriginOrAbsoluteFormTarget(target);
        },
        else => {
            try validateRequestTarget(target);
            if (std.mem.eql(u8, target, "*")) return error.MalformedStartLine;
            try validateOriginOrAbsoluteFormTarget(target);
        },
    }
}

fn validateOriginOrAbsoluteFormTarget(target: []const u8) Error!void {
    if (target[0] == '/') return;
    if (absoluteFormAuthority(target) != null) return;
    return error.MalformedStartLine;
}

pub fn validateConnectTarget(target: []const u8) Error!void {
    try validateRequestTarget(target);
    if (target[0] == '/' or target[0] == '*' or std.mem.indexOf(u8, target, "://") != null) return error.MalformedStartLine;
    try validateAuthorityForbiddenDelimiters(target, error.MalformedStartLine);

    const port: []const u8 = if (target[0] == '[') blk: {
        const end = std.mem.indexOfScalar(u8, target, ']') orelse return error.MalformedStartLine;
        if (end <= 1 or end + 2 > target.len or target[end + 1] != ':') return error.MalformedStartLine;
        break :blk target[end + 2 ..];
    } else blk: {
        if (std.mem.indexOfScalar(u8, target, '[') != null or std.mem.indexOfScalar(u8, target, ']') != null) return error.MalformedStartLine;
        const colon = std.mem.lastIndexOfScalar(u8, target, ':') orelse return error.MalformedStartLine;
        if (colon == 0 or colon + 1 >= target.len) return error.MalformedStartLine;
        // Unbracketed IPv6 is ambiguous in authority-form; require RFC 3986
        // bracket syntax so the final colon is unambiguously the port separator.
        if (std.mem.indexOfScalar(u8, target[0..colon], ':') != null) return error.MalformedStartLine;
        break :blk target[colon + 1 ..];
    };

    try validateAuthorityPort(port, error.MalformedStartLine);
}

pub fn validateRequestHost(request: Request) Error!void {
    try validateRequestHostParts(
        request.method,
        request.version,
        request.target,
        request.headers,
    );
}

fn validateRequestHostParts(
    method: Method,
    version: Version,
    target: []const u8,
    headers: []const Header,
) Error!void {
    const host = try validateHostHeaderBlockValue(version, headers);
    const target_authority = if (method == .CONNECT)
        target
    else
        absoluteFormAuthority(target) orelse return;
    try validateHostValue(target_authority);
    if (host) |host_value| {
        const normalized_host = wire.trimOws(host_value);
        if (std.ascii.eqlIgnoreCase(normalized_host, target_authority)) return;
        if (method == .CONNECT and std.ascii.eqlIgnoreCase(
            normalized_host,
            connectTargetHost(target_authority),
        )) return;
        return error.InvalidHost;
    }
}

fn normalizeParsedRequestHostParts(
    method: Method,
    version: Version,
    target: []const u8,
    headers: []Header,
) Error!void {
    const host_index = try validateHostHeaderBlockIndex(version, headers);
    const absolute_authority = if (method == .CONNECT)
        null
    else
        absoluteFormAuthority(target);
    const target_authority = if (method == .CONNECT)
        target
    else
        absolute_authority orelse return;
    try validateHostValue(target_authority);

    if (method == .CONNECT or absolute_authority != null) {
        // RFC 9112 sections 3.2.2, 3.2.3, and 3.3 make the request-target
        // authority authoritative for absolute-form and CONNECT requests.
        // Rebinding only the descriptor preserves zero-copy parsing while
        // preventing downstream routing from observing a conflicting Host.
        if (host_index) |index| headers[index].value = target_authority;
        return;
    }
}

fn connectTargetHost(authority: []const u8) []const u8 {
    if (authority[0] == '[') {
        const closing = std.mem.indexOfScalar(u8, authority, ']') orelse
            unreachable;
        return authority[0 .. closing + 1];
    }
    const colon = std.mem.lastIndexOfScalar(u8, authority, ':') orelse
        unreachable;
    return authority[0..colon];
}

pub fn validateHostHeaderBlock(version: Version, headers: []const Header) Error!void {
    _ = try validateHostHeaderBlockValue(version, headers);
}

fn validateHostHeaderBlockValue(version: Version, headers: []const Header) Error!?[]const u8 {
    const index = try validateHostHeaderBlockIndex(version, headers);
    return if (index) |value| headers[value].value else null;
}

fn validateHostHeaderBlockIndex(
    version: Version,
    headers: []const Header,
) Error!?usize {
    var found_index: ?usize = null;
    for (headers, 0..) |header, index| {
        if (!header.eqlName("host")) continue;
        if (found_index != null) return error.InvalidHost;
        found_index = index;
        try validateHostValue(header.value);
    }
    if (version == .http_1_1 and found_index == null) return error.InvalidHost;
    return found_index;
}

pub fn absoluteFormAuthority(target: []const u8) ?[]const u8 {
    if (target.len == 0 or !std.ascii.isAlphabetic(target[0])) return null;
    const scheme_end = std.mem.indexOf(u8, target, "://") orelse return null;
    if (!validUriScheme(target[0..scheme_end])) return null;
    const authority_start = scheme_end + 3;
    if (authority_start >= target.len) return null;
    const rest = target[authority_start..];
    const authority_end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    if (authority_end == 0) return null;
    const authority = rest[0..authority_end];
    if (std.mem.indexOfScalar(u8, authority, '@') != null) return null;
    return authority;
}

fn validUriScheme(scheme: []const u8) bool {
    if (scheme.len == 0 or !std.ascii.isAlphabetic(scheme[0])) return false;
    for (scheme[1..]) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '+' or byte == '-' or byte == '.')) return false;
    }
    return true;
}

pub fn validateHostValue(raw_host: []const u8) Error!void {
    const host = wire.trimOws(raw_host);
    if (host.len == 0) return error.InvalidHost;

    const bracketed = host[0] == '[';
    var closing_bracket: ?usize = null;
    var port_colon: ?usize = null;
    for (host, 0..) |byte, index| {
        if (!host_special_bytes[byte]) continue;
        switch (byte) {
            '[' => if (!bracketed) return error.InvalidHost,
            ']' => {
                if (!bracketed) return error.InvalidHost;
                if (closing_bracket == null) closing_bracket = index;
            },
            ':' => if (!bracketed) {
                if (port_colon != null) return error.InvalidHost;
                port_colon = index;
            },
            else => return error.InvalidHost,
        }
    }

    const port: ?[]const u8 = if (bracketed) blk: {
        const end = closing_bracket orelse return error.InvalidHost;
        if (end <= 1) return error.InvalidHost;
        if (end + 1 == host.len) break :blk null;
        if (host[end + 1] != ':' or end + 2 >= host.len) return error.InvalidHost;
        break :blk host[end + 2 ..];
    } else blk: {
        const colon = port_colon orelse break :blk null;
        if (colon == 0 or colon + 1 >= host.len) return error.InvalidHost;
        break :blk host[colon + 1 ..];
    };

    if (port) |value| try validateAuthorityPort(value, error.InvalidHost);
}

fn validateAuthorityForbiddenDelimiters(authority: []const u8, comptime err: Error) Error!void {
    for (authority) |byte| {
        // Authority-form is a host[:port] component, not a complete URI or a
        // comma-list.  Hyper and Go's HTTP stacks keep this surface strict
        // because userinfo/path/query/fragment/list delimiters are common
        // sources of proxy/origin disagreement and CONNECT request smuggling.
        if (byte <= 0x20 or byte == 0x7f or byte == ',' or byte == '/' or byte == '\\' or byte == '?' or byte == '#' or byte == '@') return err;
    }
}

fn validateAuthorityPort(port: []const u8, comptime err: Error) Error!void {
    if (port.len == 0) return err;
    for (port) |byte| {
        if (!std.ascii.isDigit(byte)) return err;
    }
    const parsed_port = std.fmt.parseInt(u32, port, 10) catch return err;
    if (parsed_port > std.math.maxInt(u16)) return err;
}

pub fn validateReasonPhrase(reason: []const u8) Error!void {
    for (reason) |byte| {
        // RFC reason-phrases are human-readable text after the status code.
        // They may contain SP/HTAB and obs-text, but never CR/LF or other
        // controls that could append forged fields to the response head.
        if (field_value.invalidByte(byte)) return error.MalformedStartLine;
    }
}

pub fn validateStatusCode(status: u16) Error!void {
    if (status < 100 or status > 999) return error.InvalidStatus;
}

fn parseStatusCode(status_s: []const u8) Error!u16 {
    if (status_s.len != 3) return error.InvalidStatus;
    const status = std.fmt.parseInt(u16, status_s, 10) catch return error.InvalidStatus;
    try validateStatusCode(status);
    return status;
}

pub fn validateHeaderName(name: []const u8) Error!void {
    if (name.len == 0) return error.MalformedHeader;
    for (name) |byte| {
        if (!validHeaderNameByte(byte)) return error.MalformedHeader;
    }
}

pub fn validateHeaderValue(value: []const u8) Error!void {
    for (value) |byte| {
        if (field_value.invalidByte(byte)) return error.MalformedHeader;
    }
}

const valid_header_name_bytes: [256]bool = blk: {
    var table = [_]bool{false} ** 256;
    for ('0'..'9' + 1) |byte| table[byte] = true;
    for ('A'..'Z' + 1) |byte| table[byte] = true;
    for ('a'..'z' + 1) |byte| table[byte] = true;
    for ("!#$%&'*+-.^_`|~") |byte| table[byte] = true;
    break :blk table;
};

pub inline fn validHeaderNameByte(byte: u8) bool {
    return valid_header_name_bytes[byte];
}

/// Bytes that need special handling in a Host value: the forbidden delimiters
/// plus '[', ']' and ':'. Every other byte is a plain host character, so the
/// common case costs one table lookup instead of eight comparisons.
const host_special_bytes: [256]bool = blk: {
    var table = [_]bool{false} ** 256;
    for (0..0x21) |byte| table[byte] = true;
    table[0x7f] = true;
    for (",/\\?#@[]:") |byte| table[byte] = true;
    break :blk table;
};

pub fn encodeChunked(list: *std.ArrayList(u8), allocator: std.mem.Allocator, chunks: []const []const u8, trailers: []const Header) !void {
    try validateTrailers(trailers);
    if (chunks.len == 0 and trailers.len == 0) {
        try list.appendSlice(allocator, "0\r\n\r\n");
        return;
    }
    var encoded_len: usize = 0;
    for (chunks) |chunk| {
        // A zero-sized chunk terminates the transfer coding. Empty application
        // slices therefore contribute no wire bytes; the one terminator below
        // remains the only zero-sized chunk in the message.
        if (chunk.len == 0) continue;
        encoded_len = std.math.add(usize, encoded_len, hexDigitLen(chunk.len)) catch return error.RenderBufferTooSmall;
        encoded_len = std.math.add(usize, encoded_len, 2) catch return error.RenderBufferTooSmall;
        encoded_len = std.math.add(usize, encoded_len, chunk.len) catch return error.RenderBufferTooSmall;
        encoded_len = std.math.add(usize, encoded_len, 2) catch return error.RenderBufferTooSmall;
    }
    encoded_len = std.math.add(usize, encoded_len, "0\r\n".len) catch return error.RenderBufferTooSmall;
    encoded_len = std.math.add(usize, encoded_len, try headerBlockWireLen(trailers)) catch return error.RenderBufferTooSmall;
    encoded_len = std.math.add(usize, encoded_len, 2) catch return error.RenderBufferTooSmall;
    try list.ensureUnusedCapacity(allocator, encoded_len);
    for (chunks) |chunk| {
        if (chunk.len == 0) continue;
        var tmp: [32]u8 = undefined;
        const rendered = try std.fmt.bufPrint(&tmp, "{x}\r\n", .{chunk.len});
        try list.appendSlice(allocator, rendered);
        try list.appendSlice(allocator, chunk);
        try list.appendSlice(allocator, "\r\n");
    }
    try list.appendSlice(allocator, "0\r\n");
    try writeHeaders(list, allocator, trailers);
    try list.appendSlice(allocator, "\r\n");
}

const hexDigitLen = chunk_size.hexDigitLen;

pub const DecodedChunked = struct {
    body: []u8,
    trailers: []Header,
    trailer_value_storage: [][]u8 = &.{},
    consumed: usize,

    pub fn deinit(self: *DecodedChunked, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
        freeHeaderValueStorage(allocator, self.trailer_value_storage);
        allocator.free(self.trailers);
        self.* = undefined;
    }
};

const ChunkedBodyScan = struct {
    body_len: usize,
    trailer_start: usize,
};

const ChunkedWireLayout = struct {
    body_len: usize,
    trailer_start: usize,
    trailer_fields_end: usize,
    consumed: usize,
};

fn scanChunkedBody(bytes: []const u8) Error!ChunkedBodyScan {
    var pos: usize = 0;
    var metadata: chunk_size.State = .{};
    var body_len: usize = 0;
    while (true) {
        const line_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n") orelse {
            try chunk_size.validateIncomplete(bytes[pos..]);
            return error.BufferTooShort;
        };
        const line = bytes[pos .. pos + line_end_rel];
        pos += line_end_rel + 2;
        const size = metadata.feed(line) catch |err| switch (err) {
            error.ChunkSizeOverheadTooLarge => return error.ChunkExtensionTooLarge,
            else => |other| return @errorCast(other),
        };
        const data_end = std.math.add(usize, pos, size) catch return error.ChunkSizeOverflow;
        const required_end = std.math.add(usize, data_end, 2) catch return error.ChunkSizeOverflow;
        if (bytes.len < required_end) return error.BufferTooShort;
        if (size == 0) return .{ .body_len = body_len, .trailer_start = pos };
        body_len = std.math.add(usize, body_len, size) catch return error.ChunkSizeOverflow;
        pos = data_end;
        if (!std.mem.eql(u8, bytes[pos .. pos + 2], "\r\n")) return error.InvalidChunk;
        pos += 2;
    }
}

fn scanChunkedWireBody(bytes: []const u8) Error!ChunkedWireLayout {
    const scan = try scanChunkedBody(bytes);
    const trailer_end_rel = std.mem.indexOf(
        u8,
        bytes[scan.trailer_start..],
        "\r\n",
    ) orelse return error.BufferTooShort;
    var trailer_fields_end = scan.trailer_start + trailer_end_rel;
    // A zero-length trailer block is the CRLF immediately following the zero
    // chunk. Otherwise consume fields through the first empty line.
    if (trailer_end_rel != 0) {
        const full_end_rel = std.mem.indexOf(
            u8,
            bytes[scan.trailer_start..],
            "\r\n\r\n",
        ) orelse return error.BufferTooShort;
        trailer_fields_end = scan.trailer_start + full_end_rel;
    }
    const consumed = if (trailer_end_rel == 0)
        scan.trailer_start + 2
    else
        trailer_fields_end + 4;
    return .{
        .body_len = scan.body_len,
        .trailer_start = scan.trailer_start,
        .trailer_fields_end = trailer_fields_end,
        .consumed = consumed,
    };
}

fn validateChunkedBodyForWrite(
    bytes: []const u8,
    headers: []const Header,
) Error!usize {
    const layout = try scanChunkedWireBody(bytes);
    if (layout.consumed != bytes.len) return error.InvalidChunk;
    const trailer_fields = bytes[layout.trailer_start..layout.trailer_fields_end];
    try validateTrailerFields(
        trailer_fields,
        .{ .max_headers = std.math.maxInt(usize) },
    );
    if (!hasHeaderNamed(headers, "trailer")) return layout.body_len;
    var lines = LineIterator.init(trailer_fields);
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const trailer = try parseHeaderLine(line, false);
        if (!trailerNameDeclared(headers, trailer.name)) {
            return error.InvalidTrailer;
        }
    }
    return layout.body_len;
}

fn copyChunkedBody(bytes: []const u8, out: []u8) Error!void {
    var pos: usize = 0;
    var out_pos: usize = 0;
    while (true) {
        const line_end_rel = std.mem.indexOf(u8, bytes[pos..], "\r\n") orelse return error.BufferTooShort;
        const line = bytes[pos .. pos + line_end_rel];
        pos += line_end_rel + 2;
        const semi = std.mem.indexOfScalar(u8, line, ';') orelse line.len;
        const size_part = try chunkSizePart(line[0..semi]);
        const size = try parseChunkSize(size_part);
        if (size == 0) return;
        const data_end = pos + size;
        @memcpy(out[out_pos..][0..size], bytes[pos..data_end]);
        out_pos += size;
        pos = data_end + 2;
    }
}

pub fn decodeChunked(allocator: std.mem.Allocator, bytes: []const u8, options: ParseOptions) Error!DecodedChunked {
    if (std.mem.startsWith(u8, bytes, "0\r\n\r\n")) {
        return .{
            .body = @constCast(&[_]u8{}),
            .trailers = @constCast(&[_]Header{}),
            .trailer_value_storage = @constCast(&[_][]u8{}),
            .consumed = "0\r\n\r\n".len,
        };
    }
    const layout = try scanChunkedWireBody(bytes);
    const body = if (layout.body_len == 0) @constCast(&[_]u8{}) else try allocator.alloc(u8, layout.body_len);
    errdefer if (layout.body_len != 0) allocator.free(body);
    try copyChunkedBody(bytes, body);

    if (layout.trailer_start == layout.trailer_fields_end) {
        return .{
            .body = body,
            .trailers = @constCast(&[_]Header{}),
            .trailer_value_storage = @constCast(&[_][]u8{}),
            .consumed = layout.consumed,
        };
    }

    var lines = LineIterator.init(
        bytes[layout.trailer_start..layout.trailer_fields_end],
    );
    // Response-only compatibility must never relax trailer field syntax.
    var parsed_trailers = try parseHeaderLines(
        allocator,
        &lines,
        options,
        .{},
    );
    errdefer parsed_trailers.deinit(allocator);
    try validateTrailers(parsed_trailers.headers);
    return .{
        .body = body,
        .trailers = parsed_trailers.headers,
        .trailer_value_storage = parsed_trailers.value_storage,
        .consumed = layout.consumed,
    };
}

fn freeHeaderValueStorage(allocator: std.mem.Allocator, storage: [][]u8) void {
    for (storage) |value| allocator.free(value);
    allocator.free(storage);
}

pub fn validateTrailers(trailers: []const Header) Error!void {
    for (trailers) |trailer| {
        try validateHeader(trailer);
        if (!validTrailerFieldName(trailer.name)) return error.InvalidTrailer;
    }
}

/// Validate every field-name advertised by repeated Trailer fields and, when
/// a declaration is present, require each supplied trailer to be announced.
/// A declaration may list fields that are ultimately omitted.
pub fn validateTrailerDeclarations(
    headers: []const Header,
    trailers: []const Header,
) Error!void {
    var has_declaration = false;
    for (headers) |header| {
        if (!header.eqlName("trailer")) continue;
        has_declaration = true;
        var names = std.mem.splitScalar(u8, header.value, ',');
        while (names.next()) |raw_name| {
            const name = wire.trimOws(raw_name);
            try validateHeaderName(name);
            if (!validTrailerFieldName(name)) return error.InvalidTrailer;
        }
    }
    try validateTrailers(trailers);
    if (!has_declaration) return;
    for (trailers) |trailer| {
        if (!trailerNameDeclared(headers, trailer.name)) {
            return error.InvalidTrailer;
        }
    }
}

fn trailerNameDeclared(
    headers: []const Header,
    name: []const u8,
) bool {
    for (headers) |header| {
        if (!header.eqlName("trailer")) continue;
        var names = std.mem.splitScalar(u8, header.value, ',');
        while (names.next()) |raw_name| {
            if (std.ascii.eqlIgnoreCase(wire.trimOws(raw_name), name)) {
                return true;
            }
        }
    }
    return false;
}

const chunkSizePart = chunk_size.sizePart;

pub fn parseChunkSize(raw_size: []const u8) Error!usize {
    if (raw_size.len == 0) return error.InvalidChunk;
    for (raw_size) |byte| {
        // RFC 9112 chunk-size is 1*HEXDIG.  std.fmt.parseInt would accept
        // leading '+', but wire parsers must not because peers and
        // intermediaries disagreeing here is a request-smuggling primitive.
        if (!std.ascii.isHex(byte)) return error.InvalidChunk;
    }
    return std.fmt.parseInt(usize, raw_size, 16) catch |err| switch (err) {
        error.InvalidCharacter => error.InvalidChunk,
        error.Overflow => error.ChunkSizeOverflow,
    };
}

fn validTrailerFieldName(name: []const u8) bool {
    // RFC 9110 section 6.5.1 defaults registered fields to header-only unless
    // their definitions opt into trailers. Keep known pre-content and
    // connection-control fields out, while allowing application extension
    // fields whose semantics are known only to the caller.
    return !(early_data.isHeaderName(name) or
        std.ascii.eqlIgnoreCase(name, "authorization") or
        std.ascii.eqlIgnoreCase(name, "cache-control") or
        std.ascii.eqlIgnoreCase(name, "connection") or
        std.ascii.eqlIgnoreCase(name, "content-encoding") or
        std.ascii.eqlIgnoreCase(name, "content-length") or
        std.ascii.eqlIgnoreCase(name, "content-range") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "host") or
        std.ascii.eqlIgnoreCase(name, "keep-alive") or
        std.ascii.eqlIgnoreCase(name, "max-forwards") or
        std.ascii.eqlIgnoreCase(name, "proxy-connection") or
        std.ascii.eqlIgnoreCase(name, "set-cookie") or
        std.ascii.eqlIgnoreCase(name, "trailer") or
        std.ascii.eqlIgnoreCase(name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(name, "te") or
        std.ascii.eqlIgnoreCase(name, "upgrade"));
}

test {
    _ = runtime;
    _ = @import("response_framing_tests.zig");
    _ = @import("head/tests.zig");
    _ = @import("head/folded_tests.zig");
}

test {
    _ = @import("tests.zig");
}

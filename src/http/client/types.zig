//! Public unified HTTP client types and ALPN policy.

const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2 = @import("../../http2/mod.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3 = @import("../../http3/mod.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const content_coding = @import("../content_coding.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const uri_redirect = @import("../../http1/runtime/redirect.zig");
const address_resolver = @import("../../internal/address_resolver.zig");
const tcp_connect = @import("../../internal/tcp_connect.zig");
const proxy_socks5 = @import("../../proxy/socks5.zig");

pub const Protocol = enum {
    http1,
    http2,
    http3,
};

pub const NegotiatedProtocol = enum {
    http1,
    http2,
};

pub const ProtocolPolicy = enum {
    prefer_http2,
    http1_only,
    http2_only,
};

pub const CleartextProtocol = enum {
    http1,
    http2_prior_knowledge,
};

pub const AddressResolver = address_resolver.Resolver;
pub const AddressConnectPolicy = tcp_connect.AddressConnectPolicy;
pub const HappyEyeballsOptions = tcp_connect.HappyEyeballsOptions;
pub const Socks5Options = proxy_socks5.Options;

pub const Socks5Proxy = struct {
    host: []const u8,
    port: u16 = 1080,
    options: Socks5Options = .{},
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
    never_indexed: bool = false,
};

pub const RequestOptions = struct {
    method: []const u8 = "GET",
    headers: []const Header = &.{},
    body: []const u8 = &.{},
    trailers: []const Header = &.{},
    /// Permit an explicitly configured HTTP/3 pool to use 0-RTT for this
    /// request. HTTP/1, HTTP/2, and reused HTTP/3 connections ignore it.
    allow_early_data: bool = true,
};

pub const RedirectOptions = struct {
    policy: uri_redirect.Policy = .{},
};

pub const Options = struct {
    protocol_policy: ProtocolPolicy = .prefer_http2,
    cleartext_protocol: CleartextProtocol = .http1,
    /// Permit an authenticated HTTPS peer that omits ALPN to use HTTP/1.1.
    /// This is ignored by `.http2_only`.
    allow_http1_without_alpn: bool = true,
    connect_timeout: ?std.Io.Duration = null,
    /// Optional resolver shared by standalone and pooled TCP connections.
    /// Literal IP URI hosts bypass it. Returned addresses are attempted under
    /// one connect deadline while TLS identity remains bound to the URI host.
    address_resolver: ?AddressResolver = null,
    /// Explicit multi-address connection strategy. `.ordered` preserves the
    /// resolver's exact sequential fallback; `.happy_eyeballs` stable-
    /// interleaves address families and races them with a bounded stagger.
    address_connect_policy: AddressConnectPolicy = .ordered,
    /// Route every origin through SOCKS5 with proxy-side destination DNS.
    /// TCP protocols use CONNECT; an enabled HTTP/3 pool uses UDP ASSOCIATE.
    /// One Client or Pool has one fixed proxy route; each independent origin
    /// connection retains its own SOCKS control lifetime.
    socks5_proxy: ?Socks5Proxy = null,
    tcp_nodelay: bool = true,
    http1_limits: http1_runtime.Limits = .{},
    http2_limits: http2_runtime.Limits = .{},
    tls: http2_runtime.TlsConnectOptions = .{},
};

pub const ResponseValue = union(Protocol) {
    http1: http1_runtime.OwnedResponse,
    http2: http2_runtime.OwnedResponse,
    http3: http3_runtime.OwnedHandshakeResponse,
};

pub const EarlyDataMetadata = struct {
    disposition: http3_runtime.EarlyRequestDisposition,
    retry_reason: http3_runtime.EarlyDataRetryReason,
};

const FieldSection = enum { headers, trailers };
const ResponseFields = union(Protocol) {
    http1: []const http1.Header,
    http2: []const http2.Hpack.HeaderField,
    http3: []const http3.Qpack.HeaderField,
};

/// Zero-allocation iterator over one unified response field section.
///
/// Returned names and values borrow the underlying owned response and become
/// invalid when that response is deinitialized. An optional name filter uses
/// the HTTP case-insensitive field-name comparison while retaining original
/// order, spelling, duplicates, and peer Never-Indexed metadata.
pub const HeaderIterator = struct {
    fields: ResponseFields,
    name: ?[]const u8 = null,
    index: usize = 0,

    pub fn next(self: *HeaderIterator) ?Header {
        const count = fieldCount(self.fields);
        while (self.index < count) {
            const result = fieldAt(self.fields, self.index);
            self.index += 1;
            if (self.name) |name| {
                if (!std.ascii.eqlIgnoreCase(result.name, name)) continue;
            }
            return result;
        }
        return null;
    }
};

pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    value: ResponseValue,
    early_data: ?EarlyDataMetadata = null,

    pub fn deinit(self: *OwnedResponse) void {
        const allocator = self.allocator;
        switch (self.value) {
            .http1 => |*response| response.deinit(allocator),
            .http2 => |*response| response.deinit(allocator),
            .http3 => |*response| response.deinit(allocator),
        }
        self.* = undefined;
    }

    pub fn protocol(self: OwnedResponse) Protocol {
        return std.meta.activeTag(self.value);
    }

    pub fn status(self: OwnedResponse) u16 {
        return switch (self.value) {
            .http1 => |response| response.response.status,
            .http2 => |response| response.status,
            .http3 => |response| response.response.status,
        };
    }

    pub fn body(self: OwnedResponse) []const u8 {
        return switch (self.value) {
            .http1 => |response| response.response.body,
            .http2 => |response| response.body,
            .http3 => |response| response.response.body,
        };
    }

    pub fn header(self: OwnedResponse, name: []const u8) ?[]const u8 {
        var values = self.headerValues(name);
        return if (values.next()) |field| field.value else null;
    }

    pub fn trailer(self: OwnedResponse, name: []const u8) ?[]const u8 {
        var values = self.trailerValues(name);
        return if (values.next()) |field| field.value else null;
    }

    pub fn headers(self: OwnedResponse) HeaderIterator {
        return fieldIterator(self.value, .headers, null);
    }

    pub fn trailers(self: OwnedResponse) HeaderIterator {
        return fieldIterator(self.value, .trailers, null);
    }

    pub fn headerValues(
        self: OwnedResponse,
        name: []const u8,
    ) HeaderIterator {
        return fieldIterator(self.value, .headers, name);
    }

    pub fn trailerValues(
        self: OwnedResponse,
        name: []const u8,
    ) HeaderIterator {
        return fieldIterator(self.value, .trailers, name);
    }

    /// Parse every Content-Encoding field without exposing the negotiated
    /// protocol's concrete header representation.
    pub fn contentEncoding(
        self: OwnedResponse,
    ) content_coding.Error!content_coding.Chain {
        return switch (self.value) {
            .http1 => |response| response.response.contentEncoding(),
            .http2 => |response| response.contentEncoding(),
            .http3 => |response| response.response.contentEncoding(),
        };
    }

    /// Decode every Content-Encoding layer in reverse application order.
    /// The encoded response and its headers remain owned and unchanged.
    pub fn decodeContentAlloc(
        self: OwnedResponse,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return switch (self.value) {
            .http1 => |response| response.response.decodeContentAlloc(
                allocator,
                max_output_len,
            ),
            .http2 => |response| response.decodeContentAlloc(
                allocator,
                max_output_len,
            ),
            .http3 => |response| response.response.decodeContentAlloc(
                allocator,
                max_output_len,
            ),
        };
    }

    /// Caller-buffer counterpart to `decodeContentAlloc`. `scratch` is used
    /// only when the response carries stacked non-identity encodings.
    pub fn decodeContentInto(
        self: OwnedResponse,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return switch (self.value) {
            .http1 => |response| response.response.decodeContentInto(
                out,
                scratch,
            ),
            .http2 => |response| response.decodeContentInto(out, scratch),
            .http3 => |response| response.response.decodeContentInto(
                out,
                scratch,
            ),
        };
    }
};

pub const RedirectedResponse = struct {
    allocator: std.mem.Allocator,
    response: OwnedResponse,
    final_uri: []u8,
    redirect_count: usize,

    pub fn deinit(self: *RedirectedResponse) void {
        const allocator = self.allocator;
        self.response.deinit();
        allocator.free(self.final_uri);
        self.* = undefined;
    }

    pub fn takeResponse(self: *RedirectedResponse) OwnedResponse {
        const response = self.response;
        self.allocator.free(self.final_uri);
        self.* = undefined;
        return response;
    }

    pub fn contentEncoding(
        self: RedirectedResponse,
    ) content_coding.Error!content_coding.Chain {
        return self.response.contentEncoding();
    }

    pub fn header(self: RedirectedResponse, name: []const u8) ?[]const u8 {
        return self.response.header(name);
    }

    pub fn trailer(self: RedirectedResponse, name: []const u8) ?[]const u8 {
        return self.response.trailer(name);
    }

    pub fn headers(self: RedirectedResponse) HeaderIterator {
        return self.response.headers();
    }

    pub fn trailers(self: RedirectedResponse) HeaderIterator {
        return self.response.trailers();
    }

    pub fn headerValues(
        self: RedirectedResponse,
        name: []const u8,
    ) HeaderIterator {
        return self.response.headerValues(name);
    }

    pub fn trailerValues(
        self: RedirectedResponse,
        name: []const u8,
    ) HeaderIterator {
        return self.response.trailerValues(name);
    }

    pub fn decodeContentAlloc(
        self: RedirectedResponse,
        allocator: std.mem.Allocator,
        max_output_len: usize,
    ) content_coding.Error!content_coding.DecodedBody {
        return self.response.decodeContentAlloc(allocator, max_output_len);
    }

    pub fn decodeContentInto(
        self: RedirectedResponse,
        out: []u8,
        scratch: []u8,
    ) content_coding.Error![]u8 {
        return self.response.decodeContentInto(out, scratch);
    }
};

fn fieldIterator(
    response: ResponseValue,
    section: FieldSection,
    name: ?[]const u8,
) HeaderIterator {
    const fields: ResponseFields = switch (response) {
        .http1 => |value| .{ .http1 = switch (section) {
            .headers => value.response.headers,
            .trailers => value.response.trailers,
        } },
        .http2 => |value| .{ .http2 = switch (section) {
            .headers => value.headers,
            .trailers => value.trailers,
        } },
        .http3 => |value| .{ .http3 = switch (section) {
            .headers => value.response.headers,
            .trailers => value.response.trailers,
        } },
    };
    return .{ .fields = fields, .name = name };
}

fn fieldCount(fields: ResponseFields) usize {
    return switch (fields) {
        inline else => |items| items.len,
    };
}

fn fieldAt(fields: ResponseFields, index: usize) Header {
    return switch (fields) {
        .http1 => |items| blk: {
            const field = items[index];
            break :blk .{ .name = field.name, .value = field.value };
        },
        .http2 => |items| blk: {
            const field = items[index];
            break :blk .{
                .name = field.name,
                .value = field.value,
                .never_indexed = field.never_index,
            };
        },
        .http3 => |items| blk: {
            const field = items[index];
            break :blk .{
                .name = field.name,
                .value = field.value,
                .never_indexed = field.never_indexed,
            };
        },
    };
}

const alpn_prefer_http2 = [_][]const u8{ "h2", "http/1.1" };
const alpn_http1_only = [_][]const u8{"http/1.1"};
const alpn_http2_only = [_][]const u8{"h2"};

pub fn verifiedTlsOptions(
    server_name: []const u8,
    options: Options,
) tls_stream.ClientVerifiedOptions {
    const tls = options.tls;
    return .{
        .server_name = server_name,
        .verify_host = tls.verify_host,
        .ca_bundle = tls.ca_bundle,
        .server_verifier = tls.server_verifier,
        .stapled_ocsp = tls.stapled_ocsp,
        .request_ocsp = tls.request_ocsp,
        .client_identity = tls.client_identity,
        .alpn_protocols = switch (options.protocol_policy) {
            .prefer_http2 => &alpn_prefer_http2,
            .http1_only => &alpn_http1_only,
            .http2_only => &alpn_http2_only,
        },
        .cipher_suites = tls.cipher_suites,
        .tls12_cipher_suites = tls.tls12_cipher_suites,
        .protocol_policy = tls.protocol_policy,
        .request_tls12_session_ticket = tls.request_tls12_session_ticket,
        .tls12_ticket_resumption = tls.tls12_ticket_resumption,
        .request_tls13_session_ticket = tls.request_tls13_session_ticket,
        .tls13_ticket_resumption = tls.tls13_ticket_resumption,
        .max_server_handshake_size = tls.max_server_handshake_size,
        .handshake_timeout = tls.tls_handshake_timeout,
    };
}

pub fn selectedProtocol(
    selected_alpn: ?[]const u8,
    options: Options,
) tls_stream.Error!NegotiatedProtocol {
    if (selected_alpn) |alpn| {
        if (std.mem.eql(u8, alpn, "h2")) {
            if (options.protocol_policy == .http1_only) return error.InvalidAlpn;
            return .http2;
        }
        if (std.mem.eql(u8, alpn, "http/1.1")) {
            if (options.protocol_policy == .http2_only) return error.InvalidAlpn;
            return .http1;
        }
        return error.InvalidAlpn;
    }
    if (options.protocol_policy == .http2_only or
        !options.allow_http1_without_alpn)
    {
        return error.InvalidAlpn;
    }
    return .http1;
}

test "unified HTTP ALPN policy selects only permitted protocols" {
    try std.testing.expectEqual(
        NegotiatedProtocol.http2,
        try selectedProtocol("h2", .{}),
    );
    try std.testing.expectEqual(
        NegotiatedProtocol.http1,
        try selectedProtocol("http/1.1", .{}),
    );
    try std.testing.expectEqual(
        NegotiatedProtocol.http1,
        try selectedProtocol(null, .{}),
    );
    try std.testing.expectError(
        error.InvalidAlpn,
        selectedProtocol(null, .{ .protocol_policy = .http2_only }),
    );
    try std.testing.expectError(
        error.InvalidAlpn,
        selectedProtocol("h2", .{ .protocol_policy = .http1_only }),
    );
    try std.testing.expectError(
        error.InvalidAlpn,
        selectedProtocol(null, .{ .allow_http1_without_alpn = false }),
    );
    try std.testing.expectError(
        error.InvalidAlpn,
        selectedProtocol("unexpected", .{}),
    );
}

//! Public unified HTTP client types and ALPN policy.

const std = @import("std");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const content_coding = @import("../content_coding.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const uri_redirect = @import("../../http1/runtime/redirect.zig");

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

pub const OwnedResponse = struct {
    allocator: std.mem.Allocator,
    value: ResponseValue,

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
        return switch (self.value) {
            .http1 => |response| findHeader(response.response.headers, name),
            .http2 => |response| findHeader(response.headers, name),
            .http3 => |response| findHeader(response.response.headers, name),
        };
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

fn findHeader(headers: anytype, name: []const u8) ?[]const u8 {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    }
    return null;
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

//! Cross-protocol redirect engine for the unified one-shot HTTP client.

const std = @import("std");
const uri_redirect = @import("../../http1/runtime/redirect.zig");
const types = @import("types.zig");

pub fn followDetailed(
    comptime OperationError: type,
    client: anytype,
    uri_text: []const u8,
    request: types.RequestOptions,
    redirect_options: types.RedirectOptions,
    deadline: ?std.Io.Clock.Timestamp,
    comptime Adapter: type,
) OperationError!types.RedirectedResponse {
    const allocator = client.allocator;
    const policy = redirect_options.policy;
    var chain = uri_redirect.Chain.init(allocator, policy);
    defer chain.deinit();
    try chain.recordInitial(uri_text);
    var current_uri = try allocator.dupe(u8, uri_text);
    defer allocator.free(current_uri);
    var hop_request = request;
    var owned_headers: ?[]types.Header = null;
    defer if (owned_headers) |headers| allocator.free(headers);
    var crossed_origin = false;

    while (true) {
        var response = try Adapter.request(
            client,
            current_uri,
            hop_request,
            deadline,
            crossed_origin,
            policy,
        );
        errdefer response.deinit();
        if (!uri_redirect.isRedirectStatus(response.status())) {
            return .{
                .allocator = allocator,
                .response = response,
                .final_uri = try uri_redirect.canonicalize(
                    allocator,
                    current_uri,
                ),
                .redirect_count = chain.redirects,
            };
        }
        const location = try responseLocation(response);
        if (location == null) {
            return .{
                .allocator = allocator,
                .response = response,
                .final_uri = try uri_redirect.canonicalize(
                    allocator,
                    current_uri,
                ),
                .redirect_count = chain.redirects,
            };
        }
        var next = try chain.follow(
            current_uri,
            location.?,
            response.status(),
        );
        var next_owned = true;
        defer if (next_owned) next.deinit();
        if (next.cross_origin) {
            try uri_redirect.enforceClientIdentityPolicy(
                policy,
                true,
                Adapter.clientIdentityConfigured(client),
            );
            crossed_origin = true;
        }
        const action = uri_redirect.methodActionBytes(
            policy,
            response.status(),
            hop_request.method,
        );
        const remove_credentials = next.cross_origin and
            !policy.forward_cross_origin_credentials;
        hop_request.headers = try redirectHeaders(
            allocator,
            hop_request.headers,
            remove_credentials,
            action == .rewrite_get,
            &owned_headers,
        );
        if (action == .rewrite_get) {
            hop_request.method = "GET";
            hop_request.body = &.{};
            hop_request.trailers = &.{};
        } else if (remove_credentials) {
            hop_request.trailers = &.{};
        }
        response.deinit();
        allocator.free(current_uri);
        current_uri = next.uri;
        next_owned = false;
    }
}

fn responseLocation(
    response: types.OwnedResponse,
) uri_redirect.Error!?[]const u8 {
    var found: ?[]const u8 = null;
    switch (response.value) {
        .http1 => |owned| for (owned.response.headers) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
            if (found != null or header.value.len == 0) {
                return error.InvalidRedirect;
            }
            found = header.value;
        },
        .http2 => |owned| for (owned.headers) |header| {
            if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
            if (found != null or header.value.len == 0) {
                return error.InvalidRedirect;
            }
            found = header.value;
        },
    }
    return found;
}

fn redirectHeaders(
    allocator: std.mem.Allocator,
    source: []const types.Header,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]types.Header,
) std.mem.Allocator.Error![]const types.Header {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) retained_count += 1;
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(types.Header, retained_count);
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) continue;
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectHeader(
    name: []const u8,
    remove_credentials: bool,
    remove_body: bool,
) bool {
    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (remove_credentials and uri_redirect.isCrossOriginCredential(name)) {
        return true;
    }
    if (remove_credentials and std.ascii.eqlIgnoreCase(name, "trailer")) {
        return true;
    }
    return remove_body and uri_redirect.isBodyHeader(name);
}

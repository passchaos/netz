//! grpc-core-compatible HTTP CONNECT proxy selection for TLS gRPC hosts.
//!
//! Selection is pure over an injected environment view. Process environment
//! access remains an explicit boundary so tests, embedders, and long-lived
//! services do not depend on mutable global state.
const std = @import("std");
const http1 = @import("../../http1/mod.zig");
const http1_runtime = @import("../../http1/runtime.zig");
const http2_runtime = @import("../../http2/runtime.zig");
const endpoint_host = @import("../../internal/endpoint_host.zig");

const net = std.Io.net;

pub const Error = std.mem.Allocator.Error || error{
    InvalidProxyUri,
    UnsupportedProxyScheme,
    InvalidProxyCredentials,
    InvalidOriginHost,
};

/// Borrowed values relevant to grpc-core's name proxy mapper. An explicitly
/// present empty slice is different from `null`: it suppresses lower-priority
/// variables and disables proxying.
pub const Environment = struct {
    grpc_proxy: ?[]const u8 = null,
    https_proxy: ?[]const u8 = null,
    http_proxy: ?[]const u8 = null,
    no_grpc_proxy: ?[]const u8 = null,
    no_proxy: ?[]const u8 = null,

    pub fn fromMap(map: *const std.process.Environ.Map) Environment {
        return .{
            .grpc_proxy = map.get("grpc_proxy"),
            .https_proxy = map.get("https_proxy"),
            .http_proxy = map.get("http_proxy"),
            .no_grpc_proxy = map.get("no_grpc_proxy"),
            .no_proxy = map.get("no_proxy"),
        };
    }
};

pub const ProxySource = enum {
    explicit_override,
    grpc_proxy,
    https_proxy,
    http_proxy,
};

pub const BypassSource = enum {
    no_grpc_proxy,
    no_proxy,
};

pub const DirectReason = enum {
    disabled,
    not_configured,
    empty_proxy,
    bypassed,
};

pub const DirectDecision = struct {
    reason: DirectReason,
    /// Set for `empty_proxy` and `bypassed`, identifying the selected proxy
    /// setting before direct routing won.
    proxy_source: ?ProxySource = null,
    bypass_source: ?BypassSource = null,
};

/// Owns the canonical credential-free proxy URI plus any synthesized CONNECT
/// headers. Caller-provided header values remain borrowed; generated Basic
/// credentials are owned until `deinit`.
pub const Resolved = struct {
    allocator: std.mem.Allocator,
    source: ProxySource,
    uri: []u8,
    headers: ?[]http1.Header,
    authorization: ?[]u8,
    tunnel_authority: ?[]const u8,
    options: http1_runtime.ProxyOptions,
    limits: http1_runtime.Limits,

    pub fn deinit(self: *Resolved) void {
        self.allocator.free(self.uri);
        if (self.headers) |headers| self.allocator.free(headers);
        if (self.authorization) |authorization| {
            self.allocator.free(authorization);
        }
        self.* = undefined;
    }

    pub fn httpConnectProxy(self: *const Resolved) http2_runtime.HttpConnectProxy {
        var options = self.options;
        options.headers = self.headers orelse &.{};
        return .{
            .uri = self.uri,
            .tunnel_authority = self.tunnel_authority,
            .options = options,
            .limits = self.limits,
        };
    }
};

pub const Decision = union(enum) {
    direct: DirectDecision,
    proxy: Resolved,

    pub fn deinit(self: *Decision) void {
        switch (self.*) {
            .direct => {},
            .proxy => |*proxy| proxy.deinit(),
        }
        self.* = undefined;
    }

    pub fn httpConnectProxy(self: *const Decision) ?http2_runtime.HttpConnectProxy {
        return switch (self.*) {
            .direct => null,
            .proxy => |*proxy| proxy.httpConnectProxy(),
        };
    }
};

pub const Policy = struct {
    enabled: bool = true,
    /// Equivalent to grpc-core's `GRPC_ARG_HTTP_PROXY`. `null` consults the
    /// environment; `""` explicitly disables proxying.
    explicit_uri: ?[]const u8 = null,
    /// Extra CONNECT-only transport policy. URI userinfo replaces any
    /// caller-supplied Proxy-Authorization field while retaining other fields.
    options: http1_runtime.ProxyOptions = .{},
    limits: http1_runtime.Limits = .{},
    /// Optional service-discovery CONNECT target. This never changes the
    /// origin TLS identity, SNI, or gRPC :authority.
    tunnel_authority: ?[]const u8 = null,

    pub fn resolve(
        self: Policy,
        allocator: std.mem.Allocator,
        environment: Environment,
        origin_host: []const u8,
        origin_port: u16,
    ) Error!Decision {
        if (!self.enabled) return .{ .direct = .{ .reason = .disabled } };

        const selected = selectProxy(self, environment) orelse
            return .{ .direct = .{ .reason = .not_configured } };
        if (selected.uri.len == 0) return .{ .direct = .{
            .reason = .empty_proxy,
            .proxy_source = selected.source,
        } };

        // grpc-core validates the chosen proxy before consulting no_proxy. Do
        // the same, but surface malformed configuration instead of silently
        // turning a production channel into a direct connection.
        const parsed = std.Uri.parse(selected.uri) catch
            return error.InvalidProxyUri;
        if (!std.ascii.eqlIgnoreCase(parsed.scheme, "http")) {
            return error.UnsupportedProxyScheme;
        }
        const host_component = parsed.host orelse return error.InvalidProxyUri;
        const host_text = componentBytes(host_component);
        if (host_text.len == 0) return error.InvalidProxyUri;
        validateProxyHost(host_component) catch return error.InvalidProxyUri;

        const origin = endpoint_host.parse(origin_host, origin_port) catch
            return error.InvalidOriginHost;
        if (selectedBypass(environment)) |bypass| {
            if (addressIncluded(origin, bypass.value)) return .{ .direct = .{
                .reason = .bypassed,
                .proxy_source = selected.source,
                .bypass_source = bypass.source,
            } };
        }

        const canonical_uri = try std.fmt.allocPrint(
            allocator,
            "http://{s}:{d}",
            .{ host_text, parsed.port orelse 80 },
        );
        errdefer allocator.free(canonical_uri);

        const authorization = try basicAuthorization(
            allocator,
            selected.uri,
            parsed,
        );
        errdefer if (authorization) |value| allocator.free(value);

        const headers = try mergeHeaders(
            allocator,
            self.options.headers,
            authorization,
        );
        errdefer if (headers) |owned| allocator.free(owned);

        return .{ .proxy = .{
            .allocator = allocator,
            .source = selected.source,
            .uri = canonical_uri,
            .headers = headers,
            .authorization = authorization,
            .tunnel_authority = self.tunnel_authority,
            .options = self.options,
            .limits = self.limits,
        } };
    }

    pub fn resolveMap(
        self: Policy,
        allocator: std.mem.Allocator,
        map: *const std.process.Environ.Map,
        origin_host: []const u8,
        origin_port: u16,
    ) Error!Decision {
        return self.resolve(
            allocator,
            Environment.fromMap(map),
            origin_host,
            origin_port,
        );
    }

    /// Snapshot a real Zig 0.16 process environment, resolve once, and retain
    /// only the selected owned proxy material. Callers normally pass
    /// `std.process.Init.minimal.environ` from `main`.
    pub fn resolveEnviron(
        self: Policy,
        allocator: std.mem.Allocator,
        environ: std.process.Environ,
        origin_host: []const u8,
        origin_port: u16,
    ) (Error || std.process.Environ.CreateMapError)!Decision {
        var map = try std.process.Environ.createMap(environ, allocator);
        defer map.deinit();
        return self.resolveMap(allocator, &map, origin_host, origin_port);
    }
};

const SelectedProxy = struct {
    source: ProxySource,
    uri: []const u8,
};

fn selectProxy(policy: Policy, environment: Environment) ?SelectedProxy {
    if (policy.explicit_uri) |uri| return .{
        .source = .explicit_override,
        .uri = uri,
    };
    if (environment.grpc_proxy) |uri| return .{
        .source = .grpc_proxy,
        .uri = uri,
    };
    if (environment.https_proxy) |uri| return .{
        .source = .https_proxy,
        .uri = uri,
    };
    if (environment.http_proxy) |uri| return .{
        .source = .http_proxy,
        .uri = uri,
    };
    return null;
}

const SelectedBypass = struct {
    source: BypassSource,
    value: []const u8,
};

fn selectedBypass(environment: Environment) ?SelectedBypass {
    if (environment.no_grpc_proxy) |value| return .{
        .source = .no_grpc_proxy,
        .value = value,
    };
    if (environment.no_proxy) |value| return .{
        .source = .no_proxy,
        .value = value,
    };
    return null;
}

fn componentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

fn validateProxyHost(component: std.Uri.Component) !void {
    var buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw = component.toRaw(&buffer) catch return error.InvalidHost;
    if (raw.len == 0) return error.InvalidHost;
    if (raw[0] == '[') {
        if (raw.len < 3 or raw[raw.len - 1] != ']') return error.InvalidHost;
        _ = net.IpAddress.parseIp6(raw[1 .. raw.len - 1], 0) catch
            return error.InvalidHost;
        return;
    }
    if (std.mem.findAny(u8, raw, "[]") != null) return error.InvalidHost;
    if (net.IpAddress.parse(raw, 0)) |_| return else |_| {}
    _ = net.HostName.init(raw) catch return error.InvalidHost;
}

fn basicAuthorization(
    allocator: std.mem.Allocator,
    uri_text: []const u8,
    parsed: std.Uri,
) Error!?[]u8 {
    if (parsed.user == null and parsed.password == null) return null;

    const scheme_end = std.mem.find(u8, uri_text, "://") orelse
        return error.InvalidProxyCredentials;
    const authority_start = scheme_end + 3;
    const authority_end = std.mem.findAnyPos(
        u8,
        uri_text,
        authority_start,
        &.{ '/', '?', '#' },
    ) orelse uri_text.len;
    const at = std.mem.findScalarPos(u8, uri_text, authority_start, '@') orelse
        return error.InvalidProxyCredentials;
    if (at >= authority_end) return error.InvalidProxyCredentials;
    const encoded = uri_text[authority_start..at];
    const decoded_len = strictDecodedLen(encoded) catch
        return error.InvalidProxyCredentials;
    const encoded_len = std.base64.standard.Encoder.calcSize(decoded_len);
    const value = try allocator.alloc(u8, "Basic ".len + encoded_len);
    errdefer allocator.free(value);
    @memcpy(value[0.."Basic ".len], "Basic ");

    const decoded = try allocator.alloc(u8, decoded_len);
    defer allocator.free(decoded);
    strictDecode(decoded, encoded) catch return error.InvalidProxyCredentials;
    _ = std.base64.standard.Encoder.encode(value["Basic ".len..], decoded);
    return value;
}

fn strictDecodedLen(encoded: []const u8) error{InvalidEncoding}!usize {
    var length: usize = 0;
    var index: usize = 0;
    while (index < encoded.len) {
        if (encoded[index] == '%') {
            if (index + 2 >= encoded.len) return error.InvalidEncoding;
            _ = hexByte(encoded[index + 1], encoded[index + 2]) catch
                return error.InvalidEncoding;
            index += 3;
        } else {
            index += 1;
        }
        length += 1;
    }
    return length;
}

fn strictDecode(out: []u8, encoded: []const u8) error{InvalidEncoding}!void {
    var input_index: usize = 0;
    var output_index: usize = 0;
    while (input_index < encoded.len) : (output_index += 1) {
        if (encoded[input_index] == '%') {
            if (input_index + 2 >= encoded.len) return error.InvalidEncoding;
            out[output_index] = try hexByte(
                encoded[input_index + 1],
                encoded[input_index + 2],
            );
            input_index += 3;
        } else {
            out[output_index] = encoded[input_index];
            input_index += 1;
        }
    }
    std.debug.assert(output_index == out.len);
}

fn hexByte(high: u8, low: u8) error{InvalidEncoding}!u8 {
    const high_value = std.fmt.charToDigit(high, 16) catch
        return error.InvalidEncoding;
    const low_value = std.fmt.charToDigit(low, 16) catch
        return error.InvalidEncoding;
    return high_value * 16 + low_value;
}

fn mergeHeaders(
    allocator: std.mem.Allocator,
    base: []const http1.Header,
    authorization: ?[]const u8,
) std.mem.Allocator.Error!?[]http1.Header {
    if (base.len == 0 and authorization == null) return null;

    var retained_count = base.len;
    if (authorization != null) {
        retained_count = 0;
        for (base) |header| {
            if (!header.eqlName("proxy-authorization")) retained_count += 1;
        }
    }
    const headers = try allocator.alloc(
        http1.Header,
        retained_count + @intFromBool(authorization != null),
    );
    var index: usize = 0;
    for (base) |header| {
        if (authorization != null and header.eqlName("proxy-authorization")) {
            continue;
        }
        headers[index] = header;
        index += 1;
    }
    if (authorization) |value| {
        headers[index] = .{
            .name = "Proxy-Authorization",
            .value = value,
        };
        index += 1;
    }
    std.debug.assert(index == headers.len);
    return headers;
}

fn addressIncluded(origin: endpoint_host.Parsed, list: []const u8) bool {
    var entries = std.mem.splitScalar(u8, list, ',');
    while (entries.next()) |raw_entry| {
        const entry = trimAsciiWhitespace(raw_entry);
        if (exactMatchOrSubdomain(origin.host, entry)) return true;
        if (origin.literal) |address| {
            if (cidrMatches(address, entry)) return true;
        }
    }
    return false;
}

fn exactMatchOrSubdomain(host: []const u8, raw_entry: []const u8) bool {
    const entry = if (raw_entry.len != 0 and raw_entry[0] == '.')
        raw_entry[1..]
    else
        raw_entry;
    if (entry.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(host, entry)) return true;
    if (host.len <= entry.len or
        !std.ascii.endsWithIgnoreCase(host, entry)) return false;
    return host[host.len - entry.len - 1] == '.';
}

fn cidrMatches(address: net.IpAddress, entry: []const u8) bool {
    const slash = std.mem.findScalar(u8, entry, '/') orelse return false;
    if (slash == 0 or slash + 1 == entry.len) return false;
    const prefix = std.fmt.parseInt(u8, entry[slash + 1 ..], 10) catch
        return false;
    var network_text = entry[0..slash];
    if (network_text.len >= 2 and network_text[0] == '[' and
        network_text[network_text.len - 1] == ']')
    {
        network_text = network_text[1 .. network_text.len - 1];
    }
    const network = net.IpAddress.parse(network_text, 0) catch return false;
    return switch (address) {
        .ip4 => |candidate| switch (network) {
            .ip4 => |base| prefix <= 32 and
                prefixMatches(&candidate.bytes, &base.bytes, prefix),
            .ip6 => false,
        },
        .ip6 => |candidate| switch (network) {
            .ip4 => false,
            .ip6 => |base| prefix <= 128 and
                prefixMatches(&candidate.bytes, &base.bytes, prefix),
        },
    };
}

fn prefixMatches(candidate: []const u8, network: []const u8, bits: u8) bool {
    const full_bytes: usize = @intCast(bits / 8);
    if (!std.mem.eql(u8, candidate[0..full_bytes], network[0..full_bytes])) {
        return false;
    }
    const tail_bits: u3 = @intCast(bits % 8);
    if (tail_bits == 0) return true;
    const shift: u3 = @intCast(8 - @as(u8, tail_bits));
    const mask: u8 = @as(u8, 0xff) << shift;
    return candidate[full_bytes] & mask == network[full_bytes] & mask;
}

fn trimAsciiWhitespace(value: []const u8) []const u8 {
    var start: usize = 0;
    while (start < value.len and isAsciiWhitespace(value[start])) : (start += 1) {}
    var end = value.len;
    while (end > start and isAsciiWhitespace(value[end - 1])) : (end -= 1) {}
    return value[start..end];
}

fn isAsciiWhitespace(byte: u8) bool {
    return switch (byte) {
        ' ', '\t', '\n', '\r', 0x0b, 0x0c => true,
        else => false,
    };
}

const std = @import("std");
const netz = @import("netz");

const default_uri = "https://robotics.bytedance.com/";
const max_attempts = 5;

const DiscoveredTarget = struct {
    allocator: std.mem.Allocator,
    alpn: []u8,
    connect_host: []u8,
    port: u16,
    max_age: ?u64,

    fn deinit(self: *DiscoveredTarget) void {
        self.allocator.free(self.alpn);
        self.allocator.free(self.connect_host);
        self.* = undefined;
    }
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next(); // executable name
    var uri_text: []const u8 = default_uri;
    var verify_server = false;
    var discover = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--verify")) {
            verify_server = true;
        } else if (std.mem.eql(u8, arg, "--discover")) {
            discover = true;
        } else {
            uri_text = arg;
        }
    }
    const uri = try std.Uri.parse(uri_text);

    var discovered: ?DiscoveredTarget = null;
    defer if (discovered) |*target| target.deinit();
    if (discover) {
        discovered = discoverAltSvc(allocator, io, uri_text, uri) catch |err| skipped: {
            std.debug.print("Alt-Svc discovery skipped: {s}\n", .{@errorName(err)});
            break :skipped null;
        };
    }

    // This is a protocol smoke tool, not a production WebPKI client: the QUIC
    // handshake path accepts the certificate chain unless callers provide a
    // `server_auth` verifier.  Keeping the example explicit lets it exercise
    // public HTTP/3 reachability while the verifier policy remains pluggable.
    var response = try fetchWithRetries(allocator, io, uri, verify_server, if (discovered) |*target| target else null);
    defer response.deinit(allocator);

    std.debug.print("HTTP/3 {s} -> {d}\n", .{ uri_text, response.response.status });
    for (response.response.headers) |header| {
        std.debug.print("{s}: {s}\n", .{ header.name, header.value });
    }
    const body = response.response.body;
    const preview_len = @min(body.len, 256);
    std.debug.print("body-bytes: {d}\n", .{body.len});
    if (preview_len != 0) {
        std.debug.print("body-preview:\n{s}\n", .{body[0..preview_len]});
    }
}

fn fetchWithRetries(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: std.Uri,
    verify_server: bool,
    discovered: ?*const DiscoveredTarget,
) !netz.http3.runtime.OwnedHandshakeResponse {
    var attempt: usize = 0;
    var last_err: ?anyerror = null;
    while (attempt < max_attempts) : (attempt += 1) {
        return fetchOnce(allocator, io, uri, verify_server, discovered) catch |err| {
            last_err = err;
            std.debug.print(
                "HTTP/3 fetch attempt {d}/{d} failed: {s}\n",
                .{ attempt + 1, max_attempts, @errorName(err) },
            );
            continue;
        };
    }
    return last_err orelse error.Unexpected;
}

fn fetchOnce(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: std.Uri,
    verify_server: bool,
    discovered: ?*const DiscoveredTarget,
) !netz.http3.runtime.OwnedHandshakeResponse {
    var original_dcid: [8]u8 = undefined;
    var local_cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &original_dcid);
    try std.Io.randomSecure(io, &local_cid);

    var system_store: ?netz.quic.tls.trust.SystemStore = null;
    defer if (system_store) |*store| store.deinit();
    var bundle_verifier: ?netz.quic.tls.trust.BundleVerifier = null;
    const server_auth = if (verify_server) auth: {
        const now = std.Io.Clock.real.now(io);
        system_store = try netz.quic.tls.trust.SystemStore.init(allocator, io, now);
        bundle_verifier = system_store.?.verifier(now.toSeconds());
        break :auth bundle_verifier.?.clientVerifier();
    } else null;

    if (discovered) |target| {
        return try fetchOnceViaAltSvc(
            allocator,
            io,
            uri,
            target.*,
            server_auth,
            &original_dcid,
            &local_cid,
        );
    }

    return try netz.http3.runtime.HandshakeClient.requestUri(
        allocator,
        io,
        .{ .ip4 = .unspecified(0) },
        uri,
        .{ .method = "GET" },
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &local_cid,
                .max_crypto_buffer = 64 * 1024,
                .handshake_recovery = .{
                    .initial_pto_ms = 750,
                    .max_pto_ms = 6000,
                    .max_retries = 5,
                },
                .server_auth = server_auth,
            },
            .session = .{ .max_stream_buffer = 512 * 1024 },
        },
    );
}

fn discoverAltSvc(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri_text: []const u8,
    uri: std.Uri,
) !?DiscoveredTarget {
    var endpoint = try netz.http3.runtime.uriEndpoint(allocator, uri);
    defer endpoint.deinit();

    var response = try netz.http1.runtime.Client.requestUri(allocator, io, uri_text, .{
        .method = .HEAD,
    }, .{
        .max_head_bytes = 64 * 1024,
        .max_body_bytes = 0,
    });
    defer response.deinit(allocator);

    const alt = (try netz.http3.firstHttp3AltSvcHeader(response.response.headers)) orelse {
        std.debug.print("Alt-Svc: no HTTP/3 endpoint advertised\n", .{});
        return null;
    };
    const target = try netz.http3.altSvcTarget(endpoint.tls_host, alt, endpoint.port);
    std.debug.print(
        "Alt-Svc: {s} authority={s} -> {s}:{d} ma={?d}\n",
        .{ target.alpn, alt.authority, target.connect_host, target.port, target.max_age },
    );
    const alpn = try allocator.dupe(u8, target.alpn);
    errdefer allocator.free(alpn);
    const connect_host = try allocator.dupe(u8, target.connect_host);
    errdefer allocator.free(connect_host);
    return .{
        .allocator = allocator,
        .alpn = alpn,
        .connect_host = connect_host,
        .port = target.port,
        .max_age = target.max_age,
    };
}

fn fetchOnceViaAltSvc(
    allocator: std.mem.Allocator,
    io: std.Io,
    uri: std.Uri,
    target: DiscoveredTarget,
    server_auth: ?netz.quic.tls.auth.ClientVerifier,
    original_dcid: []const u8,
    local_cid: []const u8,
) !netz.http3.runtime.OwnedHandshakeResponse {
    var origin = try netz.http3.runtime.uriEndpoint(allocator, uri);
    defer origin.deinit();
    const server = try resolveHostPort(io, target.connect_host, target.port);
    const path = try uriPathAlloc(allocator, uri);
    defer allocator.free(path);

    var client = try netz.http3.runtime.HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .unspecified(0) },
        server,
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 16 } },
        .{
            .handshake = .{
                .original_destination_connection_id = original_dcid,
                .local_connection_id = local_cid,
                .server_name = origin.tls_host,
                .alpn_protocols = &.{target.alpn},
                .max_crypto_buffer = 64 * 1024,
                .handshake_recovery = .{
                    .initial_pto_ms = 750,
                    .max_pto_ms = 6000,
                    .max_retries = 5,
                },
                .server_auth = server_auth,
            },
            .session = .{ .max_stream_buffer = 512 * 1024 },
        },
    );
    defer client.deinit();
    return try client.request(.{
        .method = "GET",
        .path = path,
        .scheme = "https",
        .authority = origin.authority,
    });
}

fn resolveHostPort(io: std.Io, host: []const u8, port: u16) !std.Io.net.IpAddress {
    if (std.Io.net.IpAddress.parse(host, port)) |address| return address else |_| {}
    const host_name = try std.Io.net.HostName.init(host);
    var lookup_buffer: [32]std.Io.net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(std.Io.net.HostName.LookupResult) = .init(&lookup_buffer);
    try std.Io.net.HostName.lookup(host_name, io, &lookup_queue, .{ .port = port });
    while (lookup_queue.getOne(io)) |result| switch (result) {
        .address => |address| return address,
        .canonical_name => {},
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => return error.Canceled,
    }
    return error.NoAddressReturned;
}

fn uriPathAlloc(allocator: std.mem.Allocator, uri: std.Uri) ![]u8 {
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

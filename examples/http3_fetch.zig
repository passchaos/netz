const std = @import("std");
const netz = @import("netz");

const default_uri = "https://robotics.bytedance.com/";
const max_attempts = 5;

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

    if (discover) {
        discoverAltSvc(allocator, io, uri_text, uri) catch |err| {
            std.debug.print("Alt-Svc discovery skipped: {s}\n", .{@errorName(err)});
        };
    }

    // This is a protocol smoke tool, not a production WebPKI client: the QUIC
    // handshake path accepts the certificate chain unless callers provide a
    // `server_auth` verifier.  Keeping the example explicit lets it exercise
    // public HTTP/3 reachability while the verifier policy remains pluggable.
    var response = try fetchWithRetries(allocator, io, uri, verify_server);
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
) !netz.http3.runtime.OwnedHandshakeResponse {
    var attempt: usize = 0;
    var last_err: ?anyerror = null;
    while (attempt < max_attempts) : (attempt += 1) {
        return fetchOnce(allocator, io, uri, verify_server) catch |err| {
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
) !void {
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
        return;
    };
    const target = try netz.http3.altSvcTarget(endpoint.tls_host, alt, endpoint.port);
    std.debug.print(
        "Alt-Svc: {s} authority={s} -> {s}:{d} ma={?d}\n",
        .{ target.alpn, alt.authority, target.connect_host, target.port, target.max_age },
    );
}

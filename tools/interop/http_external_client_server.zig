//! One-connection HTTP/1.1 and HTTP/2 server for external-client gates.

const std = @import("std");
const netz = @import("netz");

const Protocol = enum { http1, http2 };
const ClientKind = enum { curl, nghttp };
const Route = enum { first, second };

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 4 or args.len > 5) return error.InvalidArgument;
    const protocol: Protocol = if (std.mem.eql(u8, args[1], "http1"))
        .http1
    else if (std.mem.eql(u8, args[1], "http2"))
        .http2
    else
        return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[2], 10);
    if (port == 0) return error.InvalidArgument;
    const client: ClientKind = if (std.mem.eql(u8, args[3], "curl"))
        .curl
    else if (std.mem.eql(u8, args[3], "nghttp"))
        .nghttp
    else
        return error.InvalidArgument;
    const use_tls = args.len == 5 and std.mem.eql(u8, args[4], "--tls");
    if (args.len == 5 and !use_tls) return error.InvalidArgument;
    if (protocol == .http1 and client == .nghttp) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    switch (protocol) {
        .http1 => try runHttp1(allocator, io, port, client, use_tls),
        .http2 => try runHttp2(allocator, io, port, client, use_tls),
    }
}

fn runHttp1(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    client: ClientKind,
    use_tls: bool,
) !void {
    const limits: netz.http1.runtime.Limits = .{
        .max_head_bytes = 16 * 1024,
        .max_body_bytes = 16 * 1024,
    };
    if (use_tls) {
        var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            netz.tls.testing.certificate_base64,
        );
        const key_pair = try netz.tls.testing.serverKeyPair();
        var server = try netz.http1.runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = limits,
                .alpn_protocols = &.{"http/1.1"},
            },
        );
        defer server.deinit();
        try serveHttp1(&server, allocator, client, true);
    } else {
        var server = try netz.http1.runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
        defer server.deinit();
        try serveHttp1(&server, allocator, client, false);
    }
}

fn serveHttp1(
    server: anytype,
    allocator: std.mem.Allocator,
    client: ClientKind,
    use_tls: bool,
) !void {
    std.debug.print(
        "netz external HTTP client server listening protocol=http1 transport={s} client={s} server_io=zio-std-io\n",
        .{ transportName(use_tls), clientName(client) },
    );
    var connection = try server.accept();
    defer connection.close();

    var seen: u2 = 0;
    for (0..2) |_| {
        var request = try connection.readRequest(.{});
        defer request.deinit(allocator);
        const route = try validateRequest(
            client,
            request.request.method.string(),
            request.request.target,
            request.request.headers,
            request.request.body,
        );
        try markRoute(&seen, route);
        try connection.writeResponse(.{
            .status = 200,
            .headers = &.{
                .{ .name = "Content-Type", .value = "text/plain" },
                .{ .name = "X-Netz-Sequence", .value = routeNumber(route) },
            },
            .body = responseBody(client, route),
            .request_method = request.request.method,
        });
    }
    if (seen != 0b11) return error.MissingRequest;
    std.debug.print(
        "netz external HTTP client completed protocol=http1 transport={s} client={s} requests=2 connections=1 body_bytes={d} server_io=zio-std-io\n",
        .{ transportName(use_tls), clientName(client), requestBodyBytes(client) },
    );
}

fn runHttp2(
    allocator: std.mem.Allocator,
    io: std.Io,
    port: u16,
    client: ClientKind,
    use_tls: bool,
) !void {
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 16 * 1024,
    };
    if (use_tls) {
        var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            netz.tls.testing.certificate_base64,
        );
        const key_pair = try netz.tls.testing.serverKeyPair();
        var server = try netz.http2.runtime.TlsServer.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            .{
                .identity = .{
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{ .ecdsa_p256_sha256 = .{
                        .key_pair = key_pair,
                    } },
                },
                .limits = limits,
            },
        );
        defer server.deinit();
        try serveHttp2(&server, allocator, client, true);
    } else {
        var server = try netz.http2.runtime.Server.listen(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
        defer server.deinit();
        try serveHttp2(&server, allocator, client, false);
    }
}

fn serveHttp2(
    server: anytype,
    allocator: std.mem.Allocator,
    client: ClientKind,
    use_tls: bool,
) !void {
    std.debug.print(
        "netz external HTTP client server listening protocol=http2 transport={s} client={s} server_io=zio-std-io\n",
        .{ transportName(use_tls), clientName(client) },
    );
    var connection = try server.accept();
    defer connection.close();

    var seen: u2 = 0;
    var first_stream_id: ?u31 = null;
    var last_stream_id: u31 = 0;
    for (0..2) |_| {
        var request = try connection.readRequest();
        defer request.deinit(allocator);
        if (request.stream_id == 0 or request.stream_id & 1 == 0) {
            return error.InvalidStreamId;
        }
        if (first_stream_id) |first| {
            if (request.stream_id == first) return error.DuplicateStreamId;
        } else {
            first_stream_id = request.stream_id;
        }
        last_stream_id = @max(last_stream_id, request.stream_id);
        if (!std.mem.eql(
            u8,
            request.scheme,
            if (use_tls) "https" else "http",
        )) return error.InvalidScheme;
        const route = try validateRequest(
            client,
            request.method,
            request.path,
            request.headers,
            request.body,
        );
        try markRoute(&seen, route);
        try connection.writeResponse(request.stream_id, .{
            .status = 200,
            .headers = &.{
                .{ .name = "content-type", .value = "text/plain" },
                .{ .name = "x-netz-sequence", .value = routeNumber(route) },
            },
            .body = responseBody(client, route),
            .request_method = request.method,
        });
    }
    if (seen != 0b11) return error.MissingRequest;
    try connection.sendGoAway(last_stream_id, .no_error, "external-client-complete");
    std.debug.print(
        "netz external HTTP client completed protocol=http2 transport={s} client={s} requests=2 connections=1 streams=2 body_bytes={d} server_io=zio-std-io\n",
        .{ transportName(use_tls), clientName(client), requestBodyBytes(client) },
    );
}

fn validateRequest(
    client: ClientKind,
    method: []const u8,
    target: []const u8,
    headers: anytype,
    body: []const u8,
) !Route {
    if (!headerEquals(headers, "x-interop-client", clientName(client))) {
        return error.InvalidHeader;
    }
    return switch (client) {
        .curl => if (std.mem.eql(u8, target, "/upload?client=curl")) blk: {
            if (!std.mem.eql(u8, method, "POST") or
                !std.mem.eql(u8, body, "curl-request-body"))
            {
                return error.InvalidRequest;
            }
            break :blk .first;
        } else if (std.mem.eql(u8, target, "/reuse?client=curl")) blk: {
            if (!std.mem.eql(u8, method, "GET") or body.len != 0) {
                return error.InvalidRequest;
            }
            break :blk .second;
        } else return error.InvalidRequest,
        .nghttp => if (std.mem.eql(u8, target, "/first?client=nghttp")) blk: {
            if (!std.mem.eql(u8, method, "GET") or body.len != 0) {
                return error.InvalidRequest;
            }
            break :blk .first;
        } else if (std.mem.eql(u8, target, "/second?client=nghttp")) blk: {
            if (!std.mem.eql(u8, method, "GET") or body.len != 0) {
                return error.InvalidRequest;
            }
            break :blk .second;
        } else return error.InvalidRequest,
    };
}

fn headerEquals(
    headers: anytype,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) {
            return std.mem.eql(u8, header.value, value);
        }
    }
    return false;
}

fn markRoute(seen: *u2, route: Route) !void {
    const bit: u2 = switch (route) {
        .first => 0b01,
        .second => 0b10,
    };
    if (seen.* & bit != 0) return error.DuplicateRequest;
    seen.* |= bit;
}

fn routeNumber(route: Route) []const u8 {
    return switch (route) {
        .first => "1",
        .second => "2",
    };
}

fn responseBody(client: ClientKind, route: Route) []const u8 {
    return switch (client) {
        .curl => switch (route) {
            .first => "netz-curl-upload",
            .second => "netz-curl-reuse",
        },
        .nghttp => switch (route) {
            .first => "netz-nghttp-first",
            .second => "netz-nghttp-second",
        },
    };
}

fn requestBodyBytes(client: ClientKind) usize {
    return switch (client) {
        .curl => "curl-request-body".len,
        .nghttp => 0,
    };
}

fn clientName(client: ClientKind) []const u8 {
    return @tagName(client);
}

fn transportName(use_tls: bool) []const u8 {
    return if (use_tls) "tls" else "cleartext";
}

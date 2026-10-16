//! Netz HTTP/2 client for independent nghttpd server interoperability.

const std = @import("std");
const netz = @import("netz");

const first_body = "netz-nghttpd-first-body";
const second_body = "netz-nghttpd-second-body";
const reuse_body = "nghttpd-after-reuse";
const response_trailer_name = "x-nghttpd-response-complete";

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const certificate_path = if (args.len == 3) args[2] else null;
    if (certificate_path) |path| {
        if (!std.Io.Dir.path.isAbsolute(path)) return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 16 * 1024,
        .handshake_timeout = .fromSeconds(5),
    };

    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (certificate_path) |path| {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            path,
        );
    }

    var connection = if (certificate_path != null)
        try netz.http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{
                .bundle = &ca_bundle,
                .lock = &ca_lock,
            } },
        )
    else
        try netz.http2.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer connection.close();

    if (certificate_path != null and
        !std.mem.eql(u8, connection.negotiatedAlpn() orelse "", "h2"))
    {
        return error.InvalidAlpn;
    }
    if (certificate_path == null and connection.negotiatedAlpn() != null) {
        return error.InvalidAlpn;
    }

    const requests = [_]netz.http2.runtime.RequestOptions{
        .{
            .method = "POST",
            .path = "/first?client=netz",
            .authority = "localhost",
            .headers = &.{
                .{ .name = "x-netz-request", .value = "first" },
                .{
                    .name = "trailer",
                    .value = "x-netz-request-complete",
                },
            },
            .body = first_body,
            .trailers = &.{.{
                .name = "x-netz-request-complete",
                .value = "first",
            }},
        },
        .{
            .method = "POST",
            .path = "/second?client=netz",
            .authority = "localhost",
            .headers = &.{
                .{ .name = "x-netz-request", .value = "second" },
                .{
                    .name = "trailer",
                    .value = "x-netz-request-complete",
                },
            },
            .body = second_body,
            .trailers = &.{.{
                .name = "x-netz-request-complete",
                .value = "second",
            }},
        },
    };
    var responses: [requests.len]netz.http2.runtime.OwnedResponse = undefined;
    try connection.requestBodyBatchIntoWithTimeout(
        &requests,
        5,
        &responses,
        .fromSeconds(5),
    );
    defer for (&responses) |*response| response.deinit(allocator);

    const expected_bodies = [_][]const u8{ first_body, second_body };
    for (responses, expected_bodies) |response, expected_body| {
        if (response.status != 200 or
            !std.mem.eql(u8, response.body, expected_body) or
            !headerEquals(response.headers, "nghttpd-response", "echo") or
            !headerEquals(
                response.trailers,
                response_trailer_name,
                "yes",
            ))
        {
            return error.InvalidResponse;
        }
    }
    if (!connection.isReusable()) return error.ConnectionClosed;

    var reused = try connection.request(.{
        .method = "GET",
        .path = "/after.txt?client=netz",
        .authority = "localhost",
    });
    defer reused.deinit(allocator);
    if (reused.status != 200 or
        !std.mem.eql(u8, reused.body, reuse_body) or
        !headerEquals(
            reused.trailers,
            response_trailer_name,
            "yes",
        ) or
        !connection.isReusable())
    {
        return error.InvalidResponse;
    }

    std.debug.print(
        "netz HTTP/2 client interoperated with nghttpd: transport={s} requests=3 connections=1 streams=3 request_body_bytes={d} request_trailers=2 response_trailers=3 reuse=true alpn={s} client_io=zio-std-io server_io=nghttp2\n",
        .{
            if (certificate_path != null) "tls" else "h2c",
            first_body.len + second_body.len,
            if (certificate_path != null) "h2" else "n/a",
        },
    );
}

fn headerEquals(
    headers: []const netz.http2.Hpack.HeaderField,
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

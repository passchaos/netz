//! One-shot netz HTTP/2 client for process-boundary interoperability with the
//! audited local Hyper server.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var connection = try netz.http2.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_frame_payload = 16 * 1024,
            .max_body_bytes = 4096,
        },
    );
    defer connection.close();

    var response = try connection.request(.{
        .method = "POST",
        .path = "/interop?from=netz",
        .scheme = "http",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-netz-request",
            .value = "request-header",
        }},
        .body = "request-body",
        .trailers = &.{.{
            .name = "x-netz-trailer",
            .value = "request-trailer",
        }},
    });
    defer response.deinit(allocator);

    if (response.status != 201 or
        !std.mem.eql(u8, response.body, "hyper-response") or
        !headerEquals(
            response.headers,
            "x-hyper-response",
            "response-header",
        ) or
        !headerEquals(
            response.trailers,
            "x-hyper-trailer",
            "response-trailer",
        ))
    {
        return error.InvalidResponse;
    }

    std.debug.print(
        "netz HTTP/2 client interoperated with Hyper: status=201 body=14 trailers=1\n",
        .{},
    );
}

fn headerEquals(
    headers: []const netz.http2.Hpack.HeaderField,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name)) {
            return std.mem.eql(u8, header.value, value);
        }
    }
    return false;
}

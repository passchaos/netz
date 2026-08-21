//! One-shot netz HTTP/1.1 client for process-boundary interoperability with
//! the audited local Hyper server.

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
    var client = try netz.http1.runtime.Client.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .max_body_bytes = 4096 },
    );
    defer client.close();

    var writer = try client.startRequest(.{
        .method = .POST,
        .target = "/interop?from=netz",
        .host = "localhost",
        .headers = &.{
            .{
                .name = "X-Netz-Request",
                .value = "request-header",
            },
            .{ .name = "TE", .value = "trailers" },
        },
        .trailer_names = &.{"X-Netz-Trailer"},
    });
    defer writer.deinit();
    try writer.writeChunks(&.{ "netz-", "request" });
    try writer.finishTrailers(&.{.{
        .name = "X-Netz-Trailer",
        .value = "request-trailer",
    }});
    var response = try writer.readResponse();
    defer response.deinit(allocator);
    if (response.response.status != 201 or
        !std.mem.eql(u8, response.response.body, "hyper-response") or
        !headerEquals(response.response.headers, "x-hyper-response", "response-header") or
        !headerEquals(response.response.trailers, "x-hyper-trailer", "response-trailer"))
    {
        std.debug.print(
            "unexpected Hyper response: status={d} body={s} headers={d} trailers={d}\n",
            .{
                response.response.status,
                response.response.body,
                response.response.headers.len,
                response.response.trailers.len,
            },
        );
        for (response.response.headers) |header| {
            std.debug.print("header {s}: {s}\n", .{ header.name, header.value });
        }
        for (response.response.trailers) |header| {
            std.debug.print("trailer {s}: {s}\n", .{ header.name, header.value });
        }
        return error.InvalidResponse;
    }
    std.debug.print(
        "netz HTTP/1 client interoperated with Hyper: status=201 body=14 trailers=1\n",
        .{},
    );
}

fn headerEquals(
    headers: []const netz.http1.Header,
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

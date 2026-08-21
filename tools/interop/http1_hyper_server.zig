//! One-shot netz HTTP/1.1 server for process-boundary interoperability with
//! the audited local Hyper client.

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
    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{ .max_body_bytes = 4096 },
    );
    defer server.deinit();
    std.debug.print(
        "netz HTTP/1 Hyper interop server listening on {f}\n",
        .{server.address()},
    );

    var connection = try server.accept();
    defer connection.close();
    var request = try connection.readRequest(.{});
    defer request.deinit(allocator);
    if (request.request.method != .POST or
        !std.mem.eql(u8, request.request.target, "/interop?from=hyper") or
        !std.mem.eql(u8, request.request.body, "hyper-request") or
        !headerEquals(request.request.headers, "x-hyper-request", "request-header") or
        !headerEquals(request.request.trailers, "x-hyper-trailer", "request-trailer"))
    {
        return error.InvalidRequest;
    }

    var response = try connection.startResponse(.{
        .status = 201,
        .reason = "Created",
        .headers = &.{.{
            .name = "X-Netz-Response",
            .value = "response-header",
        }},
        .trailer_names = &.{"X-Netz-Trailer"},
        .request_method = request.request.method,
    });
    defer response.deinit();
    try response.writeChunks(&.{ "netz-", "response" });
    try response.finishTrailers(&.{.{
        .name = "X-Netz-Trailer",
        .value = "response-trailer",
    }});
    std.debug.print(
        "netz HTTP/1 server interoperated with Hyper: method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1\n",
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

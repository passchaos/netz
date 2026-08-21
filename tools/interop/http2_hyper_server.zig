//! One-shot netz h2c server for process-boundary interoperability with the
//! audited local Hyper client.

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

    var server = try netz.http2.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(port) },
        .{
            .max_frame_payload = 16 * 1024,
            .max_body_bytes = 4096,
        },
    );
    defer server.deinit();
    std.debug.print(
        "netz HTTP/2 Hyper interop server listening on {f}\n",
        .{server.address()},
    );

    var connection = try server.accept();
    defer connection.close();
    var request = try connection.readRequest();
    defer request.deinit(allocator);
    if (!std.mem.eql(u8, request.method, "POST") or
        !std.mem.eql(u8, request.path, "/interop?from=hyper") or
        !std.mem.eql(u8, request.scheme, "http") or
        request.authority == null or
        !std.mem.eql(u8, request.authority.?, "localhost") or
        !std.mem.eql(u8, request.body, "hyper-request") or
        !headerEquals(
            request.headers,
            "x-hyper-request",
            "request-header",
        ) or
        !headerEquals(
            request.trailers,
            "x-hyper-trailer",
            "request-trailer",
        ))
    {
        return error.InvalidRequest;
    }

    // Exercise netz's stateful response writer instead of collapsing the
    // response into the single-frame convenience path. Hyper must reassemble
    // both DATA chunks and observe trailing HEADERS with END_STREAM.
    var response = try connection.startResponse(request.stream_id, .{
        .status = 201,
        .headers = &.{.{
            .name = "x-netz-response",
            .value = "response-header",
        }},
        .request_method = request.method,
    });
    defer response.deinit();
    try response.write("netz-");
    try response.write("response");
    try response.finishTrailers(&.{.{
        .name = "x-netz-trailer",
        .value = "response-trailer",
    }});

    std.debug.print(
        "netz HTTP/2 server interoperated with Hyper: method=POST body=13 trailers=1 status=201 response_body=13 response_trailers=1\n",
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

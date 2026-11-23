//! Decode a gzip response like `curl --compressed`.
//!
//! The server sends `Content-Encoding: gzip`; the client advertises the shared
//! `accept_encoding` offer and decodes the body with
//! `OwnedResponse.decodeContentAlloc`. Decoding is bounded by an explicit
//! output ceiling, works for H1/H2/H3, and applies stacked codings in wire
//! order. `decodeContentInto` is the caller-buffer counterpart.

const std = @import("std");
const netz = @import("netz");

const plaintext = "netz decodes content codings with a bounded, caller-owned buffer. " ** 8;

pub fn main() !void {
    var gpa = std.heap.DebugAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();

    var compressed: std.ArrayList(u8) = .empty;
    defer compressed.deinit(allocator);
    try gzipCompress(allocator, plaintext, &compressed);

    var server = try netz.http1.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_head_bytes = 4096, .max_body_bytes = 64 * 1024 },
    );
    defer server.deinit();

    const ServerTask = struct {
        server: *netz.http1.runtime.Server,
        body: []const u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var connection = try self.server.accept();
            defer connection.close();
            var request = try connection.readRequest(.{});
            defer request.deinit(self.server.allocator);
            try connection.writeResponse(.{
                .headers = &.{
                    .{ .name = "content-type", .value = "text/plain" },
                    .{ .name = "content-encoding", .value = "gzip" },
                },
                .body = self.body,
                .request_method = request.request.method,
            });
        }
    };

    var task = ServerTask{ .server = &server, .body = compressed.items };
    var server_task = io.async(ServerTask.run, .{&task});
    defer server_task.cancel(io);

    const uri = try std.fmt.allocPrint(
        allocator,
        "http://127.0.0.1:{d}/compressed",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var client = try netz.http.Client.init(allocator, io, .{});
    defer client.deinit();
    var response = try client.requestUriWithTimeout(uri, .{
        .method = "GET",
        .headers = &.{.{
            .name = "accept-encoding",
            .value = netz.http.content_coding.accept_encoding,
        }},
    }, .fromSeconds(10));
    defer response.deinit();

    const chain = try netz.http.content_coding.parse(
        response.header("content-encoding"),
    );
    var decoded = try response.decodeContentAlloc(allocator, 64 * 1024);
    defer decoded.deinit(allocator);
    std.debug.print(
        "content coding {t} {d}: {d} -> {d} bytes, codings={d}, match={}\n",
        .{
            response.protocol(),
            response.status(),
            response.body().len,
            decoded.bytes.len,
            chain.items().len,
            std.mem.eql(u8, decoded.bytes, plaintext),
        },
    );

    server_task.await(io);
    if (task.err) |err| return err;
}

fn gzipCompress(
    allocator: std.mem.Allocator,
    payload: []const u8,
    output: *std.ArrayList(u8),
) !void {
    output.clearRetainingCapacity();
    var allocating = std.Io.Writer.Allocating.fromArrayList(allocator, output);
    defer output.* = allocating.toArrayList();
    // Compress requires a non-trivial output buffer up front.
    try allocating.ensureTotalCapacity(payload.len +| 64);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &allocating.writer,
        &window,
        .gzip,
        .fastest,
    );
    try compressor.writer.writeAll(payload);
    // finish() writes the final block and the gzip CRC/size footer.
    try compressor.finish();
}

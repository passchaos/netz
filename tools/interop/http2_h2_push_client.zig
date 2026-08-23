//! Netz HTTP/2 client for server-push interoperability with Rust h2.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2 and args.len != 3) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    const tls_enabled = args.len == 3;
    if (tls_enabled and !std.Io.Dir.path.isAbsolute(args[2])) {
        return error.InvalidArgument;
    }

    const allocator = std.heap.c_allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: netz.http2.runtime.Limits = .{
        .max_frame_payload = 16 * 1024,
        .max_body_bytes = 64 * 1024,
        .enable_push = true,
    };
    var ca_bundle: std.crypto.Certificate.Bundle = .empty;
    defer ca_bundle.deinit(allocator);
    var ca_lock: std.Io.RwLock = .init;
    if (tls_enabled) {
        try ca_bundle.addCertsFromFilePathAbsolute(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            args[2],
        );
    }
    var connection = if (tls_enabled)
        try netz.http2.runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            port,
            limits,
            .{ .ca_bundle = .{ .bundle = &ca_bundle, .lock = &ca_lock } },
        )
    else
        try netz.http2.runtime.Client.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(port) },
            limits,
        );
    defer connection.close();

    var parent = try connection.request(.{
        .method = "GET",
        .path = "/push-parent",
        .scheme = "http",
        .authority = "localhost",
    });
    defer parent.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), parent.status);
    try std.testing.expectEqualStrings("hyper-parent", parent.body);
    try expectHeader(parent.headers, "x-hyper-parent", "yes");

    var promise = connection.takePromisedRequest() orelse
        return error.MissingPushPromise;
    defer promise.deinit(allocator);
    try std.testing.expectEqual(@as(u31, 1), promise.parent_stream_id);
    try std.testing.expectEqual(@as(u31, 2), promise.promised_stream_id);
    try expectHeader(promise.headers, ":method", "GET");
    try expectHeader(promise.headers, ":path", "/style.css");
    try expectHeader(promise.headers, ":scheme", "https");
    try expectHeader(promise.headers, ":authority", "localhost");
    try expectHeader(promise.headers, "accept", "text/css");

    var pushed = try connection.readPushedResponse(promise);
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), pushed.status);
    try std.testing.expectEqualStrings("hyper-pushed-css", pushed.body);
    try expectHeader(pushed.headers, "content-type", "text/css");
    try expectHeader(pushed.headers, "x-hyper-push", "yes");

    std.debug.print(
        "netz HTTP/2 client accepted h2 server push: transport={s} parent_stream=1 promised_stream=2 path=/style.css body=16\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

fn expectHeader(
    headers: []const netz.http2.Hpack.HeaderField,
    name: []const u8,
    value: []const u8,
) !void {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name) and
            std.mem.eql(u8, header.value, value)) return;
    }
    return error.MissingHeader;
}

//! Netz HTTP/2 client for server-push interoperability with Rust h2.

const std = @import("std");
const netz = @import("netz");

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 2 or args.len > 4) return error.InvalidArgument;
    const port = try std.fmt.parseInt(u16, args[1], 10);
    if (port == 0) return error.InvalidArgument;
    var certificate_path: ?[]const u8 = null;
    var informational = false;
    for (args[2..]) |arg| {
        if (std.mem.eql(u8, arg, "--informational") and !informational) {
            informational = true;
        } else if (certificate_path == null and
            std.Io.Dir.path.isAbsolute(arg))
        {
            certificate_path = arg;
        } else {
            return error.InvalidArgument;
        }
    }
    const tls_enabled = certificate_path != null;

    const allocator = std.heap.c_allocator;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
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
            certificate_path.?,
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
    if (informational) {
        try runInformational(&connection, tls_enabled);
        return;
    }

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
        "netz HTTP/2 client accepted h2 server push: transport={s} parent_stream=1 promised_stream=2 path=/style.css body=16 client_io=zio-std-io server_io=rust-h2-tokio\n",
        .{if (tls_enabled) "tls" else "h2c"},
    );
}

const InformationalState = struct {
    statuses: [2]u16 = undefined,
    headers_valid: bool = true,
    count: usize = 0,

    fn observe(
        context: *anyopaque,
        head: netz.http2.runtime.StreamingResponseHead,
    ) void {
        const self: *InformationalState = @ptrCast(@alignCast(context));
        if (self.count >= self.statuses.len) {
            self.headers_valid = false;
            return;
        }
        self.statuses[self.count] = head.status;
        const expected_name = if (head.status == 103)
            "link"
        else
            "x-progress";
        const expected_value = if (head.status == 103)
            "</style.css>; rel=preload"
        else
            "half";
        self.headers_valid = self.headers_valid and
            hasHeader(head.headers, expected_name, expected_value);
        self.count += 1;
    }
};

fn runInformational(
    connection: *netz.http2.runtime.Connection,
    tls_enabled: bool,
) !void {
    var observer = InformationalState{};
    var response = try connection.requestWithInformational(.{
        .method = "GET",
        .path = "/informational",
        .scheme = "http",
        .authority = "localhost",
    }, .{
        .context = &observer,
        .on_response = InformationalState.observe,
    });
    defer response.deinit(connection.allocator);
    try std.testing.expectEqualSlices(
        u16,
        &.{ 103, 102 },
        observer.statuses[0..observer.count],
    );
    try std.testing.expect(observer.headers_valid);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("final", response.body);
    try std.testing.expect(hasHeader(
        response.headers,
        "x-h2-final",
        "yes",
    ));
    std.debug.print(
        "netz HTTP/2 client observed h2 informational responses: transport={s} statuses=103,102 final=200 body=5 client_io=zio-std-io server_io=rust-h2-tokio\n",
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

fn hasHeader(
    headers: []const netz.http2.Hpack.HeaderField,
    name: []const u8,
    value: []const u8,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, name) and
            std.mem.eql(u8, header.value, value)) return true;
    }
    return false;
}

const std = @import("std");
const netz = @import("netz");
const digest = netz.http.digest;
const payload = "independent HTTP digest " ** 12;
const generated_body = "{\"hello\": \"world\"}";

fn Response(comptime h2: bool) type {
    return if (h2) netz.http2.runtime.OwnedResponse else netz.http1.runtime.OwnedResponse;
}

fn exchange(comptime h2: bool, connection: anytype, until: std.Io.Clock.Timestamp, path: []const u8) !Response(h2) {
    return if (h2)
        connection.requestWithDeadline(.{ .path = path }, until)
    else
        connection.requestWithDeadline(.{ .target = path }, until);
}

fn owned(comptime h2: bool, response: Response(h2), allocator: std.mem.Allocator) netz.http.OwnedResponse {
    return .{ .allocator = allocator, .value = if (h2) .{ .http2 = response } else .{ .http1 = response } };
}

fn run(comptime h2: bool, allocator: std.mem.Allocator, connection: anytype, until: std.Io.Clock.Timestamp) !void {
    {
        var response = owned(h2, try exchange(h2, connection, until, "/header"), allocator);
        defer response.deinit();
        try std.testing.expectEqual(netz.http.DigestResult.sha256, try response.verifyContentDigest(.{}));
        var decoded = try response.decodeContentAlloc(allocator, 4096);
        defer decoded.deinit(allocator);
        try std.testing.expectEqualStrings(payload, decoded.bytes);
        const fields = [_]netz.http.Header{.{ .name = "content-digest", .value = response.header("content-digest").? }};
        try std.testing.expectError(error.DigestMismatch, digest.verifyContent(decoded.bytes, &fields, &.{}, .{}));
    }
    {
        var response = owned(h2, try exchange(h2, connection, until, "/trailer"), allocator);
        defer response.deinit();
        try std.testing.expectEqual(netz.http.DigestResult.sha512, try response.verifyContentDigest(.{}));
        try std.testing.expectEqualStrings(payload, response.body());
    }
    for ([_][]const u8{ "/corrupt", "/missing", "/unsupported", "/malformed" }, 0..) |path, index| {
        var response = owned(h2, try exchange(h2, connection, until, path), allocator);
        defer response.deinit();
        switch (index) {
            0 => try std.testing.expectError(error.DigestMismatch, response.verifyContentDigest(.{})),
            1 => {
                try std.testing.expectError(error.MissingContentDigest, response.verifyContentDigest(.{}));
                try std.testing.expectEqual(netz.http.DigestResult.absent, try response.verifyContentDigest(.{ .required = false }));
            },
            2 => try std.testing.expectError(error.NoSupportedDigest, response.verifyContentDigest(.{})),
            3 => try std.testing.expectError(error.InvalidDigestField, response.verifyContentDigest(.{})),
            else => unreachable,
        }
    }
    {
        const Consumer = struct {
            hasher: netz.http.DigestHasher,
            calls: usize = 0,

            fn consume(self: *@This(), bytes: []const u8) !void {
                try self.hasher.update(bytes);
                self.calls += 1;
            }
        };
        var consumer = Consumer{ .hasher = try netz.http.DigestHasher.init(.{ .max_content_bytes = payload.len }) };
        var response = if (h2)
            try connection.requestStreamingWithDeadline(.{ .path = "/stream" }, until, &consumer, Consumer.consume)
        else
            try connection.requestStreamingWithDeadline(.{ .target = "/stream" }, until, &consumer, Consumer.consume);
        defer response.deinit(allocator);
        try std.testing.expectEqual(payload.len, consumer.hasher.bytes);
        try std.testing.expect(consumer.calls > 1);
        const field = try digest.parseMessage(.content, response.headers, response.trailers, .{});
        try std.testing.expectEqual(netz.http.DigestResult.sha512, try digest.verifyComputed(field, try consumer.hasher.finish(), .{}));
    }
    {
        var storage: [digest.max_value_bytes]u8 = undefined;
        const value = try (try digest.compute(generated_body, .{})).writeInto(&storage);
        const preferences = netz.http.DigestPreferences{ .sha256 = 3, .sha512 = 10 };
        var preference_storage: [32]u8 = undefined;
        const preference_value = try preferences.writeInto(&preference_storage);
        const Header = if (h2) netz.http2.Hpack.HeaderField else netz.http1.Header;
        const headers = [_]Header{
            .{ .name = "content-digest", .value = value },
            .{ .name = "want-content-digest", .value = preference_value },
        };
        const response = if (h2)
            try connection.requestWithDeadline(.{ .method = "POST", .path = "/generated", .body = generated_body, .headers = &headers }, until)
        else
            try connection.requestWithDeadline(.{ .method = .POST, .target = "/generated", .body = generated_body, .headers = &headers }, until);
        var wrapped = owned(h2, response, allocator);
        defer wrapped.deinit();
        try std.testing.expectEqual(netz.http.DigestResult.sha512, try wrapped.verifyContentDigest(.{}));
        try std.testing.expectEqualStrings("verified", wrapped.body());
    }
    std.debug.print("HTTP digest {s} passed: requests=8 compressed=true trailers=true errors=4 streaming=true generated=true reuse=true io=zio-std-io\n", .{if (h2) "h2" else "h1"});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) return error.InvalidArgument;
    var backend = try netz.runtime.Backend.init(allocator);
    defer backend.deinit();
    const io = backend.io();
    var ca: std.crypto.Certificate.Bundle = .empty;
    defer ca.deinit(allocator);
    try ca.addCertsFromFilePathAbsolute(allocator, io, std.Io.Clock.real.now(io), args[3]);
    var ca_lock: std.Io.RwLock = .init;
    const until: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(10), .clock = .awake });
    var h1 = try netz.http1.runtime.Client.connectTlsAddressWithDeadline(allocator, io, .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[1], 10)) }, "origin.internal", "origin.internal", .{ .max_body_bytes = 4096 }, .{ .ca_bundle = .{ .bundle = &ca, .lock = &ca_lock } }, until);
    defer h1.close();
    try run(false, allocator, &h1, until);
    var h2 = try netz.http2.runtime.Client.connectTlsAddressWithDeadline(allocator, io, .{ .ip4 = .loopback(try std.fmt.parseInt(u16, args[2], 10)) }, "origin.internal", "origin.internal", .{ .max_body_bytes = 4096 }, .{ .ca_bundle = .{ .bundle = &ca, .lock = &ca_lock }, .protocol_policy = .tls13_only }, until);
    defer h2.close();
    try run(true, allocator, &h2, until);
}

const std = @import("std");
const netz = @import("netz");
const common = @import("common.zig");

pub fn run(allocator: std.mem.Allocator, io: std.Io, port: u16, version: netz.quic.Version, ca_path: []const u8) !void {
    var ca: std.crypto.Certificate.Bundle = .empty;
    defer ca.deinit(allocator);
    const now = std.Io.Clock.real.now(io);
    try ca.addCertsFromFilePathAbsolute(allocator, io, now, ca_path);
    var verifier = netz.quic.tls.trust.BundleVerifier{ .bundle = &ca, .now_seconds = now.toSeconds() };
    var dcid: [8]u8 = undefined;
    var cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &dcid);
    try std.Io.randomSecure(io, &cid);
    var client = try netz.http3.runtime.HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, .{ .ip4 = .loopback(port) }, .{ .quic = .{ .max_datagram_size = 4096 } }, .{
        .handshake = .{
            .original_destination_connection_id = &dcid,
            .local_connection_id = &cid,
            .version = version,
            .available_versions = if (version == .version_1) &.{.version_1} else &.{.version_2},
            .server_name = "localhost",
            .server_auth = verifier.clientVerifier(),
            .local_transport_parameters = common.parameters(),
            .initial_one_rtt_config = .{ .receive_window = 8192, .max_receive_window = 8192, .stream_receive_window = 2048, .max_stream_receive_window = 2048, .max_datagram_size = 1200 },
        },
        .session = .{ .max_stream_buffer = 64 * 1024, .max_stream_frame_data = 1200 },
    });
    defer client.deinit();
    for (common.paths) |path| {
        const until = common.deadline(io);
        if (std.mem.eql(u8, path, "/stream")) {
            try streaming(&client, until, allocator);
            continue;
        }
        var value_storage: [154]u8 = undefined;
        var trailer_storage: [154]u8 = undefined;
        const is_generated = std.mem.eql(u8, path, "/generated");
        const headers = [_]netz.http3.Qpack.HeaderField{
            .{ .name = "content-digest", .value = try common.field(common.generated, false, false, &value_storage) },
            .{ .name = "want-content-digest", .value = "sha-256=3, sha-512=10" },
        };
        const trailers = [_]netz.http3.Qpack.HeaderField{.{ .name = "content-digest", .value = try common.field(common.generated, false, true, &trailer_storage) }};
        var response = try client.requestWithDeadline(.{
            .method = if (is_generated) "POST" else if (std.mem.eql(u8, path, "/head")) "HEAD" else "GET",
            .path = path,
            .scheme = "https",
            .authority = "localhost",
            .body = if (is_generated) common.generated else "",
            .headers = if (is_generated) &headers else &.{},
            .trailers = if (is_generated) &trailers else &.{},
        }, until);
        defer response.deinit(allocator);
        if (std.mem.eql(u8, path, "/corrupt")) {
            try std.testing.expectError(error.DigestMismatch, response.verifyContentDigest(.{}));
            continue;
        }
        _ = try response.verifyContentDigest(.{});
        if (std.mem.eql(u8, path, "/encoded")) {
            var decoded = try response.response.decodeContentAlloc(allocator, common.payload.len);
            defer decoded.deinit(allocator);
            try std.testing.expectEqualStrings(common.payload, decoded.bytes);
        } else if (std.mem.eql(u8, path, "/head") or std.mem.eql(u8, path, "/range")) {
            _ = try netz.http.digest.verify(.representation, common.payload, response.response.headers, response.response.trailers, .{});
            if (std.mem.eql(u8, path, "/head")) {
                try std.testing.expectEqual(@as(usize, 0), response.response.body.len);
            } else {
                try std.testing.expectEqual(@as(u16, 206), response.response.status);
                try std.testing.expectEqualStrings(common.payload[8..72], response.response.body);
            }
            try std.testing.expectError(error.DigestMismatch, netz.http.digest.verify(.representation, response.response.body, response.response.headers, response.response.trailers, .{}));
        } else {
            const expected = if (is_generated) "verified" else if (std.mem.eql(u8, path, "/finish")) "done" else common.payload;
            try std.testing.expectEqualStrings(expected, response.response.body);
        }
    }
    std.debug.print("RESULT {{\"role\":\"netz-client\",\"version\":{d},\"requests\":8,\"streaming\":true,\"corruption_detected\":true,\"representation_scope\":true,\"io\":\"zio-std-io\"}}\n", .{if (version == .version_1) @as(u8, 1) else 2});
}

fn streaming(client: *netz.http3.runtime.HandshakeClient, until: std.Io.Clock.Timestamp, allocator: std.mem.Allocator) !void {
    const id = try client.startRequestWithDeadline(.{ .method = "GET", .path = "/stream", .scheme = "https", .authority = "localhost" }, 0, until);
    var hasher = try netz.http.DigestHasher.init(.{ .max_content_bytes = common.payload.len });
    var expected: ?netz.http.digest.Field = null;
    var reads: usize = 0;
    var finished = false;
    while (!finished) {
        var event = try client.receiveNextResponseEventWithDeadline(until);
        defer event.deinit(allocator);
        if (event != .message or event.message.stream_id != id) return error.UnexpectedResponse;
        switch (event.message.value) {
            .head => |head| if (head != .response or head.response.status != 200) return error.UnexpectedResponse,
            .data_available => {
                var buffer: [333]u8 = undefined;
                const count = try client.readResponseData(id, &buffer);
                if (count == 0) continue;
                if (count > common.payload.len - hasher.bytes) return error.UnexpectedResponse;
                try std.testing.expectEqualSlices(u8, common.payload[hasher.bytes..][0..count], buffer[0..count]);
                try hasher.update(buffer[0..count]);
                reads += 1;
            },
            .trailers => |trailers| expected = try netz.http.digest.parseMessage(.content, &[_]netz.http3.Qpack.HeaderField{}, trailers.fields, .{}),
            .finished => finished = true,
            .push_promise => return error.UnexpectedResponse,
        }
    }
    try std.testing.expect(reads > 1);
    try std.testing.expectEqual(common.payload.len, hasher.bytes);
    try std.testing.expectEqual(netz.http.DigestResult.sha256_and_sha512, try netz.http.digest.verifyComputed(expected orelse return error.MissingTrailer, try hasher.finish(), .{}));
}

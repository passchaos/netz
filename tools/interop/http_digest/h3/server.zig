const std = @import("std");
const netz = @import("netz");
const common = @import("common.zig");

pub fn run(allocator: std.mem.Allocator, io: std.Io, port: u16, version: netz.quic.Version, cert: []const u8, key: []const u8) !void {
    var identity = try netz.tls.server_identity_file.load(allocator, io, .cwd(), cert, key);
    defer identity.deinit();
    var cid: [8]u8 = undefined;
    try std.Io.randomSecure(io, &cid);
    var server = try netz.http3.runtime.HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(port) }, .{ .quic = .{ .max_datagram_size = 4096 } }, .{
        .handshake = .{
            .local_connection_id = &cid,
            .version = version,
            .available_versions = if (version == .version_1) &.{.version_1} else &.{.version_2},
            .local_transport_parameters = common.parameters(),
            .initial_one_rtt_config = .{ .receive_window = 8192, .max_receive_window = 8192, .stream_receive_window = 2048, .max_stream_receive_window = 2048, .max_datagram_size = 1200 },
            .identity = identity.serverIdentity(),
        },
        .session = .{ .max_stream_buffer = 64 * 1024, .max_stream_frame_data = 1200 },
    });
    defer server.deinit();
    std.debug.print("READY {d}\n", .{server.address().getPort()});
    var session = try server.acceptWithTimeout(.fromSeconds(15));
    defer session.deinit();
    var gzip_storage: [common.payload.len + 23]u8 = undefined;
    const encoded = common.gzip(&gzip_storage);
    for (common.paths) |path| {
        const until = common.deadline(io);
        var request = try session.receiveRequestWithDeadline(until);
        defer request.deinit(allocator);
        try std.testing.expectEqualStrings(path, request.request.path);
        const method = if (std.mem.eql(u8, path, "/head")) "HEAD" else if (std.mem.eql(u8, path, "/generated")) "POST" else "GET";
        try std.testing.expectEqualStrings(method, request.request.method);
        if (std.mem.eql(u8, path, "/generated")) {
            try std.testing.expectEqualStrings(common.generated, request.request.body);
            try std.testing.expectEqual(netz.http.DigestResult.sha256_and_sha512, try netz.http.digest.verifyContent(request.request.body, request.request.headers, request.request.trailers, .{}));
            const preferences = try netz.http.digest.parsePreferenceHeaders(.content, request.request.headers, .{});
            try std.testing.expectEqual(@as(?netz.http.DigestAlgorithm, .sha512), try preferences.select(.{}));
        }
        var field_storage: [154]u8 = undefined;
        var representation_storage: [154]u8 = undefined;
        var headers: [4]netz.http3.Qpack.HeaderField = undefined;
        var trailers: [1]netz.http3.Qpack.HeaderField = undefined;
        var header_count: usize = 0;
        var trailer_count: usize = 0;
        var content: []const u8 = common.payload;
        var length_storage: [32]u8 = undefined;
        if (std.mem.eql(u8, path, "/encoded")) {
            content = encoded;
            headers[header_count] = .{ .name = "content-encoding", .value = "gzip" };
            header_count += 1;
        } else if (std.mem.eql(u8, path, "/range")) {
            content = common.payload[8..72];
        } else if (std.mem.eql(u8, path, "/generated")) {
            content = "verified";
        } else if (std.mem.eql(u8, path, "/finish")) {
            content = "done";
        }
        const streaming = std.mem.eql(u8, path, "/stream");
        const head = std.mem.eql(u8, path, "/head");
        const trailer = std.mem.eql(u8, path, "/trailer") or streaming;
        const corrupt = std.mem.eql(u8, path, "/corrupt");
        var values = try netz.http.digest.compute(if (head) "" else content, .{ .sha256 = !trailer or streaming, .sha512 = trailer or corrupt });
        if (corrupt) values.sha512.?[0] ^= 1;
        const value = try values.writeInto(&field_storage);
        if (trailer) {
            trailers[0] = .{ .name = "content-digest", .value = value };
            trailer_count = 1;
        } else {
            headers[header_count] = .{ .name = "content-digest", .value = value };
            header_count += 1;
        }
        if (head or std.mem.eql(u8, path, "/range")) {
            headers[header_count] = .{ .name = "repr-digest", .value = try common.field(common.payload, false, true, &representation_storage) };
            header_count += 1;
        }
        if (head) {
            headers[header_count] = .{ .name = "content-length", .value = try std.fmt.bufPrint(&length_storage, "{d}", .{common.payload.len}) };
            header_count += 1;
        }
        try session.sendResponsePacedWithDeadline(request.stream_id, .{
            .status = if (std.mem.eql(u8, path, "/range")) 206 else 200,
            .request_method = request.request.method,
            .body = content,
            .headers = headers[0..header_count],
            .trailers = trailers[0..trailer_count],
        }, until);
    }
    std.debug.print("RESULT {{\"role\":\"netz-server\",\"version\":{d},\"requests\":8,\"generated_verified\":true,\"io\":\"zio-std-io\"}}\n", .{if (version == .version_1) @as(u8, 1) else 2});
}

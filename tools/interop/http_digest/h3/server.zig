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
            .initial_one_rtt_config = .{ .key_update_profile = if (version == .version_2) .quic_go_v0_59 else .rfc, .receive_window = 8192, .max_receive_window = 8192, .stream_receive_window = 2048, .max_stream_receive_window = 2048, .max_datagram_size = 1200 },
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
        const method = if (std.mem.eql(u8, path, "/head")) "HEAD" else if (std.mem.eql(u8, path, "/generated") or std.mem.eql(u8, path, "/sliced")) "POST" else "GET";
        try std.testing.expectEqualStrings(method, request.request.method);
        if (std.mem.eql(u8, path, "/sliced")) {
            try std.testing.expectEqualStrings(common.payload, request.request.body);
            _ = try netz.http.digest.verifyContent(request.request.body, request.request.headers, request.request.trailers, .{});
            var storage: [154]u8 = undefined;
            const trailers = [_]netz.http3.Qpack.HeaderField{.{ .name = "content-digest", .value = try common.field(common.payload, true, false, &storage) }};
            try session.startResponseWithDeadline(request.stream_id, .{ .status = 200 }, common.payload.len, until);
            const parts = [_][]const u8{ common.payload[0..17], common.payload[17..101], "", common.payload[101..4091], common.payload[4091..] };
            if (version == .version_1) {
                try session.sendResponseBodyPartsPaced(request.stream_id, &parts, false);
            } else {
                var progress: netz.http3.runtime.BodyWriteProgress = .{};
                try session.sendResponseBodyPartsPacedWithDeadline(request.stream_id, &parts, false, &progress, until);
                try std.testing.expectEqual(common.payload.len, progress.committed_bytes);
                try std.testing.expect(!progress.fin_committed);
            }
            try session.finishResponseTrailersPacedWithDeadline(request.stream_id, &trailers, until);
            continue;
        }
        if (std.mem.eql(u8, path, "/generated")) {
            try std.testing.expectEqualStrings(common.generated, request.request.body);
            try std.testing.expectEqual(netz.http.DigestResult.sha256_and_sha512, try netz.http.digest.verifyContent(request.request.body, request.request.headers, request.request.trailers, .{}));
            const preferences = try netz.http.digest.parsePreferenceHeaders(.content, request.request.headers, .{});
            try std.testing.expectEqual(@as(?netz.http.DigestAlgorithm, .sha512), try preferences.select(.{}));
        }
        var field_storage: [154]u8 = undefined;
        var representation_storage: [154]u8 = undefined;
        var headers: [4]netz.http3.Qpack.HeaderField = undefined;
        var trailers: [2]netz.http3.Qpack.HeaderField = undefined;
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
        const large_fields = std.mem.eql(u8, path, "/trailer");
        if (large_fields) {
            headers[header_count] = .{ .name = "x-large-head", .value = common.large_head };
            header_count += 1;
            trailers[trailer_count] = .{ .name = "x-large-trailer", .value = common.large_trailer };
            trailer_count += 1;
        }
        const reply = netz.http3.Response{
            .status = if (std.mem.eql(u8, path, "/range")) 206 else 200,
            .request_method = request.request.method,
            .body = content,
            .headers = headers[0..header_count],
            .trailers = trailers[0..trailer_count],
        };
        if (large_fields) {
            try session.sendResponseWithInformationalAndDeadline(request.stream_id, &.{.{ .status = 103, .headers = &.{.{ .name = "x-large-early", .value = common.large_early }} }}, reply, until);
        } else {
            try session.sendResponsePacedWithDeadline(request.stream_id, reply, until);
        }
    }
    std.debug.print("RESULT {{\"role\":\"netz-server\",\"version\":{d},\"requests\":9,\"generated_verified\":true,\"io\":\"zio-std-io\"}}\n", .{if (version == .version_1) @as(u8, 1) else 2});
}

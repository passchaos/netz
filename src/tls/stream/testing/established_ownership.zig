//! Deterministic allocation failure at the TLS result-to-stream boundary.
const std = @import("std");
const vail = @import("vail");
const tls_testing = @import("../../testing.zig");

const IoProbe = struct {
    closes: usize = 0,

    fn close(context: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
        const self: *@This() = @ptrCast(@alignCast(context.?));
        self.closes += handles.len;
    }
};

const stream: std.Io.net.Stream = .{
    .socket = .{
        // This boundary only stores the handle. The fake close callback never
        // reads it, and deinitWithoutCloseNotify never performs record I/O.
        .handle = undefined,
        .address = .{ .ip4 = .loopback(0) },
    },
};

fn fixture(comptime Established: type, allocator: std.mem.Allocator) !Established {
    var result: Established = .{ .tls13 = undefined };
    const Application = @TypeOf(result.tls13.application);
    var read = try vail.tls.secret.Secret.init(.sha256, &([_]u8{0x11} ** 32));
    defer read.deinit();
    var write = try vail.tls.secret.Secret.init(.sha256, &([_]u8{0x22} ** 32));
    defer write.deinit();
    var application: Application = undefined;
    try application.initInto(.aes_128_gcm_sha256, read, write);
    errdefer application.deinit();
    application.traffic.read.next_sequence_number = 7;
    application.traffic.write.next_sequence_number = 11;
    const alpn = try allocator.dupe(u8, "http/1.1");
    errdefer allocator.free(alpn);
    const chain = try allocator.alloc([]const u8, 1);
    errdefer allocator.free(chain);
    const certificate = try allocator.alloc(u8, tls_testing.certificate_der_len);
    errdefer allocator.free(certificate);
    try std.base64.standard.Decoder.decode(certificate, tls_testing.certificate_base64);
    chain[0] = certificate;
    result.tls13 = .{
        .allocator = allocator,
        .application = application,
        .master_secret = try vail.tls.secret.Secret.init(.sha256, &([_]u8{0x33} ** 32)),
        .exporter_master_secret = try vail.tls.secret.Secret.init(.sha256, &([_]u8{0x44} ** 32)),
        .transcript_after_client_finished = .{ .hash = .sha256, .storage = [_]u8{0x55} ** vail.tls.secret.max_len },
        .selected_alpn = alpn,
        .peer_certificate_chain = chain,
        .resumed = false,
        .early_data_accepted = false,
        .certificate_compression = null,
        .client_certificate_compression = null,
        .server_certificate_type = .x509,
        .client_certificate_type = .x509,
        .local_record_size_limit = null,
        .peer_record_size_limit = null,
        .expected_ticket_count = null,
        .application_settings_codepoint = null,
        .local_application_settings = null,
        .peer_application_settings = null,
        .ech_accepted = false,
    };
    return result;
}

pub fn failure(comptime convert: anytype, comptime Established: type) !void {
    const allocator = std.testing.allocator;
    var probe: IoProbe = .{};
    var table = std.Io.failing.vtable.*;
    table.netClose = IoProbe.close;
    const io: std.Io = .{ .userdata = &probe, .vtable = &table };
    for ([_]usize{ 0, 1 }) |fail_index| {
        var established = try fixture(Established, allocator);
        const alpn = established.tls13.selected_alpn.?;
        const chain = established.tls13.peer_certificate_chain;
        defer {
            // Restore prematurely detached buffers so the old implementation
            // fails its ownership assertion without leaking the test fixture.
            if (established.tls13.selected_alpn == null) established.tls13.selected_alpn = alpn;
            if (established.tls13.peer_certificate_chain.len == 0) established.tls13.peer_certificate_chain = chain;
            established.deinit();
        }
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index });
        try std.testing.expectError(error.OutOfMemory, convert(failing.allocator(), io, stream, "example.test", 0, true, &established));
        try std.testing.expect(established.tls13.selected_alpn != null);
        try std.testing.expectEqual(alpn.ptr, established.tls13.selected_alpn.?.ptr);
        try std.testing.expectEqual(chain.ptr, established.tls13.peer_certificate_chain.ptr);
        try std.testing.expectEqual(@as(usize, 1), established.tls13.peer_certificate_chain.len);
        try std.testing.expect(!established.tls13.application.secrets_extracted);
        try std.testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), established.tls13.application.traffic.read.traffic_secret.bytes());
        try std.testing.expectEqualSlices(u8, &([_]u8{0x22} ** 32), established.tls13.application.traffic.write.traffic_secret.bytes());
        try std.testing.expectEqual(@as(usize, 0), probe.closes);
    }
}

pub fn success(comptime convert: anytype, comptime Established: type) !void {
    const allocator = std.testing.allocator;
    var probe: IoProbe = .{};
    var table = std.Io.failing.vtable.*;
    table.netClose = IoProbe.close;
    const io: std.Io = .{ .userdata = &probe, .vtable = &table };
    for ([_]bool{ false, true }) |retain_ticket| {
        var established = try fixture(Established, allocator);
        var transferred = false;
        defer if (!transferred) established.deinit();
        const alpn = established.tls13.selected_alpn.?;
        const chain = established.tls13.peer_certificate_chain;
        const connection = try convert(allocator, io, stream, "example.test", 0, retain_ticket, &established);
        transferred = true;
        var connection_owned = true;
        defer if (connection_owned) connection.deinitWithoutCloseNotify();
        try std.testing.expectEqual(alpn.ptr, connection.selected_alpn.?.ptr);
        try std.testing.expectEqual(chain.ptr, connection.peer_certificate_chain.ptr);
        try std.testing.expectEqual(@as(u64, 7), connection.records.tls13.read_sequence);
        try std.testing.expectEqual(@as(u64, 11), connection.records.tls13.write_sequence);
        try std.testing.expectEqualSlices(u8, &([_]u8{0x11} ** 32), connection.records.tls13.read_traffic_secret.bytes());
        try std.testing.expectEqualSlices(u8, &([_]u8{0x22} ** 32), connection.records.tls13.write_traffic_secret.bytes());
        try std.testing.expectEqual(retain_ticket, connection.tls13_ticket_context != null);
        if (connection.tls13_ticket_context) |context| {
            try std.testing.expectEqualStrings("example.test", context.server_name);
            try std.testing.expectEqualSlices(u8, &([_]u8{0x33} ** 32), context.master_secret.bytes());
        }
        connection.deinitWithoutCloseNotify();
        connection_owned = false;
    }
    try std.testing.expectEqual(@as(usize, 2), probe.closes);
}

//! EOF body retention above independently authenticated TLS stream readers.
const std = @import("std");
const runtime = @import("../../runtime.zig");
const tls = @import("../../../tls/mod.zig").stream;
const tls_testing = @import("../../../tls/testing.zig");
const close_delimited = @import("close_delimited.zig");
const allocator = std.testing.allocator;
const Backend = enum { native12, native13, standard13 };
const payload = [_]u8{'t'} ** (20 * 1024);

test "HTTP1 EOF body allocation retries preserve native and standard TLS plaintext" {
    inline for (std.enums.values(Backend)) |backend| {
        var succeeded = false;
        for (0..16) |fail_index| {
            if (try exercise(backend, fail_index)) {
                succeeded = true;
                break;
            }
        }
        try std.testing.expect(succeeded);
    }
}

fn exercise(comptime backend: Backend, fail_index: usize) !bool {
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{});
    defer listener.deinit(io);
    var certificate: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate, tls_testing.certificate_base64);
    const key = try tls_testing.serverKeyPair();
    const Peer = struct {
        listener: *@TypeOf(listener),
        io: std.Io,
        certificate: []const u8,
        key: @TypeOf(key),
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.send() catch |err| {
                self.err = err;
            };
        }
        fn send(self: *@This()) !void {
            const socket = try self.listener.accept(self.io);
            var owned = true;
            errdefer if (owned) socket.close(self.io);
            const connection = try tls.ServerConnection.init(allocator, self.io, socket, .{
                .identity = .{ .certificate_chain = &.{self.certificate}, .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = self.key } } },
                .protocol_policy = if (backend == .native12) .tls12_only else .tls13_only,
            });
            owned = false;
            defer connection.deinit();
            try connection.writeAll(&payload);
            try connection.sendCloseNotify();
        }
    };
    var peer = Peer{ .listener = &listener, .io = io, .certificate = &certificate, .key = key };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();
    const socket = try listener.socket.address.connect(io, .{ .mode = .stream });
    var owned = true;
    errdefer if (owned) socket.close(io);
    const connection = if (backend == .standard13)
        try runtime.TlsClientConnection.init(allocator, io, socket, "localhost", .{ .verify_host = false })
    else
        try tls.ClientConnection.init(allocator, io, socket, .{
            .server_name = "localhost",
            .server_verifier = .{ .pinned_ecdsa_p256_public_key = key.public_key.toUncompressedSec1() },
            .protocol_policy = if (backend == .native12) .tls12_only else .tls13_only,
        });
    owned = false;
    defer connection.deinit();
    const Context = struct {
        pub const TransportType = @TypeOf(connection);
        pub const ErrorType = runtime.Error;
        pub fn readUntil(transport: TransportType, output: []u8, deadline: ?std.Io.Clock.Timestamp) ErrorType!usize {
            return if (deadline) |value| transport.readWithDeadline(output, value) else transport.read(output);
        }
    };
    var input = std.ArrayList(u8).fromOwnedSlice(try allocator.dupe(u8, "headprefix/"));
    defer input.deinit(allocator);
    var scratch: [4096]u8 = undefined;
    const limit = "prefix/".len + payload.len;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = fail_index, .resize_fail_index = 0 });
    const result = close_delimited.Reader(Context).collect(failing.allocator(), connection, &input, 4, limit, &scratch, deadline);
    if (failing.has_induced_failure) {
        try std.testing.expectError(error.OutOfMemory, result);
        try std.testing.expect(std.mem.startsWith(u8, input.items, "headprefix/"));
        try close_delimited.Reader(Context).collect(allocator, connection, &input, 4, limit, &scratch, deadline);
    } else try result;
    try std.testing.expectEqualStrings("headprefix/", input.items[0.."headprefix/".len]);
    try std.testing.expectEqualStrings(&payload, input.items["headprefix/".len..]);
    // Authenticated close_notify remains definitive EOF across later reads.
    var byte: [1]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), try connection.read(&byte));
    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    return !failing.has_induced_failure;
}

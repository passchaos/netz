const std = @import("std");
const runtime = @import("../../runtime.zig");
const identity = @import("../tls_client_identity.zig");
const tls_testing = @import("../../../tls/testing.zig");
const alpn_server = @import("../../../tls/alpn_server.zig");
const net = std.Io.net;

const CloseProbe = struct {
    var active: *CloseProbe = undefined;
    base: std.Io,
    table: std.Io.VTable,
    handle: net.Socket.Handle = undefined,
    captured: std.atomic.Value(bool) = .init(false),
    closes: std.atomic.Value(usize) = .init(0),

    fn init(base: std.Io) CloseProbe {
        var table = base.vtable.*;
        table.netConnectIp = connect;
        table.netClose = close;
        return .{ .base = base, .table = table };
    }

    fn io(self: *CloseProbe) std.Io {
        active = self;
        return .{ .userdata = self.base.userdata, .vtable = &self.table };
    }

    fn deinit(self: *CloseProbe) void {
        // Rescue a missing close without hiding the failed count assertion.
        if (self.captured.load(.acquire) and self.closes.load(.monotonic) == 0) {
            self.base.vtable.netClose(self.base.userdata, &.{self.handle});
        }
    }

    fn connect(userdata: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
        const self = active;
        const socket = try self.base.vtable.netConnectIp(userdata, address, options);
        self.handle = socket.handle;
        self.captured.store(true, .release);
        return socket;
    }

    fn close(userdata: ?*anyopaque, handles: []const net.Socket.Handle) void {
        const self = active;
        for (handles) |handle| {
            if (self.captured.load(.acquire) and handle == self.handle) {
                // Count every invocation but prevent an unfixed second close
                // from hitting a descriptor reused by another fixture task.
                if (self.closes.fetchAdd(1, .monotonic) != 0) continue;
            }
            self.base.vtable.netClose(userdata, &.{handle});
        }
    }
};

test "WSS vail TLS rejection closes one socket across client entry points" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const parent = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(&certificate_der, tls_testing.certificate_base64);
    const key_pair = try tls_testing.serverKeyPair();
    var server = try alpn_server.Server.listen(allocator, parent, .{
        .address = .{ .ip4 = .loopback(0) },
        .tls = .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .alpn_protocols = &.{"h2"},
        },
    });
    defer server.deinit();
    const Peer = struct {
        server: *alpn_server.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const accepted = try self.server.acceptWithTimeout(.fromSeconds(5));
            defer accepted.tls.deinit();
            try std.testing.expectEqualStrings("h2", accepted.tls.negotiatedAlpn().?);
            // Rejection occurs after authenticated TLS, before any Upgrade.
            var byte: [1]u8 = undefined;
            try std.testing.expectEqual(@as(usize, 0), try accepted.tls.readWithDeadline(&byte, .fromNow(self.server.io, .{ .raw = .fromSeconds(5), .clock = .awake })));
        }
    };
    const Route = enum { host, address, uri, adopted };
    for ([_]runtime.tls_stream.VersionPolicy{ .tls12_only, .tls13_only }) |policy| {
        for ([_]Route{ .host, .address, .uri, .adopted }) |route| {
            var probe = CloseProbe.init(parent);
            defer probe.deinit();
            const io = probe.io();
            var peer = Peer{ .server = &server };
            const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
            var joined = false;
            defer if (!joined) thread.join();
            const options: runtime.ConnectOptions = .{
                .host = "localhost",
                .vail_tls = .{
                    .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() },
                    .alpn_protocols = &.{"h2"},
                    .protocol_policy = policy,
                },
            };
            const tls: runtime.http1_runtime.TlsClientOptions = .{ .verify_host = false };
            const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake });
            var uri_buffer: [80]u8 = undefined;
            const uri = try std.fmt.bufPrint(&uri_buffer, "wss://127.0.0.1:{d}/", .{server.address().getPort()});
            const result = switch (route) {
                .host => runtime.Client.connectTlsHostWithDeadline(allocator, io, "127.0.0.1", server.address().getPort(), options, tls, deadline),
                .address => runtime.Client.connectTlsAddressWithDeadline(allocator, io, server.address(), "localhost", options, tls, deadline),
                .uri => runtime.Client.connectUriTlsWithDeadline(allocator, io, uri, options, tls, deadline),
                .adopted => runtime.Client.connectAcceptedTlsStreamWithDeadline(allocator, io, try server.address().connect(io, .{ .mode = .stream }), "localhost", options, tls, deadline),
            };
            if (result) |value| {
                var client = value;
                client.close();
                return error.TestExpectedError;
            } else |err| try std.testing.expectEqual(@as(anyerror, error.InvalidAlpn), err);
            thread.join();
            joined = true;
            if (peer.err) |err| return err;
            try std.testing.expect(probe.captured.load(.acquire));
            try std.testing.expectEqual(@as(usize, 1), probe.closes.load(.monotonic));
        }
    }
}

test "WSS vail TLS helper failure closes its input stream" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const parent = threaded.io();
    const key_pair = try tls_testing.serverKeyPair();
    inline for (.{ false, true }) |out_of_memory| {
        var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(parent, .{});
        defer listener.deinit(parent);
        var probe = CloseProbe.init(parent);
        defer probe.deinit();
        const io = probe.io();
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        const peer = try listener.accept(parent);
        defer peer.close(parent);
        var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
        const result = identity.initWithDeadline(
            if (out_of_memory) failing.allocator() else allocator,
            io,
            stream,
            "localhost",
            .{ .verify_host = false },
            .{
                .server_verifier = .{ .pinned_ecdsa_p256_public_key = key_pair.public_key.toUncompressedSec1() },
                .protocol_policy = .tls13_only,
                .handshake_timeout = if (out_of_memory) null else .zero,
            },
            .fromNow(io, .{ .raw = .fromSeconds(5), .clock = .awake }),
        );
        if (result) |connection| {
            connection.deinit();
            return error.TestExpectedError;
        } else |err| try std.testing.expectEqual(@as(anyerror, if (out_of_memory) error.OutOfMemory else error.Timeout), err);
        try std.testing.expectEqual(@as(usize, 1), probe.closes.load(.monotonic));
        var byte: [1]u8 = undefined;
        var buffers = [_][]u8{&byte};
        try std.testing.expectEqual(@as(usize, 0), try parent.vtable.netRead(parent.userdata, peer.socket.handle, &buffers));
    }
}

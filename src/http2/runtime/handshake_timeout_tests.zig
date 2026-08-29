const std = @import("std");
const http2 = @import("../mod.zig");
const runtime = @import("../runtime.zig");
const tls_stream = @import("../../tls/mod.zig").stream;
const tls_testing = @import("../../tls/testing.zig");

const net = std.Io.net;
const flag_ack: u8 = 0x1;

fn writeAll(io: std.Io, stream: net.Stream, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (count == 0) return error.SocketUnconnected;
        offset += count;
    }
}

fn readExact(io: std.Io, stream: net.Stream, bytes: []u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        var buffers = [_][]u8{bytes[offset..]};
        const count = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &buffers,
        );
        if (count == 0) return error.ConnectionClosed;
        offset += count;
    }
}

fn writeFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    frame_type: http2.FrameType,
    flags: u8,
    payload: []const u8,
) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http2.Frame{
        .header = .{
            .length = 0,
            .frame_type = frame_type,
            .flags = flags,
            .stream_id = 0,
        },
        .payload = payload,
    }).write(&encoded, allocator);
    try writeAll(io, stream, encoded.items);
}

fn readFrame(
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
) ![]u8 {
    var header_bytes: [http2.FrameHeader.encoded_len]u8 = undefined;
    try readExact(io, stream, &header_bytes);
    const header = try http2.FrameHeader.parse(&header_bytes);
    const bytes = try allocator.alloc(u8, header_bytes.len + header.length);
    errdefer allocator.free(bytes);
    @memcpy(bytes[0..header_bytes.len], &header_bytes);
    try readExact(io, stream, bytes[header_bytes.len..]);
    _ = try http2.Frame.parse(bytes);
    return bytes;
}

fn expectSettingsFrame(bytes: []const u8, ack: bool) !void {
    const frame = try http2.Frame.parse(bytes);
    try std.testing.expectEqual(http2.FrameType.settings, frame.header.frame_type);
    try std.testing.expectEqual(ack, (frame.header.flags & flag_ack) != 0);
}

fn writeH2cUpgradeRequest(io: std.Io, stream: net.Stream) !void {
    // This is the base64url encoding of the default client SETTINGS payload.
    // acceptUpgrade verifies that the binary SETTINGS repeated after 101 is
    // byte-for-byte identical, as required by RFC 7540 section 3.2.1.
    try writeAll(
        io,
        stream,
        "GET /timeout HTTP/1.1\r\n" ++
            "Host: localhost\r\n" ++
            "Connection: Upgrade, HTTP2-Settings\r\n" ++
            "Upgrade: h2c\r\n" ++
            "HTTP2-Settings: AAEAABAAAAQAAP__AAYAAEAAAAIAAAAA\r\n\r\n",
    );
}

fn ignorePeerCloseWriteError(err: anyerror) !void {
    switch (err) {
        error.BrokenPipe,
        error.ConnectionResetByPeer,
        error.SocketUnconnected,
        => {},
        else => return err,
    }
}

test "HTTP/2 server handshake times out before the client preface" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .handshake_timeout = .fromMilliseconds(75) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/2 server handshake deadline is absolute across a trickled preface" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .handshake_timeout = .fromMilliseconds(150) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);

    try writeAll(io, client, http2.connection_preface[0..8]);
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    try writeAll(io, client, http2.connection_preface[8..16]);
    try std.Io.sleep(io, .fromMilliseconds(80), .awake);
    writeAll(io, client, http2.connection_preface[16..]) catch |err|
        try ignorePeerCloseWriteError(err);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/2 client handshake times out waiting for server SETTINGS" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);
            try std.testing.expectEqual(
                http2.FrameType.settings,
                (try http2.Frame.parse(settings)).header.frame_type,
            );
            try std.Io.sleep(self.io, .fromMilliseconds(200), .awake);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{ .handshake_timeout = .fromMilliseconds(75) },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 caller deadline spans TCP setup and SETTINGS handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);
            try std.Io.sleep(self.io, .fromMilliseconds(150), .awake);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) thread.join();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectWithDeadline(
            allocator,
            io,
            listener.socket.address,
            .{
                .connect_timeout = .fromSeconds(1),
                .handshake_timeout = .fromSeconds(1),
            },
            .fromNow(io, .{
                .raw = .fromMilliseconds(20),
                .clock = .awake,
            }),
        ),
    );
    thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/2 caller deadline retains shorter connect timeout" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectWithDeadline(
            allocator,
            io,
            .{ .ip4 = .loopback(1) },
            .{ .connect_timeout = .zero },
            .fromNow(io, .{ .raw = .fromSeconds(1), .clock = .awake }),
        ),
    );
}

test "HTTP/2 connection timeout rejects a non-positive budget" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectWithTimeout(
            std.testing.allocator,
            threaded.io(),
            .{ .ip4 = .loopback(1) },
            .{},
            .zero,
        ),
    );
}

test "HTTP/2 server SETTINGS does not renew the client handshake deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);
            // Receiving and applying the server's SETTINGS is real progress,
            // but it must not replace the absolute deadline while the ACK for
            // the client's initial SETTINGS is still missing.
            try std.Io.sleep(self.io, .fromMilliseconds(80), .awake);
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                0,
                &.{},
            );
            const client_ack = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(client_ack);
            try expectSettingsFrame(client_ack, true);
            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
            writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                flag_ack,
                &.{},
            ) catch |err| try ignorePeerCloseWriteError(err);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{ .handshake_timeout = .fromMilliseconds(150) },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 control frames do not renew the client handshake deadline" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const ping_payload = [8]u8{ 1, 3, 3, 7, 9, 9, 4, 2 };
    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        ping: [8]u8,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);

            try std.Io.sleep(self.io, .fromMilliseconds(80), .awake);
            try writeFrame(
                self.allocator,
                self.io,
                stream,
                .ping,
                0,
                &self.ping,
            );
            const ping_ack_bytes = try readFrame(
                self.allocator,
                self.io,
                stream,
            );
            defer self.allocator.free(ping_ack_bytes);
            const ping_ack = try http2.Frame.parse(ping_ack_bytes);
            try std.testing.expectEqual(http2.FrameType.ping, ping_ack.header.frame_type);
            try std.testing.expect((ping_ack.header.flags & flag_ack) != 0);
            try std.testing.expectEqualSlices(u8, &self.ping, ping_ack.payload);

            try std.Io.sleep(self.io, .fromMilliseconds(100), .awake);
            writeFrame(
                self.allocator,
                self.io,
                stream,
                .settings,
                0,
                &.{},
            ) catch |err| try ignorePeerCloseWriteError(err);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
        .ping = ping_payload,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{ .handshake_timeout = .fromMilliseconds(150) },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 handshake accepts a normal exchange with a nonzero budget" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const limits: runtime.Limits = .{
        .max_frame_payload = 4096,
        .max_body_bytes = 4096,
        .handshake_timeout = .fromSeconds(2),
    };
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        limits,
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer connection.close();
            var request = connection.readRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            connection.writeResponse(request.stream_id, .{
                .body = "bounded-handshake",
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try runtime.Client.connect(allocator, io, server.address(), limits);
    defer client.close();
    var response = try client.request(.{ .path = "/bounded" });
    defer response.deinit(allocator);
    try std.testing.expectEqualStrings("bounded-handshake", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 zero handshake timeout fails before bootstrap writes" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connect(
            allocator,
            io,
            listener.socket.address,
            .{ .handshake_timeout = .zero },
        ),
    );
}

test "HTTP/2 h2c server bounds the Upgrade request head" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .handshake_timeout = .fromMilliseconds(75) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var upgrade = self.server.acceptUpgrade() catch |err| {
                self.err = err;
                return;
            };
            upgrade.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/2 h2c server bounds binary bootstrap after 101" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .handshake_timeout = .fromMilliseconds(75) },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var upgrade = self.server.acceptUpgrade() catch |err| {
                self.err = err;
                return;
            };
            upgrade.deinit(self.server.allocator);
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const client = try server.address().connect(io, .{ .mode = .stream });
    defer client.close(io);
    try writeH2cUpgradeRequest(io, client);
    var response: [71]u8 = undefined;
    try readExact(io, client, &response);
    try std.testing.expect(std.mem.startsWith(u8, &response, "HTTP/1.1 101"));

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/2 h2c client bounds the 101 response head" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            const stream = self.listener.accept(self.io) catch |err| {
                self.err = err;
                return;
            };
            defer stream.close(self.io);
            std.Io.sleep(self.io, .fromMilliseconds(200), .awake) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .io = io, .listener = &listener };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectStreamUpgrade(
            allocator,
            io,
            try listener.socket.address.connect(io, .{ .mode = .stream }),
            .{ .handshake_timeout = .fromMilliseconds(75) },
            .{ .authority = "localhost" },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 h2c client bounds SETTINGS after 101" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var request_buf: [1024]u8 = undefined;
            var request_len: usize = 0;
            while (std.mem.indexOf(u8, request_buf[0..request_len], "\r\n\r\n") == null) {
                var buffers = [_][]u8{request_buf[request_len..]};
                const count = try self.io.vtable.netRead(
                    self.io.userdata,
                    stream.socket.handle,
                    &buffers,
                );
                if (count == 0) return error.ConnectionClosed;
                request_len += count;
            }
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Upgrade: h2c\r\n\r\n",
            );
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);
            try expectSettingsFrame(settings, false);
            try std.Io.sleep(self.io, .fromMilliseconds(200), .awake);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectStreamUpgrade(
            allocator,
            io,
            stream,
            .{ .handshake_timeout = .fromMilliseconds(75) },
            .{ .authority = "localhost" },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 h2c caller deadline spans 101 and binary bootstrap" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var request_buf: [1024]u8 = undefined;
            var request_len: usize = 0;
            while (std.mem.indexOf(u8, request_buf[0..request_len], "\r\n\r\n") == null) {
                var buffers = [_][]u8{request_buf[request_len..]};
                const count = try self.io.vtable.netRead(
                    self.io.userdata,
                    stream.socket.handle,
                    &buffers,
                );
                if (count == 0) return error.ConnectionClosed;
                request_len += count;
            }

            // Consume part of the caller's budget before switching protocols.
            // The binary bootstrap must inherit the remaining time rather than
            // starting a fresh phase-sized wait after the 101 response.
            try std.Io.sleep(self.io, .fromMilliseconds(25), .awake);
            try writeAll(
                self.io,
                stream,
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Upgrade: h2c\r\n\r\n",
            );
            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);
            try expectSettingsFrame(settings, false);
            try std.Io.sleep(self.io, .fromMilliseconds(150), .awake);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    const deadline = std.Io.Clock.Timestamp.fromNow(
        io,
        .{ .raw = .fromMilliseconds(50), .clock = .awake },
    );

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectStreamUpgradeWithDeadline(
            allocator,
            io,
            stream,
            .{ .handshake_timeout = .fromSeconds(1) },
            .{ .authority = "localhost" },
            deadline,
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 h2c deadline preserves SETTINGS coalesced with 101" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            defer stream.close(self.io);
            var request_buf: [1024]u8 = undefined;
            var request_len: usize = 0;
            while (std.mem.indexOf(u8, request_buf[0..request_len], "\r\n\r\n") == null) {
                var buffers = [_][]u8{request_buf[request_len..]};
                const count = try self.io.vtable.netRead(
                    self.io.userdata,
                    stream.socket.handle,
                    &buffers,
                );
                if (count == 0) return error.ConnectionClosed;
                request_len += count;
            }

            var response: std.ArrayList(u8) = .empty;
            defer response.deinit(self.allocator);
            try response.appendSlice(
                self.allocator,
                "HTTP/1.1 101 Switching Protocols\r\n" ++
                    "Connection: Upgrade\r\n" ++
                    "Upgrade: h2c\r\n\r\n",
            );
            // A legal peer may put its first HTTP/2 frame in the same TCP
            // segment as the switching response. The unbuffered HTTP/1 reader
            // must stop exactly at CRLFCRLF so bootstrap can still consume it.
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .settings,
                    .flags = 0,
                    .stream_id = 0,
                },
                .payload = &.{},
            }).write(&response, self.allocator);
            try (http2.Frame{
                .header = .{
                    .length = 0,
                    .frame_type = .settings,
                    .flags = flag_ack,
                    .stream_id = 0,
                },
                .payload = &.{},
            }).write(&response, self.allocator);
            try writeAll(self.io, stream, response.items);

            var preface: [http2.connection_preface.len]u8 = undefined;
            try readExact(self.io, stream, &preface);
            try http2.validateClientPreface(&preface);
            const settings = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(settings);
            try expectSettingsFrame(settings, false);
            const ack = try readFrame(self.allocator, self.io, stream);
            defer self.allocator.free(ack);
            try expectSettingsFrame(ack, true);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var upgraded = try runtime.Client.connectStreamUpgradeWithTimeout(
        allocator,
        io,
        try listener.socket.address.connect(io, .{ .mode = .stream }),
        .{ .handshake_timeout = .fromSeconds(1) },
        .{ .authority = "localhost" },
        .fromSeconds(1),
    );
    upgraded.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/2 TLS server bounds bootstrap after transport handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var server = try runtime.TlsServer.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
            .limits = .{
                .handshake_timeout = .fromMilliseconds(75),
            },
            .cipher_suites = &.{.aes_128_gcm_sha256},
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *runtime.TlsServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var connection = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            connection.close();
            self.err = error.TestUnexpectedResult;
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    const stream = try server.address().connect(io, .{ .mode = .stream });
    var stream_owned = true;
    defer if (stream_owned) stream.close(io);
    const client = try tls_stream.ClientConnection.init(allocator, io, stream, .{
        .server_name = "localhost",
        .server_verifier = .{
            .pinned_ecdsa_p256_public_key = public_key,
        },
        .alpn_protocols = &.{"h2"},
        .cipher_suites = &.{.aes_128_gcm_sha256},
    });
    stream_owned = false;
    defer client.deinit();
    try std.testing.expectEqualStrings("h2", client.selected_alpn.?);

    thread.join();
    try std.testing.expectEqual(error.Timeout, shared.err.?);
}

test "HTTP/2 TLS client bounds bootstrap after transport handshake" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var listener = try (net.IpAddress{ .ip4 = .loopback(0) }).listen(
        io,
        .{ .reuse_address = true },
    );
    defer listener.deinit(io);

    const Shared = struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        listener: *net.Server,
        certificate: *const [tls_testing.certificate_der_len]u8,
        key_pair: std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            const stream = try self.listener.accept(self.io);
            var stream_owned = true;
            defer if (stream_owned) stream.close(self.io);
            const server = try tls_stream.ServerConnection.init(
                self.allocator,
                self.io,
                stream,
                .{
                    .identity = .{
                        .certificate_chain = &.{self.certificate},
                        .signer = .{ .ecdsa_p256_sha256 = .{
                            .key_pair = self.key_pair,
                        } },
                    },
                    .alpn_protocols = &.{"h2"},
                    .cipher_suites = &.{.aes_128_gcm_sha256},
                },
            );
            stream_owned = false;
            defer server.deinit();
            try std.testing.expectEqualStrings("h2", server.selected_alpn.?);
            try std.Io.sleep(self.io, .fromMilliseconds(200), .awake);
        }
    };
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .listener = &listener,
        .certificate = &certificate_der,
        .key_pair = key_pair,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    try std.testing.expectError(
        error.Timeout,
        runtime.Client.connectTlsHost(
            allocator,
            io,
            "localhost",
            listener.socket.address.ip4.port,
            .{ .handshake_timeout = .fromMilliseconds(75) },
            .{
                .server_verifier = .{
                    .pinned_ecdsa_p256_public_key = public_key,
                },
                .cipher_suites = &.{.aes_128_gcm_sha256},
            },
        ),
    );
    thread.join();
    if (shared.err) |err| return err;
}

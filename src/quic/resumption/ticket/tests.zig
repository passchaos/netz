const std = @import("std");
const ticket = @import("mod.zig");
const quic = @import("../../mod.zig");

test "stateless ticket keyring seals context-bound rotating tickets" {
    var keyring = try ticket.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0x11} ** ticket.keyring.key_len,
    });
    defer keyring.deinit();
    const opened = ticket.keyring.Opened{
        .secret = [_]u8{0x42} ** 32,
        .age_add = 17,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
    };
    const identity = try keyring.seal(
        [_]u8{0x01} ** ticket.keyring.nonce_len,
        "example:443",
        "h3",
        opened,
    );
    const decoded = try keyring.open(
        &identity,
        "example:443",
        "h3",
        1500,
    );
    try std.testing.expectEqualSlices(u8, &opened.secret, &decoded.secret);
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.open(&identity, "other:443", "h3", 1500),
    );
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.open(&identity, "example:443", "hq", 1500),
    );

    try keyring.rotate(.{
        .id = 2,
        .secret = [_]u8{0x22} ** ticket.keyring.key_len,
    });
    _ = try keyring.open(&identity, "example:443", "h3", 1500);
    const current = try keyring.seal(
        [_]u8{0x02} ** ticket.keyring.nonce_len,
        "example:443",
        "h3",
        opened,
    );
    try std.testing.expectEqual(@as(u32, 2), keyring.currentId());
    _ = try keyring.open(&current, "example:443", "h3", 1500);

    var tampered = identity;
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(
        error.AuthenticationFailed,
        keyring.open(&tampered, "example:443", "h3", 1500),
    );
    try std.testing.expectError(
        error.ExpiredTicket,
        keyring.open(&identity, "example:443", "h3", 11_001),
    );
}

test "stateless ticket keyring bounds retained rotation history" {
    var keyring = try ticket.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{1} ** ticket.keyring.key_len,
    });
    defer keyring.deinit();
    const identity = try keyring.seal(
        [_]u8{0} ** ticket.keyring.nonce_len,
        "example:443",
        "h3",
        .{
            .secret = [_]u8{9} ** 32,
            .age_add = 0,
            .issued_at_ms = 1000,
            .lifetime_seconds = 100,
        },
    );
    inline for (2..ticket.keyring.max_keys + 2) |id| {
        try keyring.rotate(.{
            .id = id,
            .secret = [_]u8{@intCast(id)} ** ticket.keyring.key_len,
        });
    }
    try std.testing.expectError(
        error.UnknownKey,
        keyring.open(&identity, "example:443", "h3", 1500),
    );
}

test "NewSessionTicket codec round-trips QUIC early-data permission" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ticket.codec.write(&encoded, std.testing.allocator, .{
        .lifetime_seconds = 3600,
        .age_add = 0x01020304,
        .nonce = "nonce",
        .ticket = "opaque-ticket",
        .allow_early_data = true,
    });

    const parsed = try ticket.codec.parse(encoded.items);
    try std.testing.expectEqual(@as(u32, 3600), parsed.lifetime_seconds);
    try std.testing.expectEqual(@as(u32, 0x01020304), parsed.age_add);
    try std.testing.expectEqualStrings("nonce", parsed.nonce);
    try std.testing.expectEqualStrings("opaque-ticket", parsed.ticket);
    try std.testing.expectEqual(
        @as(?u32, ticket.codec.quic_early_data_size),
        parsed.max_early_data_size,
    );
}

test "NewSessionTicket codec rejects invalid QUIC early-data values" {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(std.testing.allocator);
    try ticket.codec.write(&encoded, std.testing.allocator, .{
        .lifetime_seconds = 10,
        .age_add = 0,
        .nonce = &.{},
        .ticket = "ticket",
        .allow_early_data = true,
    });
    encoded.items[encoded.items.len - 1] = 0xfe;
    try std.testing.expectError(
        error.InvalidEarlyDataSize,
        ticket.codec.parse(encoded.items),
    );
}

test "session ticket PSK derivation is nonce and transcript bound" {
    const master = [_]u8{0x42} ** 32;
    const first_rms = ticket.codec.deriveResumptionMasterSecret(
        master,
        [_]u8{0x11} ** 32,
    );
    const second_rms = ticket.codec.deriveResumptionMasterSecret(
        master,
        [_]u8{0x12} ** 32,
    );
    const first = ticket.codec.derivePsk(first_rms, "nonce-1");
    const again = ticket.codec.derivePsk(first_rms, "nonce-1");
    const other_nonce = ticket.codec.derivePsk(first_rms, "nonce-2");
    try std.testing.expectEqualSlices(u8, &first, &again);
    try std.testing.expect(!std.mem.eql(u8, &first, &other_nonce));
    try std.testing.expect(!std.mem.eql(
        u8,
        &first,
        &ticket.codec.derivePsk(second_rms, "nonce-1"),
    ));
}

test "server ticket store owns, expires, and evicts LRU entries" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var store = try ticket.ServerStore.init(
        std.testing.allocator,
        threaded.io(),
        2,
    );
    defer store.deinit();

    var first_identity = [_]u8{ 'o', 'n', 'e' };
    try store.issue(.{
        .identity = &first_identity,
        .secret = [_]u8{1} ** 32,
        .age_add = 1,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
    });
    @memset(&first_identity, 'x');
    try store.issue(.{
        .identity = "two",
        .secret = [_]u8{2} ** 32,
        .age_add = 2,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
    });
    var first = (try store.lookup("one", 1001)).?;
    first.deinit();
    try store.issue(.{
        .identity = "three",
        .secret = [_]u8{3} ** 32,
        .age_add = 3,
        .issued_at_ms = 1002,
        .lifetime_seconds = 10,
    });
    try std.testing.expect((try store.lookup("two", 1002)) == null);
    var one = (try store.lookup("one", 1002)).?;
    one.deinit();
    var three = (try store.lookup("three", 1002)).?;
    three.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.count(12_001));
}

fn checkCodecAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try ticket.codec.write(&encoded, allocator, .{
        .lifetime_seconds = 10,
        .age_add = 7,
        .nonce = "nonce",
        .ticket = "ticket",
        .allow_early_data = true,
    });
    _ = try ticket.codec.parse(encoded.items);
}

test "NewSessionTicket encoding is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkCodecAllocationFailure,
        .{},
    );
}

fn checkServerStoreAllocationFailure(allocator: std.mem.Allocator) !void {
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var store = try ticket.ServerStore.init(allocator, threaded.io(), 2);
    defer store.deinit();
    try store.issue(.{
        .identity = "first",
        .secret = [_]u8{1} ** 32,
        .age_add = 1,
        .issued_at_ms = 1000,
        .lifetime_seconds = 10,
    });
    try store.issue(.{
        .identity = "second",
        .secret = [_]u8{2} ** 32,
        .age_add = 2,
        .issued_at_ms = 1001,
        .lifetime_seconds = 10,
    });
    var lease = (try store.lookup("first", 1002)).?;
    defer lease.deinit();
    try std.testing.expectEqualStrings("first", lease.identity);
}

test "server ticket store is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkServerStoreAllocationFailure,
        .{},
    );
}

test "integrated handshake uses server-Finished application traffic secrets" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        err: ?anyerror = null,
        received_ping: bool = false,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            var packet = established.connection.receivePacket() catch |err| {
                shared.err = err;
                return;
            };
            defer packet.deinit(shared.endpoint.allocator);
            for (packet.frames) |frame| {
                if (frame == .ping) shared.received_ping = true;
            }
        }
    };
    var shared = Shared{ .endpoint = &server_endpoint };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "appkey01",
            .local_connection_id = "client",
            .random = [_]u8{0xf3} ** 32,
            .x25519_secret_key = [_]u8{0xf4} ** 32,
        },
    );
    defer client.deinit();
    try client.connection.send(&.{.{ .ping = {} }});
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(shared.received_ping);
}

test "integrated handshake issues caches and automatically resumes a ticket" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    var client_cache = try quic.resumption.Cache.init(allocator, 4);
    defer client_cache.deinit();
    var server_store = try ticket.ServerStore.init(allocator, io, 4);
    defer server_store.deinit();

    const FirstServer = struct {
        endpoint: *quic.runtime.Endpoint,
        store: *ticket.ServerStore,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            _ = established.issueSessionTicket(shared.endpoint.io, .{
                .store = shared.store,
                .now_ms = 1000,
                .lifetime_seconds = 3600,
                .allow_early_data = true,
                .nonce = [_]u8{0x11} ** 16,
                .identity = [_]u8{0x22} ** 32,
                .age_add = 17,
            }) catch |err| {
                shared.err = err;
            };
        }
    };
    var first_server = FirstServer{
        .endpoint = &server_endpoint,
        .store = &server_store,
    };
    const first_thread = try std.Thread.spawn(
        .{},
        FirstServer.run,
        .{&first_server},
    );
    var first_client = try quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "first001",
            .local_connection_id = "client",
            .random = [_]u8{0xe3} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        },
    );
    try first_client.receiveAndCacheSessionTicket(.{
        .cache = &client_cache,
        .server_id = "localhost:443",
        .now_ms = 1000,
    });
    first_thread.join();
    if (first_server.err) |err| return err;
    try std.testing.expect(!first_client.resumed);
    try std.testing.expectEqual(@as(usize, 1), client_cache.count());
    try std.testing.expectEqual(@as(usize, 1), server_store.count(1000));
    first_client.deinit();

    const SecondServer = struct {
        endpoint: *quic.runtime.Endpoint,
        store: *ticket.ServerStore,
        err: ?anyerror = null,
        resumed: bool = false,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0xe5} ** 32,
                .x25519_secret_key = [_]u8{0xe6} ** 32,
                .auto_resumption = .{
                    .allocator = shared.endpoint.allocator,
                    .store = shared.store,
                    .now_ms = 1500,
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            shared.resumed = established.resumed;
            established.deinit();
        }
    };
    var second_server = SecondServer{
        .endpoint = &server_endpoint,
        .store = &server_store,
    };
    const second_thread = try std.Thread.spawn(
        .{},
        SecondServer.run,
        .{&second_server},
    );
    var second_client = try quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "second01",
            .local_connection_id = "client",
            .random = [_]u8{0xe7} ** 32,
            .x25519_secret_key = [_]u8{0xe8} ** 32,
            .auto_resumption = .{
                .cache = &client_cache,
                .server_id = "localhost:443",
                .now_ms = 1500,
            },
        },
    );
    defer second_client.deinit();
    second_thread.join();
    if (second_server.err) |err| return err;
    try std.testing.expect(second_client.resumed);
    try std.testing.expect(second_server.resumed);
}

test "integrated handshake resumes stateless tickets across key rotation" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer server_endpoint.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer client_endpoint.deinit();
    var client_cache = try quic.resumption.Cache.init(allocator, 2);
    defer client_cache.deinit();
    var keyring = try ticket.Keyring.init(.{
        .id = 1,
        .secret = [_]u8{0x71} ** ticket.keyring.key_len,
    });
    defer keyring.deinit();

    const FirstServer = struct {
        endpoint: *quic.runtime.Endpoint,
        keyring: *ticket.Keyring,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x81} ** 32,
                .x25519_secret_key = [_]u8{0x82} ** 32,
            }) catch |err| {
                shared.err = err;
                return;
            };
            defer established.deinit();
            _ = established.issueSessionTicket(shared.endpoint.io, .{
                .stateless = .{
                    .keyring = shared.keyring,
                    .server_id = "localhost:443",
                    .alpn = "h3",
                    .nonce = [_]u8{0x33} ** ticket.keyring.nonce_len,
                },
                .now_ms = 1000,
                .lifetime_seconds = 3600,
                .nonce = [_]u8{0x44} ** 16,
                .age_add = 19,
            }) catch |err| {
                shared.err = err;
            };
        }
    };
    var first_server = FirstServer{
        .endpoint = &server_endpoint,
        .keyring = &keyring,
    };
    const first_thread = try std.Thread.spawn(
        .{},
        FirstServer.run,
        .{&first_server},
    );
    var first_client = try quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "state001",
            .local_connection_id = "client",
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
    );
    try first_client.receiveAndCacheSessionTicket(.{
        .cache = &client_cache,
        .server_id = "localhost:443",
        .now_ms = 1000,
    });
    first_thread.join();
    if (first_server.err) |err| return err;
    first_client.deinit();
    try std.testing.expectEqual(@as(usize, 1), client_cache.count());

    try keyring.rotate(.{
        .id = 2,
        .secret = [_]u8{0x72} ** ticket.keyring.key_len,
    });

    const SecondServer = struct {
        endpoint: *quic.runtime.Endpoint,
        keyring: *ticket.Keyring,
        err: ?anyerror = null,
        resumed: bool = false,

        fn run(shared: *@This()) void {
            var established = quic.handshake.accept(shared.endpoint, .{
                .local_connection_id = "server",
                .random = [_]u8{0x85} ** 32,
                .x25519_secret_key = [_]u8{0x86} ** 32,
                .auto_resumption = .{
                    .allocator = shared.endpoint.allocator,
                    .stateless = .{
                        .keyring = shared.keyring,
                        .server_id = "localhost:443",
                        .alpn = "h3",
                    },
                    .now_ms = 1500,
                },
            }) catch |err| {
                shared.err = err;
                return;
            };
            shared.resumed = established.resumed;
            established.deinit();
        }
    };
    var second_server = SecondServer{
        .endpoint = &server_endpoint,
        .keyring = &keyring,
    };
    const second_thread = try std.Thread.spawn(
        .{},
        SecondServer.run,
        .{&second_server},
    );
    var second_client = try quic.handshake.connect(
        &client_endpoint,
        server_endpoint.address(),
        .{
            .original_destination_connection_id = "state002",
            .local_connection_id = "client",
            .random = [_]u8{0x87} ** 32,
            .x25519_secret_key = [_]u8{0x88} ** 32,
            .auto_resumption = .{
                .cache = &client_cache,
                .server_id = "localhost:443",
                .now_ms = 1500,
            },
        },
    );
    defer second_client.deinit();
    second_thread.join();
    if (second_server.err) |err| return err;
    try std.testing.expect(second_client.resumed);
    try std.testing.expect(second_server.resumed);
}

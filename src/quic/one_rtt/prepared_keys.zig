const std = @import("std");
const protection = @import("../protection.zig");

const Prepared = protection.PreparedPacketProtectionKeys;

/// Stable connection-owned storage for directional packet-protection state.
/// TLS negotiates one suite for both directions, so prepared AES connections
/// keep both directions in one allocation. Direct preconfigured callers with
/// AES in only one direction retain a compact single prepared-key object.
pub const Set = struct {
    const Pair = struct {
        send: Prepared,
        receive: Prepared,
    };

    const Storage = union(enum) {
        none,
        pair: *Pair,
        send_only: *Prepared,
        receive_only: *Prepared,
    };

    storage: Storage = .none,
    send_keys: ?*Prepared = null,
    receive_keys: ?*Prepared = null,

    pub fn init(
        allocator: std.mem.Allocator,
        send_keys: protection.PacketProtectionKeys,
        receive_keys: protection.PacketProtectionKeys,
    ) std.mem.Allocator.Error!Set {
        const prepare_send = supports(send_keys);
        const prepare_receive = supports(receive_keys);
        if (prepare_send and prepare_receive) {
            const pair = try allocator.create(Pair);
            pair.* = .{
                .send = .init(send_keys),
                .receive = .init(receive_keys),
            };
            return .{
                .storage = .{ .pair = pair },
                .send_keys = &pair.send,
                .receive_keys = &pair.receive,
            };
        }
        if (prepare_send) {
            const prepared = try allocator.create(Prepared);
            prepared.* = .init(send_keys);
            return .{
                .storage = .{ .send_only = prepared },
                .send_keys = prepared,
            };
        }
        if (prepare_receive) {
            const prepared = try allocator.create(Prepared);
            prepared.* = .init(receive_keys);
            return .{
                .storage = .{ .receive_only = prepared },
                .receive_keys = prepared,
            };
        }
        return .{};
    }

    pub fn deinit(self: *Set, allocator: std.mem.Allocator) void {
        switch (self.storage) {
            .none => {},
            .pair => |pair| {
                pair.send.deinit();
                pair.receive.deinit();
                allocator.destroy(pair);
            },
            .send_only, .receive_only => |prepared| prepared.destroy(allocator),
        }
        self.* = .{};
    }

    pub inline fn send(self: *const Set) ?*const Prepared {
        return self.send_keys;
    }

    pub inline fn receive(self: *const Set) ?*const Prepared {
        return self.receive_keys;
    }

    pub fn replaceSend(self: *Set, keys: protection.PacketProtectionKeys) void {
        const prepared = self.send_keys orelse return;
        prepared.replace(keys);
    }

    pub fn replaceReceive(self: *Set, keys: protection.PacketProtectionKeys) void {
        const prepared = self.receive_keys orelse return;
        prepared.replace(keys);
    }

    fn supports(keys: protection.PacketProtectionKeys) bool {
        return protection.prepared_packet_protection_enabled and
            switch (keys.suite) {
                .aes_128_gcm_sha256, .aes_256_gcm_sha384 => true,
                else => false,
            };
    }
};

test "prepared key set owns AES directions together" {
    try std.testing.expect(protection.prepared_packet_protection_enabled);

    const aes = protection.deriveAes128Keys(
        [_]u8{0x81} ** protection.secret_len,
    );
    const aes256 = try protection.deriveKeysForSecretForVersion(
        0x00000001,
        .aes_256_gcm_sha384,
        .fromSha384([_]u8{0x83} ** 48),
    );
    const chacha = protection.deriveChaCha20Keys(
        [_]u8{0x82} ** protection.secret_len,
    );
    var counting = std.testing.FailingAllocator.init(std.testing.allocator, .{});

    var both = try Set.init(counting.allocator(), aes, aes256);
    defer both.deinit(counting.allocator());
    try std.testing.expectEqual(@as(usize, 1), counting.allocations);
    try std.testing.expect(both.send() != null);
    try std.testing.expect(both.receive() != null);
    try std.testing.expect(both.send() != both.receive());
    both.replaceSend(aes256);
    both.replaceReceive(aes);
    const options: protection.ShortPacketOptions = .{
        .destination_connection_id = "prepared-pair",
        .packet_number = 203,
        .packet_number_len = 2,
        .payload = "directional pair",
    };
    var expected_send_storage: [128]u8 = undefined;
    const expected_send = try protection.sealShortPacketInto(
        &expected_send_storage,
        aes256,
        options,
    );
    var send_storage: [128]u8 = undefined;
    const sent = try protection.sealShortPacketIntoPrepared(
        &send_storage,
        both.send().?,
        options,
    );
    try std.testing.expectEqualSlices(u8, expected_send, sent);
    var expected_receive_storage: [128]u8 = undefined;
    const expected_receive = try protection.sealShortPacketInto(
        &expected_receive_storage,
        aes,
        options,
    );
    var receive_storage: [128]u8 = undefined;
    const received = try protection.sealShortPacketIntoPrepared(
        &receive_storage,
        both.receive().?,
        options,
    );
    try std.testing.expectEqualSlices(u8, expected_receive, received);

    var send_only = try Set.init(counting.allocator(), aes, chacha);
    defer send_only.deinit(counting.allocator());
    try std.testing.expectEqual(@as(usize, 2), counting.allocations);
    try std.testing.expect(send_only.send() != null);
    try std.testing.expect(send_only.receive() == null);

    var receive_only = try Set.init(counting.allocator(), chacha, aes);
    defer receive_only.deinit(counting.allocator());
    try std.testing.expectEqual(@as(usize, 3), counting.allocations);
    try std.testing.expect(receive_only.send() == null);
    try std.testing.expect(receive_only.receive() != null);

    var none = try Set.init(counting.allocator(), chacha, chacha);
    defer none.deinit(counting.allocator());
    try std.testing.expectEqual(@as(usize, 3), counting.allocations);
    try std.testing.expect(none.send() == null);
    try std.testing.expect(none.receive() == null);
}

test "prepared key set allocation failure leaves no ownership" {
    try std.testing.expect(protection.prepared_packet_protection_enabled);

    const keys = protection.deriveAes128Keys(
        [_]u8{0x84} ** protection.secret_len,
    );
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{
        .fail_index = 0,
    });
    try std.testing.expectError(
        error.OutOfMemory,
        Set.init(failing.allocator(), keys, keys),
    );
    try std.testing.expect(failing.has_induced_failure);
}

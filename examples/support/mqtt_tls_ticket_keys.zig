//! Process-lifetime TLS 1.2 ticket keys for configured MQTT listeners.
//!
//! One logical listener shares a keyring across its IPv4 and IPv6 sockets.
//! Secrets are generated from the runtime's secure RNG and wiped at teardown.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;
const Keyring = netz.tls.stream.Tls12TicketKeyring;

pub const Set = struct {
    allocator: std.mem.Allocator,
    keyrings: []?Keyring,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        listeners: []const mqtt.broker_config.Listener,
    ) !Set {
        const keyrings = try allocator.alloc(?Keyring, listeners.len);
        errdefer allocator.free(keyrings);
        @memset(keyrings, null);
        errdefer for (keyrings) |*keyring| {
            if (keyring.*) |*value| value.deinit();
        };

        for (listeners, 0..) |listener, index| {
            if (!listener.tls12_session_tickets) continue;
            var secret: [netz.tls.stream.tls12_ticket_key_len]u8 = undefined;
            defer std.crypto.secureZero(u8, &secret);
            try std.Io.randomSecure(io, &secret);
            var encoded_id: [4]u8 = undefined;
            try std.Io.randomSecure(io, &encoded_id);
            var id = std.mem.readInt(u32, &encoded_id, .big);
            if (id == 0) id = 1;
            keyrings[index] = try Keyring.init(.{
                .id = id,
                .secret = secret,
            });
        }
        return .{ .allocator = allocator, .keyrings = keyrings };
    }

    pub fn deinit(self: *Set) void {
        for (self.keyrings) |*keyring| {
            if (keyring.*) |*value| value.deinit();
        }
        self.allocator.free(self.keyrings);
        self.* = undefined;
    }

    pub fn policy(
        self: *const Set,
        listener_index: usize,
        listener: mqtt.broker_config.Listener,
    ) ?netz.tls.stream.Tls12ServerTicketPolicy {
        const keyring = if (self.keyrings[listener_index]) |*value|
            value
        else
            return null;
        return .{
            .keyring = keyring,
            .server_id = listener.tls12_session_ticket_server_id,
            .lifetime_seconds = listener.tls12_session_ticket_lifetime_seconds,
        };
    }
};

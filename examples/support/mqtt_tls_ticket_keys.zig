//! Process-lifetime TLS 1.2/1.3 ticket keys for configured MQTT listeners.
//!
//! One logical listener shares each protocol-specific keyring across its IPv4
//! and IPv6 sockets. TLS 1.2 and TLS 1.3 use independent random keys so their
//! ticket formats cannot share an AEAD key/nonce domain.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;
const Keyring = netz.tls.stream.Tls13TicketKeyring;

pub const Policies = struct {
    tls12: ?netz.tls.stream.Tls12ServerTicketPolicy,
    tls13: ?netz.tls.stream.Tls13ServerTicketPolicy,
};

const Entry = struct {
    tls12: ?Keyring = null,
    tls13: ?Keyring = null,

    fn deinit(self: *Entry) void {
        if (self.tls12) |*keyring| keyring.deinit();
        if (self.tls13) |*keyring| keyring.deinit();
        self.* = undefined;
    }
};

pub const Set = struct {
    allocator: std.mem.Allocator,
    entries: []Entry,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        listeners: []const mqtt.broker_config.Listener,
    ) !Set {
        const entries = try allocator.alloc(Entry, listeners.len);
        errdefer allocator.free(entries);
        @memset(entries, .{});
        errdefer for (entries) |*entry| {
            entry.deinit();
        };

        for (listeners, 0..) |listener, index| {
            if (listener.tls12_session_tickets) {
                entries[index].tls12 = try initKeyring(io);
            }
            if (listener.tls13_session_tickets) {
                entries[index].tls13 = try initKeyring(io);
            }
        }
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *Set) void {
        for (self.entries) |*entry| entry.deinit();
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn policies(
        self: *const Set,
        listener_index: usize,
        listener: mqtt.broker_config.Listener,
    ) Policies {
        return .{
            .tls12 = if (self.entries[listener_index].tls12) |*keyring| .{
                .keyring = keyring,
                .server_id = listener.tls12_session_ticket_server_id,
                .lifetime_seconds = listener.tls12_session_ticket_lifetime_seconds,
            } else null,
            .tls13 = if (self.entries[listener_index].tls13) |*keyring| .{
                .keyring = keyring,
                .server_id = listener.tls13_session_ticket_server_id,
                .lifetime_seconds = listener.tls13_session_ticket_lifetime_seconds,
            } else null,
        };
    }
};

fn initKeyring(io: std.Io) !Keyring {
    var secret: [netz.tls.stream.tls13_ticket_key_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &secret);
    try std.Io.randomSecure(io, &secret);
    var encoded_id: [4]u8 = undefined;
    try std.Io.randomSecure(io, &encoded_id);
    var id = std.mem.readInt(u32, &encoded_id, .big);
    if (id == 0) id = 1;
    return Keyring.init(.{ .id = id, .secret = secret });
}

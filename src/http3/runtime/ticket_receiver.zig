//! Opportunistic post-handshake NewSessionTicket reassembly for HTTP/3.
//!
//! The HTTP/3 response pump feeds authenticated 1-RTT CRYPTO frames here; no
//! additional socket read or timer is introduced merely to wait for a ticket.

const std = @import("std");
const quic = @import("../../quic/mod.zig");

pub const Stats = struct {
    stored: u64,
    discarded: u64,
};

pub const Receiver = struct {
    allocator: std.mem.Allocator,
    crypto: quic.crypto_stream.Reassembler,
    cache: ?*quic.resumption.Cache = null,
    server_id: []u8 = &.{},
    now_ms: u64 = 0,
    stored: u64 = 0,
    discarded: u64 = 0,

    pub fn init(
        allocator: std.mem.Allocator,
        max_crypto_bytes: usize,
    ) Receiver {
        return .{
            .allocator = allocator,
            .crypto = .init(allocator, max_crypto_bytes),
        };
    }

    pub fn deinit(self: *Receiver) void {
        self.crypto.deinit();
        if (self.server_id.len != 0) self.allocator.free(self.server_id);
        self.* = undefined;
    }

    pub fn configure(
        self: *Receiver,
        cache: *quic.resumption.Cache,
        server_id: []const u8,
        now_ms: u64,
    ) std.mem.Allocator.Error!void {
        const owned = try self.allocator.dupe(u8, server_id);
        if (self.server_id.len != 0) self.allocator.free(self.server_id);
        self.server_id = owned;
        self.cache = cache;
        self.now_ms = now_ms;
    }

    pub fn stats(self: *const Receiver) Stats {
        return .{ .stored = self.stored, .discarded = self.discarded };
    }

    pub fn ingest(
        self: *Receiver,
        established: *quic.handshake.EstablishedConnection,
        frames: []const quic.Frame,
    ) (quic.handshake.Error || quic.crypto_stream.Error)!void {
        const cache = self.cache orelse return;
        const secret = established.resumption_master_secret orelse
            return error.PostHandshakeTlsUnavailable;
        for (frames) |frame| switch (frame) {
            .crypto => |crypto| try self.crypto.insert(crypto),
            else => {},
        };
        while (true) {
            const available = self.crypto.available();
            if (available.len < 4) return;
            if (available[0] != 0x04) return error.InvalidNewSessionTicket;
            const body_len = (@as(usize, available[1]) << 16) |
                (@as(usize, available[2]) << 8) |
                available[3];
            const message_len = std.math.add(usize, 4, body_len) catch
                return error.InvalidNewSessionTicket;
            if (available.len < message_len) return;
            const result = try quic.resumption.ticket.handshake.cacheMessage(
                &established.connection,
                .{
                    .cache = cache,
                    .server_id = self.server_id,
                    .now_ms = self.now_ms,
                },
                secret,
                established.alpn,
                established.peer_transport_parameters,
                available[0..message_len],
            );
            switch (result) {
                .stored => self.stored +%= 1,
                .discarded => self.discarded +%= 1,
            }
            try self.crypto.consume(message_len);
            established.post_handshake_receive_crypto_offset =
                @intCast(self.crypto.read_offset);
        }
    }
};

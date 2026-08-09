//! QUIC handshake completion and HANDSHAKE_DONE delivery state.
//!
//! TLS completion and QUIC handshake confirmation are distinct at clients.
//! Servers are confirmed as soon as TLS completes, but RFC 9001 still requires
//! them to deliver HANDSHAKE_DONE reliably. Keeping this as explicit transport
//! state lets the normal 1-RTT packet pump coalesce the control frame with the
//! next application or ACK packet instead of blocking `connect`/`accept`.

pub const Status = union(enum) {
    /// Used by manually constructed 1-RTT connections that have not been told
    /// whether the TLS handshake completed.
    in_progress,
    /// TLS is complete, but a client still awaits HANDSHAKE_DONE.
    client_complete,
    /// The server is confirmed and owes one reliably delivered
    /// HANDSHAKE_DONE. The recovery group remains stable across copies sent
    /// under fresh packet numbers.
    server_pending: ?u64,
    /// No more handshake-confirmation transport work remains.
    confirmed,

    pub fn onTlsComplete(self: *Status, role: Role) void {
        self.* = switch (role) {
            .client => .client_complete,
            .server => .{ .server_pending = null },
        };
    }

    pub fn isComplete(self: Status) bool {
        return self != .in_progress;
    }

    pub fn isConfirmed(self: Status) bool {
        return switch (self) {
            .server_pending, .confirmed => true,
            .in_progress, .client_complete => false,
        };
    }

    pub fn needsHandshakeDone(self: Status) bool {
        return switch (self) {
            .server_pending => |packet_number| packet_number == null,
            else => false,
        };
    }

    /// Whether a server still needs an acknowledgment for a previously sent
    /// HANDSHAKE_DONE, even though no new copy needs scheduling right now.
    pub fn awaitingHandshakeDoneAck(self: Status) bool {
        return switch (self) {
            .server_pending => |group_id| group_id != null,
            else => false,
        };
    }

    pub fn onHandshakeDoneTracked(self: *Status, recovery_group_id: u64) void {
        switch (self.*) {
            .server_pending => |*current| current.* = recovery_group_id,
            else => {},
        }
    }

    pub fn onRecoveryUpdated(
        self: *Status,
        recovery_group_still_pending: bool,
    ) void {
        switch (self.*) {
            .server_pending => |group_id| {
                if (group_id != null and
                    !recovery_group_still_pending)
                {
                    self.* = .confirmed;
                }
            },
            else => {},
        }
    }

    pub fn onHandshakeDoneReceived(self: *Status, role: Role) error{
        InvalidFrame,
    }!void {
        if (role != .client) return error.InvalidFrame;
        switch (self.*) {
            // Manually keyed 1-RTT connections historically represent an
            // already-complete handshake without carrying TLS state.
            .in_progress => self.* = .confirmed,
            .client_complete => self.* = .confirmed,
            .confirmed => {},
            .server_pending => unreachable,
        }
    }

    pub fn recoveryGroupId(self: Status) ?u64 {
        return switch (self) {
            .server_pending => |group_id| group_id,
            else => null,
        };
    }
};

pub const Role = enum {
    client,
    server,
};

test "QUIC handshake status tracks reliable HANDSHAKE_DONE delivery" {
    const std = @import("std");

    var server: Status = .in_progress;
    server.onTlsComplete(.server);
    try std.testing.expect(server.isComplete());
    try std.testing.expect(server.isConfirmed());
    try std.testing.expect(server.needsHandshakeDone());

    server.onHandshakeDoneTracked(7);
    try std.testing.expect(!server.needsHandshakeDone());
    server.onRecoveryUpdated(true);
    try std.testing.expect(!server.needsHandshakeDone());
    server.onRecoveryUpdated(false);
    try std.testing.expectEqual(Status.confirmed, server);

    var client: Status = .in_progress;
    client.onTlsComplete(.client);
    try std.testing.expect(client.isComplete());
    try std.testing.expect(!client.isConfirmed());
    try client.onHandshakeDoneReceived(.client);
    try std.testing.expectEqual(Status.confirmed, client);
}

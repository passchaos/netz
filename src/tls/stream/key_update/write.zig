//! TLS 1.3 write-epoch transitions and resumable KeyUpdate responses.
const std = @import("std");
const vail = @import("vail");
const handshake_type_key_update = 24;

pub fn message(request_peer_update: bool) [5]u8 {
    return .{ handshake_type_key_update, 0, 0, 1, @intFromBool(request_peer_update) };
}

/// The old-epoch KeyUpdate record must reach the socket before new-epoch
/// application data. All key material stays in the stream's current epoch
/// while its one retained ciphertext record is incomplete.
pub fn respondUntil(stream: anytype, io: std.Io, socket: std.Io.net.Stream, deadline: std.Io.Clock.Timestamp, comptime Hooks: anytype) !void {
    if (!stream.peer_update_response_pending.load(.acquire)) return;
    _ = try @import("../../../internal/deadline.zig").usableAwake(io, deadline);
    if (stream.pending_write_len == 0) {
        const bytes = message(false);
        try Hooks.begin(stream, vail.tls.record.content_type_handshake, &bytes);
        stream.pending_write_key_update = true;
    } else if (!stream.pending_write_key_update) {
        return error.WriteInProgress;
    }
    var application_committed: usize = 0;
    try Hooks.finish(stream, io, socket, &application_committed, deadline);
    std.debug.assert(application_committed == 0);
}

/// Activate the new write epoch only after the KeyUpdate record is complete.
pub fn rotate(stream: anytype) !void {
    var epoch = try prepare(stream);
    epoch.activate(stream);
}

pub fn prepare(stream: anytype) !Epoch {
    var next_secret = try vail.tls.key_schedule.nextTrafficSecretFor(stream.write_traffic_secret);
    errdefer next_secret.deinit();
    var next_keys = try vail.tls.record.Keys.derive(stream.write_keys.suite, next_secret);
    errdefer next_keys.deinit();
    return .{ .secret = next_secret, .keys = next_keys };
}

pub const Epoch = struct {
    secret: vail.tls.secret.Secret,
    keys: vail.tls.record.Keys,
    pub fn deinit(self: *Epoch) void {
        self.secret.deinit();
        self.keys.deinit();
    }
    pub fn activate(self: *Epoch, stream: anytype) void {
        stream.write_keys.deinit();
        stream.write_traffic_secret.deinit();
        stream.write_keys = self.keys;
        stream.write_traffic_secret = self.secret;
        stream.write_sequence = 0;
        _ = stream.key_updates_sent.fetchAdd(1, .monotonic);
        std.crypto.secureZero(u8, std.mem.asBytes(self));
    }
};

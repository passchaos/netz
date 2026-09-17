//! Benchmark-local timing wrapper for the production X.509 verifier.

const std = @import("std");
const netz = @import("netz");

pub const Timed = struct {
    io: std.Io,
    verifier: netz.quic.tls.auth.ClientVerifier,
    connect_started_ns: u64 = 0,
    trust_started_ns: u64 = 0,
    trust_completed_ns: u64 = 0,

    pub const Phases = struct {
        pre_trust_ns: u64,
        trust_ns: u64,
        post_trust_ns: u64,
    };

    pub fn reset(self: *Timed, connect_started_ns: u64) void {
        self.connect_started_ns = connect_started_ns;
        self.trust_started_ns = 0;
        self.trust_completed_ns = 0;
    }

    pub fn clientVerifier(
        self: *Timed,
    ) netz.quic.tls.auth.ClientVerifier {
        return .{
            .verify_trust = verifyTrust,
            .context = self,
        };
    }

    pub fn phases(self: Timed, connect_completed_ns: u64) !Phases {
        if (self.connect_started_ns == 0 or
            self.trust_started_ns < self.connect_started_ns or
            self.trust_completed_ns < self.trust_started_ns or
            connect_completed_ns < self.trust_completed_ns)
        {
            return error.InvalidHandshakeTiming;
        }
        return .{
            .pre_trust_ns = self.trust_started_ns - self.connect_started_ns,
            .trust_ns = self.trust_completed_ns - self.trust_started_ns,
            .post_trust_ns = connect_completed_ns - self.trust_completed_ns,
        };
    }

    fn verifyTrust(
        context: ?*anyopaque,
        trust: netz.quic.tls.auth.TrustContext,
    ) anyerror!void {
        const self: *Timed = @ptrCast(@alignCast(
            context orelse return error.MissingTrustContext,
        ));
        self.trust_started_ns = nowNs(self.io);
        defer self.trust_completed_ns = nowNs(self.io);
        try self.verifier.verifyTrust(trust.server_name, trust.chain);
    }
};

fn nowNs(io: std.Io) u64 {
    const value = std.Io.Clock.awake.now(io).nanoseconds;
    return @intCast(@max(value, 0));
}

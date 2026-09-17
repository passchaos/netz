//! Incremental TLS transcript ownership for one QUIC client handshake.
//!
//! TLS derives several secrets and signatures from successively longer
//! prefixes of the same transcript. Retaining the negotiated hash state avoids
//! re-hashing ClientHello and ServerHello at every boundary while snapshots
//! remain cheap value copies.

const std = @import("std");
const quic = @import("../mod.zig");

pub const Flow = struct {
    state: quic.tls.transcript.State,

    pub fn init(
        hash: quic.tls.secret.Hash,
        client_hello: []const u8,
        server_hello: []const u8,
    ) Flow {
        var state = quic.tls.transcript.State.init(hash);
        state.update(client_hello);
        state.update(server_hello);
        return .{ .state = state };
    }

    pub fn append(self: *Flow, bytes: []const u8) void {
        self.state.update(bytes);
    }

    pub fn digest(self: *const Flow) quic.tls.transcript.Digest {
        return self.state.digest();
    }

    /// Hash one prospective suffix without advancing the retained transcript.
    pub fn digestAfter(
        self: *const Flow,
        bytes: []const u8,
    ) quic.tls.transcript.Digest {
        var snapshot = self.state;
        snapshot.update(bytes);
        return snapshot.digest();
    }
};

test "QUIC client transcript snapshots match one-shot hashes" {
    inline for ([_]quic.tls.secret.Hash{ .sha256, .sha384, .sm3 }) |hash| {
        var flow = Flow.init(hash, "client hello", "server hello");
        try std.testing.expectEqualSlices(
            u8,
            quic.tls.transcript.hashFor(
                hash,
                &.{ "client hello", "server hello" },
            ).bytes(),
            flow.digest().bytes(),
        );
        try std.testing.expectEqualSlices(
            u8,
            quic.tls.transcript.hashFor(
                hash,
                &.{ "client hello", "server hello", "certificate" },
            ).bytes(),
            flow.digestAfter("certificate").bytes(),
        );
        try std.testing.expectEqualSlices(
            u8,
            quic.tls.transcript.hashFor(
                hash,
                &.{ "client hello", "server hello" },
            ).bytes(),
            flow.digest().bytes(),
        );
        flow.append("server flight");
        try std.testing.expectEqualSlices(
            u8,
            quic.tls.transcript.hashFor(
                hash,
                &.{ "client hello", "server hello", "server flight" },
            ).bytes(),
            flow.digest().bytes(),
        );
    }
}

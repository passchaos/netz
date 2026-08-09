//! TLS/QUIC 0-RTT handshake policy and key-installation helpers.
//!
//! Packet transport remains in `mod.zig`.  This module connects an exclusive
//! resumption lease to ClientHello/EncryptedExtensions signaling and derives
//! the RFC 8446 client early traffic secret used for QUIC packet protection.

const std = @import("std");
const quic = @import("../mod.zig");
const vail = @import("vail");

const Sha256 = vail.crypto.sha256;

pub const Error = quic.resumption.tls_psk.Error ||
    quic.resumption.parameters.ValidationError ||
    quic.protection.VersionError ||
    error{
        InvalidEarlyDataLease,
        EarlyDataIncompatibleWithRetry,
        UnexpectedEarlyData,
    };

pub const Status = enum {
    not_offered,
    offered,
    accepted,
    rejected,
};

pub const ClientOffer = struct {
    cache: *quic.resumption.Cache,
    lease: *quic.resumption.EarlyDataLease,
    frames: []const quic.Frame,
    packet_number_len: u8 = 4,

    pub fn validate(self: ClientOffer) Error!void {
        if (self.frames.len == 0 or
            !self.lease.session.permitsEarlyData() or
            !self.cache.ownsActiveLease(self.lease.*) or
            self.packet_number_len < 1 or
            self.packet_number_len > 4)
        {
            return error.InvalidEarlyDataLease;
        }
    }
};

pub const ClientKeys = struct {
    traffic_secret: [quic.protection.secret_len]u8,
    packet: quic.protection.PacketProtectionKeys,
};

pub fn clientKeysForVersion(
    version: u32,
    psk: [Sha256.digest_len]u8,
    client_hello: []const u8,
) Error!ClientKeys {
    return clientKeysForSuiteAndVersion(
        version,
        .aes_128_gcm_sha256,
        psk,
        client_hello,
    );
}

pub fn clientKeysForSuiteAndVersion(
    version: u32,
    cipher_suite: quic.tls.cipher_suite.Suite,
    psk: [Sha256.digest_len]u8,
    client_hello: []const u8,
) Error!ClientKeys {
    const client_hello_hash = Sha256.hash(client_hello);
    const traffic_secret =
        quic.resumption.tls_psk.deriveClientEarlyTrafficSecret(
            psk,
            client_hello_hash,
        );
    return .{
        .traffic_secret = traffic_secret,
        .packet = try quic.protection.deriveKeysForVersion(
            version,
            cipher_suite,
            traffic_secret,
        ),
    };
}

pub fn validateClientAcceptance(
    offered: bool,
    resumed: bool,
    accepted: bool,
    remembered: quic.resumption.Snapshot,
    current: quic.TransportParameters,
) Error!Status {
    if (accepted and (!offered or !resumed)) return error.UnexpectedEarlyData;
    if (!offered) return .not_offered;
    if (!accepted) return .rejected;
    try remembered.validateAfterEarlyDataAccepted(current);
    return .accepted;
}

test "0-RTT handshake keys are PSK and ClientHello bound" {
    const psk = [_]u8{0x42} ** Sha256.digest_len;
    const first = try clientKeysForVersion(
        quic.Version.version_1.wireValue(),
        psk,
        "client hello one",
    );
    const again = try clientKeysForVersion(
        quic.Version.version_1.wireValue(),
        psk,
        "client hello one",
    );
    const second = try clientKeysForVersion(
        quic.Version.version_1.wireValue(),
        psk,
        "client hello two",
    );
    try std.testing.expectEqualSlices(u8, &first.traffic_secret, &again.traffic_secret);
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.traffic_secret,
        &second.traffic_secret,
    ));
}

test "0-RTT handshake acceptance validates remembered transport parameters" {
    const remembered = quic.resumption.Snapshot.fromTransportParameters(
        quic.practical_transport_parameters,
    );
    try std.testing.expectEqual(
        Status.accepted,
        try validateClientAcceptance(
            true,
            true,
            true,
            remembered,
            quic.practical_transport_parameters,
        ),
    );
    try std.testing.expectEqual(
        Status.rejected,
        try validateClientAcceptance(
            true,
            true,
            false,
            remembered,
            quic.TransportParameters{},
        ),
    );
    try std.testing.expectError(
        error.UnexpectedEarlyData,
        validateClientAcceptance(
            false,
            true,
            true,
            remembered,
            quic.practical_transport_parameters,
        ),
    );
}

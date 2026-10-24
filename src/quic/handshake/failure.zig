//! RFC 9001 TLS alerts carried by transport CONNECTION_CLOSE. Call guards only
//! around peer validation; local preparation and configuration stay ordinary errors.
const std = @import("std");
const quic = @import("../mod.zig");
const retransmit = @import("retransmit.zig");
const closing = @import("closing.zig");
const Description = @import("vail").tls.alert.Description;

pub const PacketType = enum { initial, handshake };

pub fn tlsCode(err: anyerror) ?u64 {
    const alert: Description = switch (err) {
        error.MissingAlpn => .no_application_protocol,
        error.NoSharedCipherSuite,
        error.MissingKeyShare,
        error.UnsupportedSignatureScheme,
        => .handshake_failure,
        error.MissingSupportedVersions => .protocol_version,
        error.MissingTransportParameters => .missing_extension,
        error.BadFinished,
        error.BadClientFinished,
        error.BadCertificateVerify,
        => .decrypt_error,
        error.CertificateUntrusted => .unknown_ca,
        error.ClientCertificateRequired => .certificate_required,
        error.InvalidCertificate,
        error.EmptyCertificateChain,
        error.CertificateTooLarge,
        => .bad_certificate,
        error.UnsupportedCertificateKey => .unsupported_certificate,
        error.InvalidPublicKey,
        error.KeyExchangeFailed,
        error.InvalidCipherSuite,
        error.UnexpectedEarlyData,
        => .illegal_parameter,
        error.InvalidClientHello,
        error.InvalidServerHello,
        error.InvalidEncryptedExtensions,
        error.InvalidFinished,
        error.InvalidCertificateVerify,
        error.InvalidCertificateRequest,
        error.InvalidHandshakeFlight,
        error.InvalidClientFlight,
        error.BufferTooShort,
        error.IntegerOverflow,
        => .decode_error,
        else => return null,
    };
    return 0x100 + @as(u64, @intFromEnum(alert));
}

pub fn transportCode(err: anyerror) ?u64 {
    return switch (err) {
        error.InvalidTransportParameter,
        error.InvalidTransportParameterLength,
        error.DuplicateTransportParameter,
        error.TransportParameterForbidden,
        error.BufferTooShort,
        error.MalformedVarInt,
        error.VarIntTooLarge,
        error.IntegerOverflow,
        => @intFromEnum(quic.TransportErrorCode.transport_parameter_error),
        else => null,
    };
}

pub const State = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: std.Io.net.IpAddress,
    packet_type: PacketType,
    keys: quic.protection.PacketProtectionKeys,
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
    next_packet_number: ?u64,
    client: bool = false,
    anti_amplification: ?*retransmit.AntiAmplificationBudget = null,
    closing_out: ?*?closing.Packet = null,
    closing_lifetime_ns: u64 = 0,

    pub fn guardTls(self: *State, result: anytype) @TypeOf(result) {
        return result catch |err| {
            return self.rejectTls(err);
        };
    }

    pub fn rejectTls(self: *State, err: anytype) @TypeOf(err) {
        if (tlsCode(err)) |code| self.send(code, @errorName(err)) catch {};
        return err;
    }

    pub fn guardTransport(self: *State, result: anytype) @TypeOf(result) {
        return result catch |err| {
            if (transportCode(err)) |code| self.send(code, @errorName(err)) catch {};
            return err;
        };
    }

    pub fn send(self: *State, code: u64, reason: []const u8) !void {
        const packet_number = self.next_packet_number orelse return;
        // A fatal close has one submission owner. Retire the nonce even when
        // protection or its socket submission fails; callers keep the parser
        // error and never issue another close using this packet number.
        self.next_packet_number = null;
        var payload_storage: [1200]u8 = undefined;
        var payload: std.ArrayList(u8) = .{ .items = payload_storage[0..0], .capacity = payload_storage.len };
        var fixed = std.heap.FixedBufferAllocator.init(&.{});
        try (quic.Frame{ .connection_close = .{
            .error_code = code,
            .frame_type = 0,
            .reason_phrase = reason,
        } }).write(&payload, fixed.allocator());
        if (self.client and self.packet_type == .initial) {
            // Client Initial datagrams require 1200 bytes even for a close.
            // Empty token, four-byte PN and a two-byte Length use 30 bytes
            // plus both CIDs; padding changes only the protected payload.
            const payload_len = 1200 - (30 + self.destination_connection_id.len + self.source_connection_id.len);
            if (payload.items.len < payload_len) {
                const previous = payload.items.len;
                payload.items.len = payload_len;
                @memset(payload.items[previous..], 0);
            }
        }
        var packet_storage: [1280]u8 = undefined;
        const packet = switch (self.packet_type) {
            .initial => try quic.protection.sealInitialPacketInto(&packet_storage, self.keys, .{
                .version = self.version,
                .destination_connection_id = self.destination_connection_id,
                .source_connection_id = self.source_connection_id,
                .packet_number = packet_number,
                .payload = payload.items,
            }),
            .handshake => try quic.protection.sealHandshakePacketInto(&packet_storage, self.keys, .{
                .version = self.version,
                .destination_connection_id = self.destination_connection_id,
                .source_connection_id = self.source_connection_id,
                .packet_number = packet_number,
                .payload = payload.items,
            }),
        };
        if (self.closing_out) |output| {
            var retained: closing.Packet = .{
                .len = packet.len,
                .bytes_received = if (self.anti_amplification) |budget| budget.bytes_received else 0,
                .bytes_sent = if (self.anti_amplification) |budget| budget.bytes_sent else 0,
                .lifetime_ns = self.closing_lifetime_ns,
            };
            @memcpy(retained.bytes[0..packet.len], packet);
            output.* = retained;
        }
        if (self.anti_amplification) |budget| try budget.reserve(packet.len);
        errdefer if (self.anti_amplification) |budget| budget.release(packet.len);
        try self.endpoint.sendBytes(self.peer, packet);
        if (self.closing_out) |output| {
            if (output.*) |*retained| retained.bytes_sent +|= packet.len;
        }
    }
};

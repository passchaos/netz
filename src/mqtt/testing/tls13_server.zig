//! Local TLS 1.3 peer and identity fixture used by MQTT transport tests.
//!
//! Production MQTT client tests retain this deliberately small peer to verify
//! the client independently of the production server. Server tests and the TLS
//! benchmark use `mqtt.tls_runtime.Server` with the identity exported below.

const std = @import("std");
const vail = @import("vail");

const net = std.Io.net;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;

const max_plaintext_len: usize = 16 * 1024;
const max_record_len =
    vail.tls.record.header_len +
    max_plaintext_len +
    1 +
    vail.tls.record.tag_len;

// The matching private key is the deterministic scalar in `serverKeyPair`.
// The certificate is valid from 2026-01-01 through 2036-01-01 and contains a
// localhost DNS SAN. Keeping it DER/base64 avoids filesystem fixtures.
pub const certificate_base64 =
    "MIIBMDCB1qADAgECAgISNDAKBggqhkjOPQQDAjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARawLjuCeZXZ7tsfTRAu+FcuRLUr+ELbhoX/6Hs0fLlSZe0NNZYPUqZa65oYGMMs9Ud19Qc/RZMzn4vZv5+EakUoxgwFjAUBgNVHREEDTALgglsb2NhbGhvc3QwCgYIKoZIzj0EAwIDSQAwRgIhAJFAj+UlV/FOGaVRnB/9l7wXgSet0zn4CdgFIckqC1hEAiEApPR1fJT2M9PVNn3fwdZBboKEoWrUYLVy6sMvbrhNjKU=";
pub const certificate_der_len: usize = 308;

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    listener: net.Server,

    pub fn listen(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
    ) !Server {
        return .{
            .allocator = allocator,
            .io = io,
            .listener = try bind_address.listen(io, .{
                .reuse_address = true,
            }),
        };
    }

    pub fn deinit(self: *Server) void {
        self.listener.deinit(self.io);
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.listener.socket.address;
    }

    pub fn accept(self: *Server) !Connection {
        const stream = try self.listener.accept(self.io);
        errdefer stream.close(self.io);
        return Connection.handshake(
            self.allocator,
            self.io,
            stream,
        );
    }
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    stream: net.Stream,
    read_keys: vail.tls.record.Keys,
    write_keys: vail.tls.record.Keys,
    read_sequence: u64 = 0,
    write_sequence: u64 = 0,
    closed: bool = false,

    fn handshake(
        allocator: std.mem.Allocator,
        io: std.Io,
        stream: net.Stream,
    ) !Connection {
        var client_record: [max_record_len]u8 = undefined;
        const client_hello_record = try readRecord(
            io,
            stream,
            &client_record,
        );
        if (client_hello_record[0] !=
            vail.tls.record.content_type_handshake)
        {
            return error.ExpectedHandshakeRecord;
        }
        const client_hello = client_hello_record[vail.tls.record.header_len..];
        const parsed = try vail.tls.client_hello.parse(client_hello);
        const share = (try parsed.keyShareForGroup(0x001d)) orelse
            return error.MissingKeyShare;
        const server_secret =
            [_]u8{0x71} ** vail.tls.key_exchange.secret_len;
        const server_public = try vail.tls.key_exchange.publicKey(
            server_secret,
        );
        const shared = try vail.tls.key_exchange.sharedSecret(
            server_secret,
            share.key_exchange,
        );
        const key_pair = try serverKeyPair();
        var certificate_der: [certificate_der_len]u8 = undefined;
        try std.base64.standard.Decoder.decode(
            &certificate_der,
            certificate_base64,
        );

        var flight: std.ArrayList(u8) = .empty;
        defer flight.deinit(allocator);
        const result =
            try vail.tls.server_handshake.writeServerHandshakeFlight(
                &flight,
                allocator,
                .{
                    .client_hello_bytes = client_hello,
                    .parsed_client_hello = parsed,
                    .policy = .{
                        .cipher_suites = &.{.aes_128_gcm_sha256},
                        .groups = &.{0x001d},
                    },
                    .server_random = [_]u8{0x73} ** 32,
                    .server_key_share = &server_public,
                    .shared_secret = &shared,
                    .certificate_chain = &.{&certificate_der},
                    .signer = .{
                        .ecdsa_p256_sha256 = .{
                            .key_pair = key_pair,
                        },
                    },
                },
            );

        const server_hello_len =
            4 +
            ((@as(usize, flight.items[1]) << 16) |
                (@as(usize, flight.items[2]) << 8) |
                flight.items[3]);
        var server_hello_header: [vail.tls.record.header_len]u8 =
            .{ 0x16, 0x03, 0x03, 0, 0 };
        std.mem.writeInt(
            u16,
            server_hello_header[3..5],
            @intCast(server_hello_len),
            .big,
        );
        try writeAll(io, stream, &server_hello_header);
        try writeAll(io, stream, flight.items[0..server_hello_len]);
        // Zig 0.16's TLS client switches from pending handshake keys when it
        // observes the TLS 1.3 compatibility ChangeCipherSpec record.
        try writeAll(io, stream, &.{
            0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
        });
        // `std.crypto.tls.Client` expects each handshake message as its own
        // TLSCiphertext record. Coalescing several records into one netWrite is
        // legal on TCP but exposed a parser boundary assumption in Zig 0.16;
        // preserve record boundaries in this deterministic fixture.
        var flight_offset = server_hello_len;
        while (flight_offset < flight.items.len) {
            if (flight.items.len - flight_offset <
                vail.tls.record.header_len)
            {
                return error.InvalidServerFlight;
            }
            const encrypted_len = std.mem.readInt(
                u16,
                flight.items[flight_offset + 3 ..][0..2],
                .big,
            );
            const record_len =
                vail.tls.record.header_len + encrypted_len;
            if (flight_offset + record_len > flight.items.len) {
                return error.InvalidServerFlight;
            }
            try writeAll(
                io,
                stream,
                flight.items[flight_offset .. flight_offset + record_len],
            );
            flight_offset += record_len;
        }

        const encrypted_finished = while (true) {
            const record_bytes = try readRecord(
                io,
                stream,
                &client_record,
            );
            // TLS 1.3 compatibility mode permits a cleartext dummy CCS.
            if (record_bytes[0] == 0x14) continue;
            break record_bytes;
        };
        var handshake_read_keys = try vail.tls.record.Keys.derive(
            result.selection.suite,
            result.client_handshake_traffic_secret,
        );
        defer handshake_read_keys.deinit();
        var opened_finished: [256]u8 = undefined;
        const finished = try handshake_read_keys.open(
            0,
            encrypted_finished,
            &opened_finished,
        );
        if (finished.content_type !=
            vail.tls.record.content_type_handshake or
            finished.len < 4 or
            opened_finished[0] !=
                vail.tls.server_handshake.handshake_type_finished)
        {
            return error.ExpectedClientFinished;
        }
        const finished_len =
            (@as(usize, opened_finished[1]) << 16) |
            (@as(usize, opened_finished[2]) << 8) |
            opened_finished[3];
        if (finished_len != finished.len - 4) {
            return error.ExpectedClientFinished;
        }
        const expected_finished =
            try vail.tls.key_schedule.computeFinishedFor(
                result.client_handshake_traffic_secret,
                result.transcript_after_server_finished,
            );
        if (!std.mem.eql(
            u8,
            expected_finished.bytes(),
            opened_finished[4..finished.len],
        )) return error.BadClientFinished;

        const application =
            try vail.tls.key_schedule.deriveApplicationFor(
                result.handshake_secret,
                result.transcript_after_server_finished,
            );
        return .{
            .allocator = allocator,
            .io = io,
            .stream = stream,
            .read_keys = try vail.tls.record.Keys.derive(
                result.selection.suite,
                application.client_traffic_secret,
            ),
            .write_keys = try vail.tls.record.Keys.derive(
                result.selection.suite,
                application.server_traffic_secret,
            ),
        };
    }

    pub fn deinit(self: *Connection) void {
        if (!self.closed) self.sendCloseNotify() catch {};
        self.read_keys.deinit();
        self.write_keys.deinit();
        self.stream.close(self.io);
        self.* = undefined;
    }

    /// Read one TLS application-data record into caller-owned storage.
    pub fn readApplication(
        self: *Connection,
        out: []u8,
    ) ![]u8 {
        var record_buffer: [max_record_len]u8 = undefined;
        while (true) {
            const record_bytes = try readRecord(
                self.io,
                self.stream,
                &record_buffer,
            );
            const opened = try self.read_keys.open(
                self.read_sequence,
                record_bytes,
                out,
            );
            self.read_sequence += 1;
            switch (opened.content_type) {
                vail.tls.record.content_type_application_data => return out[0..opened.len],
                vail.tls.record.content_type_alert => {
                    self.closed = true;
                    return error.ConnectionClosed;
                },
                // Post-handshake messages are not expected from the current
                // std TLS client in these bounded local tests.
                else => return error.UnexpectedTlsContent,
            }
        }
    }

    pub fn writeApplication(
        self: *Connection,
        bytes: []const u8,
    ) !void {
        var record_buffer: [max_record_len]u8 = undefined;
        const len = try self.write_keys.seal(
            self.write_sequence,
            vail.tls.record.content_type_application_data,
            bytes,
            &record_buffer,
        );
        self.write_sequence += 1;
        try writeAll(
            self.io,
            self.stream,
            record_buffer[0..len],
        );
    }

    fn sendCloseNotify(self: *Connection) !void {
        const close_notify = [_]u8{ 1, 0 };
        var record_buffer: [64]u8 = undefined;
        const len = try self.write_keys.seal(
            self.write_sequence,
            vail.tls.record.content_type_alert,
            &close_notify,
            &record_buffer,
        );
        self.write_sequence += 1;
        try writeAll(
            self.io,
            self.stream,
            record_buffer[0..len],
        );
        self.closed = true;
    }
};

pub fn serverKeyPair() !EcdsaP256Sha256.KeyPair {
    const secret = try EcdsaP256Sha256.SecretKey.fromBytes(.{
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1,
        0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12,
        0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1, 0x23,
        0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x12, 0x34,
    });
    return EcdsaP256Sha256.KeyPair.fromSecretKey(secret);
}

fn readRecord(
    io: std.Io,
    stream: net.Stream,
    buffer: []u8,
) ![]u8 {
    if (buffer.len < vail.tls.record.header_len) {
        return error.BufferTooShort;
    }
    try readExact(
        io,
        stream,
        buffer[0..vail.tls.record.header_len],
    );
    const payload_len = std.mem.readInt(u16, buffer[3..5], .big);
    const total_len = vail.tls.record.header_len + payload_len;
    if (total_len > buffer.len) return error.RecordTooLarge;
    try readExact(
        io,
        stream,
        buffer[vail.tls.record.header_len..total_len],
    );
    return buffer[0..total_len];
}

fn readExact(
    io: std.Io,
    stream: net.Stream,
    out: []u8,
) !void {
    var offset: usize = 0;
    while (offset < out.len) {
        var bufs = [_][]u8{out[offset..]};
        const n = try io.vtable.netRead(
            io.userdata,
            stream.socket.handle,
            &bufs,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

fn writeAll(
    io: std.Io,
    stream: net.Stream,
    bytes: []const u8,
) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const n = try io.vtable.netWrite(
            io.userdata,
            stream.socket.handle,
            bytes[offset..],
            &.{""},
            0,
        );
        if (n == 0) return error.ConnectionClosed;
        offset += n;
    }
}

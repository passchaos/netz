const std = @import("std");
const netz = @import("netz");

pub const max_input_bytes = 3;
pub const timeout = std.Io.Duration.fromSeconds(5);

pub const Group = enum { x25519, secp256r1, secp384r1 };

pub const Case = struct {
    version: netz.quic.Version,
    cipher_suite: netz.quic.tls_client_hello.CipherSuite,
    group: Group,
    drop_client_first: bool,
    drop_server_first: bool,
    corrupt_client_first: bool,
    corrupt_server_first: bool,
    retry: bool,
};

pub fn decode(input: []const u8) Case {
    const first = byteAt(input, 0);
    const second = byteAt(input, 1);
    const third = byteAt(input, 2);
    const fault = third % 7;
    return .{
        .version = if ((first & 1) == 0) .version_1 else .version_2,
        .cipher_suite = if ((first & 2) == 0)
            .aes_128_gcm_sha256
        else
            .aes_256_gcm_sha384,
        .group = switch (second % 3) {
            0 => .x25519,
            1 => .secp256r1,
            2 => .secp384r1,
            else => unreachable,
        },
        .drop_client_first = fault == 1 or fault == 3,
        .drop_server_first = fault == 2 or fault == 3,
        .corrupt_client_first = fault == 4,
        .corrupt_server_first = fault == 5,
        .retry = fault == 6,
    };
}

fn byteAt(input: []const u8, index: usize) u8 {
    return if (input.len == 0) 0 else input[index % input.len];
}

pub const Summary = struct {
    recovered_client_flights: usize = 0,
    recovered_server_flights: usize = 0,
    rejected_client_flights: usize = 0,
    rejected_server_flights: usize = 0,
    retries: usize = 0,
    application_round_trips: usize = 0,
};

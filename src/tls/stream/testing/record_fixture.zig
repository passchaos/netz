//! Deterministic traffic keys for socket-backed TLS record regressions.
const vail = @import("vail");
const tls13 = @import("../record_stream.zig");
const tls12 = @import("../tls12_record_stream.zig");

pub fn stream(comptime old: bool, read_fill: u8, write_fill: u8) !if (old) tls12.Stream else tls13.Stream {
    if (old) return tls12.Stream.init(
        vail.tls.tls12.TrafficState.init(try vail.tls.tls12.Keys.init(.ecdhe_ecdsa_aes_128_gcm_sha256, &([_]u8{read_fill} ** 16), &([_]u8{0x42} ** 4))),
        vail.tls.tls12.TrafficState.init(try vail.tls.tls12.Keys.init(.ecdhe_ecdsa_aes_128_gcm_sha256, &([_]u8{write_fill} ** 16), &([_]u8{0x42} ** 4))),
    );
    const suite = vail.tls.cipher_suite.Suite.aes_128_gcm_sha256;
    var read_secret = try vail.tls.secret.Secret.init(suite.hash(), &([_]u8{read_fill} ** 32));
    errdefer read_secret.deinit();
    var write_secret = try vail.tls.secret.Secret.init(suite.hash(), &([_]u8{write_fill} ** 32));
    errdefer write_secret.deinit();
    var read_keys = try vail.tls.record.Keys.derive(suite, read_secret);
    errdefer read_keys.deinit();
    var write_keys = try vail.tls.record.Keys.derive(suite, write_secret);
    errdefer write_keys.deinit();
    return tls13.Stream.init(read_keys, write_keys, read_secret, write_secret);
}

//! Shared bounded I/O, address resolution, and relay helpers used by the
//! application proxy servers.

pub const byte_bucket = @import("byte_bucket.zig");
pub const rate_stream = @import("byte_bucket/stream.zig");
pub const connect = @import("connect.zig");
pub const io = @import("io.zig");
pub const quic_relay = @import("quic_relay.zig");
pub const relay_queue = @import("relay_queue.zig");
pub const pending_input = @import("relay_queue/pending_input.zig");
pub const resolve = @import("resolve.zig");
pub const tls_relay = @import("tls_relay.zig");
pub const udp_relay = @import("udp_relay.zig");
pub const udp_session = @import("udp_session.zig");

test {
    _ = byte_bucket;
    _ = rate_stream;
    _ = connect;
    _ = io;
    _ = quic_relay;
    _ = relay_queue;
    _ = pending_input;
    _ = @import("relay_queue/stream_send_tests.zig");
    _ = resolve;
    _ = tls_relay;
    _ = udp_relay;
    _ = udp_session;
    _ = @import("service_turn_tests.zig");
}

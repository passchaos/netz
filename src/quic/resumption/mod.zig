//! Session resumption and 0-RTT policy state.
//!
//! This layer owns cached tickets and remembered transport parameters. It does
//! not pretend to implement the TLS PSK extension itself; TLS integrations can
//! acquire the owned session bytes/PSK and must consume the early-data lease
//! when any 0-RTT packet is offered.

pub const parameters = @import("parameters.zig");
pub const cache = @import("cache.zig");
pub const tls_psk = @import("tls_psk.zig");

pub const Snapshot = parameters.Snapshot;
pub const Cache = cache.Cache;
pub const Ticket = cache.Ticket;
pub const Session = cache.Session;
pub const EarlyDataLease = cache.EarlyDataLease;

test {
    _ = @import("tests.zig");
}

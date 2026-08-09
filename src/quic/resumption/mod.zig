//! Session resumption and 0-RTT policy state.
//!
//! This layer owns cached tickets, remembered transport parameters, and the
//! TLS 1.3 resumption-PSK extension/key-schedule helpers.  Early-data callers
//! must still consume an exclusive lease once any 0-RTT packet is offered.

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

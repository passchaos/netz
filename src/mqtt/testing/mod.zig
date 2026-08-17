//! Deterministic local peers for MQTT transport tests and benchmarks.
//!
//! These helpers are not production brokers. They provide real protocol
//! handshakes without external processes or network access, making transport
//! validation reproducible for downstream users as well as netz itself.

pub const tls13_server = @import("tls13_server.zig");

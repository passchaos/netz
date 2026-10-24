//! Minimal handshake closing state retained by the endpoint's CID receive
//! owner. RFC 9000 10.2.1 permits replaying the final protected packet verbatim.
const std = @import("std");
const runtime = @import("../runtime.zig");

pub const default_capacity: usize = 1024;
pub const max_packet_len: usize = 1280;
pub const minimum_response_interval_ns = 20 * std.time.ns_per_ms;

/// Written by the handshake worker, then transferred with its completion.
/// Every byte is owned; no TLS keys or parser allocation survives the worker.
pub const Packet = struct {
    bytes: [max_packet_len]u8 = undefined,
    len: usize,
    bytes_received: u64,
    bytes_sent: u64,
    lifetime_ns: u64 = 0,

    pub fn slice(self: *const Packet) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn lifetimeNs(initial_pto_ms: u32) u64 {
    return @as(u64, initial_pto_ms) * 3 * std.time.ns_per_ms;
}

pub const State = struct {
    peer: std.Io.net.IpAddress,
    version: u32,
    packet: ?Packet,
    deadline_ns: u64,
    next_response_ns: u64,
    response_interval_ns: u64 = minimum_response_interval_ns,
    max_response_interval_ns: u64,
    bytes_received: u64,
    bytes_sent: u64,

    pub fn init(peer: std.Io.net.IpAddress, version: u32, packet: ?Packet, now_ns: u64, lifetime_ns: u64) State {
        const actual_lifetime = if (packet) |value| @max(lifetime_ns, value.lifetime_ns) else lifetime_ns;
        return .{
            .peer = peer,
            .version = version,
            .packet = packet,
            .deadline_ns = now_ns +| actual_lifetime,
            .next_response_ns = now_ns,
            .max_response_interval_ns = @max(minimum_response_interval_ns, actual_lifetime / 3),
            .bytes_received = if (packet) |value| value.bytes_received else 0,
            .bytes_sent = if (packet) |value| value.bytes_sent else 0,
        };
    }

    pub fn receive(self: *State, endpoint: *runtime.Endpoint, datagram: runtime.ReceivedBytesView, now_ns: u64) runtime.Error!void {
        if (now_ns >= self.deadline_ns or !datagram.from.eql(&self.peer)) return;
        if (datagram.bytes.len == 0) return;
        if ((datagram.bytes[0] & 0x80) != 0) {
            if (datagram.bytes.len < 5 or std.mem.readInt(u32, datagram.bytes[1..5], .big) != self.version) return;
        }
        // Packet keys are discarded. Enforce three times all attributed bytes
        // even on the former validated path, and never respond to another peer.
        self.bytes_received +|= datagram.bytes.len;
        const packet = if (self.packet) |*value| value else return;
        if (now_ns < self.next_response_ns or
            packet.len > self.bytes_received *| 3 -| self.bytes_sent) return;
        self.next_response_ns = now_ns +| self.response_interval_ns;
        self.response_interval_ns = @min(self.response_interval_ns *| 2, self.max_response_interval_ns);
        try endpoint.sendBytes(self.peer, packet.slice());
        self.bytes_sent +|= packet.len;
    }
};

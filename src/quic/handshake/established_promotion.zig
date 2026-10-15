//! State transferred from the blocking TLS handshake into established QUIC.
//!
//! Keeping these actions on the first constructed `Connection` lets the
//! caller return the large established value directly. It also keeps the
//! coalesced 1-RTT and accepted/rejected 0-RTT transitions in one ownership
//! boundary for both endpoint roles.

const std = @import("std");
const quic = @import("../mod.zig");

const net = std.Io.net;

pub const CoalescedOneRtt = struct {
    from: net.IpAddress,
    bytes: []const u8,
    ecn: quic.packet_space.EcnCodepoint,
};

pub const SentEarlyData = struct {
    protected_packet_count: u64,
    sent_packet_numbers: []const u64,
    sent_datagram_size: usize,
    frames: []const quic.Frame,
};

pub const ReceivedEarlyData = struct {
    packet_number: u64,
    frames: []const quic.Frame,
};

pub const PostInit = union(enum) {
    none,
    client: struct {
        coalesced_one_rtt: ?CoalescedOneRtt = null,
        sent_early_data: ?SentEarlyData = null,
    },
    server: struct {
        coalesced_one_rtt: ?CoalescedOneRtt = null,
        received_early_data: ?ReceivedEarlyData = null,
    },
};

pub const Counters = struct {
    protected_packet_count: u64 = 0,
    sent_packet_count: usize = 0,
};

pub fn apply(
    connection: *quic.one_rtt.Connection,
    local_endpoint: quic.one_rtt.ConnectionConfig.EndpointRole,
    early_data_status: quic.zero_rtt.handshake.Status,
    post_init: PostInit,
) quic.one_rtt.Error!Counters {
    switch (post_init) {
        .none => return .{},
        .client => |client| {
            std.debug.assert(local_endpoint == .client);
            if (client.coalesced_one_rtt) |one_rtt| {
                try connection.preloadReceivedDatagram(
                    one_rtt.from,
                    one_rtt.bytes,
                    one_rtt.ecn,
                );
            }
            const early_data = client.sent_early_data orelse return .{};
            if (early_data_status == .accepted and
                early_data.sent_packet_numbers.len != 0)
            {
                try connection.importSentEarlyDataPacketNumbers(
                    0,
                    early_data.protected_packet_count,
                    early_data.sent_packet_numbers,
                    early_data.sent_datagram_size,
                    early_data.frames,
                );
            } else if (early_data.protected_packet_count != 0) {
                try connection.discardSentEarlyDataCopies(
                    0,
                    early_data.protected_packet_count,
                );
            }
            return .{
                .protected_packet_count = early_data.protected_packet_count,
                .sent_packet_count = early_data.sent_packet_numbers.len,
            };
        },
        .server => |server| {
            std.debug.assert(local_endpoint == .server);
            if (server.coalesced_one_rtt) |one_rtt| {
                try connection.preloadReceivedDatagram(
                    one_rtt.from,
                    one_rtt.bytes,
                    one_rtt.ecn,
                );
            }
            if (server.received_early_data) |early_data| {
                try connection.applyEarlyDataFrames(
                    early_data.packet_number,
                    early_data.frames,
                );
            }
            return .{};
        },
    }
}

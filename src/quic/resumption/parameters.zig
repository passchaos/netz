//! QUIC transport parameters that may be remembered for 0-RTT.
//!
//! RFC 9000 Section 7.4.1 deliberately excludes identity, ACK timing, reset,
//! and preferred-address parameters. RFC 9221 additionally permits remembering
//! `max_datagram_frame_size`.

const std = @import("std");
const quic = @import("../mod.zig");

pub const ValidationError = error{
    ReducedTransportParameter,
    MissingRememberedDatagramSupport,
};

pub const Snapshot = struct {
    active_connection_id_limit: u64,
    initial_max_data: u64,
    initial_max_stream_data_bidi_local: u64,
    initial_max_stream_data_bidi_remote: u64,
    initial_max_stream_data_uni: u64,
    initial_max_streams_bidi: u64,
    initial_max_streams_uni: u64,
    max_datagram_frame_size: ?u64 = null,

    pub fn fromTransportParameters(params: quic.TransportParameters) Snapshot {
        return .{
            .active_connection_id_limit = params.active_connection_id_limit,
            .initial_max_data = params.initial_max_data,
            .initial_max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local,
            .initial_max_stream_data_bidi_remote = params.initial_max_stream_data_bidi_remote,
            .initial_max_stream_data_uni = params.initial_max_stream_data_uni,
            .initial_max_streams_bidi = params.initial_max_streams_bidi,
            .initial_max_streams_uni = params.initial_max_streams_uni,
            .max_datagram_frame_size = params.max_datagram_frame_size,
        };
    }

    /// Apply only remembered send limits to a fresh parameter set. Forbidden
    /// fields retain their RFC defaults/current values.
    pub fn applyTo(
        self: Snapshot,
        params: *quic.TransportParameters,
    ) void {
        params.active_connection_id_limit = self.active_connection_id_limit;
        params.initial_max_data = self.initial_max_data;
        params.initial_max_stream_data_bidi_local =
            self.initial_max_stream_data_bidi_local;
        params.initial_max_stream_data_bidi_remote =
            self.initial_max_stream_data_bidi_remote;
        params.initial_max_stream_data_uni =
            self.initial_max_stream_data_uni;
        params.initial_max_streams_bidi = self.initial_max_streams_bidi;
        params.initial_max_streams_uni = self.initial_max_streams_uni;
        params.max_datagram_frame_size = self.max_datagram_frame_size;
    }

    /// RFC 9000 §7.4.1 requires the server's handshake parameters to be at
    /// least the remembered values after a client sent 0-RTT. Otherwise the
    /// connection fails with TRANSPORT_PARAMETER_ERROR.
    pub fn validateAfterEarlyDataAccepted(
        self: Snapshot,
        current: quic.TransportParameters,
    ) ValidationError!void {
        if (current.active_connection_id_limit <
            self.active_connection_id_limit or
            current.initial_max_data < self.initial_max_data or
            current.initial_max_stream_data_bidi_local <
                self.initial_max_stream_data_bidi_local or
            current.initial_max_stream_data_bidi_remote <
                self.initial_max_stream_data_bidi_remote or
            current.initial_max_stream_data_uni <
                self.initial_max_stream_data_uni or
            current.initial_max_streams_bidi <
                self.initial_max_streams_bidi or
            current.initial_max_streams_uni <
                self.initial_max_streams_uni)
        {
            return error.ReducedTransportParameter;
        }
        if (self.max_datagram_frame_size) |remembered| {
            const current_limit = current.max_datagram_frame_size orelse
                return error.MissingRememberedDatagramSupport;
            if (current_limit < remembered) {
                return error.ReducedTransportParameter;
            }
        }
    }
};

test "0-RTT snapshot remembers only permitted transport parameters" {
    const original = quic.TransportParameters{
        .original_destination_connection_id = "odcid",
        .max_idle_timeout = 1234,
        .stateless_reset_token = [_]u8{1} ** 16,
        .max_udp_payload_size = 1400,
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_local = 200,
        .initial_max_stream_data_bidi_remote = 300,
        .initial_max_stream_data_uni = 400,
        .initial_max_streams_bidi = 5,
        .initial_max_streams_uni = 6,
        .ack_delay_exponent = 10,
        .max_ack_delay = 77,
        .disable_active_migration = true,
        .active_connection_id_limit = 8,
        .max_datagram_frame_size = 1200,
    };
    const snapshot = Snapshot.fromTransportParameters(original);
    var restored = quic.TransportParameters{};
    snapshot.applyTo(&restored);

    try std.testing.expectEqual(@as(u64, 100), restored.initial_max_data);
    try std.testing.expectEqual(@as(u64, 8), restored.active_connection_id_limit);
    try std.testing.expectEqual(@as(?u64, 1200), restored.max_datagram_frame_size);
    try std.testing.expect(restored.original_destination_connection_id == null);
    try std.testing.expect(restored.stateless_reset_token == null);
    try std.testing.expectEqual(@as(u64, 0), restored.max_idle_timeout);
    try std.testing.expectEqual(
        quic.default_ack_delay_exponent,
        restored.ack_delay_exponent,
    );
    try std.testing.expectEqual(
        quic.default_max_ack_delay_ms,
        restored.max_ack_delay,
    );
    try std.testing.expect(!restored.disable_active_migration);
}

test "0-RTT snapshot rejects reduced and removed parameters" {
    const snapshot = Snapshot{
        .active_connection_id_limit = 4,
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_local = 200,
        .initial_max_stream_data_bidi_remote = 300,
        .initial_max_stream_data_uni = 400,
        .initial_max_streams_bidi = 5,
        .initial_max_streams_uni = 6,
        .max_datagram_frame_size = 1200,
    };
    const baseline = quic.TransportParameters{
        .active_connection_id_limit = 4,
        .initial_max_data = 100,
        .initial_max_stream_data_bidi_local = 200,
        .initial_max_stream_data_bidi_remote = 300,
        .initial_max_stream_data_uni = 400,
        .initial_max_streams_bidi = 5,
        .initial_max_streams_uni = 6,
        .max_datagram_frame_size = 1200,
    };
    try snapshot.validateAfterEarlyDataAccepted(baseline);

    inline for (.{
        "active_connection_id_limit",
        "initial_max_data",
        "initial_max_stream_data_bidi_local",
        "initial_max_stream_data_bidi_remote",
        "initial_max_stream_data_uni",
        "initial_max_streams_bidi",
        "initial_max_streams_uni",
    }) |field_name| {
        var reduced = baseline;
        @field(reduced, field_name) -= 1;
        try std.testing.expectError(
            error.ReducedTransportParameter,
            snapshot.validateAfterEarlyDataAccepted(reduced),
        );
    }
    var reduced_datagram = baseline;
    reduced_datagram.max_datagram_frame_size = 1199;
    try std.testing.expectError(
        error.ReducedTransportParameter,
        snapshot.validateAfterEarlyDataAccepted(reduced_datagram),
    );
    var removed_datagram = baseline;
    removed_datagram.max_datagram_frame_size = null;
    try std.testing.expectError(
        error.MissingRememberedDatagramSupport,
        snapshot.validateAfterEarlyDataAccepted(removed_datagram),
    );
}

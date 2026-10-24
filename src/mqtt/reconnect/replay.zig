//! Drain one durable QoS transmission at a time under the caller budget.

const std = @import("std");
const session = @import("../session/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub fn drain(comptime Context: type, self: *Context.ClientType, deadline: ?std.Io.Clock.Timestamp) Context.ErrorType!void {
    const active = self.connection() orelse
        return error.ConnectionUnavailable;
    // Select one packet at a time. If its socket write fails, the Session
    // store can conservatively mark exactly that packet as a retransmit;
    // later queued packets retain first-delivery DUP semantics.
    var batch: [1]session.Transmission = undefined;
    while (true) {
        if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
        const transmissions = try self.outgoing.drainIntoAvoiding(
            self.outgoing_handle,
            std.Io.Clock.awake.now(self.io),
            active.max_outgoing_inflight,
            &batch,
            active.packet_identifiers.ownership(),
        );
        if (transmissions.len == 0) return;
        for (transmissions) |transmission| {
            var wire_transmission = transmission;
            const qos1_completed_on_write =
                self.client_options.outbound_replay_capability_policy ==
                .adapt_qos1 and
                transmission == .publish and
                transmission.publish.qos == .at_least_once and
                active.peerMaximumQoS() == .at_most_once;
            if (self.client_options.outbound_replay_capability_policy ==
                .adapt_qos1 and transmission == .publish and
                transmission.publish.qos == .at_least_once)
            {
                wire_transmission.publish.qos = @enumFromInt(@min(
                    @intFromEnum(transmission.publish.qos),
                    @intFromEnum(active.peerMaximumQoS()),
                ));
                wire_transmission.publish.retain =
                    transmission.publish.retain and
                    active.peerRetainAvailable();
            }
            (if (deadline) |absolute|
                active.writeClientSessionTransmissionWithDeadline(wire_transmission, absolute)
            else
                active.writeClientSessionTransmission(wire_transmission)) catch |err| {
                if (err == error.OutgoingPacketTooLarge and
                    transmission == .publish)
                {
                    const publish_value = transmission.publish;
                    const dropped = try self.outgoing.dropOversizedPublish(
                        self.outgoing_handle,
                        publish_value.packet_id,
                    );
                    if (dropped != .dropped) {
                        return error.InvalidAcknowledgement;
                    }
                    // Maximum Packet Size may shrink across connections.
                    // Match broker/Mosquitto delivery semantics: retire
                    // only this destination, keep the transport usable,
                    // and surface an ACK-compatible terminal reason.
                    Context.finishDelivery(self, .{
                        .packet_id = if (publish_value.packet_id == 0)
                            null
                        else
                            publish_value.packet_id,
                        .qos = publish_value.qos,
                        .reason_code = 0x97,
                        .properties = &.{},
                    });
                    continue;
                }
                if (!Context.retryable(err) and
                    transmission == .publish)
                {
                    try self.outgoing.retryUnsentPublish(
                        self.outgoing_handle,
                        transmission.publish.packet_id,
                    );
                }
                self.disconnectTransport();
                return err;
            };
            if (qos1_completed_on_write) {
                // The original Packet Identifier remains the Session key
                // until the QoS 0 socket write succeeds. Only then can we
                // retire it and report completion of the caller's QoS 1
                // contract without risking loss on a failed write.
                const packet_id = transmission.publish.packet_id;
                const dropped = try self.outgoing.dropOutgoingPublish(
                    self.outgoing_handle,
                    packet_id,
                );
                if (dropped != .dropped) {
                    return error.InvalidAcknowledgement;
                }
                Context.finishDelivery(self, .{
                    .packet_id = packet_id,
                    .qos = .at_least_once,
                    .reason_code = 0,
                    .properties = &.{},
                });
            }
        }
    }
}

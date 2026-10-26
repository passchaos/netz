//! Apply one ordered client packet with bounded automatic protocol output.
const std = @import("std");
const runtime = @import("../runtime.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn apply(
            self: *Context.ClientType,
            packet_event: *runtime.ClientPacketEvent,
            deadline: std.Io.Clock.Timestamp,
        ) Context.ErrorType!?Context.EventType {
            const active = self.connection() orelse
                return error.ConnectionUnavailable;
            return switch (packet_event.*) {
                .publish => |owned| blk: {
                    if (owned.publish.packet_id) |packet_id| {
                        switch (owned.publish.qos) {
                            .at_most_once => unreachable,
                            .at_least_once => if (!self.client_options.manual_acknowledgements) {
                                active.writePubAckWithDeadline(packet_id, 0, deadline) catch |err| {
                                    self.pending_event = .{ .publish = owned };
                                    return err;
                                };
                            },
                            .exactly_once => {
                                if (self.client_options.manual_acknowledgements) {
                                    // Once the application has accepted a QoS 2
                                    // message, retransmitted PUBLISH packets belong
                                    // to the existing handshake. Re-emit PUBREC and
                                    // suppress a second application delivery.
                                    if (try self.outgoing.containsIncomingQoS2(
                                        self.outgoing_handle,
                                        packet_id,
                                    )) {
                                        const pubrec_may_be_visible =
                                            (try self.outgoing
                                                .incomingQoS2PubRecMayBeVisible(
                                                self.outgoing_handle,
                                                packet_id,
                                            )).?;
                                        if (pubrec_may_be_visible and
                                            !self.client_options
                                                .surface_incoming_qos2_retransmissions)
                                        {
                                            try active.writePubRecWithDeadline(packet_id, 0, deadline);
                                            Context.noteControlSent(self);
                                            return null;
                                        }
                                    }
                                } else {
                                    const duplicate =
                                        try self.outgoing.recordIncomingQoS2(
                                            self.outgoing_handle,
                                            packet_id,
                                        );
                                    active.writePubRecWithDeadline(packet_id, 0, deadline) catch |err| {
                                        if (!duplicate) self.pending_event = .{ .publish = owned };
                                        return err;
                                    };
                                    Context.noteControlSent(self);
                                    if (duplicate) {
                                        return null;
                                    }
                                }
                            },
                        }
                        if (!self.client_options.manual_acknowledgements) {
                            Context.noteControlSent(self);
                        }
                    }
                    break :blk .{ .publish = owned };
                },
                .puback => |owned| blk: {
                    _ = Context.applyOutgoingAck(self, owned.ack) catch |err| {
                        // The Session store removes a terminal ACK before
                        // surfacing its rejection. Notify observers while the ACK
                        // properties are still alive, then preserve the error.
                        if (err == error.PublishRefused) {
                            Context.finishDelivery(self, .{
                                .packet_id = owned.ack.packet_id,
                                .qos = .at_least_once,
                                .reason_code = owned.ack.reason_code,
                                .properties = owned.ack.properties,
                            });
                        }
                        return err;
                    };
                    Context.finishDelivery(self, .{
                        .packet_id = owned.ack.packet_id,
                        .qos = .at_least_once,
                        .reason_code = owned.ack.reason_code,
                        .properties = owned.ack.properties,
                    });
                    break :blk .{ .puback = owned };
                },
                .pubrec => |owned| blk: {
                    const action = try Context.applyOutgoingAck(self, owned.ack);
                    if (action == .send_pubrel and
                        self.client_options.outbound_qos2_release_policy ==
                            .automatic)
                    {
                        Context.replayPending(self, deadline) catch |err| {
                            self.pending_event = .{ .pubrec = owned };
                            return err;
                        };
                        Context.noteControlSent(self);
                    } else if (action == .completed) {
                        // A negative PUBREC terminates the QoS 2 transaction and
                        // is its protocol-level delivery result.
                        Context.finishDelivery(self, .{
                            .packet_id = owned.ack.packet_id,
                            .qos = .exactly_once,
                            .reason_code = owned.ack.reason_code,
                            .properties = owned.ack.properties,
                        });
                    }
                    break :blk .{ .pubrec = owned };
                },
                .pubrel => |owned| blk: {
                    const packet_id = owned.ack.packet_id;
                    const incoming_state = try self.outgoing.incomingQoS2State(
                        self.outgoing_handle,
                        packet_id,
                    );
                    if (incoming_state == null and active.hasPendingIncomingPublish(packet_id, .exactly_once)) {
                        // This includes manual acknowledgement with automatic
                        // release: PUBREL cannot precede the first PUBREC.
                        return error.UnexpectedPacket;
                    }
                    if (self.client_options.inbound_qos2_release_policy ==
                        .deferred)
                    {
                        if (incoming_state != null) {
                            try self.outgoing.markIncomingQoS2ReleasePending(
                                self.outgoing_handle,
                                packet_id,
                            );
                            // The application owns the release boundary. In
                            // particular, do not clear durable state or expose
                            // PUBCOMP until it explicitly completes the
                            // transaction.
                            break :blk .{ .pubrel = owned };
                        }
                        // A lost PUBCOMP makes the peer repeat PUBREL after local
                        // completion. Re-acknowledge it, but never manufacture a
                        // second application release event without a marker.
                        try active.writePubCompWithDeadline(packet_id, 0, deadline);
                        Context.noteControlSent(self);
                        return null;
                    }
                    if (incoming_state != null) {
                        // Session Present can resume a transaction whose receive
                        // bit lived on the old socket. Recreate only that local
                        // accounting before the normal PUBCOMP writer clears it.
                        try active.resumeIncomingQoS2(packet_id);
                        // Automatic application release has already completed.
                        // A repeated PUBREL can be answered without a marker;
                        // retaining one after ambiguous PUBCOMP output could
                        // suppress a new PUBLISH reusing this identifier.
                        try self.outgoing.completeIncomingQoS2(self.outgoing_handle, packet_id);
                    }
                    // Unknown/repeated PUBREL is idempotently acknowledged: the
                    // prior PUBCOMP may have been lost after durable completion.
                    active.writePubCompWithDeadline(packet_id, 0, deadline) catch |err| {
                        self.pending_event = .{ .pubrel = owned };
                        return err;
                    };
                    Context.noteControlSent(self);
                    break :blk .{ .pubrel = owned };
                },
                .pubcomp => |owned| blk: {
                    _ = Context.applyOutgoingAck(self, owned.ack) catch |err| {
                        if (err == error.PublishRefused) {
                            Context.finishDelivery(self, .{
                                .packet_id = owned.ack.packet_id,
                                .qos = .exactly_once,
                                .reason_code = owned.ack.reason_code,
                                .properties = owned.ack.properties,
                            });
                        }
                        return err;
                    };
                    Context.finishDelivery(self, .{
                        .packet_id = owned.ack.packet_id,
                        .qos = .exactly_once,
                        .reason_code = owned.ack.reason_code,
                        .properties = owned.ack.properties,
                    });
                    break :blk .{ .pubcomp = owned };
                },
                .pingresp => |*packet| blk: {
                    if (self.ping_response_deadline == null) {
                        return error.UnexpectedPacket;
                    }
                    self.ping_response_deadline = null;
                    packet.deinit(self.allocator);
                    break :blk .{ .pingresp = {} };
                },
                .disconnect => |owned| blk: {
                    self.disconnectTransport();
                    break :blk .{ .disconnect = owned };
                },
                .auth => |owned| blk: {
                    const complete = active.applyAuthenticationEventWithDeadline(
                        owned.auth,
                        deadline,
                    ) catch |err| {
                        // The runtime has already attempted the required protocol
                        // diagnostic for authentication state violations.
                        self.disconnectTransport();
                        return err;
                    };
                    if (!complete) {
                        const handler = self.options.value.authentication orelse
                            return error.AuthenticationNotConfigured;
                        const response = try handler.respond(
                            handler.context,
                            owned.auth,
                        );
                        active.continueReauthenticationWithDeadline(
                            0x18,
                            response,
                            deadline,
                        ) catch |err| {
                            self.pending_event = .{ .auth = owned };
                            Context.retireUnusableConnection(self);
                            return err;
                        };
                        Context.noteControlSent(self);
                    }
                    break :blk .{ .auth = owned };
                },
            };
        }
    };
}

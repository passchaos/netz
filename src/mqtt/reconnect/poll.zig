//! Single-owner event polling, automatic output recovery, and delivery order.
const std = @import("std");

pub fn Controller(comptime Context: type) type {
    return struct {
        pub fn run(
            self: *Context.ClientType,
            call_deadline: std.Io.Timestamp,
            ping_response_timeout: ?std.Io.Duration,
            cancellation_check_interval: std.Io.Duration,
            reconnect_after_transport_error: bool,
        ) Context.ErrorType!?Context.EventType {
            if (ping_response_timeout) |timeout| {
                if (timeout.nanoseconds <= 0) return error.Timeout;
            }
            if (cancellation_check_interval.nanoseconds <= 0) {
                return error.Timeout;
            }

            while (true) {
                if (self.shutdown.isSet()) return error.Canceled;
                if (self.pending_event) |event| {
                    if (std.Io.Clock.awake.now(self.io).nanoseconds >= call_deadline.nanoseconds) return null;
                    self.pending_event = null;
                    return event;
                }
                if (self.reconnect_requested.swap(false, .acq_rel)) {
                    self.disconnectTransport();
                }
                if (self.connection_state == null) {
                    return try Context.connectBefore(self, call_deadline);
                }

                const now = std.Io.Clock.awake.now(self.io);
                if (now.nanoseconds >= call_deadline.nanoseconds) return null;
                if (self.ping_response_deadline) |deadline| {
                    if (now.nanoseconds >= deadline.nanoseconds) {
                        self.disconnectTransport();
                        if (!reconnect_after_transport_error) return null;
                        return try Context.connectBefore(self, call_deadline);
                    }
                } else if (Context.keepAlive(self)) |deadline| {
                    if (now.nanoseconds >= deadline.nanoseconds) {
                        const active = self.connection().?;
                        active.writePingReqWithDeadline(call_deadline.withClock(.awake)) catch |err| {
                            const retryable = Context.retryable(err);
                            Context.retireAfterError(self, err);
                            if (!retryable) return err;
                            if (!reconnect_after_transport_error) return null;
                            return try Context.connectBefore(self, call_deadline);
                        };
                        const sent_at = std.Io.Clock.awake.now(self.io);
                        self.keep_alive_deadline = sent_at.addDuration(
                            .fromSeconds(active.keep_alive_seconds),
                        );
                        self.ping_response_deadline = sent_at.addDuration(
                            ping_response_timeout orelse
                                .fromSeconds(active.keep_alive_seconds),
                        );
                        return .{ .pingreq = {} };
                    }
                }
                const read_deadline = Context.nextDeadline(
                    self,
                    call_deadline,
                    now,
                    cancellation_check_interval,
                );
                const active = self.connection().?;
                var packet_event = active.readClientPacketEventWithDeadline(
                    read_deadline.withClock(.awake),
                ) catch |err| {
                    if (err == error.Timeout) continue;
                    if (Context.diagnose(self, err, call_deadline.withClock(.awake))) return err;
                    if (!Context.retryable(err)) {
                        self.disconnectTransport();
                        return err;
                    }
                    self.disconnectTransport();
                    if (!reconnect_after_transport_error) return null;
                    return try Context.connectBefore(self, call_deadline);
                };
                var packet_owned = true;
                defer if (packet_owned) packet_event.deinit(self.allocator);
                const client_event = Context.apply(self, &packet_event, call_deadline.withClock(.awake)) catch |err| {
                    // Observe provenance before callback/error cleanup retires a
                    // healthy transport. A callback can return a network-shaped
                    // error without an MQTT socket operation having failed.
                    const transport_failed = if (self.connection()) |current| !current.isUsable() else true;
                    // An applied event may have transferred its complete packet
                    // to the bounded delivery slot before output failed.
                    if (self.pending_event != null) packet_owned = false;
                    // A complete packet has already been consumed. Peer protocol
                    // faults receive an MQTT 5 diagnostic; local state/allocation
                    // and authentication callback failures close silently. Failed
                    // output after semantic application retains the incoming event.
                    // A valid negative publish acknowledgement is the sole terminal
                    // application result and leaves the connection usable.
                    const valid_publish_refusal = err == error.PublishRefused and
                        (packet_event == .puback or
                            packet_event == .pubrec or
                            packet_event == .pubcomp);
                    if (packet_event == .auth) {
                        // Authentication peer-state errors were diagnosed by the
                        // runtime before this callback boundary. Callback/local
                        // response errors are not peer violations, but the
                        // consumed challenge still prevents safe reuse.
                        self.disconnectTransport();
                    } else if (self.pending_event != null) {
                        // The incoming packet was already accepted; a local output
                        // error must not be diagnosed as a peer protocol fault.
                        self.disconnectTransport();
                    } else if (!valid_publish_refusal and
                        !Context.diagnose(self, err, call_deadline.withClock(.awake)))
                    {
                        self.disconnectTransport();
                    }
                    if (err == error.Timeout and std.Io.Clock.awake.now(self.io).nanoseconds >= call_deadline.nanoseconds) return null;
                    if (transport_failed and Context.retryable(err)) {
                        if (!reconnect_after_transport_error) return null;
                        if (self.pending_event) |event| {
                            if (std.Io.Clock.awake.now(self.io).nanoseconds >= call_deadline.nanoseconds) return null;
                            self.pending_event = null;
                            return event;
                        }
                        return try Context.connectBefore(self, call_deadline);
                    }
                    return err;
                };
                if (client_event) |event| {
                    packet_owned = false;
                    return event;
                }
            }
        }
    };
}

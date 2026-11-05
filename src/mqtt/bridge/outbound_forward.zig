//! Owned-event forwarding and fair target completion for QoS 0/1 bridges.
const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const engine = @import("outbound_engine.zig");
const Error = engine.Error;
const TargetPublishResult = engine.TargetPublishResult;
const refreshMessageExpiry = engine.refreshMessageExpiry;
const bridgePollOptions = engine.bridgePollOptions;
const bridgeClientPollOptions = engine.bridgeClientPollOptions;

pub fn Operations(comptime Self: type) type {
    return struct {
        pub fn forward(
            self: *Self,
            source_publish: *const mqtt.Publish,
            poll_options: reconnect.PollOptions,
        ) (Error || std.Io.Cancelable)!void {
            const source_epoch = self.source_session_epoch;
            const rule = self.matchingRule(source_publish.topic) orelse {
                self.source.disconnectTransport();
                return error.TopicOutsideBridgeRule;
            };
            if (@intFromEnum(source_publish.qos) >
                @intFromEnum(rule.value.qos))
            {
                self.source.disconnectTransport();
                return error.InvalidBridgeQoS;
            }
            const target_topic = rule.value.mapMatchedTopicAlloc(
                self.allocator,
                source_publish.topic,
            ) catch |err| switch (err) {
                error.EmptyMappedTopic => {
                    _ = self.acknowledgeSource(source_publish, 0);
                    return;
                },
                else => |other| return other,
            };
            defer self.allocator.free(target_topic);
            var properties: std.ArrayList(mqtt.Property) = .empty;
            defer properties.deinit(self.allocator);
            try properties.ensureTotalCapacity(
                self.allocator,
                source_publish.properties.len,
            );
            for (source_publish.properties) |property| {
                if ((property == .two_byte and
                    property.two_byte.id == .topic_alias) or
                    (property == .varint and
                        property.varint.id == .subscription_identifier))
                {
                    continue;
                }
                properties.appendAssumeCapacity(property);
            }
            const received_at_ns = std.Io.Clock.awake.now(
                self.source.io,
            ).nanoseconds;
            const expiry_interval = mqtt.messageExpiryInterval(properties.items);
            if (self.target.connection() == null) {
                try self.connectTargetWhileServingSource(
                    source_publish,
                    poll_options,
                );
            }
            if (source_publish.qos == .exactly_once) {
                return self.forwardDurableQoS2(
                    source_publish,
                    target_topic,
                    properties.items,
                    poll_options,
                );
            }
            var target_result = publishTarget(
                self,
                target_topic,
                source_publish,
                &properties,
                expiry_interval,
                received_at_ns,
            ) catch |err| {
                if (err == error.OutgoingPacketTooLarge) {
                    // Match broker delivery semantics: a per-peer packet cap
                    // drops this destination without poisoning either
                    // connection. MQTT 5 sources get Quota Exceeded; MQTT
                    // 3.1.1 sources receive their version's success-only ACK.
                    _ = self.acknowledgeSource(source_publish, 0x97);
                    return;
                }
                if (source_publish.qos == .at_least_once) {
                    self.source.disconnectTransport();
                }
                return err;
            };
            switch (target_result) {
                .expired => {
                    _ = self.acknowledgeSource(source_publish, 0);
                    return;
                },
                .completed => {
                    if (source_publish.qos != .at_most_once) {
                        self.completeSource(
                            source_publish,
                            source_epoch,
                            0,
                        );
                    }
                    return;
                },
                .published => {},
            }
            if (source_publish.qos == .at_most_once) return;
            errdefer self.source.disconnectTransport();
            var target_packet_id = target_result.published orelse
                return error.UnexpectedPacket;
            const fair_source_poll = bridgePollOptions(poll_options);
            while (true) {
                if (self.once and self.target.connection() == null) return error.ConnectionClosed;
                const target_poll = bridgeClientPollOptions(
                    &self.target,
                    poll_options,
                );
                const maybe_target_event = self.target.pollWithOptions(target_poll) catch |err|
                    switch (err) {
                        error.PublishRefused => {
                            if (!self.target_delivery.completed or
                                self.target_delivery.packet_id != target_packet_id)
                            {
                                self.target.disconnectTransport();
                                return error.TargetAcknowledgementMismatch;
                            }
                            self.completeSource(
                                source_publish,
                                source_epoch,
                                self.target_delivery.reason_code,
                            );
                            return;
                        },
                        else => |other| {
                            self.target.disconnectTransport();
                            return other;
                        },
                    };
                if (maybe_target_event) |event_value| {
                    var target_event = event_value;
                    defer target_event.deinit(self.allocator);
                    switch (target_event) {
                        .connected => |connected| {
                            try self.noteTargetConnected(connected);
                            if (!connected.session_resumed) {
                                target_result = publishTarget(
                                    self,
                                    target_topic,
                                    source_publish,
                                    &properties,
                                    expiry_interval,
                                    received_at_ns,
                                ) catch |err| {
                                    if (err == error.OutgoingPacketTooLarge) {
                                        self.completeSource(
                                            source_publish,
                                            source_epoch,
                                            0x97,
                                        );
                                        return;
                                    }
                                    return err;
                                };
                                switch (target_result) {
                                    .expired, .completed => {
                                        self.completeSource(
                                            source_publish,
                                            source_epoch,
                                            0,
                                        );
                                        return;
                                    },
                                    .published => {},
                                }
                                target_packet_id = target_result.published orelse
                                    return error.UnexpectedPacket;
                            } else {
                                if (try @This().completeWaitingSource(
                                    self,
                                    source_publish,
                                    source_epoch,
                                    target_packet_id,
                                )) return;
                            }
                        },
                        .puback => |owned| {
                            if (owned.ack.packet_id != target_packet_id) {
                                self.target.disconnectTransport();
                                return error.TargetAcknowledgementMismatch;
                            }
                            self.completeSource(
                                source_publish,
                                source_epoch,
                                owned.ack.reason_code,
                            );
                            return;
                        },
                        .disconnect => self.target.disconnectTransport(),
                        .publish => |owned| try self.handleTargetPublish(
                            &owned.publish,
                        ),
                        .pubrel => |owned| try self.handleTargetPubRel(
                            owned.ack.packet_id,
                        ),
                        .pingreq, .pingresp, .auth => {},
                        .pubrec, .pubcomp => {
                            self.target.disconnectTransport();
                            return error.UnexpectedPacket;
                        },
                    }
                }
                if (maybe_target_event == null and
                    try @This().completeWaitingSource(
                        self,
                        source_publish,
                        source_epoch,
                        target_packet_id,
                    )) return;
                try self.serviceSourceWhileWaiting(
                    source_publish,
                    fair_source_poll,
                );
            }
        }

        /// Complete the source once the target client has no queued or inflight
        /// PUBLISH left. This also covers a message the target pruned because
        /// its Message Expiry Interval elapsed while no target event arrived.
        fn completeWaitingSource(
            self: *Self,
            source_publish: *const mqtt.Publish,
            source_epoch: u64,
            target_packet_id: u16,
        ) Error!bool {
            const stats = try self.target.outgoingStats();
            if (stats.queued_count != 0 or stats.inflight_count != 0) {
                return false;
            }
            const reason_code = blk: {
                if (!self.target_delivery.completed) {
                    break :blk @as(u8, 0);
                }
                if (self.target_delivery.packet_id != target_packet_id) {
                    return error.TargetAcknowledgementMismatch;
                }
                const reason = self.target_delivery.reason_code;
                self.target_delivery.reset();
                break :blk reason;
            };
            self.completeSource(source_publish, source_epoch, reason_code);
            return true;
        }

        pub fn publishTarget(
            self: *Self,
            topic: []const u8,
            source_publish: *const mqtt.Publish,
            properties: *std.ArrayList(mqtt.Property),
            expiry_interval: ?u32,
            received_at_ns: i96,
        ) (Error || std.Io.Cancelable)!TargetPublishResult {
            if (self.target.connection() == null) {
                return error.ConnectionUnavailable;
            }
            if (!refreshMessageExpiry(
                properties.items,
                expiry_interval,
                received_at_ns,
                std.Io.Clock.awake.now(self.target.io).nanoseconds,
            )) return .expired;
            const active = self.target.connection() orelse
                return error.ConnectionUnavailable;
            const target_qos: mqtt.QoS = @enumFromInt(@min(
                @intFromEnum(source_publish.qos),
                @intFromEnum(active.peerMaximumQoS()),
            ));
            self.target_delivery.reset();
            const attempt = try self.target.publishOneAttempt(
                topic,
                source_publish.payload,
                .{
                    .qos = target_qos,
                    .retain = self.preserve_retain and
                        source_publish.retain and
                        active.peerRetainAvailable(),
                    .properties = properties.items,
                },
            );
            if (target_qos == .at_most_once) return .completed;
            if (source_publish.qos == .at_least_once) {
                const stats = try self.target.outgoingStats();
                if (stats.queued_count == 0 and stats.inflight_count == 0) {
                    return .expired;
                }
            }
            return .{ .published = attempt.packet_id };
        }
    };
}

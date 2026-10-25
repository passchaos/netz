//! In-process source adapter for the outbound bridge's coordinated state machine.
//!
//! The broker owns outgoing delivery and its journal. A separate receipt Store
//! supplies the coordinator's receive-side markers; it never owns a transport
//! or duplicates the broker's queue. Source ACKs follow coordinator commits.

const std = @import("std");
const mqtt = @import("../mod.zig");
const broker_mod = @import("../broker.zig");
const local_consumer = @import("../broker/local_consumer.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const session = @import("../session/mod.zig");
const snapshot = @import("../reconnect/snapshot.zig");
const subscription = @import("../reconnect/subscription.zig");
const local_wait = @import("local_wait.zig");

pub const Error = broker_mod.Error || snapshot.Error || error{SourceSessionLost};

const OwnedPublish = struct {
    publish: mqtt.Publish,
    event: broker_mod.LocalConsumerEvent,

    pub fn deinit(self: *@This(), _: std.mem.Allocator) void {
        self.event.deinit();
        self.* = undefined;
    }
};

const OwnedAck = struct {
    ack: mqtt.AckPacket,

    pub fn deinit(self: *@This(), _: std.mem.Allocator) void {
        self.* = undefined;
    }
};

pub const Event = union(enum) {
    connected: reconnect.ConnectEvent,
    publish: OwnedPublish,
    pubrel: OwnedAck,
    puback: void,
    pubrec: void,
    pubcomp: void,
    disconnect: void,
    pingreq: void,
    pingresp: void,
    auth: void,

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .publish => |*value| value.deinit(allocator),
            .pubrel => |*value| value.deinit(allocator),
            else => {},
        }
        self.* = undefined;
    }
};

pub const Client = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    broker: *broker_mod.Broker,
    id: [16]u8,
    client_id: []u8,
    clean_session: bool,
    replace_mismatched_session: bool,
    shutdown: *std.Io.Event,
    wake: *broker_mod.LocalConsumerWake,
    subscriptions: std.ArrayList(subscription.Owned) = .empty,
    consumer: ?broker_mod.LocalConsumer = null,
    receipts: session.Store,
    receipt_handle: session.Handle,
    selected: ?union(enum) { publish: u16, pubrel: u16, qos0_completion: void } = null,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        broker: *broker_mod.Broker,
        id: [16]u8,
        options: runtime.ConnectOptions,
        shutdown: *std.Io.Event,
        replace_mismatched_session: bool,
    ) Error!Client {
        const client_id = try allocator.dupe(u8, options.client_id);
        errdefer allocator.free(client_id);
        const wake = try allocator.create(broker_mod.LocalConsumerWake);
        errdefer allocator.destroy(wake);
        wake.* = .{};
        var receipts = session.Store.init(allocator, .{ .max_sessions = 1 });
        errdefer receipts.deinit();
        const opened = try receipts.open(
            client_id,
            options.clean_start,
            if (options.clean_start) 0 else std.math.maxInt(u32),
            .zero,
        );
        return .{
            .allocator = allocator,
            .io = io,
            .broker = broker,
            .id = id,
            .client_id = client_id,
            .clean_session = options.clean_start,
            .replace_mismatched_session = replace_mismatched_session,
            .shutdown = shutdown,
            .wake = wake,
            .receipts = receipts,
            .receipt_handle = opened.handle,
        };
    }

    pub fn deinit(self: *Client) void {
        self.disconnectTransport();
        for (self.subscriptions.items) |*value| value.deinit(self.allocator);
        self.subscriptions.deinit(self.allocator);
        self.receipts.deinit();
        self.allocator.destroy(self.wake);
        self.allocator.free(self.client_id);
        self.* = undefined;
    }

    pub fn seedSubscription(self: *Client, value: mqtt.Subscription, properties: []const mqtt.Property) Error!void {
        var owned = try subscription.Owned.clone(self.allocator, value, properties);
        errdefer owned.deinit(self.allocator);
        try self.subscriptions.append(self.allocator, owned);
    }

    pub fn isConnected(self: *const Client) bool {
        return self.consumer != null;
    }

    pub fn protocolVersion(_: *const Client) mqtt.ProtocolVersion {
        return .v5;
    }

    pub fn connect(self: *Client) Error!reconnect.ConnectEvent {
        if (self.shutdown.isSet()) return error.Canceled;
        if (self.consumer) |consumer| return .{ .session_present = consumer.session_present, .failed_attempts = 0 };
        const values = try self.allocator.alloc(mqtt.Subscription, self.subscriptions.items.len);
        defer self.allocator.free(values);
        for (values, self.subscriptions.items) |*value, owned| value.* = owned.value();
        var consumer = try self.broker.openLocalConsumer(.{
            .id = self.id,
            .subscriptions = values,
            .receive_maximum = 1,
            .wake = self.wake,
            .clean_session = self.clean_session,
            .replace_mismatched_session = self.replace_mismatched_session,
        });
        errdefer self.broker.closeLocalConsumer(&consumer);
        self.consumer = consumer;
        return .{ .session_present = consumer.session_present, .failed_attempts = 0 };
    }

    pub fn pendingCount(self: *Client) Error!usize {
        if (self.consumer == null) return error.SourceSessionLost;
        return self.broker.localConsumerPendingCount(&self.consumer.?);
    }

    pub fn deliveryGeneration(self: *const Client) u64 {
        return self.wake.observe();
    }

    pub const waitForPending = local_wait.waitForPending;

    pub fn disconnectTransport(self: *Client) void {
        if (self.consumer) |*consumer| self.broker.closeLocalConsumer(consumer);
        self.consumer = null;
        self.selected = null;
    }

    pub fn disconnect(self: *Client, _: u8) Error!void {
        self.disconnectTransport();
    }

    pub fn pollWithOptions(self: *Client, _: reconnect.PollOptions) Error!?Event {
        if (self.shutdown.isSet()) return error.Canceled;
        if (self.consumer == null) return .{ .connected = try self.connect() };
        if (try self.finishPendingCompletion()) return null;
        // Preserve a selected publication while its target is pending. Once
        // QoS 0 finishes at the target, retry only the broker completion. A
        // selected PUBREL can be replayed after a coordinator commit rollback,
        // or finish an already-staged PUBCOMP whose broker journal write failed.
        if (self.selected) |selected| switch (selected) {
            .publish => return null,
            .qos0_completion => unreachable,
            .pubrel => |packet_id| {
                const state = try self.receipts.incomingQoS2State(self.receipt_handle, packet_id);
                if (state != .release_pending) return error.InvalidAcknowledgement;
                return releaseEvent(packet_id);
            },
        };
        var event = self.broker.pollLocalConsumer(&self.consumer.?) catch |err| switch (err) {
            error.InflightFull => return null,
            else => return err,
        } orelse return null;
        errdefer event.deinit();
        return switch (event) {
            .publish => |publish| blk: {
                self.selected = .{ .publish = publish.value.packet_id orelse 0 };
                break :blk .{ .publish = .{ .publish = publish.value, .event = event } };
            },
            .pubrel => |packet_id| blk: {
                const state = try self.receipts.incomingQoS2State(self.receipt_handle, packet_id);
                if (state == null) {
                    // The coordinator durably cleared after target completion
                    // but the final broker PUBCOMP commit was interrupted.
                    self.selected = .{ .pubrel = packet_id };
                    try self.writeStagedIncomingQoS2Completion(packet_id, .{});
                    break :blk null;
                }
                try self.receipts.markIncomingQoS2ReleasePending(self.receipt_handle, packet_id);
                self.selected = .{ .pubrel = packet_id };
                break :blk releaseEvent(packet_id);
            },
        };
    }

    /// Finish local durability after the target has already accepted delivery.
    /// This never selects a queued publication or writes to the target.
    pub fn finishPendingCompletion(self: *Client) Error!bool {
        const selected = self.selected orelse return false;
        switch (selected) {
            .publish => return false,
            .qos0_completion => try self.completeQoS0(),
            .pubrel => |packet_id| {
                if (try self.receipts.incomingQoS2State(self.receipt_handle, packet_id) != null) return false;
                try self.writeStagedIncomingQoS2Completion(packet_id, .{});
            },
        }
        return true;
    }

    pub fn completeQoS0(self: *Client) Error!void {
        const selected = self.selected orelse return error.InvalidAcknowledgement;
        if (selected != .qos0_completion and
            (selected != .publish or selected.publish != 0)) return error.InvalidAcknowledgement;
        const consumer = if (self.consumer) |*value| value else return error.SourceSessionLost;
        self.selected = .qos0_completion;
        try self.broker.completeLocalConsumerQoS0(consumer);
        self.selected = null;
    }

    pub fn acknowledge(self: *Client, packet_id: u16, qos: mqtt.QoS, options: runtime.AcknowledgeOptions) Error!void {
        if (qos != .at_least_once) return error.InvalidAcknowledgement;
        _ = try self.broker.acknowledgeLocalConsumer(&self.consumer.?, .puback, packet_id, options.reason_code);
        self.selected = null;
    }

    pub fn outgoingStats(self: *Client) Error!session.Stats {
        return self.receipts.stats(self.receipt_handle);
    }

    pub fn incomingQoS2State(self: *Client, packet_id: u16) Error!?session.IncomingQoS2State {
        // Queried after a durable terminal target outcome. A broker ACK may
        // already have committed while clearing the coordinator was interrupted.
        // Retiring that receipt cannot cause the target message to be resent.
        const receipt = try self.receipts.incomingQoS2State(self.receipt_handle, packet_id);
        if (receipt != null and self.consumer != null) {
            self.broker.state_mutex.lockUncancelable(self.io);
            const state = self.broker.sessions.outgoingQoSState(self.consumer.?.session, packet_id) catch |err| {
                self.broker.state_mutex.unlock(self.io);
                return err;
            };
            self.broker.state_mutex.unlock(self.io);
            if (state == null) {
                try self.receipts.completeIncomingQoS2(self.receipt_handle, packet_id);
                self.selected = null;
                return null;
            }
        }
        return self.receipts.incomingQoS2State(self.receipt_handle, packet_id);
    }

    pub fn validateTransaction(self: *Client, packet_id: u16) Error!void {
        if (self.consumer == null) return error.SourceSessionLost;
        self.broker.state_mutex.lockUncancelable(self.io);
        defer self.broker.state_mutex.unlock(self.io);
        const state = try self.broker.sessions.outgoingQoSState(self.consumer.?.session, packet_id);
        if (state != .await_pubrec and state != .await_pubcomp) return error.SourceSessionLost;
    }

    pub fn stageIncomingQoS2(self: *Client, packet_id: u16) Error!void {
        if (try self.receipts.stageIncomingQoS2(self.receipt_handle, packet_id)) return error.InvalidAcknowledgement;
    }

    pub fn discardStagedIncomingQoS2(self: *Client, packet_id: u16) Error!void {
        try self.receipts.discardStagedIncomingQoS2(self.receipt_handle, packet_id);
    }

    pub fn flushStagedIncomingQoS2(self: *Client, packet_id: u16, options: runtime.AcknowledgeOptions) Error!void {
        try mqtt.validateAckReasonCode(.pubrec, options.reason_code);
        // An earlier failed broker journal write may already have advanced its
        // in-memory phase. Flush its durability barrier by polling later.
        self.broker.state_mutex.lockUncancelable(self.io);
        const state = self.broker.sessions.outgoingQoSState(self.consumer.?.session, packet_id) catch |err| {
            self.broker.state_mutex.unlock(self.io);
            return err;
        };
        self.broker.state_mutex.unlock(self.io);
        if (state == .await_pubrec) {
            _ = try self.broker.acknowledgeLocalConsumer(&self.consumer.?, .pubrec, packet_id, options.reason_code);
        } else if (state != .await_pubcomp or options.reason_code >= 0x80) {
            return error.SourceSessionLost;
        }
        try self.receipts.markIncomingQoS2PubRecStarted(self.receipt_handle, packet_id);
        self.selected = null;
        if (options.reason_code >= 0x80) try self.receipts.completeIncomingQoS2(self.receipt_handle, packet_id);
    }

    pub fn stageIncomingQoS2Completion(self: *Client, packet_id: u16, _: runtime.AcknowledgeOptions) Error!void {
        try self.receipts.completeIncomingQoS2(self.receipt_handle, packet_id);
    }

    pub fn discardStagedIncomingQoS2Completion(self: *Client, packet_id: u16) Error!void {
        try self.receipts.restoreIncomingQoS2ReleasePending(self.receipt_handle, packet_id);
    }

    pub fn writeStagedIncomingQoS2Completion(self: *Client, packet_id: u16, _: runtime.AcknowledgeOptions) Error!void {
        const selected = self.selected orelse return error.InvalidAcknowledgement;
        if (selected != .pubrel or selected.pubrel != packet_id or
            (try self.receipts.incomingQoS2State(self.receipt_handle, packet_id)) != null) return error.InvalidAcknowledgement;
        const consumer = if (self.consumer) |*value| value else return error.SourceSessionLost;
        _ = try self.broker.localConsumerPendingCount(consumer);
        self.broker.state_mutex.lockUncancelable(self.io);
        const state = self.broker.sessions.outgoingQoSState(consumer.session, packet_id) catch |err| {
            self.broker.state_mutex.unlock(self.io);
            return err;
        };
        self.broker.state_mutex.unlock(self.io);
        if (state != null) {
            _ = try self.broker.acknowledgeLocalConsumer(consumer, .pubcomp, packet_id, 0);
        } else if (self.broker.commitLogEnabled()) {
            // ACK removal can precede a failed snapshot/journal allocation.
            // Retrying the now-unknown Packet Identifier cannot commit that
            // mutation; append its complete live image before selecting more.
            while (true) {
                _ = self.broker.appendCommit() catch |err| {
                    if (err != error.SnapshotBusy) return err;
                    try std.Io.sleep(self.io, .fromMilliseconds(1), .awake);
                    continue;
                };
                break;
            }
        }
        self.selected = null;
    }

    pub fn writeSessionSnapshotAt(self: *Client, out: *std.ArrayList(u8), now: std.Io.Timestamp, realtime: std.Io.Timestamp) Error!void {
        try snapshot.encode(&self.receipts, self.receipt_handle, .v5, self.client_id, out, self.allocator, now, realtime);
    }

    pub fn restoreSessionSnapshotAt(self: *Client, bytes: []const u8, now: std.Io.Timestamp, realtime: std.Io.Timestamp) Error!void {
        var restored = try snapshot.decode(self.allocator, bytes, self.receipts.options, .v5, self.client_id, now, realtime);
        defer restored.deinit();
        self.receipts.swap(&restored.store);
        self.receipt_handle = restored.handle;
    }
};

fn releaseEvent(packet_id: u16) Event {
    return .{ .pubrel = .{ .ack = .{ .packet_type = .pubrel, .packet_id = packet_id } } };
}

test {
    _ = @import("local_source_tests.zig");
}

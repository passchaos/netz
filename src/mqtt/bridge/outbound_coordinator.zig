//! Durable state image and commit journal for a two-broker outbound bridge.
//!
//! Every committed record binds the bridge configuration identity, both MQTT
//! reconnect Session snapshots, the source Session epoch, and at most one
//! serialized cross-broker QoS 2 transaction. The outbound bridge deliberately
//! processes one such transaction at a time, so a complete state image keeps
//! recovery simple and bounded.

const std = @import("std");
const mqtt = @import("../mod.zig");
const reconnect = @import("../reconnect.zig");
const runtime = @import("../runtime.zig");
const codec = @import("../persistence/codec.zig");
const commit_log = @import("../persistence/commit_log.zig");
const owned_properties = @import("../owned_properties.zig");

const magic = "netz-mqtt-outbound-bridge\x00";
const version: u32 = 1;

pub const Identity = [32]u8;

pub const Phase = enum(u8) {
    target_await_pubrec,
    target_await_pubcomp,
    target_complete,
    target_rejected,
};

pub const Transaction = struct {
    phase: Phase,
    source_session_epoch: u64,
    target_session_epoch: u64,
    source_packet_id: u16,
    target_packet_id: u16,
    target_reason_code: u8 = 0,
    source_retain: bool,
    source_topic: []const u8,
    source_payload: []const u8,
    source_properties: []const mqtt.Property,
    source_expiry_interval: ?u32,
};

pub const OwnedTransaction = struct {
    phase: Phase,
    source_session_epoch: u64,
    target_session_epoch: u64,
    source_packet_id: u16,
    target_packet_id: u16,
    target_reason_code: u8,
    source_retain: bool,
    source_topic: []u8,
    source_payload: []u8,
    source_properties: []mqtt.Property,
    source_expiry_interval: ?u32,

    fn init(
        allocator: std.mem.Allocator,
        value: Transaction,
    ) Error!OwnedTransaction {
        if (value.source_session_epoch == 0 or
            value.target_session_epoch == 0 or
            value.source_packet_id == 0 or value.target_packet_id == 0)
        {
            return error.CorruptCoordinatorSnapshot;
        }
        try mqtt.validateTopicName(value.source_topic);
        try mqtt.validatePublishProperties(value.source_properties);
        switch (value.phase) {
            .target_await_pubrec, .target_await_pubcomp, .target_complete => if (value.target_reason_code >= 0x80) {
                return error.CorruptCoordinatorSnapshot;
            },
            .target_rejected => if (value.target_reason_code < 0x80) {
                return error.CorruptCoordinatorSnapshot;
            },
        }
        const topic = try allocator.dupe(u8, value.source_topic);
        errdefer allocator.free(topic);
        const payload = try allocator.dupe(u8, value.source_payload);
        errdefer allocator.free(payload);
        const copied = try owned_properties.clone(
            allocator,
            value.source_properties,
            keepStableProperty,
        );
        return .{
            .phase = value.phase,
            .source_session_epoch = value.source_session_epoch,
            .target_session_epoch = value.target_session_epoch,
            .source_packet_id = value.source_packet_id,
            .target_packet_id = value.target_packet_id,
            .target_reason_code = value.target_reason_code,
            .source_retain = value.source_retain,
            .source_topic = topic,
            .source_payload = payload,
            .source_properties = copied.properties,
            .source_expiry_interval = value.source_expiry_interval,
        };
    }

    pub fn deinit(self: *OwnedTransaction, allocator: std.mem.Allocator) void {
        owned_properties.deinit(allocator, self.source_properties);
        allocator.free(self.source_payload);
        allocator.free(self.source_topic);
        self.* = undefined;
    }

    pub fn view(self: *const OwnedTransaction) Transaction {
        return .{
            .phase = self.phase,
            .source_session_epoch = self.source_session_epoch,
            .target_session_epoch = self.target_session_epoch,
            .source_packet_id = self.source_packet_id,
            .target_packet_id = self.target_packet_id,
            .target_reason_code = self.target_reason_code,
            .source_retain = self.source_retain,
            .source_topic = self.source_topic,
            .source_payload = self.source_payload,
            .source_properties = self.source_properties,
            .source_expiry_interval = self.source_expiry_interval,
        };
    }
};

pub const Error = commit_log.Error || reconnect.Error ||
    reconnect.SessionSnapshotError ||
    codec.Error || error{
    CoordinatorIdentityMismatch,
    CorruptCoordinatorSnapshot,
    OwnedPropertyLimitExceeded,
};

pub const Options = struct {
    max_file_bytes: usize = commit_log.default_max_file_bytes,
    max_record_bytes: usize = commit_log.default_max_record_bytes,
};

pub const Store = struct {
    allocator: std.mem.Allocator,
    log: commit_log.Log,
    identity: Identity,
    source_session_epoch: u64,
    target_session_epoch: u64,
    transaction: ?OwnedTransaction = null,

    pub fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: Options,
        identity: Identity,
        source: *reconnect.Client,
        target: *reconnect.Client,
    ) Error!Store {
        try validateState(
            null,
            0,
            0,
            source,
            target,
        );
        const encoded = try encode(
            allocator,
            identity,
            0,
            0,
            null,
            source,
            target,
            std.Io.Clock.awake.now(io),
            std.Io.Clock.real.now(io),
        );
        defer allocator.free(encoded);
        const log = try commit_log.Log.createWithInitial(
            allocator,
            io,
            dir,
            sub_path,
            logOptions(options),
            encoded,
        );
        return .{
            .allocator = allocator,
            .log = log,
            .identity = identity,
            .source_session_epoch = 0,
            .target_session_epoch = 0,
        };
    }

    /// Restore into two newly initialized, offline reconnect Clients. If this
    /// fails the caller must discard both Clients; each individual Session
    /// restore remains transactional.
    pub fn restore(
        allocator: std.mem.Allocator,
        io: std.Io,
        dir: std.Io.Dir,
        sub_path: []const u8,
        options: Options,
        identity: Identity,
        source: *reconnect.Client,
        target: *reconnect.Client,
    ) Error!Store {
        var log = try commit_log.Log.open(
            allocator,
            io,
            dir,
            sub_path,
            logOptions(options),
        );
        errdefer log.deinit();
        const latest = try log.latestAlloc();
        defer allocator.free(latest);
        var decoded = try decode(allocator, latest, identity);
        defer decoded.deinit(allocator);
        const now = std.Io.Clock.awake.now(io);
        const realtime = std.Io.Clock.real.now(io);
        try source.restoreSessionSnapshotAt(
            decoded.source_snapshot,
            now,
            realtime,
        );
        try target.restoreSessionSnapshotAt(
            decoded.target_snapshot,
            now,
            realtime,
        );
        try validateDecoded(&decoded, source, target);
        const transaction = decoded.transaction;
        decoded.transaction = null;
        return .{
            .allocator = allocator,
            .log = log,
            .identity = identity,
            .source_session_epoch = decoded.source_session_epoch,
            .target_session_epoch = decoded.target_session_epoch,
            .transaction = transaction,
        };
    }

    pub fn deinit(self: *Store) void {
        if (self.transaction) |*transaction| {
            transaction.deinit(self.allocator);
        }
        self.log.deinit();
        self.* = undefined;
    }

    pub fn currentTransaction(self: *const Store) ?Transaction {
        return if (self.transaction) |*transaction|
            transaction.view()
        else
            null;
    }

    /// Append and fsync one complete bridge state generation. No allocation
    /// or fallible operation occurs after the journal accepts the record, so
    /// the in-memory transaction always matches the newest durable image.
    pub fn commit(
        self: *Store,
        source: *reconnect.Client,
        target: *reconnect.Client,
        source_session_epoch: u64,
        target_session_epoch: u64,
        transaction: ?Transaction,
    ) Error!u64 {
        var owned = if (transaction) |value|
            try OwnedTransaction.init(self.allocator, value)
        else
            null;
        errdefer if (owned) |*value| value.deinit(self.allocator);
        const canonical_transaction = if (owned) |*value|
            value.view()
        else
            null;
        try validateState(
            canonical_transaction,
            source_session_epoch,
            target_session_epoch,
            source,
            target,
        );
        const encoded = try encode(
            self.allocator,
            self.identity,
            source_session_epoch,
            target_session_epoch,
            canonical_transaction,
            source,
            target,
            std.Io.Clock.awake.now(source.io),
            std.Io.Clock.real.now(source.io),
        );
        defer self.allocator.free(encoded);
        const sequence = try self.log.append(encoded);
        if (self.transaction) |*previous| previous.deinit(self.allocator);
        self.transaction = owned;
        owned = null;
        self.source_session_epoch = source_session_epoch;
        self.target_session_epoch = target_session_epoch;
        return sequence;
    }
};

fn validateDecoded(
    decoded: *const Decoded,
    source: *reconnect.Client,
    target: *reconnect.Client,
) Error!void {
    return validateState(
        if (decoded.transaction) |*transaction| transaction.view() else null,
        decoded.source_session_epoch,
        decoded.target_session_epoch,
        source,
        target,
    );
}

fn validateState(
    maybe_transaction: ?Transaction,
    source_session_epoch: u64,
    target_session_epoch: u64,
    source: *reconnect.Client,
    target: *reconnect.Client,
) Error!void {
    const transaction = maybe_transaction orelse {
        if ((try source.outgoingStats()).incoming_qos2_count != 0 or
            (try target.outgoingStats()).inflight_count != 0)
        {
            return error.CorruptCoordinatorSnapshot;
        }
        return;
    };
    if (transaction.source_session_epoch != source_session_epoch or
        transaction.target_session_epoch != target_session_epoch)
    {
        return error.CorruptCoordinatorSnapshot;
    }
    const target_state = try target.outgoingQoSState(
        transaction.target_packet_id,
    );
    const target_stats = try target.outgoingStats();
    switch (transaction.phase) {
        .target_await_pubrec => if (target_state != .await_pubrec or
            target_stats.inflight_count != 1)
        {
            return error.CorruptCoordinatorSnapshot;
        },
        .target_await_pubcomp => if (target_state != .await_pubcomp or
            target_stats.inflight_count != 1)
        {
            return error.CorruptCoordinatorSnapshot;
        },
        .target_complete => if (target_state != null or
            target_stats.inflight_count != 0 or
            transaction.target_reason_code >= 0x80)
        {
            return error.CorruptCoordinatorSnapshot;
        },
        .target_rejected => if (target_state != null or
            target_stats.inflight_count != 0 or
            transaction.target_reason_code < 0x80)
        {
            return error.CorruptCoordinatorSnapshot;
        },
    }
    const source_state = try source.incomingQoS2State(
        transaction.source_packet_id,
    );
    if (source_state != .await_pubrel and
        source_state != .release_pending)
    {
        return error.CorruptCoordinatorSnapshot;
    }
    if ((try source.outgoingStats()).incoming_qos2_count != 1) {
        return error.CorruptCoordinatorSnapshot;
    }
}

const Decoded = struct {
    source_session_epoch: u64,
    target_session_epoch: u64,
    source_snapshot: []const u8,
    target_snapshot: []const u8,
    transaction: ?OwnedTransaction,

    fn deinit(self: *Decoded, allocator: std.mem.Allocator) void {
        if (self.transaction) |*transaction| transaction.deinit(allocator);
        self.* = undefined;
    }
};

fn encode(
    allocator: std.mem.Allocator,
    identity: Identity,
    source_session_epoch: u64,
    target_session_epoch: u64,
    transaction: ?Transaction,
    source: *reconnect.Client,
    target: *reconnect.Client,
    monotonic_now: std.Io.Timestamp,
    realtime_now: std.Io.Timestamp,
) Error![]u8 {
    var source_snapshot: std.ArrayList(u8) = .empty;
    defer source_snapshot.deinit(allocator);
    try source.writeSessionSnapshotAt(
        &source_snapshot,
        monotonic_now,
        realtime_now,
    );
    var target_snapshot: std.ArrayList(u8) = .empty;
    defer target_snapshot.deinit(allocator);
    try target.writeSessionSnapshotAt(
        &target_snapshot,
        monotonic_now,
        realtime_now,
    );

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, magic);
    try codec.appendInt(&out, allocator, u32, version);
    try out.appendSlice(allocator, &identity);
    try codec.appendInt(&out, allocator, u64, source_session_epoch);
    try codec.appendInt(&out, allocator, u64, target_session_epoch);
    try codec.appendBlob(&out, allocator, source_snapshot.items);
    try codec.appendBlob(&out, allocator, target_snapshot.items);
    try codec.appendBool(&out, allocator, transaction != null);
    if (transaction) |value| {
        try codec.appendInt(&out, allocator, u8, @intFromEnum(value.phase));
        try codec.appendInt(
            &out,
            allocator,
            u64,
            value.source_session_epoch,
        );
        try codec.appendInt(
            &out,
            allocator,
            u64,
            value.target_session_epoch,
        );
        try codec.appendInt(&out, allocator, u16, value.source_packet_id);
        try codec.appendInt(&out, allocator, u16, value.target_packet_id);
        try codec.appendInt(&out, allocator, u8, value.target_reason_code);
        try codec.appendBool(&out, allocator, value.source_retain);
        try codec.appendBlob(&out, allocator, value.source_topic);
        try codec.appendBlob(&out, allocator, value.source_payload);
        try codec.appendProperties(
            &out,
            allocator,
            value.source_properties,
        );
        try codec.appendOptionalInt(
            &out,
            allocator,
            u32,
            value.source_expiry_interval,
        );
    }
    try codec.appendInt(
        &out,
        allocator,
        u32,
        std.hash.crc.Crc32.hash(out.items),
    );
    return out.toOwnedSlice(allocator);
}

fn decode(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected_identity: Identity,
) Error!Decoded {
    const minimum_len = magic.len + @sizeOf(u32) + @sizeOf(Identity) +
        2 * @sizeOf(u64) + 2 * @sizeOf(u32) + @sizeOf(u8) + @sizeOf(u32);
    if (bytes.len < minimum_len) return error.CorruptCoordinatorSnapshot;
    const payload = bytes[0 .. bytes.len - @sizeOf(u32)];
    const expected_crc = std.mem.readInt(
        u32,
        bytes[bytes.len - @sizeOf(u32) ..][0..@sizeOf(u32)],
        .big,
    );
    if (std.hash.crc.Crc32.hash(payload) != expected_crc) {
        return error.CorruptCoordinatorSnapshot;
    }
    var cursor = codec.Cursor.init(payload);
    const found_magic = cursor.inner.readSlice(magic.len) catch
        return error.CorruptCoordinatorSnapshot;
    if (!std.mem.eql(u8, found_magic, magic)) {
        return error.CorruptCoordinatorSnapshot;
    }
    if (try cursor.readInt(u32) != version) {
        return error.UnsupportedSnapshotVersion;
    }
    const found_identity = cursor.inner.readSlice(@sizeOf(Identity)) catch
        return error.CorruptCoordinatorSnapshot;
    if (!std.mem.eql(u8, found_identity, &expected_identity)) {
        return error.CoordinatorIdentityMismatch;
    }
    const source_session_epoch = try cursor.readInt(u64);
    const target_session_epoch = try cursor.readInt(u64);
    const source_snapshot = try cursor.readBlob();
    const target_snapshot = try cursor.readBlob();
    var transaction: ?OwnedTransaction = null;
    errdefer if (transaction) |*value| value.deinit(allocator);
    if (try cursor.readBool()) {
        const phase = std.enums.fromInt(
            Phase,
            try cursor.readInt(u8),
        ) orelse return error.CorruptCoordinatorSnapshot;
        const transaction_epoch = try cursor.readInt(u64);
        const transaction_target_epoch = try cursor.readInt(u64);
        const source_packet_id = try cursor.readInt(u16);
        const target_packet_id = try cursor.readInt(u16);
        const target_reason_code = try cursor.readInt(u8);
        const source_retain = try cursor.readBool();
        const source_topic = try cursor.readBlob();
        const source_payload = try cursor.readBlob();
        const source_properties = try cursor.readProperties(allocator);
        // The property array is allocated, but all string/binary fields still
        // borrow the encoded snapshot. OwnedTransaction.init deep-copies them.
        defer allocator.free(source_properties);
        const source_expiry_interval = try cursor.readOptionalInt(u32);
        transaction = try OwnedTransaction.init(allocator, .{
            .phase = phase,
            .source_session_epoch = transaction_epoch,
            .target_session_epoch = transaction_target_epoch,
            .source_packet_id = source_packet_id,
            .target_packet_id = target_packet_id,
            .target_reason_code = target_reason_code,
            .source_retain = source_retain,
            .source_topic = source_topic,
            .source_payload = source_payload,
            .source_properties = source_properties,
            .source_expiry_interval = source_expiry_interval,
        });
    }
    try cursor.finish();
    return .{
        .source_session_epoch = source_session_epoch,
        .target_session_epoch = target_session_epoch,
        .source_snapshot = source_snapshot,
        .target_snapshot = target_snapshot,
        .transaction = transaction,
    };
}

fn logOptions(options: Options) commit_log.Options {
    return .{
        .max_file_bytes = options.max_file_bytes,
        .max_record_bytes = options.max_record_bytes,
    };
}

fn keepStableProperty(property: mqtt.Property) bool {
    return !((property == .two_byte and
        property.two_byte.id == .topic_alias) or
        (property == .varint and
            property.varint.id == .subscription_identifier) or
        (property == .four_byte and
            property.four_byte.id == .message_expiry_interval));
}

test "outbound coordinator envelope binds identity and transaction" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    const unused = std.Io.net.IpAddress{ .ip4 = .loopback(1) };
    var source = try reconnect.Client.init(
        allocator,
        io,
        unused,
        .{
            .protocol = .v5,
            .client_id = "coordinator-source",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer source.deinit();
    var target = try reconnect.Client.init(
        allocator,
        io,
        unused,
        .{
            .protocol = .v5,
            .client_id = "coordinator-target",
            .clean_start = false,
            .properties = &properties,
        },
        .{},
        &shutdown,
    );
    defer target.deinit();
    const identity = [_]u8{0x42} ** @sizeOf(Identity);
    const transaction = Transaction{
        .phase = .target_await_pubrec,
        .source_session_epoch = 7,
        .target_session_epoch = 13,
        .source_packet_id = 11,
        .target_packet_id = 19,
        .source_retain = true,
        .source_topic = "source/topic",
        .source_payload = "payload",
        .source_properties = &.{.{ .utf8_pair = .{
            .id = .user_property,
            .key = "coordinator",
            .value = "durable",
        } }},
        .source_expiry_interval = 30,
    };
    const encoded = try encode(
        allocator,
        identity,
        7,
        13,
        transaction,
        &source,
        &target,
        .zero,
        .zero,
    );
    defer allocator.free(encoded);
    var decoded = try decode(allocator, encoded, identity);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 7), decoded.source_session_epoch);
    try std.testing.expectEqual(@as(u64, 13), decoded.target_session_epoch);
    const restored = decoded.transaction.?.view();
    try std.testing.expectEqual(Phase.target_await_pubrec, restored.phase);
    try std.testing.expectEqual(@as(u16, 11), restored.source_packet_id);
    try std.testing.expectEqual(@as(u16, 19), restored.target_packet_id);
    try std.testing.expectEqualStrings("source/topic", restored.source_topic);
    try std.testing.expectEqualStrings("payload", restored.source_payload);
    var wrong_identity = identity;
    wrong_identity[0] ^= 1;
    try std.testing.expectError(
        error.CoordinatorIdentityMismatch,
        decode(allocator, encoded, wrong_identity),
    );
    const corrupt = try allocator.dupe(u8, encoded);
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    try std.testing.expectError(
        error.CorruptCoordinatorSnapshot,
        decode(allocator, corrupt, identity),
    );
}

test "outbound coordinator journal restores both client snapshots" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var shutdown: std.Io.Event = .unset;
    const properties = [_]mqtt.Property{.{ .four_byte = .{
        .id = .session_expiry_interval,
        .value = 60,
    } }};
    const unused = std.Io.net.IpAddress{ .ip4 = .loopback(1) };
    const source_options = runtime.ConnectOptions{
        .protocol = .v5,
        .client_id = "coordinator-journal-source",
        .clean_start = false,
        .properties = &properties,
    };
    const target_options = runtime.ConnectOptions{
        .protocol = .v5,
        .client_id = "coordinator-journal-target",
        .clean_start = false,
        .properties = &properties,
    };
    var source = try reconnect.Client.init(
        allocator,
        io,
        unused,
        source_options,
        .{},
        &shutdown,
    );
    defer source.deinit();
    var target = try reconnect.Client.init(
        allocator,
        io,
        unused,
        target_options,
        .{},
        &shutdown,
    );
    defer target.deinit();
    const identity = [_]u8{0x24} ** @sizeOf(Identity);
    var store = try Store.create(
        allocator,
        io,
        tmp.dir,
        "outbound.log",
        .{},
        identity,
        &source,
        &target,
    );
    _ = try store.commit(&source, &target, 9, 15, null);
    store.deinit();

    var restored_source = try reconnect.Client.init(
        allocator,
        io,
        unused,
        source_options,
        .{},
        &shutdown,
    );
    defer restored_source.deinit();
    var restored_target = try reconnect.Client.init(
        allocator,
        io,
        unused,
        target_options,
        .{},
        &shutdown,
    );
    defer restored_target.deinit();
    var reopened = try Store.restore(
        allocator,
        io,
        tmp.dir,
        "outbound.log",
        .{},
        identity,
        &restored_source,
        &restored_target,
    );
    defer reopened.deinit();
    try std.testing.expectEqual(@as(u64, 9), reopened.source_session_epoch);
    try std.testing.expectEqual(@as(u64, 15), reopened.target_session_epoch);
    try std.testing.expect(reopened.currentTransaction() == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        (try restored_source.outgoingStats()).inflight_count,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        (try restored_target.outgoingStats()).inflight_count,
    );
}

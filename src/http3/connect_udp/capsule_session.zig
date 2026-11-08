//! RFC 9298 Context ID 0 data plane carried by RFC 9297 DATAGRAM capsules.
//!
//! HTTP/1.1 and HTTP/2 lack QUIC DATAGRAM framing, so capsule bytes form one
//! continuous stream. This adapter retains split capsule prefixes/values,
//! skips unknown capsules and Context IDs, and resumes partially committed
//! writes without duplicating a byte prefix.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");
const quic = @import("../../quic/mod.zig");

pub const Options = struct {
    max_incomplete_capsule_bytes: usize = 65_560,
    max_payload_size: usize = 65_575,
    max_capsule_value_bytes: usize = 256 * 1024,
};

pub fn Session(
    comptime ResetCode: type,
    comptime Capsule: type,
    comptime ContextProtocol: type,
    comptime Tunnel: type,
    comptime WriteProgress: type,
) type {
    return struct {
        const ConfigurationState = if (@hasDecl(
            ContextProtocol,
            "ConfigurationState",
        )) ContextProtocol.ConfigurationState else struct {};

        allocator: std.mem.Allocator,
        io: std.Io,
        tunnel: Tunnel,
        options: Options,
        receive_buffer: std.ArrayList(u8) = .empty,
        receive_offset: usize = 0,
        /// Cached capsule header for the incomplete capsule at
        /// `pending_header.offset`. Fragment boundaries are arbitrary, so a
        /// large datagram can otherwise be re-parsed dozens of times before
        /// its value bytes finish arriving.
        pending_header: ?PendingHeader = null,
        peer_finished: bool = false,
        pending_send: ?PendingSend = null,
        configuration: ?*ConfigurationState = null,

        const Self = @This();
        pub const supports_blocking_relay = true;

        const PendingHeader = struct {
            offset: usize,
            header_len: usize,
            value_len: usize,

            fn totalLen(self: PendingHeader) usize {
                return self.header_len + self.value_len;
            }
        };

        const PendingSend = struct {
            header: [24]u8 = undefined,
            header_len: usize,
            capsule_type: u64,
            payload: []const u8,
            committed: usize = 0,

            fn totalLen(self: *const PendingSend) usize {
                return self.header_len + self.payload.len;
            }

            fn matches(
                self: *const PendingSend,
                capsule_type: u64,
                payload: []const u8,
            ) bool {
                return self.capsule_type == capsule_type and
                    self.payload.len == payload.len and
                    (payload.len == 0 or self.payload.ptr == payload.ptr);
            }

            fn remainingSlices(
                self: *const PendingSend,
                storage: *[2][]const u8,
            ) []const []const u8 {
                if (self.committed < self.header_len) {
                    storage[0] = self.header[self.committed..self.header_len];
                    storage[1] = self.payload;
                    return storage;
                }
                storage[0] = self.payload[self.committed - self.header_len ..];
                return storage[0..1];
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            tunnel: Tunnel,
            options: Options,
        ) Self {
            return .{
                .allocator = allocator,
                .io = io,
                .tunnel = tunnel,
                .options = options,
            };
        }

        pub fn deinit(self: *Self) void {
            self.discardPreparedConfiguration();
            self.receive_buffer.deinit(self.allocator);
            if (@hasDecl(Tunnel, "deinit")) self.tunnel.deinit();
            self.* = undefined;
        }

        pub fn streamId(self: *const Self) u31 {
            return self.tunnel.stream_id;
        }

        pub fn bindConfigurationState(
            self: *Self,
            state: *ConfigurationState,
        ) !void {
            if (!@hasDecl(ContextProtocol, "ConfigurationState")) {
                return error.InvalidCapsule;
            }
            if (self.pending_send != null or self.configuration != null) {
                return error.WriteInProgress;
            }
            self.configuration = state;
        }

        pub fn maxPayloadSize(self: *const Self) ?usize {
            return @min(
                ContextProtocol.max_context_payload_size,
                self.options.max_payload_size,
            );
        }

        pub fn writeInProgress(self: *const Self) bool {
            return self.pending_send != null;
        }

        pub fn committedBytes(self: *const Self) usize {
            return if (self.pending_send) |pending| pending.committed else 0;
        }

        pub fn send(self: *Self, payload: []const u8) !void {
            try self.preparePacketSend(payload);
            return self.finishPreparedSend();
        }

        /// Send one non-DATAGRAM Capsule value. On timeout, the borrowed value
        /// must remain stable and the same type/value pair must be retried.
        pub fn sendCapsule(
            self: *Self,
            encoded: []const u8,
        ) !void {
            const parsed = try self.validateEncodedCapsule(encoded);
            return self.sendCapsuleValue(
                parsed.capsule.capsule_type,
                parsed.capsule.value,
            );
        }

        pub fn sendCapsuleValue(
            self: *Self,
            capsule_type: u64,
            value: []const u8,
        ) !void {
            if (capsule_type == Capsule.CapsuleType.datagram) {
                return error.InvalidFrame;
            }
            try self.prepareCapsuleSend(capsule_type, value, false);
            return self.finishPreparedSend();
        }

        fn finishPreparedSend(self: *Self) !void {
            var slices_storage: [2][]const u8 = undefined;
            const slices = self.pending_send.?.remainingSlices(
                &slices_storage,
            );
            self.tunnel.writeSlices(slices, false) catch |err| {
                self.discardPreparedConfiguration();
                self.pending_send = null;
                return err;
            };
            self.commitPreparedConfiguration();
            self.pending_send = null;
        }

        pub fn sendWithTimeout(
            self: *Self,
            payload: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendWithDeadline(payload, .fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn sendWithDeadline(
            self: *Self,
            payload: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            try self.preparePacketSend(payload);
            return self.finishPreparedSendWithDeadline(deadline);
        }

        pub fn sendCapsuleWithTimeout(
            self: *Self,
            encoded: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendCapsuleWithDeadline(
                encoded,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendCapsuleWithDeadline(
            self: *Self,
            encoded: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            const parsed = try self.validateEncodedCapsule(encoded);
            return self.sendCapsuleValueWithDeadline(
                parsed.capsule.capsule_type,
                parsed.capsule.value,
                deadline,
            );
        }

        pub fn sendCapsuleValueWithTimeout(
            self: *Self,
            capsule_type: u64,
            value: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendCapsuleValueWithDeadline(
                capsule_type,
                value,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn sendCapsuleValueWithDeadline(
            self: *Self,
            capsule_type: u64,
            value: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            if (capsule_type == Capsule.CapsuleType.datagram) {
                return error.InvalidFrame;
            }
            try self.prepareCapsuleSend(capsule_type, value, false);
            return self.finishPreparedSendWithDeadline(deadline);
        }

        fn validateEncodedCapsule(
            self: *Self,
            encoded: []const u8,
        ) !Capsule.Parsed {
            const parsed = try Capsule.parse(encoded);
            if (parsed.consumed != encoded.len or
                parsed.capsule.capsule_type == Capsule.CapsuleType.datagram or
                parsed.capsule.value.len > self.options.max_capsule_value_bytes)
            {
                return error.InvalidFrame;
            }
            if (@hasDecl(
                ContextProtocol,
                "validateConfigurationCapsule",
            )) {
                if (!try ContextProtocol.validateConfigurationCapsule(
                    parsed.capsule.capsule_type,
                    parsed.capsule.value,
                )) return error.InvalidFrame;
            }
            return parsed;
        }

        fn finishPreparedSendWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            var slices_storage: [2][]const u8 = undefined;
            const slices = self.pending_send.?.remainingSlices(
                &slices_storage,
            );
            var progress: WriteProgress = .{};
            self.tunnel.writeSlicesWithDeadline(
                slices,
                false,
                &progress,
                deadline,
            ) catch |err| {
                self.pending_send.?.committed += progress.committed_bytes;
                if (err != error.Timeout) {
                    self.discardPreparedConfiguration();
                    self.pending_send = null;
                }
                return err;
            };
            self.pending_send.?.committed += progress.committed_bytes;
            std.debug.assert(
                self.pending_send.?.committed ==
                    self.pending_send.?.totalLen(),
            );
            self.commitPreparedConfiguration();
            self.pending_send = null;
        }

        pub fn closeWrite(self: *Self) !void {
            if (self.pending_send != null) return error.WriteInProgress;
            try self.tunnel.closeWrite();
        }

        pub fn receive(self: *Self) !ContextProtocol.OwnedContextPayload {
            return self.receiveUntil(null);
        }

        pub fn receiveWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !ContextProtocol.OwnedContextPayload {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveWithDeadline(.fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn receiveWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !ContextProtocol.OwnedContextPayload {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveUntil(deadline);
        }

        pub const OwnedCapsule = struct {
            stream_id: u62,
            capsule_type: u64,
            storage: []u8,
            value: []const u8,

            pub fn deinit(
                self: *OwnedCapsule,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.storage);
                self.* = undefined;
            }
        };

        pub const OwnedEvent = union(enum) {
            payload: ContextProtocol.OwnedContextPayload,
            capsule: OwnedCapsule,

            pub fn deinit(
                self: *OwnedEvent,
                allocator: std.mem.Allocator,
            ) void {
                switch (self.*) {
                    .payload => |*payload| payload.deinit(allocator),
                    .capsule => |*value| value.deinit(allocator),
                }
                self.* = undefined;
            }
        };

        /// Receive the next Capsule without skipping CONNECT-IP configuration
        /// types. The returned value is owned independently of stream scratch.
        pub fn receiveCapsule(self: *Self) !OwnedCapsule {
            return self.receiveCapsuleUntil(null);
        }

        pub fn receiveCapsuleWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !OwnedCapsule {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveCapsuleWithDeadline(.fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn receiveCapsuleWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !OwnedCapsule {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveCapsuleUntil(deadline);
        }

        /// Receive either a Context ID 0 payload or a recognized protocol
        /// configuration Capsule without consuming the other event class.
        pub fn receiveEvent(self: *Self) !OwnedEvent {
            return self.receiveEventUntil(null);
        }

        pub fn receiveEventWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !OwnedEvent {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveEventWithDeadline(.fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn receiveEventWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !OwnedEvent {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveEventUntil(deadline);
        }

        /// Receive one Context ID 0 UDP payload into caller storage. A short
        /// output returns BufferTooShort without consuming the parsed capsule,
        /// so the caller can retry with a larger buffer.
        pub fn receiveInto(
            self: *Self,
            out: []u8,
        ) !ContextProtocol.ReceivedContextPayload {
            return self.receiveIntoUntil(out, null);
        }

        /// Relative-timeout caller-buffer receive. Incomplete Capsule bytes
        /// and a complete payload rejected for short output remain resumable.
        pub fn receiveIntoWithTimeout(
            self: *Self,
            out: []u8,
            timeout: std.Io.Duration,
        ) !ContextProtocol.ReceivedContextPayload {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveIntoWithDeadline(out, .fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        /// Absolute awake-clock counterpart to `receiveIntoWithTimeout`.
        pub fn receiveIntoWithDeadline(
            self: *Self,
            out: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) !ContextProtocol.ReceivedContextPayload {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            return self.receiveIntoUntil(out, deadline);
        }

        fn preparePacketSend(self: *Self, payload: []const u8) !void {
            if (payload.len > @min(
                ContextProtocol.max_context_payload_size,
                self.options.max_payload_size,
            )) {
                return error.PayloadTooLarge;
            }
            return self.prepareCapsuleSend(
                Capsule.CapsuleType.datagram,
                payload,
                true,
            );
        }

        fn prepareCapsuleSend(
            self: *Self,
            capsule_type_value: u64,
            payload: []const u8,
            include_context: bool,
        ) !void {
            if (self.pending_send) |*pending| {
                if (!pending.matches(capsule_type_value, payload)) {
                    return error.WriteInProgress;
                }
                return;
            }
            if (!include_context and
                payload.len > self.options.max_capsule_value_bytes)
            {
                return error.ExcessiveLoad;
            }
            if (!include_context and @hasDecl(
                ContextProtocol,
                "validateConfigurationCapsule",
            )) {
                if (!try ContextProtocol.validateConfigurationCapsule(
                    capsule_type_value,
                    payload,
                )) return error.InvalidFrame;
            }
            if (!include_context) {
                try self.prepareLocalConfiguration(
                    capsule_type_value,
                    payload,
                );
            }
            var pending = PendingSend{
                .header_len = 0,
                .capsule_type = capsule_type_value,
                .payload = payload,
            };
            var offset: usize = 0;
            const capsule_type = try quic.varint.encodeInto(
                pending.header[offset..],
                capsule_type_value,
            );
            offset += capsule_type.len;
            const value_len = std.math.add(
                usize,
                payload.len,
                @intFromBool(include_context),
            ) catch return error.IntegerOverflow;
            const length = try quic.varint.encodeInto(
                pending.header[offset..],
                @intCast(value_len),
            );
            offset += length.len;
            if (include_context) {
                pending.header[offset] = 0;
                offset += 1;
            }
            pending.header_len = offset;
            self.pending_send = pending;
        }

        fn receiveUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !ContextProtocol.OwnedContextPayload {
            const buffered = try self.nextDatagramUntil(deadline);
            const owned = try self.allocator.dupe(u8, buffered.payload);
            self.receive_offset += buffered.consumed;
            return .{
                .stream_id = @intCast(self.tunnel.stream_id),
                .storage = owned,
                .payload = owned,
            };
        }

        fn receiveCapsuleUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !OwnedCapsule {
            while (true) {
                const buffered = try self.nextCapsuleUntil(deadline);
                const recognized = self.validatePeerConfiguration(
                    buffered.capsule_type,
                    buffered.value,
                ) catch |err| return self.abortMalformed(err);
                if (@hasDecl(
                    ContextProtocol,
                    "validateConfigurationCapsule",
                ) and !recognized) {
                    self.receive_offset += buffered.consumed;
                    continue;
                }
                const owned = try self.allocator.dupe(u8, buffered.value);
                errdefer self.allocator.free(owned);
                try self.commitPeerConfiguration(
                    buffered.capsule_type,
                    buffered.value,
                );
                self.receive_offset += buffered.consumed;
                return .{
                    .stream_id = @intCast(self.tunnel.stream_id),
                    .capsule_type = buffered.capsule_type,
                    .storage = owned,
                    .value = owned,
                };
            }
        }

        fn receiveEventUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !OwnedEvent {
            while (true) {
                const buffered = try self.nextCapsuleUntil(deadline);
                if (buffered.capsule_type == Capsule.CapsuleType.datagram) {
                    const datagram = ContextProtocol.ContextDatagram.parse(
                        buffered.value,
                    ) catch |err| return self.abortMalformed(err);
                    if (datagram.context_id !=
                        ContextProtocol.payload_context_id)
                    {
                        self.receive_offset += buffered.consumed;
                        continue;
                    }
                    const owned = try self.allocator.dupe(
                        u8,
                        datagram.payload,
                    );
                    self.receive_offset += buffered.consumed;
                    return .{ .payload = .{
                        .stream_id = @intCast(self.tunnel.stream_id),
                        .storage = owned,
                        .payload = owned,
                    } };
                }
                if (@hasDecl(
                    ContextProtocol,
                    "validateConfigurationCapsule",
                )) {
                    const recognized = ContextProtocol
                        .validateConfigurationCapsule(
                        buffered.capsule_type,
                        buffered.value,
                    ) catch |err| return self.abortMalformed(err);
                    if (!recognized) {
                        self.receive_offset += buffered.consumed;
                        continue;
                    }
                    const owned = try self.allocator.dupe(
                        u8,
                        buffered.value,
                    );
                    errdefer self.allocator.free(owned);
                    try self.commitPeerConfiguration(
                        buffered.capsule_type,
                        buffered.value,
                    );
                    self.receive_offset += buffered.consumed;
                    return .{ .capsule = .{
                        .stream_id = @intCast(self.tunnel.stream_id),
                        .capsule_type = buffered.capsule_type,
                        .storage = owned,
                        .value = owned,
                    } };
                }
                self.receive_offset += buffered.consumed;
            }
        }

        fn receiveIntoUntil(
            self: *Self,
            out: []u8,
            deadline: ?std.Io.Clock.Timestamp,
        ) !ContextProtocol.ReceivedContextPayload {
            const buffered = try self.nextDatagramUntil(deadline);
            if (out.len < buffered.payload.len) return error.BufferTooShort;
            @memcpy(out[0..buffered.payload.len], buffered.payload);
            self.receive_offset += buffered.consumed;
            return .{
                .stream_id = @intCast(self.tunnel.stream_id),
                .payload = out[0..buffered.payload.len],
            };
        }

        fn nextDatagramUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !BufferedUdpPayload {
            while (true) {
                if (try self.pollBuffered()) |payload| return payload;
                if (self.bufferedLen() >
                    self.options.max_incomplete_capsule_bytes)
                {
                    return self.abortExcessiveLoad();
                }
                if (self.peer_finished) {
                    if (self.bufferedLen() != 0) {
                        return self.abortMalformed(error.BufferTooShort);
                    }
                    return error.ConnectionClosed;
                }
                self.compactReceiveBuffer();
                var data = if (deadline) |absolute|
                    try self.tunnel.readWithDeadline(absolute)
                else
                    try self.tunnel.read();
                defer data.deinit(self.allocator);
                try self.receive_buffer.appendSlice(
                    self.allocator,
                    data.data,
                );
                self.peer_finished = data.end_stream;
                if (self.bufferedLen() >
                    self.options.max_incomplete_capsule_bytes)
                {
                    // Complete capsules are drained before another read. A
                    // suffix beyond this bound is therefore one incomplete
                    // capsule, not a batch of ready application messages.
                    if (try self.pollBuffered()) |payload| return payload;
                    if (self.bufferedLen() >
                        self.options.max_incomplete_capsule_bytes)
                    {
                        return self.abortExcessiveLoad();
                    }
                }
            }
        }

        const BufferedUdpPayload = struct {
            payload: []const u8,
            consumed: usize,
        };

        const BufferedCapsule = struct {
            capsule_type: u64,
            value: []const u8,
            consumed: usize,
        };

        fn nextCapsuleUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !BufferedCapsule {
            while (true) {
                if (try self.pollBufferedCapsule()) |value| return value;
                if (self.bufferedLen() >
                    self.options.max_incomplete_capsule_bytes)
                {
                    return self.abortExcessiveLoad();
                }
                if (self.peer_finished) {
                    if (self.bufferedLen() != 0) {
                        return self.abortMalformed(error.BufferTooShort);
                    }
                    return error.ConnectionClosed;
                }
                self.compactReceiveBuffer();
                var data = if (deadline) |absolute|
                    try self.tunnel.readWithDeadline(absolute)
                else
                    try self.tunnel.read();
                defer data.deinit(self.allocator);
                try self.receive_buffer.appendSlice(self.allocator, data.data);
                self.peer_finished = data.end_stream;
                if (self.bufferedLen() >
                    self.options.max_incomplete_capsule_bytes)
                {
                    if (try self.pollBufferedCapsule()) |value| return value;
                    if (self.bufferedLen() >
                        self.options.max_incomplete_capsule_bytes)
                    {
                        return self.abortExcessiveLoad();
                    }
                }
            }
        }

        fn pollBuffered(self: *Self) !?BufferedUdpPayload {
            while (self.receive_offset < self.receive_buffer.items.len) {
                const remaining = self.receive_buffer.items[self.receive_offset..];
                if (self.pending_header) |pending| {
                    if (pending.offset == self.receive_offset and
                        remaining.len < pending.totalLen())
                    {
                        return null;
                    }
                    self.pending_header = null;
                }
                const parsed = Capsule.parse(remaining) catch |err| switch (err) {
                    error.BufferTooShort => {
                        self.cacheIncompleteHeader(remaining);
                        return null;
                    },
                    else => |other| return self.abortMalformed(other),
                };
                if (parsed.capsule.capsule_type !=
                    Capsule.CapsuleType.datagram)
                {
                    const recognized = self.validatePeerConfiguration(
                        parsed.capsule.capsule_type,
                        parsed.capsule.value,
                    ) catch |err| return self.abortMalformed(err);
                    if (recognized) {
                        try self.commitPeerConfiguration(
                            parsed.capsule.capsule_type,
                            parsed.capsule.value,
                        );
                    }
                    self.receive_offset += parsed.consumed;
                    continue;
                }
                const datagram = ContextProtocol.ContextDatagram.parse(
                    parsed.capsule.value,
                ) catch |err| return self.abortMalformed(err);
                if (datagram.context_id != ContextProtocol.payload_context_id) {
                    self.receive_offset += parsed.consumed;
                    continue;
                }
                return .{
                    .payload = datagram.payload,
                    .consumed = parsed.consumed,
                };
            }
            self.receive_buffer.clearRetainingCapacity();
            self.receive_offset = 0;
            return null;
        }

        fn pollBufferedCapsule(self: *Self) !?BufferedCapsule {
            if (self.receive_offset >= self.receive_buffer.items.len) {
                self.receive_buffer.clearRetainingCapacity();
                self.receive_offset = 0;
                return null;
            }
            const remaining = self.receive_buffer.items[self.receive_offset..];
            if (self.pending_header) |pending| {
                if (pending.offset == self.receive_offset and
                    remaining.len < pending.totalLen())
                {
                    return null;
                }
                self.pending_header = null;
            }
            const parsed = Capsule.parse(remaining) catch |err| switch (err) {
                error.BufferTooShort => {
                    self.cacheIncompleteHeader(remaining);
                    return null;
                },
                else => |other| return self.abortMalformed(other),
            };
            if (parsed.capsule.value.len >
                self.options.max_capsule_value_bytes)
            {
                return self.abortExcessiveLoad();
            }
            return .{
                .capsule_type = parsed.capsule.capsule_type,
                .value = parsed.capsule.value,
                .consumed = parsed.consumed,
            };
        }

        fn cacheIncompleteHeader(self: *Self, remaining: []const u8) void {
            const header = Capsule.parseHeader(remaining) catch return;
            self.pending_header = .{
                .offset = self.receive_offset,
                .header_len = header.header_len,
                .value_len = header.value_len,
            };
        }

        fn bufferedLen(self: *const Self) usize {
            return self.receive_buffer.items.len - self.receive_offset;
        }

        fn compactReceiveBuffer(self: *Self) void {
            if (self.receive_offset == 0) return;
            const remaining = self.bufferedLen();
            if (remaining != 0) {
                @memmove(
                    self.receive_buffer.items[0..remaining],
                    self.receive_buffer.items[self.receive_offset..],
                );
            }
            self.receive_buffer.items.len = remaining;
            self.receive_offset = 0;
        }

        fn abortMalformed(self: *Self, err: anyerror) anyerror {
            self.tunnel.reset(ResetCode.protocol_error) catch |reset_err| {
                return reset_err;
            };
            return err;
        }

        fn abortExcessiveLoad(self: *Self) anyerror {
            self.tunnel.reset(ResetCode.enhance_your_calm) catch |err| {
                return err;
            };
            return error.ExcessiveLoad;
        }

        fn prepareLocalConfiguration(
            self: *Self,
            capsule_type: u64,
            value: []const u8,
        ) !void {
            if (@hasDecl(ContextProtocol, "ConfigurationState")) {
                if (self.configuration) |state| {
                    try state.prepareLocalCapsule(capsule_type, value);
                }
            }
        }

        fn commitPreparedConfiguration(self: *Self) void {
            if (@hasDecl(ContextProtocol, "ConfigurationState")) {
                if (self.configuration) |state| {
                    state.commitPreparedLocalCapsule();
                }
            }
        }

        fn discardPreparedConfiguration(self: *Self) void {
            if (@hasDecl(ContextProtocol, "ConfigurationState")) {
                if (self.configuration) |state| {
                    state.discardPreparedLocalCapsule();
                }
            }
        }

        fn validatePeerConfiguration(
            self: *Self,
            capsule_type: u64,
            value: []const u8,
        ) !bool {
            _ = self;
            if (@hasDecl(
                ContextProtocol,
                "validateConfigurationCapsule",
            )) {
                return try ContextProtocol
                    .validateConfigurationCapsule(capsule_type, value);
            }
            return true;
        }

        fn commitPeerConfiguration(
            self: *Self,
            capsule_type: u64,
            value: []const u8,
        ) !void {
            if (@hasDecl(ContextProtocol, "ConfigurationState")) {
                if (self.configuration) |state| {
                    _ = state.applyPeerCapsule(
                        capsule_type,
                        value,
                    ) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        error.ExcessiveLoad => return self.abortExcessiveLoad(),
                        else => return self.abortMalformed(err),
                    };
                }
            }
        }
    };
}

//! RFC 9484 HTTP/3 Session combining reliable configuration Capsules with
//! Context ID 0 QUIC DATAGRAM IP packets under one connection reader.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

pub const Role = enum { client, server };

pub fn Session(
    comptime Http3: type,
    comptime ConnectIp: type,
    comptime Parent: type,
    comptime BodyWriteProgress: type,
    comptime role: Role,
) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        parent: *Parent,
        stream_id: u62,
        datagrams: ConnectIp.Session(Parent),
        receive_buffer: std.ArrayList(u8) = .empty,
        receive_offset: usize = 0,
        peer_finished: bool = false,
        read_scratch: std.ArrayList(u8) = .empty,
        pending_send: ?PendingSend = null,

        const Self = @This();
        pub const supports_blocking_relay = false;
        pub const read_chunk_bytes: usize = 16 * 1024;
        pub const max_configuration_capsule_bytes: usize = 256 * 1024;

        const PendingSend = struct {
            ptr: [*]const u8,
            len: usize,
            committed: usize = 0,

            fn matches(self: PendingSend, encoded: []const u8) bool {
                return self.len == encoded.len and
                    (encoded.len == 0 or self.ptr == encoded.ptr);
            }
        };

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

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            parent: *Parent,
            stream_id: u62,
        ) Self {
            return .{
                .allocator = allocator,
                .io = io,
                .parent = parent,
                .stream_id = stream_id,
                .datagrams = ConnectIp.Session(Parent).init(
                    allocator,
                    io,
                    parent,
                    stream_id,
                ),
            };
        }

        pub fn deinit(self: *Self) void {
            self.datagrams.deinit();
            self.receive_buffer.deinit(self.allocator);
            self.read_scratch.deinit(self.allocator);
            self.* = undefined;
        }

        pub fn streamId(self: *const Self) u62 {
            return self.stream_id;
        }

        pub fn writeInProgress(self: *const Self) bool {
            return self.pending_send != null;
        }

        /// EndpointServer delivers request/response FIN as an outer event.
        /// Dispatcher owners feed that terminal observation back into the
        /// typed Session so later polls report stable association closure.
        pub fn observePeerFinished(self: *Self) void {
            self.peer_finished = true;
        }

        pub fn maxPayloadSize(self: *const Self) ?usize {
            return self.datagrams.maxPayloadSize();
        }

        pub fn maxReceivePayloadSize(self: *const Self) ?usize {
            return self.datagrams.maxReceivePayloadSize();
        }

        pub fn send(self: *Self, packet: []const u8) !void {
            return self.datagrams.send(packet);
        }

        pub fn trySend(self: *Self, packet: []const u8) !void {
            return self.datagrams.trySend(packet);
        }

        pub fn sendWithTimeout(
            self: *Self,
            packet: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            return self.datagrams.sendWithTimeout(packet, timeout);
        }

        pub fn sendWithDeadline(
            self: *Self,
            packet: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            return self.datagrams.sendWithDeadline(packet, deadline);
        }

        pub fn receive(self: *Self) !ConnectIp.OwnedIpPayload {
            return self.datagrams.receive();
        }

        pub fn receiveWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !ConnectIp.OwnedIpPayload {
            return self.datagrams.receiveWithTimeout(timeout);
        }

        pub fn receiveWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !ConnectIp.OwnedIpPayload {
            return self.datagrams.receiveWithDeadline(deadline);
        }

        pub fn receiveInto(
            self: *Self,
            out: []u8,
        ) !ConnectIp.ReceivedIpPayload {
            return self.datagrams.receiveInto(out);
        }

        pub fn receiveIntoWithTimeout(
            self: *Self,
            out: []u8,
            timeout: std.Io.Duration,
        ) !ConnectIp.ReceivedIpPayload {
            return self.datagrams.receiveIntoWithTimeout(out, timeout);
        }

        pub fn receiveIntoWithDeadline(
            self: *Self,
            out: []u8,
            deadline: std.Io.Clock.Timestamp,
        ) !ConnectIp.ReceivedIpPayload {
            return self.datagrams.receiveIntoWithDeadline(out, deadline);
        }

        pub fn pollReceiveInto(
            self: *Self,
            out: []u8,
        ) !?ConnectIp.ReceivedIpPayload {
            return self.datagrams.pollReceiveInto(out);
        }

        pub fn pollReceiveIntoStep(
            self: *Self,
            out: []u8,
        ) !ConnectIp.Session(Parent).PollReceiveStep {
            return self.datagrams.pollReceiveIntoStep(out);
        }

        /// Send one complete caller-encoded ADDRESS_* or ROUTE_ADVERTISEMENT
        /// Capsule. A timed partial write retains the borrowed byte identity.
        pub fn sendCapsule(self: *Self, encoded: []const u8) !void {
            try self.prepareSend(encoded);
            self.sendBody(encoded[self.pending_send.?.committed..], false) catch |err| {
                self.pending_send = null;
                return err;
            };
            self.pending_send = null;
        }

        /// One transactional DATA-frame attempt for dispatcher owners. Pacing,
        /// congestion, or flow-control refusal retains the borrowed identity.
        pub fn trySendCapsule(self: *Self, encoded: []const u8) !void {
            try self.prepareSend(encoded);
            self.trySendBody(
                encoded[self.pending_send.?.committed..],
                false,
            ) catch |err| switch (err) {
                error.PacingLimited,
                error.CongestionLimited,
                error.FlowControlBlocked,
                => return err,
                else => {
                    self.pending_send = null;
                    return err;
                },
            };
            self.pending_send = null;
        }

        pub fn sendCapsuleWithTimeout(
            self: *Self,
            encoded: []const u8,
            timeout: std.Io.Duration,
        ) !void {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.sendCapsuleWithDeadline(encoded, .fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn sendCapsuleWithDeadline(
            self: *Self,
            encoded: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            _ = try deadline_policy.usableAwake(self.io, deadline);
            try self.prepareSend(encoded);
            var progress: BodyWriteProgress = .{};
            self.sendBodyWithDeadline(
                encoded[self.pending_send.?.committed..],
                false,
                &progress,
                deadline,
            ) catch |err| {
                self.pending_send.?.committed += progress.committed_bytes;
                if (err != error.Timeout) self.pending_send = null;
                return err;
            };
            self.pending_send.?.committed += progress.committed_bytes;
            std.debug.assert(self.pending_send.?.committed == encoded.len);
            self.pending_send = null;
        }

        pub fn closeWrite(self: *Self) !void {
            if (self.pending_send != null) return error.WriteInProgress;
            return self.sendBody(&.{}, true);
        }

        pub fn tryCloseWrite(self: *Self) !void {
            if (self.pending_send != null) return error.WriteInProgress;
            return self.trySendBody(&.{}, true);
        }

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

        /// Poll only already-routed CONNECT DATA. This never receives from the
        /// QUIC endpoint and is safe under EndpointServer ownership.
        pub fn pollReceiveCapsule(self: *Self) !?OwnedCapsule {
            if (try self.takeBufferedCapsule()) |owned| return owned;
            if (self.peer_finished) return self.finishedCapsuleRead();
            try self.pumpStreamOnce();
            if (try self.takeBufferedCapsule()) |owned| return owned;
            if (self.peer_finished) return self.finishedCapsuleRead();
            return null;
        }

        fn prepareSend(self: *Self, encoded: []const u8) !void {
            if (self.pending_send) |pending| {
                if (!pending.matches(encoded)) return error.WriteInProgress;
                return;
            }
            const parsed = try Http3.capsule.parse(encoded);
            if (parsed.consumed != encoded.len or
                !parsed.capsule.isConnectIpConfiguration() or
                parsed.capsule.value.len > max_configuration_capsule_bytes)
            {
                return error.InvalidFrame;
            }
            try validateConfigurationCapsule(parsed.capsule);
            self.pending_send = .{
                .ptr = encoded.ptr,
                .len = encoded.len,
            };
        }

        fn receiveCapsuleUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !OwnedCapsule {
            while (true) {
                if (try self.takeBufferedCapsule()) |owned| return owned;
                if (self.peer_finished) {
                    if (self.bufferedLen() != 0) {
                        try self.cancelMalformed();
                        return error.BufferTooShort;
                    }
                    return error.ConnectDatagramAssociationClosed;
                }
                self.compactReceiveBuffer();
                try self.pumpStream(deadline);
            }
        }

        fn takeBufferedCapsule(self: *Self) !?OwnedCapsule {
            while (self.receive_offset < self.receive_buffer.items.len) {
                const parsed = Http3.capsule.parse(
                    self.receive_buffer.items[self.receive_offset..],
                ) catch |err| switch (err) {
                    error.BufferTooShort => return null,
                    else => {
                        try self.cancelMalformed();
                        return err;
                    },
                };
                if (parsed.capsule.value.len >
                    max_configuration_capsule_bytes)
                {
                    try self.cancelMalformed();
                    return error.ExcessiveLoad;
                }
                self.receive_offset += parsed.consumed;
                if (!parsed.capsule.isConnectIpConfiguration()) continue;
                validateConfigurationCapsule(parsed.capsule) catch |err| {
                    try self.cancelMalformed();
                    return err;
                };
                const storage = try self.allocator.dupe(
                    u8,
                    parsed.capsule.value,
                );
                return .{
                    .stream_id = self.stream_id,
                    .capsule_type = parsed.capsule.capsule_type,
                    .storage = storage,
                    .value = storage,
                };
            }
            self.receive_buffer.clearRetainingCapacity();
            self.receive_offset = 0;
            return null;
        }

        fn finishedCapsuleRead(self: *Self) !?OwnedCapsule {
            if (self.bufferedLen() != 0) {
                try self.cancelMalformed();
                return error.BufferTooShort;
            }
            return error.ConnectDatagramAssociationClosed;
        }

        fn pumpStream(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !void {
            if (role == .client) {
                while (true) {
                    var event = if (deadline) |absolute|
                        (try self.parent.receiveResponseEventWithDeadline(
                            self.stream_id,
                            absolute,
                        )) orelse continue
                    else
                        (try self.parent.receiveResponseEvent(
                            self.stream_id,
                        )) orelse continue;
                    defer event.deinit(self.allocator);
                    switch (event) {
                        .data_available => return self.readAvailableData(),
                        .finished => self.peer_finished = true,
                        .head, .push_promise, .trailers => {
                            try self.cancelMalformed();
                            return error.InvalidFrame;
                        },
                    }
                    return;
                }
            } else {
                var event = if (deadline) |absolute|
                    try self.parent.receiveRequestEventForWithDeadline(
                        self.stream_id,
                        absolute,
                    )
                else
                    try self.parent.receiveRequestEventFor(self.stream_id);
                defer event.deinit(self.allocator);
                switch (event) {
                    .reset => return error.RequestCancelled,
                    .message => |message| switch (message.value) {
                        .data_available => return self.readAvailableData(),
                        .finished => self.peer_finished = true,
                        .head, .push_promise, .trailers => {
                            try self.cancelMalformed();
                            return error.InvalidFrame;
                        },
                    },
                }
            }
        }

        fn readAvailableData(self: *Self) !void {
            try self.read_scratch.resize(self.allocator, read_chunk_bytes);
            const count = if (role == .client)
                try self.parent.readResponseData(
                    self.stream_id,
                    self.read_scratch.items,
                )
            else
                try self.parent.readRequestData(
                    self.stream_id,
                    self.read_scratch.items,
                );
            if (count != 0) {
                try self.receive_buffer.appendSlice(
                    self.allocator,
                    self.read_scratch.items[0..count],
                );
            }
        }

        fn pumpStreamOnce(self: *Self) !void {
            if (role == .client) {
                var event = (try self.parent.pollResponseEventOnce(
                    self.stream_id,
                )) orelse return;
                defer event.deinit(self.allocator);
                switch (event) {
                    .data_available => return self.readAvailableDataOnce(),
                    .finished => self.peer_finished = true,
                    .head, .push_promise, .trailers => {
                        try self.cancelMalformed();
                        return error.InvalidFrame;
                    },
                }
            } else {
                var event = (try self.parent.pollRequestEventForOnce(
                    self.stream_id,
                )) orelse return;
                defer event.deinit(self.allocator);
                switch (event) {
                    .reset => return error.RequestCancelled,
                    .message => |message| switch (message.value) {
                        .data_available => return self.readAvailableDataOnce(),
                        .finished => self.peer_finished = true,
                        .head, .push_promise, .trailers => {
                            try self.cancelMalformed();
                            return error.InvalidFrame;
                        },
                    },
                }
            }
        }

        fn readAvailableDataOnce(self: *Self) !void {
            try self.read_scratch.resize(self.allocator, read_chunk_bytes);
            const maybe_count = if (role == .client)
                try self.parent.readResponseDataOnce(
                    self.stream_id,
                    self.read_scratch.items,
                )
            else
                try self.parent.readRequestDataOnce(
                    self.stream_id,
                    self.read_scratch.items,
                );
            const count = maybe_count orelse return;
            if (count != 0) {
                try self.receive_buffer.appendSlice(
                    self.allocator,
                    self.read_scratch.items[0..count],
                );
            }
        }

        fn sendBody(self: *Self, data: []const u8, fin: bool) !void {
            return if (role == .client)
                self.parent.sendRequestBodyPaced(self.stream_id, data, fin)
            else
                self.parent.sendResponseBodyPaced(self.stream_id, data, fin);
        }

        fn sendBodyWithDeadline(
            self: *Self,
            data: []const u8,
            fin: bool,
            progress: *BodyWriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            return if (role == .client)
                self.parent.sendRequestBodyPacedWithDeadline(
                    self.stream_id,
                    data,
                    fin,
                    progress,
                    deadline,
                )
            else
                self.parent.sendResponseBodyPacedWithDeadline(
                    self.stream_id,
                    data,
                    fin,
                    progress,
                    deadline,
                );
        }

        fn trySendBody(self: *Self, data: []const u8, fin: bool) !void {
            return if (role == .client)
                self.parent.trySendRequestBody(self.stream_id, data, fin)
            else
                self.parent.trySendResponseBody(self.stream_id, data, fin);
        }

        fn cancelMalformed(self: *Self) !void {
            return self.parent.cancelRequest(
                self.stream_id,
                Http3.ApplicationErrorCode.message_error,
            );
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

        fn validateConfigurationCapsule(value: Http3.capsule.Capsule) !void {
            switch (value.capsule_type) {
                ConnectIp.capsules.address_assign_type => _ = try ConnectIp.capsules.parseAddressAssign(value.value),
                ConnectIp.capsules.address_request_type => _ = try ConnectIp.capsules.parseAddressRequest(value.value),
                ConnectIp.capsules.route_advertisement_type => _ = try ConnectIp.capsules.parseRouteAdvertisement(value.value),
                else => return error.InvalidFrame,
            }
        }
    };
}

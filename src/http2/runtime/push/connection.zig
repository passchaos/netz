//! Push receive orchestration over connection-owned HTTP/2 transport hooks.

const std = @import("std");
const http2 = @import("../../mod.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const receive = @import("receive.zig");
const credit = @import("credit.zig");
const OwnedFrame = @import("../frame/io.zig").OwnedFrame;
const flag_end_headers: u8 = 0x4;
const flag_end_stream: u8 = 0x1;

pub fn Lifecycle(comptime hooks: anytype) type {
    return struct {
        pub fn read(self: anytype, promise: anytype, deadline: ?std.Io.Clock.Timestamp) hooks.Error!hooks.Response {
            if (self.callback_reader_active or self.duplex_reader_active) return error.UnexpectedFrame;
            if (self.role != .client) return error.UnexpectedFrame;
            if (!self.push_state.isRemoteReserved(
                promise.promised_stream_id,
            ) or self.push_state.hasPending(promise.promised_stream_id)) {
                return error.InvalidStreamId;
            }
            const id = promise.promised_stream_id;
            while (true) {
                if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
                const received = &self.push_state.state.?.received;
                if (received.get(id).?.finished) {
                    if (received.get(id).?.failure) |err| {
                        _ = self.push_state.releaseRemote(self.allocator, id);
                        return err;
                    }
                    const response = try received.take(self.allocator, id);
                    _ = self.push_state.releaseRemote(self.allocator, id);
                    return .{
                        .headers = response.headers,
                        .status = response.status,
                        .body = response.body,
                        .trailers = response.trailers,
                        .body_allowed = response.body_allowed,
                        .trailers_only = response.trailers_only,
                    };
                }
                // Fully committed buffered responses remain readable after a
                // later connection-level close or failed cleanup write.
                if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
                if (self.pending_push_header != null) {
                    try resumePendingPushHeader(self, deadline);
                    continue;
                }
                try hooks.prepareQueued(self, deadline);
                const borrowed = try hooks.readRaw(self, deadline);
                if (try receivePushedFrame(self, borrowed.frame, deadline)) continue;
                if (try hooks.handleConnection(self, borrowed.frame, deadline)) continue;
                if (borrowed.frame.header.frame_type == .goaway) {
                    try hooks.recordGoAway(self, try http2.GoAwayPayload.parse(borrowed.frame));
                    continue;
                }
                const bytes = try self.allocator.dupe(u8, borrowed.bytes);
                var frame_owned = true;
                defer if (frame_owned) self.allocator.free(bytes);
                const frame = OwnedFrame{ .bytes = bytes, .frame = http2.Frame.parse(bytes) catch unreachable };
                try hooks.queueSibling(self, frame);
                frame_owned = false;
            }
        }

        pub fn occupiedPushSlots(self: anytype) usize {
            var count = self.active_peer_streams.items.len;
            if (self.push_state.state) |state| {
                for (state.remote.items) |id| if (!self.active_peer_index.contains(id)) {
                    count += 1;
                };
            }
            return count;
        }

        fn pushedReceiveLimits(self: anytype) receive.Limits {
            return .{
                .max_bytes = self.limits.max_buffered_push_bytes,
                .max_body_bytes = self.limits.max_body_bytes,
                .max_informational_responses = self.limits.max_informational_responses,
            };
        }

        fn finishPushedReceive(self: anytype, id: u31) void {
            hooks.releasePeer(self, id);
            hooks.forgetWindows(self, id);
        }

        pub fn returnHeldCredit(self: anytype, id: u31, extra: usize, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            return credit.release(self, id, extra, deadline, .{ .ErrorType = hooks.Error, .returnCredit = hooks.returnCredit });
        }

        fn resetPush(self: anytype, id: u31, code: http2.ErrorCode, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            if (self.terminal_write_failed) return;
            hooks.reset(self, id, code, deadline) catch |err| {
                // Even peer-close errors can follow an accepted frame prefix.
                // Keep complete buffered responses but never append more bytes.
                self.aggregate_timeout_unusable = true;
                self.terminal_write_failed = true;
                switch (err) {
                    error.SocketUnconnected, error.ConnectionResetByPeer => {},
                    else => return err,
                }
            };
        }

        fn failPushedReceive(self: anytype, id: u31, err: receive.Error, extra_credit: usize, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            const previous = self.push_state.state.?.received.get(id) orelse return;
            const was_finished = previous.finished and previous.failure == null;
            self.push_state.state.?.received.fail(self.allocator, id, err);
            defer finishPushedReceive(self, id);
            if (!was_finished) try returnHeldCredit(self, id, extra_credit, deadline);
            const code: http2.ErrorCode = if (was_finished and err == error.UnexpectedFrame) .stream_closed else switch (err) {
                error.PushBufferFull, error.MessageTooLarge, error.OutOfMemory => .cancel,
                else => .protocol_error,
            };
            try resetPush(self, id, code, deadline);
        }

        fn acceptPushedHeaders(self: anytype, id: u31, fields: []http2.Hpack.HeaderField, end_stream: bool, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            const received = &self.push_state.state.?.received;
            // Cancellation may retire the owner while an already-started
            // HEADERS block is awaiting CONTINUATION. Its HPACK input still
            // advances the connection dictionary, then its fields are freed.
            if (received.get(id) == null) {
                hooks.freeHeaders(self.allocator, fields);
                return;
            }
            received.headers(self.allocator, id, fields, end_stream, pushedReceiveLimits(self)) catch |err| {
                try failPushedReceive(self, id, err, 0, deadline);
                return;
            };
            if (received.get(id).?.finished) finishPushedReceive(self, id);
        }

        pub fn resumePendingPushHeader(self: anytype, deadline: ?std.Io.Clock.Timestamp) hooks.Error!void {
            const pending = self.pending_push_header orelse return;
            self.push_ingress_headers_active = true;
            defer self.push_ingress_headers_active = false;
            const fields = (hooks.resumeHeader(pending, self, deadline) catch |err| {
                if (err == error.Timeout) return err;
                if (self.hpack_decoder.lastDecodeWasCompressionError()) {
                    self.aggregate_timeout_unusable = true;
                    hooks.goAway(self, hooks.processed(self.*), .compression_error, "push-hpack", deadline) catch {};
                } else if (err == error.MessageTooLarge and pending.end_headers) {
                    const id = pending.stream_id;
                    hooks.deinitHeader(pending, self.allocator);
                    self.allocator.destroy(pending);
                    self.pending_push_header = null;
                    try failPushedReceive(self, id, error.MessageTooLarge, 0, deadline);
                    return;
                } else self.aggregate_timeout_unusable = true;
                return err;
            }) orelse return error.UnexpectedFrame;
            const id = pending.stream_id;
            const end_stream = pending.end_stream;
            hooks.deinitHeader(pending, self.allocator);
            self.allocator.destroy(pending);
            self.pending_push_header = null;
            try acceptPushedHeaders(self, id, fields, end_stream, deadline);
        }

        pub fn receivePushedFrame(self: anytype, frame: http2.Frame, deadline: ?std.Io.Clock.Timestamp) hooks.Error!bool {
            if (self.role != .client or !self.limits.enable_push) return false;
            if (frame.header.frame_type == .push_promise) {
                self.push_ingress_headers_active = true;
                defer self.push_ingress_headers_active = false;
                hooks.promise(self, frame, deadline) catch |err| {
                    self.aggregate_timeout_unusable = true;
                    return err;
                };
                return true;
            }
            const state = self.push_state.state orelse return false;
            const id = frame.header.stream_id;
            const entry = state.received.get(id) orelse return false;
            if (entry.failure != null and hooks.wasReset(self, id)) {
                self.push_ingress_headers_active = true;
                defer self.push_ingress_headers_active = false;
                if (try hooks.discardReset(self, frame, deadline)) return true;
            }
            switch (frame.header.frame_type) {
                .headers => {
                    if (!entry.started) {
                        try hooks.activate(self, id);
                        entry.started = true;
                    }
                    const parsed = hooks.parseHeaders(self, frame) catch |err| {
                        try failPushedReceive(self, id, err, 0, deadline);
                        return true;
                    };
                    if ((frame.header.flags & flag_end_headers) != 0) {
                        const fields = hooks.decodeHeaders(self.allocator, parsed.header_block, self.limits, &self.hpack_decoder) catch |err| {
                            if (self.hpack_decoder.lastDecodeWasCompressionError()) {
                                self.aggregate_timeout_unusable = true;
                                hooks.goAway(self, hooks.processed(self.*), .compression_error, "push-hpack", deadline) catch {};
                            } else if (err == error.MessageTooLarge) {
                                try failPushedReceive(self, id, error.MessageTooLarge, 0, deadline);
                                return true;
                            } else self.aggregate_timeout_unusable = true;
                            return err;
                        };
                        try acceptPushedHeaders(self, id, fields, (frame.header.flags & flag_end_stream) != 0, deadline);
                    } else {
                        const pending = self.allocator.create(hooks.Header) catch |err| {
                            self.aggregate_timeout_unusable = true;
                            return err;
                        };
                        pending.* = hooks.initHeader(self, frame) catch |err| {
                            self.allocator.destroy(pending);
                            self.aggregate_timeout_unusable = true;
                            return err;
                        };
                        self.pending_push_header = pending;
                        try resumePendingPushHeader(self, deadline);
                    }
                    return true;
                },
                .data => {
                    if (entry.finished) {
                        _ = try http2.DataPayload.parse(frame);
                        try self.recv_connection_window.receive(frame.payload.len);
                        try credit.refund(self, frame.payload.len, deadline, .{ .ErrorType = hooks.Error, .returnCredit = hooks.returnCredit });
                        if (!hooks.wasReset(self, id)) try resetPush(self, id, .stream_closed, deadline);
                        return true;
                    }
                    if (!entry.started) {
                        self.aggregate_timeout_unusable = true;
                        try hooks.goAway(self, hooks.processed(self.*), .protocol_error, "data-on-reserved-push", deadline);
                        return error.InvalidFrame;
                    }
                    const before = self.recv_connection_window.value;
                    const generation = state.received.connection_refill_generation;
                    const data = try hooks.takeData(self, id, frame);
                    defer hooks.releaseData(self, data);
                    const ended = (frame.header.flags & flag_end_stream) != 0;
                    state.received.data(self.allocator, id, data.data, ended, pushedReceiveLimits(self)) catch |err| {
                        try failPushedReceive(self, id, err, frame.payload.len, deadline);
                        return true;
                    };
                    try hooks.credit(self, id, data, ended, deadline);
                    state.received.accountData(id, before, self.recv_connection_window.value, data.adaptive_connection_increment, generation);
                    if (state.received.get(id).?.finished) finishPushedReceive(self, id);
                    return true;
                },
                .rst_stream => {
                    _ = try http2.ResetStreamPayload.parse(frame);
                    const was_finished = entry.finished;
                    state.received.fail(self.allocator, id, error.StreamReset);
                    defer finishPushedReceive(self, id);
                    if (!was_finished) try returnHeldCredit(self, id, 0, deadline);
                    return true;
                },
                .window_update => {
                    if (!entry.started and !entry.finished) {
                        self.aggregate_timeout_unusable = true;
                        try hooks.goAway(self, hooks.processed(self.*), .protocol_error, "window-on-reserved-push", deadline);
                        return error.InvalidFrame;
                    }
                    return false;
                },
                else => return false,
            }
        }
    };
}

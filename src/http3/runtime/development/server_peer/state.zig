const std = @import("std");
const http3 = @import("../../../mod.zig");
const quic = @import("../../../../quic/mod.zig");
const runtime_error = @import("../../error.zig");
const request_buffer = @import("../request_buffer.zig");
const buffered_request = @import("../../stream/buffered/request.zig");
const stream_events = @import("../../stream/events.zig");
const stream_lifecycle = @import("../../stream/lifecycle.zig");
const streaming_set = @import("../../stream/set.zig");
const outbound_body = @import("../../stream/outbound_body.zig");
const qpack_state = @import("../../qpack/state.zig");
const send_scratch = @import("../../send/scratch.zig");

const net = std.Io.net;
const Error = runtime_error.Error;
const DevelopmentRequestStreamSet = request_buffer.Set;
const RequestStreamSet = buffered_request.Set;
const StreamingRequestEvent = stream_events.Request;
const StreamingRequestSet = streaming_set.Set;
const ServerRequestLifecycle = stream_lifecycle.Server;
const QpackDecodeState = qpack_state.QpackDecodeState;
const QpackEncodeState = qpack_state.QpackEncodeState;
const OutboundBodySet = outbound_body.Set;
const StreamMessageSendScratch = send_scratch.Message;
const development_settings: http3.Settings = .{ .enable_connect_protocol = true };

fn requestPriority(headers: []const http3.Qpack.HeaderField) http3.Priority {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, "priority")) {
            return http3.Priority.parse(header.value);
        }
    }
    return .{};
}

pub const Set = struct {
    pub const ErrorContext = struct {
        from: net.IpAddress,
        stream_id: u62,
    };

    pub const Peer = struct {
        pub const ResponseContext = struct {
            scratch: *StreamMessageSendScratch,
            qpack_encode: *QpackEncodeState,
            outbound_bodies: *OutboundBodySet,
            response_send_offsets: *std.AutoHashMapUnmanaged(u62, u64),
        };

        pub const Cancellation = struct {
            local_final_size: u64,
            send_reset: bool,
        };

        address: net.IpAddress,
        request_streams: RequestStreamSet,
        streaming_requests: StreamingRequestSet,
        lifecycle: ServerRequestLifecycle,
        qpack_decode: QpackDecodeState,
        qpack_encode: QpackEncodeState,
        outbound_bodies: OutboundBodySet,
        response_send_offsets: std.AutoHashMapUnmanaged(u62, u64) = .empty,
        stream_send_scratch: StreamMessageSendScratch = .{},
        unusable: bool = false,

        pub fn init(
            allocator: std.mem.Allocator,
            address: net.IpAddress,
            max_stream_buffer: usize,
            max_streams: usize,
        ) Peer {
            return .{
                .address = address,
                .request_streams = .init(allocator, max_stream_buffer, max_streams),
                .streaming_requests = .init(
                    allocator,
                    max_streams,
                    max_stream_buffer,
                    development_settings,
                    .request,
                ),
                .lifecycle = .init(allocator),
                .qpack_decode = .init(allocator, 0, max_stream_buffer),
                .qpack_encode = .init(allocator, 0, max_stream_buffer),
                .outbound_bodies = .init(allocator, max_streams),
            };
        }

        pub fn deinit(self: *Peer, allocator: std.mem.Allocator) void {
            self.stream_send_scratch.deinit(allocator);
            self.response_send_offsets.deinit(allocator);
            self.outbound_bodies.deinit();
            self.qpack_encode.deinit();
            self.qpack_decode.deinit();
            self.lifecycle.deinit();
            self.streaming_requests.deinit();
            self.request_streams.deinit();
            self.* = undefined;
        }

        pub fn retainedCount(self: Peer) usize {
            var count = self.lifecycle.count();
            count += self.request_streams.countNotTrackedBy(self.lifecycle);
            count += self.streaming_requests.countNotTrackedBy(self.lifecycle);
            return count;
        }

        pub fn hasOwnedState(self: Peer) bool {
            return self.retainedCount() != 0 or
                !self.outbound_bodies.isEmpty() or
                self.response_send_offsets.count() != 0;
        }

        pub fn prepareInformational(
            self: *Peer,
            stream_id: u62,
            streaming_mode: bool,
        ) Error!ResponseContext {
            if (self.unusable) return error.ConnectionUnusable;
            if (!streaming_mode or !self.lifecycle.contains(stream_id) or
                self.outbound_bodies.find(stream_id) != null)
            {
                return error.UnexpectedStream;
            }
            self.stream_send_scratch.reset();
            return self.responseContext();
        }

        pub fn prepareResponseHead(
            self: *Peer,
            stream_id: u62,
            streaming_mode: bool,
        ) Error!ResponseContext {
            if (self.unusable) return error.ConnectionUnusable;
            if (!streaming_mode or !self.lifecycle.contains(stream_id)) {
                return error.UnexpectedStream;
            }
            self.stream_send_scratch.reset();
            return self.responseContext();
        }

        pub fn prepareResponseBody(
            self: *Peer,
            stream_id: u62,
        ) Error!*OutboundBodySet {
            if (self.unusable) return error.ConnectionUnusable;
            const body = self.outbound_bodies.find(stream_id) orelse
                return error.UnexpectedStream;
            if (body.send.fin_sent) return error.UnexpectedStream;
            return &self.outbound_bodies;
        }

        pub fn responseContext(self: *Peer) ResponseContext {
            return .{
                .scratch = &self.stream_send_scratch,
                .qpack_encode = &self.qpack_encode,
                .outbound_bodies = &self.outbound_bodies,
                .response_send_offsets = &self.response_send_offsets,
            };
        }

        pub fn markSendFailed(self: *Peer) void {
            self.unusable = true;
        }

        pub fn responsePrefixOffset(self: Peer, stream_id: u62) u64 {
            return self.response_send_offsets.get(stream_id) orelse 0;
        }

        pub fn abandonEncodedResponse(self: *Peer, stream_id: u62) void {
            self.qpack_encode.abandonStream(stream_id);
        }

        pub fn discardResponseBody(self: *Peer, stream_id: u62) void {
            _ = self.outbound_bodies.finish(stream_id);
        }

        pub fn commitResponseHead(
            self: *Peer,
            stream_id: u62,
            body_allowed: bool,
            expected_length: ?usize,
        ) void {
            _ = self.response_send_offsets.remove(stream_id);
            if (!body_allowed or expected_length == 0) {
                self.lifecycle.markFinished(stream_id);
                self.finishSendIfExchangeComplete(stream_id);
            }
        }

        pub fn commitResponseBody(self: *Peer, stream_id: u62, fin: bool) void {
            if (!fin) return;
            self.lifecycle.markFinished(stream_id);
            self.finishSendIfExchangeComplete(stream_id);
        }

        pub fn cancelRequest(self: *Peer, stream_id: u62) Error!Cancellation {
            const body = self.outbound_bodies.find(stream_id);
            if (body == null and !self.lifecycle.contains(stream_id) and
                !self.request_streams.contains(stream_id) and
                !self.streaming_requests.contains(stream_id) and
                !self.response_send_offsets.contains(stream_id))
            {
                return error.UnexpectedStream;
            }
            const result: Cancellation = .{
                .local_final_size = if (body) |entry|
                    entry.send.next_offset
                else
                    self.response_send_offsets.get(stream_id) orelse 0,
                .send_reset = if (body) |entry|
                    !entry.send.fin_sent
                else
                    self.lifecycle.contains(stream_id),
            };
            self.request_streams.remove(stream_id);
            self.streaming_requests.remove(stream_id);
            _ = self.response_send_offsets.remove(stream_id);
            self.lifecycle.markFinished(stream_id);
            _ = self.outbound_bodies.finish(stream_id);
            return result;
        }

        fn finishSendIfExchangeComplete(
            self: *Peer,
            stream_id: u62,
        ) void {
            if (self.request_streams.contains(stream_id) or
                self.streaming_requests.contains(stream_id)) return;
            const body = self.outbound_bodies.find(stream_id) orelse return;
            if (body.send.fin_sent) _ = self.outbound_bodies.finish(stream_id);
        }

        fn takeUnadmittedReset(self: *Peer) ?StreamingRequestSet.Reset {
            return self.streaming_requests.takeFirstResetNotTrackedBy(
                self.lifecycle,
            );
        }
    };

    allocator: std.mem.Allocator,
    // Peer objects are individually allocated so an ArrayList growth cannot
    // invalidate a pointer held by a concurrent response sender. A peer is
    // removed only after it has no active receive or response lifecycle.
    peers: std.ArrayList(*Peer) = .empty,
    max_stream_buffer: usize,
    max_streams: usize,
    last_peer_index: ?usize = null,
    last_error: ?ErrorContext = null,

    pub fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) Set {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    pub fn deinit(self: *Set) void {
        for (self.peers.items) |peer| {
            peer.deinit(self.allocator);
            self.allocator.destroy(peer);
        }
        self.peers.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn totalRetained(self: Set) usize {
        var total: usize = 0;
        for (self.peers.items) |peer| total += peer.retainedCount();
        return total;
    }

    pub fn find(
        self: *Set,
        address: net.IpAddress,
    ) ?*Peer {
        for (self.peers.items) |peer| {
            if (peer.address.eql(&address)) return peer;
        }
        return null;
    }

    pub fn hasPeer(self: *Set, address: net.IpAddress) bool {
        return self.find(address) != null;
    }

    pub fn peerHasOwnedState(self: *Set, address: net.IpAddress) bool {
        const peer = self.find(address) orelse return false;
        return peer.hasOwnedState();
    }

    pub fn containsRequest(
        self: *Set,
        address: net.IpAddress,
        stream_id: u62,
    ) bool {
        const peer = self.find(address) orelse return false;
        return peer.request_streams.contains(stream_id) or
            peer.streaming_requests.contains(stream_id) or
            peer.lifecycle.contains(stream_id);
    }

    pub fn getOrCreate(
        self: *Set,
        address: net.IpAddress,
    ) Error!*Peer {
        if (self.find(address)) |peer| return peer;
        const peer = try self.allocator.create(Peer);
        errdefer self.allocator.destroy(peer);
        peer.* = .init(
            self.allocator,
            address,
            self.max_stream_buffer,
            self.max_streams,
        );
        errdefer peer.deinit(self.allocator);
        try self.peers.append(self.allocator, peer);
        return peer;
    }

    /// Move all partial aggregate request streams into incremental readers.
    /// Capacity for every destination allocation is reserved first, so an OOM
    /// leaves the source set untouched and the caller can retry the transition.
    pub fn adoptBufferedRequests(
        self: *Set,
        buffered: *DevelopmentRequestStreamSet,
    ) Error!void {
        if (buffered.isEmpty()) return;
        if (self.totalRetained() > self.max_streams -| buffered.count()) {
            return error.ExcessiveLoad;
        }
        var index: usize = 0;
        while (buffered.entryView(index)) |entry| : (index += 1) {
            if (self.find(entry.from)) |peer| {
                if (peer.request_streams.contains(entry.stream_id) or
                    peer.streaming_requests.contains(entry.stream_id))
                {
                    return error.UnexpectedStream;
                }
            }
        }

        var additional_peers: usize = 0;
        index = 0;
        while (buffered.entryView(index)) |entry| : (index += 1) {
            var already_counted = self.find(entry.from) != null;
            if (!already_counted) {
                var prior_index: usize = 0;
                while (prior_index < index) : (prior_index += 1) {
                    const prior = buffered.entryView(prior_index).?;
                    if (prior.from.eql(&entry.from)) {
                        already_counted = true;
                        break;
                    }
                }
            }
            if (!already_counted) additional_peers += 1;
        }
        try self.peers.ensureUnusedCapacity(
            self.allocator,
            additional_peers,
        );

        // Construct all missing peers before touching the source stream set.
        // These allocations are the only ones not covered by per-peer reserve.
        const original_peer_count = self.peers.items.len;
        errdefer {
            while (self.peers.items.len > original_peer_count) {
                const peer = self.peers.pop().?;
                peer.deinit(self.allocator);
                self.allocator.destroy(peer);
            }
        }
        index = 0;
        while (buffered.entryView(index)) |entry| : (index += 1) {
            if (self.find(entry.from) != null) continue;
            const peer = try self.allocator.create(Peer);
            errdefer self.allocator.destroy(peer);
            peer.* = .init(
                self.allocator,
                entry.from,
                self.max_stream_buffer,
                self.max_streams,
            );
            self.peers.appendAssumeCapacity(peer);
        }

        for (self.peers.items) |peer| {
            const incoming = buffered.countForPeer(peer.address);
            if (incoming == 0) continue;
            if (peer.retainedCount() + incoming > self.max_streams) {
                return error.ExcessiveLoad;
            }
            try peer.streaming_requests.reserveEntries(incoming);
        }

        // No operation below can fail: the two destination containers were
        // fully reserved above. Preserve aggregate insertion order while
        // transferring each receive buffer exactly once.
        buffered.transferAllAssumeCapacity(
            self,
            Set.adoptBufferedRequestAssumeCapacity,
        );
    }

    fn adoptBufferedRequestAssumeCapacity(
        self: *Set,
        transfer: DevelopmentRequestStreamSet.Transfer,
    ) void {
        const stream_id: u62 = @intCast(transfer.receive.stream_id);
        const peer = self.find(transfer.from) orelse unreachable;
        std.debug.assert(!peer.request_streams.contains(stream_id));
        std.debug.assert(!peer.streaming_requests.contains(stream_id));
        _ = peer.streaming_requests.adoptRequestReceiveAssumeCapacity(
            transfer.receive,
            transfer.from,
        );
    }

    pub fn insert(
        self: *Set,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        const stream_id: u62 = @intCast(frame.stream_id);
        var peer = self.find(from);
        if (peer == null and self.totalRetained() >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const created = peer == null;
        peer = peer orelse try self.getOrCreate(from);
        errdefer if (created and peer.?.retainedCount() == 0) {
            self.removePeer(from);
        };
        if (!peer.?.request_streams.contains(stream_id) and
            !peer.?.streaming_requests.contains(stream_id) and
            self.totalRetained() >= self.max_streams)
        {
            return error.ExcessiveLoad;
        }
        try peer.?.streaming_requests.insertRequest(
            &peer.?.request_streams,
            from,
            frame,
        );
    }

    pub fn recordReset(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        const peer = self.find(from) orelse return;
        const replaces_stream = peer.request_streams.contains(stream_id) or
            peer.streaming_requests.contains(stream_id);
        if (!replaces_stream) return;
        const new_reset = try peer.streaming_requests.prepareReset(
            from,
            stream_id,
            application_error_code,
            peer.request_streams.count(),
            true,
        );
        if (!new_reset) return;
        peer.streaming_requests.recordPreparedNewResetAssumeCapacity(
            from,
            stream_id,
            application_error_code,
        );
        peer.request_streams.remove(stream_id);
    }

    pub fn pollRequestEvent(
        self: *Set,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatching(null, null, false);
    }

    pub fn pollRequestHead(
        self: *Set,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatching(null, null, true);
    }

    pub fn pollRequestEventFor(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!?StreamingRequestEvent {
        return self.pollRequestEventMatching(from, stream_id, false);
    }

    fn pollRequestEventMatching(
        self: *Set,
        from: ?net.IpAddress,
        stream_id: ?u62,
        head_only: bool,
    ) Error!?StreamingRequestEvent {
        self.last_error = null;
        if (self.peers.items.len == 0) return null;
        var index = if (self.last_peer_index) |last|
            (last + 1) % self.peers.items.len
        else
            0;
        var remaining = self.peers.items.len;
        while (remaining != 0) : (remaining -= 1) {
            const peer = self.peers.items[index];
            if (from != null and !peer.address.eql(&from.?)) {
                index = (index + 1) % self.peers.items.len;
                continue;
            }
            // A targeted receive owns only its stream's terminal event. An
            // untargeted receive preserves the reset queue's FIFO order.
            if (head_only) {
                // Admission has no public reset event to return. Drain every
                // abandoned pre-head stream before polling headers so a burst
                // of reset-only traffic cannot pin bounded stream slots or
                // force this call to wait for an unrelated future datagram.
                while (peer.takeUnadmittedReset()) |reset| {
                    peer.lifecycle.markFinished(reset.stream_id);
                    _ = peer.outbound_bodies.finish(reset.stream_id);
                    _ = peer.response_send_offsets.remove(reset.stream_id);
                }
            } else if (if (stream_id) |target|
                peer.streaming_requests.takeReset(target)
            else
                peer.streaming_requests.takeFirstReset()) |reset_event|
            {
                peer.lifecycle.markFinished(reset_event.stream_id);
                _ = peer.outbound_bodies.finish(reset_event.stream_id);
                _ = peer.response_send_offsets.remove(reset_event.stream_id);
                self.last_peer_index = index;
                return .{ .reset = .{
                    .from = reset_event.from,
                    .stream_id = reset_event.stream_id,
                    .application_error_code = reset_event.application_error_code,
                } };
            }
            if (peer.streaming_requests.mightProduceRequestHead(
                &peer.request_streams,
                stream_id,
            )) {
                try peer.lifecycle.prepareMarkReceived();
            }
            if (peer.streaming_requests.nextMatchingEvent(
                &peer.request_streams,
                peer.qpack_decode.table,
                0,
                stream_id,
                head_only,
            ) catch |err| {
                if (peer.streaming_requests.lastErrorStreamId()) |failed_stream| {
                    self.last_error = .{
                        .from = peer.address,
                        .stream_id = failed_stream,
                    };
                }
                return err;
            }) |ready| {
                const ready_stream_id: u62 = @intCast(
                    ready.entry.reader.streamId(),
                );
                if (ready.event == .head) {
                    const priority: http3.Priority = switch (ready.event.head) {
                        .request => |request| requestPriority(request.headers),
                        .response => .{},
                    };
                    peer.lifecycle.markReceivedAssumeCapacity(
                        ready_stream_id,
                        priority,
                    );
                } else if (ready.event == .finished) {
                    peer.streaming_requests.remove(ready_stream_id);
                    peer.finishSendIfExchangeComplete(ready_stream_id);
                }
                self.last_peer_index = index;
                return .{ .message = .{
                    .from = peer.address,
                    .stream_id = ready_stream_id,
                    .value = ready.event,
                } };
            }
            if (peer.retainedCount() == 0 and
                peer.outbound_bodies.isEmpty())
            {
                peer.deinit(self.allocator);
                const removed = self.peers.swapRemove(index);
                self.allocator.destroy(removed);
                self.last_peer_index = null;
                if (self.peers.items.len == 0) return null;
                index %= self.peers.items.len;
                continue;
            }
            index = (index + 1) % self.peers.items.len;
        }
        return null;
    }

    pub fn lastError(self: Set) ?ErrorContext {
        return self.last_error;
    }

    /// Remove all state associated with one request while the caller holds
    /// the development server's receive-state mutex.
    pub fn retireRequest(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) bool {
        const peer = self.find(from) orelse return false;
        const existed = peer.lifecycle.contains(stream_id) or
            peer.request_streams.contains(stream_id) or
            peer.streaming_requests.contains(stream_id) or
            peer.outbound_bodies.find(stream_id) != null;
        if (!existed) return false;
        peer.request_streams.remove(stream_id);
        peer.streaming_requests.remove(stream_id);
        _ = peer.response_send_offsets.remove(stream_id);
        peer.lifecycle.markFinished(stream_id);
        _ = peer.outbound_bodies.finish(stream_id);
        return true;
    }

    pub fn readRequestData(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const peer = self.find(from) orelse return error.UnexpectedStream;
        const entry = peer.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.readData(out);
    }

    pub fn skipRequestData(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!usize {
        const peer = self.find(from) orelse return error.UnexpectedStream;
        const entry = peer.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.skipData();
    }

    pub fn removePeer(
        self: *Set,
        address: net.IpAddress,
    ) void {
        for (self.peers.items, 0..) |peer, index| {
            if (!peer.address.eql(&address)) continue;
            peer.deinit(self.allocator);
            _ = self.peers.swapRemove(index);
            self.allocator.destroy(peer);
            self.last_peer_index = null;
            return;
        }
    }
};

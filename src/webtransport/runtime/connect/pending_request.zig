//! Owned CONNECT metadata retained while the sole endpoint reader negotiates
//! SETTINGS. Caller option slices may be released as soon as begin returns.

const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const headers = @import("headers.zig");
const application_protocol = @import("../../application_protocol.zig");

pub const Request = struct {
    storage: []u8,
    fields: []http3.Qpack.HeaderField,
    authority: []const u8,
    path: []const u8,
    origin: []const u8,
    encoded: std.ArrayList(u8) = .empty,
    offset: usize = 0,
    prepared: bool = false,
    reserved: bool = false,

    pub fn init(allocator: std.mem.Allocator, authority: []const u8, path: []const u8, origin: []const u8, additional: []const http3.Qpack.HeaderField) (http3.Error || std.mem.Allocator.Error)!Request {
        return initWithOffer(allocator, authority, path, origin, additional, null);
    }

    pub fn initWithOffer(allocator: std.mem.Allocator, authority: []const u8, path: []const u8, origin: []const u8, additional: []const http3.Qpack.HeaderField, offer: ?*const application_protocol.Request) (http3.Error || std.mem.Allocator.Error)!Request {
        try headers.validate(additional, .request);
        var total = try add(authority.len, path.len);
        total = try add(total, origin.len);
        var count: usize = 0;
        for (additional) |field| {
            if (offer != null and std.ascii.eqlIgnoreCase(field.name, application_protocol.available_header)) continue;
            total = try add(total, field.name.len);
            total = try add(total, field.value.len);
            count += 1;
        }
        const offer_field = if (offer) |value| if (value.present) @as(?http3.Qpack.HeaderField, value.header[0]) else null else null;
        if (offer_field) |field| {
            total = try add(total, field.name.len);
            total = try add(total, field.value.len);
            count += 1;
        }
        const storage = try allocator.alloc(u8, total);
        errdefer allocator.free(storage);
        const fields = try allocator.alloc(http3.Qpack.HeaderField, count);
        errdefer allocator.free(fields);
        var offset: usize = 0;
        const owned_authority = copy(storage, &offset, authority);
        const owned_path = copy(storage, &offset, path);
        const owned_origin = copy(storage, &offset, origin);
        var index: usize = 0;
        if (offer_field) |field| {
            fields[index] = .{ .name = copy(storage, &offset, field.name), .value = copy(storage, &offset, field.value) };
            index += 1;
        }
        for (additional) |field| {
            if (offer != null and std.ascii.eqlIgnoreCase(field.name, application_protocol.available_header)) continue;
            fields[index] = .{ .name = copy(storage, &offset, field.name), .value = copy(storage, &offset, field.value) };
            index += 1;
        }
        return .{ .storage = storage, .fields = fields, .authority = owned_authority, .path = owned_path, .origin = owned_origin };
    }

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        self.encoded.deinit(allocator);
        allocator.free(self.fields);
        allocator.free(self.storage);
        self.* = undefined;
    }

    /// Stage literal/static QPACK and bookkeeping before reserving an ID.
    /// Each retry submits at most one packet and advances only committed bytes.
    pub fn submit(self: *Request, h3: *http3.runtime.HandshakeClient, version: http3.WebTransportVersion, stream_id: u62) http3.runtime.Error!bool {
        const connection = &h3.established.connection;
        const next = std.math.add(u62, stream_id, 4) catch return error.StreamCreationError;
        if (h3.next_stream_id != stream_id) return error.StreamCreationError;
        if (!h3.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        if (h3.options.max_stream_frame_data == 0) return error.InvalidFrame;
        if (!self.prepared) {
            var stack: [headers.stack_capacity]http3.Qpack.HeaderField = undefined;
            var prepared_headers = try headers.prepareRequestForVersion(h3.allocator, self.origin, self.fields, &stack, version);
            defer prepared_headers.deinit(h3.allocator);
            var encoded: std.ArrayList(u8) = .empty;
            errdefer encoded.deinit(h3.allocator);
            const streaming = try (http3.Request{ .method = "CONNECT", .scheme = "https", .authority = self.authority, .path = self.path, .headers = prepared_headers.fields }).writeStreamingHead(&encoded, h3.allocator, h3.control.settings.peer, null);
            std.debug.assert(streaming.body_allowed and streaming.expected_length == null);
            try h3.outbound_bodies.reserveOpen(stream_id);
            try h3.request_lifecycle.open(stream_id, "CONNECT", true);
            self.encoded = encoded;
            self.prepared = true;
        }
        if (!self.reserved) {
            if (connection.nextLocalBidirectionalStreamId() != stream_id) return error.StreamCreationError;
            const actual = try connection.tryOpenStream();
            std.debug.assert(actual == stream_id);
            h3.request_lifecycle.markAllocated(stream_id);
            self.reserved = true;
        }
        const credit = connection.streamSendCredit(stream_id);
        if (credit.connection == 0 or credit.stream == 0) return error.FlowControlBlocked;
        const upper = @min(self.encoded.items.len - self.offset, @min(h3.options.max_stream_frame_data, credit.available()));
        var low: usize = 0;
        var high = upper;
        while (low < high) {
            const count = low + (high - low + 1) / 2;
            const frame = quic.Frame{ .stream = .{ .stream_id = stream_id, .offset = self.offset, .data = self.encoded.items[self.offset..][0..count] } };
            const packet_len = connection.packetLenForFramesAtOffset(0, &.{frame}) catch |err| switch (err) {
                error.DatagramTooLarge => std.math.maxInt(usize),
                else => return err,
            };
            if (packet_len <= credit.max_datagram_size and try frame.wireLen() <= credit.congestion) low = count else high = count - 1;
        }
        if (low == 0) return error.CongestionLimited;
        try connection.trySend(&.{.{ .stream = .{ .stream_id = stream_id, .offset = self.offset, .data = self.encoded.items[self.offset..][0..low] } }});
        self.offset += low;
        if (self.offset != self.encoded.items.len) return false;
        var send = quic.stream_state.SendState.init(stream_id);
        send.next_offset = self.offset;
        h3.outbound_bodies.appendOpenAssumeCapacity(stream_id, send, null);
        h3.next_stream_id = next;
        return true;
    }
};

fn add(left: usize, right: usize) error{IntegerOverflow}!usize {
    return std.math.add(usize, left, right) catch error.IntegerOverflow;
}

fn copy(storage: []u8, offset: *usize, value: []const u8) []const u8 {
    const result = storage[offset.*..][0..value.len];
    @memcpy(result, value);
    offset.* += value.len;
    return result;
}

test "WebTransport pending CONNECT metadata allocation is transactional" {
    inline for (.{ @as(usize, 0), @as(usize, 1) }) |failure| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = failure });
        try std.testing.expectError(error.OutOfMemory, Request.init(failing.allocator(), "localhost", "/wt", "https://localhost", &.{.{ .name = "x-metadata", .value = "value" }}));
    }
}

test "WebTransport pending CONNECT owns options and resumes large headers after backpressure" {
    const Pair = @import("../session_control/test_support/handshake_pair.zig").Pair;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    var pair: Pair = undefined;
    try pair.init(threaded.io());
    defer pair.deinit();
    var value = [_]u8{'v'} ** 8192;
    var request = try Request.init(std.testing.allocator, "localhost", "/large", "https://localhost", &.{.{ .name = "x-large", .value = &value }});
    defer request.deinit(std.testing.allocator);
    value[0] = 'x';
    try std.testing.expectEqual(@as(u8, 'v'), request.fields[0].value[0]);
    const id = pair.client.h3.next_stream_id;
    try std.testing.expect(!try request.submit(&pair.client.h3, .draft16, id));
    const submitted = request.offset;
    try std.testing.expect(submitted > 0 and submitted < request.encoded.items.len);
    const next_transport = pair.connection(.client).nextLocalBidirectionalStreamId();
    _ = try quic.one_rtt.testing.clampSendStreamLimitToUsed(pair.connection(.client), id);
    try std.testing.expectError(error.FlowControlBlocked, request.submit(&pair.client.h3, .draft16, id));
    try std.testing.expectEqual(submitted, request.offset);
    try std.testing.expectEqual(next_transport, pair.connection(.client).nextLocalBidirectionalStreamId());
    try pair.connection(.server).send(&.{.{ .max_stream_data = .{ .stream_id = id, .maximum_stream_data = 65536 } }});
    const deadline = std.Io.Clock.Timestamp.fromNow(threaded.io(), .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (quic.one_rtt.testing.sendStreamLimit(pair.connection(.client), id).? == submitted) try pair.receiveProgress(.client, deadline);
    while (!try request.submit(&pair.client.h3, .draft16, id)) {}
    try std.testing.expectEqual(request.encoded.items.len, request.offset);
    try std.testing.expectEqual(id + 4, pair.client.h3.next_stream_id);
    while ((if (pair.connection(.server).recvStreamStats(id)) |stats| stats.highest_received_offset else 0) < request.encoded.items.len) try pair.receiveProgress(.server, deadline);
    var event = (try pair.server.h3.pollRequestEventOnce()) orelse return error.TestUnexpectedResult;
    defer event.deinit(std.testing.allocator);
    try std.testing.expect(event == .message and event.message.value == .head and event.message.value.head == .request);
    const head = event.message.value.head.request;
    try std.testing.expectEqualStrings("/large", head.path);
    try headers.validateRequestForVersion(head, .draft16);
    var found = false;
    for (head.headers) |field| {
        if (!std.mem.eql(u8, field.name, "x-large")) continue;
        found = true;
        try std.testing.expectEqual(@as(usize, 8192), field.value.len);
        for (field.value) |byte| try std.testing.expectEqual(@as(u8, 'v'), byte);
    }
    try std.testing.expect(found);
}

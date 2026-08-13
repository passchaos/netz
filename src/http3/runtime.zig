const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");

const net = std.Io.net;

pub const Error = http3.Error || quic.runtime.Error || quic.handshake.Error || quic.one_rtt.Error || quic.stream_state.Error || net.HostName.ValidateError || net.HostName.LookupError || error{
    MissingStreamFrame,
    UnexpectedStream,
    GoAwayReceived,
    RequestRejected,
    ClosedCriticalStream,
    InvalidUri,
};

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;
const first_server_push_stream_id: u62 = 15;

pub const UriEndpoint = struct {
    allocator: std.mem.Allocator,
    host_storage: []u8,
    authority: []u8,
    port: u16,
    target: Target,
    /// Host text suitable for TLS SNI/certificate policy. Bracketed IPv6 URI
    /// literals drop their brackets here while authority keeps them.
    tls_host: []const u8,

    pub const Target = union(enum) {
        host: net.HostName,
        ip: net.IpAddress,
    };

    pub fn deinit(self: *UriEndpoint) void {
        self.allocator.free(self.authority);
        self.allocator.free(self.host_storage);
        self.* = undefined;
    }

    pub fn resolve(self: UriEndpoint, io: std.Io) Error!net.IpAddress {
        return switch (self.target) {
            .ip => |address| address,
            .host => |host| try resolveHostName(io, host, self.port),
        };
    }

    pub fn resolveAll(
        self: UriEndpoint,
        allocator: std.mem.Allocator,
        io: std.Io,
    ) Error![]net.IpAddress {
        return switch (self.target) {
            .ip => |address| try ownedSingleAddress(allocator, address),
            .host => |host| try resolveHostAddresses(allocator, io, host, self.port),
        };
    }
};

pub const UriRequestOptions = struct {
    method: []const u8 = "GET",
    headers: []const http3.Qpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http3.Qpack.HeaderField = &.{},
};

pub fn uriEndpoint(allocator: std.mem.Allocator, uri: std.Uri) Error!UriEndpoint {
    if (uri.user != null or uri.password != null) return error.InvalidUri;
    if (uri.scheme.len == 0 or !std.ascii.eqlIgnoreCase(uri.scheme, "https")) {
        return error.InvalidUri;
    }
    const host_component = uri.host orelse return error.InvalidUri;
    const host_storage = try uriHostToOwned(allocator, host_component);
    errdefer allocator.free(host_storage);

    const port = uri.port orelse 443;
    const authority = if (uri.port == null)
        try allocator.dupe(u8, host_storage)
    else
        try std.fmt.allocPrint(allocator, "{s}:{d}", .{ host_storage, port });
    errdefer allocator.free(authority);

    const target, const tls_host = try uriTargetForHost(host_storage, port);
    return .{
        .allocator = allocator,
        .host_storage = host_storage,
        .authority = authority,
        .port = port,
        .target = target,
        .tls_host = tls_host,
    };
}

fn uriHostToOwned(allocator: std.mem.Allocator, host: std.Uri.Component) Error![]u8 {
    var buffer: [net.HostName.max_len + 2]u8 = undefined;
    const raw = host.toRaw(&buffer) catch return error.InvalidUri;
    if (raw.len == 0) return error.InvalidUri;
    return allocator.dupe(u8, raw);
}

fn uriTargetForHost(host: []const u8, port: u16) Error!struct { UriEndpoint.Target, []const u8 } {
    if (host[0] == '[') {
        if (host[host.len - 1] != ']') return error.InvalidUri;
        const inner = host[1 .. host.len - 1];
        if (inner.len == 0) return error.InvalidUri;
        const ip6 = net.IpAddress.parseIp6(inner, port) catch return error.InvalidUri;
        return .{ .{ .ip = ip6 }, inner };
    }
    if (std.mem.indexOfScalar(u8, host, '[') != null or
        std.mem.indexOfScalar(u8, host, ']') != null)
    {
        return error.InvalidUri;
    }
    if (net.IpAddress.parse(host, port)) |address| {
        return .{ .{ .ip = address }, host };
    } else |_| {}
    return .{ .{ .host = try net.HostName.init(host) }, host };
}

fn resolveHostName(io: std.Io, host: net.HostName, port: u16) Error!net.IpAddress {
    var lookup_buffer: [32]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) = .init(&lookup_buffer);
    try net.HostName.lookup(host, io, &lookup_queue, .{ .port = port });
    var first: ?net.IpAddress = null;
    while (lookup_queue.getOne(io)) |result| {
        switch (result) {
            .address => |address| {
                if (first == null) first = address;
            },
            .canonical_name => {},
        }
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => return error.Canceled,
    }
    return first orelse error.NoAddressReturned;
}

fn resolveHostAddresses(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: net.HostName,
    port: u16,
) Error![]net.IpAddress {
    var lookup_buffer: [32]net.HostName.LookupResult = undefined;
    var lookup_queue: std.Io.Queue(net.HostName.LookupResult) = .init(&lookup_buffer);
    try net.HostName.lookup(host, io, &lookup_queue, .{ .port = port });

    var addresses: [32]net.IpAddress = undefined;
    var address_count: usize = 0;
    while (lookup_queue.getOne(io)) |result| {
        switch (result) {
            .address => |address| appendUniqueResolvedAddress(
                &addresses,
                &address_count,
                address,
            ),
            .canonical_name => {},
        }
    } else |err| switch (err) {
        error.Closed => {},
        error.Canceled => return error.Canceled,
    }
    if (address_count == 0) return error.NoAddressReturned;
    return try allocator.dupe(net.IpAddress, addresses[0..address_count]);
}

fn appendUniqueResolvedAddress(
    addresses: *[32]net.IpAddress,
    address_count: *usize,
    address: net.IpAddress,
) void {
    for (addresses[0..address_count.*]) |*existing| {
        if (existing.eql(&address)) return;
    }
    if (address_count.* == addresses.len) return;
    addresses[address_count.*] = address;
    address_count.* += 1;
}

fn resolveHostPort(io: std.Io, host: []const u8, port: u16) Error!net.IpAddress {
    if (net.IpAddress.parse(host, port)) |address| return address else |_| {}
    const host_name = try net.HostName.init(host);
    return try resolveHostName(io, host_name, port);
}

fn resolveHostPortAddresses(
    allocator: std.mem.Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
) Error![]net.IpAddress {
    if (net.IpAddress.parse(host, port)) |address| {
        return try ownedSingleAddress(allocator, address);
    } else |_| {}
    const host_name = try net.HostName.init(host);
    return try resolveHostAddresses(allocator, io, host_name, port);
}

fn ownedSingleAddress(
    allocator: std.mem.Allocator,
    address: net.IpAddress,
) std.mem.Allocator.Error![]net.IpAddress {
    const addresses = try allocator.alloc(net.IpAddress, 1);
    addresses[0] = address;
    return addresses;
}

fn uriPathAlloc(allocator: std.mem.Allocator, uri: std.Uri) Error![]u8 {
    const path_value = uriComponentBytes(uri.path);
    const path = if (path_value.len == 0) "/" else path_value;
    if (uri.query) |query| {
        return try std.fmt.allocPrint(allocator, "{s}?{s}", .{ path, uriComponentBytes(query) });
    }
    return try allocator.dupe(u8, path);
}

fn uriComponentBytes(component: std.Uri.Component) []const u8 {
    return switch (component) {
        .raw, .percent_encoded => |value| value,
    };
}

test "HTTP/3 URI endpoint parses authorities for handshake clients" {
    const allocator = std.testing.allocator;

    const host_uri = try std.Uri.parse("https://Example.COM:8443/robots.txt");
    var host_endpoint = try uriEndpoint(allocator, host_uri);
    defer host_endpoint.deinit();
    try std.testing.expectEqualStrings("Example.COM:8443", host_endpoint.authority);
    try std.testing.expectEqualStrings("Example.COM", host_endpoint.tls_host);
    try std.testing.expectEqual(@as(u16, 8443), host_endpoint.port);
    try std.testing.expect(host_endpoint.target == .host);

    const ip4_uri = try std.Uri.parse("https://127.0.0.1/");
    var ip4_endpoint = try uriEndpoint(allocator, ip4_uri);
    defer ip4_endpoint.deinit();
    try std.testing.expectEqualStrings("127.0.0.1", ip4_endpoint.authority);
    try std.testing.expectEqual(@as(u16, 443), ip4_endpoint.port);
    try std.testing.expect(ip4_endpoint.target == .ip);

    const ip6_uri = try std.Uri.parse("https://[::1]:9443/");
    var ip6_endpoint = try uriEndpoint(allocator, ip6_uri);
    defer ip6_endpoint.deinit();
    try std.testing.expectEqualStrings("[::1]:9443", ip6_endpoint.authority);
    try std.testing.expectEqualStrings("::1", ip6_endpoint.tls_host);
    try std.testing.expectEqual(@as(u16, 9443), ip6_endpoint.port);
    try std.testing.expect(ip6_endpoint.target == .ip);

    try std.testing.expectError(error.InvalidUri, uriEndpoint(allocator, try std.Uri.parse("http://example.com/")));
    try std.testing.expectError(error.InvalidUri, uriEndpoint(allocator, try std.Uri.parse("https://user@example.com/")));
}

/// Reusable protection scratch for the preconfigured-key HTTP/3 runtime.
///
/// The handshake-backed runtime owns this storage inside `one_rtt.Connection`;
/// the lightweight Protected runtime has no connection object, so it keeps the
/// same lifetime explicitly to avoid sizing allocations on every packet batch.
const ProtectedSendState = struct {
    allocator: std.mem.Allocator,
    payload_scratch: std.ArrayList(u8) = .empty,
    packet_scratch: std.ArrayList(u8) = .empty,

    fn init(allocator: std.mem.Allocator) ProtectedSendState {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *ProtectedSendState) void {
        self.payload_scratch.deinit(self.allocator);
        self.packet_scratch.deinit(self.allocator);
        self.* = undefined;
    }

    fn sendFrames(
        self: *ProtectedSendState,
        endpoint: *quic.runtime.Endpoint,
        to: net.IpAddress,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id: []const u8,
        next_packet_number: *u64,
        frames: []const quic.Frame,
        max_frames_per_packet: usize,
    ) Error!void {
        const chunk_size = @max(@as(usize, 1), max_frames_per_packet);
        var frame_offset: usize = 0;
        while (frame_offset < frames.len) {
            var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
                undefined;
            var packet_count: usize = 0;
            while (frame_offset < frames.len and packet_count < packets.len) {
                const end = @min(frames.len, frame_offset + chunk_size);
                packets[packet_count] = frames[frame_offset..end];
                packet_count += 1;
                frame_offset = end;
            }

            // Preserve the direct path for the latency-sensitive single-packet
            // case. Batch sizing and scratch management only pay off once at
            // least two UDP datagrams can share one GSO/sendmmsg submission.
            if (packet_count == 1) {
                try quic.one_rtt.sendFrames(endpoint, to, keys, .{
                    .destination_connection_id = destination_connection_id,
                    .packet_number = next_packet_number.*,
                    .frames = packets[0],
                });
                next_packet_number.* = std.math.add(
                    u64,
                    next_packet_number.*,
                    1,
                ) catch return error.InvalidPacketNumber;
                continue;
            }

            const options: quic.one_rtt.BatchSendOptions = .{
                .destination_connection_id = destination_connection_id,
                .first_packet_number = next_packet_number.*,
                .packets = packets[0..packet_count],
            };
            const sizes = try quic.one_rtt.batchStorageSizes(options);
            try self.payload_scratch.ensureTotalCapacity(
                self.allocator,
                sizes.payload,
            );
            try self.packet_scratch.ensureTotalCapacity(
                self.allocator,
                sizes.packet,
            );
            self.payload_scratch.items.len = sizes.payload;
            defer self.payload_scratch.items.len = 0;
            self.packet_scratch.items.len = sizes.packet;
            defer self.packet_scratch.items.len = 0;

            const result = try quic.one_rtt.sendFramesBatchIntoProgress(
                endpoint,
                to,
                keys,
                options,
                self.payload_scratch.items,
                self.packet_scratch.items,
            );
            // A packet number becomes consumed as soon as the socket accepts
            // its datagram. Preserve a partial batch prefix even though this
            // lightweight runtime has no retransmission queue for the suffix.
            next_packet_number.* = std.math.add(
                u64,
                next_packet_number.*,
                result.sent_count,
            ) catch return error.InvalidPacketNumber;
            if (result.send_error) |err| return err;
            std.debug.assert(result.sent_count == packet_count);
        }
    }
};

/// Lazily drains one QUIC/GRO receive batch a packet at a time.
///
/// HTTP/3 stream readers intentionally observe only one packet before returning
/// control to the application. Retaining the unconsumed suffix here preserves
/// bounded DATA windows while still amortizing the kernel receive and QUIC
/// decryption work across all GRO segments.
const ConnectionPacketCursor = struct {
    batch: ?quic.one_rtt.ReceivedPacketBatch = null,
    ack_pending: bool = false,

    fn deinit(self: *ConnectionPacketCursor) void {
        if (self.batch) |*batch| batch.deinit();
        self.* = undefined;
    }

    fn take(
        self: *ConnectionPacketCursor,
        connection: *quic.one_rtt.Connection,
    ) Error!quic.one_rtt.ReceivedPacket {
        if (self.ack_pending) {
            try connection.sendAck(0);
            self.ack_pending = false;
        }
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet| return packet;
            batch.deinit();
            self.batch = null;
        }
        if (!connection.endpoint.groReceiveEnabled()) {
            var packet = try connection.receivePacketServicingTimers();
            errdefer packet.deinit(connection.endpoint.allocator);
            _ = connection.sendAckForPacketsIfNeeded(
                @as(*const [1]quic.one_rtt.ReceivedPacket, &packet),
            ) catch {
                // Transport state has already accepted this packet. Preserve
                // application delivery and retry the cumulative ACK before
                // reading another packet rather than dropping the HTTP/3 data.
                self.ack_pending = true;
            };
            return packet;
        }
        var batch = try connection.receivePacketBatch();
        errdefer batch.deinit();
        _ = connection.sendAckForPacketsIfNeeded(
            batch.packets[batch.next_index..],
        ) catch {
            self.ack_pending = true;
        };
        const packet = batch.takeNext() orelse return error.MissingStreamFrame;
        self.batch = batch;
        return packet;
    }
};

/// Stateless-key counterpart used by the preconfigured protected runtime.
const ProtectedPacketCursor = struct {
    const Batch = struct {
        allocator: std.mem.Allocator,
        packets: []quic.one_rtt.ReceivedPacket,
        next_index: usize = 0,

        fn deinit(self: *Batch) void {
            for (self.packets[self.next_index..]) |*packet| {
                packet.deinit(self.allocator);
            }
            self.allocator.free(self.packets);
            self.* = undefined;
        }

        fn takeNext(self: *Batch) ?quic.one_rtt.ReceivedPacket {
            if (self.next_index == self.packets.len) return null;
            const packet = self.packets[self.next_index];
            self.next_index += 1;
            return packet;
        }
    };

    batch: ?Batch = null,

    fn deinit(self: *ProtectedPacketCursor) void {
        if (self.batch) |*batch| batch.deinit();
        self.* = undefined;
    }

    fn take(
        self: *ProtectedPacketCursor,
        endpoint: *quic.runtime.Endpoint,
        keys: quic.protection.PacketProtectionKeys,
        destination_connection_id_len: usize,
        expected_packet_number: *u64,
        max_frames: usize,
    ) Error!quic.one_rtt.ReceivedPacket {
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet| {
                expected_packet_number.* = packet.packet.packet_number + 1;
                return packet;
            }
            batch.deinit();
            self.batch = null;
        }

        if (!endpoint.groReceiveEnabled()) {
            const packet = try quic.one_rtt.receive(
                endpoint,
                keys,
                destination_connection_id_len,
                expected_packet_number.*,
                max_frames,
            );
            expected_packet_number.* = packet.packet.packet_number + 1;
            return packet;
        }
        var datagrams = try endpoint.receiveBytesBatch();
        defer datagrams.deinit(endpoint.allocator);
        const packets = try endpoint.allocator.alloc(
            quic.one_rtt.ReceivedPacket,
            datagrams.segment_count,
        );
        var completed: usize = 0;
        errdefer {
            for (packets[0..completed]) |*packet| {
                packet.deinit(endpoint.allocator);
            }
            endpoint.allocator.free(packets);
        }
        var next_expected = expected_packet_number.*;
        for (packets, 0..) |*packet, index| {
            const bytes = datagrams.datagramAt(index) orelse
                return error.InvalidPacket;
            packet.* = try quic.one_rtt.openReceivedBytes(
                endpoint,
                datagrams.from,
                bytes,
                keys,
                destination_connection_id_len,
                next_expected,
                max_frames,
            );
            next_expected = packet.packet.packet_number + 1;
            completed += 1;
        }
        var batch = Batch{
            .allocator = endpoint.allocator,
            .packets = packets,
        };
        const packet = batch.takeNext() orelse return error.MissingStreamFrame;
        expected_packet_number.* = packet.packet.packet_number + 1;
        self.batch = batch;
        return packet;
    }
};

pub const Limits = struct {
    quic: quic.runtime.Limits = .{},
    /// Maximum bytes buffered while reassembling one HTTP/3 request/response
    /// stream in the cleartext development runtime.  Protected/handshake
    /// runtimes already expose this via their session options; keeping the
    /// cleartext path explicit prevents large STREAM offsets from turning the
    /// UDP frame endpoint into an unbounded message buffer.
    max_stream_buffer: usize = 64 * 1024,
    /// Maximum request streams retained concurrently by server runtimes.
    /// This bounds both incomplete interleaved streams and complete streams
    /// waiting for the application or a QPACK Required Insert Count.
    max_concurrent_request_streams: usize = 128,
    /// Maximum payload bytes per QUIC STREAM frame emitted by the cleartext
    /// development runtime.  Keeping this separate from UDP datagram size lets
    /// tests and callers exercise normal HTTP/3 body fragmentation like tquic's
    /// `send_body` path instead of requiring one whole message to fit in a
    /// single UDP frame datagram.
    max_stream_frame_data: usize = 1200,
};

pub const StreamingHead = union(enum) {
    request: http3.DecodedRequestHead,
    response: http3.DecodedResponseHead,

    pub fn deinit(self: *StreamingHead, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .request => |*head| head.deinit(allocator),
            .response => |*head| head.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const StreamingEvent = union(enum) {
    head: StreamingHead,
    push_promise: PushPromise,
    data_available,
    trailers: http3.DecodedTrailers,
    finished,

    pub const PushPromise = struct {
        push_id: u64,
        request: http3.DecodedRequestHead,

        pub fn deinit(
            self: *PushPromise,
            allocator: std.mem.Allocator,
        ) void {
            self.request.deinit(allocator);
            self.* = undefined;
        }
    };

    pub fn deinit(self: *StreamingEvent, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .head => |*head| head.deinit(allocator),
            .push_promise => |*promise| promise.deinit(allocator),
            .trailers => |*trailers| trailers.deinit(allocator),
            .data_available, .finished => {},
        }
        self.* = undefined;
    }
};

/// One event from the server-side request-stream poller.
///
/// Request streams are multiplexed, so every event carries its peer and stream
/// identity. A reset is data rather than an unqualified error: otherwise an
/// application polling several streams could not determine which request was
/// cancelled.
pub const StreamingRequestEvent = union(enum) {
    message: Message,
    reset: Reset,

    pub const Message = struct {
        from: net.IpAddress,
        stream_id: u62,
        value: StreamingEvent,
    };

    pub const Reset = struct {
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    };

    pub fn deinit(
        self: *StreamingRequestEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .message => |*message| message.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

/// One event from the client-side response-stream poller.
///
/// This is the response counterpart to `StreamingRequestEvent`: applications
/// can drive all outstanding requests from one loop, then pass the reported
/// stream ID to `readResponseData` when DATA is available.
pub const StreamingResponseEvent = union(enum) {
    message: Message,
    reset: Reset,

    pub const Message = struct {
        stream_id: u62,
        value: StreamingEvent,
    };

    pub const Reset = struct {
        stream_id: u62,
        application_error_code: u64,
    };

    pub fn deinit(
        self: *StreamingResponseEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .message => |*message| message.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

/// One incremental event from a server-initiated push stream.
///
/// Push ID and QUIC stream ID are intentionally both exposed: the former
/// correlates the response with PUSH_PROMISE/CANCEL_PUSH, while the latter is
/// the QPACK section-acknowledgment and transport flow-control identity.
pub const StreamingPushEvent = struct {
    push_id: u64,
    request_stream_id: u62,
    stream_id: u62,
    value: StreamingEvent,

    pub fn deinit(
        self: *StreamingPushEvent,
        allocator: std.mem.Allocator,
    ) void {
        self.value.deinit(allocator);
        self.* = undefined;
    }
};

pub const PushedResponse = struct {
    push_id: u64,
    request_stream_id: u62,
    stream_id: u62,
    response: http3.DecodedResponse,

    pub fn deinit(
        self: *PushedResponse,
        allocator: std.mem.Allocator,
    ) void {
        self.response.deinit(allocator);
        self.* = undefined;
    }
};

pub const ServerPush = struct {
    push_id: u64,
    request: http3.Request,
    response: http3.Response,
};

pub const StreamingMessageReader = struct {
    const Kind = enum { request, response };
    const Phase = enum {
        initial_headers,
        body,
        trailers,
        done,
    };

    allocator: std.mem.Allocator,
    receive: quic.stream_state.RecvState,
    settings: http3.Settings,
    kind: Kind,
    push_promises_allowed: bool = false,
    phase: Phase = .initial_headers,
    current_frame: ?http3.Frame.Header = null,
    current_header_consumed: bool = false,
    current_payload_read: usize = 0,
    body_read: usize = 0,
    content_length: ?usize = null,
    body_allowed: bool = true,
    final_observed: bool = false,
    /// Absolute HTTP/3 stream offset already returned to QUIC flow control.
    credited_offset: usize = 0,

    pub fn initRequest(
        allocator: std.mem.Allocator,
        stream_id: u64,
        max_buffered: usize,
        settings: http3.Settings,
    ) StreamingMessageReader {
        return .{
            .allocator = allocator,
            .receive = .init(allocator, stream_id, max_buffered),
            .settings = settings,
            .kind = .request,
        };
    }

    pub fn initResponse(
        allocator: std.mem.Allocator,
        stream_id: u64,
        max_buffered: usize,
        settings: http3.Settings,
    ) StreamingMessageReader {
        return .{
            .allocator = allocator,
            .receive = .init(allocator, stream_id, max_buffered),
            .settings = settings,
            .kind = .response,
            .push_promises_allowed = true,
        };
    }

    pub fn deinit(self: *StreamingMessageReader) void {
        self.receive.deinit();
        self.* = undefined;
    }

    pub fn insert(
        self: *StreamingMessageReader,
        frame: quic.StreamFrame,
    ) Error!void {
        try self.receive.insert(frame);
        if (frame.fin) self.final_observed = true;
    }

    pub fn next(
        self: *StreamingMessageReader,
        table: http3.Qpack.DynamicTable,
    ) Error!?StreamingEvent {
        if (self.phase == .done) return null;
        while (true) {
            if (self.current_frame == null) {
                const available = self.receive.available();
                if (available.len == 0) {
                    if (self.receive.complete()) {
                        return self.finishAtStreamEnd();
                    }
                    return null;
                }
                const header = http3.Frame.parseHeader(available) catch |err| switch (err) {
                    error.BufferTooShort => return null,
                    else => return err,
                };
                self.current_frame = header;
                self.current_header_consumed = false;
                self.current_payload_read = 0;
                // QPACK field sections remain wholly unconsumed until semantic
                // decoding succeeds, making QpackBlocked/OOM retryable without
                // cloning the receive window. DATA and ignorable frames can
                // commit their header immediately.
                if (header.frame_type != http3.FrameType.headers and
                    header.frame_type != http3.FrameType.push_promise)
                {
                    try self.receive.consume(header.header_length);
                    self.current_header_consumed = true;
                }
            }
            const header = self.current_frame.?;
            switch (header.frame_type) {
                http3.FrameType.headers => {
                    const total_length = try header.totalLength();
                    if (self.receive.available().len < total_length) {
                        if (self.framePayloadTruncated()) {
                            return error.BufferTooShort;
                        }
                        return null;
                    }
                    const payload = self.receive.available()[header.header_length..total_length];
                    if (self.phase == .initial_headers) {
                        var final_head = true;
                        const event = switch (self.kind) {
                            .request => blk: {
                                var head = try http3.decodeRequestHeadFieldSectionWithDynamicTable(
                                    self.allocator,
                                    payload,
                                    self.settings,
                                    table,
                                );
                                head.consumed =
                                    header.header_length +
                                    header.payload_length;
                                self.content_length = head.content_length;
                                self.body_allowed = head.body_allowed;
                                break :blk StreamingEvent{
                                    .head = .{ .request = head },
                                };
                            },
                            .response => blk: {
                                var head = try http3.decodeResponseHeadFieldSectionWithDynamicTable(
                                    self.allocator,
                                    payload,
                                    self.settings,
                                    table,
                                );
                                head.consumed =
                                    header.header_length +
                                    header.payload_length;
                                final_head = head.status >= 200;
                                if (final_head) {
                                    self.content_length = head.content_length;
                                    self.body_allowed = head.body_allowed;
                                }
                                break :blk StreamingEvent{
                                    .head = .{ .response = head },
                                };
                            },
                        };
                        try self.receive.consume(total_length);
                        self.current_frame = null;
                        self.current_header_consumed = false;
                        if (final_head) self.phase = .body;
                        return event;
                    }
                    if (self.phase != .body) return error.UnexpectedFrame;
                    if (!self.body_allowed) return error.InvalidContentLength;
                    const trailers = try http3.decodeTrailersWithDynamicTable(
                        self.allocator,
                        payload,
                        self.settings,
                        table,
                    );
                    try self.receive.consume(total_length);
                    self.current_frame = null;
                    self.current_header_consumed = false;
                    self.phase = .trailers;
                    return .{ .trailers = trailers };
                },
                http3.FrameType.push_promise => {
                    if (self.kind != .response or
                        !self.push_promises_allowed or
                        self.phase == .trailers)
                    {
                        return error.UnexpectedFrame;
                    }
                    const total_length = try header.totalLength();
                    if (self.receive.available().len < total_length) {
                        if (self.framePayloadTruncated()) {
                            return error.BufferTooShort;
                        }
                        return null;
                    }
                    const payload = self.receive.available()[header.header_length..total_length];
                    var promise = try http3
                        .decodePushPromiseWithDynamicTable(
                        self.allocator,
                        payload,
                        self.settings,
                        table,
                    );
                    errdefer promise.deinit(self.allocator);
                    try self.receive.consume(total_length);
                    self.current_frame = null;
                    self.current_header_consumed = false;
                    return .{ .push_promise = .{
                        .push_id = promise.push_id,
                        .request = promise.request,
                    } };
                },
                http3.FrameType.data => {
                    if (self.phase != .body) return error.UnexpectedFrame;
                    if (!self.body_allowed and header.payload_length != 0) {
                        return error.InvalidContentLength;
                    }
                    const next_body = std.math.add(
                        usize,
                        self.body_read,
                        header.payload_length - self.current_payload_read,
                    ) catch return error.InvalidContentLength;
                    if (self.content_length) |expected| {
                        if (next_body > expected) return error.InvalidContentLength;
                    }
                    if (header.payload_length == 0) {
                        self.current_frame = null;
                        self.current_header_consumed = false;
                        continue;
                    }
                    if (self.receive.available().len == 0) {
                        if (self.framePayloadTruncated()) {
                            return error.BufferTooShort;
                        }
                        return null;
                    }
                    return .data_available;
                },
                else => {
                    if (streamingForbiddenFrame(header.frame_type)) {
                        return error.UnexpectedFrame;
                    }
                    const remaining = header.payload_length - self.current_payload_read;
                    const skip = @min(remaining, self.receive.available().len);
                    try self.receive.consume(skip);
                    self.current_payload_read += skip;
                    if (self.current_payload_read == header.payload_length) {
                        self.current_frame = null;
                        self.current_header_consumed = false;
                        continue;
                    }
                    if (self.framePayloadTruncated()) {
                        return error.BufferTooShort;
                    }
                    return null;
                },
            }
        }
    }

    pub fn readData(
        self: *StreamingMessageReader,
        out: []u8,
    ) Error!usize {
        const header = self.current_frame orelse return error.UnexpectedFrame;
        if (header.frame_type != http3.FrameType.data or self.phase != .body) {
            return error.UnexpectedFrame;
        }
        const remaining = header.payload_length - self.current_payload_read;
        const count = @min(remaining, @min(out.len, self.receive.available().len));
        if (count == 0) return 0;
        @memcpy(out[0..count], self.receive.available()[0..count]);
        try self.receive.consume(count);
        self.current_payload_read += count;
        self.body_read += count;
        if (self.current_payload_read == header.payload_length) {
            self.current_frame = null;
            self.current_header_consumed = false;
            self.current_payload_read = 0;
        }
        return count;
    }

    pub fn skipData(self: *StreamingMessageReader) Error!usize {
        const header = self.current_frame orelse return error.UnexpectedFrame;
        if (header.frame_type != http3.FrameType.data or self.phase != .body) {
            return error.UnexpectedFrame;
        }
        const remaining = header.payload_length - self.current_payload_read;
        const count = @min(remaining, self.receive.available().len);
        if (count == 0) return 0;
        try self.receive.consume(count);
        self.current_payload_read += count;
        self.body_read += count;
        if (self.current_payload_read == header.payload_length) {
            self.current_frame = null;
            self.current_header_consumed = false;
            self.current_payload_read = 0;
        }
        return count;
    }

    fn uncreditedConsumed(self: StreamingMessageReader) usize {
        std.debug.assert(self.receive.read_offset >= self.credited_offset);
        return self.receive.read_offset - self.credited_offset;
    }

    fn markCredited(self: *StreamingMessageReader, amount: usize) void {
        std.debug.assert(amount <= self.uncreditedConsumed());
        self.credited_offset += amount;
    }

    fn finishAtStreamEnd(self: *StreamingMessageReader) Error!?StreamingEvent {
        if (self.current_frame != null) return error.BufferTooShort;
        if (self.phase == .initial_headers) return error.ExpectedHeadersFrame;
        if (self.content_length) |expected| {
            if (self.body_read != expected) return error.InvalidContentLength;
        }
        self.phase = .done;
        return .finished;
    }

    fn framePayloadTruncated(self: StreamingMessageReader) bool {
        const header = self.current_frame orelse return false;
        const final_size = self.receive.final_size orelse return false;
        const remaining = header.payload_length - self.current_payload_read;
        const unconsumed_header = if (self.current_header_consumed)
            0
        else
            header.header_length;
        const required_end = std.math.add(
            usize,
            self.receive.read_offset,
            std.math.add(
                usize,
                unconsumed_header,
                remaining,
            ) catch return true,
        ) catch return true;
        return required_end > final_size;
    }

    /// Whether abandoning the current field section requires a QPACK Stream
    /// Cancellation instruction.
    ///
    /// HEADERS and PUSH_PROMISE bytes remain unconsumed until decoding succeeds.
    /// Consequently a complete dynamic prefix here identifies a section that
    /// has not emitted a Section Acknowledgment yet, regardless of whether its
    /// required inserts have since arrived.
    fn hasUnacknowledgedDynamicSection(
        self: StreamingMessageReader,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const available = self.receive.available();
        var offset: usize = 0;
        if (self.current_frame) |current| {
            if (frameCarriesFieldSection(current.frame_type)) {
                return frameFieldSectionUsesDynamicTable(
                    available,
                    current,
                    table,
                );
            }
            // Frames without field sections commit their headers eagerly. Skip
            // the unconsumed payload before scanning complete frames queued
            // behind it (notably dynamic trailers or promises).
            const remaining =
                current.payload_length - self.current_payload_read;
            if (available.len < remaining) return false;
            offset = remaining;
        }
        while (offset < available.len) {
            const header = http3.Frame.parseHeader(
                available[offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => return false,
                else => return err,
            };
            if (frameCarriesFieldSection(header.frame_type) and
                try frameFieldSectionUsesDynamicTable(
                    available[offset..],
                    header,
                    table,
                ))
            {
                return true;
            }
            const frame_length = try header.totalLength();
            if (available.len - offset < frame_length) return false;
            offset += frame_length;
        }
        return false;
    }
};

fn frameCarriesFieldSection(frame_type: u64) bool {
    return frame_type == http3.FrameType.headers or
        frame_type == http3.FrameType.push_promise;
}

fn frameFieldSectionUsesDynamicTable(
    bytes: []const u8,
    header: http3.Frame.Header,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    if (bytes.len <= header.header_length) return false;
    const payload_available = @min(
        header.payload_length,
        bytes.len - header.header_length,
    );
    const payload = bytes[header.header_length..][0..payload_available];
    const field_section = if (header.frame_type ==
        http3.FrameType.push_promise)
        (http3.parsePushPromisePayload(payload) catch |err| switch (err) {
            error.BufferTooShort => return false,
            else => return err,
        }).field_section
    else
        payload;
    const prefix = http3.Qpack.decodeFieldSectionPrefix(
        field_section,
        table,
    ) catch |err| switch (err) {
        error.BufferTooShort => return false,
        else => return err,
    };
    return prefix.required_insert_count != 0;
}

fn streamingForbiddenFrame(frame_type: u64) bool {
    return switch (frame_type) {
        http3.FrameType.cancel_push,
        http3.FrameType.settings,
        http3.FrameType.goaway,
        http3.FrameType.max_push_id,
        http3.FrameType.priority_update_request,
        http3.FrameType.priority_update_push,
        => true,
        else => false,
    };
}

/// Connection-scoped receive side of QPACK.
///
/// Encoder-stream bytes are QUIC stream data, so instructions can be split,
/// duplicated, or delivered out of order. This state reassembles that stream,
/// applies only complete instructions, and coalesces decoder feedback without
/// losing the trailing partial instruction.
pub const QpackDecodeState = struct {
    allocator: std.mem.Allocator,
    table: http3.Qpack.DynamicTable,
    encoder_stream: ?quic.stream_state.RecvState = null,
    encoder_stream_type_received: bool = false,
    decoder_instructions: std.ArrayList(u8) = .empty,
    acknowledged_insert_count: u64 = 0,
    max_stream_buffer: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_table_capacity: usize,
        max_stream_buffer: usize,
    ) QpackDecodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, max_table_capacity),
            .max_stream_buffer = max_stream_buffer,
        };
    }

    pub fn deinit(self: *QpackDecodeState) void {
        if (self.encoder_stream) |*stream| stream.deinit();
        self.table.deinit();
        self.decoder_instructions.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn applyEncoderStreamFrame(
        self: *QpackDecodeState,
        control: *http3.ControlState,
        stream: quic.StreamFrame,
    ) Error!void {
        if (stream.fin) return error.ClosedCriticalStream;
        if (self.encoder_stream == null) {
            self.encoder_stream = quic.stream_state.RecvState.init(
                self.allocator,
                stream.stream_id,
                self.max_stream_buffer,
            );
        }
        const receive = &self.encoder_stream.?;
        try receive.insert(stream);

        // Consume and validate the stream type independently from instruction
        // framing. It can itself be split across retransmitted STREAM frames.
        if (!self.encoder_stream_type_received) {
            const available = receive.available();
            if (available.len == 0) return;
            const prefix = quic.varint.decodeSlice(available) catch |err| switch (err) {
                error.BufferTooShort => return,
                else => return error.QpackEncoderStreamError,
            };
            if (@as(http3.StreamType, @enumFromInt(prefix.value)) != .qpack_encoder) {
                return error.InvalidStreamType;
            }
            try control.registerQpackStream(.qpack_encoder, stream.stream_id);
            try receive.consume(prefix.len);
            self.encoder_stream_type_received = true;
        }

        // One Insert Count Increment encoded with a 6-bit prefix needs at
        // most 11 bytes for a u64. Reserve before mutating the dynamic table so
        // allocation failure leaves both stream consumption and table state
        // retryable.
        try self.decoder_instructions.ensureUnusedCapacity(self.allocator, 11);
        var inserted_total: u64 = 0;
        while (receive.available().len != 0) {
            const available = receive.available();
            var decoded = http3.Qpack.decodeEncoderInstruction(
                self.allocator,
                available,
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                error.OutOfMemory => return err,
                else => return error.QpackEncoderStreamError,
            };
            defer decoded.deinit(self.allocator);
            const before = self.table.insert_count;
            applyDecodedEncoderInstruction(&self.table, decoded.instruction) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => return error.QpackEncoderStreamError,
            };
            try receive.consume(decoded.consumed);
            inserted_total = std.math.add(
                u64,
                inserted_total,
                self.table.insert_count - before,
            ) catch return error.QpackDecoderStreamError;
        }
        if (inserted_total != 0) try self.recordInsertCount(inserted_total);
    }

    pub fn decodeFieldSection(
        self: *QpackDecodeState,
        allocator: std.mem.Allocator,
        stream_id: u64,
        block: []const u8,
    ) Error!http3.Qpack.DynamicBlockDecode {
        // Section Acknowledgment uses a 7-bit prefix and has the same 11-byte
        // worst case. Reserve before allocating/decoding the field section so
        // an OOM cannot strand a successfully decoded result without feedback.
        try self.decoder_instructions.ensureUnusedCapacity(self.allocator, 11);
        const decoded = try http3.Qpack.decodeDynamicBlock(
            allocator,
            block,
            self.table,
        );
        if (decoded.required_insert_count != 0) {
            try http3.Qpack.writeDecoderInstruction(
                &self.decoder_instructions,
                self.allocator,
                .{ .section_acknowledgment = stream_id },
            );
        }
        return decoded;
    }

    /// Transfer pending decoder instructions to the caller. Ownership is
    /// explicit because returning a borrowed slice and then clearing the
    /// ArrayList would let later appends overwrite bytes before the transport
    /// sends them.
    pub fn takeDecoderInstructions(self: *QpackDecodeState) std.mem.Allocator.Error![]u8 {
        return self.decoder_instructions.toOwnedSlice(self.allocator);
    }

    pub fn pendingDecoderInstructions(self: QpackDecodeState) []const u8 {
        return self.decoder_instructions.items;
    }

    pub fn clearDecoderInstructions(self: *QpackDecodeState) void {
        self.decoder_instructions.clearRetainingCapacity();
    }

    pub fn acknowledgeSections(
        self: *QpackDecodeState,
        stream_id: u64,
        count: usize,
    ) Error!void {
        try self.decoder_instructions.ensureUnusedCapacity(
            self.allocator,
            11 *| count,
        );
        for (0..count) |_| {
            try http3.Qpack.writeDecoderInstruction(
                &self.decoder_instructions,
                self.allocator,
                .{ .section_acknowledgment = stream_id },
            );
        }
    }

    pub fn recordStreamCancellation(
        self: *QpackDecodeState,
        stream_id: u64,
    ) Error!void {
        try http3.Qpack.writeDecoderInstruction(
            &self.decoder_instructions,
            self.allocator,
            .{ .stream_cancellation = stream_id },
        );
    }

    fn recordInsertCount(self: *QpackDecodeState, inserted: u64) Error!void {
        const next = std.math.add(u64, self.acknowledged_insert_count, inserted) catch
            return error.QpackDecoderStreamError;
        try http3.Qpack.writeDecoderInstruction(
            &self.decoder_instructions,
            self.allocator,
            .{ .insert_count_increment = inserted },
        );
        self.acknowledged_insert_count = next;
    }
};

fn applyDecodedEncoderInstruction(
    table: *http3.Qpack.DynamicTable,
    instruction: http3.Qpack.EncoderInstruction,
) Error!void {
    switch (instruction) {
        .set_capacity => |capacity| try table.setCapacity(
            std.math.cast(usize, capacity) orelse return error.QpackEncoderStreamError,
        ),
        .duplicate => |index| _ = try table.duplicate(index),
        .insert_literal => |literal| _ = try table.insert(literal.name, literal.value),
        .insert_name_reference => |reference| {
            const name = if (reference.static) blk: {
                const entry = http3.Qpack.staticEntry(
                    std.math.cast(usize, reference.name_index) orelse
                        return error.QpackEncoderStreamError,
                ) orelse return error.QpackEncoderStreamError;
                break :blk entry.name;
            } else blk: {
                const entry = table.relative(reference.name_index) orelse
                    return error.QpackEncoderStreamError;
                break :blk entry.name;
            };
            _ = try table.insert(name, reference.value);
        },
    }
}

pub const QpackEncodeState = struct {
    const PendingSection = struct {
        stream_id: u64,
        required_insert_count: u64,
        references: []u64,

        fn deinit(self: *PendingSection, allocator: std.mem.Allocator) void {
            allocator.free(self.references);
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    table: http3.Qpack.DynamicTable,
    known_received_count: u64 = 0,
    pending_sections: std.ArrayList(PendingSection) = .empty,
    /// First pending field section per stream. QPACK decoder feedback names
    /// streams rather than individual sections, and sections on the same stream
    /// must be acknowledged/cancelled in FIFO order, so this index points at
    /// the earliest retained section for each stream.
    pending_section_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    reference_counts: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    encoder_instructions: std.ArrayList(u8) = .empty,
    decoder_stream: ?quic.stream_state.RecvState = null,
    decoder_stream_type_received: bool = false,
    peer_max_capacity: ?usize = null,
    max_stream_buffer: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        peer_max_capacity: usize,
        max_stream_buffer: usize,
    ) QpackEncodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, peer_max_capacity),
            .peer_max_capacity = peer_max_capacity,
            .max_stream_buffer = max_stream_buffer,
        };
    }

    /// Create an encoder before the peer's SETTINGS frame is available.
    ///
    /// The zero-capacity table cannot queue inserts until
    /// `configurePeerCapacity` binds it to the immutable advertised limit.
    pub fn initAwaitingPeerSettings(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
    ) QpackEncodeState {
        return .{
            .allocator = allocator,
            .table = .init(allocator, 0),
            .max_stream_buffer = max_stream_buffer,
        };
    }

    pub fn deinit(self: *QpackEncodeState) void {
        if (self.decoder_stream) |*stream| stream.deinit();
        for (self.pending_sections.items) |*section| section.deinit(self.allocator);
        self.pending_sections.deinit(self.allocator);
        self.pending_section_index.deinit(self.allocator);
        self.reference_counts.deinit(self.allocator);
        self.encoder_instructions.deinit(self.allocator);
        self.table.deinit();
        self.* = undefined;
    }

    pub fn setCapacity(
        self: *QpackEncodeState,
        capacity: usize,
    ) http3.Error!void {
        try self.ensureEvictableForCapacity(capacity);
        const original_len = self.encoder_instructions.items.len;
        errdefer self.encoder_instructions.shrinkRetainingCapacity(original_len);
        try http3.Qpack.writeEncoderInstruction(
            &self.encoder_instructions,
            self.allocator,
            .{ .set_capacity = capacity },
        );
        try self.table.setCapacity(capacity);
    }

    pub fn configurePeerCapacity(
        self: *QpackEncodeState,
        capacity: usize,
    ) http3.Error!void {
        if (self.peer_max_capacity) |configured| {
            if (configured != capacity) return error.QpackEncoderStreamError;
            return;
        }
        if (self.table.insert_count != 0 or self.table.entryCount() != 0) {
            return error.QpackEncoderStreamError;
        }
        const previous_max_capacity = self.table.max_capacity;
        errdefer self.table.max_capacity = previous_max_capacity;
        self.table.max_capacity = capacity;
        if (capacity != 0) try self.setCapacity(capacity);
        self.peer_max_capacity = capacity;
    }

    pub fn insertField(
        self: *QpackEncodeState,
        name: []const u8,
        value: []const u8,
    ) http3.Error!?u64 {
        const entry_size = std.math.add(
            usize,
            std.math.add(usize, name.len, value.len) catch
                return error.QpackEncoderStreamError,
            http3.Qpack.dynamic_entry_overhead,
        ) catch return error.QpackEncoderStreamError;
        if (entry_size > self.table.capacity) return null;
        if (!self.canEvictForInsert(entry_size)) return null;

        var instruction: http3.Qpack.EncoderInstruction = undefined;
        if (findQpackStaticName(name)) |index| {
            instruction = .{ .insert_name_reference = .{
                .static = true,
                .name_index = index,
                .value = value,
            } };
        } else if (self.table.findName(name)) |absolute_index| {
            const relative = self.table.insert_count - absolute_index - 1;
            instruction = .{ .insert_name_reference = .{
                .static = false,
                .name_index = relative,
                .value = value,
            } };
        } else {
            instruction = .{ .insert_literal = .{ .name = name, .value = value } };
        }
        const original_len = self.encoder_instructions.items.len;
        errdefer self.encoder_instructions.shrinkRetainingCapacity(original_len);
        try http3.Qpack.writeEncoderInstruction(
            &self.encoder_instructions,
            self.allocator,
            instruction,
        );
        return try self.table.insert(name, value);
    }

    pub fn encodeFieldSection(
        self: *QpackEncodeState,
        list: *std.ArrayList(u8),
        stream_id: u64,
        fields: []const http3.Qpack.HeaderField,
    ) http3.Error!void {
        const original_len = list.items.len;
        errdefer list.shrinkRetainingCapacity(original_len);
        var references: std.ArrayList(u64) = .empty;
        errdefer references.deinit(self.allocator);
        try http3.Qpack.encodeDynamicBlockKnownReceived(
            list,
            self.allocator,
            fields,
            self.table,
            self.known_received_count,
            &references,
        );
        if (references.items.len == 0) {
            references.deinit(self.allocator);
            return;
        }

        const owned = try references.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned);
        try self.pending_sections.ensureUnusedCapacity(self.allocator, 1);
        const pending_slot = try self.pending_section_index.getOrPut(
            self.allocator,
            stream_id,
        );
        errdefer if (!pending_slot.found_existing) {
            _ = self.pending_section_index.remove(stream_id);
        };
        // `encodeDynamicBlockKnownReceived` already deduplicates references
        // within this field section. Reserve the section's full reference
        // count as a safe upper bound and update counts in one hash-map pass
        // instead of probing once with `contains` and again with `getOrPut`.
        try self.reference_counts.ensureUnusedCapacity(
            self.allocator,
            std.math.cast(u32, owned.len) orelse
                return error.OutOfMemory,
        );
        for (owned) |absolute_index| {
            const entry = self.reference_counts.getOrPutAssumeCapacity(
                absolute_index,
            );
            if (!entry.found_existing) entry.value_ptr.* = 0;
            entry.value_ptr.* += 1;
        }
        const pending_index = self.pending_sections.items.len;
        self.pending_sections.appendAssumeCapacity(.{
            .stream_id = stream_id,
            .required_insert_count = maxReferencedInsertCount(owned),
            .references = owned,
        });
        if (!pending_slot.found_existing) {
            pending_slot.value_ptr.* = pending_index;
        }
    }

    pub fn applyDecoderStreamFrame(
        self: *QpackEncodeState,
        control: *http3.ControlState,
        stream: quic.StreamFrame,
    ) Error!void {
        if (stream.fin) return error.ClosedCriticalStream;
        if (self.decoder_stream == null) {
            self.decoder_stream = quic.stream_state.RecvState.init(
                self.allocator,
                stream.stream_id,
                self.max_stream_buffer,
            );
        }
        const receive = &self.decoder_stream.?;
        try receive.insert(stream);
        if (!self.decoder_stream_type_received) {
            const available = receive.available();
            if (available.len == 0) return;
            const prefix = quic.varint.decodeSlice(available) catch |err| switch (err) {
                error.BufferTooShort => return,
                else => return error.QpackDecoderStreamError,
            };
            if (@as(http3.StreamType, @enumFromInt(prefix.value)) != .qpack_decoder) {
                return error.InvalidStreamType;
            }
            try control.registerQpackStream(.qpack_decoder, stream.stream_id);
            try receive.consume(prefix.len);
            self.decoder_stream_type_received = true;
        }

        while (receive.available().len != 0) {
            const decoded = http3.Qpack.decodeDecoderInstruction(
                receive.available(),
            ) catch |err| switch (err) {
                error.BufferTooShort => break,
                else => return error.QpackDecoderStreamError,
            };
            try self.applyDecoderInstruction(decoded.instruction);
            try receive.consume(decoded.consumed);
        }
    }

    pub fn pendingEncoderInstructions(self: QpackEncodeState) []const u8 {
        return self.encoder_instructions.items;
    }

    pub fn clearEncoderInstructions(self: *QpackEncodeState) void {
        self.encoder_instructions.clearRetainingCapacity();
    }

    pub fn abandonStream(self: *QpackEncodeState, stream_id: u64) void {
        _ = self.releaseSectionsForStream(stream_id);
    }

    pub fn hasPendingSections(self: QpackEncodeState, stream_id: u64) bool {
        return self.pending_section_index.count() != 0 and
            self.pending_section_index.contains(stream_id);
    }

    fn rollbackPendingSections(self: *QpackEncodeState, original_len: usize) void {
        while (self.pending_sections.items.len > original_len) {
            self.releaseSection(self.pending_sections.items.len - 1);
        }
    }

    fn applyDecoderInstruction(
        self: *QpackEncodeState,
        instruction: http3.Qpack.DecoderInstruction,
    ) Error!void {
        switch (instruction) {
            .insert_count_increment => |increment| {
                const next = std.math.add(
                    u64,
                    self.known_received_count,
                    increment,
                ) catch return error.QpackDecoderStreamError;
                if (next > self.table.insert_count) return error.QpackDecoderStreamError;
                self.known_received_count = next;
            },
            .section_acknowledgment => |stream_id| {
                const index = self.findPendingSection(stream_id) orelse
                    return error.QpackDecoderStreamError;
                const required_insert_count =
                    self.pending_sections.items[index].required_insert_count;
                self.releaseSection(index);
                // Section Ack implicitly acknowledges all inserts up to RIC.
                self.known_received_count = @max(
                    self.known_received_count,
                    required_insert_count,
                );
            },
            .stream_cancellation => |stream_id| {
                if (self.releaseSectionsForStream(stream_id) == 0) {
                    return error.QpackDecoderStreamError;
                }
            },
        }
    }

    fn findPendingSection(self: QpackEncodeState, stream_id: u64) ?usize {
        if (self.pending_section_index.count() == 0) return null;
        return self.pending_section_index.get(stream_id);
    }

    fn releaseSection(self: *QpackEncodeState, index: usize) void {
        var section = if (index == self.pending_sections.items.len - 1)
            self.pending_sections.pop().?
        else
            self.pending_sections.orderedRemove(index);
        const removed_stream_id = section.stream_id;
        const removed_was_first =
            self.pending_section_index.get(removed_stream_id) == index;
        if (removed_was_first) {
            _ = self.pending_section_index.remove(removed_stream_id);
        }
        if (index < self.pending_sections.items.len) {
            self.repairPendingSectionIndexFrom(index);
        }
        self.releaseSectionReferences(&section);
    }

    fn releaseSectionReferences(
        self: *QpackEncodeState,
        section: *PendingSection,
    ) void {
        for (section.references) |absolute_index| {
            const count = self.reference_counts.getPtr(absolute_index).?;
            count.* -= 1;
            if (count.* == 0) _ = self.reference_counts.remove(absolute_index);
        }
        section.deinit(self.allocator);
    }

    fn releaseSectionsForStream(
        self: *QpackEncodeState,
        stream_id: u64,
    ) usize {
        if (self.pending_section_index.count() == 0) return 0;
        const start_index = self.pending_section_index.get(stream_id) orelse return 0;
        var write_index: usize = start_index;
        var released: usize = 0;
        for (self.pending_sections.items[start_index..], start_index..) |section, read_index| {
            if (section.stream_id == stream_id) {
                // QPACK Section Acknowledgment identifies only the stream, so
                // multiple outstanding header/trailer sections on the same
                // stream must retain FIFO order.  Compact in one stable pass
                // instead of repeated `orderedRemove` memmoves or
                // `swapRemove`-based reordering.
                var removed = section;
                self.releaseSectionReferences(&removed);
                released += 1;
                continue;
            }
            if (write_index != read_index) {
                self.pending_sections.items[write_index] = section;
            }
            write_index += 1;
        }
        self.pending_sections.items.len = write_index;
        _ = self.pending_section_index.remove(stream_id);
        self.repairPendingSectionIndexFrom(start_index);
        return released;
    }

    fn rebuildPendingSectionIndexAssumeCapacity(self: *QpackEncodeState) void {
        self.pending_section_index.clearRetainingCapacity();
        for (self.pending_sections.items, 0..) |section, index| {
            if (!self.pending_section_index.contains(section.stream_id)) {
                self.pending_section_index.putAssumeCapacityNoClobber(
                    section.stream_id,
                    index,
                );
            }
        }
    }

    fn repairPendingSectionIndexFrom(
        self: *QpackEncodeState,
        start_index: usize,
    ) void {
        var index = start_index;
        while (index < self.pending_sections.items.len) : (index += 1) {
            const stream_id = self.pending_sections.items[index].stream_id;
            if (self.pending_section_index.getPtr(stream_id)) |mapped| {
                if (mapped.* > index) mapped.* = index;
            } else {
                self.pending_section_index.putAssumeCapacityNoClobber(
                    stream_id,
                    index,
                );
            }
        }
    }

    fn canEvictForInsert(
        self: QpackEncodeState,
        incoming_size: usize,
    ) bool {
        var simulated_size = self.table.current_size;
        var index = self.table.head;
        while (simulated_size > self.table.capacity or
            incoming_size > self.table.capacity - simulated_size)
        {
            if (index >= self.table.entries.items.len) return false;
            const entry = self.table.entries.items[index];
            if (!self.entryEvictable(entry.absolute_index)) return false;
            simulated_size -= entry.size();
            index += 1;
        }
        return true;
    }

    fn ensureEvictableForCapacity(
        self: QpackEncodeState,
        capacity: usize,
    ) http3.Error!void {
        if (capacity > self.table.max_capacity) return error.QpackEncoderStreamError;
        var simulated_size = self.table.current_size;
        var index = self.table.head;
        while (simulated_size > capacity) {
            const entry = self.table.entries.items[index];
            if (!self.entryEvictable(entry.absolute_index)) return error.QpackEncoderStreamError;
            simulated_size -= entry.size();
            index += 1;
        }
    }

    fn entryEvictable(self: QpackEncodeState, absolute_index: u64) bool {
        if (absolute_index >= self.known_received_count) return false;
        return self.reference_counts.count() == 0 or
            !self.reference_counts.contains(absolute_index);
    }

    fn maxReferencedInsertCount(references: []const u64) u64 {
        var required_insert_count: u64 = 0;
        for (references) |absolute_index| {
            required_insert_count = @max(
                required_insert_count,
                absolute_index + 1,
            );
        }
        return required_insert_count;
    }
};

fn findQpackStaticName(name: []const u8) ?u64 {
    return http3.Qpack.findStaticName(name);
}

pub const Server = struct {
    quic_server: quic.runtime.Server,
    limits: Limits = .{},

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .quic_server = try .bind(allocator, io, bind_address, limits.quic), .limits = limits };
    }

    pub fn deinit(self: *Server) void {
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *Server) Error!OwnedRequest {
        var assembled = try receiveRuntimeStreamBytes(&self.quic_server.endpoint, null, self.limits.max_stream_buffer);
        errdefer assembled.deinit(self.quic_server.endpoint.allocator);
        var request = try http3.decodeRequest(self.quic_server.endpoint.allocator, assembled.bytes);
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        const owned_parts = try assembled.intoOwnedParts(self.quic_server.endpoint.allocator);
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .datagram = owned_parts.datagram,
            .extra_datagrams = owned_parts.extra_datagrams,
            .bytes = owned_parts.bytes,
            .request = request,
        };
    }

    pub fn receiveRequestsConcurrent(self: *Server, count: usize) Error!OwnedRequestBatch {
        var group: std.Io.Group = .init;
        const requests = try self.quic_server.endpoint.allocator.alloc(?OwnedRequest, count);
        errdefer self.quic_server.endpoint.allocator.free(requests);
        @memset(requests, null);
        const errors = try self.quic_server.endpoint.allocator.alloc(?anyerror, count);
        errdefer self.quic_server.endpoint.allocator.free(errors);
        @memset(errors, null);

        for (requests, errors) |*request, *err_slot| {
            const task = RequestTask{
                .server = self,
                .request = request,
                .err = err_slot,
            };
            group.async(self.quic_server.endpoint.io, RequestTask.run, .{task});
        }

        try group.await(self.quic_server.endpoint.io);
        return .{ .allocator = self.quic_server.endpoint.allocator, .requests = requests, .errors = errors };
    }

    pub fn sendResponse(self: *Server, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(to, stream_id, &.{}, response);
    }

    pub fn sendResponseWithInformational(
        self: *Server,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        try http3.writeResponseSequence(&encoded, self.quic_server.endpoint.allocator, informational, response);
        try sendRuntimeStreamMessage(&self.quic_server.endpoint, to, stream_id, encoded.items, self.limits.max_stream_frame_data);
    }
};

const RequestTask = struct {
    server: *Server,
    request: *?OwnedRequest,
    err: *?anyerror,

    fn run(task: RequestTask) std.Io.Cancelable!void {
        task.request.* = task.server.receiveRequest() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

pub const Client = struct {
    quic_client: quic.runtime.Client,
    limits: Limits = .{},
    next_stream_id: u62 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits) Error!Client {
        return .{ .quic_client = try .connect(allocator, io, local_address, server, limits.quic), .limits = limits };
    }

    pub fn deinit(self: *Client) void {
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.quic_client.address();
    }

    pub fn request(self: *Client, request_options: http3.Request) Error!OwnedResponse {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // client-initiated bidirectional stream ids.

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.write(&encoded, self.quic_client.endpoint.allocator);

        try sendRuntimeStreamMessage(&self.quic_client.endpoint, self.quic_client.peer, stream_id, encoded.items, self.limits.max_stream_frame_data);

        var assembled = try receiveRuntimeStreamBytes(&self.quic_client.endpoint, stream_id, self.limits.max_stream_buffer);
        errdefer assembled.deinit(self.quic_client.endpoint.allocator);
        try http3.validateResponsePushPromises(.{}, assembled.bytes);
        var response = try http3.decodeResponse(self.quic_client.endpoint.allocator, assembled.bytes);
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        const owned_parts = try assembled.intoOwnedParts(self.quic_client.endpoint.allocator);
        return .{
            .datagram = owned_parts.datagram,
            .extra_datagrams = owned_parts.extra_datagrams,
            .bytes = owned_parts.bytes,
            .response = response,
        };
    }
};

const RuntimeAssembledStream = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
    datagrams: []quic.runtime.OwnedDatagram,

    fn deinit(self: *RuntimeAssembledStream, allocator: std.mem.Allocator) void {
        for (self.datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    fn intoOwnedParts(self: *RuntimeAssembledStream, allocator: std.mem.Allocator) std.mem.Allocator.Error!struct {
        datagram: quic.runtime.OwnedDatagram,
        extra_datagrams: []quic.runtime.OwnedDatagram,
        bytes: []u8,
    } {
        std.debug.assert(self.datagrams.len != 0);
        const extra_datagrams = try allocator.alloc(quic.runtime.OwnedDatagram, self.datagrams.len - 1);
        @memcpy(extra_datagrams, self.datagrams[1..]);
        const datagram = self.datagrams[0];
        allocator.free(self.datagrams);
        self.datagrams = &.{};
        const bytes = self.bytes;
        self.bytes = &.{};
        return .{ .datagram = datagram, .extra_datagrams = extra_datagrams, .bytes = bytes };
    }
};

fn sendRuntimeStreamMessage(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    stream_id: u62,
    bytes: []const u8,
    max_stream_frame_data: usize,
) Error!void {
    var send_state = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try send_state.appendFrames(&frames, endpoint.allocator, bytes, max_stream_frame_data, true);
    for (frames.items) |frame| {
        try endpoint.sendFrames(to, &.{frame});
    }
}

fn receiveRuntimeStreamBytes(endpoint: *quic.runtime.Endpoint, expected_stream_id: ?u62, max_stream_buffer: usize) Error!RuntimeAssembledStream {
    var recv: ?quic.stream_state.RecvState = null;
    defer if (recv) |*state| state.deinit();
    var datagrams: std.ArrayList(quic.runtime.OwnedDatagram) = .empty;
    errdefer {
        for (datagrams.items) |*datagram| datagram.deinit(endpoint.allocator);
        datagrams.deinit(endpoint.allocator);
    }
    var from: ?net.IpAddress = null;
    var stream_id: ?u62 = expected_stream_id;

    while (true) {
        var datagram = try endpoint.receive();
        var datagram_owned = true;
        errdefer if (datagram_owned) datagram.deinit(endpoint.allocator);
        if (from == null) from = datagram.from;

        var consumed = false;
        for (datagram.frames) |frame| {
            if (frame != .stream) continue;
            switch (try messageStreamDisposition(frame.stream.stream_id)) {
                .ignore => continue,
                .request_response => {},
            }
            const incoming_id: u62 = @intCast(frame.stream.stream_id);
            if (stream_id) |id| {
                if (incoming_id != id) {
                    if (expected_stream_id != null) return error.UnexpectedStream;
                    continue;
                }
            } else {
                stream_id = incoming_id;
            }
            if (recv == null) recv = quic.stream_state.RecvState.init(endpoint.allocator, incoming_id, max_stream_buffer);
            if (recv) |*state| {
                try state.insert(frame.stream);
                consumed = true;
                if (state.final_size != null and state.contiguous_end >= state.final_size.?) {
                    const bytes = try endpoint.allocator.dupe(u8, state.buffer.items[0..state.final_size.?]);
                    errdefer endpoint.allocator.free(bytes);
                    try datagrams.append(endpoint.allocator, datagram);
                    datagram_owned = false;
                    return .{
                        .from = from.?,
                        .stream_id = stream_id.?,
                        .bytes = bytes,
                        .datagrams = try datagrams.toOwnedSlice(endpoint.allocator),
                    };
                }
            }
        }

        if (consumed) {
            try datagrams.append(endpoint.allocator, datagram);
            datagram_owned = false;
        } else {
            datagram.deinit(endpoint.allocator);
            datagram_owned = false;
        }
    }
}

pub const OwnedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    datagram: quic.runtime.OwnedDatagram,
    extra_datagrams: []quic.runtime.OwnedDatagram = &.{},
    bytes: []u8 = &.{},
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        self.datagram.deinit(allocator);
        for (self.extra_datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const OwnedRequestBatch = struct {
    allocator: std.mem.Allocator,
    requests: []?OwnedRequest,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedRequestBatch) void {
        for (self.requests) |*request| {
            if (request.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.requests);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedRequestBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedRequestBatch) usize {
        var count: usize = 0;
        for (self.requests) |request| {
            if (request != null) count += 1;
        }
        return count;
    }
};

pub const OwnedResponse = struct {
    datagram: quic.runtime.OwnedDatagram,
    extra_datagrams: []quic.runtime.OwnedDatagram = &.{},
    bytes: []u8 = &.{},
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        self.datagram.deinit(allocator);
        for (self.extra_datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const ProtectedConfig = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_stream_frame_data: usize = 1200,
};

pub const HandshakeSessionOptions = struct {
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_concurrent_request_streams: usize = 128,
    max_stream_frame_data: usize = 1200,
    /// Maximum HTTP/3 DATA bytes one paced helper attempt may hand to QUIC.
    ///
    /// The default remains conservative for callers using the standard 1200B
    /// path MTU. Loopback/high-throughput callers can raise this together with
    /// `max_stream_frame_data`, `max_frames_per_packet`, and the handshake
    /// one_rtt max datagram size to reduce ACK/flow-control pump iterations.
    paced_body_chunk_bytes: usize = 1024,
    /// Experimental DATA-frame send path that avoids copying most body bytes
    /// into a temporary HTTP/3 DATA payload. It is opt-in because shared
    /// payload lifetime is subtle for multi-stream batching; benchmark enables
    /// it only for single-stream transfer.
    enable_data_prefix_fast_path: bool = false,
};

pub const HandshakeServerOptions = struct {
    handshake: quic.handshake.ServerOptions,
    session: HandshakeSessionOptions = .{},
};

pub const HandshakeClientOptions = struct {
    handshake: quic.handshake.ClientOptions,
    session: HandshakeSessionOptions = .{},
};

pub const HandshakeServer = struct {
    quic_server: quic.runtime.Server,
    allocator: std.mem.Allocator,
    handshake_options: quic.handshake.ServerOptions,
    session_options: HandshakeSessionOptions,
    local_connection_id: []u8,
    alpn_protocol: []u8,
    transport_parameters: []u8,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, options: HandshakeServerOptions) Error!HandshakeServer {
        try validateBlockedStreamLimit(
            options.session.local_settings,
            options.session.max_concurrent_request_streams,
        );
        var quic_server = try quic.runtime.Server.bind(allocator, io, bind_address, limits.quic);
        errdefer quic_server.deinit();

        const local_connection_id = try allocator.dupe(u8, options.handshake.local_connection_id);
        errdefer allocator.free(local_connection_id);
        const alpn_protocol = try allocator.dupe(u8, options.handshake.alpn_protocol);
        errdefer allocator.free(alpn_protocol);
        const transport_parameters = try allocator.dupe(u8, options.handshake.transport_parameters);
        errdefer allocator.free(transport_parameters);

        var handshake_options = options.handshake;
        handshake_options.local_connection_id = local_connection_id;
        handshake_options.alpn_protocol = alpn_protocol;
        handshake_options.transport_parameters = transport_parameters;

        return .{
            .quic_server = quic_server,
            .allocator = allocator,
            .handshake_options = handshake_options,
            .session_options = options.session,
            .local_connection_id = local_connection_id,
            .alpn_protocol = alpn_protocol,
            .transport_parameters = transport_parameters,
        };
    }

    pub fn deinit(self: *HandshakeServer) void {
        self.quic_server.deinit();
        self.allocator.free(self.local_connection_id);
        self.allocator.free(self.alpn_protocol);
        self.allocator.free(self.transport_parameters);
        self.* = undefined;
    }

    pub fn address(self: HandshakeServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn accept(self: *HandshakeServer) Error!HandshakeServerSession {
        var established = try quic.handshake.accept(&self.quic_server.endpoint, self.handshake_options);
        errdefer established.deinit();
        const max_capacity = std.math.cast(
            usize,
            self.session_options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        return .{
            .established = established,
            .options = self.session_options,
            .qpack_decode = .init(
                established.connection.endpoint.allocator,
                max_capacity,
                self.session_options.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                established.connection.endpoint.allocator,
                self.session_options.max_stream_buffer,
            ),
            .request_streams = .init(
                established.connection.endpoint.allocator,
                self.session_options.max_stream_buffer,
                self.session_options.max_concurrent_request_streams,
            ),
            .streaming_requests = .init(
                established.connection.endpoint.allocator,
                self.session_options.max_concurrent_request_streams,
                self.session_options.max_stream_buffer,
                self.session_options.local_settings,
                .request,
            ),
            .request_lifecycle = .init(
                established.connection.endpoint.allocator,
            ),
            .outbound_bodies = .init(
                established.connection.endpoint.allocator,
                self.session_options.max_concurrent_request_streams,
            ),
        };
    }
};

pub const HandshakeServerSession = struct {
    established: quic.handshake.EstablishedConnection,
    options: HandshakeSessionOptions,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    request_streams: RequestStreamSet,
    streaming_requests: StreamingRequestSet,
    receive_packets: ConnectionPacketCursor = .{},
    request_lifecycle: ServerRequestLifecycle,
    outbound_bodies: OutboundBodySet,
    sent_push_ids: std.ArrayList(u64) = .empty,
    peer_promised_push_ids: std.ArrayList(u64) = .empty,
    next_push_stream_id: u62 = first_server_push_stream_id,

    pub fn deinit(self: *HandshakeServerSession) void {
        self.outbound_bodies.deinit();
        self.sent_push_ids.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.peer_promised_push_ids.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.receive_packets.deinit();
        self.control.deinit(self.established.connection.endpoint.allocator);
        self.request_lifecycle.deinit();
        self.streaming_requests.deinit();
        self.request_streams.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.established.deinit();
        self.* = undefined;
    }

    pub fn receiveRequest(self: *HandshakeServerSession) Error!OwnedHandshakeRequest {
        if (self.streaming_requests.retainedCount() != 0) {
            return error.UnexpectedStream;
        }
        const assembled = receiveConnectionRequestStreamBytes(
            &self.established.connection,
            &self.receive_packets,
            self.options,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.request_streams,
            self.peer_promised_push_ids.items,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                try self.sendQpackFeedback();
                return err;
            },
            else => return err,
        };
        errdefer self.established.connection.endpoint.allocator.free(assembled.bytes);
        var request = try http3.decodeRequestWithDynamicTable(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.options.local_settings,
            self.qpack_decode.table,
        );
        errdefer request.deinit(self.established.connection.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            request.qpack_section_acknowledgments,
        );
        try self.request_lifecycle.markReceived(assembled.stream_id);
        try self.sendQpackFeedback();
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    /// Poll one event from any multiplexed request stream without aggregating
    /// DATA payloads. The returned stream ID is then used with
    /// `readRequestData`, matching tquic's poll/recv_body split while retaining
    /// netz's owned decoded heads and dynamic trailers.
    pub fn receiveRequestEvent(
        self: *HandshakeServerSession,
    ) Error!StreamingRequestEvent {
        while (true) {
            try self.releaseStreamingRequestCapacity();
            if (self.streaming_requests.takeFirstReset()) |reset| {
                self.request_lifecycle.markFinished(reset.stream_id);
                self.qpack_encode.abandonStream(reset.stream_id);
                _ = self.outbound_bodies.finish(reset.stream_id);
                return .{ .reset = .{
                    .from = reset.from,
                    .stream_id = reset.stream_id,
                    .application_error_code = reset.application_error_code,
                } };
            }
            if (try self.streaming_requests.nextRequest(
                &self.request_streams,
                self.qpack_decode.table,
                self.options.local_settings.qpack_blocked_streams,
            )) |ready| {
                return try self.applyStreamingRequestEvent(
                    ready.entry,
                    ready.event,
                );
            }
            try self.receiveRequestPacket();
        }
    }

    pub fn readRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return read;
    }

    pub fn skipRequestData(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const skipped = try entry.reader.skipData();
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return skipped;
    }

    pub fn sendResponse(self: *HandshakeServerSession, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(stream_id, &.{}, response);
    }

    pub fn sendResponseWithPush(
        self: *HandshakeServerSession,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        const push_stream_id = self.next_push_stream_id;
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        const max_push_id = self.control.peer_max_push_id orelse
            return error.PushIdExceeded;
        if (push.push_id > max_push_id) return error.PushIdExceeded;
        try self.peer_promised_push_ids.ensureUnusedCapacity(
            self.established.connection.endpoint.allocator,
            1,
        );
        try validateNewServerPush(
            self.control,
            self.sent_push_ids.items,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
        try self.sent_push_ids.ensureUnusedCapacity(
            self.established.connection.endpoint.allocator,
            1,
        );
        try sendConnectionPush(
            &self.established.connection,
            self.options,
            self.control.settings.peer,
            request_stream_id,
            response,
            push_stream_id,
            push,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
        self.sent_push_ids.appendAssumeCapacity(push.push_id);
        self.peer_promised_push_ids.appendAssumeCapacity(push.push_id);
        self.next_push_stream_id = next_push_stream_id;
        self.request_lifecycle.markFinished(request_stream_id);
        return push_stream_id;
    }

    pub fn startResponse(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
    ) Error!void {
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(
            self.established.connection.endpoint.allocator,
        );
        const streaming = try response.writeStreamingHeadDynamic(
            &encoded,
            self.established.connection.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendConnectionStreamingHead(
            &self.established.connection,
            encoded.items,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            self.options,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.outbound_bodies,
        );
        if (!streaming.body_allowed or
            streaming.expected_length == 0)
        {
            self.request_lifecycle.markFinished(stream_id);
        }
    }

    pub fn sendResponseBody(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try sendConnectionBodyChunk(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.options,
        );
        if (fin) self.request_lifecycle.markFinished(stream_id);
    }

    /// Send response DATA while driving the receive side when QUIC
    /// backpressure says the peer must first ACK or extend flow-control
    /// credit.
    ///
    /// The plain `sendResponseBody` API intentionally exposes
    /// `CongestionLimited`/`FlowControlBlocked` for event-loop integrations
    /// that already own their writable scheduling. This helper is the blocking
    /// counterpart for simple runtimes and benchmarks: it processes
    /// request-side packets, preserving ACK/MAX_* progress, then retries the
    /// same small DATA chunk.
    pub fn sendResponseBodyPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (data.len == 0) {
            try self.sendResponseBodyPacedChunk(stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedBodyChunkLimit(self.options);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendResponseBodyPacedChunk(
                stream_id,
                data[offset..end],
                fin and end == data.len,
            );
            offset = end;
        }
    }

    fn sendResponseBodyPacedChunk(
        self: *HandshakeServerSession,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendResponseBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacket();
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn finishResponseTrailers(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        try sendConnectionTrailers(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            self.options,
        );
        self.request_lifecycle.markFinished(stream_id);
    }

    /// Blocking counterpart to `finishResponseTrailers` that keeps receiving
    /// request-side packets until the response trailers can be written.
    pub fn finishResponseTrailersPaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
            self.finishResponseTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacket();
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn sendResponseWithInformational(
        self: *HandshakeServerSession,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        try sendConnectionResponseSequence(
            &self.established.connection,
            stream_id,
            informational,
            response,
            self.options,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
        self.request_lifecycle.markFinished(stream_id);
    }

    pub fn sendGoAway(self: *HandshakeServerSession, stream_id: u64) Error!void {
        try validateServerGoAwayStreamId(stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        try sendConnectionControlFrame(&self.established.connection, &self.control, &self.control_send, self.options, .goaway, stream_id);
    }

    pub fn initiateShutdown(self: *HandshakeServerSession) Error!void {
        if (self.request_lifecycle.shutdown_state != .active) return;
        try self.sendGoAway(@as(u64, quic.varint.max_value) & ~@as(u64, 0x3));
        self.request_lifecycle.shutdown_state = .initial_goaway;
    }

    pub fn completeShutdown(self: *HandshakeServerSession) Error!void {
        if (self.request_lifecycle.shutdown_state != .initial_goaway) return;
        if (self.request_streams.entries.items.len != 0 or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAway(try self.request_lifecycle.finalGoAwayId());
        self.request_lifecycle.shutdown_state = .final_goaway;
    }

    pub fn drainComplete(self: HandshakeServerSession) bool {
        return self.request_lifecycle.drainComplete(
            self.request_streams,
            self.streaming_requests,
            self.control.local_goaway_id,
        );
    }

    pub fn cancelRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        var cancel_qpack = try self.request_streams.cancel(
            stream_id,
            self.qpack_decode.table,
        );
        cancel_qpack = cancel_qpack or
            try self.streaming_requests.hasUnacknowledgedDynamicSection(
                stream_id,
                self.qpack_decode.table,
            );
        self.streaming_requests.remove(stream_id);
        try cancelConnectionRequest(
            &self.established.connection,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            stream_id,
            application_error_code,
            cancel_qpack,
        );
        self.qpack_encode.abandonStream(stream_id);
        self.request_lifecycle.markFinished(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    pub fn rejectRequest(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        try self.cancelRequest(
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
        );
    }

    fn receiveRequestPacket(self: *HandshakeServerSession) Error!void {
        var packet = try self.receive_packets.take(
            &self.established.connection,
        );
        defer packet.deinit(
            self.established.connection.endpoint.allocator,
        );
        _ = try applyServerRequestPacketFrames(
            packet.from,
            packet.frames,
            self.established.connection.endpoint.allocator,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.request_streams,
            &self.streaming_requests,
            self.peer_promised_push_ids.items,
        );
        // Encoder-stream inserts and reset cancellations both queue decoder
        // instructions. Flush them at the packet boundary so a peer does not
        // remain artificially blocked until another HEADERS event appears.
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    fn applyStreamingRequestEvent(
        self: *HandshakeServerSession,
        entry: *StreamingRequestSet.Entry,
        event: StreamingEvent,
    ) Error!StreamingRequestEvent {
        const stream_id: u62 = @intCast(entry.reader.receive.stream_id);
        const from = entry.from orelse return error.UnexpectedStream;
        if (try streamingRequestSectionAcknowledgments(event)) |count| {
            try self.qpack_decode.acknowledgeSections(stream_id, count);
            try self.sendQpackFeedback();
        }
        if (event == .head) {
            try self.request_lifecycle.markReceived(stream_id);
        } else if (event == .finished) {
            self.streaming_requests.remove(stream_id);
        }
        return .{ .message = .{
            .from = from,
            .stream_id = stream_id,
            .value = event,
        } };
    }

    fn releaseStreamingRequestCapacity(
        self: *HandshakeServerSession,
    ) Error!void {
        for (self.streaming_requests.entries.items) |*entry| {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
    }

    fn sendQpackFeedback(self: *HandshakeServerSession) Error!void {
        try sendConnectionQpackFeedback(
            &self.established.connection,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
        );
    }
};

pub const HandshakeClient = struct {
    endpoint: *quic.runtime.Endpoint,
    peer: net.IpAddress,
    allocator: std.mem.Allocator,
    established: quic.handshake.EstablishedConnection,
    options: HandshakeSessionOptions,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    response_streams: ResponseStreamSet,
    streaming_responses: StreamingResponseSet,
    push_streams: PushStreamSet,
    receive_packets: ConnectionPacketCursor = .{},
    request_lifecycle: ClientRequestLifecycle,
    outbound_bodies: OutboundBodySet,
    next_stream_id: u62 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, options: HandshakeClientOptions) Error!HandshakeClient {
        try validateBlockedStreamLimit(
            options.session.local_settings,
            options.session.max_concurrent_request_streams,
        );
        const endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(endpoint);
        endpoint.* = try quic.runtime.Endpoint.bind(allocator, io, local_address, limits.quic);
        errdefer endpoint.deinit();

        var established = try quic.handshake.connect(endpoint, server, options.handshake);
        errdefer established.deinit();
        const max_capacity = std.math.cast(
            usize,
            options.session.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        return .{
            .endpoint = endpoint,
            .peer = server,
            .allocator = allocator,
            .established = established,
            .options = options.session,
            .qpack_decode = .init(
                allocator,
                max_capacity,
                options.session.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                options.session.max_stream_buffer,
            ),
            .response_streams = .init(
                allocator,
                options.session.max_stream_buffer,
                options.session.max_concurrent_request_streams,
            ),
            .streaming_responses = .init(
                allocator,
                options.session.max_concurrent_request_streams,
                options.session.max_stream_buffer,
                options.session.local_settings,
                .response,
            ),
            .push_streams = .init(
                allocator,
                options.session.max_concurrent_request_streams,
                options.session.max_stream_buffer,
                options.session.local_settings,
            ),
            .request_lifecycle = .init(
                allocator,
                options.session.max_concurrent_request_streams,
            ),
            .outbound_bodies = .init(
                allocator,
                options.session.max_concurrent_request_streams,
            ),
        };
    }

    /// Try every DNS result that can be reached from `local_address`.
    ///
    /// Public HTTP/3 origins often publish many CDN anycast addresses.  A
    /// single edge can temporarily black-hole UDP/443, which otherwise surfaces
    /// as a QUIC `HandshakeTimeout` even though another address from the same
    /// DNS answer is healthy.  This helper keeps protocol/authentication errors
    /// fail-fast, but treats path-level failures as per-address and falls back
    /// to the next resolved endpoint before giving up.
    fn connectAnyResolvedAddress(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        servers: []const net.IpAddress,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        if (servers.len == 0) return error.NoAddressReturned;

        var attempted = false;
        var last_err: ?Error = null;
        for (servers) |server| {
            if (!sameIpAddressFamily(local_address, server)) continue;
            attempted = true;
            return connect(
                allocator,
                io,
                local_address,
                server,
                limits,
                options,
            ) catch |err| {
                last_err = err;
                if (shouldTryNextResolvedAddress(err)) continue;
                return err;
            };
        }
        if (!attempted) return error.AddressFamilyUnsupported;
        return last_err orelse error.NoAddressReturned;
    }

    fn sameIpAddressFamily(a: net.IpAddress, b: net.IpAddress) bool {
        return switch (a) {
            .ip4 => switch (b) {
                .ip4 => true,
                .ip6 => false,
            },
            .ip6 => switch (b) {
                .ip4 => false,
                .ip6 => true,
            },
        };
    }

    fn shouldTryNextResolvedAddress(err: Error) bool {
        return switch (err) {
            error.HandshakeTimeout,
            error.HandshakeSendFailed,
            error.HandshakeReceiveFailed,
            error.AddressFamilyUnsupported,
            error.ConnectionRefused,
            error.ConnectionResetByPeer,
            error.HostUnreachable,
            error.NetworkDown,
            error.NetworkUnreachable,
            error.PortUnreachable,
            => true,
            else => false,
        };
    }

    pub fn connectUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!HandshakeClient {
        var endpoint = try uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const servers = try endpoint.resolveAll(allocator, io);
        defer allocator.free(servers);
        var connect_options = options;
        if (connect_options.handshake.server_name == null) {
            connect_options.handshake.server_name = endpoint.tls_host;
        }
        return try connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
        );
    }

    pub fn requestUri(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!OwnedHandshakeResponse {
        var endpoint = try uriEndpoint(allocator, uri);
        defer endpoint.deinit();
        const path = try uriPathAlloc(allocator, uri);
        defer allocator.free(path);
        const servers = try endpoint.resolveAll(allocator, io);
        defer allocator.free(servers);

        var connect_options = options;
        if (connect_options.handshake.server_name == null) {
            connect_options.handshake.server_name = endpoint.tls_host;
        }
        var client = try connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
        );
        defer client.deinit();

        return try client.request(.{
            .method = request_options.method,
            .path = path,
            .scheme = "https",
            .authority = endpoint.authority,
            .headers = request_options.headers,
            .body = request_options.body,
            .trailers = request_options.trailers,
        });
    }

    pub fn requestUriAltSvc(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        target: http3.AltSvcTarget,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!OwnedHandshakeResponse {
        if (!http3.isHttp3Alpn(target.alpn)) return error.InvalidHeader;
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        const path = try uriPathAlloc(allocator, uri);
        defer allocator.free(path);
        const servers = try resolveHostPortAddresses(
            allocator,
            io,
            target.connect_host,
            target.port,
        );
        defer allocator.free(servers);

        var connect_options = options;
        connect_options.handshake.server_name = origin.tls_host;
        connect_options.handshake.alpn_protocols = &.{target.alpn};
        var client = try connectAnyResolvedAddress(
            allocator,
            io,
            local_address,
            servers,
            limits,
            connect_options,
        );
        defer client.deinit();

        return try client.request(.{
            .method = request_options.method,
            .path = path,
            .scheme = "https",
            .authority = origin.authority,
            .headers = request_options.headers,
            .body = request_options.body,
            .trailers = request_options.trailers,
        });
    }

    /// Resolve the first HTTP/3 Alt-Svc advertisement from any header list
    /// whose items expose `.name` and `.value`, then issue an origin-preserving
    /// HTTP/3 request to the advertised alternative service.
    pub fn requestUriAltSvcHeader(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        uri: std.Uri,
        headers: anytype,
        request_options: UriRequestOptions,
        limits: Limits,
        options: HandshakeClientOptions,
    ) Error!OwnedHandshakeResponse {
        var origin = try uriEndpoint(allocator, uri);
        defer origin.deinit();
        const target = (try http3.firstHttp3AltSvcTarget(
            origin.tls_host,
            headers,
            origin.port,
        )) orelse return error.InvalidHeader;
        return try requestUriAltSvc(
            allocator,
            io,
            local_address,
            uri,
            target,
            request_options,
            limits,
            options,
        );
    }

    pub fn deinit(self: *HandshakeClient) void {
        self.outbound_bodies.deinit();
        self.receive_packets.deinit();
        self.push_streams.deinit();
        self.streaming_responses.deinit();
        self.request_lifecycle.deinit();
        self.response_streams.deinit();
        self.control.deinit(self.allocator);
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.established.deinit();
        self.endpoint.deinit();
        self.allocator.destroy(self.endpoint);
        self.* = undefined;
    }

    pub fn address(self: HandshakeClient) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn request(self: *HandshakeClient, request_options: http3.Request) Error!OwnedHandshakeResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponse(stream_id);
    }

    pub fn sendRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(stream_id);
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        self.next_stream_id += 4;

        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionMessage(
            &self.established.connection,
            stream_id,
            request_options,
            self.options,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
        return stream_id;
    }

    pub fn startRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        try self.request_lifecycle.open(stream_id);
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        self.next_stream_id += 4;
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.allocator);
        const streaming = try request_options.writeStreamingHeadDynamic(
            &encoded,
            self.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendConnectionStreamingHead(
            &self.established.connection,
            encoded.items,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            self.options,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.outbound_bodies,
        );
        return stream_id;
    }

    pub fn sendRequestBody(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendConnectionBodyChunk(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
            self.options,
        );
    }

    /// Send request DATA and synchronously pump peer packets when QUIC
    /// congestion or flow-control state is not yet writable.
    ///
    /// This mirrors production event loops (quicz/tquic style): a failed write
    /// due to `CongestionLimited` or `FlowControlBlocked` is not terminal, it
    /// means the connection must process ACK/MAX_* frames before retrying. The
    /// method keeps aggregate `receiveResponse` usable by routing those packets
    /// through the normal response queues instead of activating the streaming
    /// response reader.
    pub fn sendRequestBodyPaced(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (data.len == 0) {
            try self.sendRequestBodyPacedChunk(stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedBodyChunkLimit(self.options);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendRequestBodyPacedChunk(
                stream_id,
                data[offset..end],
                fin and end == data.len,
            );
            offset = end;
        }
    }

    fn sendRequestBodyPacedChunk(
        self: *HandshakeClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendRequestBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponseProgressForSend(stream_id);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn finishRequestTrailers(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendConnectionTrailers(
            &self.established.connection,
            &self.outbound_bodies,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            self.options,
        );
    }

    /// Blocking counterpart to `finishRequestTrailers` that keeps processing
    /// response-side ACK/MAX_* packets until the trailer section is writable.
    pub fn finishRequestTrailersPaced(
        self: *HandshakeClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
            self.finishRequestTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponseProgressForSend(stream_id);
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn receiveResponse(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!OwnedHandshakeResponse {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        const assembled = receiveConnectionResponseStreamBytes(
            &self.established.connection,
            &self.receive_packets,
            stream_id,
            self.options,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
        ) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                try self.sendQpackFeedback();
                _ = try self.request_lifecycle.finish(stream_id);
                _ = self.outbound_bodies.finish(stream_id);
                self.qpack_encode.abandonStream(stream_id);
                return err;
            },
            else => return err,
        };
        errdefer self.established.connection.endpoint.allocator.free(assembled.bytes);
        try http3.validateResponsePushPromises(self.control, assembled.bytes);
        try registerResponsePushPromises(
            &self.push_streams,
            assembled.stream_id,
            assembled.bytes,
        );
        var response = try http3.decodeResponseWithDynamicTable(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
        );
        errdefer response.deinit(self.established.connection.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            response.qpack_section_acknowledgments,
        );
        try self.sendQpackFeedback();
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn receiveNextResponse(
        self: *HandshakeClient,
    ) Error!OwnedHandshakeResponseEvent {
        if (self.request_lifecycle.outstanding.items.len == 0) {
            return error.UnexpectedStream;
        }
        while (true) {
            if (self.response_streams.firstReset()) |reset| {
                if (self.request_lifecycle.contains(reset.stream_id)) {
                    _ = self.response_streams.takeReset(reset.stream_id);
                    try self.sendQpackFeedback();
                    _ = try self.request_lifecycle.finish(reset.stream_id);
                    _ = self.outbound_bodies.finish(reset.stream_id);
                    self.qpack_encode.abandonStream(reset.stream_id);
                    return .{ .reset = .{
                        .stream_id = reset.stream_id,
                        .application_error_code = reset.application_error_code,
                    } };
                }
            }
            if (try self.response_streams.firstReadyStream(
                self.qpack_decode.table,
                self.options.local_settings.qpack_blocked_streams,
            )) |stream_id| {
                if (!self.request_lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
                return .{ .response = .{
                    .stream_id = stream_id,
                    .value = try self.receiveResponse(stream_id),
                } };
            }
            try receiveConnectionResponsePacket(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
            );
        }
    }

    /// Advance one response stream without assembling its DATA payload.
    ///
    /// The first call transfers any already-buffered STREAM ranges into the
    /// incremental reader without copying. Subsequent packet pumping keeps
    /// other active response streams in their own bounded windows, so callers
    /// may interleave this API across multiple outstanding requests.
    pub fn receiveResponseEvent(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id)) |active| {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &active.reader,
            );
        }
        if (self.response_streams.takeReset(stream_id)) |code| {
            try self.sendQpackFeedback();
            try self.finishStreamingResponse(stream_id);
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        const entry = try self.streaming_responses.activateResponse(
            &self.response_streams,
            stream_id,
        );
        if (try entry.reader.next(self.qpack_decode.table)) |event| {
            var owned_event = event;
            errdefer owned_event.deinit(
                self.established.connection.endpoint.allocator,
            );
            try self.applyStreamingResponseEvent(stream_id, owned_event);
            return owned_event;
        }
        try receiveConnectionResponsePacket(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
        );
        if (self.response_streams.takeReset(stream_id)) |code| {
            try self.sendQpackFeedback();
            try self.finishStreamingResponse(stream_id);
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        const active = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        if (try active.reader.next(self.qpack_decode.table)) |event| {
            var owned_event = event;
            errdefer owned_event.deinit(
                self.established.connection.endpoint.allocator,
            );
            try self.applyStreamingResponseEvent(stream_id, owned_event);
            return owned_event;
        }
        return null;
    }

    /// Copy currently available DATA bytes into caller-owned storage.
    ///
    /// Returning zero means the current DATA frame needs more STREAM bytes;
    /// call `receiveResponseEvent` again to pump another packet.
    pub fn readResponseData(
        self: *HandshakeClient,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return read;
    }

    pub fn skipResponseData(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        const skipped = try entry.reader.skipData();
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        return skipped;
    }

    fn releaseStreamingResponseCapacity(self: *HandshakeClient) Error!void {
        for (self.streaming_responses.entries.items) |*entry| {
            try releaseStreamingReaderCapacity(
                &self.established.connection,
                &entry.reader,
            );
        }
    }

    /// Poll one promised response without aggregating its DATA payload.
    pub fn receivePushEvent(
        self: *HandshakeClient,
    ) Error!StreamingPushEvent {
        return self.receivePushEventMatching(null);
    }

    fn receivePushEventMatching(
        self: *HandshakeClient,
        target_push_id: ?u64,
    ) Error!StreamingPushEvent {
        while (true) {
            for (self.push_streams.entries.items) |*entry| {
                if (entry.reader) |*reader| {
                    try releaseStreamingReaderCapacity(
                        &self.established.connection,
                        reader,
                    );
                }
            }
            try self.applyPendingPushCancellations();
            if (try self.push_streams.next(
                self.qpack_decode.table,
                self.options.local_settings.qpack_blocked_streams,
                target_push_id,
            )) |ready| {
                var event = ready.event;
                errdefer event.deinit(self.allocator);
                if (event.value == .push_promise) {
                    return error.UnexpectedFrame;
                }
                if (try streamingResponseSectionAcknowledgments(
                    event.value,
                )) |count| {
                    try self.qpack_decode.acknowledgeSections(
                        event.stream_id,
                        count,
                    );
                    try self.sendQpackFeedback();
                }
                if (event.value == .finished) {
                    self.push_streams.removeFinished(ready.index);
                }
                return event;
            }
            try receiveConnectionResponsePacket(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
            );
        }
    }

    fn applyPendingPushCancellations(
        self: *HandshakeClient,
    ) Error!void {
        while (self.push_streams.takeCancelledStream()) |stream_id| {
            try self.established.connection.sendStopSending(
                stream_id,
                http3.ApplicationErrorCode.request_cancelled,
            );
        }
    }

    pub fn readPushData(
        self: *HandshakeClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        const entry = self.push_streams.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader.?,
        );
        return entry.reader.?.readData(out);
    }

    pub fn receivePush(
        self: *HandshakeClient,
    ) Error!PushedResponse {
        var head: ?http3.DecodedResponseHead = null;
        errdefer if (head) |*value| value.deinit(self.allocator);
        var trailers: ?http3.DecodedTrailers = null;
        errdefer if (trailers) |*value| value.deinit(self.allocator);
        var body: std.ArrayList(u8) = .empty;
        errdefer body.deinit(self.allocator);
        var push_id: ?u64 = null;
        var request_stream_id: u62 = 0;
        var push_stream_id: u62 = 0;
        while (true) {
            var event = try self.receivePushEventMatching(push_id);
            defer event.deinit(self.allocator);
            if (push_id) |expected| {
                if (event.push_id != expected) return error.UnexpectedStream;
            } else {
                push_id = event.push_id;
                request_stream_id = event.request_stream_id;
                push_stream_id = event.stream_id;
            }
            switch (event.value) {
                .head => |value| {
                    if (head != null or value != .response) {
                        return error.UnexpectedFrame;
                    }
                    head = value.response;
                    event.value = .finished;
                },
                .data_available => {
                    var chunk: [4096]u8 = undefined;
                    while (true) {
                        const entry = self.push_streams.findByPushId(
                            event.push_id,
                        ) orelse return error.UnexpectedStream;
                        if (entry.reader.?.current_frame == null) break;
                        const count = try self.readPushData(
                            event.push_id,
                            &chunk,
                        );
                        if (count == 0) break;
                        try body.appendSlice(self.allocator, chunk[0..count]);
                    }
                },
                .trailers => |value| {
                    if (trailers != null) return error.UnexpectedFrame;
                    trailers = value;
                    event.value = .finished;
                },
                .finished => {},
                .push_promise => return error.UnexpectedFrame,
            }
            if (event.value != .finished or
                self.push_streams.findByPushId(event.push_id) != null)
            {
                continue;
            }
            const decoded_head = head orelse return error.ExpectedHeadersFrame;
            const body_storage: ?[]u8 = if (body.items.len == 0) storage: {
                body.deinit(self.allocator);
                break :storage null;
            } else try body.toOwnedSlice(self.allocator);
            const trailer_fields: []http3.Qpack.HeaderField = if (trailers) |value|
                value.fields
            else
                @constCast(&.{});
            const acknowledgments =
                decoded_head.qpack_section_acknowledgments +
                if (trailers) |value|
                    value.qpack_section_acknowledgments
                else
                    0;
            return .{
                .push_id = push_id.?,
                .request_stream_id = request_stream_id,
                .stream_id = push_stream_id,
                .response = .{
                    .status = decoded_head.status,
                    .headers = decoded_head.headers,
                    .trailers = trailer_fields,
                    .body = if (body_storage) |storage| storage else &.{},
                    .body_storage = body_storage,
                    .consumed = 0,
                    .qpack_section_acknowledgments = acknowledgments,
                },
            };
        }
    }

    /// Poll one incremental event from any outstanding response stream.
    ///
    /// The first call selects streaming mode for all currently buffered
    /// responses. Continue using streaming APIs for those stream IDs; aggregate
    /// `receiveResponse` cannot reclaim a reader whose head/body has advanced.
    pub fn receiveNextResponseEvent(
        self: *HandshakeClient,
    ) Error!StreamingResponseEvent {
        if (self.request_lifecycle.outstanding.items.len == 0) {
            return error.UnexpectedStream;
        }
        while (true) {
            try self.releaseStreamingResponseCapacity();
            if (self.response_streams.firstReset()) |reset| {
                if (!self.request_lifecycle.contains(reset.stream_id)) {
                    return error.UnexpectedStream;
                }
                _ = self.response_streams.takeReset(reset.stream_id);
                try self.sendQpackFeedback();
                try self.finishStreamingResponse(reset.stream_id);
                return .{ .reset = .{
                    .stream_id = reset.stream_id,
                    .application_error_code = reset.application_error_code,
                } };
            }
            if (try self.streaming_responses.nextResponse(
                &self.response_streams,
                self.qpack_decode.table,
                self.options.local_settings.qpack_blocked_streams,
            )) |ready| {
                const stream_id: u62 = @intCast(
                    ready.entry.reader.receive.stream_id,
                );
                var owned_event = ready.event;
                errdefer owned_event.deinit(
                    self.established.connection.endpoint.allocator,
                );
                try self.applyStreamingResponseEvent(
                    stream_id,
                    owned_event,
                );
                return .{ .message = .{
                    .stream_id = stream_id,
                    .value = owned_event,
                } };
            }
            try self.releaseStreamingResponseCapacity();
            try receiveConnectionResponsePacket(
                &self.established.connection,
                &self.receive_packets,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                &self.response_streams,
                &self.streaming_responses,
                &self.push_streams,
                &self.request_lifecycle,
            );
        }
    }

    pub fn sendGoAway(self: *HandshakeClient, stream_id: u64) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionControlFrame(&self.established.connection, &self.control, &self.control_send, self.options, .goaway, stream_id);
    }

    /// Advertise the inclusive server-push ID limit.
    pub fn sendMaxPushId(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        try self.push_streams.reservePromisesThrough(push_id);
        const previous_max_push_id = self.control.local_max_push_id;
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        sendConnectionPushControl(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .max_push_id,
            push_id,
        ) catch |err| {
            self.control.local_max_push_id = previous_max_push_id;
            return err;
        };
    }

    pub fn cancelPush(
        self: *HandshakeClient,
        push_id: u64,
    ) Error!void {
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionPushControl(
            &self.established.connection,
            &self.control,
            &self.control_send,
            self.options,
            .cancel_push,
            push_id,
        );
        try self.push_streams.observePeerCancellation(push_id);
        try self.applyPendingPushCancellations();
    }

    pub fn cancelRequest(
        self: *HandshakeClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        var cancel_qpack = try self.response_streams
            .requiresQpackCancellation(
            stream_id,
            self.qpack_decode.table,
        );
        cancel_qpack = cancel_qpack or
            try self.streaming_responses.hasUnacknowledgedDynamicSection(
                stream_id,
                self.qpack_decode.table,
            );
        try cancelConnectionRequest(
            &self.established.connection,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            stream_id,
            application_error_code,
            cancel_qpack,
        );
        self.qpack_encode.abandonStream(stream_id);
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    pub fn sendPriorityUpdate(
        self: *HandshakeClient,
        stream_id: u62,
        priority: http3.Priority,
    ) Error!void {
        // PRIORITY_UPDATE can precede the request itself, which is essential
        // for this synchronous request API: `next_stream_id` is the one request
        // stream that may be prioritized before request() opens it.
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionPriorityUpdate(
            &self.established.connection,
            &self.control_send,
            self.options,
            stream_id,
            priority,
        );
    }

    pub fn sendPushPriorityUpdate(
        self: *HandshakeClient,
        push_id: u64,
        priority: http3.Priority,
    ) Error!void {
        if (self.push_streams.findPromise(push_id) == null) {
            return error.UnexpectedStream;
        }
        try sendConnectionSettings(
            &self.established.connection,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        try sendConnectionPriorityUpdateRaw(
            &self.established.connection,
            &self.control_send,
            self.options,
            http3.FrameType.priority_update_push,
            push_id,
            priority,
        );
    }

    fn sendQpackFeedback(self: *HandshakeClient) Error!void {
        try sendConnectionQpackFeedback(
            &self.established.connection,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
        );
    }

    fn receiveResponseProgressForSend(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        try self.failIfRequestResetForSend(stream_id);
        try receiveConnectionResponsePacket(
            &self.established.connection,
            &self.receive_packets,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.response_streams,
            &self.streaming_responses,
            &self.push_streams,
            &self.request_lifecycle,
        );
        try self.failIfRequestResetForSend(stream_id);
    }

    fn failIfRequestResetForSend(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        const code = self.response_streams.takeReset(stream_id) orelse return;
        try self.sendQpackFeedback();
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        return responseResetError(code);
    }

    fn applyStreamingResponseEvent(
        self: *HandshakeClient,
        stream_id: u62,
        event: StreamingEvent,
    ) Error!void {
        const section = try streamingResponseSectionAcknowledgments(event);
        if (event == .push_promise) {
            try http3.validatePushPromise(
                self.control,
                event.push_promise.push_id,
            );
            try self.push_streams.registerPromise(
                event.push_promise.push_id,
                stream_id,
            );
        }
        if (section) |acknowledgments| {
            try self.qpack_decode.acknowledgeSections(
                stream_id,
                acknowledgments,
            );
            // Encoder-stream insert count increments are also queued in the
            // decoder feedback buffer. Flush on every decoded field section,
            // even when that section itself used only static entries.
            try self.sendQpackFeedback();
        }
        if (event == .finished) {
            try self.finishStreamingResponse(stream_id);
        }
    }

    fn finishStreamingResponse(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        self.streaming_responses.remove(stream_id);
    }
};

pub const OwnedHandshakeRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedHandshakeRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedHandshakeResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedHandshakeResponseEvent = union(enum) {
    response: struct {
        stream_id: u62,
        value: OwnedHandshakeResponse,
    },
    reset: struct {
        stream_id: u62,
        application_error_code: u64,
    },

    pub fn deinit(
        self: *OwnedHandshakeResponseEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .response => |*response| response.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

pub const ProtectedServer = struct {
    quic_server: quic.runtime.Server,
    config: ProtectedConfig,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(server_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    protected_send: ProtectedSendState,
    request_streams: RequestStreamSet,
    streaming_requests: StreamingRequestSet,
    receive_packets: ProtectedPacketCursor = .{},
    request_lifecycle: ServerRequestLifecycle,
    outbound_bodies: OutboundBodySet,
    sent_push_ids: std.ArrayList(u64) = .empty,
    peer_promised_push_ids: std.ArrayList(u64) = .empty,
    next_push_stream_id: u62 = first_server_push_stream_id,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedServer {
        try validateBlockedStreamLimit(
            config.local_settings,
            limits.max_concurrent_request_streams,
        );
        var quic_server = try quic.runtime.Server.bind(allocator, io, bind_address, limits.quic);
        errdefer quic_server.deinit();
        const max_capacity = std.math.cast(usize, config.local_settings.qpack_max_table_capacity) orelse
            return error.InvalidSetting;
        return .{
            .quic_server = quic_server,
            .config = config,
            .qpack_decode = .init(allocator, max_capacity, config.max_stream_buffer),
            // The peer's encoder capacity is not known until its SETTINGS
            // frame arrives. Starting at zero prevents speculative inserts
            // from exceeding an as-yet-unadvertised limit.
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                config.max_stream_buffer,
            ),
            .protected_send = .init(allocator),
            .request_streams = .init(
                allocator,
                config.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .streaming_requests = .init(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.local_settings,
                .request,
            ),
            .request_lifecycle = .init(allocator),
            .outbound_bodies = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
        };
    }

    pub fn deinit(self: *ProtectedServer) void {
        self.outbound_bodies.deinit();
        self.sent_push_ids.deinit(self.quic_server.endpoint.allocator);
        self.peer_promised_push_ids.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.receive_packets.deinit();
        self.control.deinit(self.quic_server.endpoint.allocator);
        self.request_lifecycle.deinit();
        self.streaming_requests.deinit();
        self.request_streams.deinit();
        self.protected_send.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: ProtectedServer) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *ProtectedServer) Error!OwnedProtectedRequest {
        if (self.streaming_requests.retainedCount() != 0) {
            return error.UnexpectedStream;
        }
        const assembled = try self.receiveStreamBytes(null);
        errdefer self.quic_server.endpoint.allocator.free(assembled.bytes);
        var request = try http3.decodeRequestWithDynamicTable(
            self.quic_server.endpoint.allocator,
            assembled.bytes,
            self.config.local_settings,
            self.qpack_decode.table,
        );
        errdefer request.deinit(self.quic_server.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            request.qpack_section_acknowledgments,
        );
        try self.request_lifecycle.markReceived(assembled.stream_id);
        try self.sendQpackFeedback(assembled.from);
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    /// Poll the next event from any client request stream.
    ///
    /// Unlike `receiveRequest`, this never aggregates DATA payloads. Once a
    /// head identifies a stream, applications can interleave polling with
    /// `readRequestData`; STREAM ranges for every active request remain bounded
    /// by `ProtectedConfig.max_stream_buffer`.
    pub fn receiveRequestEvent(
        self: *ProtectedServer,
    ) Error!StreamingRequestEvent {
        while (true) {
            if (self.streaming_requests.takeFirstReset()) |reset| {
                self.request_lifecycle.markFinished(reset.stream_id);
                self.qpack_encode.abandonStream(reset.stream_id);
                _ = self.outbound_bodies.finish(reset.stream_id);
                return .{ .reset = .{
                    .from = reset.from,
                    .stream_id = reset.stream_id,
                    .application_error_code = reset.application_error_code,
                } };
            }
            if (try self.streaming_requests.nextRequest(
                &self.request_streams,
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |ready| {
                return try self.applyStreamingRequestEvent(
                    ready.entry,
                    ready.event,
                );
            }
            try self.receiveRequestPacket();
        }
    }

    pub fn readRequestData(
        self: *ProtectedServer,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.readData(out);
    }

    pub fn sendResponse(self: *ProtectedServer, to: net.IpAddress, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(to, stream_id, &.{}, response);
    }

    pub fn sendResponseWithPush(
        self: *ProtectedServer,
        to: net.IpAddress,
        request_stream_id: u62,
        response: http3.Response,
        push: ServerPush,
    ) Error!u62 {
        const push_stream_id = self.next_push_stream_id;
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        const max_push_id = self.control.peer_max_push_id orelse
            return error.PushIdExceeded;
        if (push.push_id > max_push_id) return error.PushIdExceeded;
        try self.peer_promised_push_ids.ensureUnusedCapacity(
            self.quic_server.endpoint.allocator,
            1,
        );
        try validateNewServerPush(
            self.control,
            self.sent_push_ids.items,
            push.push_id,
        );
        const next_push_stream_id = std.math.add(
            u62,
            push_stream_id,
            4,
        ) catch return error.StreamCreationError;
        try self.sent_push_ids.ensureUnusedCapacity(
            self.quic_server.endpoint.allocator,
            1,
        );
        try sendProtectedPush(
            &self.quic_server.endpoint,
            to,
            self.config,
            self.control.settings.peer,
            request_stream_id,
            response,
            push_stream_id,
            push,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
        self.sent_push_ids.appendAssumeCapacity(push.push_id);
        self.peer_promised_push_ids.appendAssumeCapacity(push.push_id);
        self.next_push_stream_id = next_push_stream_id;
        self.request_lifecycle.markFinished(request_stream_id);
        return push_stream_id;
    }

    pub fn startResponse(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        response: http3.Response,
        body_length: ?usize,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        const streaming = try response.writeStreamingHeadDynamic(
            &encoded,
            self.quic_server.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendProtectedStreamingHead(
            &self.quic_server.endpoint,
            to,
            self.config,
            encoded.items,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
        );
        if (!streaming.body_allowed or
            streaming.expected_length == 0)
        {
            self.request_lifecycle.markFinished(stream_id);
        }
    }

    pub fn sendResponseBody(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        try sendProtectedBodyChunk(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
        );
        if (fin) self.request_lifecycle.markFinished(stream_id);
    }

    pub fn finishResponseTrailers(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        try sendProtectedTrailers(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
        self.request_lifecycle.markFinished(stream_id);
    }

    pub fn sendResponseWithInformational(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        informational: []const http3.InformationalResponse,
        response: http3.Response,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_server.endpoint.allocator);
        // A field section can acquire dynamic-table references before any
        // network I/O. Release those references if either the encoder stream
        // or response stream cannot be sent; speculative inserts remain useful
        // for a later response and are safe because they are not referenced.
        var response_sent = false;
        errdefer if (!response_sent) self.qpack_encode.abandonStream(stream_id);
        try http3.writeResponseSequenceDynamic(
            &encoded,
            self.quic_server.endpoint.allocator,
            informational,
            response,
            self.control.settings.peer,
            stream_id,
            &self.qpack_encode,
        );
        try sendProtectedQpackEncoderInstructions(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
        var send_state = quic.stream_state.SendState.init(stream_id);
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_server.endpoint.allocator);
        try send_state.appendFrames(&frames, self.quic_server.endpoint.allocator, encoded.items, self.config.max_stream_frame_data, true);
        try sendProtectedFrames(
            &self.quic_server.endpoint,
            to,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            frames.items,
            self.config.max_frames_per_packet,
            &self.protected_send,
        );
        response_sent = true;
        self.request_lifecycle.markFinished(stream_id);
    }

    pub fn sendGoAway(self: *ProtectedServer, to: net.IpAddress, stream_id: u64) Error!void {
        try validateServerGoAwayStreamId(stream_id);
        try sendProtectedSettings(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            server_control_stream_id,
        );
        try sendProtectedControlFrame(&self.quic_server.endpoint, to, self.config, &self.control, &self.control_send, &self.next_packet_number, &self.protected_send, .goaway, stream_id);
    }

    pub fn initiateShutdown(
        self: *ProtectedServer,
        to: net.IpAddress,
    ) Error!void {
        if (self.request_lifecycle.shutdown_state != .active) return;
        try self.sendGoAway(
            to,
            @as(u64, quic.varint.max_value) & ~@as(u64, 0x3),
        );
        self.request_lifecycle.shutdown_state = .initial_goaway;
    }

    pub fn completeShutdown(
        self: *ProtectedServer,
        to: net.IpAddress,
    ) Error!void {
        if (self.request_lifecycle.shutdown_state != .initial_goaway) return;
        if (self.request_streams.entries.items.len != 0 or
            self.streaming_requests.retainedCount() != 0)
        {
            return error.RequestIncomplete;
        }
        try self.sendGoAway(
            to,
            try self.request_lifecycle.finalGoAwayId(),
        );
        self.request_lifecycle.shutdown_state = .final_goaway;
    }

    pub fn drainComplete(self: ProtectedServer) bool {
        return self.request_lifecycle.drainComplete(
            self.request_streams,
            self.streaming_requests,
            self.control.local_goaway_id,
        );
    }

    pub fn cancelRequest(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        var cancel_qpack = try self.request_streams.cancel(
            stream_id,
            self.qpack_decode.table,
        );
        cancel_qpack = cancel_qpack or
            try self.streaming_requests.hasUnacknowledgedDynamicSection(
                stream_id,
                self.qpack_decode.table,
            );
        self.streaming_requests.remove(stream_id);
        try sendProtectedRequestCancellation(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            stream_id,
            application_error_code,
            cancel_qpack,
        );
        self.qpack_encode.abandonStream(stream_id);
        self.request_lifecycle.markFinished(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    pub fn rejectRequest(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
    ) Error!void {
        try self.cancelRequest(
            to,
            stream_id,
            http3.ApplicationErrorCode.request_rejected,
        );
    }

    fn receiveStreamBytes(self: *ProtectedServer, expected_stream_id: ?u62) Error!AssembledStream {
        std.debug.assert(expected_stream_id == null);
        if (try self.request_streams.takeReady(
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
        )) |ready| return ready;

        while (true) {
            var packet = try self.receive_packets.take(
                &self.quic_server.endpoint,
                self.config.receive_keys,
                self.config.local_connection_id.len,
                &self.expected_packet_number,
                self.config.max_frames_per_packet,
            );
            defer packet.deinit(self.quic_server.endpoint.allocator);
            if (try applyServerRequestPacketFrames(
                packet.from,
                packet.frames,
                self.quic_server.endpoint.allocator,
                &self.control,
                &self.qpack_decode,
                &self.qpack_encode,
                &self.request_streams,
                null,
                self.peer_promised_push_ids.items,
            )) |reset| {
                try self.sendQpackFeedback(reset.from);
                return requestResetError(reset.application_error_code);
            }
            if (try self.request_streams.takeReady(
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |ready| {
                return ready;
            }
        }
    }

    fn receiveRequestPacket(self: *ProtectedServer) Error!void {
        var packet = try self.receive_packets.take(
            &self.quic_server.endpoint,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            &self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        defer packet.deinit(self.quic_server.endpoint.allocator);

        _ = try applyServerRequestPacketFrames(
            packet.from,
            packet.frames,
            self.quic_server.endpoint.allocator,
            &self.control,
            &self.qpack_decode,
            &self.qpack_encode,
            &self.request_streams,
            &self.streaming_requests,
            self.peer_promised_push_ids.items,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback(packet.from);
        }
    }

    fn applyStreamingRequestEvent(
        self: *ProtectedServer,
        entry: *StreamingRequestSet.Entry,
        event: StreamingEvent,
    ) Error!StreamingRequestEvent {
        const stream_id: u62 = @intCast(entry.reader.receive.stream_id);
        const from = entry.from orelse return error.UnexpectedStream;
        if (try streamingRequestSectionAcknowledgments(event)) |count| {
            try self.qpack_decode.acknowledgeSections(stream_id, count);
            try self.sendQpackFeedback(from);
        }
        if (event == .head) {
            try self.request_lifecycle.markReceived(stream_id);
        } else if (event == .finished) {
            self.streaming_requests.remove(stream_id);
        }
        return .{ .message = .{
            .from = from,
            .stream_id = stream_id,
            .value = event,
        } };
    }

    fn sendQpackFeedback(self: *ProtectedServer, to: net.IpAddress) Error!void {
        try sendProtectedQpackFeedback(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
    }
};

pub const ProtectedClient = struct {
    quic_client: quic.runtime.Client,
    config: ProtectedConfig,
    control: http3.ControlState = .{},
    control_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_control_stream_id),
    qpack_decode: QpackDecodeState,
    qpack_encode: QpackEncodeState,
    qpack_encoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_encoder_stream_id),
    qpack_encoder_prefix_sent: bool = false,
    qpack_decoder_send: quic.stream_state.SendState = quic.stream_state.SendState.init(client_qpack_decoder_stream_id),
    qpack_decoder_prefix_sent: bool = false,
    protected_send: ProtectedSendState,
    response_streams: ResponseStreamSet,
    streaming_responses: StreamingResponseSet,
    push_streams: PushStreamSet,
    receive_packets: ProtectedPacketCursor = .{},
    request_lifecycle: ClientRequestLifecycle,
    outbound_bodies: OutboundBodySet,
    next_stream_id: u62 = 0,
    next_packet_number: u64 = 0,
    expected_packet_number: u64 = 0,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, server: net.IpAddress, limits: Limits, config: ProtectedConfig) Error!ProtectedClient {
        try validateBlockedStreamLimit(
            config.local_settings,
            limits.max_concurrent_request_streams,
        );
        var quic_client = try quic.runtime.Client.connect(allocator, io, local_address, server, limits.quic);
        errdefer quic_client.deinit();
        const max_capacity = std.math.cast(usize, config.local_settings.qpack_max_table_capacity) orelse
            return error.InvalidSetting;
        return .{
            .quic_client = quic_client,
            .config = config,
            .qpack_decode = .init(allocator, max_capacity, config.max_stream_buffer),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                config.max_stream_buffer,
            ),
            .protected_send = .init(allocator),
            .response_streams = .init(
                allocator,
                config.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
            .streaming_responses = .init(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.local_settings,
                .response,
            ),
            .push_streams = .init(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.local_settings,
            ),
            .request_lifecycle = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
            .outbound_bodies = .init(
                allocator,
                limits.max_concurrent_request_streams,
            ),
        };
    }

    pub fn deinit(self: *ProtectedClient) void {
        self.outbound_bodies.deinit();
        self.receive_packets.deinit();
        self.push_streams.deinit();
        self.streaming_responses.deinit();
        self.request_lifecycle.deinit();
        self.response_streams.deinit();
        self.control.deinit(self.quic_client.endpoint.allocator);
        self.protected_send.deinit();
        self.qpack_encode.deinit();
        self.qpack_decode.deinit();
        self.quic_client.deinit();
        self.* = undefined;
    }

    pub fn request(self: *ProtectedClient, request_options: http3.Request) Error!OwnedProtectedResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponse(stream_id);
    }

    pub fn sendRequest(
        self: *ProtectedClient,
        request_options: http3.Request,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(stream_id);
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        self.next_stream_id += 4;

        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        var request_sent = false;
        errdefer if (!request_sent) self.qpack_encode.abandonStream(stream_id);
        try request_options.writeDynamic(
            &encoded,
            self.quic_client.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            &self.qpack_encode,
        );
        try sendProtectedQpackEncoderInstructions(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
        var send_state = quic.stream_state.SendState.init(stream_id);
        var frames: std.ArrayList(quic.Frame) = .empty;
        defer frames.deinit(self.quic_client.endpoint.allocator);
        try send_state.appendFrames(&frames, self.quic_client.endpoint.allocator, encoded.items, self.config.max_stream_frame_data, true);
        try sendProtectedFrames(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            frames.items,
            self.config.max_frames_per_packet,
            &self.protected_send,
        );
        request_sent = true;
        return stream_id;
    }

    pub fn startRequest(
        self: *ProtectedClient,
        request_options: http3.Request,
        body_length: ?usize,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) {
            return error.GoAwayReceived;
        }
        try self.request_lifecycle.open(stream_id);
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        self.next_stream_id += 4;
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        const streaming = try request_options.writeStreamingHeadDynamic(
            &encoded,
            self.quic_client.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendProtectedStreamingHead(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            encoded.items,
            stream_id,
            streaming.expected_length,
            streaming.body_allowed,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
        );
        return stream_id;
    }

    pub fn sendRequestBody(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendProtectedBodyChunk(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            data,
            fin,
        );
    }

    pub fn finishRequestTrailers(
        self: *ProtectedClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        try sendProtectedTrailers(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &self.outbound_bodies,
            stream_id,
            trailers,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
        );
    }

    pub fn receiveResponse(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!OwnedProtectedResponse {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.streaming_responses.find(stream_id) != null) {
            return error.UnexpectedStream;
        }
        const assembled = self.receiveStreamBytes(stream_id) catch |err| switch (err) {
            error.RequestCancelled, error.RequestRejected => {
                try self.sendQpackFeedback();
                _ = try self.request_lifecycle.finish(stream_id);
                _ = self.outbound_bodies.finish(stream_id);
                self.qpack_encode.abandonStream(stream_id);
                return err;
            },
            else => return err,
        };
        errdefer self.quic_client.endpoint.allocator.free(assembled.bytes);
        try http3.validateResponsePushPromises(self.control, assembled.bytes);
        try registerResponsePushPromises(
            &self.push_streams,
            assembled.stream_id,
            assembled.bytes,
        );
        var response = try http3.decodeResponseWithDynamicTable(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
        );
        errdefer response.deinit(self.quic_client.endpoint.allocator);
        try self.qpack_decode.acknowledgeSections(
            assembled.stream_id,
            response.qpack_section_acknowledgments,
        );
        try self.sendQpackFeedback();
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        return .{ .stream_bytes = assembled.bytes, .response = response };
    }

    pub fn receiveNextResponse(
        self: *ProtectedClient,
    ) Error!OwnedProtectedResponseEvent {
        if (self.request_lifecycle.outstanding.items.len == 0) {
            return error.UnexpectedStream;
        }
        while (true) {
            if (self.response_streams.firstReset()) |reset| {
                if (self.request_lifecycle.contains(reset.stream_id)) {
                    _ = self.response_streams.takeReset(reset.stream_id);
                    _ = try self.request_lifecycle.finish(reset.stream_id);
                    _ = self.outbound_bodies.finish(reset.stream_id);
                    self.qpack_encode.abandonStream(reset.stream_id);
                    return .{ .reset = .{
                        .stream_id = reset.stream_id,
                        .application_error_code = reset.application_error_code,
                    } };
                }
            }
            if (try self.response_streams.firstReadyStream(
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |stream_id| {
                if (!self.request_lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
                return .{ .response = .{
                    .stream_id = stream_id,
                    .value = try self.receiveResponse(stream_id),
                } };
            }
            try self.receiveResponsePacket();
        }
    }

    pub fn receiveResponseEvent(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!?StreamingEvent {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        if (self.response_streams.takeReset(stream_id)) |code| {
            try self.finishStreamingResponse(stream_id);
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        const entry = try self.streaming_responses.activateResponse(
            &self.response_streams,
            stream_id,
        );
        if (try entry.reader.next(self.qpack_decode.table)) |event| {
            var owned_event = event;
            errdefer owned_event.deinit(
                self.quic_client.endpoint.allocator,
            );
            try self.applyStreamingResponseEvent(stream_id, owned_event);
            return owned_event;
        }
        try self.receiveResponsePacket();
        if (self.response_streams.takeReset(stream_id)) |code| {
            try self.finishStreamingResponse(stream_id);
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        const active = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        if (try active.reader.next(self.qpack_decode.table)) |event| {
            var owned_event = event;
            errdefer owned_event.deinit(
                self.quic_client.endpoint.allocator,
            );
            try self.applyStreamingResponseEvent(stream_id, owned_event);
            return owned_event;
        }
        return null;
    }

    /// Poll one incremental event from any outstanding response stream.
    ///
    /// The first call selects streaming mode for all currently buffered
    /// responses. Continue using streaming APIs for those stream IDs; aggregate
    /// `receiveResponse` cannot reclaim a reader whose head/body has advanced.
    pub fn receiveNextResponseEvent(
        self: *ProtectedClient,
    ) Error!StreamingResponseEvent {
        if (self.request_lifecycle.outstanding.items.len == 0) {
            return error.UnexpectedStream;
        }
        while (true) {
            if (self.response_streams.firstReset()) |reset| {
                if (!self.request_lifecycle.contains(reset.stream_id)) {
                    return error.UnexpectedStream;
                }
                _ = self.response_streams.takeReset(reset.stream_id);
                try self.finishStreamingResponse(reset.stream_id);
                return .{ .reset = .{
                    .stream_id = reset.stream_id,
                    .application_error_code = reset.application_error_code,
                } };
            }
            if (try self.streaming_responses.nextResponse(
                &self.response_streams,
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |ready| {
                const stream_id: u62 = @intCast(
                    ready.entry.reader.receive.stream_id,
                );
                var owned_event = ready.event;
                errdefer owned_event.deinit(
                    self.quic_client.endpoint.allocator,
                );
                try self.applyStreamingResponseEvent(
                    stream_id,
                    owned_event,
                );
                return .{ .message = .{
                    .stream_id = stream_id,
                    .value = owned_event,
                } };
            }
            try self.receiveResponsePacket();
        }
    }

    pub fn readResponseData(
        self: *ProtectedClient,
        stream_id: u62,
        out: []u8,
    ) Error!usize {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        return entry.reader.readData(out);
    }

    pub fn receivePushEvent(
        self: *ProtectedClient,
    ) Error!StreamingPushEvent {
        return self.receivePushEventMatching(null);
    }

    fn receivePushEventMatching(
        self: *ProtectedClient,
        target_push_id: ?u64,
    ) Error!StreamingPushEvent {
        while (true) {
            try self.applyPendingPushCancellations();
            if (try self.push_streams.next(
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
                target_push_id,
            )) |ready| {
                var event = ready.event;
                errdefer event.deinit(
                    self.quic_client.endpoint.allocator,
                );
                if (event.value == .push_promise) {
                    return error.UnexpectedFrame;
                }
                if (try streamingResponseSectionAcknowledgments(
                    event.value,
                )) |count| {
                    try self.qpack_decode.acknowledgeSections(
                        event.stream_id,
                        count,
                    );
                    try self.sendQpackFeedback();
                }
                if (event.value == .finished) {
                    self.push_streams.removeFinished(ready.index);
                }
                return event;
            }
            try self.receiveResponsePacket();
        }
    }

    fn applyPendingPushCancellations(
        self: *ProtectedClient,
    ) Error!void {
        while (self.push_streams.takeCancelledStream()) |stream_id| {
            const frames = [_]quic.Frame{.{ .stop_sending = .{
                .stream_id = stream_id,
                .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            } }};
            try sendProtectedFrames(
                &self.quic_client.endpoint,
                self.quic_client.peer,
                self.config.send_keys,
                self.config.peer_connection_id,
                &self.next_packet_number,
                &frames,
                self.config.max_frames_per_packet,
                &self.protected_send,
            );
        }
    }

    pub fn readPushData(
        self: *ProtectedClient,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        return self.push_streams.readData(push_id, out);
    }

    pub fn receivePush(
        self: *ProtectedClient,
    ) Error!PushedResponse {
        return receiveProtectedPush(self);
    }

    pub fn sendGoAway(self: *ProtectedClient, stream_id: u64) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedControlFrame(&self.quic_client.endpoint, self.quic_client.peer, self.config, &self.control, &self.control_send, &self.next_packet_number, &self.protected_send, .goaway, stream_id);
    }

    pub fn sendMaxPushId(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!void {
        try self.push_streams.reservePromisesThrough(push_id);
        const previous_max_push_id = self.control.local_max_push_id;
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        sendProtectedPushControl(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            .max_push_id,
            push_id,
        ) catch |err| {
            self.control.local_max_push_id = previous_max_push_id;
            return err;
        };
    }

    pub fn cancelPush(
        self: *ProtectedClient,
        push_id: u64,
    ) Error!void {
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedPushControl(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            .cancel_push,
            push_id,
        );
        try self.push_streams.observePeerCancellation(push_id);
        try self.applyPendingPushCancellations();
    }

    pub fn cancelRequest(
        self: *ProtectedClient,
        stream_id: u62,
        application_error_code: u64,
    ) Error!void {
        var cancel_qpack = try self.response_streams
            .requiresQpackCancellation(
            stream_id,
            self.qpack_decode.table,
        );
        cancel_qpack = cancel_qpack or
            try self.streaming_responses.hasUnacknowledgedDynamicSection(
                stream_id,
                self.qpack_decode.table,
            );
        try sendProtectedRequestCancellation(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            stream_id,
            application_error_code,
            cancel_qpack,
        );
        self.qpack_encode.abandonStream(stream_id);
        self.response_streams.remove(stream_id);
        self.streaming_responses.remove(stream_id);
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
    }

    pub fn sendPriorityUpdate(
        self: *ProtectedClient,
        stream_id: u62,
        priority: http3.Priority,
    ) Error!void {
        if (stream_id > self.next_stream_id) return error.UnexpectedFrame;
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedPriorityUpdate(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            stream_id,
            priority,
        );
    }

    pub fn sendPushPriorityUpdate(
        self: *ProtectedClient,
        push_id: u64,
        priority: http3.Priority,
    ) Error!void {
        if (self.push_streams.findPromise(push_id) == null) {
            return error.UnexpectedStream;
        }
        try sendProtectedSettings(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
            client_control_stream_id,
        );
        try sendProtectedPriorityUpdateRaw(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.control_send,
            &self.next_packet_number,
            &self.protected_send,
            http3.FrameType.priority_update_push,
            push_id,
            priority,
        );
    }

    fn receiveStreamBytes(self: *ProtectedClient, expected_stream_id: u62) Error!AssembledStream {
        if (self.response_streams.takeReset(expected_stream_id)) |code| {
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        if (try self.response_streams.takeReady(
            expected_stream_id,
            self.qpack_decode.table,
            self.config.local_settings.qpack_blocked_streams,
        )) |ready| return ready;
        while (true) {
            try self.receiveResponsePacket();
            if (self.response_streams.takeReset(expected_stream_id)) |code| {
                return if (code == http3.ApplicationErrorCode.request_rejected)
                    error.RequestRejected
                else
                    error.RequestCancelled;
            }
            if (try self.response_streams.takeReady(
                expected_stream_id,
                self.qpack_decode.table,
                self.config.local_settings.qpack_blocked_streams,
            )) |ready| {
                return ready;
            }
        }
    }

    fn receiveResponsePacket(self: *ProtectedClient) Error!void {
        var packet = try self.receive_packets.take(
            &self.quic_client.endpoint,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            &self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        defer packet.deinit(self.quic_client.endpoint.allocator);
        var flush_qpack_feedback = false;
        for (packet.frames) |frame| {
            try rejectCriticalStreamClosureFrame(self.control, frame, .client);
            if (frame == .reset_stream and
                (frame.reset_stream.stream_id & 0x03) == 0x03)
            {
                const stream_id: u62 = @intCast(
                    frame.reset_stream.stream_id,
                );
                if (try self.push_streams
                    .hasUnacknowledgedDynamicSection(
                    stream_id,
                    self.qpack_decode.table,
                )) {
                    try self.qpack_decode.recordStreamCancellation(
                        stream_id,
                    );
                    flush_qpack_feedback = true;
                }
                self.push_streams.removeByStreamId(stream_id);
                continue;
            }
            if (frame == .reset_stream and
                (try messageStreamDisposition(
                    frame.reset_stream.stream_id,
                )) == .request_response)
            {
                const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
                if (!self.request_lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
                flush_qpack_feedback =
                    try recordClientResponseReset(
                        &self.response_streams,
                        &self.streaming_responses,
                        &self.qpack_decode,
                        stream_id,
                        frame.reset_stream.application_error_code,
                    ) or flush_qpack_feedback;
                continue;
            }
            if (frame != .stream) continue;
            if (isPeerQpackStreamFrame(
                self.control,
                self.qpack_encode.decoder_stream,
                frame.stream,
                .client,
                .qpack_decoder,
            )) {
                self.push_streams.removeByStreamId(
                    @intCast(frame.stream.stream_id),
                );
                try self.qpack_encode.applyDecoderStreamFrame(
                    &self.control,
                    frame.stream,
                );
                continue;
            }
            if (isPeerQpackStreamFrame(
                self.control,
                self.qpack_decode.encoder_stream,
                frame.stream,
                .client,
                .qpack_encoder,
            )) {
                self.push_streams.removeByStreamId(
                    @intCast(frame.stream.stream_id),
                );
                try self.qpack_decode.applyEncoderStreamFrame(
                    &self.control,
                    frame.stream,
                );
                continue;
            }
            if (try applyControlStreamFrameForRole(
                &self.control,
                self.quic_client.endpoint.allocator,
                frame.stream,
                .client,
            )) {
                self.push_streams.removeByStreamId(
                    @intCast(frame.stream.stream_id),
                );
                if (self.control.peer_cancelled_push_id) |push_id| {
                    try self.push_streams.observePeerCancellation(
                        push_id,
                    );
                }
                try configureQpackEncoderFromPeerSettings(
                    self.control,
                    &self.qpack_encode,
                );
                continue;
            }
            if (try self.push_streams.insert(
                packet.from,
                frame.stream,
                self.control,
            )) {
                continue;
            }
            if ((try messageStreamDisposition(frame.stream.stream_id)) == .ignore) continue;
            const stream_id: u62 = @intCast(frame.stream.stream_id);
            if (!self.request_lifecycle.contains(stream_id)) {
                return error.UnexpectedStream;
            }
            if (try self.streaming_responses.insert(packet.from, frame.stream)) {
                continue;
            }
            try self.response_streams.insert(packet.from, frame.stream);
        }
        if (flush_qpack_feedback) try self.sendQpackFeedback();
    }

    fn applyStreamingResponseEvent(
        self: *ProtectedClient,
        stream_id: u62,
        event: StreamingEvent,
    ) Error!void {
        const section = try streamingResponseSectionAcknowledgments(event);
        if (event == .push_promise) {
            try http3.validatePushPromise(
                self.control,
                event.push_promise.push_id,
            );
            try self.push_streams.registerPromise(
                event.push_promise.push_id,
                stream_id,
            );
        }
        if (section) |acknowledgments| {
            try self.qpack_decode.acknowledgeSections(
                stream_id,
                acknowledgments,
            );
            // This also flushes Insert Count Increment instructions produced
            // while pumping the peer's encoder stream.
            try self.sendQpackFeedback();
        }
        if (event == .finished) {
            try self.finishStreamingResponse(stream_id);
        }
    }

    fn finishStreamingResponse(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!void {
        _ = try self.request_lifecycle.finish(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.qpack_encode.abandonStream(stream_id);
        self.streaming_responses.remove(stream_id);
    }

    fn sendQpackFeedback(self: *ProtectedClient) Error!void {
        try sendProtectedQpackFeedback(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.qpack_decode,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
    }
};

fn streamingResponseSectionAcknowledgments(
    event: StreamingEvent,
) Error!?usize {
    return switch (event) {
        .head => |head| switch (head) {
            .request => error.UnexpectedFrame,
            .response => |response| response.qpack_section_acknowledgments,
        },
        .push_promise => |promise| promise.request.qpack_section_acknowledgments,
        .trailers => |trailers| trailers.qpack_section_acknowledgments,
        .data_available, .finished => null,
    };
}

fn streamingRequestSectionAcknowledgments(
    event: StreamingEvent,
) Error!?usize {
    return switch (event) {
        .head => |head| switch (head) {
            .request => |request| request.qpack_section_acknowledgments,
            .response => error.UnexpectedFrame,
        },
        .push_promise => error.UnexpectedFrame,
        .trailers => |trailers| trailers.qpack_section_acknowledgments,
        .data_available, .finished => null,
    };
}

fn receiveProtectedPush(
    client: *ProtectedClient,
) Error!PushedResponse {
    const allocator = client.quic_client.endpoint.allocator;
    var head: ?http3.DecodedResponseHead = null;
    errdefer if (head) |*value| value.deinit(allocator);
    var trailers: ?http3.DecodedTrailers = null;
    errdefer if (trailers) |*value| value.deinit(allocator);
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var push_id: ?u64 = null;
    var request_stream_id: u62 = 0;
    var push_stream_id: u62 = 0;
    while (true) {
        var event = try client.receivePushEventMatching(push_id);
        defer event.deinit(allocator);
        if (push_id) |expected| {
            if (event.push_id != expected) return error.UnexpectedStream;
        } else {
            push_id = event.push_id;
            request_stream_id = event.request_stream_id;
            push_stream_id = event.stream_id;
        }
        switch (event.value) {
            .head => |value| {
                if (head != null or value != .response) {
                    return error.UnexpectedFrame;
                }
                head = value.response;
                event.value = .finished;
            },
            .data_available => {
                var chunk: [4096]u8 = undefined;
                while (true) {
                    const entry = client.push_streams.findByPushId(
                        event.push_id,
                    ) orelse return error.UnexpectedStream;
                    if (entry.reader.?.current_frame == null) break;
                    const count = try client.readPushData(
                        event.push_id,
                        &chunk,
                    );
                    if (count == 0) break;
                    try body.appendSlice(allocator, chunk[0..count]);
                }
            },
            .trailers => |value| {
                if (trailers != null) return error.UnexpectedFrame;
                trailers = value;
                event.value = .finished;
            },
            .finished => {},
            .push_promise => return error.UnexpectedFrame,
        }
        if (event.value != .finished or
            client.push_streams.findByPushId(event.push_id) != null)
        {
            continue;
        }
        const decoded_head = head orelse return error.ExpectedHeadersFrame;
        const body_storage: ?[]u8 = if (body.items.len == 0) storage: {
            body.deinit(allocator);
            break :storage null;
        } else try body.toOwnedSlice(allocator);
        const trailer_fields: []http3.Qpack.HeaderField = if (trailers) |value|
            value.fields
        else
            @constCast(&.{});
        const acknowledgments =
            decoded_head.qpack_section_acknowledgments +
            if (trailers) |value|
                value.qpack_section_acknowledgments
            else
                0;
        return .{
            .push_id = push_id.?,
            .request_stream_id = request_stream_id,
            .stream_id = push_stream_id,
            .response = .{
                .status = decoded_head.status,
                .headers = decoded_head.headers,
                .trailers = trailer_fields,
                .body = if (body_storage) |storage| storage else &.{},
                .body_storage = body_storage,
                .consumed = 0,
                .qpack_section_acknowledgments = acknowledgments,
            },
        };
    }
}

fn registerResponsePushPromises(
    pushes: *PushStreamSet,
    request_stream_id: u62,
    bytes: []const u8,
) Error!void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        if (frame.frame_type != http3.FrameType.push_promise) continue;
        const promise = try http3.parsePushPromisePayload(frame.payload);
        try pushes.registerPromise(promise.push_id, request_stream_id);
    }
}

fn releaseStreamingReaderCapacity(
    connection: *quic.one_rtt.Connection,
    reader: *StreamingMessageReader,
) Error!void {
    const amount = reader.uncreditedConsumed();
    if (amount == 0) return;
    try connection.releaseReceivedCapacity(
        reader.receive.stream_id,
        amount,
    );
    reader.markCredited(amount);
}

pub const OwnedProtectedRequest = struct {
    from: net.IpAddress,
    stream_id: u62,
    stream_bytes: []u8,
    request: http3.DecodedRequest,

    pub fn deinit(self: *OwnedProtectedRequest, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedProtectedResponse = struct {
    stream_bytes: []u8,
    response: http3.DecodedResponse,

    pub fn deinit(self: *OwnedProtectedResponse, allocator: std.mem.Allocator) void {
        self.response.deinit(allocator);
        allocator.free(self.stream_bytes);
        self.* = undefined;
    }
};

pub const OwnedProtectedResponseEvent = union(enum) {
    response: struct {
        stream_id: u62,
        value: OwnedProtectedResponse,
    },
    reset: struct {
        stream_id: u62,
        application_error_code: u64,
    },

    pub fn deinit(
        self: *OwnedProtectedResponseEvent,
        allocator: std.mem.Allocator,
    ) void {
        switch (self.*) {
            .response => |*response| response.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

const AssembledStream = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
};

fn validateBlockedStreamLimit(
    settings: http3.Settings,
    max_concurrent_streams: usize,
) Error!void {
    try settings.validateLocal();
    const runtime_limit = std.math.cast(
        u64,
        max_concurrent_streams,
    ) orelse std.math.maxInt(u64);
    if (settings.qpack_blocked_streams > runtime_limit) {
        return error.QpackDynamicTableUnsupported;
    }
}

const RequestStreamSet = struct {
    const Entry = struct {
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,

        fn deinit(self: *Entry) void {
            self.receive.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_stream_index: ?usize = null,
    max_stream_buffer: usize,
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) RequestStreamSet {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    fn deinit(self: *RequestStreamSet) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.* = undefined;
    }

    fn insert(
        self: *RequestStreamSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        const entry = try self.getOrCreate(from, frame.stream_id);
        try entry.receive.insert(frame);
    }

    fn takeReady(
        self: *RequestStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?AssembledStream {
        var ready_index: ?usize = null;
        var blocked_streams: u64 = 0;
        for (self.entries.items, 0..) |*entry, index| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;
            if (ready_index != null and max_blocked_streams == 0) break;
            const bytes = entry.receive.buffer.items[0..final_size];
            if (max_blocked_streams != 0 and
                try messageBlockedByQpack(bytes, table))
            {
                blocked_streams += 1;
                if (blocked_streams > max_blocked_streams) {
                    return error.QpackDecompressionFailed;
                }
                continue;
            }
            if (ready_index == null) ready_index = index;
        }
        const index = ready_index orelse return null;
        const entry = &self.entries.items[index];
        const final_size = entry.receive.final_size.?;
        const owned = try self.allocator.dupe(
            u8,
            entry.receive.buffer.items[0..final_size],
        );
        const from = entry.from;
        const stream_id: u62 = @intCast(entry.receive.stream_id);
        var removed = self.takeEntry(stream_id).?;
        removed.deinit();
        return .{ .from = from, .stream_id = stream_id, .bytes = owned };
    }

    fn getOrCreate(
        self: *RequestStreamSet,
        from: net.IpAddress,
        stream_id: u64,
    ) Error!*Entry {
        const key: u62 = @intCast(stream_id);
        if (self.entries.items.len >= self.max_streams) {
            if (self.entry_index.get(key)) |index| {
                const entry = &self.entries.items[index];
                if (!entry.from.eql(&from)) return error.UnexpectedStream;
                return entry;
            }
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(self.allocator, key);
        if (slot.found_existing) {
            const entry = &self.entries.items[slot.value_ptr.*];
            // A single HTTP/3 connection has one peer address in these
            // runtimes; accepting one stream from multiple sources would
            // merge unrelated connection state.
            if (!entry.from.eql(&from)) return error.UnexpectedStream;
            return entry;
        }
        errdefer _ = self.entry_index.remove(key);
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{
            .receive = .init(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
            ),
            .from = from,
        });
        slot.value_ptr.* = index;
        self.considerLowestStream(index);
        return &self.entries.items[index];
    }

    fn appendEntryAssumeCapacity(
        self: *RequestStreamSet,
        entry: Entry,
    ) *Entry {
        const index = self.entries.items.len;
        const stream_id: u62 = @intCast(entry.receive.stream_id);
        self.entries.appendAssumeCapacity(entry);
        self.entry_index.putAssumeCapacity(stream_id, index);
        self.considerLowestStream(index);
        return &self.entries.items[index];
    }

    fn takeEntry(self: *RequestStreamSet, stream_id: u62) ?Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const last_index = self.entries.items.len - 1;
        const lowest = self.lowest_stream_index;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.receive.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.receive.stream_id)).?.* =
                index;
        }
        if (self.entries.items.len == 0) {
            self.lowest_stream_index = null;
        } else if (lowest == index) {
            self.recomputeLowestStream();
        } else if (lowest == last_index) {
            self.lowest_stream_index = index;
        }
        return removed;
    }

    fn cancel(
        self: *RequestStreamSet,
        stream_id: u64,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const requires_qpack_cancellation =
            try self.requiresQpackCancellation(stream_id, table);
        self.remove(stream_id);
        return requires_qpack_cancellation;
    }

    fn requiresQpackCancellation(
        self: RequestStreamSet,
        stream_id: u64,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const key = std.math.cast(u62, stream_id) orelse return false;
        if (self.entry_index.count() == 0) return false;
        const index = self.entry_index.get(key) orelse return false;
        return try bufferedReceiveUsesDynamicQpack(
            self.entries.items[index].receive,
            table,
        );
    }

    fn remove(self: *RequestStreamSet, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        var removed = self.takeEntry(key) orelse return;
        removed.deinit();
    }

    fn takeReceive(
        self: *RequestStreamSet,
        stream_id: u62,
    ) ?struct {
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,
    } {
        const removed = self.takeEntry(stream_id) orelse return null;
        return .{
            .receive = removed.receive,
            .from = removed.from,
        };
    }

    fn contains(self: RequestStreamSet, stream_id: u62) bool {
        return self.entry_index.count() != 0 and
            self.entry_index.contains(stream_id);
    }

    fn lowestStream(self: RequestStreamSet) ?u62 {
        const index = self.lowest_stream_index orelse return null;
        return @intCast(self.entries.items[index].receive.stream_id);
    }

    fn considerLowestStream(self: *RequestStreamSet, index: usize) void {
        const lowest = self.lowest_stream_index orelse {
            self.lowest_stream_index = index;
            return;
        };
        if (self.entries.items[index].receive.stream_id <
            self.entries.items[lowest].receive.stream_id)
        {
            self.lowest_stream_index = index;
        }
    }

    fn recomputeLowestStream(self: *RequestStreamSet) void {
        self.lowest_stream_index = null;
        for (self.entries.items, 0..) |_, index| {
            self.considerLowestStream(index);
        }
    }
};

const ResponseStreamSet = struct {
    const Entry = struct {
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,

        fn deinit(self: *Entry) void {
            self.receive.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    resets: std.AutoHashMapUnmanaged(u62, u64) = .empty,
    reset_order: std.ArrayList(u62) = .empty,
    reset_head: usize = 0,
    max_stream_buffer: usize,
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) ResponseStreamSet {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    fn deinit(self: *ResponseStreamSet) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.resets.deinit(self.allocator);
        self.reset_order.deinit(self.allocator);
        self.* = undefined;
    }

    fn insert(
        self: *ResponseStreamSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        const stream_id: u62 = @intCast(frame.stream_id);
        if (self.resets.count() != 0 and self.resets.contains(stream_id)) return;
        const entry = try self.getOrCreate(from, stream_id);
        try entry.receive.insert(frame);
    }

    fn recordReset(
        self: *ResponseStreamSet,
        stream_id: u62,
        application_error_code: u64,
    ) std.mem.Allocator.Error!void {
        const slot = try self.resets.getOrPut(self.allocator, stream_id);
        if (!slot.found_existing) {
            if (self.reset_head != 0 and
                self.reset_order.items.len == self.reset_order.capacity)
            {
                self.compactResetOrder();
            }
            try self.reset_order.ensureUnusedCapacity(self.allocator, 1);
            self.reset_order.appendAssumeCapacity(stream_id);
        }
        slot.value_ptr.* = application_error_code;
        self.remove(stream_id);
    }

    fn takeReset(self: *ResponseStreamSet, stream_id: u62) ?u64 {
        if (self.resets.count() == 0) return null;
        const code = self.resets.get(stream_id) orelse return null;
        _ = self.resets.remove(stream_id);
        self.removeResetOrder(stream_id);
        return code;
    }

    fn firstReadyStream(
        self: *ResponseStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?u62 {
        var ready_stream_id: ?u62 = null;
        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;
            const bytes = entry.receive.buffer.items[0..final_size];
            if (max_blocked_streams != 0 and
                try messageBlockedByQpack(bytes, table))
            {
                blocked_streams += 1;
                if (blocked_streams > max_blocked_streams) {
                    return error.QpackDecompressionFailed;
                }
                continue;
            }
            if (ready_stream_id == null) {
                ready_stream_id = @intCast(entry.receive.stream_id);
                if (max_blocked_streams == 0) return ready_stream_id;
            }
        }
        return ready_stream_id;
    }

    fn firstReset(self: *ResponseStreamSet) ?struct {
        stream_id: u62,
        application_error_code: u64,
    } {
        while (self.resetCount() != 0) {
            const stream_id = self.reset_order.items[self.reset_head];
            if (self.resets.get(stream_id)) |code| {
                return .{
                    .stream_id = stream_id,
                    .application_error_code = code,
                };
            }
            self.reset_head += 1;
            self.compactResetOrderIfSparse();
        }
        return null;
    }

    fn count(self: ResponseStreamSet) usize {
        return self.entries.items.len + self.resets.count();
    }

    fn resetCount(self: ResponseStreamSet) usize {
        return self.reset_order.items.len - self.reset_head;
    }

    fn removeResetOrder(self: *ResponseStreamSet, stream_id: u62) void {
        var index = self.reset_head;
        while (index < self.reset_order.items.len) : (index += 1) {
            if (self.reset_order.items[index] != stream_id) continue;
            if (index == self.reset_head) {
                self.reset_head += 1;
            } else if (index == self.reset_order.items.len - 1) {
                _ = self.reset_order.pop();
            } else {
                _ = self.reset_order.orderedRemove(index);
                if (self.reset_head > index) self.reset_head -= 1;
            }
            self.compactResetOrderIfSparse();
            return;
        }
    }

    fn compactResetOrderIfSparse(self: *ResponseStreamSet) void {
        if (self.reset_head == 0) return;
        if (self.reset_head == self.reset_order.items.len or
            self.reset_head >= self.reset_order.items.len / 2)
        {
            self.compactResetOrder();
        }
    }

    fn compactResetOrder(self: *ResponseStreamSet) void {
        if (self.reset_head == 0) return;
        const remaining = self.resetCount();
        if (remaining != 0) {
            @memmove(
                self.reset_order.items[0..remaining],
                self.reset_order.items[self.reset_head..],
            );
        }
        self.reset_order.items.len = remaining;
        self.reset_head = 0;
    }

    fn takeReady(
        self: *ResponseStreamSet,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?AssembledStream {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const entry = &self.entries.items[index];
        const final_size = entry.receive.final_size orelse return null;
        if (entry.receive.contiguous_end < final_size) return null;
        const bytes = entry.receive.buffer.items[0..final_size];
        if (max_blocked_streams != 0 and try messageBlockedByQpack(bytes, table)) {
            if (try self.blockedReadyStreamCount(table) > max_blocked_streams) {
                return error.QpackDecompressionFailed;
            }
            return null;
        }
        const owned = try self.allocator.dupe(
            u8,
            bytes,
        );
        const from = entry.from;
        var removed = self.takeEntry(stream_id).?;
        removed.deinit();
        return .{ .from = from, .stream_id = stream_id, .bytes = owned };
    }

    fn blockedReadyStreamCount(
        self: *ResponseStreamSet,
        table: http3.Qpack.DynamicTable,
    ) Error!u64 {
        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;
            const bytes = entry.receive.buffer.items[0..final_size];
            if (try messageBlockedByQpack(bytes, table)) blocked_streams += 1;
        }
        return blocked_streams;
    }

    fn appendEntryAssumeCapacity(
        self: *ResponseStreamSet,
        entry: Entry,
    ) *Entry {
        const index = self.entries.items.len;
        const stream_id: u62 = @intCast(entry.receive.stream_id);
        self.entries.appendAssumeCapacity(entry);
        self.entry_index.putAssumeCapacity(stream_id, index);
        return &self.entries.items[index];
    }

    fn remove(self: *ResponseStreamSet, stream_id: u62) void {
        var removed = self.takeEntry(stream_id) orelse return;
        removed.deinit();
    }

    fn takeEntry(self: *ResponseStreamSet, stream_id: u62) ?Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const last_index = self.entries.items.len - 1;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.receive.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.receive.stream_id)).?.* =
                index;
        }
        return removed;
    }

    fn takeReceive(
        self: *ResponseStreamSet,
        stream_id: u62,
    ) ?struct {
        receive: quic.stream_state.RecvState,
        from: net.IpAddress,
    } {
        const removed = self.takeEntry(stream_id) orelse return null;
        return .{
            .receive = removed.receive,
            .from = removed.from,
        };
    }

    fn requiresQpackCancellation(
        self: ResponseStreamSet,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        if (self.entry_index.count() == 0) return false;
        const index = self.entry_index.get(stream_id) orelse return false;
        return try bufferedReceiveUsesDynamicQpack(
            self.entries.items[index].receive,
            table,
        );
    }

    fn getOrCreate(
        self: *ResponseStreamSet,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!*Entry {
        if (self.entries.items.len >= self.max_streams) {
            if (self.entry_index.get(stream_id)) |index| {
                const entry = &self.entries.items[index];
                if (!entry.from.eql(&from)) return error.UnexpectedStream;
                return entry;
            }
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(self.allocator, stream_id);
        if (slot.found_existing) {
            const entry = &self.entries.items[slot.value_ptr.*];
            if (!entry.from.eql(&from)) return error.UnexpectedStream;
            return entry;
        }
        errdefer _ = self.entry_index.remove(stream_id);
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{
            .receive = .init(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
            ),
            .from = from,
        });
        slot.value_ptr.* = index;
        return &self.entries.items[index];
    }
};

const StreamingMessageSet = struct {
    const Kind = enum { request, response };

    const Reset = struct {
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    };

    const Entry = struct {
        reader: StreamingMessageReader,
        from: ?net.IpAddress = null,

        fn deinit(self: *Entry) void {
            self.reader.deinit();
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_entry_index: ?usize = null,
    resets: std.ArrayList(Reset) = .empty,
    reset_head: usize = 0,
    reset_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_reset_index: ?usize = null,
    max_streams: usize,
    max_stream_buffer: usize,
    settings: http3.Settings,
    kind: Kind,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        settings: http3.Settings,
        kind: Kind,
    ) StreamingMessageSet {
        return .{
            .allocator = allocator,
            .max_streams = max_streams,
            .max_stream_buffer = max_stream_buffer,
            .settings = settings,
            .kind = kind,
        };
    }

    fn deinit(self: *StreamingMessageSet) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.resets.deinit(self.allocator);
        self.reset_index.deinit(self.allocator);
        self.* = undefined;
    }

    fn activateResponse(
        self: *StreamingMessageSet,
        buffered: *ResponseStreamSet,
        stream_id: u62,
    ) Error!*Entry {
        if (self.kind != .response) return error.UnexpectedStream;
        if (self.find(stream_id)) |entry| return entry;
        if (self.entries.items.len + buffered.count() >= self.max_streams and
            !bufferedHasResponse(buffered.*, stream_id))
        {
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(
            self.allocator,
            stream_id,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.entry_index.remove(stream_id);

        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        if (buffered.takeReceive(stream_id)) |owned| {
            return self.appendEntryAssumeCapacity(.{
                .reader = .{
                    .allocator = self.allocator,
                    .receive = owned.receive,
                    .settings = self.settings,
                    .kind = .response,
                    .push_promises_allowed = true,
                    .credited_offset = owned.receive.read_offset,
                },
                .from = owned.from,
            }, slot.value_ptr);
        }
        return self.appendEntryAssumeCapacity(.{
            .reader = .initResponse(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
                self.settings,
            ),
        }, slot.value_ptr);
    }

    fn activateBufferedResponses(
        self: *StreamingMessageSet,
        buffered: *ResponseStreamSet,
    ) Error!void {
        if (self.kind != .response) return error.UnexpectedStream;
        while (buffered.entries.items.len != 0) {
            const stream_id: u62 = @intCast(
                buffered.entries.items[0].receive.stream_id,
            );
            _ = try self.activateResponse(buffered, stream_id);
        }
    }

    fn nextResponse(
        self: *StreamingMessageSet,
        buffered: *ResponseStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?struct {
        entry: *Entry,
        event: StreamingEvent,
    } {
        if (self.kind != .response) return error.UnexpectedStream;
        try self.activateBufferedResponses(buffered);
        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            const event = entry.reader.next(table) catch |err| switch (err) {
                error.QpackBlocked => {
                    blocked_streams += 1;
                    if (blocked_streams > max_blocked_streams) {
                        return error.QpackDecompressionFailed;
                    }
                    continue;
                },
                else => return err,
            };
            if (event) |value| return .{ .entry = entry, .event = value };
        }
        return null;
    }

    fn activateRequest(
        self: *StreamingMessageSet,
        buffered: *RequestStreamSet,
        stream_id: u62,
    ) Error!*Entry {
        if (self.kind != .request) return error.UnexpectedStream;
        if (self.find(stream_id)) |entry| return entry;
        if (self.retainedCount() >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const slot = try self.entry_index.getOrPut(
            self.allocator,
            stream_id,
        );
        std.debug.assert(!slot.found_existing);
        errdefer _ = self.entry_index.remove(stream_id);

        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        if (buffered.takeReceive(stream_id)) |owned| {
            return self.appendEntryAssumeCapacity(.{
                .reader = .{
                    .allocator = self.allocator,
                    .receive = owned.receive,
                    .settings = self.settings,
                    .kind = .request,
                    .credited_offset = owned.receive.read_offset,
                },
                .from = owned.from,
            }, slot.value_ptr);
        }
        return self.appendEntryAssumeCapacity(.{
            .reader = .initRequest(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
                self.settings,
            ),
        }, slot.value_ptr);
    }

    fn insert(
        self: *StreamingMessageSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!bool {
        const stream_id: u62 = @intCast(frame.stream_id);
        const entry = self.find(stream_id) orelse return false;
        if (entry.from) |existing| {
            if (!existing.eql(&from)) return error.UnexpectedStream;
        } else {
            entry.from = from;
        }
        try entry.reader.insert(frame);
        return true;
    }

    fn appendEntryAssumeCapacity(
        self: *StreamingMessageSet,
        entry: Entry,
        index_slot: *usize,
    ) *Entry {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        index_slot.* = index;
        self.considerLowestEntry(index);
        return &self.entries.items[index];
    }

    fn remove(self: *StreamingMessageSet, stream_id: u62) void {
        self.removeEntry(stream_id);
        if (self.reset_index.count() == 0) return;
        if (self.reset_index.get(stream_id)) |index| {
            self.removeResetAt(index);
            self.compactResetQueueIfSparse();
        }
    }

    fn removeEntry(self: *StreamingMessageSet, stream_id: u62) void {
        var removed = self.takeEntry(stream_id) orelse return;
        removed.deinit();
    }

    fn takeEntry(self: *StreamingMessageSet, stream_id: u62) ?Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        const last_index = self.entries.items.len - 1;
        const lowest = self.lowest_entry_index;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.reader.receive.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.reader.receive.stream_id)).?.* =
                index;
        }
        if (self.entries.items.len == 0) {
            self.lowest_entry_index = null;
        } else if (lowest == index) {
            self.recomputeLowestEntry();
        } else if (lowest == last_index) {
            self.lowest_entry_index = index;
        }
        return removed;
    }

    fn find(self: *StreamingMessageSet, stream_id: u62) ?*Entry {
        if (self.entry_index.count() == 0) return null;
        const index = self.entry_index.get(stream_id) orelse return null;
        if (index >= self.entries.items.len) return null;
        if (self.entries.items[index].reader.receive.stream_id != stream_id) {
            return null;
        }
        return &self.entries.items[index];
    }

    fn activateBufferedRequests(
        self: *StreamingMessageSet,
        buffered: *RequestStreamSet,
    ) Error!void {
        while (buffered.entries.items.len != 0) {
            const stream_id: u62 = @intCast(
                buffered.entries.items[0].receive.stream_id,
            );
            _ = try self.activateRequest(buffered, stream_id);
        }
    }

    fn prepareReset(
        self: *StreamingMessageSet,
        from: net.IpAddress,
        stream_id: u62,
        buffered_streams: usize,
        replaces_stream: bool,
    ) Error!void {
        if (self.kind != .request) return error.UnexpectedStream;
        if (self.reset_index.get(stream_id)) |index| {
            const reset = self.resets.items[index];
            if (!reset.from.eql(&from)) return error.UnexpectedStream;
            return;
        }
        const projected_count =
            buffered_streams +
            self.retainedCount() +
            @intFromBool(!replaces_stream);
        if (projected_count > self.max_streams) {
            return error.ExcessiveLoad;
        }
        if (self.reset_head != 0 and
            self.resets.items.len == self.resets.capacity)
        {
            self.compactResetQueue();
        }
        try self.resets.ensureUnusedCapacity(self.allocator, 1);
        try self.reset_index.ensureUnusedCapacity(self.allocator, 1);
    }

    fn recordResetAssumeCapacity(
        self: *StreamingMessageSet,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        if (self.reset_index.get(stream_id)) |index| {
            const reset = &self.resets.items[index];
            reset.application_error_code = application_error_code;
            return;
        }
        self.recordNewResetAssumeCapacity(
            from,
            stream_id,
            application_error_code,
        );
    }

    fn recordPreparedNewResetAssumeCapacity(
        self: *StreamingMessageSet,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        std.debug.assert(self.reset_index.get(stream_id) == null);
        self.recordNewResetAssumeCapacity(
            from,
            stream_id,
            application_error_code,
        );
    }

    fn recordNewResetAssumeCapacity(
        self: *StreamingMessageSet,
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    ) void {
        var removed_entry = self.takeEntry(stream_id);
        if (self.reset_head != 0 and
            self.resets.items.len == self.resets.capacity)
        {
            self.compactResetQueue();
        }
        const index = self.resets.items.len;
        self.resets.appendAssumeCapacity(.{
            .from = from,
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        });
        self.reset_index.putAssumeCapacityNoClobber(
            stream_id,
            index,
        );
        self.considerLowestReset(index);
        if (removed_entry) |*entry| entry.deinit();
    }

    fn takeFirstReset(self: *StreamingMessageSet) ?Reset {
        if (self.resetCount() == 0) return null;
        const old_head = self.reset_head;
        const reset = self.resets.items[old_head];
        _ = self.reset_index.remove(reset.stream_id);
        self.reset_head += 1;
        if (self.resetCount() == 0) {
            self.lowest_reset_index = null;
        } else if (self.lowest_reset_index == old_head) {
            self.recomputeLowestReset();
        }
        // Reset delivery is FIFO but may happen in bursts. Advancing a cursor
        // keeps each pop O(1); occasional compaction reclaims consumed slots
        // before a bounded max-stream queue would otherwise appear full.
        self.compactResetQueueIfSparse();
        return reset;
    }

    fn contains(self: StreamingMessageSet, stream_id: u62) bool {
        if (self.entry_index.count() != 0 and
            self.entry_index.contains(stream_id)) return true;
        return self.reset_index.count() != 0 and
            self.reset_index.contains(stream_id);
    }

    fn retainedCount(self: StreamingMessageSet) usize {
        return self.entries.items.len + self.resetCount();
    }

    fn insertRequest(
        self: *StreamingMessageSet,
        buffered: *RequestStreamSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
    ) Error!void {
        if (self.kind != .request) return error.UnexpectedStream;
        if (try self.insert(from, frame)) return;
        const stream_id: u62 = @intCast(frame.stream_id);
        // RESET_STREAM is terminal for an HTTP/3 request stream. Ignore any
        // STREAM frame later in the same packet instead of recreating a reader
        // behind the queued reset event.
        if (self.contains(stream_id)) return;
        if (!buffered.contains(stream_id) and
            buffered.entries.items.len + self.retainedCount() >=
                self.max_streams)
        {
            return error.ExcessiveLoad;
        }
        try buffered.insert(from, frame);
    }

    fn nextRequest(
        self: *StreamingMessageSet,
        buffered: *RequestStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
    ) Error!?struct {
        entry: *Entry,
        event: StreamingEvent,
    } {
        if (self.kind != .request) return error.UnexpectedStream;
        try self.activateBufferedRequests(buffered);
        var blocked_streams: u64 = 0;
        for (self.entries.items) |*entry| {
            const event = entry.reader.next(table) catch |err| switch (err) {
                error.QpackBlocked => {
                    blocked_streams += 1;
                    if (blocked_streams > max_blocked_streams) {
                        return error.QpackDecompressionFailed;
                    }
                    continue;
                },
                else => return err,
            };
            if (event) |value| return .{ .entry = entry, .event = value };
        }
        return null;
    }

    fn hasUnacknowledgedDynamicSection(
        self: *StreamingMessageSet,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const entry = self.find(stream_id) orelse return false;
        return entry.reader.hasUnacknowledgedDynamicSection(table);
    }

    fn lowestEntryStream(self: StreamingMessageSet) ?u62 {
        const index = self.lowest_entry_index orelse return null;
        return @intCast(self.entries.items[index].reader.receive.stream_id);
    }

    fn lowestResetStream(self: StreamingMessageSet) ?u62 {
        const index = self.lowest_reset_index orelse return null;
        if (index < self.reset_head or index >= self.resets.items.len) return null;
        return self.resets.items[index].stream_id;
    }

    fn resetCount(self: StreamingMessageSet) usize {
        return self.resets.items.len - self.reset_head;
    }

    fn compactResetQueueIfSparse(self: *StreamingMessageSet) void {
        if (self.reset_head == 0) return;
        if (self.reset_head == self.resets.items.len or
            self.reset_head >= self.resets.items.len / 2)
        {
            self.compactResetQueue();
        }
    }

    fn compactResetQueue(self: *StreamingMessageSet) void {
        if (self.reset_head == 0) return;
        const remaining = self.resetCount();
        if (remaining != 0) {
            @memmove(
                self.resets.items[0..remaining],
                self.resets.items[self.reset_head..],
            );
        }
        self.resets.items.len = remaining;
        self.reset_head = 0;
        self.rebuildResetIndexAssumeCapacity();
        self.recomputeLowestReset();
    }

    fn removeResetAt(self: *StreamingMessageSet, index: usize) void {
        const last_index = self.resets.items.len - 1;
        const lowest = self.lowest_reset_index;
        const removed = self.resets.swapRemove(index);
        _ = self.reset_index.remove(removed.stream_id);
        if (index < self.resets.items.len) {
            const moved = self.resets.items[index];
            self.reset_index.getPtr(moved.stream_id).?.* = index;
        }
        if (self.resetCount() == 0) {
            self.lowest_reset_index = null;
        } else if (lowest == index) {
            self.recomputeLowestReset();
        } else if (lowest == last_index) {
            self.lowest_reset_index = index;
        }
    }

    fn rebuildResetIndexAssumeCapacity(self: *StreamingMessageSet) void {
        self.reset_index.clearRetainingCapacity();
        for (self.resets.items[self.reset_head..], self.reset_head..) |reset, index| {
            self.reset_index.putAssumeCapacityNoClobber(reset.stream_id, index);
        }
    }

    fn considerLowestEntry(self: *StreamingMessageSet, index: usize) void {
        const lowest = self.lowest_entry_index orelse {
            self.lowest_entry_index = index;
            return;
        };
        if (self.entries.items[index].reader.receive.stream_id <
            self.entries.items[lowest].reader.receive.stream_id)
        {
            self.lowest_entry_index = index;
        }
    }

    fn recomputeLowestEntry(self: *StreamingMessageSet) void {
        self.lowest_entry_index = null;
        for (self.entries.items, 0..) |_, index| {
            self.considerLowestEntry(index);
        }
    }

    fn considerLowestReset(self: *StreamingMessageSet, index: usize) void {
        if (index < self.reset_head) return;
        const lowest = self.lowest_reset_index orelse {
            self.lowest_reset_index = index;
            return;
        };
        if (self.resets.items[index].stream_id <
            self.resets.items[lowest].stream_id)
        {
            self.lowest_reset_index = index;
        }
    }

    fn recomputeLowestReset(self: *StreamingMessageSet) void {
        self.lowest_reset_index = null;
        var index = self.reset_head;
        while (index < self.resets.items.len) : (index += 1) {
            self.considerLowestReset(index);
        }
    }
};

const StreamingResponseSet = StreamingMessageSet;
const StreamingRequestSet = StreamingMessageSet;

const PushStreamSet = struct {
    const PrefixResult = enum {
        incomplete,
        push,
        other,
    };

    const Entry = struct {
        receive: quic.stream_state.RecvState,
        reader: ?StreamingMessageReader = null,
        push_id: ?u64 = null,
        from: ?net.IpAddress = null,

        fn deinit(self: *Entry) void {
            if (self.reader) |*reader| {
                reader.deinit();
            } else {
                self.receive.deinit();
            }
            self.* = undefined;
        }

        fn receiveState(self: *Entry) *quic.stream_state.RecvState {
            if (self.reader) |*reader| return &reader.receive;
            return &self.receive;
        }

        fn streamId(self: *const Entry) u64 {
            if (self.reader) |*reader| return reader.receive.stream_id;
            return self.receive.stream_id;
        }

        fn parsePrefix(
            self: *Entry,
            control: http3.ControlState,
            settings: http3.Settings,
        ) Error!PrefixResult {
            if (self.reader != null) return .push;
            const available = self.receive.available();
            var cursor = @import("../internal/wire.zig").Cursor.init(
                available,
            );
            const stream_type: http3.StreamType = @enumFromInt(
                quic.varint.decode(&cursor) catch |err| switch (err) {
                    error.BufferTooShort => {
                        if (self.receive.final_size != null) {
                            return error.InvalidStreamType;
                        }
                        return .incomplete;
                    },
                    else => return err,
                },
            );
            if (stream_type != .push) return .other;
            const push_id = quic.varint.decode(&cursor) catch |err| switch (err) {
                error.BufferTooShort => {
                    if (self.receive.final_size != null) {
                        return error.InvalidStreamType;
                    }
                    return .incomplete;
                },
                else => return err,
            };
            try http3.validatePushPromise(control, push_id);

            // Transfer the reassembler rather than copying payload bytes. The
            // message reader starts after both varints but keeps absolute QUIC
            // offsets for reset handling and receive-credit replenishment.
            try self.receive.consume(cursor.pos);
            const receive = self.receive;
            self.reader = .{
                .allocator = receive.allocator,
                .receive = receive,
                .settings = settings,
                .kind = .response,
            };
            self.push_id = push_id;
            return .push;
        }
    };

    const Promise = struct {
        const State = enum {
            promised,
            active,
            finished,
        };

        push_id: u64,
        request_stream_id: u62,
        state: State = .promised,
    };

    const ReadyEvent = struct {
        index: usize,
        event: StreamingPushEvent,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    stream_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    push_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    promises: std.ArrayList(Promise) = .empty,
    promise_index: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    cancelled_stream_ids: std.ArrayList(u62) = .empty,
    cancelled_stream_head: usize = 0,
    max_streams: usize,
    max_stream_buffer: usize,
    settings: http3.Settings,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        settings: http3.Settings,
    ) PushStreamSet {
        return .{
            .allocator = allocator,
            .max_streams = max_streams,
            .max_stream_buffer = max_stream_buffer,
            .settings = settings,
        };
    }

    fn deinit(self: *PushStreamSet) void {
        for (self.entries.items) |*entry| entry.deinit();
        self.entries.deinit(self.allocator);
        self.stream_index.deinit(self.allocator);
        self.push_index.deinit(self.allocator);
        self.promises.deinit(self.allocator);
        self.promise_index.deinit(self.allocator);
        self.cancelled_stream_ids.deinit(self.allocator);
        self.* = undefined;
    }

    fn reservePromisesThrough(
        self: *PushStreamSet,
        push_id: u64,
    ) Error!void {
        _ = push_id;
        try self.promises.ensureTotalCapacity(
            self.allocator,
            self.max_streams,
        );
        try self.promise_index.ensureTotalCapacity(
            self.allocator,
            std.math.cast(u32, self.max_streams) orelse
                return error.OutOfMemory,
        );
        try self.cancelled_stream_ids.ensureTotalCapacity(
            self.allocator,
            self.max_streams,
        );
    }

    fn registerPromise(
        self: *PushStreamSet,
        push_id: u64,
        request_stream_id: u62,
    ) Error!void {
        // RFC 9114 permits the same push to be promised by multiple request
        // streams. The first parent remains the canonical correlation exposed
        // on push events.
        if (self.promises.items.len == self.promises.capacity) {
            if (self.promise_index.contains(push_id)) return;
            // MAX_PUSH_ID reserves one slot for every legal unique ID before
            // it is put on the wire, making event application allocation-free
            // after the request reader has transactionally consumed bytes.
            return error.ExcessiveLoad;
        }
        const slot = self.promise_index.getOrPutAssumeCapacity(push_id);
        if (slot.found_existing) return;
        const index = self.promises.items.len;
        self.promises.appendAssumeCapacity(.{
            .push_id = push_id,
            .request_stream_id = request_stream_id,
        });
        slot.value_ptr.* = index;
        errdefer {
            _ = self.promise_index.remove(push_id);
            _ = self.promises.pop();
        }
        if (self.findByPushId(push_id)) |entry| {
            try self.validateBinding(entry);
        }
    }

    fn appendEntryAssumeCapacity(
        self: *PushStreamSet,
        entry: Entry,
        stream_slot: *usize,
    ) *Entry {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(entry);
        stream_slot.* = index;
        if (self.entries.items[index].push_id) |push_id| {
            self.push_index.putAssumeCapacity(push_id, index);
        }
        return &self.entries.items[index];
    }

    fn rememberPushBinding(
        self: *PushStreamSet,
        entry: *const Entry,
    ) Error!void {
        const push_id = entry.push_id orelse return;
        const stream_id: u62 = @intCast(entry.streamId());
        const index = self.stream_index.get(stream_id) orelse return;
        const slot = try self.push_index.getOrPut(self.allocator, push_id);
        if (slot.found_existing) {
            if (slot.value_ptr.* != index) return error.DuplicatePushId;
            return;
        }
        slot.value_ptr.* = index;
    }

    fn takeEntryAt(self: *PushStreamSet, index: usize) Entry {
        const last_index = self.entries.items.len - 1;
        const removed = self.entries.swapRemove(index);
        _ = self.stream_index.remove(@intCast(removed.streamId()));
        if (removed.push_id) |push_id| _ = self.push_index.remove(push_id);
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.stream_index.getPtr(@intCast(moved.streamId())).?.* = index;
            if (moved.push_id) |push_id| {
                self.push_index.getPtr(push_id).?.* = index;
            }
        }
        return removed;
    }

    fn insert(
        self: *PushStreamSet,
        from: net.IpAddress,
        frame: quic.StreamFrame,
        control: http3.ControlState,
    ) Error!bool {
        if ((frame.stream_id & 0x03) != 0x03) return false;
        if (self.findByStreamId(frame.stream_id)) |entry| {
            if (entry.from) |existing| {
                if (!existing.eql(&from)) return error.UnexpectedStream;
            }
            const receive = entry.receiveState();
            try receive.insert(frame);
            switch (try entry.parsePrefix(control, self.settings)) {
                .incomplete => {},
                .push => {
                    try self.validateBinding(entry);
                    try self.rememberPushBinding(entry);
                },
                .other => {
                    self.removeStream(frame.stream_id);
                    return false;
                },
            }
            return true;
        }
        // Buffer unmatched nonzero ranges even when offset zero is reordered
        // behind them. At offset zero the one-byte push type must already be
        // visible; never steal a fragmented unknown/critical stream from its
        // dedicated router.
        if (frame.offset == 0) {
            const stream_type = peekUniStreamType(frame) orelse {
                if (frame.fin) return error.InvalidStreamType;
                return false;
            };
            if (stream_type != .push) return false;
        }
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const stream_id: u62 = @intCast(frame.stream_id);
        const stream_slot = try self.stream_index.getOrPut(
            self.allocator,
            stream_id,
        );
        std.debug.assert(!stream_slot.found_existing);
        errdefer _ = self.stream_index.remove(stream_id);
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        const entry = self.appendEntryAssumeCapacity(.{
            .receive = .init(
                self.allocator,
                frame.stream_id,
                self.max_stream_buffer,
            ),
            .from = from,
        }, stream_slot.value_ptr);
        errdefer {
            var removed = self.takeEntryAt(self.entries.items.len - 1);
            removed.deinit();
        }
        try entry.receive.insert(frame);
        switch (try entry.parsePrefix(control, self.settings)) {
            .incomplete => {},
            .push => {
                try self.validateBinding(entry);
                try self.rememberPushBinding(entry);
            },
            .other => {
                self.removeStream(frame.stream_id);
                return false;
            },
        }
        return true;
    }

    fn next(
        self: *PushStreamSet,
        table: http3.Qpack.DynamicTable,
        max_blocked_streams: u64,
        target_push_id: ?u64,
    ) Error!?ReadyEvent {
        if (target_push_id) |push_id| {
            if (self.push_index.count() == 0) return null;
            const index = self.push_index.get(push_id) orelse return null;
            return self.nextEntryEvent(
                index,
                table,
                max_blocked_streams,
            );
        }

        var blocked_streams: u64 = 0;
        for (self.entries.items, 0..) |*entry, index| {
            if (entry.reader == null) continue;
            const push_id = entry.push_id orelse continue;
            const promise = self.findPromise(push_id) orelse continue;
            const event = entry.reader.?.next(table) catch |err| switch (err) {
                error.QpackBlocked => {
                    blocked_streams += 1;
                    if (blocked_streams > max_blocked_streams) {
                        return error.QpackDecompressionFailed;
                    }
                    continue;
                },
                else => return err,
            };
            if (event) |value| {
                return .{
                    .index = index,
                    .event = .{
                        .push_id = push_id,
                        .request_stream_id = promise.request_stream_id,
                        .stream_id = @intCast(
                            entry.reader.?.receive.stream_id,
                        ),
                        .value = value,
                    },
                };
            }
        }
        return null;
    }

    fn nextEntryEvent(
        self: *PushStreamSet,
        index: usize,
        table: http3.Qpack.DynamicTable,
        remaining_blocked_budget: u64,
    ) Error!?ReadyEvent {
        if (index >= self.entries.items.len) return null;
        const entry = &self.entries.items[index];
        if (entry.reader == null) return null;
        const push_id = entry.push_id orelse return null;
        const promise = self.findPromise(push_id) orelse return null;
        const event = entry.reader.?.next(table) catch |err| switch (err) {
            error.QpackBlocked => {
                if (remaining_blocked_budget == 0) {
                    return error.QpackDecompressionFailed;
                }
                return null;
            },
            else => return err,
        };
        if (event) |value| {
            return .{
                .index = index,
                .event = .{
                    .push_id = push_id,
                    .request_stream_id = promise.request_stream_id,
                    .stream_id = @intCast(
                        entry.reader.?.receive.stream_id,
                    ),
                    .value = value,
                },
            };
        }
        return null;
    }

    fn observePeerCancellation(
        self: *PushStreamSet,
        push_id: u64,
    ) Error!void {
        const promise = self.findPromise(push_id) orelse
            return error.UnexpectedStream;
        if (promise.state == .finished) return;
        promise.state = .finished;
        if (self.findByPushId(push_id)) |entry| {
            const stream_id: u62 = @intCast(entry.streamId());
            if (self.cancelled_stream_head != 0 and
                self.cancelled_stream_ids.items.len ==
                    self.cancelled_stream_ids.capacity)
            {
                self.compactCancelledStreamQueue();
            }
            if (self.cancelled_stream_ids.items.len ==
                self.cancelled_stream_ids.capacity)
            {
                return error.ExcessiveLoad;
            }
            self.cancelled_stream_ids.appendAssumeCapacity(stream_id);
            self.removeStream(stream_id);
        }
    }

    fn takeCancelledStream(self: *PushStreamSet) ?u62 {
        if (self.cancelledStreamCount() == 0) return null;
        const stream_id = self.cancelled_stream_ids.items[self.cancelled_stream_head];
        self.cancelled_stream_head += 1;
        self.compactCancelledStreamQueueIfSparse();
        return stream_id;
    }

    fn readData(
        self: *PushStreamSet,
        push_id: u64,
        out: []u8,
    ) Error!usize {
        const entry = self.findByPushId(push_id) orelse
            return error.UnexpectedStream;
        return entry.reader.?.readData(out);
    }

    fn removeFinished(self: *PushStreamSet, index: usize) void {
        const push_id = self.entries.items[index].push_id.?;
        const promise = self.findPromise(push_id) orelse unreachable;
        promise.state = .finished;
        var removed = self.takeEntryAt(index);
        removed.deinit();
    }

    fn hasUnacknowledgedDynamicSection(
        self: *PushStreamSet,
        stream_id: u62,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const entry = self.findByStreamId(stream_id) orelse return false;
        if (entry.reader) |reader| {
            return reader.hasUnacknowledgedDynamicSection(table);
        }
        return false;
    }

    fn removeByStreamId(self: *PushStreamSet, stream_id: u62) void {
        self.removeStream(stream_id);
    }

    fn cancelledStreamCount(self: PushStreamSet) usize {
        return self.cancelled_stream_ids.items.len -
            self.cancelled_stream_head;
    }

    fn compactCancelledStreamQueueIfSparse(self: *PushStreamSet) void {
        if (self.cancelled_stream_head == 0) return;
        if (self.cancelled_stream_head == self.cancelled_stream_ids.items.len or
            self.cancelled_stream_head >=
                self.cancelled_stream_ids.items.len / 2)
        {
            self.compactCancelledStreamQueue();
        }
    }

    fn compactCancelledStreamQueue(self: *PushStreamSet) void {
        if (self.cancelled_stream_head == 0) return;
        const remaining = self.cancelledStreamCount();
        if (remaining != 0) {
            @memmove(
                self.cancelled_stream_ids.items[0..remaining],
                self.cancelled_stream_ids.items[self.cancelled_stream_head..],
            );
        }
        self.cancelled_stream_ids.items.len = remaining;
        self.cancelled_stream_head = 0;
    }

    fn findByStreamId(self: *PushStreamSet, stream_id: u64) ?*Entry {
        const key = std.math.cast(u62, stream_id) orelse return null;
        if (self.stream_index.count() == 0) return null;
        const index = self.stream_index.get(key) orelse return null;
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    fn findByPushId(self: *PushStreamSet, push_id: u64) ?*Entry {
        if (self.push_index.count() == 0) return null;
        const index = self.push_index.get(push_id) orelse return null;
        if (index >= self.entries.items.len) return null;
        return &self.entries.items[index];
    }

    fn removeStream(self: *PushStreamSet, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        if (self.stream_index.count() == 0) return;
        const index = self.stream_index.get(key) orelse return;
        var removed = self.takeEntryAt(index);
        removed.deinit();
    }

    fn validateBinding(self: PushStreamSet, entry: *const Entry) Error!void {
        const push_id = entry.push_id orelse return;
        // QUIC does not preserve ordering across streams, so the push stream
        // may arrive before the request stream carrying PUSH_PROMISE. Retain
        // it, but `next` will not expose response events until the promise is
        // registered by the request-stream decoder.
        const stream_id: u62 = @intCast(entry.streamId());
        const entry_index = self.stream_index.get(stream_id) orelse return;
        if (self.push_index.get(push_id)) |existing_index| {
            if (existing_index != entry_index) return error.DuplicatePushId;
        }
        if (self.findPromise(push_id)) |promise| {
            if (promise.state == .finished) return error.DuplicatePushId;
            promise.state = .active;
        }
    }

    fn appendPromisedIds(
        self: PushStreamSet,
        out: *std.ArrayList(u64),
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!void {
        try out.ensureUnusedCapacity(allocator, self.promises.items.len);
        for (self.promises.items) |promise| {
            out.appendAssumeCapacity(promise.push_id);
        }
    }

    fn findPromise(self: PushStreamSet, push_id: u64) ?*Promise {
        if (self.promise_index.count() == 0) return null;
        const index = self.promise_index.get(push_id) orelse return null;
        if (index >= self.promises.items.len) return null;
        return &self.promises.items[index];
    }
};

fn bufferedHasResponse(
    buffered: ResponseStreamSet,
    stream_id: u62,
) bool {
    return (buffered.resets.count() != 0 and
        buffered.resets.contains(stream_id)) or
        (buffered.entry_index.count() != 0 and
            buffered.entry_index.contains(stream_id));
}

const ClientRequestLifecycle = struct {
    allocator: std.mem.Allocator,
    outstanding: std.ArrayList(u62) = .empty,
    outstanding_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    finished: std.AutoHashMapUnmanaged(u62, void) = .empty,
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
    ) ClientRequestLifecycle {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    fn deinit(self: *ClientRequestLifecycle) void {
        self.outstanding.deinit(self.allocator);
        self.outstanding_index.deinit(self.allocator);
        self.finished.deinit(self.allocator);
        self.* = undefined;
    }

    fn open(self: *ClientRequestLifecycle, stream_id: u62) Error!void {
        if (self.outstanding.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const slot = try self.outstanding_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) return error.UnexpectedStream;
        errdefer _ = self.outstanding_index.remove(stream_id);
        const index = self.outstanding.items.len;
        try self.outstanding.append(self.allocator, stream_id);
        slot.value_ptr.* = index;
    }

    fn contains(self: ClientRequestLifecycle, stream_id: u62) bool {
        return self.outstanding_index.count() != 0 and
            self.outstanding_index.contains(stream_id);
    }

    fn isFinished(self: ClientRequestLifecycle, stream_id: u62) bool {
        return self.finished.count() != 0 and self.finished.contains(stream_id);
    }

    fn finish(self: *ClientRequestLifecycle, stream_id: u62) Error!bool {
        if (self.outstanding_index.count() == 0) return false;
        const index = self.outstanding_index.get(stream_id) orelse return false;
        try self.finished.put(self.allocator, stream_id, {});
        errdefer _ = self.finished.remove(stream_id);
        const last_index = self.outstanding.items.len - 1;
        const removed = self.outstanding.swapRemove(index);
        _ = self.outstanding_index.remove(removed);
        if (index != last_index) {
            const moved = self.outstanding.items[index];
            self.outstanding_index.getPtr(moved).?.* = index;
        }
        return true;
    }
};

test "HTTP/3 client request lifecycle indexes outstanding streams" {
    const allocator = std.testing.allocator;
    var lifecycle = ClientRequestLifecycle.init(allocator, 3);
    defer lifecycle.deinit();

    try lifecycle.open(0);
    try lifecycle.open(4);
    try lifecycle.open(8);
    try std.testing.expect(lifecycle.contains(0));
    try std.testing.expect(lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expectError(error.ExcessiveLoad, lifecycle.open(12));

    // Removing from the middle uses swapRemove; the moved stream must keep a
    // valid index because send/receive body paths call contains() frequently.
    try std.testing.expect(try lifecycle.finish(4));
    try std.testing.expect(!lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expect(try lifecycle.finish(8));
    try std.testing.expect(!lifecycle.contains(8));

    try lifecycle.open(12);
    try std.testing.expect(lifecycle.contains(12));
    try std.testing.expect(!try lifecycle.finish(4));
    try std.testing.expect(try lifecycle.finish(0));
    try std.testing.expect(try lifecycle.finish(12));
    try std.testing.expectEqual(@as(usize, 0), lifecycle.outstanding.items.len);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.outstanding_index.count());
}

const OutboundBodySet = struct {
    const Entry = struct {
        send: quic.stream_state.SendState,
        expected_length: ?usize,
        written: usize = 0,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    last_entry_index: ?usize = null,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    frame_scratch: std.ArrayList(quic.Frame) = .empty,
    payload_scratch: std.ArrayList(u8) = .empty,
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
    ) OutboundBodySet {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    fn deinit(self: *OutboundBodySet) void {
        self.payload_scratch.deinit(self.allocator);
        self.frame_scratch.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.entry_index.deinit(self.allocator);
        self.* = undefined;
    }

    fn reserveOpen(
        self: *OutboundBodySet,
        stream_id: u62,
    ) Error!void {
        if (self.entries.items.len != 0 and
            self.find(stream_id) != null) return error.UnexpectedStream;
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.ensureUnusedCapacity(self.allocator, 1);
        try self.entry_index.ensureUnusedCapacity(self.allocator, 1);
    }

    fn appendOpenAssumeCapacity(
        self: *OutboundBodySet,
        stream_id: u62,
        send: quic.stream_state.SendState,
        expected_length: ?usize,
    ) void {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{
            .send = send,
            .expected_length = expected_length,
        });
        self.entry_index.putAssumeCapacity(stream_id, index);
        self.last_entry_index = index;
    }

    fn prepareChunk(
        self: *OutboundBodySet,
        stream_id: u62,
        chunk_len: usize,
        fin: bool,
    ) Error!*Entry {
        const entry = self.find(stream_id) orelse return error.UnexpectedStream;
        try self.prepareChunkForEntry(entry, chunk_len, fin);
        return entry;
    }

    fn prepareChunkForEntry(
        self: *OutboundBodySet,
        entry: *Entry,
        chunk_len: usize,
        fin: bool,
    ) Error!void {
        _ = self;
        const next_written = std.math.add(
            usize,
            entry.written,
            chunk_len,
        ) catch return error.InvalidContentLength;
        if (entry.expected_length) |expected| {
            if (next_written > expected) return error.InvalidContentLength;
            if (fin and next_written != expected) {
                return error.InvalidContentLength;
            }
        }
        if (!fin and chunk_len == 0) return error.InvalidFrame;
        entry.written = next_written;
    }

    fn prepareTrailers(
        self: *OutboundBodySet,
        stream_id: u62,
    ) Error!*Entry {
        const entry = self.find(stream_id) orelse return error.UnexpectedStream;
        if (entry.expected_length) |expected| {
            if (entry.written != expected) return error.InvalidContentLength;
        }
        return entry;
    }

    fn finish(self: *OutboundBodySet, stream_id: u62) bool {
        if (self.entries.items.len == 0) return false;
        const index = if (self.last_entry_index) |cached| blk: {
            if (cached < self.entries.items.len and
                self.entries.items[cached].send.stream_id == stream_id)
            {
                break :blk cached;
            }
            break :blk self.entry_index.get(stream_id) orelse return false;
        } else self.entry_index.get(stream_id) orelse return false;
        const last_index = self.entries.items.len - 1;
        const removed = self.entries.swapRemove(index);
        _ = self.entry_index.remove(@intCast(removed.send.stream_id));
        if (index != last_index) {
            const moved = self.entries.items[index];
            self.entry_index.getPtr(@intCast(moved.send.stream_id)).?.* = index;
        }
        self.last_entry_index = null;
        return true;
    }

    fn find(self: *OutboundBodySet, stream_id: u62) ?*Entry {
        if (self.entries.items.len == 0) return null;
        if (self.last_entry_index) |index| {
            if (index < self.entries.items.len and
                self.entries.items[index].send.stream_id == stream_id)
            {
                return &self.entries.items[index];
            }
        }
        const index = self.entry_index.get(stream_id) orelse return null;
        if (index >= self.entries.items.len) return null;
        if (self.entries.items[index].send.stream_id != stream_id) return null;
        self.last_entry_index = index;
        return &self.entries.items[index];
    }
};

pub const ShutdownState = enum {
    active,
    initial_goaway,
    final_goaway,
};

const ServerRequestLifecycle = struct {
    allocator: std.mem.Allocator,
    active_streams: std.ArrayList(u62) = .empty,
    active_stream_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    lowest_active_stream_index: ?usize = null,
    highest_processed_stream_id: ?u62 = null,
    shutdown_state: ShutdownState = .active,

    fn init(allocator: std.mem.Allocator) ServerRequestLifecycle {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *ServerRequestLifecycle) void {
        self.active_streams.deinit(self.allocator);
        self.active_stream_index.deinit(self.allocator);
        self.* = undefined;
    }

    fn markReceived(
        self: *ServerRequestLifecycle,
        stream_id: u62,
    ) Error!void {
        const slot = try self.active_stream_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) return error.UnexpectedStream;
        errdefer _ = self.active_stream_index.remove(stream_id);
        const index = self.active_streams.items.len;
        try self.active_streams.append(self.allocator, stream_id);
        slot.value_ptr.* = index;
        self.considerLowestActiveStream(index);
        self.highest_processed_stream_id = if (self.highest_processed_stream_id) |highest|
            @max(highest, stream_id)
        else
            stream_id;
    }

    fn markFinished(self: *ServerRequestLifecycle, stream_id: u64) void {
        const key = std.math.cast(u62, stream_id) orelse return;
        if (self.active_stream_index.count() == 0) return;
        const index = self.active_stream_index.get(key) orelse return;
        const last_index = self.active_streams.items.len - 1;
        const lowest = self.lowest_active_stream_index;
        const removed = self.active_streams.swapRemove(index);
        _ = self.active_stream_index.remove(removed);
        if (index != last_index) {
            const moved = self.active_streams.items[index];
            self.active_stream_index.getPtr(moved).?.* = index;
        }
        if (self.active_streams.items.len == 0) {
            self.lowest_active_stream_index = null;
        } else if (lowest == index) {
            self.recomputeLowestActiveStream();
        } else if (lowest == last_index) {
            self.lowest_active_stream_index = index;
        }
    }

    fn finalGoAwayId(self: ServerRequestLifecycle) Error!u64 {
        const highest = self.highest_processed_stream_id orelse return 0;
        return std.math.add(u64, highest, 4) catch error.InvalidFrame;
    }

    fn drainComplete(
        self: ServerRequestLifecycle,
        request_streams: RequestStreamSet,
        streaming_requests: StreamingRequestSet,
        local_goaway_id: ?u64,
    ) bool {
        if (self.shutdown_state != .final_goaway) return false;
        const goaway_id = local_goaway_id orelse return false;
        if (self.lowestActiveStream()) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        if (request_streams.lowestStream()) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        if (streaming_requests.lowestEntryStream()) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        if (streaming_requests.lowestResetStream()) |stream_id| {
            if (stream_id < goaway_id) return false;
        }
        return true;
    }

    fn lowestActiveStream(self: ServerRequestLifecycle) ?u62 {
        const index = self.lowest_active_stream_index orelse return null;
        return self.active_streams.items[index];
    }

    fn considerLowestActiveStream(
        self: *ServerRequestLifecycle,
        index: usize,
    ) void {
        const lowest = self.lowest_active_stream_index orelse {
            self.lowest_active_stream_index = index;
            return;
        };
        if (self.active_streams.items[index] < self.active_streams.items[lowest]) {
            self.lowest_active_stream_index = index;
        }
    }

    fn recomputeLowestActiveStream(self: *ServerRequestLifecycle) void {
        self.lowest_active_stream_index = null;
        for (self.active_streams.items, 0..) |_, index| {
            self.considerLowestActiveStream(index);
        }
    }
};

test "HTTP/3 server request lifecycle indexes active streams" {
    const allocator = std.testing.allocator;
    var lifecycle = ServerRequestLifecycle.init(allocator);
    defer lifecycle.deinit();

    try lifecycle.markReceived(0);
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try lifecycle.markReceived(4);
    try lifecycle.markReceived(8);
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectError(error.UnexpectedStream, lifecycle.markReceived(4));
    try std.testing.expectEqual(@as(?u62, 8), lifecycle.highest_processed_stream_id);
    try std.testing.expectEqual(@as(u64, 12), try lifecycle.finalGoAwayId());

    lifecycle.markFinished(4);
    try std.testing.expect(!lifecycle.active_stream_index.contains(4));
    try std.testing.expect(lifecycle.active_stream_index.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    lifecycle.markFinished(8);
    try std.testing.expect(!lifecycle.active_stream_index.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    lifecycle.markFinished(999);
    try std.testing.expect(lifecycle.active_stream_index.contains(0));
    lifecycle.markFinished(0);
    try std.testing.expectEqual(@as(?u62, null), lifecycle.lowestActiveStream());
    try std.testing.expectEqual(@as(usize, 0), lifecycle.active_streams.items.len);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.active_stream_index.count());
    lifecycle.markFinished(16);
    try std.testing.expectEqual(@as(usize, 0), lifecycle.active_stream_index.count());
}

test "HTTP/3 outbound body set indexes open streaming bodies" {
    const allocator = std.testing.allocator;
    var bodies = OutboundBodySet.init(allocator, 3);
    defer bodies.deinit();

    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try bodies.reserveOpen(stream_id);
        bodies.appendOpenAssumeCapacity(
            stream_id,
            quic.stream_state.SendState.init(stream_id),
            null,
        );
    }
    try std.testing.expectError(error.ExcessiveLoad, bodies.reserveOpen(12));

    try std.testing.expect(bodies.find(4) != null);
    try std.testing.expect(bodies.finish(4));
    try std.testing.expect(bodies.find(4) == null);
    // Finishing stream 4 moved another entry into its slot. The index for that
    // moved entry must still let later DATA/trailer calls find the body state.
    try std.testing.expect(bodies.find(8) != null);
    try std.testing.expect(bodies.finish(8));

    try bodies.reserveOpen(12);
    bodies.appendOpenAssumeCapacity(
        12,
        quic.stream_state.SendState.init(12),
        5,
    );
    const entry = try bodies.prepareChunk(12, 5, true);
    try std.testing.expectEqual(@as(usize, 5), entry.written);
    try std.testing.expect(!bodies.finish(4));
    try std.testing.expect(bodies.finish(0));
    try std.testing.expect(bodies.finish(12));
    try std.testing.expectEqual(@as(usize, 0), bodies.entries.items.len);
    try std.testing.expectEqual(@as(usize, 0), bodies.entry_index.count());
    try std.testing.expect(!bodies.finish(16));
    try std.testing.expect(bodies.find(16) == null);
}

fn messageBlockedByQpack(
    bytes: []const u8,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = try http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        );
        if (prefix.required_insert_count > table.insert_count) return true;
    }
    return false;
}

fn messageUsesDynamicQpack(
    bytes: []const u8,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const frame = try http3.Frame.parse(bytes[offset..]);
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = try http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        );
        if (prefix.required_insert_count != 0) return true;
    }
    return false;
}

fn bufferedReceiveUsesDynamicQpack(
    receive: quic.stream_state.RecvState,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    const relative_start = receive.read_offset - receive.storage_offset;
    const relative_end = receive.contiguous_end - receive.storage_offset;
    const available = receive.buffer.items[relative_start..relative_end];
    var offset: usize = 0;
    while (offset < available.len) {
        const frame = http3.Frame.parse(available[offset..]) catch |err| switch (err) {
            // A reset can interrupt any frame. Only complete field-section
            // frames can have established a QPACK dependency at this point.
            error.BufferTooShort => return false,
            else => return err,
        };
        offset += frame.consumed;
        const field_section = try frameFieldSectionPayload(
            frame.frame_type,
            frame.payload,
        ) orelse continue;
        const prefix = try http3.Qpack.decodeFieldSectionPrefix(
            field_section,
            table,
        );
        if (prefix.required_insert_count != 0) return true;
    }
    return false;
}

fn frameFieldSectionPayload(
    frame_type: u64,
    payload: []const u8,
) Error!?[]const u8 {
    return switch (frame_type) {
        http3.FrameType.headers => payload,
        http3.FrameType.push_promise => (try http3.parsePushPromisePayload(payload)).field_section,
        else => null,
    };
}

fn sendConnectionMessage(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    request: http3.Request,
    options: HandshakeSessionOptions,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try request.writeDynamic(
        &encoded,
        connection.endpoint.allocator,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(&frames, connection.endpoint.allocator, encoded.items, options.max_stream_frame_data, true);
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
    message_sent = true;
}

fn sendConnectionResponseSequence(
    connection: *quic.one_rtt.Connection,
    stream_id: u62,
    informational: []const http3.InformationalResponse,
    response: http3.Response,
    options: HandshakeSessionOptions,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try http3.writeResponseSequenceDynamic(
        &encoded,
        connection.endpoint.allocator,
        informational,
        response,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(&frames, connection.endpoint.allocator, encoded.items, options.max_stream_frame_data, true);
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
    message_sent = true;
}

fn encodePushMessages(
    allocator: std.mem.Allocator,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    parent: *std.ArrayList(u8),
    pushed: *std.ArrayList(u8),
) Error!void {
    try http3.writePushPromiseDynamic(
        parent,
        allocator,
        push.push_id,
        push.request,
        peer_settings,
        request_stream_id,
        qpack,
    );
    try response.writeDynamic(
        parent,
        allocator,
        peer_settings,
        request_stream_id,
        qpack,
    );
    const push_stream_type = @intFromEnum(http3.StreamType.push);
    const push_stream_type_len = try quic.varint.length(push_stream_type);
    const push_id_len = try quic.varint.length(push.push_id);
    try pushed.ensureUnusedCapacity(
        allocator,
        @as(usize, push_stream_type_len) + push_id_len,
    );
    quic.varint.encodeWithLenAssumeCapacity(
        pushed,
        push_stream_type,
        push_stream_type_len,
    );
    quic.varint.encodeWithLenAssumeCapacity(
        pushed,
        push.push_id,
        push_id_len,
    );
    try push.response.writeDynamic(
        pushed,
        allocator,
        peer_settings,
        push_stream_id,
        qpack,
    );
}

fn appendMessageFrames(
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    stream_id: u62,
    bytes: []const u8,
    max_stream_frame_data: usize,
) Error!void {
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        frames,
        allocator,
        bytes,
        max_stream_frame_data,
        true,
    );
}

fn sendConnectionPush(
    connection: *quic.one_rtt.Connection,
    options: HandshakeSessionOptions,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    var parent: std.ArrayList(u8) = .empty;
    defer parent.deinit(connection.endpoint.allocator);
    var pushed: std.ArrayList(u8) = .empty;
    defer pushed.deinit(connection.endpoint.allocator);
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try encodePushMessages(
        connection.endpoint.allocator,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        &parent,
        &pushed,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    // Promise bytes precede the pushed response in this frame list. QUIC may
    // reorder the streams, and the receive lifecycle deliberately tolerates
    // that, but same-call ordering minimizes unnecessary buffering.
    try appendMessageFrames(
        &frames,
        connection.endpoint.allocator,
        request_stream_id,
        parent.items,
        options.max_stream_frame_data,
    );
    try appendMessageFrames(
        &frames,
        connection.endpoint.allocator,
        push_stream_id,
        pushed.items,
        options.max_stream_frame_data,
    );
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
}

fn sendProtectedPush(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    peer_settings: http3.Settings,
    request_stream_id: u62,
    response: http3.Response,
    push_stream_id: u62,
    push: ServerPush,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    var parent: std.ArrayList(u8) = .empty;
    defer parent.deinit(endpoint.allocator);
    var pushed: std.ArrayList(u8) = .empty;
    defer pushed.deinit(endpoint.allocator);
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try encodePushMessages(
        endpoint.allocator,
        peer_settings,
        request_stream_id,
        response,
        push_stream_id,
        push,
        qpack,
        &parent,
        &pushed,
    );
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try appendMessageFrames(
        &frames,
        endpoint.allocator,
        request_stream_id,
        parent.items,
        config.max_stream_frame_data,
    );
    try appendMessageFrames(
        &frames,
        endpoint.allocator,
        push_stream_id,
        pushed.items,
        config.max_stream_frame_data,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
}

fn sendConnectionStreamingHead(
    connection: *quic.one_rtt.Connection,
    encoded: []const u8,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    options: HandshakeSessionOptions,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    bodies: *OutboundBodySet,
) Error!void {
    const retain_body_state = body_allowed and
        (expected_length == null or expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    try sendConnectionQpackEncoderInstructions(
        connection,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send.appendFrames(
        &frames,
        connection.endpoint.allocator,
        encoded,
        options.max_stream_frame_data,
        !body_allowed or
            (expected_length != null and expected_length.? == 0),
    );
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
    if (retain_body_state) {
        var body_send = quic.stream_state.SendState.init(stream_id);
        body_send.next_offset = send.next_offset;
        bodies.appendOpenAssumeCapacity(
            stream_id,
            body_send,
            expected_length,
        );
    }
}

fn sendProtectedStreamingHead(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    encoded: []const u8,
    stream_id: u62,
    expected_length: ?usize,
    body_allowed: bool,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
) Error!void {
    const retain_body_state = body_allowed and
        (expected_length == null or expected_length.? != 0);
    if (retain_body_state) try bodies.reserveOpen(stream_id);
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try send.appendFrames(
        &frames,
        endpoint.allocator,
        encoded,
        config.max_stream_frame_data,
        !body_allowed or
            (expected_length != null and expected_length.? == 0),
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    if (retain_body_state) {
        var body_send = quic.stream_state.SendState.init(stream_id);
        body_send.next_offset = send.next_offset;
        bodies.appendOpenAssumeCapacity(
            stream_id,
            body_send,
            expected_length,
        );
    }
}

fn writeDataFrame(
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    data: []const u8,
) Error!void {
    if (data.len == 0) return;
    try (http3.Frame{
        .frame_type = http3.FrameType.data,
        .payload = data,
        .consumed = 0,
    }).write(list, allocator);
}

const paced_body_frame_overhead_margin: usize = 64;

fn pacedBodyChunkLimit(options: HandshakeSessionOptions) usize {
    // A paced retry unit may be split into several QUIC STREAM frames, but
    // `sendConnectionFrames` packs only `max_frames_per_packet` of them into
    // one QUIC packet. Keep the DATA chunk within that per-packet frame budget
    // and leave a conservative allowance for HTTP/3 DATA framing, STREAM frame
    // prefixes, packet number, and AEAD overhead. The option defaults to 1 KiB
    // for compatibility with the standard 1200B path-MTU configuration, while
    // benchmarks can raise it once their handshake 1-RTT datagram size is also
    // raised.
    const frame_budget = options.max_stream_frame_data *|
        @max(@as(usize, 1), options.max_frames_per_packet);
    const data_budget = if (frame_budget > paced_body_frame_overhead_margin)
        frame_budget - paced_body_frame_overhead_margin
    else
        1;
    return @max(
        @as(usize, 1),
        @min(options.paced_body_chunk_bytes, data_budget),
    );
}

fn sendConnectionBodyChunk(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
    options: HandshakeSessionOptions,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    const previous = entry.*;
    errdefer entry.* = previous;
    try bodies.prepareChunkForEntry(entry, data.len, fin);
    bodies.frame_scratch.clearRetainingCapacity();
    var prefix: [data_frame_prefix_capacity]u8 = undefined;
    if (options.enable_data_prefix_fast_path and
        try appendDataFrameStreamFramesFast(
            &entry.send,
            &bodies.frame_scratch,
            connection.endpoint.allocator,
            &prefix,
            data,
            fin,
            options.max_stream_frame_data,
        ))
    {
        try sendConnectionFrames(
            connection,
            bodies.frame_scratch.items,
            options.max_frames_per_packet,
        );
        if (fin) _ = bodies.finish(stream_id);
        return;
    }

    bodies.payload_scratch.clearRetainingCapacity();
    try writeDataFrame(
        &bodies.payload_scratch,
        connection.endpoint.allocator,
        data,
    );
    try entry.send.appendFrames(
        &bodies.frame_scratch,
        connection.endpoint.allocator,
        bodies.payload_scratch.items,
        options.max_stream_frame_data,
        fin,
    );
    try sendConnectionFrames(
        connection,
        bodies.frame_scratch.items,
        options.max_frames_per_packet,
    );
    if (fin) _ = bodies.finish(stream_id);
}

const data_frame_prefix_capacity: usize = 4096;

fn appendDataFrameStreamFramesFast(
    send: *quic.stream_state.SendState,
    frames: *std.ArrayList(quic.Frame),
    allocator: std.mem.Allocator,
    prefix: *[data_frame_prefix_capacity]u8,
    data: []const u8,
    fin: bool,
    max_stream_frame_data: usize,
) Error!bool {
    if (data.len == 0 or max_stream_frame_data == 0) return false;
    if (send.fin_sent) return error.FinalSizeMismatch;
    const payload_len_u64 = std.math.cast(u64, data.len) orelse
        return error.IntegerOverflow;
    var prefix_len: usize = 0;
    const type_bytes = try quic.varint.encodeInto(
        prefix[prefix_len..],
        http3.FrameType.data,
    );
    prefix_len += type_bytes.len;
    const len_bytes = try quic.varint.encodeInto(
        prefix[prefix_len..],
        payload_len_u64,
    );
    prefix_len += len_bytes.len;
    if (prefix_len >= max_stream_frame_data) return false;
    const first_body_len = @min(
        data.len,
        @min(max_stream_frame_data - prefix_len, prefix.len - prefix_len),
    );
    if (first_body_len == 0) return false;
    @memcpy(prefix[prefix_len..][0..first_body_len], data[0..first_body_len]);
    const first_len = prefix_len + first_body_len;
    const remaining = data[first_body_len..];
    const additional = if (remaining.len == 0)
        @as(usize, 0)
    else
        std.math.divCeil(usize, remaining.len, max_stream_frame_data) catch
            return error.InvalidFrameLength;
    try frames.ensureUnusedCapacity(allocator, 1 + additional);
    frames.appendAssumeCapacity(.{ .stream = .{
        .stream_id = send.stream_id,
        .offset = send.next_offset,
        .data = prefix[0..first_len],
        .fin = fin and remaining.len == 0,
    } });
    send.next_offset += first_len;
    var written: usize = 0;
    while (written < remaining.len) {
        const chunk_len = @min(max_stream_frame_data, remaining.len - written);
        const is_last = written + chunk_len == remaining.len;
        frames.appendAssumeCapacity(.{ .stream = .{
            .stream_id = send.stream_id,
            .offset = send.next_offset,
            .data = remaining[written .. written + chunk_len],
            .fin = fin and is_last,
        } });
        send.next_offset += chunk_len;
        written += chunk_len;
    }
    if (fin) send.fin_sent = true;
    return true;
}

fn sendProtectedBodyChunk(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    stream_id: u62,
    data: []const u8,
    fin: bool,
) Error!void {
    const entry = bodies.find(stream_id) orelse return error.UnexpectedStream;
    const previous = entry.*;
    errdefer entry.* = previous;
    try bodies.prepareChunkForEntry(entry, data.len, fin);
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try writeDataFrame(&payload, endpoint.allocator, data);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try entry.send.appendFrames(
        &frames,
        endpoint.allocator,
        payload.items,
        config.max_stream_frame_data,
        fin,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    if (fin) _ = bodies.finish(stream_id);
}

fn sendConnectionTrailers(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    stream_id: u62,
    trailers: []const http3.Qpack.HeaderField,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    options: HandshakeSessionOptions,
) Error!void {
    const entry = try bodies.prepareTrailers(stream_id);
    const previous = entry.*;
    errdefer entry.* = previous;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(connection.endpoint.allocator);
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try http3.writeTrailersDynamic(
        &encoded,
        connection.endpoint.allocator,
        trailers,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try entry.send.appendFrames(
        &frames,
        connection.endpoint.allocator,
        encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
    _ = bodies.finish(stream_id);
}

fn sendProtectedTrailers(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    bodies: *OutboundBodySet,
    stream_id: u62,
    trailers: []const http3.Qpack.HeaderField,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    const entry = try bodies.prepareTrailers(stream_id);
    const previous = entry.*;
    errdefer entry.* = previous;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(endpoint.allocator);
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try http3.writeTrailersDynamic(
        &encoded,
        endpoint.allocator,
        trailers,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendProtectedQpackEncoderInstructions(
        endpoint,
        to,
        config,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        next_packet_number,
        protected_send,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try entry.send.appendFrames(
        &frames,
        endpoint.allocator,
        encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    _ = bodies.finish(stream_id);
}

fn sendConnectionFrames(connection: *quic.one_rtt.Connection, frames: []const quic.Frame, max_frames_per_packet: usize) Error!void {
    const chunk_size = @max(@as(usize, 1), max_frames_per_packet);
    if (frames.len <= chunk_size) {
        try connection.send(frames);
        return;
    }
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
        undefined;
    var packet_count: usize = 0;
    var offset: usize = 0;
    while (offset < frames.len) {
        const end = @min(frames.len, offset + chunk_size);
        packets[packet_count] = frames[offset..end];
        packet_count += 1;
        offset = end;
        if (packet_count == packets.len or offset == frames.len) {
            try connection.sendMany(packets[0..packet_count]);
            packet_count = 0;
        }
    }
}

fn receiveConnectionRequestStreamBytes(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    request_streams: *RequestStreamSet,
    peer_promised_push_ids: []const u64,
) Error!AssembledStream {
    if (try request_streams.takeReady(
        qpack_decode.table,
        options.local_settings.qpack_blocked_streams,
    )) |ready| return ready;

    while (true) {
        var packet = try receive_packets.take(connection);
        defer packet.deinit(connection.endpoint.allocator);
        if (try applyServerRequestPacketFrames(
            packet.from,
            packet.frames,
            connection.endpoint.allocator,
            control,
            qpack_decode,
            qpack_encode,
            request_streams,
            null,
            peer_promised_push_ids,
        )) |reset| {
            return requestResetError(reset.application_error_code);
        }
        if (try request_streams.takeReady(
            qpack_decode.table,
            options.local_settings.qpack_blocked_streams,
        )) |ready| {
            return ready;
        }
    }
}

const RequestStreamReset = struct {
    from: net.IpAddress,
    stream_id: u62,
    application_error_code: u64,
};

fn requestResetError(application_error_code: u64) Error {
    return if (application_error_code ==
        http3.ApplicationErrorCode.request_rejected)
        error.RequestRejected
    else
        error.RequestCancelled;
}

fn responseResetError(application_error_code: u64) Error {
    return if (application_error_code ==
        http3.ApplicationErrorCode.request_rejected)
        error.RequestRejected
    else
        error.RequestCancelled;
}

/// Route one packet through the shared server-side HTTP/3 stream state.
///
/// Aggregate and incremental consumers intentionally share this function:
/// control/QPACK classification, GOAWAY rejection, peer-address validation,
/// concurrency accounting, and reset cancellation must not drift merely
/// because an application chooses a different body-consumption API.
fn applyServerRequestPacketFrames(
    from: net.IpAddress,
    frames: []const quic.Frame,
    allocator: std.mem.Allocator,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    request_streams: *RequestStreamSet,
    streaming_requests: ?*StreamingRequestSet,
    peer_promised_push_ids: []const u64,
) Error!?RequestStreamReset {
    var first_reset: ?RequestStreamReset = null;
    for (frames) |frame| {
        try rejectCriticalStreamClosureFrame(control.*, frame, .server);
        if (frame == .reset_stream and
            (try messageStreamDisposition(
                frame.reset_stream.stream_id,
            )) == .request_response)
        {
            const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
            const replaces_stream =
                request_streams.contains(stream_id) or
                if (streaming_requests) |streaming|
                    streaming.contains(stream_id)
                else
                    false;
            var cancel_qpack = try request_streams
                .requiresQpackCancellation(
                stream_id,
                qpack_decode.table,
            );
            if (streaming_requests) |streaming| {
                cancel_qpack = cancel_qpack or
                    try streaming.hasUnacknowledgedDynamicSection(
                        stream_id,
                        qpack_decode.table,
                    );
                // Reserve before mutating QPACK or destroying the reader. This
                // makes reset routing transactional under allocator failure.
                try streaming.prepareReset(
                    from,
                    stream_id,
                    request_streams.entries.items.len,
                    replaces_stream,
                );
                // Reserve decoder feedback before retiring the reader. If the
                // event queue has been reserved, all remaining operations are
                // allocation-free and cannot strand one half of the state.
                if (cancel_qpack) {
                    try qpack_decode.recordStreamCancellation(stream_id);
                    cancel_qpack = false;
                }
                streaming.recordPreparedNewResetAssumeCapacity(
                    from,
                    stream_id,
                    frame.reset_stream.application_error_code,
                );
            }
            if (cancel_qpack) {
                try qpack_decode.recordStreamCancellation(stream_id);
            }
            request_streams.remove(stream_id);
            if (first_reset == null) {
                first_reset = .{
                    .from = from,
                    .stream_id = stream_id,
                    .application_error_code = frame.reset_stream.application_error_code,
                };
            }
            continue;
        }
        if (frame != .stream) continue;
        if (isPeerQpackStreamFrame(
            control.*,
            qpack_encode.decoder_stream,
            frame.stream,
            .server,
            .qpack_decoder,
        )) {
            try qpack_encode.applyDecoderStreamFrame(control, frame.stream);
            continue;
        }
        if (isPeerQpackStreamFrame(
            control.*,
            qpack_decode.encoder_stream,
            frame.stream,
            .server,
            .qpack_encoder,
        )) {
            try qpack_decode.applyEncoderStreamFrame(control, frame.stream);
            continue;
        }
        if (try applyControlStreamFrameForRoleWithPushes(
            control,
            allocator,
            frame.stream,
            .server,
            peer_promised_push_ids,
        )) {
            try configureQpackEncoderFromPeerSettings(
                control.*,
                qpack_encode,
            );
            continue;
        }
        if ((try messageStreamDisposition(
            frame.stream.stream_id,
        )) == .ignore) continue;
        const stream_id: u62 = @intCast(frame.stream.stream_id);
        if (rejectByLocalGoAway(control.*, .server, stream_id)) {
            return error.RequestRejected;
        }
        if (streaming_requests) |streaming| {
            try streaming.insertRequest(request_streams, from, frame.stream);
        } else {
            try request_streams.insert(from, frame.stream);
        }
    }
    return first_reset;
}

fn receiveConnectionResponseStreamBytes(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    expected_stream_id: u62,
    options: HandshakeSessionOptions,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    response_streams: *ResponseStreamSet,
    streaming_responses: *StreamingResponseSet,
    push_streams: *PushStreamSet,
    request_lifecycle: *const ClientRequestLifecycle,
) Error!AssembledStream {
    if (response_streams.takeReset(expected_stream_id)) |code| {
        return if (code == http3.ApplicationErrorCode.request_rejected)
            error.RequestRejected
        else
            error.RequestCancelled;
    }
    if (try response_streams.takeReady(
        expected_stream_id,
        qpack_decode.table,
        options.local_settings.qpack_blocked_streams,
    )) |ready| return ready;

    while (true) {
        try receiveConnectionResponsePacket(
            connection,
            receive_packets,
            control,
            qpack_decode,
            qpack_encode,
            response_streams,
            streaming_responses,
            push_streams,
            request_lifecycle,
        );
        if (response_streams.takeReset(expected_stream_id)) |code| {
            return if (code == http3.ApplicationErrorCode.request_rejected)
                error.RequestRejected
            else
                error.RequestCancelled;
        }
        if (try response_streams.takeReady(
            expected_stream_id,
            qpack_decode.table,
            options.local_settings.qpack_blocked_streams,
        )) |ready| {
            return ready;
        }
    }
}

fn receiveConnectionResponsePacket(
    connection: *quic.one_rtt.Connection,
    receive_packets: *ConnectionPacketCursor,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    push_streams: ?*PushStreamSet,
    request_lifecycle: ?*const ClientRequestLifecycle,
) Error!void {
    var packet = try receive_packets.take(connection);
    defer packet.deinit(connection.endpoint.allocator);
    for (packet.frames) |frame| {
        try rejectCriticalStreamClosureFrame(control.*, frame, .client);
        if (frame == .reset_stream and
            (frame.reset_stream.stream_id & 0x03) == 0x03)
        {
            if (push_streams) |pushes| {
                const stream_id: u62 = @intCast(
                    frame.reset_stream.stream_id,
                );
                if (try pushes.hasUnacknowledgedDynamicSection(
                    stream_id,
                    qpack_decode.table,
                )) {
                    try qpack_decode.recordStreamCancellation(stream_id);
                }
                pushes.removeByStreamId(stream_id);
            }
            continue;
        }
        if (frame == .reset_stream and
            (try messageStreamDisposition(
                frame.reset_stream.stream_id,
            )) == .request_response)
        {
            const stream_id: u62 = @intCast(frame.reset_stream.stream_id);
            if (request_lifecycle) |lifecycle| {
                if (lifecycle.isFinished(stream_id)) continue;
                if (!lifecycle.contains(stream_id)) {
                    return error.UnexpectedStream;
                }
            }
            _ = try recordClientResponseReset(
                response_streams,
                streaming_responses,
                qpack_decode,
                stream_id,
                frame.reset_stream.application_error_code,
            );
            continue;
        }
        if (frame != .stream) continue;
        if (isPeerQpackStreamFrame(
            control.*,
            qpack_encode.decoder_stream,
            frame.stream,
            .client,
            .qpack_decoder,
        )) {
            if (push_streams) |pushes| {
                pushes.removeByStreamId(@intCast(frame.stream.stream_id));
            }
            try qpack_encode.applyDecoderStreamFrame(control, frame.stream);
            continue;
        }
        if (isPeerQpackStreamFrame(
            control.*,
            qpack_decode.encoder_stream,
            frame.stream,
            .client,
            .qpack_encoder,
        )) {
            if (push_streams) |pushes| {
                pushes.removeByStreamId(@intCast(frame.stream.stream_id));
            }
            try qpack_decode.applyEncoderStreamFrame(control, frame.stream);
            continue;
        }
        if (try applyControlStreamFrameForRole(
            control,
            connection.endpoint.allocator,
            frame.stream,
            .client,
        )) {
            if (push_streams) |pushes| {
                pushes.removeByStreamId(@intCast(frame.stream.stream_id));
                if (control.peer_cancelled_push_id) |push_id| {
                    try pushes.observePeerCancellation(push_id);
                }
            }
            try configureQpackEncoderFromPeerSettings(
                control.*,
                qpack_encode,
            );
            continue;
        }
        if (push_streams) |pushes| {
            if (try pushes.insert(packet.from, frame.stream, control.*)) {
                continue;
            }
        }
        if ((try messageStreamDisposition(frame.stream.stream_id)) == .ignore) continue;
        const stream_id: u62 = @intCast(frame.stream.stream_id);
        if (request_lifecycle) |lifecycle| {
            if (lifecycle.isFinished(stream_id)) continue;
            if (!lifecycle.contains(stream_id)) return error.UnexpectedStream;
        }
        if (streaming_responses) |streaming| {
            if (try streaming.insert(packet.from, frame.stream)) continue;
        }
        try response_streams.insert(packet.from, frame.stream);
    }
}

/// Retire all receive-side state for a reset response stream atomically.
///
/// The reset map and both stream containers reserve their final shapes before
/// QPACK feedback mutates. Once Stream Cancellation is queued, no remaining
/// operation can fail, so an allocator error can never leave a cancellation
/// instruction referring to a reader that is still live and retryable.
fn recordClientResponseReset(
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    qpack_decode: *QpackDecodeState,
    stream_id: u62,
    application_error_code: u64,
) Error!bool {
    const reset_slot = try response_streams.resets.getOrPut(
        response_streams.allocator,
        stream_id,
    );
    if (reset_slot.found_existing) {
        if (reset_slot.value_ptr.* != application_error_code) {
            return error.UnexpectedStream;
        }
        return false;
    }
    if (response_streams.reset_head != 0 and
        response_streams.reset_order.items.len ==
            response_streams.reset_order.capacity)
    {
        response_streams.compactResetOrder();
    }
    try response_streams.reset_order.ensureUnusedCapacity(
        response_streams.allocator,
        1,
    );

    var order_appended = false;
    errdefer {
        _ = response_streams.resets.remove(stream_id);
        if (order_appended) response_streams.removeResetOrder(stream_id);
    }

    var buffered_entry = response_streams.takeEntry(stream_id);
    errdefer if (buffered_entry) |entry| {
        response_streams.entries.appendAssumeCapacity(entry);
    };
    var streaming_entry = if (streaming_responses) |streaming|
        streaming.takeEntry(stream_id)
    else
        null;
    errdefer if (streaming_entry) |entry| {
        streaming_responses.?.entries.appendAssumeCapacity(entry);
    };

    var cancel_qpack = if (buffered_entry) |entry|
        try bufferedReceiveUsesDynamicQpack(
            entry.receive,
            qpack_decode.table,
        )
    else
        false;
    if (streaming_entry) |entry| {
        cancel_qpack = cancel_qpack or
            try entry.reader.hasUnacknowledgedDynamicSection(
                qpack_decode.table,
            );
    }
    if (cancel_qpack) {
        try qpack_decode.recordStreamCancellation(stream_id);
    }

    response_streams.reset_order.appendAssumeCapacity(stream_id);
    order_appended = true;
    reset_slot.value_ptr.* = application_error_code;
    if (buffered_entry) |*entry| entry.deinit();
    buffered_entry = null;
    if (streaming_entry) |*entry| entry.deinit();
    streaming_entry = null;
    return cancel_qpack;
}

const ControlFrameKind = enum { goaway };
const PushControlFrameKind = enum { max_push_id, cancel_push };

fn validateServerGoAwayStreamId(stream_id: u64) Error!void {
    // RFC 9114 requires a server GOAWAY identifier to be a client-initiated
    // bidirectional request stream ID.  Client-initiated bidirectional stream
    // IDs are exactly the multiples of four.
    if ((stream_id & 0x3) != 0) return error.InvalidFrame;
}

fn validateClientGoAwayPushId(push_id: u64) Error!void {
    if (push_id > quic.varint.max_value) return error.InvalidFrame;
}

fn validateNewServerPush(
    control: http3.ControlState,
    sent_push_ids: []const u64,
    push_id: u64,
) Error!void {
    if (control.peer_goaway_id) |goaway_id| {
        if (push_id >= goaway_id) return error.GoAwayReceived;
    }
    if (control.pushCancelled(push_id)) {
        return error.RequestCancelled;
    }
    for (sent_push_ids) |existing| {
        if (existing == push_id) return error.DuplicatePushId;
    }
}

fn rejectByLocalGoAway(control: http3.ControlState, role: ControlStreamRole, stream_id: u64) bool {
    return switch (role) {
        // A server GOAWAY carries the largest client-initiated request stream
        // ID that can still be processed, so server receive paths must reject
        // newer request streams after sending GOAWAY.  A client GOAWAY carries
        // a push ID instead (RFC 9114 §5.2), not a response stream ID; using it
        // to filter server responses would incorrectly reject the in-flight
        // response on stream 0 after a client sends GOAWAY(0).
        .server => !control.acceptsLocalRequestStream(stream_id),
        .client => false,
    };
}

fn controlFramePayload(
    control: *http3.ControlState,
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    switch (kind) {
        .goaway => try control.writeGoAway(list, allocator, value),
    }
}

fn sendConnectionControlFrame(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    try controlFramePayload(control, &payload, connection.endpoint.allocator, kind, value);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try control_send.appendFrames(&frames, connection.endpoint.allocator, payload.items, payload.items.len, false);
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
}

fn pushControlFramePayload(
    control: *http3.ControlState,
    list: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    kind: PushControlFrameKind,
    push_id: u64,
) Error!void {
    switch (kind) {
        .max_push_id => try control.writeMaxPushId(
            list,
            allocator,
            push_id,
        ),
        .cancel_push => {
            const max_push_id = control.local_max_push_id orelse
                return error.PushIdExceeded;
            if (push_id > max_push_id) return error.PushIdExceeded;
            try http3.writeCancelPushFrame(list, allocator, push_id);
        },
    }
}

fn sendConnectionPushControl(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    kind: PushControlFrameKind,
    push_id: u64,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    const previous_max_push_id = control.local_max_push_id;
    const previous_send = control_send.*;
    errdefer control.local_max_push_id = previous_max_push_id;
    errdefer control_send.* = previous_send;
    try pushControlFramePayload(
        control,
        &payload,
        connection.endpoint.allocator,
        kind,
        push_id,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try control_send.appendFrames(
        &frames,
        connection.endpoint.allocator,
        payload.items,
        payload.items.len,
        false,
    );
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
}

fn sendConnectionPriorityUpdate(
    connection: *quic.one_rtt.Connection,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    stream_id: u62,
    priority: http3.Priority,
) Error!void {
    try sendConnectionPriorityUpdateRaw(
        connection,
        control_send,
        options,
        http3.FrameType.priority_update_request,
        stream_id,
        priority,
    );
}

fn sendConnectionPriorityUpdateRaw(
    connection: *quic.one_rtt.Connection,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    frame_type: u64,
    prioritized_element_id: u64,
    priority: http3.Priority,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    var field_value_buf: [16]u8 = undefined;
    try http3.writePriorityUpdateFrameRaw(
        &payload,
        connection.endpoint.allocator,
        frame_type,
        prioritized_element_id,
        priority.serialize(&field_value_buf),
    );
    const previous_send = control_send.*;
    errdefer control_send.* = previous_send;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try control_send.appendFrames(
        &frames,
        connection.endpoint.allocator,
        payload.items,
        payload.items.len,
        false,
    );
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
}

fn sendProtectedControlFrame(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try controlFramePayload(control, &payload, endpoint.allocator, kind, value);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try control_send.appendFrames(&frames, endpoint.allocator, payload.items, payload.items.len, false);
    try sendProtectedFrames(endpoint, to, config.send_keys, config.peer_connection_id, next_packet_number, frames.items, config.max_frames_per_packet, protected_send);
}

fn sendProtectedPushControl(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    kind: PushControlFrameKind,
    push_id: u64,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    const previous_max_push_id = control.local_max_push_id;
    const previous_send = control_send.*;
    errdefer control.local_max_push_id = previous_max_push_id;
    errdefer control_send.* = previous_send;
    try pushControlFramePayload(
        control,
        &payload,
        endpoint.allocator,
        kind,
        push_id,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try control_send.appendFrames(
        &frames,
        endpoint.allocator,
        payload.items,
        payload.items.len,
        false,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
}

fn sendProtectedPriorityUpdate(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    stream_id: u62,
    priority: http3.Priority,
) Error!void {
    try sendProtectedPriorityUpdateRaw(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        http3.FrameType.priority_update_request,
        stream_id,
        priority,
    );
}

fn sendProtectedPriorityUpdateRaw(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    frame_type: u64,
    prioritized_element_id: u64,
    priority: http3.Priority,
) Error!void {
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    var field_value_buf: [16]u8 = undefined;
    try http3.writePriorityUpdateFrameRaw(
        &payload,
        endpoint.allocator,
        frame_type,
        prioritized_element_id,
        priority.serialize(&field_value_buf),
    );
    const previous_send = control_send.*;
    errdefer control_send.* = previous_send;
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try control_send.appendFrames(
        &frames,
        endpoint.allocator,
        payload.items,
        payload.items.len,
        false,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
}

fn sendConnectionSettings(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    options: HandshakeSessionOptions,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    const previous_settings = control.settings;
    const previous_control_send = control_send.*;
    const previous_encoder_send = qpack_encoder_send.*;
    const previous_decoder_send = qpack_decoder_send.*;
    errdefer control.settings = previous_settings;
    errdefer control_send.* = previous_control_send;
    errdefer qpack_encoder_send.* = previous_encoder_send;
    errdefer qpack_decoder_send.* = previous_decoder_send;
    try control.writeSettingsStream(&payload, connection.endpoint.allocator, options.local_settings);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(&frames, connection.endpoint.allocator, payload.items, payload.items.len, false);

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(connection.endpoint.allocator);
    var qpack_decoder: std.ArrayList(u8) = .empty;
    defer qpack_decoder.deinit(connection.endpoint.allocator);
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &qpack_encoder,
            connection.endpoint.allocator,
        );
    }
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(
            &qpack_decoder,
            connection.endpoint.allocator,
        );
    }
    const encoder_stream_id =
        if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(
            encoder_stream_id,
        );
    }
    if (qpack_encoder.items.len != 0) {
        try qpack_encoder_send.appendFrames(
            &frames,
            connection.endpoint.allocator,
            qpack_encoder.items,
            qpack_encoder.items.len,
            false,
        );
    }
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (qpack_decoder.items.len != 0) {
        try qpack_decoder_send.appendFrames(
            &frames,
            connection.endpoint.allocator,
            qpack_decoder.items,
            qpack_decoder.items.len,
            false,
        );
    }
    try sendConnectionFrames(connection, frames.items, options.max_frames_per_packet);
    if (qpack_encoder.items.len != 0) qpack_encoder_prefix_sent.* = true;
    if (qpack_decoder.items.len != 0) qpack_decoder_prefix_sent.* = true;
}

fn sendConnectionQpackEncoderInstructions(
    connection: *quic.one_rtt.Connection,
    qpack: *QpackEncodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: HandshakeSessionOptions,
) Error!void {
    const pending = qpack.pendingEncoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    try payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &payload,
            connection.endpoint.allocator,
        );
    }
    payload.appendSliceAssumeCapacity(pending);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(
        &frames,
        connection.endpoint.allocator,
        payload.items,
        options.max_stream_frame_data,
        false,
    );
    // Keep the critical encoder stream in an earlier packet than any field
    // section that may depend on it, including when frame-list chunking is one.
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
    prefix_sent.* = true;
    qpack.clearEncoderInstructions();
}

fn sendConnectionQpackFeedback(
    connection: *quic.one_rtt.Connection,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: HandshakeSessionOptions,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(connection.endpoint.allocator);
    try payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &payload,
        connection.endpoint.allocator,
    );
    payload.appendSliceAssumeCapacity(pending);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(connection.endpoint.allocator);
    try send_state.appendFrames(
        &frames,
        connection.endpoint.allocator,
        payload.items,
        options.max_stream_frame_data,
        false,
    );
    try sendConnectionFrames(
        connection,
        frames.items,
        options.max_frames_per_packet,
    );
    prefix_sent.* = true;
    qpack.clearDecoderInstructions();
}

fn cancelConnectionRequest(
    connection: *quic.one_rtt.Connection,
    qpack: *QpackDecodeState,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    options: HandshakeSessionOptions,
    stream_id: u62,
    application_error_code: u64,
    cancel_qpack: bool,
) Error!void {
    try connection.resetStream(stream_id, application_error_code);
    try connection.sendStopSending(stream_id, application_error_code);
    if (cancel_qpack) {
        try qpack.recordStreamCancellation(stream_id);
        try sendConnectionQpackFeedback(
            connection,
            qpack,
            qpack_decoder_send,
            qpack_decoder_prefix_sent,
            options,
        );
    }
}

fn sendProtectedSettings(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    stream_id: u62,
) Error!void {
    if (control.settings.sent) return;

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    const previous_settings = control.settings;
    const previous_control_send = control_send.*;
    const previous_encoder_send = qpack_encoder_send.*;
    const previous_decoder_send = qpack_decoder_send.*;
    errdefer control.settings = previous_settings;
    // appendFrames advances offsets before the UDP send. Restoring all three
    // streams makes a retry emit identical bytes at identical offsets after an
    // allocation or socket failure (including a partially sent frame batch).
    errdefer control_send.* = previous_control_send;
    errdefer qpack_encoder_send.* = previous_encoder_send;
    errdefer qpack_decoder_send.* = previous_decoder_send;
    try control.writeSettingsStream(&payload, endpoint.allocator, config.local_settings);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(&frames, endpoint.allocator, payload.items, payload.items.len, false);

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(endpoint.allocator);
    var qpack_decoder: std.ArrayList(u8) = .empty;
    defer qpack_decoder.deinit(endpoint.allocator);
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(&qpack_encoder, endpoint.allocator);
    }
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(&qpack_decoder, endpoint.allocator);
    }
    const encoder_stream_id =
        if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(encoder_stream_id);
    }
    if (qpack_encoder.items.len != 0) {
        try qpack_encoder_send.appendFrames(
            &frames,
            endpoint.allocator,
            qpack_encoder.items,
            qpack_encoder.items.len,
            false,
        );
    }
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (qpack_decoder.items.len != 0) {
        try qpack_decoder_send.appendFrames(
            &frames,
            endpoint.allocator,
            qpack_decoder.items,
            qpack_decoder.items.len,
            false,
        );
    }
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    if (qpack_encoder.items.len != 0) qpack_encoder_prefix_sent.* = true;
    if (qpack_decoder.items.len != 0) qpack_decoder_prefix_sent.* = true;
}

fn sendProtectedQpackEncoderInstructions(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    qpack: *QpackEncodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    const pending = qpack.pendingEncoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try payload.ensureTotalCapacity(
        endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(&payload, endpoint.allocator);
    }
    payload.appendSliceAssumeCapacity(pending);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try send_state.appendFrames(
        &frames,
        endpoint.allocator,
        payload.items,
        config.max_stream_frame_data,
        false,
    );
    // Encoder-stream bytes must be visible before any request/response field
    // section that could depend on them. A separate send also preserves this
    // ordering when max_frames_per_packet would otherwise split one frame list.
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    prefix_sent.* = true;
    qpack.clearEncoderInstructions();
}

fn sendProtectedQpackFeedback(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(endpoint.allocator);
    try payload.ensureTotalCapacity(
        endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &payload,
        endpoint.allocator,
    );
    const instruction_offset = payload.items.len;
    payload.appendSliceAssumeCapacity(pending);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(endpoint.allocator);
    try send_state.appendFrames(
        &frames,
        endpoint.allocator,
        payload.items,
        config.max_stream_frame_data,
        false,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    prefix_sent.* = true;
    _ = instruction_offset;
    qpack.clearDecoderInstructions();
}

fn sendProtectedRequestCancellation(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    qpack: *QpackDecodeState,
    qpack_decoder_send: *quic.stream_state.SendState,
    qpack_decoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    stream_id: u62,
    application_error_code: u64,
    cancel_qpack: bool,
) Error!void {
    const frames = [_]quic.Frame{
        .{ .reset_stream = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
            .final_size = 0,
        } },
        .{ .stop_sending = .{
            .stream_id = stream_id,
            .application_error_code = application_error_code,
        } },
    };
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        &frames,
        config.max_frames_per_packet,
        protected_send,
    );
    if (cancel_qpack) {
        try qpack.recordStreamCancellation(stream_id);
        try sendProtectedQpackFeedback(
            endpoint,
            to,
            config,
            qpack,
            qpack_decoder_send,
            qpack_decoder_prefix_sent,
            next_packet_number,
            protected_send,
        );
    }
}

const ControlStreamRole = enum {
    client,
    server,
};

fn configureQpackEncoderFromPeerSettings(
    control: http3.ControlState,
    qpack: *QpackEncodeState,
) Error!void {
    if (!control.settings.received) return;
    const capacity = std.math.cast(
        usize,
        control.settings.peer.qpack_max_table_capacity,
    ) orelse return error.InvalidSetting;
    try qpack.configurePeerCapacity(capacity);
}

fn isPeerQpackStreamFrame(
    control: http3.ControlState,
    receive: ?quic.stream_state.RecvState,
    stream: quic.StreamFrame,
    role: ControlStreamRole,
    stream_type: http3.StreamType,
) bool {
    if ((stream.stream_id & 0x02) == 0) return false;
    if (receive) |state| {
        return state.stream_id == stream.stream_id;
    }

    const registered = switch (stream_type) {
        .qpack_encoder => control.peer_qpack_encoder_stream_id,
        .qpack_decoder => control.peer_qpack_decoder_stream_id,
        else => return false,
    };
    if (registered) |stream_id| {
        return stream_id == stream.stream_id;
    }

    // The fixed IDs are the first legal unidirectional streams allocated by
    // this compact runtime and let reordered nonzero-offset frames be routed
    // before their prefix arrives. At offset zero, always trust the explicit
    // stream type instead so peers can allocate critical streams in another
    // order without a fixed-ID false positive.
    const expected_stream_id: u62 = switch (role) {
        .client => switch (stream_type) {
            .qpack_encoder => server_qpack_encoder_stream_id,
            .qpack_decoder => server_qpack_decoder_stream_id,
            else => unreachable,
        },
        .server => switch (stream_type) {
            .qpack_encoder => client_qpack_encoder_stream_id,
            .qpack_decoder => client_qpack_decoder_stream_id,
            else => unreachable,
        },
    };
    if (stream.offset == 0) return peekUniStreamType(stream) == stream_type;
    return stream.stream_id == expected_stream_id;
}

fn applyControlStreamFrameForRole(control: *http3.ControlState, allocator: std.mem.Allocator, stream: quic.StreamFrame, role: ControlStreamRole) Error!bool {
    return applyControlStreamFrameForRoleWithPushes(
        control,
        allocator,
        stream,
        role,
        null,
    );
}

fn applyControlStreamFrameForRoleWithPushes(
    control: *http3.ControlState,
    allocator: std.mem.Allocator,
    stream: quic.StreamFrame,
    role: ControlStreamRole,
    promised_push_ids: ?[]const u64,
) Error!bool {
    // HTTP/3 control, QPACK, and push streams are unidirectional.  Request and
    // response STREAM frames are already validated by the message decoder, so
    // skip the expensive control-state clone/rollback path for the common
    // bidirectional data path.
    if ((stream.stream_id & 0x02) == 0) return false;
    if (role == .server and stream.offset == 0) {
        if (peekUniStreamType(stream) == .push) return error.StreamCreationError;
    }
    if (stream.offset == 0) {
        switch (peekUniStreamType(stream) orelse return false) {
            .control, .qpack_encoder, .qpack_decoder => {},
            else => return false,
        }
    } else if (!isRegisteredCriticalStream(control.*, stream.stream_id)) {
        return false;
    }
    if (role == .client and
        try controlStreamContainsClientOnlyFrame(control.*, stream))
    {
        return error.UnexpectedFrame;
    }
    var previous = try control.clone(allocator);
    var previous_owned = true;
    defer if (previous_owned) previous.deinit(allocator);
    const handled = applyControlStreamFrame(control, allocator, stream) catch |err| {
        control.deinit(allocator);
        control.* = previous;
        previous_owned = false;
        return err;
    };
    if (handled and role == .client) {
        if (control.peer_goaway_id != previous.peer_goaway_id) {
            validateServerGoAwayStreamId(control.peer_goaway_id.?) catch |err| {
                control.deinit(allocator);
                control.* = previous;
                previous_owned = false;
                return err;
            };
        }
        // MAX_PUSH_ID and PRIORITY_UPDATE are client-to-server control frames.
        // A client receiving them from a server must treat the frame as
        // unexpected; restore state so callers can recover or close cleanly.
        if (control.peer_max_push_id != previous.peer_max_push_id or
            control.priority_update_generation !=
                previous.priority_update_generation)
        {
            control.deinit(allocator);
            control.* = previous;
            previous_owned = false;
            return error.UnexpectedFrame;
        }
        // CANCEL_PUSH is also client-to-server only.
        if (control.push_cancellation_generation !=
            previous.push_cancellation_generation)
        {
            control.deinit(allocator);
            control.* = previous;
            previous_owned = false;
            return error.UnexpectedFrame;
        }
    }
    if (handled and role == .server and control.peer_goaway_id != previous.peer_goaway_id) {
        validateClientGoAwayPushId(control.peer_goaway_id.?) catch |err| {
            control.deinit(allocator);
            control.* = previous;
            previous_owned = false;
            return err;
        };
    }
    if (handled and role == .server and
        control.push_cancellation_generation !=
            previous.push_cancellation_generation)
    {
        const max_push_id = control.peer_max_push_id orelse {
            control.deinit(allocator);
            control.* = previous;
            previous_owned = false;
            return error.PushIdExceeded;
        };
        for (control.peer_cancelled_push_ids.items[previous.peer_cancelled_push_ids.items.len..]) |push_id| {
            if (push_id > max_push_id) {
                control.deinit(allocator);
                control.* = previous;
                previous_owned = false;
                return error.PushIdExceeded;
            }
        }
    }
    if (handled and role == .server and
        control.priority_update_generation !=
            previous.priority_update_generation and
        control.latest_priority_update_type ==
            http3.FrameType.priority_update_push)
    {
        const update = control.latest_priority_update.?;
        const within_limit = if (control.peer_max_push_id) |max_push_id|
            update.prioritized_element_id <= max_push_id
        else
            false;
        var promised = promised_push_ids == null;
        if (promised_push_ids) |push_ids| {
            for (push_ids) |push_id| {
                if (push_id == update.prioritized_element_id) {
                    promised = true;
                    break;
                }
            }
        }
        if (!within_limit or !promised) {
            control.deinit(allocator);
            control.* = previous;
            previous_owned = false;
            return error.PushIdExceeded;
        }
    }
    return handled;
}

fn controlStreamContainsClientOnlyFrame(
    control: http3.ControlState,
    stream: quic.StreamFrame,
) Error!bool {
    const payload = if (stream.offset == 0) blk: {
        var cursor = @import("../internal/wire.zig").Cursor.init(stream.data);
        const stream_type: http3.StreamType = @enumFromInt(
            quic.varint.decode(&cursor) catch return false,
        );
        if (stream_type != .control) return false;
        break :blk stream.data[cursor.pos..];
    } else blk: {
        if (control.peer_control_stream_id != stream.stream_id) return false;
        break :blk stream.data;
    };
    var offset: usize = 0;
    while (offset < payload.len) {
        const frame = try http3.Frame.parse(payload[offset..]);
        offset += frame.consumed;
        switch (frame.frame_type) {
            http3.FrameType.max_push_id,
            http3.FrameType.cancel_push,
            http3.FrameType.priority_update_request,
            http3.FrameType.priority_update_push,
            => return true,
            else => {},
        }
    }
    return false;
}

fn peekUniStreamType(stream: quic.StreamFrame) ?http3.StreamType {
    var prefix_cursor = @import("../internal/wire.zig").Cursor.init(stream.data);
    return @enumFromInt(quic.varint.decode(&prefix_cursor) catch return null);
}

fn applyControlStreamFrame(control: *http3.ControlState, allocator: std.mem.Allocator, stream: quic.StreamFrame) Error!bool {
    // HTTP/3 control and QPACK streams are unidirectional QUIC streams.  Offset
    // zero carries the stream type varint; subsequent frames on an already
    // registered critical stream contain only that stream's payload.
    if ((stream.stream_id & 0x02) == 0) return false;
    const stream_offset = std.math.cast(usize, stream.offset) orelse
        return error.InvalidStreamRange;
    const stream_end = std.math.add(
        usize,
        stream_offset,
        stream.data.len,
    ) catch return error.InvalidStreamRange;
    if (isRegisteredCriticalStream(control.*, stream.stream_id)) {
        try rejectClosedCriticalStream(stream);
    }
    if (control.peer_control_stream_id != null and
        control.peer_control_stream_id.? == stream.stream_id)
    {
        if (stream_end <= control.peer_control_stream_consumed_offset) {
            return true;
        }
        if (stream_offset > control.peer_control_stream_consumed_offset) {
            return error.BufferTooShort;
        }
        const payload_start =
            control.peer_control_stream_consumed_offset - stream_offset;
        try control.applyControlPayload(
            allocator,
            stream.data[payload_start..],
        );
        control.peer_control_stream_consumed_offset = stream_end;
        return true;
    }
    if (stream.offset != 0) {
        if ((control.peer_qpack_encoder_stream_id != null and control.peer_qpack_encoder_stream_id.? == stream.stream_id) or
            (control.peer_qpack_decoder_stream_id != null and control.peer_qpack_decoder_stream_id.? == stream.stream_id))
        {
            return error.QpackDynamicTableUnsupported;
        }
        return false;
    }

    if (stream.data.len == 0) return false;
    var prefix_cursor = @import("../internal/wire.zig").Cursor.init(stream.data);
    const stream_type = peekUniStreamType(stream) orelse return false;
    _ = quic.varint.decode(&prefix_cursor) catch unreachable;
    switch (stream_type) {
        .control => {
            try rejectClosedCriticalStream(stream);
            try control.registerControlStream(stream.stream_id);
            const apply_start = @max(
                prefix_cursor.pos,
                control.peer_control_stream_consumed_offset,
            );
            if (apply_start < stream.data.len) {
                try control.applyControlPayload(
                    allocator,
                    stream.data[apply_start..],
                );
            }
            control.peer_control_stream_consumed_offset = stream_end;
        },
        .qpack_encoder, .qpack_decoder => {
            try rejectClosedCriticalStream(stream);
            try control.registerQpackStream(stream_type, stream.stream_id);
            if (stream.data[prefix_cursor.pos..].len != 0) return error.QpackDynamicTableUnsupported;
        },
        else => return false,
    }
    return true;
}

fn isRegisteredCriticalStream(control: http3.ControlState, stream_id: u64) bool {
    return (control.peer_control_stream_id != null and control.peer_control_stream_id.? == stream_id) or
        (control.peer_qpack_encoder_stream_id != null and control.peer_qpack_encoder_stream_id.? == stream_id) or
        (control.peer_qpack_decoder_stream_id != null and control.peer_qpack_decoder_stream_id.? == stream_id);
}

fn isLocalCriticalStream(role: ControlStreamRole, stream_id: u64) bool {
    return switch (role) {
        .client => stream_id == client_control_stream_id or stream_id == client_qpack_encoder_stream_id or stream_id == client_qpack_decoder_stream_id,
        .server => stream_id == server_control_stream_id or stream_id == server_qpack_encoder_stream_id or stream_id == server_qpack_decoder_stream_id,
    };
}

fn rejectCriticalStreamClosureFrame(control: http3.ControlState, frame: quic.Frame, role: ControlStreamRole) Error!void {
    switch (frame) {
        .reset_stream => |reset| {
            if (isRegisteredCriticalStream(control, reset.stream_id)) return error.ClosedCriticalStream;
        },
        .stop_sending => |stop| {
            // RFC 9204 §4.2 also forbids requesting closure of the peer's
            // QPACK streams.  Treat STOP_SENDING for our locally-created
            // critical streams the same way tquic/quic-zig treat reset/FIN:
            // as H3_CLOSED_CRITICAL_STREAM at the HTTP/3 layer.
            if (isLocalCriticalStream(role, stop.stream_id)) return error.ClosedCriticalStream;
        },
        else => {},
    }
}

fn rejectClosedCriticalStream(stream: quic.StreamFrame) Error!void {
    // RFC 9114 §6.2.1 and RFC 9204 §4.2 make the control stream and both
    // QPACK streams connection-long-lived critical streams.  Mature stacks
    // (tquic, quic-zig) surface a FIN on any of these streams as
    // H3_CLOSED_CRITICAL_STREAM instead of silently accepting a truncated
    // control/QPACK context.
    if (stream.fin) return error.ClosedCriticalStream;
}

fn sendProtectedFrames(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    keys: quic.protection.PacketProtectionKeys,
    destination_connection_id: []const u8,
    next_packet_number: *u64,
    frames: []const quic.Frame,
    max_frames_per_packet: usize,
    protected_send: *ProtectedSendState,
) Error!void {
    try protected_send.sendFrames(
        endpoint,
        to,
        keys,
        destination_connection_id,
        next_packet_number,
        frames,
        max_frames_per_packet,
    );
}

const MessageStreamDisposition = enum {
    request_response,
    ignore,
};

fn messageStreamDisposition(stream_id: u64) Error!MessageStreamDisposition {
    if ((stream_id & 0x02) != 0) return .ignore;
    // HTTP/3 request/response streams are always client-initiated
    // bidirectional streams.  Without a negotiated extension, a server-initiated
    // bidirectional stream is a connection-level H3_STREAM_CREATION_ERROR.
    if ((stream_id & 0x01) != 0) return error.StreamCreationError;
    return .request_response;
}

fn findMessageStreamFrame(frames: []const quic.Frame) Error!?quic.StreamFrame {
    for (frames) |frame| {
        if (frame != .stream) continue;
        switch (try messageStreamDisposition(frame.stream.stream_id)) {
            .request_response => return frame.stream,
            .ignore => continue,
        }
    }
    return null;
}

fn findStreamFrame(frames: []const quic.Frame) ?quic.StreamFrame {
    for (frames) |frame| {
        if (frame == .stream) return frame.stream;
    }
    return null;
}

test "HTTP/3 server GOAWAY validates request stream ids" {
    try validateServerGoAwayStreamId(0);
    try validateServerGoAwayStreamId(4);
    try validateServerGoAwayStreamId(128);
    try std.testing.expectError(error.InvalidFrame, validateServerGoAwayStreamId(1));
    try std.testing.expectError(error.InvalidFrame, validateServerGoAwayStreamId(2));
    try std.testing.expectError(error.InvalidFrame, validateServerGoAwayStreamId(3));
    try validateClientGoAwayPushId(0);
    try validateClientGoAwayPushId(1);
    try validateClientGoAwayPushId(quic.varint.max_value);

    try std.testing.expect(!rejectByLocalGoAway(.{ .local_goaway_id = 0 }, .client, 0));
    try std.testing.expect(!rejectByLocalGoAway(.{ .local_goaway_id = 0 }, .client, 4));
    try std.testing.expect(!rejectByLocalGoAway(.{ .local_goaway_id = 4 }, .server, 0));
    try std.testing.expect(rejectByLocalGoAway(.{ .local_goaway_id = 4 }, .server, 4));
}

test "HTTP/3 client rejects server-only control frames" {
    const allocator = std.testing.allocator;

    var ignored_message_control = http3.ControlState{};
    defer ignored_message_control.deinit(allocator);
    try std.testing.expect(!try applyControlStreamFrameForRole(
        &ignored_message_control,
        allocator,
        .{
            .stream_id = 0,
            .offset = 0,
            .fin = false,
            // On bidirectional request/response streams this is a DATA frame,
            // not a unidirectional stream-type prefix.  Keep role validation
            // from interpreting the DATA length as MAX_PUSH_ID and rejecting a
            // message stream before the message decoder sees it.
            .data = &.{ 0x00, 0x0d, 0x00 },
        },
        .client,
    ));

    var ignored_extension_control = http3.ControlState{};
    defer ignored_extension_control.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expect(!try applyControlStreamFrameForRole(
        &ignored_extension_control,
        no_alloc.allocator(),
        .{
            .stream_id = 3,
            .offset = 0,
            .fin = false,
            // Unknown unidirectional streams are extension-owned.  Role
            // validation should ignore them without cloning control state.
            .data = &.{ 0x21, 0x00 },
        },
        .client,
    ));
    try std.testing.expect(!try applyControlStreamFrameForRole(
        &ignored_extension_control,
        no_alloc.allocator(),
        .{
            .stream_id = 3,
            .offset = 2,
            .fin = false,
            .data = &.{0x0d},
        },
        .client,
    ));
    try std.testing.expect(!no_alloc.has_induced_failure);

    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    var goaway_payload: std.ArrayList(u8) = .empty;
    defer goaway_payload.deinit(allocator);

    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 1);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);

    var client_control = http3.ControlState{};
    defer client_control.deinit(allocator);
    try std.testing.expectError(error.InvalidFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.peer_goaway_id == null);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writeMaxPushIdFrame(&stream_bytes, allocator, 4);

    client_control.deinit(allocator);
    client_control = .{};
    try std.testing.expectError(error.UnexpectedFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.peer_max_push_id == null);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(&stream_bytes, allocator, 0, .{ .urgency = 1 });
    client_control.deinit(allocator);
    client_control = .{};
    try std.testing.expectError(error.UnexpectedFrame, applyControlStreamFrameForRole(&client_control, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
    try std.testing.expect(client_control.latest_priority_update == null);

    // A second server PRIORITY_UPDATE must be rejected too. Comparing only
    // optional presence let this bypass role validation once one update had
    // already populated connection state.
    var repeated_client_control = http3.ControlState{};
    defer repeated_client_control.deinit(allocator);
    repeated_client_control.settings.received = true;
    var first_illegal: std.ArrayList(u8) = .empty;
    defer first_illegal.deinit(allocator);
    try http3.writePriorityUpdateFrame(
        &first_illegal,
        allocator,
        0,
        .{ .urgency = 1 },
    );
    try repeated_client_control.applyFrame(
        allocator,
        try http3.Frame.parse(first_illegal.items),
    );
    const generation =
        repeated_client_control.priority_update_generation;
    var second_illegal: std.ArrayList(u8) = .empty;
    defer second_illegal.deinit(allocator);
    try http3.writeControlStreamPrefix(&second_illegal, allocator);
    try http3.writePriorityUpdateFrame(
        &second_illegal,
        allocator,
        4,
        .{ .urgency = 2 },
    );
    try std.testing.expectError(
        error.UnexpectedFrame,
        applyControlStreamFrameForRole(
            &repeated_client_control,
            allocator,
            .{
                .stream_id = 3,
                .offset = 0,
                .data = second_illegal.items,
            },
            .client,
        ),
    );
    try std.testing.expectEqual(
        generation,
        repeated_client_control.priority_update_generation,
    );
    try std.testing.expect(
        repeated_client_control.requestPriorityUpdate(4) == null,
    );

    stream_bytes.clearRetainingCapacity();
    goaway_payload.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try quic.varint.encode(&goaway_payload, allocator, 1);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);

    var server_control = http3.ControlState{};
    defer server_control.deinit(allocator);
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expectEqual(@as(?u64, 1), server_control.peer_goaway_id);

    const next_control_offset = stream_bytes.items.len;
    stream_bytes.clearRetainingCapacity();
    goaway_payload.clearRetainingCapacity();
    try quic.varint.encode(&goaway_payload, allocator, 0);
    try (http3.Frame{ .frame_type = http3.FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&stream_bytes, allocator);
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = next_control_offset,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expectEqual(@as(?u64, 0), server_control.peer_goaway_id);

    stream_bytes.clearRetainingCapacity();
    try http3.writeControlStreamPrefix(&stream_bytes, allocator);
    try http3.writeSettingsFrame(&stream_bytes, allocator, .{});
    try http3.writePriorityUpdateFrame(&stream_bytes, allocator, 0, .{ .urgency = 1 });

    server_control.deinit(allocator);
    server_control = .{};
    try std.testing.expect(try applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));
    try std.testing.expect(server_control.latest_priority_update != null);

    stream_bytes.clearRetainingCapacity();
    try quic.varint.encode(&stream_bytes, allocator, @intFromEnum(http3.StreamType.push));
    server_control.deinit(allocator);
    server_control = .{};
    try std.testing.expectError(error.StreamCreationError, applyControlStreamFrameForRole(&server_control, allocator, .{
        .stream_id = 2,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .server));

    var client_control_for_push = http3.ControlState{};
    try std.testing.expect(!try applyControlStreamFrameForRole(&client_control_for_push, allocator, .{
        .stream_id = 3,
        .offset = 0,
        .fin = false,
        .data = stream_bytes.items,
    }, .client));
}

test "HTTP/3 connection control frames advance control stream offset" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xf1, 0xf2, 0xf3, 0xf4 };
    const server_cid = [_]u8{ 0xf5, 0xf6, 0xf7, 0xf8 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xf1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xf2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    try client.sendGoAway(0);
    var first = try quic.one_rtt.receive(&server.quic_server.endpoint, client_keys, server_cid.len, 0, 8);
    defer first.deinit(allocator);
    const first_stream = findStreamFrame(first.frames) orelse return error.MissingStreamFrame;
    try std.testing.expectEqual(@as(u64, 0), first_stream.offset);
    try std.testing.expect(try applyControlStreamFrame(&server.control, allocator, first_stream));

    var second = try quic.one_rtt.receive(&server.quic_server.endpoint, client_keys, server_cid.len, 1, 8);
    defer second.deinit(allocator);
    const second_stream = findStreamFrame(second.frames) orelse return error.MissingStreamFrame;
    try std.testing.expect(second_stream.offset > 0);
    try std.testing.expect(try applyControlStreamFrame(&server.control, allocator, second_stream));
    try std.testing.expectEqual(@as(?u64, 0), server.control.peer_goaway_id);

    try client.sendGoAway(0);
    var third = try quic.one_rtt.receive(&server.quic_server.endpoint, client_keys, server_cid.len, 2, 8);
    defer third.deinit(allocator);
    const third_stream = findStreamFrame(third.frames) orelse return error.MissingStreamFrame;
    try std.testing.expect(third_stream.offset > second_stream.offset);
    try std.testing.expect(try applyControlStreamFrame(&server.control, allocator, third_stream));
    try std.testing.expectEqual(@as(?u64, 0), server.control.peer_goaway_id);
}

test "HTTP/3 runtime rejects non-empty QPACK critical streams" {
    const allocator = std.testing.allocator;
    var control = http3.ControlState{};
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&payload, allocator);
    try payload.append(allocator, 0x3f); // Set Dynamic Table Capacity prefix/instruction byte.

    try std.testing.expectError(error.QpackDynamicTableUnsupported, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = payload.items,
    }));
    try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), control.peer_qpack_encoder_stream_id);
}

test "HTTP/3 protected send state reuses batch scratch" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer receiver.deinit();
    var sender = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer sender.deinit();

    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x6b} ** quic.protection.secret_len,
    );
    const frame_storage = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "one" } },
        .{ .stream = .{ .stream_id = 0, .offset = 3, .data = "two" } },
        .{ .stream = .{ .stream_id = 0, .offset = 6, .data = "three" } },
    };
    var send_state = ProtectedSendState.init(allocator);
    defer send_state.deinit();
    var next_packet_number: u64 = 0;
    try send_state.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "cid",
        &next_packet_number,
        &frame_storage,
        1,
    );
    const payload_capacity = send_state.payload_scratch.capacity;
    const packet_capacity = send_state.packet_scratch.capacity;
    try std.testing.expect(payload_capacity != 0);
    try std.testing.expect(packet_capacity != 0);
    try std.testing.expectEqual(@as(u64, 3), next_packet_number);
    try std.testing.expectEqual(@as(usize, 0), send_state.payload_scratch.items.len);
    try std.testing.expectEqual(@as(usize, 0), send_state.packet_scratch.items.len);

    // A same-sized batch must stay on the steady-state allocation-free path.
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    send_state.allocator = no_alloc.allocator();
    try send_state.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "cid",
        &next_packet_number,
        &frame_storage,
        1,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(payload_capacity, send_state.payload_scratch.capacity);
    try std.testing.expectEqual(packet_capacity, send_state.packet_scratch.capacity);
    try std.testing.expectEqual(@as(u64, 6), next_packet_number);
}

test "HTTP/3 QPACK decoder state reassembles split and reordered encoder instructions" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 256, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_literal = .{
        .name = "x-runtime",
        .value = "split-across-stream-frames",
    } });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_name_reference = .{
        .static = true,
        .name_index = 1,
        .value = "/dynamic",
    } });
    const split = bytes.items.len / 2;

    // Deliver the suffix first. Nothing is contiguous from offset zero, so no
    // stream registration, table mutation, or decoder feedback is possible.
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = split,
        .data = bytes.items[split..],
    });
    try std.testing.expect(control.peer_qpack_encoder_stream_id == null);
    try std.testing.expectEqual(@as(usize, 0), state.table.entryCount());
    try std.testing.expectEqual(@as(usize, 0), state.decoder_instructions.items.len);

    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items[0..split],
    });
    try std.testing.expectEqual(
        @as(?u64, client_qpack_encoder_stream_id),
        control.peer_qpack_encoder_stream_id,
    );
    try std.testing.expectEqual(@as(usize, 256), state.table.capacity);
    try std.testing.expectEqual(@as(u64, 2), state.table.insert_count);
    try std.testing.expectEqualStrings("x-runtime", state.table.absolute(0).?.name);
    try std.testing.expectEqualStrings(":path", state.table.absolute(1).?.name);
    try std.testing.expectEqualStrings("/dynamic", state.table.absolute(1).?.value);

    const feedback = try state.takeDecoderInstructions();
    defer allocator.free(feedback);
    const increment = try http3.Qpack.decodeDecoderInstruction(feedback);
    try std.testing.expectEqual(@as(usize, feedback.len), increment.consumed);
    try std.testing.expectEqual(
        @as(u64, 2),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(@as(u64, 2), state.acknowledged_insert_count);

    // An identical retransmission is accepted by RecvState and cannot apply
    // instructions or acknowledgments a second time.
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items,
    });
    try std.testing.expectEqual(@as(u64, 2), state.table.insert_count);
    try std.testing.expectEqual(@as(usize, 0), state.decoder_instructions.items.len);
}

test "HTTP/3 QPACK decoder state retains a partial instruction and acknowledges field section" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 256, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 256 });
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .insert_literal = .{
        .name = "x-partial",
        .value = "value-that-needs-the-second-frame",
    } });
    const split = bytes.items.len - 3;
    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .data = bytes.items[0..split],
    });
    try std.testing.expectEqual(@as(u64, 0), state.table.insert_count);
    try std.testing.expect(state.encoder_stream.?.available().len != 0);

    try state.applyEncoderStreamFrame(&control, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = split,
        .data = bytes.items[split..],
    });
    try std.testing.expectEqual(@as(u64, 1), state.table.insert_count);
    try std.testing.expectEqual(@as(usize, 0), state.encoder_stream.?.available().len);

    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = "x-partial", .value = "value-that-needs-the-second-frame" },
    }, state.table);
    var decoded = try state.decodeFieldSection(allocator, 12, field_section.items);
    defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
    try std.testing.expectEqual(@as(usize, 1), decoded.fields.len);
    try std.testing.expectEqualStrings("x-partial", decoded.fields[0].name);

    const feedback = try state.takeDecoderInstructions();
    defer allocator.free(feedback);
    const increment = try http3.Qpack.decodeDecoderInstruction(feedback);
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback[increment.consumed..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        @as(u64, 12),
        acknowledgment.instruction.section_acknowledgment,
    );
}

test "HTTP/3 QPACK decoder state rejects capacity overflow and critical stream FIN" {
    const allocator = std.testing.allocator;
    var state = QpackDecodeState.init(allocator, 64, 4096);
    defer state.deinit();
    var control = http3.ControlState{};

    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(&bytes, allocator, .{ .set_capacity = 65 });
    try std.testing.expectError(error.QpackEncoderStreamError, state.applyEncoderStreamFrame(
        &control,
        .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = bytes.items,
        },
    ));

    var fin_state = QpackDecodeState.init(allocator, 64, 4096);
    defer fin_state.deinit();
    try std.testing.expectError(error.ClosedCriticalStream, fin_state.applyEncoderStreamFrame(
        &control,
        .{
            .stream_id = client_qpack_encoder_stream_id,
            .offset = 0,
            .data = &.{@intFromEnum(http3.StreamType.qpack_encoder)},
            .fin = true,
        },
    ));
}

test "HTTP/3 QPACK encoder state waits for insert acknowledgment before dynamic reference" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 256, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(256);
    try std.testing.expectEqual(
        @as(?u64, 0),
        try encoder.insertField("x-encode", "reused"),
    );

    const fields = [_]http3.Qpack.HeaderField{
        .{ .name = "x-encode", .value = "reused" },
    };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var first_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        first.items,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &first_decoded);
    try std.testing.expectEqual(@as(u64, 0), first_decoded.required_insert_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);

    var decoder_bytes: std.ArrayList(u8) = .empty;
    defer decoder_bytes.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&decoder_bytes, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &decoder_bytes,
        allocator,
        .{ .insert_count_increment = 1 },
    );
    var control = http3.ControlState{};
    const split = decoder_bytes.items.len - 1;
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = split,
        .data = decoder_bytes.items[split..],
    });
    try std.testing.expectEqual(@as(u64, 0), encoder.known_received_count);
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = decoder_bytes.items[0..split],
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(
        @as(?u64, client_qpack_decoder_stream_id),
        control.peer_qpack_decoder_stream_id,
    );

    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &fields);
    var second_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        second.items,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &second_decoded);
    try std.testing.expectEqual(@as(u64, 1), second_decoded.required_insert_count);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(0));

    var acknowledgment: std.ArrayList(u8) = .empty;
    defer acknowledgment.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &acknowledgment,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = decoder_bytes.items.len,
        .data = acknowledgment.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expect(!encoder.reference_counts.contains(0));
    try std.testing.expect(!encoder.hasPendingSections(4));
    encoder.abandonStream(4);

    // Retransmitting the same decoder bytes cannot acknowledge twice.
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = decoder_bytes.items,
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
}

test "HTTP/3 QPACK encoder binds once to peer SETTINGS capacity" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();

    try std.testing.expect(encoder.peer_max_capacity == null);
    try std.testing.expectEqual(@as(usize, 0), encoder.table.capacity);
    try encoder.configurePeerCapacity(256);
    try std.testing.expectEqual(@as(?usize, 256), encoder.peer_max_capacity);
    try std.testing.expectEqual(@as(usize, 256), encoder.table.max_capacity);
    try std.testing.expectEqual(@as(usize, 256), encoder.table.capacity);
    const instruction_len = encoder.pendingEncoderInstructions().len;
    try std.testing.expect(instruction_len != 0);

    // Reprocessing retransmitted control bytes is idempotent, while a changed
    // value would violate HTTP/3's one-SETTINGS-frame connection contract.
    try encoder.configurePeerCapacity(256);
    try std.testing.expectEqual(
        instruction_len,
        encoder.pendingEncoderInstructions().len,
    );
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        encoder.configurePeerCapacity(128),
    );
}

test "HTTP/3 QPACK encoder state protects referenced entries from eviction" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 34, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(34);
    _ = try encoder.insertField("a", "1");

    var control = http3.ControlState{};
    const decoder_stream = [_]u8{
        @intFromEnum(http3.StreamType.qpack_decoder),
        0x01, // Insert Count Increment = 1.
    };
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = &decoder_stream,
    });

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 8, &.{
        .{ .name = "a", .value = "1" },
    });
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);

    // Inserting b would evict referenced a. The encoder must skip the insert,
    // not violate QPACK's prohibited-eviction rule.
    try std.testing.expectEqual(
        @as(?u64, null),
        try encoder.insertField("b", "2"),
    );
    try std.testing.expectEqualStrings("a", encoder.table.relative(0).?.name);

    var cancel_bytes: std.ArrayList(u8) = .empty;
    defer cancel_bytes.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &cancel_bytes,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = decoder_stream.len,
        .data = cancel_bytes.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);

    // Once acknowledged and unreferenced, a becomes evictable.
    try std.testing.expectEqual(
        @as(?u64, 1),
        try encoder.insertField("b", "2"),
    );
    try std.testing.expect(encoder.table.absolute(0) == null);
    try std.testing.expectEqualStrings("b", encoder.table.relative(0).?.name);
}

test "HTTP/3 QPACK stream cancellation compacts pending sections stably" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-one", "one");
    _ = try encoder.insertField("x-two", "two");
    _ = try encoder.insertField("x-three", "three");
    encoder.known_received_count = encoder.table.insert_count;

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 4, &.{
        .{ .name = "x-one", .value = "one" },
    });
    var canceled: std.ArrayList(u8) = .empty;
    defer canceled.deinit(allocator);
    try encoder.encodeFieldSection(&canceled, 8, &.{
        .{ .name = "x-one", .value = "one" },
    });
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &.{
        .{ .name = "x-two", .value = "two" },
    });
    var third: std.ArrayList(u8) = .empty;
    defer third.deinit(allocator);
    try encoder.encodeFieldSection(&third, 4, &.{
        .{ .name = "x-three", .value = "three" },
    });
    try std.testing.expectEqual(@as(usize, 4), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(?usize, 1), encoder.pending_section_index.get(8));

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });

    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[0].stream_id);
    try std.testing.expectEqual(@as(u64, 1), encoder.pending_sections.items[0].required_insert_count);
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[1].stream_id);
    try std.testing.expectEqual(@as(u64, 2), encoder.pending_sections.items[1].required_insert_count);
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[2].stream_id);
    try std.testing.expectEqual(@as(u64, 3), encoder.pending_sections.items[2].required_insert_count);
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(0));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(1));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(2));

    try std.testing.expectEqual(@as(usize, 0), encoder.releaseSectionsForStream(8));
    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_section_index.count());

    var ack_first: std.ArrayList(u8) = .empty;
    defer ack_first.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &ack_first,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = feedback.items.len,
        .data = ack_first.items,
    });
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(u64, 2), encoder.pending_sections.items[0].required_insert_count);
    try std.testing.expectEqual(@as(u64, 3), encoder.pending_sections.items[1].required_insert_count);
    try std.testing.expect(!encoder.reference_counts.contains(0));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(1));
    try std.testing.expectEqual(@as(?usize, 1), encoder.reference_counts.get(2));
}

test "HTTP/3 QPACK pending section index repairs shifted streams" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-one", "one");
    _ = try encoder.insertField("x-two", "two");
    encoder.known_received_count = encoder.table.insert_count;

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 4, &.{
        .{ .name = "x-one", .value = "one" },
    });
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 8, &.{
        .{ .name = "x-two", .value = "two" },
    });
    var third: std.ArrayList(u8) = .empty;
    defer third.deinit(allocator);
    try encoder.encodeFieldSection(&third, 4, &.{
        .{ .name = "x-two", .value = "two" },
    });
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
    try std.testing.expectEqual(@as(?usize, 1), encoder.pending_section_index.get(8));

    var control = http3.ControlState{};
    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .section_acknowledgment = 4 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });
    try std.testing.expectEqual(@as(usize, 2), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(8));
    try std.testing.expectEqual(@as(?usize, 1), encoder.pending_section_index.get(4));

    var cancel: std.ArrayList(u8) = .empty;
    defer cancel.deinit(allocator);
    try http3.Qpack.writeDecoderInstruction(
        &cancel,
        allocator,
        .{ .stream_cancellation = 8 },
    );
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = feedback.items.len,
        .data = cancel.items,
    });
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expect(!encoder.pending_section_index.contains(8));
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(4));
}

test "HTTP/3 QPACK encoder state rejects invalid decoder feedback" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 128, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(128);
    _ = try encoder.insertField("a", "1");
    var control = http3.ControlState{};

    const excessive_increment = [_]u8{
        @intFromEnum(http3.StreamType.qpack_decoder),
        0x02,
    };
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        encoder.applyDecoderStreamFrame(&control, .{
            .stream_id = client_qpack_decoder_stream_id,
            .offset = 0,
            .data = &excessive_increment,
        }),
    );

    var ack_without_section = QpackEncodeState.init(allocator, 128, 4096);
    defer ack_without_section.deinit();
    var acknowledgment: std.ArrayList(u8) = .empty;
    defer acknowledgment.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&acknowledgment, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &acknowledgment,
        allocator,
        .{ .section_acknowledgment = 0 },
    );
    var second_control = http3.ControlState{};
    try std.testing.expectError(
        error.QpackDecoderStreamError,
        ack_without_section.applyDecoderStreamFrame(
            &second_control,
            .{
                .stream_id = client_qpack_decoder_stream_id,
                .offset = 0,
                .data = acknowledgment.items,
            },
        ),
    );
}

fn checkQpackEncoderStateAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerCapacity(256);
    _ = try encoder.insertField("x-one", "value-one");
    _ = try encoder.insertField("x-two", "value-two");

    // Simulate a decoder that has processed both inserts, then exercise
    // multi-container field-section reference tracking.
    encoder.known_received_count = encoder.table.insert_count;
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 12, &.{
        .{ .name = "x-one", .value = "value-one" },
        .{ .name = "x-two", .value = "value-two" },
    });
}

test "HTTP/3 QPACK encoder state is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackEncoderStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 dynamic request writer inserts first and compresses after decoder feedback" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);

    const request = http3.Request{
        .method = "GET",
        .path = "/dynamic-writer",
        .authority = "example.com",
        .headers = &.{
            .{ .name = "x-service-release", .value = "2026.08.09" },
            .{ .name = "authorization", .value = "Bearer secret" },
            .{ .name = "cookie", .value = "session=secret" },
        },
    };
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try request.writeDynamic(&first, allocator, .{}, 0, &encoder);
    const first_headers = try http3.Frame.parse(first.items);
    var first_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        first_headers.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &first_decoded);
    try std.testing.expectEqual(@as(u64, 0), first_decoded.required_insert_count);
    try std.testing.expect(encoder.table.findExact(
        "x-service-release",
        "2026.08.09",
    ) != null);
    try std.testing.expect(encoder.table.findName("authorization") == null);
    try std.testing.expect(encoder.table.findName("cookie") == null);
    try std.testing.expect(encoder.pendingEncoderInstructions().len != 0);

    // Decoder feedback makes the speculative insert referenceable without
    // risking a blocked request stream.
    encoder.known_received_count = encoder.table.insert_count;
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try request.writeDynamic(&second, allocator, .{}, 4, &encoder);
    const second_headers = try http3.Frame.parse(second.items);
    var second_decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        second_headers.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &second_decoded);
    try std.testing.expect(second_decoded.required_insert_count != 0);
    try std.testing.expect(second.items.len < first.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(u64, 4), encoder.pending_sections.items[0].stream_id);
}

test "HTTP/3 dynamic response writer tracks informational final and trailer sections" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-release", "netz-2026");
    encoder.known_received_count = encoder.table.insert_count;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try http3.writeResponseSequenceDynamic(
        &encoded,
        allocator,
        &.{.{
            .status = 103,
            .headers = &.{.{ .name = "x-release", .value = "netz-2026" }},
        }},
        .{
            .status = 200,
            .headers = &.{.{ .name = "x-release", .value = "netz-2026" }},
            .body = "ok",
            .trailers = &.{.{ .name = "x-release", .value = "netz-2026" }},
        },
        .{},
        8,
        &encoder,
    );
    try std.testing.expectEqual(@as(usize, 3), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 1), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(?usize, 0), encoder.pending_section_index.get(8));
    for (encoder.pending_sections.items) |section| {
        try std.testing.expectEqual(@as(u64, 8), section.stream_id);
        try std.testing.expectEqual(@as(u64, 1), section.required_insert_count);
    }

    var cursor: usize = 0;
    var dynamic_sections: usize = 0;
    while (cursor < encoded.items.len) {
        const frame = try http3.Frame.parse(encoded.items[cursor..]);
        cursor += frame.consumed;
        if (frame.frame_type != http3.FrameType.headers) continue;
        var decoded = try http3.Qpack.decodeDynamicBlock(
            allocator,
            frame.payload,
            encoder.table,
        );
        defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
        dynamic_sections += @intFromBool(decoded.required_insert_count != 0);
    }
    try std.testing.expectEqual(@as(usize, 3), dynamic_sections);
    encoder.abandonStream(8);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_sections.items.len);
    try std.testing.expectEqual(@as(usize, 0), encoder.pending_section_index.count());
    try std.testing.expectEqual(@as(usize, 0), encoder.reference_counts.count());
}

test "HTTP/3 streaming request head adds and validates content length" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const streaming = try (http3.Request{
        .method = "POST",
        .path = "/streaming",
        .authority = "example.test",
    }).writeStreamingHeadDynamic(
        &encoded,
        allocator,
        .{},
        0,
        11,
        &encoder,
    );
    try std.testing.expectEqual(
        @as(?usize, 11),
        streaming.expected_length,
    );
    try std.testing.expect(streaming.body_allowed);
    const frame = try http3.Frame.parse(encoded.items);
    try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
    try std.testing.expectEqual(frame.consumed, encoded.items.len);
    var decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        frame.payload,
        encoder.table,
    );
    defer http3.Qpack.freeDynamicBlock(allocator, &decoded);
    var content_length_value: ?[]const u8 = null;
    for (decoded.fields) |field| {
        if (std.mem.eql(u8, field.name, "content-length")) {
            content_length_value = field.value;
        }
    }
    try std.testing.expectEqualStrings(
        "11",
        content_length_value orelse return error.TestUnexpectedResult,
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Request{
            .method = "POST",
            .path = "/streaming",
            .headers = &.{.{
                .name = "content-length",
                .value = "12",
            }},
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            4,
            11,
            &encoder,
        ),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Request{
            .method = "CONNECT",
            .path = "",
            .authority = "example.test:443",
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            8,
            1,
            &encoder,
        ),
    );
}

test "HTTP/3 streaming response head enforces bodyless status" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    const streaming = try (http3.Response{
        .status = 200,
    }).writeStreamingHeadDynamic(
        &encoded,
        allocator,
        .{},
        0,
        null,
        &encoder,
    );
    try std.testing.expectEqual(
        @as(?usize, null),
        streaming.expected_length,
    );
    try std.testing.expect(streaming.body_allowed);
    try std.testing.expectEqual(
        http3.FrameType.headers,
        (try http3.Frame.parse(encoded.items)).frame_type,
    );

    encoded.clearRetainingCapacity();
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Response{
            .status = 204,
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            4,
            1,
            &encoder,
        ),
    );
    try std.testing.expectError(
        error.InvalidContentLength,
        (http3.Response{
            .status = 204,
            .headers = &.{.{
                .name = "content-length",
                .value = "0",
            }},
        }).writeStreamingHeadDynamic(
            &encoded,
            allocator,
            .{},
            8,
            null,
            &encoder,
        ),
    );
}

test "HTTP/3 incremental reader streams DATA through bounded window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 100 * 1024;
    var table = http3.Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-stream", "owned");

    var fields: [6]http3.Qpack.HeaderField = .{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/large-stream" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = undefined },
        .{ .name = "x-stream", .value = "owned" },
    };
    var content_length_buf: [32]u8 = undefined;
    fields[4].value = try std.fmt.bufPrint(
        &content_length_buf,
        "{}",
        .{body_len},
    );
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &fields, table);
    var message_prefix: std.ArrayList(u8) = .empty;
    defer message_prefix.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&message_prefix, allocator);
    try quic.varint.encode(
        &message_prefix,
        allocator,
        http3.FrameType.data,
    );
    try quic.varint.encode(&message_prefix, allocator, body_len);

    var trailer_block: std.ArrayList(u8) = .empty;
    defer trailer_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &trailer_block,
        allocator,
        &.{.{ .name = "x-finished", .value = "yes" }},
        table,
    );
    var trailer_frame: std.ArrayList(u8) = .empty;
    defer trailer_frame.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = trailer_block.items,
        .consumed = 0,
    }).write(&trailer_frame, allocator);

    var reader = StreamingMessageReader.initRequest(
        allocator,
        0,
        512,
        .{},
    );
    defer reader.deinit();
    var absolute_offset: u64 = 0;
    try reader.insert(.{
        .stream_id = 0,
        .offset = absolute_offset,
        .data = message_prefix.items,
    });
    absolute_offset += message_prefix.items.len;
    var head_event = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer head_event.deinit(allocator);
    try std.testing.expect(head_event == .head);
    try std.testing.expectEqualStrings(
        "/large-stream",
        head_event.head.request.path,
    );
    try std.testing.expectEqual(
        @as(?usize, body_len),
        head_event.head.request.content_length,
    );

    var body_checksum: u64 = 0;
    var body_read: usize = 0;
    var payload_chunk: [257]u8 = undefined;
    for (&payload_chunk, 0..) |*byte, index| byte.* = @truncate(index);
    var read_buf: [113]u8 = undefined;
    while (body_read < body_len) {
        const send_len = @min(payload_chunk.len, body_len - body_read);
        try reader.insert(.{
            .stream_id = 0,
            .offset = absolute_offset,
            .data = payload_chunk[0..send_len],
        });
        absolute_offset += send_len;
        while (true) {
            const event = (try reader.next(table)) orelse break;
            try std.testing.expect(event == .data_available);
            while (reader.current_frame != null) {
                const read = try reader.readData(&read_buf);
                if (read == 0) break;
                for (read_buf[0..read]) |byte| body_checksum +%= byte;
                body_read += read;
            }
        }
        try std.testing.expect(reader.receive.buffer.items.len <= 512);
    }

    try reader.insert(.{
        .stream_id = 0,
        .offset = absolute_offset,
        .data = trailer_frame.items,
        .fin = true,
    });
    var trailers_event = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer trailers_event.deinit(allocator);
    try std.testing.expect(trailers_event == .trailers);
    try std.testing.expectEqualStrings(
        "yes",
        trailers_event.trailers.fields[0].value,
    );
    var finished = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
    try std.testing.expectEqual(body_len, body_read);

    // Each transmitted chunk restarts the deterministic payload pattern.
    var expected_checksum: u64 = 0;
    var remaining = body_len;
    while (remaining != 0) {
        const send_len = @min(payload_chunk.len, remaining);
        for (payload_chunk[0..send_len]) |byte| expected_checksum +%= byte;
        remaining -= send_len;
    }
    try std.testing.expectEqual(expected_checksum, body_checksum);
}

test "HTTP/3 incremental response reader emits informational and detects truncation" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "103" },
    }, table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);
    block.clearRetainingCapacity();
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "4" },
    }, table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.data,
        .payload = "abc",
        .consumed = 0,
    }).write(&bytes, allocator);

    var reader = StreamingMessageReader.initResponse(
        allocator,
        0,
        128,
        .{},
    );
    defer reader.deinit();
    try reader.insert(.{
        .stream_id = 0,
        .data = bytes.items,
        .fin = true,
    });
    var informational = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer informational.deinit(allocator);
    try std.testing.expect(informational == .head);
    try std.testing.expectEqual(
        @as(u16, 103),
        informational.head.response.status,
    );
    var final = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer final.deinit(allocator);
    try std.testing.expect(final == .head);
    try std.testing.expectEqual(@as(u16, 200), final.head.response.status);
    try std.testing.expect((try reader.next(table)).? == .data_available);
    var data: [4]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 3), try reader.readData(&data));
    try std.testing.expectError(
        error.InvalidContentLength,
        reader.next(table),
    );
}

test "HTTP/3 incremental response reader owns dynamic PUSH_PROMISE before final head" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-promise-kind", "dynamic-asset");
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, table);
    try http3.writePushPromiseFrame(&bytes, allocator, 3, block.items);
    block.clearRetainingCapacity();
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "0" },
    }, table);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&bytes, allocator);

    var reader = StreamingMessageReader.initResponse(
        allocator,
        0,
        512,
        .{},
    );
    var reader_owned = true;
    defer if (reader_owned) reader.deinit();
    try reader.insert(.{
        .stream_id = 0,
        .data = bytes.items,
        .fin = true,
    });
    var promise = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 3), promise.push_promise.push_id);
    try std.testing.expectEqualStrings(
        "/asset.css",
        promise.push_promise.request.path,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        promise.push_promise.request.qpack_section_acknowledgments,
    );
    try std.testing.expectEqualStrings(
        "dynamic-asset",
        promise.push_promise.request.headers[4].value,
    );
    // A promise is metadata for the eventual response; it must not advance the
    // message phase or make the following final HEADERS look like trailers.
    var head = (try reader.next(table)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    try std.testing.expectEqual(@as(u16, 200), head.head.response.status);
    // Event storage must remain valid after the stream window is destroyed.
    reader.deinit();
    reader_owned = false;
    try std.testing.expectEqualStrings(
        "example.test",
        promise.push_promise.request.authority.?,
    );
}

test "HTTP/3 incremental response reader detects dynamic PUSH_PROMISE cancellation" {
    const allocator = std.testing.allocator;
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-promise-kind", "dynamic-asset");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, table);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try http3.writePushPromiseFrame(&bytes, allocator, 3, block.items);

    var reader = StreamingMessageReader.initResponse(
        allocator,
        0,
        512,
        .{},
    );
    defer reader.deinit();
    try reader.insert(.{
        .stream_id = 0,
        .data = bytes.items,
    });
    try std.testing.expect(
        try reader.hasUnacknowledgedDynamicSection(table),
    );
}

test "HTTP/3 push stream set binds promise and streams response" {
    const allocator = std.testing.allocator;
    var pushes = PushStreamSet.init(allocator, 4, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(3);
    try pushes.registerPromise(3, 0);

    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "asset",
    }).write(&response, allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try quic.varint.encode(
        &bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&bytes, allocator, 3);
    try bytes.appendSlice(allocator, response.items);

    var control = http3.ControlState{ .local_max_push_id = 3 };
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    try std.testing.expect(try pushes.insert(from, .{
        .stream_id = 15,
        .data = bytes.items,
        .fin = true,
    }, control));
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    var head = (try pushes.next(table, 0, null)).?;
    defer head.event.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), head.event.push_id);
    try std.testing.expectEqual(
        @as(u62, 0),
        head.event.request_stream_id,
    );
    try std.testing.expectEqual(@as(u62, 15), head.event.stream_id);
    try std.testing.expect(head.event.value == .head);
    try std.testing.expectEqual(
        @as(u16, 200),
        head.event.value.head.response.status,
    );
    try std.testing.expect((try pushes.next(table, 0, null)).?.event.value ==
        .data_available);
    var body: [8]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 5),
        try pushes.readData(3, &body),
    );
    try std.testing.expectEqualStrings("asset", body[0..5]);

    // Targeted polling uses the push-id index and should not scan unrelated
    // retained push streams first.
    try pushes.registerPromise(1, 0);
    var other_bytes: std.ArrayList(u8) = .empty;
    defer other_bytes.deinit(allocator);
    try quic.varint.encode(
        &other_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&other_bytes, allocator, 1);
    try other_bytes.appendSlice(allocator, response.items);
    try std.testing.expect(try pushes.insert(from, .{
        .stream_id = 19,
        .data = other_bytes.items,
        .fin = true,
    }, control));
    const targeted = (try pushes.next(table, 0, 3)).?;
    try std.testing.expect(targeted.event.value == .finished);
    var targeted_event = targeted.event;
    targeted_event.deinit(allocator);
    pushes.removeFinished(targeted.index);
    try std.testing.expect(pushes.findByPushId(3) == null);

    const finished = (try pushes.next(table, 0, null)).?;
    try std.testing.expect(finished.event.value == .head);
    var finished_event = finished.event;
    finished_event.deinit(allocator);

    // The same push may be promised on more than one request stream.
    try pushes.registerPromise(3, 4);
    _ = &control;
}

test "HTTP/3 push stream set retains response until promise arrives" {
    const allocator = std.testing.allocator;
    var pushes = PushStreamSet.init(allocator, 4, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(3);
    var response: std.ArrayList(u8) = .empty;
    defer response.deinit(allocator);
    try (http3.Response{ .status = 204 }).write(&response, allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try quic.varint.encode(
        &bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&bytes, allocator, 1);
    try bytes.appendSlice(allocator, response.items);
    const control = http3.ControlState{ .local_max_push_id = 3 };
    try std.testing.expect(try pushes.insert(
        .{ .ip4 = .loopback(443) },
        .{
            .stream_id = 15,
            .data = bytes.items,
            .fin = true,
        },
        control,
    ));
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try std.testing.expect((try pushes.next(table, 0, null)) == null);
    try pushes.registerPromise(1, 0);
    const event = (try pushes.next(table, 0, null)).?;
    try std.testing.expect(event.event.value == .head);
    var owned_event = event.event;
    owned_event.deinit(allocator);
}

test "HTTP/3 streaming request reset queue reuses consumed FIFO slots" {
    const allocator = std.testing.allocator;
    var requests = StreamingRequestSet.init(allocator, 3, 512, .{}, .request);
    defer requests.deinit();

    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    for ([_]u62{ 0, 4, 8 }) |stream_id| {
        try requests.prepareReset(from, stream_id, 0, false);
        requests.recordResetAssumeCapacity(
            from,
            stream_id,
            http3.ApplicationErrorCode.request_cancelled,
        );
    }
    try std.testing.expectEqual(@as(usize, 3), requests.resetCount());
    try std.testing.expectEqual(@as(usize, 3), requests.reset_index.count());
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestResetStream());
    try std.testing.expect(requests.contains(4));

    const first = requests.takeFirstReset() orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqual(@as(usize, 2), requests.resetCount());
    try std.testing.expectEqual(@as(usize, 2), requests.reset_index.count());
    try std.testing.expectEqual(@as(?u62, 4), requests.lowestResetStream());
    try std.testing.expect(!requests.contains(0));

    // The queue has consumed a head element. Adding a replacement must reuse
    // that FIFO space rather than reporting max-stream exhaustion.
    try requests.prepareReset(from, 12, 0, false);
    requests.recordResetAssumeCapacity(
        from,
        12,
        http3.ApplicationErrorCode.request_cancelled,
    );
    try std.testing.expectEqual(@as(usize, 3), requests.reset_index.count());
    try std.testing.expect(requests.contains(12));

    requests.remove(8);
    try std.testing.expect(!requests.contains(8));
    try std.testing.expectEqual(@as(usize, 2), requests.reset_index.count());
    try std.testing.expectEqual(@as(?u62, 4), requests.lowestResetStream());

    for ([_]u62{ 4, 12 }) |stream_id| {
        const reset = requests.takeFirstReset() orelse
            return error.TestUnexpectedResult;
        try std.testing.expectEqual(stream_id, reset.stream_id);
    }
    try std.testing.expect(requests.takeFirstReset() == null);
    try std.testing.expectEqual(@as(usize, 0), requests.resetCount());
    try std.testing.expectEqual(@as(usize, 0), requests.reset_index.count());
}

test "HTTP/3 streaming message set indexes active readers" {
    const allocator = std.testing.allocator;
    var responses = StreamingResponseSet.init(allocator, 3, 512, .{}, .response);
    defer responses.deinit();
    var buffered = ResponseStreamSet.init(allocator, 512, 3);
    defer buffered.deinit();

    const from: net.IpAddress = .{ .ip4 = .loopback(443) };
    try buffered.insert(from, .{
        .stream_id = 0,
        .data = "a",
    });
    try buffered.insert(from, .{
        .stream_id = 4,
        .data = "b",
    });
    try buffered.insert(from, .{
        .stream_id = 8,
        .data = "c",
    });
    _ = try responses.activateResponse(&buffered, 0);
    _ = try responses.activateResponse(&buffered, 4);
    _ = try responses.activateResponse(&buffered, 8);
    try std.testing.expect(responses.find(4) != null);
    try std.testing.expectEqual(@as(?u62, 0), responses.lowestEntryStream());

    responses.removeEntry(4);
    try std.testing.expect(responses.find(4) == null);
    // Removing the middle entry swaps another reader into that slot; the
    // stream-id index must follow it so later DATA, reset, or QPACK-cancel
    // checks can find the active reader without a linear scan.
    try std.testing.expect(responses.find(8) != null);
    try std.testing.expectEqual(@as(?u62, 0), responses.lowestEntryStream());

    const taken = responses.takeEntry(8) orelse return error.TestUnexpectedResult;
    var owned = taken;
    defer owned.deinit();
    try std.testing.expect(responses.find(8) == null);
    try std.testing.expectEqual(@as(usize, 1), responses.entry_index.count());
    try std.testing.expectEqual(@as(?u62, 0), responses.lowestEntryStream());
    responses.removeEntry(0);
    try std.testing.expectEqual(@as(usize, 0), responses.entry_index.count());
    try std.testing.expectEqual(@as(?u62, null), responses.lowestEntryStream());
    try std.testing.expect(!responses.contains(0));
    responses.remove(0);
    try std.testing.expect(responses.takeEntry(0) == null);
}

test "HTTP/3 buffered stream sets index reassembly entries" {
    const allocator = std.testing.allocator;
    const from: net.IpAddress = .{ .ip4 = .loopback(443) };

    var requests = RequestStreamSet.init(allocator, 512, 3);
    defer requests.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try requests.insert(from, .{
            .stream_id = stream_id,
            .data = "x",
        });
    }
    try std.testing.expect(requests.contains(4));
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestStream());
    var taken_request = requests.takeReceive(4) orelse
        return error.TestUnexpectedResult;
    taken_request.receive.deinit();
    try std.testing.expect(!requests.contains(4));
    try std.testing.expect(requests.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestStream());
    requests.remove(8);
    try std.testing.expect(!requests.contains(8));
    try std.testing.expectEqual(@as(?u62, 0), requests.lowestStream());
    requests.remove(0);
    try std.testing.expectEqual(@as(?u62, null), requests.lowestStream());
    try std.testing.expectEqual(@as(usize, 0), requests.entry_index.count());
    requests.remove(20);
    try std.testing.expect(requests.takeReceive(20) == null);
    var empty_table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer empty_table.deinit();
    try std.testing.expect(!try requests.requiresQpackCancellation(
        20,
        empty_table,
    ));

    try requests.insert(from, .{
        .stream_id = 12,
        .data = "target",
        .fin = true,
    });
    try requests.insert(from, .{
        .stream_id = 16,
        .data = "other",
        .fin = true,
    });
    var request_table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer request_table.deinit();
    const ready_request = (try requests.takeReady(request_table, 0)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(ready_request.bytes);
    try std.testing.expectEqual(@as(u62, 12), ready_request.stream_id);
    try std.testing.expectEqualStrings("target", ready_request.bytes);
    try std.testing.expect(!requests.contains(12));
    try std.testing.expect(requests.contains(16));

    var responses = ResponseStreamSet.init(allocator, 512, 3);
    defer responses.deinit();
    inline for (.{ @as(u62, 0), @as(u62, 4), @as(u62, 8) }) |stream_id| {
        try responses.insert(from, .{
            .stream_id = stream_id,
            .data = "x",
        });
    }
    var taken_response = responses.takeReceive(4) orelse
        return error.TestUnexpectedResult;
    taken_response.receive.deinit();
    try std.testing.expect(responses.entry_index.get(4) == null);
    try std.testing.expect(responses.entry_index.get(8) != null);
    responses.remove(8);
    try std.testing.expect(responses.entry_index.get(8) == null);
    try std.testing.expectEqual(@as(usize, 1), responses.entry_index.count());
    try std.testing.expect(bufferedHasResponse(responses, 0));
    try std.testing.expect(!bufferedHasResponse(responses, 4));
    try std.testing.expect(!bufferedHasResponse(responses, 8));
    try responses.recordReset(20, http3.ApplicationErrorCode.request_cancelled);
    try std.testing.expect(bufferedHasResponse(responses, 20));
    try std.testing.expectEqual(@as(usize, 1), responses.resetCount());
    _ = responses.takeReset(20);
    try std.testing.expect(!bufferedHasResponse(responses, 20));
    try std.testing.expectEqual(@as(usize, 0), responses.resetCount());
    try std.testing.expect(responses.takeReset(20) == null);

    try responses.recordReset(24, 0x24);
    try responses.recordReset(28, 0x28);
    try responses.recordReset(24, 0x42); // update without duplicating FIFO slot.
    try std.testing.expectEqual(@as(usize, 2), responses.resetCount());
    try std.testing.expectEqual(@as(u64, 0x28), responses.takeReset(28).?);
    try std.testing.expectEqual(@as(usize, 1), responses.resetCount());
    try responses.recordReset(28, 0x28);
    try std.testing.expectEqual(@as(usize, 2), responses.resetCount());
    try std.testing.expectEqual(@as(u62, 24), responses.firstReset().?.stream_id);
    try std.testing.expectEqual(@as(u64, 0x42), responses.firstReset().?.application_error_code);
    try std.testing.expectEqual(@as(u64, 0x42), responses.takeReset(24).?);
    try std.testing.expectEqual(@as(u62, 28), responses.firstReset().?.stream_id);
    try std.testing.expectEqual(@as(u64, 0x28), responses.takeReset(28).?);
    try std.testing.expect(responses.firstReset() == null);

    try responses.insert(from, .{
        .stream_id = 12,
        .data = "target",
        .fin = true,
    });
    try responses.insert(from, .{
        .stream_id = 16,
        .data = "other",
        .fin = true,
    });
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try std.testing.expectEqual(@as(?u62, 12), try responses.firstReadyStream(table, 0));
    const ready = (try responses.takeReady(12, table, 0)) orelse
        return error.TestUnexpectedResult;
    defer allocator.free(ready.bytes);
    try std.testing.expectEqual(@as(u62, 12), ready.stream_id);
    try std.testing.expectEqualStrings("target", ready.bytes);
    try std.testing.expect(responses.entry_index.get(12) == null);
    try std.testing.expect(responses.entry_index.get(16) != null);
    responses.remove(16);
    responses.remove(0);
    try std.testing.expectEqual(@as(usize, 0), responses.entry_index.count());
    try std.testing.expect((try responses.takeReady(16, table, 0)) == null);
    try std.testing.expect(responses.takeReceive(16) == null);
    try std.testing.expect(!try responses.requiresQpackCancellation(
        16,
        table,
    ));
}

test "HTTP/3 push cancellation queue reuses consumed FIFO slots" {
    const allocator = std.testing.allocator;
    var pushes = PushStreamSet.init(allocator, 4, 512, .{});
    defer pushes.deinit();
    try pushes.reservePromisesThrough(4);

    for ([_]struct { push_id: u64, stream_id: u64 }{
        .{ .push_id = 1, .stream_id = 15 },
        .{ .push_id = 2, .stream_id = 19 },
        .{ .push_id = 3, .stream_id = 23 },
    }) |item| {
        try pushes.registerPromise(item.push_id, 0);
        try pushes.entries.ensureUnusedCapacity(allocator, 1);
        const stream_slot = try pushes.stream_index.getOrPut(
            allocator,
            @as(u62, @intCast(item.stream_id)),
        );
        std.debug.assert(!stream_slot.found_existing);
        try pushes.push_index.ensureUnusedCapacity(allocator, 1);
        _ = pushes.appendEntryAssumeCapacity(.{
            .receive = quic.stream_state.RecvState.init(
                allocator,
                item.stream_id,
                512,
            ),
            .push_id = item.push_id,
        }, stream_slot.value_ptr);
        try pushes.observePeerCancellation(item.push_id);
    }
    try std.testing.expectEqual(
        @as(usize, 3),
        pushes.cancelledStreamCount(),
    );

    try std.testing.expectEqual(
        @as(u62, 15),
        pushes.takeCancelledStream() orelse return error.TestUnexpectedResult,
    );

    try pushes.registerPromise(4, 0);
    try pushes.entries.ensureUnusedCapacity(allocator, 1);
    const stream_slot = try pushes.stream_index.getOrPut(allocator, 27);
    std.debug.assert(!stream_slot.found_existing);
    try pushes.push_index.ensureUnusedCapacity(allocator, 1);
    _ = pushes.appendEntryAssumeCapacity(.{
        .receive = quic.stream_state.RecvState.init(allocator, 27, 512),
        .push_id = 4,
    }, stream_slot.value_ptr);
    try pushes.observePeerCancellation(4);

    for ([_]u62{ 19, 23, 27 }) |stream_id| {
        try std.testing.expectEqual(
            stream_id,
            pushes.takeCancelledStream() orelse return error.TestUnexpectedResult,
        );
    }
    try std.testing.expect(pushes.takeCancelledStream() == null);
    try std.testing.expectEqual(@as(usize, 0), pushes.cancelledStreamCount());
    try std.testing.expectEqual(@as(usize, 0), pushes.stream_index.count());
    try std.testing.expectEqual(@as(usize, 0), pushes.push_index.count());
    pushes.removeByStreamId(27);
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try std.testing.expect((try pushes.next(table, 0, 4)) == null);
    try std.testing.expectEqual(@as(usize, 4), pushes.promise_index.count());
}

test "HTTP/3 incremental reader retries blocked HEADERS transactionally" {
    const allocator = std.testing.allocator;
    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked-head", "ready-later");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "204" },
        .{ .name = "x-blocked-head", .value = "ready-later" },
    }, encoder_table);
    var frame: std.ArrayList(u8) = .empty;
    defer frame.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&frame, allocator);

    var decoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer decoder_table.deinit();
    try decoder_table.setCapacity(256);
    var reader = StreamingMessageReader.initResponse(
        allocator,
        0,
        512,
        .{},
    );
    defer reader.deinit();
    try reader.insert(.{
        .stream_id = 0,
        .data = frame.items,
        .fin = true,
    });
    const read_offset = reader.receive.read_offset;
    try std.testing.expectError(
        error.QpackBlocked,
        reader.next(decoder_table),
    );
    try std.testing.expectEqual(read_offset, reader.receive.read_offset);
    try std.testing.expect(reader.current_frame != null);

    _ = try decoder_table.insert("x-blocked-head", "ready-later");
    var head = (try reader.next(decoder_table)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    try std.testing.expectEqual(@as(u16, 204), head.head.response.status);
}

fn checkDynamicQpackWriterAllocationFailure(allocator: std.mem.Allocator) !void {
    var encoder = QpackEncodeState.init(allocator, 512, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(512);
    _ = try encoder.insertField("x-existing", "existing-value");
    encoder.known_received_count = encoder.table.insert_count;

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/transactional",
        .authority = "example.com",
        .headers = &.{
            .{ .name = "x-existing", .value = "existing-value" },
            .{ .name = "x-future", .value = "future-value" },
        },
        .body = "body",
        .trailers = &.{.{ .name = "x-trailer", .value = "trailer-value" }},
    }).writeDynamic(
        &encoded,
        allocator,
        .{},
        0,
        &encoder,
    );
}

test "HTTP/3 dynamic writer is leak-free under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackWriterAllocationFailure,
        .{},
    );
}

test "HTTP/3 runtime rejects closed critical streams" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .fin = true,
        .data = control_bytes.items,
    }));
    try std.testing.expect(control.peer_control_stream_id == null);

    try std.testing.expect(try applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .fin = false,
        .data = control_bytes.items,
    }));
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = control_bytes.items.len,
        .fin = true,
        .data = &.{},
    }));

    var qpack_encoder: std.ArrayList(u8) = .empty;
    defer qpack_encoder.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&qpack_encoder, allocator);

    var qpack_control = http3.ControlState{};
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .fin = true,
        .data = qpack_encoder.items,
    }));

    try std.testing.expect(try applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = 0,
        .fin = false,
        .data = qpack_encoder.items,
    }));
    try std.testing.expectError(error.ClosedCriticalStream, applyControlStreamFrame(&qpack_control, allocator, .{
        .stream_id = client_qpack_encoder_stream_id,
        .offset = qpack_encoder.items.len,
        .fin = true,
        .data = &.{},
    }));
}

test "HTTP/3 runtime rejects critical stream reset requests" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    try std.testing.expect(try applyControlStreamFrame(&control, allocator, .{
        .stream_id = client_control_stream_id,
        .offset = 0,
        .data = control_bytes.items,
    }));

    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(control, .{ .reset_stream = .{
        .stream_id = client_control_stream_id,
        .application_error_code = 0,
        .final_size = control_bytes.items.len,
    } }, .server));

    try rejectCriticalStreamClosureFrame(control, .{ .reset_stream = .{
        .stream_id = 0,
        .application_error_code = 0,
        .final_size = 0,
    } }, .server);

    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = client_qpack_encoder_stream_id,
        .application_error_code = 0,
    } }, .client));
    try std.testing.expectError(error.ClosedCriticalStream, rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = server_control_stream_id,
        .application_error_code = 0,
    } }, .server));

    try rejectCriticalStreamClosureFrame(.{}, .{ .stop_sending = .{
        .stream_id = 0,
        .application_error_code = 0,
    } }, .client);
}

test "HTTP/3 protected runtime exchanges request and response over QUIC 1-RTT" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x01 };
    const server_cid = [_]u8{ 0xca, 0xfe, 0x00, 0x02 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xa1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xa2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_settings = .{ .h3_datagram = true },
        .max_stream_frame_data = 7,
    });
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/protected-h3", request.request.path);
            try std.testing.expectEqualStrings("ping split across stream frames", request.request.body);
            try std.testing.expect(server_ptr.control.settings.received);
            try std.testing.expectEqual(@as(u64, 4), server_ptr.control.settings.peer.webtransport_max_sessions);
            try std.testing.expectEqual(@as(?u64, client_control_stream_id), server_ptr.control.peer_control_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), server_ptr.control.peer_qpack_encoder_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_decoder_stream_id), server_ptr.control.peer_qpack_decoder_stream_id);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong",
            });
            try std.testing.expect(server_ptr.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .webtransport_max_sessions = 4 },
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/protected-h3",
        .authority = "localhost",
        .body = "ping split across stream frames",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(?u64, server_control_stream_id), client.control.peer_control_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_encoder_stream_id), client.control.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_decoder_stream_id), client.control.peer_qpack_decoder_stream_id);

    client.control.peer_goaway_id = client.next_stream_id;
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-goaway",
    }));
}

test "HTTP/3 protected server retains interleaved request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x91, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x92, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x93} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x94} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/first",
        .authority = "localhost",
        .body = "first-body",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/second",
        .authority = "localhost",
        .body = "second-body",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;

    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .offset = 0,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = 4,
            .offset = 0,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &frames,
        frames.len,
        &client.protected_send,
    );

    // The whole packet is consumed before returning. Ready streams retain
    // deterministic creation order, and stream 4 remains queued for the next
    // application receive even though it completed earlier in the packet.
    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 0), first.stream_id);
    try std.testing.expectEqualStrings("/first", first.request.path);
    try std.testing.expectEqualStrings("first-body", first.request.body);
    try std.testing.expectEqual(@as(usize, 1), server.request_streams.entries.items.len);

    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try std.testing.expectEqual(@as(u62, 4), second.stream_id);
    try std.testing.expectEqualStrings("/second", second.request.path);
    try std.testing.expectEqualStrings("second-body", second.request.body);
    try std.testing.expectEqual(@as(usize, 0), server.request_streams.entries.items.len);
}

test "HTTP/3 protected server drains GRO request batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x89, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x8a, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8b} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8c} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer client_endpoint.deinit();
    if (!server.quic_server.endpoint.groReceiveEnabled() or
        !client_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    }).write(&first, allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    }).write(&second, allocator);
    try std.testing.expectEqual(first.items.len, second.items.len);

    const frames0 = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .data = first.items,
        .fin = true,
    } }};
    const frames1 = [_]quic.Frame{.{ .stream = .{
        .stream_id = 4,
        .data = second.items,
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &frames0, &frames1 };
    try quic.one_rtt.sendFramesBatch(
        &client_endpoint,
        server.address(),
        client_keys,
        .{
            .destination_connection_id = &server_cid,
            .first_packet_number = 0,
            .packets = &packets,
        },
    );

    var first_request = try server.receiveRequest();
    defer first_request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/gro-one",
        first_request.request.path,
    );
    try std.testing.expect(server.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        server.receive_packets.batch.?.packets.len -
            server.receive_packets.batch.?.next_index,
    );
    // The second packet was decrypted with the same GRO receive but has not
    // entered HTTP/3 stream storage before the application asks for it.
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_streams.entries.items.len,
    );

    var second_request = try server.receiveRequest();
    defer second_request.deinit(allocator);
    try std.testing.expectEqualStrings(
        "/gro-two",
        second_request.request.path,
    );
    try std.testing.expectEqual(
        @as(u64, 2),
        server.expected_packet_number,
    );
}

test "HTTP/3 protected client drains GRO response batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x8d, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x8e, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8f} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x90} ** quic.protection.secret_len,
    );
    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 1400 },
    );
    defer server_endpoint.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server_endpoint.address(),
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();
    if (!client.quic_client.endpoint.groReceiveEnabled() or
        !server_endpoint.gsoSendEnabled())
    {
        return error.SkipZigTest;
    }

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    });
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "one",
    }).write(&first, allocator);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "two",
    }).write(&second, allocator);
    try std.testing.expectEqual(first.items.len, second.items.len);

    const frames0 = [_]quic.Frame{.{ .stream = .{
        .stream_id = first_id,
        .data = first.items,
        .fin = true,
    } }};
    const frames1 = [_]quic.Frame{.{ .stream = .{
        .stream_id = second_id,
        .data = second.items,
        .fin = true,
    } }};
    const packets = [_][]const quic.Frame{ &frames0, &frames1 };
    try quic.one_rtt.sendFramesBatch(
        &server_endpoint,
        client.quic_client.address(),
        server_keys,
        .{
            .destination_connection_id = &client_cid,
            .first_packet_number = 0,
            .packets = &packets,
        },
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(first_id, first_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "one",
        first_event.response.value.response.body,
    );
    try std.testing.expect(client.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.receive_packets.batch.?.packets.len -
            client.receive_packets.batch.?.next_index,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.response_streams.entries.items.len,
    );

    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(second_id, second_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "two",
        second_event.response.value.response.body,
    );
}

test "HTTP/3 protected server bounds concurrent request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x95, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x96, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x97} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x98} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
            .max_concurrent_request_streams = 1,
        },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const frames = [_]quic.Frame{
        .{ .stream = .{ .stream_id = 0, .data = "partial-zero" } },
        .{ .stream = .{ .stream_id = 4, .data = "partial-four" } },
    };
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &frames,
        frames.len,
        &client.protected_send,
    );
    try std.testing.expectError(error.ExcessiveLoad, server.receiveRequest());
    try std.testing.expectEqual(@as(usize, 1), server.request_streams.entries.items.len);
}

test "HTTP/3 runtime rejects blocked-stream limit above retention bound" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xb6, 0x10, 0x20, 0x30 };
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    try std.testing.expectError(
        error.QpackDynamicTableUnsupported,
        ProtectedClient.connect(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            .{ .ip4 = .loopback(9) },
            .{
                .max_concurrent_request_streams = 1,
            },
            .{
                .receive_keys = keys,
                .send_keys = keys,
                .local_connection_id = &client_cid,
                .peer_connection_id = &server_cid,
                .local_settings = .{
                    .qpack_blocked_streams = 2,
                },
            },
        ),
    );
}

test "HTTP/3 protected server surfaces request reset and clears reassembly" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x99, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x9a, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9b} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9c} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .data = "partial request",
        } },
        .{ .reset_stream = .{
            .stream_id = 0,
            .application_error_code = http3.ApplicationErrorCode.request_cancelled,
            .final_size = "partial request".len,
        } },
    };
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &frames,
        frames.len,
        &client.protected_send,
    );
    try std.testing.expectError(error.RequestCancelled, server.receiveRequest());
    try std.testing.expectEqual(@as(usize, 0), server.request_streams.entries.items.len);
}

test "HTTP/3 protected server performs two-phase graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0x9d, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0x9e, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0x9f} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa0} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/drain",
        .authority = "localhost",
    }).write(&request_bytes, allocator);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        request_bytes.items,
        request_bytes.items.len,
        true,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try server.initiateShutdown(request.from);
    try std.testing.expectEqual(
        ShutdownState.initial_goaway,
        server.request_lifecycle.shutdown_state,
    );
    try std.testing.expect(!server.drainComplete());
    try server.completeShutdown(request.from);
    try std.testing.expectEqual(
        ShutdownState.final_goaway,
        server.request_lifecycle.shutdown_state,
    );
    try std.testing.expectEqual(@as(?u64, 4), server.control.local_goaway_id);
    try std.testing.expect(!server.drainComplete());

    try server.sendResponse(request.from, request.stream_id, .{
        .status = 204,
    });
    try std.testing.expect(server.drainComplete());

    // Process SETTINGS plus both GOAWAY frames before opening another stream.
    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 4)
    {
        var packet = try quic.one_rtt.receive(
            &client.quic_client.endpoint,
            server_keys,
            client_cid.len,
            client.expected_packet_number,
            8,
        );
        defer packet.deinit(allocator);
        client.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            _ = try applyControlStreamFrameForRole(
                &client.control,
                allocator,
                frame.stream,
                .client,
            );
        }
    }
    client.next_stream_id = 4;
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-drain",
    }));
}

test "HTTP/3 protected client sends persistent priority updates" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xa2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendPriorityUpdate(0, .{ .urgency = 1 });
    try client.sendPriorityUpdate(0, .{
        .urgency = 6,
        .incremental = true,
    });
    try std.testing.expectError(
        error.UnexpectedFrame,
        client.sendPriorityUpdate(4, .{}),
    );

    while (server.control.latest_priority_update == null or
        server.control.latest_priority_update.?.priority().urgency != 6)
    {
        var packet = try quic.one_rtt.receive(
            &server.quic_server.endpoint,
            client_keys,
            server_cid.len,
            server.expected_packet_number,
            8,
        );
        defer packet.deinit(allocator);
        server.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            _ = try applyControlStreamFrameForRole(
                &server.control,
                allocator,
                frame.stream,
                .server,
            );
        }
    }
    const update = server.control.latest_priority_update.?;
    try std.testing.expectEqual(@as(u64, 0), update.prioritized_element_id);
    try std.testing.expectEqual(@as(u3, 6), update.priority().urgency);
    try std.testing.expect(update.priority().incremental);
    try std.testing.expect(client.control_send.next_offset > 1);
}

test "HTTP/3 protected client advertises and cancels server push IDs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xc6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(4);
    try client.sendMaxPushId(8);
    try std.testing.expectError(
        error.MaxPushIdReduced,
        client.sendMaxPushId(7),
    );
    try std.testing.expectError(error.PushIdExceeded, client.cancelPush(9));
    try client.push_streams.registerPromise(7, 0);
    try client.push_streams.registerPromise(3, 0);
    try client.cancelPush(7);
    try client.cancelPush(3);

    while (server.control.peer_max_push_id != 8 or
        !server.control.pushCancelled(7) or
        !server.control.pushCancelled(3))
    {
        var packet = try quic.one_rtt.receive(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            server.expected_packet_number,
            server.config.max_frames_per_packet,
        );
        defer packet.deinit(allocator);
        server.expected_packet_number = packet.packet.packet_number + 1;
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            if (try applyControlStreamFrameForRole(
                &server.control,
                allocator,
                frame.stream,
                .server,
            )) {
                try configureQpackEncoderFromPeerSettings(
                    server.control,
                    &server.qpack_encode,
                );
            }
        }
    }
    try std.testing.expectEqual(
        @as(?u64, 8),
        server.control.peer_max_push_id,
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        server.control.peer_cancelled_push_ids.items.len,
    );
}

test "HTTP/3 protected client retains interleaved responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xa6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xa8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    try std.testing.expectEqual(@as(u62, 0), first_id);
    try std.testing.expectEqual(@as(u62, 4), second_id);

    var first_request = try server.receiveRequest();
    defer first_request.deinit(allocator);
    var second_request = try server.receiveRequest();
    defer second_request.deinit(allocator);
    try std.testing.expectEqual(first_id, first_request.stream_id);
    try std.testing.expectEqual(second_id, second_request.stream_id);

    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "first-response",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "second-response",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = first_id,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = second_id,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = first_id,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        frames[0..2],
        2,
        &server.protected_send,
    );
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        frames[2..],
        1,
        &server.protected_send,
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(
        second_id,
        first_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "second-response",
        first_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.request_lifecycle.outstanding.items.len,
    );
    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        first_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "first-response",
        second_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.outstanding.items.len,
    );
    try std.testing.expectError(
        error.UnexpectedStream,
        client.receiveResponse(first_id),
    );
}

test "HTTP/3 protected client polls interleaved streaming responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xba, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xbc} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const first_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/early",
            .authority = "localhost",
        },
        null,
    );
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/reset",
        .authority = "localhost",
    });
    try std.testing.expectEqual(
        @as(usize, 1),
        client.outbound_bodies.entries.items.len,
    );

    var first_response: std.ArrayList(u8) = .empty;
    defer first_response.deinit(allocator);
    try (http3.Response{
        .status = 200,
        .body = "early",
    }).write(&first_response, allocator);
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = first_id,
            .data = first_response.items,
            .fin = true,
        } },
        .{ .reset_stream = .{
            .stream_id = second_id,
            .application_error_code = http3.ApplicationErrorCode.request_rejected,
            .final_size = 0,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        1,
        &server.protected_send,
    );

    var saw_head = false;
    var saw_body = false;
    var saw_finished = false;
    var saw_reset = false;
    var read_buf: [16]u8 = undefined;
    while (client.request_lifecycle.outstanding.items.len != 0) {
        var event = try client.receiveNextResponseEvent();
        defer event.deinit(allocator);
        switch (event) {
            .reset => |reset| {
                try std.testing.expectEqual(second_id, reset.stream_id);
                try std.testing.expectEqual(
                    @as(u64, http3.ApplicationErrorCode.request_rejected),
                    reset.application_error_code,
                );
                saw_reset = true;
            },
            .message => |message| {
                try std.testing.expectEqual(first_id, message.stream_id);
                switch (message.value) {
                    .head => saw_head = true,
                    .push_promise => return error.TestUnexpectedResult,
                    .data_available => {
                        const read = try client.readResponseData(
                            first_id,
                            &read_buf,
                        );
                        try std.testing.expectEqualStrings(
                            "early",
                            read_buf[0..read],
                        );
                        saw_body = true;
                    },
                    .trailers => return error.TestUnexpectedResult,
                    .finished => saw_finished = true,
                }
            },
        }
    }
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_body);
    try std.testing.expect(saw_finished);
    try std.testing.expect(saw_reset);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.entries.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entries.items.len,
    );
}

test "HTTP/3 protected client streams owned push promise events" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xca, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcc} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .qpack_max_table_capacity = 256 },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(3);
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/index",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqual(stream_id, request.stream_id);

    var response_block: std.ArrayList(u8) = .empty;
    defer response_block.deinit(allocator);
    var table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer table.deinit();
    try table.setCapacity(256);
    _ = try table.insert("x-promise-kind", "dynamic-asset");
    try http3.Qpack.encodeDynamicBlock(
        &response_block,
        allocator,
        &.{.{ .name = ":status", .value = "200" }},
        table,
    );
    var promise_block: std.ArrayList(u8) = .empty;
    defer promise_block.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&promise_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-promise-kind", .value = "dynamic-asset" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &response_bytes,
        allocator,
        3,
        promise_block.items,
    );
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = response_block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);

    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder_bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-promise-kind",
            .value = "dynamic-asset",
        } },
    );
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = server_qpack_encoder_stream_id,
            .data = encoder_bytes.items,
        } },
        .{ .stream = .{
            .stream_id = stream_id,
            .data = response_bytes.items,
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    var promise = (try client.receiveResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 3), promise.push_promise.push_id);
    try std.testing.expectEqualStrings(
        "/asset.css",
        promise.push_promise.request.path,
    );
    try std.testing.expectEqualStrings(
        "example.test",
        promise.push_promise.request.authority.?,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        promise.push_promise.request.qpack_section_acknowledgments,
    );
    try std.testing.expectEqualStrings(
        "dynamic-asset",
        promise.push_promise.request.headers[4].value,
    );

    // The event path must flush both feedback instructions generated by this
    // packet: the insert-count increment and the promise's section ack.
    var feedback_packet = try server.receive_packets.take(
        &server.quic_server.endpoint,
        server.config.receive_keys,
        server.config.local_connection_id.len,
        &server.expected_packet_number,
        server.config.max_frames_per_packet,
    );
    defer feedback_packet.deinit(allocator);
    var feedback_bytes: std.ArrayList(u8) = .empty;
    defer feedback_bytes.deinit(allocator);
    for (feedback_packet.frames) |frame| {
        if (frame != .stream or
            frame.stream.stream_id != client_qpack_decoder_stream_id)
        {
            continue;
        }
        try feedback_bytes.appendSlice(allocator, frame.stream.data);
    }
    const increment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items,
    );
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[increment.consumed..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        stream_id,
        acknowledgment.instruction.section_acknowledgment,
    );

    var head = (try client.receiveResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer head.deinit(allocator);
    try std.testing.expect(head == .head);
    var finished = (try client.receiveResponseEvent(stream_id)) orelse
        return error.TestUnexpectedResult;
    defer finished.deinit(allocator);
    try std.testing.expect(finished == .finished);
}

test "HTTP/3 protected client streams promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xd1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(3);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/index",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var promise_fields: std.ArrayList(u8) = .empty;
    defer promise_fields.deinit(allocator);
    var literal_table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer literal_table.deinit();
    try http3.Qpack.encodeDynamicBlock(
        &promise_fields,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/asset.css" },
            .{ .name = ":authority", .value = "example.test" },
        },
        literal_table,
    );
    var request_response: std.ArrayList(u8) = .empty;
    defer request_response.deinit(allocator);
    try http3.writePushPromiseFrame(
        &request_response,
        allocator,
        3,
        promise_fields.items,
    );
    try (http3.Response{ .status = 204 }).write(
        &request_response,
        allocator,
    );

    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 3);
    try (http3.Response{
        .status = 200,
        .body = "asset",
    }).write(&push_bytes, allocator);

    // Deliver the push stream first to exercise cross-stream reordering. It is
    // retained but cannot surface until PUSH_PROMISE is decoded below.
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 15,
            .data = push_bytes.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = request_stream_id,
            .data = request_response.items,
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        server.config.max_frames_per_packet,
        &server.protected_send,
    );

    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 3), promise.push_promise.push_id);

    var push_head = try client.receivePushEvent();
    defer push_head.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), push_head.push_id);
    try std.testing.expectEqual(
        request_stream_id,
        push_head.request_stream_id,
    );
    try std.testing.expectEqual(@as(u62, 15), push_head.stream_id);
    try std.testing.expect(push_head.value == .head);
    try std.testing.expectEqual(
        @as(u16, 200),
        push_head.value.head.response.status,
    );
    var data = try client.receivePushEvent();
    defer data.deinit(allocator);
    try std.testing.expect(data.value == .data_available);
    var body: [8]u8 = undefined;
    try std.testing.expectEqual(
        @as(usize, 5),
        try client.readPushData(3, &body),
    );
    try std.testing.expectEqualStrings("asset", body[0..5]);
    var finished = try client.receivePushEvent();
    defer finished.deinit(allocator);
    try std.testing.expect(finished.value == .finished);
    try std.testing.expect(client.push_streams.findByPushId(3) == null);
}

test "HTTP/3 protected client sends priority update for promised push" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xb5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xb6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();
    try server.peer_promised_push_ids.append(allocator, 2);
    try client.sendMaxPushId(2);
    try client.push_streams.registerPromise(2, 0);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendPushPriorityUpdate(1, .{}),
    );
    try client.sendPushPriorityUpdate(2, .{
        .urgency = 1,
        .incremental = true,
    });
    while (server.control.pushPriorityUpdate(2) == null) {
        var packet = try server.receive_packets.take(
            &server.quic_server.endpoint,
            server.config.receive_keys,
            server.config.local_connection_id.len,
            &server.expected_packet_number,
            server.config.max_frames_per_packet,
        );
        defer packet.deinit(allocator);
        for (packet.frames) |frame| {
            if (frame != .stream) continue;
            _ = try applyControlStreamFrameForRole(
                &server.control,
                allocator,
                frame.stream,
                .server,
            );
        }
    }
    const update = server.control.pushPriorityUpdate(2).?;
    try std.testing.expectEqual(@as(u3, 1), update.priority().urgency);
    try std.testing.expect(update.priority().incremental);
}

test "HTTP/3 protected client aggregates promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xe1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xe2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(1);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);

    var fields: std.ArrayList(u8) = .empty;
    defer fields.deinit(allocator);
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    try http3.Qpack.encodeDynamicBlock(&fields, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/app.js" },
        .{ .name = ":authority", .value = "example.test" },
    }, table);
    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try http3.writePushPromiseFrame(
        &response_bytes,
        allocator,
        1,
        fields.items,
    );
    try (http3.Response{ .status = 204 }).write(
        &response_bytes,
        allocator,
    );
    var push_bytes: std.ArrayList(u8) = .empty;
    defer push_bytes.deinit(allocator);
    try quic.varint.encode(
        &push_bytes,
        allocator,
        @intFromEnum(http3.StreamType.push),
    );
    try quic.varint.encode(&push_bytes, allocator, 1);
    try (http3.Response{
        .status = 200,
        .body = "javascript",
        .trailers = &.{.{ .name = "x-push", .value = "done" }},
    }).write(&push_bytes, allocator);
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = request_stream_id,
            .data = response_bytes.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 15,
            .data = push_bytes.items,
            .fin = true,
        } },
    };
    try sendProtectedFrames(
        &server.quic_server.endpoint,
        client.quic_client.address(),
        server.config.send_keys,
        server.config.peer_connection_id,
        &server.next_packet_number,
        &frames,
        server.config.max_frames_per_packet,
        &server.protected_send,
    );
    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    var pushed = try client.receivePush();
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqual(request_stream_id, pushed.request_stream_id);
    try std.testing.expectEqual(@as(u16, 200), pushed.response.status);
    try std.testing.expectEqualStrings("javascript", pushed.response.body);
    try std.testing.expectEqualStrings(
        "done",
        pushed.response.trailers[0].value,
    );
}

test "HTTP/3 protected server sends promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const client_cid = [_]u8{ 0xf5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xf6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xf8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(2);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "example.test",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    const push_stream_id = try server.sendResponseWithPush(
        request.from,
        request.stream_id,
        .{ .status = 204 },
        .{
            .push_id = 2,
            .request = .{
                .method = "GET",
                .path = "/style.css",
                .authority = "example.test",
            },
            .response = .{
                .status = 200,
                .body = "css",
            },
        },
    );
    try std.testing.expectEqual(
        first_server_push_stream_id,
        push_stream_id,
    );
    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    try std.testing.expectEqual(@as(u64, 2), promise.push_promise.push_id);
    try std.testing.expectEqualStrings(
        "/style.css",
        promise.push_promise.request.path,
    );
    var parent_head = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer parent_head.deinit(allocator);
    try std.testing.expect(parent_head == .head);
    try std.testing.expectEqual(
        @as(u16, 204),
        parent_head.head.response.status,
    );
    var pushed = try client.receivePush();
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(push_stream_id, pushed.stream_id);
    try std.testing.expectEqualStrings("css", pushed.response.body);
}

test "HTTP/3 protected client reports next response reset with stream id" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xa9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xaa, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xab} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xac} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/reset",
        .authority = "localhost",
    });
    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try server.rejectRequest(request.from, stream_id);

    var event = try client.receiveNextResponse();
    defer event.deinit(allocator);
    try std.testing.expect(event == .reset);
    try std.testing.expectEqual(stream_id, event.reset.stream_id);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.request_rejected),
        event.reset.application_error_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.outstanding.items.len,
    );
}

test "HTTP/3 protected runtime streams request and response DATA chunks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xb2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xb4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_frame_data = 5,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(
                server_ptr.quic_server.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "request-chunks",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            try server_ptr.startResponse(
                request.from,
                request.stream_id,
                .{ .status = 200 },
                "response-chunks".len,
            );
            try server_ptr.sendResponseBody(
                request.from,
                request.stream_id,
                "response-",
                false,
            );
            try std.testing.expectError(
                error.InvalidContentLength,
                server_ptr.sendResponseBody(
                    request.from,
                    request.stream_id,
                    "too-long-chunk",
                    true,
                ),
            );
            try server_ptr.sendResponseBody(
                request.from,
                request.stream_id,
                "chunks",
                false,
            );
            try server_ptr.finishResponseTrailers(
                request.from,
                request.stream_id,
                &.{.{ .name = "x-response-checksum", .value = "ok" }},
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                server_ptr.outbound_bodies.entries.items.len,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_frame_data = 5,
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/stream-body",
            .authority = "localhost",
        },
        "request-chunks".len,
    );
    try client.sendRequestBody(stream_id, "request-", false);
    try std.testing.expectError(
        error.InvalidContentLength,
        client.sendRequestBody(stream_id, "short", true),
    );
    try client.sendRequestBody(stream_id, "chunks", false);
    try client.finishRequestTrailers(
        stream_id,
        &.{.{ .name = "x-request-checksum", .value = "ok" }},
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.entries.items.len,
    );
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings(
        "response-chunks",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );
}

test "HTTP/3 protected server streams interleaved requests through small windows" {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer std.testing.expect(gpa.deinit() == .ok) catch @panic("leak");
    const allocator = gpa.allocator();
    const body_len: usize = 64 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xd1, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd2, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd4} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = .{
                .qpack_max_table_capacity = 512,
                .qpack_blocked_streams = 2,
            },
            .max_stream_buffer = 512,
            .max_stream_frame_data = 480,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{
                .qpack_max_table_capacity = 512,
                .qpack_blocked_streams = 2,
            },
            .max_stream_buffer = 512,
            .max_stream_frame_data = 480,
        },
    );
    defer client.deinit();

    // Two exchanges are required by the non-blocking encoder policy: the first
    // advertises SETTINGS and queues inserts, while feedback received during
    // the second unlocks dynamic references for the streamed requests below.
    for (0..2) |_| {
        const warmup_id = try client.sendRequest(.{
            .method = "POST",
            .path = "/stream-request",
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-request-kind",
                .value = "bounded-protected",
            }},
            .body = "warmup",
            .trailers = &.{.{
                .name = "x-request-finished",
                .value = "yes",
            }},
        });
        var warmup = try server.receiveRequest();
        defer warmup.deinit(allocator);
        try std.testing.expectEqual(warmup_id, warmup.stream_id);
        try server.sendResponse(warmup.from, warmup.stream_id, .{
            .status = 204,
        });
        var warmup_response = try client.receiveResponse(warmup_id);
        defer warmup_response.deinit(allocator);
    }

    const first_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/stream-request",
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-request-kind",
                .value = "bounded-protected",
            }},
        },
        body_len,
    );
    try client.sendRequestBody(first_id, &([_]u8{0xa5} ** 400), false);
    const second_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/stream-request",
            .authority = "localhost",
            .headers = &.{.{
                .name = "x-request-kind",
                .value = "bounded-protected",
            }},
        },
        6,
    );
    try client.sendRequestBody(second_id, "second", false);
    try client.finishRequestTrailers(second_id, &.{.{
        .name = "x-request-finished",
        .value = "yes",
    }});

    const Sender = struct {
        client: *ProtectedClient,
        stream_id: u62,
        err: ?anyerror = null,

        fn run(sender: *@This()) void {
            sender.runFallible() catch |err| {
                sender.err = err;
            };
        }

        fn runFallible(sender: *@This()) !void {
            var chunk: [400]u8 = undefined;
            for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
            var remaining = body_len - 400;
            while (remaining != 0) {
                const count = @min(chunk.len, remaining);
                try sender.client.sendRequestBody(
                    sender.stream_id,
                    chunk[0..count],
                    false,
                );
                remaining -= count;
            }
            try sender.client.finishRequestTrailers(sender.stream_id, &.{.{
                .name = "x-request-finished",
                .value = "yes",
            }});
        }
    };
    var sender = Sender{ .client = &client, .stream_id = first_id };
    const sender_thread = try std.Thread.spawn(.{}, Sender.run, .{&sender});
    var sender_joined = false;
    defer if (!sender_joined) sender_thread.join();

    var heads: usize = 0;
    var dynamic_heads: usize = 0;
    var trailers: usize = 0;
    var dynamic_trailers: usize = 0;
    var finished: usize = 0;
    var first_read: usize = 0;
    var second_read: usize = 0;
    var first_checksum: u64 = 0;
    var second_checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (finished != 2) {
        var event = try server.receiveRequestEvent();
        defer event.deinit(allocator);
        try std.testing.expect(event == .message);
        const message = &event.message;
        switch (message.value) {
            .head => |head| {
                try std.testing.expect(head == .request);
                if (head.request.qpack_section_acknowledgments != 0) {
                    dynamic_heads += 1;
                }
                heads += 1;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = server.streaming_requests.find(
                        message.stream_id,
                    ).?;
                    if (active.reader.current_frame == null) break;
                    const read = try server.readRequestData(
                        message.stream_id,
                        &read_buf,
                    );
                    if (read == 0) break;
                    if (message.stream_id == first_id) {
                        for (read_buf[0..read]) |byte| {
                            first_checksum +%= byte;
                        }
                        first_read += read;
                    } else {
                        try std.testing.expectEqual(second_id, message.stream_id);
                        for (read_buf[0..read]) |byte| {
                            second_checksum +%= byte;
                        }
                        second_read += read;
                    }
                }
                const active = server.streaming_requests.find(
                    message.stream_id,
                ).?;
                try std.testing.expect(
                    active.reader.receive.buffer.items.len <= 512,
                );
            },
            .trailers => |decoded| {
                try std.testing.expectEqualStrings(
                    "yes",
                    decoded.fields[0].value,
                );
                if (decoded.qpack_section_acknowledgments != 0) {
                    dynamic_trailers += 1;
                }
                trailers += 1;
            },
            .finished => finished += 1,
        }
    }
    sender_thread.join();
    sender_joined = true;
    if (sender.err) |err| return err;

    var expected_first: u64 = 400 * 0xa5;
    var chunk: [400]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
    const remaining = body_len - 400;
    var chunk_sum: u64 = 0;
    for (chunk) |byte| chunk_sum += byte;
    expected_first += chunk_sum * (remaining / chunk.len);
    for (chunk[0 .. remaining % chunk.len]) |byte| expected_first += byte;
    var expected_second: u64 = 0;
    for ("second") |byte| expected_second += byte;

    try std.testing.expectEqual(@as(usize, 2), heads);
    try std.testing.expect(dynamic_heads != 0);
    try std.testing.expectEqual(@as(usize, 2), trailers);
    try std.testing.expect(dynamic_trailers != 0);
    try std.testing.expectEqual(body_len, first_read);
    try std.testing.expectEqual(@as(usize, 6), second_read);
    try std.testing.expectEqual(expected_first, first_checksum);
    try std.testing.expectEqual(expected_second, second_checksum);
    try std.testing.expectEqual(
        @as(usize, 0),
        server.streaming_requests.retainedCount(),
    );
}

test "HTTP/3 protected server reports streamed request reset with stream id" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xd5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_buffer = 512,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_buffer = 512,
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/cancel-stream",
            .authority = "localhost",
        },
        null,
    );
    var event = try server.receiveRequestEvent();
    defer event.deinit(allocator);
    try std.testing.expect(event == .message);
    try std.testing.expect(event.message.value == .head);
    try std.testing.expectEqual(stream_id, event.message.stream_id);

    try client.cancelRequest(
        stream_id,
        http3.ApplicationErrorCode.request_cancelled,
    );
    var reset = try server.receiveRequestEvent();
    defer reset.deinit(allocator);
    try std.testing.expect(reset == .reset);
    try std.testing.expectEqual(stream_id, reset.reset.stream_id);
    try std.testing.expectEqual(
        @as(u64, http3.ApplicationErrorCode.request_cancelled),
        reset.reset.application_error_code,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.streaming_requests.retainedCount(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        server.request_lifecycle.active_streams.items.len,
    );
}

test "HTTP/3 protected client streams large response through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 128 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc9, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xca, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcb} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xcc} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .max_stream_frame_data = 480,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(
                server_ptr.quic_server.endpoint.allocator,
            );
            try server_ptr.startResponse(
                request.from,
                request.stream_id,
                .{ .status = 200 },
                body_len,
            );
            var chunk: [400]u8 = undefined;
            for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
            var remaining = body_len;
            while (remaining != 0) {
                const count = @min(chunk.len, remaining);
                try server_ptr.sendResponseBody(
                    request.from,
                    request.stream_id,
                    chunk[0..count],
                    false,
                );
                remaining -= count;
            }
            try server_ptr.finishResponseTrailers(
                request.from,
                request.stream_id,
                &.{.{ .name = "x-stream-finished", .value = "yes" }},
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{
            .quic = .{
                .max_datagram_size = 4096,
                .max_frames_per_datagram = 8,
            },
            .max_stream_buffer = 512,
        },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_buffer = 512,
            .max_stream_frame_data = 480,
        },
    );
    defer client.deinit();

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/large-stream",
        .authority = "localhost",
    });
    var saw_head = false;
    var saw_trailers = false;
    var body_read: usize = 0;
    var checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (client.request_lifecycle.contains(stream_id)) {
        const event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expectEqual(@as(u16, 200), head.response.status);
                try std.testing.expectEqual(
                    @as(?usize, body_len),
                    head.response.content_length,
                );
                saw_head = true;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = client.streaming_responses.find(stream_id).?;
                    if (active.reader.current_frame == null) break;
                    const read = try client.readResponseData(
                        stream_id,
                        &read_buf,
                    );
                    if (read == 0) break;
                    for (read_buf[0..read]) |byte| checksum +%= byte;
                    body_read += read;
                }
                const active = client.streaming_responses.find(stream_id).?;
                try std.testing.expect(
                    active.reader.receive.buffer.items.len <= 512,
                );
            },
            .trailers => |trailers| {
                try std.testing.expectEqualStrings(
                    "yes",
                    trailers.fields[0].value,
                );
                saw_trailers = true;
            },
            .finished => {},
        }
    }
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_trailers);
    try std.testing.expectEqual(body_len, body_read);
    try std.testing.expect(checksum != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entries.items.len,
    );
}

test "HTTP/3 protected runtime reuses acknowledged dynamic QPACK entries" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc1, 0x11, 0x22, 0x33 };
    const server_cid = [_]u8{ 0xc2, 0x11, 0x22, 0x33 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc3} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xc4} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = .{ .qpack_max_table_capacity = 512 },
            // Exercise instruction fragmentation and the persistent encoder
            // stream offset rather than relying on one-frame instructions.
            .max_stream_frame_data = 5,
            .max_frames_per_packet = 2,
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *ProtectedServer) !void {
            for (0..3) |exchange| {
                var request = try server_ptr.receiveRequest();
                defer request.deinit(
                    server_ptr.quic_server.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/protected-dynamic",
                    request.request.path,
                );
                var repeated_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(u8, header.name, "x-runtime-request")) {
                        repeated_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "repeated-request-value",
                    repeated_value orelse return error.TestUnexpectedResult,
                );

                if (exchange == 1) {
                    // Request two carries inserts but remains literal because
                    // SETTINGS_QPACK_BLOCKED_STREAMS is zero. Its feedback
                    // enables request three to use those entries.
                    try std.testing.expectEqual(
                        @as(usize, 0),
                        request.request.qpack_section_acknowledgments,
                    );
                    try std.testing.expect(
                        server_ptr.qpack_decode.table.insert_count != 0,
                    );
                    // Feedback for response one is consumed while waiting for
                    // request two, so response two can already be dynamic.
                    try std.testing.expect(
                        server_ptr.qpack_encode.known_received_count != 0,
                    );
                } else if (exchange == 2) {
                    try std.testing.expect(
                        request.request.qpack_section_acknowledgments != 0,
                    );
                }

                try server_ptr.sendResponse(
                    request.from,
                    request.stream_id,
                    .{
                        .status = 200,
                        .headers = &.{.{
                            .name = "x-runtime-response",
                            .value = "repeated-response-value",
                        }},
                        .body = "ok",
                    },
                );
                if (exchange != 0) {
                    try std.testing.expect(
                        server_ptr.qpack_encode.pending_sections.items.len != 0,
                    );
                }
            }
            try std.testing.expect(
                server_ptr.qpack_encoder_send.next_offset > 1,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .qpack_max_table_capacity = 512 },
            .max_stream_frame_data = 5,
            .max_frames_per_packet = 2,
        },
    );
    defer client.deinit();

    for (0..3) |_| {
        var response = try client.request(.{
            .method = "GET",
            .path = "/protected-dynamic",
            .authority = "example.test",
            .headers = &.{.{
                .name = "x-runtime-request",
                .value = "repeated-request-value",
            }},
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        var repeated_value: ?[]const u8 = null;
        for (response.response.headers) |header| {
            if (std.mem.eql(u8, header.name, "x-runtime-response")) {
                repeated_value = header.value;
            }
        }
        try std.testing.expectEqualStrings(
            "repeated-response-value",
            repeated_value orelse return error.TestUnexpectedResult,
        );
    }

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(client.qpack_encode.known_received_count != 0);
    try std.testing.expect(client.qpack_decode.table.insert_count != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(client.qpack_encoder_send.next_offset > 1);
}

test "HTTP/3 protected server decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xda, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xdb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd3} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd4} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer client.deinit();

    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );

    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.writeQpackEncoderStreamPrefix(&encoder_bytes, allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-live",
            .value = "protected-runtime",
        } },
    );
    var encoder_send = quic.stream_state.SendState.init(client_qpack_encoder_stream_id);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-live", "protected-runtime");
    const request_fields = [_]http3.Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/qpack-live" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-live", .value = "protected-runtime" },
    };
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &field_section,
        allocator,
        &request_fields,
        encoder_table,
    );
    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        request_bytes.items,
        request_bytes.items.len,
        true,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var received = try server.receiveRequest();
    defer received.deinit(allocator);
    try std.testing.expectEqualStrings("GET", received.request.method);
    try std.testing.expectEqualStrings("/qpack-live", received.request.path);
    var live_value: ?[]const u8 = null;
    for (received.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-live")) live_value = header.value;
    }
    try std.testing.expectEqualStrings("protected-runtime", live_value orelse
        return error.TestUnexpectedResult);
    try std.testing.expectEqual(@as(u64, 1), server.qpack_decode.table.insert_count);

    // Decoder feedback is sent after successful request decoding. Because the
    // server has not sent SETTINGS yet, this first write also carries the
    // decoder-stream type prefix at offset zero, followed by Increment +
    // Section Ack.
    var feedback_packet = try quic.one_rtt.receive(
        &client.quic_client.endpoint,
        server_keys,
        client_cid.len,
        0,
        8,
    );
    defer feedback_packet.deinit(allocator);
    var feedback_bytes: std.ArrayList(u8) = .empty;
    defer feedback_bytes.deinit(allocator);
    for (feedback_packet.frames) |frame| {
        if (frame != .stream or frame.stream.stream_id != server_qpack_decoder_stream_id) continue;
        try feedback_bytes.appendSlice(allocator, frame.stream.data);
    }
    try std.testing.expect(feedback_bytes.items.len != 0);
    var feedback_cursor = @import("../internal/wire.zig").Cursor.init(
        feedback_bytes.items,
    );
    try std.testing.expectEqual(
        @as(u64, @intFromEnum(http3.StreamType.qpack_decoder)),
        try quic.varint.decode(&feedback_cursor),
    );
    const increment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[feedback_cursor.pos..],
    );
    const acknowledgment = try http3.Qpack.decodeDecoderInstruction(
        feedback_bytes.items[feedback_cursor.pos + increment.consumed ..],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        increment.instruction.insert_count_increment,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        acknowledgment.instruction.section_acknowledgment,
    );
}

test "HTTP/3 protected server resumes multiple blocked QPACK requests" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xd5, 0x10, 0x20, 0x30 };
    const server_cid = [_]u8{ 0xd6, 0x10, 0x20, 0x30 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd7} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xd8} ** quic.protection.secret_len,
    );

    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 2,
            },
            .max_stream_frame_data = 1024,
        },
    );
    defer server.deinit();
    var client = try ProtectedClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    );
    defer client.deinit();

    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-blocked", "message-before-insert");
    var first_field_section: std.ArrayList(u8) = .empty;
    defer first_field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &first_field_section,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/blocked-one" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "x-blocked", .value = "message-before-insert" },
        },
        encoder_table,
    );
    var second_field_section: std.ArrayList(u8) = .empty;
    defer second_field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(
        &second_field_section,
        allocator,
        &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/blocked-two" },
            .{ .name = ":authority", .value = "localhost" },
            .{ .name = "x-blocked", .value = "message-before-insert" },
        },
        encoder_table,
    );
    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = first_field_section.items,
        .consumed = 0,
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = second_field_section.items,
        .consumed = 0,
    }).write(&second_message, allocator);

    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    var first_send = quic.stream_state.SendState.init(0);
    try first_send.appendFrames(
        &frames,
        allocator,
        first_message.items,
        first_message.items.len,
        true,
    );
    var second_send = quic.stream_state.SendState.init(4);
    try second_send.appendFrames(
        &frames,
        allocator,
        second_message.items,
        second_message.items.len,
        true,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    // Send the encoder instructions only after the complete dependent request.
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-blocked",
            .value = "message-before-insert",
        } },
    );
    frames.clearRetainingCapacity();
    // SETTINGS already emitted the encoder-stream type at offset zero.
    client.qpack_encoder_send.next_offset = @max(
        client.qpack_encoder_send.next_offset,
        1,
    );
    try client.qpack_encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        frames.items,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    var first = try server.receiveRequest();
    defer first.deinit(allocator);
    try std.testing.expectEqualStrings("/blocked-one", first.request.path);
    try std.testing.expectEqual(
        @as(usize, 1),
        server.request_streams.entries.items.len,
    );
    var second = try server.receiveRequest();
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("/blocked-two", second.request.path);
    var value: ?[]const u8 = null;
    for (second.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-blocked")) value = header.value;
    }
    try std.testing.expectEqualStrings(
        "message-before-insert",
        value orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(@as(u64, 1), server.qpack_decode.table.insert_count);
    try std.testing.expectEqual(
        @as(u64, 2),
        server.config.local_settings.qpack_blocked_streams,
    );
}

test "HTTP/3 protected client decodes dynamic QPACK response and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xea, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xeb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xe3} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xe4} ** quic.protection.secret_len);

    var server_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    );
    defer server_endpoint.deinit();
    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server_endpoint.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 1024,
    });
    defer client.deinit();

    const Shared = struct {
        endpoint: *quic.runtime.Endpoint,
        client_address: net.IpAddress,
        server_keys: quic.protection.PacketProtectionKeys,
        client_keys: quic.protection.PacketProtectionKeys,
        client_cid: []const u8,
        server_cid: []const u8,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(shared: *@This()) !void {
            // Consume the client's static request plus control/QPACK bootstrap.
            var request_recv = quic.stream_state.RecvState.init(
                allocator,
                0,
                64 * 1024,
            );
            defer request_recv.deinit();
            var expected_packet_number: u64 = 0;
            while (request_recv.final_size == null or
                request_recv.contiguous_end < request_recv.final_size.?)
            {
                var packet = try quic.one_rtt.receive(
                    shared.endpoint,
                    shared.client_keys,
                    shared.server_cid.len,
                    expected_packet_number,
                    8,
                );
                defer packet.deinit(allocator);
                expected_packet_number = packet.packet.packet_number + 1;
                for (packet.frames) |frame| {
                    if (frame == .stream and frame.stream.stream_id == 0) {
                        try request_recv.insert(frame.stream);
                    }
                }
            }

            var encoder: std.ArrayList(u8) = .empty;
            defer encoder.deinit(allocator);
            try http3.writeQpackEncoderStreamPrefix(&encoder, allocator);
            try http3.Qpack.writeEncoderInstruction(
                &encoder,
                allocator,
                .{ .set_capacity = 256 },
            );
            try http3.Qpack.writeEncoderInstruction(
                &encoder,
                allocator,
                .{ .insert_literal = .{
                    .name = "x-response",
                    .value = "dynamic-client",
                } },
            );
            var frames: std.ArrayList(quic.Frame) = .empty;
            defer frames.deinit(allocator);
            var protected_send = ProtectedSendState.init(allocator);
            defer protected_send.deinit();
            var encoder_send = quic.stream_state.SendState.init(
                server_qpack_encoder_stream_id,
            );
            try encoder_send.appendFrames(
                &frames,
                allocator,
                encoder.items,
                encoder.items.len,
                false,
            );
            var next_packet_number: u64 = 0;
            try sendProtectedFrames(
                shared.endpoint,
                shared.client_address,
                shared.server_keys,
                shared.client_cid,
                &next_packet_number,
                frames.items,
                8,
                &protected_send,
            );

            var table = http3.Qpack.DynamicTable.init(allocator, 256);
            defer table.deinit();
            try table.setCapacity(256);
            _ = try table.insert("x-response", "dynamic-client");
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(allocator);
            try http3.Qpack.encodeDynamicBlock(&block, allocator, &.{
                .{ .name = ":status", .value = "200" },
                .{ .name = "content-length", .value = "2" },
                .{ .name = "x-response", .value = "dynamic-client" },
            }, table);
            var message: std.ArrayList(u8) = .empty;
            defer message.deinit(allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.headers,
                .payload = block.items,
                .consumed = 0,
            }).write(&message, allocator);
            try (http3.Frame{
                .frame_type = http3.FrameType.data,
                .payload = "ok",
                .consumed = 0,
            }).write(&message, allocator);
            frames.clearRetainingCapacity();
            var response_send = quic.stream_state.SendState.init(0);
            try response_send.appendFrames(
                &frames,
                allocator,
                message.items,
                message.items.len,
                true,
            );
            try sendProtectedFrames(
                shared.endpoint,
                shared.client_address,
                shared.server_keys,
                shared.client_cid,
                &next_packet_number,
                frames.items,
                8,
                &protected_send,
            );
        }
    };

    var shared = Shared{
        .endpoint = &server_endpoint,
        .client_address = client.quic_client.address(),
        .server_keys = server_keys,
        .client_keys = client_keys,
        .client_cid = &client_cid,
        .server_cid = &server_cid,
    };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var response = try client.request(.{
        .method = "GET",
        .path = "/dynamic-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("ok", response.response.body);
    var dynamic_value: ?[]const u8 = null;
    for (response.response.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-response")) {
            dynamic_value = header.value;
        }
    }
    try std.testing.expectEqualStrings("dynamic-client", dynamic_value orelse
        return error.TestUnexpectedResult);
    try std.testing.expectEqual(@as(u64, 1), client.qpack_decode.table.insert_count);
}

test "HTTP/3 handshake server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xe2} ** 32,
            .x25519_secret_key = [_]u8{0xe4} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            session.control.local_goaway_id = 0;
            try std.testing.expectError(error.RequestRejected, session.receiveRequest());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0xe1} ** 32,
            .x25519_secret_key = [_]u8{0xe3} ** 32,
        },
    });
    defer client.deinit();

    try sendConnectionSettings(
        &client.established.connection,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    try sendConnectionMessage(
        &client.established.connection,
        0,
        .{ .method = "GET", .path = "/rejected", .authority = "localhost" },
        client.options,
        client.control.settings.peer,
        &client.qpack_encode,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected server rejects requests beyond local GOAWAY" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xaa, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xbb, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xd1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xd2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();
    server.control.local_goaway_id = 0;

    const Shared = struct {
        server: *ProtectedServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            std.testing.expectError(error.RequestRejected, shared.server.receiveRequest()) catch |err| {
                shared.err = err;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    // Send a request without waiting for a response; the server-side receive path
    // should reject it because local GOAWAY(0) says no client request stream is
    // still acceptable.
    try sendProtectedSettings(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        &client.next_packet_number,
        &client.protected_send,
        client_control_stream_id,
    );
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (http3.Request{ .method = "GET", .path = "/rejected", .authority = "localhost" }).write(&encoded, allocator);
    var send_state = quic.stream_state.SendState.init(0);
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);
    try send_state.appendFrames(&frames, allocator, encoded.items, encoded.items.len, true);
    try sendProtectedFrames(&client.quic_client.endpoint, client.quic_client.peer, client.config.send_keys, client.config.peer_connection_id, &client.next_packet_number, frames.items, client.config.max_frames_per_packet, &client.protected_send);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 protected runtime rejects server-initiated bidirectional message streams" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xc1, 0x01, 0x02, 0x03 };
    const server_cid = [_]u8{ 0xc2, 0x01, 0x02, 0x03 };
    const client_keys = quic.protection.deriveAes128Keys([_]u8{0xc1} ** quic.protection.secret_len);
    const server_keys = quic.protection.deriveAes128Keys([_]u8{0xc2} ** quic.protection.secret_len);

    var server = try ProtectedServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = client_keys,
        .send_keys = server_keys,
        .local_connection_id = &server_cid,
        .peer_connection_id = &client_cid,
    });
    defer server.deinit();

    var client = try ProtectedClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .receive_keys = server_keys,
        .send_keys = client_keys,
        .local_connection_id = &client_cid,
        .peer_connection_id = &server_cid,
    });
    defer client.deinit();

    const invalid = [_]quic.Frame{.{
        .stream = .{
            .stream_id = 1, // server-initiated bidirectional: invalid for HTTP/3 messages.
            .data = "not a request stream",
            .fin = true,
        },
    }};
    try sendProtectedFrames(
        &client.quic_client.endpoint,
        client.quic_client.peer,
        client.config.send_keys,
        client.config.peer_connection_id,
        &client.next_packet_number,
        &invalid,
        client.config.max_frames_per_packet,
        &client.protected_send,
    );

    try std.testing.expectError(error.StreamCreationError, server.receiveRequest());
}

test "HTTP/3 handshake runtime establishes QUIC and exchanges request response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x73} ** 32,
            .x25519_secret_key = [_]u8{0x74} ** 32,
        },
        .session = .{ .local_settings = .{ .h3_datagram = true }, .max_stream_frame_data = 7 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectEqualStrings("h3", session.established.alpn);

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3-handshake", request.request.path);
            try std.testing.expectEqualStrings("split by handshake runtime", request.request.body);
            try std.testing.expect(session.control.settings.received);
            try std.testing.expectEqual(@as(u64, 6), session.control.settings.peer.webtransport_max_sessions);
            try std.testing.expectEqual(@as(?u64, client_control_stream_id), session.control.peer_control_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_encoder_stream_id), session.control.peer_qpack_encoder_stream_id);
            try std.testing.expectEqual(@as(?u64, client_qpack_decoder_stream_id), session.control.peer_qpack_decoder_stream_id);
            try session.sendResponse(request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "handshake pong",
            });
            try std.testing.expect(session.control.settings.sent);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x71} ** 32,
            .x25519_secret_key = [_]u8{0x72} ** 32,
        },
        .session = .{ .local_settings = .{ .webtransport_max_sessions = 6 }, .max_stream_frame_data = 7 },
    });
    defer client.deinit();
    try std.testing.expectEqualStrings("h3", client.established.alpn);

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3-handshake",
        .authority = "localhost",
        .body = "split by handshake runtime",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expectEqualStrings("handshake pong", response.response.body);
    try std.testing.expect(client.control.settings.sent);
    try std.testing.expect(client.control.settings.received);
    try std.testing.expect(client.control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(?u64, server_control_stream_id), client.control.peer_control_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_encoder_stream_id), client.control.peer_qpack_encoder_stream_id);
    try std.testing.expectEqual(@as(?u64, server_qpack_decoder_stream_id), client.control.peer_qpack_decoder_stream_id);
}

test "HTTP/3 handshake client requests from URI endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa1, 0xb1, 0xc1, 0xd1, 0xe1, 0xf1, 0x01, 0x11 };
    const client_cid = [_]u8{ 0xa2, 0xb2, 0xc2, 0xd2 };
    const server_cid = [_]u8{ 0xa3, 0xb3, 0xc3, 0xd3 };

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xa4} ** 32,
            .x25519_secret_key = [_]u8{0xa5} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/uri", request.request.path);
            try std.testing.expectEqualStrings("127.0.0.1", request.request.authority.?[0..9]);
            try session.sendResponse(request.stream_id, .{
                .status = 204,
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var uri_buf: [64]u8 = undefined;
    const uri_text = try std.fmt.bufPrint(&uri_buf, "https://127.0.0.1:{d}/uri", .{server.address().ip4.port});
    const uri = try std.Uri.parse(uri_text);
    var response = try HandshakeClient.requestUri(allocator, io, .{ .ip4 = .loopback(0) }, uri, .{}, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xa6} ** 32,
            .x25519_secret_key = [_]u8{0xa7} ** 32,
        },
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client requests via Alt-Svc target" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8 };
    const client_cid = [_]u8{ 0xb9, 0xba, 0xbb, 0xbc };
    const server_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const uri = try std.Uri.parse("https://origin.example/alt");

    try std.testing.expectError(error.InvalidHeader, HandshakeClient.requestUriAltSvc(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        .{ .alpn = "h2", .connect_host = "127.0.0.1", .origin_host = "origin.example", .port = 443 },
        .{},
        .{},
        .{ .handshake = .{ .original_destination_connection_id = &original_dcid, .local_connection_id = &client_cid } },
    ));

    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0xb4} ** 32,
            .x25519_secret_key = [_]u8{0xb5} ** 32,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            var request = try session.receiveRequest();
            defer request.deinit(session.established.connection.endpoint.allocator);
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/alt", request.request.path);
            try std.testing.expectEqualStrings("origin.example", request.request.authority.?);
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    const server_address = server.address();
    var alt_svc_value_buf: [64]u8 = undefined;
    const alt_svc_value = try std.fmt.bufPrint(
        &alt_svc_value_buf,
        "h3=\"127.0.0.1:{d}\"; ma=60",
        .{server_address.ip4.port},
    );
    const alt_svc_headers = [_]http3.Qpack.HeaderField{
        .{ .name = "alt-svc", .value = alt_svc_value },
    };
    var response = try HandshakeClient.requestUriAltSvcHeader(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        uri,
        &alt_svc_headers,
        .{},
        .{ .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 } },
        .{ .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .random = [_]u8{0xb6} ** 32,
            .x25519_secret_key = [_]u8{0xb7} ** 32,
        } },
    );
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake server retains interleaved request streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58 };
    const client_cid = [_]u8{ 0x59, 0x5a, 0x5b, 0x5c };
    const server_cid = [_]u8{ 0x5d, 0x5e, 0x5f, 0x60 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x63} ** 32,
                .x25519_secret_key = [_]u8{0x64} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 0), first.stream_id);
            try std.testing.expectEqualStrings("/first", first.request.path);
            try std.testing.expectEqual(
                @as(usize, 1),
                session.request_streams.entries.items.len,
            );

            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(@as(u62, 4), second.stream_id);
            try std.testing.expectEqualStrings("/second", second.request.path);
            try std.testing.expectEqual(
                @as(usize, 0),
                session.request_streams.entries.items.len,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x61} ** 32,
                .x25519_secret_key = [_]u8{0x62} ** 32,
            },
        },
    );
    defer client.deinit();

    try sendConnectionSettings(
        &client.established.connection,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    var first_message: std.ArrayList(u8) = .empty;
    defer first_message.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    }).write(&first_message, allocator);
    var second_message: std.ArrayList(u8) = .empty;
    defer second_message.deinit(allocator);
    try (http3.Request{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    }).write(&second_message, allocator);
    const first_split = first_message.items.len / 2;
    const frames = [_]quic.Frame{
        .{ .stream = .{
            .stream_id = 0,
            .data = first_message.items[0..first_split],
        } },
        .{ .stream = .{
            .stream_id = 4,
            .data = second_message.items,
            .fin = true,
        } },
        .{ .stream = .{
            .stream_id = 0,
            .offset = first_split,
            .data = first_message.items[first_split..],
            .fin = true,
        } },
    };
    try client.established.connection.send(&frames);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client cancellation reaches server" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c };
    const client_cid = [_]u8{ 0x6d, 0x6e, 0x6f, 0x70 };
    const server_cid = [_]u8{ 0x71, 0x72, 0x73, 0x74 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x77} ** 32,
                .x25519_secret_key = [_]u8{0x78} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try std.testing.expectError(
                error.RequestCancelled,
                session.receiveRequest(),
            );
            try std.testing.expectEqual(
                @as(usize, 0),
                session.request_streams.entries.items.len,
            );
            const reset = session.established.connection.streamResetReceived(0) orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                @as(u64, http3.ApplicationErrorCode.request_cancelled),
                reset.application_error_code,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x75} ** 32,
                .x25519_secret_key = [_]u8{0x76} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.cancelRequest(
        0,
        http3.ApplicationErrorCode.request_cancelled,
    );
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake server performs two-phase graceful shutdown" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80 };
    const client_cid = [_]u8{ 0x81, 0x82, 0x83, 0x84 };
    const server_cid = [_]u8{ 0x85, 0x86, 0x87, 0x88 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x8b} ** 32,
                .x25519_secret_key = [_]u8{0x8c} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.initiateShutdown();
            try session.completeShutdown();
            try std.testing.expectEqual(
                @as(?u64, 4),
                session.control.local_goaway_id,
            );
            try std.testing.expect(!session.drainComplete());
            try session.sendResponse(request.stream_id, .{ .status = 204 });
            try std.testing.expect(session.drainComplete());
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x89} ** 32,
                .x25519_secret_key = [_]u8{0x8a} ** 32,
            },
        },
    );
    defer client.deinit();

    var response = try client.request(.{
        .method = "GET",
        .path = "/graceful",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
    try std.testing.expectEqual(@as(?u64, 4), client.control.peer_goaway_id);
    try std.testing.expectError(error.GoAwayReceived, client.request(.{
        .method = "GET",
        .path = "/after-graceful",
    }));
}

test "HTTP/3 handshake client sends priority update before request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94 };
    const client_cid = [_]u8{ 0x95, 0x96, 0x97, 0x98 };
    const server_cid = [_]u8{ 0x99, 0x9a, 0x9b, 0x9c };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0x9f} ** 32,
                .x25519_secret_key = [_]u8{0xa0} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            const update = session.control.latest_priority_update orelse
                return error.TestUnexpectedResult;
            try std.testing.expectEqual(
                request.stream_id,
                update.prioritized_element_id,
            );
            try std.testing.expectEqual(
                @as(u3, 2),
                update.priority().urgency,
            );
            try std.testing.expect(update.priority().incremental);
            try session.sendResponse(request.stream_id, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0x9d} ** 32,
                .x25519_secret_key = [_]u8{0x9e} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.sendPriorityUpdate(0, .{
        .urgency = 2,
        .incremental = true,
    });
    var response = try client.request(.{
        .method = "GET",
        .path = "/prioritized",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client advertises and cancels server push IDs" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4 };
    const client_cid = [_]u8{ 0xd5, 0xd6, 0xd7, 0xd8 };
    const server_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xdf} ** 32,
                .x25519_secret_key = [_]u8{0xe0} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            while (session.control.peer_max_push_id != 8 or
                !session.control.pushCancelled(7) or
                !session.control.pushCancelled(3))
            {
                var packet = try session.established.connection.receivePacket();
                defer packet.deinit(
                    session.established.connection.endpoint.allocator,
                );
                for (packet.frames) |frame| {
                    if (frame != .stream) continue;
                    if (try applyControlStreamFrameForRole(
                        &session.control,
                        session.established.connection.endpoint.allocator,
                        frame.stream,
                        .server,
                    )) {
                        try configureQpackEncoderFromPeerSettings(
                            session.control,
                            &session.qpack_encode,
                        );
                    }
                }
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xdd} ** 32,
                .x25519_secret_key = [_]u8{0xde} ** 32,
            },
        },
    );
    defer client.deinit();

    try client.sendMaxPushId(4);
    try client.sendMaxPushId(8);
    try std.testing.expectError(
        error.MaxPushIdReduced,
        client.sendMaxPushId(7),
    );
    try std.testing.expectError(error.PushIdExceeded, client.cancelPush(9));
    try client.push_streams.registerPromise(7, 0);
    try client.push_streams.registerPromise(3, 0);
    try client.cancelPush(7);
    try client.cancelPush(3);
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client streams promised push response" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8 };
    const client_cid = [_]u8{ 0xe9, 0xea, 0xeb, 0xec };
    const server_cid = [_]u8{ 0xed, 0xee, 0xef, 0xf0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            while (session.control.peer_max_push_id != 1) {
                try session.receiveRequestPacket();
            }
            const session_allocator =
                session.established.connection.endpoint.allocator;
            var promise_fields: std.ArrayList(u8) = .empty;
            defer promise_fields.deinit(session_allocator);
            var table = http3.Qpack.DynamicTable.init(session_allocator, 0);
            defer table.deinit();
            try http3.Qpack.encodeDynamicBlock(
                &promise_fields,
                session_allocator,
                &.{
                    .{ .name = ":method", .value = "GET" },
                    .{ .name = ":scheme", .value = "https" },
                    .{ .name = ":path", .value = "/handshake.css" },
                    .{ .name = ":authority", .value = "localhost" },
                },
                table,
            );
            var response_bytes: std.ArrayList(u8) = .empty;
            defer response_bytes.deinit(session_allocator);
            try http3.writePushPromiseFrame(
                &response_bytes,
                session_allocator,
                1,
                promise_fields.items,
            );
            try (http3.Response{ .status = 204 }).write(
                &response_bytes,
                session_allocator,
            );
            var push_bytes: std.ArrayList(u8) = .empty;
            defer push_bytes.deinit(session_allocator);
            try quic.varint.encode(
                &push_bytes,
                session_allocator,
                @intFromEnum(http3.StreamType.push),
            );
            try quic.varint.encode(&push_bytes, session_allocator, 1);
            try (http3.Response{
                .status = 200,
                .body = "handshake-asset",
            }).write(&push_bytes, session_allocator);
            const frames = [_]quic.Frame{
                .{ .stream = .{
                    .stream_id = request.stream_id,
                    .data = response_bytes.items,
                    .fin = true,
                } },
                .{ .stream = .{
                    .stream_id = 15,
                    .data = push_bytes.items,
                    .fin = true,
                } },
            };
            try session.established.connection.send(&frames);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var thread_joined = false;
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
        },
    );
    defer client.deinit();
    defer if (!thread_joined) thread.join();
    try client.sendMaxPushId(1);
    const request_stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/",
        .authority = "localhost",
    });
    var promise = while (true) {
        if (try client.receiveResponseEvent(request_stream_id)) |event| {
            break event;
        }
    };
    defer promise.deinit(allocator);
    try std.testing.expect(promise == .push_promise);
    var pushed = try client.receivePush();
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqualStrings(
        "handshake-asset",
        pushed.response.body,
    );
    thread.join();
    thread_joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client sends priority update for promised push" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const original_dcid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8 };
    const client_cid = [_]u8{ 0xc9, 0xca, 0xcb, 0xcc };
    const server_cid = [_]u8{ 0xcd, 0xce, 0xcf, 0xd0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xd1} ** 32,
                .x25519_secret_key = [_]u8{0xd2} ** 32,
            },
        },
    );
    defer server.deinit();
    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            try session.peer_promised_push_ids.append(
                session.established.connection.endpoint.allocator,
                1,
            );
            while (session.control.pushPriorityUpdate(1) == null) {
                try session.receiveRequestPacket();
            }
            const priority =
                session.control.pushPriorityUpdate(1).?.priority();
            try std.testing.expectEqual(@as(u3, 4), priority.urgency);
            try std.testing.expect(priority.incremental);
        }
    };
    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{},
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xd3} ** 32,
                .x25519_secret_key = [_]u8{0xd4} ** 32,
            },
        },
    );
    defer client.deinit();
    try client.sendMaxPushId(1);
    try client.push_streams.registerPromise(1, 0);
    try client.sendPushPriorityUpdate(1, .{
        .urgency = 4,
        .incremental = true,
    });
    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client retains interleaved responses" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8 };
    const client_cid = [_]u8{ 0xa9, 0xaa, 0xab, 0xac };
    const server_cid = [_]u8{ 0xad, 0xae, 0xaf, 0xb0 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try session.sendResponse(second.stream_id, .{
                .status = 200,
                .body = "second-response",
            });
            try session.sendResponse(first.stream_id, .{
                .status = 200,
                .body = "first-response",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
        },
    );
    defer client.deinit();

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/first",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/second",
        .authority = "localhost",
    });
    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(
        second_id,
        first_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "second-response",
        first_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        client.request_lifecycle.outstanding.items.len,
    );
    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        first_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "first-response",
        second_event.response.value.response.body,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.outstanding.items.len,
    );
}

test "HTTP/3 handshake client drains GRO response batch one packet at a time" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc };
    const client_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var first = try session.receiveRequest();
            defer first.deinit(
                session.established.connection.endpoint.allocator,
            );
            var second = try session.receiveRequest();
            defer second.deinit(
                session.established.connection.endpoint.allocator,
            );
            try sendConnectionSettings(
                &session.established.connection,
                &session.control,
                &session.control_send,
                &session.qpack_encoder_send,
                &session.qpack_encoder_prefix_sent,
                &session.qpack_decoder_send,
                &session.qpack_decoder_prefix_sent,
                session.options,
                server_control_stream_id,
            );

            var first_bytes: std.ArrayList(u8) = .empty;
            defer first_bytes.deinit(
                session.established.connection.endpoint.allocator,
            );
            try (http3.Response{
                .status = 200,
                .body = "response-one",
            }).write(
                &first_bytes,
                session.established.connection.endpoint.allocator,
            );
            var second_bytes: std.ArrayList(u8) = .empty;
            defer second_bytes.deinit(
                session.established.connection.endpoint.allocator,
            );
            try (http3.Response{
                .status = 200,
                .body = "response-two",
            }).write(
                &second_bytes,
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqual(
                first_bytes.items.len,
                second_bytes.items.len,
            );
            const second_frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = second.stream_id,
                .data = second_bytes.items,
                .fin = true,
            } }};
            const first_frames = [_]quic.Frame{.{ .stream = .{
                .stream_id = first.stream_id,
                .data = first_bytes.items,
                .fin = true,
            } }};
            const packets = [_][]const quic.Frame{
                &second_frames,
                &first_frames,
            };
            try session.established.connection.sendMany(&packets);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 1400,
            .max_frames_per_datagram = 8,
            .enable_gro_receive = true,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
        },
    );
    defer client.deinit();
    if (!client.endpoint.groReceiveEnabled()) {
        thread.join();
        if (shared.err) |err| return err;
        return error.SkipZigTest;
    }

    const first_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-one",
        .authority = "localhost",
    });
    const second_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/gro-two",
        .authority = "localhost",
    });
    var second_event = try client.receiveNextResponse();
    defer second_event.deinit(allocator);
    try std.testing.expect(second_event == .response);
    try std.testing.expectEqual(
        second_id,
        second_event.response.stream_id,
    );
    try std.testing.expectEqualStrings(
        "response-two",
        second_event.response.value.response.body,
    );
    try std.testing.expect(client.receive_packets.batch != null);
    try std.testing.expectEqual(
        @as(usize, 1),
        client.receive_packets.batch.?.remaining(),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.response_streams.entries.items.len,
    );

    var first_event = try client.receiveNextResponse();
    defer first_event.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(first_event == .response);
    try std.testing.expectEqual(first_id, first_event.response.stream_id);
    try std.testing.expectEqualStrings(
        "response-one",
        first_event.response.value.response.body,
    );
}

test "HTTP/3 handshake runtime streams request and response DATA chunks" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc };
    const client_cid = [_]u8{ 0xbd, 0xbe, 0xbf, 0xc0 };
    const server_cid = [_]u8{ 0xc1, 0xc2, 0xc3, 0xc4 };
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xc7} ** 32,
                .x25519_secret_key = [_]u8{0xc8} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings(
                "handshake-request",
                request.request.body,
            );
            try std.testing.expectEqualStrings(
                "ok",
                request.request.trailers[0].value,
            );
            try session.startResponse(
                request.stream_id,
                .{ .status = 200 },
                "handshake-response".len,
            );
            try session.sendResponseBody(
                request.stream_id,
                "handshake-",
                false,
            );
            try session.sendResponseBody(
                request.stream_id,
                "response",
                false,
            );
            try session.finishResponseTrailers(
                request.stream_id,
                &.{.{ .name = "x-response-checksum", .value = "ok" }},
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xc5} ** 32,
                .x25519_secret_key = [_]u8{0xc6} ** 32,
            },
            .session = .{ .max_stream_frame_data = 5 },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/streaming",
            .authority = "localhost",
        },
        "handshake-request".len,
    );
    try client.sendRequestBody(stream_id, "handshake-", false);
    try client.sendRequestBody(stream_id, "request", false);
    try client.finishRequestTrailers(
        stream_id,
        &.{.{ .name = "x-request-checksum", .value = "ok" }},
    );
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqualStrings(
        "handshake-response",
        response.response.body,
    );
    try std.testing.expectEqualStrings(
        "ok",
        response.response.trailers[0].value,
    );
}

test "HTTP/3 handshake server streams large request through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 64 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7 };
    const client_cid = [_]u8{ 0xe8, 0xe9, 0xea, 0xeb };
    const server_cid = [_]u8{ 0xec, 0xed, 0xee, 0xef };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xf3} ** 32,
                .x25519_secret_key = [_]u8{0xf4} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            var saw_head = false;
            var saw_trailers = false;
            var body_read: usize = 0;
            var checksum: u64 = 0;
            var stream_id: ?u62 = null;
            var read_buf: [113]u8 = undefined;
            while (session.streaming_requests.retainedCount() != 0 or
                !saw_head)
            {
                var event = try session.receiveRequestEvent();
                defer event.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expect(event == .message);
                const message = &event.message;
                if (stream_id) |expected| {
                    try std.testing.expectEqual(expected, message.stream_id);
                } else {
                    stream_id = message.stream_id;
                }
                switch (message.value) {
                    .head => |head| {
                        try std.testing.expect(head == .request);
                        try std.testing.expectEqual(
                            @as(?usize, body_len),
                            head.request.content_length,
                        );
                        saw_head = true;
                    },
                    .push_promise => return error.TestUnexpectedResult,
                    .data_available => {
                        while (true) {
                            const active = session.streaming_requests.find(
                                message.stream_id,
                            ).?;
                            if (active.reader.current_frame == null) break;
                            const read = try session.readRequestData(
                                message.stream_id,
                                &read_buf,
                            );
                            if (read == 0) break;
                            for (read_buf[0..read]) |byte| checksum +%= byte;
                            body_read += read;
                        }
                        const active = session.streaming_requests.find(
                            message.stream_id,
                        ).?;
                        try std.testing.expect(
                            active.reader.receive.buffer.items.len <= 512,
                        );
                    },
                    .trailers => |trailers| {
                        try std.testing.expectEqualStrings(
                            "yes",
                            trailers.fields[0].value,
                        );
                        saw_trailers = true;
                    },
                    .finished => {},
                }
            }
            try std.testing.expect(saw_head);
            try std.testing.expect(saw_trailers);
            try std.testing.expectEqual(body_len, body_read);

            var chunk: [400]u8 = undefined;
            var chunk_sum: u64 = 0;
            for (&chunk, 0..) |*byte, index| {
                byte.* = @truncate(index);
                chunk_sum += byte.*;
            }
            var expected = chunk_sum * (body_len / chunk.len);
            for (chunk[0 .. body_len % chunk.len]) |byte| expected += byte;
            try std.testing.expectEqual(expected, checksum);
            try session.sendResponse(stream_id.?, .{ .status = 204 });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xf1} ** 32,
                .x25519_secret_key = [_]u8{0xf2} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/large-handshake-request",
            .authority = "localhost",
        },
        body_len,
    );
    var chunk: [400]u8 = undefined;
    for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
    var remaining = body_len;
    while (remaining != 0) {
        const count = @min(chunk.len, remaining);
        try client.sendRequestBodyPaced(
            stream_id,
            chunk[0..count],
            false,
        );
        remaining -= count;
    }
    try client.finishRequestTrailersPaced(stream_id, &.{.{
        .name = "x-request-finished",
        .value = "yes",
    }});
    var response = try client.receiveResponse(stream_id);
    defer response.deinit(allocator);
    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(u16, 204), response.response.status);
}

test "HTTP/3 handshake client streams dynamic response through small window" {
    const allocator = std.testing.allocator;
    const body_len: usize = 1024 * 1024;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7 };
    const client_cid = [_]u8{ 0xd8, 0xd9, 0xda, 0xdb };
    const server_cid = [_]u8{ 0xdc, 0xdd, 0xde, 0xdf };
    var server_transport = quic.practical_transport_parameters;
    server_transport.initial_max_data = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    server_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var client_transport = quic.practical_transport_parameters;
    client_transport.initial_max_data = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_local = 16 * 1024;
    client_transport.initial_max_stream_data_bidi_remote = 16 * 1024;
    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .local_transport_parameters = server_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_frame_data = 480,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            for (0..3) |exchange| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/large-handshake-stream",
                    request.request.path,
                );
                if (exchange != 0) {
                    // The first response inserts both repeated fields. Reading
                    // the next request pumps the client's Insert Count
                    // Increment, allowing later response sections to reference
                    // those entries without blocking.
                    try std.testing.expect(
                        session.qpack_encode.known_received_count >= 2,
                    );
                }
                const response: http3.Response = .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "x-stream-kind",
                        .value = "bounded-handshake",
                    }},
                    .trailers = &.{.{
                        .name = "x-stream-finished",
                        .value = "yes",
                    }},
                };
                if (exchange < 2) {
                    var warmup = response;
                    warmup.body = "warmup";
                    try session.sendResponse(request.stream_id, warmup);
                    continue;
                }
                try session.startResponse(
                    request.stream_id,
                    .{
                        .status = response.status,
                        .headers = response.headers,
                    },
                    body_len,
                );
                var chunk: [400]u8 = undefined;
                for (&chunk, 0..) |*byte, index| byte.* = @truncate(index);
                var remaining = body_len;
                while (remaining != 0) {
                    const count = @min(chunk.len, remaining);
                    try session.sendResponseBodyPaced(
                        request.stream_id,
                        chunk[0..count],
                        false,
                    );
                    remaining -= count;
                }
                try session.finishResponseTrailersPaced(
                    request.stream_id,
                    response.trailers,
                );
                return;
            }
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .local_transport_parameters = client_transport,
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1200,
                },
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
            },
            .session = .{
                .local_settings = .{
                    .qpack_max_table_capacity = 512,
                    .qpack_blocked_streams = 2,
                },
                .max_stream_buffer = 512,
                .max_stream_frame_data = 480,
            },
        },
    );
    defer client.deinit();

    for (0..2) |exchange| {
        var warmup = try client.request(.{
            .method = "GET",
            .path = "/large-handshake-stream",
            .authority = "localhost",
        });
        defer warmup.deinit(allocator);
        try std.testing.expectEqualStrings("warmup", warmup.response.body);
        if (exchange == 1) {
            try std.testing.expect(
                warmup.response.qpack_section_acknowledgments != 0,
            );
        }
    }

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/large-handshake-stream",
        .authority = "localhost",
    });
    var saw_head = false;
    var saw_trailers = false;
    var body_read: usize = 0;
    var checksum: u64 = 0;
    var read_buf: [113]u8 = undefined;
    while (client.request_lifecycle.contains(stream_id)) {
        const event = (try client.receiveResponseEvent(stream_id)) orelse
            continue;
        var owned_event = event;
        defer owned_event.deinit(allocator);
        switch (owned_event) {
            .head => |head| {
                try std.testing.expectEqual(
                    @as(u16, 200),
                    head.response.status,
                );
                try std.testing.expectEqual(
                    @as(?usize, body_len),
                    head.response.content_length,
                );
                try std.testing.expect(
                    head.response.qpack_section_acknowledgments != 0,
                );
                saw_head = true;
            },
            .push_promise => return error.TestUnexpectedResult,
            .data_available => {
                while (true) {
                    const active = client.streaming_responses.find(
                        stream_id,
                    ).?;
                    if (active.reader.current_frame == null) break;
                    const read = try client.readResponseData(
                        stream_id,
                        &read_buf,
                    );
                    if (read == 0) break;
                    for (read_buf[0..read]) |byte| checksum +%= byte;
                    body_read += read;
                }
                const active = client.streaming_responses.find(stream_id).?;
                try std.testing.expect(
                    active.reader.receive.buffer.items.len <= 512,
                );
            },
            .trailers => |trailers| {
                try std.testing.expectEqualStrings(
                    "yes",
                    trailers.fields[0].value,
                );
                try std.testing.expect(
                    trailers.qpack_section_acknowledgments != 0,
                );
                saw_trailers = true;
            },
            .finished => {},
        }
    }
    thread.join();
    if (shared.err) |err| return err;

    var chunk: [400]u8 = undefined;
    var chunk_checksum: u64 = 0;
    for (&chunk, 0..) |*byte, index| {
        byte.* = @truncate(index);
        chunk_checksum += byte.*;
    }
    var expected_checksum =
        chunk_checksum * (body_len / chunk.len);
    for (chunk[0 .. body_len % chunk.len]) |byte| {
        expected_checksum += byte;
    }
    try std.testing.expect(saw_head);
    try std.testing.expect(saw_trailers);
    try std.testing.expectEqual(body_len, body_read);
    try std.testing.expectEqual(expected_checksum, checksum);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.streaming_responses.entries.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.request_lifecycle.outstanding.items.len,
    );
}

test "HTTP/3 handshake runtime reuses acknowledged dynamic QPACK entries" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    const client_cid = [_]u8{ 0xa8, 0xa9, 0xaa, 0xab };
    const server_cid = [_]u8{ 0xac, 0xad, 0xae, 0xaf };

    var server = try HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .local_connection_id = &server_cid,
                .random = [_]u8{0xb3} ** 32,
                .x25519_secret_key = [_]u8{0xb4} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 512 },
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 5,
            },
        },
    );
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();

            for (0..3) |exchange| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                try std.testing.expectEqualStrings(
                    "/handshake-dynamic",
                    request.request.path,
                );
                var repeated_value: ?[]const u8 = null;
                for (request.request.headers) |header| {
                    if (std.mem.eql(u8, header.name, "x-handshake-request")) {
                        repeated_value = header.value;
                    }
                }
                try std.testing.expectEqualStrings(
                    "repeated-request-value",
                    repeated_value orelse return error.TestUnexpectedResult,
                );

                if (exchange == 1) {
                    // The second request carries inserts but remains literal
                    // under SETTINGS_QPACK_BLOCKED_STREAMS=0. Waiting for it
                    // also consumes feedback that unlocks response reuse.
                    try std.testing.expectEqual(
                        @as(usize, 0),
                        request.request.qpack_section_acknowledgments,
                    );
                    try std.testing.expect(
                        session.qpack_decode.table.insert_count != 0,
                    );
                    try std.testing.expect(
                        session.qpack_encode.known_received_count != 0,
                    );
                } else if (exchange == 2) {
                    try std.testing.expect(
                        request.request.qpack_section_acknowledgments != 0,
                    );
                }

                try session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .headers = &.{.{
                        .name = "x-handshake-response",
                        .value = "repeated-response-value",
                    }},
                    .body = "ok",
                });
                if (exchange != 0) {
                    try std.testing.expect(
                        session.qpack_encode.pending_sections.items.len != 0,
                    );
                }
            }
            try std.testing.expect(
                session.qpack_encoder_send.next_offset > 1,
            );
            try std.testing.expect(
                session.qpack_decoder_send.next_offset > 1,
            );
            try std.testing.expectEqual(
                @as(?usize, 512),
                session.qpack_encode.peer_max_capacity,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try HandshakeClient.connect(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        server.address(),
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{
            .handshake = .{
                .original_destination_connection_id = &original_dcid,
                .local_connection_id = &client_cid,
                .server_name = "localhost",
                .random = [_]u8{0xb1} ** 32,
                .x25519_secret_key = [_]u8{0xb2} ** 32,
            },
            .session = .{
                .local_settings = .{ .qpack_max_table_capacity = 512 },
                .max_frames_per_packet = 2,
                .max_stream_frame_data = 5,
            },
        },
    );
    defer client.deinit();

    for (0..3) |_| {
        var response = try client.request(.{
            .method = "GET",
            .path = "/handshake-dynamic",
            .authority = "example.test",
            .headers = &.{.{
                .name = "x-handshake-request",
                .value = "repeated-request-value",
            }},
        });
        defer response.deinit(allocator);
        try std.testing.expectEqual(@as(u16, 200), response.response.status);
        var repeated_value: ?[]const u8 = null;
        for (response.response.headers) |header| {
            if (std.mem.eql(u8, header.name, "x-handshake-response")) {
                repeated_value = header.value;
            }
        }
        try std.testing.expectEqualStrings(
            "repeated-response-value",
            repeated_value orelse return error.TestUnexpectedResult,
        );
    }

    thread.join();
    if (shared.err) |err| return err;
    try std.testing.expect(client.qpack_encode.known_received_count != 0);
    try std.testing.expect(client.qpack_decode.table.insert_count != 0);
    try std.testing.expectEqual(
        @as(usize, 0),
        client.qpack_encode.pending_sections.items.len,
    );
    try std.testing.expect(client.qpack_encoder_send.next_offset > 1);
    try std.testing.expect(client.qpack_decoder_send.next_offset > 1);
    try std.testing.expectEqual(
        @as(?usize, 512),
        client.qpack_encode.peer_max_capacity,
    );
}

test "HTTP/3 handshake runtime decodes dynamic QPACK request and sends feedback" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{ 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7 };
    const client_cid = [_]u8{ 0xf8, 0xf9, 0xfa, 0xfb };
    const server_cid = [_]u8{ 0xfc, 0xfd, 0xfe, 0xff };
    var server = try HandshakeServer.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .local_connection_id = &server_cid,
            .random = [_]u8{0x83} ** 32,
            .x25519_secret_key = [_]u8{0x84} ** 32,
        },
        .session = .{
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
            },
            .max_stream_frame_data = 1024,
        },
    });
    defer server.deinit();

    const Shared = struct {
        server: *HandshakeServer,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *HandshakeServer) !void {
            var session = try server_ptr.accept();
            defer session.deinit();
            // Advertise capacity before accepting any dependent encoder
            // instruction or field section.
            try sendConnectionSettings(
                &session.established.connection,
                &session.control,
                &session.control_send,
                &session.qpack_encoder_send,
                &session.qpack_encoder_prefix_sent,
                &session.qpack_decoder_send,
                &session.qpack_decoder_prefix_sent,
                session.options,
                server_control_stream_id,
            );
            var request = try session.receiveRequest();
            defer request.deinit(
                session.established.connection.endpoint.allocator,
            );
            try std.testing.expectEqualStrings("GET", request.request.method);
            try std.testing.expectEqualStrings("/handshake-qpack", request.request.path);
            var value: ?[]const u8 = null;
            for (request.request.headers) |header| {
                if (std.mem.eql(u8, header.name, "x-handshake")) {
                    value = header.value;
                }
            }
            try std.testing.expectEqualStrings("dynamic", value orelse
                return error.TestUnexpectedResult);
            try std.testing.expectEqual(
                @as(u64, 1),
                session.qpack_decode.table.insert_count,
            );
            try std.testing.expectEqual(
                @as(u64, 1),
                session.options.local_settings.qpack_blocked_streams,
            );
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var client = try HandshakeClient.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    }, .{
        .handshake = .{
            .original_destination_connection_id = &original_dcid,
            .local_connection_id = &client_cid,
            .server_name = "localhost",
            .random = [_]u8{0x81} ** 32,
            .x25519_secret_key = [_]u8{0x82} ** 32,
        },
        .session = .{
            .local_settings = .{ .qpack_max_table_capacity = 256 },
            .max_stream_frame_data = 1024,
        },
    });
    defer client.deinit();

    // Process the server SETTINGS and critical-stream prefixes before using
    // its advertised QPACK capacity.
    var settings_packet = try client.established.connection.receivePacket();
    defer settings_packet.deinit(allocator);
    for (settings_packet.frames) |frame| {
        if (frame != .stream) continue;
        if ((frame.stream.stream_id & 0x02) != 0 and
            frame.stream.stream_id == server_qpack_encoder_stream_id)
        {
            try client.qpack_decode.applyEncoderStreamFrame(
                &client.control,
                frame.stream,
            );
            continue;
        }
        _ = try applyControlStreamFrameForRole(
            &client.control,
            allocator,
            frame.stream,
            .client,
        );
    }
    try std.testing.expectEqual(
        @as(u64, 256),
        client.control.settings.peer.qpack_max_table_capacity,
    );

    try sendConnectionSettings(
        &client.established.connection,
        &client.control,
        &client.control_send,
        &client.qpack_encoder_send,
        &client.qpack_encoder_prefix_sent,
        &client.qpack_decoder_send,
        &client.qpack_decoder_prefix_sent,
        client.options,
        client_control_stream_id,
    );
    var frames: std.ArrayList(quic.Frame) = .empty;
    defer frames.deinit(allocator);

    var encoder_table = http3.Qpack.DynamicTable.init(allocator, 256);
    defer encoder_table.deinit();
    try encoder_table.setCapacity(256);
    _ = try encoder_table.insert("x-handshake", "dynamic");
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try http3.Qpack.encodeDynamicBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/handshake-qpack" },
        .{ .name = ":authority", .value = "localhost" },
        .{ .name = "x-handshake", .value = "dynamic" },
    }, encoder_table);
    var message: std.ArrayList(u8) = .empty;
    defer message.deinit(allocator);
    try (http3.Frame{
        .frame_type = http3.FrameType.headers,
        .payload = field_section.items,
        .consumed = 0,
    }).write(&message, allocator);
    frames.clearRetainingCapacity();
    var request_send = quic.stream_state.SendState.init(0);
    try request_send.appendFrames(
        &frames,
        allocator,
        message.items,
        message.items.len,
        true,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    // Deliver the dependent message first, then unblock it with split encoder
    // instructions on the persistent stream.
    var encoder_bytes: std.ArrayList(u8) = .empty;
    defer encoder_bytes.deinit(allocator);
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .set_capacity = 256 },
    );
    try http3.Qpack.writeEncoderInstruction(
        &encoder_bytes,
        allocator,
        .{ .insert_literal = .{
            .name = "x-handshake",
            .value = "dynamic",
        } },
    );
    frames.clearRetainingCapacity();
    try client.qpack_encoder_send.appendFrames(
        &frames,
        allocator,
        encoder_bytes.items,
        encoder_bytes.items.len / 2,
        false,
    );
    try sendConnectionFrames(
        &client.established.connection,
        frames.items,
        client.options.max_frames_per_packet,
    );

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 runtime exchanges request and response over QUIC UDP frame endpoint" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/h3", request.request.path);
            try std.testing.expectEqualStrings("ping split by dev sender", request.request.body);
            try std.testing.expect(request.extra_datagrams.len != 0);
            try server_ptr.sendResponse(request.from, request.stream_id, .{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "pong split by dev sender",
            });
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
        .max_stream_frame_data = 7,
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "POST",
        .path = "/h3",
        .authority = "localhost",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "ping split by dev sender",
    });
    defer response.deinit(allocator);

    thread.join();
    if (shared.err) |err| return err;

    try std.testing.expectEqual(@as(u16, 200), response.response.status);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("pong split by dev sender", response.response.body);
}

test "HTTP/3 dev runtime assembles split STREAM request and response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("POST", request.request.method);
            try std.testing.expectEqualStrings("/split", request.request.path);
            try std.testing.expectEqualStrings("split request body", request.request.body);
            try std.testing.expectEqual(@as(u62, 0), request.stream_id);
            try std.testing.expect(request.extra_datagrams.len != 0);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
                .body = "split response body",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            const first = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }};
            const second = [_]quic.Frame{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }};
            try server_ptr.quic_server.sendFrames(request.from, &first);
            try server_ptr.quic_server.sendFrames(request.from, &second);
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var encoded_request: std.ArrayList(u8) = .empty;
    defer encoded_request.deinit(allocator);
    try (http3.Request{
        .method = "POST",
        .path = "/split",
        .authority = "localhost",
        .body = "split request body",
    }).write(&encoded_request, allocator);
    const split = encoded_request.items.len / 2;
    const first = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .data = encoded_request.items[0..split],
        .fin = false,
    } }};
    const second = [_]quic.Frame{.{ .stream = .{
        .stream_id = 0,
        .offset = split,
        .data = encoded_request.items[split..],
        .fin = true,
    } }};
    try client.quic_client.sendFrames(&first);
    try client.quic_client.sendFrames(&second);

    var assembled = try receiveRuntimeStreamBytes(&client.quic_client.endpoint, 0, client.limits.max_stream_buffer);
    defer assembled.deinit(allocator);
    try std.testing.expect(assembled.datagrams.len > 1);
    var response = try http3.decodeResponse(allocator, assembled.bytes);
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("split response body", response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev client assembles split STREAM response" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            runFallible(shared.server) catch |err| {
                shared.err = err;
            };
        }

        fn runFallible(server_ptr: *Server) !void {
            var request = try server_ptr.receiveRequest();
            defer request.deinit(server_ptr.quic_server.endpoint.allocator);
            try std.testing.expectEqualStrings("/split-response", request.request.path);

            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(server_ptr.quic_server.endpoint.allocator);
            try (http3.Response{
                .status = 200,
                .body = "client public API assembled this split response",
            }).write(&encoded, server_ptr.quic_server.endpoint.allocator);

            const mid = encoded.items.len / 2;
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = 0,
                .data = encoded.items[0..mid],
                .fin = false,
            } }});
            try server_ptr.quic_server.sendFrames(request.from, &.{.{ .stream = .{
                .stream_id = request.stream_id,
                .offset = mid,
                .data = encoded.items[mid..],
                .fin = true,
            } }});
        }
    };

    var shared = Shared{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client.deinit();

    var response = try client.request(.{
        .method = "GET",
        .path = "/split-response",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    try std.testing.expect(response.extra_datagrams.len != 0);
    try std.testing.expectEqualStrings("client public API assembled this split response", response.response.body);

    thread.join();
    if (shared.err) |err| return err;
}

test "HTTP/3 dev runtime enforces stream reassembly limit" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var receiver = try quic.runtime.Endpoint.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer receiver.deinit();
    var sender = try quic.runtime.Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, receiver.address(), .{
        .max_datagram_size = 4096,
        .max_frames_per_datagram = 8,
    });
    defer sender.deinit();

    try sender.sendFrames(&.{.{ .stream = .{
        .stream_id = 0,
        .offset = 32,
        .data = "too-far",
        .fin = true,
    } }});
    try std.testing.expectError(error.StreamBufferTooLarge, receiveRuntimeStreamBytes(&receiver, 0, 16));
}

test "HTTP/3 dev runtime receives requests with std.Io async batch" {
    const allocator = std.testing.allocator;

    var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
    defer threaded.deinit();
    const io = threaded.io();

    var server = try Server.bind(allocator, io, .{ .ip4 = .loopback(0) }, .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer server.deinit();

    const Shared = struct {
        server: *Server,
        batch: ?OwnedRequestBatch = null,
        err: ?anyerror = null,

        fn run(shared: *@This()) void {
            shared.batch = shared.server.receiveRequestsConcurrent(2) catch |err| {
                shared.err = err;
                return;
            };
        }
    };

    var shared = Shared{ .server = &server };
    const receiver = try std.Thread.spawn(.{}, Shared.run, .{&shared});

    var client_a = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_a.deinit();
    var client_b = try Client.connect(allocator, io, .{ .ip4 = .loopback(0) }, server.address(), .{
        .quic = .{ .max_datagram_size = 4096, .max_frames_per_datagram = 8 },
    });
    defer client_b.deinit();

    const req_a = http3.Request{ .method = "POST", .path = "/batch-a", .authority = "localhost", .body = "a" };
    const req_b = http3.Request{ .method = "POST", .path = "/batch-b", .authority = "localhost", .body = "b" };
    var encoded_a: std.ArrayList(u8) = .empty;
    defer encoded_a.deinit(allocator);
    var encoded_b: std.ArrayList(u8) = .empty;
    defer encoded_b.deinit(allocator);
    try req_a.write(&encoded_a, allocator);
    try req_b.write(&encoded_b, allocator);
    const frame_a = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_a.items, .fin = true } }};
    const frame_b = [_]quic.Frame{.{ .stream = .{ .stream_id = 0, .data = encoded_b.items, .fin = true } }};
    try client_a.quic_client.sendFrames(&frame_a);
    try client_b.quic_client.sendFrames(&frame_b);

    receiver.join();
    if (shared.err) |err| return err;
    var batch = shared.batch.?;
    defer batch.deinit();
    if (batch.firstError()) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), batch.receivedCount());

    var saw_a = false;
    var saw_b = false;
    for (batch.requests) |maybe_request| {
        const request = maybe_request.?;
        if (std.mem.eql(u8, request.request.path, "/batch-a")) saw_a = true;
        if (std.mem.eql(u8, request.request.path, "/batch-b")) saw_b = true;
    }
    try std.testing.expect(saw_a);
    try std.testing.expect(saw_b);
}

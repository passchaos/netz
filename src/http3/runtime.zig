const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");
const body_batch = @import("runtime/body_batch.zig");
const response_scheduler = @import("runtime/response_scheduler.zig");

const net = std.Io.net;

pub const InformationalResponseHead = http3.InformationalResponseHead;
pub const InformationalObserver = http3.InformationalObserver;

/// Reports a callback-scoped informational response together with the request
/// stream selected by `receiveNextResponseWithInformational`. The header
/// fields borrow decoder storage and must not be retained after the callback.
pub const MultiplexedInformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        stream_id: u62,
        response: InformationalResponseHead,
    ) void,
};

/// Reports a callback-scoped pushed informational response with every identity
/// needed to correlate it to both the PUSH_PROMISE and its QUIC stream.
pub const PushInformationalObserver = struct {
    context: *anyopaque,
    on_response: *const fn (
        context: *anyopaque,
        push_id: u64,
        request_stream_id: u62,
        stream_id: u62,
        response: InformationalResponseHead,
    ) void,
};

const MultiplexedInformationalContext = struct {
    observer: MultiplexedInformationalObserver,
    stream_id: u62,

    fn notify(
        context: *anyopaque,
        response: InformationalResponseHead,
    ) void {
        const self: *@This() = @ptrCast(@alignCast(context));
        self.observer.on_response(
            self.observer.context,
            self.stream_id,
            response,
        );
    }
};

pub const Error = http3.Error || quic.runtime.Error || quic.handshake.Error || quic.one_rtt.Error || quic.stream_state.Error || net.HostName.ValidateError || net.HostName.LookupError || error{
    MissingStreamFrame,
    UnexpectedStream,
    GoAwayReceived,
    RequestRejected,
    ClosedCriticalStream,
    InvalidUri,
    InvalidAlpn,
};

const client_control_stream_id: u62 = 2;
const client_qpack_encoder_stream_id: u62 = 6;
const client_qpack_decoder_stream_id: u62 = 10;
const server_control_stream_id: u62 = 3;
const server_qpack_encoder_stream_id: u62 = 7;
const server_qpack_decoder_stream_id: u62 = 11;
const first_server_push_stream_id: u62 = 15;
const response_scheduler_stack_capacity: usize = 16;

/// Reusable storage for one HTTP/3 request-stream send operation.
///
/// The HTTP/3 session APIs serialize writes through mutable session ownership.
/// Handshake connections copy protected payloads into recovery-owned storage,
/// while the preconfigured-key runtime protects and submits each datagram
/// synchronously. Consequently both the encoded message bytes and their
/// borrowing STREAM frame descriptors may be cleared as soon as send returns.
const StreamMessageSendScratch = struct {
    encoded: std.ArrayList(u8) = .empty,
    frames: std.ArrayList(quic.Frame) = .empty,

    fn reset(self: *StreamMessageSendScratch) void {
        self.encoded.clearRetainingCapacity();
        self.frames.clearRetainingCapacity();
    }

    fn deinit(
        self: *StreamMessageSendScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.frames.deinit(allocator);
        self.encoded.deinit(allocator);
        self.* = undefined;
    }
};

/// Reusable storage for one server-push operation.
///
/// PUSH_PROMISE plus the parent response and the pushed response must coexist:
/// STREAM descriptors borrow both byte ranges until QUIC has copied/protected
/// them. Keeping two independent encoded lists preserves that lifetime while
/// still allowing every later push on the serialized session API to reuse all
/// three allocations.
const PushSendScratch = struct {
    parent: std.ArrayList(u8) = .empty,
    pushed: std.ArrayList(u8) = .empty,
    frames: std.ArrayList(quic.Frame) = .empty,

    fn reset(self: *PushSendScratch) void {
        self.parent.clearRetainingCapacity();
        self.pushed.clearRetainingCapacity();
        self.frames.clearRetainingCapacity();
    }

    fn deinit(
        self: *PushSendScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.frames.deinit(allocator);
        self.pushed.deinit(allocator);
        self.parent.deinit(allocator);
        self.* = undefined;
    }
};

/// Independent construction storage for HTTP/3 control and QPACK streams.
///
/// Request/response/Push encodings stay live while encoder instructions are
/// emitted first, so critical-stream sends cannot safely reuse either message
/// scratch. The resulting STREAM views are needed only until `Connection.send`
/// copies them into its packet and recovery storage.
const CriticalStreamSendScratch = struct {
    payload: std.ArrayList(u8) = .empty,
    frames: std.ArrayList(quic.Frame) = .empty,

    fn reset(self: *CriticalStreamSendScratch) void {
        self.payload.clearRetainingCapacity();
        self.frames.clearRetainingCapacity();
    }

    fn deinit(
        self: *CriticalStreamSendScratch,
        allocator: std.mem.Allocator,
    ) void {
        self.frames.deinit(allocator);
        self.payload.deinit(allocator);
        self.* = undefined;
    }
};

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

/// Build the HTTP/3 origin-form request target from a parsed HTTPS URI.
///
/// The returned allocation preserves the URI's raw/percent-encoded path and
/// query bytes while deliberately excluding fragments, which are not sent in
/// HTTP requests.
pub fn uriRequestTargetAlloc(
    allocator: std.mem.Allocator,
    uri: std.Uri,
) Error![]u8 {
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
    /// Control and QPACK STREAM descriptors borrow these bytes until packet
    /// protection finishes. Keep them separate from the wire payload scratch,
    /// which is overwritten while serializing those same descriptors.
    critical_stream_payload: std.ArrayList(u8) = .empty,
    critical_stream_frames: std.ArrayList(quic.Frame) = .empty,
    payload_scratch: std.ArrayList(u8) = .empty,
    packet_scratch: std.ArrayList(u8) = .empty,

    fn init(allocator: std.mem.Allocator) ProtectedSendState {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *ProtectedSendState) void {
        self.payload_scratch.deinit(self.allocator);
        self.packet_scratch.deinit(self.allocator);
        self.critical_stream_frames.deinit(self.allocator);
        self.critical_stream_payload.deinit(self.allocator);
        self.* = undefined;
    }

    fn resetCriticalStreamScratch(self: *ProtectedSendState) void {
        self.critical_stream_payload.clearRetainingCapacity();
        self.critical_stream_frames.clearRetainingCapacity();
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

            // The batch-into API is allocation-free for one packet as well as
            // many. Reusing its exact payload/packet storage avoids two heap
            // allocations on the latency-sensitive single-datagram path.
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

    fn visit(
        self: *ConnectionPacketCursor,
        connection: *quic.one_rtt.Connection,
        context: anytype,
        comptime visitor: *const fn (
            @TypeOf(context),
            quic.one_rtt.ReceivedPacketView,
        ) Error!void,
    ) Error!void {
        if (self.ack_pending) {
            try connection.sendAck(0);
            self.ack_pending = false;
        }
        if (self.batch) |*batch| {
            if (batch.takeNext()) |packet_value| {
                var packet = packet_value;
                defer packet.deinit(connection.endpoint.allocator);
                return visitor(context, packetView(packet));
            }
            batch.deinit();
            self.batch = null;
        }
        if (!connection.endpoint.groReceiveEnabled()) {
            const Context = @TypeOf(context);
            const AdapterContext = struct {
                cursor: *ConnectionPacketCursor,
                connection: *quic.one_rtt.Connection,
                context: Context,
            };
            const Adapter = struct {
                fn visit(
                    adapter: *AdapterContext,
                    packet: quic.one_rtt.ReceivedPacketView,
                ) Error!void {
                    _ = adapter.connection.sendAckForPacketIfNeeded(
                        packet.packet_number,
                        packet.frames,
                    ) catch {
                        // QUIC and HTTP/3 state already accepted the packet. A
                        // cumulative ACK can be retried before the next receive
                        // without manufacturing packet ownership for recovery.
                        adapter.cursor.ack_pending = true;
                    };
                    try visitor(adapter.context, packet);
                }
            };
            var adapter: AdapterContext = .{
                .cursor = self,
                .connection = connection,
                .context = context,
            };
            return connection.visitPacketServicingTimers(
                &adapter,
                Adapter.visit,
            );
        }
        var batch = try connection.receivePacketBatchServicingTimers();
        errdefer batch.deinit();
        _ = connection.sendAckForPacketsIfNeeded(
            batch.packets[batch.next_index..],
        ) catch {
            self.ack_pending = true;
        };
        var packet = batch.takeNext() orelse return error.MissingStreamFrame;
        defer packet.deinit(connection.endpoint.allocator);
        self.batch = batch;
        return visitor(context, packetView(packet));
    }
};

fn packetView(packet: quic.one_rtt.ReceivedPacket) quic.one_rtt.ReceivedPacketView {
    return .{
        .from = packet.from,
        .packet_number = packet.packet.packet_number,
        .frames = packet.frames,
        .peer_initiated_key_update = packet.peer_initiated_key_update,
    };
}

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
    /// Maximum number of 1xx response heads accepted on one request or push
    /// stream before the final response. The bound applies in aggregate and
    /// incremental modes even when the application ignores those heads. This
    /// is configurable rather than quic-go's hard-coded limit of five.
    max_informational_responses: usize =
        http3.default_max_informational_responses,
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

/// A peer request-stream receiver abandoned the response direction.
///
/// HTTP/3 clients express this with QUIC STOP_SENDING, most commonly using
/// H3_REQUEST_CANCELLED when a response body is closed before EOF. Keeping the
/// stream ID and application code avoids collapsing peer cancellation into a
/// generic write failure in multiplexed servers.
pub const PeerResponseCancellation = struct {
    stream_id: u62,
    application_error_code: u64,
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
    informational: []const http3.InformationalResponse = &.{},
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
    informational_count: usize = 0,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
    response_request_method: ?[]const u8 = null,
    response_extended_connect: bool = false,
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
        return initResponseWithInformationalLimit(
            allocator,
            stream_id,
            max_buffered,
            settings,
            http3.default_max_informational_responses,
        );
    }

    pub fn initResponseWithInformationalLimit(
        allocator: std.mem.Allocator,
        stream_id: u64,
        max_buffered: usize,
        settings: http3.Settings,
        max_informational_responses: usize,
    ) StreamingMessageReader {
        return .{
            .allocator = allocator,
            .receive = .init(allocator, stream_id, max_buffered),
            .settings = settings,
            .kind = .response,
            .push_promises_allowed = true,
            .max_informational_responses = max_informational_responses,
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
                                try http3.applyResponseHeadRequestSemantics(
                                    &head,
                                    self.response_request_method,
                                    self.response_extended_connect,
                                );
                                head.consumed =
                                    header.header_length +
                                    header.payload_length;
                                final_head = head.status >= 200;
                                if (!final_head) {
                                    self.informational_count = std.math.add(
                                        usize,
                                        self.informational_count,
                                        1,
                                    ) catch {
                                        head.deinit(self.allocator);
                                        return error.TooManyInformationalResponses;
                                    };
                                    if (self.informational_count >
                                        self.max_informational_responses)
                                    {
                                        head.deinit(self.allocator);
                                        return error.TooManyInformationalResponses;
                                    }
                                }
                                if (final_head) {
                                    self.content_length = if (head.body_allowed)
                                        head.content_length
                                    else
                                        null;
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
    /// Number of not-yet-decodable field sections on each request/push stream.
    /// QPACK limits potentially blocked streams, not individual sections, so
    /// multiple interim/final/trailer sections share one budget slot.
    blocked_section_counts: std.AutoHashMapUnmanaged(u64, usize) = .empty,
    encoder_instructions: std.ArrayList(u8) = .empty,
    decoder_stream: ?quic.stream_state.RecvState = null,
    decoder_stream_type_received: bool = false,
    peer_max_capacity: ?usize = null,
    peer_max_blocked_streams: ?u64 = null,
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
            .peer_max_blocked_streams = 0,
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
        self.blocked_section_counts.deinit(self.allocator);
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
        return self.configurePeerLimits(capacity, 0);
    }

    /// Bind the encoder once to the peer's immutable QPACK SETTINGS.
    ///
    /// Before SETTINGS arrives the encoder uses literals. Afterwards it may
    /// reference unacknowledged inserts only while doing so keeps the number of
    /// potentially blocked streams within the peer-advertised limit.
    pub fn configurePeerLimits(
        self: *QpackEncodeState,
        capacity: usize,
        max_blocked_streams: u64,
    ) http3.Error!void {
        if (max_blocked_streams >
            http3.Settings.max_supported_qpack_blocked_streams)
        {
            return error.QpackEncoderStreamError;
        }
        if (self.peer_max_capacity) |configured_capacity| {
            if (configured_capacity != capacity or
                self.peer_max_blocked_streams.? != max_blocked_streams)
            {
                return error.QpackEncoderStreamError;
            }
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
        self.peer_max_blocked_streams = max_blocked_streams;
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
        const reference_limit = if (self.mayRiskBlockedStream(stream_id))
            self.table.insert_count
        else
            self.known_received_count;
        try http3.Qpack.encodeDynamicBlockWithReferenceLimit(
            list,
            self.allocator,
            fields,
            self.table,
            reference_limit,
            &references,
        );
        if (references.items.len == 0) {
            references.deinit(self.allocator);
            return;
        }

        const owned = try references.toOwnedSlice(self.allocator);
        errdefer self.allocator.free(owned);
        const required_insert_count = maxReferencedInsertCount(owned);
        const potentially_blocked =
            required_insert_count > self.known_received_count;
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
        if (potentially_blocked and
            !self.blocked_section_counts.contains(stream_id))
        {
            // At most one new map slot is needed for a new blocked stream,
            // even when several sections on that stream reference inserts.
            try self.blocked_section_counts.ensureUnusedCapacity(
                self.allocator,
                1,
            );
        }
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
            .required_insert_count = required_insert_count,
            .references = owned,
        });
        if (!pending_slot.found_existing) {
            pending_slot.value_ptr.* = pending_index;
        }
        if (potentially_blocked) {
            const blocked = self.blocked_section_counts
                .getOrPutAssumeCapacity(stream_id);
            if (!blocked.found_existing) blocked.value_ptr.* = 0;
            blocked.value_ptr.* += 1;
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
                self.rebuildBlockedSectionCounts();
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
                self.rebuildBlockedSectionCounts();
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
        if (section.required_insert_count > self.known_received_count) {
            const blocked = self.blocked_section_counts
                .getPtr(section.stream_id).?;
            blocked.* -= 1;
            if (blocked.* == 0) {
                _ = self.blocked_section_counts.remove(section.stream_id);
            }
        }
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

    fn mayRiskBlockedStream(
        self: QpackEncodeState,
        stream_id: u64,
    ) bool {
        if (self.known_received_count >= self.table.insert_count) return false;
        const limit = self.peer_max_blocked_streams orelse return false;
        if (limit == 0) return false;
        if (self.blocked_section_counts.contains(stream_id)) return true;
        return self.blocked_section_counts.count() < limit;
    }

    fn rebuildBlockedSectionCounts(self: *QpackEncodeState) void {
        self.blocked_section_counts.clearRetainingCapacity();
        for (self.pending_sections.items) |section| {
            if (section.required_insert_count <= self.known_received_count) {
                continue;
            }
            const blocked = self.blocked_section_counts
                .getOrPutAssumeCapacity(section.stream_id);
            if (!blocked.found_existing) blocked.value_ptr.* = 0;
            blocked.value_ptr.* += 1;
        }
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
    request_receive_mutex: std.Io.Mutex = .init,
    request_streams: DevelopmentRequestStreamSet,
    response_send_mutex: std.Io.Mutex = .init,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{
            .quic_server = try .bind(allocator, io, bind_address, limits.quic),
            .limits = limits,
            .request_streams = .init(
                allocator,
                limits.max_stream_buffer,
                limits.max_concurrent_request_streams,
            ),
        };
    }

    pub fn deinit(self: *Server) void {
        self.request_streams.deinit();
        self.quic_server.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.quic_server.address();
    }

    pub fn receiveRequest(self: *Server) Error!OwnedRequest {
        self.request_receive_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.request_receive_mutex.unlock(self.quic_server.endpoint.io);

        var assembled = while (true) {
            if (try self.request_streams.takeReady()) |ready| break ready;
            var datagram = try self.quic_server.receive();
            var owned = true;
            defer if (owned) datagram.deinit(
                self.quic_server.endpoint.allocator,
            );
            if (try self.request_streams.insertDatagram(&datagram)) {
                owned = false;
            }
        };
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
        var batch = try OwnedRequestBatch.init(
            self.quic_server.endpoint.allocator,
            count,
        );
        errdefer batch.deinit();

        for (batch.requests, batch.errors) |*request, *err_slot| {
            const task = RequestTask{
                .server = self,
                .request = request,
                .err = err_slot,
            };
            group.async(self.quic_server.endpoint.io, RequestTask.run, .{task});
        }

        try group.await(self.quic_server.endpoint.io);
        return batch;
    }

    /// Receive, handle, and respond to exactly `count` requests with bounded
    /// concurrency. Each worker owns one request for the whole callback/send
    /// cycle, while the returned result retains that request so callers can
    /// correlate handler or transport failures with peer and stream metadata.
    ///
    /// The same `context` may be entered concurrently. Applications that
    /// mutate it must provide their own synchronization. The `OwnedRequest`
    /// passed by value is borrowed from the result: the handler must not
    /// deinitialize it or retain slices after the result is deinitialized.
    pub fn serveConcurrent(
        self: *Server,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!http3.Response,
        count: usize,
    ) Error!ConcurrentServeResult {
        var group: std.Io.Group = .init;
        var result = try OwnedRequestBatch.init(
            self.quic_server.endpoint.allocator,
            count,
        );
        errdefer result.deinit();

        for (result.requests, result.errors) |*request, *err_slot| {
            const task = ServeRequestTask(HandlerContext){
                .server = self,
                .context = context,
                .handler = handler,
                .request = request,
                .err = err_slot,
            };
            group.async(
                self.quic_server.endpoint.io,
                ServeRequestTask(HandlerContext).run,
                .{task},
            );
        }

        try group.await(self.quic_server.endpoint.io);
        return result;
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
        // A response may span several UDP datagrams. Keep its STREAM frames
        // contiguous on the shared development endpoint and protect mutable
        // send-interceptor state from concurrent serving workers.
        self.response_send_mutex.lockUncancelable(
            self.quic_server.endpoint.io,
        );
        defer self.response_send_mutex.unlock(self.quic_server.endpoint.io);
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

fn ServeRequestTask(comptime HandlerContext: type) type {
    return struct {
        server: *Server,
        context: *HandlerContext,
        handler: *const fn (
            *HandlerContext,
            OwnedRequest,
        ) Error!http3.Response,
        request: *?OwnedRequest,
        err: *?anyerror,

        fn run(task: @This()) std.Io.Cancelable!void {
            task.request.* = task.server.receiveRequest() catch |err| {
                task.err.* = err;
                return;
            };
            const request = task.request.*.?;
            var response = task.handler(task.context, request) catch |err| {
                task.err.* = err;
                return;
            };
            if (response.request_method == null) {
                response.request_method = request.request.method;
                response.extended_connect = requestHasProtocol(
                    request.request.headers,
                );
            }
            task.server.sendResponse(
                request.from,
                request.stream_id,
                response,
            ) catch |err| {
                task.err.* = err;
                return;
            };
            task.err.* = null;
        }
    };
}

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
        return self.requestWithInformational(request_options, null);
    }

    /// Send a development-runtime request and report each borrowed 1xx head.
    pub fn requestWithInformational(
        self: *Client,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedResponse {
        const stream_id = self.next_stream_id;
        self.next_stream_id += 4; // client-initiated bidirectional stream ids.

        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(self.quic_client.endpoint.allocator);
        try request_options.write(&encoded, self.quic_client.endpoint.allocator);

        try sendRuntimeStreamMessage(&self.quic_client.endpoint, self.quic_client.peer, stream_id, encoded.items, self.limits.max_stream_frame_data);

        var assembled = try receiveRuntimeStreamBytes(&self.quic_client.endpoint, stream_id, self.limits.max_stream_buffer);
        errdefer assembled.deinit(self.quic_client.endpoint.allocator);
        try http3.validateResponsePushPromises(.{}, assembled.bytes);
        var response = try http3.decodeResponseWithOptions(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            .{
                .max_informational_responses = self.limits.max_informational_responses,
                .informational = informational,
                .request_method = request_options.method,
                .extended_connect = requestHasProtocol(
                    request_options.headers,
                ),
            },
        );
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

/// Cleartext development-runtime request assembly keyed by both peer address
/// and stream ID. UDP clients all start at stream zero, so the stream ID alone
/// cannot identify a request when one server endpoint serves several peers.
/// The server serializes mutation of this set but releases the lock before
/// invoking application handlers.
const DevelopmentRequestStreamSet = struct {
    const Entry = struct {
        from: net.IpAddress,
        receive: quic.stream_state.RecvState,
        datagrams: std.ArrayList(quic.runtime.OwnedDatagram) = .empty,

        fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
            self.receive.deinit();
            for (self.datagrams.items) |*datagram| {
                datagram.deinit(allocator);
            }
            self.datagrams.deinit(allocator);
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    max_stream_buffer: usize,
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) DevelopmentRequestStreamSet {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    fn deinit(self: *DevelopmentRequestStreamSet) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    /// Insert every request/response STREAM frame from one datagram. Returns
    /// whether ownership of the datagram moved into a request entry. The dev
    /// framing used here emits one stream per datagram, but rejecting a second
    /// relevant stream prevents ambiguous ownership if a caller crafts one.
    fn insertDatagram(
        self: *DevelopmentRequestStreamSet,
        datagram: *quic.runtime.OwnedDatagram,
    ) Error!bool {
        var selected_stream_id: ?u62 = null;
        for (datagram.frames) |frame| {
            if (frame != .stream) continue;
            switch (try messageStreamDisposition(frame.stream.stream_id)) {
                .ignore => continue,
                .request_response => {},
            }
            const stream_id: u62 = @intCast(frame.stream.stream_id);
            if (selected_stream_id) |selected| {
                if (selected != stream_id) return error.UnexpectedStream;
            } else {
                selected_stream_id = stream_id;
            }
            const entry = try self.getOrCreate(
                datagram.from,
                stream_id,
            );
            entry.receive.insert(frame.stream) catch |err| {
                self.discard(datagram.from, stream_id);
                return err;
            };
        }
        const stream_id = selected_stream_id orelse return false;
        const entry = self.find(datagram.from, stream_id).?;
        entry.datagrams.append(self.allocator, datagram.*) catch |err| {
            // Without the diagnostic/ownership datagram, a completed request
            // cannot satisfy OwnedRequest's non-empty datagram invariant.
            self.discard(datagram.from, stream_id);
            return err;
        };
        return true;
    }

    fn takeReady(
        self: *DevelopmentRequestStreamSet,
    ) Error!?RuntimeAssembledStream {
        for (self.entries.items, 0..) |*entry, index| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;

            const bytes = try self.allocator.dupe(
                u8,
                entry.receive.buffer.items[0..final_size],
            );
            errdefer self.allocator.free(bytes);
            const datagrams = try entry.datagrams.toOwnedSlice(self.allocator);
            const from = entry.from;
            const stream_id: u62 = @intCast(entry.receive.stream_id);
            entry.receive.deinit();
            _ = self.entries.swapRemove(index);
            return .{
                .from = from,
                .stream_id = stream_id,
                .bytes = bytes,
                .datagrams = datagrams,
            };
        }
        return null;
    }

    fn getOrCreate(
        self: *DevelopmentRequestStreamSet,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!*Entry {
        if (self.find(from, stream_id)) |entry| return entry;
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.append(self.allocator, .{
            .from = from,
            .receive = .init(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
            ),
        });
        return &self.entries.items[self.entries.items.len - 1];
    }

    fn find(
        self: *DevelopmentRequestStreamSet,
        from: net.IpAddress,
        stream_id: u62,
    ) ?*Entry {
        for (self.entries.items) |*entry| {
            if (entry.receive.stream_id == stream_id and
                entry.from.eql(&from)) return entry;
        }
        return null;
    }

    fn discard(
        self: *DevelopmentRequestStreamSet,
        from: net.IpAddress,
        stream_id: u62,
    ) void {
        for (self.entries.items, 0..) |*entry, index| {
            if (entry.receive.stream_id != stream_id or
                !entry.from.eql(&from)) continue;
            entry.deinit(self.allocator);
            _ = self.entries.swapRemove(index);
            return;
        }
    }
};

pub const OwnedRequestBatch = struct {
    allocator: std.mem.Allocator,
    requests: []?OwnedRequest,
    errors: []?anyerror,

    fn init(
        allocator: std.mem.Allocator,
        count: usize,
    ) std.mem.Allocator.Error!OwnedRequestBatch {
        const requests = try allocator.alloc(?OwnedRequest, count);
        errdefer allocator.free(requests);
        @memset(requests, null);
        const errors = try allocator.alloc(?anyerror, count);
        @memset(errors, null);
        return .{
            .allocator = allocator,
            .requests = requests,
            .errors = errors,
        };
    }

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

    /// Number of workers that received a request, completed the handler, and
    /// sent the response. For a receive-only batch this is the number of
    /// successfully decoded requests.
    pub fn successCount(self: OwnedRequestBatch) usize {
        var count: usize = 0;
        for (self.errors) |err| {
            if (err == null) count += 1;
        }
        return count;
    }
};

/// Bounded serving keeps the decoded requests alongside per-worker errors so
/// callers can inspect failures without losing the request that caused them.
pub const ConcurrentServeResult = OwnedRequestBatch;

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

/// Options for the preconfigured-key protected HTTP/3 runtime.
///
/// This runtime intentionally bypasses the integrated QUIC handshake and does
/// not own a full `one_rtt.Connection`; it is best suited for deterministic
/// packet-protection, QPACK, and HTTP/3 stream-state tests.  Use the
/// handshake-backed runtime for production-like large transfers that require
/// complete QUIC recovery, pacing, and flow-control feedback loops.
pub const ProtectedConfig = struct {
    receive_keys: quic.protection.PacketProtectionKeys,
    send_keys: quic.protection.PacketProtectionKeys,
    local_connection_id: []const u8,
    peer_connection_id: []const u8,
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    /// Maximum retained bytes for one protected HTTP/3 streaming reader. This
    /// is a local memory bound for the lightweight runtime, not a replacement
    /// for full QUIC receive-window negotiation.
    max_stream_buffer: usize = 64 * 1024,
    /// Optional peer receive window for protected streaming body senders.
    ///
    /// A real QUIC handshake exchanges transport parameters and `MAX_STREAM_DATA`
    /// frames through `one_rtt.Connection`.  The preconfigured-key runtime has
    /// no transport-parameter handshake, so callers that want deterministic
    /// small-window streaming can seed the peer window explicitly here.
    peer_stream_flow_window: ?usize = null,
    max_stream_frame_data: usize = 1200,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
};

pub const HandshakeSessionOptions = struct {
    local_settings: http3.Settings = .{},
    max_frames_per_packet: usize = 8,
    max_stream_buffer: usize = 64 * 1024,
    max_concurrent_request_streams: usize = 128,
    max_stream_frame_data: usize = 1200,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
    /// Maximum HTTP/3 DATA bytes one paced helper attempt may hand to QUIC.
    ///
    /// The default remains conservative for callers using the standard 1200B
    /// path MTU. Loopback/high-throughput callers can raise this together with
    /// `max_stream_frame_data`, `max_frames_per_packet`, and the handshake
    /// one_rtt max datagram size to reduce ACK/flow-control pump iterations.
    paced_body_chunk_bytes: usize = 1024,
    /// Experimental DATA-frame send path that emits the DATA prefix from
    /// per-packet scratch and borrows immutable application body slices until
    /// QUIC takes stable recovery ownership. Multi-stream batches keep one
    /// prefix buffer per packet, so their descriptors do not alias.
    enable_data_prefix_fast_path: bool = false,
    /// Optional delay after this many socket-visible response body bytes.
    ///
    /// A zero byte threshold disables the delay. Production event loops should
    /// leave both fields at zero and resume sends from their normal writable or
    /// timer callbacks. Same-process loopback workloads using jumbo UDP
    /// datagrams may set them so the peer thread periodically drains a small
    /// kernel receive queue without delaying every packet-sized scheduler pass.
    response_scheduler_batch_delay_bytes: usize = 0,
    /// Optional delay after this many socket-visible response DATA packets.
    ///
    /// Packet-count pacing is preferable for same-process benchmarks because
    /// it stays stable when the DATA chunk size changes. Either threshold may
    /// be enabled; reaching the first one resets both counters.
    response_scheduler_batch_delay_packets: usize = 0,
    response_scheduler_batch_delay_ns: u64 = 0,
    /// Maximum number of independently prioritized response streams submitted
    /// in one transport batch. One preserves sequential UDP writes while still
    /// rotating incremental streams; larger values enable sendmmsg/GSO-style
    /// cross-stream batches on hosts with suitably sized receive queues.
    response_scheduler_max_batch_packets: usize =
        quic.one_rtt.max_batch_packets,
};

pub const BodyChunk = body_batch.Chunk;
pub const ResponseBody = body_batch.ResponseBody;

fn responseBodyIndex(
    responses: []const ResponseBody,
    stream_id: u62,
) ?usize {
    for (responses, 0..) |response, index| {
        if (response.stream_id == stream_id) return index;
    }
    return null;
}

fn stackFirstSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    stack: []T,
    len: usize,
) std.mem.Allocator.Error![]T {
    if (len <= stack.len) return stack[0..len];
    return allocator.alloc(T, len);
}

fn freeStackFirstSlice(
    comptime T: type,
    allocator: std.mem.Allocator,
    stack: []T,
    storage: []T,
) void {
    if (storage.ptr != stack.ptr) allocator.free(storage);
}

/// Narrow white-box surface for runtime tests kept in focused modules.
pub const testing = struct {
    pub const response_scheduler_test_stack_capacity =
        response_scheduler_stack_capacity;

    pub fn stackFirstSliceForTest(
        comptime T: type,
        allocator: std.mem.Allocator,
        stack: []T,
        len: usize,
    ) std.mem.Allocator.Error![]T {
        return stackFirstSlice(T, allocator, stack, len);
    }

    pub fn freeStackFirstSliceForTest(
        comptime T: type,
        allocator: std.mem.Allocator,
        stack: []T,
        storage: []T,
    ) void {
        freeStackFirstSlice(T, allocator, stack, storage);
    }
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
        return HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
    }

    /// Accept from a client Initial already received/classified by the shared
    /// QUIC endpoint dispatcher. This prevents the HTTP/3 accept path from
    /// performing a second read for the first datagram.
    pub fn acceptFromInitial(
        self: *HandshakeServer,
        initial: *quic.endpoint_dispatcher.Event,
    ) Error!HandshakeServerSession {
        return self.acceptFromInitialSource(
            .fromEndpoint(&self.quic_server.endpoint),
            initial,
        );
    }

    /// Accept a dispatcher-owned Initial while receiving every later QUIC
    /// handshake datagram from an injected source. A shared endpoint uses a
    /// bounded pending-handshake inbox here so this worker never competes with
    /// the endpoint's sole UDP receive owner.
    pub fn acceptFromInitialSource(
        self: *HandshakeServer,
        source: quic.runtime.DatagramSource,
        initial: *quic.endpoint_dispatcher.Event,
    ) Error!HandshakeServerSession {
        const datagram = initial.takeNewInitial() orelse
            return error.InvalidHandshakeFlight;
        var established = try quic.handshake.acceptFromInitialSource(
            &self.quic_server.endpoint,
            source,
            datagram,
            self.handshake_options,
        );
        errdefer established.deinit();
        return HandshakeServerSession.initEstablished(
            established,
            self.session_options,
        );
    }

    /// Accept one authenticated QUIC connection and serve up to
    /// `max_requests` HTTP/3 requests on it. The handler runs serially because
    /// a `HandshakeServerSession` owns one mutable QUIC/QPACK state machine;
    /// multiplexed applications that need independent scheduling can retain
    /// the lower-level request-event APIs.
    pub fn serveConnection(
        self: *HandshakeServer,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
        max_requests: usize,
    ) Error!usize {
        var session = try self.accept();
        defer session.deinit();
        return session.serve(
            HandlerContext,
            context,
            handler,
            max_requests,
        );
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
    stream_send_scratch: StreamMessageSendScratch = .{},
    push_send_scratch: PushSendScratch = .{},
    critical_stream_send_scratch: CriticalStreamSendScratch = .{},
    sent_push_ids: std.ArrayList(u64) = .empty,
    peer_promised_push_ids: std.ArrayList(u64) = .empty,
    next_push_stream_id: u62 = first_server_push_stream_id,

    pub fn initEstablished(
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
    ) Error!HandshakeServerSession {
        if (!http3.isHttp3Alpn(established.alpn)) return error.InvalidAlpn;
        const max_capacity = std.math.cast(
            usize,
            options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        const allocator = established.connection.endpoint.allocator;
        return .{
            .established = established,
            .options = options,
            .qpack_decode = .init(
                allocator,
                max_capacity,
                options.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                options.max_stream_buffer,
            ),
            .request_streams = .init(
                allocator,
                options.max_stream_buffer,
                options.max_concurrent_request_streams,
            ),
            .streaming_requests = .init(
                allocator,
                options.max_concurrent_request_streams,
                options.max_stream_buffer,
                options.local_settings,
                .request,
            ),
            .request_lifecycle = .init(allocator),
            .outbound_bodies = .init(
                allocator,
                options.max_concurrent_request_streams,
            ),
        };
    }

    pub fn initPreconfigured(
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        options: HandshakeSessionOptions,
        transport: quic.handshake.PreconfiguredConnectionOptions,
    ) Error!HandshakeServerSession {
        try validateBlockedStreamLimit(
            options.local_settings,
            options.max_concurrent_request_streams,
        );
        var established = try quic.handshake.establishPreconfigured(
            endpoint,
            peer,
            .server,
            transport,
        );
        errdefer established.deinit();
        return initEstablished(established, options);
    }

    /// Reserve one server-initiated unidirectional stream ID.
    ///
    /// HTTP/3 push streams and WebTransport unidirectional streams share this
    /// QUIC ID space. Keeping allocation here prevents sibling protocol
    /// adapters from independently selecting the same stream.
    pub fn reserveServerUnidirectionalStreamId(
        self: *HandshakeServerSession,
    ) Error!u62 {
        const stream_id = self.next_push_stream_id;
        self.next_push_stream_id = std.math.add(
            u62,
            stream_id,
            4,
        ) catch return error.StreamCreationError;
        return stream_id;
    }

    /// Advertise local HTTP/3 settings before waiting for a request.
    ///
    /// Some event-driven clients wait for the server control stream before
    /// opening their first extended CONNECT. Ordinary request/response calls
    /// invoke the same idempotent helper automatically, while protocol
    /// adapters can use this to avoid a peer-settings/request deadlock.
    pub fn ensureSettingsSent(self: *HandshakeServerSession) Error!void {
        try sendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
    }

    pub fn deinit(self: *HandshakeServerSession) void {
        self.critical_stream_send_scratch.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.push_send_scratch.deinit(
            self.established.connection.endpoint.allocator,
        );
        self.stream_send_scratch.deinit(
            self.established.connection.endpoint.allocator,
        );
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

    pub fn negotiatedAlpn(self: HandshakeServerSession) []const u8 {
        return self.established.alpn;
    }

    pub fn negotiatedCipherSuite(
        self: HandshakeServerSession,
    ) quic.tls.cipher_suite.Suite {
        return self.established.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: HandshakeServerSession,
    ) quic.tls.secret.Hash {
        return self.established.negotiatedTranscriptHash();
    }

    pub fn peerCertificates(
        self: *const HandshakeServerSession,
    ) ?[]const []const u8 {
        return self.established.peerCertificates();
    }

    pub fn exportKeyingMaterial(
        self: *const HandshakeServerSession,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.established.exportKeyingMaterial(label, context, out);
    }

    pub fn initiateKeyUpdate(self: *HandshakeServerSession) Error!void {
        try self.established.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: HandshakeServerSession) u64 {
        return self.established.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: HandshakeServerSession) u64 {
        return self.established.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: HandshakeServerSession) bool {
        return self.established.keyUpdateAwaitingAck();
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
        try self.request_lifecycle.markReceived(
            assembled.stream_id,
            requestPriority(request.headers),
        );
        try self.sendQpackFeedback();
        return .{
            .from = assembled.from,
            .stream_id = assembled.stream_id,
            .stream_bytes = assembled.bytes,
            .request = request,
        };
    }

    /// Receive one complete request, invoke the handler, and send its complete
    /// response. Request storage remains valid for the duration of the handler
    /// and is released after the response has been copied into QUIC recovery
    /// storage. Use the streaming APIs for bodies that should not be aggregated.
    pub fn serveOne(
        self: *HandshakeServerSession,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
    ) Error!u62 {
        var request = try self.receiveRequest();
        defer request.deinit(
            self.established.connection.endpoint.allocator,
        );
        var response = try handler(context, request);
        if (response.request_method == null) {
            response.request_method = request.request.method;
            response.extended_connect = requestHasProtocol(
                request.request.headers,
            );
        }
        try self.sendResponsePaced(request.stream_id, response);
        return request.stream_id;
    }

    /// Serve a bounded number of requests on one authenticated connection and
    /// then send the two-phase HTTP/3 GOAWAY sequence. Existing accepted
    /// requests finish normally; a peer cannot start a later request stream
    /// after the final GOAWAY identifier.
    pub fn serve(
        self: *HandshakeServerSession,
        comptime HandlerContext: type,
        context: *HandlerContext,
        comptime handler: *const fn (
            *HandlerContext,
            OwnedHandshakeRequest,
        ) Error!http3.Response,
        max_requests: usize,
    ) Error!usize {
        if (max_requests == 0) return 0;
        var served: usize = 0;
        while (served < max_requests) : (served += 1) {
            _ = try self.serveOne(HandlerContext, context, handler);
        }
        // Announce graceful shutdown only after the bounded loop has accepted
        // its last request. Sending the maximum-ID GOAWAY up front is useful
        // for externally-triggered shutdown, but may legitimately cause a
        // client to stop creating requests before this convenience loop has
        // reached its caller-selected count.
        try self.initiateShutdown();
        try self.completeShutdown();
        return served;
    }

    /// Poll one event from any multiplexed request stream without aggregating
    /// DATA payloads. The returned stream ID is then used with
    /// `readRequestData`, matching tquic's poll/recv_body split while retaining
    /// netz's owned decoded heads and dynamic trailers.
    pub fn receiveRequestEvent(
        self: *HandshakeServerSession,
    ) Error!StreamingRequestEvent {
        while (true) {
            if (try self.pollRequestEvent()) |event| return event;
            try self.receiveRequestPacket();
        }
    }

    /// Return the next request event already present in QUIC stream state.
    ///
    /// This method never reads the UDP socket. Endpoint-wide dispatchers call
    /// `processRequestPacket` after their sole socket receive, then poll each
    /// affected HTTP/3 session without allowing per-connection readers to race.
    pub fn pollRequestEvent(
        self: *HandshakeServerSession,
    ) Error!?StreamingRequestEvent {
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
        return null;
    }

    /// Apply an already authenticated packet delivered by the endpoint-wide
    /// QUIC dispatcher. The packet remains caller-owned. ACK policy and QPACK
    /// feedback match the blocking receive path, but no socket read occurs.
    pub fn processRequestPacket(
        self: *HandshakeServerSession,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (self.receive_packets.ack_pending) {
            try self.established.connection.sendAck(0);
            self.receive_packets.ack_pending = false;
        }
        _ = self.established.connection.sendAckForPacketIfNeeded(
            packet.packet.packet_number,
            packet.frames,
        ) catch {
            self.receive_packets.ack_pending = true;
        };
        try visitStreamingServerRequestPacket(
            self,
            packetView(packet.*),
        );
        try self.flushRequestPacketFeedback();
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

    /// Detach an established Extended CONNECT receive stream from HTTP/3
    /// message parsing.
    ///
    /// Protocol adapters such as WebTransport parse their own long-lived DATA
    /// payload after HTTP semantics establish the tunnel. The initial HEADERS
    /// must already have been consumed with `receiveRequestEvent`; detaching
    /// before that point would bypass QPACK acknowledgments and request
    /// validation.
    pub fn detachRequestStream(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!void {
        const entry = self.streaming_requests.find(stream_id) orelse
            return error.UnexpectedStream;
        if (entry.reader.phase != .body or
            entry.reader.current_frame != null)
        {
            return error.UnexpectedStream;
        }
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        var removed = self.streaming_requests.takeEntry(stream_id) orelse
            return error.UnexpectedStream;
        removed.deinit();
    }

    /// Pump one packet after an Extended CONNECT stream has been detached.
    ///
    /// The QUIC connection still assembles all STREAM data. This adapter keeps
    /// HTTP/3 control/QPACK and unrelated request streams progressing while
    /// leaving the detached CONNECT stream's bytes for its protocol owner.
    pub fn receiveDetachedRequestProgress(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
    ) Error!void {
        try self.receive_packets.visit(
            &self.established.connection,
            .{ self, detached_stream_id },
            visitDetachedServerRequestPacket,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    /// Apply a dispatcher-owned packet while preserving bytes on one detached
    /// Extended CONNECT stream for its protocol adapter.
    pub fn processDetachedRequestPacket(
        self: *HandshakeServerSession,
        detached_stream_id: u62,
        packet: *const quic.one_rtt.ReceivedPacket,
    ) Error!void {
        if (self.receive_packets.ack_pending) {
            try self.established.connection.sendAck(0);
            self.receive_packets.ack_pending = false;
        }
        _ = self.established.connection.sendAckForPacketIfNeeded(
            packet.packet.packet_number,
            packet.frames,
        ) catch {
            self.receive_packets.ack_pending = true;
        };
        try visitDetachedServerRequestPacket(
            .{ self, detached_stream_id },
            packetView(packet.*),
        );
        try self.flushRequestPacketFeedback();
    }

    pub fn sendResponse(self: *HandshakeServerSession, stream_id: u62, response: http3.Response) Error!void {
        try self.sendResponseWithInformational(stream_id, &.{}, response);
    }

    /// Blocking aggregate-response helper for convenience serving loops. It
    /// sends the response body in bounded chunks and pumps ACK and MAX_*
    /// packets whenever body or trailer transmission exhausts peer credit.
    pub fn sendResponsePaced(
        self: *HandshakeServerSession,
        stream_id: u62,
        response: http3.Response,
    ) Error!void {
        try response.validateBodySemantics();
        try self.startResponse(
            stream_id,
            .{
                .status = response.status,
                .headers = response.headers,
                .request_method = response.request_method,
                .extended_connect = response.extended_connect,
            },
            response.body.len,
        );
        if (!response.suppressesBody() and response.body.len != 0) {
            try self.sendResponseBodyPaced(
                stream_id,
                response.body,
                response.trailers.len == 0,
            );
        }
        if (!response.suppressesBody() and response.trailers.len != 0) {
            try self.finishResponseTrailersPaced(
                stream_id,
                response.trailers,
            );
        }
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
            &self.critical_stream_send_scratch,
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
            &self.push_send_scratch,
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        self.stream_send_scratch.reset();
        const streaming = try response.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.established.connection.endpoint.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendConnectionStreamingHead(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
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
        if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
        }
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

    /// Batched counterpart to `sendResponseBodyPaced` for concurrent response
    /// streams. Each contribution becomes one QUIC packet and the socket-visible
    /// prefix commits atomically into the corresponding body stream states.
    pub fn sendResponseBodyBatchPaced(
        self: *HandshakeServerSession,
        chunks: []const BodyChunk,
    ) Error!void {
        try sendConnectionBodyBatchPaced(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeServerSession.receiveBatchProgressForSend,
            HandshakeServerSession.finishBatchResponseStream,
        );
    }

    /// Send complete response bodies using RFC 9218 request priorities.
    ///
    /// This is the multi-stream blocking counterpart to
    /// `sendResponseBodyPaced`. The scheduler evaluates current QUIC credit
    /// before each packet pass, gives a received PRIORITY_UPDATE precedence
    /// over the request's Priority field, serializes non-incremental responses
    /// by stream ID, and round-robins incremental peers. Processing packets
    /// between blocked passes also makes live priority updates affect the next
    /// unsent DATA packet rather than only future API calls.
    pub fn sendResponseBodiesPaced(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
    ) Error!void {
        if (responses.len == 0) return;
        const allocator =
            self.established.connection.endpoint.allocator;
        var response_index = std.AutoHashMapUnmanaged(u62, usize).empty;
        defer response_index.deinit(allocator);
        const use_response_index =
            responses.len > response_scheduler_stack_capacity;
        if (use_response_index) {
            const response_count = std.math.cast(
                u32,
                responses.len,
            ) orelse return error.ExcessiveLoad;
            try response_index.ensureTotalCapacity(
                allocator,
                response_count,
            );
        }
        var offsets_stack: [response_scheduler_stack_capacity]usize = undefined;
        const offsets = try stackFirstSlice(
            usize,
            allocator,
            &offsets_stack,
            responses.len,
        );
        defer freeStackFirstSlice(usize, allocator, &offsets_stack, offsets);
        @memset(offsets, 0);
        var candidates_stack: [response_scheduler_stack_capacity]response_scheduler.Candidate = undefined;
        const candidates = try stackFirstSlice(
            response_scheduler.Candidate,
            allocator,
            &candidates_stack,
            responses.len,
        );
        defer freeStackFirstSlice(
            response_scheduler.Candidate,
            allocator,
            &candidates_stack,
            candidates,
        );
        var chunks_stack: [response_scheduler_stack_capacity]BodyChunk =
            undefined;
        const chunks = try stackFirstSlice(
            BodyChunk,
            allocator,
            &chunks_stack,
            responses.len,
        );
        defer freeStackFirstSlice(
            BodyChunk,
            allocator,
            &chunks_stack,
            chunks,
        );

        for (responses, 0..) |response, index| {
            if (self.outbound_bodies.find(response.stream_id) == null) {
                return error.UnexpectedStream;
            }
            if (use_response_index) {
                const slot = response_index.getOrPutAssumeCapacity(
                    response.stream_id,
                );
                if (slot.found_existing) {
                    return error.UnexpectedStream;
                }
                slot.value_ptr.* = index;
            } else {
                for (responses[0..index]) |prior| {
                    if (prior.stream_id == response.stream_id) {
                        return error.UnexpectedStream;
                    }
                }
            }
        }

        var remaining_responses = responses.len;
        for (responses) |response| {
            if (response.data.len == 0) remaining_responses -= 1;
        }
        // Empty fixed-length bodies are normally closed by startResponse.
        // Reject an accidental open zero-length body rather than spinning
        // without a DATA contribution that can carry FIN.
        if (remaining_responses != responses.len) {
            return error.InvalidFrame;
        }

        const chunk_limit = pacedBodyChunkLimit(self.options);
        const max_batch_packets = response_scheduler.batchPacketLimit(
            self.options.response_scheduler_max_batch_packets,
            quic.one_rtt.max_batch_packets,
        );
        var next_stream: usize = 0;
        var delay_budget = response_scheduler.DelayBudget{};
        while (remaining_responses != 0) {
            self.refreshResponseCandidates(
                responses,
                offsets,
                candidates,
                chunk_limit,
            );
            const selection = response_scheduler.select(candidates) orelse {
                try self.receiveRequestPacket();
                continue;
            };

            var chunk_count: usize = 0;
            var iterator = response_scheduler.Iterator.init(
                candidates,
                selection,
                next_stream,
            );
            var last_selected: ?usize = null;
            while (iterator.next()) |index| {
                const response = responses[index];
                const count = @min(
                    candidates[index].remaining,
                    candidates[index].send_capacity,
                    chunk_limit,
                );
                if (count == 0) continue;
                const end = offsets[index] + count;
                chunks[chunk_count] = .{
                    .stream_id = response.stream_id,
                    .data = response.data[offsets[index]..end],
                    .fin = end == response.data.len,
                };
                chunk_count += 1;
                last_selected = index;
                if (chunk_count == max_batch_packets) break;
            }
            if (chunk_count == 0) {
                try self.receiveRequestPacket();
                continue;
            }

            const sent_count = sendConnectionBodyBatchPacedProgress(
                &self.established.connection,
                &self.outbound_bodies,
                chunks[0..chunk_count],
                self.options,
                self,
                HandshakeServerSession.finishBatchResponseStream,
            ) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveRequestPacket();
                    continue;
                },
                error.PacingLimited => {
                    try self.established.connection
                        .waitForPacingAvailability();
                    continue;
                },
                else => return err,
            };
            var sent_body_bytes: usize = 0;
            for (chunks[0..sent_count]) |chunk| {
                const index = if (use_response_index)
                    response_index.get(chunk.stream_id) orelse
                        return error.UnexpectedStream
                else
                    responseBodyIndex(
                        responses,
                        chunk.stream_id,
                    ) orelse return error.UnexpectedStream;
                offsets[index] += chunk.data.len;
                if (offsets[index] == responses[index].data.len) {
                    remaining_responses -= 1;
                }
                sent_body_bytes +|= chunk.data.len;
            }
            delay_budget.record(sent_body_bytes, sent_count);
            if (self.options.response_scheduler_batch_delay_ns != 0 and
                delay_budget.due(
                    self.options.response_scheduler_batch_delay_bytes,
                    self.options.response_scheduler_batch_delay_packets,
                ))
            {
                const delay_ns = std.math.cast(
                    i64,
                    self.options.response_scheduler_batch_delay_ns,
                ) orelse std.math.maxInt(i64);
                try std.Io.sleep(
                    self.established.connection.endpoint.io,
                    .fromNanoseconds(delay_ns),
                    .awake,
                );
                delay_budget.reset();
            }
            if (selection.exclusive_index == null) {
                // Rotate only incremental passes. An exclusive stream retains
                // ownership until completion unless it becomes blocked or a
                // live PRIORITY_UPDATE changes the selected class.
                if (sent_count != 0) {
                    const last_sent = if (use_response_index)
                        response_index.get(
                            chunks[sent_count - 1].stream_id,
                        ) orelse return error.UnexpectedStream
                    else
                        responseBodyIndex(
                            responses,
                            chunks[sent_count - 1].stream_id,
                        ) orelse return error.UnexpectedStream;
                    next_stream = (last_sent + 1) % responses.len;
                } else if (last_selected != null) {
                    next_stream = (last_selected.? + 1) % responses.len;
                }
            }
        }
    }

    fn refreshResponseCandidates(
        self: *HandshakeServerSession,
        responses: []const ResponseBody,
        offsets: []const usize,
        candidates: []response_scheduler.Candidate,
        chunk_limit: usize,
    ) void {
        std.debug.assert(responses.len == offsets.len);
        std.debug.assert(responses.len == candidates.len);
        const connection_capacity =
            self.established.connection.streamSendCredit(0).connection;
        const congestion_capacity =
            self.established.connection.congestionAvailable();
        for (responses, offsets, candidates) |response, offset, *candidate| {
            const remaining = response.data.len - offset;
            const credit = self.established.connection.streamSendCredit(
                response.stream_id,
            );
            const connection = std.math.cast(
                usize,
                connection_capacity,
            ) orelse std.math.maxInt(usize);
            const stream = std.math.cast(
                usize,
                credit.stream,
            ) orelse std.math.maxInt(usize);
            candidate.* = .{
                .stream_id = response.stream_id,
                .remaining = remaining,
                .send_capacity = responseBodySendCapacity(
                    remaining,
                    connection,
                    stream,
                    congestion_capacity,
                    credit.max_datagram_size,
                    chunk_limit,
                ),
                .priority = self.effectiveResponsePriority(
                    response.stream_id,
                ),
            };
        }
    }

    fn effectiveResponsePriority(
        self: HandshakeServerSession,
        stream_id: u62,
    ) http3.Priority {
        if (self.control.requestPriorityUpdate(stream_id)) |update| {
            return update.priority();
        }
        return self.request_lifecycle.priority(stream_id);
    }

    fn receiveBatchProgressForSend(
        self: *HandshakeServerSession,
    ) Error!void {
        try self.receiveRequestPacket();
    }

    fn finishBatchResponseStream(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) void {
        self.request_lifecycle.markFinished(stream_id);
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
        if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
            return responseResetError(cancel.application_error_code);
        }
        try sendConnectionTrailers(
            &self.established.connection,
            &self.outbound_bodies,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
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

    /// Wait until the peer cancels the response direction of `stream_id`.
    ///
    /// The request itself can already be complete: closing an unread response
    /// body sends STOP_SENDING, not RESET_STREAM, so it must be observed from
    /// the local QUIC send state. Packets for unrelated request streams remain
    /// routed while this blocking convenience method waits.
    pub fn receivePeerResponseCancellation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!PeerResponseCancellation {
        if (!self.request_lifecycle.contains(stream_id)) {
            return error.UnexpectedStream;
        }
        while (true) {
            if (try self.finishPeerResponseCancellation(stream_id)) |cancel| {
                return cancel;
            }
            try self.receiveRequestPacket();
        }
    }

    fn finishPeerResponseCancellation(
        self: *HandshakeServerSession,
        stream_id: u62,
    ) Error!?PeerResponseCancellation {
        const stopped = self.established.connection.streamStopped(stream_id) orelse
            return null;
        // Do the only fallible cleanup first. If sending MAX_STREAMS is
        // temporarily blocked, the caller can retry without losing the
        // cancellation or partially retiring HTTP/3 bookkeeping.
        _ = try self.established.connection.releaseCompletedPeerStream(
            stream_id,
        );
        self.qpack_encode.abandonStream(stream_id);
        _ = self.outbound_bodies.finish(stream_id);
        self.request_lifecycle.markFinished(stream_id);
        return .{
            .stream_id = stream_id,
            .application_error_code = stopped.application_error_code,
        };
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
            &self.critical_stream_send_scratch,
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
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
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

    /// Advertise RFC 9412 origins on the server control stream. Clients must
    /// still validate certificate authority before coalescing requests.
    pub fn sendOrigins(
        self: *HandshakeServerSession,
        origins: []const []const u8,
    ) Error!void {
        try sendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            server_control_stream_id,
        );
        const previous_sent = self.control.local_origin_set_sent;
        errdefer self.control.local_origin_set_sent = previous_sent;
        self.critical_stream_send_scratch.reset();
        try self.control.writeOrigins(
            &self.critical_stream_send_scratch.payload,
            self.established.connection.endpoint.allocator,
            origins,
        );
        const previous_send = self.control_send;
        errdefer self.control_send = previous_send;
        try self.control_send.appendFrames(
            &self.critical_stream_send_scratch.frames,
            self.established.connection.endpoint.allocator,
            self.critical_stream_send_scratch.payload.items,
            self.options.max_stream_frame_data,
            false,
        );
        try sendConnectionFrames(
            &self.established.connection,
            self.critical_stream_send_scratch.frames.items,
            self.options.max_frames_per_packet,
        );
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
            &self.critical_stream_send_scratch,
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
        try self.receive_packets.visit(
            &self.established.connection,
            self,
            visitStreamingServerRequestPacket,
        );
        // Encoder-stream inserts and reset cancellations both queue decoder
        // instructions. Flush them at the packet boundary so a peer does not
        // remain artificially blocked until another HEADERS event appears.
        try self.flushRequestPacketFeedback();
    }

    fn flushRequestPacketFeedback(self: *HandshakeServerSession) Error!void {
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback();
        }
    }

    /// Process one transport packet for control-stream progress without
    /// requiring a complete application request to become ready.
    pub fn pollControl(self: *HandshakeServerSession) Error!void {
        try self.receiveRequestPacket();
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
            try self.request_lifecycle.markReceived(
                stream_id,
                switch (event) {
                    .head => |head| switch (head) {
                        .request => |request| requestPriority(
                            request.headers,
                        ),
                        .response => .{},
                    },
                    else => .{},
                },
            );
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
            &self.critical_stream_send_scratch,
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
    stream_send_scratch: StreamMessageSendScratch = .{},
    critical_stream_send_scratch: CriticalStreamSendScratch = .{},
    next_stream_id: u62 = 0,

    /// Reserve one client-initiated bidirectional stream ID.
    ///
    /// Request streams and WebTransport bidirectional streams share this QUIC
    /// ID space. Protocol adapters must reserve through this method rather than
    /// maintaining an independent counter.
    pub fn reserveClientBidirectionalStreamId(
        self: *HandshakeClient,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        self.next_stream_id = std.math.add(
            u62,
            stream_id,
            4,
        ) catch return error.StreamCreationError;
        return stream_id;
    }

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
        return initOwnedEstablished(
            allocator,
            endpoint,
            server,
            established,
            options.session,
        );
    }

    /// Build the HTTP/3 client state around a successfully initialized QUIC
    /// connection. Ownership of both `endpoint` and `established` transfers
    /// only on success. Keeping this common path prevents the TLS and external
    /// key-negotiation entry points from drifting in lifecycle behavior.
    fn initOwnedEstablished(
        allocator: std.mem.Allocator,
        endpoint: *quic.runtime.Endpoint,
        peer: net.IpAddress,
        established: quic.handshake.EstablishedConnection,
        options: HandshakeSessionOptions,
    ) Error!HandshakeClient {
        if (!http3.isHttp3Alpn(established.alpn)) return error.InvalidAlpn;
        const max_capacity = std.math.cast(
            usize,
            options.local_settings.qpack_max_table_capacity,
        ) orelse return error.InvalidSetting;
        return .{
            .endpoint = endpoint,
            .peer = peer,
            .allocator = allocator,
            .established = established,
            .options = options,
            .qpack_decode = .init(
                allocator,
                max_capacity,
                options.max_stream_buffer,
            ),
            .qpack_encode = .initAwaitingPeerSettings(
                allocator,
                options.max_stream_buffer,
            ),
            .response_streams = .init(
                allocator,
                options.max_stream_buffer,
                options.max_concurrent_request_streams,
            ),
            .streaming_responses = .initWithInformationalLimit(
                allocator,
                options.max_concurrent_request_streams,
                options.max_stream_buffer,
                options.max_informational_responses,
                options.local_settings,
                .response,
            ),
            .push_streams = .initWithInformationalLimit(
                allocator,
                options.max_concurrent_request_streams,
                options.max_stream_buffer,
                options.max_informational_responses,
                options.local_settings,
            ),
            .request_lifecycle = .init(
                allocator,
                options.max_concurrent_request_streams,
            ),
            .outbound_bodies = .init(
                allocator,
                options.max_concurrent_request_streams,
            ),
        };
    }

    pub fn initPreconfigured(
        allocator: std.mem.Allocator,
        io: std.Io,
        local_address: net.IpAddress,
        peer: net.IpAddress,
        limits: Limits,
        options: HandshakeSessionOptions,
        transport: quic.handshake.PreconfiguredConnectionOptions,
    ) Error!HandshakeClient {
        try validateBlockedStreamLimit(
            options.local_settings,
            options.max_concurrent_request_streams,
        );
        const endpoint = try allocator.create(quic.runtime.Endpoint);
        errdefer allocator.destroy(endpoint);
        endpoint.* = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            local_address,
            limits.quic,
        );
        errdefer endpoint.deinit();
        var established = try quic.handshake.establishPreconfigured(
            endpoint,
            peer,
            .client,
            transport,
        );
        errdefer established.deinit();
        return initOwnedEstablished(
            allocator,
            endpoint,
            peer,
            established,
            options,
        );
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
        const path = try uriRequestTargetAlloc(allocator, uri);
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
        const path = try uriRequestTargetAlloc(allocator, uri);
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
        self.critical_stream_send_scratch.deinit(self.allocator);
        self.stream_send_scratch.deinit(self.allocator);
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

    pub fn negotiatedAlpn(self: HandshakeClient) []const u8 {
        return self.established.alpn;
    }

    pub fn negotiatedCipherSuite(
        self: HandshakeClient,
    ) quic.tls.cipher_suite.Suite {
        return self.established.negotiatedCipherSuite();
    }

    pub fn negotiatedTranscriptHash(
        self: HandshakeClient,
    ) quic.tls.secret.Hash {
        return self.established.negotiatedTranscriptHash();
    }

    pub fn peerCertificates(
        self: *const HandshakeClient,
    ) ?[]const []const u8 {
        return self.established.peerCertificates();
    }

    pub fn exportKeyingMaterial(
        self: *const HandshakeClient,
        label: []const u8,
        context: []const u8,
        out: []u8,
    ) Error!void {
        try self.established.exportKeyingMaterial(label, context, out);
    }

    pub fn initiateKeyUpdate(self: *HandshakeClient) Error!void {
        try self.established.initiateKeyUpdate();
    }

    pub fn localKeyUpdateCount(self: HandshakeClient) u64 {
        return self.established.localKeyUpdateCount();
    }

    pub fn peerKeyUpdateCount(self: HandshakeClient) u64 {
        return self.established.peerKeyUpdateCount();
    }

    pub fn keyUpdateAwaitingAck(self: HandshakeClient) bool {
        return self.established.keyUpdateAwaitingAck();
    }

    pub fn peerGoAwayId(self: HandshakeClient) ?u64 {
        return self.control.peer_goaway_id;
    }

    pub fn goAwayRetryDisposition(
        self: HandshakeClient,
        stream_id: u62,
    ) GoAwayRetryDisposition {
        const goaway_id = self.control.peer_goaway_id orelse
            return .no_goaway;
        return if (stream_id >= goaway_id)
            .safe_to_retry
        else
            .may_have_been_processed;
    }

    pub fn request(self: *HandshakeClient, request_options: http3.Request) Error!OwnedHandshakeResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponse(stream_id);
    }

    /// Send a request and observe ordered 1xx heads before the final response.
    pub fn requestWithInformational(
        self: *HandshakeClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedHandshakeResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponseWithInformational(stream_id, informational);
    }

    pub fn sendRequest(
        self: *HandshakeClient,
        request_options: http3.Request,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        const reserved = try self.reserveClientBidirectionalStreamId();
        std.debug.assert(reserved == stream_id);

        try sendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
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
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
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
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
        errdefer _ = self.request_lifecycle.finish(stream_id) catch false;
        const reserved = try self.reserveClientBidirectionalStreamId();
        std.debug.assert(reserved == stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
            &self.control,
            &self.control_send,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.qpack_decoder_send,
            &self.qpack_decoder_prefix_sent,
            self.options,
            client_control_stream_id,
        );
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
            self.allocator,
            self.control.settings.peer,
            stream_id,
            body_length,
            &self.qpack_encode,
        );
        errdefer self.qpack_encode.abandonStream(stream_id);
        try sendConnectionStreamingHead(
            &self.established.connection,
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
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

    /// Send one DATA contribution per active request stream as a stateful QUIC
    /// packet batch.
    ///
    /// The input order determines packet order and each stream may appear at
    /// most once. Congestion, flow control, and pacing are handled like
    /// `sendRequestBodyPaced`, but socket-visible packet prefixes are committed
    /// together so multi-stream schedulers can amortize protection and
    /// sendmmsg/GSO overhead without sharing mutable DATA payload storage.
    pub fn sendRequestBodyBatchPaced(
        self: *HandshakeClient,
        chunks: []const BodyChunk,
    ) Error!void {
        for (chunks) |chunk| {
            if (!self.request_lifecycle.contains(chunk.stream_id)) {
                return error.UnexpectedStream;
            }
        }
        try sendConnectionBodyBatchPaced(
            &self.established.connection,
            &self.outbound_bodies,
            chunks,
            self.options,
            self,
            HandshakeClient.receiveBatchProgressForSend,
            HandshakeClient.finishBatchRequestStream,
        );
    }

    fn receiveBatchProgressForSend(self: *HandshakeClient) Error!void {
        if (self.request_lifecycle.outstanding.items.len == 0) {
            return error.UnexpectedStream;
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
            null,
        );
        if (self.response_streams.firstReset()) |reset| {
            if (!self.request_lifecycle.contains(reset.stream_id)) return;
            _ = self.response_streams.takeReset(reset.stream_id);
            try self.sendQpackFeedback();
            _ = try self.request_lifecycle.finish(reset.stream_id);
            _ = self.outbound_bodies.finish(reset.stream_id);
            self.qpack_encode.abandonStream(reset.stream_id);
            return responseResetError(reset.application_error_code);
        }
    }

    fn finishBatchRequestStream(
        self: *HandshakeClient,
        stream_id: u62,
    ) void {
        _ = self;
        _ = stream_id;
        // A request remains outstanding until its response is consumed. The
        // shared batch helper already retires only the outbound body state.
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
            &self.stream_send_scratch,
            &self.critical_stream_send_scratch,
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
        return self.receiveResponseWithInformational(stream_id, null);
    }

    /// Aggregate a response while observing ordered, callback-scoped 1xx heads.
    pub fn receiveResponseWithInformational(
        self: *HandshakeClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
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
        var response = try http3.decodeResponseWithDynamicTableAndOptions(
            self.established.connection.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    stream_id,
                );
                options.max_informational_responses =
                    self.options.max_informational_responses;
                options.informational = informational;
                break :blk options;
            },
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
        return self.receiveNextResponseWithInformational(null);
    }

    /// Aggregate whichever outstanding response becomes ready first and
    /// correlate every callback-scoped 1xx head with its request stream.
    pub fn receiveNextResponseWithInformational(
        self: *HandshakeClient,
        informational: ?MultiplexedInformationalObserver,
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
                if (informational) |observer| {
                    // Aggregate decoding is synchronous, so this stack adapter
                    // remains alive for every callback and cannot escape.
                    var adapter = MultiplexedInformationalContext{
                        .observer = observer,
                        .stream_id = stream_id,
                    };
                    return .{ .response = .{
                        .stream_id = stream_id,
                        .value = try self.receiveResponseWithInformational(
                            stream_id,
                            .{
                                .context = &adapter,
                                .on_response = MultiplexedInformationalContext.notify,
                            },
                        ),
                    } };
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
                null,
            );
        }
    }

    /// Process one peer packet and retain any HTTP/3 events for the normal
    /// response and push APIs.
    ///
    /// Applications normally make progress implicitly through a blocking
    /// response call. A control-only exchange, such as waiting for the
    /// server GOAWAY that acknowledges a client-initiated shutdown, has no
    /// response stream to drive that path. This explicit pump also permits
    /// event loops to observe GOAWAY while an accepted response remains
    /// buffered and available to `receiveResponse`.
    pub fn receiveProgress(self: *HandshakeClient) Error!void {
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
            null,
        );
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
        self.request_lifecycle.applyResponseReaderSemantics(
            stream_id,
            &entry.reader,
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
            null,
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
        self.request_lifecycle.applyResponseReaderSemantics(
            stream_id,
            &active.reader,
        );
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

    /// Detach an established Extended CONNECT response stream from HTTP/3
    /// message parsing after final response HEADERS have been consumed.
    pub fn detachResponseStream(
        self: *HandshakeClient,
        stream_id: u62,
    ) Error!void {
        const entry = self.streaming_responses.find(stream_id) orelse
            return error.UnexpectedStream;
        if (entry.reader.phase != .body or
            entry.reader.current_frame != null)
        {
            return error.UnexpectedStream;
        }
        try releaseStreamingReaderCapacity(
            &self.established.connection,
            &entry.reader,
        );
        var removed = self.streaming_responses.takeEntry(stream_id) orelse
            return error.UnexpectedStream;
        removed.deinit();
    }

    /// Client counterpart to `receiveDetachedRequestProgress`.
    pub fn receiveDetachedResponseProgress(
        self: *HandshakeClient,
        detached_stream_id: u62,
    ) Error!void {
        if (self.request_lifecycle.outstanding.items.len == 0) {
            return error.UnexpectedStream;
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
            detached_stream_id,
        );
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
                null,
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
        return self.receivePushWithInformational(null);
    }

    /// Aggregate one promised response while reporting its ordered 1xx heads.
    pub fn receivePushWithInformational(
        self: *HandshakeClient,
        informational: ?PushInformationalObserver,
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
                    if (value != .response) {
                        return error.UnexpectedFrame;
                    }
                    if (value.response.status < 200) {
                        if (informational) |observer| {
                            observer.on_response(
                                observer.context,
                                event.push_id,
                                event.request_stream_id,
                                event.stream_id,
                                .{
                                    .status = value.response.status,
                                    .headers = value.response.headers,
                                },
                            );
                        }
                        // The shared reader already enforced the per-stream
                        // bound; the owned event is released after this
                        // callback while aggregation awaits the final head.
                        continue;
                    }
                    if (head != null) return error.UnexpectedFrame;
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
            )) |ready_value| {
                var ready = ready_value;
                const stream_id: u62 = @intCast(
                    ready.entry.reader.receive.stream_id,
                );
                self.request_lifecycle.applyResponseReaderSemantics(
                    stream_id,
                    &ready.entry.reader,
                );
                // `nextResponse` decoded this head before the request context
                // was applied. Revalidate the owned event immediately so the
                // caller never observes HEAD/CONNECT DATA semantics.
                if (ready.event == .head and
                    ready.event.head == .response)
                {
                    try http3.applyResponseHeadRequestSemantics(
                        &ready.event.head.response,
                        ready.entry.reader.response_request_method,
                        ready.entry.reader.response_extended_connect,
                    );
                    ready.entry.reader.body_allowed =
                        ready.event.head.response.body_allowed;
                    if (!ready.entry.reader.body_allowed) {
                        ready.entry.reader.content_length = null;
                    }
                }
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
                null,
            );
        }
    }

    pub fn sendGoAway(self: *HandshakeClient, stream_id: u64) Error!void {
        try validateClientGoAwayPushId(stream_id);
        try sendConnectionSettings(
            &self.established.connection,
            &self.critical_stream_send_scratch,
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

    pub fn peerOrigins(self: HandshakeClient) []const http3.OriginKey {
        return self.control.peerOrigins();
    }

    pub fn peerOriginSetInitialized(self: HandshakeClient) bool {
        return self.control.peerOriginSetInitialized();
    }

    pub fn peerOriginKnown(
        self: HandshakeClient,
        origin: http3.Origin,
    ) bool {
        return self.control.peerOriginKnown(origin);
    }

    pub fn peerOriginSetAllows(
        self: HandshakeClient,
        initial_origin: http3.Origin,
        requested_origin: http3.Origin,
    ) ?bool {
        return self.control.peerOriginSetAllows(
            initial_origin,
            requested_origin,
        );
    }

    /// Apply RFC 8336's 421 Misdirected Request removal rule. The caller
    /// supplies the request origin because response state intentionally stores
    /// no redundant authority copy after dispatch.
    pub fn removePeerOriginAfterMisdirected(
        self: *HandshakeClient,
        origin: http3.Origin,
    ) Error!void {
        try self.control.removePeerOrigin(self.allocator, origin);
    }

    /// Process one transport packet for SETTINGS/ORIGIN/GOAWAY progress
    /// without waiting for an application response event.
    pub fn pollControl(self: *HandshakeClient) Error!void {
        try self.receiveResponsePacket();
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
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
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
            &self.critical_stream_send_scratch,
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
            null,
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
    stream_send_scratch: StreamMessageSendScratch = .{},
    push_send_scratch: PushSendScratch = .{},
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
        self.push_send_scratch.deinit(
            self.quic_server.endpoint.allocator,
        );
        self.stream_send_scratch.deinit(
            self.quic_server.endpoint.allocator,
        );
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
        try self.request_lifecycle.markReceived(
            assembled.stream_id,
            requestPriority(request.headers),
        );
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
        try sendProtectedReaderCapacity(
            &self.quic_server.endpoint,
            entry.from orelse return error.UnexpectedStream,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try sendProtectedReaderCapacity(
            &self.quic_server.endpoint,
            entry.from orelse return error.UnexpectedStream,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        return read;
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
            &self.push_send_scratch,
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
        self.stream_send_scratch.reset();
        const streaming = try response.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
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
            &self.stream_send_scratch,
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
        if (self.config.peer_stream_flow_window) |window| {
            try self.outbound_bodies.enableFlowLimit(stream_id, window);
        }
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

    pub fn sendResponseBodyPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (data.len == 0) {
            try self.sendResponseBodyPacedChunk(to, stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
        var offset: usize = 0;
        while (offset < data.len) {
            const end = @min(data.len, offset + chunk_limit);
            try self.sendResponseBodyPacedChunk(
                to,
                stream_id,
                data[offset..end],
                fin and end == data.len,
            );
            offset = end;
        }
    }

    fn sendResponseBodyPacedChunk(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendResponseBody(to, stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    _ = try self.receiveRequestPacketTimeout(100_000);
                    continue;
                },
                else => return err,
            };
            _ = try self.receiveRequestPacketTimeout(100_000);
            return;
        }
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
            &self.stream_send_scratch,
        );
        self.request_lifecycle.markFinished(stream_id);
    }

    pub fn finishResponseTrailersPaced(
        self: *ProtectedServer,
        to: net.IpAddress,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
            self.finishResponseTrailers(to, stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    _ = try self.receiveRequestPacketTimeout(100_000);
                    continue;
                },
                else => return err,
            };
            return;
        }
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
        try sendProtectedResponseSequence(
            &self.quic_server.endpoint,
            to,
            self.config,
            &self.stream_send_scratch,
            stream_id,
            informational,
            response,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
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

    pub fn sendOrigins(
        self: *ProtectedServer,
        to: net.IpAddress,
        origins: []const []const u8,
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
        const previous_sent = self.control.local_origin_set_sent;
        errdefer self.control.local_origin_set_sent = previous_sent;
        self.protected_send.resetCriticalStreamScratch();
        try self.control.writeOrigins(
            &self.protected_send.critical_stream_payload,
            self.quic_server.endpoint.allocator,
            origins,
        );
        const previous_send = self.control_send;
        errdefer self.control_send = previous_send;
        try self.control_send.appendFrames(
            &self.protected_send.critical_stream_frames,
            self.quic_server.endpoint.allocator,
            self.protected_send.critical_stream_payload.items,
            self.config.max_stream_frame_data,
            false,
        );
        try sendProtectedFrames(
            &self.quic_server.endpoint,
            to,
            self.config.send_keys,
            self.config.peer_connection_id,
            &self.next_packet_number,
            self.protected_send.critical_stream_frames.items,
            self.config.max_frames_per_packet,
            &self.protected_send,
        );
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
            updateOutboundBodyFlowLimitsFromFrames(
                &self.outbound_bodies,
                packet.frames,
            );
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
                null,
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

        updateOutboundBodyFlowLimitsFromFrames(
            &self.outbound_bodies,
            packet.frames,
        );
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
            null,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback(packet.from);
        }
    }

    /// Process one protected transport packet for control-stream progress.
    pub fn pollControl(self: *ProtectedServer) Error!void {
        try self.receiveRequestPacket();
    }

    fn receiveRequestPacketTimeout(
        self: *ProtectedServer,
        timeout_ns: i64,
    ) Error!bool {
        var datagram = self.quic_server.endpoint.receiveBytesTimeout(.{
            .duration = .{
                .clock = .awake,
                .raw = .fromNanoseconds(timeout_ns),
            },
        }) catch |err| switch (err) {
            error.Timeout => return false,
            else => |other| return @errorCast(other),
        };
        defer datagram.deinit(self.quic_server.endpoint.allocator);
        var packet = try quic.one_rtt.openReceivedBytes(
            &self.quic_server.endpoint,
            datagram.from,
            datagram.bytes,
            self.config.receive_keys,
            self.config.local_connection_id.len,
            self.expected_packet_number,
            self.config.max_frames_per_packet,
        );
        defer packet.deinit(self.quic_server.endpoint.allocator);
        self.expected_packet_number = packet.packet.packet_number + 1;
        updateOutboundBodyFlowLimitsFromFrames(
            &self.outbound_bodies,
            packet.frames,
        );
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
            null,
        );
        if (self.qpack_decode.pendingDecoderInstructions().len != 0) {
            try self.sendQpackFeedback(packet.from);
        }
        return true;
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
            try self.request_lifecycle.markReceived(
                stream_id,
                switch (event) {
                    .head => |head| switch (head) {
                        .request => |request| requestPriority(
                            request.headers,
                        ),
                        .response => .{},
                    },
                    else => .{},
                },
            );
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
    stream_send_scratch: StreamMessageSendScratch = .{},
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
            .streaming_responses = .initWithInformationalLimit(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.max_informational_responses,
                config.local_settings,
                .response,
            ),
            .push_streams = .initWithInformationalLimit(
                allocator,
                limits.max_concurrent_request_streams,
                config.max_stream_buffer,
                config.max_informational_responses,
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
        self.stream_send_scratch.deinit(
            self.quic_client.endpoint.allocator,
        );
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

    pub fn peerGoAwayId(self: ProtectedClient) ?u64 {
        return self.control.peer_goaway_id;
    }

    pub fn goAwayRetryDisposition(
        self: ProtectedClient,
        stream_id: u62,
    ) GoAwayRetryDisposition {
        const goaway_id = self.control.peer_goaway_id orelse
            return .no_goaway;
        return if (stream_id >= goaway_id)
            .safe_to_retry
        else
            .may_have_been_processed;
    }

    /// Send a protected request and observe ordered 1xx heads before final.
    pub fn requestWithInformational(
        self: *ProtectedClient,
        request_options: http3.Request,
        informational: ?http3.InformationalObserver,
    ) Error!OwnedProtectedResponse {
        const stream_id = try self.sendRequest(request_options);
        return self.receiveResponseWithInformational(stream_id, informational);
    }

    pub fn sendRequest(
        self: *ProtectedClient,
        request_options: http3.Request,
    ) Error!u62 {
        const stream_id = self.next_stream_id;
        if (!self.control.acceptsRequestStream(stream_id)) return error.GoAwayReceived;
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
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
        try sendProtectedMessage(
            &self.quic_client.endpoint,
            self.quic_client.peer,
            self.config,
            &self.stream_send_scratch,
            stream_id,
            request_options,
            self.control.settings.peer,
            &self.qpack_encode,
            &self.qpack_encoder_send,
            &self.qpack_encoder_prefix_sent,
            &self.next_packet_number,
            &self.protected_send,
        );
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
        try self.request_lifecycle.open(
            stream_id,
            request_options.method,
            requestHasProtocol(request_options.headers),
        );
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
        self.stream_send_scratch.reset();
        const streaming = try request_options.writeStreamingHeadDynamic(
            &self.stream_send_scratch.encoded,
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
            &self.stream_send_scratch,
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
        if (self.config.peer_stream_flow_window) |window| {
            try self.outbound_bodies.enableFlowLimit(stream_id, window);
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

    pub fn sendRequestBodyPaced(
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        if (data.len == 0) {
            try self.sendRequestBodyPacedChunk(stream_id, data, fin);
            return;
        }
        const chunk_limit = pacedProtectedBodyChunkLimit(self.config);
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
        self: *ProtectedClient,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) Error!void {
        while (true) {
            self.sendRequestBody(stream_id, data, fin) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponsePacket();
                    continue;
                },
                else => return err,
            };
            return;
        }
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
            &self.stream_send_scratch,
        );
    }

    pub fn finishRequestTrailersPaced(
        self: *ProtectedClient,
        stream_id: u62,
        trailers: []const http3.Qpack.HeaderField,
    ) Error!void {
        while (true) {
            self.finishRequestTrailers(stream_id, trailers) catch |err| switch (err) {
                error.FlowControlBlocked, error.CongestionLimited => {
                    try self.receiveResponsePacket();
                    continue;
                },
                else => return err,
            };
            return;
        }
    }

    pub fn receiveResponse(
        self: *ProtectedClient,
        stream_id: u62,
    ) Error!OwnedProtectedResponse {
        return self.receiveResponseWithInformational(stream_id, null);
    }

    /// Aggregate a protected response with callback-scoped 1xx observation.
    pub fn receiveResponseWithInformational(
        self: *ProtectedClient,
        stream_id: u62,
        informational: ?http3.InformationalObserver,
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
        var response = try http3.decodeResponseWithDynamicTableAndOptions(
            self.quic_client.endpoint.allocator,
            assembled.bytes,
            self.control.settings.local,
            self.qpack_decode.table,
            blk: {
                var options = self.request_lifecycle.responseDecodeOptions(
                    stream_id,
                );
                options.max_informational_responses =
                    self.config.max_informational_responses;
                options.informational = informational;
                break :blk options;
            },
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
        return self.receiveNextResponseWithInformational(null);
    }

    /// Aggregate whichever outstanding response becomes ready first and
    /// correlate every callback-scoped 1xx head with its request stream.
    pub fn receiveNextResponseWithInformational(
        self: *ProtectedClient,
        informational: ?MultiplexedInformationalObserver,
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
                if (informational) |observer| {
                    // Aggregate decoding is synchronous, so this stack adapter
                    // remains alive for every callback and cannot escape.
                    var adapter = MultiplexedInformationalContext{
                        .observer = observer,
                        .stream_id = stream_id,
                    };
                    return .{ .response = .{
                        .stream_id = stream_id,
                        .value = try self.receiveResponseWithInformational(
                            stream_id,
                            .{
                                .context = &adapter,
                                .on_response = MultiplexedInformationalContext.notify,
                            },
                        ),
                    } };
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
        self.request_lifecycle.applyResponseReaderSemantics(
            stream_id,
            &entry.reader,
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
        self.request_lifecycle.applyResponseReaderSemantics(
            stream_id,
            &active.reader,
        );
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
            )) |ready_value| {
                var ready = ready_value;
                const stream_id: u62 = @intCast(
                    ready.entry.reader.receive.stream_id,
                );
                self.request_lifecycle.applyResponseReaderSemantics(
                    stream_id,
                    &ready.entry.reader,
                );
                if (ready.event == .head and
                    ready.event.head == .response)
                {
                    try http3.applyResponseHeadRequestSemantics(
                        &ready.event.head.response,
                        ready.entry.reader.response_request_method,
                        ready.entry.reader.response_extended_connect,
                    );
                    ready.entry.reader.body_allowed =
                        ready.event.head.response.body_allowed;
                    if (!ready.entry.reader.body_allowed) {
                        ready.entry.reader.content_length = null;
                    }
                }
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
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            entry.from orelse self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        const read = try entry.reader.readData(out);
        try sendProtectedReaderCapacity(
            &self.quic_client.endpoint,
            entry.from orelse self.quic_client.peer,
            self.config,
            &self.next_packet_number,
            &self.protected_send,
            &entry.reader,
        );
        return read;
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
        return self.receivePushWithInformational(null);
    }

    /// Aggregate one promised response while reporting its ordered 1xx heads.
    pub fn receivePushWithInformational(
        self: *ProtectedClient,
        informational: ?PushInformationalObserver,
    ) Error!PushedResponse {
        return receiveProtectedPush(self, informational);
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

    pub fn peerOrigins(self: ProtectedClient) []const http3.OriginKey {
        return self.control.peerOrigins();
    }

    pub fn peerOriginSetInitialized(self: ProtectedClient) bool {
        return self.control.peerOriginSetInitialized();
    }

    pub fn peerOriginKnown(
        self: ProtectedClient,
        origin: http3.Origin,
    ) bool {
        return self.control.peerOriginKnown(origin);
    }

    pub fn peerOriginSetAllows(
        self: ProtectedClient,
        initial_origin: http3.Origin,
        requested_origin: http3.Origin,
    ) ?bool {
        return self.control.peerOriginSetAllows(
            initial_origin,
            requested_origin,
        );
    }

    pub fn removePeerOriginAfterMisdirected(
        self: *ProtectedClient,
        origin: http3.Origin,
    ) Error!void {
        try self.control.removePeerOrigin(
            self.quic_client.endpoint.allocator,
            origin,
        );
    }

    /// Process one protected transport packet for control-stream progress.
    pub fn pollControl(self: *ProtectedClient) Error!void {
        try self.receiveResponsePacket();
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
        updateOutboundBodyFlowLimitsFromFrames(
            &self.outbound_bodies,
            packet.frames,
        );
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
    informational: ?PushInformationalObserver,
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
                if (value != .response) {
                    return error.UnexpectedFrame;
                }
                if (value.response.status < 200) {
                    if (informational) |observer| {
                        observer.on_response(
                            observer.context,
                            event.push_id,
                            event.request_stream_id,
                            event.stream_id,
                            .{
                                .status = value.response.status,
                                .headers = value.response.headers,
                            },
                        );
                    }
                    continue;
                }
                if (head != null) return error.UnexpectedFrame;
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

fn sendProtectedReaderCapacity(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    reader: *StreamingMessageReader,
) Error!void {
    const amount = reader.uncreditedConsumed();
    if (amount == 0) return;
    const credited = std.math.add(
        u64,
        reader.credited_offset,
        amount,
    ) catch return error.InvalidFrameLength;
    const window = std.math.cast(u64, reader.receive.max_buffered) orelse
        return error.InvalidFrameLength;
    const maximum_stream_data = std.math.add(
        u64,
        credited,
        window,
    ) catch quic.varint.max_value;
    const frames = [_]quic.Frame{.{ .max_stream_data = .{
        .stream_id = reader.receive.stream_id,
        .maximum_stream_data = @min(maximum_stream_data, quic.varint.max_value),
    } }};
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
    reader.markCredited(amount);
}

fn updateOutboundBodyFlowLimitsFromFrames(
    bodies: *OutboundBodySet,
    frames: []const quic.Frame,
) void {
    for (frames) |frame| {
        if (frame != .max_stream_data) continue;
        const stream_id = std.math.cast(
            u62,
            frame.max_stream_data.stream_id,
        ) orelse continue;
        bodies.updateFlowLimit(
            stream_id,
            frame.max_stream_data.maximum_stream_data,
        );
    }
}

fn requestPriority(
    headers: []const http3.Qpack.HeaderField,
) http3.Priority {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, "priority")) {
            return http3.Priority.parse(header.value);
        }
    }
    return .{};
}

fn requestHasProtocol(
    headers: []const http3.Qpack.HeaderField,
) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
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
    max_informational_responses: usize,
    settings: http3.Settings,
    kind: Kind,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        settings: http3.Settings,
        kind: Kind,
    ) StreamingMessageSet {
        return initWithInformationalLimit(
            allocator,
            max_streams,
            max_stream_buffer,
            http3.default_max_informational_responses,
            settings,
            kind,
        );
    }

    fn initWithInformationalLimit(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        max_informational_responses: usize,
        settings: http3.Settings,
        kind: Kind,
    ) StreamingMessageSet {
        return .{
            .allocator = allocator,
            .max_streams = max_streams,
            .max_stream_buffer = max_stream_buffer,
            .max_informational_responses = max_informational_responses,
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
                    .max_informational_responses = self.max_informational_responses,
                    .credited_offset = owned.receive.read_offset,
                },
                .from = owned.from,
            }, slot.value_ptr);
        }
        return self.appendEntryAssumeCapacity(.{
            .reader = .initResponseWithInformationalLimit(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
                self.settings,
                self.max_informational_responses,
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
            max_informational_responses: usize,
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
                .max_informational_responses = max_informational_responses,
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
    max_informational_responses: usize,
    settings: http3.Settings,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        settings: http3.Settings,
    ) PushStreamSet {
        return initWithInformationalLimit(
            allocator,
            max_streams,
            max_stream_buffer,
            http3.default_max_informational_responses,
            settings,
        );
    }

    fn initWithInformationalLimit(
        allocator: std.mem.Allocator,
        max_streams: usize,
        max_stream_buffer: usize,
        max_informational_responses: usize,
        settings: http3.Settings,
    ) PushStreamSet {
        return .{
            .allocator = allocator,
            .max_streams = max_streams,
            .max_stream_buffer = max_stream_buffer,
            .max_informational_responses = max_informational_responses,
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
            switch (try entry.parsePrefix(
                control,
                self.settings,
                self.max_informational_responses,
            )) {
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
        switch (try entry.parsePrefix(
            control,
            self.settings,
            self.max_informational_responses,
        )) {
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
    const Semantics = struct {
        stream_id: u62,
        method: []u8,
        extended_connect: bool,
    };

    allocator: std.mem.Allocator,
    outstanding: std.ArrayList(u62) = .empty,
    outstanding_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    semantics: std.ArrayList(Semantics) = .empty,
    finished: std.AutoHashMapUnmanaged(u62, void) = .empty,
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
    ) ClientRequestLifecycle {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    fn deinit(self: *ClientRequestLifecycle) void {
        for (self.semantics.items) |entry| {
            self.allocator.free(entry.method);
        }
        self.outstanding.deinit(self.allocator);
        self.outstanding_index.deinit(self.allocator);
        self.semantics.deinit(self.allocator);
        self.finished.deinit(self.allocator);
        self.* = undefined;
    }

    fn open(
        self: *ClientRequestLifecycle,
        stream_id: u62,
        method: []const u8,
        extended_connect: bool,
    ) Error!void {
        if (self.outstanding.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        const method_copy = try self.allocator.dupe(u8, method);
        errdefer self.allocator.free(method_copy);
        const slot = try self.outstanding_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) return error.UnexpectedStream;
        errdefer _ = self.outstanding_index.remove(stream_id);
        const index = self.outstanding.items.len;
        try self.outstanding.append(self.allocator, stream_id);
        errdefer _ = self.outstanding.pop();
        try self.semantics.append(self.allocator, .{
            .stream_id = stream_id,
            .method = method_copy,
            .extended_connect = extended_connect,
        });
        slot.value_ptr.* = index;
    }

    fn contains(self: ClientRequestLifecycle, stream_id: u62) bool {
        return self.outstanding_index.count() != 0 and
            self.outstanding_index.contains(stream_id);
    }

    fn isFinished(self: ClientRequestLifecycle, stream_id: u62) bool {
        return self.finished.count() != 0 and self.finished.contains(stream_id);
    }

    fn responseDecodeOptions(
        self: ClientRequestLifecycle,
        stream_id: u62,
    ) http3.ResponseDecodeOptions {
        const index = self.outstanding_index.get(stream_id) orelse return .{};
        if (index >= self.semantics.items.len or
            self.semantics.items[index].stream_id != stream_id) return .{};
        const value = self.semantics.items[index];
        return .{
            .request_method = value.method,
            .extended_connect = value.extended_connect,
        };
    }

    fn applyResponseReaderSemantics(
        self: ClientRequestLifecycle,
        stream_id: u62,
        reader: *StreamingMessageReader,
    ) void {
        const options = self.responseDecodeOptions(stream_id);
        reader.response_request_method = options.request_method;
        reader.response_extended_connect = options.extended_connect;
    }

    fn finish(self: *ClientRequestLifecycle, stream_id: u62) Error!bool {
        if (self.outstanding_index.count() == 0) return false;
        const index = self.outstanding_index.get(stream_id) orelse return false;
        try self.finished.put(self.allocator, stream_id, {});
        errdefer _ = self.finished.remove(stream_id);
        const last_index = self.outstanding.items.len - 1;
        const removed = self.outstanding.swapRemove(index);
        const removed_semantics = self.semantics.swapRemove(index);
        std.debug.assert(removed_semantics.stream_id == removed);
        self.allocator.free(removed_semantics.method);
        _ = self.outstanding_index.remove(removed);
        if (index != last_index) {
            const moved = self.outstanding.items[index];
            self.outstanding_index.getPtr(moved).?.* = index;
            std.debug.assert(self.semantics.items[index].stream_id == moved);
        }
        return true;
    }
};

test "HTTP/3 client request lifecycle indexes outstanding streams" {
    const allocator = std.testing.allocator;
    var lifecycle = ClientRequestLifecycle.init(allocator, 3);
    defer lifecycle.deinit();

    try lifecycle.open(0, "GET", false);
    try lifecycle.open(4, "HEAD", false);
    try lifecycle.open(8, "CONNECT", true);
    try std.testing.expect(lifecycle.contains(0));
    try std.testing.expect(lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expectError(
        error.ExcessiveLoad,
        lifecycle.open(12, "GET", false),
    );
    try std.testing.expectEqualStrings(
        "HEAD",
        lifecycle.responseDecodeOptions(4).request_method.?,
    );
    try std.testing.expect(lifecycle.responseDecodeOptions(8).extended_connect);

    // Removing from the middle uses swapRemove; the moved stream must keep a
    // valid index because send/receive body paths call contains() frequently.
    try std.testing.expect(try lifecycle.finish(4));
    try std.testing.expect(!lifecycle.contains(4));
    try std.testing.expect(lifecycle.contains(8));
    try std.testing.expect(try lifecycle.finish(8));
    try std.testing.expect(!lifecycle.contains(8));

    try lifecycle.open(12, "POST", false);
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
        /// Optional peer-advertised stream offset for lightweight protected
        /// runtimes. The handshake runtime keeps this state in
        /// `one_rtt.Connection`; preconfigured-key paths use it only for
        /// blocking helpers that need deterministic small receive windows.
        flow_limit: ?u64 = null,
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    last_entry_index: ?usize = null,
    entry_index: std.AutoHashMapUnmanaged(u62, usize) = .empty,
    frame_scratch: std.ArrayList(quic.Frame) = .empty,
    payload_scratch: std.ArrayList(u8) = .empty,
    data_prefix_scratch: body_batch.Prefix = undefined,
    batch_scratch: body_batch.Scratch = .{},
    max_streams: usize,

    fn init(
        allocator: std.mem.Allocator,
        max_streams: usize,
    ) OutboundBodySet {
        return .{ .allocator = allocator, .max_streams = max_streams };
    }

    fn deinit(self: *OutboundBodySet) void {
        self.batch_scratch.deinit(self.allocator);
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

    fn enableFlowLimit(
        self: *OutboundBodySet,
        stream_id: u62,
        additional_window: usize,
    ) Error!void {
        const entry = self.find(stream_id) orelse return error.UnexpectedStream;
        if (entry.flow_limit != null) return;
        const window = std.math.cast(u64, additional_window) orelse
            return error.InvalidWindow;
        entry.flow_limit = std.math.add(
            u64,
            entry.send.next_offset,
            window,
        ) catch return error.InvalidWindow;
    }

    fn updateFlowLimit(
        self: *OutboundBodySet,
        stream_id: u62,
        maximum_stream_data: u64,
    ) void {
        const entry = self.find(stream_id) orelse return;
        const current = entry.flow_limit orelse return;
        if (maximum_stream_data <= current) return;
        entry.flow_limit = maximum_stream_data;
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

/// RFC 9114 §5.2 processing certainty for a client-initiated request stream.
/// A stream at or above the server's GOAWAY identifier was not processed and
/// may be retried on another connection, subject to application replay policy.
pub const GoAwayRetryDisposition = enum {
    no_goaway,
    may_have_been_processed,
    safe_to_retry,
};

const ServerRequestLifecycle = struct {
    const ActiveRequest = struct {
        stream_id: u62,
        priority: http3.Priority,
    };

    allocator: std.mem.Allocator,
    active_streams: std.ArrayList(ActiveRequest) = .empty,
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
        initial_priority: http3.Priority,
    ) Error!void {
        const slot = try self.active_stream_index.getOrPut(
            self.allocator,
            stream_id,
        );
        if (slot.found_existing) return error.UnexpectedStream;
        errdefer _ = self.active_stream_index.remove(stream_id);
        const index = self.active_streams.items.len;
        try self.active_streams.append(self.allocator, .{
            .stream_id = stream_id,
            .priority = initial_priority,
        });
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
        _ = self.active_stream_index.remove(removed.stream_id);
        if (index != last_index) {
            const moved = self.active_streams.items[index];
            self.active_stream_index.getPtr(moved.stream_id).?.* = index;
        }
        if (self.active_streams.items.len == 0) {
            self.lowest_active_stream_index = null;
        } else if (lowest == index) {
            self.recomputeLowestActiveStream();
        } else if (lowest == last_index) {
            self.lowest_active_stream_index = index;
        }
    }

    fn contains(self: ServerRequestLifecycle, stream_id: u62) bool {
        return self.active_stream_index.count() != 0 and
            self.active_stream_index.contains(stream_id);
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
        return self.active_streams.items[index].stream_id;
    }

    fn priority(
        self: ServerRequestLifecycle,
        stream_id: u62,
    ) http3.Priority {
        if (self.active_stream_index.count() == 0) return .{};
        const index = self.active_stream_index.get(stream_id) orelse
            return .{};
        if (index >= self.active_streams.items.len) return .{};
        const active = self.active_streams.items[index];
        if (active.stream_id != stream_id) return .{};
        return active.priority;
    }

    fn considerLowestActiveStream(
        self: *ServerRequestLifecycle,
        index: usize,
    ) void {
        const lowest = self.lowest_active_stream_index orelse {
            self.lowest_active_stream_index = index;
            return;
        };
        if (self.active_streams.items[index].stream_id <
            self.active_streams.items[lowest].stream_id)
        {
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

    try lifecycle.markReceived(0, .{ .urgency = 5 });
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectEqual(
        @as(u3, 5),
        lifecycle.priority(0).urgency,
    );
    try lifecycle.markReceived(4, .{ .urgency = 1 });
    try lifecycle.markReceived(8, .{});
    try std.testing.expectEqual(@as(?u62, 0), lifecycle.lowestActiveStream());
    try std.testing.expectError(
        error.UnexpectedStream,
        lifecycle.markReceived(4, .{}),
    );
    try std.testing.expectEqual(@as(?u62, 8), lifecycle.highest_processed_stream_id);
    try std.testing.expectEqual(@as(u64, 12), try lifecycle.finalGoAwayId());

    lifecycle.markFinished(4);
    try std.testing.expect(!lifecycle.active_stream_index.contains(4));
    try std.testing.expect(lifecycle.active_stream_index.contains(8));
    try std.testing.expectEqual(
        @as(u3, 3),
        lifecycle.priority(8).urgency,
    );
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

test "HTTP/3 response capacity bypasses header-only send credit" {
    try std.testing.expectEqual(
        @as(usize, 0),
        responseBodySendCapacity(256, 64, 256, 256, 1200, 1024),
    );
    try std.testing.expectEqual(
        @as(usize, 192),
        responseBodySendCapacity(256, 512, 256, 512, 1200, 1024),
    );
    try std.testing.expectEqual(
        @as(usize, 100),
        responseBodySendCapacity(100, 512, 512, 512, 1200, 1024),
    );
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
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    request: http3.Request,
    options: HandshakeSessionOptions,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    scratch.reset();
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try request.writeDynamic(
        &scratch.encoded,
        connection.endpoint.allocator,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    message_sent = true;
}

fn sendConnectionResponseSequence(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
    stream_id: u62,
    informational: []const http3.InformationalResponse,
    response: http3.Response,
    options: HandshakeSessionOptions,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
) Error!void {
    scratch.reset();
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try http3.writeResponseSequenceDynamic(
        &scratch.encoded,
        connection.endpoint.allocator,
        informational,
        response,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    message_sent = true;
}

fn sendProtectedMessage(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    request: http3.Request,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    scratch.reset();
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try request.writeDynamic(
        &scratch.encoded,
        endpoint.allocator,
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

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        scratch.frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
    message_sent = true;
}

fn sendProtectedResponseSequence(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    scratch: *StreamMessageSendScratch,
    stream_id: u62,
    informational: []const http3.InformationalResponse,
    response: http3.Response,
    peer_settings: http3.Settings,
    qpack: *QpackEncodeState,
    qpack_encoder_send: *quic.stream_state.SendState,
    qpack_encoder_prefix_sent: *bool,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
) Error!void {
    scratch.reset();
    // A field section can acquire dynamic-table references before any network
    // I/O. Release those references when encoder- or response-stream sending
    // fails; unreferenced speculative inserts remain useful for later sends.
    var message_sent = false;
    errdefer if (!message_sent) qpack.abandonStream(stream_id);
    try http3.writeResponseSequenceDynamic(
        &scratch.encoded,
        endpoint.allocator,
        informational,
        response,
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

    var send_state = quic.stream_state.SendState.init(stream_id);
    try send_state.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        scratch.frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
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
    try http3.writeResponseSequenceDynamic(
        pushed,
        allocator,
        push.informational,
        push.response,
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
    scratch: *PushSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
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
    scratch.reset();
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
        &scratch.parent,
        &scratch.pushed,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    // Promise bytes precede the pushed response in this frame list. QUIC may
    // reorder the streams, and the receive lifecycle deliberately tolerates
    // that, but same-call ordering minimizes unnecessary buffering.
    try appendMessageFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        request_stream_id,
        scratch.parent.items,
        options.max_stream_frame_data,
    );
    try appendMessageFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        push_stream_id,
        scratch.pushed.items,
        options.max_stream_frame_data,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
}

fn sendProtectedPush(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    scratch: *PushSendScratch,
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
    scratch.reset();
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
        &scratch.parent,
        &scratch.pushed,
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
    try appendMessageFrames(
        &scratch.frames,
        endpoint.allocator,
        request_stream_id,
        scratch.parent.items,
        config.max_stream_frame_data,
    );
    try appendMessageFrames(
        &scratch.frames,
        endpoint.allocator,
        push_stream_id,
        scratch.pushed.items,
        config.max_stream_frame_data,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        scratch.frames.items,
        config.max_frames_per_packet,
        protected_send,
    );
}

fn sendConnectionStreamingHead(
    connection: *quic.one_rtt.Connection,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
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
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    var send = quic.stream_state.SendState.init(stream_id);
    try send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        !body_allowed or
            (expected_length != null and expected_length.? == 0),
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
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
    scratch: *StreamMessageSendScratch,
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
    try send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
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
        scratch.frames.items,
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

fn responseBodySendCapacity(
    remaining: usize,
    connection: usize,
    stream: usize,
    congestion: usize,
    datagram_size: usize,
    chunk_limit: usize,
) usize {
    if (remaining == 0) return 0;
    const credit = @min(
        connection,
        stream,
        congestion,
        datagram_size,
        chunk_limit,
    );
    // QUIC credit counts the HTTP/3 DATA prefix and QUIC STREAM-frame
    // metadata too. Requiring this conservative margin prevents a candidate
    // with only header-sized credit from winning urgency selection and then
    // blocking a lower-urgency response that could make useful progress.
    if (credit <= paced_body_frame_overhead_margin) return 0;
    return @min(remaining, credit - paced_body_frame_overhead_margin);
}

fn pacedProtectedBodyChunkLimit(config: ProtectedConfig) usize {
    const frame_budget = config.max_stream_frame_data *|
        @max(@as(usize, 1), config.max_frames_per_packet);
    const data_budget = if (frame_budget > paced_body_frame_overhead_margin)
        frame_budget - paced_body_frame_overhead_margin
    else
        1;
    return @max(@as(usize, 1), data_budget);
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
    var prefix: body_batch.Prefix = undefined;
    if (options.enable_data_prefix_fast_path and
        try body_batch.appendDataStreamFrames(
            &entry.send,
            &bodies.frame_scratch,
            connection.endpoint.allocator,
            &prefix,
            data,
            fin,
            options.max_stream_frame_data,
            options.max_frames_per_packet,
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

fn sendConnectionBodyBatchPaced(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    options: HandshakeSessionOptions,
    context: anytype,
    comptime receive_progress: anytype,
    comptime finish_stream: anytype,
) Error!void {
    var sent: usize = 0;
    while (sent < chunks.len) {
        sent += sendConnectionBodyBatchPacedProgress(
            connection,
            bodies,
            chunks[sent..],
            options,
            context,
            finish_stream,
        ) catch |err| switch (err) {
            error.FlowControlBlocked, error.CongestionLimited => {
                try receive_progress(context);
                continue;
            },
            error.PacingLimited => {
                try connection.waitForPacingAvailability();
                continue;
            },
            else => return err,
        };
    }
}

/// Send at most one transport-accepted prefix of `chunks`.
///
/// Returning after each socket-visible prefix gives higher-level schedulers a
/// replan point for newly received PRIORITY_UPDATE frames. The compatibility
/// batch API loops over this primitive to preserve its all-chunks contract.
fn sendConnectionBodyBatchPacedProgress(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    chunks: []const BodyChunk,
    options: HandshakeSessionOptions,
    context: anytype,
    comptime finish_stream: anytype,
) Error!usize {
    if (chunks.len == 0) return 0;
    for (chunks, 0..) |chunk, i| {
        if (chunk.data.len > pacedBodyChunkLimit(options)) {
            return error.DatagramTooLarge;
        }
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (chunks[j].stream_id == chunk.stream_id) {
                return error.UnexpectedStream;
            }
        }
    }

    const Staged = struct {
        stream_id: u62,
        entry: OutboundBodySet.Entry,
        fin: bool,
    };
    var staged: [quic.one_rtt.max_batch_packets]Staged = undefined;
    var packets: [quic.one_rtt.max_batch_packets][]const quic.Frame =
        undefined;
    const count = @min(quic.one_rtt.max_batch_packets, chunks.len);
    const window = chunks[0..count];
    try bodies.batch_scratch.begin(bodies.allocator, count);

    for (window, 0..) |chunk, i| {
        const current = bodies.find(chunk.stream_id) orelse
            return error.UnexpectedStream;
        staged[i] = .{
            .stream_id = chunk.stream_id,
            .entry = current.*,
            .fin = chunk.fin,
        };
        try bodies.prepareChunkForEntry(
            &staged[i].entry,
            chunk.data.len,
            chunk.fin,
        );
        const frame_start = bodies.batch_scratch.frames.items.len;
        if (chunk.data.len == 0) {
            try staged[i].entry.send.appendFrames(
                &bodies.batch_scratch.frames,
                bodies.allocator,
                &.{},
                options.max_stream_frame_data,
                chunk.fin,
            );
        } else if (!try body_batch.appendDataStreamFrames(
            &staged[i].entry.send,
            &bodies.batch_scratch.frames,
            bodies.allocator,
            &bodies.batch_scratch.prefixes.items[i],
            chunk.data,
            chunk.fin,
            options.max_stream_frame_data,
            options.max_frames_per_packet,
        )) {
            return error.DatagramTooLarge;
        }
        const frame_len =
            bodies.batch_scratch.frames.items.len - frame_start;
        if (frame_len == 0 or
            frame_len > @max(@as(usize, 1), options.max_frames_per_packet))
        {
            return error.DatagramTooLarge;
        }
        bodies.batch_scratch.frame_ranges.items[i] = .{
            .start = frame_start,
            .len = frame_len,
        };
    }

    for (bodies.batch_scratch.frame_ranges.items[0..count], 0..) |range, i| {
        packets[i] = bodies.batch_scratch.frames.items[range.start .. range.start + range.len];
        if (try connection.packetLenForFramesAtOffset(
            i,
            packets[i],
        ) > connection.currentSendDatagramSize()) {
            return error.DatagramTooLarge;
        }
    }

    const result = try connection.sendManyProgress(packets[0..count]);
    if (result.sent_count > count or
        result.protected_count > count or
        result.sent_count > result.protected_count)
    {
        return error.Unexpected;
    }

    // QUIC commits only the socket-visible prefix. Mirror that exact
    // prefix into HTTP/3 body offsets and FIN state; protected-but-unsent
    // suffix packets consumed nonces but had their transport flow state
    // rolled back and remain safe to retry under fresh packet numbers.
    for (staged[0..result.sent_count]) |committed| {
        const entry = bodies.find(committed.stream_id) orelse
            return error.UnexpectedStream;
        entry.* = committed.entry;
        if (committed.fin) {
            _ = bodies.finish(committed.stream_id);
            finish_stream(context, committed.stream_id);
        }
    }
    if (result.send_error) |err| return err;
    if (result.sent_count != result.protected_count) {
        return error.Unexpected;
    }
    if (result.sent_count == 0) return error.Unexpected;
    return result.sent_count;
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
    bodies.frame_scratch.clearRetainingCapacity();
    if (try body_batch.appendDataStreamFrames(
        &entry.send,
        &bodies.frame_scratch,
        endpoint.allocator,
        &bodies.data_prefix_scratch,
        data,
        fin,
        config.max_stream_frame_data,
        config.max_frames_per_packet,
    )) {
        if (entry.flow_limit) |limit| {
            if (entry.send.next_offset > limit) {
                return error.FlowControlBlocked;
            }
        }
        try sendProtectedFrames(
            endpoint,
            to,
            config.send_keys,
            config.peer_connection_id,
            next_packet_number,
            bodies.frame_scratch.items,
            config.max_frames_per_packet,
            protected_send,
        );
        if (fin) _ = bodies.finish(stream_id);
        return;
    }

    bodies.payload_scratch.clearRetainingCapacity();
    try writeDataFrame(
        &bodies.payload_scratch,
        endpoint.allocator,
        data,
    );
    if (entry.flow_limit) |limit| {
        const next_offset = std.math.add(
            u64,
            entry.send.next_offset,
            bodies.payload_scratch.items.len,
        ) catch return error.InvalidFrameLength;
        if (next_offset > limit) return error.FlowControlBlocked;
    }
    try entry.send.appendFrames(
        &bodies.frame_scratch,
        endpoint.allocator,
        bodies.payload_scratch.items,
        config.max_stream_frame_data,
        fin,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        bodies.frame_scratch.items,
        config.max_frames_per_packet,
        protected_send,
    );
    if (fin) _ = bodies.finish(stream_id);
}

fn sendConnectionTrailers(
    connection: *quic.one_rtt.Connection,
    bodies: *OutboundBodySet,
    scratch: *StreamMessageSendScratch,
    critical_scratch: *CriticalStreamSendScratch,
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
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try http3.writeTrailersDynamic(
        &scratch.encoded,
        connection.endpoint.allocator,
        trailers,
        peer_settings,
        stream_id,
        qpack,
    );
    try sendConnectionQpackEncoderInstructions(
        connection,
        critical_scratch,
        qpack,
        qpack_encoder_send,
        qpack_encoder_prefix_sent,
        options,
    );
    try entry.send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.encoded.items,
        options.max_stream_frame_data,
        true,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
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
    scratch: *StreamMessageSendScratch,
) Error!void {
    const entry = try bodies.prepareTrailers(stream_id);
    const previous = entry.*;
    errdefer entry.* = previous;
    scratch.reset();
    const pending_sections_len = qpack.pending_sections.items.len;
    errdefer qpack.rollbackPendingSections(pending_sections_len);
    try http3.writeTrailersDynamic(
        &scratch.encoded,
        endpoint.allocator,
        trailers,
        peer_settings,
        stream_id,
        qpack,
    );
    if (entry.flow_limit) |limit| {
        const next_offset = std.math.add(
            u64,
            entry.send.next_offset,
            scratch.encoded.items.len,
        ) catch return error.InvalidFrameLength;
        if (next_offset > limit) return error.FlowControlBlocked;
    }
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
    try entry.send.appendFrames(
        &scratch.frames,
        endpoint.allocator,
        scratch.encoded.items,
        config.max_stream_frame_data,
        true,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        scratch.frames.items,
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

fn visitStreamingServerRequestPacket(
    session: *HandshakeServerSession,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    _ = try applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        session.established.connection.endpoint.allocator,
        &session.control,
        &session.qpack_decode,
        &session.qpack_encode,
        &session.request_streams,
        &session.streaming_requests,
        session.peer_promised_push_ids.items,
        null,
    );
}

fn visitDetachedServerRequestPacket(
    context: struct { *HandshakeServerSession, u62 },
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    const session, const detached_stream_id = context;
    _ = try applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        session.established.connection.endpoint.allocator,
        &session.control,
        &session.qpack_decode,
        &session.qpack_encode,
        &session.request_streams,
        &session.streaming_requests,
        session.peer_promised_push_ids.items,
        detached_stream_id,
    );
}

const ConnectionRequestReceiveContext = struct {
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    request_streams: *RequestStreamSet,
    peer_promised_push_ids: []const u64,
    reset: ?RequestStreamReset = null,
};

fn visitConnectionRequestPacket(
    context: *ConnectionRequestReceiveContext,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    context.reset = try applyServerRequestPacketFrames(
        packet.from,
        packet.frames,
        context.connection.endpoint.allocator,
        context.control,
        context.qpack_decode,
        context.qpack_encode,
        context.request_streams,
        null,
        context.peer_promised_push_ids,
        null,
    );
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
        var context: ConnectionRequestReceiveContext = .{
            .connection = connection,
            .control = control,
            .qpack_decode = qpack_decode,
            .qpack_encode = qpack_encode,
            .request_streams = request_streams,
            .peer_promised_push_ids = peer_promised_push_ids,
        };
        try receive_packets.visit(
            connection,
            &context,
            visitConnectionRequestPacket,
        );
        if (context.reset) |reset| {
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
    detached_stream_id: ?u62,
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
        if (detached_stream_id != null and
            frame.stream.stream_id == detached_stream_id.?)
        {
            // QUIC has already assembled this frame in the connection receive
            // state. Its protocol adapter consumes it directly.
            continue;
        }
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
            null,
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
    detached_stream_id: ?u62,
) Error!void {
    var context: ConnectionResponseReceiveContext = .{
        .connection = connection,
        .control = control,
        .qpack_decode = qpack_decode,
        .qpack_encode = qpack_encode,
        .response_streams = response_streams,
        .streaming_responses = streaming_responses,
        .push_streams = push_streams,
        .request_lifecycle = request_lifecycle,
        .detached_stream_id = detached_stream_id,
    };
    try receive_packets.visit(
        connection,
        &context,
        visitConnectionResponsePacket,
    );
}

const ConnectionResponseReceiveContext = struct {
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    qpack_decode: *QpackDecodeState,
    qpack_encode: *QpackEncodeState,
    response_streams: *ResponseStreamSet,
    streaming_responses: ?*StreamingResponseSet,
    push_streams: ?*PushStreamSet,
    request_lifecycle: ?*const ClientRequestLifecycle,
    detached_stream_id: ?u62,
};

fn visitConnectionResponsePacket(
    context: *ConnectionResponseReceiveContext,
    packet: quic.one_rtt.ReceivedPacketView,
) Error!void {
    const connection = context.connection;
    const control = context.control;
    const qpack_decode = context.qpack_decode;
    const qpack_encode = context.qpack_encode;
    const response_streams = context.response_streams;
    const streaming_responses = context.streaming_responses;
    const push_streams = context.push_streams;
    const request_lifecycle = context.request_lifecycle;
    const detached_stream_id = context.detached_stream_id;
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
        if (detached_stream_id != null and
            frame.stream.stream_id == detached_stream_id.?)
        {
            continue;
        }
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

fn controlFramePayloadInto(
    control: *http3.ControlState,
    storage: *[http3.max_single_varint_frame_len]u8,
    kind: ControlFrameKind,
    value: u64,
) Error![]const u8 {
    return switch (kind) {
        .goaway => control.writeGoAwayInto(storage, value),
    };
}

fn sendConnectionControlFrame(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    kind: ControlFrameKind,
    value: u64,
) Error!void {
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_goaway_id = control.local_goaway_id;
    errdefer control.local_goaway_id = previous_goaway_id;
    const payload = try controlFramePayloadInto(control, &payload_storage, kind, value);
    try sendConnectionControlBytes(connection, control_send, options, payload);
}

fn pushControlFramePayloadInto(
    control: *http3.ControlState,
    storage: *[http3.max_single_varint_frame_len]u8,
    kind: PushControlFrameKind,
    push_id: u64,
) Error![]const u8 {
    return switch (kind) {
        .max_push_id => control.writeMaxPushIdInto(storage, push_id),
        .cancel_push => {
            const max_push_id = control.local_max_push_id orelse
                return error.PushIdExceeded;
            if (push_id > max_push_id) return error.PushIdExceeded;
            return http3.writeCancelPushFrameInto(storage, push_id);
        },
    };
}

fn sendConnectionControlBytes(
    connection: *quic.one_rtt.Connection,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    payload: []const u8,
) Error!void {
    const previous_send = control_send.*;
    errdefer control_send.* = previous_send;
    var frame_storage: [http3.max_priority_update_frame_len]quic.Frame = undefined;
    const frames = try controlFramesInto(
        control_send,
        &frame_storage,
        payload,
        options.max_stream_frame_data,
    );
    try sendConnectionFrames(connection, frames, options.max_frames_per_packet);
}

/// Split a small control message without allocating a temporary frame list.
/// The largest runtime control payload is a canonical PRIORITY_UPDATE at 19
/// bytes, so even the deliberately tiny one-byte STREAM chunk size used by
/// tests fits the fixed frame array.
fn controlFramesInto(
    control_send: *quic.stream_state.SendState,
    storage: *[http3.max_priority_update_frame_len]quic.Frame,
    payload: []const u8,
    max_frame_data_len: usize,
) Error![]const quic.Frame {
    std.debug.assert(payload.len <= storage.len);
    if (control_send.fin_sent) return error.FinalSizeMismatch;
    if (max_frame_data_len == 0) return error.InvalidStreamRange;
    const next_offset = std.math.add(
        u64,
        control_send.next_offset,
        payload.len,
    ) catch return error.InvalidStreamRange;
    var payload_offset: usize = 0;
    var frame_count: usize = 0;
    while (payload_offset < payload.len) {
        const chunk_len = @min(
            max_frame_data_len,
            payload.len - payload_offset,
        );
        storage[frame_count] = .{ .stream = .{
            .stream_id = control_send.stream_id,
            .offset = control_send.next_offset + payload_offset,
            .data = payload[payload_offset..][0..chunk_len],
            .fin = false,
        } };
        frame_count += 1;
        payload_offset += chunk_len;
    }
    control_send.next_offset = next_offset;
    return storage[0..frame_count];
}

fn sendConnectionPushControl(
    connection: *quic.one_rtt.Connection,
    control: *http3.ControlState,
    control_send: *quic.stream_state.SendState,
    options: HandshakeSessionOptions,
    kind: PushControlFrameKind,
    push_id: u64,
) Error!void {
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_max_push_id = control.local_max_push_id;
    errdefer control.local_max_push_id = previous_max_push_id;
    const payload = try pushControlFramePayloadInto(
        control,
        &payload_storage,
        kind,
        push_id,
    );
    try sendConnectionControlBytes(connection, control_send, options, payload);
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
    var payload_storage: [http3.max_priority_update_frame_len]u8 = undefined;
    const payload = switch (frame_type) {
        http3.FrameType.priority_update_request => try http3.writePriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        http3.FrameType.priority_update_push => try http3.writePushPriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        else => return error.InvalidPriorityUpdate,
    };
    try sendConnectionControlBytes(connection, control_send, options, payload);
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
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_goaway_id = control.local_goaway_id;
    errdefer control.local_goaway_id = previous_goaway_id;
    const payload = try controlFramePayloadInto(
        control,
        &payload_storage,
        kind,
        value,
    );
    try sendProtectedControlBytes(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        payload,
    );
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
    var payload_storage: [http3.max_single_varint_frame_len]u8 = undefined;
    const previous_max_push_id = control.local_max_push_id;
    errdefer control.local_max_push_id = previous_max_push_id;
    const payload = try pushControlFramePayloadInto(
        control,
        &payload_storage,
        kind,
        push_id,
    );
    try sendProtectedControlBytes(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        payload,
    );
}

fn sendProtectedControlBytes(
    endpoint: *quic.runtime.Endpoint,
    to: net.IpAddress,
    config: ProtectedConfig,
    control_send: *quic.stream_state.SendState,
    next_packet_number: *u64,
    protected_send: *ProtectedSendState,
    payload: []const u8,
) Error!void {
    const previous_send = control_send.*;
    errdefer control_send.* = previous_send;
    var frame_storage: [http3.max_priority_update_frame_len]quic.Frame = undefined;
    const frames = try controlFramesInto(
        control_send,
        &frame_storage,
        payload,
        config.max_stream_frame_data,
    );
    try sendProtectedFrames(
        endpoint,
        to,
        config.send_keys,
        config.peer_connection_id,
        next_packet_number,
        frames,
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
    var payload_storage: [http3.max_priority_update_frame_len]u8 = undefined;
    const payload = switch (frame_type) {
        http3.FrameType.priority_update_request => try http3.writePriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        http3.FrameType.priority_update_push => try http3.writePushPriorityUpdateFrameInto(
            &payload_storage,
            prioritized_element_id,
            priority,
        ),
        else => return error.InvalidPriorityUpdate,
    };
    try sendProtectedControlBytes(
        endpoint,
        to,
        config,
        control_send,
        next_packet_number,
        protected_send,
        payload,
    );
}

fn sendConnectionSettings(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
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

    const previous_settings = control.settings;
    const previous_control_send = control_send.*;
    const previous_encoder_send = qpack_encoder_send.*;
    const previous_decoder_send = qpack_decoder_send.*;
    errdefer control.settings = previous_settings;
    errdefer control_send.* = previous_control_send;
    errdefer qpack_encoder_send.* = previous_encoder_send;
    errdefer qpack_decoder_send.* = previous_decoder_send;
    scratch.reset();
    try control.writeSettingsStream(
        &scratch.payload,
        connection.endpoint.allocator,
        options.local_settings,
    );
    const control_end = scratch.payload.items.len;
    const encoder_start = control_end;
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }
    const encoder_end = scratch.payload.items.len;
    const decoder_start = encoder_end;
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }

    // Append all bytes before forming borrowing slices so an ArrayList growth
    // cannot invalidate an earlier control/QPACK STREAM descriptor.
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items[0..control_end],
        control_end,
        false,
    );
    const encoder_stream_id =
        if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(
            encoder_stream_id,
        );
    }
    if (encoder_end != encoder_start) {
        try qpack_encoder_send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[encoder_start..encoder_end],
            encoder_end - encoder_start,
            false,
        );
    }
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (scratch.payload.items.len != decoder_start) {
        try qpack_decoder_send.appendFrames(
            &scratch.frames,
            connection.endpoint.allocator,
            scratch.payload.items[decoder_start..],
            scratch.payload.items.len - decoder_start,
            false,
        );
    }
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    if (encoder_end != encoder_start) qpack_encoder_prefix_sent.* = true;
    if (scratch.payload.items.len != decoder_start) {
        qpack_decoder_prefix_sent.* = true;
    }
}

fn sendConnectionQpackEncoderInstructions(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    qpack: *QpackEncodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: HandshakeSessionOptions,
) Error!void {
    const pending = qpack.pendingEncoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    scratch.reset();
    try scratch.payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(
            &scratch.payload,
            connection.endpoint.allocator,
        );
    }
    scratch.payload.appendSliceAssumeCapacity(pending);

    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items,
        options.max_stream_frame_data,
        false,
    );
    // Keep the critical encoder stream in an earlier packet than any field
    // section that may depend on it, including when frame-list chunking is one.
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    prefix_sent.* = true;
    qpack.clearEncoderInstructions();
}

fn sendConnectionQpackFeedback(
    connection: *quic.one_rtt.Connection,
    scratch: *CriticalStreamSendScratch,
    qpack: *QpackDecodeState,
    send_state: *quic.stream_state.SendState,
    prefix_sent: *bool,
    options: HandshakeSessionOptions,
) Error!void {
    const pending = qpack.pendingDecoderInstructions();
    if (pending.len == 0) return;

    const previous_send = send_state.*;
    errdefer send_state.* = previous_send;
    scratch.reset();
    try scratch.payload.ensureTotalCapacity(
        connection.endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        &scratch.payload,
        connection.endpoint.allocator,
    );
    scratch.payload.appendSliceAssumeCapacity(pending);
    try send_state.appendFrames(
        &scratch.frames,
        connection.endpoint.allocator,
        scratch.payload.items,
        options.max_stream_frame_data,
        false,
    );
    try sendConnectionFrames(
        connection,
        scratch.frames.items,
        options.max_frames_per_packet,
    );
    prefix_sent.* = true;
    qpack.clearDecoderInstructions();
}

fn cancelConnectionRequest(
    connection: *quic.one_rtt.Connection,
    critical_scratch: *CriticalStreamSendScratch,
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
            critical_scratch,
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
    protected_send.resetCriticalStreamScratch();
    const payload = &protected_send.critical_stream_payload;
    const frames = &protected_send.critical_stream_frames;
    try control.writeSettingsStream(
        payload,
        endpoint.allocator,
        config.local_settings,
    );
    const control_end = payload.items.len;
    const encoder_start = control_end;
    const is_client = stream_id == client_control_stream_id;
    if (!qpack_encoder_prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(payload, endpoint.allocator);
    }
    const encoder_end = payload.items.len;
    const decoder_start = encoder_end;
    if (!qpack_decoder_prefix_sent.*) {
        try http3.writeQpackDecoderStreamPrefix(payload, endpoint.allocator);
    }

    // Form borrowing slices only after every append is complete: growing the
    // shared byte list while frames already point into it would invalidate the
    // earlier control/QPACK STREAM descriptors.
    if (control_send.stream_id != stream_id) control_send.* = quic.stream_state.SendState.init(stream_id);
    try control_send.appendFrames(
        frames,
        endpoint.allocator,
        payload.items[0..control_end],
        control_end,
        false,
    );
    const encoder_stream_id =
        if (is_client) client_qpack_encoder_stream_id else server_qpack_encoder_stream_id;
    if (qpack_encoder_send.stream_id != encoder_stream_id) {
        qpack_encoder_send.* = quic.stream_state.SendState.init(encoder_stream_id);
    }
    if (encoder_end != encoder_start) {
        try qpack_encoder_send.appendFrames(
            frames,
            endpoint.allocator,
            payload.items[encoder_start..encoder_end],
            encoder_end - encoder_start,
            false,
        );
    }
    if (qpack_decoder_send.stream_id != (if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id)) {
        qpack_decoder_send.* = quic.stream_state.SendState.init(
            if (is_client) client_qpack_decoder_stream_id else server_qpack_decoder_stream_id,
        );
    }
    if (payload.items.len != decoder_start) {
        try qpack_decoder_send.appendFrames(
            frames,
            endpoint.allocator,
            payload.items[decoder_start..],
            payload.items.len - decoder_start,
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
    if (encoder_end != encoder_start) qpack_encoder_prefix_sent.* = true;
    if (payload.items.len != decoder_start) qpack_decoder_prefix_sent.* = true;
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
    protected_send.resetCriticalStreamScratch();
    const payload = &protected_send.critical_stream_payload;
    const frames = &protected_send.critical_stream_frames;
    try payload.ensureTotalCapacity(
        endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) {
        try http3.writeQpackEncoderStreamPrefix(payload, endpoint.allocator);
    }
    payload.appendSliceAssumeCapacity(pending);

    try send_state.appendFrames(
        frames,
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
    protected_send.resetCriticalStreamScratch();
    const payload = &protected_send.critical_stream_payload;
    const frames = &protected_send.critical_stream_frames;
    try payload.ensureTotalCapacity(
        endpoint.allocator,
        @intFromBool(!prefix_sent.*) + pending.len,
    );
    if (!prefix_sent.*) try http3.writeQpackDecoderStreamPrefix(
        payload,
        endpoint.allocator,
    );
    payload.appendSliceAssumeCapacity(pending);

    try send_state.appendFrames(
        frames,
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
    try qpack.configurePeerLimits(
        capacity,
        control.settings.peer.qpack_blocked_streams,
    );
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
        if (control.peer_client_only_frame_generation !=
            previous.peer_client_only_frame_generation or
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
        control.peer_origin_generation != previous.peer_origin_generation)
    {
        // RFC 9412 defines ORIGIN only from servers to clients. Roll back the
        // complete frame even when it arrived across several STREAM packets.
        control.deinit(allocator);
        control.* = previous;
        previous_owned = false;
        return error.UnexpectedFrame;
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
        const frame = http3.Frame.parse(payload[offset..]) catch |err| switch (err) {
            error.BufferTooShort => return false,
            else => return err,
        };
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
        try control.appendControlPayload(
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
                try control.appendControlPayload(
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

test "HTTP/3 control frame splitting uses caller storage transactionally" {
    var send = quic.stream_state.SendState.init(client_control_stream_id);
    send.next_offset = 9;
    var storage: [http3.max_priority_update_frame_len]quic.Frame = undefined;
    const frames = try controlFramesInto(&send, &storage, "abcdef", 2);
    try std.testing.expectEqual(@as(usize, 3), frames.len);
    try std.testing.expectEqual(@as(u64, 15), send.next_offset);
    for (frames, 0..) |frame, i| {
        try std.testing.expect(frame == .stream);
        try std.testing.expectEqual(client_control_stream_id, frame.stream.stream_id);
        try std.testing.expectEqual(@as(u64, 9 + i * 2), frame.stream.offset);
        try std.testing.expectEqualSlices(
            u8,
            "abcdef"[i * 2 ..][0..2],
            frame.stream.data,
        );
        try std.testing.expect(!frame.stream.fin);
    }

    const before = send;
    try std.testing.expectError(
        error.InvalidStreamRange,
        controlFramesInto(&send, &storage, "x", 0),
    );
    try std.testing.expectEqualDeep(before, send);
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

    const retry_client = HandshakeClient{
        .endpoint = undefined,
        .peer = .{ .ip4 = .loopback(443) },
        .allocator = std.testing.allocator,
        .established = undefined,
        .options = .{},
        .qpack_decode = undefined,
        .qpack_encode = undefined,
        .response_streams = undefined,
        .streaming_responses = undefined,
        .push_streams = undefined,
        .request_lifecycle = undefined,
        .outbound_bodies = undefined,
    };
    try std.testing.expectEqual(
        GoAwayRetryDisposition.no_goaway,
        retry_client.goAwayRetryDisposition(0),
    );
    var after_goaway = retry_client;
    after_goaway.control.peer_goaway_id = 8;
    try std.testing.expectEqual(@as(?u64, 8), after_goaway.peerGoAwayId());
    try std.testing.expectEqual(
        GoAwayRetryDisposition.may_have_been_processed,
        after_goaway.goAwayRetryDisposition(4),
    );
    try std.testing.expectEqual(
        GoAwayRetryDisposition.safe_to_retry,
        after_goaway.goAwayRetryDisposition(8),
    );
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

    var origin_payload: std.ArrayList(u8) = .empty;
    defer origin_payload.deinit(allocator);
    try http3.writeControlStreamPrefix(&origin_payload, allocator);
    try http3.writeSettingsFrame(&origin_payload, allocator, .{});
    try http3.OriginPayload.write(
        &origin_payload,
        allocator,
        &.{"https://illegal-client.example"},
    );
    var origin_server_control = http3.ControlState{};
    defer origin_server_control.deinit(allocator);
    try std.testing.expectError(
        error.UnexpectedFrame,
        applyControlStreamFrameForRole(
            &origin_server_control,
            allocator,
            .{
                .stream_id = client_control_stream_id,
                .offset = 0,
                .data = origin_payload.items,
            },
            .server,
        ),
    );
    try std.testing.expect(
        !origin_server_control.peerOriginSetInitialized(),
    );
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

test "HTTP/3 protected runtime sends and accumulates RFC 9412 origins" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xe1, 0xe2, 0xe3, 0xe4 };
    const server_cid = [_]u8{ 0xe5, 0xe6, 0xe7, 0xe8 };
    const client_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xe9} ** quic.protection.secret_len,
    );
    const server_keys = quic.protection.deriveAes128Keys(
        [_]u8{0xea} ** quic.protection.secret_len,
    );
    var server = try ProtectedServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{ .max_datagram_size = 4096 } },
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
        .{ .quic = .{ .max_datagram_size = 4096 } },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
        },
    );
    defer client.deinit();

    try server.sendOrigins(client.quic_client.address(), &.{
        "https://Example.COM",
        "https://cdn.example.com:8443",
    });
    try server.sendOrigins(client.quic_client.address(), &.{
        "https://example.com:443",
        "https://img.example.com",
    });
    // ORIGIN is processed by the same shared control-stream receive path as
    // SETTINGS and GOAWAY. Reading any application response is unnecessary;
    // consume the two control packets directly to isolate this extension.
    try client.pollControl();
    while (client.peerOrigins().len < 3) {
        try client.pollControl();
    }

    try std.testing.expect(client.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 3), client.peerOrigins().len);
    try std.testing.expect(client.peerOriginKnown(
        try http3.requestOrigin("https", "example.com"),
    ));
    try std.testing.expect(client.peerOriginKnown(
        try http3.requestOrigin("https", "CDN.EXAMPLE.COM:8443"),
    ));
    try std.testing.expect(client.peerOriginKnown(
        try http3.requestOrigin("https", "img.example.com:443"),
    ));
}

test "HTTP/3 runtime rejects non-empty QPACK critical streams" {
    const allocator = std.testing.allocator;
    var control = http3.ControlState{};
    defer control.deinit(allocator);
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

    // The one-packet path uses the same retained wire scratch. Pointing the
    // endpoint itself at the failing allocator catches a regression to the
    // allocating `one_rtt.sendFrames` convenience function.
    const original_endpoint_allocator = sender.allocator;
    sender.allocator = no_alloc.allocator();
    defer sender.allocator = original_endpoint_allocator;
    try send_state.sendFrames(
        &sender,
        receiver.address(),
        keys,
        "cid",
        &next_packet_number,
        frame_storage[0..1],
        1,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(u64, 7), next_packet_number);
}

test "HTTP/3 protected critical streams reuse send scratch" {
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
        [_]u8{0x7b} ** quic.protection.secret_len,
    );
    const local_cid = "client";
    const peer_cid = "server";
    const config: ProtectedConfig = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = local_cid,
        .peer_connection_id = peer_cid,
        .local_settings = .{ .qpack_max_table_capacity = 256 },
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 2,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var next_packet_number: u64 = 0;

    // Allocation failure before the first SETTINGS write must leave all
    // protocol offsets and sent flags retryable.
    var control = http3.ControlState{};
    defer control.deinit(allocator);
    var control_send = quic.stream_state.SendState.init(
        client_control_stream_id,
    );
    var qpack_encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    var qpack_decoder_send = quic.stream_state.SendState.init(
        client_qpack_decoder_stream_id,
    );
    var encoder_prefix_sent = false;
    var decoder_prefix_sent = false;
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = fail_first.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        sendProtectedSettings(
            &sender,
            receiver.address(),
            config,
            &control,
            &control_send,
            &qpack_encoder_send,
            &encoder_prefix_sent,
            &qpack_decoder_send,
            &decoder_prefix_sent,
            &next_packet_number,
            &protected_send,
            client_control_stream_id,
        ),
    );
    sender.allocator = allocator;
    try std.testing.expect(fail_first.has_induced_failure);
    try std.testing.expect(!control.settings.sent);
    try std.testing.expectEqual(@as(u64, 0), control_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), qpack_encoder_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), qpack_decoder_send.next_offset);
    try std.testing.expect(!encoder_prefix_sent);
    try std.testing.expect(!decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), next_packet_number);

    try sendProtectedSettings(
        &sender,
        receiver.address(),
        config,
        &control,
        &control_send,
        &qpack_encoder_send,
        &encoder_prefix_sent,
        &qpack_decoder_send,
        &decoder_prefix_sent,
        &next_packet_number,
        &protected_send,
        client_control_stream_id,
    );

    var encoder = QpackEncodeState.init(allocator, 256, 4096);
    defer encoder.deinit();
    try encoder.setCapacity(256);
    _ = try encoder.insertField(
        "x-critical-one",
        "encoder-instruction",
    );
    try sendProtectedQpackEncoderInstructions(
        &sender,
        receiver.address(),
        config,
        &encoder,
        &qpack_encoder_send,
        &encoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );

    var decoder = QpackDecodeState.init(allocator, 256, 4096);
    defer decoder.deinit();
    try decoder.recordStreamCancellation(quic.varint.max_value);
    try sendProtectedQpackFeedback(
        &sender,
        receiver.address(),
        config,
        &decoder,
        &qpack_decoder_send,
        &decoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );

    const critical_payload_capacity =
        protected_send.critical_stream_payload.capacity;
    const critical_frame_capacity =
        protected_send.critical_stream_frames.capacity;
    const wire_payload_capacity = protected_send.payload_scratch.capacity;
    const wire_packet_capacity = protected_send.packet_scratch.capacity;
    const critical_payload_ptr = protected_send.critical_stream_payload
        .allocatedSlice().ptr;
    const critical_frame_ptr = protected_send.critical_stream_frames
        .allocatedSlice().ptr;
    const wire_payload_ptr = protected_send.payload_scratch.allocatedSlice().ptr;
    const wire_packet_ptr = protected_send.packet_scratch.allocatedSlice().ptr;
    try std.testing.expect(critical_payload_capacity != 0);
    try std.testing.expect(critical_frame_capacity != 0);
    try std.testing.expect(wire_payload_capacity != 0);
    try std.testing.expect(wire_packet_capacity != 0);

    // Prepare all protocol-owned instructions before switching allocators so
    // the assertion isolates transport scratch rather than QPACK table growth.
    _ = try encoder.insertField(
        "x-critical-two",
        "encoder-instruction",
    );
    try decoder.recordStreamCancellation(quic.varint.max_value - 4);
    var second_control = http3.ControlState{};
    defer second_control.deinit(allocator);
    var second_control_send = quic.stream_state.SendState.init(
        client_control_stream_id,
    );
    var second_encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    var second_decoder_send = quic.stream_state.SendState.init(
        client_qpack_decoder_stream_id,
    );
    var second_encoder_prefix = false;
    var second_decoder_prefix = false;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = no_alloc.allocator();
    protected_send.allocator = no_alloc.allocator();
    defer {
        sender.allocator = allocator;
        protected_send.allocator = allocator;
    }
    try sendProtectedSettings(
        &sender,
        receiver.address(),
        config,
        &second_control,
        &second_control_send,
        &second_encoder_send,
        &second_encoder_prefix,
        &second_decoder_send,
        &second_decoder_prefix,
        &next_packet_number,
        &protected_send,
        client_control_stream_id,
    );
    try sendProtectedQpackEncoderInstructions(
        &sender,
        receiver.address(),
        config,
        &encoder,
        &qpack_encoder_send,
        &encoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );
    try sendProtectedQpackFeedback(
        &sender,
        receiver.address(),
        config,
        &decoder,
        &qpack_decoder_send,
        &decoder_prefix_sent,
        &next_packet_number,
        &protected_send,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        critical_payload_capacity,
        protected_send.critical_stream_payload.capacity,
    );
    try std.testing.expectEqual(
        critical_frame_capacity,
        protected_send.critical_stream_frames.capacity,
    );
    try std.testing.expectEqual(
        wire_payload_capacity,
        protected_send.payload_scratch.capacity,
    );
    try std.testing.expectEqual(
        wire_packet_capacity,
        protected_send.packet_scratch.capacity,
    );
    try std.testing.expectEqual(
        critical_payload_ptr,
        protected_send.critical_stream_payload.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        critical_frame_ptr,
        protected_send.critical_stream_frames.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        wire_payload_ptr,
        protected_send.payload_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        wire_packet_ptr,
        protected_send.packet_scratch.allocatedSlice().ptr,
    );
}

test "HTTP/3 connection SETTINGS allocation failure rolls back state" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var peer_endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer peer_endpoint.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .max_datagram_size = 4096 },
    );
    defer endpoint.deinit();
    const keys = quic.protection.deriveAes128Keys(
        [_]u8{0x8b} ** quic.protection.secret_len,
    );
    var connection = try quic.one_rtt.Connection.init(&endpoint, .{
        .peer = peer_endpoint.address(),
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .tls_handshake_complete = true,
        .enable_pacing = false,
    });
    defer connection.deinit();

    var control = http3.ControlState{};
    defer control.deinit(allocator);
    var control_send = quic.stream_state.SendState.init(
        client_control_stream_id,
    );
    var encoder_send = quic.stream_state.SendState.init(
        client_qpack_encoder_stream_id,
    );
    var decoder_send = quic.stream_state.SendState.init(
        client_qpack_decoder_stream_id,
    );
    var encoder_prefix_sent = false;
    var decoder_prefix_sent = false;
    var scratch: CriticalStreamSendScratch = .{};
    defer scratch.deinit(allocator);
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    endpoint.allocator = fail_first.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        sendConnectionSettings(
            &connection,
            &scratch,
            &control,
            &control_send,
            &encoder_send,
            &encoder_prefix_sent,
            &decoder_send,
            &decoder_prefix_sent,
            .{},
            client_control_stream_id,
        ),
    );
    endpoint.allocator = allocator;
    try std.testing.expect(fail_first.has_induced_failure);
    try std.testing.expect(!control.settings.sent);
    try std.testing.expectEqual(@as(u64, 0), control_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), encoder_send.next_offset);
    try std.testing.expectEqual(@as(u64, 0), decoder_send.next_offset);
    try std.testing.expect(!encoder_prefix_sent);
    try std.testing.expect(!decoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), connection.next_packet_number);

    try sendConnectionSettings(
        &connection,
        &scratch,
        &control,
        &control_send,
        &encoder_send,
        &encoder_prefix_sent,
        &decoder_send,
        &decoder_prefix_sent,
        .{},
        client_control_stream_id,
    );
    try std.testing.expect(control.settings.sent);
    try std.testing.expect(encoder_prefix_sent);
    try std.testing.expect(decoder_prefix_sent);
    try std.testing.expect(scratch.payload.capacity != 0);
    try std.testing.expect(scratch.frames.capacity != 0);
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
    try encoder.configurePeerLimits(256, 2);
    try std.testing.expectEqual(@as(?usize, 256), encoder.peer_max_capacity);
    try std.testing.expectEqual(@as(?u64, 2), encoder.peer_max_blocked_streams);
    try std.testing.expectEqual(@as(usize, 256), encoder.table.max_capacity);
    try std.testing.expectEqual(@as(usize, 256), encoder.table.capacity);
    const instruction_len = encoder.pendingEncoderInstructions().len;
    try std.testing.expect(instruction_len != 0);

    // Reprocessing retransmitted control bytes is idempotent, while a changed
    // value would violate HTTP/3's one-SETTINGS-frame connection contract.
    try encoder.configurePeerLimits(256, 2);
    try std.testing.expectEqual(
        instruction_len,
        encoder.pendingEncoderInstructions().len,
    );
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        encoder.configurePeerLimits(128, 2),
    );
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        encoder.configurePeerLimits(256, 1),
    );
    var excessive = QpackEncodeState.initAwaitingPeerSettings(
        allocator,
        4096,
    );
    defer excessive.deinit();
    try std.testing.expectError(
        error.QpackEncoderStreamError,
        excessive.configurePeerLimits(
            256,
            http3.Settings.max_supported_qpack_blocked_streams + 1,
        ),
    );
}

test "HTTP/3 QPACK encoder spends the peer blocked-stream budget" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(512, 1);
    _ = try encoder.insertField("x-speculative", "repeated-value");

    const fields = [_]http3.Qpack.HeaderField{.{
        .name = "x-speculative",
        .value = "repeated-value",
    }};
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    const first_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        first.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 1), first_prefix.required_insert_count);
    try std.testing.expectEqual(@as(usize, 1), encoder.blocked_section_counts.count());
    try std.testing.expectEqual(
        @as(?usize, 1),
        encoder.blocked_section_counts.get(0),
    );

    // More sections on the same ordered request stream consume no additional
    // SETTINGS_QPACK_BLOCKED_STREAMS credit. A different stream must remain
    // literal until decoder feedback releases the sole slot.
    var same_stream: std.ArrayList(u8) = .empty;
    defer same_stream.deinit(allocator);
    try encoder.encodeFieldSection(&same_stream, 0, &fields);
    const same_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        same_stream.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 1), same_prefix.required_insert_count);
    try std.testing.expectEqual(
        @as(?usize, 2),
        encoder.blocked_section_counts.get(0),
    );

    var gated: std.ArrayList(u8) = .empty;
    defer gated.deinit(allocator);
    try encoder.encodeFieldSection(&gated, 4, &fields);
    const gated_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        gated.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 0), gated_prefix.required_insert_count);
    try std.testing.expect(!encoder.hasPendingSections(4));

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .insert_count_increment = 1 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());

    var released: std.ArrayList(u8) = .empty;
    defer released.deinit(allocator);
    try encoder.encodeFieldSection(&released, 4, &fields);
    const released_prefix = try http3.Qpack.decodeFieldSectionPrefix(
        released.items,
        encoder.table,
    );
    try std.testing.expectEqual(@as(u64, 1), released_prefix.required_insert_count);
    try std.testing.expect(encoder.hasPendingSections(4));
}

test "HTTP/3 QPACK Section Ack releases speculative blocked streams" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(512, 2);
    _ = try encoder.insertField("x-speculative", "ack-value");

    const fields = [_]http3.Qpack.HeaderField{.{
        .name = "x-speculative",
        .value = "ack-value",
    }};
    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try encoder.encodeFieldSection(&second, 4, &fields);
    try std.testing.expectEqual(@as(usize, 2), encoder.blocked_section_counts.count());

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .section_acknowledgment = 0 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });

    // Section Ack advances Known Received Count to the section's RIC. That
    // makes every other section depending only on the same insert unblocked.
    try std.testing.expectEqual(@as(u64, 1), encoder.known_received_count);
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());
    try std.testing.expect(!encoder.hasPendingSections(0));
    try std.testing.expect(encoder.hasPendingSections(4));
}

test "HTTP/3 QPACK Stream Cancellation releases blocked-stream credit" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(512, 1);
    _ = try encoder.insertField("x-speculative", "cancel-value");
    const fields = [_]http3.Qpack.HeaderField{.{
        .name = "x-speculative",
        .value = "cancel-value",
    }};

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try encoder.encodeFieldSection(&first, 0, &fields);
    var gated: std.ArrayList(u8) = .empty;
    defer gated.deinit(allocator);
    try encoder.encodeFieldSection(&gated, 4, &fields);
    try std.testing.expectEqual(
        @as(u64, 0),
        (try http3.Qpack.decodeFieldSectionPrefix(
            gated.items,
            encoder.table,
        )).required_insert_count,
    );

    var feedback: std.ArrayList(u8) = .empty;
    defer feedback.deinit(allocator);
    try http3.writeQpackDecoderStreamPrefix(&feedback, allocator);
    try http3.Qpack.writeDecoderInstruction(
        &feedback,
        allocator,
        .{ .stream_cancellation = 0 },
    );
    var control = http3.ControlState{};
    try encoder.applyDecoderStreamFrame(&control, .{
        .stream_id = client_qpack_decoder_stream_id,
        .offset = 0,
        .data = feedback.items,
    });
    try std.testing.expectEqual(@as(usize, 0), encoder.blocked_section_counts.count());

    var released: std.ArrayList(u8) = .empty;
    defer released.deinit(allocator);
    try encoder.encodeFieldSection(&released, 4, &fields);
    try std.testing.expectEqual(
        @as(u64, 1),
        (try http3.Qpack.decodeFieldSectionPrefix(
            released.items,
            encoder.table,
        )).required_insert_count,
    );
}

test "HTTP/3 protected runtime sends a speculative QPACK request" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    const client_cid = [_]u8{ 0xb1, 0x71, 0x72, 0x73 };
    const server_cid = [_]u8{ 0xb2, 0x71, 0x72, 0x73 };
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
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
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
            .local_settings = .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 1,
            },
            .max_stream_frame_data = 1024,
        },
    );
    defer client.deinit();

    // Exchange SETTINGS before sending the application request so the client
    // can consume the peer's blocked-stream allowance immediately.
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
    try sendProtectedSettings(
        &server.quic_server.endpoint,
        client.quic_client.endpoint.address(),
        server.config,
        &server.control,
        &server.control_send,
        &server.qpack_encoder_send,
        &server.qpack_encoder_prefix_sent,
        &server.qpack_decoder_send,
        &server.qpack_decoder_prefix_sent,
        &server.next_packet_number,
        &server.protected_send,
        server_control_stream_id,
    );
    while (!client.control.settings.received) {
        try client.receiveResponsePacket();
    }
    try std.testing.expectEqual(
        @as(?u64, 1),
        client.qpack_encode.peer_max_blocked_streams,
    );

    _ = try client.qpack_encode.insertField(
        "x-speculative-runtime",
        "sent-before-feedback",
    );
    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/speculative-qpack",
        .authority = "localhost",
        .headers = &.{.{
            .name = "x-speculative-runtime",
            .value = "sent-before-feedback",
        }},
    });
    try std.testing.expectEqual(@as(u62, 0), stream_id);
    try std.testing.expectEqual(@as(u64, 0), client.qpack_encode.known_received_count);
    try std.testing.expectEqual(
        @as(?usize, 1),
        client.qpack_encode.blocked_section_counts.get(stream_id),
    );

    var request = try server.receiveRequest();
    defer request.deinit(allocator);
    try std.testing.expectEqualStrings("/speculative-qpack", request.request.path);
    var value: ?[]const u8 = null;
    for (request.request.headers) |header| {
        if (std.mem.eql(u8, header.name, "x-speculative-runtime")) {
            value = header.value;
        }
    }
    try std.testing.expectEqualStrings(
        "sent-before-feedback",
        value orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        request.request.qpack_section_acknowledgments,
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

fn checkQpackSpeculativeEncodeAllocationFailure(
    allocator: std.mem.Allocator,
) !void {
    var encoder = QpackEncodeState.initAwaitingPeerSettings(allocator, 4096);
    defer encoder.deinit();
    try encoder.configurePeerLimits(256, 1);
    _ = try encoder.insertField("x-speculative", "repeated-value");
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try encoder.encodeFieldSection(&block, 0, &.{.{
        .name = "x-speculative",
        .value = "repeated-value",
    }});
    try std.testing.expectEqual(
        @as(?usize, 1),
        encoder.blocked_section_counts.get(0),
    );
}

test "HTTP/3 speculative QPACK encoding is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkQpackSpeculativeEncodeAllocationFailure,
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
    var requests = StreamingRequestSet.init(
        allocator,
        3,
        512,
        .{},
        .request,
    );
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
    var responses = StreamingResponseSet.init(
        allocator,
        3,
        512,
        .{},
        .response,
    );
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

test "HTTP/3 dynamic HEADERS reuse one output allocation" {
    const allocator = std.testing.allocator;
    var encoder = QpackEncodeState.init(allocator, 0, 4096);
    defer encoder.deinit();
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    const fields = [_]http3.Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/scratch" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
    };

    try encoder.encodeFieldSection(&output, 0, &fields);
    const required_capacity = output.items.len + 16;
    output.clearRetainingCapacity();
    try output.ensureTotalCapacity(allocator, required_capacity);
    const reusable_capacity = output.capacity;
    output.clearRetainingCapacity();

    var fail_after_output = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    encoder.allocator = fail_after_output.allocator();
    try (http3.Request{
        .method = "GET",
        .path = "/scratch",
        .authority = "example.test",
    }).writeDynamic(
        &output,
        fail_after_output.allocator(),
        .{},
        4,
        &encoder,
    );
    try std.testing.expect(!fail_after_output.has_induced_failure);
    try std.testing.expectEqual(reusable_capacity, output.capacity);
    const frame = try http3.Frame.parse(output.items);
    try std.testing.expectEqual(http3.FrameType.headers, frame.frame_type);
    var table = http3.Qpack.DynamicTable.init(allocator, 0);
    defer table.deinit();
    const decoded = try http3.Qpack.decodeDynamicBlock(
        allocator,
        frame.payload,
        table,
    );
    defer http3.Qpack.freeDecodedFields(allocator, decoded.fields);
    try std.testing.expectEqual(@as(usize, 4), decoded.fields.len);
    try std.testing.expectEqualStrings("/scratch", decoded.fields[1].value);
}

test "HTTP/3 runtime rejects closed critical streams" {
    const allocator = std.testing.allocator;

    var control_bytes: std.ArrayList(u8) = .empty;
    defer control_bytes.deinit(allocator);
    try http3.writeControlStreamPrefix(&control_bytes, allocator);
    try http3.writeSettingsFrame(&control_bytes, allocator, .{});

    var control = http3.ControlState{};
    defer control.deinit(allocator);
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
    defer qpack_control.deinit(allocator);
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
    defer control.deinit(allocator);
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
    try http3.writeResponseSequence(
        &push_bytes,
        allocator,
        &.{ .{ .status = 103 }, .{ .status = 102 } },
        .{
            .status = 200,
            .body = "javascript",
            .trailers = &.{.{ .name = "x-push", .value = "done" }},
        },
    );
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
    try client.sendMaxPushId(3);
    var parent_capacity: usize = 0;
    var pushed_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var parent_ptr: [*]u8 = undefined;
    var pushed_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    for (0..2) |exchange| {
        const request_stream_id = try client.sendRequest(.{
            .method = "GET",
            .path = "/",
            .authority = "example.test",
        });
        var request = try server.receiveRequest();
        defer request.deinit(allocator);
        const push_id: u64 = @intCast(exchange + 2);
        const push_stream_id = try server.sendResponseWithPush(
            request.from,
            request.stream_id,
            .{ .status = 204 },
            .{
                .push_id = push_id,
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
            first_server_push_stream_id + @as(u62, @intCast(exchange * 4)),
            push_stream_id,
        );
        if (exchange == 0) {
            parent_capacity = server.push_send_scratch.parent.capacity;
            pushed_capacity = server.push_send_scratch.pushed.capacity;
            frame_capacity = server.push_send_scratch.frames.capacity;
            try std.testing.expect(parent_capacity != 0);
            try std.testing.expect(pushed_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            parent_ptr = server.push_send_scratch.parent.allocatedSlice().ptr;
            pushed_ptr = server.push_send_scratch.pushed.allocatedSlice().ptr;
            frame_ptr = server.push_send_scratch.frames.allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                parent_capacity,
                server.push_send_scratch.parent.capacity,
            );
            try std.testing.expectEqual(
                pushed_capacity,
                server.push_send_scratch.pushed.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                server.push_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                parent_ptr,
                server.push_send_scratch.parent.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                pushed_ptr,
                server.push_send_scratch.pushed.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                server.push_send_scratch.frames.allocatedSlice().ptr,
            );
        }
        var promise = while (true) {
            if (try client.receiveResponseEvent(request_stream_id)) |event| {
                break event;
            }
        };
        defer promise.deinit(allocator);
        try std.testing.expect(promise == .push_promise);
        try std.testing.expectEqual(push_id, promise.push_promise.push_id);
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
}

test "HTTP/3 Push send scratch rolls back QPACK references on allocation failure" {
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
        [_]u8{0xf9} ** quic.protection.secret_len,
    );
    const config: ProtectedConfig = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "server",
        .peer_connection_id = "client",
        .max_stream_frame_data = 1200,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var qpack = QpackEncodeState.init(allocator, 256, 4096);
    defer qpack.deinit();
    try qpack.setCapacity(256);
    _ = try qpack.insertField("x-push-dynamic", "reused-value");
    qpack.known_received_count = qpack.table.insert_count;

    var scratch: PushSendScratch = .{};
    defer scratch.deinit(allocator);
    try scratch.parent.ensureTotalCapacity(allocator, 512);
    try scratch.pushed.ensureTotalCapacity(allocator, 16);
    try scratch.frames.ensureTotalCapacity(allocator, 16);
    const parent_ptr = scratch.parent.allocatedSlice().ptr;
    const pushed_ptr = scratch.pushed.allocatedSlice().ptr;
    const frame_ptr = scratch.frames.allocatedSlice().ptr;
    const pending_sections_len = qpack.pending_sections.items.len;
    var qpack_encoder_send = quic.stream_state.SendState.init(
        server_qpack_encoder_stream_id,
    );
    var qpack_encoder_prefix_sent = false;
    var next_packet_number: u64 = 0;

    var fail_growth = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = fail_growth.allocator();
    defer sender.allocator = allocator;
    try std.testing.expectError(
        error.OutOfMemory,
        sendProtectedPush(
            &sender,
            receiver.address(),
            config,
            &scratch,
            .{
                .qpack_max_table_capacity = 256,
                .qpack_blocked_streams = 2,
            },
            0,
            .{
                .status = 204,
                .headers = &.{.{
                    .name = "x-push-dynamic",
                    .value = "reused-value",
                }},
            },
            first_server_push_stream_id,
            .{
                .push_id = 0,
                .request = .{
                    .method = "GET",
                    .path = "/asset.css",
                    .authority = "example.test",
                    .headers = &.{.{
                        .name = "x-push-dynamic",
                        .value = "reused-value",
                    }},
                },
                // Force the second live output buffer to grow only after the
                // parent has already registered dynamic QPACK references.
                .response = .{
                    .status = 200,
                    .body = &([_]u8{'x'} ** 512),
                },
            },
            &qpack,
            &qpack_encoder_send,
            &qpack_encoder_prefix_sent,
            &next_packet_number,
            &protected_send,
        ),
    );
    try std.testing.expect(fail_growth.has_induced_failure);
    try std.testing.expectEqual(
        pending_sections_len,
        qpack.pending_sections.items.len,
    );
    try std.testing.expectEqual(@as(usize, 0), qpack.reference_counts.count());
    try std.testing.expectEqual(@as(u64, 0), qpack_encoder_send.next_offset);
    try std.testing.expect(!qpack_encoder_prefix_sent);
    try std.testing.expectEqual(@as(u64, 0), next_packet_number);
    try std.testing.expectEqual(parent_ptr, scratch.parent.allocatedSlice().ptr);
    try std.testing.expectEqual(pushed_ptr, scratch.pushed.allocatedSlice().ptr);
    try std.testing.expectEqual(frame_ptr, scratch.frames.allocatedSlice().ptr);
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
            // Give the head and trailer encodings one deliberately shared
            // backing allocation so this test detects either helper falling
            // back to private temporary lists.
            try server_ptr.stream_send_scratch.encoded.ensureTotalCapacity(
                server_ptr.quic_server.endpoint.allocator,
                256,
            );
            try server_ptr.stream_send_scratch.frames.ensureTotalCapacity(
                server_ptr.quic_server.endpoint.allocator,
                32,
            );
            try server_ptr.startResponse(
                request.from,
                request.stream_id,
                .{ .status = 200 },
                "response-chunks".len,
            );
            try server_ptr.outbound_bodies.frame_scratch.ensureTotalCapacity(
                server_ptr.quic_server.endpoint.allocator,
                16,
            );
            const head_encoded_capacity =
                server_ptr.stream_send_scratch.encoded.capacity;
            const head_frame_capacity =
                server_ptr.stream_send_scratch.frames.capacity;
            const head_encoded_ptr = server_ptr.stream_send_scratch.encoded
                .allocatedSlice().ptr;
            const head_frame_ptr = server_ptr.stream_send_scratch.frames
                .allocatedSlice().ptr;
            const body_frame_capacity =
                server_ptr.outbound_bodies.frame_scratch.capacity;
            const body_frame_ptr = server_ptr.outbound_bodies.frame_scratch
                .allocatedSlice().ptr;
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
            try std.testing.expectEqual(
                body_frame_capacity,
                server_ptr.outbound_bodies.frame_scratch.capacity,
            );
            try std.testing.expectEqual(
                body_frame_ptr,
                server_ptr.outbound_bodies.frame_scratch.allocatedSlice().ptr,
            );
            // The direct DATA-prefix path borrows the application bytes and
            // should never materialize a complete DATA frame in payload scratch.
            try std.testing.expectEqual(
                @as(usize, 0),
                server_ptr.outbound_bodies.payload_scratch.capacity,
            );
            const response_entry = server_ptr.outbound_bodies.find(
                request.stream_id,
            ).?;
            response_entry.flow_limit = response_entry.send.next_offset;
            try std.testing.expectError(
                error.FlowControlBlocked,
                server_ptr.finishResponseTrailers(
                    request.from,
                    request.stream_id,
                    &.{.{
                        .name = "x-response-checksum",
                        .value = "ok",
                    }},
                ),
            );
            response_entry.flow_limit = null;
            try server_ptr.finishResponseTrailers(
                request.from,
                request.stream_id,
                &.{.{ .name = "x-response-checksum", .value = "ok" }},
            );
            try std.testing.expectEqual(
                head_encoded_capacity,
                server_ptr.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                head_frame_capacity,
                server_ptr.stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                head_encoded_ptr,
                server_ptr.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                head_frame_ptr,
                server_ptr.stream_send_scratch.frames.allocatedSlice().ptr,
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

    try client.stream_send_scratch.encoded.ensureTotalCapacity(allocator, 256);
    try client.stream_send_scratch.frames.ensureTotalCapacity(allocator, 32);
    try client.outbound_bodies.frame_scratch.ensureTotalCapacity(allocator, 16);
    const stream_id = try client.startRequest(
        .{
            .method = "POST",
            .path = "/stream-body",
            .authority = "localhost",
        },
        "request-chunks".len,
    );
    const head_encoded_capacity = client.stream_send_scratch.encoded.capacity;
    const head_frame_capacity = client.stream_send_scratch.frames.capacity;
    const head_encoded_ptr = client.stream_send_scratch.encoded
        .allocatedSlice().ptr;
    const head_frame_ptr = client.stream_send_scratch.frames
        .allocatedSlice().ptr;
    const body_frame_capacity = client.outbound_bodies.frame_scratch.capacity;
    const body_frame_ptr = client.outbound_bodies.frame_scratch
        .allocatedSlice().ptr;
    try client.sendRequestBody(stream_id, "request-", false);
    try std.testing.expectError(
        error.InvalidContentLength,
        client.sendRequestBody(stream_id, "short", true),
    );
    try client.sendRequestBody(stream_id, "chunks", false);
    try std.testing.expectEqual(
        body_frame_capacity,
        client.outbound_bodies.frame_scratch.capacity,
    );
    try std.testing.expectEqual(
        body_frame_ptr,
        client.outbound_bodies.frame_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        client.outbound_bodies.payload_scratch.capacity,
    );
    const request_entry = client.outbound_bodies.find(stream_id).?;
    request_entry.flow_limit = request_entry.send.next_offset;
    try std.testing.expectError(
        error.FlowControlBlocked,
        client.finishRequestTrailers(
            stream_id,
            &.{.{ .name = "x-request-checksum", .value = "ok" }},
        ),
    );
    request_entry.flow_limit = null;
    try client.finishRequestTrailers(
        stream_id,
        &.{.{ .name = "x-request-checksum", .value = "ok" }},
    );
    try std.testing.expectEqual(
        head_encoded_capacity,
        client.stream_send_scratch.encoded.capacity,
    );
    try std.testing.expectEqual(
        head_frame_capacity,
        client.stream_send_scratch.frames.capacity,
    );
    try std.testing.expectEqual(
        head_encoded_ptr,
        client.stream_send_scratch.encoded.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        head_frame_ptr,
        client.stream_send_scratch.frames.allocatedSlice().ptr,
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

test "HTTP/3 protected DATA send retries without allocation" {
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
        [_]u8{0xb5} ** quic.protection.secret_len,
    );
    const config: ProtectedConfig = .{
        .receive_keys = keys,
        .send_keys = keys,
        .local_connection_id = "client",
        .peer_connection_id = "server",
        .max_stream_frame_data = 5,
        .max_frames_per_packet = 2,
    };
    var protected_send = ProtectedSendState.init(allocator);
    defer protected_send.deinit();
    var bodies = OutboundBodySet.init(allocator, 1);
    defer bodies.deinit();
    try bodies.reserveOpen(0);
    bodies.appendOpenAssumeCapacity(
        0,
        quic.stream_state.SendState.init(0),
        12,
    );
    try bodies.frame_scratch.ensureTotalCapacity(allocator, 16);

    var next_packet_number: u64 = 0;
    try sendProtectedBodyChunk(
        &sender,
        receiver.address(),
        config,
        &next_packet_number,
        &protected_send,
        &bodies,
        0,
        "first-",
        false,
    );
    const first_entry = bodies.find(0).?.*;
    const body_frame_capacity = bodies.frame_scratch.capacity;
    const body_frame_ptr = bodies.frame_scratch.allocatedSlice().ptr;
    const wire_payload_capacity = protected_send.payload_scratch.capacity;
    const wire_packet_capacity = protected_send.packet_scratch.capacity;
    const wire_payload_ptr = protected_send.payload_scratch.allocatedSlice().ptr;
    const wire_packet_ptr = protected_send.packet_scratch.allocatedSlice().ptr;
    try std.testing.expectEqual(@as(usize, 0), bodies.payload_scratch.capacity);

    // Flow-control rejection happens after the direct-prefix frame plan is
    // built. The body offset, byte count, and FIN state must all roll back.
    bodies.find(0).?.flow_limit = first_entry.send.next_offset;
    try std.testing.expectError(
        error.FlowControlBlocked,
        sendProtectedBodyChunk(
            &sender,
            receiver.address(),
            config,
            &next_packet_number,
            &protected_send,
            &bodies,
            0,
            "second",
            true,
        ),
    );
    const blocked_entry = bodies.find(0).?.*;
    try std.testing.expectEqual(first_entry.send.next_offset, blocked_entry.send.next_offset);
    try std.testing.expectEqual(first_entry.written, blocked_entry.written);
    try std.testing.expectEqual(first_entry.send.fin_sent, blocked_entry.send.fin_sent);
    // Flow-control validation precedes packet protection, so a rejected retry
    // cannot consume a packet number.
    try std.testing.expectEqual(@as(u64, 1), next_packet_number);
    bodies.find(0).?.flow_limit = null;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    sender.allocator = no_alloc.allocator();
    protected_send.allocator = no_alloc.allocator();
    defer {
        sender.allocator = allocator;
        protected_send.allocator = allocator;
    }
    try sendProtectedBodyChunk(
        &sender,
        receiver.address(),
        config,
        &next_packet_number,
        &protected_send,
        &bodies,
        0,
        "second",
        true,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expect(bodies.find(0) == null);
    try std.testing.expectEqual(body_frame_capacity, bodies.frame_scratch.capacity);
    try std.testing.expectEqual(body_frame_ptr, bodies.frame_scratch.allocatedSlice().ptr);
    try std.testing.expectEqual(@as(usize, 0), bodies.payload_scratch.capacity);
    try std.testing.expectEqual(
        wire_payload_capacity,
        protected_send.payload_scratch.capacity,
    );
    try std.testing.expectEqual(
        wire_packet_capacity,
        protected_send.packet_scratch.capacity,
    );
    try std.testing.expectEqual(
        wire_payload_ptr,
        protected_send.payload_scratch.allocatedSlice().ptr,
    );
    try std.testing.expectEqual(
        wire_packet_ptr,
        protected_send.packet_scratch.allocatedSlice().ptr,
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
    const body_len: usize = 1024 * 1024;
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
            .peer_stream_flow_window = 1024,
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
                try server_ptr.sendResponseBodyPaced(
                    request.from,
                    request.stream_id,
                    chunk[0..count],
                    false,
                );
                remaining -= count;
            }
            try server_ptr.finishResponseTrailersPaced(
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
            .max_stream_buffer = 1024,
        },
        .{
            .receive_keys = server_keys,
            .send_keys = client_keys,
            .local_connection_id = &client_cid,
            .peer_connection_id = &server_cid,
            .max_stream_buffer = 1024,
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
                    active.reader.receive.buffer.items.len <= 1024,
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
            var encoded_capacity: usize = 0;
            var frame_capacity: usize = 0;
            var encoded_ptr: [*]u8 = undefined;
            var frame_ptr: [*]quic.Frame = undefined;
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
                if (exchange == 0) {
                    encoded_capacity =
                        server_ptr.stream_send_scratch.encoded.capacity;
                    frame_capacity =
                        server_ptr.stream_send_scratch.frames.capacity;
                    try std.testing.expect(encoded_capacity != 0);
                    try std.testing.expect(frame_capacity != 0);
                    encoded_ptr = server_ptr.stream_send_scratch.encoded
                        .allocatedSlice().ptr;
                    frame_ptr = server_ptr.stream_send_scratch.frames
                        .allocatedSlice().ptr;
                } else {
                    try std.testing.expectEqual(
                        encoded_capacity,
                        server_ptr.stream_send_scratch.encoded.capacity,
                    );
                    try std.testing.expectEqual(
                        frame_capacity,
                        server_ptr.stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        encoded_ptr,
                        server_ptr.stream_send_scratch.encoded
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        frame_ptr,
                        server_ptr.stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
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

    var encoded_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var encoded_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    for (0..3) |exchange| {
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
        if (exchange == 0) {
            encoded_capacity = client.stream_send_scratch.encoded.capacity;
            frame_capacity = client.stream_send_scratch.frames.capacity;
            try std.testing.expect(encoded_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            encoded_ptr = client.stream_send_scratch.encoded
                .allocatedSlice().ptr;
            frame_ptr = client.stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                encoded_capacity,
                client.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                client.stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                encoded_ptr,
                client.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                client.stream_send_scratch.frames.allocatedSlice().ptr,
            );
        }
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
        &client.critical_stream_send_scratch,
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
        &client.stream_send_scratch,
        &client.critical_stream_send_scratch,
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
        &client.critical_stream_send_scratch,
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

    const stream_id = try client.sendRequest(.{
        .method = "GET",
        .path = "/graceful",
        .authority = "localhost",
    });
    while (client.control.peer_goaway_id == null or
        client.control.peer_goaway_id.? != 4)
    {
        try client.receiveProgress();
    }
    var response = try client.receiveResponse(stream_id);
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
    const Observation = struct {
        push_ids: [2]u64 = undefined,
        request_stream_ids: [2]u62 = undefined,
        stream_ids: [2]u62 = undefined,
        statuses: [2]u16 = undefined,
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            push_id: u64,
            request_stream_id: u62,
            stream_id: u62,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count >= self.statuses.len) return;
            self.push_ids[self.count] = push_id;
            self.request_stream_ids[self.count] = request_stream_id;
            self.stream_ids[self.count] = stream_id;
            self.statuses[self.count] = response.status;
            self.count += 1;
        }
    };
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
            const push_stream_id = try session.sendResponseWithPush(
                request.stream_id,
                .{ .status = 204 },
                .{
                    .push_id = 1,
                    .request = .{
                        .method = "GET",
                        .path = "/handshake.css",
                        .authority = "localhost",
                    },
                    .informational = &.{
                        .{ .status = 103 },
                        .{ .status = 102 },
                    },
                    .response = .{
                        .status = 200,
                        .body = "handshake-asset",
                    },
                },
            );
            try std.testing.expectEqual(
                first_server_push_stream_id,
                push_stream_id,
            );
            try std.testing.expect(
                session.push_send_scratch.parent.capacity != 0,
            );
            try std.testing.expect(
                session.push_send_scratch.pushed.capacity != 0,
            );
            try std.testing.expect(
                session.push_send_scratch.frames.capacity != 0,
            );
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
    var observation: Observation = .{};
    var pushed = try client.receivePushWithInformational(.{
        .context = &observation,
        .on_response = Observation.observe,
    });
    defer pushed.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 1), pushed.push_id);
    try std.testing.expectEqual(request_stream_id, pushed.request_stream_id);
    try std.testing.expectEqual(@as(u62, 15), pushed.stream_id);
    try std.testing.expectEqualStrings(
        "handshake-asset",
        pushed.response.body,
    );
    try std.testing.expectEqual(@as(usize, 2), observation.count);
    for (observation.statuses, 0..) |status, index| {
        try std.testing.expectEqual(@as(u64, 1), observation.push_ids[index]);
        try std.testing.expectEqual(
            request_stream_id,
            observation.request_stream_ids[index],
        );
        try std.testing.expectEqual(@as(u62, 15), observation.stream_ids[index]);
        try std.testing.expectEqual(
            if (index == 0) @as(u16, 103) else 102,
            status,
        );
    }
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
    const Observation = struct {
        stream_ids: [4]u62 = undefined,
        statuses: [4]u16 = undefined,
        count: usize = 0,

        fn observe(
            context: *anyopaque,
            stream_id: u62,
            response: InformationalResponseHead,
        ) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (self.count >= self.statuses.len) return;
            self.stream_ids[self.count] = stream_id;
            self.statuses[self.count] = response.status;
            self.count += 1;
        }
    };

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
            try session.sendResponseWithInformational(
                second.stream_id,
                &.{ .{ .status = 103 }, .{ .status = 102 } },
                .{ .status = 200, .body = "second-response" },
            );
            try session.sendResponseWithInformational(
                first.stream_id,
                &.{ .{ .status = 103 }, .{ .status = 102 } },
                .{ .status = 200, .body = "first-response" },
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
    var observation: Observation = .{};
    const observer: MultiplexedInformationalObserver = .{
        .context = &observation,
        .on_response = Observation.observe,
    };
    var first_event = try client.receiveNextResponseWithInformational(observer);
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
    var second_event = try client.receiveNextResponseWithInformational(observer);
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
    try std.testing.expectEqual(@as(usize, 4), observation.count);
    for (observation.statuses, 0..) |status, index| {
        try std.testing.expectEqual(
            if (index < 2) second_id else first_id,
            observation.stream_ids[index],
        );
        try std.testing.expectEqual(
            if (index % 2 == 0) @as(u16, 103) else 102,
            status,
        );
    }
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
                &session.critical_stream_send_scratch,
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
    // Force the cursor through the timer-aware GRO branch rather than the
    // no-deadline shortcut. The server's two response packets should still be
    // retained as one owning batch behind the first application event.
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    client.established.connection.ack_delay_start_ns = @intCast(now);
    client.established.connection.ack_delay_deadline_ns =
        @intCast(now + std.time.ns_per_s);
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

test "HTTP/3 handshake client batches request DATA across streams" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();

    const original_dcid = [_]u8{
        0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8,
    };
    const client_cid = [_]u8{ 0xd9, 0xda, 0xdb, 0xdc };
    const server_cid = [_]u8{ 0xdd, 0xde, 0xdf, 0xe0 };
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xe1} ** 32,
                .x25519_secret_key = [_]u8{0xe2} ** 32,
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
            var saw_first = false;
            var saw_second = false;
            var first_stream_id: ?u62 = null;
            var second_stream_id: ?u62 = null;
            for (0..2) |_| {
                var request = try session.receiveRequest();
                defer request.deinit(
                    session.established.connection.endpoint.allocator,
                );
                if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/batch-first",
                )) {
                    try std.testing.expectEqualStrings(
                        "first-body",
                        request.request.body,
                    );
                    saw_first = true;
                    first_stream_id = request.stream_id;
                } else if (std.mem.eql(
                    u8,
                    request.request.path,
                    "/batch-second",
                )) {
                    try std.testing.expectEqualStrings(
                        "second-body",
                        request.request.body,
                    );
                    saw_second = true;
                    second_stream_id = request.stream_id;
                } else {
                    return error.TestUnexpectedResult;
                }
            }
            try std.testing.expect(saw_first);
            try std.testing.expect(saw_second);
            try session.startResponse(
                first_stream_id.?,
                .{ .status = 200 },
                "first-response".len,
            );
            try session.startResponse(
                second_stream_id.?,
                .{ .status = 200 },
                "second-response".len,
            );
            try session.sendResponseBodyBatchPaced(&.{
                .{
                    .stream_id = first_stream_id.?,
                    .data = "first-response",
                    .fin = true,
                },
                .{
                    .stream_id = second_stream_id.?,
                    .data = "second-response",
                    .fin = true,
                },
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
                .initial_one_rtt_config = .{
                    .max_datagram_size = 1400,
                    .enable_pacing = false,
                },
                .random = [_]u8{0xe3} ** 32,
                .x25519_secret_key = [_]u8{0xe4} ** 32,
            },
        },
    );
    defer client.deinit();

    const first = try client.startRequest(.{
        .method = "POST",
        .path = "/batch-first",
        .authority = "localhost",
    }, "first-body".len);
    const second = try client.startRequest(.{
        .method = "POST",
        .path = "/batch-second",
        .authority = "localhost",
    }, "second-body".len);
    try std.testing.expectError(
        error.UnexpectedStream,
        client.sendRequestBodyBatchPaced(&.{
            .{ .stream_id = first, .data = "first-body", .fin = true },
            .{ .stream_id = first, .data = "first-body", .fin = true },
        }),
    );
    try client.sendRequestBodyBatchPaced(&.{
        .{ .stream_id = first, .data = "first-body", .fin = true },
        .{ .stream_id = second, .data = "second-body", .fin = true },
    });
    for (0..2) |_| {
        var event = try client.receiveNextResponse();
        defer event.deinit(allocator);
        try std.testing.expect(event == .response);
        try std.testing.expectEqual(@as(u16, 200), event.response.value.response.status);
        if (event.response.stream_id == first) {
            try std.testing.expectEqualStrings(
                "first-response",
                event.response.value.response.body,
            );
        } else if (event.response.stream_id == second) {
            try std.testing.expectEqualStrings(
                "second-response",
                event.response.value.response.body,
            );
        } else {
            return error.TestUnexpectedResult;
        }
    }
    thread.join();
    if (shared.err) |err| return err;
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
            var encoded_capacity: usize = 0;
            var frame_capacity: usize = 0;
            var encoded_ptr: [*]u8 = undefined;
            var frame_ptr: [*]quic.Frame = undefined;
            var critical_capacity: usize = 0;
            var critical_frames_capacity: usize = 0;
            var critical_ptr: [*]u8 = undefined;
            var critical_frames_ptr: [*]quic.Frame = undefined;

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
                if (exchange == 0) {
                    encoded_capacity =
                        session.stream_send_scratch.encoded.capacity;
                    frame_capacity =
                        session.stream_send_scratch.frames.capacity;
                    try std.testing.expect(encoded_capacity != 0);
                    try std.testing.expect(frame_capacity != 0);
                    encoded_ptr = session.stream_send_scratch.encoded
                        .allocatedSlice().ptr;
                    frame_ptr = session.stream_send_scratch.frames
                        .allocatedSlice().ptr;
                } else {
                    try std.testing.expectEqual(
                        encoded_capacity,
                        session.stream_send_scratch.encoded.capacity,
                    );
                    try std.testing.expectEqual(
                        frame_capacity,
                        session.stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        encoded_ptr,
                        session.stream_send_scratch.encoded
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        frame_ptr,
                        session.stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
                // The second exchange can carry the first dynamic inserts and
                // therefore establishes the steady-state high-water mark.
                if (exchange == 1) {
                    critical_capacity = session
                        .critical_stream_send_scratch.payload.capacity;
                    critical_frames_capacity = session
                        .critical_stream_send_scratch.frames.capacity;
                    try std.testing.expect(critical_capacity != 0);
                    try std.testing.expect(critical_frames_capacity != 0);
                    critical_ptr = session.critical_stream_send_scratch.payload
                        .allocatedSlice().ptr;
                    critical_frames_ptr = session
                        .critical_stream_send_scratch.frames.allocatedSlice().ptr;
                } else if (exchange == 2) {
                    try std.testing.expectEqual(
                        critical_capacity,
                        session.critical_stream_send_scratch.payload.capacity,
                    );
                    try std.testing.expectEqual(
                        critical_frames_capacity,
                        session.critical_stream_send_scratch.frames.capacity,
                    );
                    try std.testing.expectEqual(
                        critical_ptr,
                        session.critical_stream_send_scratch.payload
                            .allocatedSlice().ptr,
                    );
                    try std.testing.expectEqual(
                        critical_frames_ptr,
                        session.critical_stream_send_scratch.frames
                            .allocatedSlice().ptr,
                    );
                }
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

    var encoded_capacity: usize = 0;
    var frame_capacity: usize = 0;
    var encoded_ptr: [*]u8 = undefined;
    var frame_ptr: [*]quic.Frame = undefined;
    var critical_capacity: usize = 0;
    var critical_frames_capacity: usize = 0;
    var critical_ptr: [*]u8 = undefined;
    var critical_frames_ptr: [*]quic.Frame = undefined;
    for (0..3) |exchange| {
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
        if (exchange == 0) {
            encoded_capacity = client.stream_send_scratch.encoded.capacity;
            frame_capacity = client.stream_send_scratch.frames.capacity;
            try std.testing.expect(encoded_capacity != 0);
            try std.testing.expect(frame_capacity != 0);
            encoded_ptr = client.stream_send_scratch.encoded
                .allocatedSlice().ptr;
            frame_ptr = client.stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else {
            try std.testing.expectEqual(
                encoded_capacity,
                client.stream_send_scratch.encoded.capacity,
            );
            try std.testing.expectEqual(
                frame_capacity,
                client.stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                encoded_ptr,
                client.stream_send_scratch.encoded.allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                frame_ptr,
                client.stream_send_scratch.frames.allocatedSlice().ptr,
            );
        }
        if (exchange == 1) {
            critical_capacity =
                client.critical_stream_send_scratch.payload.capacity;
            critical_frames_capacity =
                client.critical_stream_send_scratch.frames.capacity;
            try std.testing.expect(critical_capacity != 0);
            try std.testing.expect(critical_frames_capacity != 0);
            critical_ptr = client.critical_stream_send_scratch.payload
                .allocatedSlice().ptr;
            critical_frames_ptr = client.critical_stream_send_scratch.frames
                .allocatedSlice().ptr;
        } else if (exchange == 2) {
            try std.testing.expectEqual(
                critical_capacity,
                client.critical_stream_send_scratch.payload.capacity,
            );
            try std.testing.expectEqual(
                critical_frames_capacity,
                client.critical_stream_send_scratch.frames.capacity,
            );
            try std.testing.expectEqual(
                critical_ptr,
                client.critical_stream_send_scratch.payload
                    .allocatedSlice().ptr,
            );
            try std.testing.expectEqual(
                critical_frames_ptr,
                client.critical_stream_send_scratch.frames
                    .allocatedSlice().ptr,
            );
        }
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
                &session.critical_stream_send_scratch,
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
        &client.critical_stream_send_scratch,
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

test {
    _ = @import("runtime/development_server_tests.zig");
    _ = @import("runtime/endpoint_dispatcher_tests.zig");
    _ = @import("runtime/handshake_server_serve_tests.zig");
    _ = @import("runtime/cancellation_tests.zig");
    _ = @import("runtime/informational_tests.zig");
    _ = @import("runtime/response_scheduler_tests.zig");
}

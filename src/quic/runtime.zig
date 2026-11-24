const std = @import("std");
const cancellation = @import("../internal/cancellation.zig");

test {
    _ = @import("runtime/receive_cancel_tests.zig");
}
const builtin = @import("builtin");
const quic = @import("mod.zig");
const deadline_policy = @import("../internal/deadline.zig");
const socket_binding = @import("../internal/socket_binding.zig");
const socks5_proxy = @import("../proxy/socks5.zig");
const socks5_udp = socks5_proxy.udp;

const net = std.Io.net;

pub const Error = socket_binding.Error || quic.Error || error{
    EmptyDatagram,
    DatagramTooLarge,
    TrailingBytes,
    NoConnectionRoute,
    EcnUnavailable,
    ProxyDomainSourceUnsupported,
    ProxyRouteLimitReached,
    ProxyRouteSourceLimitReached,
    InvalidProxyRouteCapacity,
    UnexpectedRelaySource,
    InvalidGroSegment,
    CallerBufferReceiveWithGro,
} || socks5_udp.CodecError || quic.connection_router.Error || net.IpAddress.BindError || net.Socket.SendError || net.Socket.ReceiveError || std.Io.RandomSecureError || std.Io.Cancelable;
pub const ReceiveTimeoutError = Error ||
    std.Io.Timeout.Error ||
    std.Io.ConcurrentError;

/// UDP payload traffic observed at the userspace socket boundary.
///
/// Byte counts exclude IP and UDP headers. With GSO or a valid GRO batch,
/// datagram counts describe logical UDP segments rather than syscall count.
pub const SocketTrafficStats = struct {
    sent_datagrams: u64 = 0,
    sent_bytes: u64 = 0,
    received_datagrams: u64 = 0,
    received_bytes: u64 = 0,

    pub fn since(self: SocketTrafficStats, previous: SocketTrafficStats) SocketTrafficStats {
        return .{
            .sent_datagrams = self.sent_datagrams -% previous.sent_datagrams,
            .sent_bytes = self.sent_bytes -% previous.sent_bytes,
            .received_datagrams = self.received_datagrams -% previous.received_datagrams,
            .received_bytes = self.received_bytes -% previous.received_bytes,
        };
    }
};

/// Optional thread-safe sink for complete Endpoint UDP traffic.
///
/// Keeping this caller-owned avoids imposing atomic increments on ordinary
/// endpoints. The sink must outlive every operation using the endpoint.
pub const SocketTrafficCounters = struct {
    sent_datagrams: std.atomic.Value(u64) = .init(0),
    sent_bytes: std.atomic.Value(u64) = .init(0),
    received_datagrams: std.atomic.Value(u64) = .init(0),
    received_bytes: std.atomic.Value(u64) = .init(0),

    pub fn stats(self: *const SocketTrafficCounters) SocketTrafficStats {
        return .{
            .sent_datagrams = self.sent_datagrams.load(.monotonic),
            .sent_bytes = self.sent_bytes.load(.monotonic),
            .received_datagrams = self.received_datagrams.load(.monotonic),
            .received_bytes = self.received_bytes.load(.monotonic),
        };
    }

    fn recordSent(
        self: *SocketTrafficCounters,
        datagrams: usize,
        bytes: usize,
    ) void {
        _ = self.sent_datagrams.fetchAdd(@intCast(datagrams), .monotonic);
        _ = self.sent_bytes.fetchAdd(@intCast(bytes), .monotonic);
    }

    fn recordReceived(
        self: *SocketTrafficCounters,
        datagrams: usize,
        bytes: usize,
    ) void {
        _ = self.received_datagrams.fetchAdd(@intCast(datagrams), .monotonic);
        _ = self.received_bytes.fetchAdd(@intCast(bytes), .monotonic);
    }
};

pub const Limits = struct {
    pub const SendInterceptor = struct {
        context: *anyopaque,
        /// Return true to consume the datagram without handing it to the
        /// socket. This narrow hook supports deterministic benchmark/test
        /// network emulation while production endpoints pay one predictable
        /// null check and keep all QUIC recovery state unchanged.
        should_drop: ?*const fn (
            context: *anyopaque,
            bytes: []const u8,
        ) bool = null,
        /// Return true to consume this datagram now and send it immediately
        /// after the next non-dropped datagram. Endpoint-owned storage keeps
        /// the caller's packet buffer lifetime unchanged while exercising
        /// genuine UDP/QUIC packet reordering.
        should_hold: ?*const fn (
            context: *anyopaque,
            bytes: []const u8,
        ) bool = null,
        /// Mutate an endpoint-owned datagram copy before socket submission.
        /// Return true when the copy should replace the caller's bytes. This
        /// supports deterministic corruption while preserving caller lifetime
        /// and QUIC's original packet-number/recovery bookkeeping.
        corrupt: ?*const fn (
            context: *anyopaque,
            bytes: []u8,
        ) bool = null,
    };

    /// Constrain every UDP socket opened for this endpoint to one interface.
    /// Source IP/port remains the positional local bind address.
    network_interface: ?socket_binding.NetworkInterface = null,
    max_datagram_size: usize = 65_535,
    max_frames_per_datagram: usize = 256,
    /// Best-effort SO_RCVBUF target for UDP sockets.
    ///
    /// High-throughput QUIC workloads can burst many datagrams before the peer
    /// gets scheduled to drain its socket. A larger kernel receive queue avoids
    /// local benchmark drops that would otherwise force PTO recovery or leave
    /// simple blocking examples waiting for a response the kernel discarded.
    /// The kernel may clamp or double this value; unsupported platforms ignore
    /// it.
    socket_receive_buffer_bytes: usize = 4 * 1024 * 1024,
    /// Use Linux UDP_SEGMENT when a batch is already laid out as compatible
    /// contiguous segments. Unsupported kernels still fall back automatically.
    enable_gso_send: bool = true,
    /// Enable Linux UDP_GRO coalescing. Coalesced packets are exposed through
    /// the batch receive API without per-packet syscalls. Keep this opt-in
    /// because single-datagram consumers cannot amortize GRO bookkeeping.
    enable_gro_receive: bool = false,
    send_interceptor: ?SendInterceptor = null,
    /// Optional complete UDP payload accounting for diagnostics and
    /// reproducible benchmarks. Null keeps the production fast path at one
    /// predictable branch and performs no atomic operations.
    socket_traffic_counters: ?*SocketTrafficCounters = null,
};

pub const SendManyBytesResult = struct {
    /// Number of datagrams successfully handed to the socket, always a prefix
    /// of the caller's slice.
    sent_count: usize,
    /// A batch syscall can send a non-empty prefix before reporting the error
    /// for the next datagram. Keeping that progress lets stateful transports
    /// commit consumed packet numbers instead of accidentally reusing them.
    send_error: ?net.Socket.SendError = null,
};

/// One UDP payload and its destination for heterogeneous endpoint batches.
/// The payload and address storage must remain valid until the send call
/// returns; the endpoint never retains either view.
pub const AddressedDatagram = struct {
    to: net.IpAddress,
    bytes: []const u8,
};

/// Caller storage required to preserve the largest possible UDP_GRO receive.
pub const max_gro_receive_bytes: usize = std.math.maxInt(u16);

/// Maximum number of independent UDP messages accepted by one caller-buffer
/// receive. This matches the standard Threaded backend's bounded batch size
/// and keeps all message/control descriptors on the stack.
pub const max_receive_batch_messages: usize = 64;

const HeldSend = struct {
    to: net.IpAddress,
    bytes: []u8,
    ecn: quic.packet_space.EcnCodepoint,
};

const Socks5UdpState = struct {
    const FixedDomain = struct {
        host: []u8,
        port: u16,
        logical_peer: net.IpAddress,
        active: bool = true,
    };

    const DomainRoute = struct {
        host: []u8,
        port: u16,
        logical_peer: net.IpAddress,
        references: usize = 1,
        sources: []net.IpAddress,
        source_count: usize = 0,
    };

    control: net.Stream,
    relay: net.IpAddress,
    send_storage: []u8,
    fixed_domain: ?FixedDomain = null,
    domain_routes: std.ArrayListUnmanaged(DomainRoute) = .empty,
    max_domain_routes: usize = 0,
    max_sources_per_route: usize = 0,
    next_route_id: u32 = 1,
};

pub const Socks5DomainRouteLimits = struct {
    max_routes: usize,
    max_sources_per_route: usize = 64,
};

fn socks5FrameCapacity(max_datagram_size: usize) usize {
    return @min(
        @as(usize, std.math.maxInt(u16)),
        std.math.add(
            usize,
            max_datagram_size,
            socks5_udp.max_header_len,
        ) catch @as(usize, std.math.maxInt(u16)),
    );
}

fn nextSocks5LogicalPeer(
    proxy: *Socks5UdpState,
    local_address: net.IpAddress,
    port: u16,
) Error!net.IpAddress {
    for (0..65_535) |_| {
        const id = proxy.next_route_id;
        proxy.next_route_id = if (id == 65_535) 1 else id + 1;
        const candidate: net.IpAddress = switch (local_address) {
            .ip4 => .{ .ip4 = .{
                .bytes = .{
                    198,
                    18,
                    @truncate(id >> 8),
                    @truncate(id),
                },
                .port = port,
            } },
            .ip6 => .{ .ip6 = .{
                .bytes = .{
                    0xfd, 0, 0, 0, 0,                   0,                   0,                  0,
                    0,    0, 0, 0, @truncate(id >> 24), @truncate(id >> 16), @truncate(id >> 8), @truncate(id),
                },
                .port = port,
            } },
        };
        if (proxy.fixed_domain) |fixed| {
            if (fixed.logical_peer.eql(&candidate)) continue;
        }
        for (proxy.domain_routes.items) |route| {
            if (route.logical_peer.eql(&candidate)) break;
        } else return candidate;
    }
    return error.ProxyRouteLimitReached;
}

pub const Server = struct {
    endpoint: Endpoint,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Server {
        return .{ .endpoint = try .bind(allocator, io, bind_address, limits) };
    }

    pub fn deinit(self: *Server) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Server) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn receive(self: *Server) Error!OwnedDatagram {
        return self.endpoint.receive();
    }

    pub fn receiveWithTimeout(
        self: *Server,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedDatagram {
        return self.endpoint.receiveWithTimeout(timeout);
    }

    pub fn receiveWithDeadline(
        self: *Server,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDatagram {
        return self.endpoint.receiveWithDeadline(deadline);
    }

    pub fn receiveBytesHandlingVersionNegotiation(self: *Server, supported_versions: []const u32) Error!OwnedBytes {
        return self.endpoint.receiveBytesHandlingVersionNegotiation(supported_versions);
    }

    pub fn receiveBytesHandlingVersionNegotiationWithTimeout(
        self: *Server,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.endpoint.receiveBytesHandlingVersionNegotiationWithTimeout(
            supported_versions,
            timeout,
        );
    }

    pub fn receiveBytesHandlingVersionNegotiationWithDeadline(
        self: *Server,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.endpoint.receiveBytesHandlingVersionNegotiationWithDeadline(
            supported_versions,
            deadline,
        );
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiation(
        self: *Server,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
    ) Error!RoutedBytes {
        return self.endpoint.receiveRoutedBytesHandlingVersionNegotiation(router, supported_versions);
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiationWithTimeout(
        self: *Server,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!RoutedBytes {
        return self.endpoint.receiveRoutedBytesHandlingVersionNegotiationWithTimeout(
            router,
            supported_versions,
            timeout,
        );
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiationWithDeadline(
        self: *Server,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!RoutedBytes {
        return self.endpoint.receiveRoutedBytesHandlingVersionNegotiationWithDeadline(
            router,
            supported_versions,
            deadline,
        );
    }

    pub fn sendFrames(self: *Server, to: net.IpAddress, frames: []const quic.Frame) Error!void {
        try self.endpoint.sendFrames(to, frames);
    }
};

pub const Client = struct {
    endpoint: Endpoint,
    peer: net.IpAddress,

    pub fn connect(allocator: std.mem.Allocator, io: std.Io, local_address: net.IpAddress, peer: net.IpAddress, limits: Limits) Error!Client {
        return .{
            .endpoint = try .bind(allocator, io, local_address, limits),
            .peer = peer,
        };
    }

    pub fn deinit(self: *Client) void {
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn address(self: Client) net.IpAddress {
        return self.endpoint.address();
    }

    pub fn sendFrames(self: *Client, frames: []const quic.Frame) Error!void {
        try self.endpoint.sendFrames(self.peer, frames);
    }

    pub fn receive(self: *Client) Error!OwnedDatagram {
        return self.endpoint.receive();
    }

    pub fn receiveWithTimeout(
        self: *Client,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedDatagram {
        return self.endpoint.receiveWithTimeout(timeout);
    }

    pub fn receiveWithDeadline(
        self: *Client,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDatagram {
        return self.endpoint.receiveWithDeadline(deadline);
    }
};

pub const Endpoint = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    socket: net.Socket,
    /// Present only when the socket belongs to an RFC 1928 UDP association.
    /// The TCP stream must remain open for the complete endpoint lifetime.
    socks5_udp: ?Socks5UdpState = null,
    limits: Limits = .{},
    receive_ecn_enabled: bool = false,
    send_ecn_mark: quic.packet_space.EcnCodepoint = .not_ect,
    /// Deterministic fault injection for automatic ECN fallback tests. The
    /// production default is always false; keeping the failure at the socket
    /// option boundary exercises the same transaction and rollback path as an
    /// unsupported operating system.
    test_force_ecn_unavailable: bool = false,
    gso_send_enabled: bool = udpGsoSupported(),
    gro_receive_enabled: bool = false,
    /// Serializes socket options and fault-injection state with the associated
    /// send syscall. Multiple QUIC connections can share an endpoint and send
    /// from independent workers; without this lock an ECN mark, held packet,
    /// or first GSO capability failure could race across connections.
    send_mutex: std.Io.Mutex = .init,
    socket_receive_mutex: std.Io.Mutex = .init,
    pending_receive_mutex: std.Io.Mutex = .init,
    socks5_route_mutex: std.Io.Mutex = .init,
    pending_received: std.ArrayList(OwnedBytes) = .empty,
    pending_receive_index: usize = 0,
    held_send: ?HeldSend = null,

    pub fn bind(allocator: std.mem.Allocator, io: std.Io, bind_address: net.IpAddress, limits: Limits) Error!Endpoint {
        var endpoint = Endpoint{
            .io = io,
            .allocator = allocator,
            .socket = try socket_binding.bindDatagram(io, bind_address, limits.network_interface),
            .limits = limits,
            .gso_send_enabled = limits.enable_gso_send and udpGsoSupported(),
        };
        errdefer endpoint.deinit();
        endpoint.configureSocketReceiveBuffer();
        endpoint.enableEcnReceive();
        endpoint.enableGroReceive();
        return endpoint;
    }

    /// Transfer a live `proxy.socks5.UdpAssociation` into a QUIC endpoint.
    ///
    /// The association pointer becomes invalid on success. SOCKS5 cannot carry
    /// destination-path ECN or preserve kernel GSO/GRO records, so the adapter
    /// explicitly disables those capabilities while retaining exact batch
    /// prefix progress through bounded per-datagram framing.
    pub fn fromSocks5Association(
        allocator: std.mem.Allocator,
        association: *socks5_proxy.UdpAssociation,
        limits: Limits,
    ) Error!Endpoint {
        return initSocks5Association(
            allocator,
            association,
            limits,
            null,
            0,
            0,
        );
    }

    /// Build one association that can retain a bounded set of proxy-resolved
    /// domain routes. Callers register a route before constructing each QUIC
    /// connection and release it after the connection is fully unregistered.
    pub fn fromSocks5AssociationForDomains(
        allocator: std.mem.Allocator,
        association: *socks5_proxy.UdpAssociation,
        route_limits: Socks5DomainRouteLimits,
        limits: Limits,
    ) Error!Endpoint {
        if (route_limits.max_routes == 0 or
            route_limits.max_routes > 65_535 or
            route_limits.max_sources_per_route == 0 or
            route_limits.max_sources_per_route > 65_535)
        {
            return error.InvalidProxyRouteCapacity;
        }
        return initSocks5Association(
            allocator,
            association,
            limits,
            null,
            route_limits.max_routes,
            route_limits.max_sources_per_route,
        );
    }

    /// Route one logical QUIC peer through a proxy-resolved DNS target. This
    /// preserves SOCKS5h-style DNS privacy while QUIC retains one stable path
    /// identity for the initial origin. Other peer addresses (for example a
    /// validated preferred address) continue through the association as IPs.
    pub fn fromSocks5AssociationForDomain(
        allocator: std.mem.Allocator,
        association: *socks5_proxy.UdpAssociation,
        domain: []const u8,
        port: u16,
        logical_peer: net.IpAddress,
        limits: Limits,
    ) Error!Endpoint {
        _ = try socks5_udp.Address.fromHost(domain, port);
        if (net.IpAddress.parse(domain, port)) |_| {
            return error.InvalidHostName;
        } else |_| {}
        const owned_domain = try allocator.dupe(u8, domain);
        errdefer allocator.free(owned_domain);
        return initSocks5Association(
            allocator,
            association,
            limits,
            .{
                .host = owned_domain,
                .port = port,
                .logical_peer = logical_peer,
            },
            0,
            0,
        );
    }

    fn initSocks5Association(
        allocator: std.mem.Allocator,
        association: *socks5_proxy.UdpAssociation,
        limits: Limits,
        fixed_domain: ?Socks5UdpState.FixedDomain,
        max_domain_routes: usize,
        max_sources_per_route: usize,
    ) Error!Endpoint {
        const send_storage = try allocator.alloc(
            u8,
            socks5FrameCapacity(limits.max_datagram_size),
        );
        errdefer allocator.free(send_storage);
        var domain_routes: std.ArrayListUnmanaged(
            Socks5UdpState.DomainRoute,
        ) = .empty;
        errdefer domain_routes.deinit(allocator);
        if (max_domain_routes != 0) {
            try domain_routes.ensureTotalCapacity(
                allocator,
                max_domain_routes,
            );
        }
        const io = association.io;
        if (limits.network_interface) |interface| {
            try socket_binding.validateDatagramFamily(association.socket.handle, std.meta.activeTag(association.socket.address));
            try socket_binding.applyInterface(association.io, association.socket.handle, std.meta.activeTag(association.socket.address), .dgram, interface);
        }
        const socket = association.socket;
        const relay = association.relay;
        const control = association.control.takeStream();
        association.* = undefined;
        var endpoint: Endpoint = .{
            .io = io,
            .allocator = allocator,
            .socket = socket,
            .socks5_udp = .{
                .control = control,
                .relay = relay,
                .send_storage = send_storage,
                .fixed_domain = fixed_domain,
                .domain_routes = domain_routes,
                .max_domain_routes = max_domain_routes,
                .max_sources_per_route = max_sources_per_route,
            },
            .limits = limits,
            .gso_send_enabled = false,
            .gro_receive_enabled = false,
        };
        endpoint.configureSocketReceiveBuffer();
        return endpoint;
    }

    pub fn deinit(self: *Endpoint) void {
        for (self.pending_received.items[self.pending_receive_index..]) |*pending| {
            pending.deinit(self.allocator);
        }
        self.pending_received.deinit(self.allocator);
        if (self.held_send) |held| self.allocator.free(held.bytes);
        self.socket.close(self.io);
        if (self.socks5_udp) |proxy| {
            proxy.control.close(self.io);
            self.allocator.free(proxy.send_storage);
            if (proxy.fixed_domain) |fixed| self.allocator.free(fixed.host);
            for (proxy.domain_routes.items) |route| {
                self.allocator.free(route.host);
                self.allocator.free(route.sources);
            }
            var routes = proxy.domain_routes;
            routes.deinit(self.allocator);
        }
        self.* = undefined;
    }

    pub fn address(self: Endpoint) net.IpAddress {
        return self.socket.address;
    }

    pub fn gsoSendEnabled(self: Endpoint) bool {
        return self.gso_send_enabled;
    }

    pub fn groReceiveEnabled(self: Endpoint) bool {
        return self.gro_receive_enabled;
    }

    pub fn usesSocks5Udp(self: Endpoint) bool {
        return self.socks5_udp != null;
    }

    /// Caller storage needed for one socket receive, including any transport
    /// envelope stripped before QUIC parses the datagram.
    pub fn receiveIntoCapacity(self: Endpoint) usize {
        return self.receiveBufferCapacity();
    }

    /// Retain one proxy-resolved domain and return its stable internal QUIC
    /// peer. Repeated registrations share the same mapping by reference.
    pub fn retainSocks5DomainRoute(
        self: *Endpoint,
        domain: []const u8,
        port: u16,
    ) Error!net.IpAddress {
        return self.socks5DomainRoute(domain, port, true);
    }

    /// Return a persistent route without increasing its reference count.
    /// Shared endpoint owners use this for their bounded lifetime route cache.
    pub fn ensureSocks5DomainRoute(
        self: *Endpoint,
        domain: []const u8,
        port: u16,
    ) Error!net.IpAddress {
        return self.socks5DomainRoute(domain, port, false);
    }

    fn socks5DomainRoute(
        self: *Endpoint,
        domain: []const u8,
        port: u16,
        retain_existing: bool,
    ) Error!net.IpAddress {
        _ = try socks5_udp.Address.fromHost(domain, port);
        if (net.IpAddress.parse(domain, port)) |_| {
            return error.InvalidHostName;
        } else |_| {}
        self.socks5_route_mutex.lockUncancelable(self.io);
        defer self.socks5_route_mutex.unlock(self.io);
        const proxy = if (self.socks5_udp) |*value| value else return error.InvalidProxyRouteCapacity;
        if (proxy.max_domain_routes == 0) {
            return error.InvalidProxyRouteCapacity;
        }
        for (proxy.domain_routes.items) |*route| {
            if (route.port == port and
                std.ascii.eqlIgnoreCase(route.host, domain))
            {
                if (retain_existing) {
                    route.references = std.math.add(
                        usize,
                        route.references,
                        1,
                    ) catch return error.ProxyRouteLimitReached;
                }
                return route.logical_peer;
            }
        }
        if (proxy.domain_routes.items.len >= proxy.max_domain_routes) {
            return error.ProxyRouteLimitReached;
        }
        const logical_peer = try nextSocks5LogicalPeer(proxy, self.socket.address, port);
        const owned_domain = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(owned_domain);
        const sources = try self.allocator.alloc(
            net.IpAddress,
            proxy.max_sources_per_route,
        );
        proxy.domain_routes.appendAssumeCapacity(.{
            .host = owned_domain,
            .port = port,
            .logical_peer = logical_peer,
            .sources = sources,
        });
        return logical_peer;
    }

    /// Release one retained mapping. The final release waits for any active
    /// send to finish before freeing its hostname storage.
    pub fn releaseSocks5DomainRoute(
        self: *Endpoint,
        logical_peer: net.IpAddress,
    ) bool {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        self.socks5_route_mutex.lockUncancelable(self.io);
        defer self.socks5_route_mutex.unlock(self.io);
        const proxy = if (self.socks5_udp) |*value| value else return false;
        for (proxy.domain_routes.items, 0..) |*route, index| {
            if (!route.logical_peer.eql(&logical_peer)) continue;
            std.debug.assert(route.references != 0);
            route.references -= 1;
            if (route.references != 0) return true;
            const removed = proxy.domain_routes.swapRemove(index);
            self.allocator.free(removed.host);
            self.allocator.free(removed.sources);
            return true;
        }
        return false;
    }

    pub fn socks5DomainRouteCount(self: *Endpoint) usize {
        self.socks5_route_mutex.lockUncancelable(self.io);
        defer self.socks5_route_mutex.unlock(self.io);
        return if (self.socks5_udp) |proxy|
            proxy.domain_routes.items.len
        else
            0;
    }

    /// CID routing has already identified a connection when this is called.
    /// Restore its logical domain peer without guessing from the proxy's
    /// returned source IP, which may be shared by several hostnames.
    pub fn normalizeSocks5RoutedPeer(
        self: *Endpoint,
        routed_peer: net.IpAddress,
        received_from: net.IpAddress,
    ) net.IpAddress {
        self.socks5_route_mutex.lockUncancelable(self.io);
        defer self.socks5_route_mutex.unlock(self.io);
        const proxy = self.socks5_udp orelse return received_from;
        if (proxy.fixed_domain) |fixed| {
            if (fixed.logical_peer.eql(&routed_peer)) return routed_peer;
        }
        for (proxy.domain_routes.items) |route| {
            if (!route.logical_peer.eql(&routed_peer)) continue;
            for (route.sources[0..route.source_count]) |source| {
                if (source.eql(&received_from)) return routed_peer;
            }
            return received_from;
        }
        return received_from;
    }

    /// A pending handshake CID proves which logical domain route owns this
    /// source. Remember it before the inbox performs its strict peer check.
    pub fn normalizeSocks5PendingPeer(
        self: *Endpoint,
        routed_peer: net.IpAddress,
        received_from: net.IpAddress,
    ) Error!net.IpAddress {
        self.socks5_route_mutex.lockUncancelable(self.io);
        defer self.socks5_route_mutex.unlock(self.io);
        const proxy = if (self.socks5_udp) |*value| value else return received_from;
        if (proxy.fixed_domain) |fixed| {
            if (fixed.logical_peer.eql(&routed_peer)) return routed_peer;
        }
        for (proxy.domain_routes.items) |*route| {
            if (!route.logical_peer.eql(&routed_peer)) continue;
            for (route.sources[0..route.source_count]) |source| {
                if (source.eql(&received_from)) return routed_peer;
            }
            if (route.source_count == route.sources.len) {
                return error.ProxyRouteSourceLimitReached;
            }
            route.sources[route.source_count] = received_from;
            route.source_count += 1;
            return routed_peer;
        }
        return received_from;
    }

    pub fn sendBytes(self: *Endpoint, to: net.IpAddress, bytes: []const u8) Error!void {
        try self.sendBytesWithEcn(to, bytes, .not_ect);
    }

    /// Send one UDP datagram with the requested ECN codepoint on platforms
    /// where the socket API exposes TOS/TCLASS marking.  Unsupported platforms
    /// reject non-Not-ECT marks instead of silently pretending ECN validation
    /// can run.
    pub fn sendBytesWithEcn(self: *Endpoint, to: net.IpAddress, bytes: []const u8, ecn: quic.packet_space.EcnCodepoint) Error!void {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        return self.sendBytesWithEcnLocked(to, bytes, ecn);
    }

    fn sendBytesWithEcnLocked(self: *Endpoint, to: net.IpAddress, bytes: []const u8, ecn: quic.packet_space.EcnCodepoint) Error!void {
        if (bytes.len == 0) return error.EmptyDatagram;
        if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        if (self.limits.send_interceptor) |interceptor| {
            if (interceptor.should_drop) |should_drop| {
                if (should_drop(interceptor.context, bytes)) {
                    try self.flushHeldSend();
                    return;
                }
            }
            if (self.held_send != null) {
                try self.sendSocketDatagram(to, bytes, ecn);
                // The current datagram is already socket-visible here. The
                // interceptor exists to emulate reordering/loss; reporting a
                // later held-packet flush error would make stateful QUIC callers
                // roll back this successfully sent packet and reuse its nonce.
                // Treat the older held datagram as lost so recovery can repair it.
                self.flushHeldSend() catch {};
                return;
            }
            if (interceptor.should_hold) |should_hold| {
                if (should_hold(interceptor.context, bytes)) {
                    const held_bytes = try self.allocator.dupe(u8, bytes);
                    self.held_send = .{
                        .to = to,
                        .bytes = held_bytes,
                        .ecn = ecn,
                    };
                    return;
                }
            }
            if (interceptor.corrupt) |corrupt| {
                const copy = try self.allocator.dupe(u8, bytes);
                defer self.allocator.free(copy);
                if (corrupt(interceptor.context, copy)) {
                    try self.sendSocketDatagram(to, copy, ecn);
                    return;
                }
            }
        }
        try self.sendSocketDatagram(to, bytes, ecn);
    }

    fn sendSocketDatagram(
        self: *Endpoint,
        to: net.IpAddress,
        bytes: []const u8,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!void {
        try self.validateSocks5PayloadSize(to, bytes.len);
        if (self.socks5_udp != null) {
            // SOCKS5 framing has no per-datagram ECN slot; the socket-wide
            // fallback rejects anything but Not-ECT.
            try self.applyOutgoingEcnMark(ecn);
        } else if (comptime builtin.os.tag == .linux) {
            if (ecn != .not_ect and
                (self.test_force_ecn_unavailable or !socketEcnSupported()))
            {
                return error.EcnUnavailable;
            }
            // Carry ECN as an ancillary message instead of flipping the
            // socket-wide mark, which costs a setsockopt on every ACK/data
            // transition. Not-ECT is the socket default, so ACK-only packets
            // skip the control entirely.
            var control: [ecn_send_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
            const ctrl: []const u8 = if (ecn == .not_ect)
                &.{}
            else
                encodeEcnControl(&control, to == .ip6, ecn);
            var message: net.OutgoingMessage = .{
                .address = &to,
                .data_ptr = bytes.ptr,
                .data_len = bytes.len,
                .control = ctrl,
            };
            const send_error, const sent_count = self.io.vtable.netSend(
                self.io.userdata,
                self.socket.handle,
                (&message)[0..1],
                .{},
            );
            // A single datagram is all-or-nothing at this boundary: if the
            // backend reports it complete, a trailing error cannot make the
            // bytes unsent. Reporting the error here would make stateful
            // callers roll back credit for data the peer already received.
            if (sent_count == 1) {
                self.recordSocketSent(1, bytes.len);
                return;
            }
            if (send_error) |err| return err;
            return error.Unexpected;
        } else {
            try self.applyOutgoingEcnMark(ecn);
        }
        if (self.socks5_udp) |*proxy| {
            const destination = self.socks5Destination(to);
            const framed = try socks5_udp.encodeDatagram(
                proxy.send_storage,
                destination,
                bytes,
            );
            try self.socket.send(self.io, &proxy.relay, framed);
            if (proxy.fixed_domain) |*fixed| {
                fixed.active = to.eql(&fixed.logical_peer);
            }
            self.recordSocketSent(1, framed.len);
            return;
        }
        try self.socket.send(self.io, &to, bytes);
        self.recordSocketSent(1, bytes.len);
    }

    fn flushHeldSend(self: *Endpoint) Error!void {
        const held = self.held_send orelse return;
        self.held_send = null;
        defer self.allocator.free(held.bytes);
        try self.sendSocketDatagram(held.to, held.bytes, held.ecn);
    }

    /// Send multiple UDP datagrams through the backend's batch primitive.
    ///
    /// Zig's Threaded backend maps this to Linux `sendmmsg` in chunks of 64
    /// messages; other backends retain identical semantics with a safe
    /// per-message fallback. Validation happens before the first syscall so
    /// invalid input cannot produce a partially sent batch.
    pub fn sendManyBytes(self: *Endpoint, to: net.IpAddress, datagrams: []const []const u8) Error!void {
        const result = try self.sendManyBytesProgress(to, datagrams);
        if (result.send_error) |err| return err;
        std.debug.assert(result.sent_count == datagrams.len);
    }

    /// Send a batch while preserving progress if the socket accepts a prefix.
    ///
    /// Linux `sendmmsg` and the portable per-message fallback can both report
    /// an error after earlier datagrams have already left the process. A plain
    /// error union cannot carry that count, so stateful callers such as QUIC
    /// recovery use this result to commit the sent prefix and roll back only
    /// the unsent suffix. Validation and ECN setup still fail through the error
    /// union because they happen before the first datagram can be emitted.
    pub fn sendManyBytesProgress(self: *Endpoint, to: net.IpAddress, datagrams: []const []const u8) Error!SendManyBytesResult {
        return self.sendManyBytesProgressWithEcn(
            to,
            datagrams,
            .not_ect,
        );
    }

    /// Send a batch while applying one ECN codepoint to every datagram.
    ///
    /// QUIC's stateful batch packetizer currently emits one path-scoped policy
    /// decision per batch.  Keeping that decision explicit here preserves the
    /// existing default `Not-ECT` surface while letting 1-RTT automatically
    /// mark ordinary application batches with `ECT(0)` when ECN is still being
    /// validated on the current path.
    pub fn sendManyBytesProgressWithEcn(
        self: *Endpoint,
        to: net.IpAddress,
        datagrams: []const []const u8,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!SendManyBytesResult {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        return self.sendManyBytesProgressLocked(to, datagrams, ecn);
    }

    fn sendManyBytesProgressLocked(
        self: *Endpoint,
        to: net.IpAddress,
        datagrams: []const []const u8,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!SendManyBytesResult {
        if (datagrams.len == 0) return .{ .sent_count = 0 };
        for (datagrams) |bytes| {
            if (bytes.len == 0) return error.EmptyDatagram;
            if (bytes.len > self.limits.max_datagram_size) return error.DatagramTooLarge;
        }
        if (self.limits.send_interceptor != null) {
            // A dropped datagram is still consumed from QUIC's perspective;
            // submitting individually preserves exact deterministic filtering
            // and prevents GSO from hiding segment boundaries.
            var sent_count: usize = 0;
            for (datagrams) |bytes| {
                self.sendBytesWithEcnLocked(to, bytes, ecn) catch |err| {
                    const send_error = endpointSocketSendError(err);
                    if (send_error) |value| {
                        return .{
                            .sent_count = sent_count,
                            .send_error = value,
                        };
                    }
                    // A prior interceptor datagram was already consumed, but
                    // the progress result cannot carry non-socket failures such
                    // as an allocation error from a later corrupt/hold action.
                    // Preserve the visible prefix and surface a terminal generic
                    // send error instead of losing that progress to the union.
                    if (sent_count != 0) {
                        return .{
                            .sent_count = sent_count,
                            .send_error = error.Unexpected,
                        };
                    }
                    return err;
                };
                sent_count += 1;
            }
            // A batch ending exactly on a selected packet has no later call
            // inside this batch to release it. Flush at the batch boundary so
            // deterministic reordering never silently becomes packet loss.
            // A held packet is a deliberately delayed/lossy test artifact. If
            // its final flush fails, every caller datagram has nevertheless
            // been consumed and any already-visible successor must stay
            // committed. Recovery will retransmit the missing older packet.
            self.flushHeldSend() catch {};
            return .{ .sent_count = datagrams.len };
        }
        if (self.socks5_udp != null) {
            try self.validateSocks5DatagramSize(to, datagrams);
            try self.applyOutgoingEcnMark(ecn);
            var sent_count: usize = 0;
            for (datagrams) |bytes| {
                self.sendSocketDatagram(to, bytes, ecn) catch |err| {
                    if (endpointSocketSendError(err)) |send_error| {
                        return .{
                            .sent_count = sent_count,
                            .send_error = send_error,
                        };
                    }
                    if (sent_count != 0) {
                        return .{
                            .sent_count = sent_count,
                            .send_error = error.Unexpected,
                        };
                    }
                    return err;
                };
                sent_count += 1;
            }
            return .{ .sent_count = sent_count };
        }
        var ecn_control: [ecn_send_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        const cmsg_ecn = comptime builtin.os.tag == .linux;
        const ecn_ctrl: []const u8 = if (cmsg_ecn and ecn != .not_ect)
            encodeEcnControl(&ecn_control, to == .ip6, ecn)
        else
            &.{};
        if (cmsg_ecn) {
            if (ecn != .not_ect and
                (self.test_force_ecn_unavailable or !socketEcnSupported()))
            {
                return error.EcnUnavailable;
            }
        } else try self.applyOutgoingEcnMark(ecn);

        if (self.gso_send_enabled) {
            if (gsoPlan(datagrams)) |plan| {
                if (self.sendGso(to, plan, ecn_ctrl)) |result| return result;
            }
        }

        // Match the Threaded backend's Linux sendmmsg chunk size. Keeping the
        // descriptors on the stack makes steady-state batch submission
        // allocation-free on every backend.
        var message_storage: [64]net.OutgoingMessage = undefined;
        var expected_lengths: [64]usize = undefined;
        var offset: usize = 0;
        while (offset < datagrams.len) {
            const count = @min(message_storage.len, datagrams.len - offset);
            const messages = message_storage[0..count];
            const chunk = datagrams[offset..][0..count];
            for (messages, chunk) |*message, bytes| {
                message.* = .{
                    .address = &to,
                    .data_ptr = bytes.ptr,
                    .data_len = bytes.len,
                    .control = ecn_ctrl,
                };
            }
            for (expected_lengths[0..count], chunk) |*expected, bytes| {
                expected.* = bytes.len;
            }
            const progress = self.sendMessageChunk(
                messages,
                expected_lengths[0..count],
            );
            offset += progress.sent_count;
            if (progress.send_error) |err| {
                return .{ .sent_count = offset, .send_error = err };
            }
            std.debug.assert(progress.sent_count == count);
        }
        return .{ .sent_count = offset };
    }

    /// Batch UDP payloads for different peer addresses under one socket lock
    /// and one backend submission per bounded chunk. This is the endpoint
    /// counterpart to Quinn's separation between protocol `Transmit` objects
    /// and the shared UDP socket owner. One ECN policy applies to the batch;
    /// callers with different policies must group them separately.
    pub fn sendManyAddressedBytes(
        self: *Endpoint,
        datagrams: []const AddressedDatagram,
    ) Error!void {
        const result = try self.sendManyAddressedBytesProgress(datagrams);
        if (result.send_error) |err| return err;
        std.debug.assert(result.sent_count == datagrams.len);
    }

    /// Not-ECT addressed batch with explicit socket-visible prefix progress.
    pub fn sendManyAddressedBytesProgress(
        self: *Endpoint,
        datagrams: []const AddressedDatagram,
    ) Error!SendManyBytesResult {
        return self.sendManyAddressedBytesProgressWithEcn(
            datagrams,
            .not_ect,
        );
    }

    /// Addressed prefix-progress batch with one explicit ECN policy.
    pub fn sendManyAddressedBytesProgressWithEcn(
        self: *Endpoint,
        datagrams: []const AddressedDatagram,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!SendManyBytesResult {
        self.send_mutex.lockUncancelable(self.io);
        defer self.send_mutex.unlock(self.io);
        return self.sendManyAddressedBytesProgressWithEcnLocked(
            datagrams,
            ecn,
        );
    }

    fn sendManyAddressedBytesProgressWithEcnLocked(
        self: *Endpoint,
        datagrams: []const AddressedDatagram,
        ecn: quic.packet_space.EcnCodepoint,
    ) Error!SendManyBytesResult {
        if (datagrams.len == 0) return .{ .sent_count = 0 };
        for (datagrams) |datagram| {
            if (datagram.bytes.len == 0) return error.EmptyDatagram;
            if (datagram.bytes.len > self.limits.max_datagram_size) {
                return error.DatagramTooLarge;
            }
        }
        if (self.limits.send_interceptor != null) {
            var sent_count: usize = 0;
            for (datagrams) |datagram| {
                self.sendBytesWithEcnLocked(
                    datagram.to,
                    datagram.bytes,
                    ecn,
                ) catch |err| {
                    if (endpointSocketSendError(err)) |send_error| {
                        return .{
                            .sent_count = sent_count,
                            .send_error = send_error,
                        };
                    }
                    if (sent_count != 0) {
                        return .{
                            .sent_count = sent_count,
                            .send_error = error.Unexpected,
                        };
                    }
                    return err;
                };
                sent_count += 1;
            }
            self.flushHeldSend() catch {};
            return .{ .sent_count = datagrams.len };
        }
        if (self.socks5_udp != null) {
            for (datagrams) |datagram| {
                try self.validateSocks5PayloadSize(
                    datagram.to,
                    datagram.bytes.len,
                );
            }
            try self.applyOutgoingEcnMark(ecn);
            var sent_count: usize = 0;
            for (datagrams) |datagram| {
                self.sendSocketDatagram(
                    datagram.to,
                    datagram.bytes,
                    ecn,
                ) catch |err| {
                    if (endpointSocketSendError(err)) |send_error| {
                        return .{
                            .sent_count = sent_count,
                            .send_error = send_error,
                        };
                    }
                    if (sent_count != 0) {
                        return .{
                            .sent_count = sent_count,
                            .send_error = error.Unexpected,
                        };
                    }
                    return err;
                };
                sent_count += 1;
            }
            return .{ .sent_count = sent_count };
        }
        var ecn_control_v4: [ecn_send_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var ecn_control_v6: [ecn_send_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        const cmsg_ecn = comptime builtin.os.tag == .linux;
        const ecn_ctrl_v4: []const u8 = if (cmsg_ecn and ecn != .not_ect)
            encodeEcnControl(&ecn_control_v4, false, ecn)
        else
            &.{};
        const ecn_ctrl_v6: []const u8 = if (cmsg_ecn and ecn != .not_ect)
            encodeEcnControl(&ecn_control_v6, true, ecn)
        else
            &.{};
        if (cmsg_ecn) {
            if (ecn != .not_ect and
                (self.test_force_ecn_unavailable or !socketEcnSupported()))
            {
                return error.EcnUnavailable;
            }
        } else try self.applyOutgoingEcnMark(ecn);

        var message_storage: [64]net.OutgoingMessage = undefined;
        var expected_lengths: [64]usize = undefined;
        var offset: usize = 0;
        while (offset < datagrams.len) {
            const count = @min(
                message_storage.len,
                datagrams.len - offset,
            );
            const messages = message_storage[0..count];
            const chunk = datagrams[offset..][0..count];
            for (messages, chunk) |*message, *datagram| {
                message.* = .{
                    .address = &datagram.to,
                    .data_ptr = datagram.bytes.ptr,
                    .data_len = datagram.bytes.len,
                    .control = if (datagram.to == .ip6) ecn_ctrl_v6 else ecn_ctrl_v4,
                };
            }
            for (expected_lengths[0..count], chunk) |*expected, datagram| {
                expected.* = datagram.bytes.len;
            }
            const progress = self.sendMessageChunk(
                messages,
                expected_lengths[0..count],
            );
            offset += progress.sent_count;
            if (progress.send_error) |err| {
                return .{ .sent_count = offset, .send_error = err };
            }
            std.debug.assert(progress.sent_count == count);
        }
        return .{ .sent_count = offset };
    }

    /// Submit one already validated descriptor chunk and normalize every
    /// backend outcome to the same prefix-progress contract used by both the
    /// same- and heterogeneous-destination public batch APIs.
    fn sendMessageChunk(
        self: *Endpoint,
        messages: []net.OutgoingMessage,
        expected_lengths: []const usize,
    ) SendManyBytesResult {
        std.debug.assert(messages.len != 0);
        std.debug.assert(messages.len == expected_lengths.len);
        const send_error, const sent_count = self.io.vtable.netSend(
            self.io.userdata,
            self.socket.handle,
            messages,
            .{},
        );
        if (sent_count > messages.len) {
            // The exact visible subset is unknowable. Consume the submitted
            // chunk so stateful transports never reuse a protected nonce.
            return .{
                .sent_count = messages.len,
                .send_error = error.Unexpected,
            };
        }
        self.recordSocketSentMessages(messages[0..sent_count]);
        for (
            messages[0..sent_count],
            expected_lengths[0..sent_count],
        ) |message, expected_len| {
            if (message.data_len != expected_len) {
                return .{
                    .sent_count = sent_count,
                    .send_error = error.MessageOversize,
                };
            }
        }
        if (send_error) |err| {
            return .{ .sent_count = sent_count, .send_error = err };
        }
        if (sent_count != messages.len) {
            // A short count without an accompanying error violates std.Io's
            // send-many contract; surface it instead of spinning.
            return .{
                .sent_count = sent_count,
                .send_error = error.Unexpected,
            };
        }
        return .{ .sent_count = sent_count };
    }

    /// Submit a Linux UDP GSO super-packet. Returning `null` means the kernel
    /// rejected GSO before accepting data and the caller should retry through
    /// the portable send-many path.
    fn sendGso(self: *Endpoint, to: net.IpAddress, plan: GsoPlan, ecn_ctrl: []const u8) ?SendManyBytesResult {
        var control: [udp_gso_control_len + ecn_send_control_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        const gso_storage: *[udp_gso_control_len]u8 = control[0..udp_gso_control_len];
        const gso_slice = encodeUdpGsoControl(gso_storage, plan.segment_size);
        var control_len = gso_slice.len;
        if (ecn_ctrl.len != 0) {
            @memcpy(control[control_len..][0..ecn_ctrl.len], ecn_ctrl);
            control_len += ecn_ctrl.len;
        }
        var message: net.OutgoingMessage = .{
            .address = &to,
            .data_ptr = plan.data_ptr,
            .data_len = plan.total_len,
            .control = control[0..control_len],
        };
        const send_error, const sent_count = self.io.vtable.netSend(
            self.io.userdata,
            self.socket.handle,
            (&message)[0..1],
            .{},
        );
        if (sent_count == 1) {
            const actual_segments = std.math.divCeil(
                usize,
                message.data_len,
                plan.segment_size,
            ) catch 0;
            self.recordSocketSent(actual_segments, message.data_len);
            return .{
                .sent_count = plan.segment_count,
                .send_error = if (message.data_len == plan.total_len)
                    send_error
                else
                    error.MessageOversize,
            };
        }
        if (sent_count > 1) {
            // The backend violated its ABI. Conservatively consume every
            // segment because the exact subset visible on the network is no
            // longer knowable and QUIC packet numbers must never be reused.
            return .{ .sent_count = plan.segment_count, .send_error = error.Unexpected };
        }
        const err = send_error orelse return .{ .sent_count = 0, .send_error = error.Unexpected };
        if (gsoFallbackError(err)) {
            // Linux reports unsupported UDP_SEGMENT through an I/O-style
            // socket error. Zig deliberately normalizes undocumented errno
            // values to Unexpected, so remember the failure and avoid paying
            // for another speculative GSO syscall on this endpoint.
            self.gso_send_enabled = false;
            return null;
        }
        return .{ .sent_count = 0, .send_error = err };
    }

    fn recordSocketSent(
        self: *Endpoint,
        datagrams: usize,
        bytes: usize,
    ) void {
        const counters = self.limits.socket_traffic_counters orelse return;
        counters.recordSent(datagrams, bytes);
    }

    fn recordSocketSentMessages(
        self: *Endpoint,
        messages: []const net.OutgoingMessage,
    ) void {
        const counters = self.limits.socket_traffic_counters orelse return;
        var bytes: usize = 0;
        for (messages) |message| bytes +|= message.data_len;
        counters.recordSent(messages.len, bytes);
    }

    fn recordSocketReceived(
        self: *Endpoint,
        incoming: net.IncomingMessage,
    ) void {
        const counters = self.limits.socket_traffic_counters orelse return;
        var datagrams: usize = 1;
        if (self.gro_receive_enabled) {
            const control = receiveControlFromBytes(incoming.control);
            if (control.gro_segment_size) |segment_size| {
                if (segment_size != 0) {
                    datagrams = std.math.divCeil(
                        usize,
                        incoming.data.len,
                        segment_size,
                    ) catch 1;
                }
            }
        }
        counters.recordReceived(datagrams, incoming.data.len);
    }

    pub fn sendFrames(self: *Endpoint, to: net.IpAddress, frames: []const quic.Frame) Error!void {
        var payload_len: usize = 0;
        for (frames) |frame| {
            payload_len = std.math.add(
                usize,
                payload_len,
                try frame.wireLen(),
            ) catch return error.InvalidFrameLength;
        }
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.ensureTotalCapacity(self.allocator, payload_len);
        for (frames) |frame| try frame.write(&payload, self.allocator);
        try self.sendBytes(to, payload.items);
    }

    /// Build a Version Negotiation response for a received unsupported-version
    /// long-header datagram.
    ///
    /// This is intentionally version-independent: it only peeks the invariant
    /// long-header fields, validates endpoint configuration, and then delegates
    /// packet serialization to `quic.writeVersionNegotiationPacket`.  Malformed
    /// or truncated trigger datagrams are dropped by returning `null`, which is
    /// the safer socket-loop behavior for attacker-controlled UDP input.
    pub fn versionNegotiationResponse(
        self: *Endpoint,
        datagram: []const u8,
        supported_versions: []const u32,
    ) Error!?[]u8 {
        try validateSupportedVersions(supported_versions);
        const ids = peekUnsupportedVersionConnectionIds(datagram, supported_versions) orelse return null;
        const options: quic.VersionNegotiationPacketOptions = .{
            .first_byte = try versionNegotiationFirstByte(self.io),
            .destination_connection_id = ids.source_connection_id,
            .source_connection_id = ids.destination_connection_id,
            .versions = supported_versions,
        };
        const response = try self.allocator.alloc(
            u8,
            try quic.versionNegotiationPacketLen(options),
        );
        errdefer self.allocator.free(response);
        _ = try quic.writeVersionNegotiationPacketInto(response, options);
        return response;
    }

    /// Send Version Negotiation to `to` when `datagram` is an unsupported QUIC
    /// long-header packet. Returns `false` for short headers, already-supported
    /// versions, received Version Negotiation packets, or malformed datagrams.
    pub fn sendVersionNegotiationIfUnsupported(
        self: *Endpoint,
        to: net.IpAddress,
        datagram: []const u8,
        supported_versions: []const u32,
    ) Error!bool {
        try validateSupportedVersions(supported_versions);
        const ids = peekUnsupportedVersionConnectionIds(
            datagram,
            supported_versions,
        ) orelse return false;
        const options: quic.VersionNegotiationPacketOptions = .{
            .first_byte = try versionNegotiationFirstByte(self.io),
            .destination_connection_id = ids.source_connection_id,
            .source_connection_id = ids.destination_connection_id,
            .versions = supported_versions,
        };
        const response_len = try quic.versionNegotiationPacketLen(options);
        if (response_len > self.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        var stack_storage: [256]u8 = undefined;
        if (response_len <= stack_storage.len) {
            const response = try quic.writeVersionNegotiationPacketInto(
                &stack_storage,
                options,
            );
            try self.sendBytes(to, response);
        } else {
            // Version lists are normally two entries. Retain exact allocation
            // as a bounded fallback for applications advertising unusually
            // large experimental-version sets.
            const storage = try self.allocator.alloc(u8, response_len);
            defer self.allocator.free(storage);
            const response = try quic.writeVersionNegotiationPacketInto(
                storage,
                options,
            );
            try self.sendBytes(to, response);
        }
        return true;
    }

    /// Send a stateless reset for an unknown-CID short-header datagram.
    ///
    /// The response is always smaller than the triggering packet and capped at
    /// 1200 bytes. This both follows RFC 9000's loop-avoidance requirement and
    /// keeps attacker-triggered endpoint work allocation-free.
    pub fn sendStatelessResetForConnectionId(
        self: *Endpoint,
        to: net.IpAddress,
        triggering_datagram: []const u8,
        static_key: [quic.stateless_reset.static_key_len]u8,
        connection_id: []const u8,
    ) Error!bool {
        if (connection_id.len == 0 or
            connection_id.len > quic.connection_router.max_connection_id_len)
        {
            return error.InvalidConnectionId;
        }
        const response_len = quic.stateless_reset.responseLen(
            triggering_datagram,
            self.limits.max_datagram_size,
        ) orelse return false;
        var storage: [quic.stateless_reset.max_response_len]u8 = undefined;
        const response = quic.stateless_reset.encodeForConnectionIdInto(
            &storage,
            self.io,
            response_len,
            static_key,
            connection_id,
        ) catch |err| switch (err) {
            error.InvalidLength, error.InvalidHeaderForm => unreachable,
            error.BufferTooShort => return error.BufferTooShort,
            error.Canceled => return error.Canceled,
            error.EntropyUnavailable => return error.EntropyUnavailable,
            error.OutOfMemory => return error.OutOfMemory,
        };
        try self.sendBytes(to, response);
        return true;
    }

    pub fn receive(self: *Endpoint) Error!OwnedDatagram {
        return self.receiveUntil(null) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveWithTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedDatagram {
        return self.receiveUntil(timeout);
    }

    pub fn receiveWithDeadline(
        self: *Endpoint,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedDatagram {
        return self.receiveUntil(.{ .deadline = try deadline_policy.usableAwake(self.io, deadline) });
    }

    fn receiveUntil(
        self: *Endpoint,
        timeout: ?std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedDatagram {
        var raw = if (timeout) |bounded|
            try self.receiveBytesTimeout(bounded)
        else
            try self.receiveBytes();
        errdefer raw.deinit(self.allocator);
        if (raw.bytes.len == 0) return error.EmptyDatagram;

        var frames: std.ArrayList(quic.Frame) = .empty;
        errdefer {
            quic.deinitOwnedFrameSlice(frames.items, self.allocator);
            frames.deinit(self.allocator);
        }

        var pos: usize = 0;
        while (pos < raw.bytes.len) {
            if (frames.items.len >= self.limits.max_frames_per_datagram) return error.DatagramTooLarge;
            var parsed = try quic.parseFrameOwned(self.allocator, raw.bytes[pos..]);
            var appended = false;
            defer if (!appended) parsed.deinitOwned(self.allocator);
            if (parsed.consumed == 0) return error.TrailingBytes;
            try frames.append(self.allocator, parsed.frame);
            appended = true;
            pos += parsed.consumed;
        }

        const owned_frames = try frames.toOwnedSlice(self.allocator);
        return .{
            .from = raw.from,
            .bytes = raw.bytes,
            .ecn = raw.ecn,
            .frames = owned_frames,
            .shared_buffer = raw.shared_buffer,
        };
    }

    pub fn receiveBytes(self: *Endpoint) Error!OwnedBytes {
        return self.receiveBytesWithEcn();
    }

    /// Receive one non-GRO datagram directly into caller storage.
    ///
    /// The returned bytes borrow `buffer` until the caller reuses it. GRO is
    /// rejected because one kernel receive can contain several logical
    /// datagrams whose suffix must remain owned after this call returns; use
    /// `receiveBytesBatch` for that shape.
    pub fn receiveBytesInto(
        self: *Endpoint,
        buffer: []u8,
    ) Error!ReceivedBytesView {
        if (buffer.len == 0) return error.BufferTooShort;
        if (self.gro_receive_enabled) {
            return error.CallerBufferReceiveWithGro;
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        return self.receiveKernelBytesInto(buffer);
    }

    /// Deadline-aware counterpart to `receiveBytesInto`.
    pub fn receiveBytesIntoTimeout(
        self: *Endpoint,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!ReceivedBytesView {
        if (buffer.len == 0) return error.BufferTooShort;
        if (self.gro_receive_enabled) {
            return error.CallerBufferReceiveWithGro;
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        return self.receiveKernelBytesIntoTimeout(buffer, timeout);
    }

    pub fn receiveBytesIntoWithTimeout(
        self: *Endpoint,
        buffer: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!ReceivedBytesView {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveBytesIntoWithDeadline(buffer, .fromNow(self.io, .{
            .clock = .awake,
            .raw = timeout,
        }));
    }

    pub fn receiveBytesIntoWithDeadline(
        self: *Endpoint,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ReceivedBytesView {
        return self.receiveBytesIntoTimeout(
            buffer,
            .{ .deadline = try deadline_policy.usableAwake(
                self.io,
                deadline,
            ) },
        );
    }

    /// Wait for one UDP datagram and drain up to `out.len` already-ready
    /// datagrams into caller storage. Each returned view remains valid until
    /// `buffer` is reused. The buffer must reserve `max_datagram_size` bytes
    /// per output slot so an oversized datagram cannot truncate a later slot.
    ///
    /// This API batches independent socket messages. GRO endpoints must use
    /// `receiveBytesBatchIntoTimeout`, whose segments share one source and ECN
    /// control record.
    pub fn receiveManyBytesIntoTimeout(
        self: *Endpoint,
        buffer: []u8,
        out: []ReceivedBytesView,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!usize {
        try self.validateManyReceiveBuffers(buffer, out);
        var messages: [max_receive_batch_messages]net.IncomingMessage =
            undefined;
        var controls: [max_receive_batch_messages][
            receive_control_buffer_len
        ]u8 align(@alignOf(EcnCmsgHdr)) = undefined;

        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        const deadline = timeout.toDeadline(self.io);
        while (true) {
            for (
                messages[0..out.len],
                controls[0..out.len],
            ) |*message, *control| {
                message.* = .init;
                // recvmsg writes the ancillary prefix and returns its exact
                // length. Unused suffixes and batch slots are never inspected.
                message.control = control;
            }
            const receive_error, const count = self.socket.receiveManyTimeout(
                self.io,
                messages[0..out.len],
                buffer,
                .{},
                deadline,
            );
            if (count == 0) {
                if (receive_error) |err| {
                    if (err == error.MessageOversize) continue;
                }
            }
            return self.finishManyKernelBytesInto(
                messages[0..out.len],
                out,
                receive_error,
                count,
            );
        }
    }

    pub fn finishManyKernelBytesInto(
        self: *Endpoint,
        messages: []const net.IncomingMessage,
        out: []ReceivedBytesView,
        receive_error: ?ReceiveTimeoutError,
        count: usize,
    ) ReceiveTimeoutError!usize {
        std.debug.assert(count <= messages.len and count <= out.len);
        if (count == 0) {
            if (receive_error) |err| return err;
            unreachable;
        }
        if (receive_error) |err| cancellation.preserveIgnored(self.io, err);
        // `std.Io` may report an error from a nonblocking drain after one or
        // more datagrams were already removed from the socket. Preserve that
        // visible prefix; a persistent socket error will be observed by the
        // next receive call.
        for (messages[0..count], out[0..count]) |incoming, *view| {
            self.recordSocketReceived(incoming);
            view.* = try self.finishKernelBytesInto(incoming);
        }
        return count;
    }

    pub fn receiveManyBytesIntoWithTimeout(
        self: *Endpoint,
        buffer: []u8,
        out: []ReceivedBytesView,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveManyBytesIntoWithDeadline(
            buffer,
            out,
            .fromNow(self.io, .{ .clock = .awake, .raw = timeout }),
        );
    }

    pub fn receiveManyBytesIntoWithDeadline(
        self: *Endpoint,
        buffer: []u8,
        out: []ReceivedBytesView,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!usize {
        return self.receiveManyBytesIntoTimeout(buffer, out, .{
            .deadline = try deadline_policy.usableAwake(self.io, deadline),
        });
    }

    /// Receive one datagram with a caller-supplied deadline.
    ///
    /// Pending GRO segments are consumed before arming a kernel timeout. This
    /// keeps timed handshake loops compatible with the ordinary receive FIFO.
    pub fn receiveBytesTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        if (self.takePendingReceived()) |pending| return pending;
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (self.takePendingReceived()) |pending| return pending;
        return self.receiveKernelBytesTimeout(timeout);
    }

    pub fn receiveBytesWithTimeout(
        self: *Endpoint,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedBytes {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveBytesWithDeadline(.fromNow(self.io, .{
            .clock = .awake,
            .raw = timeout,
        }));
    }

    pub fn receiveBytesWithDeadline(
        self: *Endpoint,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.receiveBytesTimeout(.{
            .deadline = try deadline_policy.usableAwake(self.io, deadline),
        });
    }

    /// Receive one kernel datagram, which may contain multiple UDP_GRO
    /// segments. The returned batch owns one allocation and exposes individual
    /// datagrams as borrowed slices through `datagramAt`.
    pub fn receiveBytesBatch(self: *Endpoint) Error!OwnedBytesBatch {
        return self.receiveBytesBatchWithEcn();
    }

    /// Receive one kernel/GRO batch with a caller-supplied timeout.
    ///
    /// Unlike `receiveBytesTimeout`, this preserves coalesced segments as one
    /// owning batch instead of moving the suffix into the single-datagram FIFO.
    /// QUIC's blocking batch pump uses it to arm PTO/ACK deadlines without
    /// forfeiting GRO amortization.
    pub fn receiveBytesBatchTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytesBatch {
        if (self.takePendingReceived()) |pending| {
            return ownedBytesAsBatch(pending);
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (self.takePendingReceived()) |pending| {
            return ownedBytesAsBatch(pending);
        }
        return self.receiveKernelBytesBatchTimeout(timeout);
    }

    pub fn receiveBytesBatchWithTimeout(
        self: *Endpoint,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedBytesBatch {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveBytesBatchWithDeadline(.fromNow(self.io, .{
            .clock = .awake,
            .raw = timeout,
        }));
    }

    pub fn receiveBytesBatchWithDeadline(
        self: *Endpoint,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedBytesBatch {
        return self.receiveBytesBatchTimeout(.{
            .deadline = try deadline_policy.usableAwake(self.io, deadline),
        });
    }

    pub fn receiveBytesBatchWithEcn(self: *Endpoint) Error!OwnedBytesBatch {
        if (self.takePendingReceived()) |pending| {
            return ownedBytesAsBatch(pending);
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        // Another receive may have filled the FIFO while this caller waited
        // for the socket. Recheck before issuing an unnecessary blocking recv.
        if (self.takePendingReceived()) |pending| return ownedBytesAsBatch(pending);
        return self.receiveKernelBytesBatchWithEcn();
    }

    /// Receive one kernel datagram or UDP_GRO batch directly into caller
    /// storage. The returned segment slices remain valid until `buffer` is
    /// reused. GRO endpoints require `max_gro_receive_bytes` bytes so a kernel
    /// batch can never be consumed through a truncated buffer.
    pub fn receiveBytesBatchInto(
        self: *Endpoint,
        buffer: []u8,
    ) Error!ReceivedBytesBatchView {
        try self.validateBatchReceiveBuffer(buffer);
        if (try self.copyPendingReceivedIntoBatch(buffer)) |pending| {
            return pending;
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (try self.copyPendingReceivedIntoBatch(buffer)) |pending| {
            return pending;
        }
        return self.receiveKernelBytesBatchInto(buffer);
    }

    pub fn receiveBytesBatchIntoTimeout(
        self: *Endpoint,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!ReceivedBytesBatchView {
        try self.validateBatchReceiveBuffer(buffer);
        if (try self.copyPendingReceivedIntoBatch(buffer)) |pending| {
            return pending;
        }
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (try self.copyPendingReceivedIntoBatch(buffer)) |pending| {
            return pending;
        }
        return self.receiveKernelBytesBatchIntoTimeout(buffer, timeout);
    }

    pub fn receiveBytesBatchIntoWithTimeout(
        self: *Endpoint,
        buffer: []u8,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!ReceivedBytesBatchView {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveBytesBatchIntoWithDeadline(buffer, .fromNow(
            self.io,
            .{ .clock = .awake, .raw = timeout },
        ));
    }

    pub fn receiveBytesBatchIntoWithDeadline(
        self: *Endpoint,
        buffer: []u8,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!ReceivedBytesBatchView {
        return self.receiveBytesBatchIntoTimeout(buffer, .{
            .deadline = try deadline_policy.usableAwake(self.io, deadline),
        });
    }

    /// Receive one UDP datagram and preserve the kernel-reported ECN codepoint.
    /// If ancillary ECN reception was unavailable when the socket was bound,
    /// callers get `.not_ect`, matching the conservative QUIC fallback.
    pub fn receiveBytesWithEcn(self: *Endpoint) Error!OwnedBytes {
        if (self.takePendingReceived()) |pending| return pending;
        self.socket_receive_mutex.lockUncancelable(self.io);
        defer self.socket_receive_mutex.unlock(self.io);
        if (self.takePendingReceived()) |pending| return pending;

        var batch = try self.receiveKernelBytesBatchWithEcn();
        errdefer batch.deinit(self.allocator);
        if (batch.segment_count == 1) {
            const result: OwnedBytes = .{
                .from = batch.from,
                .received_on = batch.received_on,
                .bytes = batch.storage,
                .ecn = batch.ecn,
                .shared_buffer = batch.shared_buffer,
            };
            batch.disown();
            return result;
        }

        self.pending_receive_mutex.lockUncancelable(self.io);
        defer self.pending_receive_mutex.unlock(self.io);
        try self.ensurePendingReceivedCapacity(batch.segment_count - 1);
        const shared = try self.allocator.create(SharedReceiveBuffer);
        shared.* = .{
            .allocator = self.allocator,
            .storage = batch.storage,
            .references = .init(batch.segment_count),
        };
        batch.disown();
        var index: usize = 1;
        while (index < batch.segment_count) : (index += 1) {
            self.pending_received.appendAssumeCapacity(.{
                .from = batch.from,
                .received_on = batch.received_on,
                .bytes = batch.datagramAtUnchecked(index),
                .ecn = batch.ecn,
                .shared_buffer = shared,
            });
        }
        return .{
            .from = batch.from,
            .received_on = batch.received_on,
            .bytes = batch.datagramAtUnchecked(0),
            .ecn = batch.ecn,
            .shared_buffer = shared,
        };
    }

    pub fn receiveKernelBytesBatchWithEcn(self: *Endpoint) Error!OwnedBytesBatch {
        const receive_capacity = self.receiveBufferCapacity();
        const buffer = try self.allocator.alloc(u8, receive_capacity);
        errdefer self.allocator.free(buffer);
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelInto(
            &incoming,
            &control_buffer,
            buffer,
        );
        self.recordSocketReceived(incoming);
        return self.finishKernelBytesBatch(buffer, incoming);
    }

    /// Receive one kernel UDP message while ignoring asynchronous ICMP
    /// Packet-Too-Big/Fragmentation-Needed reports. std.Io exposes those
    /// unauthenticated path hints as MessageOversize from the recv operation;
    /// actual oversized datagrams remain distinguishable through MSG_TRUNC or
    /// MSG_CTRUNC and are rejected by the finish helpers below.
    fn receiveOneKernelInto(
        self: *Endpoint,
        incoming: *net.IncomingMessage,
        control_buffer: []u8,
        data_buffer: []u8,
    ) Error!void {
        while (true) {
            prepareKernelReceive(incoming, control_buffer);
            const maybe_err, const count = (try self.io.operate(.{
                .net_receive = .{
                    .socket_handle = self.socket.handle,
                    .message_buffer = incoming[0..1],
                    .data_buffer = data_buffer,
                    .flags = .{},
                },
            })).net_receive;
            if (maybe_err) |err| {
                if (err == error.MessageOversize) continue;
                return err;
            }
            std.debug.assert(count == 1);
            return;
        }
    }

    fn receiveOneKernelIntoTimeout(
        self: *Endpoint,
        incoming: *net.IncomingMessage,
        control_buffer: []u8,
        data_buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!void {
        // Converting a relative timeout once prevents ignored ICMP errors from
        // renewing the caller's receive budget.
        const deadline = timeout.toDeadline(self.io);
        while (true) {
            prepareKernelReceive(incoming, control_buffer);
            const maybe_err, const count = (try self.io.operateTimeout(
                .{ .net_receive = .{
                    .socket_handle = self.socket.handle,
                    .message_buffer = incoming[0..1],
                    .data_buffer = data_buffer,
                    .flags = .{},
                } },
                deadline,
            )).net_receive;
            if (maybe_err) |err| {
                if (err == error.MessageOversize) continue;
                return err;
            }
            std.debug.assert(count == 1);
            return;
        }
    }

    fn prepareKernelReceive(
        incoming: *net.IncomingMessage,
        control_buffer: []u8,
    ) void {
        @memset(control_buffer, 0);
        incoming.* = .init;
        incoming.control = control_buffer;
    }

    fn receiveKernelBytesBatchInto(
        self: *Endpoint,
        buffer: []u8,
    ) Error!ReceivedBytesBatchView {
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelInto(
            &incoming,
            &control_buffer,
            buffer,
        );
        self.recordSocketReceived(incoming);
        return self.finishKernelBytesBatchView(incoming);
    }

    fn receiveKernelBytesBatchIntoTimeout(
        self: *Endpoint,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!ReceivedBytesBatchView {
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelIntoTimeout(
            &incoming,
            &control_buffer,
            buffer,
            timeout,
        );
        self.recordSocketReceived(incoming);
        return self.finishKernelBytesBatchView(incoming);
    }

    pub fn receiveKernelBytesInto(
        self: *Endpoint,
        buffer: []u8,
    ) Error!ReceivedBytesView {
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelInto(
            &incoming,
            &control_buffer,
            buffer,
        );
        self.recordSocketReceived(incoming);
        return self.finishKernelBytesInto(incoming);
    }

    fn receiveKernelBytesIntoTimeout(
        self: *Endpoint,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!ReceivedBytesView {
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelIntoTimeout(
            &incoming,
            &control_buffer,
            buffer,
            timeout,
        );
        self.recordSocketReceived(incoming);
        return self.finishKernelBytesInto(incoming);
    }

    pub fn finishKernelBytesInto(
        self: *Endpoint,
        incoming: net.IncomingMessage,
    ) Error!ReceivedBytesView {
        if (incoming.data.len == 0) return error.EmptyDatagram;
        if (incoming.flags.trunc or incoming.flags.ctrunc) {
            return error.DatagramTooLarge;
        }
        const normalized = try self.finishSocks5Incoming(incoming);
        if (normalized.data.len == 0) return error.EmptyDatagram;
        if (normalized.data.len > self.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        const control = receiveControlFromBytes(normalized.control);
        if (control.gro_segment_size != null) {
            return error.CallerBufferReceiveWithGro;
        }
        return .{
            .from = normalized.from,
            .received_on = self,
            .bytes = normalized.data,
            .ecn = if (self.receive_ecn_enabled) control.ecn else .not_ect,
        };
    }

    fn receiveKernelBytesBatchTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytesBatch {
        const receive_capacity = self.receiveBufferCapacity();
        const buffer = try self.allocator.alloc(u8, receive_capacity);
        errdefer self.allocator.free(buffer);
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelIntoTimeout(
            &incoming,
            &control_buffer,
            buffer,
            timeout,
        );
        self.recordSocketReceived(incoming);
        return self.finishKernelBytesBatch(buffer, incoming);
    }

    fn finishKernelBytesBatch(
        self: *Endpoint,
        buffer: []u8,
        incoming: net.IncomingMessage,
    ) Error!OwnedBytesBatch {
        const view = try self.finishKernelBytesBatchView(incoming);
        if (view.storage.ptr != buffer.ptr) {
            @memmove(buffer[0..view.storage.len], view.storage);
        }
        // Most allocator implementations can shrink this allocation in place.
        // Returning receive storage directly avoids an alloc-copy-free cycle.
        const storage = try self.allocator.realloc(buffer, view.storage.len);
        return .{
            .from = view.from,
            .received_on = view.received_on,
            .storage = storage,
            .segment_size = view.segment_size,
            .segment_count = view.segment_count,
            .ecn = view.ecn,
        };
    }

    pub fn finishKernelBytesBatchView(
        self: *Endpoint,
        incoming: net.IncomingMessage,
    ) Error!ReceivedBytesBatchView {
        if (incoming.data.len == 0) return error.EmptyDatagram;
        if (incoming.flags.trunc or incoming.flags.ctrunc) {
            return error.DatagramTooLarge;
        }
        const normalized = try self.finishSocks5Incoming(incoming);
        if (normalized.data.len == 0) return error.EmptyDatagram;
        const control = receiveControlFromBytes(normalized.control);
        const ecn = if (self.receive_ecn_enabled) control.ecn else .not_ect;
        const segment_size = control.gro_segment_size orelse {
            if (normalized.data.len > self.limits.max_datagram_size) {
                return error.DatagramTooLarge;
            }
            return .{
                .from = normalized.from,
                .received_on = self,
                .storage = normalized.data,
                .segment_size = normalized.data.len,
                .segment_count = 1,
                .ecn = ecn,
            };
        };
        if (!self.gro_receive_enabled or
            segment_size == 0 or
            segment_size > self.limits.max_datagram_size or
            normalized.data.len <= segment_size)
        {
            return error.InvalidGroSegment;
        }
        const segment_count = std.math.divCeil(
            usize,
            normalized.data.len,
            segment_size,
        ) catch return error.InvalidGroSegment;
        if (segment_count < 2 or segment_count > udp_gro_max_segments) {
            return error.InvalidGroSegment;
        }
        return .{
            .from = normalized.from,
            .received_on = self,
            .storage = normalized.data,
            .segment_size = segment_size,
            .segment_count = segment_count,
            .ecn = ecn,
        };
    }

    fn finishSocks5Incoming(
        self: *Endpoint,
        incoming: net.IncomingMessage,
    ) Error!net.IncomingMessage {
        const proxy = self.socks5_udp orelse return incoming;
        if (!incoming.from.eql(&proxy.relay)) {
            return error.UnexpectedRelaySource;
        }
        const datagram = try socks5_udp.decodeDatagram(incoming.data);
        const source = switch (datagram.source) {
            .ip => |ip| if (proxy.fixed_domain) |fixed|
                if (fixed.active and ip.getPort() == fixed.port)
                    fixed.logical_peer
                else
                    ip
            else
                ip,
            .domain => |domain| if (proxy.fixed_domain) |fixed|
                if (fixed.active and domain.port == fixed.port and
                    std.ascii.eqlIgnoreCase(domain.host, fixed.host))
                    fixed.logical_peer
                else
                    return error.ProxyDomainSourceUnsupported
            else
                return error.ProxyDomainSourceUnsupported,
        };
        var normalized = incoming;
        normalized.from = source;
        normalized.data = datagram.payload;
        // Any ancillary ECN/GRO record describes the client-to-relay path, not
        // the relayed destination path, so it must not enter QUIC validation.
        normalized.control = normalized.data[0..0];
        return normalized;
    }

    fn receiveBufferCapacity(self: Endpoint) usize {
        if (self.gro_receive_enabled) return max_gro_receive_bytes;
        if (self.socks5_udp == null) return self.limits.max_datagram_size;
        return socks5FrameCapacity(self.limits.max_datagram_size);
    }

    fn validateBatchReceiveBuffer(
        self: Endpoint,
        buffer: []u8,
    ) Error!void {
        if (buffer.len == 0) return error.BufferTooShort;
        const required = self.receiveBufferCapacity();
        if (buffer.len < required) return error.BufferTooShort;
    }

    fn validateManyReceiveBuffers(
        self: Endpoint,
        buffer: []u8,
        out: []ReceivedBytesView,
    ) Error!void {
        if (self.gro_receive_enabled) {
            return error.CallerBufferReceiveWithGro;
        }
        if (out.len == 0 or out.len > max_receive_batch_messages) {
            return error.BufferTooShort;
        }
        const required = std.math.mul(
            usize,
            self.receiveBufferCapacity(),
            out.len,
        ) catch return error.BufferTooShort;
        if (buffer.len < required) return error.BufferTooShort;
    }

    fn copyPendingReceivedIntoBatch(
        self: *Endpoint,
        buffer: []u8,
    ) Error!?ReceivedBytesBatchView {
        self.pending_receive_mutex.lockUncancelable(self.io);
        defer self.pending_receive_mutex.unlock(self.io);
        if (self.pending_receive_index >= self.pending_received.items.len) {
            return null;
        }
        var pending = self.pending_received.items[self.pending_receive_index];
        if (pending.bytes.len > buffer.len) return error.BufferTooShort;
        @memcpy(buffer[0..pending.bytes.len], pending.bytes);
        const result: ReceivedBytesBatchView = .{
            .from = pending.from,
            .received_on = pending.received_on,
            .storage = buffer[0..pending.bytes.len],
            .segment_size = pending.bytes.len,
            .segment_count = 1,
            .ecn = pending.ecn,
        };
        self.pending_receive_index += 1;
        self.compactPendingReceivedIfSparse();
        pending.deinit(self.allocator);
        return result;
    }

    fn receiveKernelBytesTimeout(
        self: *Endpoint,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        const receive_capacity = self.receiveBufferCapacity();
        const buffer = try self.allocator.alloc(u8, receive_capacity);
        errdefer self.allocator.free(buffer);
        var control_buffer: [receive_control_buffer_len]u8 align(@alignOf(EcnCmsgHdr)) = undefined;
        var incoming: net.IncomingMessage = undefined;
        try self.receiveOneKernelIntoTimeout(
            &incoming,
            &control_buffer,
            buffer,
            timeout,
        );
        self.recordSocketReceived(incoming);
        if (incoming.data.len == 0) return error.EmptyDatagram;
        if (incoming.flags.trunc or incoming.flags.ctrunc) {
            return error.DatagramTooLarge;
        }
        const normalized = try self.finishSocks5Incoming(incoming);
        if (normalized.data.len == 0) return error.EmptyDatagram;
        const control = receiveControlFromBytes(normalized.control);
        if (control.gro_segment_size) |segment_size| {
            if (!self.gro_receive_enabled or
                segment_size == 0 or
                segment_size > self.limits.max_datagram_size or
                normalized.data.len < segment_size)
            {
                return error.InvalidGroSegment;
            }
            // Timed handshake reads consume one logical datagram. Queue any
            // additional GRO segments into the same FIFO used by normal reads.
            const segment_count = std.math.divCeil(
                usize,
                normalized.data.len,
                segment_size,
            ) catch return error.InvalidGroSegment;
            if (segment_count > 1) {
                const storage = try self.allocator.realloc(
                    buffer,
                    normalized.data.len,
                );
                const shared = try self.allocator.create(
                    SharedReceiveBuffer,
                );
                shared.* = .{
                    .allocator = self.allocator,
                    .storage = storage,
                    .references = .init(segment_count),
                };
                self.pending_receive_mutex.lockUncancelable(self.io);
                defer self.pending_receive_mutex.unlock(self.io);
                try self.ensurePendingReceivedCapacity(segment_count - 1);
                var index: usize = 1;
                while (index < segment_count) : (index += 1) {
                    const start = index * segment_size;
                    const end = @min(start + segment_size, storage.len);
                    self.pending_received.appendAssumeCapacity(.{
                        .from = normalized.from,
                        .received_on = self,
                        .bytes = storage[start..end],
                        .ecn = if (self.receive_ecn_enabled)
                            control.ecn
                        else
                            .not_ect,
                        .shared_buffer = shared,
                    });
                }
                return .{
                    .from = normalized.from,
                    .received_on = self,
                    .bytes = storage[0..segment_size],
                    .ecn = if (self.receive_ecn_enabled)
                        control.ecn
                    else
                        .not_ect,
                    .shared_buffer = shared,
                };
            }
        }
        if (normalized.data.len > self.limits.max_datagram_size) {
            return error.DatagramTooLarge;
        }
        if (normalized.data.ptr != buffer.ptr) {
            @memmove(buffer[0..normalized.data.len], normalized.data);
        }
        const bytes = try self.allocator.realloc(
            buffer,
            normalized.data.len,
        );
        return .{
            .from = normalized.from,
            .received_on = self,
            .bytes = bytes,
            .ecn = if (self.receive_ecn_enabled)
                control.ecn
            else
                .not_ect,
        };
    }

    fn takePendingReceived(self: *Endpoint) ?OwnedBytes {
        self.pending_receive_mutex.lockUncancelable(self.io);
        defer self.pending_receive_mutex.unlock(self.io);
        if (self.pending_receive_index >= self.pending_received.items.len) return null;

        const pending = self.pending_received.items[self.pending_receive_index];
        self.pending_receive_index += 1;
        self.compactPendingReceivedIfSparse();
        return pending;
    }

    pub fn pendingReceivedCount(self: *const Endpoint) usize {
        return self.pending_received.items.len - self.pending_receive_index;
    }

    pub fn ensurePendingReceivedCapacity(
        self: *Endpoint,
        additional_count: usize,
    ) std.mem.Allocator.Error!void {
        if (self.pending_receive_index != 0 and
            self.pending_received.items.len + additional_count >
                self.pending_received.capacity)
        {
            self.compactPendingReceived();
        }
        try self.pending_received.ensureUnusedCapacity(
            self.allocator,
            additional_count,
        );
    }

    fn compactPendingReceivedIfSparse(self: *Endpoint) void {
        if (self.pending_receive_index == 0) return;
        if (self.pending_receive_index == self.pending_received.items.len or
            self.pending_receive_index >= self.pending_received.items.len / 2)
        {
            self.compactPendingReceived();
        }
    }

    fn compactPendingReceived(self: *Endpoint) void {
        if (self.pending_receive_index == 0) return;
        const remaining = self.pendingReceivedCount();
        if (remaining != 0) {
            @memmove(
                self.pending_received.items[0..remaining],
                self.pending_received.items[self.pending_receive_index..],
            );
        }
        self.pending_received.items.len = remaining;
        self.pending_receive_index = 0;
    }

    fn enableEcnReceive(self: *Endpoint) void {
        if (!socketEcnSupported()) return;
        const enabled: u32 = 1;
        const enabled_bytes = std.mem.asBytes(&enabled);
        self.receive_ecn_enabled = switch (self.socket.address) {
            .ip4 => rawSetSockOpt(self.socket.handle, ipproto_ip, ip_recvtos, enabled_bytes),
            .ip6 => rawSetSockOpt(self.socket.handle, ipproto_ipv6, ipv6_recvtclass, enabled_bytes),
        };
    }

    fn configureSocketReceiveBuffer(self: *Endpoint) void {
        if (self.limits.socket_receive_buffer_bytes == 0) return;
        const size: u32 = std.math.cast(
            u32,
            self.limits.socket_receive_buffer_bytes,
        ) orelse std.math.maxInt(u32);
        _ = rawSetSockOpt(
            self.socket.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVBUF,
            std.mem.asBytes(&size),
        );
    }

    fn validateSocks5DatagramSize(
        self: *Endpoint,
        to: net.IpAddress,
        datagrams: []const []const u8,
    ) Error!void {
        if (self.socks5_udp == null) return;
        for (datagrams) |bytes| {
            try self.validateSocks5PayloadSize(to, bytes.len);
        }
    }

    fn validateSocks5PayloadSize(
        self: *Endpoint,
        to: net.IpAddress,
        payload_len: usize,
    ) Error!void {
        if (self.socks5_udp == null) return;
        const header_len = try socks5_udp.headerLen(
            self.socks5Destination(to),
        );
        if (payload_len > std.math.maxInt(u16) - header_len) {
            return error.DatagramTooLarge;
        }
    }

    fn socks5Destination(
        self: *Endpoint,
        to: net.IpAddress,
    ) socks5_udp.Address {
        self.socks5_route_mutex.lockUncancelable(self.io);
        defer self.socks5_route_mutex.unlock(self.io);
        if (self.socks5_udp) |proxy| {
            if (proxy.fixed_domain) |fixed| {
                if (to.eql(&fixed.logical_peer)) return .{ .domain = .{
                    .host = fixed.host,
                    .port = fixed.port,
                } };
            }
            for (proxy.domain_routes.items) |route| {
                if (to.eql(&route.logical_peer)) return .{ .domain = .{
                    .host = route.host,
                    .port = route.port,
                } };
            }
        }
        return .{ .ip = to };
    }

    fn enableGroReceive(self: *Endpoint) void {
        if (!self.limits.enable_gro_receive or !udpGroSupported()) return;
        const enabled: u32 = 1;
        self.gro_receive_enabled = rawSetSockOpt(
            self.socket.handle,
            udp_gso_level,
            udp_gro_segment,
            std.mem.asBytes(&enabled),
        );
    }

    fn applyOutgoingEcnMark(self: *Endpoint, ecn: quic.packet_space.EcnCodepoint) Error!void {
        if (self.test_force_ecn_unavailable and ecn != .not_ect) {
            return error.EcnUnavailable;
        }
        if (self.socks5_udp != null) {
            if (ecn != .not_ect) return error.EcnUnavailable;
            self.send_ecn_mark = .not_ect;
            return;
        }
        if (ecn == self.send_ecn_mark) return;
        if (!socketEcnSupported()) {
            if (ecn == .not_ect) {
                self.send_ecn_mark = .not_ect;
                return;
            }
            return error.EcnUnavailable;
        }
        const mark: u32 = ecnCodepointBits(ecn);
        const mark_bytes = std.mem.asBytes(&mark);
        const marked = switch (self.socket.address) {
            .ip4 => rawSetSockOpt(self.socket.handle, ipproto_ip, ip_tos, mark_bytes),
            .ip6 => rawSetSockOpt(self.socket.handle, ipproto_ipv6, ipv6_tclass, mark_bytes),
        };
        if (!marked) return error.EcnUnavailable;
        self.send_ecn_mark = ecn;
    }

    /// Receive the next non-Version-Negotiation-triggering datagram.
    ///
    /// Unsupported-version long headers are answered on the same UDP path and
    /// consumed; the caller receives the next datagram that should continue
    /// through normal routing/packet processing. This mirrors mature QUIC
    /// endpoint loops that perform Version Negotiation before CID routing.
    pub fn receiveBytesHandlingVersionNegotiation(self: *Endpoint, supported_versions: []const u32) Error!OwnedBytes {
        return self.receiveBytesHandlingVersionNegotiationUntil(
            supported_versions,
            null,
        ) catch |err| switch (err) {
            error.Timeout, error.ConcurrencyUnavailable => unreachable,
            else => |other| return @errorCast(other),
        };
    }

    pub fn receiveBytesHandlingVersionNegotiationWithTimeout(
        self: *Endpoint,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.receiveBytesHandlingVersionNegotiationUntil(
            supported_versions,
            timeout.toDeadline(self.io),
        );
    }

    pub fn receiveBytesHandlingVersionNegotiationWithDeadline(
        self: *Endpoint,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.receiveBytesHandlingVersionNegotiationUntil(
            supported_versions,
            .{ .deadline = try deadline_policy.usableAwake(
                self.io,
                deadline,
            ) },
        );
    }

    fn receiveBytesHandlingVersionNegotiationUntil(
        self: *Endpoint,
        supported_versions: []const u32,
        timeout: ?std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        try validateSupportedVersions(supported_versions);
        while (true) {
            var raw = if (timeout) |bounded|
                try self.receiveBytesTimeout(bounded)
            else
                try self.receiveBytes();
            errdefer raw.deinit(self.allocator);
            if (try self.sendVersionNegotiationIfUnsupported(raw.from, raw.bytes, supported_versions)) {
                raw.deinit(self.allocator);
                continue;
            }
            return raw;
        }
    }

    pub fn receiveRoutedBytes(self: *Endpoint, router: quic.connection_router.Router) Error!RoutedBytes {
        var raw = try self.receiveBytes();
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagramFrom(raw.from, raw.bytes)) orelse return error.NoConnectionRoute;
        return .{ .datagram = raw, .route = routed.route, .destination_connection_id = routed.destination_connection_id };
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiation(
        self: *Endpoint,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
    ) Error!RoutedBytes {
        var raw = try self.receiveBytesHandlingVersionNegotiation(supported_versions);
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagramFrom(raw.from, raw.bytes)) orelse return error.NoConnectionRoute;
        return .{ .datagram = raw, .route = routed.route, .destination_connection_id = routed.destination_connection_id };
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiationWithTimeout(
        self: *Endpoint,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!RoutedBytes {
        var raw = try self.receiveBytesHandlingVersionNegotiationWithTimeout(
            supported_versions,
            timeout,
        );
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagramFrom(raw.from, raw.bytes)) orelse
            return error.NoConnectionRoute;
        return .{
            .datagram = raw,
            .route = routed.route,
            .destination_connection_id = routed.destination_connection_id,
        };
    }

    pub fn receiveRoutedBytesHandlingVersionNegotiationWithDeadline(
        self: *Endpoint,
        router: quic.connection_router.Router,
        supported_versions: []const u32,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!RoutedBytes {
        var raw = try self.receiveBytesHandlingVersionNegotiationWithDeadline(
            supported_versions,
            deadline,
        );
        errdefer raw.deinit(self.allocator);
        const routed = (try router.routeDatagramFrom(raw.from, raw.bytes)) orelse
            return error.NoConnectionRoute;
        return .{
            .datagram = raw,
            .route = routed.route,
            .destination_connection_id = routed.destination_connection_id,
        };
    }

    pub fn receiveManyConcurrent(self: *Endpoint, count: usize) Error!OwnedDatagramBatch {
        var group: std.Io.Group = .init;
        const datagrams = try self.allocator.alloc(?OwnedDatagram, count);
        errdefer self.allocator.free(datagrams);
        @memset(datagrams, null);
        const errors = try self.allocator.alloc(?anyerror, count);
        errdefer self.allocator.free(errors);
        @memset(errors, null);

        for (datagrams, errors) |*datagram, *err_slot| {
            const task = ReceiveTask{
                .endpoint = self,
                .datagram = datagram,
                .err = err_slot,
            };
            group.async(self.io, ReceiveTask.run, .{task});
        }

        try group.await(self.io);
        return .{ .allocator = self.allocator, .datagrams = datagrams, .errors = errors };
    }
};

pub const EcnCmsgHdr = switch (builtin.os.tag) {
    .linux, .macos => std.c.cmsghdr,
    else => extern struct {
        len: usize,
        level: i32,
        type: i32,
    },
};

const ecn_control_buffer_len = cmsgSpace(@sizeOf(u32)) * 2;
pub const udp_gso_level: i32 = 17; // SOL_UDP on Linux.
pub const udp_gso_segment: i32 = 103; // UDP_SEGMENT from linux/udp.h.
const udp_gso_max_segments: usize = 64;
pub const udp_gso_control_len = cmsgSpace(@sizeOf(u16));
pub const udp_gro_segment: u32 = 104; // UDP_GRO from linux/udp.h.
const udp_gro_max_segments: usize = 64;
pub const receive_control_buffer_len = ecn_control_buffer_len + cmsgSpace(@sizeOf(i32));

pub const ipproto_ip: i32 = 0;
const ip_tos: u32 = switch (builtin.os.tag) {
    .linux => 1,
    .macos => 3,
    else => 0,
};
const ip_recvtos: u32 = switch (builtin.os.tag) {
    .linux => 13,
    .macos => 27,
    else => 0,
};
pub const ip_tos_cmsg_type: i32 = switch (builtin.os.tag) {
    .linux => 1,
    .macos => 27,
    else => 0,
};
const ipproto_ipv6: i32 = switch (builtin.os.tag) {
    .linux, .macos => std.posix.IPPROTO.IPV6,
    else => 0,
};
const ipv6_tclass: u32 = switch (builtin.os.tag) {
    .linux => 67,
    .macos => 36,
    else => 0,
};
const ipv6_recvtclass: u32 = switch (builtin.os.tag) {
    .linux => 66,
    .macos => 35,
    else => 0,
};

pub fn socketEcnSupported() bool {
    return switch (builtin.os.tag) {
        .linux, .macos => true,
        else => false,
    };
}

/// Per-message ECN control. Carrying the codepoint as an ancillary message
/// avoids a socket-wide `setsockopt` every time bidirectional QUIC traffic
/// switches between data packets (ECT(0)) and ACK-only packets (Not-ECT).
/// Linux-only: other targets keep the socket-wide fallback.
const ecn_send_control_len = cmsgSpace(@sizeOf(u32));

fn encodeEcnControl(
    storage: *[ecn_send_control_len]u8,
    ipv6: bool,
    ecn: quic.packet_space.EcnCodepoint,
) []const u8 {
    @memset(storage, 0);
    const header: *EcnCmsgHdr = @ptrCast(@alignCast(storage));
    header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(u32),
        .level = if (ipv6) ipproto_ipv6 else ipproto_ip,
        .type = if (ipv6) @intCast(ipv6_tclass) else ip_tos_cmsg_type,
    };
    const value: u32 = ecnCodepointBits(ecn);
    @memcpy(
        storage[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u32)],
        std.mem.asBytes(&value),
    );
    return storage;
}

pub const testing = struct {
    pub fn forceEcnUnavailable(endpoint: *Endpoint, enabled: bool) void {
        endpoint.test_force_ecn_unavailable = enabled;
    }
};

pub fn udpGsoSupported() bool {
    return builtin.os.tag == .linux;
}

pub fn udpGroSupported() bool {
    return builtin.os.tag == .linux;
}

const GsoPlan = struct {
    data_ptr: [*]const u8,
    total_len: usize,
    segment_size: u16,
    segment_count: usize,
};

/// Return a zero-copy GSO plan only when the caller's datagrams already have
/// the exact memory layout required by UDP_SEGMENT: contiguous equal-sized
/// segments, with only the final segment allowed to be shorter.
pub fn gsoPlan(datagrams: []const []const u8) ?GsoPlan {
    if (!udpGsoSupported() or datagrams.len < 2 or datagrams.len > udp_gso_max_segments) return null;
    const segment_size = std.math.cast(u16, datagrams[0].len) orelse return null;
    if (segment_size == 0) return null;

    var total_len = datagrams[0].len;
    var previous = datagrams[0];
    for (datagrams[1..], 1..) |bytes, index| {
        if (@intFromPtr(bytes.ptr) != @intFromPtr(previous.ptr) + previous.len) return null;
        const is_last = index == datagrams.len - 1;
        if ((!is_last and bytes.len != segment_size) or (is_last and bytes.len > segment_size)) return null;
        total_len = std.math.add(usize, total_len, bytes.len) catch return null;
        previous = bytes;
    }
    // Linux stores the UDP super-packet length in a 16-bit field. This bound
    // also matches mature s2n-quic's GSO aggregation limit.
    if (total_len > std.math.maxInt(u16)) return null;
    return .{
        .data_ptr = datagrams[0].ptr,
        .total_len = total_len,
        .segment_size = segment_size,
        .segment_count = datagrams.len,
    };
}

pub fn encodeUdpGsoControl(storage: *[udp_gso_control_len]u8, segment_size: u16) []const u8 {
    @memset(storage, 0);
    const header: *EcnCmsgHdr = @ptrCast(@alignCast(storage));
    header.* = .{
        .len = @sizeOf(EcnCmsgHdr) + @sizeOf(u16),
        .level = udp_gso_level,
        .type = udp_gso_segment,
    };
    @memcpy(
        storage[@sizeOf(EcnCmsgHdr)..][0..@sizeOf(u16)],
        std.mem.asBytes(&segment_size),
    );
    return storage;
}

fn endpointSocketSendError(err: Error) ?net.Socket.SendError {
    return switch (err) {
        error.MessageOversize => error.MessageOversize,
        error.SystemResources => error.SystemResources,
        error.NetworkUnreachable => error.NetworkUnreachable,
        error.HostUnreachable => error.HostUnreachable,
        error.NetworkDown => error.NetworkDown,
        error.ConnectionRefused => error.ConnectionRefused,
        error.AddressFamilyUnsupported => error.AddressFamilyUnsupported,
        error.FastOpenAlreadyInProgress => error.FastOpenAlreadyInProgress,
        error.ConnectionResetByPeer => error.ConnectionResetByPeer,
        error.SocketUnconnected => error.SocketUnconnected,
        error.AccessDenied => error.AccessDenied,
        error.Canceled => error.Canceled,
        error.Unexpected => error.Unexpected,
        else => null,
    };
}

fn gsoFallbackError(err: net.Socket.SendError) bool {
    // Linux uses EIO for a rejected UDP_SEGMENT operation. Zig's portable
    // socket error set has no EIO case, so std.Io normalizes it to Unexpected.
    return err == error.Unexpected;
}

fn rawSetSockOpt(fd: std.posix.socket_t, level: i32, optname: u32, opt: []const u8) bool {
    if (comptime builtin.os.tag == .windows) {
        // std.Io's Windows socket handle is an AFD handle, not a Winsock
        // SOCKET. Optional POSIX socket tuning therefore remains disabled on
        // this backend instead of calling std.posix.setsockopt.
        return unsupportedRawSetSockOpt(fd, level, optname, opt);
    }
    std.posix.setsockopt(fd, level, optname, opt) catch return false;
    return true;
}

fn unsupportedRawSetSockOpt(fd: std.posix.socket_t, level: i32, optname: u32, opt: []const u8) bool {
    _ = fd;
    _ = level;
    _ = optname;
    _ = opt;
    return false;
}

pub fn ecnCodepointBits(ecn: quic.packet_space.EcnCodepoint) u32 {
    return switch (ecn) {
        .not_ect => 0b00,
        .ect0 => 0b10,
        .ect1 => 0b01,
        .ce => 0b11,
    };
}

fn ecnFromBits(bits: u2) quic.packet_space.EcnCodepoint {
    return switch (bits) {
        0b00 => .not_ect,
        0b10 => .ect0,
        0b01 => .ect1,
        0b11 => .ce,
    };
}

pub fn cmsgSpace(data_len: usize) usize {
    return std.mem.alignForward(usize, @sizeOf(EcnCmsgHdr) + data_len, @alignOf(EcnCmsgHdr));
}

fn ecnFromControl(control: []const u8) quic.packet_space.EcnCodepoint {
    return receiveControlFromBytes(control).ecn;
}

const ReceiveControl = struct {
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    gro_segment_size: ?usize = null,
};

pub fn receiveControlFromBytes(control: []const u8) ReceiveControl {
    var result: ReceiveControl = .{};
    if (!socketEcnSupported() and !udpGroSupported()) return result;
    var offset: usize = 0;
    while (offset + @sizeOf(EcnCmsgHdr) <= control.len) {
        const header: *const EcnCmsgHdr = @ptrCast(@alignCast(control[offset..].ptr));
        const cmsg_len: usize = @intCast(header.len);
        if (cmsg_len < @sizeOf(EcnCmsgHdr) or offset + cmsg_len > control.len) break;
        const data = control[offset + @sizeOf(EcnCmsgHdr) .. offset + cmsg_len];
        const ipv4_tos = header.level == ipproto_ip and header.type == ip_tos_cmsg_type;
        const ipv6_tclass_cmsg = header.level == ipproto_ipv6 and header.type == @as(i32, @intCast(ipv6_tclass));
        if ((ipv4_tos or ipv6_tclass_cmsg) and data.len != 0) {
            result.ecn = ecnFromBits(@truncate(data[0] & 0x03));
        } else if (header.level == udp_gso_level and
            header.type == @as(i32, @intCast(udp_gro_segment)) and
            data.len >= @sizeOf(i32))
        {
            const segment_size = std.mem.bytesToValue(i32, data[0..@sizeOf(i32)]);
            if (segment_size > 0) result.gro_segment_size = @intCast(segment_size);
        }
        offset += cmsgSpace(cmsg_len - @sizeOf(EcnCmsgHdr));
    }
    return result;
}

const LongHeaderConnectionIds = struct {
    version: u32,
    destination_connection_id: []const u8,
    source_connection_id: []const u8,
};

fn validateSupportedVersions(supported_versions: []const u32) Error!void {
    if (supported_versions.len == 0) return error.InvalidVersionNegotiation;
    var has_real_version = false;
    for (supported_versions) |version| {
        if (version == quic.Version.negotiation.wireValue()) return error.InvalidVersionNegotiation;
        if (!quic.isReservedVersionWire(version)) has_real_version = true;
    }
    if (!has_real_version) return error.InvalidVersionNegotiation;
}

fn versionListContains(supported_versions: []const u32, version: u32) bool {
    if (quic.isReservedVersionWire(version)) return false;
    for (supported_versions) |supported| {
        if (quic.isReservedVersionWire(supported)) continue;
        if (supported == version) return true;
    }
    return false;
}

fn versionNegotiationFirstByte(io: std.Io) std.Io.RandomSecureError!u8 {
    // RFC 9000 leaves the Version Negotiation first byte's lower bits unused.
    // Mature stacks randomize them (while forcing Header Form=1) so endpoints do
    // not ossify on one fixed long-header/type-specific pattern.
    var byte: [1]u8 = undefined;
    try std.Io.randomSecure(io, &byte);
    return byte[0] | 0x80;
}

pub fn peekUnsupportedVersionConnectionIds(datagram: []const u8, supported_versions: []const u32) ?LongHeaderConnectionIds {
    if (datagram.len < 5) return null;
    const first_byte = datagram[0];
    if ((first_byte & 0x80) == 0) return null;
    // Valid QUIC packets have the fixed bit set. Dropping fixed-bit-clear
    // datagrams also avoids replying to random non-QUIC UDP traffic.
    if ((first_byte & 0x40) == 0) return null;

    const version = std.mem.readInt(u32, datagram[1..5], .big);
    if (version == quic.Version.negotiation.wireValue()) return null;
    if (versionListContains(supported_versions, version)) return null;

    if (datagram.len < 6) return null;
    const dcid_len = datagram[5];
    if (dcid_len > 20) return null;
    const dcid_start: usize = 6;
    const dcid_end = dcid_start + @as(usize, dcid_len);
    if (datagram.len < dcid_end + 1) return null;

    const scid_len = datagram[dcid_end];
    if (scid_len > 20) return null;
    const scid_start = dcid_end + 1;
    const scid_end = scid_start + @as(usize, scid_len);
    if (datagram.len < scid_end) return null;

    return .{
        .version = version,
        .destination_connection_id = datagram[dcid_start..dcid_end],
        .source_connection_id = datagram[scid_start..scid_end],
    };
}

const ReceiveTask = struct {
    endpoint: *Endpoint,
    datagram: *?OwnedDatagram,
    err: *?anyerror,

    fn run(task: ReceiveTask) std.Io.Cancelable!void {
        task.datagram.* = task.endpoint.receive() catch |err| {
            task.err.* = err;
            return;
        };
        task.err.* = null;
    }
};

const SharedReceiveBuffer = struct {
    allocator: std.mem.Allocator,
    storage: []u8,
    references: std.atomic.Value(usize),

    fn release(self: *SharedReceiveBuffer) void {
        // Each GRO segment owns one reference. The acquire pairs with releases
        // from other threads so the final owner can safely free both objects.
        if (self.references.fetchSub(1, .release) != 1) return;
        _ = self.references.load(.acquire);
        const allocator = self.allocator;
        allocator.free(self.storage);
        allocator.destroy(self);
    }
};

pub const OwnedBytesBatch = struct {
    from: net.IpAddress,
    /// UDP endpoint that received this batch. Null is reserved for manually
    /// constructed/test datagrams that have no socket provenance.
    received_on: ?*Endpoint = null,
    storage: []u8,
    segment_size: usize,
    segment_count: usize,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    shared_buffer: ?*SharedReceiveBuffer = null,
    owns_storage: bool = true,

    pub fn datagramAt(self: OwnedBytesBatch, index: usize) ?[]const u8 {
        if (index >= self.segment_count) return null;
        return self.datagramAtUnchecked(index);
    }

    pub fn datagramAtMutable(self: *OwnedBytesBatch, index: usize) ?[]u8 {
        if (index >= self.segment_count) return null;
        return self.datagramAtUnchecked(index);
    }

    fn datagramAtUnchecked(self: OwnedBytesBatch, index: usize) []u8 {
        const start = index * self.segment_size;
        const end = @min(start + self.segment_size, self.storage.len);
        return self.storage[start..end];
    }

    fn disown(self: *OwnedBytesBatch) void {
        self.owns_storage = false;
    }

    pub fn deinit(self: *OwnedBytesBatch, allocator: std.mem.Allocator) void {
        if (self.owns_storage) {
            if (self.shared_buffer) |shared| {
                shared.release();
            } else {
                allocator.free(self.storage);
            }
        }
        self.* = undefined;
    }
};

pub const ReceivedBytesBatchView = struct {
    from: net.IpAddress,
    received_on: ?*Endpoint = null,
    storage: []u8,
    segment_size: usize,
    segment_count: usize,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,

    pub fn datagramAt(self: ReceivedBytesBatchView, index: usize) ?[]const u8 {
        if (index >= self.segment_count) return null;
        return self.datagramAtUnchecked(index);
    }

    pub fn datagramAtMutable(
        self: *ReceivedBytesBatchView,
        index: usize,
    ) ?[]u8 {
        if (index >= self.segment_count) return null;
        return self.datagramAtUnchecked(index);
    }

    fn datagramAtUnchecked(self: ReceivedBytesBatchView, index: usize) []u8 {
        const start = index * self.segment_size;
        const end = @min(start + self.segment_size, self.storage.len);
        return self.storage[start..end];
    }
};

pub const OwnedBytes = struct {
    from: net.IpAddress,
    /// Preserve the local half of the UDP four-tuple across CID routing.
    /// Multi-endpoint QUIC owners use this to answer path validation from the
    /// exact address that received the challenge.
    received_on: ?*Endpoint = null,
    bytes: []u8,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    shared_buffer: ?*SharedReceiveBuffer = null,
    /// Optional release hook for bytes that borrow caller-managed storage.
    /// Owned endpoint and inbox datagrams leave this null and retain their
    /// existing allocator/shared-buffer destruction path.
    borrowed_release: ?BorrowedBytesRelease = null,

    pub fn deinit(self: *OwnedBytes, allocator: std.mem.Allocator) void {
        if (self.borrowed_release) |release| {
            std.debug.assert(self.shared_buffer == null);
            release.release_fn(release.context);
        } else if (self.shared_buffer) |shared| {
            shared.release();
        } else {
            allocator.free(self.bytes);
        }
        self.* = undefined;
    }
};

pub const BorrowedBytesRelease = struct {
    context: *anyopaque,
    release_fn: *const fn (context: *anyopaque) void,
};

/// Type-erased source for lifetime-managed QUIC datagrams.
///
/// Handshake state machines use this instead of assuming they own the UDP
/// socket. The ordinary endpoint adapter additionally exposes an optional
/// caller-buffer receive path, while a multi-connection endpoint can supply a
/// CID-routed per-handshake inbox with the original owning contract.
pub const DatagramSource = struct {
    context: *anyopaque,
    receive_timeout_fn: *const fn (
        context: *anyopaque,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes,
    /// Optional direct receive path used by short-lived state machines that
    /// can keep caller storage alive until `OwnedBytes.deinit`. Sources backed
    /// by queues retain ownership and leave this unset.
    receive_into_timeout_fn: ?*const fn (
        context: *anyopaque,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!ReceivedBytesView = null,
    receive_into_capacity: usize = 0,

    pub fn fromEndpoint(endpoint: *Endpoint) DatagramSource {
        return .{
            .context = endpoint,
            .receive_timeout_fn = endpointReceiveTimeout,
            .receive_into_timeout_fn = if (endpoint.gro_receive_enabled)
                null
            else
                endpointReceiveIntoTimeout,
            .receive_into_capacity = if (endpoint.gro_receive_enabled)
                0
            else
                endpoint.receiveBufferCapacity(),
        };
    }

    pub fn receive(self: DatagramSource) ReceiveTimeoutError!OwnedBytes {
        return self.receiveTimeout(.none);
    }

    pub fn receiveTimeout(
        self: DatagramSource,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.receive_timeout_fn(self.context, timeout);
    }

    pub fn receiveIntoTimeout(
        self: DatagramSource,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!?ReceivedBytesView {
        const receive_fn = self.receive_into_timeout_fn orelse return null;
        if (buffer.len < self.receive_into_capacity) {
            return error.BufferTooShort;
        }
        return try receive_fn(self.context, buffer, timeout);
    }

    pub fn receiveIntoCapacity(self: DatagramSource) usize {
        if (self.receive_into_timeout_fn == null) return 0;
        return self.receive_into_capacity;
    }

    pub fn receiveWithTimeout(
        self: DatagramSource,
        timeout: std.Io.Duration,
    ) ReceiveTimeoutError!OwnedBytes {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveTimeout(.{ .duration = .{
            .clock = .awake,
            .raw = timeout,
        } });
    }

    /// Preserve a caller-owned absolute budget through either an endpoint or
    /// a routed handshake inbox. Sources themselves remain type-erased, so
    /// clock validation belongs to the concrete implementation.
    pub fn receiveWithDeadline(
        self: DatagramSource,
        deadline: std.Io.Clock.Timestamp,
    ) ReceiveTimeoutError!OwnedBytes {
        return self.receiveTimeout(.{ .deadline = deadline });
    }

    fn endpointReceiveTimeout(
        context: *anyopaque,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!OwnedBytes {
        const endpoint: *Endpoint = @ptrCast(@alignCast(context));
        return endpoint.receiveBytesTimeout(switch (timeout) {
            .deadline => |deadline| .{ .deadline = try deadline_policy.usableAwake(endpoint.io, deadline) },
            else => timeout,
        });
    }

    fn endpointReceiveIntoTimeout(
        context: *anyopaque,
        buffer: []u8,
        timeout: std.Io.Timeout,
    ) ReceiveTimeoutError!ReceivedBytesView {
        const endpoint: *Endpoint = @ptrCast(@alignCast(context));
        return endpoint.receiveBytesIntoTimeout(buffer, switch (timeout) {
            .deadline => |deadline| .{
                .deadline = try deadline_policy.usableAwake(
                    endpoint.io,
                    deadline,
                ),
            },
            else => timeout,
        });
    }
};

pub const ReceivedBytesView = struct {
    from: net.IpAddress,
    received_on: ?*Endpoint = null,
    bytes: []u8,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
};

fn ownedBytesAsBatch(bytes: OwnedBytes) OwnedBytesBatch {
    return .{
        .from = bytes.from,
        .received_on = bytes.received_on,
        .storage = bytes.bytes,
        .segment_size = bytes.bytes.len,
        .segment_count = 1,
        .ecn = bytes.ecn,
        .shared_buffer = bytes.shared_buffer,
    };
}

pub const RoutedBytes = struct {
    datagram: OwnedBytes,
    route: quic.connection_router.Route,
    destination_connection_id: []const u8,

    pub fn deinit(self: *RoutedBytes, allocator: std.mem.Allocator) void {
        self.datagram.deinit(allocator);
        self.* = undefined;
    }
};

/// Borrowed counterpart to `RoutedBytes` for single-owner event loops that
/// receive into reusable caller storage. The destination CID points into the
/// same mutable datagram and remains valid only until that storage is reused.
pub const RoutedBytesView = struct {
    datagram: ReceivedBytesView,
    route: quic.connection_router.Route,
    destination_connection_id: []const u8,
};

pub const OwnedDatagram = struct {
    from: net.IpAddress,
    bytes: []u8,
    ecn: quic.packet_space.EcnCodepoint = .not_ect,
    frames: []quic.Frame,
    shared_buffer: ?*SharedReceiveBuffer = null,

    pub fn deinit(self: *OwnedDatagram, allocator: std.mem.Allocator) void {
        quic.deinitOwnedFrameSlice(self.frames, allocator);
        allocator.free(self.frames);
        if (self.shared_buffer) |shared| {
            shared.release();
        } else {
            allocator.free(self.bytes);
        }
        self.* = undefined;
    }
};

pub const OwnedDatagramBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?OwnedDatagram,
    errors: []?anyerror,

    pub fn deinit(self: *OwnedDatagramBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: OwnedDatagramBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: OwnedDatagramBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            if (datagram != null) count += 1;
        }
        return count;
    }
};

pub fn emptyIncomingFlags() net.IncomingMessage.Flags {
    return .{
        .eor = false,
        .trunc = false,
        .ctrunc = false,
        .oob = false,
        .errqueue = false,
    };
}

pub const RejectFirstGsoSend = struct {
    delegate: std.Io,
    calls: usize = 0,
    gso_calls: usize = 0,
    fallback_calls: usize = 0,

    pub fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *RejectFirstGsoSend = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        if (messages.len == 1 and messages[0].control.len != 0) {
            self.gso_calls += 1;
            return .{ error.Unexpected, 0 };
        }
        self.fallback_calls += 1;
        return self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages,
            flags,
        );
    }
};

pub const AcceptFirstBatchDatagram = struct {
    delegate: std.Io,
    calls: usize = 0,

    pub fn netSend(
        userdata: ?*anyopaque,
        socket_handle: net.Socket.Handle,
        messages: []net.OutgoingMessage,
        flags: net.SendFlags,
    ) struct { ?net.Socket.SendError, usize } {
        const self: *AcceptFirstBatchDatagram = @ptrCast(@alignCast(userdata));
        self.calls += 1;
        const send_error, const sent_count = self.delegate.vtable.netSend(
            self.delegate.userdata,
            socket_handle,
            messages[0..@min(messages.len, 1)],
            flags,
        );
        if (send_error != null or sent_count != 1) {
            return .{ send_error orelse error.Unexpected, sent_count };
        }
        return .{ error.NetworkDown, 1 };
    }
};

pub const RejectMessageOversizeReceives = struct {
    delegate: std.Io,
    remaining_failures: usize = 0,
    receive_calls: usize = 0,

    pub fn arm(self: *@This(), failures: usize) void {
        self.remaining_failures = failures;
        self.receive_calls = 0;
    }

    pub fn operate(
        userdata: ?*anyopaque,
        operation: std.Io.Operation,
    ) std.Io.Cancelable!std.Io.Operation.Result {
        const self: *@This() = @ptrCast(@alignCast(userdata.?));
        if (std.meta.activeTag(operation) == .net_receive) {
            self.receive_calls += 1;
            if (self.remaining_failures != 0) {
                self.remaining_failures -= 1;
                return .{ .net_receive = .{ error.MessageOversize, 0 } };
            }
        }
        return self.delegate.vtable.operate(
            self.delegate.userdata,
            operation,
        );
    }
};

test {
    _ = @import("runtime/tests.zig");
    _ = @import("runtime/network_interface_tests.zig");
}

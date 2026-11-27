//! Hysteria v3 QUIC server: control hello, TCP data streams, and UDP datagrams.
//!
//! The implementation follows the Hysteria protocol specification: a client
//! hello on a bidirectional control stream, one data stream per relay request,
//! TCP relay on that stream, and UDP relay over QUIC datagrams.

const std = @import("std");
const netz = @import("../netz.zig");

const protocol = @import("v3_protocol.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const io_helpers = @import("../internal/io.zig");
const byte_bucket = @import("../internal/byte_bucket.zig");
const rate_stream = @import("../internal/byte_bucket/stream.zig");
const udp_address = @import("../internal/udp_session/address.zig");

const quic = netz.quic;
const net = std.Io.net;

pub const Config = @import("config.zig").Config;

pub const Error = error{
    RateLimited,
    AuthenticationFailed,
    AuthTimeout,
    InvalidRequest,
    ConnectionClosed,
    ConnectionLimitExceeded,
};

pub const Server = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    endpoint: quic.runtime.Endpoint,
    limiter: limits.ConnectionLimiter,
    running: std.atomic.Value(bool) = .init(true),
    active_jobs: std.atomic.Value(usize) = .init(0),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        bind_address: net.IpAddress,
        config: Config,
    ) !Server {
        if (config.password.len == 0) return error.AuthenticationFailed;
        var endpoint = try quic.runtime.Endpoint.bind(
            allocator,
            io,
            bind_address,
            .{ .max_datagram_size = config.max_datagram_size },
        );
        errdefer endpoint.deinit();
        var limiter = try limits.ConnectionLimiter.init(
            allocator,
            io,
            config.limits,
        );
        errdefer limiter.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .config = config,
            .endpoint = endpoint,
            .limiter = limiter,
        };
    }

    pub fn deinit(self: *Server) void {
        self.running.store(false, .release);
        while (self.active_jobs.load(.acquire) != 0) {
            std.Io.sleep(self.io, .fromMilliseconds(1), .awake) catch {};
        }
        self.limiter.deinit();
        self.endpoint.deinit();
        self.* = undefined;
    }

    pub fn requestStop(self: *Server) void {
        self.running.store(false, .release);
    }

    pub fn address(self: *const Server) net.IpAddress {
        return self.endpoint.address();
    }

    /// Serve concurrent connections through the shared endpoint owner.
    pub fn serve(self: *Server) !void {
        return @import("shared/server.zig").serve(self);
    }
};

const Relay = struct {
    state: *State,
    tcp: net.Stream,
    stream_id: u64,
    send_offset: u64 = 0,
    quic_done: bool = false,
    tcp_done: bool = false,
    closed: bool = false,
};

const Assoc = struct {
    state: *State,
    id: u32,
    stream_id: u64,
    socket: net.Socket,
    next_msg_id: u16 = 0,
    last_activity: i64,
    closed: bool = false,
};

const Pending = struct {
    stream_id: u64 = 0,
    buffer: [512]u8 = undefined,
    used: usize = 0,
    active: bool = false,
};

const max_fragments: u8 = 16;
const max_fragment_entries: usize = 64;
const fragment_idle_ns: i64 = 5 * std.time.ns_per_s;

const Fragment = struct {
    active: bool = false,
    session_id: u32 = 0,
    msg_id: u16 = 0,
    frag_count: u8 = 0,
    received: u16 = 0,
    total: usize = 0,
    parts: [max_fragments]?[]u8 = @splat(null),
    last_activity: i64 = 0,

    fn deinit(self: *Fragment, allocator: std.mem.Allocator) void {
        for (&self.parts) |*part| {
            if (part.*) |bytes| allocator.free(bytes);
            part.* = null;
        }
        self.* = .{};
    }
};

const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    established: *quic.handshake.EstablishedConnection,
    config: Config,
    relays: std.ArrayList(*Relay) = .empty,
    assocs: std.ArrayList(*Assoc) = .empty,
    pending: [8]Pending = @splat(.{}),
    fragments: [max_fragment_entries]Fragment = @splat(.{}),
    control_stream: u64 = 0,
    next_session_id: u32 = 1,
    send_bucket: byte_bucket.ByteBucket,
    recv_bucket: byte_bucket.ByteBucket,
    last_activity: i64,
    running: bool = true,
};

pub fn processEstablished(
    allocator: std.mem.Allocator,
    io: std.Io,
    established: *quic.handshake.EstablishedConnection,
    config: Config,
    limiter: ?*limits.ConnectionLimiter,
) !void {
    const peer = established.connection.config.peer;
    if (config.rate_limiter) |value| {
        const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
        if (!value.allow(peer, 1, now)) return error.RateLimited;
    }
    if (limiter) |value| try value.acquire(peer);
    defer if (limiter) |value| value.release(peer);
    if (config.stats) |value| value.connectionOpened();
    defer if (config.stats) |value| value.connectionClosed();

    var state = State{
        .allocator = allocator,
        .io = io,
        .established = established,
        .config = config,
        .send_bucket = byte_bucket.ByteBucket.initWithBurst(
            config.send_bps,
            config.rate_burst_bytes,
            @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds),
        ),
        .recv_bucket = byte_bucket.ByteBucket.initWithBurst(
            config.recv_bps,
            config.rate_burst_bytes,
            @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds),
        ),
        .last_activity = @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds),
    };
    defer {
        state.running = false;
        shutdownAllAssocs(&state);
        shutdownAllRelays(&state);
        for (&state.fragments) |*fragment| fragment.deinit(allocator);
        state.assocs.deinit(allocator);
        state.relays.deinit(allocator);
    }

    authenticate(&state) catch |err| switch (err) {
        error.ConnectionClosed, error.Canceled => return,
        else => return err,
    };
    relayLoop(&state) catch |err| switch (err) {
        error.ConnectionClosed, error.Canceled => {},
        else => return err,
    };
}

fn authenticate(state: *State) !void {
    const deadline = std.Io.Timestamp.now(state.io, .awake).nanoseconds +
        state.config.auth_timeout.nanoseconds;
    var storage: [512]u8 = undefined;
    var used: usize = 0;
    var control_stream: ?u64 = null;
    var buffer: [4096]u8 = undefined;
    while (true) {
        const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
        if (now >= deadline) return error.AuthTimeout;
        const event = state.established.connection.receiveStreamWithTimeout(
            &buffer,
            .fromMilliseconds(10),
        ) catch |err| switch (err) {
            error.Timeout => continue,
            else => return err,
        };
        switch (event) {
            .data => |data| {
                if (protocol_isUni(data.stream_id)) continue;
                if (control_stream == null) control_stream = data.stream_id;
                if (data.stream_id != control_stream.?) continue;
                if (used + data.bytes > storage.len) return error.InvalidRequest;
                @memcpy(storage[used..][0..data.bytes], buffer[0..data.bytes]);
                used += data.bytes;
                const hello = protocol.parseClientHello(storage[0..used]) catch |err| switch (err) {
                    error.Incomplete => continue,
                    else => return error.AuthenticationFailed,
                };
                if (!authMatches(hello.auth, state.config.password)) {
                    if (state.config.stats) |value| value.authFailure();
                    return error.AuthenticationFailed;
                }
                const send_bps = negotiateRate(
                    state.config.send_bps,
                    hello.recv_bps,
                );
                const recv_bps = negotiateRate(
                    state.config.recv_bps,
                    hello.send_bps,
                );
                const now_ns: i64 = @intCast(
                    std.Io.Timestamp.now(state.io, .awake).nanoseconds,
                );
                state.send_bucket = byte_bucket.ByteBucket.initWithBurst(send_bps, state.config.rate_burst_bytes, now_ns);
                state.recv_bucket = byte_bucket.ByteBucket.initWithBurst(recv_bps, state.config.rate_burst_bytes, now_ns);
                const response = try protocol.buildServerHello(
                    state.allocator,
                    true,
                    send_bps,
                    recv_bps,
                    "",
                );
                defer state.allocator.free(response);
                _ = try sendStreamData(
                    state,
                    control_stream.?,
                    0,
                    response,
                    false,
                );
                state.control_stream = control_stream.?;
                return;
            },
            .reset => return error.ConnectionClosed,
        }
    }
}

fn protocol_isUni(stream_id: u64) bool {
    return (stream_id & 0x2) != 0;
}

pub fn negotiateRate(server_rate: u64, client_rate: u64) u64 {
    if (server_rate == 0) return client_rate;
    if (client_rate == 0) return server_rate;
    return @min(server_rate, client_rate);
}

fn authMatches(actual: []const u8, expected: []const u8) bool {
    var difference: usize = if (actual.len == expected.len) 0 else 1;
    const limit = @min(actual.len, expected.len);
    for (0..limit) |index| {
        difference |= actual[index] ^ expected[index];
    }
    return difference == 0;
}

fn relayLoop(state: *State) !void {
    var buffer: [4096]u8 = undefined;
    while (state.running) {
        const event = state.established.connection.receiveStreamWithTimeout(
            &buffer,
            .fromMilliseconds(10),
        ) catch |err| switch (err) {
            error.Timeout => {
                drainDatagrams(state, &buffer) catch {};
                drainRelayReads(state) catch {};
                drainAssocReads(state) catch {};
                cleanupRelays(state);
                cleanupAssocs(state);
                cleanupFragments(state);
                const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
                if (now - state.last_activity >= state.config.idle_timeout.nanoseconds) {
                    break;
                }
                continue;
            },
            else => return err,
        };
        state.last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds);
        switch (event) {
            .data => |data| {
                if (data.stream_id == state.control_stream) continue;
                if (protocol_isUni(data.stream_id)) continue;
                try handleDataStream(
                    state,
                    data.stream_id,
                    buffer[0..data.bytes],
                    data.fin,
                );
            },
            .reset => |reset| {
                closeRelayStream(state, reset.stream_id);
                closeAssocForStream(state, reset.stream_id);
            },
        }
        drainDatagrams(state, &buffer) catch {};
        drainRelayReads(state) catch {};
        drainAssocReads(state) catch {};
        cleanupRelays(state);
        cleanupAssocs(state);
        cleanupFragments(state);
    }
}

fn handleDataStream(
    state: *State,
    stream_id: u64,
    data: []const u8,
    fin: bool,
) !void {
    if (findAssocByStream(state, stream_id)) |assoc| {
        if (fin) closeAssoc(state, assoc.id);
        return;
    }
    if (findRelay(state, stream_id)) |relay| {
        if (data.len > 0) {
            try writeRateLimited(state, relay.tcp, data);
        }
        if (fin) {
            relay.tcp.shutdown(state.io, .send) catch {};
            relay.quic_done = true;
        }
        return;
    }

    const pending = pendingFor(state, stream_id) orelse return error.InvalidRequest;
    if (pending.used + data.len > pending.buffer.len) {
        pending.active = false;
        pending.used = 0;
        return error.InvalidRequest;
    }
    @memcpy(pending.buffer[pending.used..][0..data.len], data);
    pending.used += data.len;

    const request = protocol.parseRequest(
        pending.buffer[0..pending.used],
    ) catch |err| switch (err) {
        error.Incomplete => {
            if (fin) {
                pending.active = false;
                pending.used = 0;
            }
            return;
        },
        else => {
            pending.active = false;
            pending.used = 0;
            return error.InvalidRequest;
        },
    };
    const request_end = 3 + request.host.len + 2;
    const target: destination.Target = parseTarget(request.host, request.port) orelse {
        pending.active = false;
        pending.used = 0;
        return error.InvalidRequest;
    };

    if (request.request_type == .tcp) {
        if (state.relays.items.len >= state.config.max_relays) {
            pending.active = false;
            pending.used = 0;
            try sendFailure(state, stream_id);
            return;
        }
        const tcp = destination.connectTarget(
            state.allocator,
            state.io,
            reload.policyFor(state.config.acl, state.config.policy_store),
            target,
            .connect,
            state.config.connect_timeout,
        ) catch {
            pending.active = false;
            pending.used = 0;
            try sendFailure(state, stream_id);
            return;
        };
        errdefer tcp.close(state.io);
        const response = try protocol.buildResponse(
            state.allocator,
            true,
            0,
            "",
        );
        defer state.allocator.free(response);
        _ = try sendStreamData(state, stream_id, 0, response, false);

        const relay = try state.allocator.create(Relay);
        relay.* = .{
            .state = state,
            .tcp = tcp,
            .stream_id = stream_id,
            .send_offset = response.len,
        };
        try state.relays.append(state.allocator, relay);
        const pending_used = pending.used;
        pending.active = false;
        pending.used = 0;
        if (request_end < pending_used) {
            const initial = pending.buffer[request_end..pending_used];
            try writeRateLimited(state, tcp, initial);
        }
        if (fin) {
            tcp.shutdown(state.io, .send) catch {};
            relay.quic_done = true;
        }
        return;
    }

    if (state.assocs.items.len >= state.config.max_assocs) {
        pending.active = false;
        pending.used = 0;
        try sendFailure(state, stream_id);
        return;
    }
    const socket = try (net.IpAddress{ .ip4 = .unspecified(0) }).bind(
        state.io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    errdefer socket.close(state.io);
    const session_id = state.next_session_id;
    state.next_session_id +%= 1;
    if (state.next_session_id == 0) state.next_session_id = 1;

    const assoc = try state.allocator.create(Assoc);
    assoc.* = .{
        .state = state,
        .id = session_id,
        .stream_id = stream_id,
        .socket = socket,
        .last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
    };
    try state.assocs.append(state.allocator, assoc);
    pending.active = false;
    pending.used = 0;

    const response = try protocol.buildResponse(
        state.allocator,
        true,
        session_id,
        "",
    );
    defer state.allocator.free(response);
    _ = try sendStreamData(state, stream_id, 0, response, false);
    if (fin) closeAssoc(state, session_id);
}

fn parseTarget(host: []const u8, port: u16) ?destination.Target {
    if (net.IpAddress.parse(host, port)) |ip| {
        return .{ .ip = ip };
    } else |_| {}
    _ = net.HostName.init(host) catch return null;
    return .{ .domain = .{ .host = host, .port = port } };
}

fn sendFailure(state: *State, stream_id: u64) !void {
    const response = try protocol.buildResponse(
        state.allocator,
        false,
        0,
        "connect failed",
    );
    defer state.allocator.free(response);
    _ = sendStreamData(state, stream_id, 0, response, true) catch {};
}

fn drainDatagrams(state: *State, buffer: []u8) !void {
    while (true) {
        const datagram = state.established.connection.popDatagram(buffer) catch return;
        const bytes = datagram orelse return;
        const message = protocol.parseUdpMessage(bytes) catch continue;
        handleUdpMessage(state, message) catch continue;
    }
}

fn handleUdpMessage(state: *State, message: protocol.UdpMessage) !void {
    if (message.frag_count == 1) {
        return forwardUdp(
            state,
            message.session_id,
            message.host,
            message.port,
            message.data,
        );
    }
    return handleFragment(state, message);
}

fn handleFragment(state: *State, message: protocol.UdpMessage) !void {
    if (message.frag_count > max_fragments or message.frag_id >= message.frag_count) {
        return;
    }
    var slot: ?*Fragment = null;
    for (&state.fragments) |*fragment| {
        if (fragment.active and
            fragment.session_id == message.session_id and
            fragment.msg_id == message.msg_id)
        {
            slot = fragment;
            break;
        }
    }
    if (slot == null) {
        for (&state.fragments) |*fragment| {
            if (!fragment.active) {
                slot = fragment;
                break;
            }
        }
    }
    if (slot == null) {
        // Evict the oldest entry to keep the cache bounded.
        var oldest: *Fragment = &state.fragments[0];
        for (&state.fragments) |*fragment| {
            if (fragment.last_activity < oldest.last_activity) oldest = fragment;
        }
        oldest.deinit(state.allocator);
        slot = oldest;
    }
    const fragment = slot.?;
    if (!fragment.active) {
        fragment.* = .{
            .active = true,
            .session_id = message.session_id,
            .msg_id = message.msg_id,
            .frag_count = message.frag_count,
            .last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
        };
    }
    if (fragment.frag_count != message.frag_count) {
        fragment.deinit(state.allocator);
        return;
    }
    if (fragment.parts[message.frag_id] != null) return;
    if (fragment.total + message.data.len > state.config.max_datagram_size) {
        fragment.deinit(state.allocator);
        return;
    }
    const part = try state.allocator.dupe(u8, message.data);
    fragment.parts[message.frag_id] = part;
    fragment.total += part.len;
    fragment.received |= @as(u16, 1) << @intCast(message.frag_id);
    fragment.last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds);

    const complete: u16 = if (message.frag_count == 16)
        0xffff
    else
        (@as(u16, 1) << @intCast(message.frag_count)) - 1;
    if (fragment.received != complete) return;

    const reassembled = try state.allocator.alloc(u8, fragment.total);
    defer state.allocator.free(reassembled);
    var offset: usize = 0;
    var index: usize = 0;
    while (index < message.frag_count) : (index += 1) {
        const bytes = fragment.parts[index] orelse {
            fragment.deinit(state.allocator);
            return;
        };
        @memcpy(reassembled[offset..][0..bytes.len], bytes);
        offset += bytes.len;
    }
    const session_id = fragment.session_id;
    const host_copy = try state.allocator.dupe(u8, message.host);
    defer state.allocator.free(host_copy);
    const port = message.port;
    fragment.deinit(state.allocator);
    try forwardUdp(state, session_id, host_copy, port, reassembled);
}

fn forwardUdp(
    state: *State,
    session_id: u32,
    host: []const u8,
    port: u16,
    data: []const u8,
) !void {
    const assoc = findAssoc(state, session_id) orelse return;
    const target = parseTarget(host, port) orelse return;
    const resolved = destination.resolveTarget(
        state.allocator,
        state.io,
        reload.policyFor(state.config.acl, state.config.policy_store),
        target,
        .udp_associate,
        state.config.connect_timeout,
    ) catch return;
    if (state.recv_bucket.rate != 0 and data.len > state.recv_bucket.capacity) return;
    try state.recv_bucket.waitWithDeadline(data.len, state.io, try io_helpers.deadlineFromTimeout(state.io, state.config.idle_timeout));
    assoc.socket.send(state.io, &resolved, data) catch {
        state.recv_bucket.refund(data.len);
        return;
    };
    if (state.config.stats) |value| {
        value.addBytesIn(@intCast(data.len));
    }
    assoc.last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds);
}

fn cleanupFragments(state: *State) void {
    const now: i64 = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds);
    for (&state.fragments) |*fragment| {
        if (fragment.active and now - fragment.last_activity >= fragment_idle_ns) {
            fragment.deinit(state.allocator);
        }
    }
}

fn drainAssocReads(state: *State) !void {
    const poll = std.Io.Duration.fromMilliseconds(10);
    const buffer = try state.allocator.alloc(u8, state.config.max_datagram_size);
    defer state.allocator.free(buffer);
    for (state.assocs.items) |assoc| {
        if (assoc.closed) continue;
        while (true) {
            const message = assoc.socket.receiveTimeout(
                state.io,
                buffer,
                .{ .duration = .{ .raw = poll, .clock = .awake } },
            ) catch |err| switch (err) {
                error.Timeout => break,
                else => {
                    assoc.closed = true;
                    break;
                },
            };
            if (message.flags.trunc) continue;
            var host_buffer: [64]u8 = undefined;
            const host = udp_address.formatHost(&host_buffer, message.from) catch continue;
            const encoded = protocol.buildUdpMessage(
                state.allocator,
                assoc.id,
                host,
                message.from.getPort(),
                assoc.next_msg_id,
                0,
                1,
                message.data,
            ) catch continue;
            defer state.allocator.free(encoded);
            assoc.next_msg_id +%= 1;
            if (encoded.len > state.config.max_datagram_size) continue;
            if (state.send_bucket.rate != 0 and encoded.len > state.send_bucket.capacity) continue;
            try state.send_bucket.waitWithDeadline(encoded.len, state.io, try io_helpers.deadlineFromTimeout(state.io, state.config.idle_timeout));
            state.established.connection.sendDatagram(encoded) catch {
                state.send_bucket.refund(encoded.len);
                continue;
            };
            if (state.config.stats) |value| {
                value.addBytesOut(@intCast(message.data.len));
            }
            assoc.last_activity = @intCast(
                std.Io.Timestamp.now(state.io, .awake).nanoseconds,
            );
        }
    }
}

fn findAssoc(state: *State, id: u32) ?*Assoc {
    for (state.assocs.items) |assoc| {
        if (assoc.id == id and !assoc.closed) return assoc;
    }
    return null;
}

fn findAssocByStream(state: *State, stream_id: u64) ?*Assoc {
    for (state.assocs.items) |assoc| {
        if (assoc.stream_id == stream_id and !assoc.closed) return assoc;
    }
    return null;
}

fn closeAssoc(state: *State, id: u32) void {
    if (findAssoc(state, id)) |assoc| assoc.closed = true;
}

fn closeAssocForStream(state: *State, stream_id: u64) void {
    if (findAssocByStream(state, stream_id)) |assoc| assoc.closed = true;
}

fn cleanupAssocs(state: *State) void {
    var index: usize = 0;
    while (index < state.assocs.items.len) {
        const assoc = state.assocs.items[index];
        const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
        if (assoc.closed or now - assoc.last_activity >= state.config.idle_timeout.nanoseconds) {
            assoc.socket.close(state.io);
            state.allocator.destroy(assoc);
            _ = state.assocs.swapRemove(index);
        } else {
            index += 1;
        }
    }
}

fn shutdownAllAssocs(state: *State) void {
    for (state.assocs.items) |assoc| {
        assoc.socket.close(state.io);
        state.allocator.destroy(assoc);
    }
}

fn findRelay(state: *State, stream_id: u64) ?*Relay {
    for (state.relays.items) |relay| {
        if (relay.stream_id == stream_id and !relay.closed) return relay;
    }
    return null;
}

fn closeRelayStream(state: *State, stream_id: u64) void {
    if (findRelay(state, stream_id)) |relay| {
        relay.closed = true;
        relay.tcp.shutdown(state.io, .both) catch {};
    }
}

fn pendingFor(state: *State, stream_id: u64) ?*Pending {
    for (&state.pending) |*pending| {
        if (pending.active and pending.stream_id == stream_id) return pending;
    }
    for (&state.pending) |*pending| {
        if (!pending.active) {
            pending.* = .{ .stream_id = stream_id, .active = true };
            return pending;
        }
    }
    return null;
}

fn drainRelayReads(state: *State) !void {
    const poll = std.Io.Duration.fromMilliseconds(10);
    const buffer = try state.allocator.alloc(u8, state.config.relay_buffer_size);
    defer state.allocator.free(buffer);
    for (state.relays.items) |relay| {
        if (relay.closed or relay.tcp_done) continue;
        while (true) {
            const count = io_helpers.readSome(
                state.io,
                relay.tcp,
                buffer,
                currentDeadline(state.io, poll),
            ) catch |err| switch (err) {
                error.Timeout => break,
                else => {
                    relay.closed = true;
                    break;
                },
            };
            if (count == 0) {
                _ = sendStreamData(state, relay.stream_id, relay.send_offset, "", true) catch {};
                relay.tcp_done = true;
                break;
            }
            const sent = sendStreamData(
                state,
                relay.stream_id,
                relay.send_offset,
                buffer[0..count],
                false,
            ) catch {
                relay.closed = true;
                break;
            };
            relay.send_offset += sent;
            if (state.config.stats) |value| {
                value.addBytesOut(@intCast(count));
            }
        }
    }
}

fn cleanupRelays(state: *State) void {
    var index: usize = 0;
    while (index < state.relays.items.len) {
        const relay = state.relays.items[index];
        if ((relay.tcp_done and relay.quic_done) or relay.closed) {
            relay.closed = true;
            relay.tcp.shutdown(state.io, .both) catch {};
            relay.tcp.close(state.io);
            state.allocator.destroy(relay);
            _ = state.relays.swapRemove(index);
        } else {
            index += 1;
        }
    }
}

fn shutdownAllRelays(state: *State) void {
    for (state.relays.items) |relay| {
        relay.tcp.shutdown(state.io, .both) catch {};
        relay.tcp.close(state.io);
        state.allocator.destroy(relay);
    }
}

fn writeRateLimited(state: *State, stream: net.Stream, data: []const u8) !void {
    var committed: usize = 0;
    const result = rate_stream.write(&state.recv_bucket, state.io, stream, data, &committed, try io_helpers.deadlineFromTimeout(state.io, state.config.idle_timeout));
    if (state.config.stats) |value| value.addBytesIn(@intCast(committed));
    try result;
}

fn sendStreamData(
    state: *State,
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
) !usize {
    if (data.len == 0 and !fin) return 0;
    const deadline = (try io_helpers.deadlineFromTimeout(state.io, state.config.idle_timeout)).?;
    var sent: usize = 0;
    for (0..200) |_| {
        const available = try state.send_bucket.waitAvailable(data.len - sent, state.io, deadline);
        const end = sent + @as(usize, @intCast(available));
        var call_deadline = std.Io.Clock.Timestamp.fromNow(state.io, .{ .clock = .awake, .raw = .fromMilliseconds(20) });
        call_deadline.raw.nanoseconds = @min(call_deadline.raw.nanoseconds, deadline.raw.nanoseconds);
        var committed: usize = 0;
        const result = state.established.connection.sendStreamWithDeadline(
            stream_id,
            offset + sent,
            data[sent..end],
            fin and end == data.len,
            &committed,
            call_deadline,
        );
        const charged = state.send_bucket.tryConsume(committed, @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds));
        std.debug.assert(charged);
        sent += committed;
        if (result) |_| {
            if (data.len == 0 or sent >= data.len) return sent;
        } else |err| switch (err) {
            error.Timeout => try std.Io.sleep(state.io, .fromMilliseconds(1), .awake),
            else => return err,
        }
    }
    return error.ConnectionClosed;
}

fn currentDeadline(
    io: std.Io,
    timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, timeout) catch null;
}

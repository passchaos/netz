//! TUIC v5 QUIC server with UUID/token authentication and TCP relays.

const std = @import("std");
const netz = @import("../netz.zig");

const protocol = @import("protocol.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const packet_stream = @import("packet_stream.zig");
const PacketStream = packet_stream.PacketStream;
const relay_mod = @import("../internal/relay_queue.zig");
const stream_sender = @import("../internal/relay_queue/stream_send.zig");

const quic = netz.quic;
const net = std.Io.net;

pub const Config = @import("config.zig").Config;

pub const Error = error{
    RateLimited,
    ConnectionLimitExceeded,
    ClientConnectionLimitExceeded,
    ClientTableFull,
    AuthenticationFailed,
    AuthenticationRequired,
    AuthTimeout,
    InvalidCommand,
    InvalidAddress,
    ConnectionClosed,
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

    fn acceptOne(self: *Server) !quic.handshake.EstablishedConnection {
        var local_cid: [4]u8 = undefined;
        self.io.random(&local_cid);
        var random: [32]u8 = undefined;
        self.io.random(&random);
        var x25519: [32]u8 = undefined;
        self.io.random(&x25519);
        return quic.handshake.accept(
            &self.endpoint,
            .{
                .local_connection_id = &local_cid,
                .alpn_protocol = self.config.alpn_protocol,
                .identity = self.config.identity,
                .random = random,
                .x25519_secret_key = x25519,
                .max_crypto_buffer = 64 * 1024,
            },
        );
    }

    /// Accept and serve exactly one QUIC connection on the calling thread.
    /// This keeps the endpoint single-owner for interop and focused tests.
    pub fn serveOne(self: *Server) !void {
        var established = try self.acceptOne();
        defer established.deinit();
        return processEstablished(
            self.allocator,
            self.io,
            &established,
            self.config,
            &self.limiter,
        );
    }

    /// Serve concurrent connections through the shared endpoint owner. The
    /// pump thread owns the UDP socket and every established connection; TCP
    /// relays use bounded queues and short async tasks for DNS/connect.
    pub fn serve(self: *Server) !void {
        return @import("shared/server.zig").serve(self);
    }
};

const Relay = relay_mod.Relay;

const AssocMode = enum { uni, datagram };

const Assoc = struct {
    state: *State,
    id: u16,
    socket: net.Socket,
    mode: AssocMode,
    packet_stream: PacketStream = .{},
    next_pkt_id: u16 = 0,
    last_activity: std.atomic.Value(i64),
    closed: std.atomic.Value(bool) = .init(false),
};

const UniPending = @import("uni_input.zig").Input;

const Pending = struct {
    stream_id: u64 = 0,
    input: @import("../internal/relay_queue/pending_input.zig").Buffer = .{},
    fin: bool = false,
    active: bool = false,
};

const max_fragments: u8 = 16;
const max_fragment_entries: usize = 64;
const fragment_idle_ns: i64 = 5 * std.time.ns_per_s;

const Fragment = struct {
    active: bool = false,
    assoc_id: u16 = 0,
    pkt_id: u16 = 0,
    frag_total: u8 = 0,
    received: u16 = 0,
    total: usize = 0,
    mode: AssocMode = .uni,
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
    retiring_packet_streams: packet_stream.Retirements = .{},
    pending: [8]Pending = @splat(.{}),
    uni_pending: [8]UniPending = @splat(.{}),
    fragments: [max_fragment_entries]Fragment = @splat(.{}),
    auth_buffer: [50]u8 = undefined,
    auth_used: usize = 0,
    authenticated: bool = false,
    last_activity: std.atomic.Value(i64),
    running: std.atomic.Value(bool) = .init(true),
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
        .last_activity = .init(
            @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds),
        ),
    };
    defer {
        state.running.store(false, .release);
        shutdownAllAssocs(&state);
        shutdownAllRelays(&state);
        for (&state.fragments) |*fragment| fragment.deinit(allocator);
        for (&state.uni_pending) |*pending| pending.deinit(allocator);
        for (&state.pending) |*pending| pending.input.deinit(allocator);
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
    var buffer: [4096]u8 = undefined;
    while (!state.authenticated) {
        const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
        if (now >= deadline) return error.AuthTimeout;

        const event = state.established.connection.receiveStreamWithTimeout(
            &buffer,
            .fromMilliseconds(10),
        ) catch |err| {
            switch (err) {
                error.Timeout => continue,
                else => return err,
            }
        };

        switch (event) {
            .data => |data| {
                if (!protocol.isUnidirectional(data.stream_id)) {
                    try handleBidiData(state, data.stream_id, buffer[0..data.bytes], data.fin);
                    continue;
                }
                if (data.bytes == 0) continue;
                if (state.auth_used + data.bytes > state.auth_buffer.len) {
                    return error.InvalidCommand;
                }
                @memcpy(
                    state.auth_buffer[state.auth_used..][0..data.bytes],
                    buffer[0..data.bytes],
                );
                state.auth_used += data.bytes;
                if (state.auth_used >= 50) {
                    try verifyAuthentication(state);
                    for (&state.pending) |*pending| {
                        if (!pending.active) continue;
                        try handleBidiData(state, pending.stream_id, &.{}, false);
                    }
                }
            },
            .reset => |reset| {
                if (protocol.isUnidirectional(reset.stream_id)) return error.AuthenticationFailed;
                closeRelayStream(state, reset.stream_id);
            },
        }
    }
}

fn verifyAuthentication(state: *State) !void {
    const auth = protocol.parseAuthenticate(
        state.auth_buffer[0..50],
    ) catch return error.AuthenticationFailed;
    var difference: u8 = 0;
    for (auth.uuid, state.config.uuid) |lhs, rhs| difference |= lhs ^ rhs;
    if (difference != 0) return error.AuthenticationFailed;

    var expected: [32]u8 = undefined;
    try state.established.exportKeyingMaterial(
        &auth.uuid,
        state.config.password,
        &expected,
    );
    var token_difference: u8 = 0;
    for (auth.token, expected) |lhs, rhs| token_difference |= lhs ^ rhs;
    if (token_difference != 0) return error.AuthenticationFailed;
    state.authenticated = true;
}

fn relayLoop(state: *State) !void {
    var buffer: [4096]u8 = undefined;
    while (state.running.load(.acquire)) {
        const event = state.established.connection.receiveStreamWithTimeout(
            &buffer,
            .fromMilliseconds(10),
        ) catch |err| {
            switch (err) {
                error.Timeout => {
                    drainDatagrams(state, &buffer) catch {};
                    drainAssocReplies(state) catch {};
                    serviceRelays(state);
                    cleanupRelays(state);
                    cleanupAssocs(state);
                    cleanupFragments(state);
                    const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
                    if (now - state.last_activity.load(.acquire) >=
                        state.config.idle_timeout.nanoseconds)
                    {
                        break;
                    }
                    continue;
                },
                else => return err,
            }
        };

        state.last_activity.store(
            @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
            .release,
        );
        switch (event) {
            .data => |data| {
                if (protocol.isUnidirectional(data.stream_id)) {
                    try handleUniData(state, data.stream_id, buffer[0..data.bytes], data.fin);
                } else {
                    try handleBidiData(state, data.stream_id, buffer[0..data.bytes], data.fin);
                }
            },
            .reset => |reset| {
                closeRelayStream(state, reset.stream_id);
                closeAssocForStream(state, reset.stream_id);
            },
        }
        drainDatagrams(state, &buffer) catch {};
        drainAssocReplies(state) catch {};
        serviceRelays(state);
        cleanupRelays(state);
        cleanupAssocs(state);
        cleanupFragments(state);
    }
}

fn handleBidiData(
    state: *State,
    stream_id: u64,
    data: []const u8,
    fin: bool,
) !void {
    if (findRelay(state, stream_id)) |relay| {
        try relay.queueInbound(data);
        if (fin) relay.quic_done.store(true, .release);
        relay.touch();
        return;
    }

    const pending = pendingFor(state, stream_id) orelse
        return error.InvalidCommand;
    pending.input.append(state.allocator, state.config.max_pending_stream_bytes, data) catch |err| {
        pending.active = false;
        pending.input.len = 0;
        pending.fin = false;
        return err;
    };
    if (fin) pending.fin = true;
    if (!state.authenticated) return;

    const command_bytes = pending.input.bytes();
    const connect = protocol.parseConnect(
        command_bytes,
    ) catch return;
    const target: destination.Target = switch (connect.address) {
        .none => return error.InvalidAddress,
        .ip => |ip| .{ .ip = ip },
        .domain => |domain| .{ .domain = .{
            .host = domain.host,
            .port = domain.port,
        } },
    };
    const tcp = destination.connectTarget(
        state.allocator,
        state.io,
        reload.policyFor(state.config.acl, state.config.policy_store),
        target,
        .connect,
        state.config.connect_timeout,
    ) catch |err| {
        if (state.config.stats) |value| {
            if (err == error.DestinationDenied) value.deniedRequest();
        }
        return err;
    };
    var tcp_owned = true;
    errdefer if (tcp_owned) tcp.close(state.io);

    if (state.relays.items.len >= state.config.max_relays) {
        return error.ConnectionLimitExceeded;
    }
    try state.relays.ensureUnusedCapacity(state.allocator, 1);
    const relay = try Relay.createWithOptions(state.allocator, state.io, tcp, stream_id, .{
        .idle_timeout = state.config.idle_timeout,
        .buffer_size = state.config.relay_buffer_size,
        .maximum_input_bytes = state.config.max_pending_stream_bytes,
    });
    tcp_owned = false;
    errdefer relay.deinit();
    const pending_fin = pending.fin;
    pending.active = false;
    pending.input.len = 0;
    pending.fin = false;

    if (connect.end < command_bytes.len) {
        // The command and payload may have arrived in one chunk; `data` was
        // copied into the pending buffer, so forward the suffix.
        const initial = command_bytes[connect.end..];
        try relay.queueInbound(initial);
    }
    if (pending_fin) {
        relay.quic_done.store(true, .release);
    }

    state.relays.appendAssumeCapacity(relay);
}

fn serviceRelays(state: *State) void {
    for (state.relays.items) |relay| {
        if (relay.closed.load(.acquire)) continue;
        relay.serviceInput();
        relay.flushOutbound(state, sendRelayItem);
        if (relay.quic_done.load(.acquire) and relay.inputDrained()) {
            relay.shutdownTcpSend();
        }
    }
}

fn sendRelayItem(state: *State, relay: *Relay, item: relay_mod.Outbound) relay_mod.SendResult {
    const remaining = switch (item) {
        .data => |bytes| bytes.len - relay.pending_data_start,
        .fin => 0,
    };
    var progress: stream_sender.Progress = .{};
    const result = stream_sender.send(quic, &state.established.connection, relay, item, remaining, &progress);
    if (progress.committed_bytes != 0 or relay.quic_fin_sent) {
        state.last_activity.store(@intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds), .release);
    }
    result catch |err| switch (err) {
        error.CongestionLimited, error.PacingLimited, error.FlowControlBlocked, error.AntiAmplificationLimited => return .blocked,
        else => return .fatal,
    };
    return if (progress.complete) .complete else .progress;
}

fn findRelay(state: *State, stream_id: u64) ?*Relay {
    for (state.relays.items) |relay| {
        if (relay.stream_id == stream_id and
            !relay.closed.load(.acquire))
        {
            return relay;
        }
    }
    return null;
}

fn pendingFor(state: *State, stream_id: u64) ?*Pending {
    for (&state.pending) |*pending| {
        if (pending.active and pending.stream_id == stream_id) return pending;
    }
    for (&state.pending) |*pending| {
        if (!pending.active) {
            pending.stream_id = stream_id;
            pending.active = true;
            pending.input.len = 0;
            pending.fin = false;
            return pending;
        }
    }
    return null;
}

fn closeRelayStream(state: *State, stream_id: u64) void {
    for (&state.pending) |*pending| {
        if (pending.active and pending.stream_id == stream_id) {
            pending.active = false;
            pending.input.len = 0;
            pending.fin = false;
        }
    }
    if (findRelay(state, stream_id)) |relay| {
        relay.closed.store(true, .release);
        relay.tcp.shutdown(state.io, .both) catch {};
    }
}

fn cleanupRelays(state: *State) void {
    var index: usize = 0;
    while (index < state.relays.items.len) {
        const relay = state.relays.items[index];
        if ((relay.quic_fin_sent and relay.quic_done.load(.acquire) and relay.inputDrained()) or
            relay.closed.load(.acquire) or relay.idle(@intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds)))
        {
            relay.deinit();
            _ = state.relays.swapRemove(index);
        } else {
            index += 1;
        }
    }
}

fn shutdownAllRelays(state: *State) void {
    for (state.relays.items) |relay| relay.deinit();
}

fn handleUniData(
    state: *State,
    stream_id: u64,
    data: []const u8,
    fin: bool,
) !void {
    const pending = uniPendingFor(state, stream_id) orelse
        return error.InvalidCommand;
    try pending.append(state.allocator, state.config.max_datagram_size, data);
    const command_bytes = pending.input.bytes();

    var offset: usize = 0;
    while (offset + 2 <= command_bytes.len) {
        switch (command_bytes[offset + 1]) {
            @intFromEnum(protocol.CommandType.packet) => {
                const parsed = protocol.parsePacket(
                    command_bytes[offset..command_bytes.len],
                ) catch {
                    break;
                };
                try handlePacket(state, parsed.packet, .uni);
                offset += parsed.end;
            },
            @intFromEnum(protocol.CommandType.dissociate) => {
                if (command_bytes.len - offset < 4) break;
                const assoc_id = protocol.parseDissociate(
                    command_bytes[offset..][0..4],
                ) catch break;
                closeAssoc(state, assoc_id);
                offset += 4;
            },
            @intFromEnum(protocol.CommandType.heartbeat) => {
                offset += 2;
            },
            else => return error.InvalidCommand,
        }
    }

    pending.consume(offset);
    try pending.finish(fin);
}

fn uniPendingFor(state: *State, stream_id: u64) ?*UniPending {
    for (&state.uni_pending) |*pending| {
        if (pending.active and pending.stream_id == stream_id) return pending;
    }
    for (&state.uni_pending) |*pending| {
        if (!pending.active) {
            pending.start(stream_id);
            return pending;
        }
    }
    return null;
}

fn drainDatagrams(state: *State, buffer: []u8) !void {
    while (true) {
        const datagram = state.established.connection.popDatagram(buffer) catch {
            return;
        };
        const bytes = datagram orelse return;
        const parsed = protocol.parsePacket(bytes) catch continue;
        handlePacket(state, parsed.packet, .datagram) catch continue;
    }
}

fn handlePacket(
    state: *State,
    packet: protocol.Packet,
    mode: AssocMode,
) anyerror!void {
    if (packet.frag_total != 1) {
        return handleFragment(state, packet, mode);
    }
    const target: destination.Target = switch (packet.address) {
        .none => return error.InvalidAddress,
        .ip => |ip| .{ .ip = ip },
        .domain => |domain| .{ .domain = .{
            .host = domain.host,
            .port = domain.port,
        } },
    };
    const resolved = destination.resolveTarget(
        state.allocator,
        state.io,
        reload.policyFor(state.config.acl, state.config.policy_store),
        target,
        .udp_associate,
        state.config.connect_timeout,
    ) catch return;

    var assoc = findAssoc(state, packet.assoc_id);
    if (assoc == null) {
        if (state.assocs.items.len >= state.config.max_assocs) return;
        assoc = try createAssoc(state, packet.assoc_id, mode, resolved);
    } else if (assoc.?.mode != mode) {
        return;
    }
    assoc.?.socket.send(state.io, &resolved, packet.payload) catch return;
    if (state.config.stats) |value| {
        value.addBytesIn(@intCast(packet.payload.len));
    }
    assoc.?.last_activity.store(
        @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
        .release,
    );
}

fn createAssoc(
    state: *State,
    id: u16,
    mode: AssocMode,
    resolved: net.IpAddress,
) !*Assoc {
    if (state.assocs.items.len >= state.config.max_assocs) return error.ConnectionLimitExceeded;
    const bind_address = switch (resolved) {
        .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
        .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
    };
    const socket = try bind_address.bind(
        state.io,
        .{ .mode = .dgram, .protocol = .udp },
    );
    errdefer socket.close(state.io);

    const assoc = try state.allocator.create(Assoc);
    errdefer state.allocator.destroy(assoc);
    assoc.* = .{
        .state = state,
        .id = id,
        .socket = socket,
        .mode = mode,
        .last_activity = .init(
            @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
        ),
    };
    try state.assocs.append(state.allocator, assoc);
    return assoc;
}

/// Poll every association's UDP socket and forward responses on the main
/// relay loop. Keeping connection sends on the same thread that owns the QUIC
/// receive path avoids cross-thread send/receive races; replies are bounded by
/// the loop's short receive window.
fn drainAssocReplies(state: *State) !void {
    flushRetiringPacketStreams(state);
    const buffer = state.allocator.alloc(
        u8,
        state.config.max_datagram_size,
    ) catch return;
    defer state.allocator.free(buffer);

    const poll_timeout: std.Io.Timeout = .{
        .duration = .{
            .raw = .fromMilliseconds(1),
            .clock = .awake,
        },
    };
    for (state.assocs.items) |assoc| {
        if (assoc.closed.load(.acquire)) continue;
        const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
        if (now - assoc.last_activity.load(.acquire) >=
            state.config.idle_timeout.nanoseconds)
        {
            assoc.closed.store(true, .release);
            continue;
        }
        while (true) {
            const message = assoc.socket.receiveTimeout(
                state.io,
                buffer,
                poll_timeout,
            ) catch |err| switch (err) {
                error.Timeout => break,
                else => {
                    assoc.closed.store(true, .release);
                    break;
                },
            };
            if (message.flags.trunc) continue;
            const encoded = protocol.buildPacket(state.allocator, .{
                .assoc_id = assoc.id,
                .pkt_id = assoc.next_pkt_id,
                .frag_total = 1,
                .frag_id = 0,
                .address = .{ .ip = message.from },
                .payload = message.data,
            }) catch continue;
            defer state.allocator.free(encoded);
            assoc.next_pkt_id +%= 1;
            sendAssocPayload(state, assoc, encoded) catch {
                assoc.closed.store(true, .release);
                break;
            };
            assoc.last_activity.store(
                @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
                .release,
            );
        }
    }
}

fn sendAssocPayload(
    state: *State,
    assoc: *Assoc,
    encoded: []const u8,
) !void {
    switch (assoc.mode) {
        .datagram => {
            try state.established.connection.sendDatagram(encoded);
            if (state.config.stats) |value| {
                value.addBytesOut(@intCast(encoded.len));
            }
        },
        .uni => {
            var attempts: usize = 0;
            while (attempts < 100) : (attempts += 1) {
                var progress: packet_stream.Progress = .{};
                const result = assoc.packet_stream.sendWithTimeout(&state.established.connection, encoded, .fromMilliseconds(100), &progress);
                if (state.config.stats) |value| value.addBytesOut(@intCast(progress.committed_bytes));
                if (progress.fin_committed) return;
                result catch |err| switch (err) {
                    error.Timeout => continue,
                    else => {
                        assoc.packet_stream.beginCancel();
                        return err;
                    },
                };
            }
            assoc.packet_stream.beginCancel();
            return error.ConnectionClosed;
        },
    }
}

fn handleFragment(
    state: *State,
    packet: protocol.Packet,
    mode: AssocMode,
) anyerror!void {
    if (packet.frag_total > max_fragments or packet.frag_id >= packet.frag_total) {
        return;
    }
    var slot: ?*Fragment = null;
    for (&state.fragments) |*fragment| {
        if (fragment.active and
            fragment.assoc_id == packet.assoc_id and
            fragment.pkt_id == packet.pkt_id)
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
            .assoc_id = packet.assoc_id,
            .pkt_id = packet.pkt_id,
            .frag_total = packet.frag_total,
            .mode = mode,
            .last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
        };
    }
    if (fragment.frag_total != packet.frag_total or fragment.mode != mode) {
        fragment.deinit(state.allocator);
        return;
    }
    if (fragment.parts[packet.frag_id] != null) return;
    if (fragment.total + packet.payload.len > state.config.max_datagram_size) {
        fragment.deinit(state.allocator);
        return;
    }
    const part = try state.allocator.dupe(u8, packet.payload);
    fragment.parts[packet.frag_id] = part;
    fragment.total += part.len;
    fragment.received |= @as(u16, 1) << @intCast(packet.frag_id);
    fragment.last_activity = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds);

    const complete: u16 = if (packet.frag_total == 16)
        0xffff
    else
        (@as(u16, 1) << @intCast(packet.frag_total)) - 1;
    if (fragment.received != complete) return;

    const reassembled = try state.allocator.alloc(u8, fragment.total);
    defer state.allocator.free(reassembled);
    var offset: usize = 0;
    var index: usize = 0;
    while (index < packet.frag_total) : (index += 1) {
        const bytes = fragment.parts[index] orelse {
            fragment.deinit(state.allocator);
            return;
        };
        @memcpy(reassembled[offset..][0..bytes.len], bytes);
        offset += bytes.len;
    }
    const complete_packet = protocol.Packet{
        .assoc_id = packet.assoc_id,
        .pkt_id = packet.pkt_id,
        .frag_total = 1,
        .frag_id = 0,
        .address = packet.address,
        .payload = reassembled,
    };
    fragment.deinit(state.allocator);
    try handlePacket(state, complete_packet, mode);
}

fn cleanupFragments(state: *State) void {
    const now: i64 = @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds);
    for (&state.fragments) |*fragment| {
        if (fragment.active and now - fragment.last_activity >= fragment_idle_ns) {
            fragment.deinit(state.allocator);
        }
    }
}

fn findAssoc(state: *State, id: u16) ?*Assoc {
    for (state.assocs.items) |assoc| {
        if (assoc.id == id and !assoc.closed.load(.acquire)) return assoc;
    }
    return null;
}

fn closeAssocForStream(state: *State, stream_id: u64) void {
    for (state.assocs.items) |assoc| {
        if (assoc.packet_stream.stream_id == stream_id) {
            closeAssoc(state, assoc.id);
            return;
        }
    }
}

fn closeAssoc(state: *State, id: u16) void {
    if (findAssoc(state, id)) |assoc| {
        assoc.closed.store(true, .release);
    }
}

fn cleanupAssocs(state: *State) void {
    var index: usize = 0;
    while (index < state.assocs.items.len) {
        const assoc = state.assocs.items[index];
        if (assoc.closed.load(.acquire)) {
            retirePacketStream(state, &assoc.packet_stream);
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
        assoc.closed.store(true, .release);
    }
    for (state.assocs.items) |assoc| {
        assoc.socket.close(state.io);
        state.allocator.destroy(assoc);
    }
}

fn retirePacketStream(state: *State, stream: *PacketStream) void {
    if (state.retiring_packet_streams.add(stream)) return;
    state.running.store(false, .release);
    stream.* = .{};
}

fn flushRetiringPacketStreams(state: *State) void {
    if (state.retiring_packet_streams.count == 0) return;
    const result = state.retiring_packet_streams.flush(&state.established.connection);
    result catch |err| switch (err) {
        error.CongestionLimited, error.PacingLimited, error.AntiAmplificationLimited => {},
        else => state.running.store(false, .release),
    };
}

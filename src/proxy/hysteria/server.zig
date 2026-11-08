//! Hysteria 1-style CONNECT-over-QUIC server with password authentication.
//!
//! Each bidirectional QUIC stream carries one HTTP CONNECT head followed by
//! relay payload. Requests are authenticated with `Hysteria-Auth`, checked
//! against the ACL, and relayed to the target over TCP. Multiplexed streams on
//! one QUIC connection are supported. Hysteria UDP relay and obfuscation are
//! intentionally out of scope for this bounded server.

const std = @import("std");
const netz = @import("../netz.zig");

const protocol = @import("protocol.zig");
const acl = @import("../runtime/acl.zig");
const reload = @import("../runtime/reload.zig");
const limits = @import("../runtime/limits.zig");
const stats_mod = @import("../runtime/stats.zig");
const rate_limit = @import("../runtime/rate_limit.zig");
const destination = @import("../runtime/destination.zig");
const io_helpers = @import("../internal/io.zig");

const quic = netz.quic;
const net = std.Io.net;

pub const Config = struct {
    password: []const u8,
    identity: quic.tls.auth.ServerIdentity,
    alpn_protocol: []const u8 = "hysteria",
    acl: acl.Policy = .{},
    policy_store: ?*reload.Reloadable = null,
    limits: limits.Options = .{},
    connect_timeout: std.Io.Duration = .fromSeconds(10),
    idle_timeout: std.Io.Duration = .fromSeconds(120),
    auth_timeout: std.Io.Duration = .fromSeconds(10),
    max_datagram_size: usize = 4096,
    relay_buffer_size: usize = 16 * 1024,
    /// Maximum concurrent CONNECT streams per QUIC connection.
    max_relays: usize = 64,
    stats: ?*stats_mod.Stats = null,
    rate_limiter: ?*rate_limit.Limiter = null,
};

pub const Error = error{
    RateLimited,
    AuthenticationFailed,
    AuthTimeout,
    InvalidRequest,
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
        const endpoint = try quic.runtime.Endpoint.bind(
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

    pub fn serve(self: *Server) !void {
        while (self.running.load(.acquire)) {
            var local_cid: [4]u8 = undefined;
            self.io.random(&local_cid);
            var random: [32]u8 = undefined;
            self.io.random(&random);
            var x25519: [32]u8 = undefined;
            self.io.random(&x25519);
            var established = quic.handshake.accept(
                &self.endpoint,
                .{
                    .local_connection_id = &local_cid,
                    .alpn_protocol = self.config.alpn_protocol,
                    .identity = self.config.identity,
                    .random = random,
                    .x25519_secret_key = x25519,
                    .max_crypto_buffer = 64 * 1024,
                },
            ) catch continue;
            const job = self.allocator.create(Job) catch {
                established.deinit();
                continue;
            };
            job.* = .{ .server = self, .established = established };
            self.active_jobs.fetchAdd(1, .monotonic);
            const thread = std.Thread.spawn(.{}, Job.run, .{job}) catch {
                self.active_jobs.fetchSub(1, .release);
                self.allocator.destroy(job);
                job.established.deinit();
                continue;
            };
            thread.detach();
        }
    }

    const Job = struct {
        server: *Server,
        established: quic.handshake.EstablishedConnection,

        fn run(self: *Job) void {
            const server = self.server;
            defer server.active_jobs.fetchSub(1, .release);
            defer server.allocator.destroy(self);
            defer self.established.deinit();
            processEstablished(
                server.allocator,
                server.io,
                &self.established,
                server.config,
                &server.limiter,
            ) catch {};
        }
    };
};

const Relay = struct {
    state: *State,
    tcp: net.Stream,
    stream_id: u64,
    send_offset: u64,
    quic_done: std.atomic.Value(bool) = .init(false),
    tcp_done: std.atomic.Value(bool) = .init(false),
    closed: std.atomic.Value(bool) = .init(false),
};

const Pending = struct {
    stream_id: u64 = 0,
    buffer: [4096]u8 = undefined,
    used: usize = 0,
    active: bool = false,
    rejected: bool = false,
};

const State = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    established: *quic.handshake.EstablishedConnection,
    config: Config,
    mutex: std.Io.Mutex = .init,
    relays: std.ArrayList(*Relay) = .empty,
    relay_buffer: []u8,
    relay_cursor: usize = 0,
    pending: [8]Pending = @splat(.{}),
    authenticated_once: bool = false,
    auth_deadline: i64,
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

    const now = std.Io.Timestamp.now(io, .awake).nanoseconds;
    const relay_buffer = try allocator.alloc(u8, config.relay_buffer_size);
    var state = State{
        .allocator = allocator,
        .io = io,
        .established = established,
        .config = config,
        .relay_buffer = relay_buffer,
        .auth_deadline = @intCast(now + config.auth_timeout.nanoseconds),
        .last_activity = .init(@intCast(now)),
    };
    defer {
        state.running.store(false, .release);
        shutdownAllRelays(&state);
        state.relays.deinit(allocator);
        allocator.free(relay_buffer);
    }

    relayLoop(&state) catch |err| switch (err) {
        error.ConnectionClosed, error.Canceled => {},
        else => return err,
    };
}

fn relayLoop(state: *State) !void {
    var buffer: [4096]u8 = undefined;
    while (state.running.load(.acquire)) {
        state.mutex.lockUncancelable(state.io);
        const event = state.established.connection.receiveStreamWithTimeout(
            &buffer,
            .fromMilliseconds(10),
        ) catch |err| {
            state.mutex.unlock(state.io);
            switch (err) {
                error.Timeout => {
                    cleanupRelays(state);
                    const now = std.Io.Timestamp.now(state.io, .awake).nanoseconds;
                    if (now - state.last_activity.load(.acquire) >=
                        state.config.idle_timeout.nanoseconds)
                    {
                        break;
                    }
                    if (!state.authenticated_once and now >= state.auth_deadline) {
                        return error.AuthTimeout;
                    }
                    continue;
                },
                else => return err,
            }
        };
        state.mutex.unlock(state.io);

        state.last_activity.store(
            @intCast(std.Io.Timestamp.now(state.io, .awake).nanoseconds),
            .release,
        );
        switch (event) {
            .data => |data| {
                try handleStreamData(
                    state,
                    data.stream_id,
                    buffer[0..data.bytes],
                    data.fin,
                );
            },
            .reset => |reset| closeRelayStream(state, reset.stream_id),
        }
        drainRelayReads(state) catch {};
        cleanupRelays(state);
    }
}

fn handleStreamData(
    state: *State,
    stream_id: u64,
    data: []const u8,
    fin: bool,
) !void {
    if (findRelay(state, stream_id)) |relay| {
        if (data.len > 0) {
            try io_helpers.writeAll(
                state.io,
                relay.tcp,
                data,
                currentDeadline(state.io, state.config.idle_timeout),
            );
            if (state.config.stats) |value| {
                value.addBytesIn(@intCast(data.len));
            }
        }
        if (fin) {
            relay.tcp.shutdown(state.io, .send) catch {};
            relay.quic_done.store(true, .release);
        }
        return;
    }

    const pending = pendingFor(state, stream_id) orelse
        return error.InvalidRequest;
    if (pending.rejected) return;
    if (pending.used + data.len > pending.buffer.len) {
        try rejectStream(state, stream_id, pending, protocol.forbidden_response);
        return;
    }
    @memcpy(pending.buffer[pending.used..][0..data.len], data);
    pending.used += data.len;

    const request = protocol.parseRequest(pending.buffer[0..pending.used]) catch |err| switch (err) {
        error.Incomplete => {
            if (fin) {
                try rejectStream(
                    state,
                    stream_id,
                    pending,
                    protocol.forbidden_response,
                );
            }
            return;
        },
        else => {
            try rejectStream(state, stream_id, pending, protocol.forbidden_response);
            return;
        },
    };
    if (!authMatches(request.auth, state.config.password)) {
        if (state.config.stats) |value| value.deniedRequest();
        try rejectStream(
            state,
            stream_id,
            pending,
            protocol.auth_required_response,
        );
        return;
    }

    if (state.relays.items.len >= state.config.max_relays) {
        try rejectStream(state, stream_id, pending, protocol.forbidden_response);
        return;
    }

    const target: destination.Target = switch (request.authority) {
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
        try rejectStream(state, stream_id, pending, protocol.forbidden_response);
        return;
    };
    errdefer tcp.close(state.io);

    try sendStreamData(
        state,
        stream_id,
        0,
        protocol.success_response,
        false,
    );

    const relay = try state.allocator.create(Relay);
    errdefer state.allocator.destroy(relay);
    relay.* = .{
        .state = state,
        .tcp = tcp,
        .stream_id = stream_id,
        .send_offset = protocol.success_response.len,
    };
    try state.relays.append(state.allocator, relay);
    state.authenticated_once = true;

    const pending_used = pending.used;
    pending.active = false;
    pending.used = 0;

    if (request.end < pending_used) {
        try io_helpers.writeAll(
            state.io,
            tcp,
            pending.buffer[request.end..pending_used],
            currentDeadline(state.io, state.config.idle_timeout),
        );
        if (state.config.stats) |value| {
            value.addBytesIn(@intCast(pending_used - request.end));
        }
    }
    if (fin) {
        tcp.shutdown(state.io, .send) catch {};
        relay.quic_done.store(true, .release);
    }
}

fn rejectStream(
    state: *State,
    stream_id: u64,
    pending: *Pending,
    response: []const u8,
) !void {
    pending.rejected = true;
    pending.used = 0;
    sendStreamData(state, stream_id, 0, response, true) catch {};
}

fn authMatches(actual: []const u8, expected: []const u8) bool {
    var difference: usize = if (actual.len == expected.len) 0 else 1;
    const limit = @min(actual.len, expected.len);
    for (0..limit) |index| {
        difference |= actual[index] ^ expected[index];
    }
    return difference == 0;
}

fn sendStreamData(
    state: *State,
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
) !void {
    if (data.len == 0 and !fin) return;
    var sent: usize = 0;
    var attempts: usize = 0;
    while (attempts < 200) : (attempts += 1) {
        var committed: usize = 0;
        state.mutex.lockUncancelable(state.io);
        const result = state.established.connection.sendStreamWithTimeout(
            stream_id,
            offset + sent,
            data[sent..],
            fin,
            &committed,
            .fromMilliseconds(20),
        );
        state.mutex.unlock(state.io);
        sent += committed;
        if (result) |_| {
            if (data.len == 0 or sent >= data.len) return;
            continue;
        } else |err| switch (err) {
            error.Timeout => {
                std.Io.sleep(state.io, .fromMilliseconds(1), .awake) catch {};
            },
            else => return err,
        }
    }
    return error.ConnectionClosed;
}

/// Poll TCP relay sockets from the QUIC receive loop. Keeping both directions
/// on one thread avoids cross-thread contention for the connection state and
/// avoids parking an async worker on a long blocking read.
fn drainRelayReads(state: *State) !void {
    const poll_deadline = io_helpers.deadlineFromTimeout(
        state.io,
        .fromMilliseconds(10),
    ) catch null;
    const relay_count = state.relays.items.len;
    if (relay_count == 0) return;
    var step: usize = 0;
    while (step < relay_count) : (step += 1) {
        const index = (state.relay_cursor + step) % relay_count;
        const relay = state.relays.items[index];
        if (relay.closed.load(.acquire) or relay.tcp_done.load(.acquire)) {
            continue;
        }
        while (true) {
            const count = io_helpers.readSome(
                state.io,
                relay.tcp,
                state.relay_buffer,
                poll_deadline,
            ) catch |err| switch (err) {
                error.Timeout => break,
                else => {
                    relay.closed.store(true, .release);
                    break;
                },
            };
            if (count == 0) {
                sendStreamData(
                    state,
                    relay.stream_id,
                    relay.send_offset,
                    "",
                    true,
                ) catch {};
                relay.tcp_done.store(true, .release);
                break;
            }
            sendStreamData(
                state,
                relay.stream_id,
                relay.send_offset,
                state.relay_buffer[0..count],
                false,
            ) catch {
                relay.closed.store(true, .release);
                break;
            };
            relay.send_offset += count;
            if (state.config.stats) |value| {
                value.addBytesOut(@intCast(count));
            }
        }
    }
    state.relay_cursor = (state.relay_cursor + 1) % relay_count;
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
            pending.* = .{ .stream_id = stream_id, .active = true };
            return pending;
        }
    }
    return null;
}

fn closeRelayStream(state: *State, stream_id: u64) void {
    if (findRelay(state, stream_id)) |relay| {
        relay.closed.store(true, .release);
        relay.tcp.shutdown(state.io, .both) catch {};
    }
}

fn cleanupRelays(state: *State) void {
    var index: usize = 0;
    while (index < state.relays.items.len) {
        const relay = state.relays.items[index];
        if ((relay.tcp_done.load(.acquire) and
            relay.quic_done.load(.acquire)) or
            relay.closed.load(.acquire))
        {
            relay.closed.store(true, .release);
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
        relay.closed.store(true, .release);
        relay.tcp.shutdown(state.io, .both) catch {};
    }
    for (state.relays.items) |relay| {
        relay.tcp.close(state.io);
        state.allocator.destroy(relay);
    }
}

fn currentDeadline(
    io: std.Io,
    idle_timeout: std.Io.Duration,
) ?std.Io.Clock.Timestamp {
    return io_helpers.deadlineFromTimeout(io, idle_timeout) catch null;
}

//! TUIC v5 server driven by the shared QUIC endpoint owner.
//!
//! One pump thread owns the UDP socket and every established connection.
//! Blocking DNS/connect work runs in short-lived async tasks that post results
//! back through a bounded inbox; target TCP and UDP I/O has independent
//! bounded owners. The pump never waits for a target socket, so
//! multiple TUIC connections share one endpoint without receive contention.

const std = @import("std");
const net = std.Io.net;

const netz = @import("../../netz.zig");
const protocol = @import("../protocol.zig");
const Config = @import("../config.zig").Config;
const limits = @import("../../runtime/limits.zig");
const reload = @import("../../runtime/reload.zig");
const destination = @import("../../runtime/destination.zig");
const relay_mod = @import("../../internal/relay_queue.zig");
const udp_session = @import("../../internal/udp_session.zig");
const UdpSession = udp_session.Session;
const pending_input = @import("../../internal/relay_queue/pending_input.zig");
const stream_sender = @import("../../internal/relay_queue/stream_send.zig");
const PacketStream = @import("../packet_stream.zig").PacketStream;

const quic = netz.quic;
const Relay = relay_mod.Relay;

const max_events = 32;
const max_relays = 64;
const max_assocs = 64;
const max_fragments: u8 = 16;
const max_fragment_entries = 64;
const fragment_idle_ns: i64 = 5 * std.time.ns_per_s;
const inbox_capacity = 16;
const assoc_pending_sends = udp_session.Replies.capacity;
const inbound_write_budget_ns = 10 * std.time.ns_per_ms;

const Mode = enum { uni, datagram };

const Pending = struct {
    stream_id: u64 = 0,
    input: pending_input.Buffer = .{},
    active: bool = false,
    connecting: bool = false,
    command_end: usize = 0,
    fin: bool = false,
};

const uni_input = @import("../uni_input.zig");
const UniPending = uni_input.Input;

const Fragment = struct {
    active: bool = false,
    assoc_id: u16 = 0,
    pkt_id: u16 = 0,
    frag_total: u8 = 0,
    received: u16 = 0,
    total: usize = 0,
    mode: Mode = .uni,
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

const Assoc = struct {
    id: u16,
    socket: net.Socket,
    target_io: UdpSession = .{},
    mode: Mode,
    packet_stream: PacketStream = .{},
    next_pkt_id: u16 = 0,
    last_activity_ns: i64,
    closed: bool = false,
    pending_replies: udp_session.Replies = .{},
};

const Inbox = union(enum) {
    relay_ready: struct { stream_id: u64, tcp: net.Stream },
    relay_failed: struct { stream_id: u64 },
    assoc_ready: struct {
        id: u16,
        socket: net.Socket,
        resolved: net.IpAddress,
        mode: Mode,
        payload: []u8,
    },
    assoc_failed: struct { id: u16 },
};

const Task = union(enum) {
    connect: ConnectTask,
    assoc: AssocTask,
};

pub const Pump = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    endpoint: *quic.runtime.Endpoint,
    config: Config,
    limiter: *limits.ConnectionLimiter,
    shared: quic.endpoint_server.Server,
    receive_storage: []u8,
    versions: [2]u32,
    connections: std.ArrayList(*Connection) = .empty,
    by_handle: std.AutoHashMapUnmanaged(
        quic.endpoint_dispatcher.ConnectionHandle,
        *Connection,
    ) = .empty,
    running: std.atomic.Value(bool) = .init(true),
    stop_flag: *std.atomic.Value(bool),
    task_storage: [32]Task = undefined,
    tasks: std.Io.Queue(Task) = undefined,
    workers: [2]std.Thread = undefined,
    workers_started: bool = false,
    ready: std.atomic.Value(bool) = .init(false),

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        endpoint: *quic.runtime.Endpoint,
        config: Config,
        limiter: *limits.ConnectionLimiter,
        stop_flag: *std.atomic.Value(bool),
    ) !Pump {
        const receive_storage = try allocator.alloc(
            u8,
            max_events * endpoint.limits.max_datagram_size,
        );
        errdefer allocator.free(receive_storage);
        var shared = try quic.endpoint_server.Server.init(
            allocator,
            endpoint,
            .{
                .local_connection_id = &.{},
                .alpn_protocol = config.alpn_protocol,
                .identity = config.identity,
                .max_crypto_buffer = 64 * 1024,
                .initial_one_rtt_config = .{},
            },
            .{
                .max_pending_handshakes = 128,
                .max_connections = 1024,
                .inbox_capacity = 16,
                .handshake_timeout_ms = @intCast(
                    @min(
                        @divTrunc(
                            config.auth_timeout.nanoseconds,
                            std.time.ns_per_ms,
                        ) +| 1,
                        30_000,
                    ),
                ),
            },
        );
        errdefer shared.deinit();
        return .{
            .allocator = allocator,
            .io = io,
            .endpoint = endpoint,
            .config = config,
            .limiter = limiter,
            .shared = shared,
            .receive_storage = receive_storage,
            .stop_flag = stop_flag,
            .versions = .{
                quic.Version.version_1.wireValue(),
                quic.Version.version_2.wireValue(),
            },
        };
    }

    pub fn deinit(self: *Pump) void {
        if (self.workers_started) {
            self.tasks.close(self.io);
            for (&self.workers) |*worker| worker.join();
            self.workers_started = false;
        }
        for (self.connections.items) |conn| {
            _ = self.shared.removeConnection(conn.handle) catch false;
            conn.release();
        }
        self.connections.deinit(self.allocator);
        self.by_handle.deinit(self.allocator);
        self.shared.deinit();
        self.allocator.free(self.receive_storage);
        self.* = undefined;
    }

    fn startWorkers(self: *Pump) !void {
        self.tasks = .init(&self.task_storage);
        for (&self.workers, 0..) |*worker, index| {
            worker.* = std.Thread.spawn(
                .{},
                workerMain,
                .{ self, index },
            ) catch |err| {
                self.tasks.close(self.io);
                for (self.workers[0..index]) |started| started.join();
                return err;
            };
        }
        self.workers_started = true;
    }

    fn postTask(self: *Pump, task: Task) bool {
        const count = self.tasks.put(
            self.io,
            &.{task},
            0,
        ) catch return false;
        return count == 1;
    }

    fn workerMain(self: *Pump, index: usize) void {
        _ = index;
        while (true) {
            const task = self.tasks.getOne(self.io) catch return;
            switch (task) {
                .connect => |connect| connect.execute(),
                .assoc => |assoc| assoc.execute(),
            }
        }
    }

    pub fn stop(self: *Pump) void {
        self.running.store(false, .release);
    }

    fn notifyReady(context: ?*anyopaque) void {
        const self: *Pump = @ptrCast(@alignCast(context.?));
        self.ready.store(true, .release);
    }

    fn serviceReadyRelays(self: *Pump) void {
        for (self.connections.items) |conn| {
            if (conn.closed.load(.acquire)) continue;
            conn.serviceAssocs(true);
            conn.serviceRelays(true);
        }
    }

    pub fn run(self: *Pump) !void {
        var events: [max_events]quic.endpoint_server.VisitEvent = undefined;
        var ready_turns: usize = 0;
        while (self.running.load(.acquire) and
            self.stop_flag.load(.acquire))
        {
            // At most eight completion turns precede the sole QUIC receive
            // owner, so continuous target progress cannot suppress input.
            if (self.ready.swap(false, .acq_rel) and ready_turns < 8) {
                self.serviceReadyRelays();
                ready_turns += 1;
                continue;
            }
            ready_turns = 0;
            const count = self.shared.receiveManyVisitingTimeout(
                &self.versions,
                self.receive_storage,
                &events,
                .{ .duration = .{
                    .clock = .awake,
                    .raw = .fromMilliseconds(2),
                } },
                {},
                visitNoop,
            ) catch |err| switch (err) {
                error.Timeout => 0,
                else => return err,
            };
            for (events[0..count]) |*event| {
                defer event.deinit(self.allocator);
                switch (event.*) {
                    .connected => |handle| self.onConnected(handle),
                    .packet, .timer, .handshake_failed, .unrouted => {},
                }
            }
            self.serviceConnections();
        }
    }

    fn onConnected(
        self: *Pump,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
    ) void {
        if (self.by_handle.contains(handle)) return;
        const established = self.shared.connection(handle) orelse return;
        const peer = established.connection.config.peer;
        if (self.config.rate_limiter) |value| {
            const now = std.Io.Timestamp.now(self.io, .awake).nanoseconds;
            if (!value.allow(peer, 1, now)) {
                _ = self.shared.removeConnection(handle) catch false;
                return;
            }
        }
        self.limiter.acquire(peer) catch {
            _ = self.shared.removeConnection(handle) catch false;
            return;
        };
        const conn = Connection.create(self, handle, established, peer) catch {
            self.limiter.release(peer);
            _ = self.shared.removeConnection(handle) catch false;
            return;
        };
        self.connections.append(self.allocator, conn) catch {
            _ = self.shared.removeConnection(handle) catch false;
            conn.release();
            return;
        };
        self.by_handle.put(self.allocator, handle, conn) catch {
            _ = self.connections.pop();
            _ = self.shared.removeConnection(handle) catch false;
            conn.release();
            return;
        };
        if (self.config.stats) |value| value.connectionOpened();
    }

    fn serviceConnections(self: *Pump) void {
        var index: usize = 0;
        while (index < self.connections.items.len) {
            const conn = self.connections.items[index];
            serviceConnection(conn) catch {
                self.removeConnection(conn);
                continue;
            };
            if (conn.closed.load(.acquire)) {
                self.removeConnection(conn);
                continue;
            }
            index += 1;
        }
    }

    fn removeConnection(self: *Pump, conn: *Connection) void {
        const index = for (self.connections.items, 0..) |candidate, i| {
            if (candidate == conn) break i;
        } else return;
        _ = self.connections.swapRemove(index);
        _ = self.by_handle.remove(conn.handle);
        _ = self.shared.removeConnection(conn.handle) catch false;
        conn.release();
    }

    fn serviceConnection(conn: *Connection) !void {
        try conn.drainInbox();
        if (conn.closed.load(.acquire)) return;
        try conn.pollStreams();
        conn.drainDatagrams();
        conn.serviceAssocs(false);
        conn.serviceRelays(false);
        conn.cleanup();
        conn.checkTimeouts();
    }

    fn visitNoop(
        _: void,
        _: quic.endpoint_dispatcher.RoutedPacketView,
    ) !void {}
};

pub const Connection = struct {
    pump: *Pump,
    handle: quic.endpoint_dispatcher.ConnectionHandle,
    established: *quic.handshake.EstablishedConnection,
    peer: net.IpAddress,
    refs: std.atomic.Value(usize) = .init(1),
    closed: std.atomic.Value(bool) = .init(false),
    created_ns: i64,
    last_activity_ns: i64,
    authenticated: bool = false,
    auth_buffer: [50]u8 = undefined,
    auth_used: usize = 0,
    relays: std.ArrayList(*Relay) = .empty,
    assocs: std.ArrayList(*Assoc) = .empty,
    retiring_packet_streams: @import("../packet_stream.zig").Retirements = .{},
    pending: [8]Pending = @splat(.{}),
    uni_pending: [8]UniPending = @splat(.{}),
    fragments: [max_fragment_entries]Fragment = @splat(.{}),
    resolving_assocs: [8]?u16 = @splat(null),
    datagram_buffer: []u8,
    inbox_storage: [inbox_capacity]Inbox = undefined,
    inbox: std.Io.Queue(Inbox) = undefined,

    fn create(
        pump: *Pump,
        handle: quic.endpoint_dispatcher.ConnectionHandle,
        established: *quic.handshake.EstablishedConnection,
        peer: net.IpAddress,
    ) !*Connection {
        const conn = try pump.allocator.create(Connection);
        errdefer pump.allocator.destroy(conn);
        const datagram_buffer = try pump.allocator.alloc(
            u8,
            pump.config.max_datagram_size,
        );
        errdefer pump.allocator.free(datagram_buffer);
        const now = nowNs(pump.io);
        conn.* = .{
            .pump = pump,
            .handle = handle,
            .established = established,
            .peer = peer,
            .created_ns = now,
            .last_activity_ns = now,
            .datagram_buffer = datagram_buffer,
        };
        conn.inbox = .init(&conn.inbox_storage);
        return conn;
    }

    fn retain(self: *Connection) *Connection {
        _ = self.refs.fetchAdd(1, .monotonic);
        return self;
    }

    fn release(self: *Connection) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        self.deinit();
    }

    fn deinit(self: *Connection) void {
        self.closed.store(true, .release);
        self.inbox.close(self.pump.io);
        while (true) {
            var batch: [inbox_capacity]Inbox = undefined;
            const count = self.inbox.get(self.pump.io, &batch, 0) catch break;
            if (count == 0) break;
            for (batch[0..count]) |command| freeInbox(
                self.pump.allocator,
                self.pump.io,
                command,
            );
        }
        for (self.relays.items) |relay| relay.deinit();
        self.relays.deinit(self.pump.allocator);
        for (self.assocs.items) |assoc| self.freeAssoc(assoc);
        self.assocs.deinit(self.pump.allocator);
        for (&self.fragments) |*fragment| {
            fragment.deinit(self.pump.allocator);
        }
        for (&self.pending) |*pending| pending.input.deinit(self.pump.allocator);
        for (&self.uni_pending) |*pending| pending.deinit(self.pump.allocator);
        self.pump.allocator.free(self.datagram_buffer);
        if (self.pump.config.stats) |value| value.connectionClosed();
        self.pump.limiter.release(self.peer);
        self.pump.allocator.destroy(self);
    }

    fn post(self: *Connection, command: Inbox) !void {
        return self.inbox.putOne(self.pump.io, command);
    }

    fn touch(self: *Connection) void {
        self.last_activity_ns = nowNs(self.pump.io);
    }

    fn drainInbox(self: *Connection) !void {
        while (true) {
            var batch: [inbox_capacity]Inbox = undefined;
            const count = self.inbox.get(self.pump.io, &batch, 0) catch break;
            if (count == 0) break;
            for (batch[0..count]) |command| {
                try self.applyInbox(command);
            }
        }
    }

    fn applyInbox(self: *Connection, command: Inbox) !void {
        switch (command) {
            .relay_ready => |ready| {
                const pending = self.pendingForId(ready.stream_id) orelse {
                    ready.tcp.close(self.pump.io);
                    return;
                };
                if (pending.connecting == false) {
                    ready.tcp.close(self.pump.io);
                    return;
                }
                if (self.relays.items.len >= self.pump.config.max_relays) {
                    ready.tcp.close(self.pump.io);
                    self.failPending(pending);
                    return;
                }
                self.relays.ensureUnusedCapacity(self.pump.allocator, 1) catch {
                    ready.tcp.close(self.pump.io);
                    self.failPending(pending);
                    return;
                };
                const relay = Relay.createWithOptions(
                    self.pump.allocator,
                    self.pump.io,
                    ready.tcp,
                    ready.stream_id,
                    .{
                        .idle_timeout = self.pump.config.idle_timeout,
                        .buffer_size = self.pump.config.relay_buffer_size,
                        .notify_context = self.pump,
                        .notify = Pump.notifyReady,
                    },
                ) catch {
                    ready.tcp.close(self.pump.io);
                    self.failPending(pending);
                    return;
                };
                self.relays.appendAssumeCapacity(relay);
                if (pending.input.len > pending.command_end) {
                    relay.queueInbound(
                        pending.input.bytes()[pending.command_end..pending.input.len],
                    ) catch {
                        relay.deinit();
                        _ = self.relays.pop();
                        self.failPending(pending);
                        return;
                    };
                }
                if (pending.fin) relay.quic_done.store(true, .release);
                pending.active = false;
                pending.input.deinit(self.pump.allocator);
                pending.connecting = false;
                pending.fin = false;
                self.touch();
            },
            .relay_failed => |failed| {
                if (self.pendingForId(failed.stream_id)) |pending| {
                    self.failPending(pending);
                }
            },
            .assoc_ready => |ready| {
                defer self.pump.allocator.free(ready.payload);
                self.clearResolving(ready.id);
                if (self.findAssoc(ready.id) != null) {
                    ready.socket.close(self.pump.io);
                    return;
                }
                if (self.assocs.items.len >= self.pump.config.max_assocs) {
                    ready.socket.close(self.pump.io);
                    return;
                }
                const assoc = self.createAssoc(
                    ready.id,
                    ready.socket,
                    ready.mode,
                ) catch {
                    ready.socket.close(self.pump.io);
                    return;
                };
                self.enqueueAssocPayload(assoc, .{ .ip = ready.resolved }, ready.payload);
            },
            .assoc_failed => |failed| {
                self.clearResolving(failed.id);
            },
        }
    }

    fn failPending(self: *Connection, pending: *Pending) void {
        const stream_id = pending.stream_id;
        const final_size: usize = 0;
        pending.active = false;
        pending.input.deinit(self.pump.allocator);
        pending.connecting = false;
        self.sendReset(stream_id, final_size);
    }

    fn sendReset(self: *Connection, stream_id: u64, final_size: usize) void {
        self.pump.shared.trySend(self.handle, &.{ .{
            .reset_stream = .{
                .stream_id = stream_id,
                .application_error_code = 0,
                .final_size = final_size,
            },
        }, .{ .stop_sending = .{
            .stream_id = stream_id,
            .application_error_code = 0,
        } } }) catch {};
    }

    fn pendingForId(self: *Connection, stream_id: u64) ?*Pending {
        for (&self.pending) |*pending| {
            if (pending.active and pending.stream_id == stream_id) return pending;
        }
        return null;
    }

    fn pendingSlot(self: *Connection, stream_id: u64) ?*Pending {
        if (self.pendingForId(stream_id)) |pending| return pending;
        for (&self.pending) |*pending| {
            if (!pending.active) {
                pending.input.deinit(self.pump.allocator);
                pending.* = .{ .stream_id = stream_id, .active = true };
                return pending;
            }
        }
        return null;
    }

    fn pollStreams(self: *Connection) !void {
        var buffer: [4096]u8 = undefined;
        while (true) {
            const event = self.pump.shared.pollStream(
                self.handle,
                &buffer,
            ) catch |err| switch (err) {
                error.UnknownConnectionHandle => {
                    self.closed.store(true, .release);
                    return;
                },
                else => return err,
            } orelse return;
            self.touch();
            switch (event) {
                .data => |data| {
                    const bytes = buffer[0..data.bytes];
                    if (protocol.isUnidirectional(data.stream_id)) {
                        try self.handleUniData(data.stream_id, bytes, data.fin);
                    } else {
                        try self.handleBidiData(data.stream_id, bytes, data.fin);
                    }
                },
                .reset => |reset| {
                    self.handleResetStream(reset.stream_id);
                },
            }
        }
    }

    fn handleBidiData(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) !void {
        if (self.findRelay(stream_id)) |relay| {
            relay.queueInbound(data) catch {
                relay.closed.store(true, .release);
                return;
            };
            if (fin) relay.quic_done.store(true, .release);
            relay.touch();
            // Submit the collected input batch when this service turn ends.
            return;
        }
        const pending = self.pendingSlot(stream_id) orelse
            return error.InvalidCommand;
        pending.input.append(self.pump.allocator, self.pump.config.max_pending_stream_bytes, data) catch {
            self.failPending(pending);
            return;
        };
        if (fin) pending.fin = true;
        if (!self.authenticated) return;
        if (pending.connecting) return;
        try self.tryConnect(pending);
    }

    fn tryConnect(self: *Connection, pending: *Pending) !void {
        const connect = protocol.parseConnect(
            pending.input.bytes()[0..pending.input.len],
        ) catch return;
        var target = switch (connect.address) {
            .none => {
                self.failPending(pending);
                return;
            },
            .ip => |ip| destination.Target{ .ip = ip },
            .domain => |domain| destination.Target{ .domain = .{
                .host = domain.host,
                .port = domain.port,
            } },
        };
        var host_copy: []u8 = &.{};
        if (target == .domain) {
            host_copy = self.pump.allocator.dupe(u8, target.domain.host) catch {
                self.failPending(pending);
                return;
            };
            target.domain.host = host_copy;
        }
        pending.command_end = connect.end;
        pending.connecting = true;
        const task = ConnectTask{
            .conn = self.retain(),
            .stream_id = pending.stream_id,
            .target = target,
            .host = host_copy,
        };
        if (!self.pump.postTask(.{ .connect = task })) {
            self.release();
            if (host_copy.len != 0) self.pump.allocator.free(host_copy);
            self.failPending(pending);
        }
    }

    fn handleUniData(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) !void {
        if (!self.authenticated) {
            const take = @min(
                self.auth_buffer.len - self.auth_used,
                data.len,
            );
            @memcpy(
                self.auth_buffer[self.auth_used..][0..take],
                data[0..take],
            );
            self.auth_used += take;
            if (self.auth_used < self.auth_buffer.len) return;
            self.verifyAuthentication() catch {
                self.closed.store(true, .release);
                return;
            };
            try self.resumePending();
            if (take < data.len) {
                try self.handleUniData(stream_id, data[take..], fin);
            }
            return;
        }
        const pending = self.uniPendingFor(stream_id) orelse {
            self.closed.store(true, .release);
            return;
        };
        try pending.append(self.pump.allocator, self.pump.config.max_datagram_size, data);
        const command_bytes = pending.input.bytes();

        var offset: usize = 0;
        while (offset + 2 <= command_bytes.len) {
            switch (command_bytes[offset + 1]) {
                @intFromEnum(protocol.CommandType.packet) => {
                    const parsed = protocol.parsePacket(
                        command_bytes[offset..command_bytes.len],
                    ) catch break;
                    self.handlePacket(parsed.packet, .uni);
                    offset += parsed.end;
                },
                @intFromEnum(protocol.CommandType.dissociate) => {
                    if (command_bytes.len - offset < 4) break;
                    const assoc_id = protocol.parseDissociate(
                        command_bytes[offset..][0..4],
                    ) catch break;
                    self.closeAssoc(assoc_id);
                    offset += 4;
                },
                @intFromEnum(protocol.CommandType.heartbeat) => {
                    offset += 2;
                },
                else => {
                    self.closed.store(true, .release);
                    return;
                },
            }
        }
        pending.consume(offset);
        try pending.finish(fin);
    }

    fn resumePending(self: *Connection) !void {
        for (&self.pending) |*pending| {
            if (!pending.active or pending.connecting) continue;
            try self.tryConnect(pending);
        }
    }

    fn verifyAuthentication(self: *Connection) !void {
        const auth = protocol.parseAuthenticate(
            self.auth_buffer[0..self.auth_used],
        ) catch return error.AuthenticationFailed;
        var difference: u8 = 0;
        for (auth.uuid, self.pump.config.uuid) |lhs, rhs| {
            difference |= lhs ^ rhs;
        }
        if (difference != 0) return error.AuthenticationFailed;
        var expected: [32]u8 = undefined;
        try self.established.exportKeyingMaterial(
            &auth.uuid,
            self.pump.config.password,
            &expected,
        );
        var token_difference: u8 = 0;
        for (auth.token, expected) |lhs, rhs| {
            token_difference |= lhs ^ rhs;
        }
        if (token_difference != 0) return error.AuthenticationFailed;
        self.authenticated = true;
    }

    fn drainDatagrams(self: *Connection) void {
        while (true) {
            const datagram = self.established.connection.popDatagram(
                self.datagram_buffer,
            ) catch return;
            const bytes = datagram orelse return;
            const parsed = protocol.parsePacket(bytes) catch continue;
            self.handlePacket(parsed.packet, .datagram);
        }
    }

    fn handlePacket(
        self: *Connection,
        packet: protocol.Packet,
        mode: Mode,
    ) void {
        if (packet.frag_total != 1) {
            self.handleFragment(packet, mode);
            return;
        }
        self.touch();
        const target: destination.Target = switch (packet.address) {
            .none => return,
            .ip => |ip| .{ .ip = ip },
            .domain => |domain| .{ .domain = .{
                .host = domain.host,
                .port = domain.port,
            } },
        };
        if (self.findAssoc(packet.assoc_id)) |assoc| {
            self.sendAssocPayload(assoc, packet, target);
            return;
        }
        switch (packet.address) {
            .ip => |ip| {
                const socket = bindAssoc(self.pump.io, ip) catch return;
                const assoc = self.createAssoc(
                    packet.assoc_id,
                    socket,
                    mode,
                ) catch {
                    socket.close(self.pump.io);
                    return;
                };
                self.sendAssocPayload(assoc, packet, target);
            },
            .domain => |domain| {
                if (!self.beginResolving(packet.assoc_id)) return;
                const host = self.pump.allocator.dupe(
                    u8,
                    domain.host,
                ) catch {
                    self.clearResolving(packet.assoc_id);
                    return;
                };
                const payload = self.pump.allocator.dupe(
                    u8,
                    packet.payload,
                ) catch {
                    self.pump.allocator.free(host);
                    self.clearResolving(packet.assoc_id);
                    return;
                };
                const task = AssocTask{
                    .conn = self.retain(),
                    .id = packet.assoc_id,
                    .mode = mode,
                    .host = host,
                    .port = domain.port,
                    .payload = payload,
                };
                if (!self.pump.postTask(.{ .assoc = task })) {
                    self.release();
                    self.pump.allocator.free(host);
                    self.pump.allocator.free(payload);
                    self.clearResolving(packet.assoc_id);
                }
            },
            .none => {},
        }
    }

    fn sendAssocPayload(
        self: *Connection,
        assoc: *Assoc,
        packet: protocol.Packet,
        target: destination.Target,
    ) void {
        self.enqueueAssocPayload(assoc, target, packet.payload);
    }

    fn enqueueAssocPayload(self: *Connection, assoc: *Assoc, target: destination.Target, payload: []const u8) void {
        if (assoc.closed) return;
        if (!(assoc.target_io.enqueue(target, payload) catch return)) return;
        assoc.last_activity_ns = nowNs(self.pump.io);
    }

    fn settleUdp(self: *Connection, result: UdpSession.Completion) void {
        if (self.pump.config.stats) |value| {
            value.addBytesIn(@intCast(result.committed_bytes));
        }
    }

    fn createAssoc(
        self: *Connection,
        id: u16,
        socket: net.Socket,
        mode: Mode,
    ) !*Assoc {
        if (self.assocs.items.len >= self.pump.config.max_assocs) return error.AssociationLimitReached;
        const assoc = try self.pump.allocator.create(Assoc);
        errdefer self.pump.allocator.destroy(assoc);
        assoc.* = .{
            .id = id,
            .socket = socket,
            .mode = mode,
            .last_activity_ns = nowNs(self.pump.io),
        };
        try assoc.target_io.init(self.pump.allocator, self.pump.io, socket, .{
            .maximum_datagram_bytes = self.pump.config.max_datagram_size,
            .resolve_timeout = self.pump.config.connect_timeout,
            .policy = self.pump.config.acl,
            .policy_store = self.pump.config.policy_store,
            .notify_context = self.pump,
            .notify = Pump.notifyReady,
        });
        errdefer assoc.target_io.deinit();
        try self.assocs.append(self.pump.allocator, assoc);
        return assoc;
    }

    fn serviceAssocs(self: *Connection, ready_only: bool) void {
        self.flushRetiringPacketStreams();
        for (self.assocs.items) |assoc| {
            if (assoc.closed) continue;
            const ready = assoc.target_io.ready.swap(false, .acq_rel);
            if (ready_only and !ready) continue;
            for (0..UdpSession.send_capacity) |_| {
                self.settleUdp(assoc.target_io.takeSent() orelse break);
            }
            self.flushAssocSends(assoc);
            for (0..UdpSession.receive_capacity) |_| {
                var message = assoc.target_io.takeReceived() orelse break;
                defer message.release();
                if (message.truncated) continue;
                const encoded = protocol.buildPacket(
                    self.pump.allocator,
                    .{
                        .assoc_id = assoc.id,
                        .pkt_id = assoc.next_pkt_id,
                        .frag_total = 1,
                        .frag_id = 0,
                        .address = .{ .ip = message.from },
                        .payload = message.bytes,
                    },
                ) catch continue;
                assoc.next_pkt_id +%= 1;
                self.queueAssocSend(assoc, encoded);
                assoc.last_activity_ns = nowNs(self.pump.io);
                self.touch();
            }
            self.flushAssocSends(assoc);
            if (assoc.target_io.receive_failed.load(.acquire) and !assoc.target_io.hasReceived()) {
                assoc.closed = true;
                continue;
            }
            const now = nowNs(self.pump.io);
            if (now - assoc.last_activity_ns >=
                self.pump.config.idle_timeout.nanoseconds)
            {
                assoc.closed = true;
            }
        }
    }

    fn queueAssocSend(self: *Connection, assoc: *Assoc, encoded: []u8) void {
        if (!assoc.pending_replies.enqueue(encoded)) self.pump.allocator.free(encoded);
    }

    fn flushAssocSends(self: *Connection, assoc: *Assoc) void {
        for (0..assoc_pending_sends) |_| {
            const encoded = assoc.pending_replies.peek() orelse break;
            const sent = self.sendAssocBytes(assoc, encoded) catch {
                assoc.packet_stream.beginCancel();
                self.pump.allocator.free(assoc.pending_replies.pop().?);
                continue;
            };
            if (!sent) return;
            self.pump.allocator.free(assoc.pending_replies.pop().?);
        }
    }

    fn sendAssocBytes(
        self: *Connection,
        assoc: *Assoc,
        encoded: []const u8,
    ) !bool {
        switch (assoc.mode) {
            .datagram => {
                self.established.connection.trySendDatagram(
                    encoded,
                ) catch |err| switch (err) {
                    error.CongestionLimited,
                    error.PacingLimited,
                    error.AntiAmplificationLimited,
                    => return false,
                    else => return err,
                };
                if (self.pump.config.stats) |value| {
                    value.addBytesOut(@intCast(encoded.len));
                }
                return true;
            },
            .uni => {
                defer self.pump.shared.dispatcher.refreshConnectionTimer(self.handle) catch {};
                var progress: @import("../packet_stream.zig").Progress = .{};
                const result = assoc.packet_stream.send(&self.established.connection, encoded, &progress);
                if (self.pump.config.stats) |value| value.addBytesOut(@intCast(progress.committed_bytes));
                if (progress.fin_committed) return true;
                result catch |err| switch (err) {
                    error.CongestionLimited,
                    error.PacingLimited,
                    error.FlowControlBlocked,
                    error.AntiAmplificationLimited,
                    error.StreamLimitExceeded,
                    => return false,
                    else => return err,
                };
                return false;
            },
        }
    }

    fn serviceRelays(self: *Connection, ready_only: bool) void {
        var index: usize = 0;
        while (index < self.relays.items.len) {
            const relay = self.relays.items[index];
            const ready = relay.ready.swap(false, .acq_rel);
            if (ready_only and !ready) {
                index += 1;
                continue;
            }
            relay.serviceInput();
            self.flushRelayOutbound(relay);
            if (relay.quic_done.load(.acquire) and
                relay.inputDrained())
            {
                relay.shutdownTcpSend();
            }
            if (relay.closed.load(.acquire) or relay.idle(nowNs(self.pump.io))) {
                relay.deinit();
                _ = self.relays.swapRemove(index);
                continue;
            }
            index += 1;
        }
    }

    fn flushRelayOutbound(self: *Connection, relay: *Relay) void {
        relay.flushOutbound(self, sendRelayItem);
    }

    fn sendRelayItem(
        self: *Connection,
        relay: *Relay,
        item: relay_mod.Outbound,
    ) relay_mod.SendResult {
        const remaining = switch (item) {
            .data => |bytes| bytes.len - relay.pending_data_start,
            .fin => 0,
        };
        var progress: stream_sender.Progress = .{};
        const established = self.pump.shared.connection(self.handle) orelse return .fatal;
        const result = stream_sender.send(quic, &established.connection, relay, item, remaining, &progress);
        self.pump.shared.dispatcher.refreshConnectionTimer(self.handle) catch return .fatal;
        result catch |err| switch (err) {
            error.CongestionLimited, error.PacingLimited, error.FlowControlBlocked, error.AntiAmplificationLimited => return .blocked,
            else => return .fatal,
        };
        return if (progress.complete) .complete else .progress;
    }

    fn findRelay(self: *Connection, stream_id: u64) ?*Relay {
        for (self.relays.items) |relay| {
            if (relay.stream_id == stream_id and
                !relay.closed.load(.acquire))
            {
                return relay;
            }
        }
        return null;
    }

    fn handleResetStream(self: *Connection, stream_id: u64) void {
        uni_input.cancelStream(&self.uni_pending, stream_id);
        self.closeRelayStream(stream_id);
        self.closeAssocForStream(stream_id);
    }

    fn closeRelayStream(self: *Connection, stream_id: u64) void {
        if (self.pendingForId(stream_id)) |pending| {
            pending.input.deinit(self.pump.allocator);
            pending.active = false;
            pending.connecting = false;
        }
        if (self.findRelay(stream_id)) |relay| {
            relay.closed.store(true, .release);
        }
    }

    fn findAssoc(self: *Connection, id: u16) ?*Assoc {
        for (self.assocs.items) |assoc| {
            if (assoc.id == id and !assoc.closed) return assoc;
        }
        return null;
    }

    fn closeAssocForStream(self: *Connection, stream_id: u64) void {
        for (self.assocs.items) |assoc| {
            if (assoc.packet_stream.stream_id == stream_id) {
                assoc.closed = true;
                return;
            }
        }
    }

    fn closeAssoc(self: *Connection, id: u16) void {
        if (self.findAssoc(id)) |assoc| assoc.closed = true;
    }

    fn beginResolving(self: *Connection, id: u16) bool {
        for (&self.resolving_assocs) |*slot| {
            if (slot.* == id) return false;
        }
        for (&self.resolving_assocs) |*slot| {
            if (slot.* == null) {
                slot.* = id;
                return true;
            }
        }
        return false;
    }

    fn clearResolving(self: *Connection, id: u16) void {
        for (&self.resolving_assocs) |*slot| {
            if (slot.* == id) slot.* = null;
        }
    }

    fn handleFragment(
        self: *Connection,
        packet: protocol.Packet,
        mode: Mode,
    ) void {
        if (packet.frag_total > max_fragments or
            packet.frag_id >= packet.frag_total)
        {
            return;
        }
        var slot: ?*Fragment = null;
        for (&self.fragments) |*fragment| {
            if (fragment.active and
                fragment.assoc_id == packet.assoc_id and
                fragment.pkt_id == packet.pkt_id)
            {
                slot = fragment;
                break;
            }
        }
        if (slot == null) {
            for (&self.fragments) |*fragment| {
                if (!fragment.active) {
                    slot = fragment;
                    break;
                }
            }
        }
        if (slot == null) {
            var oldest: *Fragment = &self.fragments[0];
            for (&self.fragments) |*fragment| {
                if (fragment.last_activity < oldest.last_activity) {
                    oldest = fragment;
                }
            }
            oldest.deinit(self.pump.allocator);
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
                .last_activity = nowNs(self.pump.io),
            };
        }
        if (fragment.frag_total != packet.frag_total or
            fragment.mode != mode)
        {
            fragment.deinit(self.pump.allocator);
            return;
        }
        if (fragment.parts[packet.frag_id] != null) return;
        if (fragment.total + packet.payload.len >
            self.pump.config.max_datagram_size)
        {
            fragment.deinit(self.pump.allocator);
            return;
        }
        const part = self.pump.allocator.dupe(
            u8,
            packet.payload,
        ) catch return;
        fragment.parts[packet.frag_id] = part;
        fragment.total += part.len;
        fragment.received |= @as(u16, 1) << @intCast(packet.frag_id);
        fragment.last_activity = nowNs(self.pump.io);

        const complete: u16 = if (packet.frag_total == 16)
            0xffff
        else
            (@as(u16, 1) << @intCast(packet.frag_total)) - 1;
        if (fragment.received != complete) return;

        const reassembled = self.pump.allocator.alloc(
            u8,
            fragment.total,
        ) catch {
            fragment.deinit(self.pump.allocator);
            return;
        };
        defer self.pump.allocator.free(reassembled);
        var offset: usize = 0;
        var index: usize = 0;
        while (index < packet.frag_total) : (index += 1) {
            const bytes = fragment.parts[index] orelse {
                fragment.deinit(self.pump.allocator);
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
        fragment.deinit(self.pump.allocator);
        self.handlePacket(complete_packet, mode);
    }

    fn cleanup(self: *Connection) void {
        const now = nowNs(self.pump.io);
        for (&self.fragments) |*fragment| {
            if (fragment.active and
                now - fragment.last_activity >= fragment_idle_ns)
            {
                fragment.deinit(self.pump.allocator);
            }
        }
        var index: usize = 0;
        while (index < self.assocs.items.len) {
            const assoc = self.assocs.items[index];
            if (assoc.closed) {
                self.freeAssoc(assoc);
                _ = self.assocs.swapRemove(index);
            } else {
                index += 1;
            }
        }
    }

    fn freeAssoc(self: *Connection, assoc: *Assoc) void {
        self.retirePacketStream(&assoc.packet_stream);
        assoc.target_io.stop();
        while (assoc.target_io.takeSent()) |result| self.settleUdp(result);
        assoc.target_io.deinit();
        assoc.socket.close(self.pump.io);
        assoc.pending_replies.deinit(self.pump.allocator);
        self.pump.allocator.destroy(assoc);
    }

    fn retirePacketStream(self: *Connection, stream: *PacketStream) void {
        if (stream.stream_id == null) return;
        if (!self.closed.load(.acquire) and self.retiring_packet_streams.add(stream)) return;
        self.closed.store(true, .release);
        stream.* = .{};
    }

    fn flushRetiringPacketStreams(self: *Connection) void {
        if (self.closed.load(.acquire) or self.retiring_packet_streams.count == 0) return;
        defer self.pump.shared.dispatcher.refreshConnectionTimer(self.handle) catch {};
        self.retiring_packet_streams.flush(&self.established.connection) catch |err| switch (err) {
            error.CongestionLimited, error.PacingLimited, error.AntiAmplificationLimited => {},
            else => self.closed.store(true, .release),
        };
    }

    fn checkTimeouts(self: *Connection) void {
        const now = nowNs(self.pump.io);
        if (!self.authenticated and
            now - self.created_ns >= self.pump.config.auth_timeout.nanoseconds)
        {
            self.closed.store(true, .release);
            return;
        }
        if (now - self.last_activity_ns >=
            self.pump.config.idle_timeout.nanoseconds)
        {
            self.closed.store(true, .release);
        }
    }

    fn uniPendingFor(
        self: *Connection,
        stream_id: u64,
    ) ?*UniPending {
        for (&self.uni_pending) |*pending| {
            if (pending.active and pending.stream_id == stream_id) {
                return pending;
            }
        }
        for (&self.uni_pending) |*pending| {
            if (!pending.active) {
                pending.start(stream_id);
                return pending;
            }
        }
        return null;
    }
};

const ConnectTask = struct {
    conn: *Connection,
    stream_id: u64,
    target: destination.Target,
    host: []u8 = &.{},

    fn execute(task: ConnectTask) void {
        defer task.conn.release();
        defer if (task.host.len != 0) task.conn.pump.allocator.free(task.host);
        const policy = reload.policyFor(
            task.conn.pump.config.acl,
            task.conn.pump.config.policy_store,
        );
        const tcp = destination.connectTarget(
            task.conn.pump.allocator,
            task.conn.pump.io,
            policy,
            task.target,
            .connect,
            task.conn.pump.config.connect_timeout,
        ) catch {
            task.conn.post(.{ .relay_failed = .{
                .stream_id = task.stream_id,
            } }) catch {};
            return;
        };
        task.conn.post(.{ .relay_ready = .{
            .stream_id = task.stream_id,
            .tcp = tcp,
        } }) catch {
            tcp.close(task.conn.pump.io);
        };
    }
};

const AssocTask = struct {
    conn: *Connection,
    id: u16,
    mode: Mode,
    host: []u8,
    port: u16,
    payload: []u8,

    fn execute(task: AssocTask) void {
        defer task.conn.release();
        defer task.conn.pump.allocator.free(task.host);
        defer task.conn.pump.allocator.free(task.payload);
        const policy = reload.policyFor(
            task.conn.pump.config.acl,
            task.conn.pump.config.policy_store,
        );
        const resolved = destination.resolveTarget(
            task.conn.pump.allocator,
            task.conn.pump.io,
            policy,
            .{ .domain = .{ .host = task.host, .port = task.port } },
            .udp_associate,
            task.conn.pump.config.connect_timeout,
        ) catch {
            task.conn.post(.{ .assoc_failed = .{ .id = task.id } }) catch {};
            return;
        };
        const socket = bindAssoc(task.conn.pump.io, resolved) catch {
            task.conn.post(.{ .assoc_failed = .{ .id = task.id } }) catch {};
            return;
        };
        const payload = task.conn.pump.allocator.dupe(
            u8,
            task.payload,
        ) catch {
            socket.close(task.conn.pump.io);
            task.conn.post(.{ .assoc_failed = .{ .id = task.id } }) catch {};
            return;
        };
        task.conn.post(.{ .assoc_ready = .{
            .id = task.id,
            .socket = socket,
            .resolved = resolved,
            .mode = task.mode,
            .payload = payload,
        } }) catch {
            socket.close(task.conn.pump.io);
            task.conn.pump.allocator.free(payload);
        };
    }
};

fn bindAssoc(io: std.Io, resolved: net.IpAddress) !net.Socket {
    const bind_address = switch (resolved) {
        .ip4 => net.IpAddress{ .ip4 = .unspecified(0) },
        .ip6 => net.IpAddress{ .ip6 = .unspecified(0) },
    };
    return bind_address.bind(io, .{ .mode = .dgram, .protocol = .udp });
}

fn freeInbox(
    allocator: std.mem.Allocator,
    io: std.Io,
    command: Inbox,
) void {
    switch (command) {
        .relay_ready => |ready| ready.tcp.close(io),
        .assoc_ready => |ready| {
            ready.socket.close(io);
            allocator.free(ready.payload);
        },
        .relay_failed, .assoc_failed => {},
    }
}

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
}

const max_datagram_size = 4096;

pub fn serve(server: anytype) !void {
    var pump = try Pump.init(
        server.allocator,
        server.io,
        &server.endpoint,
        server.config,
        &server.limiter,
        &server.running,
    );
    defer pump.deinit();
    try pump.startWorkers();
    return pump.run();
}

test "TUIC shared UDP uni packets release parser slots on FIN" {
    var running: std.atomic.Value(bool) = .init(true);
    var pump: Pump = .{ .allocator = std.testing.allocator, .io = undefined, .endpoint = undefined, .config = .{ .uuid = @splat(0), .password = "parser", .identity = undefined }, .limiter = undefined, .shared = undefined, .receive_storage = &.{}, .versions = .{ 1, 2 }, .stop_flag = &running };
    var connection: Connection = .{
        .pump = &pump,
        .handle = 1,
        .established = undefined,
        .peer = .{ .ip4 = .loopback(1) },
        .created_ns = 0,
        .last_activity_ns = 0,
        .authenticated = true,
        .datagram_buffer = &.{},
    };
    defer for (&connection.uni_pending) |*pending| pending.deinit(std.testing.allocator);
    const heartbeat = [_]u8{ protocol.version, @intFromEnum(protocol.CommandType.heartbeat) };
    for (0..128) |index| {
        const stream_id: u64 = 2 + 4 * index;
        try connection.handleUniData(stream_id, heartbeat[0..1], false);
        var active: usize = 0;
        for (&connection.uni_pending) |*pending| active += @intFromBool(pending.active);
        try std.testing.expectEqual(@as(usize, 1), active);
        try connection.handleUniData(stream_id, heartbeat[1..], true);
        for (&connection.uni_pending) |*pending| try std.testing.expect(!pending.active and pending.input.len == 0);
    }
    try std.testing.expectError(error.InvalidCommand, connection.handleUniData(1026, heartbeat[0..1], true));
    for (&connection.uni_pending) |*pending| try std.testing.expect(!pending.active and pending.input.len == 0);
}

test "TUIC shared UDP uni reset returns parser slot and retains allocation" {
    const Case = struct {
        fn run(io: std.Io) !void {
            var running: std.atomic.Value(bool) = .init(true);
            var pump: Pump = .{ .allocator = std.testing.allocator, .io = undefined, .endpoint = undefined, .config = .{ .uuid = @splat(0), .password = "parser", .identity = undefined }, .limiter = undefined, .shared = undefined, .receive_storage = &.{}, .versions = .{ 1, 2 }, .stop_flag = &running };
            var connection: Connection = .{ .pump = &pump, .handle = 1, .established = undefined, .peer = .{ .ip4 = .loopback(1) }, .created_ns = 0, .last_activity_ns = 0, .authenticated = true, .datagram_buffer = &.{} };
            defer for (&connection.uni_pending) |*pending| pending.deinit(std.testing.allocator);
            try @import("../uni_reset_tests.zig").exercise(io, &connection, &pump.allocator, Connection.handleUniData, Connection.handleResetStream);
        }
    };
    try @import("../../../internal/testing/native_protocol_io.zig").run(Case.run);
}

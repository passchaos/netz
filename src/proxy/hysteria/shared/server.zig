//! Hysteria v3 server driven by the shared QUIC endpoint owner.
//!
//! The pump owns the UDP socket and every established connection. Blocking
//! destination connects run on bounded worker threads; TCP reads publish
//! through bounded queues and TCP writes use short partial-write turns. This
//! removes the single-socket receive contention of the older per-connection
//! blocking loop.

const std = @import("std");
const net = std.Io.net;

const netz = @import("../../netz.zig");
const protocol = @import("../v3_protocol.zig");
const Config = @import("../config.zig").Config;
const limits = @import("../../runtime/limits.zig");
const reload = @import("../../runtime/reload.zig");
const destination = @import("../../runtime/destination.zig");
const byte_bucket = @import("../../internal/byte_bucket.zig");
const relay_mod = @import("../../internal/relay_queue.zig");
const pending_input = @import("../../internal/relay_queue/pending_input.zig");
const stream_sender = @import("../../internal/relay_queue/stream_send.zig");

const quic = netz.quic;
const Relay = relay_mod.Relay;

const max_events = 32;
const max_fragments: u8 = 16;
const max_fragment_entries = 64;
const fragment_idle_ns: i64 = 5 * std.time.ns_per_s;
const inbox_capacity = 16;
const assoc_pending_sends = 8;

const Pending = struct {
    stream_id: u64 = 0,
    input: pending_input.Buffer = .{},
    active: bool = false,
    connecting: bool = false,
    command_end: usize = 0,
    fin: bool = false,
    request_type: protocol.RequestType = .tcp,
    host_start: usize = 0,
    host_len: usize = 0,
    port: u16 = 0,
    response_len: usize = 0,
    response_sent: bool = false,
    session_id: u32 = 0,
};

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

const Assoc = struct {
    id: u32,
    stream_id: u64,
    socket: net.Socket,
    next_msg_id: u16 = 0,
    last_activity_ns: i64,
    closed: bool = false,
    pending_sends: [assoc_pending_sends]?[]u8 = @splat(null),
};

const Inbox = union(enum) {
    relay_ready: struct { stream_id: u64, tcp: net.Stream },
    relay_failed: struct { stream_id: u64 },
};

const Task = struct {
    conn: *Connection,
    stream_id: u64,
    target: destination.Target,
    host: []u8 = &.{},

    fn execute(task: Task) void {
        defer task.conn.release();
        defer if (task.host.len != 0) {
            task.conn.pump.allocator.free(task.host);
        };
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
            task.execute();
        }
    }

    fn notifyReady(context: ?*anyopaque) void {
        const self: *Pump = @ptrCast(@alignCast(context.?));
        self.ready.store(true, .release);
    }

    fn serviceReadyRelays(self: *Pump) void {
        for (self.connections.items) |conn| conn.serviceRelays(true);
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
        _ = conn.flushControlResponse();
        conn.resumePending();
        try conn.pollStreams();
        conn.drainDatagrams();
        conn.serviceAssocs();
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
    control_stream: u64 = 0,
    hello_buffer: [512]u8 = undefined,
    hello_used: usize = 0,
    control_response: ?[]u8 = null,
    next_session_id: u32 = 1,
    send_bucket: byte_bucket.ByteBucket,
    recv_bucket: byte_bucket.ByteBucket,
    relays: std.ArrayList(*Relay) = .empty,
    assocs: std.ArrayList(*Assoc) = .empty,
    pending: [8]Pending = @splat(.{}),
    fragments: [max_fragment_entries]Fragment = @splat(.{}),
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
            .send_bucket = byte_bucket.ByteBucket.initWithBurst(
                pump.config.send_bps,
                pump.config.rate_burst_bytes,
                now,
            ),
            .recv_bucket = byte_bucket.ByteBucket.initWithBurst(
                pump.config.recv_bps,
                pump.config.rate_burst_bytes,
                now,
            ),
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
                self.pump.io,
                command,
            );
        }
        if (self.control_response) |response| {
            self.pump.allocator.free(response);
        }
        for (self.relays.items) |relay| self.destroyRelay(relay);
        self.relays.deinit(self.pump.allocator);
        for (self.assocs.items) |assoc| self.freeAssoc(assoc);
        self.assocs.deinit(self.pump.allocator);
        for (&self.fragments) |*fragment| {
            fragment.deinit(self.pump.allocator);
        }
        for (&self.pending) |*pending| pending.input.deinit(self.pump.allocator);
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
                if (!pending.connecting or !pending.response_sent) {
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
                relay.send_offset = pending.response_len;
                self.relays.appendAssumeCapacity(relay);
                if (pending.input.len > pending.command_end) {
                    relay.queueInbound(
                        pending.input.bytes()[pending.command_end..pending.input.len],
                    ) catch {
                        self.destroyRelay(relay);
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
        }
    }

    fn failPending(self: *Connection, pending: *Pending) void {
        const stream_id = pending.stream_id;
        const final_size = pending.response_len;
        pending.active = false;
        pending.input.deinit(self.pump.allocator);
        pending.connecting = false;
        pending.fin = false;
        pending.response_sent = false;
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
                    if (protocol_isUni(data.stream_id)) continue;
                    try self.handleDataStream(
                        data.stream_id,
                        buffer[0..data.bytes],
                        data.fin,
                    );
                },
                .reset => |reset| {
                    self.closeRelayStream(reset.stream_id);
                    self.closeAssocForStream(reset.stream_id);
                },
            }
        }
    }

    fn handleDataStream(
        self: *Connection,
        stream_id: u64,
        data: []const u8,
        fin: bool,
    ) !void {
        if (self.authenticated and stream_id == self.control_stream) return;
        if (self.findRelay(stream_id)) |relay| {
            if (data.len != 0) {
                relay.queueInbound(data) catch {
                    relay.closed.store(true, .release);
                    return;
                };
            }
            if (fin) relay.quic_done.store(true, .release);
            relay.touch();
            return;
        }
        if (self.findAssocByStream(stream_id)) |assoc| {
            if (fin) assoc.closed = true;
            return;
        }
        if (!self.authenticated) {
            if (self.control_stream == 0) self.control_stream = stream_id;
            if (stream_id != self.control_stream) return;
            if (self.hello_used + data.len > self.hello_buffer.len) {
                self.closed.store(true, .release);
                return;
            }
            @memcpy(
                self.hello_buffer[self.hello_used..][0..data.len],
                data,
            );
            self.hello_used += data.len;
            try self.tryAuthenticate();
            return;
        }
        const pending = self.pendingSlot(stream_id) orelse
            return error.InvalidRequest;
        pending.input.append(self.pump.allocator, self.pump.config.max_pending_stream_bytes, data) catch {
            self.failPending(pending);
            return;
        };
        if (fin) pending.fin = true;
        if (pending.connecting or pending.response_sent) return;
        self.tryStartPending(pending);
    }

    fn tryAuthenticate(self: *Connection) !void {
        const hello = protocol.parseClientHello(
            self.hello_buffer[0..self.hello_used],
        ) catch |err| switch (err) {
            error.Incomplete => return,
            else => {
                self.closed.store(true, .release);
                return;
            },
        };
        if (!authMatches(hello.auth, self.pump.config.password)) {
            if (self.pump.config.stats) |value| value.authFailure();
            self.closed.store(true, .release);
            return;
        }
        const send_bps = negotiateRate(
            self.pump.config.send_bps,
            hello.recv_bps,
        );
        const recv_bps = negotiateRate(
            self.pump.config.recv_bps,
            hello.send_bps,
        );
        const now = nowNs(self.pump.io);
        self.send_bucket = byte_bucket.ByteBucket.initWithBurst(send_bps, self.pump.config.rate_burst_bytes, now);
        self.recv_bucket = byte_bucket.ByteBucket.initWithBurst(recv_bps, self.pump.config.rate_burst_bytes, now);
        self.control_response = try protocol.buildServerHello(
            self.pump.allocator,
            true,
            send_bps,
            recv_bps,
            "",
        );
        self.authenticated = true;
    }

    fn resumePending(self: *Connection) void {
        for (&self.pending) |*pending| {
            if (!pending.active or pending.connecting or
                pending.response_sent) continue;
            self.tryStartPending(pending);
        }
    }

    fn flushControlResponse(self: *Connection) bool {
        const response = self.control_response orelse return true;
        self.pump.shared.trySend(self.handle, &.{.{
            .stream = .{
                .stream_id = self.control_stream,
                .offset = 0,
                .data = response,
                .fin = false,
            },
        }}) catch |err| switch (err) {
            error.CongestionLimited,
            error.PacingLimited,
            error.FlowControlBlocked,
            error.AntiAmplificationLimited,
            => return false,
            else => {
                self.pump.allocator.free(response);
                self.control_response = null;
                self.closed.store(true, .release);
                return true;
            },
        };
        self.pump.allocator.free(response);
        self.control_response = null;
        return true;
    }

    fn tryStartPending(self: *Connection, pending: *Pending) void {
        const request = protocol.parseRequest(
            pending.input.bytes()[0..pending.input.len],
        ) catch |err| switch (err) {
            error.Incomplete => return,
            else => {
                self.failPending(pending);
                return;
            },
        };
        pending.request_type = request.request_type;
        pending.host_start = 3;
        pending.host_len = request.host.len;
        pending.port = request.port;
        pending.command_end = 3 + request.host.len + 2;

        if (!pending.response_sent) {
            const session_id: u32 = if (request.request_type == .udp) blk: {
                const id = self.next_session_id;
                self.next_session_id +%= 1;
                if (self.next_session_id == 0) self.next_session_id = 1;
                break :blk id;
            } else 0;
            const response = protocol.buildResponse(
                self.pump.allocator,
                true,
                session_id,
                "",
            ) catch {
                self.failPending(pending);
                return;
            };
            defer self.pump.allocator.free(response);
            self.pump.shared.trySend(self.handle, &.{.{
                .stream = .{
                    .stream_id = pending.stream_id,
                    .offset = 0,
                    .data = response,
                    .fin = false,
                },
            }}) catch |err| switch (err) {
                error.CongestionLimited,
                error.PacingLimited,
                error.FlowControlBlocked,
                error.AntiAmplificationLimited,
                => return,
                else => {
                    self.failPending(pending);
                    return;
                },
            };
            pending.response_len = response.len;
            pending.response_sent = true;
            pending.session_id = session_id;
        }

        if (pending.request_type == .udp) {
            if (self.assocs.items.len >= self.pump.config.max_assocs) {
                self.failPending(pending);
                return;
            }
            const socket = bindAssoc(self.pump.io) catch {
                self.failPending(pending);
                return;
            };
            const assoc = self.pump.allocator.create(Assoc) catch {
                socket.close(self.pump.io);
                self.failPending(pending);
                return;
            };
            assoc.* = .{
                .id = pending.session_id,
                .stream_id = pending.stream_id,
                .socket = socket,
                .last_activity_ns = nowNs(self.pump.io),
            };
            self.assocs.append(self.pump.allocator, assoc) catch {
                socket.close(self.pump.io);
                self.pump.allocator.destroy(assoc);
                self.failPending(pending);
                return;
            };
            if (pending.fin) assoc.closed = true;
            pending.active = false;
            pending.input.deinit(self.pump.allocator);
            pending.fin = false;
            self.touch();
            return;
        }

        if (self.relays.items.len >= self.pump.config.max_relays) {
            self.failPending(pending);
            return;
        }
        const host = pending.input.bytes()[pending.host_start..][0..pending.host_len];
        const target = parseTarget(host, pending.port) orelse {
            self.failPending(pending);
            return;
        };
        var host_copy: []u8 = &.{};
        const owned_target: destination.Target = switch (target) {
            .ip => target,
            .domain => blk: {
                host_copy = self.pump.allocator.dupe(u8, host) catch {
                    self.failPending(pending);
                    return;
                };
                break :blk .{ .domain = .{
                    .host = host_copy,
                    .port = pending.port,
                } };
            },
        };
        pending.connecting = true;
        const task = Task{
            .conn = self.retain(),
            .stream_id = pending.stream_id,
            .target = owned_target,
            .host = host_copy,
        };
        if (!self.pump.postTask(task)) {
            self.release();
            if (host_copy.len != 0) {
                self.pump.allocator.free(host_copy);
            }
            self.failPending(pending);
        }
    }

    fn drainDatagrams(self: *Connection) void {
        while (true) {
            const datagram = self.established.connection.popDatagram(
                self.datagram_buffer,
            ) catch return;
            const bytes = datagram orelse return;
            const message = protocol.parseUdpMessage(bytes) catch continue;
            self.handleUdpMessage(message);
        }
    }

    fn handleUdpMessage(
        self: *Connection,
        message: protocol.UdpMessage,
    ) void {
        if (message.frag_count == 1) {
            self.forwardUdp(
                message.session_id,
                message.host,
                message.port,
                message.data,
            );
            return;
        }
        self.handleFragment(message);
    }

    fn handleFragment(
        self: *Connection,
        message: protocol.UdpMessage,
    ) void {
        if (message.frag_count > max_fragments or
            message.frag_id >= message.frag_count)
        {
            return;
        }
        var slot: ?*Fragment = null;
        for (&self.fragments) |*fragment| {
            if (fragment.active and
                fragment.session_id == message.session_id and
                fragment.msg_id == message.msg_id)
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
                .session_id = message.session_id,
                .msg_id = message.msg_id,
                .frag_count = message.frag_count,
                .last_activity = nowNs(self.pump.io),
            };
        }
        if (fragment.frag_count != message.frag_count) {
            fragment.deinit(self.pump.allocator);
            return;
        }
        if (fragment.parts[message.frag_id] != null) return;
        if (fragment.total + message.data.len >
            self.pump.config.max_datagram_size)
        {
            fragment.deinit(self.pump.allocator);
            return;
        }
        const part = self.pump.allocator.dupe(
            u8,
            message.data,
        ) catch return;
        fragment.parts[message.frag_id] = part;
        fragment.total += part.len;
        fragment.received |= @as(u16, 1) << @intCast(message.frag_id);
        fragment.last_activity = nowNs(self.pump.io);

        const complete: u16 = if (message.frag_count == 16)
            0xffff
        else
            (@as(u16, 1) << @intCast(message.frag_count)) - 1;
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
        while (index < message.frag_count) : (index += 1) {
            const bytes = fragment.parts[index] orelse {
                fragment.deinit(self.pump.allocator);
                return;
            };
            @memcpy(reassembled[offset..][0..bytes.len], bytes);
            offset += bytes.len;
        }
        const session_id = fragment.session_id;
        const host_copy = self.pump.allocator.dupe(
            u8,
            message.host,
        ) catch {
            fragment.deinit(self.pump.allocator);
            return;
        };
        defer self.pump.allocator.free(host_copy);
        const port = message.port;
        fragment.deinit(self.pump.allocator);
        self.forwardUdp(session_id, host_copy, port, reassembled);
    }

    fn forwardUdp(
        self: *Connection,
        session_id: u32,
        host: []const u8,
        port: u16,
        data: []const u8,
    ) void {
        const assoc = self.findAssoc(session_id) orelse return;
        const target = parseTarget(host, port) orelse return;
        const now = nowNs(self.pump.io);
        if (self.recv_bucket.available(data.len, now) != data.len) return;
        const resolved = switch (target) {
            .ip => |ip| ip,
            .domain => |domain| destination.resolveTarget(
                self.pump.allocator,
                self.pump.io,
                reload.policyFor(
                    self.pump.config.acl,
                    self.pump.config.policy_store,
                ),
                .{ .domain = domain },
                .udp_associate,
                self.pump.config.connect_timeout,
            ) catch return,
        };
        assoc.socket.send(self.pump.io, &resolved, data) catch return;
        const charged = self.recv_bucket.tryConsume(data.len, now);
        std.debug.assert(charged);
        if (self.pump.config.stats) |value| {
            value.addBytesIn(@intCast(data.len));
        }
        assoc.last_activity_ns = nowNs(self.pump.io);
    }

    fn serviceAssocs(self: *Connection) void {
        for (self.assocs.items) |assoc| {
            if (assoc.closed) continue;
            self.flushAssocSends(assoc);
            while (true) {
                const message = assoc.socket.receiveTimeout(
                    self.pump.io,
                    self.datagram_buffer,
                    .{ .duration = .{
                        .clock = .awake,
                        .raw = .fromMilliseconds(1),
                    } },
                ) catch |err| switch (err) {
                    error.Timeout => break,
                    else => {
                        assoc.closed = true;
                        break;
                    },
                };
                if (message.flags.trunc) continue;
                var host_buffer: [64]u8 = undefined;
                const host = std.fmt.bufPrint(
                    &host_buffer,
                    "{}",
                    .{message.from},
                ) catch continue;
                const encoded = protocol.buildUdpMessage(
                    self.pump.allocator,
                    assoc.id,
                    host,
                    message.from.getPort(),
                    assoc.next_msg_id,
                    0,
                    1,
                    message.data,
                ) catch continue;
                assoc.next_msg_id +%= 1;
                self.queueAssocSend(assoc, encoded);
                assoc.last_activity_ns = nowNs(self.pump.io);
                self.touch();
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
        for (&assoc.pending_sends) |*slot| {
            if (slot.* != null) continue;
            slot.* = encoded;
            self.flushAssocSends(assoc);
            return;
        }
        self.pump.allocator.free(encoded);
    }

    fn flushAssocSends(self: *Connection, assoc: *Assoc) void {
        for (&assoc.pending_sends) |*slot| {
            const encoded = slot.* orelse continue;
            if (encoded.len > self.pump.config.max_datagram_size or
                (self.send_bucket.rate != 0 and encoded.len > self.send_bucket.capacity))
            {
                self.pump.allocator.free(encoded);
                slot.* = null;
                continue;
            }
            const now = nowNs(self.pump.io);
            if (self.send_bucket.available(encoded.len, now) != encoded.len) return;
            self.established.connection.trySendDatagram(
                encoded,
            ) catch |err| switch (err) {
                error.CongestionLimited,
                error.PacingLimited,
                error.AntiAmplificationLimited,
                => return,
                else => {
                    self.pump.allocator.free(encoded);
                    slot.* = null;
                    continue;
                },
            };
            const charged = self.send_bucket.tryConsume(encoded.len, now);
            std.debug.assert(charged);
            if (self.pump.config.stats) |value| {
                value.addBytesOut(@intCast(encoded.len));
            }
            self.pump.allocator.free(encoded);
            slot.* = null;
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
            if (relay.takeInputCompletion()) |result| self.settleInput(result);
            const pending_bytes = relay.readyInboundBytes();
            const now = nowNs(self.pump.io);
            const allowed = self.recv_bucket.available(pending_bytes, now);
            // Charge the reservation before the writer can commit bytes.
            const charged = self.recv_bucket.tryConsume(allowed, now);
            std.debug.assert(charged);
            const submitted = relay.submitInput(@intCast(allowed));
            std.debug.assert(submitted <= allowed);
            self.recv_bucket.refund(allowed - submitted);
            self.flushRelayOutbound(relay);
            if (relay.quic_done.load(.acquire) and
                relay.inputDrained())
            {
                relay.shutdownTcpSend();
            }
            if (relay.closed.load(.acquire) or
                relay.idle(nowNs(self.pump.io)))
            {
                self.destroyRelay(relay);
                _ = self.relays.swapRemove(index);
                continue;
            }
            index += 1;
        }
    }

    fn settleInput(self: *Connection, result: Relay.InputCompletion) void {
        std.debug.assert(result.committed_bytes <= result.reserved_bytes);
        self.recv_bucket.refund(result.reserved_bytes - result.committed_bytes);
    }

    fn destroyRelay(self: *Connection, relay: *Relay) void {
        if (relay.stopInput()) |result| self.settleInput(result);
        relay.deinit();
    }

    fn flushRelayOutbound(self: *Connection, relay: *Relay) void {
        relay.flushOutbound(self, sendRelayItem);
    }

    fn sendRelayItem(
        self: *Connection,
        relay: *Relay,
        item: relay_mod.Outbound,
    ) relay_mod.SendResult {
        const now = nowNs(self.pump.io);
        const remaining = switch (item) {
            .data => |bytes| bytes.len - relay.pending_data_start,
            .fin => 0,
        };
        const allowed = @as(usize, @intCast(self.send_bucket.available(remaining, now)));
        if (remaining != 0 and allowed == 0) return .blocked;
        var progress: stream_sender.Progress = .{};
        const established = self.pump.shared.connection(self.handle) orelse return .fatal;
        const result = stream_sender.send(quic, &established.connection, relay, item, allowed, &progress);
        const charged = self.send_bucket.tryConsume(progress.committed_bytes, now);
        std.debug.assert(charged);
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

    fn findAssoc(self: *Connection, id: u32) ?*Assoc {
        for (self.assocs.items) |assoc| {
            if (assoc.id == id and !assoc.closed) return assoc;
        }
        return null;
    }

    fn findAssocByStream(self: *Connection, stream_id: u64) ?*Assoc {
        for (self.assocs.items) |assoc| {
            if (assoc.stream_id == stream_id and !assoc.closed) {
                return assoc;
            }
        }
        return null;
    }

    fn closeAssocForStream(self: *Connection, stream_id: u64) void {
        if (self.findAssocByStream(stream_id)) |assoc| assoc.closed = true;
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
        assoc.socket.close(self.pump.io);
        for (&assoc.pending_sends) |*slot| {
            if (slot.*) |bytes| self.pump.allocator.free(bytes);
            slot.* = null;
        }
        self.pump.allocator.destroy(assoc);
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
};

fn bindAssoc(io: std.Io) !net.Socket {
    return (net.IpAddress{ .ip4 = .unspecified(0) }).bind(
        io,
        .{ .mode = .dgram, .protocol = .udp },
    );
}

fn freeInbox(io: std.Io, command: Inbox) void {
    switch (command) {
        .relay_ready => |ready| ready.tcp.close(io),
        .relay_failed => {},
    }
}

fn parseTarget(host: []const u8, port: u16) ?destination.Target {
    if (net.IpAddress.parse(host, port)) |ip| {
        return .{ .ip = ip };
    } else |_| {}
    _ = net.HostName.init(host) catch return null;
    return .{ .domain = .{ .host = host, .port = port } };
}

fn protocol_isUni(stream_id: u64) bool {
    return (stream_id & 0x2) != 0;
}

fn negotiateRate(server_rate: u64, client_rate: u64) u64 {
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

fn nowNs(io: std.Io) i64 {
    return @intCast(std.Io.Timestamp.now(io, .awake).nanoseconds);
}

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

test "Hysteria shared target loans reserve refund and retire exact receive credit" {
    try @import("input_tests.zig").run(Pump, Connection, Connection.serviceRelays, Connection.settleInput, Connection.destroyRelay, Pump.notifyReady);
}

//! Server-side `grpc.channelz.v1` registry, counters and wire codec.
//!
//! Applications register top-level channels and servers with a `Registry`,
//! update the atomic counters from their call path, and dispatch unary
//! Channelz requests through `Registry.handle`. The registry owns every
//! encoded name/target and remains valid until `deinit`.
//!
//! The implemented surface covers `GetTopChannels`, `GetServers`, `GetServer`,
//! `GetServerSockets`, `GetChannel`, `GetSubchannel` and `GetSocket`. Socket
//! and subchannel inventories are intentionally empty because this library
//! does not expose a stable socket/subchannel object model; `GetSubchannel`
//! and `GetSocket` report `NotFound`. Channel traces are omitted.

const std = @import("std");
const pb = @import("protobuf.zig");
const runtime = @import("runtime.zig");
const call = @import("call.zig");
const wire = @import("wire.zig");
const http2 = @import("../http2/mod.zig");
const observability = @import("observability.zig");

pub const service = "grpc.channelz.v1.Channelz";
pub const get_top_channels_path = "/grpc.channelz.v1.Channelz/GetTopChannels";
pub const get_servers_path = "/grpc.channelz.v1.Channelz/GetServers";
pub const get_server_path = "/grpc.channelz.v1.Channelz/GetServer";
pub const get_server_sockets_path = "/grpc.channelz.v1.Channelz/GetServerSockets";
pub const get_channel_path = "/grpc.channelz.v1.Channelz/GetChannel";
pub const get_subchannel_path = "/grpc.channelz.v1.Channelz/GetSubchannel";
pub const get_socket_path = "/grpc.channelz.v1.Channelz/GetSocket";

pub const Error = std.mem.Allocator.Error || pb.Error || error{
    InvalidRequest,
    NotFound,
    Unimplemented,
};
pub const ServeError = Error || runtime.Error;

pub const ConnectivityState = enum(u32) {
    unknown = 0,
    idle = 1,
    connecting = 2,
    ready = 3,
    transient_failure = 4,
    shutdown = 5,
};

pub const default_page_size: usize = 100;
pub const max_page_size: usize = 1000;
pub const max_trace_events: usize = 16;

pub const TraceSeverity = enum(u32) {
    unknown = 0,
    info = 1,
    warning = 2,
    @"error" = 3,
};

const TraceEvent = struct {
    description: []const u8,
    severity: TraceSeverity,
    timestamp_ns: i64,
};

const TraceRing = struct {
    events: [max_trace_events]TraceEvent = undefined,
    start: usize = 0,
    count: usize = 0,
    total: u64 = 0,
    creation_ns: i64,

    fn init(io: std.Io) TraceRing {
        const now = std.Io.Timestamp.now(io, .real).toNanoseconds();
        return .{ .creation_ns = @intCast(now) };
    }

    fn deinit(self: *TraceRing, allocator: std.mem.Allocator) void {
        var index: usize = 0;
        while (index < self.count) : (index += 1) {
            allocator.free(self.events[(self.start + index) % max_trace_events].description);
        }
        self.* = undefined;
    }

    fn add(
        self: *TraceRing,
        allocator: std.mem.Allocator,
        io: std.Io,
        description: []const u8,
        severity: TraceSeverity,
    ) !void {
        const owned = try allocator.dupe(u8, description);
        errdefer allocator.free(owned);
        const now: i64 = @intCast(std.Io.Timestamp.now(io, .real).toNanoseconds());
        if (self.count == max_trace_events) {
            allocator.free(self.events[self.start].description);
            self.events[self.start] = .{
                .description = owned,
                .severity = severity,
                .timestamp_ns = now,
            };
            self.start = (self.start + 1) % max_trace_events;
        } else {
            self.events[(self.start + self.count) % max_trace_events] = .{
                .description = owned,
                .severity = severity,
                .timestamp_ns = now,
            };
            self.count += 1;
        }
        self.total +%= 1;
    }
};

/// One top-level channel. Counters are updated lock-free; `name` and `target`
/// are immutable after registration.
pub const Channel = struct {
    registry: *Registry,
    id: i64,
    name: []const u8,
    target: []const u8,
    state: std.atomic.Value(u32),
    calls_started: std.atomic.Value(i64) = .init(0),
    calls_succeeded: std.atomic.Value(i64) = .init(0),
    calls_failed: std.atomic.Value(i64) = .init(0),
    last_call_started_ns: std.atomic.Value(i64) = .init(0),
    trace: TraceRing,
    subchannels: std.ArrayList(i64) = .empty,

    pub fn setState(self: *Channel, state: ConnectivityState) void {
        self.state.store(@intFromEnum(state), .release);
    }

    pub fn addTrace(
        self: *Channel,
        description: []const u8,
        severity: TraceSeverity,
    ) Error!void {
        self.registry.mutex.lockUncancelable(self.registry.io);
        defer self.registry.mutex.unlock(self.registry.io);
        try self.trace.add(
            self.registry.allocator,
            self.registry.io,
            description,
            severity,
        );
    }

    pub fn addSubchannel(self: *Channel, subchannel: *Subchannel) Error!void {
        if (subchannel.registry != self.registry) return error.InvalidRequest;
        self.registry.mutex.lockUncancelable(self.registry.io);
        defer self.registry.mutex.unlock(self.registry.io);
        var index = self.subchannels.items.len;
        while (index != 0 and self.subchannels.items[index - 1] > subchannel.id) index -= 1;
        try self.subchannels.insert(self.registry.allocator, index, subchannel.id);
    }

    pub fn callStarted(self: *Channel) void {
        _ = self.calls_started.fetchAdd(1, .monotonic);
        const now = std.Io.Timestamp.now(self.registry.io, .real).toNanoseconds();
        self.last_call_started_ns.store(@intCast(now), .release);
    }

    pub fn callSucceeded(self: *Channel) void {
        _ = self.calls_succeeded.fetchAdd(1, .monotonic);
    }

    pub fn callFailed(self: *Channel) void {
        _ = self.calls_failed.fetchAdd(1, .monotonic);
    }

    /// Allocation-free observer for `grpc.runtime.Client.setObserver`.
    pub fn observer(self: *Channel) observability.ServerObserver {
        return .{
            .context = self,
            .call_started_fn = observerStarted,
            .call_succeeded_fn = observerSucceeded,
            .call_failed_fn = observerFailed,
        };
    }

    fn observerStarted(context: *anyopaque) void {
        const self: *Channel = @ptrCast(@alignCast(context));
        self.callStarted();
    }

    fn observerSucceeded(context: *anyopaque) void {
        const self: *Channel = @ptrCast(@alignCast(context));
        self.callSucceeded();
    }

    fn observerFailed(context: *anyopaque) void {
        const self: *Channel = @ptrCast(@alignCast(context));
        self.callFailed();
    }

    fn destroy(self: *Channel, allocator: std.mem.Allocator) void {
        self.subchannels.deinit(allocator);
        self.trace.deinit(allocator);
        allocator.free(self.name);
        allocator.free(self.target);
        allocator.destroy(self);
    }
};

/// One subchannel. Subchannel refs use the distinct field numbers required by
/// the Channelz schema; data and trace semantics match channels.
pub const Subchannel = struct {
    registry: *Registry,
    id: i64,
    name: []const u8,
    target: []const u8,
    state: std.atomic.Value(u32),
    calls_started: std.atomic.Value(i64) = .init(0),
    calls_succeeded: std.atomic.Value(i64) = .init(0),
    calls_failed: std.atomic.Value(i64) = .init(0),
    last_call_started_ns: std.atomic.Value(i64) = .init(0),
    trace: TraceRing,

    pub fn setState(self: *Subchannel, state: ConnectivityState) void {
        self.state.store(@intFromEnum(state), .release);
    }

    pub fn addTrace(
        self: *Subchannel,
        description: []const u8,
        severity: TraceSeverity,
    ) Error!void {
        self.registry.mutex.lockUncancelable(self.registry.io);
        defer self.registry.mutex.unlock(self.registry.io);
        try self.trace.add(
            self.registry.allocator,
            self.registry.io,
            description,
            severity,
        );
    }

    pub fn callStarted(self: *Subchannel) void {
        _ = self.calls_started.fetchAdd(1, .monotonic);
        const now = std.Io.Timestamp.now(self.registry.io, .real).toNanoseconds();
        self.last_call_started_ns.store(@intCast(now), .release);
    }

    pub fn callSucceeded(self: *Subchannel) void {
        _ = self.calls_succeeded.fetchAdd(1, .monotonic);
    }

    pub fn callFailed(self: *Subchannel) void {
        _ = self.calls_failed.fetchAdd(1, .monotonic);
    }

    fn destroy(self: *Subchannel, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        allocator.free(self.name);
        allocator.free(self.target);
        allocator.destroy(self);
    }
};

/// One server. Call counters use the same lock-free update pattern as
/// `Channel`.
pub const Server = struct {
    registry: *Registry,
    id: i64,
    name: []const u8,
    listen_sockets: std.ArrayList(i64) = .empty,
    calls_started: std.atomic.Value(i64) = .init(0),
    calls_succeeded: std.atomic.Value(i64) = .init(0),
    calls_failed: std.atomic.Value(i64) = .init(0),
    last_call_started_ns: std.atomic.Value(i64) = .init(0),
    trace: TraceRing,

    pub fn addListenSocket(self: *Server, socket: *Socket) Error!void {
        if (socket.registry != self.registry) return error.InvalidRequest;
        self.registry.mutex.lockUncancelable(self.registry.io);
        defer self.registry.mutex.unlock(self.registry.io);
        var index = self.listen_sockets.items.len;
        while (index != 0 and self.listen_sockets.items[index - 1] > socket.id) index -= 1;
        try self.listen_sockets.insert(self.registry.allocator, index, socket.id);
    }

    pub fn addTrace(
        self: *Server,
        description: []const u8,
        severity: TraceSeverity,
    ) Error!void {
        self.registry.mutex.lockUncancelable(self.registry.io);
        defer self.registry.mutex.unlock(self.registry.io);
        try self.trace.add(
            self.registry.allocator,
            self.registry.io,
            description,
            severity,
        );
    }

    /// Allocation-free observer for `grpc.runtime.ServerOptions`.
    pub fn observer(self: *Server) observability.ServerObserver {
        return .{
            .context = self,
            .call_started_fn = observerStarted,
            .call_succeeded_fn = observerSucceeded,
            .call_failed_fn = observerFailed,
        };
    }

    fn observerStarted(context: *anyopaque) void {
        const self: *Server = @ptrCast(@alignCast(context));
        self.callStarted();
    }

    fn observerSucceeded(context: *anyopaque) void {
        const self: *Server = @ptrCast(@alignCast(context));
        self.callSucceeded();
    }

    fn observerFailed(context: *anyopaque) void {
        const self: *Server = @ptrCast(@alignCast(context));
        self.callFailed();
    }

    pub fn callStarted(self: *Server) void {
        _ = self.calls_started.fetchAdd(1, .monotonic);
        const now = std.Io.Timestamp.now(self.registry.io, .real).toNanoseconds();
        self.last_call_started_ns.store(@intCast(now), .release);
    }

    pub fn callSucceeded(self: *Server) void {
        _ = self.calls_succeeded.fetchAdd(1, .monotonic);
    }

    pub fn callFailed(self: *Server) void {
        _ = self.calls_failed.fetchAdd(1, .monotonic);
    }

    fn destroy(self: *Server, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        self.listen_sockets.deinit(allocator);
        allocator.free(self.name);
        allocator.destroy(self);
    }
};

/// A socket address reported by Channelz. TCP/IP addresses keep their binary
/// form; Unix and opaque addresses own their strings.
pub const Address = union(enum) {
    tcpip: std.Io.net.IpAddress,
    uds: []const u8,
    other: []const u8,

    fn deinit(self: Address, allocator: std.mem.Allocator) void {
        switch (self) {
            .tcpip => {},
            .uds => |value| allocator.free(value),
            .other => |value| allocator.free(value),
        }
    }

    fn clone(self: Address, allocator: std.mem.Allocator) !Address {
        return switch (self) {
            .tcpip => |value| .{ .tcpip = value },
            .uds => |value| .{ .uds = try allocator.dupe(u8, value) },
            .other => |value| .{ .other = try allocator.dupe(u8, value) },
        };
    }
};

/// One socket with stream/message counters. `local` and `remote` are
/// registry-owned addresses.
pub const Socket = struct {
    registry: *Registry,
    id: i64,
    name: []const u8,
    local: Address,
    remote: ?Address,
    streams_started: std.atomic.Value(i64) = .init(0),
    streams_succeeded: std.atomic.Value(i64) = .init(0),
    streams_failed: std.atomic.Value(i64) = .init(0),
    messages_sent: std.atomic.Value(i64) = .init(0),
    messages_received: std.atomic.Value(i64) = .init(0),
    keep_alives_sent: std.atomic.Value(i64) = .init(0),

    pub fn streamStarted(self: *Socket) void {
        _ = self.streams_started.fetchAdd(1, .monotonic);
    }

    pub fn streamSucceeded(self: *Socket) void {
        _ = self.streams_succeeded.fetchAdd(1, .monotonic);
    }

    pub fn streamFailed(self: *Socket) void {
        _ = self.streams_failed.fetchAdd(1, .monotonic);
    }

    pub fn messageSent(self: *Socket) void {
        _ = self.messages_sent.fetchAdd(1, .monotonic);
    }

    pub fn messageReceived(self: *Socket) void {
        _ = self.messages_received.fetchAdd(1, .monotonic);
    }

    pub fn keepAliveSent(self: *Socket) void {
        _ = self.keep_alives_sent.fetchAdd(1, .monotonic);
    }

    fn destroy(self: *Socket, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.local.deinit(allocator);
        if (self.remote) |remote| remote.deinit(allocator);
        allocator.destroy(self);
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    channels: std.ArrayList(*Channel) = .empty,
    subchannels: std.ArrayList(*Subchannel) = .empty,
    servers: std.ArrayList(*Server) = .empty,
    sockets: std.ArrayList(*Socket) = .empty,
    next_channel_id: i64 = 1,
    next_subchannel_id: i64 = 1,
    next_server_id: i64 = 1,
    next_socket_id: i64 = 1,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Registry {
        return .{ .allocator = allocator, .io = io };
    }

    pub fn deinit(self: *Registry) void {
        self.mutex.lockUncancelable(self.io);
        for (self.channels.items) |channel| channel.destroy(self.allocator);
        for (self.subchannels.items) |subchannel| subchannel.destroy(self.allocator);
        for (self.servers.items) |server| server.destroy(self.allocator);
        for (self.sockets.items) |socket| socket.destroy(self.allocator);
        self.channels.deinit(self.allocator);
        self.subchannels.deinit(self.allocator);
        self.servers.deinit(self.allocator);
        self.sockets.deinit(self.allocator);
        self.mutex.unlock(self.io);
        self.* = undefined;
    }

    /// Register a top-level channel. The returned handle remains valid until
    /// `removeChannel` or registry teardown.
    pub fn addChannel(self: *Registry, name: []const u8, target: []const u8) Error!*Channel {
        const channel = try self.allocator.create(Channel);
        errdefer self.allocator.destroy(channel);
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const id = self.next_channel_id;
        self.next_channel_id = std.math.add(i64, id, 1) catch return error.InvalidRequest;
        channel.* = .{
            .registry = self,
            .id = id,
            .name = owned_name,
            .target = owned_target,
            .state = .init(@intFromEnum(ConnectivityState.idle)),
            .trace = TraceRing.init(self.io),
        };
        try self.channels.append(self.allocator, channel);
        return channel;
    }

    pub fn addSubchannel(self: *Registry, name: []const u8, target: []const u8) Error!*Subchannel {
        const subchannel = try self.allocator.create(Subchannel);
        errdefer self.allocator.destroy(subchannel);
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_target = try self.allocator.dupe(u8, target);
        errdefer self.allocator.free(owned_target);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const id = self.next_subchannel_id;
        self.next_subchannel_id = std.math.add(i64, id, 1) catch return error.InvalidRequest;
        subchannel.* = .{
            .registry = self,
            .id = id,
            .name = owned_name,
            .target = owned_target,
            .state = .init(@intFromEnum(ConnectivityState.idle)),
            .trace = TraceRing.init(self.io),
        };
        try self.subchannels.append(self.allocator, subchannel);
        return subchannel;
    }

    pub fn addServer(self: *Registry, name: []const u8) Error!*Server {
        const server = try self.allocator.create(Server);
        errdefer self.allocator.destroy(server);
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const id = self.next_server_id;
        self.next_server_id = std.math.add(i64, id, 1) catch return error.InvalidRequest;
        server.* = .{
            .registry = self,
            .id = id,
            .name = owned_name,
            .trace = TraceRing.init(self.io),
        };
        try self.servers.append(self.allocator, server);
        return server;
    }

    pub fn addSocket(
        self: *Registry,
        name: []const u8,
        local: Address,
        remote: ?Address,
    ) Error!*Socket {
        const socket = try self.allocator.create(Socket);
        errdefer self.allocator.destroy(socket);
        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_local = try local.clone(self.allocator);
        errdefer owned_local.deinit(self.allocator);
        const owned_remote = if (remote) |value| try value.clone(self.allocator) else null;
        errdefer if (owned_remote) |value| value.deinit(self.allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const id = self.next_socket_id;
        self.next_socket_id = std.math.add(i64, id, 1) catch return error.InvalidRequest;
        socket.* = .{
            .registry = self,
            .id = id,
            .name = owned_name,
            .local = owned_local,
            .remote = owned_remote,
        };
        try self.sockets.append(self.allocator, socket);
        return socket;
    }

    /// Remove and destroy a channel. The caller must not use the handle after
    /// this returns.
    pub fn removeChannel(self: *Registry, channel: *Channel) bool {
        self.mutex.lockUncancelable(self.io);
        for (self.channels.items, 0..) |candidate, index| {
            if (candidate != channel) continue;
            _ = self.channels.orderedRemove(index);
            self.mutex.unlock(self.io);
            channel.destroy(self.allocator);
            return true;
        }
        self.mutex.unlock(self.io);
        return false;
    }

    /// Remove and destroy a subchannel. The caller must not use the handle
    /// after this returns. Channel references remain as stale ids until the
    /// application removes them explicitly.
    pub fn removeSubchannel(self: *Registry, subchannel: *Subchannel) bool {
        self.mutex.lockUncancelable(self.io);
        for (self.subchannels.items, 0..) |candidate, index| {
            if (candidate != subchannel) continue;
            _ = self.subchannels.orderedRemove(index);
            self.mutex.unlock(self.io);
            subchannel.destroy(self.allocator);
            return true;
        }
        self.mutex.unlock(self.io);
        return false;
    }

    /// Remove and destroy a server. The caller must not use the handle after
    /// this returns.
    pub fn removeServer(self: *Registry, server: *Server) bool {
        self.mutex.lockUncancelable(self.io);
        for (self.servers.items, 0..) |candidate, index| {
            if (candidate != server) continue;
            _ = self.servers.orderedRemove(index);
            self.mutex.unlock(self.io);
            server.destroy(self.allocator);
            return true;
        }
        self.mutex.unlock(self.io);
        return false;
    }

    /// Remove and destroy a socket. The caller must not use the handle after
    /// this returns. Server listen-socket references remain as stale ids until
    /// the application removes them explicitly.
    pub fn removeSocket(self: *Registry, socket: *Socket) bool {
        self.mutex.lockUncancelable(self.io);
        for (self.sockets.items, 0..) |candidate, index| {
            if (candidate != socket) continue;
            _ = self.sockets.orderedRemove(index);
            self.mutex.unlock(self.io);
            socket.destroy(self.allocator);
            return true;
        }
        self.mutex.unlock(self.io);
        return false;
    }

    pub fn handlesPath(path: []const u8) bool {
        return std.mem.startsWith(u8, path, "/grpc.channelz.v1.Channelz/");
    }

    /// Handle one unary Channelz request. Returns null when `path` is not a
    /// Channelz method. The returned bytes are owned by `allocator`.
    pub fn handle(
        self: *Registry,
        allocator: std.mem.Allocator,
        path: []const u8,
        request_bytes: []const u8,
    ) Error!?[]u8 {
        if (!handlesPath(path)) return null;
        if (std.mem.eql(u8, path, get_top_channels_path)) {
            return try self.topChannels(allocator, request_bytes);
        }
        if (std.mem.eql(u8, path, get_servers_path)) {
            return try self.serversResponse(allocator, request_bytes);
        }
        if (std.mem.eql(u8, path, get_server_path)) {
            return try self.serverResponse(allocator, request_bytes);
        }
        if (std.mem.eql(u8, path, get_channel_path)) {
            return try self.channelResponse(allocator, request_bytes);
        }
        if (std.mem.eql(u8, path, get_server_sockets_path)) {
            return try self.serverSocketsResponse(allocator, request_bytes);
        }
        if (std.mem.eql(u8, path, get_socket_path)) {
            return try self.socketResponse(allocator, request_bytes);
        }
        if (std.mem.eql(u8, path, get_subchannel_path)) {
            return try self.subchannelResponse(allocator, request_bytes);
        }
        return error.Unimplemented;
    }

    fn topChannels(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        const request = try parsePageRequest(request_bytes, 1);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const page = pageBounds(Channel, self.channels.items, request);
        for (self.channels.items[page.start..page.end]) |channel| {
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try encodeChannel(&encoded, allocator, channel);
            try putBytesField(&out, allocator, 1, encoded.items);
        }
        try putBoolField(&out, allocator, 2, page.end == self.channels.items.len);
        return out.toOwnedSlice(allocator);
    }

    fn serversResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        const request = try parsePageRequest(request_bytes, 1);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const page = pageBounds(Server, self.servers.items, request);
        for (self.servers.items[page.start..page.end]) |server| {
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try encodeServer(&encoded, allocator, server);
            try putBytesField(&out, allocator, 1, encoded.items);
        }
        try putBoolField(&out, allocator, 2, page.end == self.servers.items.len);
        return out.toOwnedSlice(allocator);
    }

    fn serverResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        const id = try parseId(request_bytes, 1);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const server = self.findServer(id) orelse return error.NotFound;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encodeServer(&encoded, allocator, server);
        try putBytesField(&out, allocator, 1, encoded.items);
        return out.toOwnedSlice(allocator);
    }

    fn channelResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        const id = try parseId(request_bytes, 1);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const channel = self.findChannel(id) orelse return error.NotFound;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encodeChannel(&encoded, allocator, channel);
        try putBytesField(&out, allocator, 1, encoded.items);
        return out.toOwnedSlice(allocator);
    }

    fn subchannelResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        const id = try parseId(request_bytes, 1);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const subchannel = self.findSubchannel(id) orelse return error.NotFound;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encodeSubchannel(&encoded, allocator, subchannel);
        try putBytesField(&out, allocator, 1, encoded.items);
        return out.toOwnedSlice(allocator);
    }

    fn serverSocketsResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        var reader = pb.Reader{ .bytes = request_bytes };
        var server_id: i64 = 0;
        var start: i64 = 0;
        var max_results: i64 = 0;
        while (try reader.next()) |field| switch (field.number) {
            1 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                server_id = @bitCast(try reader.varint());
            },
            2 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                start = @bitCast(try reader.varint());
            },
            3 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                max_results = @bitCast(try reader.varint());
            },
            else => try reader.skip(field),
        };
        if (server_id <= 0 or start < 0 or max_results < 0) return error.InvalidRequest;
        const limit: usize = if (max_results == 0)
            default_page_size
        else
            @min(@as(usize, @intCast(max_results)), max_page_size);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const server = self.findServer(server_id) orelse return error.NotFound;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        var index: usize = 0;
        var count: usize = 0;
        while (index < server.listen_sockets.items.len) : (index += 1) {
            const socket_id = server.listen_sockets.items[index];
            if (socket_id < start) continue;
            if (count == limit) break;
            const socket = self.findSocket(socket_id) orelse continue;
            var encoded: std.ArrayList(u8) = .empty;
            defer encoded.deinit(allocator);
            try encodeSocketRef(&encoded, allocator, socket.id, socket.name);
            try putBytesField(&out, allocator, 1, encoded.items);
            count += 1;
        }
        var end = true;
        while (index < server.listen_sockets.items.len) : (index += 1) {
            const socket_id = server.listen_sockets.items[index];
            if (socket_id < start) continue;
            if (self.findSocket(socket_id) != null) {
                end = false;
                break;
            }
        }
        try putBoolField(&out, allocator, 2, end);
        return out.toOwnedSlice(allocator);
    }

    fn socketResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        const id = try parseId(request_bytes, 1);
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const socket = self.findSocket(id) orelse return error.NotFound;
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try encodeSocket(&encoded, allocator, socket);
        try putBytesField(&out, allocator, 1, encoded.items);
        return out.toOwnedSlice(allocator);
    }

    fn findChannel(self: *Registry, id: i64) ?*Channel {
        for (self.channels.items) |channel| if (channel.id == id) return channel;
        return null;
    }

    fn findSubchannel(self: *Registry, id: i64) ?*Subchannel {
        for (self.subchannels.items) |subchannel| if (subchannel.id == id) return subchannel;
        return null;
    }

    fn findServer(self: *Registry, id: i64) ?*Server {
        for (self.servers.items) |server| if (server.id == id) return server;
        return null;
    }

    fn findSocket(self: *Registry, id: i64) ?*Socket {
        for (self.sockets.items) |socket| if (socket.id == id) return socket;
        return null;
    }
};

/// Dispatch one already-read unary request when it targets Channelz.
///
/// Returns false for an unrelated path without writing a response. Channelz
/// protocol errors are converted to the standard gRPC status; transport errors
/// are returned to the caller.
pub fn serve(
    registry: *Registry,
    connection: *runtime.ServerConnection,
    request: *const runtime.OwnedUnaryRequest,
) ServeError!bool {
    const path = request.request.path;
    if (!Registry.handlesPath(path)) return false;
    const allocator = connection.connection.allocator;
    const encoded = (registry.handle(
        allocator,
        path,
        request.request.message.payload,
    ) catch |err| switch (err) {
        error.NotFound => {
            try connection.writeUnary(request.request.stream_id, .{
                .status = .not_found,
                .status_message = "channelz entity not found",
            });
            return true;
        },
        error.Unimplemented => {
            try connection.writeUnary(request.request.stream_id, .{
                .status = .unimplemented,
                .status_message = "channelz method not implemented",
            });
            return true;
        },
        error.InvalidRequest => {
            try connection.writeUnary(request.request.stream_id, .{
                .status = .invalid_argument,
                .status_message = "invalid channelz request",
            });
            return true;
        },
        else => return err,
    }) orelse return false;
    defer allocator.free(encoded);
    try connection.writeUnary(request.request.stream_id, .{ .message = encoded });
    return true;
}

pub const Timestamp = struct {
    seconds: i64 = 0,
    nanos: u32 = 0,
};

pub const ChannelData = struct {
    state: ConnectivityState = .unknown,
    target: []const u8 = "",
    calls_started: i64 = 0,
    calls_succeeded: i64 = 0,
    calls_failed: i64 = 0,
    last_call_started: ?Timestamp = null,
};

pub const TraceEventInfo = struct {
    description: []const u8 = "",
    severity: TraceSeverity = .unknown,
    timestamp: ?Timestamp = null,
};

pub const TraceInfo = struct {
    num_events_logged: i64 = 0,
    creation_timestamp: ?Timestamp = null,
    events: []TraceEventInfo = &.{},
};

pub const SubchannelRefInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
};

pub const ChannelInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
    data: ChannelData = .{},
    trace: ?TraceInfo = null,
    subchannels: []SubchannelRefInfo = &.{},
};

pub const SubchannelInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
    data: ChannelData = .{},
    trace: ?TraceInfo = null,
};

pub const ServerData = struct {
    calls_started: i64 = 0,
    calls_succeeded: i64 = 0,
    calls_failed: i64 = 0,
    last_call_started: ?Timestamp = null,
};

pub const ServerInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
    data: ServerData = .{},
    trace: ?TraceInfo = null,
    listen_sockets: []SocketRefInfo = &.{},
};

/// Owned page of top-level channels. `channels` borrow `arena` storage.
pub const TopChannels = struct {
    arena: std.heap.ArenaAllocator,
    channels: []ChannelInfo = &.{},
    end: bool = false,

    pub fn deinit(self: *TopChannels) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Owned page of servers. `servers` borrow `arena` storage.
pub const ServersPage = struct {
    arena: std.heap.ArenaAllocator,
    servers: []ServerInfo = &.{},
    end: bool = false,

    pub fn deinit(self: *ServersPage) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const OwnedChannel = struct {
    arena: std.heap.ArenaAllocator,
    value: ChannelInfo,

    pub fn deinit(self: *OwnedChannel) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const OwnedSubchannel = struct {
    arena: std.heap.ArenaAllocator,
    value: SubchannelInfo,

    pub fn deinit(self: *OwnedSubchannel) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const OwnedServer = struct {
    arena: std.heap.ArenaAllocator,
    value: ServerInfo,

    pub fn deinit(self: *OwnedServer) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const SocketRefInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
};

pub const SocketData = struct {
    streams_started: i64 = 0,
    streams_succeeded: i64 = 0,
    streams_failed: i64 = 0,
    messages_sent: i64 = 0,
    messages_received: i64 = 0,
    keep_alives_sent: i64 = 0,
};

pub const SocketInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
    data: SocketData = .{},
    local: ?Address = null,
    remote: ?Address = null,
};

/// Owned socket page. `sockets` borrow `arena` storage.
pub const SocketPage = struct {
    arena: std.heap.ArenaAllocator,
    sockets: []SocketRefInfo = &.{},
    end: bool = false,

    pub fn deinit(self: *SocketPage) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const OwnedSocket = struct {
    arena: std.heap.ArenaAllocator,
    value: SocketInfo,

    pub fn deinit(self: *OwnedSocket) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn decodeTopChannels(allocator: std.mem.Allocator, bytes: []const u8) Error!TopChannels {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var values: std.ArrayList(ChannelInfo) = .empty;
    var end = false;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => try values.append(owned, try decodeChannelInfo(owned, try reader.bytesValue())),
        2 => end = (try reader.varint()) != 0,
        else => try reader.skip(field),
    };
    return .{
        .arena = arena,
        .channels = try values.toOwnedSlice(owned),
        .end = end,
    };
}

pub fn decodeServers(allocator: std.mem.Allocator, bytes: []const u8) Error!ServersPage {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var values: std.ArrayList(ServerInfo) = .empty;
    var end = false;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => try values.append(owned, try decodeServerInfo(owned, try reader.bytesValue())),
        2 => end = (try reader.varint()) != 0,
        else => try reader.skip(field),
    };
    return .{
        .arena = arena,
        .servers = try values.toOwnedSlice(owned),
        .end = end,
    };
}

pub fn decodeChannelResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!OwnedChannel {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var value: ?ChannelInfo = null;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value = try decodeChannelInfo(owned, try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return .{ .arena = arena, .value = value orelse return error.InvalidRequest };
}

pub fn decodeServerResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!OwnedServer {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var value: ?ServerInfo = null;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value = try decodeServerInfo(owned, try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return .{ .arena = arena, .value = value orelse return error.InvalidRequest };
}

pub fn decodeServerSockets(allocator: std.mem.Allocator, bytes: []const u8) Error!SocketPage {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var values: std.ArrayList(SocketRefInfo) = .empty;
    var end = false;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => try values.append(owned, try decodeSocketRef(owned, try reader.bytesValue())),
        2 => end = (try reader.varint()) != 0,
        else => try reader.skip(field),
    };
    return .{
        .arena = arena,
        .sockets = try values.toOwnedSlice(owned),
        .end = end,
    };
}

pub fn decodeSocketResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!OwnedSocket {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var value: ?SocketInfo = null;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value = try decodeSocketInfo(owned, try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return .{ .arena = arena, .value = value orelse return error.InvalidRequest };
}

fn decodeSocketRef(allocator: std.mem.Allocator, bytes: []const u8) Error!SocketRefInfo {
    var value = SocketRefInfo{};
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        3 => value.id = @bitCast(try reader.varint()),
        4 => value.name = try allocator.dupe(u8, try reader.string()),
        else => try reader.skip(field),
    };
    return value;
}

fn decodeSocketInfo(allocator: std.mem.Allocator, bytes: []const u8) Error!SocketInfo {
    var value = SocketInfo{};
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            const ref = try decodeSocketRef(allocator, try reader.bytesValue());
            value.id = ref.id;
            value.name = ref.name;
        },
        2 => {
            var data = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try data.next()) |item| switch (item.number) {
                1 => value.data.streams_started = @bitCast(try data.varint()),
                2 => value.data.streams_succeeded = @bitCast(try data.varint()),
                3 => value.data.streams_failed = @bitCast(try data.varint()),
                4 => value.data.messages_sent = @bitCast(try data.varint()),
                5 => value.data.messages_received = @bitCast(try data.varint()),
                6 => value.data.keep_alives_sent = @bitCast(try data.varint()),
                else => try data.skip(item),
            };
        },
        3 => value.local = try decodeAddress(allocator, try reader.bytesValue()),
        4 => value.remote = try decodeAddress(allocator, try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return value;
}

fn decodeAddress(allocator: std.mem.Allocator, bytes: []const u8) Error!Address {
    var reader = pb.Reader{ .bytes = bytes };
    var result: ?Address = null;
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            var tcp = pb.Reader{ .bytes = try reader.bytesValue() };
            var ip: ?[]const u8 = null;
            var port: u16 = 0;
            while (try tcp.next()) |item| switch (item.number) {
                1 => ip = try tcp.bytesValue(),
                2 => port = std.math.cast(u16, try tcp.varint()) orelse return error.InvalidRequest,
                else => try tcp.skip(item),
            };
            const address = ip orelse return error.InvalidRequest;
            result = switch (address.len) {
                4 => .{ .tcpip = .{ .ip4 = .{ .bytes = address[0..4].*, .port = port } } },
                16 => .{ .tcpip = .{ .ip6 = .{ .bytes = address[0..16].*, .port = port } } },
                else => return error.InvalidRequest,
            };
        },
        2 => {
            var uds = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try uds.next()) |item| switch (item.number) {
                1 => result = .{ .uds = try allocator.dupe(u8, try uds.string()) },
                else => try uds.skip(item),
            };
        },
        3 => {
            var other = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try other.next()) |item| switch (item.number) {
                1 => result = .{ .other = try allocator.dupe(u8, try other.string()) },
                else => try other.skip(item),
            };
        },
        else => try reader.skip(field),
    };
    return result orelse error.InvalidRequest;
}

fn decodeChannelInfo(allocator: std.mem.Allocator, bytes: []const u8) Error!ChannelInfo {
    var value = ChannelInfo{};
    var subchannels: std.ArrayList(SubchannelRefInfo) = .empty;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            var ref = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try ref.next()) |item| switch (item.number) {
                1 => value.id = @bitCast(try ref.varint()),
                2 => value.name = try allocator.dupe(u8, try ref.string()),
                else => try ref.skip(item),
            };
        },
        2 => {
            var data = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try data.next()) |item| switch (item.number) {
                1 => {
                    var state = pb.Reader{ .bytes = try data.bytesValue() };
                    while (try state.next()) |entry| switch (entry.number) {
                        1 => {
                            const raw = std.math.cast(
                                u32,
                                try state.varint(),
                            ) orelse 0;
                            value.data.state = std.enums.fromInt(
                                ConnectivityState,
                                raw,
                            ) orelse .unknown;
                        },
                        else => try state.skip(entry),
                    };
                },
                2 => value.data.target = try allocator.dupe(u8, try data.string()),
                3 => value.trace = try decodeTrace(allocator, try data.bytesValue()),
                4 => value.data.calls_started = @bitCast(try data.varint()),
                5 => value.data.calls_succeeded = @bitCast(try data.varint()),
                6 => value.data.calls_failed = @bitCast(try data.varint()),
                7 => value.data.last_call_started = try decodeTimestamp(try data.bytesValue()),
                else => try data.skip(item),
            };
        },
        4 => try subchannels.append(
            allocator,
            try decodeSubchannelRef(allocator, try reader.bytesValue()),
        ),
        else => try reader.skip(field),
    };
    value.subchannels = try subchannels.toOwnedSlice(allocator);
    return value;
}

fn decodeSubchannelRef(allocator: std.mem.Allocator, bytes: []const u8) Error!SubchannelRefInfo {
    var value = SubchannelRefInfo{};
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        7 => value.id = @bitCast(try reader.varint()),
        8 => value.name = try allocator.dupe(u8, try reader.string()),
        else => try reader.skip(field),
    };
    return value;
}

fn decodeSubchannelInfo(allocator: std.mem.Allocator, bytes: []const u8) Error!SubchannelInfo {
    var value = SubchannelInfo{};
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            const ref = try decodeSubchannelRef(allocator, try reader.bytesValue());
            value.id = ref.id;
            value.name = ref.name;
        },
        2 => {
            var data = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try data.next()) |item| switch (item.number) {
                1 => {
                    var state = pb.Reader{ .bytes = try data.bytesValue() };
                    while (try state.next()) |entry| switch (entry.number) {
                        1 => {
                            const raw = std.math.cast(
                                u32,
                                try state.varint(),
                            ) orelse 0;
                            value.data.state = std.enums.fromInt(
                                ConnectivityState,
                                raw,
                            ) orelse .unknown;
                        },
                        else => try state.skip(entry),
                    };
                },
                2 => value.data.target = try allocator.dupe(u8, try data.string()),
                3 => value.trace = try decodeTrace(allocator, try data.bytesValue()),
                4 => value.data.calls_started = @bitCast(try data.varint()),
                5 => value.data.calls_succeeded = @bitCast(try data.varint()),
                6 => value.data.calls_failed = @bitCast(try data.varint()),
                7 => value.data.last_call_started = try decodeTimestamp(try data.bytesValue()),
                else => try data.skip(item),
            };
        },
        else => try reader.skip(field),
    };
    return value;
}

pub fn decodeSubchannelResponse(allocator: std.mem.Allocator, bytes: []const u8) Error!OwnedSubchannel {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var value: ?SubchannelInfo = null;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value = try decodeSubchannelInfo(owned, try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return .{ .arena = arena, .value = value orelse return error.InvalidRequest };
}

fn decodeServerInfo(allocator: std.mem.Allocator, bytes: []const u8) Error!ServerInfo {
    var value = ServerInfo{};
    var listen_sockets: std.ArrayList(SocketRefInfo) = .empty;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => {
            var ref = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try ref.next()) |item| switch (item.number) {
                5 => value.id = @bitCast(try ref.varint()),
                6 => value.name = try allocator.dupe(u8, try ref.string()),
                else => try ref.skip(item),
            };
        },
        2 => {
            var data = pb.Reader{ .bytes = try reader.bytesValue() };
            while (try data.next()) |item| switch (item.number) {
                1 => value.trace = try decodeTrace(allocator, try data.bytesValue()),
                2 => value.data.calls_started = @bitCast(try data.varint()),
                3 => value.data.calls_succeeded = @bitCast(try data.varint()),
                4 => value.data.calls_failed = @bitCast(try data.varint()),
                5 => value.data.last_call_started = try decodeTimestamp(try data.bytesValue()),
                else => try data.skip(item),
            };
        },
        3 => try listen_sockets.append(
            allocator,
            try decodeSocketRef(allocator, try reader.bytesValue()),
        ),
        else => try reader.skip(field),
    };
    value.listen_sockets = try listen_sockets.toOwnedSlice(allocator);
    return value;
}

fn decodeTrace(allocator: std.mem.Allocator, bytes: []const u8) Error!TraceInfo {
    var value = TraceInfo{};
    var events: std.ArrayList(TraceEventInfo) = .empty;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value.num_events_logged = @bitCast(try reader.varint()),
        2 => value.creation_timestamp = try decodeTimestamp(try reader.bytesValue()),
        3 => try events.append(allocator, try decodeTraceEvent(allocator, try reader.bytesValue())),
        else => try reader.skip(field),
    };
    value.events = try events.toOwnedSlice(allocator);
    return value;
}

fn decodeTraceEvent(allocator: std.mem.Allocator, bytes: []const u8) Error!TraceEventInfo {
    var value = TraceEventInfo{};
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value.description = try allocator.dupe(u8, try reader.string()),
        2 => {
            const raw = std.math.cast(u32, try reader.varint()) orelse 0;
            value.severity = std.enums.fromInt(TraceSeverity, raw) orelse .unknown;
        },
        3 => value.timestamp = try decodeTimestamp(try reader.bytesValue()),
        else => try reader.skip(field),
    };
    return value;
}

fn decodeTimestamp(bytes: []const u8) Error!Timestamp {
    var value = Timestamp{};
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        1 => value.seconds = @bitCast(try reader.varint()),
        2 => value.nanos = std.math.cast(u32, try reader.varint()) orelse return error.InvalidRequest,
        else => try reader.skip(field),
    };
    return value;
}

pub fn encodePageRequest(
    allocator: std.mem.Allocator,
    start: i64,
    max_results: i64,
) Error![]u8 {
    if (start < 0 or max_results < 0) return error.InvalidRequest;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    if (start != 0) try putVarintField(&out, allocator, 1, @bitCast(start));
    if (max_results != 0) try putVarintField(&out, allocator, 2, @bitCast(max_results));
    return out.toOwnedSlice(allocator);
}

pub fn encodeIdRequest(allocator: std.mem.Allocator, id: i64) Error![]u8 {
    if (id <= 0) return error.InvalidRequest;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try putVarintField(&out, allocator, 1, @intCast(id));
    return out.toOwnedSlice(allocator);
}

pub fn encodeServerSocketsRequest(
    allocator: std.mem.Allocator,
    server_id: i64,
    start_socket_id: i64,
    max_results: i64,
) Error![]u8 {
    if (server_id <= 0 or start_socket_id < 0 or max_results < 0) return error.InvalidRequest;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try putVarintField(&out, allocator, 1, @intCast(server_id));
    if (start_socket_id != 0) try putVarintField(&out, allocator, 2, @bitCast(start_socket_id));
    if (max_results != 0) try putVarintField(&out, allocator, 3, @bitCast(max_results));
    return out.toOwnedSlice(allocator);
}

pub const ClientOptions = struct {
    authority: []const u8 = "localhost",
    timeout: ?wire.Timeout = null,
    metadata: []const http2.Hpack.HeaderField = &.{},
};

pub const ClientError = Error || runtime.Error || error{ RpcFailed, InvalidResponse };

/// Unary Channelz client over one connected `grpc.runtime.Client`.
pub const Client = struct {
    allocator: std.mem.Allocator,
    connection: *runtime.Client,
    options: ClientOptions = .{},

    pub fn getTopChannels(
        self: *Client,
        start: i64,
        max_results: i64,
    ) ClientError!TopChannels {
        const request = try encodePageRequest(self.allocator, start, max_results);
        defer self.allocator.free(request);
        var response = try self.unary(get_top_channels_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeTopChannels(self.allocator, message.payload);
    }

    pub fn getServers(
        self: *Client,
        start: i64,
        max_results: i64,
    ) ClientError!ServersPage {
        const request = try encodePageRequest(self.allocator, start, max_results);
        defer self.allocator.free(request);
        var response = try self.unary(get_servers_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeServers(self.allocator, message.payload);
    }

    pub fn getServer(self: *Client, id: i64) ClientError!OwnedServer {
        const request = try encodeIdRequest(self.allocator, id);
        defer self.allocator.free(request);
        var response = try self.unary(get_server_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeServerResponse(self.allocator, message.payload);
    }

    pub fn getChannel(self: *Client, id: i64) ClientError!OwnedChannel {
        const request = try encodeIdRequest(self.allocator, id);
        defer self.allocator.free(request);
        var response = try self.unary(get_channel_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeChannelResponse(self.allocator, message.payload);
    }

    pub fn getSubchannel(self: *Client, id: i64) ClientError!OwnedSubchannel {
        const request = try encodeIdRequest(self.allocator, id);
        defer self.allocator.free(request);
        var response = try self.unary(get_subchannel_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeSubchannelResponse(self.allocator, message.payload);
    }

    pub fn getServerSockets(
        self: *Client,
        server_id: i64,
        start_socket_id: i64,
        max_results: i64,
    ) ClientError!SocketPage {
        const request = try encodeServerSocketsRequest(
            self.allocator,
            server_id,
            start_socket_id,
            max_results,
        );
        defer self.allocator.free(request);
        var response = try self.unary(get_server_sockets_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeServerSockets(self.allocator, message.payload);
    }

    pub fn getSocket(self: *Client, id: i64) ClientError!OwnedSocket {
        const request = try encodeIdRequest(self.allocator, id);
        defer self.allocator.free(request);
        var response = try self.unary(get_socket_path, request);
        defer response.deinit();
        const message = response.message orelse return error.InvalidResponse;
        return decodeSocketResponse(self.allocator, message.payload);
    }

    fn unary(
        self: *Client,
        path: []const u8,
        message: []const u8,
    ) ClientError!call.UnaryResponse {
        var response = try self.connection.unary(.{
            .path = path,
            .authority = self.options.authority,
            .message = message,
            .timeout = self.options.timeout,
            .metadata = self.options.metadata,
        });
        if (response.status != .ok) {
            const status = response.status;
            response.deinit();
            return switch (status) {
                .not_found => error.NotFound,
                .unimplemented => error.Unimplemented,
                .invalid_argument => error.InvalidRequest,
                else => error.RpcFailed,
            };
        }
        return response;
    }
};

const PageRequest = struct { start: i64, limit: usize };

fn parsePageRequest(bytes: []const u8, start_field: u32) Error!PageRequest {
    var reader = pb.Reader{ .bytes = bytes };
    var start: i64 = 0;
    var max_results: i64 = 0;
    while (try reader.next()) |field| {
        if (field.number == start_field) {
            if (field.wire_type != 0) return error.InvalidRequest;
            start = @bitCast(try reader.varint());
        } else if (field.number == start_field + 1) {
            if (field.wire_type != 0) return error.InvalidRequest;
            max_results = @bitCast(try reader.varint());
        } else try reader.skip(field);
    }
    if (start < 0 or max_results < 0) return error.InvalidRequest;
    const limit: usize = if (max_results == 0)
        default_page_size
    else
        @min(@as(usize, @intCast(max_results)), max_page_size);
    return .{ .start = start, .limit = limit };
}

fn parseId(bytes: []const u8, field_number: u32) Error!i64 {
    var reader = pb.Reader{ .bytes = bytes };
    var id: i64 = 0;
    while (try reader.next()) |field| {
        if (field.number == field_number) {
            if (field.wire_type != 0) return error.InvalidRequest;
            id = @bitCast(try reader.varint());
        } else try reader.skip(field);
    }
    if (id <= 0) return error.InvalidRequest;
    return id;
}

fn pageBounds(comptime T: type, items: []const *T, request: PageRequest) struct { start: usize, end: usize } {
    var start: usize = 0;
    while (start < items.len) : (start += 1) {
        if (items[start].id >= request.start) break;
    }
    return .{ .start = start, .end = @min(items.len, start + request.limit) };
}

fn encodeTraceMessage(out: *std.ArrayList(u8), allocator: std.mem.Allocator, trace: *const TraceRing) !void {
    if (trace.total != 0) try putVarintField(out, allocator, 1, trace.total);
    try putTimestampField(out, allocator, 2, trace.creation_ns);
    var index: usize = 0;
    while (index < trace.count) : (index += 1) {
        const event = trace.events[(trace.start + index) % max_trace_events];
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        if (event.description.len != 0) try putBytesField(&encoded, allocator, 1, event.description);
        if (event.severity != .unknown) {
            try putVarintField(&encoded, allocator, 2, @intCast(@intFromEnum(event.severity)));
        }
        try putTimestampField(&encoded, allocator, 3, event.timestamp_ns);
        try putBytesField(out, allocator, 3, encoded.items);
    }
}

fn encodeChannelData(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    state: u32,
    target: []const u8,
    started: i64,
    succeeded: i64,
    failed: i64,
    last_call_started_ns: i64,
    trace: *const TraceRing,
) !void {
    var state_message: std.ArrayList(u8) = .empty;
    defer state_message.deinit(allocator);
    try putVarintField(&state_message, allocator, 1, state);
    try putBytesField(out, allocator, 1, state_message.items);
    if (target.len != 0) try putBytesField(out, allocator, 2, target);
    var trace_message: std.ArrayList(u8) = .empty;
    defer trace_message.deinit(allocator);
    try encodeTraceMessage(&trace_message, allocator, trace);
    try putBytesField(out, allocator, 3, trace_message.items);
    if (started != 0) try putVarintField(out, allocator, 4, @bitCast(started));
    if (succeeded != 0) try putVarintField(out, allocator, 5, @bitCast(succeeded));
    if (failed != 0) try putVarintField(out, allocator, 6, @bitCast(failed));
    if (last_call_started_ns != 0) {
        try putTimestampField(out, allocator, 7, last_call_started_ns);
    }
}

fn encodeChannel(out: *std.ArrayList(u8), allocator: std.mem.Allocator, channel: *const Channel) !void {
    var ref: std.ArrayList(u8) = .empty;
    defer ref.deinit(allocator);
    try putVarintField(&ref, allocator, 1, @intCast(channel.id));
    if (channel.name.len != 0) try putBytesField(&ref, allocator, 2, channel.name);
    try putBytesField(out, allocator, 1, ref.items);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    try encodeChannelData(
        &data,
        allocator,
        channel.state.load(.acquire),
        channel.target,
        channel.calls_started.load(.monotonic),
        channel.calls_succeeded.load(.monotonic),
        channel.calls_failed.load(.monotonic),
        channel.last_call_started_ns.load(.acquire),
        &channel.trace,
    );
    try putBytesField(out, allocator, 2, data.items);
    for (channel.subchannels.items) |id| {
        const subchannel = channel.registry.findSubchannel(id) orelse continue;
        var subchannel_ref: std.ArrayList(u8) = .empty;
        defer subchannel_ref.deinit(allocator);
        try encodeSubchannelRef(&subchannel_ref, allocator, subchannel.id, subchannel.name);
        try putBytesField(out, allocator, 4, subchannel_ref.items);
    }
}

fn encodeSubchannelRef(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    id: i64,
    name: []const u8,
) !void {
    try putVarintField(out, allocator, 7, @intCast(id));
    if (name.len != 0) try putBytesField(out, allocator, 8, name);
}

fn encodeSubchannel(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    subchannel: *const Subchannel,
) !void {
    var ref: std.ArrayList(u8) = .empty;
    defer ref.deinit(allocator);
    try encodeSubchannelRef(&ref, allocator, subchannel.id, subchannel.name);
    try putBytesField(out, allocator, 1, ref.items);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    try encodeChannelData(
        &data,
        allocator,
        subchannel.state.load(.acquire),
        subchannel.target,
        subchannel.calls_started.load(.monotonic),
        subchannel.calls_succeeded.load(.monotonic),
        subchannel.calls_failed.load(.monotonic),
        subchannel.last_call_started_ns.load(.acquire),
        &subchannel.trace,
    );
    try putBytesField(out, allocator, 2, data.items);
}

fn encodeServer(out: *std.ArrayList(u8), allocator: std.mem.Allocator, server: *const Server) !void {
    var ref: std.ArrayList(u8) = .empty;
    defer ref.deinit(allocator);
    try putVarintField(&ref, allocator, 5, @intCast(server.id));
    if (server.name.len != 0) try putBytesField(&ref, allocator, 6, server.name);
    try putBytesField(out, allocator, 1, ref.items);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    var trace: std.ArrayList(u8) = .empty;
    defer trace.deinit(allocator);
    try encodeTraceMessage(&trace, allocator, &server.trace);
    try putBytesField(&data, allocator, 1, trace.items);
    const started = server.calls_started.load(.monotonic);
    const succeeded = server.calls_succeeded.load(.monotonic);
    const failed = server.calls_failed.load(.monotonic);
    if (started != 0) try putVarintField(&data, allocator, 2, @bitCast(started));
    if (succeeded != 0) try putVarintField(&data, allocator, 3, @bitCast(succeeded));
    if (failed != 0) try putVarintField(&data, allocator, 4, @bitCast(failed));
    const last = server.last_call_started_ns.load(.acquire);
    if (last != 0) try putTimestampField(&data, allocator, 5, last);
    try putBytesField(out, allocator, 2, data.items);
    for (server.listen_sockets.items) |id| {
        const socket = server.registry.findSocket(id) orelse continue;
        var socket_ref: std.ArrayList(u8) = .empty;
        defer socket_ref.deinit(allocator);
        try encodeSocketRef(&socket_ref, allocator, socket.id, socket.name);
        try putBytesField(out, allocator, 3, socket_ref.items);
    }
}

fn encodeSocketRef(out: *std.ArrayList(u8), allocator: std.mem.Allocator, id: i64, name: []const u8) !void {
    try putVarintField(out, allocator, 3, @intCast(id));
    if (name.len != 0) try putBytesField(out, allocator, 4, name);
}

fn encodeAddress(out: *std.ArrayList(u8), allocator: std.mem.Allocator, address: Address) !void {
    switch (address) {
        .tcpip => |value| {
            const bytes, const port = switch (value) {
                .ip4 => |ip| .{ ip.bytes[0..], ip.port },
                .ip6 => |ip| .{ ip.bytes[0..], ip.port },
            };
            var tcp: std.ArrayList(u8) = .empty;
            defer tcp.deinit(allocator);
            try putBytesField(&tcp, allocator, 1, bytes);
            try putVarintField(&tcp, allocator, 2, port);
            try putBytesField(out, allocator, 1, tcp.items);
        },
        .uds => |value| {
            var uds: std.ArrayList(u8) = .empty;
            defer uds.deinit(allocator);
            try putBytesField(&uds, allocator, 1, value);
            try putBytesField(out, allocator, 2, uds.items);
        },
        .other => |value| {
            var other: std.ArrayList(u8) = .empty;
            defer other.deinit(allocator);
            try putBytesField(&other, allocator, 1, value);
            try putBytesField(out, allocator, 3, other.items);
        },
    }
}

fn encodeSocket(out: *std.ArrayList(u8), allocator: std.mem.Allocator, socket: *const Socket) !void {
    var ref: std.ArrayList(u8) = .empty;
    defer ref.deinit(allocator);
    try encodeSocketRef(&ref, allocator, socket.id, socket.name);
    try putBytesField(out, allocator, 1, ref.items);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    const started = socket.streams_started.load(.monotonic);
    const succeeded = socket.streams_succeeded.load(.monotonic);
    const failed = socket.streams_failed.load(.monotonic);
    const sent = socket.messages_sent.load(.monotonic);
    const received = socket.messages_received.load(.monotonic);
    const keep_alives = socket.keep_alives_sent.load(.monotonic);
    if (started != 0) try putVarintField(&data, allocator, 1, @bitCast(started));
    if (succeeded != 0) try putVarintField(&data, allocator, 2, @bitCast(succeeded));
    if (failed != 0) try putVarintField(&data, allocator, 3, @bitCast(failed));
    if (sent != 0) try putVarintField(&data, allocator, 4, @bitCast(sent));
    if (received != 0) try putVarintField(&data, allocator, 5, @bitCast(received));
    if (keep_alives != 0) try putVarintField(&data, allocator, 6, @bitCast(keep_alives));
    try putBytesField(out, allocator, 2, data.items);

    var local: std.ArrayList(u8) = .empty;
    defer local.deinit(allocator);
    try encodeAddress(&local, allocator, socket.local);
    try putBytesField(out, allocator, 3, local.items);
    if (socket.remote) |remote| {
        var remote_message: std.ArrayList(u8) = .empty;
        defer remote_message.deinit(allocator);
        try encodeAddress(&remote_message, allocator, remote);
        try putBytesField(out, allocator, 4, remote_message.items);
    }
}

fn putTimestampField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u32, ns: i64) !void {
    var timestamp: std.ArrayList(u8) = .empty;
    defer timestamp.deinit(allocator);
    const seconds = @divFloor(ns, std.time.ns_per_s);
    const nanos = @mod(ns, std.time.ns_per_s);
    if (seconds != 0) try putVarintField(&timestamp, allocator, 1, @bitCast(seconds));
    if (nanos != 0) try putVarintField(&timestamp, allocator, 2, @intCast(nanos));
    try putBytesField(out, allocator, number, timestamp.items);
}

fn putBoolField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u32, value: bool) !void {
    try putVarintField(out, allocator, number, if (value) 1 else 0);
}

fn putVarintField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u32, value: u64) !void {
    try putKey(out, allocator, number, 0);
    try putVarint(out, allocator, value);
}

fn putBytesField(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u32, bytes: []const u8) !void {
    try putKey(out, allocator, number, 2);
    try putVarint(out, allocator, @intCast(bytes.len));
    try out.appendSlice(allocator, bytes);
}

fn putKey(out: *std.ArrayList(u8), allocator: std.mem.Allocator, number: u32, wire_type: u3) !void {
    try putVarint(out, allocator, (@as(u64, number) << 3) | @as(u64, wire_type));
}

fn putVarint(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u64) !void {
    var remaining = value;
    while (remaining >= 0x80) {
        try out.append(allocator, @as(u8, @truncate(remaining)) | 0x80);
        remaining >>= 7;
    }
    try out.append(allocator, @truncate(remaining));
}

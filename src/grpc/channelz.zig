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

    pub fn setState(self: *Channel, state: ConnectivityState) void {
        self.state.store(@intFromEnum(state), .release);
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

    fn destroy(self: *Channel, allocator: std.mem.Allocator) void {
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
    calls_started: std.atomic.Value(i64) = .init(0),
    calls_succeeded: std.atomic.Value(i64) = .init(0),
    calls_failed: std.atomic.Value(i64) = .init(0),
    last_call_started_ns: std.atomic.Value(i64) = .init(0),

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
        allocator.free(self.name);
        allocator.destroy(self);
    }
};

pub const Registry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    mutex: std.Io.Mutex = .init,
    channels: std.ArrayList(*Channel) = .empty,
    servers: std.ArrayList(*Server) = .empty,
    next_channel_id: i64 = 1,
    next_server_id: i64 = 1,

    pub fn init(allocator: std.mem.Allocator, io: std.Io) Registry {
        return .{ .allocator = allocator, .io = io };
    }

    pub fn deinit(self: *Registry) void {
        self.mutex.lockUncancelable(self.io);
        for (self.channels.items) |channel| channel.destroy(self.allocator);
        for (self.servers.items) |server| server.destroy(self.allocator);
        self.channels.deinit(self.allocator);
        self.servers.deinit(self.allocator);
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
        };
        try self.channels.append(self.allocator, channel);
        return channel;
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
        server.* = .{ .registry = self, .id = id, .name = owned_name };
        try self.servers.append(self.allocator, server);
        return server;
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
        if (std.mem.eql(u8, path, get_subchannel_path) or
            std.mem.eql(u8, path, get_socket_path))
        {
            return error.NotFound;
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

    fn serverSocketsResponse(self: *Registry, allocator: std.mem.Allocator, request_bytes: []const u8) Error![]u8 {
        var reader = pb.Reader{ .bytes = request_bytes };
        var id: i64 = 0;
        var max_results: i64 = 0;
        while (try reader.next()) |field| switch (field.number) {
            1 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                id = @bitCast(try reader.varint());
            },
            2 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                _ = try reader.varint();
            },
            3 => {
                if (field.wire_type != 0) return error.InvalidRequest;
                max_results = @bitCast(try reader.varint());
            },
            else => try reader.skip(field),
        };
        if (id <= 0 or max_results < 0) return error.InvalidRequest;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.findServer(id) == null) return error.NotFound;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        try putBoolField(&out, allocator, 2, true);
        return out.toOwnedSlice(allocator);
    }

    fn findChannel(self: *Registry, id: i64) ?*Channel {
        for (self.channels.items) |channel| if (channel.id == id) return channel;
        return null;
    }

    fn findServer(self: *Registry, id: i64) ?*Server {
        for (self.servers.items) |server| if (server.id == id) return server;
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

pub const ChannelInfo = struct {
    id: i64 = 0,
    name: []const u8 = "",
    data: ChannelData = .{},
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

pub const OwnedServer = struct {
    arena: std.heap.ArenaAllocator,
    value: ServerInfo,

    pub fn deinit(self: *OwnedServer) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const SocketPage = struct {
    end: bool = false,
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

pub fn decodeServerSockets(bytes: []const u8) Error!SocketPage {
    var end = false;
    var reader = pb.Reader{ .bytes = bytes };
    while (try reader.next()) |field| switch (field.number) {
        2 => end = (try reader.varint()) != 0,
        else => try reader.skip(field),
    };
    return .{ .end = end };
}

fn decodeChannelInfo(allocator: std.mem.Allocator, bytes: []const u8) Error!ChannelInfo {
    var value = ChannelInfo{};
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

fn decodeServerInfo(allocator: std.mem.Allocator, bytes: []const u8) Error!ServerInfo {
    var value = ServerInfo{};
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
                2 => value.data.calls_started = @bitCast(try data.varint()),
                3 => value.data.calls_succeeded = @bitCast(try data.varint()),
                4 => value.data.calls_failed = @bitCast(try data.varint()),
                5 => value.data.last_call_started = try decodeTimestamp(try data.bytesValue()),
                else => try data.skip(item),
            };
        },
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
        return decodeServerSockets(message.payload);
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

fn encodeChannel(out: *std.ArrayList(u8), allocator: std.mem.Allocator, channel: *const Channel) !void {
    var ref: std.ArrayList(u8) = .empty;
    defer ref.deinit(allocator);
    try putVarintField(&ref, allocator, 1, @intCast(channel.id));
    if (channel.name.len != 0) try putBytesField(&ref, allocator, 2, channel.name);
    try putBytesField(out, allocator, 1, ref.items);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    var state: std.ArrayList(u8) = .empty;
    defer state.deinit(allocator);
    try putVarintField(&state, allocator, 1, channel.state.load(.acquire));
    try putBytesField(&data, allocator, 1, state.items);
    if (channel.target.len != 0) try putBytesField(&data, allocator, 2, channel.target);
    const started = channel.calls_started.load(.monotonic);
    const succeeded = channel.calls_succeeded.load(.monotonic);
    const failed = channel.calls_failed.load(.monotonic);
    if (started != 0) try putVarintField(&data, allocator, 4, @bitCast(started));
    if (succeeded != 0) try putVarintField(&data, allocator, 5, @bitCast(succeeded));
    if (failed != 0) try putVarintField(&data, allocator, 6, @bitCast(failed));
    const last = channel.last_call_started_ns.load(.acquire);
    if (last != 0) try putTimestampField(&data, allocator, 7, last);
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
    const started = server.calls_started.load(.monotonic);
    const succeeded = server.calls_succeeded.load(.monotonic);
    const failed = server.calls_failed.load(.monotonic);
    if (started != 0) try putVarintField(&data, allocator, 2, @bitCast(started));
    if (succeeded != 0) try putVarintField(&data, allocator, 3, @bitCast(succeeded));
    if (failed != 0) try putVarintField(&data, allocator, 4, @bitCast(failed));
    const last = server.last_call_started_ns.load(.acquire);
    if (last != 0) try putTimestampField(&data, allocator, 5, last);
    try putBytesField(out, allocator, 2, data.items);
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

//! Owned EndpointServer commands, admission metadata, and results.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const runtime = @import("../runtime.zig");
const state_model = @import("../state.zig");
const client_job = @import("../endpoint_client/job.zig");

pub const Handle = client_job.Handle;
pub const Event = client_job.Event;
pub const Bytes = client_job.Bytes;

pub const PendingHandle = struct {
    index: u32,
    generation: u64,
};

pub const RequestData = struct {
    allocator: std.mem.Allocator,
    handle: PendingHandle,
    path: []u8,
    authority: ?[]u8,
    origin: ?[]u8,
    headers: []http2.Hpack.HeaderField,

    pub fn clone(allocator: std.mem.Allocator, handle: PendingHandle, request: *const runtime.PendingDuplexSession) std.mem.Allocator.Error!RequestData {
        const headers = try cloneOwnedHeaders(allocator, request.request.headers);
        errdefer freeOwnedHeaders(allocator, headers);
        const path = try allocator.dupe(u8, request.request.path);
        errdefer allocator.free(path);
        const authority = if (request.request.authority) |value| try allocator.dupe(u8, value) else null;
        errdefer if (authority) |value| allocator.free(value);
        const origin = findHeader(request.request.headers, "origin");
        const owned_origin = if (origin) |value| try allocator.dupe(u8, value) else null;
        return .{ .allocator = allocator, .handle = handle, .path = path, .authority = authority, .origin = owned_origin, .headers = headers };
    }

    pub fn header(self: RequestData, name: []const u8) ?[]const u8 {
        return findHeader(self.headers, name);
    }

    pub fn deinit(self: *RequestData) void {
        freeOwnedHeaders(self.allocator, self.headers);
        self.allocator.free(self.path);
        if (self.authority) |value| self.allocator.free(value);
        if (self.origin) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

pub const Accepted = struct {
    allocator: std.mem.Allocator,
    handle: Handle,
    selected_protocol: ?[]u8,

    pub fn clone(allocator: std.mem.Allocator, handle: Handle, selected: ?[]const u8) std.mem.Allocator.Error!Accepted {
        return .{ .allocator = allocator, .handle = handle, .selected_protocol = if (selected) |value| try allocator.dupe(u8, value) else null };
    }

    pub fn deinit(self: *Accepted) void {
        if (self.selected_protocol) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

fn findHeader(headers: []const http2.Hpack.HeaderField, name: []const u8) ?[]const u8 {
    for (headers) |header| if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
    return null;
}

fn cloneOwnedHeaders(allocator: std.mem.Allocator, source: []const http2.Hpack.HeaderField) std.mem.Allocator.Error![]http2.Hpack.HeaderField {
    const headers = try allocator.alloc(http2.Hpack.HeaderField, source.len);
    var initialized: usize = 0;
    errdefer {
        for (headers[0..initialized]) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        allocator.free(headers);
    }
    for (source, headers) |field, *target| {
        const name = try allocator.dupe(u8, field.name);
        const value = allocator.dupe(u8, field.value) catch |err| {
            allocator.free(name);
            return err;
        };
        target.* = .{ .name = name, .value = value, .never_index = field.never_index };
        initialized += 1;
    }
    return headers;
}

fn freeOwnedHeaders(allocator: std.mem.Allocator, headers: []http2.Hpack.HeaderField) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

pub const Command = union(enum) {
    receive_request,
    accept: struct { handle: PendingHandle, options: runtime.ServerOptions },
    reject: struct { handle: PendingHandle, options: runtime.RejectOptions },
    abandon_pending: PendingHandle,
    send_datagram: struct { handle: Handle, data: []const u8 },
    receive: Handle,
    close: struct { handle: Handle, code: u32, reason: []const u8 },
    remove: Handle,
    open_stream: struct { handle: Handle, direction: state_model.Direction },
    send_stream: struct { handle: Handle, id: u62, data: []const u8, fin: bool },
    consume: struct { handle: Handle, id: u62, bytes: u64 },
    retire_stream: struct { handle: Handle, id: u62 },
    reset_stream: struct { handle: Handle, id: u62, code: u32 },
    stop_sending: struct { handle: Handle, id: u62, code: u32 },
    grant_data: struct { handle: Handle, limit: u64 },
    grant_streams: struct { handle: Handle, direction: state_model.Direction, limit: u64 },
    grant_stream_data: struct { handle: Handle, id: u62, limit: u64 },
    drain: Handle,
    export_keying_material: struct { handle: Handle, label: []const u8, context: []const u8, length: usize },
};

fn cloneHeaders(allocator: std.mem.Allocator, headers: []const http2.Hpack.HeaderField) std.mem.Allocator.Error![]const http2.Hpack.HeaderField {
    return try cloneOwnedHeaders(allocator, headers);
}

fn cloneProtocols(allocator: std.mem.Allocator, values: []const []const u8) std.mem.Allocator.Error![]const []const u8 {
    const result = try allocator.alloc([]const u8, values.len);
    for (values, result) |value, *target| target.* = try allocator.dupe(u8, value);
    return result;
}

fn cloneServerOptions(allocator: std.mem.Allocator, source: runtime.ServerOptions) std.mem.Allocator.Error!runtime.ServerOptions {
    return .{
        .origin = switch (source.origin) {
            .same_origin_or_absent => .same_origin_or_absent,
            .allow_any => .allow_any,
            .exact => |values| .{ .exact = try cloneProtocols(allocator, values) },
        },
        .protocols = .{ .values = try cloneProtocols(allocator, source.protocols.values), .required = source.protocols.required },
        .headers = try cloneHeaders(allocator, source.headers),
        .initial_receive_stream_data = source.initial_receive_stream_data,
        .session = source.session,
    };
}

fn cloneRejectOptions(allocator: std.mem.Allocator, source: runtime.RejectOptions) std.mem.Allocator.Error!runtime.RejectOptions {
    return .{
        .status = source.status,
        .headers = try cloneHeaders(allocator, source.headers),
        .body = try allocator.dupe(u8, source.body),
        .trailers = try cloneHeaders(allocator, source.trailers),
    };
}

fn cloneCommand(allocator: std.mem.Allocator, source: Command) std.mem.Allocator.Error!Command {
    return switch (source) {
        .accept => |value| .{ .accept = .{ .handle = value.handle, .options = try cloneServerOptions(allocator, value.options) } },
        .reject => |value| .{ .reject = .{ .handle = value.handle, .options = try cloneRejectOptions(allocator, value.options) } },
        .send_datagram => |value| .{ .send_datagram = .{ .handle = value.handle, .data = try allocator.dupe(u8, value.data) } },
        .send_stream => |value| .{ .send_stream = .{ .handle = value.handle, .id = value.id, .data = try allocator.dupe(u8, value.data), .fin = value.fin } },
        .close => |value| .{ .close = .{ .handle = value.handle, .code = value.code, .reason = try allocator.dupe(u8, value.reason) } },
        .export_keying_material => |value| .{ .export_keying_material = .{
            .handle = value.handle,
            .label = try allocator.dupe(u8, value.label),
            .context = try allocator.dupe(u8, value.context),
            .length = value.length,
        } },
        else => source,
    };
}

pub fn Job(comptime State: type) type {
    return struct {
        const Self = @This();
        pub const Completion = enum(u32) { waiting, completed, abandoned };

        parent: *State,
        refs: std.atomic.Value(usize) = .init(1),
        completion: std.atomic.Value(Completion) = .init(.waiting),
        arena: std.heap.ArenaAllocator,
        command: Command,
        deadline: std.Io.Clock.Timestamp,
        next: ?*Self = null,
        waiting_request: bool = false,
        request: ?RequestData = null,
        accepted: ?Accepted = null,
        event: ?Event = null,
        stream_id: ?u62 = null,
        removed: ?bool = null,
        bytes: ?Bytes = null,
        err: ?anyerror = null,
        done: std.Io.Event = .unset,

        pub fn create(parent: *State, command: Command, deadline: std.Io.Clock.Timestamp) std.mem.Allocator.Error!*Self {
            const job = try parent.allocator.create(Self);
            job.* = .{ .parent = parent, .arena = .init(parent.allocator), .command = undefined, .deadline = deadline };
            errdefer {
                job.arena.deinit();
                parent.allocator.destroy(job);
            }
            job.command = try cloneCommand(job.arena.allocator(), command);
            parent.retain();
            return job;
        }
        pub fn retain(self: *Self) void {
            _ = self.refs.fetchAdd(1, .monotonic);
        }
        pub fn release(self: *Self) void {
            if (self.refs.fetchSub(1, .acq_rel) != 1) return;
            std.debug.assert(!self.waiting_request);
            if (self.request) |*value| value.deinit();
            if (self.accepted) |*value| value.deinit();
            if (self.event) |*value| value.deinit();
            if (self.bytes) |*value| value.deinit();
            const parent = self.parent;
            self.arena.deinit();
            parent.allocator.destroy(self);
            parent.release();
        }
        pub fn abandon(self: *Self) bool {
            return self.completion.cmpxchgStrong(.waiting, .abandoned, .acq_rel, .acquire) == null;
        }
        pub fn canceled(self: *const Self) bool {
            return self.completion.load(.acquire) == .abandoned;
        }
        pub fn checkExecution(self: *const Self, io: std.Io) error{ Canceled, Timeout }!void {
            if (self.canceled()) return error.Canceled;
            if (self.deadline.clock != .awake or self.deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        }
        pub fn takeRequest(self: *Self) RequestData {
            const value = self.request.?;
            self.request = null;
            return value;
        }
        pub fn takeAccepted(self: *Self) Accepted {
            const value = self.accepted.?;
            self.accepted = null;
            return value;
        }
        pub fn takeEvent(self: *Self) Event {
            const value = self.event.?;
            self.event = null;
            return value;
        }
        pub fn takeBytes(self: *Self) Bytes {
            const value = self.bytes.?;
            self.bytes = null;
            return value;
        }
    };
}

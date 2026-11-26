//! Owned commands and results shared by endpoint callers and its sole worker.
const std = @import("std");
const slice_storage = @import("../endpoint/slice_storage.zig");
const capsule = @import("../capsule.zig");
const state = @import("../state.zig");
const runtime = @import("../runtime.zig");
const session_mod = @import("../session.zig");

pub const Handle = struct {
    index: u32,
    generation: u64,
};

pub const Accepted = struct {
    allocator: std.mem.Allocator,
    handle: Handle,
    status: u16,
    headers: []@import("../../../http2/mod.zig").Hpack.HeaderField,
    selected_protocol: ?[]u8,

    pub fn clone(allocator: std.mem.Allocator, handle: Handle, session: *const session_mod.Session) std.mem.Allocator.Error!Accepted {
        const Header = @import("../../../http2/mod.zig").Hpack.HeaderField;
        const source = session.responseHeaders();
        const headers = try allocator.alloc(Header, source.len);
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
        const selected = if (session.selected_protocol) |value| try allocator.dupe(u8, value) else null;
        return .{ .allocator = allocator, .handle = handle, .status = session.responseStatus().?, .headers = headers, .selected_protocol = selected };
    }

    pub fn responseHeader(self: Accepted, name: []const u8) ?[]const u8 {
        for (self.headers) |header| if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        return null;
    }

    pub fn deinit(self: *Accepted) void {
        for (self.headers) |header| {
            self.allocator.free(header.name);
            self.allocator.free(header.value);
        }
        self.allocator.free(self.headers);
        if (self.selected_protocol) |value| self.allocator.free(value);
        self.* = undefined;
    }
};

pub const Event = struct {
    allocator: std.mem.Allocator,
    value: Value,

    pub const Value = union(enum) {
        stream: capsule.Stream,
        reset: capsule.Reset,
        stopped: capsule.StreamError,
        datagram: []u8,
        closed: struct { code: u32, reason: []u8 },
        draining,
        progress,
    };

    pub fn clone(allocator: std.mem.Allocator, source: session_mod.Event) std.mem.Allocator.Error!Event {
        return .{ .allocator = allocator, .value = switch (source) {
            .stream => |stream| .{ .stream = .{ .id = stream.id, .data = try allocator.dupe(u8, stream.data), .fin = stream.fin } },
            .reset => |reset| .{ .reset = reset },
            .stopped => |stopped| .{ .stopped = stopped },
            .datagram => |data| .{ .datagram = try allocator.dupe(u8, data) },
            .closed => |closed| .{ .closed = .{ .code = closed.code, .reason = try allocator.dupe(u8, closed.reason) } },
            .draining => .draining,
            .progress => .progress,
        } };
    }

    pub fn deinit(self: *Event) void {
        switch (self.value) {
            .stream => |stream| self.allocator.free(stream.data),
            .datagram => |data| self.allocator.free(data),
            .closed => |closed| self.allocator.free(closed.reason),
            else => {},
        }
        self.* = undefined;
    }
};

pub const Bytes = struct {
    allocator: std.mem.Allocator,
    value: []u8,

    pub fn deinit(self: *Bytes) void {
        self.allocator.free(self.value);
        self.* = undefined;
    }
};

pub const Command = union(enum) {
    connect: runtime.ClientOptions,
    send_datagram: struct { handle: Handle, data: []const u8 },
    receive: Handle,
    close: struct { handle: Handle, code: u32, reason: []const u8 },
    remove: Handle,
    open_stream: struct { handle: Handle, direction: state.Direction },
    send_stream: struct { handle: Handle, id: u62, data: []const u8, fin: bool },
    consume: struct { handle: Handle, id: u62, bytes: u64 },
    retire_stream: struct { handle: Handle, id: u62 },
    reset_stream: struct { handle: Handle, id: u62, code: u32 },
    stop_sending: struct { handle: Handle, id: u62, code: u32 },
    grant_data: struct { handle: Handle, limit: u64 },
    grant_streams: struct { handle: Handle, direction: state.Direction, limit: u64 },
    grant_stream_data: struct { handle: Handle, id: u62, limit: u64 },
    drain: Handle,
    export_keying_material: struct { handle: Handle, label: []const u8, context: []const u8, length: usize },
};

fn cloneHeaders(allocator: std.mem.Allocator, headers: []const @import("../../../http2/mod.zig").Hpack.HeaderField) std.mem.Allocator.Error![]const @import("../../../http2/mod.zig").Hpack.HeaderField {
    const result = try allocator.alloc(@import("../../../http2/mod.zig").Hpack.HeaderField, headers.len);
    for (headers, result) |source, *target| target.* = .{
        .name = try allocator.dupe(u8, source.name),
        .value = try allocator.dupe(u8, source.value),
        .never_index = source.never_index,
    };
    return result;
}

fn cloneConnect(allocator: std.mem.Allocator, source: runtime.ClientOptions) std.mem.Allocator.Error!runtime.ClientOptions {
    const values = try allocator.alloc([]const u8, source.protocols.values.len);
    for (source.protocols.values, values) |value, *target| target.* = try allocator.dupe(u8, value);
    return .{
        .path = try allocator.dupe(u8, source.path),
        .authority = try allocator.dupe(u8, source.authority),
        .origin = if (source.origin) |origin| try allocator.dupe(u8, origin) else null,
        .headers = try cloneHeaders(allocator, source.headers),
        .initial_receive_stream_data = source.initial_receive_stream_data,
        .protocols = .{ .values = values, .required = source.protocols.required },
        .session = source.session,
    };
}

fn cloneCommand(allocator: std.mem.Allocator, source: Command) std.mem.Allocator.Error!Command {
    return switch (source) {
        .connect => |options| .{ .connect = try cloneConnect(allocator, options) },
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
        accepted: ?Accepted = null,
        rejection: ?runtime.Rejection = null,
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

        pub fn createStreamSlices(parent: *State, handle: Handle, id: u62, slices: []const []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) (std.mem.Allocator.Error || error{CapsuleTooLarge})!*Self {
            const length = try slice_storage.byteLength(slices);
            // An empty payload initializes the regular command lifecycle without
            // allocating payload storage. The arena then owns the sole copy.
            const job = try create(parent, .{ .send_stream = .{ .handle = handle, .id = id, .data = &.{}, .fin = fin } }, deadline);
            errdefer job.release();
            const data = try job.arena.allocator().alloc(u8, length);
            slice_storage.copy(data, slices);
            job.command.send_stream.data = data;
            return job;
        }

        pub fn retain(self: *Self) void {
            _ = self.refs.fetchAdd(1, .monotonic);
        }

        pub fn release(self: *Self) void {
            if (self.refs.fetchSub(1, .acq_rel) != 1) return;
            if (self.accepted) |*accepted| accepted.deinit();
            if (self.rejection) |*rejection| rejection.deinit();
            if (self.event) |*event| event.deinit();
            if (self.bytes) |*bytes| bytes.deinit();
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

        /// Called by the sole owner before any Session state or output is
        /// changed. The waiter may not yet have run its own timeout path.
        pub fn checkExecution(self: *const Self, io: std.Io) error{ Canceled, Timeout }!void {
            if (self.canceled()) return error.Canceled;
            if (self.deadline.clock != .awake or self.deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        }

        pub fn takeRejection(self: *Self) runtime.Rejection {
            const result = self.rejection.?;
            self.rejection = null;
            return result;
        }

        pub fn takeAccepted(self: *Self) Accepted {
            const result = self.accepted.?;
            self.accepted = null;
            return result;
        }

        pub fn takeEvent(self: *Self) Event {
            const result = self.event.?;
            self.event = null;
            return result;
        }

        pub fn takeBytes(self: *Self) Bytes {
            const result = self.bytes.?;
            self.bytes = null;
            return result;
        }
    };
}

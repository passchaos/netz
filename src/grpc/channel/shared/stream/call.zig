//! Heap-owned RPC state shared by its transport owner and user capabilities.
const std = @import("std");
const streaming = @import("../../../stream/runtime.zig");
const duplex = @import("../../../stream/duplex.zig");
const outbound_ownership = @import("../../../stream/duplex/outbound_ownership.zig");
const codec = @import("../../../stream/codec.zig");
const wire = @import("../../../wire.zig");
const http2 = @import("../../../../http2/mod.zig");
const inputs = @import("../request_inputs.zig");
const Wake = @import("../wake.zig").Wake;

pub const Message = codec.OwnedDecodedMessage;

pub const Event = union(enum) {
    informational: http2.runtime.DuplexResponseHead,
    initial_metadata: http2.runtime.DuplexResponseHead,
    message: Message,
    terminal: duplex.Response,
    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .informational, .initial_metadata => |*head| head.deinit(allocator),
            .message => |*message| message.deinit(),
            .terminal => |*response| response.deinit(),
        }
        self.* = undefined;
    }
};

pub const WriteInput = struct {
    payload: []const u8 = &.{},
    options: codec.MessageOptions = .{},
    final: bool = false,
    finish_only: bool = false,
    deadline: ?std.Io.Clock.Timestamp = null,
};

/// Prefix-reserved payload storage for zero-copy handoff into a queued shared
/// write. Allocate it through `Writer.allocMessage`, serialize directly into
/// `payload`, and either submit it or call `deinit`.
pub const OwnedWriteMessage = outbound_ownership.OwnedMessage;

pub const Write = struct {
    const Completion = enum(u32) { waiting, completed, abandoned };
    allocator: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    completion: std.atomic.Value(Completion) = .init(.waiting),
    storage: []u8,
    payload_released: bool = false,
    options: codec.MessageOptions,
    final: bool,
    finish_only: bool,
    deadline: ?std.Io.Clock.Timestamp,
    staged: bool = false,
    done: std.Io.Event = .unset,
    err: ?anyerror = null,

    pub fn create(
        allocator: std.mem.Allocator,
        input: WriteInput,
    ) (std.mem.Allocator.Error || error{GrpcMessageTooLarge})!*Write {
        const command = try allocator.create(Write);
        errdefer allocator.destroy(command);
        const encoded_len = if (input.finish_only)
            0
        else
            wire.encodedMessageLen(input.payload.len) catch
                return error.GrpcMessageTooLarge;
        const storage = try allocator.alloc(u8, encoded_len);
        if (!input.finish_only) @memcpy(storage[5..], input.payload);
        command.* = .{
            .allocator = allocator,
            .storage = storage,
            .options = input.options,
            .final = input.final,
            .finish_only = input.finish_only,
            .deadline = input.deadline,
        };
        return command;
    }
    pub fn createOwned(
        allocator: std.mem.Allocator,
        message: *OwnedWriteMessage,
        input: WriteInput,
    ) (std.mem.Allocator.Error || error{InvalidStreamState})!*Write {
        std.debug.assert(!input.finish_only and input.payload.len == 0);
        const command = try allocator.create(Write);
        errdefer allocator.destroy(command);
        command.* = .{
            .allocator = allocator,
            .storage = try message.takeFor(allocator),
            .options = input.options,
            .final = input.final,
            .finish_only = false,
            .deadline = input.deadline,
        };
        return command;
    }
    pub fn retain(self: *Write) void {
        _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Write) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (!self.payload_released) self.allocator.free(self.storage);
        self.allocator.destroy(self);
    }
    pub fn payload(self: *const Write) []const u8 {
        std.debug.assert(!self.payload_released and !self.finish_only);
        return self.storage[5..];
    }
    pub fn messageStorage(self: *Write) []u8 {
        std.debug.assert(!self.payload_released and !self.finish_only);
        return self.storage;
    }
    /// The transport staging buffer owns the encoded message after this point.
    pub fn releasePayload(self: *Write) void {
        std.debug.assert(!self.payload_released);
        self.allocator.free(self.storage);
        self.storage = &.{};
        self.payload_released = true;
    }
    /// Transfer the prefix-reserved allocation to the transport staging
    /// buffer after it has accepted ownership.
    pub fn transferPayload(self: *Write) []u8 {
        std.debug.assert(!self.payload_released);
        const storage = self.storage;
        self.storage = &.{};
        self.payload_released = true;
        return storage;
    }
    pub fn abandon(self: *Write) bool {
        return self.completion.cmpxchgStrong(.waiting, .abandoned, .acq_rel, .acquire) == null;
    }
    pub fn complete(self: *Write, io: std.Io, err: ?anyerror) void {
        self.err = err;
        const previous = self.completion.cmpxchgStrong(.waiting, .completed, .release, .acquire);
        if (previous == null) {
            self.done.set(io);
        } else std.debug.assert(previous.? == .abandoned);
        self.release();
    }
};

pub fn Call(comptime State: type) type {
    return struct {
        parent: *State,
        options: streaming.RequestOptions,
        owned_inputs: inputs.Inputs,
        deadline: ?std.Io.Clock.Timestamp,
        refs: std.atomic.Value(usize) = .init(1),
        cancel_requested: std.atomic.Value(bool) = .init(false),
        owner_wake: std.atomic.Value(?*Wake) = .init(null),
        retired: bool = false,
        retired_event: std.Io.Event = .unset,
        changed: std.Io.Event = .unset,
        failure_code: std.atomic.Value(std.meta.Int(.unsigned, @bitSizeOf(anyerror))) = .init(0),
        write: ?*Write = null,
        request_finished: bool = false,
        read_busy: std.atomic.Value(bool) = .init(false),
        parse_body: bool = false,
        initial: ?http2.runtime.DuplexResponseHead = null,
        information: std.ArrayList(http2.runtime.DuplexResponseHead) = .empty,
        terminal: ?duplex.Response = null,
        terminal_taken: bool = false,
        bytes: []u8 = &.{},
        head: usize = 0,
        len: usize = 0,
        credit: usize = 0,
        decoder: ?codec.Decoder = null,
        chunk: ?[]u8 = null,
        chunk_offset: usize = 0,

        const Self = @This();
        pub fn create(parent: *State, options: streaming.RequestOptions, deadline: ?std.Io.Clock.Timestamp) State.Failure!*Self {
            const call = try parent.allocator.create(Self);
            errdefer parent.allocator.destroy(call);
            const owned = try inputs.clone(parent.allocator, options);
            parent.retain();
            call.* = .{ .parent = parent, .options = owned.options, .owned_inputs = owned.inputs, .deadline = deadline };
            return call;
        }
        pub fn retain(self: *Self) void {
            _ = self.refs.fetchAdd(1, .monotonic);
        }
        pub fn release(self: *Self) void {
            if (self.refs.fetchSub(1, .acq_rel) != 1) return;
            const allocator = self.parent.allocator;
            std.debug.assert(self.retired and self.write == null);
            if (self.initial) |*head| head.deinit(allocator);
            for (self.information.items) |*head| head.deinit(allocator);
            self.information.deinit(allocator);
            if (self.terminal) |*response| response.deinit();
            if (self.decoder) |*decoder| decoder.deinit();
            if (self.chunk) |chunk| allocator.free(chunk);
            allocator.free(self.bytes);
            self.owned_inputs.deinit();
            if (self.owner_wake.load(.acquire)) |wake| wake.release();
            const parent = self.parent;
            allocator.destroy(self);
            parent.release();
        }
        pub fn setOwnerWake(self: *Self, wake: *Wake) void {
            wake.retain();
            std.debug.assert(self.owner_wake.swap(wake, .release) == null);
        }
        pub fn requestCancel(self: *Self) void {
            self.cancel_requested.store(true, .release);
            if (self.owner_wake.load(.acquire)) |wake| wake.set(self.parent.io);
        }
        pub fn fail(self: *Self, err: anyerror) void {
            const ErrorInt = std.meta.Int(.unsigned, @bitSizeOf(anyerror));
            _ = self.failure_code.cmpxchgStrong(0, @as(ErrorInt, @intFromError(err)), .acq_rel, .acquire);
        }
        pub fn failureValue(self: *const Self) ?anyerror {
            const code = self.failure_code.load(.acquire);
            return if (code == 0) null else @errorFromInt(code);
        }
        pub fn cancel(self: *Self) void {
            self.requestCancel();
            self.retired_event.waitUncancelable(self.parent.io);
        }
        pub fn cancelBefore(self: *Self, deadline: std.Io.Clock.Timestamp) std.Io.Event.WaitTimeoutError!void {
            self.requestCancel();
            while (true) {
                self.retired_event.waitTimeout(self.parent.io, .{ .deadline = deadline }) catch |err| {
                    // A timed Event wait can report a spurious futex wake as
                    // Timeout. Only the caller's absolute deadline expires it.
                    if (err == error.Timeout and deadline.durationFromNow(self.parent.io).raw.nanoseconds > 0) continue;
                    return err;
                };
                return;
            }
        }
        pub fn appendLocked(self: *Self, data: []const u8) State.Failure!void {
            if (data.len > self.bytes.len - self.len) return error.StreamReceiveBufferExceeded;
            if (data.len == 0) return;
            const tail = (self.head + self.len) % self.bytes.len;
            const first = @min(data.len, self.bytes.len - tail);
            @memcpy(self.bytes[tail..][0..first], data[0..first]);
            @memcpy(self.bytes[0 .. data.len - first], data[first..]);
            self.len += data.len;
            self.changed.set(self.parent.io);
        }
        pub fn finishWriteLocked(self: *Self, err: ?anyerror) void {
            const write = self.write orelse return;
            self.write = null;
            write.complete(self.parent.io, err);
        }
        /// The opening caller owns the sole reference until enqueue succeeds.
        /// No endpoint owner or capability can observe this unpublished call.
        pub fn retireUnsubmitted(self: *Self, err: anyerror) void {
            std.debug.assert(self.refs.load(.acquire) == 1 and self.write == null);
            self.retireLocked(err);
        }

        pub fn retireLocked(self: *Self, err: ?anyerror) void {
            if (self.retired) return;
            if (err) |value| self.fail(value);
            self.finishWriteLocked(self.failureValue() orelse error.ConnectionClosed);
            self.retired = true;
            self.changed.set(self.parent.io);
            self.retired_event.set(self.parent.io);
        }
    };
}

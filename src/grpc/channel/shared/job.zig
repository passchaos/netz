const std = @import("std");
const call = @import("../../call.zig");
const inputs = @import("request_inputs.zig");
const Wake = @import("wake.zig").Wake;
const State = @import("state.zig").State;
const ring_hash = @import("../ring_hash.zig");
const HedgeControl = @import("hedging/control.zig").Control;

pub const Job = struct {
    pub const Completion = enum(u32) { waiting, completed, abandoned };
    parent: ?*State = null,
    refs: std.atomic.Value(usize) = .init(1),
    completion: std.atomic.Value(Completion) = .init(.waiting),
    owner_wake: std.atomic.Value(?*Wake) = .init(null),
    owned_inputs: ?inputs.Inputs = null,
    /// Prefix-reserved storage: bytes 0..5 are the gRPC frame header and the
    /// remaining bytes own the caller payload.
    owned_message: ?[]u8 = null,
    options: call.UnaryCallOptions,
    deadline: ?std.Io.Clock.Timestamp,
    rpc_deadline: ?std.Io.Clock.Timestamp = null,
    wait_for_ready: bool,
    previous_attempts: ?u8,
    routing_hash: ?ring_hash.RequestHash = null,
    selected_worker: ?*State.Worker = null,
    drop_revision: u64 = 0,
    cluster_drop_revision: u64 = 0,
    circuit_permit: ?@import("../circuit_breaker.zig").Permit = null,
    stream: ?*@import("state.zig").State.StreamCall = null,
    next: ?*Job = null,
    result: ?call.UnaryResponse = null,
    err: ?anyerror = null,
    done: std.Io.Event = .unset,
    /// Set by the worker after the unary stream opens; completion then reports LRS stats.
    lrs_registration: ?@import("lrs_stats.zig").Registration = null,
    /// Retained beyond an interrupted caller until this physical job retires.
    hedging_control: ?*HedgeControl = null,

    pub fn create(
        parent: *State,
        options: call.UnaryCallOptions,
        deadline: ?std.Io.Clock.Timestamp,
        rpc_deadline: ?std.Io.Clock.Timestamp,
        previous: ?u8,
    ) (std.mem.Allocator.Error || error{ MissingRequestHash, GrpcMessageTooLarge, InvalidMessageCount })!*Job {
        const allocator = parent.allocator;
        const routing_hash: ?ring_hash.RequestHash = null;
        const job = try allocator.create(Job);
        errdefer allocator.destroy(job);
        var request = try inputs.clone(allocator, options);
        errdefer request.inputs.deinit();
        const payload = if (options.owned_message) |owned| blk: {
            if (options.message.len != 0) return error.InvalidMessageCount;
            break :blk owned.payload();
        } else options.message;
        if (payload.len > std.math.maxInt(u32)) {
            return error.GrpcMessageTooLarge;
        }
        const encoded_len = std.math.add(
            usize,
            5,
            payload.len,
        ) catch return error.GrpcMessageTooLarge;
        const message = try allocator.alloc(u8, encoded_len);
        errdefer allocator.free(message);
        @memcpy(message[5..], payload);
        request.options.message = message[5..];
        // The job owns its queued copy; the caller's prefix-reserved storage
        // stays caller-owned and reusable.
        request.options.owned_message = null;
        parent.retain();
        job.* = .{ .parent = parent, .options = request.options, .deadline = deadline, .rpc_deadline = rpc_deadline, .wait_for_ready = options.wait_for_ready orelse false, .previous_attempts = previous, .routing_hash = routing_hash, .owned_inputs = request.inputs, .owned_message = message };
        return job;
    }

    pub fn createStream(parent: *State, stream: *State.StreamCall, deadline: ?std.Io.Clock.Timestamp, ready: bool) (std.mem.Allocator.Error || error{MissingRequestHash})!*Job {
        const routing_hash: ?ring_hash.RequestHash = null;
        const job = try parent.allocator.create(Job);
        parent.retain();
        stream.retain();
        job.* = .{ .parent = parent, .options = .{ .path = stream.options.path, .message = &.{} }, .deadline = deadline, .rpc_deadline = null, .wait_for_ready = ready, .previous_attempts = null, .routing_hash = routing_hash, .stream = stream };
        return job;
    }
    pub fn retain(self: *Job) void {
        if (self.parent != null) _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Job) void {
        const parent = self.parent orelse return;
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.circuit_permit) |*permit| permit.release();
        if (self.result) |*result| result.deinit();
        self.releaseMessage();
        if (self.owned_inputs) |*owned| owned.deinit();
        if (self.lrs_registration) |registration| registration.release();
        if (self.hedging_control) |control| control.release();
        if (self.stream) |stream| stream.release();
        if (self.owner_wake.load(.acquire)) |wake| wake.release();
        parent.allocator.destroy(self);
        parent.release();
    }
    pub fn releaseMessage(self: *Job) void {
        if (self.owned_message) |message| {
            self.parent.?.allocator.free(message);
            self.owned_message = null;
            self.options.message = &.{};
        }
    }
    pub fn setOwnerWake(self: *Job, wake: *Wake) void {
        wake.retain();
        std.debug.assert(self.owner_wake.swap(wake, .release) == null);
    }
    pub fn requestHash(
        self: *const Job,
        io: std.Io,
        config: ring_hash.Config,
    ) error{MissingRequestHash}!ring_hash.RequestHash {
        if (self.stream) |stream| {
            return ring_hash.requestHash(io, config, stream.options);
        }
        return ring_hash.requestHash(io, config, self.options);
    }
    pub fn abandon(self: *Job) bool {
        return self.completion.cmpxchgStrong(.waiting, .abandoned, .acq_rel, .acquire) == null;
    }
    pub fn canceled(self: *const Job) bool {
        return self.completion.load(.acquire) == .abandoned or
            if (self.hedging_control) |control| control.isLoser(self.hedgeIndex()) else false;
    }
    pub fn hedgeIndex(self: *const Job) u8 {
        return self.previous_attempts orelse 0;
    }
    pub fn setHedgingControl(self: *Job, control: *HedgeControl) void {
        std.debug.assert(self.hedging_control == null);
        control.retain();
        self.hedging_control = control;
    }
    pub fn takeResult(self: *Job) call.UnaryResponse {
        const result = self.result.?;
        self.result = null;
        return result;
    }
};

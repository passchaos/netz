const std = @import("std");
const call = @import("../../call.zig");
const inputs = @import("request_inputs.zig");
const Wake = @import("wake.zig").Wake;
const State = @import("state.zig").State;

pub const Job = struct {
    pub const Completion = enum(u32) { waiting, completed, abandoned };
    parent: ?*State = null,
    refs: std.atomic.Value(usize) = .init(1),
    completion: std.atomic.Value(Completion) = .init(.waiting),
    owner_wake: std.atomic.Value(?*Wake) = .init(null),
    owned_inputs: ?inputs.Inputs = null,
    owned_message: ?[]u8 = null,
    options: call.UnaryCallOptions,
    deadline: ?std.Io.Clock.Timestamp,
    rpc_deadline: ?std.Io.Clock.Timestamp = null,
    wait_for_ready: bool,
    previous_attempts: ?u8,
    stream: ?*@import("state.zig").State.StreamCall = null,
    next: ?*Job = null,
    result: ?call.UnaryResponse = null,
    err: ?anyerror = null,
    done: std.Io.Event = .unset,

    pub fn create(
        parent: *State,
        options: call.UnaryCallOptions,
        deadline: ?std.Io.Clock.Timestamp,
        rpc_deadline: ?std.Io.Clock.Timestamp,
        previous: ?u8,
    ) std.mem.Allocator.Error!*Job {
        const allocator = parent.allocator;
        const job = try allocator.create(Job);
        errdefer allocator.destroy(job);
        var request = try inputs.clone(allocator, options);
        errdefer request.inputs.deinit();
        const message = try allocator.dupe(u8, options.message);
        request.options.message = message;
        parent.retain();
        job.* = .{ .parent = parent, .options = request.options, .deadline = deadline, .rpc_deadline = rpc_deadline, .wait_for_ready = options.wait_for_ready orelse false, .previous_attempts = previous, .owned_inputs = request.inputs, .owned_message = message };
        return job;
    }

    pub fn createStream(parent: *State, stream: *State.StreamCall, deadline: ?std.Io.Clock.Timestamp, ready: bool) std.mem.Allocator.Error!*Job {
        const job = try parent.allocator.create(Job);
        parent.retain();
        stream.retain();
        job.* = .{ .parent = parent, .options = .{ .path = stream.options.path, .message = &.{} }, .deadline = deadline, .rpc_deadline = null, .wait_for_ready = ready, .previous_attempts = null, .stream = stream };
        return job;
    }
    pub fn retain(self: *Job) void {
        if (self.parent != null) _ = self.refs.fetchAdd(1, .monotonic);
    }
    pub fn release(self: *Job) void {
        const parent = self.parent orelse return;
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        if (self.result) |*result| result.deinit();
        self.releaseMessage();
        if (self.owned_inputs) |*owned| owned.deinit();
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
    pub fn abandon(self: *Job) bool {
        return self.completion.cmpxchgStrong(.waiting, .abandoned, .acq_rel, .acquire) == null;
    }
    pub fn canceled(self: *const Job) bool {
        return self.completion.load(.acquire) == .abandoned;
    }
    pub fn takeResult(self: *Job) call.UnaryResponse {
        const result = self.result.?;
        self.result = null;
        return result;
    }
};

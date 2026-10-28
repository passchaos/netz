//! Reference-counted send handles and concurrent background endpoint owners.
const std = @import("std");
const channel = @import("../channel.zig");
const call = @import("../call.zig");
const connectivity = @import("connectivity.zig");
const state_module = @import("shared/state.zig");
const State = state_module.State;
const streaming = @import("../stream/runtime.zig");
pub const Duplex = @import("shared/stream.zig").Duplex;
pub const StreamWriter = @import("shared/stream.zig").Writer;
pub const StreamReader = @import("shared/stream.zig").Reader;
pub const StreamEvent = @import("shared/stream.zig").Event;
pub const Error = state_module.Error;
pub const Options = state_module.Options;

pub const Sender = struct {
    state: *State,
    pub fn clone(self: Sender) Sender {
        self.state.retain();
        return self;
    }
    pub fn deinit(self: *Sender) void {
        self.state.release();
        self.* = undefined;
    }
    pub fn unary(self: Sender, options: call.UnaryCallOptions) Error!call.UnaryResponse {
        return self.unaryResolved(options, null);
    }
    pub fn unaryWithRetry(self: Sender, options: call.UnaryCallOptions, policy: call.RetryPolicy) Error!call.UnaryResponse {
        return self.unaryResolved(options, policy);
    }
    pub fn startDuplex(self: Sender, options: streaming.RequestOptions) Error!Duplex {
        const entered = std.Io.Clock.awake.now(self.state.io);
        return .{ .call = try @import("shared/stream/open.zig").open(self.state, options, entered) };
    }
    fn unaryResolved(self: Sender, options: call.UnaryCallOptions, policy: ?call.RetryPolicy) Error!call.UnaryResponse {
        const entered = std.Io.Clock.awake.now(self.state.io);
        if (options.message.len > options.requestMessageLimit()) return error.GrpcMessageTooLarge;
        _ = try call.parseRequestMetadata("POST", options.path, &.{ .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "te", .value = "trailers" } });
        try call.validateCustomMetadata(options.metadata);
        try call.validateCustomBinaryMetadata(options.binary_metadata);
        return self.state.unary(options, policy, entered);
    }
};

pub const SharedChannel = struct {
    state: *State,
    pub fn init(allocator: std.mem.Allocator, io: std.Io, target: channel.Target, options: Options) Error!SharedChannel {
        return .{ .state = try @import("shared/init.zig").create(allocator, io, target, options) };
    }
    pub fn sender(self: SharedChannel) Sender {
        self.state.retain();
        return .{ .state = self.state };
    }
    pub fn connect(self: SharedChannel) void {
        self.state.lock();
        defer self.state.unlock();
        if (self.state.closed) return;
        self.state.demand = true;
        if (self.state.tracker.snapshot().state == .idle) self.state.tracker.setState(.connecting);
        self.state.wakeAllLocked();
    }
    pub fn watchConnectivity(self: SharedChannel) connectivity.Watch {
        return .init(self.state.tracker);
    }
    pub fn connectivityState(self: SharedChannel) connectivity.State {
        return self.state.tracker.snapshot().state;
    }
    /// Latest resolver membership; retained cursors still identify their
    /// original endpoint when a later update changes this ordinal.
    pub fn watchEndpointConnectivity(self: SharedChannel, index: usize) ?connectivity.Watch {
        return self.state.watchEndpoint(index);
    }
    pub fn endpointCount(self: SharedChannel) usize {
        return self.state.endpointCount();
    }
    pub fn requestNameResolution(self: SharedChannel) Error!void {
        return self.state.requestNameResolution();
    }
    pub fn refreshNameResolutionWithDeadline(self: SharedChannel, deadline: std.Io.Clock.Timestamp) Error!usize {
        return self.state.refreshNameResolution(deadline);
    }
    pub fn refreshNameResolutionWithTimeout(self: SharedChannel, timeout: std.Io.Duration) Error!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.refreshNameResolutionWithDeadline(.fromNow(self.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn deinit(self: *SharedChannel) void {
        self.state.close();
        self.state.group.cancel(self.state.io);
        self.state.stopResolution();
        self.state.release();
        self.* = undefined;
    }
};

test {
    _ = @import("shared/tests.zig");
    _ = @import("shared/admission_tests.zig");
    _ = @import("shared/resolution/tests.zig");
    _ = @import("shared/stream/tests.zig");
}

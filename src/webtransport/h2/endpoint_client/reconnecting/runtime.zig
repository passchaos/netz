//! Public reconnecting client and generation-scoped Session routing.
const std = @import("std");
const h2_state = @import("../../state.zig");
const h2_runtime = @import("../../runtime.zig");
const endpoint = @import("../../endpoint_client.zig");
const core = @import("core.zig");

pub const Error = core.Error;
pub const Target = core.Target;
pub const CustomConnector = core.CustomConnector;
pub const Backoff = core.Backoff;
pub const Options = core.Options;
pub const Event = endpoint.Event;
pub const KeyingMaterial = endpoint.KeyingMaterial;

pub const Handle = struct {
    connection_generation: u64,
    session: endpoint.Handle,
};

pub const Accepted = struct {
    handle: Handle,
    inner: endpoint.Accepted,

    pub fn status(self: Accepted) u16 {
        return self.inner.status;
    }
    pub fn responseHeader(self: Accepted, name: []const u8) ?[]const u8 {
        return self.inner.responseHeader(name);
    }
    pub fn applicationProtocol(self: Accepted) ?[]const u8 {
        return self.inner.selected_protocol;
    }
    pub fn deinit(self: *Accepted) void {
        self.inner.deinit();
        self.* = undefined;
    }
};

pub const ConnectAttempt = struct {
    generation: *core.Generation,
    inner: endpoint.ConnectAttempt,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.inner.accepted();
    }
    pub fn status(self: ConnectAttempt) u16 {
        return self.inner.status();
    }
    pub fn responseHeader(self: ConnectAttempt, name: []const u8) ?[]const u8 {
        return self.inner.responseHeader(name);
    }
    pub fn body(self: ConnectAttempt) []const u8 {
        return self.inner.body();
    }
    pub fn trailers(self: ConnectAttempt) []const @import("../../../../http2/mod.zig").Hpack.HeaderField {
        return self.inner.trailers();
    }
    pub fn requireAccepted(self: *ConnectAttempt) Error!Accepted {
        const accepted_value = try self.inner.requireAccepted();
        const result = Accepted{
            .handle = .{
                .connection_generation = self.generation.id,
                .session = accepted_value.handle,
            },
            .inner = accepted_value,
        };
        const generation = self.generation;
        self.* = undefined;
        generation.release();
        return result;
    }
    pub fn deinit(self: *ConnectAttempt) void {
        self.inner.deinit();
        self.generation.release();
        self.* = undefined;
    }
};

pub const ReconnectingEndpointClient = struct {
    state: *core.State,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        target: Target,
        options: Options,
    ) Error!ReconnectingEndpointClient {
        return .{ .state = try core.State.create(allocator, io, target, options) };
    }

    pub fn connectAttemptWithDeadline(
        self: ReconnectingEndpointClient,
        options: h2_runtime.ClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!ConnectAttempt {
        try self.state.enter();
        defer self.state.leave();
        while (true) {
            const generation_value = try self.state.acquireCurrent(deadline);
            const attempt = generation_value.client.connectAttemptWithDeadline(
                options,
                deadline,
            ) catch |err| {
                const retired = self.state.retireAfterConnectError(
                    generation_value,
                    err,
                );
                generation_value.release();
                if (retired and
                    deadline.durationFromNow(self.state.io).raw.nanoseconds > 0)
                {
                    continue;
                }
                return err;
            };
            return .{ .generation = generation_value, .inner = attempt };
        }
    }

    pub fn connectAttemptWithTimeout(
        self: ReconnectingEndpointClient,
        options: h2_runtime.ClientOptions,
        timeout: std.Io.Duration,
    ) Error!ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectAttemptWithDeadline(options, .fromNow(
            self.state.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    pub fn connectWithDeadline(
        self: ReconnectingEndpointClient,
        options: h2_runtime.ClientOptions,
        deadline: std.Io.Clock.Timestamp,
    ) Error!Handle {
        var attempt = try self.connectAttemptWithDeadline(options, deadline);
        errdefer attempt.deinit();
        var accepted = try attempt.requireAccepted();
        defer accepted.deinit();
        return accepted.handle;
    }

    pub fn connectWithTimeout(
        self: ReconnectingEndpointClient,
        options: h2_runtime.ClientOptions,
        timeout: std.Io.Duration,
    ) Error!Handle {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(options, .fromNow(
            self.state.io,
            .{ .raw = timeout, .clock = .awake },
        ));
    }

    fn generation(
        self: ReconnectingEndpointClient,
        handle: Handle,
    ) Error!*core.Generation {
        return self.state.acquireHandle(handle.connection_generation);
    }

    fn failed(
        self: ReconnectingEndpointClient,
        generation_value: *core.Generation,
        err: anyerror,
    ) anyerror {
        _ = self.state.retireAfterError(generation_value, err);
        return err;
    }

    pub fn sendDatagramWithDeadline(self: ReconnectingEndpointClient, handle: Handle, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.sendDatagramWithDeadline(handle.session, data, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn sendDatagramWithTimeout(self: ReconnectingEndpointClient, handle: Handle, data: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendDatagramWithDeadline(handle, data, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn receiveWithDeadline(self: ReconnectingEndpointClient, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!Event {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.receiveWithDeadline(handle.session, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn receiveWithTimeout(self: ReconnectingEndpointClient, handle: Handle, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.receiveWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn closeWithDeadline(self: ReconnectingEndpointClient, handle: Handle, code: u32, reason: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.closeWithDeadline(handle.session, code, reason, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn closeWithTimeout(self: ReconnectingEndpointClient, handle: Handle, code: u32, reason: []const u8, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.closeWithDeadline(handle, code, reason, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn removeWithDeadline(self: ReconnectingEndpointClient, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!bool {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.removeWithDeadline(handle.session, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn removeWithTimeout(self: ReconnectingEndpointClient, handle: Handle, timeout: std.Io.Duration) Error!bool {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.removeWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn openStreamWithDeadline(self: ReconnectingEndpointClient, handle: Handle, direction: h2_state.Direction, deadline: std.Io.Clock.Timestamp) Error!u62 {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.openStreamWithDeadline(handle.session, direction, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn openStreamWithTimeout(self: ReconnectingEndpointClient, handle: Handle, direction: h2_state.Direction, timeout: std.Io.Duration) Error!u62 {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.openStreamWithDeadline(handle, direction, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn sendStreamWithDeadline(self: ReconnectingEndpointClient, handle: Handle, id: u62, data: []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.sendStreamWithDeadline(handle.session, id, data, fin, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn sendStreamWithTimeout(self: ReconnectingEndpointClient, handle: Handle, id: u62, data: []const u8, fin: bool, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.sendStreamWithDeadline(handle, id, data, fin, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn consumeWithDeadline(self: ReconnectingEndpointClient, handle: Handle, id: u62, bytes: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.consumeWithDeadline(handle.session, id, bytes, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn consumeWithTimeout(self: ReconnectingEndpointClient, handle: Handle, id: u62, bytes: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.consumeWithDeadline(handle, id, bytes, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn retireStreamWithDeadline(self: ReconnectingEndpointClient, handle: Handle, id: u62, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.retireStreamWithDeadline(handle.session, id, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn retireStreamWithTimeout(self: ReconnectingEndpointClient, handle: Handle, id: u62, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.retireStreamWithDeadline(handle, id, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn resetStreamWithDeadline(self: ReconnectingEndpointClient, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.resetStreamWithDeadline(handle.session, id, code, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn resetStreamWithTimeout(self: ReconnectingEndpointClient, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.resetStreamWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn stopSendingWithDeadline(self: ReconnectingEndpointClient, handle: Handle, id: u62, code: u32, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.stopSendingWithDeadline(handle.session, id, code, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn stopSendingWithTimeout(self: ReconnectingEndpointClient, handle: Handle, id: u62, code: u32, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.stopSendingWithDeadline(handle, id, code, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantDataWithDeadline(self: ReconnectingEndpointClient, handle: Handle, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.grantDataWithDeadline(handle.session, limit, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn grantDataWithTimeout(self: ReconnectingEndpointClient, handle: Handle, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantDataWithDeadline(handle, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamsWithDeadline(self: ReconnectingEndpointClient, handle: Handle, direction: h2_state.Direction, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.grantStreamsWithDeadline(handle.session, direction, limit, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn grantStreamsWithTimeout(self: ReconnectingEndpointClient, handle: Handle, direction: h2_state.Direction, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamsWithDeadline(handle, direction, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn grantStreamDataWithDeadline(self: ReconnectingEndpointClient, handle: Handle, id: u62, limit: u64, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.grantStreamDataWithDeadline(handle.session, id, limit, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn grantStreamDataWithTimeout(self: ReconnectingEndpointClient, handle: Handle, id: u62, limit: u64, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.grantStreamDataWithDeadline(handle, id, limit, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn drainWithDeadline(self: ReconnectingEndpointClient, handle: Handle, deadline: std.Io.Clock.Timestamp) Error!void {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.drainWithDeadline(handle.session, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn drainWithTimeout(self: ReconnectingEndpointClient, handle: Handle, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.drainWithDeadline(handle, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }
    pub fn exportKeyingMaterialWithDeadline(self: ReconnectingEndpointClient, handle: Handle, label: []const u8, context: []const u8, length: usize, deadline: std.Io.Clock.Timestamp) Error!KeyingMaterial {
        try self.state.enter();
        defer self.state.leave();
        const value = try self.generation(handle);
        defer value.release();
        return value.client.exportKeyingMaterialWithDeadline(handle.session, label, context, length, deadline) catch |err| return @errorCast(self.failed(value, err));
    }
    pub fn exportKeyingMaterialWithTimeout(self: ReconnectingEndpointClient, handle: Handle, label: []const u8, context: []const u8, length: usize, timeout: std.Io.Duration) Error!KeyingMaterial {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.exportKeyingMaterialWithDeadline(handle, label, context, length, .fromNow(self.state.io, .{ .raw = timeout, .clock = .awake }));
    }

    pub fn deinit(self: *ReconnectingEndpointClient) void {
        self.state.closeAndDestroy();
        self.* = undefined;
    }
};

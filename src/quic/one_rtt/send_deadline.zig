//! Bounded 1-RTT sends retain actual transport commits before reporting expiry.
const std = @import("std");
const runtime = @import("../one_rtt.zig");
const quic = @import("../mod.zig");
const bounded = @import("../../internal/progress_deadline.zig");

pub const Error = runtime.Error || bounded.BudgetError;

pub fn one(connection: anytype, frames: []const quic.Frame, until: std.Io.Clock.Timestamp) Error!void {
    const Connection = @typeInfo(@TypeOf(connection)).pointer.child;
    const outcome = bounded.before(connection.endpoint.io, until, Connection.trySend, .{ connection, frames });
    const result = outcome.result orelse return outcome.wait_error orelse error.Unexpected;
    result catch |err| {
        if (err == error.Canceled) if (outcome.wait_error) |wait_error| return wait_error;
        return err;
    };
    // trySend is a one-packet transaction: successful return confirms the
    // socket and transport-state commit, including when a timer raced it.
}

pub fn many(connection: anytype, packets: []const []const quic.Frame, progress: *runtime.ConnectionBatchSendResult, until: std.Io.Clock.Timestamp) Error!void {
    progress.* = .{ .sent_count = 0, .protected_count = 0 };
    const Connection = @typeInfo(@TypeOf(connection)).pointer.child;
    const outcome = bounded.before(connection.endpoint.io, until, Connection.sendManyProgress, .{ connection, packets });
    const result = outcome.result orelse return outcome.wait_error orelse error.Unexpected;
    progress.* = result catch |err| {
        if (err == error.Canceled) if (outcome.wait_error) |wait_error| return wait_error;
        return err;
    };
    if (progress.send_error) |err| {
        if (err == error.Canceled) if (outcome.wait_error) |wait_error| {
            if (progress.protected_count != 0 and progress.sent_count == progress.protected_count) {
                progress.send_error = null;
                return;
            }
            return wait_error;
        };
        return err;
    }
    if (progress.sent_count != progress.protected_count) return outcome.wait_error orelse error.Unexpected;
}

//! Consumer-owned decoding keeps bounded encoded input off endpoint threads.
const std = @import("std");
const call_module = @import("call.zig");
const codec = @import("../../../stream/codec.zig");
const metadata = @import("../../../call.zig");
const deadline_policy = @import("../../../../internal/deadline.zig");

fn fail(call: anytype, err: anyerror) void {
    call.fail(err);
    call.requestCancel();
}

fn interrupted(call: anytype, err: anyerror, rpc_expired: bool, cancel_call_on_interrupt: bool) void {
    if ((err == error.Canceled and cancel_call_on_interrupt) or rpc_expired) fail(call, err);
}

pub fn next(call: anytype, requested: ?std.Io.Clock.Timestamp, cancel_call_on_interrupt: bool) @TypeOf(call.parent.*).Failure!call_module.Event {
    if (requested) |until| if (until.clock != .awake) return error.Timeout;
    const state = call.parent;
    call.retain();
    defer call.release();
    if (call.read_busy.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.InvalidStreamState;
    defer call.read_busy.store(false, .release);
    const deadline = deadline_policy.earlier(call.deadline, requested);
    const Collector = struct {
        const Result = union(enum) {
            none,
            message: call_module.Message,
            borrowed: codec.DecodedMessage,
        };
        allocator: std.mem.Allocator,
        result: Result = .none,
        fn consumeBorrowed(self: *@This(), message: codec.DecodedMessage) @TypeOf(state.*).Failure!void {
            std.debug.assert(self.result == .none);
            if (message.was_compressed or message.payload.len == 0) {
                self.result = .{ .message = .{
                    .allocator = self.allocator,
                    .payload = try self.allocator.dupe(u8, message.payload),
                    .was_compressed = message.was_compressed,
                } };
            } else {
                self.result = .{ .borrowed = message };
            }
        }
        fn consumeOwned(self: *@This(), message: codec.OwnedDecodedMessage) @TypeOf(state.*).Failure!void {
            std.debug.assert(self.result == .none);
            self.result = .{ .message = .{
                .allocator = message.allocator,
                .payload = message.payload,
                .was_compressed = message.was_compressed,
            } };
        }
    };
    while (true) {
        // DATA/metadata/terminal committed before the RPC deadline remains
        // consumable afterwards. A caller-selected read deadline still bounds
        // mutex admission; otherwise only an empty receive waits on the RPC.
        const locally_ready = call.changed.isSet();
        const admission_deadline = if (locally_ready) requested else deadline;
        // Before admission no cursor or buffered ownership has moved. A local
        // lock timeout/cancellation is retryable; the endpoint independently
        // enforces the RPC deadline once it regains State ownership.
        try state.lockBefore(admission_deadline);
        if (call.failureValue()) |failure| {
            state.unlock();
            return @errorCast(failure);
        }
        if (call.terminal_taken) {
            state.unlock();
            return error.ConnectionClosed;
        }
        if (call.information.items.len != 0) {
            const head = call.information.orderedRemove(0);
            state.unlock();
            return .{ .informational = head };
        }
        if (call.initial) |head| {
            if (call.parse_body and call.decoder == null) {
                call.decoder = codec.Decoder.init(state.allocator, call.options.responseMessageLimit(), metadata.headerValue(head.headers, "grpc-encoding"), call.options.accepted_encodings) catch |err| {
                    state.unlock();
                    fail(call, err);
                    return err;
                };
            }
            call.initial = null;
            state.unlock();
            return .{ .initial_metadata = head };
        }
        if (call.len != 0) {
            const size = @min(call.len, state.options.max_write_bytes_per_turn);
            const first = @min(size, call.bytes.len - call.head);
            const decoder = if (call.decoder) |*value| value else {
                state.unlock();
                fail(call, error.InvalidStreamState);
                return error.InvalidStreamState;
            };
            // Feed the call-owned ring directly. The unconsumed ring region is
            // protected by `head`/`len` while the state lock is released, so a
            // second reader cannot observe it and the endpoint cannot overwrite
            // it before this reader commits the consumed prefix below.
            state.unlock();
            var collector = Collector{ .allocator = state.allocator };
            const progress = decoder.feedLimitedAssembledOwned(
                call.bytes[call.head..][0..first],
                1,
                &collector,
                Collector.consumeBorrowed,
                Collector.consumeOwned,
            ) catch |err| {
                fail(call, err);
                return @errorCast(err);
            };
            state.lock();
            if (call.failureValue()) |failure| {
                state.unlock();
                if (collector.result == .message) collector.result.message.deinit();
                return @errorCast(failure);
            }
            if (progress.consumed == 0) {
                state.unlock();
                fail(call, error.InvalidStreamState);
                return error.InvalidStreamState;
            }
            if (collector.result == .borrowed) {
                const borrowed = collector.result.borrowed;
                collector.result = .{ .message = .{
                    .allocator = state.allocator,
                    .payload = state.allocator.dupe(u8, borrowed.payload) catch |err| {
                        state.unlock();
                        fail(call, err);
                        return err;
                    },
                    .was_compressed = false,
                } };
            }
            call.head = (call.head + progress.consumed) % call.bytes.len;
            call.len -= progress.consumed;
            call.credit += progress.consumed;
            state.wakeAllLocked();
            state.unlock();
            if (collector.result == .message) {
                return .{ .message = collector.result.message };
            }
            continue;
        }
        if (call.terminal) |response| {
            if (call.decoder) |*decoder| decoder.finish() catch |err| {
                call.fail(err);
                state.unlock();
                call.requestCancel();
                return err;
            };
            call.terminal = null;
            call.terminal_taken = true;
            state.unlock();
            return .{ .terminal = response };
        }
        call.changed.reset();
        state.unlock();
        while (true) {
            const waited = if (deadline) |until| call.changed.waitTimeout(state.io, .{ .deadline = until }) else call.changed.wait(state.io);
            waited catch |err| {
                if (err == error.Timeout and deadline.?.durationFromNow(state.io).raw.nanoseconds > 0) continue;
                const rpc_expired = call.deadline != null and call.deadline.?.durationFromNow(state.io).raw.nanoseconds <= 0;
                // No message or cursor ownership moved while this wait was
                // pending. ADS can cancel a losing local read and resume the
                // same receive queue; an expired RPC still cancels the call.
                interrupted(call, err, rpc_expired, cancel_call_on_interrupt);
                return err;
            };
            break;
        }
    }
}

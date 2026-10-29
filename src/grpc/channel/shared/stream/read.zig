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

fn interrupted(call: anytype, err: anyerror, rpc_expired: bool) void {
    if (err == error.Canceled or rpc_expired) fail(call, err);
}

pub fn next(call: anytype, requested: ?std.Io.Clock.Timestamp) @TypeOf(call.parent.*).Failure!call_module.Event {
    if (requested) |until| if (until.clock != .awake) return error.Timeout;
    const state = call.parent;
    call.retain();
    defer call.release();
    if (call.read_busy.cmpxchgStrong(false, true, .acq_rel, .acquire) != null) return error.InvalidStreamState;
    defer call.read_busy.store(false, .release);
    const deadline = deadline_policy.earlier(call.deadline, requested);
    const Collector = struct {
        allocator: std.mem.Allocator,
        message: ?call_module.Message = null,
        fn consume(self: *@This(), message: codec.DecodedMessage) @TypeOf(state.*).Failure!void {
            self.message = .{ .allocator = self.allocator, .payload = try self.allocator.dupe(u8, message.payload), .was_compressed = message.was_compressed };
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
        if (call.chunk == null and call.len != 0) {
            const size = @min(call.len, state.options.max_write_bytes_per_turn);
            const bytes = state.allocator.alloc(u8, size) catch |err| {
                state.unlock();
                fail(call, err);
                return err;
            };
            const first = @min(size, call.bytes.len - call.head);
            @memcpy(bytes[0..first], call.bytes[call.head..][0..first]);
            @memcpy(bytes[first..], call.bytes[0 .. size - first]);
            call.head = (call.head + size) % call.bytes.len;
            call.len -= size;
            call.credit += size;
            call.chunk = bytes;
            call.chunk_offset = 0;
            state.wakeAllLocked();
        }
        if (call.chunk) |bytes| {
            state.unlock();
            var collector = Collector{ .allocator = state.allocator };
            const decoder = if (call.decoder) |*value| value else {
                fail(call, error.InvalidStreamState);
                return error.InvalidStreamState;
            };
            const progress = decoder.feedLimited(bytes[call.chunk_offset..], 1, &collector, Collector.consume) catch |err| {
                fail(call, err);
                return @errorCast(err);
            };
            call.chunk_offset += progress.consumed;
            if (call.chunk_offset == bytes.len) {
                state.allocator.free(bytes);
                call.chunk = null;
            }
            if (collector.message) |message| return .{ .message = message };
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
                interrupted(call, err, rpc_expired);
                return err;
            };
            break;
        }
    }
}

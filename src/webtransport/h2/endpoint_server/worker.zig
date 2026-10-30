//! Sole owner of the server HTTP/2 connection, pending requests, and Sessions.
const std = @import("std");
const http2 = @import("../../../http2/mod.zig");
const runtime = @import("../runtime.zig");
const job_mod = @import("job.zig");

pub fn Worker(comptime State: type) type {
    return struct {
        const Job = State.Job;
        const ExecuteResult = enum { completed, deferred };
        const PollResult = struct { progress: bool = false, blocked: bool = false };

        pub fn run(state: *State) std.Io.Cancelable!void {
            var terminal: ?anyerror = null;
            defer {
                for (state.pending) |*slot| if (slot.request) |*request| {
                    request.deinit();
                    slot.request = null;
                };
                for (state.sessions) |*slot| if (slot.session) |*session| {
                    session.deinit();
                    slot.session = null;
                    slot.failure = null;
                };
                state.pending_count = 0;
                state.session_count = 0;
                state.connection.close();
                state.workerStopped(terminal);
                state.release();
            }
            while (true) {
                while (state.claim()) |job| {
                    if (job.canceled()) {
                        _ = state.finish(job, error.Canceled);
                        continue;
                    }
                    const result = execute(state, job) catch |err| {
                        _ = state.finish(job, err);
                        if (state.connection.aggregate_timeout_unusable) {
                            terminal = err;
                            return;
                        }
                        continue;
                    };
                    if (result == .deferred) continue;
                    completeJob(state, job);
                }
                fulfillRequests(state);
                const buffered = pollRouted(state, outputDeadline(state)) catch |err| {
                    if (err == error.Canceled) return error.Canceled;
                    terminal = err;
                    return;
                };
                if (buffered.progress and !buffered.blocked) continue;
                state.lock();
                if (state.closed) {
                    state.unlock();
                    return;
                }
                if (state.head != null) {
                    state.unlock();
                    continue;
                }
                state.wake.reset();
                const pending_blocked = state.pending_input_blocked;
                state.unlock();
                if (buffered.blocked or pending_blocked) {
                    state.wake.wait(state.io) catch |err| {
                        if (err == error.Canceled) return error.Canceled;
                        terminal = err;
                        return;
                    };
                    continue;
                }
                const event = state.connection.pumpServerUntilOrWake(
                    state.nextRequestDeadline(),
                    state.options.operation_timeout,
                    &state.wake,
                ) catch |err| {
                    if (err == error.Canceled) return error.Canceled;
                    if (err == error.Timeout and !state.connection.aggregate_timeout_unusable) continue;
                    terminal = err;
                    return;
                };
                processPump(state, event, outputDeadline(state)) catch |err| {
                    if (state.connection.aggregate_timeout_unusable) {
                        terminal = err;
                        return;
                    }
                };
            }
        }

        fn execute(state: *State, job: *Job) !ExecuteResult {
            switch (job.command) {
                .receive_request => {
                    if (try deliverOldest(state, job)) return .completed;
                    state.waitForRequest(job);
                    return .deferred;
                },
                .accept => |value| try accept(state, job, value.handle, value.options),
                .reject => |value| try reject(state, value.handle, value.options, job.deadline),
                .abandon_pending => |handle| job.removed = removePending(state, handle, true),
                .send_datagram => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.sendDatagramWithDeadline(value.data, job.deadline), job.deadline);
                },
                .receive => |handle| job.event = try job_mod.Event.clone(state.allocator, try (try state.session(handle)).receiveWithDeadline(job.deadline)),
                .close => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.closeWithDeadline(value.code, value.reason, job.deadline), job.deadline);
                },
                .remove => |handle| job.removed = removeSession(state, handle),
                .open_stream => |value| job.stream_id = try (try state.session(value.handle)).openStream(value.direction),
                .send_stream => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.sendStreamWithDeadline(value.id, value.data, value.fin, job.deadline), job.deadline);
                },
                .consume => |value| try (try state.session(value.handle)).consume(value.id, value.bytes),
                .retire_stream => |value| try (try state.session(value.handle)).retireStream(value.id),
                .reset_stream => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.resetStreamWithDeadline(value.id, value.code, job.deadline), job.deadline);
                },
                .stop_sending => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.stopSendingWithDeadline(value.id, value.code, job.deadline), job.deadline);
                },
                .grant_data => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.grantDataWithDeadline(value.limit, job.deadline), job.deadline);
                },
                .grant_streams => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.grantStreamsWithDeadline(value.direction, value.limit, job.deadline), job.deadline);
                },
                .grant_stream_data => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.grantStreamDataWithDeadline(value.id, value.limit, job.deadline), job.deadline);
                },
                .drain => |handle| {
                    const session = try state.session(handle);
                    try completeWrite(state, session, session.drainWithDeadline(job.deadline), job.deadline);
                },
                .export_keying_material => |value| {
                    const session = try state.session(value.handle);
                    const output = try state.allocator.alloc(u8, value.length);
                    errdefer state.allocator.free(output);
                    try session.exportKeyingMaterial(value.label, value.context, output);
                    job.bytes = .{ .allocator = state.allocator, .value = output };
                },
            }
            return .completed;
        }

        fn completeJob(state: *State, job: *Job) void {
            job.retain();
            const delivered = state.finish(job, null);
            if (!delivered) rollbackAbandoned(state, job);
            job.release();
        }

        fn deliverOldest(state: *State, job: *Job) !bool {
            var selected: ?usize = null;
            var sequence: u64 = std.math.maxInt(u64);
            for (state.pending, 0..) |slot, index| if (slot.request != null and !slot.claimed and slot.sequence < sequence) {
                selected = index;
                sequence = slot.sequence;
            };
            const index = selected orelse return false;
            const slot = &state.pending[index];
            const handle: job_mod.PendingHandle = .{ .index = @intCast(index), .generation = slot.generation };
            job.request = try job_mod.RequestData.clone(state.allocator, handle, &slot.request.?);
            slot.claimed = true;
            return true;
        }

        fn fulfillRequests(state: *State) void {
            while (true) {
                const job = state.takeRequestWaiter() orelse return;
                const delivered = deliverOldest(state, job) catch |err| {
                    _ = state.finish(job, err);
                    continue;
                };
                if (delivered) {
                    completeJob(state, job);
                } else {
                    state.waitForRequest(job);
                    return;
                }
            }
        }

        fn storePending(state: *State, pending: runtime.PendingDuplexSession, deadline: std.Io.Clock.Timestamp) !void {
            if (state.pending_count >= state.pending.len) {
                var rejected = pending;
                try rejectOwned(state, &rejected, .{ .status = 429 }, deadline);
                return error.PendingCapacity;
            }
            for (state.pending) |*slot| if (slot.request == null) {
                slot.request = pending;
                slot.claimed = false;
                slot.sequence = state.next_sequence;
                state.next_sequence +%= 1;
                if (state.next_sequence == 0) state.next_sequence = 1;
                state.pending_count += 1;
                return;
            };
            unreachable;
        }

        fn processPump(state: *State, event: http2.runtime.ServerDuplexPumpEvent, deadline: std.Io.Clock.Timestamp) !void {
            switch (event) {
                .request => |request| try storePending(state, try runtime.prepareDuplexRequestWithDeadline(&state.connection, request, deadline), deadline),
                .stream => |stream_id| {
                    for (state.pending) |slot| if (slot.request) |request| {
                        if (request.request.stream_id == stream_id) {
                            state.pending_input_blocked = true;
                            break;
                        }
                    };
                },
                .progress, .wake => {},
            }
            fulfillRequests(state);
        }

        fn accept(state: *State, job: *Job, handle: job_mod.PendingHandle, options: runtime.ServerOptions) !void {
            if (state.session_count >= state.sessions.len) {
                try reject(state, handle, .{ .status = 429 }, job.deadline);
                return error.EndpointCapacity;
            }
            const pending = try state.request(handle);
            var session = runtime.acceptDuplexWithDeadline(state.allocator, &state.connection, pending, options, job.deadline) catch |err| {
                if (!pending.active) _ = removePending(state, handle, false);
                return err;
            };
            errdefer session.deinit();
            _ = removePending(state, handle, false);
            for (state.sessions, 0..) |*slot, index| if (!slot.occupied()) {
                const session_handle: job_mod.Handle = .{ .index = @intCast(index), .generation = slot.generation };
                var accepted = try job_mod.Accepted.clone(state.allocator, session_handle, session.selected_protocol);
                errdefer accepted.deinit();
                slot.session = session;
                state.session_count += 1;
                job.accepted = accepted;
                return;
            };
            unreachable;
        }

        fn reject(state: *State, handle: job_mod.PendingHandle, options: runtime.RejectOptions, deadline: std.Io.Clock.Timestamp) !void {
            const pending = try state.request(handle);
            try rejectOwned(state, pending, options, deadline);
            _ = removePending(state, handle, false);
        }

        fn rejectOwned(state: *State, pending: *runtime.PendingDuplexSession, options: runtime.RejectOptions, deadline: std.Io.Clock.Timestamp) anyerror!void {
            while (true) {
                runtime.rejectDuplexWithDeadline(pending, options, deadline) catch |err| {
                    if (err != error.ResponseAvailable) return err;
                    if (try pending.request.pollRequestEventWithDeadline(deadline)) |event_value| {
                        var event = event_value;
                        event.deinit(state.connection.allocator);
                        continue;
                    }
                    try progressRouted(state, deadline);
                    continue;
                };
                return;
            }
        }

        fn removePending(state: *State, handle: job_mod.PendingHandle, deinit: bool) bool {
            if (handle.index >= state.pending.len) return false;
            const slot = &state.pending[handle.index];
            if (slot.generation != handle.generation or slot.request == null) return false;
            if (deinit) slot.request.?.deinit();
            slot.request = null;
            slot.claimed = false;
            slot.sequence = 0;
            slot.generation +%= 1;
            if (slot.generation == 0) slot.generation = 1;
            state.pending_count -= 1;
            state.pending_input_blocked = false;
            return true;
        }

        fn removeSession(state: *State, handle: job_mod.Handle) bool {
            if (handle.index >= state.sessions.len) return false;
            const slot = &state.sessions[handle.index];
            if (slot.generation != handle.generation or !slot.occupied()) return false;
            if (slot.session) |*session| session.deinit();
            slot.session = null;
            slot.failure = null;
            slot.generation +%= 1;
            if (slot.generation == 0) slot.generation = 1;
            state.session_count -= 1;
            return true;
        }

        fn rollbackAbandoned(state: *State, job: *Job) void {
            if (job.request) |*request| {
                const slot = &state.pending[request.handle.index];
                if (slot.generation == request.handle.generation) slot.claimed = false;
                request.deinit();
                job.request = null;
            }
            if (job.accepted) |*accepted| {
                _ = removeSession(state, accepted.handle);
                accepted.deinit();
                job.accepted = null;
            }
        }

        fn completeWrite(state: *State, session: *@import("../session.zig").Session, initial: anyerror!void, deadline: std.Io.Clock.Timestamp) !void {
            initial catch |err| {
                if (err != error.ResponseAvailable) return err;
                try progressRouted(state, deadline);
            };
            while (session.pending != null) {
                session.resumeWriteWithDeadline(deadline) catch |err| {
                    if (err == error.ResponseAvailable) {
                        try progressRouted(state, deadline);
                        continue;
                    }
                    return err;
                };
            }
        }

        fn progressRouted(state: *State, deadline: std.Io.Clock.Timestamp) !void {
            while (true) {
                const result = try pollRouted(state, deadline);
                if (result.progress or result.blocked) return;
                var wake: std.Io.Event = .unset;
                const event = try state.connection.pumpServerUntilOrWake(deadline, state.options.operation_timeout, &wake);
                try processPump(state, event, deadline);
                if (state.pending_input_blocked) return error.PendingEvent;
            }
        }

        fn pollRouted(state: *State, deadline: std.Io.Clock.Timestamp) !PollResult {
            var result: PollResult = .{};
            for (state.sessions) |*slot| if (slot.session) |*session| {
                const progress = session.pollWithDeadline(deadline) catch |err| {
                    if (err == error.PendingEvent) {
                        result.blocked = true;
                        continue;
                    }
                    if (err == error.ResponseAvailable) {
                        result.progress = true;
                        continue;
                    }
                    if (state.connection.aggregate_timeout_unusable) return err;
                    session.deinit();
                    slot.session = null;
                    slot.failure = err;
                    result.progress = true;
                    continue;
                };
                result.progress = progress or result.progress;
            };
            return result;
        }

        fn outputDeadline(state: *State) std.Io.Clock.Timestamp {
            return .fromNow(state.io, .{ .raw = state.options.operation_timeout, .clock = .awake });
        }
    };
}

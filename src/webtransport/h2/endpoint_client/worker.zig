//! Sole owner of the HTTP/2 connection and every multiplexed Session.
const std = @import("std");
const runtime = @import("../runtime.zig");
const job_mod = @import("job.zig");

pub fn Worker(comptime State: type) type {
    return struct {
        const Job = State.Job;

        pub fn run(state: *State) std.Io.Cancelable!void {
            var terminal: ?anyerror = null;
            defer {
                for (state.slots) |*slot| if (slot.session) |*session| {
                    session.deinit();
                    slot.session = null;
                    slot.failure = null;
                };
                state.active_sessions = 0;
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
                    execute(state, job) catch |err| {
                        _ = state.finish(job, err);
                        if (state.connection.aggregate_timeout_unusable) {
                            terminal = err;
                            return;
                        }
                        continue;
                    };
                    job.retain();
                    const delivered = state.finish(job, null);
                    if (!delivered) rollbackAbandoned(state, job);
                    job.release();
                }
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
                const active = state.connection.activeClientDuplexCount() != 0;
                state.unlock();
                if (!active or buffered.blocked) {
                    state.wake.wait(state.io) catch |err| {
                        if (err == error.Canceled) return error.Canceled;
                        terminal = err;
                        return;
                    };
                    continue;
                }
                _ = state.connection.pumpClientUntilOrWake(
                    null,
                    state.options.operation_timeout,
                    &state.wake,
                ) catch |err| {
                    if (err == error.Canceled) return error.Canceled;
                    if (err == error.Timeout and !state.connection.aggregate_timeout_unusable) continue;
                    terminal = err;
                    return;
                };
            }
        }

        fn execute(state: *State, job: *Job) !void {
            switch (job.command) {
                .connect => |options| try connect(state, job, options),
                .send_datagram => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.sendDatagramWithDeadline(value.data, job.deadline), job.deadline);
                },
                .receive => |handle| {
                    const event = try (try state.session(handle)).receiveWithDeadline(job.deadline);
                    job.event = try job_mod.Event.clone(state.allocator, event);
                },
                .close => |value| {
                    const session = try state.session(value.handle);
                    try completeWrite(state, session, session.closeWithDeadline(value.code, value.reason, job.deadline), job.deadline);
                },
                .remove => |handle| remove(state, job, handle),
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
                _ = try state.connection.pumpClientDuplexWithDeadline(deadline);
            }
        }

        const PollResult = struct { progress: bool = false, blocked: bool = false };

        fn pollRouted(state: *State, deadline: std.Io.Clock.Timestamp) !PollResult {
            var result: PollResult = .{};
            for (state.slots) |*slot| if (slot.session) |*session| {
                const progress = session.pollWithDeadline(deadline) catch |err| {
                    if (err == error.PendingEvent) {
                        result.blocked = true;
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

        fn connect(state: *State, job: *Job, options: runtime.ClientOptions) !void {
            if (state.active_sessions >= state.slots.len) return error.EndpointCapacity;
            var attempt = try runtime.connectDuplexAttemptWithDeadline(
                state.allocator,
                &state.connection,
                options,
                job.deadline,
            );
            var attempt_owned = true;
            defer if (attempt_owned) attempt.deinit();
            if (!attempt.accepted()) {
                job.rejection = attempt.rejection.?;
                attempt.rejection = null;
                return;
            }
            var session = try attempt.requireAccepted();
            attempt_owned = false;
            errdefer session.deinit();
            for (state.slots, 0..) |*slot, index| if (!slot.occupied()) {
                const handle: job_mod.Handle = .{ .index = @intCast(index), .generation = slot.generation };
                var accepted = try job_mod.Accepted.clone(state.allocator, handle, &session);
                errdefer accepted.deinit();
                slot.session = session;
                state.active_sessions += 1;
                job.accepted = accepted;
                return;
            };
            unreachable;
        }

        fn removeHandle(state: *State, handle: job_mod.Handle) bool {
            if (handle.index >= state.slots.len) {
                return false;
            }
            const slot = &state.slots[handle.index];
            if (slot.generation != handle.generation or !slot.occupied()) {
                return false;
            }
            if (slot.session) |*session| session.deinit();
            slot.session = null;
            slot.failure = null;
            slot.generation +%= 1;
            if (slot.generation == 0) slot.generation = 1;
            state.active_sessions -= 1;
            return true;
        }

        fn remove(state: *State, job: *Job, handle: job_mod.Handle) void {
            job.removed = removeHandle(state, handle);
        }

        fn rollbackAbandoned(state: *State, job: *Job) void {
            if (job.accepted) |*accepted| {
                _ = removeHandle(state, accepted.handle);
                accepted.deinit();
                job.accepted = null;
            }
        }
    };
}

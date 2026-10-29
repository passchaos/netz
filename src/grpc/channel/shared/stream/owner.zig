//! Endpoint-thread transport progress for shared streaming calls.
const std = @import("std");
const netz_runtime = @import("../../../../runtime.zig");
const duplex = @import("../../../stream/duplex.zig");
const http2 = @import("../../../../http2/mod.zig");
const Job = @import("../job.zig").Job;

pub fn Owner(comptime State: type) type {
    return struct {
        pub const Active = struct {
            call: *State.StreamCall,
            stream: duplex.ClientDuplex,
        };
        fn earlier(a: ?std.Io.Clock.Timestamp, b: std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
            return if (a) |value| if (std.Io.Clock.Timestamp.compare(value, .lt, b)) value else b else b;
        }
        pub fn open(worker: anytype, job: *Job, output: std.Io.Clock.Timestamp) State.Failure!void {
            const state = worker.parent;
            const call = job.stream.?;
            state.lock();
            const canceled = job.canceled() or call.cancel_requested.load(.acquire) or state.closed;
            state.unlock();
            if (canceled) return error.Canceled;
            try worker.streams.ensureUnusedCapacity(state.allocator, 1);
            const maximum = if (worker.connection.?.limits.adaptive_window)
                worker.connection.?.limits.adaptive_window_max
            else
                worker.connection.?.limits.initial_window_size;
            if (maximum > state.options.max_buffered_stream_bytes) return error.InvalidSharedOptions;
            call.bytes = try state.allocator.alloc(u8, @max(maximum, 1));
            var stream = try duplex.startDuplexWithDeadlines(worker.connection.?, state.allocator, call.options, call.deadline, earlier(call.deadline, output));
            errdefer stream.deinit();
            try stream.transport.deferResponseStreamCredit();
            call.retain();
            call.setOwnerWake(worker.wake);
            worker.streams.appendAssumeCapacity(.{ .call = call, .stream = stream });
            state.finish(job, null, null);
        }
        pub fn fail(worker: anytype, index: usize, err: anyerror) void {
            const state = worker.parent;
            const call = worker.streams.items[index].call;
            worker.streams.items[index].stream.cancel() catch {};
            worker.streams.items[index].stream.deinit();
            _ = worker.streams.swapRemove(index);
            state.lock();
            call.retireLocked(if (state.closed) error.SharedChannelClosed else err);
            state.unlock();
            call.release();
        }
        fn complete(worker: anytype, index: usize, response: duplex.Response) void {
            const state = worker.parent;
            const call = worker.streams.items[index].call;
            worker.streams.items[index].stream.deinit();
            _ = worker.streams.swapRemove(index);
            state.lock();
            call.terminal = response;
            call.retireLocked(null);
            state.unlock();
            call.release();
        }
        fn cloneHead(allocator: std.mem.Allocator, head: duplex.ResponseHead) State.Failure!http2.runtime.DuplexResponseHead {
            const fields = try allocator.alloc(http2.Hpack.HeaderField, head.headers.len);
            errdefer allocator.free(fields);
            var size: usize = 0;
            for (head.headers) |field| size = std.math.add(usize, size, field.name.len + field.value.len) catch return error.MessageTooLarge;
            const storage = try allocator.alloc(u8, size);
            errdefer allocator.free(storage);
            var offset: usize = 0;
            for (head.headers, fields, 0..) |field, *copy, index| {
                const name = storage[offset..][0..field.name.len];
                @memcpy(name, field.name);
                offset += field.name.len;
                const value = storage[offset..][0..field.value.len];
                @memcpy(value, field.value);
                offset += field.value.len;
                copy.* = .{ .name = name, .value = value, .never_index = field.never_index, .block_storage = if (index == 0) storage else null };
            }
            if (fields.len == 0) allocator.free(storage);
            return .{ .headers = fields, .status = head.status };
        }
        pub fn tick(worker: anytype, output: std.Io.Clock.Timestamp) State.Failure!bool {
            const state = worker.parent;
            const now = netz_runtime.cachedAwakeTimestamp(state.io);
            var progress = false;
            var index: usize = 0;
            while (index < worker.streams.items.len) {
                const active = &worker.streams.items[index];
                const call = active.call;
                state.lock();
                const canceled = state.closed or call.cancel_requested.load(.acquire);
                const write = call.write;
                const credit = call.credit;
                state.unlock();
                const expired = if (call.deadline) |until|
                    std.Io.Clock.Timestamp.compare(until, .lte, now)
                else
                    false;
                const write_expired = if (write) |value| blk: {
                    const until = value.deadline orelse break :blk false;
                    break :blk std.Io.Clock.Timestamp.compare(
                        until,
                        .lte,
                        now,
                    );
                } else false;
                if (canceled or expired or write_expired) {
                    fail(worker, index, if (expired or write_expired) error.Timeout else error.Canceled);
                    progress = true;
                    continue;
                }
                const deadline = earlier(call.deadline, output);
                if (credit != 0) {
                    const granted = active.stream.transport.releaseResponseStreamCreditBatchedWithDeadline(credit, deadline) catch |err| {
                        fail(worker, index, err);
                        progress = true;
                        continue;
                    };
                    state.lock();
                    call.credit -= granted;
                    state.unlock();
                    progress = granted != 0 or progress;
                }
                const ready = active.stream.pollRawResponseEventBatchedWithDeadline(deadline) catch |err| {
                    fail(worker, index, err);
                    progress = true;
                    continue;
                };
                if (ready) |value| {
                    var event = value;
                    switch (event) {
                        .initial_metadata => |head| {
                            const owned = cloneHead(state.allocator, head) catch |err| {
                                fail(worker, index, err);
                                progress = true;
                                continue;
                            };
                            state.lock();
                            call.initial = owned;
                            call.parse_body = active.stream.parse_response_body;
                            call.changed.set(state.io);
                            state.unlock();
                        },
                        .informational => |head| {
                            state.lock();
                            call.information.append(state.allocator, head) catch |err| {
                                state.unlock();
                                event.deinit(state.allocator);
                                fail(worker, index, err);
                                progress = true;
                                continue;
                            };
                            call.changed.set(state.io);
                            state.unlock();
                            event = .progress;
                        },
                        .data => |data| {
                            state.lock();
                            call.appendLocked(data.data) catch |err| {
                                state.unlock();
                                event.deinit(state.allocator);
                                fail(worker, index, err);
                                progress = true;
                                continue;
                            };
                            state.unlock();
                            if (active.stream.pending_terminal != null) {
                                // Final DATA already committed its terminal
                                // status. Publish it with the copied bytes
                                // before another owner turn can expire the RPC
                                // or attempt credit output on the closed stream.
                                const terminal = active.stream.pollRawResponseEventBatchedWithDeadline(deadline) catch |err| {
                                    event.deinit(state.allocator);
                                    fail(worker, index, err);
                                    progress = true;
                                    continue;
                                };
                                std.debug.assert(terminal != null and terminal.? == .terminal);
                                event.deinit(state.allocator);
                                complete(worker, index, terminal.?.terminal);
                                progress = true;
                                continue;
                            }
                        },
                        .terminal => |response| {
                            complete(worker, index, response);
                            progress = true;
                            continue;
                        },
                        .progress => {},
                    }
                    event.deinit(state.allocator);
                    progress = true;
                }
                if (write) |command| {
                    const until = earlier(command.deadline, deadline);
                    if (command.finish_only) {
                        _ = active.stream.finishRequestWithDeadline(until) catch |err| {
                            fail(worker, index, err);
                            progress = true;
                            continue;
                        };
                        state.lock();
                        call.request_finished = true;
                        call.finishWriteLocked(null);
                        state.unlock();
                        progress = true;
                    } else {
                        if (!command.staged) {
                            (if (command.final)
                                active.stream.stageFinalMessage(command.payload, command.options)
                            else
                                active.stream.stageMessage(command.payload, command.options)) catch |err| {
                                fail(worker, index, err);
                                progress = true;
                                continue;
                            };
                            command.staged = true;
                            command.releasePayload();
                            progress = true;
                        }
                        const before = active.stream.transport.requestCommittedBytes();
                        const result = active.stream.pollResumeMessageWithDeadline(until, state.options.max_write_bytes_per_turn) catch |err| {
                            fail(worker, index, err);
                            progress = true;
                            continue;
                        };
                        if (result == .complete) {
                            state.lock();
                            call.request_finished = command.final;
                            call.finishWriteLocked(null);
                            state.unlock();
                            progress = true;
                        } else if (before != active.stream.transport.requestCommittedBytes()) progress = true;
                    }
                }
                index += 1;
            }
            return progress;
        }
    };
}

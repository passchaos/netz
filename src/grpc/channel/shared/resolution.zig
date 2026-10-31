//! A hostname's resolver runs independently of every application connection.
const std = @import("std");

pub fn Resolution(comptime State: type) type {
    return struct {
        fn requestLocked(state: *State) State.Failure!void {
            if (state.closed) return error.SharedChannelClosed;
            var found = false;
            for (state.sources) |*source| if (source.resolver != null) {
                source.refresh_requested = true;
                source.wake.set(state.io);
                found = true;
            };
            if (!found) return error.InvalidChannelOptions;
            state.demand = true;
            state.recomputeLocked();
            state.wakeAllLocked();
        }
        pub fn request(state: *State) State.Failure!void {
            try state.lockBefore(null);
            defer state.unlock();
            try requestLocked(state);
        }
        pub fn refresh(state: *State, deadline: std.Io.Clock.Timestamp) State.Failure!usize {
            _ = try @import("../../../internal/deadline.zig").usableAwake(state.io, deadline);
            const generations = try state.allocator.alloc(u64, state.sources.len);
            defer state.allocator.free(generations);
            try state.lockBefore(deadline);
            for (state.sources, generations) |source, *generation| generation.* = source.generation;
            requestLocked(state) catch |err| {
                state.unlock();
                return err;
            };
            state.unlock();
            while (true) {
                try state.lockBefore(deadline);
                if (state.closed) {
                    state.unlock();
                    return error.SharedChannelClosed;
                }
                var complete = true;
                var failure: ?anyerror = null;
                for (state.sources, generations) |source, generation| {
                    if (source.resolver == null) continue;
                    if (source.generation == generation) complete = false else if (source.last_error) |err| {
                        failure = err;
                    }
                }
                const count = state.endpointCountLocked();
                state.resolution_changed.reset();
                state.unlock();
                if (failure) |err| return @errorCast(err);
                if (complete) return count;
                state.resolution_changed.waitTimeout(state.io, .{ .deadline = deadline }) catch |err| {
                    if (err == error.Timeout and deadline.durationFromNow(state.io).raw.nanoseconds > 0) continue;
                    return err;
                };
            }
        }
        pub fn run(state: *State, source_index: usize) std.Io.Cancelable!void {
            const source = &state.sources[source_index];
            const resolver = source.resolver.?;
            var retry_at: ?std.Io.Clock.Timestamp = null;
            while (true) {
                state.lock();
                if (state.closed) {
                    state.unlock();
                    return;
                }
                const demand = state.demand;
                const requested = source.refresh_requested;
                source.refresh_requested = false;
                const reset_backoff = source.backoff_reset_requested;
                source.backoff_reset_requested = false;
                source.wake.reset();
                state.unlock();
                if (demand) {
                    if (reset_backoff) retry_at = null;
                    if (retry_at) |until| if (until.durationFromNow(state.io).raw.nanoseconds > 0) {
                        source.wake.waitTimeout(state.io, .{ .deadline = until }) catch |err| {
                            if (err == error.Canceled) return error.Canceled;
                        };
                        continue;
                    };
                    const started = resolver.startConcurrent() catch |err| {
                        state.lock();
                        source.generation +%= 1;
                        source.last_error = err;
                        state.recomputeLocked();
                        state.resolution_changed.set(state.io);
                        state.unlock();
                        retry_at = .fromNow(state.io, .{ .clock = .awake, .raw = state.options.channel.backoff.initial_backoff });
                        continue;
                    };
                    retry_at = null;
                    if (reset_backoff) resolver.resetBackoff() else if (!started and requested) resolver.requestRefresh();
                }
                if (resolver.takePublished()) |published| {
                    var failure: ?anyerror = null;
                    var accepted = true;
                    switch (published.result) {
                        .addresses => |addresses| {
                            defer state.allocator.free(addresses);
                            State.Membership.reconcile(state, source_index, addresses) catch |err| {
                                failure = err;
                                accepted = false;
                            };
                            if (addresses.len == 0) {
                                failure = error.NoAddressReturned;
                                accepted = false;
                            }
                        },
                        .failure => |err| failure = err,
                    }
                    resolver.acknowledge(accepted);
                    state.lock();
                    source.generation +%= 1;
                    source.last_error = failure;
                    state.recomputeLocked();
                    state.resolution_changed.set(state.io);
                    state.unlock();
                    continue;
                }
                if (!demand) {
                    try source.wake.wait(state.io);
                    continue;
                }
                try source.wake.wait(state.io);
            }
        }
    };
}

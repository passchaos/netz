//! Stable endpoint owners, atomic candidate lists, and draining retirement.
const std = @import("std");
const channel = @import("../../channel.zig");
const connectivity = @import("../connectivity.zig");
const Wake = @import("wake.zig").Wake;

pub fn Membership(comptime State: type) type {
    return struct {
        pub fn createLocked(state: *State, source_index: usize, address: ?std.Io.net.IpAddress) State.Failure!*State.Worker {
            const allocator = state.allocator;
            try state.workers.ensureUnusedCapacity(allocator, 1);
            const worker = try allocator.create(State.Worker);
            errdefer allocator.destroy(worker);
            var options = state.options.channel;
            options.address_resolver = null;
            // The SharedChannel state owns endpoint selection. Each worker's
            // child Channel owns exactly one physical target and must not
            // instantiate the outer least-request, ring, or WRR scheduler.
            options.selection_policy = .pick_first;
            options.shuffle_address_list = false;
            const target = state.sources[source_index].target(address);
            var owner = if (state.config) |*config|
                try channel.Channel.initWithServiceConfigChild(allocator, state.io, target, options, config)
            else
                try channel.Channel.init(allocator, state.io, target, options);
            errdefer owner.deinit();
            const tracker = try connectivity.Tracker.create(allocator, state.io);
            errdefer tracker.release();
            const orca_tracker = try State.OrcaTracker.create(
                allocator,
                state.io,
            );
            errdefer orca_tracker.release();
            const wake = try Wake.create(allocator);
            errdefer wake.release();
            worker.* = .{ .parent = state, .source_index = source_index, .address = address, .owner = owner, .tracker = tracker, .orca_tracker = orca_tracker, .wake = wake };
            try state.group.concurrent(state.io, State.Worker.run, .{worker});
            state.workers.appendAssumeCapacity(worker);
            state.wrr_scheduler.next_update_ns = 0;
            return worker;
        }

        fn contains(members: []const *State.Worker, worker: *State.Worker) bool {
            for (members) |member| if (member == worker) return true;
            return false;
        }
        fn retireLocked(state: *State, worker: *State.Worker) void {
            worker.retired = true;
            worker.eligible = false;
            worker.capacity = 0;
            worker.tracker.setState(.shutdown);
            worker.orca_tracker.shutdown();
            state.wrr_scheduler.remove(worker);
            if (state.selected == worker) state.selected = null;
            if (state.least_request_selected == worker) {
                state.least_request_selected = null;
            }
            worker.wake.set(state.io);
        }
        pub fn promoteLocked(state: *State, source_index: usize) void {
            if (state.closed) return;
            const source = &state.sources[source_index];
            const pending = source.pending orelse return;
            var old_ready = false;
            for (source.current) |worker| old_ready = old_ready or worker.published == .ready;
            var ready = false;
            var seen_all = true;
            var failed_all = pending.len != 0;
            for (pending) |worker| {
                ready = ready or worker.published == .ready;
                seen_all = seen_all and worker.published != .idle;
                failed_all = failed_all and worker.published == .transient_failure;
            }
            if (pending.len != 0 and old_ready and !(ready and seen_all) and !failed_all) return;
            const old = source.current;
            source.current = pending;
            source.pending = null;
            state.ring_hash_dirty = true;
            for (pending) |worker| worker.eligible = true;
            for (old) |worker| if (!contains(pending, worker)) retireLocked(state, worker);
            state.allocator.free(old);
            state.next_pick = 0;
            state.wakeAllLocked();
        }

        pub fn reconcile(state: *State, source_index: usize, addresses: []std.Io.net.IpAddress) State.Failure!void {
            var unique: usize = 0;
            for (addresses) |address| {
                for (addresses[0..unique]) |*prior| {
                    if (prior.eql(&address)) break;
                } else {
                    addresses[unique] = address;
                    unique += 1;
                }
            }
            const members = try state.allocator.alloc(*State.Worker, unique);
            errdefer state.allocator.free(members);
            state.lock();
            defer state.unlock();
            if (state.closed) return error.SharedChannelClosed;
            if (state.shuffle_addresses) {
                var remaining = unique;
                while (remaining > 1) {
                    remaining -= 1;
                    var random: usize = undefined;
                    state.io.random(std.mem.asBytes(&random));
                    std.mem.swap(std.Io.net.IpAddress, &addresses[remaining], &addresses[random % (remaining + 1)]);
                }
            }
            const source = &state.sources[source_index];
            var initialized: usize = 0;
            errdefer for (members[0..initialized]) |worker| {
                if (!contains(source.current, worker) and !contains(source.pending orelse &.{}, worker)) retireLocked(state, worker);
            };
            for (addresses[0..unique], members) |address, *member| {
                const existing = for (state.workers.items) |worker| {
                    if (worker.retired or worker.source_index != source_index) continue;
                    if (worker.address) |*prior| if (prior.eql(&address)) break worker;
                } else null;
                member.* = existing orelse try createLocked(state, source_index, address);
                initialized += 1;
            }
            if (source.pending) |previous| {
                for (previous) |worker| if (!contains(source.current, worker) and !contains(members, worker)) retireLocked(state, worker);
                state.allocator.free(previous);
            }
            source.pending = members;
            promoteLocked(state, source_index);
            state.recomputeLocked();
            state.wakeAllLocked();
        }
    };
}

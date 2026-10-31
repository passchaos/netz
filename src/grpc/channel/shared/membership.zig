//! Stable endpoint owners, atomic candidate lists, and draining retirement.
const std = @import("std");
const channel = @import("../../channel.zig");
const connectivity = @import("../connectivity.zig");
const Wake = @import("wake.zig").Wake;

pub fn Membership(comptime State: type) type {
    return struct {
        pub fn createLocked(state: *State, source_index: usize, address: ?std.Io.net.IpAddress) State.Failure!*State.Worker {
            try state.workers.ensureUnusedCapacity(state.allocator, 1);
            const source = state.sources[source_index];
            const orca = if (state.orca_oob) |*value| value else if (state.weighted_target) |*runtime| runtime.orcaForPath(source.endpoint.hierarchicalPath()) else null;
            const worker = try prepare(state, source, source_index, address, state.config.load(.acquire), if (state.weighted_target) |*runtime| runtime.outlierCount() else 0, state.health_service, orca);
            errdefer destroyUnstarted(worker);
            try state.group.concurrent(state.io, State.Worker.run, .{worker});
            state.workers.appendAssumeCapacity(worker);
            worker.activation.set(state.io);
            state.wrr_scheduler.next_update_ns = 0;
            return worker;
        }

        pub fn prepare(state: *State, source: *State.Source, source_index: usize, address: ?std.Io.net.IpAddress, config: ?*@import("config_generation.zig").Generation, outlier_count: usize, health_service: ?[]const u8, orca: ?*const @import("orca/config.zig").Config) State.Failure!*State.Worker {
            const allocator = state.allocator;
            const worker = try allocator.create(State.Worker);
            errdefer allocator.destroy(worker);
            var options = state.options.channel;
            options.address_resolver = null;
            // The SharedChannel state owns endpoint selection. Each worker's
            // child Channel owns exactly one physical target and must not
            // instantiate the outer least-request, ring, or WRR scheduler.
            options.selection_policy = .pick_first;
            options.shuffle_address_list = false;
            const target = source.target(address);
            var owner = if (config) |generation|
                try channel.Channel.initWithServiceConfigChild(allocator, state.io, target, options, &generation.config)
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
            const weighted_outliers: []@import("../outlier_detection.zig").Endpoint = if (outlier_count == 0)
                @constCast(&[_]@import("../outlier_detection.zig").Endpoint{})
            else blk: {
                const values = try allocator.alloc(
                    @import("../outlier_detection.zig").Endpoint,
                    outlier_count,
                );
                for (values) |*value| value.* = .{};
                break :blk values;
            };
            errdefer allocator.free(weighted_outliers);
            const settings = try @import("worker_settings.zig").Settings.create(allocator, health_service, orca);
            errdefer settings.destroy();
            worker.* = .{
                .parent = state,
                .source_index = source_index,
                .source = source,
                .settings = settings,
                .address = address,
                .owner = owner,
                .tracker = tracker,
                .orca_tracker = orca_tracker,
                .wake = wake,
                .weighted_outliers = weighted_outliers,
            };
            worker.source.retain();
            return worker;
        }

        pub fn destroyUnstarted(worker: *State.Worker) void {
            const allocator = worker.parent.allocator;
            worker.owner.deinit();
            worker.tracker.release();
            worker.orca_tracker.release();
            worker.wake.release();
            allocator.free(worker.weighted_outliers);
            worker.settings.destroy();
            worker.source.release();
            allocator.destroy(worker);
        }

        fn contains(members: []const *State.Worker, worker: *State.Worker) bool {
            for (members) |member| if (member == worker) return true;
            return false;
        }
        pub fn retireLocked(state: *State, worker: *State.Worker) void {
            worker.retired = true;
            worker.eligible = false;
            worker.capacity = 0;
            worker.tracker.setState(.shutdown);
            worker.orca_tracker.shutdown();
            state.wrr_scheduler.remove(worker);
            if (state.selected == worker) state.selected = null;
            if (state.weighted_target_selected == worker) {
                state.weighted_target_selected = null;
            }
            if (state.least_request_selected == worker) {
                state.least_request_selected = null;
            }
            worker.wake.set(state.io);
        }
        pub fn promoteLocked(state: *State, source_index: usize) void {
            if (state.closed) return;
            const source = state.sources[source_index];
            if (source.retired or source.suspended) return;
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
            if (state.weighted_target) |*runtime| runtime.invalidatePickers();
            for (pending) |worker| worker.eligible = true;
            for (old) |worker| if (!contains(pending, worker)) retireLocked(state, worker);
            state.allocator.free(old);
            state.next_pick = 0;
            state.wakeAllLocked();
        }

        pub fn reconcile(state: *State, source: *State.Source, addresses: []std.Io.net.IpAddress) State.Failure!void {
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
            if (source.retired or source.suspended) return error.SharedChannelClosed;
            const source_index = for (state.sources, 0..) |candidate, index| {
                if (candidate == source) break index;
            } else return error.SharedChannelClosed;
            var initialized: usize = 0;
            errdefer for (members[0..initialized]) |worker| {
                if (!contains(source.current, worker) and !contains(source.pending orelse &.{}, worker)) retireLocked(state, worker);
            };
            for (addresses[0..unique], members) |address, *member| {
                const existing = for (state.workers.items) |worker| {
                    if (worker.retired or worker.source != source) continue;
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

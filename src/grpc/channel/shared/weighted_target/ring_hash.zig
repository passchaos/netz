//! Child-local ketama ring construction and source fallback.
const std = @import("std");
const ring_hash = @import("../../ring_hash.zig");

pub fn pick(
    allocator: std.mem.Allocator,
    runtime: anytype,
    node: anytype,
    leaf: anytype,
    state: anytype,
    job: anytype,
) !?@TypeOf(state.workers.items[0]) {
    if (leaf.ring_dirty) {
        for (state.sources) |source| {
            if (!pathMatches(
                source.endpoint.hierarchicalPath(),
                node.path,
            )) continue;
            if (source.resolver != null and source.generation == 0 and
                source.current.len == 0)
            {
                return null;
            }
        }
        const ContextType = Context(
            @TypeOf(runtime),
            @TypeOf(node),
            @TypeOf(state),
        );
        var context = ContextType{
            .runtime = runtime,
            .node = node,
            .state = state,
        };
        leaf.ring.rebuild(
            allocator,
            &context,
            uniqueSourceCount(runtime, node, state),
            leaf.ring_hash_config,
            ring_hash.default_ring_size_cap,
            ContextType.key,
            ContextType.weight,
        ) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.InvalidSharedOptions,
        };
        leaf.ring_dirty = false;
    }
    const request_hash = try job.requestHash(
        state.io,
        leaf.ring_hash_config,
    );
    const start = leaf.ring.start(request_hash.value) orelse return null;
    const source_count = uniqueSourceCount(runtime, node, state);
    for (0..source_count) |ordinal| {
        const local_index = leaf.ring.uniqueEndpointAt(
            start,
            ordinal,
        ) orelse return null;
        const source_index = uniqueSourceAt(
            runtime,
            node,
            state,
            local_index,
        ).?;
        switch (pickSource(runtime, state, source_index)) {
            .worker => |worker| return worker,
            .pending => if (!request_hash.random) return null,
            .failed => {},
        }
    }
    return null;
}

fn Context(
    comptime RuntimePointer: type,
    comptime NodePointer: type,
    comptime StatePointer: type,
) type {
    return struct {
        runtime: RuntimePointer,
        node: NodePointer,
        state: StatePointer,

        fn key(
            self: *@This(),
            index: usize,
            buffer: *[256]u8,
        ) ![]const u8 {
            const source_index = uniqueSourceAt(
                self.runtime,
                self.node,
                self.state,
                index,
            ).?;
            const source = &self.state.sources[source_index];
            return source.ringHashKey(
                if (source.current.len == 0)
                    null
                else
                    source.current[0].address,
                buffer,
            );
        }

        fn weight(self: *@This(), index: usize) u32 {
            const source_index = uniqueSourceAt(
                self.runtime,
                self.node,
                self.state,
                index,
            ).?;
            const endpoint = self.state.sources[source_index].endpoint;
            var result: u32 = 0;
            for (self.state.sources) |source| {
                if (!pathMatches(
                    source.endpoint.hierarchicalPath(),
                    self.node.path,
                )) continue;
                if (ring_hash.sameEndpointIdentity(
                    source.endpoint,
                    endpoint,
                )) {
                    result +|= source.ring_hash_weight;
                }
            }
            return result;
        }
    };
}

fn uniqueSourceCount(runtime: anytype, node: anytype, state: anytype) usize {
    var count: usize = 0;
    for (state.sources, 0..) |source, index| {
        if (!pathMatches(
            source.endpoint.hierarchicalPath(),
            node.path,
        ) or sourceDuplicate(runtime, node, state, index)) continue;
        count += 1;
    }
    return count;
}

fn uniqueSourceAt(
    runtime: anytype,
    node: anytype,
    state: anytype,
    target: usize,
) ?usize {
    var ordinal: usize = 0;
    for (state.sources, 0..) |source, index| {
        if (!pathMatches(
            source.endpoint.hierarchicalPath(),
            node.path,
        ) or sourceDuplicate(runtime, node, state, index)) continue;
        if (ordinal == target) return index;
        ordinal += 1;
    }
    return null;
}

fn sourceDuplicate(
    _: anytype,
    node: anytype,
    state: anytype,
    index: usize,
) bool {
    const endpoint = state.sources[index].endpoint;
    for (state.sources[0..index]) |prior| {
        if (!pathMatches(
            prior.endpoint.hierarchicalPath(),
            node.path,
        )) continue;
        if (ring_hash.sameEndpointIdentity(
            prior.endpoint,
            endpoint,
        )) return true;
    }
    return false;
}

fn SourcePick(comptime WorkerPointer: type) type {
    return union(enum) {
        worker: WorkerPointer,
        pending,
        failed,
    };
}

fn pickSource(
    runtime: anytype,
    state: anytype,
    source_index: usize,
) SourcePick(@TypeOf(
    state.sources[0].current[0],
)) {
    const source = &state.sources[source_index];
    var pending = source.resolver != null and source.current.len == 0;
    for (source.current) |worker| {
        if (!worker.eligible or worker.retired or
            runtime.workerEjected(state, worker)) continue;
        switch (worker.published) {
            .ready => if (worker.capacity != 0) {
                return .{ .worker = worker };
            } else {
                pending = true;
            },
            .idle, .connecting => pending = true,
            .transient_failure, .shutdown => {},
        }
    }
    return if (pending) .pending else .failed;
}

fn pathMatches(
    endpoint_path: []const []const u8,
    node_path: []const []const u8,
) bool {
    if (endpoint_path.len < node_path.len) return false;
    for (node_path, endpoint_path[0..node_path.len]) |expected, actual| {
        if (!std.mem.eql(u8, expected, actual)) return false;
    }
    return true;
}

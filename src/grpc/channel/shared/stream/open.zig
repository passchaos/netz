//! Opening retains request metadata until the background owner commits HEADERS.
const std = @import("std");
const streaming = @import("../../../stream/runtime.zig");
const service_config = @import("../../../service_config.zig");
const call = @import("../../../call.zig");
const Job = @import("../job.zig").Job;

pub fn open(state: anytype, options: streaming.RequestOptions, entered: std.Io.Timestamp) @TypeOf(state.*).Failure!*@TypeOf(state.*).StreamCall {
    const State = @TypeOf(state.*);
    const config_generation = state.retainConfig();
    defer if (config_generation) |config| config.release();
    var resolved: service_config.ResolvedStreaming = .{ .options = options, .hedging_policy = null, .wait_for_ready = options.wait_for_ready orelse false };
    if (config_generation) |config| {
        resolved = try config.config.resolveStreaming(options);
    }
    if (resolved.hedging_policy != null) return error.InvalidSharedOptions;
    resolved.options.wait_for_ready = resolved.wait_for_ready;
    const deadline: ?std.Io.Clock.Timestamp = if (resolved.options.timeout) |timeout| .{ .raw = entered.addDuration(timeout.duration()), .clock = .awake } else null;
    // Resolve against one retained immutable generation so a later dynamic
    // publication cannot invalidate borrowed method-policy strings.
    try state.lockBefore(deadline);
    const closed = state.closed;
    state.unlock();
    if (closed) return error.SharedChannelClosed;
    _ = try call.parseRequestMetadata("POST", options.path, &.{ .{ .name = "content-type", .value = "application/grpc" }, .{ .name = "te", .value = "trailers" } });
    try call.validateCustomMetadata(options.metadata);
    try call.validateCustomBinaryMetadata(options.binary_metadata);

    const stream = try State.StreamCall.create(state, resolved.options, deadline);
    var submitted = false;
    errdefer |err| {
        if (!submitted) stream.retireUnsubmitted(err);
        stream.release();
    }
    const job = try Job.createStream(state, stream, deadline, resolved.wait_for_ready);
    defer job.release();
    try state.enqueue(job);
    submitted = true;
    try state.awaitJob(job);
    return stream;
}

const std = @import("std");
const Shared = @import("../shared.zig");
const State = @import("state.zig").State;
const Job = @import("job.zig").Job;
const Wake = @import("wake.zig").Wake;
const call = @import("../../call.zig");

fn response(allocator: std.mem.Allocator, bytes: []const u8) !call.UnaryResponse {
    const body = try allocator.dupe(u8, bytes);
    return .{ .allocator = allocator, .transport = null, .status = .ok, .status_message = &.{}, .message = .{ .compressed = false, .payload = body }, .was_compressed = false, .encoding = null, .owned_message = body };
}

test "gRPC retired Job owns request inputs and wake storage after the caller releases them" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try Shared.SharedChannel.init(std.testing.allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    state.closed = false;
    defer state.closed = true;
    const refs = state.refs.load(.acquire);
    var body: [8]u8 = "original".*;
    var path: [7]u8 = "/svc/Op".*;
    var value: [6]u8 = "before".*;
    var binary: [3]u8 = .{ 0, 255, 42 };
    const job = try Job.create(state, .{ .path = &path, .message = &body, .authority = "host.test", .scheme = "https", .metadata = &.{.{ .name = "x-value", .value = &value, .never_index = true }}, .binary_metadata = &.{.{ .name = "x-value-bin", .value = &binary }} }, null, null, null);
    var caller = true;
    defer if (caller) job.release();
    job.retain(); // Fake endpoint owns an assigned Job until completion.
    var endpoint = true;
    defer if (endpoint) job.release();
    const wake = try Wake.create(std.testing.allocator);
    job.setOwnerWake(wake);
    wake.release(); // Endpoint wake storage now belongs only to the Job.
    try std.testing.expect(job.abandon());
    job.release();
    caller = false;
    @memset(&body, 'x');
    @memset(&path, 'y');
    @memset(&value, 'z');
    @memset(&binary, 7);
    try std.testing.expectEqualStrings("original", job.options.message);
    try std.testing.expectEqualStrings("/svc/Op", job.options.path);
    try std.testing.expectEqualStrings("before", job.options.metadata[0].value);
    try std.testing.expect(job.options.metadata[0].never_index);
    try std.testing.expectEqualSlices(u8, &.{ 0, 255, 42 }, job.options.binary_metadata[0].value);
    wake.set(io);
    try std.testing.expect(wake.event.isSet());
    // A late success must be destroyed by endpoint ownership, not leaked to
    // the caller whose timeout/cancellation has already won this attempt.
    endpoint = false;
    state.finish(job, try response(std.testing.allocator, "late"), null);
    try std.testing.expectEqual(refs, state.refs.load(.acquire));
}

test "gRPC Job completed response wins later abandonment and transfers once" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try Shared.SharedChannel.init(std.testing.allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    state.closed = false;
    defer state.closed = true;
    const job = try Job.create(state, .{ .path = "/svc/Op", .message = "body" }, .{ .clock = .awake, .raw = .zero }, null, null);
    var owned = true;
    defer if (owned) job.release();
    job.retain();
    state.finish(job, try response(std.testing.allocator, "winner"), null);
    try std.testing.expect(!job.abandon());
    try state.awaitJob(job);
    var result = job.takeResult();
    defer result.deinit();
    job.release();
    owned = false;
    try std.testing.expectEqualStrings("winner", result.message.?.payload);
}

test "gRPC Job input allocation failures preserve parent and release partial clones" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try Shared.SharedChannel.init(std.testing.allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator, state: *State) !void {
            const old = state.allocator;
            state.allocator = allocator;
            defer state.allocator = old;
            const refs = state.refs.load(.acquire);
            const job = Job.create(state, .{ .path = "/svc/Op", .message = "body", .authority = "host.test", .scheme = "https", .metadata = &.{.{ .name = "x-name", .value = "value" }}, .binary_metadata = &.{.{ .name = "x-byte-bin", .value = &.{ 0, 255 } }} }, null, null, null) catch |err| {
                try std.testing.expectEqual(refs, state.refs.load(.acquire));
                return err;
            };
            job.release();
            try std.testing.expectEqual(refs, state.refs.load(.acquire));
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Scenario.run, .{sender.state});
}

test "gRPC queued abandoned Job is reclaimed by the next shared owner" {
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var channel = try Shared.SharedChannel.init(std.testing.allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
    var sender = channel.sender();
    defer sender.deinit();
    channel.deinit();
    const state = sender.state;
    state.closed = false;
    defer state.closed = true;
    const refs = state.refs.load(.acquire);
    const job = try Job.create(state, .{ .path = "/svc/Op", .message = "body", .wait_for_ready = true }, .{ .clock = .awake, .raw = .zero }, null, null);
    job.retain();
    state.head = job;
    state.tail = job;
    state.queued = 1;
    try std.testing.expectError(error.Timeout, state.awaitJob(job));
    job.release();
    state.lock();
    state.unlock();
    try std.testing.expect(state.head == null and state.tail == null);
    try std.testing.expectEqual(@as(usize, 0), state.queued);
    try std.testing.expectEqual(refs, state.refs.load(.acquire));
}

//! Trust startup preserves cancellation and the original connection budget.
const std = @import("std");
const trust = @import("../client_trust.zig");
const loading = @import("loading.zig");
const quic = @import("../mod.zig");

const FaultIo = struct {
    canceled: bool = false,
    opens: usize = 0,
    fn context(userdata: ?*anyopaque) *@This() {
        return @ptrCast(@alignCast(userdata.?));
    }
    fn check(userdata: ?*anyopaque) std.Io.Cancelable!void {
        if (context(userdata).canceled) return error.Canceled;
    }
    fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
        return .{ .nanoseconds = @as(i96, 1_790_000_000) * std.time.ns_per_s };
    }
    fn open(userdata: ?*anyopaque, _: std.Io.Dir, _: []const u8, _: std.Io.Dir.OpenFileOptions) std.Io.File.OpenError!std.Io.File {
        context(userdata).opens += 1;
        return error.Canceled;
    }
    const table: std.Io.VTable = blk: {
        var value = std.Io.failing.vtable.*;
        value.checkCancel = check;
        value.now = now;
        value.dirOpenFile = open;
        break :blk value;
    };
    fn io(self: *@This()) std.Io {
        return .{ .userdata = self, .vtable = &table };
    }
};

test "QUIC trust load preserves cancellation while opening configured roots" {
    if (comptime @import("builtin").os.tag == .windows) return error.SkipZigTest;
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    var endpoint = try quic.runtime.Endpoint.bind(std.testing.allocator, backend.io(), .{ .ip4 = .loopback(0) }, .{});
    defer endpoint.deinit();
    var probe: FaultIo = .{};
    var entries = [_]?[*:0]const u8{ "SSL_CERT_FILE=/netz-canceled-roots.pem", null };
    const environ: std.process.Environ = .{ .block = .{ .slice = entries[0..1 :null] } };
    endpoint.io = probe.io();
    defer endpoint.io = backend.io();
    try std.testing.expectError(error.Canceled, quic.handshake.connect(&endpoint, .{ .ip4 = .loopback(443) }, .{
        .original_destination_connection_id = "trust-origin",
        .local_connection_id = "trust-client",
        .system_environ = environ,
    }));
    try std.testing.expectEqual(@as(usize, 1), probe.opens);
}

test "QUIC trust load rejects pending cancellation before default roots" {
    var probe: FaultIo = .{ .canceled = true };
    var options: quic.handshake.ClientOptions = .{ .original_destination_connection_id = "trust-origin", .local_connection_id = "trust-client" };
    var store: ?trust.SystemStore = null;
    defer if (store) |*value| value.deinit();
    try std.testing.expectError(error.Canceled, trust.applyPlatformRootDefault(std.testing.allocator, probe.io(), &options, &store));
    try std.testing.expect(store == null);
    try std.testing.expect(options.system_store == null);
    try std.testing.expectEqual(@as(usize, 0), probe.opens);
}

test "QUIC trust load deadline cancels and joins blocked loading" {
    var backend = try @import("zio").Runtime.init(std.testing.allocator, .{});
    defer backend.deinit();
    const io = backend.io();
    const Loader = struct {
        fn run(run_io: std.Io) !trust.SystemStore {
            try std.Io.sleep(run_io, .fromSeconds(1), .awake);
            return trust.SystemStore.initEmpty(std.testing.allocator);
        }
    };
    const started = std.Io.Clock.awake.now(io);
    const deadline: std.Io.Clock.Timestamp = .{ .clock = .awake, .raw = started.addDuration(.fromMilliseconds(50)) };
    const result = loading.before(io, deadline, Loader.run, .{io});
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.TestExpectedError;
    } else |err| try std.testing.expectEqual(@as(anyerror, error.Timeout), err);
    try std.testing.expect(started.durationTo(std.Io.Clock.awake.now(io)).nanoseconds < 500 * std.time.ns_per_ms);
}

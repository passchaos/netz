const std = @import("std");
const runtime = @import("../../runtime.zig");
const Probe = @import("../../../internal/testing/startup_entropy.zig").Probe;

const Entry = enum { origin, redirect, alt_svc, alt_svc_redirect, early_alt_svc };

fn exercise(comptime entry: Entry) !void {
    var early = try runtime.PreparedEarlyRequest.init(std.testing.allocator, .{ .method = "GET", .path = "/", .authority = "startup.test" }, .{}, .{});
    defer early.deinit();
    const Transport = struct {
        calls: usize = 0,
        fn connect(context: *anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.net.IpAddress, _: []const u8, _: u16, _: runtime.Limits, _: runtime.HandshakeClientOptions) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return error.ConnectionRefused;
        }
    };
    inline for (.{ false, true }) |zero| {
        inline for (.{ false, true }) |custom_transport| {
            var probe: Probe = .{};
            var transport: Transport = .{};
            var context: runtime.HandshakeClientPoolDefaultConnector = .{ .options = .{
                .connect_timeout = .fromMilliseconds(if (zero) 0 else 1000),
                .handshake = .{ .original_destination_connection_id = "", .local_connection_id = "" },
            }, .transport = if (custom_transport) .{ .context = &transport, .connect = Transport.connect } else null };
            const connector = context.connector();
            const uri = try std.Uri.parse("https://startup.test/");
            const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
            const redirect: runtime.HandshakeClientPoolRedirectConnectContext = .{ .cross_origin = true, .forward_client_identity = false };
            const target: @import("../../mod.zig").AltSvcTarget = .{ .alpn = "h3", .connect_host = "alternative.startup.test", .port = 443, .origin_host = "startup.test" };
            const result = switch (entry) {
                .origin => connector.connect(connector.context, std.testing.allocator, probe.io(), address, uri, .{}),
                .redirect => connector.connect_redirect.?(connector.context, std.testing.allocator, probe.io(), address, uri, .{}, redirect),
                .alt_svc => connector.connect_alt_svc.?(connector.context, std.testing.allocator, probe.io(), address, uri, target, .{}),
                .alt_svc_redirect => connector.connect_alt_svc_redirect.?(connector.context, std.testing.allocator, probe.io(), address, uri, target, .{}, redirect),
                .early_alt_svc => early_result: {
                    const connected = connector.connect_early_alt_svc.?(connector.context, std.testing.allocator, probe.io(), address, uri, target, .{}, &early);
                    break :early_result if (connected) |value| value.client else |err| err;
                },
            };
            try std.testing.expectError(if (zero) error.HandshakeTimeout else error.ConcurrencyUnavailable, result);
            try probe.expectUntouched(if (zero) 0 else 1);
            try std.testing.expectEqual(@as(usize, 0), transport.calls);
        }
    }
}

test "HTTP3 startup entropy default pool origin starts the complete connection budget" {
    try exercise(.origin);
}
test "HTTP3 startup entropy default pool redirect starts the complete connection budget" {
    try exercise(.redirect);
}
test "HTTP3 startup entropy default pool Alt-Svc starts the complete connection budget" {
    try exercise(.alt_svc);
}
test "HTTP3 startup entropy default pool Alt-Svc redirect starts the complete connection budget" {
    try exercise(.alt_svc_redirect);
}
test "HTTP3 startup entropy default pool early Alt-Svc starts the complete connection budget" {
    try exercise(.early_alt_svc);
}

test "HTTP3 startup entropy default pool custom transport keeps only timely failures" {
    const Delegate = struct {
        backend: std.Io.Threaded,
        expire: bool,
        now_override: std.atomic.Value(i64) = .init(0),
        calls: usize = 0,
        remaining: ?std.Io.Duration = null,
        fn context(userdata: ?*anyopaque) *@This() {
            const backend: *std.Io.Threaded = @ptrCast(@alignCast(userdata.?));
            return @alignCast(@fieldParentPtr("backend", backend));
        }
        fn now(userdata: ?*anyopaque, clock: std.Io.Clock) std.Io.Timestamp {
            const self = context(userdata);
            const override = self.now_override.load(.acquire);
            if (clock == .awake and override != 0) return .{ .nanoseconds = override };
            return clock.now(self.backend.io());
        }
        fn connect(userdata: *anyopaque, _: std.mem.Allocator, _: std.Io, _: std.Io.net.IpAddress, _: []const u8, _: u16, _: runtime.Limits, options: runtime.HandshakeClientOptions) runtime.Error!runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(userdata));
            self.calls += 1;
            self.remaining = options.connect_timeout;
            if (self.expire) self.now_override.store(@intCast(std.Io.Clock.awake.now(self.backend.io()).nanoseconds + 600 * std.time.ns_per_s), .release);
            return error.ConnectionRefused;
        }
    };
    inline for (.{ false, true }) |expire| {
        var delegate: Delegate = .{ .backend = .init(std.testing.allocator, .{}), .expire = expire };
        defer delegate.backend.deinit();
        const native_io = delegate.backend.io();
        var table = native_io.vtable.*;
        table.now = Delegate.now;
        const io: std.Io = .{ .userdata = native_io.userdata, .vtable = &table };
        var context: runtime.HandshakeClientPoolDefaultConnector = .{
            .options = .{ .connect_timeout = .fromSeconds(60), .handshake = .{ .original_destination_connection_id = "", .local_connection_id = "" } },
            .transport = .{ .context = &delegate, .connect = Delegate.connect },
        };
        const connector = context.connector();
        try std.testing.expectError(if (expire) error.HandshakeTimeout else error.ConnectionRefused, connector.connect(connector.context, std.testing.allocator, io, .{ .ip4 = .loopback(0) }, try std.Uri.parse("https://startup.test/"), .{}));
        try std.testing.expectEqual(@as(usize, 1), delegate.calls);
        try std.testing.expect(delegate.remaining.?.nanoseconds > 0);
        try std.testing.expect(delegate.remaining.?.nanoseconds <= std.Io.Duration.fromSeconds(60).nanoseconds);
    }
}

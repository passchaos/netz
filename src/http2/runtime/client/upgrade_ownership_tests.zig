const std = @import("std");
const runtime = @import("../../runtime.zig");
const transition = @import("../../../internal/testing/connection_transition.zig");
const net = std.Io.net;

test "HTTP/2 h2c stream ownership closes when deadline expires after TCP connect" {
    inline for (.{ false, true }) |relative| {
        const Connect = struct {
            fn run(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, deadline: std.Io.Clock.Timestamp) runtime.ResponseTimeoutError!runtime.OwnedResponse {
                const limits: runtime.Limits = .{ .connect_timeout = null };
                const request: runtime.RequestOptions = .{ .authority = "localhost" };
                return if (relative)
                    runtime.Client.connectUpgradeWithTimeout(allocator, io, address, limits, request, .fromSeconds(2))
                else
                    runtime.Client.connectUpgradeWithDeadline(allocator, io, address, limits, request, deadline);
            }
        };
        try transition.expectClosedAfterConnect(Connect.run);
    }
}

test "HTTP/2 h2c stream ownership closes on expired or foreign-clock adopted deadlines" {
    inline for (.{ false, true }) |foreign_clock| {
        const Adopt = struct {
            fn run(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, deadline: std.Io.Clock.Timestamp) runtime.Error!runtime.H2cUpgradeResult {
                const stream = try address.connect(io, .{ .mode = .stream });
                var absolute = deadline;
                if (foreign_clock) absolute.clock = .real;
                return runtime.Client.connectStreamUpgradeWithDeadline(allocator, io, stream, .{}, .{ .authority = "localhost" }, absolute);
            }
        };
        try transition.expectClosedAfterAdoption(Adopt.run);
    }
}

test "HTTP/2 h2c stream ownership closes on non-positive adopted timeouts" {
    inline for (.{ 0, -1 }) |nanoseconds| {
        const Adopt = struct {
            fn run(allocator: std.mem.Allocator, io: std.Io, address: net.IpAddress, _: std.Io.Clock.Timestamp) runtime.Error!runtime.H2cUpgradeResult {
                const stream = try address.connect(io, .{ .mode = .stream });
                return runtime.Client.connectStreamUpgradeWithTimeout(allocator, io, stream, .{}, .{ .authority = "localhost" }, .fromNanoseconds(nanoseconds));
            }
        };
        try transition.expectClosedAfterAdoption(Adopt.run);
    }
}

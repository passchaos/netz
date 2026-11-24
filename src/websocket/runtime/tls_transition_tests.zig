const std = @import("std");
const runtime = @import("../runtime.zig");
const transition = @import("../../internal/testing/connection_transition.zig");

test "WSS TLS ownership closes stream when deadline expires after TCP connect" {
    inline for (.{ false, true }) |vail_tls| {
        inline for (.{ false, true }) |named| {
            const Connect = struct {
                fn run(allocator: std.mem.Allocator, io: std.Io, address: std.Io.net.IpAddress, deadline: std.Io.Clock.Timestamp) runtime.Error!runtime.Connection {
                    const options: runtime.ConnectOptions = .{ .host = "localhost", .vail_tls = if (vail_tls) .{} else null };
                    const tls: runtime.http1_runtime.TlsClientOptions = .{ .verify_host = false, .handshake_timeout = .fromSeconds(10) };
                    return if (named)
                        runtime.Client.connectTlsHostWithDeadline(allocator, io, "127.0.0.1", address.getPort(), options, tls, deadline)
                    else
                        runtime.Client.connectTlsAddressWithDeadline(allocator, io, address, "localhost", options, tls, deadline);
                }
            };
            try transition.expectClosedAfterConnect(Connect.run);
        }
    }
}

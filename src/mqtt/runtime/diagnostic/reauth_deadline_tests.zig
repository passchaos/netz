const std = @import("std");
const mqtt = @import("../../mod.zig");
const Pair = @import("../acknowledgement/test_connection.zig").Pair;
const BlockedWrite = @import("../acknowledgement/deadline_tests.zig").BlockedWrite;
const allocator = std.testing.allocator;
const method = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "mirror" } }};
const other = [_]mqtt.Property{.{ .utf8 = .{ .id = .authentication_method, .value = "other" } }};

test "MQTT bounded reauthentication diagnostics retain method errors across receive accept and apply" {
    const Mode = enum { receive, accept, apply };
    for (std.enums.values(Mode)) |mode| {
        for ([_]bool{ false, true }) |absolute| {
            var threaded = std.Io.Threaded.init(allocator, .{ .async_limit = .unlimited });
            defer threaded.deinit();
            const io = threaded.io();
            var blocked = BlockedWrite{ .delegate = io, .packet_type = .disconnect };
            BlockedWrite.active = &blocked;
            defer BlockedWrite.active = null;
            var vtable = io.vtable.*;
            vtable.netWrite = BlockedWrite.netWrite;
            const observed_io = std.Io{ .userdata = io.userdata, .vtable = &vtable };
            var pair = try Pair.init(observed_io, .v5);
            defer pair.deinit();
            try pair.client.authentication.beginConnect(allocator, &method);
            pair.client.authentication.phase = .active;
            if (mode == .accept) {
                pair.client.endpoint_role = .server;
                pair.peer.endpoint_role = .client;
                try pair.peer.writeAuth(0x19, &other);
            } else {
                try pair.client.beginReauthenticationWithProperties(&method);
                var initial = try pair.peer.readAuth();
                initial.deinit(allocator);
                if (mode == .receive) try pair.peer.writeAuth(0x18, &other);
            }
            blocked.armed.store(true, .release);
            const timeout = std.Io.Duration.fromMilliseconds(50);
            const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .raw = timeout, .clock = .awake });
            switch (mode) {
                .receive => try std.testing.expectError(error.AuthenticationMethodMismatch, if (absolute) pair.client.receiveReauthenticationWithDeadline(deadline) else pair.client.receiveReauthenticationWithTimeout(timeout)),
                .accept => try std.testing.expectError(error.AuthenticationMethodMismatch, if (absolute) pair.client.acceptReauthenticationWithDeadline(deadline) else pair.client.acceptReauthenticationWithTimeout(timeout)),
                .apply => try std.testing.expectError(error.AuthenticationMethodMismatch, pair.client.applyAuthenticationEventWithDeadline(.{ .reason_code = 0x18, .properties = @constCast(&other) }, deadline)),
            }
            try std.testing.expect(blocked.entered.load(.acquire));
            try std.testing.expect(blocked.canceled.load(.acquire));
            try std.testing.expect(!pair.client.isUsable());
        }
    }
}

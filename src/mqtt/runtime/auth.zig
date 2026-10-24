//! MQTT 5 enhanced-authentication state shared by all runtime transports.
//!
//! Mosquitto keeps distinct authenticating, active, and reauthenticating
//! states. This compact equivalent additionally owns the negotiated method so
//! CONNECT/AUTH/CONNACK packets cannot change or borrow it accidentally.

const std = @import("std");
const mqtt = @import("../mod.zig");

pub const Error = mqtt.Error || error{
    AuthenticationInProgress,
    AuthenticationMethodMismatch,
    AuthenticationNotConfigured,
    InvalidAuthenticationState,
};

pub const Phase = enum {
    inactive,
    authenticating,
    active,
    reauthenticating,
};

test "MQTT auth state rejects mismatched methods and traffic" {
    const allocator = std.testing.allocator;
    var state: State = .{};
    defer state.deinit(allocator);
    var method = "mirror".*;
    try state.beginConnect(allocator, &.{.{ .utf8 = .{
        .id = .authentication_method,
        .value = &method,
    } }});
    method[0] = 'x';
    try std.testing.expectEqualStrings("mirror", state.method().?);
    if (@sizeOf(usize) == 8) {
        try std.testing.expectEqual(@as(usize, 16), @sizeOf(State));
    }
    try std.testing.expectEqual(Phase.authenticating, state.phase);
    try std.testing.expectError(
        error.AuthenticationInProgress,
        state.ensurePacketAllowed(.publish),
    );
    try std.testing.expectError(
        error.AuthenticationMethodMismatch,
        state.validatePeerProperties(&.{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "other",
        } }}),
    );
    try state.receiveInitialAuth(.{
        .reason_code = 0x18,
        .properties = @constCast(&[_]mqtt.Property{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } }}),
    });
    try state.finishServerInitial();
    try std.testing.expectEqual(Phase.active, state.phase);
    try state.beginReauthentication(&.{.{ .utf8 = .{
        .id = .authentication_method,
        .value = "mirror",
    } }});
    try state.ensurePacketAllowed(.pingreq);
    try state.ensurePacketAllowed(.publish);
    try state.ensurePacketAllowed(.puback);
    try std.testing.expect(try state.receiveReauth(.{
        .reason_code = 0,
        .properties = @constCast(&[_]mqtt.Property{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } }}),
    }));
    try std.testing.expectEqual(Phase.active, state.phase);
}

test "MQTT auth method allocation failure leaves inactive state" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    var state: State = .{};
    try std.testing.expectError(
        error.OutOfMemory,
        state.beginConnect(failing.allocator(), &.{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "method",
        } }}),
    );
    try std.testing.expect(state.method() == null);
    try std.testing.expectEqual(Phase.inactive, state.phase);
}

test "MQTT auth state rejects a method introduced by CONNACK" {
    var state: State = .{};
    try state.beginConnect(std.testing.allocator, &.{});
    try std.testing.expectEqual(Phase.active, state.phase);
    try std.testing.expectError(
        error.AuthenticationMethodMismatch,
        state.receiveInitialConnAck(.{
            .session_present = false,
            .reason_code = 0,
            .properties = @constCast(&[_]mqtt.Property{.{ .utf8 = .{
                .id = .authentication_method,
                .value = "unsolicited",
            } }}),
        }),
    );
    try std.testing.expectEqual(Phase.active, state.phase);
}

pub const State = struct {
    method_ptr: [*]u8 = undefined,
    method_len: u16 = 0,
    has_method: bool = false,
    phase: Phase = .inactive,

    pub fn method(self: State) ?[]const u8 {
        if (!self.has_method) return null;
        return self.method_ptr[0..self.method_len];
    }

    pub fn deinit(
        self: *State,
        allocator: std.mem.Allocator,
    ) void {
        if (self.has_method) {
            allocator.free(self.method_ptr[0..self.method_len]);
        }
        self.* = undefined;
    }

    pub fn beginConnect(
        self: *State,
        allocator: std.mem.Allocator,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.phase != .inactive or self.has_method) {
            return error.InvalidAuthenticationState;
        }
        const method_value = mqtt.authenticationMethod(properties) orelse {
            self.phase = .active;
            return;
        };
        const method_len = std.math.cast(u16, method_value.len) orelse
            return error.InvalidProperty;
        const owned = try allocator.dupe(u8, method_value);
        self.method_ptr = owned.ptr;
        self.method_len = method_len;
        self.has_method = true;
        self.phase = .authenticating;
    }

    pub fn validatePeerProperties(
        self: State,
        properties: []const mqtt.Property,
    ) Error!void {
        const expected = self.method() orelse
            return error.AuthenticationNotConfigured;
        const actual = mqtt.authenticationMethod(properties) orelse
            return error.AuthenticationMethodMismatch;
        if (!std.mem.eql(u8, expected, actual)) {
            return error.AuthenticationMethodMismatch;
        }
    }

    pub fn receiveInitialAuth(self: *State, auth: mqtt.Auth) Error!void {
        if (self.phase != .authenticating or auth.reason_code != 0x18) {
            return error.InvalidAuthenticationState;
        }
        try self.validatePeerProperties(auth.properties);
    }

    pub fn receiveInitialConnAck(
        self: *State,
        connack: mqtt.ConnAck,
    ) Error!void {
        if (self.phase == .active) {
            // A server cannot introduce Enhanced Authentication when the
            // CONNECT did not select a method.
            if (mqtt.authenticationMethod(connack.properties) != null) {
                return error.AuthenticationMethodMismatch;
            }
            return;
        }
        if (self.phase != .authenticating) return error.InvalidAuthenticationState;
        // Failed CONNACK may omit Authentication Method. If it is present it
        // must still match, but refusal reporting must not be hidden behind a
        // synthetic method-mismatch error.
        if (mqtt.authenticationMethod(connack.properties) != null) {
            try self.validatePeerProperties(connack.properties);
        } else if (connack.reason_code == 0) {
            return error.AuthenticationMethodMismatch;
        }
        self.phase = .active;
    }

    pub fn finishServerInitial(self: *State) Error!void {
        if (self.phase != .authenticating) {
            return error.InvalidAuthenticationState;
        }
        self.phase = .active;
    }

    pub fn beginReauthentication(
        self: *State,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.phase != .active) {
            return error.AuthenticationInProgress;
        }
        try self.validatePeerProperties(properties);
        self.phase = .reauthenticating;
    }

    pub fn receiveReauth(self: *State, auth: mqtt.Auth) Error!bool {
        if (self.phase != .reauthenticating) {
            return error.InvalidAuthenticationState;
        }
        try self.validatePeerProperties(auth.properties);
        return switch (auth.reason_code) {
            0x18 => false,
            0x00 => blk: {
                self.phase = .active;
                break :blk true;
            },
            else => error.InvalidAuthenticationState,
        };
    }

    pub fn finishReauthentication(self: *State) Error!void {
        if (self.phase != .reauthenticating) {
            return error.InvalidAuthenticationState;
        }
        self.phase = .active;
    }

    pub fn ensurePacketAllowed(
        self: State,
        packet_type: mqtt.PacketType,
    ) Error!void {
        switch (self.phase) {
            // MQTT 5 4.12.1 permits normal packet flow using the previous
            // authentication while a new exchange is still in progress.
            .inactive, .active, .reauthenticating => return,
            .authenticating => switch (packet_type) {
                .connect, .connack, .auth, .disconnect => return,
                else => return error.AuthenticationInProgress,
            },
        }
    }
};

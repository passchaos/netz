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
    try std.testing.expectEqualStrings("mirror", state.method.?);
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
    try std.testing.expectError(
        error.AuthenticationInProgress,
        state.ensurePacketAllowed(.pingreq),
    );
    try std.testing.expect(try state.receiveReauth(.{
        .reason_code = 0,
        .properties = @constCast(&[_]mqtt.Property{.{ .utf8 = .{
            .id = .authentication_method,
            .value = "mirror",
        } }}),
    }));
    try std.testing.expectEqual(Phase.active, state.phase);
}

pub const State = struct {
    method: ?[]u8 = null,
    phase: Phase = .inactive,

    pub fn deinit(
        self: *State,
        allocator: std.mem.Allocator,
    ) void {
        if (self.method) |method| allocator.free(method);
        self.* = undefined;
    }

    pub fn beginConnect(
        self: *State,
        allocator: std.mem.Allocator,
        properties: []const mqtt.Property,
    ) Error!void {
        if (self.phase != .inactive or self.method != null) {
            return error.InvalidAuthenticationState;
        }
        const method = mqtt.authenticationMethod(properties) orelse {
            self.phase = .active;
            return;
        };
        self.method = try allocator.dupe(u8, method);
        self.phase = .authenticating;
    }

    pub fn validatePeerProperties(
        self: State,
        properties: []const mqtt.Property,
    ) Error!void {
        const expected = self.method orelse
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
        if (self.phase != .authenticating) {
            return error.InvalidAuthenticationState;
        }
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
            .inactive, .active => return,
            .authenticating => switch (packet_type) {
                .connect, .connack, .auth, .disconnect => return,
                else => return error.AuthenticationInProgress,
            },
            .reauthenticating => switch (packet_type) {
                .auth, .disconnect => return,
                else => return error.AuthenticationInProgress,
            },
        }
    }
};

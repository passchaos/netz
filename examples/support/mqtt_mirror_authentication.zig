//! Deterministic MQTT 5 Enhanced Authentication policy for wire interop.
//!
//! This intentionally mirrors Mosquitto's test plugin rather than providing a
//! credential mechanism. Keeping it outside the broker example's main module
//! makes the production `AuthenticationHandler` path visible without
//! embedding the fixture protocol in that already-large entry point.

const std = @import("std");
const netz = @import("netz");

pub const method = "mirror";
pub const initial_data = "step1";
pub const server_challenge = "1pets";
pub const client_response = "supercalifragilisticexpialidocious";

pub const Policy = struct {
    allocator: std.mem.Allocator,

    pub fn handler(self: *Policy) netz.mqtt.broker.AuthenticationHandler {
        return .{
            .context = self,
            .start = start,
            .handle = handle,
        };
    }

    fn start(
        context: *anyopaque,
        pending: *netz.mqtt.runtime.PendingAcceptedClient,
    ) netz.mqtt.broker.Error!void {
        const self: *Policy = @ptrCast(@alignCast(context));
        try requireMethod(pending.connect.connect.properties);
        try requireData(
            pending.connect.connect.properties,
            initial_data,
        );
        try pending.challengeAuthentication(server_challenge);
        var response = try pending.receiveAuthentication();
        defer response.deinit(self.allocator);
        if (response.auth.reason_code != 0x18) {
            return error.InvalidAuthenticationState;
        }
        try requireData(response.auth.properties, client_response);
        try pending.authorizeAuthentication();
    }

    fn handle(
        _: *anyopaque,
        connection: *netz.mqtt.runtime.Connection,
        auth: netz.mqtt.Auth,
        complete: bool,
    ) netz.mqtt.broker.Error!void {
        if (complete) return error.InvalidAuthenticationState;
        switch (auth.reason_code) {
            0x19 => {
                try requireData(auth.properties, initial_data);
                try connection.continueReauthentication(
                    0x18,
                    server_challenge,
                );
            },
            0x18 => {
                try requireData(auth.properties, client_response);
                try connection.continueReauthenticationWithProperties(
                    0,
                    &.{.{ .utf8 = .{
                        .id = .authentication_method,
                        .value = method,
                    } }},
                );
            },
            else => return error.InvalidAuthenticationState,
        }
    }

    fn requireMethod(properties: []const netz.mqtt.Property) !void {
        const actual = netz.mqtt.authenticationMethod(properties) orelse
            return error.AuthenticationNotConfigured;
        if (!std.mem.eql(u8, method, actual)) {
            return error.AuthenticationMethodMismatch;
        }
    }

    fn requireData(
        properties: []const netz.mqtt.Property,
        expected: []const u8,
    ) !void {
        const actual = netz.mqtt.authenticationData(properties) orelse
            return error.InvalidAuthenticationState;
        if (!std.mem.eql(u8, expected, actual)) {
            return error.InvalidAuthenticationState;
        }
    }
};

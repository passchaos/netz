//! Deterministic MQTT 5 Enhanced Authentication policy for wire interop.
//!
//! This mirrors Mosquitto's single-step and multi-step test plugins rather
//! than providing a credential mechanism. Keeping it outside the broker
//! example's main module makes the production `AuthenticationHandler` path
//! visible without embedding fixture protocols in that already-large entry
//! point.

const std = @import("std");
const netz = @import("netz");

const mirror_method = "mirror";
const single_method = "single";
const error_method = "error";
const repeat_method = "repeat";
const initial_data = "step1";
const server_challenge = "1pets";
const client_response = "supercalifragilisticexpialidocious";

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
        const properties = pending.connect.connect.properties;
        const method = netz.mqtt.authenticationMethod(properties) orelse
            return error.AuthenticationNotConfigured;
        if (std.mem.eql(u8, method, error_method)) {
            return error.InvalidAuthenticationState;
        }
        if (std.mem.eql(u8, method, single_method)) {
            const data = try authenticationData(properties);
            if (std.mem.eql(u8, data, "data")) {
                try pending.authorizeAuthentication();
            } else {
                try pending.rejectAuthentication(0x87);
            }
            return;
        }
        if (std.mem.eql(u8, method, repeat_method)) {
            const data = try authenticationData(properties);
            if (std.mem.eql(u8, data, "repeat")) {
                try pending.authorizeAuthentication();
            } else {
                try pending.rejectAuthentication(0x87);
            }
            return;
        }
        if (!std.mem.eql(u8, method, mirror_method)) {
            try pending.rejectAuthentication(0x8c);
            return;
        }

        const data = try authenticationData(properties);
        if (std.mem.eql(u8, data, "somedata")) {
            try pending.authorizeAuthenticationWithData("atademos");
            return;
        }
        if (!std.mem.eql(u8, data, initial_data)) {
            try pending.rejectAuthentication(0x87);
            return;
        }
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
        const method = netz.mqtt.authenticationMethod(auth.properties) orelse
            return error.AuthenticationNotConfigured;
        if (std.mem.eql(u8, method, repeat_method)) {
            if (auth.reason_code != 0x19) {
                return error.InvalidAuthenticationState;
            }
            try requireData(auth.properties, "repeat");
            try connection.rejectReauthentication(0x87);
            return;
        }
        if (!std.mem.eql(u8, method, mirror_method)) {
            return error.AuthenticationMethodMismatch;
        }
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
                        .value = mirror_method,
                    } }},
                );
            },
            else => return error.InvalidAuthenticationState,
        }
    }

    fn authenticationData(
        properties: []const netz.mqtt.Property,
    ) ![]const u8 {
        return netz.mqtt.authenticationData(properties) orelse
            error.InvalidAuthenticationState;
    }

    fn requireData(
        properties: []const netz.mqtt.Property,
        expected: []const u8,
    ) !void {
        const actual = try authenticationData(properties);
        if (!std.mem.eql(u8, expected, actual)) {
            return error.InvalidAuthenticationState;
        }
    }
};

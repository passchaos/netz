//! MQTT protocol-violation diagnostics shared by client and broker runtimes.

const std = @import("std");
const mqtt = @import("../mod.zig");

/// Map an established peer violation to an MQTT 5 DISCONNECT reason. Errors
/// caused by local resources, application policy, or transport failure return
/// null and must not be presented to the peer as malformed input.
pub fn disconnectReason(
    err: anyerror,
    sender: mqtt.DisconnectSender,
) ?u8 {
    const reason_code: u8 = switch (err) {
        error.QoSNotSupported => 0x9b,
        error.RetainNotSupported => 0x9a,
        error.TopicAliasInvalid => 0x94,
        error.ReceiveMaximumExceeded => 0x93,
        error.SharedSubscriptionsNotSupported => 0x9e,
        error.SubscriptionIdentifiersNotSupported => 0xa1,
        error.WildcardSubscriptionsNotSupported => 0xa2,
        error.InvalidPacketDirection,
        error.ReservedPacketType,
        error.InvalidProperty,
        error.InvalidReasonCode,
        error.InvalidTopic,
        error.InvalidSubscription,
        error.InvalidPacketIdentifier,
        error.InvalidAcknowledgement,
        error.UnexpectedPacket,
        => 0x82,
        error.InvalidPacketType,
        error.InvalidFlags,
        error.InvalidQoS,
        error.InvalidPropertyIdentifier,
        error.MalformedPropertyContext,
        error.MalformedSubscriptionOptions,
        error.BufferTooShort,
        error.MalformedRemainingLength,
        error.RemainingLengthTooLarge,
        error.InvalidUtf8,
        => 0x81,
        error.PacketTooLarge => 0x95,
        else => return null,
    };
    mqtt.validateDisconnectReasonForSender(reason_code, sender) catch {
        // Capability errors have server-only reason codes. A client that sees
        // the peer violate one of its advertised limits reports the generic
        // Protocol Error instead.
        return 0x82;
    };
    return reason_code;
}

test "MQTT protocol violation DISCONNECT reasons respect sender direction" {
    try std.testing.expectEqual(
        @as(?u8, 0x9b),
        disconnectReason(error.QoSNotSupported, .server),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x82),
        disconnectReason(error.QoSNotSupported, .client),
    );
    try std.testing.expectEqual(
        @as(?u8, 0x81),
        disconnectReason(error.InvalidFlags, .client),
    );
    try std.testing.expectEqual(
        @as(?u8, null),
        disconnectReason(error.OutOfMemory, .client),
    );
}

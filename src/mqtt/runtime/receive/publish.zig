//! Own resolved Topic Names before committing incoming publication state.
const mqtt = @import("../../mod.zig");

pub fn decode(connection: anytype, packet: anytype, comptime Hooks: anytype) Hooks.ErrorType!Hooks.PublishType {
    var value = try mqtt.Publish.parsePayload(connection.allocator, connection.protocol, packet.fixed.flags, packet.remainingBytes());
    errdefer value.deinit(connection.allocator);
    try Hooks.validateUtf8(connection.*, value.topic);
    try Hooks.validateProperties(connection.*, value.properties);
    try Hooks.validateCapabilities(connection.*, value);
    try Hooks.validateAlias(connection.*, value);
    var owned_topic: ?[]u8 = null;
    errdefer if (owned_topic) |topic| connection.allocator.free(topic);
    if (value.topic.len == 0) {
        const alias = mqtt.topicAlias(value.properties) orelse return error.InvalidTopic;
        const stored = Hooks.aliasTopic(connection, alias) orelse return error.InvalidTopic;
        // Packet payload storage cannot own a Topic Name omitted on the wire.
        // Alias replacement or connection close must not invalidate this value.
        owned_topic = try connection.allocator.dupe(u8, stored);
        value.topic = owned_topic.?;
    }
    try Hooks.commit(connection, &value, owned_topic == null);
    return .{ .packet = packet, .publish = value, .owned_topic = owned_topic };
}

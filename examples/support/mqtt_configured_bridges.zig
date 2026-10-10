//! Runtime ownership for inbound bridges declared by mqtt_broker_config.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;

pub const Set = struct {
    allocator: std.mem.Allocator,
    values: []mqtt.bridge.Bridge,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *mqtt.broker.Broker,
        configured: []const mqtt.broker_config.Bridge,
        shutdown: *std.Io.Event,
    ) !Set {
        const values = try allocator.alloc(mqtt.bridge.Bridge, configured.len);
        errdefer allocator.free(values);
        var initialized: usize = 0;
        errdefer {
            while (initialized != 0) {
                initialized -= 1;
                values[initialized].deinit();
            }
        }
        for (configured, values) |source, *bridge| {
            const rules = try allocator.alloc(mqtt.bridge.Rule, source.rules.len);
            defer allocator.free(rules);
            for (source.rules, rules) |rule, *runtime_rule| {
                runtime_rule.* = .{
                    .filter = rule.filter,
                    .qos = rule.qos,
                    .local_prefix = rule.local_prefix,
                    .remote_prefix = rule.remote_prefix,
                };
            }
            var properties: [1]mqtt.Property = undefined;
            const property_slice: []const mqtt.Property = if (source.protocol == .v5 and
                source.session_expiry_interval != 0)
            blk: {
                properties[0] = .{ .four_byte = .{
                    .id = .session_expiry_interval,
                    .value = source.session_expiry_interval,
                } };
                break :blk &properties;
            } else &.{};
            bridge.* = try mqtt.bridge.Bridge.initHostMany(
                allocator,
                io,
                local,
                source.host,
                source.port,
                .{
                    .connect = .{
                        .protocol = source.protocol,
                        .client_id = source.clientId(),
                        .clean_start = source.clean_session,
                        .keep_alive_seconds = source.keep_alive_seconds,
                        .properties = property_slice,
                        .username = if (source.remote_username.len == 0)
                            null
                        else
                            source.remote_username,
                        .password = if (source.remote_password.len == 0)
                            null
                        else
                            source.remote_password,
                    },
                    .reconnect_policy = .{
                        .initial_delay = .fromSeconds(
                            source.restart.base_seconds,
                        ),
                        .max_delay = .fromSeconds(source.restart.cap_seconds),
                        .backoff = if (source.restart.jitter)
                            .exponential
                        else
                            .fixed,
                        .jitter = if (source.restart.jitter) .full else .none,
                    },
                    .rules = rules,
                    .bridge_id = if (source.usesQoS2())
                        stableBridgeId(source)
                    else
                        null,
                },
                shutdown,
            );
            initialized += 1;
        }
        return .{ .allocator = allocator, .values = values };
    }

    pub fn deinit(self: *Set) void {
        var remaining = self.values.len;
        while (remaining != 0) {
            remaining -= 1;
            self.values[remaining].deinit();
        }
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

fn stableBridgeId(source: mqtt.broker_config.Bridge) [16]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("netz mqtt inbound bridge v1\x00");
    hashField(&hasher, source.name);
    hashField(&hasher, source.clientId());
    hasher.update(&.{@intFromEnum(source.protocol)});
    hashInteger(&hasher, source.rules.len);
    for (source.rules) |rule| {
        hashField(&hasher, rule.filter);
        hasher.update(&.{@intFromEnum(rule.qos)});
        hashField(&hasher, rule.local_prefix);
        hashField(&hasher, rule.remote_prefix);
    }
    const digest = hasher.finalResult();
    return digest[0..16].*;
}

fn hashField(hasher: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    hashInteger(hasher, value.len);
    hasher.update(value);
}

fn hashInteger(hasher: *std.crypto.hash.sha2.Sha256, value: usize) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, @intCast(value), .little);
    hasher.update(&encoded);
}

test "configured bridge identifiers bind identity and mappings" {
    var name = "upstream".*;
    var host = "broker.example".*;
    var client_id = "bridge-client".*;
    var filter = "remote/sensors/#".*;
    var local_prefix = "local/".*;
    var remote_prefix = "remote/".*;
    var rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &filter,
        .qos = .exactly_once,
        .local_prefix = &local_prefix,
        .remote_prefix = &remote_prefix,
    }};
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .rules = &rules,
        .remote_client_id = &client_id,
    };
    try std.testing.expectEqual(
        stableBridgeId(source),
        stableBridgeId(source),
    );
    const original = stableBridgeId(source);
    filter[filter.len - 1] = '+';
    try std.testing.expect(!std.mem.eql(
        u8,
        &original,
        &stableBridgeId(source),
    ));
}

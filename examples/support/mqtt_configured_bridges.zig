//! Runtime ownership for inbound bridges declared by mqtt_broker_config.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;
const CertificateBundle = std.crypto.Certificate.Bundle;

const max_bridge_ca_file_bytes: usize = 4 * 1024 * 1024;

const ConfiguredConnector = struct {
    source: *const mqtt.broker_config.Bridge,
    tls_options: ?mqtt.tls_runtime.ConnectOptions = null,
    next_address: usize = 0,

    fn connector(self: *ConfiguredConnector) mqtt.runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt.runtime.ConnectOptions,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        const self: *ConfiguredConnector = @ptrCast(@alignCast(context));
        const endpoint = self.takeEndpoint();
        if (self.tls_options) |options| {
            var tls_connector = mqtt.tls_runtime.HostReconnectConnector{
                .host = endpoint.host,
                .port = endpoint.port,
                .options = options,
            };
            return tls_connector.connector().connectAttempt(
                allocator,
                io,
                mqtt_options,
            );
        }
        return mqtt.runtime.Client.connectHostAttempt(
            allocator,
            io,
            endpoint.host,
            endpoint.port,
            mqtt_options,
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt.runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        const self: *ConfiguredConnector = @ptrCast(@alignCast(context));
        const endpoint = self.takeEndpoint();
        if (self.tls_options) |options| {
            var tls_connector = mqtt.tls_runtime.HostReconnectConnector{
                .host = endpoint.host,
                .port = endpoint.port,
                .options = options,
            };
            return tls_connector.connector().connectAttemptWithDeadline(
                allocator,
                io,
                mqtt_options,
                deadline,
            );
        }
        return mqtt.runtime.Client.connectHostAttemptWithDeadline(
            allocator,
            io,
            endpoint.host,
            endpoint.port,
            mqtt_options,
            deadline,
        );
    }

    fn takeEndpoint(self: *ConfiguredConnector) mqtt.broker_config.BridgeEndpoint {
        const index = self.next_address;
        self.next_address = (index + 1) % self.source.addressCount();
        return self.source.addressAt(index);
    }
};

const ConnectorResources = struct {
    ca_bundle: CertificateBundle = .empty,
    ca_lock: std.Io.RwLock = .init,
    identity: ?netz.tls.server_identity_file.Identity = null,
    alpn_protocols: [1][]const u8 = undefined,
    connector: ConfiguredConnector = undefined,

    fn deinit(self: *ConnectorResources, allocator: std.mem.Allocator) void {
        if (self.identity) |*identity| identity.deinit();
        self.ca_bundle.deinit(allocator);
        self.* = undefined;
    }
};

pub const Set = struct {
    allocator: std.mem.Allocator,
    values: []mqtt.bridge.Bridge,
    connector_resources: []ConnectorResources,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *mqtt.broker.Broker,
        configured: []const mqtt.broker_config.Bridge,
        shutdown: *std.Io.Event,
    ) !Set {
        const values = try allocator.alloc(mqtt.bridge.Bridge, configured.len);
        errdefer allocator.free(values);
        const connector_resources = try allocator.alloc(
            ConnectorResources,
            configured.len,
        );
        errdefer allocator.free(connector_resources);
        @memset(connector_resources, .{});
        errdefer for (connector_resources) |*resources| {
            resources.deinit(allocator);
        };
        var initialized: usize = 0;
        errdefer {
            while (initialized != 0) {
                initialized -= 1;
                values[initialized].deinit();
            }
        }
        for (configured, values, connector_resources) |*source, *bridge, *resources| {
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
            const options = mqtt.bridge.MultiOptions{
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
                    stableBridgeId(source.*)
                else
                    null,
            };
            bridge.* = if (source.usesTls() or source.addressCount() > 1) blk: {
                if (source.usesTls()) {
                    try loadTlsResources(
                        resources,
                        allocator,
                        io,
                        std.Io.Dir.cwd(),
                        source,
                    );
                } else {
                    resources.connector = .{ .source = source };
                }
                break :blk try mqtt.bridge.Bridge.initConnectorMany(
                    allocator,
                    io,
                    local,
                    resources.connector.connector(),
                    options,
                    shutdown,
                );
            } else try mqtt.bridge.Bridge.initHostMany(
                allocator,
                io,
                local,
                source.host,
                source.port,
                options,
                shutdown,
            );
            initialized += 1;
        }
        return .{
            .allocator = allocator,
            .values = values,
            .connector_resources = connector_resources,
        };
    }

    pub fn deinit(self: *Set) void {
        var remaining = self.values.len;
        while (remaining != 0) {
            remaining -= 1;
            self.values[remaining].deinit();
        }
        for (self.connector_resources) |*resources| {
            resources.deinit(self.allocator);
        }
        self.allocator.free(self.connector_resources);
        self.allocator.free(self.values);
        self.* = undefined;
    }
};

fn loadTlsResources(
    resources: *ConnectorResources,
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    source: *const mqtt.broker_config.Bridge,
) !void {
    if (source.ca_file.len != 0) {
        if (source.use_os_ca_certificates) {
            try resources.ca_bundle.rescan(
                allocator,
                io,
                std.Io.Clock.real.now(io),
            );
        }
        const ca_source = try dir.readFileAlloc(
            io,
            source.ca_file,
            allocator,
            .limited(max_bridge_ca_file_bytes + 1),
        );
        defer allocator.free(ca_source);
        if (ca_source.len > max_bridge_ca_file_bytes) {
            return error.BridgeCaFileTooLarge;
        }
        if (std.mem.indexOf(
            u8,
            ca_source,
            "-----BEGIN CERTIFICATE-----",
        ) == null) return error.EmptyBridgeCaFile;
        try resources.ca_bundle.addCertsFromFilePath(
            allocator,
            io,
            std.Io.Clock.real.now(io),
            dir,
            source.ca_file,
        );
    }
    if (source.certificate_file.len != 0) {
        resources.identity = if (source.private_key_password_file.len != 0)
            try netz.tls.server_identity_file.loadWithPasswordFile(
                allocator,
                io,
                dir,
                source.certificate_file,
                source.private_key_file,
                source.private_key_password_file,
            )
        else
            try netz.tls.server_identity_file.load(
                allocator,
                io,
                dir,
                source.certificate_file,
                source.private_key_file,
            );
    }
    if (source.alpn.len != 0) resources.alpn_protocols[0] = source.alpn;
    const server_identity = if (resources.identity) |*identity|
        identity.serverIdentity()
    else
        null;
    resources.connector = .{
        .source = source,
        .tls_options = .{
            .mqtt = .{ .client_id = source.clientId() },
            .tls = .{
                .ca_bundle = if (source.ca_file.len != 0) .{
                    .bundle = &resources.ca_bundle,
                    .lock = &resources.ca_lock,
                } else null,
            },
            .use_vail = true,
            .client_identity = if (server_identity) |identity| .{
                .certificate_chain = identity.certificate_chain,
                .signer = identity.signer,
                .certificate_type = identity.certificate_type,
            } else null,
            .alpn_protocols = if (source.alpn.len == 0)
                &.{}
            else
                resources.alpn_protocols[0..1],
        },
    };
}

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

test "configured bridge rejects an empty explicit CA file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "empty.pem", .data = "" });
    var name = "tls-upstream".*;
    var host = "localhost".*;
    var ca_file = "empty.pem".*;
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .rules = &.{},
        .ca_file = &ca_file,
    };
    var resources: ConnectorResources = .{};
    defer resources.deinit(allocator);
    try std.testing.expectError(
        error.EmptyBridgeCaFile,
        loadTlsResources(&resources, allocator, io, tmp.dir, &source),
    );
}

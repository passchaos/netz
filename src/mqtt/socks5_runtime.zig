//! Native MQTT and MQTT-over-TLS through reusable SOCKS5 CONNECT tunnels.
//!
//! The proxy route is borrowed. MQTT reconnect clients deep-own their normal
//! CONNECT state while these adapters retain only proxy and TLS transport
//! policy, matching the ownership split of the direct hostname connectors.

const std = @import("std");
const mqtt_runtime = @import("runtime.zig");
const mqtt_tls = @import("tls_runtime.zig");
const proxy_socks5 = @import("../proxy/socks5.zig");

pub const Options = proxy_socks5.Options;
pub const Credentials = proxy_socks5.Credentials;

pub const Route = struct {
    proxy_host: []const u8,
    proxy_port: u16 = 1080,
    target_host: []const u8,
    target_port: u16,
    options: Options = .{},

    fn effective(
        self: Route,
        mqtt_options: mqtt_runtime.ConnectOptions,
    ) Options {
        var options = self.options;
        if (options.connect_timeout == null) {
            options.connect_timeout = mqtt_options.network_connect_timeout;
        }
        if (options.address_resolver == null) {
            options.address_resolver = mqtt_options.address_resolver;
        }
        if (options.address_connect_policy == null) {
            options.address_connect_policy = mqtt_options.address_connect_policy;
        }
        return options;
    }
};

pub const Client = struct {
    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectHostWithConnAck(
            allocator,
            io,
            route,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectHostAttempt(allocator, io, route, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const stream = try proxy_socks5.connectHost(
            allocator,
            io,
            route.proxy_host,
            route.proxy_port,
            route.target_host,
            route.target_port,
            route.effective(options),
        );
        return mqtt_runtime.Client.connectStreamAttempt(
            allocator,
            io,
            stream,
            options,
        );
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectHostWithConnAckWithDeadline(
            allocator,
            io,
            route,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(
            allocator,
            io,
            route,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectHostAttemptWithDeadline(
            allocator,
            io,
            route,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithConnAckWithDeadline(
            allocator,
            io,
            route,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const stream = try proxy_socks5.connectHostWithDeadline(
            allocator,
            io,
            route.proxy_host,
            route.proxy_port,
            route.target_host,
            route.target_port,
            route.effective(options),
            deadline,
        );
        return mqtt_runtime.Client.connectStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            options,
            deadline,
        );
    }

    pub fn connectHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_runtime.ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostAttemptWithDeadline(
            allocator,
            io,
            route,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }
};

pub const TlsClient = struct {
    pub fn connectHost(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectHostWithConnAck(
            allocator,
            io,
            route,
            options,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithConnAck(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectHostAttempt(allocator, io, route, options);
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostAttempt(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const stream = try proxy_socks5.connectHost(
            allocator,
            io,
            route.proxy_host,
            route.proxy_port,
            route.target_host,
            route.target_port,
            route.effective(options.mqtt),
        );
        return mqtt_tls.Client.connectStreamAttempt(
            allocator,
            io,
            stream,
            route.target_host,
            options,
        );
    }

    pub fn connectHostWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        var result = try connectHostWithConnAckWithDeadline(
            allocator,
            io,
            route,
            options,
            deadline,
        );
        defer result.connack.deinit(allocator);
        return result.connection;
    }

    pub fn connectHostWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.Connection {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithDeadline(
            allocator,
            io,
            route,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostWithConnAckWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        var attempt = try connectHostAttemptWithDeadline(
            allocator,
            io,
            route,
            options,
            deadline,
        );
        errdefer attempt.deinit(allocator);
        return attempt.requireAccepted();
    }

    pub fn connectHostWithConnAckWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectResult {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostWithConnAckWithDeadline(
            allocator,
            io,
            route,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }

    pub fn connectHostAttemptWithDeadline(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const stream = try proxy_socks5.connectHostWithDeadline(
            allocator,
            io,
            route.proxy_host,
            route.proxy_port,
            route.target_host,
            route.target_port,
            route.effective(options.mqtt),
            deadline,
        );
        return mqtt_tls.Client.connectStreamAttemptWithDeadline(
            allocator,
            io,
            stream,
            route.target_host,
            options,
            deadline,
        );
    }

    pub fn connectHostAttemptWithTimeout(
        allocator: std.mem.Allocator,
        io: std.Io,
        route: Route,
        options: mqtt_tls.ConnectOptions,
        timeout: std.Io.Duration,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return connectHostAttemptWithDeadline(
            allocator,
            io,
            route,
            options,
            .fromNow(io, .{ .raw = timeout, .clock = .awake }),
        );
    }
};

pub const ReconnectConnector = struct {
    route: Route,

    pub fn connector(self: *ReconnectConnector) mqtt_runtime.ClientConnector {
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
        options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectHostAttempt(
            allocator,
            io,
            self.route,
            options,
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *ReconnectConnector = @ptrCast(@alignCast(context));
        return Client.connectHostAttemptWithDeadline(
            allocator,
            io,
            self.route,
            options,
            deadline,
        );
    }
};

pub const TlsReconnectConnector = struct {
    route: Route,
    options: mqtt_tls.ConnectOptions,

    pub fn connector(
        self: *TlsReconnectConnector,
    ) mqtt_runtime.ClientConnector {
        return .{
            .context = self,
            .connect_attempt = connectAttempt,
            .connect_attempt_deadline = connectAttemptWithDeadline,
            .connect_attempt_with_tls_tickets = connectAttemptWithTlsTickets,
            .connect_attempt_with_tls_tickets_deadline = connectAttemptWithTlsTicketsAndDeadline,
        };
    }

    fn connectAttempt(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *TlsReconnectConnector = @ptrCast(@alignCast(context));
        return TlsClient.connectHostAttempt(
            allocator,
            io,
            self.route,
            reconnectTlsOptions(self.options, mqtt_options, .{}),
        );
    }

    fn connectAttemptWithDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *TlsReconnectConnector = @ptrCast(@alignCast(context));
        return TlsClient.connectHostAttemptWithDeadline(
            allocator,
            io,
            self.route,
            reconnectTlsOptions(self.options, mqtt_options, .{}),
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
        tickets: mqtt_runtime.ClientTlsSessionTickets,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *TlsReconnectConnector = @ptrCast(@alignCast(context));
        return TlsClient.connectHostAttempt(
            allocator,
            io,
            self.route,
            reconnectTlsOptions(self.options, mqtt_options, tickets),
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt_runtime.ConnectOptions,
        tickets: mqtt_runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt_runtime.Error!mqtt_runtime.ConnectAttempt {
        const self: *TlsReconnectConnector = @ptrCast(@alignCast(context));
        return TlsClient.connectHostAttemptWithDeadline(
            allocator,
            io,
            self.route,
            reconnectTlsOptions(self.options, mqtt_options, tickets),
            deadline,
        );
    }
};

fn reconnectTlsOptions(
    configured: mqtt_tls.ConnectOptions,
    mqtt_options: mqtt_runtime.ConnectOptions,
    tickets: mqtt_runtime.ClientTlsSessionTickets,
) mqtt_tls.ConnectOptions {
    var options = configured;
    const network_connect_timeout = options.mqtt.network_connect_timeout;
    const address_resolver = options.mqtt.address_resolver orelse
        mqtt_options.address_resolver;
    const address_connect_policy = switch (options.mqtt.address_connect_policy) {
        .ordered => mqtt_options.address_connect_policy,
        .happy_eyeballs => options.mqtt.address_connect_policy,
    };
    options.mqtt = mqtt_options;
    options.mqtt.network_connect_timeout = network_connect_timeout;
    options.mqtt.address_resolver = address_resolver;
    options.mqtt.address_connect_policy = address_connect_policy;
    if (tickets.tls12) |ticket| options.tls12_ticket_resumption = ticket;
    if (tickets.tls13) |ticket| options.tls13_ticket_resumption = ticket;
    return options;
}

test "MQTT SOCKS5 route inherits network policy with explicit proxy overrides" {
    const route = Route{
        .proxy_host = "proxy.example",
        .target_host = "broker.example",
        .target_port = 1883,
    };
    const inherited = route.effective(.{
        .client_id = "client",
        .network_connect_timeout = .fromSeconds(2),
        .address_connect_policy = .{ .happy_eyeballs = .{
            .attempt_delay = .fromMilliseconds(25),
        } },
    });
    try std.testing.expectEqual(
        @as(i64, 2 * std.time.ns_per_s),
        inherited.connect_timeout.?.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i64, 25 * std.time.ns_per_ms),
        inherited.address_connect_policy.?.happy_eyeballs
            .attempt_delay.nanoseconds,
    );

    var overridden = route;
    overridden.options.connect_timeout = .fromSeconds(1);
    overridden.options.address_connect_policy = .ordered;
    const effective = overridden.effective(.{
        .client_id = "client",
        .network_connect_timeout = .fromSeconds(2),
        .address_connect_policy = .{ .happy_eyeballs = .{} },
    });
    try std.testing.expectEqual(
        @as(i64, std.time.ns_per_s),
        effective.connect_timeout.?.nanoseconds,
    );
    try std.testing.expect(effective.address_connect_policy.? == .ordered);
}

test "MQTT TLS SOCKS5 reconnect preserves configured network policy" {
    const inherited = reconnectTlsOptions(
        .{ .mqtt = .{ .client_id = "template" } },
        .{
            .client_id = "owned",
            .network_connect_timeout = .fromSeconds(2),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(25),
            } },
        },
        .{},
    );
    try std.testing.expectEqualStrings("owned", inherited.mqtt.client_id);
    try std.testing.expectEqual(
        @as(i64, 2 * std.time.ns_per_s),
        inherited.mqtt.network_connect_timeout.?.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i64, 25 * std.time.ns_per_ms),
        inherited.mqtt.address_connect_policy.happy_eyeballs
            .attempt_delay.nanoseconds,
    );

    const configured = reconnectTlsOptions(
        .{ .mqtt = .{
            .client_id = "template",
            .network_connect_timeout = .fromSeconds(3),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(40),
            } },
        } },
        .{
            .client_id = "owned",
            .network_connect_timeout = .fromSeconds(2),
            .address_connect_policy = .{ .happy_eyeballs = .{
                .attempt_delay = .fromMilliseconds(25),
            } },
        },
        .{},
    );
    try std.testing.expectEqual(
        @as(i64, 3 * std.time.ns_per_s),
        configured.mqtt.network_connect_timeout.?.nanoseconds,
    );
    try std.testing.expectEqual(
        @as(i64, 40 * std.time.ns_per_ms),
        configured.mqtt.address_connect_policy.happy_eyeballs
            .attempt_delay.nanoseconds,
    );
}

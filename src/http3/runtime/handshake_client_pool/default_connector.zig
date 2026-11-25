//! Default owning-pool routes share preparation, deadline and result ownership.
const std = @import("std");
const http3 = @import("../../mod.zig");
const parent = @import("../handshake_client_pool.zig");
const owned = @import("../../../internal/owned_result_deadline.zig");
const ConnectionIds = @import("../../../quic/client_connection_ids.zig").Storage;

fn isolateRedirectOptions(options_value: anytype, forward_client_identity: bool) @TypeOf(options_value) {
    var options = options_value;
    options.handshake.retry_source_connection_id = &.{};
    options.handshake.server_name = null;
    options.handshake.address_validation_token = &.{};
    options.handshake.resumption_session = null;
    options.handshake.resumption_server_id = null;
    options.handshake.auto_resumption = null;
    options.handshake.early_data = null;
    options.handshake.random = null;
    options.handshake.x25519_secret_key = null;
    options.handshake.p256_secret_key = null;
    options.handshake.p384_secret_key = null;
    options.handshake.x25519_mlkem768_secret_key = null;
    options.handshake.x25519_mlkem768_seed = null;
    options.handshake.nist_hybrid_key_material = .{};
    if (!forward_client_identity) options.handshake.client_identity = null;
    return options;
}

fn scopeAutoResumption(options_value: anytype, server_id: []const u8) @TypeOf(options_value) {
    var options = options_value;
    if (options.handshake.auto_resumption) |*automatic| automatic.server_id = server_id;
    return options;
}

pub fn Context(comptime Runtime: type) type {
    return struct {
        options: Runtime.HandshakeClientOptions,
        transport: ?parent.TransportConnector(Runtime) = null,

        const Self = @This();
        const Dial = struct {
            owner: *Self,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
            target: ?http3.AltSvcTarget = null,
            redirect: ?parent.RedirectConnectContext = null,
            deadline: ?std.Io.Clock.Timestamp,
        };

        pub fn connector(self: *Self) parent.Connector(Runtime) {
            return .{
                .context = self,
                .client_identity_configured = self.options.handshake.client_identity != null,
                .connect = connect,
                .connect_redirect = connectRedirect,
                .connect_alt_svc = connectAltSvc,
                .connect_alt_svc_redirect = connectAltSvcRedirect,
                .connect_early_alt_svc = connectEarlyAltSvc,
            };
        }

        fn dial(context: *anyopaque, allocator: std.mem.Allocator, io: std.Io, local_address: std.Io.net.IpAddress, uri: std.Uri, limits: Runtime.Limits) Runtime.Error!Dial {
            const self: *Self = @ptrCast(@alignCast(context));
            return .{
                .owner = self,
                .allocator = allocator,
                .io = io,
                .local_address = local_address,
                .uri = uri,
                .limits = limits,
                .deadline = try Runtime.connectDeadline(io, self.options.connect_timeout),
            };
        }

        fn bounded(io: std.Io, deadline: ?std.Io.Clock.Timestamp, comptime work: anytype, args: std.meta.ArgsTuple(@TypeOf(work))) @typeInfo(@TypeOf(work)).@"fn".return_type.? {
            const until = deadline orelse return @call(.auto, work, args);
            return owned.before(io, until, work, args) catch |err| switch (err) {
                error.Timeout => error.HandshakeTimeout,
                else => |other| other,
            };
        }

        fn invoke(args: Dial) Runtime.Error!Runtime.HandshakeClient {
            return bounded(args.io, args.deadline, connectRoute, .{args});
        }

        fn connect(context: *anyopaque, allocator: std.mem.Allocator, io: std.Io, local_address: std.Io.net.IpAddress, uri: std.Uri, limits: Runtime.Limits) Runtime.Error!Runtime.HandshakeClient {
            return invoke(try dial(context, allocator, io, local_address, uri, limits));
        }

        fn connectRedirect(context: *anyopaque, allocator: std.mem.Allocator, io: std.Io, local_address: std.Io.net.IpAddress, uri: std.Uri, limits: Runtime.Limits, redirect: parent.RedirectConnectContext) Runtime.Error!Runtime.HandshakeClient {
            var args = try dial(context, allocator, io, local_address, uri, limits);
            args.redirect = redirect;
            return invoke(args);
        }

        fn connectAltSvc(context: *anyopaque, allocator: std.mem.Allocator, io: std.Io, local_address: std.Io.net.IpAddress, uri: std.Uri, target: http3.AltSvcTarget, limits: Runtime.Limits) Runtime.Error!Runtime.HandshakeClient {
            var args = try dial(context, allocator, io, local_address, uri, limits);
            args.target = target;
            return invoke(args);
        }

        fn connectAltSvcRedirect(context: *anyopaque, allocator: std.mem.Allocator, io: std.Io, local_address: std.Io.net.IpAddress, uri: std.Uri, target: http3.AltSvcTarget, limits: Runtime.Limits, redirect: parent.RedirectConnectContext) Runtime.Error!Runtime.HandshakeClient {
            var args = try dial(context, allocator, io, local_address, uri, limits);
            args.target = target;
            args.redirect = redirect;
            return invoke(args);
        }

        fn connectEarlyAltSvc(context: *anyopaque, allocator: std.mem.Allocator, io: std.Io, local_address: std.Io.net.IpAddress, uri: std.Uri, target: http3.AltSvcTarget, limits: Runtime.Limits, early_request: *const Runtime.PreparedEarlyRequest) Runtime.Error!parent.EarlyConnected(Runtime) {
            var args = try dial(context, allocator, io, local_address, uri, limits);
            args.target = target;
            return bounded(io, args.deadline, connectEarlyRoute, .{ args, early_request });
        }

        fn optionsFor(args: Dial, endpoint: *const Runtime.UriEndpoint) Runtime.HandshakeClientOptions {
            var options = if (args.redirect) |redirect|
                if (redirect.cross_origin) isolateRedirectOptions(args.owner.options, redirect.forward_client_identity) else scopeAutoResumption(args.owner.options, endpoint.authority)
            else
                scopeAutoResumption(args.owner.options, endpoint.authority);
            options.connect_timeout = null;
            if (args.target != null) {
                options.handshake.server_name = endpoint.tls_host;
            } else if (options.handshake.server_name == null) options.handshake.server_name = endpoint.tls_host;
            return options;
        }

        fn freshIds(args: Dial, options: *Runtime.HandshakeClientOptions, storage: *ConnectionIds) Runtime.Error!void {
            try owned.checkpoint(args.io, args.deadline);
            options.handshake.original_destination_connection_id = &.{};
            options.handshake.local_connection_id = &.{};
            // The enclosing deadline operation owns this stack through joined
            // completion, so no second watcher is needed around the one fill.
            try storage.prepareBefore(args.io, &options.handshake, null);
        }

        fn connectRoute(args: Dial) Runtime.Error!Runtime.HandshakeClient {
            try owned.checkpoint(args.io, args.deadline);
            var endpoint = try Runtime.uriEndpoint(args.allocator, args.uri);
            defer endpoint.deinit();
            return connectPreparedRoute(args, &endpoint, optionsFor(args, &endpoint));
        }

        fn connectPreparedRoute(args: Dial, endpoint: *const Runtime.UriEndpoint, options_value: Runtime.HandshakeClientOptions) Runtime.Error!Runtime.HandshakeClient {
            var options = options_value;
            var alpn: [1][]const u8 = undefined;
            if (args.target) |target| {
                alpn[0] = target.alpn;
                options.handshake.alpn_protocols = &alpn;
            }
            var ids: ConnectionIds = .{};
            try freshIds(args, &options, &ids);
            if (args.owner.transport) |transport| {
                // Legacy transports receive the remaining relative phase;
                // the enclosing owner still enforces the original timestamp.
                try owned.checkpoint(args.io, args.deadline);
                if (args.deadline) |until| options.connect_timeout = until.durationFromNow(args.io).raw;
                return transport.connect(transport.context, args.allocator, args.io, args.local_address, if (args.target) |target| target.connect_host else endpoint.tls_host, if (args.target) |target| target.port else endpoint.port, args.limits, options);
            }
            if (args.target) |target| {
                return if (args.deadline) |until|
                    Runtime.HandshakeClient.connectUriAltSvcWithDeadline(args.allocator, args.io, args.local_address, args.uri, target, args.limits, options, until)
                else
                    Runtime.HandshakeClient.connectUriAltSvc(args.allocator, args.io, args.local_address, args.uri, target, args.limits, options);
            }
            return if (args.deadline) |until|
                Runtime.HandshakeClient.connectUriWithDeadline(args.allocator, args.io, args.local_address, args.uri, args.limits, options, until)
            else
                Runtime.HandshakeClient.connectUri(args.allocator, args.io, args.local_address, args.uri, args.limits, options);
        }

        fn connectEarlyRoute(args: Dial, early_request: *const Runtime.PreparedEarlyRequest) Runtime.Error!parent.EarlyConnected(Runtime) {
            try owned.checkpoint(args.io, args.deadline);
            var endpoint = try Runtime.uriEndpoint(args.allocator, args.uri);
            defer endpoint.deinit();
            var options = optionsFor(args, &endpoint);
            // Custom transports retain their route and require explicit typed
            // early-data support; cache misses reuse this prepared origin.
            if (args.owner.transport != null) return .{ .client = try connectPreparedRoute(args, &endpoint, options) };
            const automatic = options.handshake.auto_resumption orelse return .{ .client = try connectPreparedRoute(args, &endpoint, options) };
            const target = args.target.?;
            const alpn = [_][]const u8{target.alpn};
            options.handshake.alpn_protocols = &alpn;
            var lease = (try automatic.cache.beginEarlyData(automatic.server_id, target.alpn, automatic.now_ms)) orelse return .{ .client = try connectPreparedRoute(args, &endpoint, options) };
            defer lease.deinit();
            options.handshake.auto_resumption = null;
            options.handshake.resumption_now_ms = automatic.now_ms;
            options.handshake.resumption_server_id = automatic.server_id;
            var ids: ConnectionIds = .{};
            try freshIds(args, &options, &ids);
            const connected = if (args.deadline) |until|
                try Runtime.HandshakeClient.connectUriAltSvcWithEarlyRequestWithDeadline(args.allocator, args.io, args.local_address, args.uri, target, args.limits, options, early_request, automatic.cache, &lease, until)
            else
                try Runtime.HandshakeClient.connectUriAltSvcWithEarlyRequest(args.allocator, args.io, args.local_address, args.uri, target, args.limits, options, early_request, automatic.cache, &lease);
            return .{ .client = connected.client, .disposition = connected.disposition };
        }
    };
}

test "HTTP/3 redirect options clear origin-bound handshake inputs" {
    const Runtime = @import("../../runtime.zig");
    var session: @import("../../../quic/mod.zig").resumption.Session = undefined;
    const options: Runtime.HandshakeClientOptions = .{ .handshake = .{
        .original_destination_connection_id = "original",
        .local_connection_id = "local",
        .retry_source_connection_id = "retry",
        .server_name = "first.example",
        .address_validation_token = "token",
        .random = [_]u8{0x11} ** 32,
        .x25519_secret_key = [_]u8{0x22} ** 32,
        .resumption_session = &session,
        .resumption_server_id = "first.example",
    } };
    const isolated = isolateRedirectOptions(options, false);
    try std.testing.expectEqual(@as(usize, 0), isolated.handshake.retry_source_connection_id.len);
    try std.testing.expect(isolated.handshake.server_name == null);
    try std.testing.expectEqual(@as(usize, 0), isolated.handshake.address_validation_token.len);
    try std.testing.expect(isolated.handshake.random == null);
    try std.testing.expect(isolated.handshake.x25519_secret_key == null);
    try std.testing.expect(isolated.handshake.resumption_session == null);
    try std.testing.expect(isolated.handshake.resumption_server_id == null);
    try std.testing.expect(isolated.handshake.auto_resumption == null);
    try std.testing.expect(isolated.handshake.early_data == null);
}

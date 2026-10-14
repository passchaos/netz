//! Exclusive owning pool for authenticated HTTP/3 clients.
//!
//! Each lease owns one `HandshakeClient` and therefore remains its sole QUIC
//! receive driver. Idle clients retain QPACK/control state and their socket;
//! callers provide a connector so certificate policy, resumption, CID
//! generation, and shared-endpoint strategy remain deployment-owned.

const std = @import("std");
const http3 = @import("../mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const fifo_admission = @import("../../internal/fifo_admission.zig");
const connection_budget = @import("../../internal/connection_budget.zig");
const http_method = @import("../../internal/http_method.zig");
const uri_redirect = @import("../../http1/runtime/redirect.zig");

pub const Error = error{
    InvalidPoolOptions,
    ConnectionLimitReached,
    PoolClosed,
};

/// Security context for a connector invocation caused by an HTTP redirect.
/// Custom connectors can use this to clear origin-bound tickets, cached
/// address-validation tokens, deterministic key material, and other state
/// that must not cross an authority boundary.
pub const RedirectConnectContext = struct {
    cross_origin: bool,
    forward_client_identity: bool,
};

fn isolateRedirectOptions(
    options_value: anytype,
    forward_client_identity: bool,
) @TypeOf(options_value) {
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

pub fn DefaultConnectorContext(comptime Runtime: type) type {
    return struct {
        options: Runtime.HandshakeClientOptions,

        pub fn connector(self: *@This()) Connector(Runtime) {
            return .{
                .context = self,
                .client_identity_configured = self.options.handshake.client_identity != null,
                .connect = connect,
                .connect_alt_svc = connectAltSvc,
                .connect_alt_svc_redirect = connectAltSvcRedirect,
                .connect_redirect = connectRedirect,
            };
        }

        fn connect(
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            var original_dcid: [8]u8 = undefined;
            var local_cid: [8]u8 = undefined;
            std.Io.randomSecure(io, &original_dcid) catch
                return error.Unexpected;
            std.Io.randomSecure(io, &local_cid) catch
                return error.Unexpected;
            var options = self.options;
            options.handshake.original_destination_connection_id =
                &original_dcid;
            options.handshake.local_connection_id = &local_cid;
            return Runtime.HandshakeClient.connectUri(
                allocator,
                io,
                local_address,
                uri,
                limits,
                options,
            );
        }

        fn connectRedirect(
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
            redirect: RedirectConnectContext,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (!redirect.cross_origin) {
                return connect(
                    context,
                    allocator,
                    io,
                    local_address,
                    uri,
                    limits,
                );
            }
            var original_dcid: [8]u8 = undefined;
            var local_cid: [8]u8 = undefined;
            std.Io.randomSecure(io, &original_dcid) catch
                return error.Unexpected;
            std.Io.randomSecure(io, &local_cid) catch
                return error.Unexpected;
            var options = isolateRedirectOptions(
                self.options,
                redirect.forward_client_identity,
            );
            options.handshake.original_destination_connection_id =
                &original_dcid;
            options.handshake.local_connection_id = &local_cid;
            return Runtime.HandshakeClient.connectUri(
                allocator,
                io,
                local_address,
                uri,
                limits,
                options,
            );
        }

        fn connectAltSvc(
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            target: http3.AltSvcTarget,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            var original_dcid: [8]u8 = undefined;
            var local_cid: [8]u8 = undefined;
            std.Io.randomSecure(io, &original_dcid) catch
                return error.Unexpected;
            std.Io.randomSecure(io, &local_cid) catch
                return error.Unexpected;
            var options = self.options;
            options.handshake.original_destination_connection_id =
                &original_dcid;
            options.handshake.local_connection_id = &local_cid;
            return Runtime.HandshakeClient.connectUriAltSvc(
                allocator,
                io,
                local_address,
                uri,
                target,
                limits,
                options,
            );
        }

        fn connectAltSvcRedirect(
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            target: http3.AltSvcTarget,
            limits: Runtime.Limits,
            redirect: RedirectConnectContext,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            var original_dcid: [8]u8 = undefined;
            var local_cid: [8]u8 = undefined;
            std.Io.randomSecure(io, &original_dcid) catch
                return error.Unexpected;
            std.Io.randomSecure(io, &local_cid) catch
                return error.Unexpected;
            var options = if (redirect.cross_origin)
                isolateRedirectOptions(
                    self.options,
                    redirect.forward_client_identity,
                )
            else
                self.options;
            options.handshake.original_destination_connection_id =
                &original_dcid;
            options.handshake.local_connection_id = &local_cid;
            return Runtime.HandshakeClient.connectUriAltSvc(
                allocator,
                io,
                local_address,
                uri,
                target,
                limits,
                options,
            );
        }
    };
}

pub fn Connector(comptime Runtime: type) type {
    return struct {
        context: *anyopaque,
        /// Must reflect whether this connector can present a client
        /// certificate. Pool redirects use it to enforce the default
        /// cross-origin identity boundary before any second-hop I/O.
        client_identity_configured: bool,
        connect: *const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient,
        /// Optional origin-preserving alternative-service dial. When absent,
        /// Alt-Svc acquisition fails rather than silently dialing the origin
        /// or changing request authority.
        connect_alt_svc: ?*const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            target: http3.AltSvcTarget,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient = null,
        /// Redirect-aware Alt-Svc hook. A connector that accepts cross-origin
        /// routes must clear every origin-bound resumption/token input before
        /// authenticating the new origin.
        connect_alt_svc_redirect: ?*const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            target: http3.AltSvcTarget,
            limits: Runtime.Limits,
            redirect: RedirectConnectContext,
        ) Runtime.Error!Runtime.HandshakeClient = null,
        /// Optional redirect-aware connection hook. When absent, the ordinary
        /// connector is called and remains responsible for scoping every
        /// origin-bound cache by the supplied target URI.
        connect_redirect: ?*const fn (
            context: *anyopaque,
            allocator: std.mem.Allocator,
            io: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
            redirect: RedirectConnectContext,
        ) Runtime.Error!Runtime.HandshakeClient = null,
    };
}

pub fn Options(comptime Runtime: type) type {
    return struct {
        local_address: std.Io.net.IpAddress,
        limits: Runtime.Limits = .{},
        idle: http3.origin_pool.Config = .{},
        /// Maximum idle, leased, and connecting clients. Zero is unbounded.
        max_connections: usize = 32,
        /// Optional move-stable budget shared with independently owned pools.
        /// The owner must keep it alive until this pool is deinitialized.
        shared_connection_budget: ?*connection_budget.Budget = null,
        connector: Connector(Runtime),
    };
}

pub fn Pool(comptime Runtime: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options(Runtime),
        mutex: std.Io.Mutex = .init,
        idle: IdlePool,
        leased: usize = 0,
        connections: usize = 0,
        capacity_waiters: fifo_admission.Queue = .{},
        closed: bool = false,

        const Self = @This();
        const Client = Runtime.HandshakeClient;
        const IdlePool = http3.origin_pool.Pool(Client);
        const ConnectRoute = union(enum) {
            origin,
            alt_svc: http3.AltSvcTarget,
        };

        pub const Lease = struct {
            pool: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
            was_reused: bool,
            active: bool = true,

            pub fn client(self: *Lease) *Client {
                std.debug.assert(self.active);
                return &self.client_value;
            }

            /// Return a quiescent client to the idle pool. Caching is
            /// best-effort: allocation failure closes the client instead of
            /// turning an already completed HTTP request into an application
            /// error, matching the HTTP/1 and HTTP/2 pool contract.
            pub fn release(self: *Lease) void {
                if (!self.active) return;
                self.active = false;
                self.pool.release(
                    self.client_value,
                    self.origin_key,
                );
                self.client_value = undefined;
                self.origin_key = undefined;
            }

            pub fn discard(self: *Lease) void {
                if (!self.active) return;
                self.active = false;
                self.pool.discard(self.client_value, self.origin_key);
                self.client_value = undefined;
                self.origin_key = undefined;
            }
        };

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            options: Options(Runtime),
        ) Error!Self {
            if (options.idle.max_idle_per_origin >
                options.idle.max_idle_total)
            {
                return error.InvalidPoolOptions;
            }
            return .{
                .allocator = allocator,
                .io = io,
                .options = options,
                .idle = IdlePool.init(allocator, options.idle, dropClient),
            };
        }

        pub fn deinit(self: *Self) void {
            // Leases retain a pool pointer; the caller must return them before
            // destroying the pool just as with HTTP/1 and HTTP/2 pools.
            std.debug.assert(self.leased == 0);
            std.debug.assert(self.capacity_waiters.count() == 0);
            self.close();
            std.debug.assert(self.connections == self.idle.idleCount());
            self.idle.deinit();
            self.* = undefined;
        }

        /// Reject new acquisitions and close every idle client. Outstanding
        /// leases remain valid but are discarded when returned.
        pub fn close(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            var removed: usize = 0;
            if (!self.closed) {
                self.closed = true;
                const idle_count = self.idle.idleCount();
                self.idle.deinit();
                self.idle = IdlePool.init(
                    self.allocator,
                    self.options.idle,
                    dropClient,
                );
                std.debug.assert(self.connections >= idle_count);
                self.connections -= idle_count;
                removed = idle_count;
            }
            self.capacity_waiters.notifyAll(self.io);
            self.mutex.unlock(self.io);
            self.releaseShared(removed);
        }

        pub fn acquireUri(
            self: *Self,
            uri_text: []const u8,
        ) (Runtime.Error || Error)!Lease {
            return self.acquireUriForWaiter(
                uri_text,
                null,
                null,
                .origin,
                null,
            );
        }

        pub fn acquireUriAltSvc(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
        ) (Runtime.Error || Error)!Lease {
            return self.acquireUriForWaiter(
                uri_text,
                null,
                null,
                .{ .alt_svc = target },
                null,
            );
        }

        fn acquireUriForWaiter(
            self: *Self,
            uri_text: []const u8,
            waiter: ?*fifo_admission.Queue.Waiter,
            redirect: ?RedirectConnectContext,
            route: ConnectRoute,
            shared_reclaimer: ?connection_budget.Reclaimer,
        ) (Runtime.Error || Error)!Lease {
            var blocked_on_shared = false;
            return self.acquireUriForWaiterBefore(
                uri_text,
                waiter,
                null,
                &blocked_on_shared,
                null,
                redirect,
                route,
                shared_reclaimer,
            ) catch |err| switch (err) {
                error.Timeout => unreachable,
                else => |other| return other,
            };
        }

        fn acquireUriForWaiterBefore(
            self: *Self,
            uri_text: []const u8,
            waiter: ?*fifo_admission.Queue.Waiter,
            shared_waiter: ?*connection_budget.Waiter,
            blocked_on_shared: *bool,
            deadline: ?std.Io.Clock.Timestamp,
            redirect: ?RedirectConnectContext,
            route: ConnectRoute,
            shared_reclaimer: ?connection_budget.Reclaimer,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            blocked_on_shared.* = false;
            const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(self.allocator, uri);
            defer endpoint.deinit();
            try validateConnectRoute(endpoint, route);
            const origin = try http3.requestOrigin(
                uri.scheme,
                endpoint.authority,
            );
            const origin_key = try http3.originKeyFromOrigin(
                self.allocator,
                origin,
            );

            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                if (waiter) |queued| _ = self.capacity_waiters.remove(queued);
                self.cancelSharedWaiter(shared_waiter);
                self.mutex.unlock(self.io);
                var key = origin_key;
                key.deinit();
                return error.PoolClosed;
            }
            if (!self.capacity_waiters.mayAttempt(waiter)) {
                self.cancelSharedWaiter(shared_waiter);
                if (waiter) |queued| {
                    if (!queued.linked) {
                        self.capacity_waiters.enqueue(queued);
                    } else if (queued.isNotified()) {
                        queued.rearm();
                    }
                }
                self.mutex.unlock(self.io);
                var key = origin_key;
                key.deinit();
                return error.ConnectionLimitReached;
            }
            _ = self.pruneExpiredLocked();
            const reused = self.idle.acquire(origin, nowMillis(self.io));
            if (reused != null) {
                self.cancelSharedWaiter(shared_waiter);
                self.leased += 1;
            } else if (self.options.max_connections != 0 and
                self.connections >= self.options.max_connections)
            {
                // Only idle clients are eligible for replacement. Checked-out
                // leases and connection attempts retain their reservation.
                const displaced = self.idle.takeOldest() orelse {
                    self.cancelSharedWaiter(shared_waiter);
                    if (waiter) |queued| {
                        if (!queued.linked) {
                            self.capacity_waiters.enqueue(queued);
                        } else {
                            queued.rearm();
                        }
                    }
                    self.mutex.unlock(self.io);
                    var key = origin_key;
                    key.deinit();
                    return error.ConnectionLimitReached;
                };
                self.cancelSharedWaiter(shared_waiter);
                // `connections` is intentionally unchanged: the evicted idle
                // client's slot becomes this in-progress reservation.
                self.finishAdmissionLocked(waiter);
                self.mutex.unlock(self.io);
                var old = displaced;
                old.deinit();
                return self.connectReservedBefore(
                    uri,
                    origin_key,
                    deadline,
                    redirect,
                    route,
                );
            } else {
                self.reserveShared(shared_waiter, null) catch |err| {
                    if (err == error.ConnectionLimitReached) {
                        if (self.idle.takeOldest()) |displaced| {
                            self.cancelSharedWaiter(shared_waiter);
                            self.finishAdmissionLocked(waiter);
                            self.mutex.unlock(self.io);
                            var old = displaced;
                            old.deinit();
                            return self.connectReservedBefore(
                                uri,
                                origin_key,
                                deadline,
                                redirect,
                                route,
                            );
                        }
                        self.reserveShared(
                            shared_waiter,
                            shared_reclaimer,
                        ) catch |retry_err| {
                            blocked_on_shared.* = retry_err ==
                                error.ConnectionLimitReached;
                            self.mutex.unlock(self.io);
                            var key = origin_key;
                            key.deinit();
                            return retry_err;
                        };
                        self.connections += 1;
                        self.finishAdmissionLocked(waiter);
                        self.mutex.unlock(self.io);
                        return self.connectReservedBefore(
                            uri,
                            origin_key,
                            deadline,
                            redirect,
                            route,
                        );
                    }
                    self.mutex.unlock(self.io);
                    var key = origin_key;
                    key.deinit();
                    return err;
                };
                self.connections += 1;
            }
            self.finishAdmissionLocked(waiter);
            self.mutex.unlock(self.io);
            if (reused) |client| {
                const lease: Lease = .{
                    .pool = self,
                    .client_value = client,
                    .origin_key = origin_key,
                    .was_reused = true,
                };
                return lease;
            }

            return self.connectReservedBefore(
                uri,
                origin_key,
                deadline,
                redirect,
                route,
            );
        }

        pub fn acquireUriWithTimeout(
            self: *Self,
            uri_text: []const u8,
            timeout: std.Io.Duration,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.acquireUriWithDeadline(
                uri_text,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn acquireUriWithDeadline(
            self: *Self,
            uri_text: []const u8,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            return self.acquireUriRouteWithDeadline(
                uri_text,
                .origin,
                deadline,
            );
        }

        pub fn acquireUriAltSvcWithTimeout(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            timeout: std.Io.Duration,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.acquireUriAltSvcWithDeadline(
                uri_text,
                target,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn acquireUriAltSvcWithDeadline(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            return self.acquireUriRouteWithDeadline(
                uri_text,
                .{ .alt_svc = target },
                deadline,
            );
        }

        fn acquireUriRouteWithDeadline(
            self: *Self,
            uri_text: []const u8,
            route: ConnectRoute,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            const absolute = try deadline_policy.usableAwake(
                self.io,
                deadline,
            );
            var waiter: fifo_admission.Queue.Waiter = .{};
            var shared_waiter: connection_budget.Waiter = .{};
            defer self.cancelCapacityWaiter(&waiter);
            defer self.cancelSharedWaiter(&shared_waiter);
            while (true) {
                var blocked_on_shared = false;
                return self.acquireUriForWaiterBefore(
                    uri_text,
                    &waiter,
                    &shared_waiter,
                    &blocked_on_shared,
                    absolute,
                    null,
                    route,
                    null,
                ) catch |err| switch (err) {
                    error.ConnectionLimitReached => {
                        const blocked_waiter = if (blocked_on_shared)
                            &shared_waiter
                        else
                            &waiter;
                        blocked_waiter.waitUntil(self.io, absolute) catch |wait_err| switch (wait_err) {
                            error.Timeout => return error.Timeout,
                            error.Canceled => return error.Canceled,
                        };
                        if (absolute.durationFromNow(self.io).raw.nanoseconds <= 0) {
                            return error.Timeout;
                        }
                        continue;
                    },
                    else => |other| return other,
                };
            }
        }

        fn connectReservedBefore(
            self: *Self,
            uri: std.Uri,
            origin_key_value: http3.OriginKey,
            deadline: ?std.Io.Clock.Timestamp,
            redirect: ?RedirectConnectContext,
            route: ConnectRoute,
        ) (Runtime.Error || Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Lease {
            var origin_key = origin_key_value;
            errdefer origin_key.deinit();
            var reservation_active = true;
            errdefer if (reservation_active) self.releaseReservation();
            var client = if (deadline) |absolute|
                try self.connectClientBefore(
                    uri,
                    absolute,
                    redirect,
                    route,
                )
            else
                try self.callConnector(uri, redirect, route);
            errdefer client.deinit();
            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.connections -= 1;
                self.mutex.unlock(self.io);
                self.releaseShared(1);
                reservation_active = false;
                client.deinit();
                return error.PoolClosed;
            }
            self.leased += 1;
            self.mutex.unlock(self.io);
            reservation_active = false;
            const lease: Lease = .{
                .pool = self,
                .client_value = client,
                .origin_key = origin_key,
                .was_reused = false,
            };
            origin_key = undefined;
            return lease;
        }

        /// Bound arbitrary connector implementations without extending the
        /// public connector ABI. The select drain destroys a connection that
        /// wins concurrently with timeout, so a late success cannot leak its
        /// endpoint or consume an untracked pool slot.
        fn connectClientBefore(
            self: *Self,
            uri: std.Uri,
            deadline: std.Io.Clock.Timestamp,
            redirect: ?RedirectConnectContext,
            route: ConnectRoute,
        ) (Runtime.Error || std.Io.Timeout.Error ||
            std.Io.Cancelable)!Client {
            const ConnectResult = Runtime.Error!Client;
            const Wake = union(enum) {
                connected: ConnectResult,
                timeout: std.Io.Cancelable!void,
            };
            var wake_buffer: [2]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(self.io, &wake_buffer);
            defer while (select.cancel()) |wake| switch (wake) {
                .connected => |result| if (result) |client_value| {
                    var client = client_value;
                    client.deinit();
                } else |_| {},
                .timeout => {},
            };
            select.async(
                .connected,
                callConnector,
                .{ self, uri, redirect, route },
            );
            select.async(.timeout, waitUntil, .{ self.io, deadline });
            return switch (select.await() catch |err| switch (err) {
                error.Canceled => return error.Canceled,
            }) {
                .connected => |result| result,
                .timeout => |result| {
                    result catch |err| switch (err) {
                        error.Canceled => return error.Canceled,
                    };
                    return error.Timeout;
                },
            };
        }

        fn callConnector(
            self: *Self,
            uri: std.Uri,
            redirect: ?RedirectConnectContext,
            route: ConnectRoute,
        ) Runtime.Error!Client {
            switch (route) {
                .alt_svc => |target| {
                    if (redirect) |context| {
                        if (context.cross_origin) {
                            const connect_redirect = self.options.connector
                                .connect_alt_svc_redirect orelse
                                return error.InvalidHeader;
                            return connect_redirect(
                                self.options.connector.context,
                                self.allocator,
                                self.io,
                                self.options.local_address,
                                uri,
                                target,
                                self.options.limits,
                                context,
                            );
                        }
                    }
                    const connect_alt_svc = self.options.connector.connect_alt_svc orelse
                        return error.InvalidHeader;
                    return connect_alt_svc(
                        self.options.connector.context,
                        self.allocator,
                        self.io,
                        self.options.local_address,
                        uri,
                        target,
                        self.options.limits,
                    );
                },
                .origin => {},
            }
            if (redirect) |context| {
                if (self.options.connector.connect_redirect) |connect_redirect| {
                    return connect_redirect(
                        self.options.connector.context,
                        self.allocator,
                        self.io,
                        self.options.local_address,
                        uri,
                        self.options.limits,
                        context,
                    );
                }
            }
            return self.options.connector.connect(
                self.options.connector.context,
                self.allocator,
                self.io,
                self.options.local_address,
                uri,
                self.options.limits,
            );
        }

        fn waitUntil(
            io: std.Io,
            deadline: std.Io.Clock.Timestamp,
        ) std.Io.Cancelable!void {
            try deadline.wait(io);
        }

        fn validateConnectRoute(
            endpoint: anytype,
            route: ConnectRoute,
        ) Runtime.Error!void {
            switch (route) {
                .origin => {},
                .alt_svc => |target| {
                    if (!http3.isHttp3Alpn(target.alpn) or
                        target.connect_host.len == 0 or target.port == 0 or
                        !std.ascii.eqlIgnoreCase(
                            target.origin_host,
                            endpoint.tls_host,
                        ))
                    {
                        return error.InvalidHeader;
                    }
                },
            }
        }

        pub fn requestUri(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
        ) (Runtime.Error || Error)!Runtime.OwnedHandshakeResponse {
            return self.requestUriBefore(
                uri_text,
                request_options,
                null,
                null,
                .origin,
                null,
            ) catch |err| switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
        }

        /// Carry one deadline through FIFO admission, connector execution,
        /// stale-idempotent retry, and the complete HTTP/3 response.
        pub fn requestUriWithTimeout(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            timeout: std.Io.Duration,
        ) (Runtime.ReceiveTimeoutError || Error ||
            std.Io.ConcurrentError)!Runtime.OwnedHandshakeResponse {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.requestUriWithDeadline(
                uri_text,
                request_options,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn requestUriWithDeadline(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.ReceiveTimeoutError || Error ||
            std.Io.ConcurrentError)!Runtime.OwnedHandshakeResponse {
            const absolute = try deadline_policy.usableAwake(
                self.io,
                deadline,
            );
            return self.requestUriBefore(
                uri_text,
                request_options,
                absolute,
                null,
                .origin,
                null,
            );
        }

        pub fn requestUriAltSvc(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            request_options: Runtime.UriRequestOptions,
        ) (Runtime.Error || Error)!Runtime.OwnedHandshakeResponse {
            return self.requestUriBefore(
                uri_text,
                request_options,
                null,
                null,
                .{ .alt_svc = target },
                null,
            ) catch |err| switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
        }

        pub fn requestUriAltSvcForRedirect(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            request_options: Runtime.UriRequestOptions,
            redirect: RedirectConnectContext,
        ) (Runtime.Error || Error)!Runtime.OwnedHandshakeResponse {
            return self.requestUriBefore(
                uri_text,
                request_options,
                null,
                redirect,
                .{ .alt_svc = target },
                null,
            ) catch |err| switch (err) {
                error.Timeout, error.ConcurrencyUnavailable => unreachable,
                else => |other| return @errorCast(other),
            };
        }

        pub fn requestUriAltSvcWithTimeout(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            request_options: Runtime.UriRequestOptions,
            timeout: std.Io.Duration,
        ) (Runtime.ReceiveTimeoutError || Error ||
            std.Io.ConcurrentError)!Runtime.OwnedHandshakeResponse {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.requestUriAltSvcWithDeadline(
                uri_text,
                target,
                request_options,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn requestUriAltSvcWithDeadline(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            request_options: Runtime.UriRequestOptions,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.ReceiveTimeoutError || Error ||
            std.Io.ConcurrentError)!Runtime.OwnedHandshakeResponse {
            const absolute = try deadline_policy.usableAwake(
                self.io,
                deadline,
            );
            return self.requestUriBefore(
                uri_text,
                request_options,
                absolute,
                null,
                .{ .alt_svc = target },
                null,
            );
        }

        pub fn requestUriAltSvcForRedirectWithDeadline(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            request_options: Runtime.UriRequestOptions,
            redirect: RedirectConnectContext,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.ReceiveTimeoutError || Error ||
            std.Io.ConcurrentError)!Runtime.OwnedHandshakeResponse {
            const absolute = try deadline_policy.usableAwake(
                self.io,
                deadline,
            );
            return self.requestUriBefore(
                uri_text,
                request_options,
                absolute,
                redirect,
                .{ .alt_svc = target },
                null,
            );
        }

        /// Unified-pool hook: when the shared budget is full, reclaim one idle
        /// connection from another transport before entering the FIFO wait.
        pub fn requestUriAltSvcReclaiming(
            self: *Self,
            uri_text: []const u8,
            target: http3.AltSvcTarget,
            request_options: Runtime.UriRequestOptions,
            redirect: ?RedirectConnectContext,
            deadline: ?std.Io.Clock.Timestamp,
            reclaimer: connection_budget.Reclaimer,
        ) (Runtime.ReceiveTimeoutError || Error ||
            std.Io.ConcurrentError)!Runtime.OwnedHandshakeResponse {
            const absolute = if (deadline) |value|
                try deadline_policy.usableAwake(self.io, value)
            else
                null;
            return self.requestUriBefore(
                uri_text,
                request_options,
                absolute,
                redirect,
                .{ .alt_svc = target },
                reclaimer,
            );
        }

        fn requestUriBefore(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            deadline: ?std.Io.Clock.Timestamp,
            redirect: ?RedirectConnectContext,
            route: ConnectRoute,
            shared_reclaimer: ?connection_budget.Reclaimer,
        ) (Runtime.ReceiveTimeoutError || Error)!Runtime.OwnedHandshakeResponse {
            const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(self.allocator, uri);
            defer endpoint.deinit();
            const path = try Runtime.uriRequestTargetAlloc(self.allocator, uri);
            defer self.allocator.free(path);
            var waiter: fifo_admission.Queue.Waiter = .{};
            var shared_waiter: connection_budget.Waiter = .{};
            defer self.cancelCapacityWaiter(&waiter);
            defer self.cancelSharedWaiter(&shared_waiter);

            var retry_stale = true;
            while (true) {
                var lease = if (deadline) |absolute| acquire: {
                    while (true) {
                        var blocked_on_shared = false;
                        break :acquire self.acquireUriForWaiterBefore(
                            uri_text,
                            &waiter,
                            &shared_waiter,
                            &blocked_on_shared,
                            absolute,
                            redirect,
                            route,
                            shared_reclaimer,
                        ) catch |err| switch (err) {
                            error.ConnectionLimitReached => {
                                const blocked_waiter = if (blocked_on_shared)
                                    &shared_waiter
                                else
                                    &waiter;
                                blocked_waiter.waitUntil(
                                    self.io,
                                    absolute,
                                ) catch |wait_err| switch (wait_err) {
                                    error.Timeout => return error.Timeout,
                                    error.Canceled => return error.Canceled,
                                };
                                if (absolute.durationFromNow(
                                    self.io,
                                ).raw.nanoseconds <= 0) return error.Timeout;
                                continue;
                            },
                            else => |other| return other,
                        };
                    }
                } else try self.acquireUriForWaiter(
                    uri_text,
                    null,
                    redirect,
                    route,
                    shared_reclaimer,
                );
                defer if (lease.active) lease.discard();
                const request: http3.Request = .{
                    .method = request_options.method,
                    .path = path,
                    .scheme = "https",
                    .authority = endpoint.authority,
                    .headers = request_options.headers,
                    .body = request_options.body,
                    .trailers = request_options.trailers,
                };
                if (deadline == null) {
                    var response = lease.client().request(request) catch |err| {
                        const reused = lease.was_reused;
                        lease.discard();
                        if (retry_stale and reused and
                            http_method.isIdempotent(request_options.method) and
                            retryableStaleConnectionError(err))
                        {
                            retry_stale = false;
                            continue;
                        }
                        return err;
                    };
                    errdefer response.deinit(self.allocator);
                    lease.release();
                    return response;
                }
                const stream_id = lease.client().sendRequest(request) catch |err| {
                    const reused = lease.was_reused;
                    lease.discard();
                    if (retry_stale and reused and
                        http_method.isIdempotent(request_options.method) and
                        retryableStaleConnectionError(err))
                    {
                        retry_stale = false;
                        continue;
                    }
                    return err;
                };
                var response = lease.client().receiveResponseWithDeadline(
                    stream_id,
                    deadline.?,
                ) catch |err| {
                    const reused = lease.was_reused;
                    lease.discard();
                    if (retry_stale and reused and
                        http_method.isIdempotent(request_options.method) and
                        retryableStaleConnectionError(err))
                    {
                        retry_stale = false;
                        continue;
                    }
                    return err;
                };
                errdefer response.deinit(self.allocator);
                lease.release();
                return response;
            }
        }

        pub fn requestUriFollowingRedirects(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
        ) (Runtime.RedirectError || Error)!Runtime.OwnedHandshakeResponse {
            var result = try self.requestUriFollowingRedirectsDetailedBefore(
                uri_text,
                request_options,
                redirect_options,
                null,
            );
            return result.takeResponse();
        }

        pub fn requestUriFollowingRedirectsDetailed(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
        ) (Runtime.RedirectError || Error)!Runtime.RedirectedHandshakeResponse {
            return self.requestUriFollowingRedirectsDetailedBefore(
                uri_text,
                request_options,
                redirect_options,
                null,
            );
        }

        pub fn requestUriFollowingRedirectsWithDeadline(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.RedirectTimeoutError || Error)!Runtime.OwnedHandshakeResponse {
            var result = try self.requestUriFollowingRedirectsDetailedBefore(
                uri_text,
                request_options,
                redirect_options,
                try deadline_policy.usableAwake(self.io, deadline),
            );
            return result.takeResponse();
        }

        pub fn requestUriFollowingRedirectsDetailedWithDeadline(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            deadline: std.Io.Clock.Timestamp,
        ) (Runtime.RedirectTimeoutError || Error)!Runtime.RedirectedHandshakeResponse {
            return self.requestUriFollowingRedirectsDetailedBefore(
                uri_text,
                request_options,
                redirect_options,
                try deadline_policy.usableAwake(self.io, deadline),
            );
        }

        pub fn requestUriFollowingRedirectsWithTimeout(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            timeout: std.Io.Duration,
        ) (Runtime.RedirectTimeoutError || Error)!Runtime.OwnedHandshakeResponse {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.requestUriFollowingRedirectsWithDeadline(
                uri_text,
                request_options,
                redirect_options,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn requestUriFollowingRedirectsDetailedWithTimeout(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            timeout: std.Io.Duration,
        ) (Runtime.RedirectTimeoutError || Error)!Runtime.RedirectedHandshakeResponse {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.requestUriFollowingRedirectsDetailedWithDeadline(
                uri_text,
                request_options,
                redirect_options,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        fn requestUriFollowingRedirectsDetailedBefore(
            self: *Self,
            uri_text: []const u8,
            request_options: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            deadline: ?std.Io.Clock.Timestamp,
        ) (Runtime.RedirectTimeoutError || Error)!Runtime.RedirectedHandshakeResponse {
            const policy = redirect_options.policy;
            var chain = uri_redirect.Chain.init(self.allocator, policy);
            defer chain.deinit();
            try chain.recordInitial(uri_text);
            var current_uri = try self.allocator.dupe(u8, uri_text);
            defer self.allocator.free(current_uri);
            var hop_request = request_options;
            var owned_headers: ?[]http3.Qpack.HeaderField = null;
            defer if (owned_headers) |headers| self.allocator.free(headers);
            var crossed_origin = false;

            while (true) {
                const connector_redirect: ?RedirectConnectContext =
                    if (crossed_origin) .{
                        .cross_origin = true,
                        .forward_client_identity = policy.allow_cross_origin_client_identity,
                    } else null;
                var response = try self.requestUriBefore(
                    current_uri,
                    hop_request,
                    deadline,
                    connector_redirect,
                    .origin,
                    null,
                );
                errdefer response.deinit(self.allocator);
                if (!uri_redirect.isRedirectStatus(response.response.status)) {
                    return .{
                        .allocator = self.allocator,
                        .response = response,
                        .final_uri = try uri_redirect.canonicalize(
                            self.allocator,
                            current_uri,
                        ),
                        .redirect_count = chain.redirects,
                    };
                }
                const location = try redirectLocation(
                    response.response.headers,
                );
                if (location == null) {
                    return .{
                        .allocator = self.allocator,
                        .response = response,
                        .final_uri = try uri_redirect.canonicalize(
                            self.allocator,
                            current_uri,
                        ),
                        .redirect_count = chain.redirects,
                    };
                }
                var next = try chain.follow(
                    current_uri,
                    location.?,
                    response.response.status,
                );
                var next_owned = true;
                defer if (next_owned) next.deinit();
                const next_uri = std.Uri.parse(next.uri) catch
                    return error.InvalidUri;
                if (!std.ascii.eqlIgnoreCase(next_uri.scheme, "https")) {
                    return error.InsecureRedirect;
                }
                if (next.cross_origin) {
                    try uri_redirect.enforceClientIdentityPolicy(
                        policy,
                        true,
                        self.options.connector.client_identity_configured,
                    );
                    crossed_origin = true;
                }
                const action = uri_redirect.methodActionBytes(
                    policy,
                    response.response.status,
                    hop_request.method,
                );
                const remove_credentials = next.cross_origin and
                    !policy.forward_cross_origin_credentials;
                hop_request.headers = try redirectHeaders(
                    self.allocator,
                    hop_request.headers,
                    remove_credentials,
                    action == .rewrite_get,
                    &owned_headers,
                );
                if (action == .rewrite_get) {
                    hop_request.method = "GET";
                    hop_request.body = &.{};
                    hop_request.trailers = &.{};
                } else if (remove_credentials) {
                    hop_request.trailers = &.{};
                }

                response.deinit(self.allocator);
                self.allocator.free(current_uri);
                current_uri = next.uri;
                next_owned = false;
            }
        }

        pub fn idleCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            _ = self.pruneExpiredLocked();
            return self.idle.idleCount();
        }

        pub fn stats(self: *Self) http3.origin_pool.Stats {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.idle.stats();
        }

        pub fn leasedCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.leased;
        }

        pub fn connectionCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.connections;
        }

        pub fn waitingCount(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.capacity_waiters.count();
        }

        pub fn pruneExpired(self: *Self) usize {
            self.mutex.lockUncancelable(self.io);
            defer self.mutex.unlock(self.io);
            return self.pruneExpiredLocked();
        }

        /// Retire the oldest idle client so another transport can reuse one
        /// shared-budget token. Active leases and connection attempts are never
        /// eligible.
        pub fn evictOldestIdle(self: *Self) bool {
            self.mutex.lockUncancelable(self.io);
            if (self.closed) {
                self.mutex.unlock(self.io);
                return false;
            }
            const client_value = self.idle.takeOldest() orelse {
                self.mutex.unlock(self.io);
                return false;
            };
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            self.mutex.unlock(self.io);

            var client = client_value;
            client.deinit();
            self.releaseShared(1);
            return true;
        }

        fn release(
            self: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
        ) void {
            var client = client_value;
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.leased != 0);
            self.leased -= 1;
            if (self.closed or !client.isReusable()) {
                self.connections -= 1;
                self.mutex.unlock(self.io);
                var key = origin_key;
                key.deinit();
                client.deinit();
                self.releaseShared(1);
                self.notifyCapacityWaiter();
                return;
            }
            const idle_before = self.idle.idleCount();
            self.idle.releaseKey(
                client,
                origin_key,
                nowMillis(self.io),
            ) catch {
                self.connections -= 1;
                self.mutex.unlock(self.io);
                client.deinit();
                self.releaseShared(1);
                self.notifyCapacityWaiter();
                return;
            };
            const idle_after = self.idle.idleCount();
            // The released lease already occupies one counted slot. A normal
            // append raises idle count by one. Anything less means the generic
            // idle pool dropped this client, an older client, or both under a
            // per-origin/global idle limit; mirror those closes in the owning
            // pool's total count.
            const expected_idle = idle_before +| 1;
            const dropped = expected_idle -| idle_after;
            std.debug.assert(self.connections >= dropped);
            self.connections -= dropped;
            self.notifyCapacityWaiterLocked();
            self.mutex.unlock(self.io);
            if (dropped != 0) {
                self.releaseShared(dropped);
            } else {
                self.notifyShared();
            }
        }

        fn discard(
            self: *Self,
            client_value: Client,
            origin_key: http3.OriginKey,
        ) void {
            var client = client_value;
            var key = origin_key;
            key.deinit();
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.leased != 0);
            self.leased -= 1;
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.mutex.unlock(self.io);
            client.deinit();
            self.releaseShared(1);
            // Do not let the next waiter establish a replacement before the
            // old QUIC endpoint has actually released its socket/resources.
            self.notifyCapacityWaiter();
        }

        fn dropClient(_: std.mem.Allocator, client_value: Client) void {
            var client = client_value;
            client.deinit();
        }

        fn releaseReservation(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            std.debug.assert(self.connections != 0);
            self.connections -= 1;
            self.notifyCapacityWaiterLocked();
            self.mutex.unlock(self.io);
            self.releaseShared(1);
        }

        fn pruneExpiredLocked(self: *Self) usize {
            const removed = self.idle.pruneExpired(nowMillis(self.io));
            std.debug.assert(self.connections >= removed);
            self.connections -= removed;
            if (removed != 0) self.notifyCapacityWaiterLocked();
            self.releaseShared(removed);
            return removed;
        }

        fn reserveShared(
            self: *Self,
            waiter: ?*connection_budget.Waiter,
            reclaimer: ?connection_budget.Reclaimer,
        ) connection_budget.Error!void {
            const budget = self.options.shared_connection_budget orelse return;
            if (reclaimer) |idle| {
                try budget.tryReserveReclaiming(waiter, idle);
            } else {
                try budget.tryReserve(waiter);
            }
        }

        fn cancelSharedWaiter(
            self: *Self,
            waiter: ?*connection_budget.Waiter,
        ) void {
            const queued = waiter orelse return;
            const budget = self.options.shared_connection_budget orelse return;
            budget.cancel(queued);
        }

        fn releaseShared(self: *Self, count: usize) void {
            const budget = self.options.shared_connection_budget orelse return;
            budget.release(count);
        }

        fn notifyShared(self: *Self) void {
            const budget = self.options.shared_connection_budget orelse return;
            budget.notify();
        }

        fn finishAdmissionLocked(
            self: *Self,
            waiter: ?*fifo_admission.Queue.Waiter,
        ) void {
            if (waiter) |queued| {
                if (queued.linked) {
                    std.debug.assert(self.capacity_waiters.remove(queued));
                }
            }
            if (self.hasCapacityLocked()) self.notifyCapacityWaiterLocked();
        }

        fn cancelCapacityWaiter(
            self: *Self,
            waiter: *fifo_admission.Queue.Waiter,
        ) void {
            self.mutex.lockUncancelable(self.io);
            self.capacity_waiters.cancel(waiter, self.io);
            self.mutex.unlock(self.io);
        }

        fn hasCapacityLocked(self: *const Self) bool {
            return self.closed or self.idle.idleCount() != 0 or
                self.options.max_connections == 0 or
                self.connections < self.options.max_connections;
        }

        fn notifyCapacityWaiterLocked(self: *Self) void {
            self.capacity_waiters.notifyHead(self.io);
        }

        fn notifyCapacityWaiter(self: *Self) void {
            self.mutex.lockUncancelable(self.io);
            self.notifyCapacityWaiterLocked();
            self.mutex.unlock(self.io);
        }

        test "HTTP/3 handshake client pool validates idle limits" {
            var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
            defer threaded.deinit();
            var context: u8 = 0;
            const connector: Connector(Runtime) = .{
                .context = &context,
                .client_identity_configured = false,
                .connect = struct {
                    fn connect(
                        _: *anyopaque,
                        _: std.mem.Allocator,
                        _: std.Io,
                        _: std.Io.net.IpAddress,
                        _: std.Uri,
                        _: Runtime.Limits,
                    ) Runtime.Error!Runtime.HandshakeClient {
                        return error.InvalidUri;
                    }
                }.connect,
            };
            try std.testing.expectError(
                error.InvalidPoolOptions,
                Self.init(std.testing.allocator, threaded.io(), .{
                    .local_address = .{ .ip4 = .loopback(0) },
                    .idle = .{
                        .max_idle_per_origin = 2,
                        .max_idle_total = 1,
                    },
                    .connector = connector,
                }),
            );
        }
    };
}

test "HTTP/3 handshake client pool reuses one authenticated connection" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Runtime.HandshakeServer,
        requests: usize = 0,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            for (0..2) |index| {
                var request = session.receiveRequest() catch |err| {
                    self.err = err;
                    return;
                };
                defer request.deinit(self.server.allocator);
                const expected = if (index == 0) "/one" else "/two?x=1";
                if (!std.mem.eql(u8, request.request.path, expected)) {
                    self.err = error.InvalidUri;
                    return;
                }
                const expected_method = if (index == 0) "GET" else "QUERY";
                if (!std.mem.eql(
                    u8,
                    request.request.method,
                    expected_method,
                )) {
                    self.err = error.InvalidMethod;
                    return;
                }
                session.sendResponse(request.stream_id, .{
                    .status = 200,
                    .body = if (index == 0) "one" else "two",
                }) catch |err| {
                    self.err = err;
                    return;
                };
                self.requests += 1;
            }
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    const CountingConnector = struct {
        inner: DefaultConnectorContext(Runtime),
        connects: usize = 0,

        fn connect(
            context: *anyopaque,
            allocator_value: std.mem.Allocator,
            io_value: std.Io,
            local_address: std.Io.net.IpAddress,
            uri: std.Uri,
            limits: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.connects += 1;
            return self.inner.connector().connect(
                &self.inner,
                allocator_value,
                io_value,
                local_address,
                uri,
                limits,
            );
        }
    };
    var connect_context = CountingConnector{ .inner = .{ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = .{
            .context = &connect_context,
            .client_identity_configured = false,
            .connect = CountingConnector.connect,
        },
    });
    defer pool.deinit();
    const first_uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/one",
        .{server.address().ip4.port},
    );
    defer allocator.free(first_uri);
    const second_uri = try std.fmt.allocPrint(
        allocator,
        "https://LOCALHOST:{d}/two?x=1",
        .{server.address().ip4.port},
    );
    defer allocator.free(second_uri);

    var first = try pool.requestUri(first_uri, .{});
    defer first.deinit(allocator);
    var second = try pool.requestUri(second_uri, .{ .method = "QUERY" });
    defer second.deinit(allocator);
    try std.testing.expectEqualStrings("one", first.response.body);
    try std.testing.expectEqualStrings("two", second.response.body);
    try std.testing.expectEqual(@as(usize, 1), connect_context.connects);
    try std.testing.expectEqual(@as(usize, 1), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectEqual(@as(u64, 1), pool.stats().total_reused);

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 2), shared.requests);
}

test "HTTP/3 handshake client pool enforces checked-out capacity" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Runtime.HandshakeServer,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.quic_server.endpoint.io);
                return;
            };
            defer session.deinit();
            self.accepted.set(self.server.quic_server.endpoint.io);
            self.release.wait(self.server.quic_server.endpoint.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };

    var connector_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connector_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/held",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var first = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    if (shared.err) |err| return err;
    try std.testing.expectEqual(@as(usize, 1), pool.connectionCount());
    try std.testing.expectError(
        error.ConnectionLimitReached,
        pool.acquireUri(uri),
    );
    first.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client pool timeout and close wake waiters" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Runtime.HandshakeServer,
        accepted: std.Io.Event = .unset,
        release: std.Io.Event = .unset,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                self.accepted.set(self.server.quic_server.endpoint.io);
                return;
            };
            defer session.deinit();
            self.accepted.set(self.server.quic_server.endpoint.io);
            self.release.wait(self.server.quic_server.endpoint.io) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) {
        shared.release.set(io);
        server_thread.join();
    };

    var connector_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connector_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/wait",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var lease = try pool.acquireUri(uri);
    try shared.accepted.wait(io);
    try std.testing.expectError(
        error.Timeout,
        pool.acquireUriWithTimeout(uri, .fromMilliseconds(5)),
    );
    const Waiter = struct {
        pool: *ClientPool,
        uri: []const u8,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var acquired = self.pool.acquireUriWithTimeout(
                self.uri,
                .fromSeconds(1),
            ) catch |err| {
                self.err = err;
                return;
            };
            acquired.discard();
        }
    };
    var waiter = Waiter{ .pool = &pool, .uri = uri };
    const waiter_thread = try std.Thread.spawn(.{}, Waiter.run, .{&waiter});
    try std.Io.sleep(io, .fromMilliseconds(10), .awake);
    pool.close();
    waiter_thread.join();
    try std.testing.expectEqual(error.PoolClosed, waiter.err.?);
    lease.discard();
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    shared.release.set(io);
    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client pool discards GOAWAY leases" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{
                    .key_pair = key_pair,
                } },
            },
        } },
    );
    defer server.deinit();

    const Shared = struct {
        server: *Runtime.HandshakeServer,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            session.sendResponse(request.stream_id, .{
                .status = 204,
                .request_method = request.request.method,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var connect_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connect_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/goaway",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var lease = try pool.acquireUri(uri);
    var response = try lease.client().request(.{
        .method = "GET",
        .path = "/goaway",
        .scheme = "https",
        .authority = "localhost",
    });
    defer response.deinit(allocator);
    lease.client().control.peer_goaway_id = lease.client().next_stream_id;
    lease.release();
    lease.release();
    lease.discard();
    try std.testing.expect(!lease.active);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

test "HTTP/3 handshake client pool releases failed reservations" {
    const Runtime = @import("../runtime.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const Refusing = struct {
        calls: usize = 0,
        fn connect(
            context: *anyopaque,
            _: std.mem.Allocator,
            _: std.Io,
            _: std.Io.net.IpAddress,
            _: std.Uri,
            _: Runtime.Limits,
        ) Runtime.Error!Runtime.HandshakeClient {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            return error.ConnectionRefused;
        }
    };
    var refusing = Refusing{};
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .loopback(0) },
        .max_connections = 1,
        .connector = .{
            .context = &refusing,
            .client_identity_configured = false,
            .connect = Refusing.connect,
        },
    });
    defer pool.deinit();

    inline for (0..2) |_| {
        try std.testing.expectError(
            error.ConnectionRefused,
            pool.acquireUri("https://localhost/"),
        );
        try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());
        try std.testing.expectEqual(@as(usize, 0), pool.leasedCount());
    }
    try std.testing.expectEqual(@as(usize, 2), refusing.calls);
}

test "HTTP/3 handshake client pool zero idle capacity releases totals" {
    const Runtime = @import("../runtime.zig");
    const tls_testing = @import("../../tls/testing.zig");
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [tls_testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        tls_testing.certificate_base64,
    );
    const key_pair = try tls_testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    const server_cid = [_]u8{ 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7 };
    var server = try Runtime.HandshakeServer.bind(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .{ .handshake = .{
            .local_connection_id = &server_cid,
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
        } },
    );
    defer server.deinit();
    const Shared = struct {
        server: *Runtime.HandshakeServer,
        err: ?anyerror = null,
        fn run(self: *@This()) void {
            var session = self.server.accept() catch |err| {
                self.err = err;
                return;
            };
            defer session.deinit();
            var request = session.receiveRequest() catch |err| {
                self.err = err;
                return;
            };
            defer request.deinit(self.server.allocator);
            session.sendResponse(request.stream_id, .{
                .status = 204,
                .request_method = request.request.method,
            }) catch |err| {
                self.err = err;
            };
        }
    };
    var shared = Shared{ .server = &server };
    const server_thread = try std.Thread.spawn(.{}, Shared.run, .{&shared});
    var joined = false;
    defer if (!joined) server_thread.join();

    var connector_context = DefaultConnectorContext(Runtime){ .options = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
            .server_auth = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
        },
    } };
    const ClientPool = Pool(Runtime);
    var pool = try ClientPool.init(allocator, io, .{
        .local_address = .{ .ip4 = .unspecified(0) },
        .max_connections = 1,
        .idle = .{
            .max_idle_per_origin = 0,
            .max_idle_total = 0,
        },
        .limits = .{ .quic = .{
            .max_datagram_size = 4096,
            .max_frames_per_datagram = 8,
        } },
        .connector = connector_context.connector(),
    });
    defer pool.deinit();
    const uri = try std.fmt.allocPrint(
        allocator,
        "https://localhost:{d}/no-idle",
        .{server.address().ip4.port},
    );
    defer allocator.free(uri);

    var response = try pool.requestUri(uri, .{});
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), pool.idleCount());
    try std.testing.expectEqual(@as(usize, 0), pool.connectionCount());

    server_thread.join();
    joined = true;
    if (shared.err) |err| return err;
}

fn redirectLocation(
    headers: []const http3.Qpack.HeaderField,
) uri_redirect.Error!?[]const u8 {
    var found: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "location")) continue;
        if (found != null or header.value.len == 0) {
            return error.InvalidRedirect;
        }
        found = header.value;
    }
    return found;
}

fn redirectHeaders(
    allocator: std.mem.Allocator,
    source: []const http3.Qpack.HeaderField,
    remove_credentials: bool,
    remove_body: bool,
    owned: *?[]http3.Qpack.HeaderField,
) std.mem.Allocator.Error![]const http3.Qpack.HeaderField {
    var retained_count: usize = 0;
    for (source) |header| {
        if (!dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) retained_count += 1;
    }
    if (retained_count == source.len) return source;
    if (retained_count == 0) {
        if (owned.*) |old| allocator.free(old);
        owned.* = null;
        return &.{};
    }
    const headers = try allocator.alloc(
        http3.Qpack.HeaderField,
        retained_count,
    );
    var index: usize = 0;
    for (source) |header| {
        if (dropRedirectHeader(
            header.name,
            remove_credentials,
            remove_body,
        )) continue;
        headers[index] = header;
        index += 1;
    }
    if (owned.*) |old| allocator.free(old);
    owned.* = headers;
    return headers;
}

fn dropRedirectHeader(
    name: []const u8,
    remove_credentials: bool,
    remove_body: bool,
) bool {
    if (std.ascii.eqlIgnoreCase(name, "host")) return true;
    if (remove_credentials and uri_redirect.isCrossOriginCredential(name)) {
        return true;
    }
    if (remove_credentials and std.ascii.eqlIgnoreCase(name, "trailer")) {
        return true;
    }
    return remove_body and uri_redirect.isBodyHeader(name);
}

fn nowMillis(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now <= 0) return 0;
    return @as(u64, @intCast(now)) / std.time.ns_per_ms;
}

fn retryableStaleConnectionError(err: anyerror) bool {
    return switch (err) {
        error.ConnectionClosed,
        error.ConnectionResetByPeer,
        error.GoAwayReceived,
        error.SocketUnconnected,
        error.HandshakeReceiveFailed,
        error.HandshakeSendFailed,
        => true,
        else => false,
    };
}

test "HTTP/3 redirect options clear origin-bound handshake inputs" {
    const Runtime = @import("../runtime.zig");
    var session: @import("../../quic/mod.zig").resumption.Session = undefined;
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

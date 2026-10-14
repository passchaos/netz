//! Authenticated HTTP/3 client pool with one shared UDP receive owner.
//!
//! The pool owns a primary endpoint, an optional cross-family migration
//! endpoint, and one QUIC dispatcher. Handshakes consume only CID-routed
//! inboxes, established clients remain heap-backed so dispatcher pointers stay
//! stable, and only `receive*` reads either UDP socket.

const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const owned_receive_race = @import("../../quic/owned_receive_race.zig");
const deadline_policy = @import("../../internal/deadline.zig");
const owning_pool = @import("handshake_client_pool.zig");
const shared_redirect = @import("shared_handshake_client_pool/redirect.zig");

const supported_versions = [_]u32{
    quic.Version.version_1.wireValue(),
    quic.Version.version_2.wireValue(),
};

const PendingEndpointDatagramView = struct {
    from: std.Io.net.IpAddress,
    received_on: *quic.runtime.Endpoint,
    len: usize,
    ecn: quic.packet_space.EcnCodepoint,
};

pub const Error = error{
    InvalidPoolOptions,
    ConnectionLimitReached,
    PoolClosed,
    UnknownConnectionHandle,
    InvalidLease,
};

pub fn Options(comptime Runtime: type) type {
    return struct {
        local_address: std.Io.net.IpAddress,
        /// Optional caller-selected local bind address for cross-family QUIC
        /// preferred-address migration. It must use the other address family
        /// from `local_address`; the pool remains the sole owner of both
        /// receive sockets.
        migration_local_address: ?std.Io.net.IpAddress = null,
        limits: Runtime.Limits = .{},
        client: Runtime.HandshakeClientOptions,
        idle: http3.origin_pool.Config = .{},
        /// Maximum established plus in-progress connections. Zero is
        /// unbounded. The current implementation performs one acquisition at
        /// a time on the endpoint owner.
        max_connections: usize = 32,
        handshake_inbox_capacity: usize = 32,
        /// Maximum delay before the endpoint owner checks handshake worker
        /// completion again. QUIC timers can wake it earlier.
        handshake_poll_interval: std.Io.Duration = .fromMilliseconds(5),
    };
}

pub fn Pool(comptime Runtime: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        options: Options(Runtime),
        endpoint: *quic.runtime.Endpoint,
        migration_endpoint: ?*quic.runtime.Endpoint = null,
        dispatcher: *quic.endpoint_dispatcher.Dispatcher,
        pending_multi_endpoint_datagram: ?quic.runtime.OwnedBytes = null,
        migration_receive_storage: []u8 = &.{},
        /// A second socket can complete concurrently with the selected receive
        /// result. Copy that view so no authenticated packet is lost when its
        /// endpoint buffer is reused.
        pending_multi_endpoint_storage: []u8 = &.{},
        pending_multi_endpoint_view: ?PendingEndpointDatagramView = null,
        entries: std.AutoHashMapUnmanaged(
            quic.endpoint_dispatcher.ConnectionHandle,
            *Entry,
        ) = .empty,
        next_handle: quic.endpoint_dispatcher.ConnectionHandle = 1,
        last_event_handle: ?quic.endpoint_dispatcher.ConnectionHandle = null,
        total_reused: u64 = 0,
        total_misses: u64 = 0,
        total_dropped: u64 = 0,
        release_sequence: u64 = 0,
        closed: bool = false,

        const Self = @This();
        const Client = Runtime.HandshakeClient;
        const Handle = quic.endpoint_dispatcher.ConnectionHandle;

        const Entry = struct {
            handle: Handle,
            client: *Client,
            origin_key: http3.OriginKey,
            leased: bool = true,
            registered: bool = true,
            close_pending: ?quic.one_rtt.TimerDeadline = null,
            pooled_at_ms: u64 = 0,
            release_sequence: u64 = 0,
        };

        const ConnectCompletion = union(enum) {
            client: Client,
            failure: Runtime.Error,
        };

        const Connected = struct {
            handle: Handle,
            client: *Client,
        };

        const ConnectWorker = struct {
            pool: *Self,
            source: quic.runtime.DatagramSource,
            peer: std.Io.net.IpAddress,
            uri_endpoint: *const Runtime.UriEndpoint,
            original_dcid: *const [8]u8,
            local_cid: *const [8]u8,
            deadline: ?std.Io.Clock.Timestamp,
            redirect: ?owning_pool.RedirectConnectContext,

            fn connect(self: *@This()) ConnectCompletion {
                var options = self.pool.options.client;
                if (self.redirect) |redirect| {
                    applyRedirectConnectionSecurity(&options, redirect);
                }
                options.handshake.original_destination_connection_id =
                    self.original_dcid;
                options.handshake.local_connection_id = self.local_cid;
                if (options.handshake.server_name == null) {
                    options.handshake.server_name = self.uri_endpoint.tls_host;
                }
                const result = if (self.deadline) |absolute|
                    Client.connectFromWithDeadline(
                        self.pool.endpoint,
                        self.source,
                        self.peer,
                        options,
                        absolute,
                    )
                else
                    Client.connectFrom(
                        self.pool.endpoint,
                        self.source,
                        self.peer,
                        options,
                    );
                return if (result) |value|
                    .{ .client = value }
                else |err|
                    .{ .failure = err };
            }
        };

        pub const Lease = struct {
            pool: *Self,
            handle: Handle,
            was_reused: bool,
            active: bool = true,

            pub fn connectionHandle(self: Lease) Handle {
                return self.handle;
            }

            pub fn client(self: *Lease) *Client {
                std.debug.assert(self.active);
                return self.pool.entries.get(self.handle).?.client;
            }

            /// Refresh dispatcher timers after direct client mutation.
            pub fn refresh(self: *Lease) !void {
                if (!self.active) return error.InvalidLease;
                try self.pool.refresh(self.handle);
            }

            pub fn sendRequest(
                self: *Lease,
                request: http3.Request,
            ) !u62 {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                return self.client().trySendRequest(request);
            }

            pub fn tryCancelRequest(
                self: *Lease,
                stream_id: u62,
                application_error_code: u64,
            ) !void {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                try self.client().tryCancelRequest(
                    stream_id,
                    application_error_code,
                );
            }

            pub fn trySendRequestBody(
                self: *Lease,
                stream_id: u62,
                data: []const u8,
                fin: bool,
            ) !void {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                try self.client().trySendRequestBody(stream_id, data, fin);
            }

            pub fn tryStartRequest(
                self: *Lease,
                request: http3.Request,
                body_length: ?usize,
            ) !u62 {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                return self.client().tryStartRequest(request, body_length);
            }

            pub fn tryFinishRequestTrailers(
                self: *Lease,
                stream_id: u62,
                trailers: []const http3.Qpack.HeaderField,
            ) !void {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                try self.client().tryFinishRequestTrailers(
                    stream_id,
                    trailers,
                );
            }

            pub fn trySendRequestBodyParts(
                self: *Lease,
                stream_id: u62,
                parts: []const []const u8,
                fin: bool,
            ) !void {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                try self.client().trySendRequestBodyParts(
                    stream_id,
                    parts,
                    fin,
                );
            }

            pub fn trySendRequestBodyBatch(
                self: *Lease,
                chunks: []const Runtime.BodyChunk,
            ) !Runtime.BodyBatchProgress {
                if (!self.active) return error.InvalidLease;
                defer self.pool.refresh(self.handle) catch {};
                return self.client().trySendRequestBodyBatch(chunks);
            }

            /// Start validation of the server's preferred address from the
            /// pool-owned endpoint for that address family. The first
            /// PATH_CHALLENGE is sent immediately and subsequent retransmits
            /// and failure rollback are driven by the pool receive loop.
            pub fn beginPreferredAddressMigration(
                self: *Lease,
                challenge: [8]u8,
                family: quic.one_rtt.PreferredAddressFamily,
            ) !void {
                if (!self.active) return error.InvalidLease;
                const migration_endpoint = self.pool.migration_endpoint orelse
                    return error.InvalidPoolOptions;
                const connection = &self.client().established.connection;
                try connection.beginPeerPreferredAddressMigrationFrom(
                    migration_endpoint,
                    challenge,
                    family,
                );
                const now_ns = monotonicNowNs(self.pool.io);
                connection.sendPendingPathChallengeAt(
                    now_ns,
                    connection.ptoPeriod(),
                ) catch |err| switch (err) {
                    error.AntiAmplificationLimited,
                    error.CongestionLimited,
                    error.PacingLimited,
                    => {},
                    else => |other| {
                        connection.abortPeerPreferredAddressMigration();
                        self.pool.refresh(self.handle) catch {};
                        return other;
                    },
                };
                try self.pool.refresh(self.handle);
            }

            pub fn release(self: *Lease) void {
                if (!self.active) return;
                self.active = false;
                self.pool.release(self.handle);
            }

            pub fn discard(self: *Lease) void {
                if (!self.active) return;
                self.active = false;
                self.pool.dropEntry(self.handle);
            }
        };

        pub const ResponseEvent = struct {
            connection_handle: Handle,
            response: Runtime.StreamingResponseEvent,

            pub fn deinit(
                self: *ResponseEvent,
                allocator: std.mem.Allocator,
            ) void {
                self.response.deinit(allocator);
                self.* = undefined;
            }
        };

        pub const PushEvent = struct {
            connection_handle: Handle,
            push: Runtime.StreamingPushEvent,

            pub fn deinit(
                self: *PushEvent,
                allocator: std.mem.Allocator,
            ) void {
                self.push.deinit(allocator);
                self.* = undefined;
            }
        };

        pub const Event = union(enum) {
            response: ResponseEvent,
            push: PushEvent,
            progress: Handle,
            timer: quic.endpoint_dispatcher.TimerEvent,
            closed: struct {
                connection_handle: Handle,
                timer: quic.one_rtt.TimerDeadline,
            },
            consumed,
            unrouted: quic.endpoint_dispatcher.Event,

            pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
                switch (self.*) {
                    .response => |*event| event.deinit(allocator),
                    .push => |*event| event.deinit(allocator),
                    .unrouted => |*event| event.deinit(allocator),
                    .progress, .timer, .closed, .consumed => {},
                }
                self.* = undefined;
            }
        };

        pub const RedirectOperationError =
            Runtime.RedirectTimeoutError || Error;

        const RedirectAdapter = struct {
            pub fn acquire(
                pool: *Self,
                uri_text: []const u8,
                deadline: ?std.Io.Clock.Timestamp,
                redirect: ?owning_pool.RedirectConnectContext,
            ) RedirectOperationError!Lease {
                const absolute = if (deadline) |caller_deadline|
                    try deadline_policy.capTimeout(
                        pool.io,
                        caller_deadline,
                        pool.options.client.connect_timeout,
                    )
                else
                    deadline_policy.fromTimeout(
                        pool.io,
                        pool.options.client.connect_timeout,
                    ) catch return error.HandshakeTimeout;
                return pool.acquireUriBefore(
                    uri_text,
                    absolute,
                    redirect,
                ) catch |err| return @errorCast(err);
            }
        };

        /// A redirect transaction consumes only events matching its current
        /// lease and request stream. Unrelated pool events remain caller-owned.
        pub const RedirectTransaction = shared_redirect.Transaction(
            Runtime,
            Self,
            RedirectAdapter,
            RedirectOperationError,
        );
        pub const RedirectedResponse = shared_redirect.RedirectedResponse;

        pub fn beginUriFollowingRedirects(
            self: *Self,
            uri_text: []const u8,
            request: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
        ) RedirectOperationError!RedirectTransaction {
            return RedirectTransaction.init(
                self,
                uri_text,
                request,
                redirect_options,
                null,
            );
        }

        pub fn beginUriFollowingRedirectsWithTimeout(
            self: *Self,
            uri_text: []const u8,
            request: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            timeout: std.Io.Duration,
        ) RedirectOperationError!RedirectTransaction {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.beginUriFollowingRedirectsWithDeadline(
                uri_text,
                request,
                redirect_options,
                .fromNow(self.io, .{ .raw = timeout, .clock = .awake }),
            );
        }

        pub fn beginUriFollowingRedirectsWithDeadline(
            self: *Self,
            uri_text: []const u8,
            request: Runtime.UriRequestOptions,
            redirect_options: Runtime.RedirectOptions,
            deadline: std.Io.Clock.Timestamp,
        ) RedirectOperationError!RedirectTransaction {
            return RedirectTransaction.init(
                self,
                uri_text,
                request,
                redirect_options,
                try deadline_policy.usableAwake(self.io, deadline),
            );
        }

        pub fn init(
            allocator: std.mem.Allocator,
            io: std.Io,
            options: Options(Runtime),
        ) !Self {
            if (options.idle.max_idle_per_origin >
                options.idle.max_idle_total or
                options.handshake_inbox_capacity == 0 or
                options.handshake_poll_interval.nanoseconds <= 0)
            {
                return error.InvalidPoolOptions;
            }
            const endpoint = try allocator.create(quic.runtime.Endpoint);
            errdefer allocator.destroy(endpoint);
            endpoint.* = try quic.runtime.Endpoint.bind(
                allocator,
                io,
                options.local_address,
                options.limits.quic,
            );
            errdefer endpoint.deinit();
            const migration_endpoint = if (options.migration_local_address) |migration_address| blk: {
                if (sameAddressFamily(options.local_address, migration_address)) {
                    return error.InvalidPoolOptions;
                }
                const candidate = try allocator.create(quic.runtime.Endpoint);
                errdefer allocator.destroy(candidate);
                candidate.* = try quic.runtime.Endpoint.bind(
                    allocator,
                    io,
                    migration_address,
                    options.limits.quic,
                );
                break :blk candidate;
            } else null;
            errdefer if (migration_endpoint) |candidate| {
                candidate.deinit();
                allocator.destroy(candidate);
            };
            const migration_receive_storage: []u8 = if (migration_endpoint != null)
                try allocator.alloc(u8, endpoint.limits.max_datagram_size)
            else
                @constCast(&.{});
            errdefer if (migration_receive_storage.len != 0) {
                allocator.free(migration_receive_storage);
            };
            const pending_multi_endpoint_storage: []u8 = if (migration_endpoint != null)
                try allocator.alloc(u8, endpoint.limits.max_datagram_size)
            else
                @constCast(&.{});
            errdefer if (pending_multi_endpoint_storage.len != 0) {
                allocator.free(pending_multi_endpoint_storage);
            };
            const dispatcher = try allocator.create(
                quic.endpoint_dispatcher.Dispatcher,
            );
            errdefer allocator.destroy(dispatcher);
            dispatcher.* = .init(allocator, endpoint);
            return .{
                .allocator = allocator,
                .io = io,
                .options = options,
                .endpoint = endpoint,
                .migration_endpoint = migration_endpoint,
                .dispatcher = dispatcher,
                .migration_receive_storage = migration_receive_storage,
                .pending_multi_endpoint_storage = pending_multi_endpoint_storage,
            };
        }

        pub fn deinit(self: *Self) void {
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |entry| {
                std.debug.assert(!entry.*.leased);
            }
            while (self.firstHandle()) |handle| self.dropEntry(handle);
            self.entries.deinit(self.allocator);
            if (self.pending_multi_endpoint_datagram) |*datagram| {
                datagram.deinit(
                    (datagram.received_on orelse self.endpoint).allocator,
                );
            }
            if (self.migration_receive_storage.len != 0) {
                self.allocator.free(self.migration_receive_storage);
            }
            if (self.pending_multi_endpoint_storage.len != 0) {
                self.allocator.free(self.pending_multi_endpoint_storage);
            }
            self.dispatcher.deinit();
            self.allocator.destroy(self.dispatcher);
            if (self.migration_endpoint) |candidate| {
                candidate.deinit();
                self.allocator.destroy(candidate);
            }
            self.endpoint.deinit();
            self.allocator.destroy(self.endpoint);
            self.* = undefined;
        }

        pub fn close(self: *Self) void {
            if (self.closed) return;
            self.closed = true;
            while (self.firstIdleHandle()) |handle| self.dropEntry(handle);
        }

        pub fn address(self: *const Self) std.Io.net.IpAddress {
            return self.endpoint.address();
        }

        pub fn migrationAddress(
            self: *const Self,
        ) ?std.Io.net.IpAddress {
            const candidate = self.migration_endpoint orelse return null;
            return candidate.address();
        }

        pub fn acquireUri(
            self: *Self,
            uri_text: []const u8,
        ) !Lease {
            if (self.closed) return error.PoolClosed;
            const deadline = deadline_policy.fromTimeout(
                self.io,
                self.options.client.connect_timeout,
            ) catch return error.HandshakeTimeout;
            return self.acquireUriBefore(uri_text, deadline, null);
        }

        pub fn acquireUriWithTimeout(
            self: *Self,
            uri_text: []const u8,
            timeout: std.Io.Duration,
        ) !Lease {
            if (self.closed) return error.PoolClosed;
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
        ) !Lease {
            if (self.closed) return error.PoolClosed;
            const absolute = try deadline_policy.capTimeout(
                self.io,
                deadline,
                self.options.client.connect_timeout,
            );
            return self.acquireUriBefore(uri_text, absolute, null);
        }

        fn acquireUriBefore(
            self: *Self,
            uri_text: []const u8,
            deadline: ?std.Io.Clock.Timestamp,
            redirect: ?owning_pool.RedirectConnectContext,
        ) !Lease {
            if (self.closed) return error.PoolClosed;
            const uri = std.Uri.parse(uri_text) catch return error.InvalidUri;
            var endpoint = try Runtime.uriEndpoint(self.allocator, uri);
            defer endpoint.deinit();
            const origin = try http3.requestOrigin(
                uri.scheme,
                endpoint.authority,
            );
            self.pruneExpired();
            if (self.takeIdle(origin)) |entry| {
                self.total_reused +|= 1;
                return .{
                    .pool = self,
                    .handle = entry.handle,
                    .was_reused = true,
                };
            }
            self.total_misses +|= 1;
            if (self.options.max_connections != 0 and
                self.entries.count() >= self.options.max_connections)
            {
                const displaced = self.oldestIdleHandle() orelse
                    return error.ConnectionLimitReached;
                self.dropEntry(displaced);
            }
            // Reserve the stable map slot before a successful handshake can
            // become visible. This prevents an allocation failure after
            // dispatcher promotion from tearing down a live route.
            try self.entries.ensureUnusedCapacity(self.allocator, 1);

            const addresses = try Runtime.resolveEndpointBefore(
                endpoint,
                self.allocator,
                self.io,
                deadline,
            );
            defer self.allocator.free(addresses);
            var last_error: ?anyerror = null;
            for (addresses) |peer| {
                if (!sameAddressFamily(self.options.local_address, peer)) {
                    continue;
                }
                const connected = self.connectOne(
                    &endpoint,
                    peer,
                    deadline,
                    redirect,
                ) catch |err| {
                    last_error = err;
                    if (shouldTryNextAddress(err)) continue;
                    return err;
                };
                errdefer {
                    _ = self.dispatcher.unregisterConnection(
                        connected.handle,
                    ) catch false;
                    connected.client.deinit();
                    self.allocator.destroy(connected.client);
                }
                const origin_key = try http3.originKeyFromOrigin(
                    self.allocator,
                    origin,
                );
                errdefer {
                    var key = origin_key;
                    key.deinit();
                }
                const entry = try self.allocator.create(Entry);
                errdefer self.allocator.destroy(entry);
                entry.* = .{
                    .handle = connected.handle,
                    .client = connected.client,
                    .origin_key = origin_key,
                };
                self.entries.putAssumeCapacityNoClobber(
                    connected.handle,
                    entry,
                );
                return .{
                    .pool = self,
                    .handle = connected.handle,
                    .was_reused = false,
                };
            }
            return last_error orelse error.AddressFamilyUnsupported;
        }

        fn connectOne(
            self: *Self,
            uri_endpoint: *const Runtime.UriEndpoint,
            peer: std.Io.net.IpAddress,
            deadline: ?std.Io.Clock.Timestamp,
            redirect: ?owning_pool.RedirectConnectContext,
        ) !Connected {
            var original_dcid: [8]u8 = undefined;
            var local_cid: [8]u8 = undefined;
            try std.Io.randomSecure(self.io, &original_dcid);
            try std.Io.randomSecure(self.io, &local_cid);
            const pending_handle = self.reserveHandle();
            const inbox = try self.allocator.create(quic.handshake_inbox.Inbox);
            var inbox_initialized = false;
            var inbox_registered = false;
            defer {
                if (inbox_registered) {
                    _ = self.dispatcher.unregisterPendingHandshake(
                        pending_handle,
                    ) catch false;
                }
                if (inbox_initialized) inbox.deinit();
                self.allocator.destroy(inbox);
            }
            inbox.* = try quic.handshake_inbox.Inbox.init(
                self.allocator,
                self.io,
                &.{&local_cid},
                peer,
                self.options.handshake_inbox_capacity,
            );
            inbox_initialized = true;
            try self.dispatcher.registerPendingHandshake(
                pending_handle,
                inbox,
            );
            inbox_registered = true;

            var worker_context = ConnectWorker{
                .pool = self,
                .source = inbox.datagramSource(),
                .peer = peer,
                .uri_endpoint = uri_endpoint,
                .original_dcid = &original_dcid,
                .local_cid = &local_cid,
                .deadline = deadline,
                .redirect = redirect,
            };
            const Wake = union(enum) {
                connected: ConnectCompletion,
                endpoint: quic.endpoint_dispatcher.ReceiveError!quic.endpoint_dispatcher.Event,
            };
            var wake_storage: [2]Wake = undefined;
            var select: std.Io.Select(Wake) = .init(
                self.io,
                &wake_storage,
            );
            defer while (select.cancel()) |wake_value| {
                var wake = wake_value;
                switch (wake) {
                    .connected => |*completion| switch (completion.*) {
                        .client => |*value| value.deinit(),
                        .failure => {},
                    },
                    .endpoint => |*result| if (result.*) |*event| {
                        event.deinit(self.allocator);
                    } else |_| {},
                }
            };
            try select.concurrent(
                .connected,
                ConnectWorker.connect,
                .{&worker_context},
            );

            while (true) {
                const poll_deadline = deadline_policy.earlier(
                    deadline,
                    .fromNow(self.io, .{
                        .clock = .awake,
                        .raw = self.options.handshake_poll_interval,
                    }),
                ).?;
                select.async(
                    .endpoint,
                    Self.receiveTransportWithDeadline,
                    .{ self, poll_deadline },
                );
                switch (try select.await()) {
                    .connected => |completion| switch (completion) {
                        .failure => |err| return err,
                        .client => |client_value| {
                            // Stop the competing endpoint wait before changing
                            // dispatcher routes during promotion. A completed
                            // receive may still carry owned diagnostic bytes.
                            while (select.cancel()) |wake_value| {
                                var wake = wake_value;
                                switch (wake) {
                                    .endpoint => |*result| if (result.*) |*event| {
                                        event.deinit(self.allocator);
                                    } else |_| {},
                                    .connected => unreachable,
                                }
                            }
                            const connected = try self.allocator.create(Client);
                            errdefer self.allocator.destroy(connected);
                            connected.* = client_value;
                            errdefer connected.deinit();
                            try connected.ensureSettingsSentOnce();
                            try connected.bindDispatcher();
                            try self.dispatcher.promotePendingHandshake(
                                pending_handle,
                                pending_handle,
                                &connected.established.connection,
                            );
                            inbox_registered = false;
                            return .{
                                .handle = pending_handle,
                                .client = connected,
                            };
                        },
                    },
                    .endpoint => |result| {
                        var event = result catch |err| switch (err) {
                            error.Timeout => continue,
                            else => return err,
                        };
                        defer event.deinit(self.allocator);
                        try self.applyEndpointProgress(&event);
                    },
                }
            }
        }

        pub fn poll(self: *Self) !?Event {
            return self.pollBufferedEvent();
        }

        pub fn receive(self: *Self) !Event {
            return self.receiveUntil(null);
        }

        pub fn receiveWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !Event {
            if (timeout.nanoseconds <= 0) return error.Timeout;
            return self.receiveWithDeadline(.fromNow(self.io, .{
                .raw = timeout,
                .clock = .awake,
            }));
        }

        pub fn receiveWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !Event {
            return self.receiveUntil(try deadline_policy.usableAwake(
                self.io,
                deadline,
            ));
        }

        /// Perform one bounded endpoint-owner turn. Buffered HTTP/3 events
        /// are preferred; null means the interval elapsed after any due QUIC
        /// timer was serviced.
        pub fn receiveOnce(
            self: *Self,
            poll_interval: std.Io.Duration,
        ) !?Event {
            if (poll_interval.nanoseconds <= 0) {
                return error.InvalidPoolOptions;
            }
            return self.receiveUntil(.fromNow(self.io, .{
                .raw = poll_interval,
                .clock = .awake,
            })) catch |err| switch (err) {
                error.Timeout => null,
                else => return err,
            };
        }

        /// Perform one bounded caller-buffer receive iteration. Established
        /// QUIC packets are applied while `storage` is borrowed; response and
        /// push events retain every field needed after this call. A zero
        /// result means the poll interval elapsed without a reportable event.
        pub fn receiveManyOnce(
            self: *Self,
            storage: []u8,
            output: []Event,
            poll_interval: std.Io.Duration,
        ) !usize {
            if (output.len == 0 or
                output.len > quic.runtime.max_receive_batch_messages)
            {
                return error.BufferTooShort;
            }
            if (poll_interval.nanoseconds <= 0) {
                return error.InvalidPoolOptions;
            }
            if (self.migration_endpoint != null) {
                const required_storage = std.math.mul(
                    usize,
                    output.len,
                    self.endpoint.limits.max_datagram_size,
                ) catch return error.BufferTooShort;
                if (storage.len < required_storage) {
                    return error.BufferTooShort;
                }
            }
            const deadline = std.Io.Clock.Timestamp.fromNow(
                self.io,
                .{ .raw = poll_interval, .clock = .awake },
            );
            return self.receiveManyUntil(
                storage,
                output,
                deadline,
            ) catch |err| switch (err) {
                error.Timeout => 0,
                else => |other| return other,
            };
        }

        fn receiveManyUntil(
            self: *Self,
            storage: []u8,
            output: []Event,
            deadline: std.Io.Clock.Timestamp,
        ) !usize {
            // A cross-family pool races two sockets and may need to retain the
            // simultaneously completed datagram. Drain immediately ready work
            // through the caller-buffer visitor path; subsequent calls
            // consume the retained packet before waiting.
            if (self.migration_endpoint != null) {
                return self.receiveManyMultiEndpoint(
                    storage,
                    output,
                    deadline,
                );
            }
            while (true) {
                var count: usize = 0;
                errdefer for (output[0..count]) |*event| {
                    event.deinit(self.allocator);
                };
                if (try self.pollBufferedEvent()) |event| {
                    output[0] = event;
                    return 1;
                }

                const Adapter = struct {
                    pool: *Self,

                    fn visit(
                        adapter: *@This(),
                        packet: quic.endpoint_dispatcher.RoutedPacketView,
                    ) !void {
                        try adapter.pool.processPacketView(packet);
                    }
                };
                var adapter = Adapter{ .pool = self };
                var transport_events: [
                    quic.runtime.max_receive_batch_messages
                ]quic.endpoint_dispatcher.VisitEvent = undefined;
                const transport_count = try self.dispatcher
                    .receiveManyVisitingTimeout(
                    &supported_versions,
                    storage,
                    transport_events[0..output.len],
                    .{ .deadline = deadline },
                    &adapter,
                    Adapter.visit,
                );
                defer for (transport_events[0..transport_count]) |*event| {
                    event.deinit(self.allocator);
                };

                for (transport_events[0..transport_count]) |*event| {
                    switch (event.*) {
                        .packet => |packet| {
                            const application_event =
                                (try self.pollBufferedEvent()) orelse
                                Event{ .progress = packet.connection_handle };
                            if (eventAlreadyReturned(
                                output[0..count],
                                application_event,
                            )) {
                                var duplicate = application_event;
                                duplicate.deinit(self.allocator);
                                continue;
                            }
                            output[count] = application_event;
                            count += 1;
                        },
                        .timer => |timer| {
                            const stable = try self.eventFromTimer(timer);
                            if (stable) |value| {
                                output[count] = value;
                                count += 1;
                            }
                        },
                        .new_initial, .unrouted => {
                            output[count] = .{
                                .unrouted = takeVisitEvent(event),
                            };
                            count += 1;
                        },
                        .consumed,
                        .pending_handshake,
                        .discarded_long_header,
                        => {},
                    }
                }
                if (count != 0) return count;
            }
        }

        fn receiveManyMultiEndpoint(
            self: *Self,
            storage: []u8,
            output: []Event,
            deadline: std.Io.Clock.Timestamp,
        ) !usize {
            var count: usize = 0;
            errdefer for (output[0..count]) |*event| {
                event.deinit(self.allocator);
            };
            while (count < output.len) {
                const event_storage = storage[count * self.endpoint.limits.max_datagram_size ..];
                const caller_deadline = if (count == 0)
                    deadline
                else
                    std.Io.Clock.Timestamp.fromNow(self.io, .{
                        .raw = .zero,
                        .clock = .awake,
                    });
                const event = self.receiveMultiEndpointInto(
                    event_storage,
                    caller_deadline,
                ) catch |err| switch (err) {
                    error.Timeout => if (count != 0)
                        return count
                    else
                        return err,
                    else => |other| return other,
                };
                if (eventAlreadyReturned(output[0..count], event)) {
                    var duplicate = event;
                    duplicate.deinit(self.allocator);
                    return count;
                }
                output[count] = event;
                count += 1;
            }
            return count;
        }

        fn receiveMultiEndpointInto(
            self: *Self,
            storage: []u8,
            caller_deadline: std.Io.Clock.Timestamp,
        ) !Event {
            while (true) {
                if (try self.pollBufferedEvent()) |event| return event;
                if (try self.dispatcher.poll()) |dispatcher_event_value| {
                    var dispatcher_event = dispatcher_event_value;
                    var event_owned = true;
                    defer if (event_owned) dispatcher_event.deinit(
                        self.allocator,
                    );
                    switch (dispatcher_event) {
                        .packet => |*packet| {
                            const handle = packet.connection_handle;
                            try self.processPacket(packet);
                            return (try self.pollBufferedEvent()) orelse
                                .{ .progress = handle };
                        },
                        .timer => |timer| {
                            if (try self.eventFromTimer(timer)) |event| {
                                return event;
                            }
                        },
                        .new_initial, .unrouted => {
                            event_owned = false;
                            return .{ .unrouted = dispatcher_event };
                        },
                        .consumed,
                        .pending_handshake,
                        .discarded_long_header,
                        => {},
                    }
                    continue;
                }

                const candidate = self.migration_endpoint orelse unreachable;
                const datagram = receiveViewFromEitherEndpoint(
                    self,
                    candidate,
                    storage,
                    multiEndpointReceiveTimeout(
                        self.io,
                        caller_deadline,
                        self.dispatcher.nextTimerDeadline(),
                    ),
                ) catch |err| switch (err) {
                    error.Timeout => {
                        if (caller_deadline.durationFromNow(self.io)
                            .raw.nanoseconds <= 0) return error.Timeout;
                        continue;
                    },
                    else => |other| return other,
                };
                const received_on = datagram.received_on orelse self.endpoint;
                if (received_on == candidate and datagram.bytes.len != 0 and
                    (datagram.bytes[0] & 0x80) != 0)
                {
                    continue;
                }
                if (try received_on.sendVersionNegotiationIfUnsupported(
                    datagram.from,
                    datagram.bytes,
                    &supported_versions,
                )) continue;

                const Adapter = struct {
                    pool: *Self,

                    fn visit(
                        adapter: *@This(),
                        packet: quic.endpoint_dispatcher.RoutedPacketView,
                    ) !void {
                        try adapter.pool.processPacketView(packet);
                    }
                };
                var adapter = Adapter{ .pool = self };
                var transport_event = try self.dispatcher
                    .dispatchVisitingDatagram(
                    datagram,
                    &adapter,
                    Adapter.visit,
                );
                defer transport_event.deinit(self.allocator);
                switch (transport_event) {
                    .packet => |packet| {
                        return (try self.pollBufferedEvent()) orelse
                            .{ .progress = packet.connection_handle };
                    },
                    .timer => |timer| {
                        if (try self.eventFromTimer(timer)) |event| {
                            return event;
                        }
                    },
                    .new_initial, .unrouted => {
                        return .{ .unrouted = takeVisitEvent(
                            &transport_event,
                        ) };
                    },
                    .consumed,
                    .pending_handshake,
                    .discarded_long_header,
                    => {},
                }
            }
        }

        fn receiveUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !Event {
            if (try self.pollBufferedEvent()) |event| return event;
            var routed = try self.receiveTransportUntil(deadline);
            var routed_owned = true;
            defer if (routed_owned) routed.deinit(self.allocator);
            switch (routed) {
                .packet => |*packet| {
                    const handle = packet.connection_handle;
                    try self.processPacket(packet);
                    return (try self.pollBufferedEvent()) orelse
                        .{ .progress = handle };
                },
                .timer => |timer| {
                    const entry = self.entries.get(
                        timer.connection_handle,
                    ) orelse return error.UnknownConnectionHandle;
                    if (entry.client.established.connection.closed()) {
                        const handle = entry.handle;
                        if (!entry.leased) {
                            self.dropEntry(handle);
                            return .consumed;
                        }
                        if (entry.registered) {
                            _ = try self.dispatcher.unregisterConnection(
                                handle,
                            );
                            entry.registered = false;
                        }
                        entry.close_pending = null;
                        return .{ .closed = .{
                            .connection_handle = handle,
                            .timer = timer.timer,
                        } };
                    }
                    return .{ .timer = timer };
                },
                .new_initial, .unrouted => {
                    routed_owned = false;
                    return .{ .unrouted = routed };
                },
                .consumed,
                .pending_handshake,
                .discarded_long_header,
                => return .consumed,
            }
        }

        fn receiveTransportWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) quic.endpoint_dispatcher.ReceiveError!quic.endpoint_dispatcher.Event {
            return self.receiveTransportUntil(deadline);
        }

        fn receiveTransportUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) quic.endpoint_dispatcher.ReceiveError!quic.endpoint_dispatcher.Event {
            const candidate = self.migration_endpoint orelse {
                return if (deadline) |absolute|
                    self.dispatcher.receiveWithDeadline(
                        &supported_versions,
                        absolute,
                    )
                else
                    self.dispatcher.receive(&supported_versions);
            };
            while (true) {
                if (try self.dispatcher.poll()) |event| return event;
                var datagram = receiveFromEitherEndpoint(
                    self,
                    candidate,
                    multiEndpointReceiveTimeout(
                        self.io,
                        deadline,
                        self.dispatcher.nextTimerDeadline(),
                    ),
                ) catch |err| switch (err) {
                    error.Timeout => {
                        if (deadline) |absolute| {
                            if (absolute.durationFromNow(self.io)
                                .raw.nanoseconds <= 0) return error.Timeout;
                        }
                        continue;
                    },
                    else => |other| return other,
                };
                const received_on = datagram.received_on orelse self.endpoint;
                if (received_on == candidate and datagram.bytes.len != 0 and
                    (datagram.bytes[0] & 0x80) != 0)
                {
                    datagram.deinit(received_on.allocator);
                    continue;
                }
                if (try received_on.sendVersionNegotiationIfUnsupported(
                    datagram.from,
                    datagram.bytes,
                    &supported_versions,
                )) {
                    datagram.deinit(received_on.allocator);
                    continue;
                }
                const event = try self.dispatcher.dispatch(datagram);
                if (event == .discarded_long_header) continue;
                return event;
            }
        }

        fn applyEndpointProgress(
            self: *Self,
            event: *quic.endpoint_dispatcher.Event,
        ) !void {
            switch (event.*) {
                .packet => |*packet| try self.processPacket(packet),
                .timer => |timer| {
                    if (self.entries.get(timer.connection_handle)) |entry| {
                        if (entry.client.established.connection.closed() and
                            !entry.leased)
                        {
                            self.dropEntry(entry.handle);
                        } else if (entry.client.established.connection.closed()) {
                            const handle = entry.handle;
                            if (entry.registered) {
                                _ = self.dispatcher.unregisterConnection(
                                    handle,
                                ) catch false;
                                entry.registered = false;
                            }
                            entry.close_pending = timer.timer;
                        }
                    }
                },
                .consumed,
                .pending_handshake,
                .discarded_long_header,
                .new_initial,
                .unrouted,
                => {},
            }
        }

        fn processPacket(
            self: *Self,
            packet: *quic.endpoint_dispatcher.RoutedPacket,
        ) !void {
            const entry = self.entries.get(packet.connection_handle) orelse
                return error.UnknownConnectionHandle;
            defer self.refresh(packet.connection_handle) catch {};
            try entry.client.processResponsePacket(&packet.packet);
        }

        fn processPacketView(
            self: *Self,
            packet: quic.endpoint_dispatcher.RoutedPacketView,
        ) !void {
            const entry = self.entries.get(packet.connection_handle) orelse
                return error.UnknownConnectionHandle;
            try entry.client.processResponsePacketView(packet.packet);
        }

        fn eventFromTimer(
            self: *Self,
            timer: quic.endpoint_dispatcher.TimerEvent,
        ) !?Event {
            const entry = self.entries.get(
                timer.connection_handle,
            ) orelse return error.UnknownConnectionHandle;
            if (!entry.client.established.connection.closed()) {
                return .{ .timer = timer };
            }
            const handle = entry.handle;
            if (!entry.leased) {
                self.dropEntry(handle);
                return null;
            }
            if (entry.registered) {
                _ = try self.dispatcher.unregisterConnection(handle);
                entry.registered = false;
            }
            entry.close_pending = null;
            return .{ .closed = .{
                .connection_handle = handle,
                .timer = timer.timer,
            } };
        }

        fn takeVisitEvent(
            event: *quic.endpoint_dispatcher.VisitEvent,
        ) quic.endpoint_dispatcher.Event {
            return switch (event.*) {
                .new_initial => |initial| blk: {
                    event.* = .consumed;
                    break :blk .{ .new_initial = initial };
                },
                .unrouted => |unrouted| blk: {
                    event.* = .consumed;
                    break :blk .{ .unrouted = unrouted };
                },
                else => unreachable,
            };
        }

        fn eventAlreadyReturned(
            events: []const Event,
            candidate: Event,
        ) bool {
            return switch (candidate) {
                .response => |response| responseEventAlreadyReturned(
                    events,
                    response,
                ),
                .push => |push| pushEventAlreadyReturned(events, push),
                else => false,
            };
        }

        fn responseEventAlreadyReturned(
            events: []const Event,
            candidate: ResponseEvent,
        ) bool {
            const stream_id = switch (candidate.response) {
                .reset => return false,
                .message => |message| switch (message.value) {
                    .data_available => message.stream_id,
                    .head, .push_promise, .trailers, .finished => return false,
                },
            };
            for (events) |event| switch (event) {
                .response => |previous| {
                    if (previous.connection_handle !=
                        candidate.connection_handle) continue;
                    switch (previous.response) {
                        .reset => {},
                        .message => |message| if (message.stream_id ==
                            stream_id and message.value == .data_available)
                        {
                            return true;
                        },
                    }
                },
                else => {},
            };
            return false;
        }

        fn pushEventAlreadyReturned(
            events: []const Event,
            candidate: PushEvent,
        ) bool {
            if (candidate.push.value != .data_available) return false;
            for (events) |event| switch (event) {
                .push => |previous| {
                    if (previous.connection_handle ==
                        candidate.connection_handle and
                        previous.push.stream_id == candidate.push.stream_id and
                        previous.push.value == .data_available)
                    {
                        return true;
                    }
                },
                else => {},
            };
            return false;
        }

        fn pollBufferedEvent(self: *Self) !?Event {
            if (self.entries.count() == 0) return null;
            var cursor = self.last_event_handle;
            var remaining = self.leasedCount();
            while (remaining != 0) : (remaining -= 1) {
                const entry = self.nextLeasedEntry(cursor) orelse return null;
                cursor = entry.handle;
                if (entry.close_pending) |timer| {
                    entry.close_pending = null;
                    self.last_event_handle = entry.handle;
                    return .{ .closed = .{
                        .connection_handle = entry.handle,
                        .timer = timer,
                    } };
                }
                defer self.refresh(entry.handle) catch {};
                if (try entry.client.pollNextResponseEventOnce()) |response| {
                    var owned = response;
                    errdefer owned.deinit(self.allocator);
                    self.last_event_handle = entry.handle;
                    return .{ .response = .{
                        .connection_handle = entry.handle,
                        .response = owned,
                    } };
                }
                if (try entry.client.pollPushEventOnce()) |push| {
                    var owned = push;
                    errdefer owned.deinit(self.allocator);
                    self.last_event_handle = entry.handle;
                    return .{ .push = .{
                        .connection_handle = entry.handle,
                        .push = owned,
                    } };
                }
            }
            return null;
        }

        pub fn refresh(self: *Self, handle: Handle) !void {
            const entry = self.entries.get(handle) orelse
                return error.UnknownConnectionHandle;
            if (!entry.registered) return;
            try self.dispatcher.refreshConnectionTimer(handle);
        }

        pub fn readResponseDataOnce(
            self: *Self,
            handle: Handle,
            stream_id: u62,
            out: []u8,
        ) !?usize {
            const entry = self.entries.get(handle) orelse
                return error.UnknownConnectionHandle;
            if (!entry.leased) return error.InvalidLease;
            defer self.refresh(handle) catch {};
            return entry.client.readResponseDataOnce(stream_id, out);
        }

        pub fn readPushDataOnce(
            self: *Self,
            handle: Handle,
            push_id: u64,
            out: []u8,
        ) !?usize {
            const entry = self.entries.get(handle) orelse
                return error.UnknownConnectionHandle;
            if (!entry.leased) return error.InvalidLease;
            defer self.refresh(handle) catch {};
            return entry.client.readPushDataOnce(push_id, out);
        }

        pub fn connectionCount(self: *const Self) usize {
            return self.entries.count();
        }

        pub fn routeCount(self: *const Self) usize {
            return self.dispatcher.routeCount();
        }

        pub fn pendingHandshakeCount(self: *const Self) usize {
            return self.dispatcher.pendingHandshakeCount();
        }

        pub fn leasedCount(self: *const Self) usize {
            var count: usize = 0;
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |entry| count += @intFromBool(entry.*.leased);
            return count;
        }

        pub fn idleCount(self: *const Self) usize {
            return self.entries.count() - self.leasedCount();
        }

        pub fn stats(self: *const Self) http3.origin_pool.Stats {
            return .{
                .idle = self.idleCount(),
                .total_reused = self.total_reused,
                .total_misses = self.total_misses,
                .total_dropped = self.total_dropped,
            };
        }

        fn release(self: *Self, handle: Handle) void {
            const entry = self.entries.get(handle) orelse unreachable;
            std.debug.assert(entry.leased);
            if (self.closed or !entry.client.isReusable() or
                self.options.idle.max_idle_per_origin == 0 or
                self.options.idle.max_idle_total == 0)
            {
                self.dropEntry(handle);
                return;
            }
            const origin = entry.origin_key.origin();
            if (self.idleCountForOrigin(origin) >=
                self.options.idle.max_idle_per_origin)
            {
                self.dropEntry(handle);
                return;
            }
            if (self.idleCount() >= self.options.idle.max_idle_total) {
                if (self.oldestIdleHandle()) |oldest| self.dropEntry(oldest);
            }
            entry.leased = false;
            entry.pooled_at_ms = nowMillis(self.io);
            entry.release_sequence = self.release_sequence;
            self.release_sequence +%= 1;
        }

        fn takeIdle(self: *Self, origin: http3.Origin) ?*Entry {
            var selected: ?*Entry = null;
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                const entry = value.*;
                if (entry.leased or !sameOrigin(entry.origin_key.origin(), origin)) {
                    continue;
                }
                if (!entry.client.isReusable()) continue;
                if (selected == null or
                    entry.release_sequence < selected.?.release_sequence)
                {
                    selected = entry;
                }
            }
            if (selected) |entry| entry.leased = true;
            return selected;
        }

        fn pruneExpired(self: *Self) void {
            while (self.firstExpiredIdleHandle()) |handle| {
                self.dropEntry(handle);
            }
            while (self.firstUnusableIdleHandle()) |handle| {
                self.dropEntry(handle);
            }
        }

        fn firstExpiredIdleHandle(self: *const Self) ?Handle {
            const now_ms = nowMillis(self.io);
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                const entry = value.*;
                if (!entry.leased and now_ms >= entry.pooled_at_ms and
                    now_ms - entry.pooled_at_ms >
                        self.options.idle.idle_timeout_ms)
                {
                    return entry.handle;
                }
            }
            return null;
        }

        fn firstUnusableIdleHandle(self: *const Self) ?Handle {
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                const entry = value.*;
                if (!entry.leased and !entry.client.isReusable()) {
                    return entry.handle;
                }
            }
            return null;
        }

        fn firstIdleHandle(self: *const Self) ?Handle {
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                if (!value.*.leased) return value.*.handle;
            }
            return null;
        }

        fn firstHandle(self: *const Self) ?Handle {
            var iterator = self.entries.keyIterator();
            return if (iterator.next()) |handle| handle.* else null;
        }

        fn oldestIdleHandle(self: *const Self) ?Handle {
            var selected: ?*Entry = null;
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                const entry = value.*;
                if (entry.leased) continue;
                if (selected == null or
                    entry.pooled_at_ms < selected.?.pooled_at_ms or
                    (entry.pooled_at_ms == selected.?.pooled_at_ms and
                        entry.release_sequence < selected.?.release_sequence))
                {
                    selected = entry;
                }
            }
            return if (selected) |entry| entry.handle else null;
        }

        fn idleCountForOrigin(
            self: *const Self,
            origin: http3.Origin,
        ) usize {
            var count: usize = 0;
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                const entry = value.*;
                if (!entry.leased and
                    sameOrigin(entry.origin_key.origin(), origin))
                {
                    count += 1;
                }
            }
            return count;
        }

        fn nextLeasedEntry(self: *Self, after: ?Handle) ?*Entry {
            var next: ?*Entry = null;
            var wrapped: ?*Entry = null;
            var iterator = self.entries.valueIterator();
            while (iterator.next()) |value| {
                const entry = value.*;
                if (!entry.leased or
                    (!entry.registered and entry.close_pending == null))
                {
                    continue;
                }
                if (wrapped == null or entry.handle < wrapped.?.handle) {
                    wrapped = entry;
                }
                if (after) |cursor| {
                    if (entry.handle <= cursor) continue;
                }
                if (next == null or entry.handle < next.?.handle) next = entry;
            }
            return next orelse wrapped;
        }

        fn dropEntry(self: *Self, handle: Handle) void {
            const removed = self.entries.fetchRemove(handle) orelse return;
            const entry = removed.value;
            if (entry.registered) {
                _ = self.dispatcher.unregisterConnection(handle) catch false;
            }
            if (self.last_event_handle == handle) self.last_event_handle = null;
            entry.client.deinit();
            self.allocator.destroy(entry.client);
            entry.origin_key.deinit();
            self.allocator.destroy(entry);
            self.total_dropped +|= 1;
        }

        fn reserveHandle(self: *Self) Handle {
            const handle = self.next_handle;
            self.next_handle +%= 1;
            if (self.next_handle == 0) self.next_handle = 1;
            return handle;
        }
    };
}

fn sameOrigin(a: http3.Origin, b: http3.Origin) bool {
    return a.port == b.port and
        std.ascii.eqlIgnoreCase(a.scheme, b.scheme) and
        std.ascii.eqlIgnoreCase(a.host, b.host);
}

fn sameAddressFamily(
    a: std.Io.net.IpAddress,
    b: std.Io.net.IpAddress,
) bool {
    return switch (a) {
        .ip4 => b == .ip4,
        .ip6 => b == .ip6,
    };
}

fn receiveFromEitherEndpoint(
    pool: anytype,
    candidate: *quic.runtime.Endpoint,
    timeout: std.Io.Timeout,
) quic.runtime.ReceiveTimeoutError!quic.runtime.OwnedBytes {
    if (pool.pending_multi_endpoint_view) |pending| {
        pool.pending_multi_endpoint_view = null;
        return .{
            .from = pending.from,
            .received_on = pending.received_on,
            .bytes = try pool.allocator.dupe(
                u8,
                pool.pending_multi_endpoint_storage[0..pending.len],
            ),
            .ecn = pending.ecn,
        };
    }
    return owned_receive_race.receive(
        &pool.pending_multi_endpoint_datagram,
        pool.io,
        pool.endpoint,
        candidate,
        timeout,
    );
}

fn receiveViewFromEitherEndpoint(
    pool: anytype,
    candidate: *quic.runtime.Endpoint,
    primary_storage: []u8,
    timeout: std.Io.Timeout,
) quic.runtime.ReceiveTimeoutError!quic.runtime.ReceivedBytesView {
    if (primary_storage.len == 0) return error.BufferTooShort;
    if (pool.pending_multi_endpoint_view) |pending| {
        pool.pending_multi_endpoint_view = null;
        return .{
            .from = pending.from,
            .received_on = pending.received_on,
            .bytes = pool.pending_multi_endpoint_storage[0..pending.len],
            .ecn = pending.ecn,
        };
    }
    if (pool.pending_multi_endpoint_datagram) |pending_value| {
        var pending = pending_value;
        pool.pending_multi_endpoint_datagram = null;
        defer pending.deinit(
            (pending.received_on orelse pool.endpoint).allocator,
        );
        const storage = if (pending.received_on == candidate)
            pool.migration_receive_storage
        else
            primary_storage;
        if (pending.bytes.len > storage.len) return error.BufferTooShort;
        @memcpy(storage[0..pending.bytes.len], pending.bytes);
        return .{
            .from = pending.from,
            .received_on = pending.received_on,
            .bytes = storage[0..pending.bytes.len],
            .ecn = pending.ecn,
        };
    }
    const bounded = timeout.toDeadline(pool.io);
    const ReceiveResult = quic.runtime.ReceiveTimeoutError!quic.runtime.ReceivedBytesView;
    const Wake = union(enum) {
        primary: ReceiveResult,
        candidate: ReceiveResult,
    };
    var wake_storage: [2]Wake = undefined;
    var select: std.Io.Select(Wake) = .init(pool.io, &wake_storage);
    select.async(
        .primary,
        quic.runtime.Endpoint.receiveBytesIntoTimeout,
        .{ pool.endpoint, primary_storage, bounded },
    );
    select.async(
        .candidate,
        quic.runtime.Endpoint.receiveBytesIntoTimeout,
        .{
            candidate,
            pool.migration_receive_storage[0..@min(
                primary_storage.len,
                pool.migration_receive_storage.len,
            )],
            bounded,
        },
    );
    const first = select.await() catch |err| {
        select.cancelDiscard();
        return err;
    };
    while (select.cancel()) |wake| switch (wake) {
        .primary, .candidate => |result| if (result) |view| {
            if (pool.pending_multi_endpoint_view == null) {
                std.debug.assert(
                    view.bytes.len <=
                        pool.pending_multi_endpoint_storage.len,
                );
                @memcpy(
                    pool.pending_multi_endpoint_storage[0..view.bytes.len],
                    view.bytes,
                );
                pool.pending_multi_endpoint_view = .{
                    .from = view.from,
                    .received_on = view.received_on orelse pool.endpoint,
                    .len = view.bytes.len,
                    .ecn = view.ecn,
                };
            }
        } else |_| {},
    };
    return switch (first) {
        .primary => |result| try result,
        .candidate => |result| try result,
    };
}

fn multiEndpointReceiveTimeout(
    io: std.Io,
    caller_deadline: ?std.Io.Clock.Timestamp,
    scheduled: ?quic.endpoint_timers.EndpointTimerDeadline,
) std.Io.Timeout {
    var remaining_ns: ?i96 = if (caller_deadline) |deadline|
        deadline.durationFromNow(io).raw.nanoseconds
    else
        null;
    if (scheduled) |value| {
        const timer = std.Io.Clock.Timestamp{
            .clock = .awake,
            .raw = .fromNanoseconds(
                std.math.cast(i96, value.timer.deadline_ns) orelse
                    std.math.maxInt(i96),
            ),
        };
        const duration = timer.durationFromNow(io).raw.nanoseconds;
        remaining_ns = if (remaining_ns) |current|
            @min(current, duration)
        else
            duration;
    }
    return if (remaining_ns) |nanoseconds| .{ .duration = .{
        .clock = .awake,
        .raw = .fromNanoseconds(@max(nanoseconds, 0)),
    } } else .none;
}

fn applyRedirectConnectionSecurity(
    options: anytype,
    redirect: owning_pool.RedirectConnectContext,
) void {
    if (!redirect.cross_origin) return;
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
    if (!redirect.forward_client_identity) {
        options.handshake.client_identity = null;
    }
}

fn shouldTryNextAddress(err: anyerror) bool {
    return switch (err) {
        error.HandshakeTimeout,
        error.HandshakeSendFailed,
        error.HandshakeReceiveFailed,
        error.AddressFamilyUnsupported,
        error.ConnectionRefused,
        error.ConnectionResetByPeer,
        error.HostUnreachable,
        error.NetworkDown,
        error.NetworkUnreachable,
        error.PortUnreachable,
        => true,
        else => false,
    };
}

fn nowMillis(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now <= 0) return 0;
    return @intCast(@divTrunc(now, std.time.ns_per_ms));
}

fn monotonicNowNs(io: std.Io) u64 {
    const now = std.Io.Clock.awake.now(io).nanoseconds;
    if (now <= 0) return 0;
    return std.math.cast(u64, now) orelse std.math.maxInt(u64);
}

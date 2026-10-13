//! Runtime ownership for inbound bridges declared by mqtt_broker_config.

const std = @import("std");
const netz = @import("netz");

const mqtt = netz.mqtt;
const CertificateBundle = std.crypto.Certificate.Bundle;

const max_bridge_ca_file_bytes: usize = 4 * 1024 * 1024;

const ConfiguredConnector = struct {
    source: *const mqtt.broker_config.Bridge,
    tls_options: ?mqtt.tls_runtime.ConnectOptions = null,
    next_address: std.atomic.Value(usize) = .init(0),
    current_address: std.atomic.Value(usize) = .init(std.math.maxInt(usize)),
    connected_at_ns: std.atomic.Value(i64) = .init(0),
    private_bridge_supported: std.atomic.Value(bool) = .init(true),
    require_private_bridge: bool = false,

    fn connector(self: *ConfiguredConnector) mqtt.runtime.ClientConnector {
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
        mqtt_options: mqtt.runtime.ConnectOptions,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        const self: *ConfiguredConnector = @ptrCast(@alignCast(context));
        return self.connectAttemptMaybeBefore(
            allocator,
            io,
            mqtt_options,
            .{},
            null,
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
        return self.connectAttemptMaybeBefore(
            allocator,
            io,
            mqtt_options,
            .{},
            deadline,
        );
    }

    fn connectAttemptWithTlsTickets(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt.runtime.ConnectOptions,
        tickets: mqtt.runtime.ClientTlsSessionTickets,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        const self: *ConfiguredConnector = @ptrCast(@alignCast(context));
        return self.connectAttemptMaybeBefore(
            allocator,
            io,
            mqtt_options,
            tickets,
            null,
        );
    }

    fn connectAttemptWithTlsTicketsAndDeadline(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt.runtime.ConnectOptions,
        tickets: mqtt.runtime.ClientTlsSessionTickets,
        deadline: std.Io.Clock.Timestamp,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        const self: *ConfiguredConnector = @ptrCast(@alignCast(context));
        return self.connectAttemptMaybeBefore(
            allocator,
            io,
            mqtt_options,
            tickets,
            deadline,
        );
    }

    fn connectAttemptMaybeBefore(
        self: *ConfiguredConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        mqtt_options: mqtt.runtime.ConnectOptions,
        tls_tickets: mqtt.runtime.ClientTlsSessionTickets,
        deadline: ?std.Io.Clock.Timestamp,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        const index, const endpoint = self.takeEndpoint();
        var options = mqtt_options;
        options.bridge_mode = options.bridge_mode and
            self.private_bridge_supported.load(.acquire);
        var attempt = self.connectEndpointMaybeBefore(
            allocator,
            io,
            endpoint,
            options,
            tls_tickets,
            deadline,
        ) catch |err| {
            self.noteAttempt(index, false, io);
            return err;
        };
        if (options.bridge_mode and !attempt.accepted() and
            attempt.connack.connack.reason_code == 0x01)
        {
            if (self.require_private_bridge) {
                self.noteAttempt(index, false, io);
                return attempt;
            }
            attempt.deinit(allocator);
            self.private_bridge_supported.store(false, .release);
            options.bridge_mode = false;
            attempt = self.connectEndpointMaybeBefore(
                allocator,
                io,
                endpoint,
                options,
                tls_tickets,
                deadline,
            ) catch |err| {
                self.noteAttempt(index, false, io);
                return err;
            };
        }
        self.noteAttempt(index, attempt.accepted(), io);
        return attempt;
    }

    fn connectEndpointMaybeBefore(
        self: *ConfiguredConnector,
        allocator: std.mem.Allocator,
        io: std.Io,
        endpoint: mqtt.broker_config.BridgeEndpoint,
        mqtt_options: mqtt.runtime.ConnectOptions,
        tls_tickets: mqtt.runtime.ClientTlsSessionTickets,
        deadline: ?std.Io.Clock.Timestamp,
    ) mqtt.runtime.Error!mqtt.runtime.ConnectAttempt {
        if (self.tls_options) |configured| {
            var options = reconnectTlsOptions(configured, mqtt_options);
            if (tls12TicketForEndpoint(io, endpoint, tls_tickets.tls12)) |ticket| {
                options.tls12_ticket_resumption = ticket;
            } else if (tls_tickets.tls12 != null) {
                options.tls12_ticket_resumption = null;
            }
            if (tls13TicketForEndpoint(io, endpoint, tls_tickets.tls13)) |ticket| {
                options.tls13_ticket_resumption = ticket;
            } else if (tls_tickets.tls13 != null) {
                options.tls13_ticket_resumption = null;
            }
            if (self.source.bind_address) |local_address| {
                return if (deadline) |absolute|
                    mqtt.tls_runtime.Client.connectHostAttemptBoundWithDeadline(
                        allocator,
                        io,
                        endpoint.host,
                        endpoint.port,
                        local_address,
                        options,
                        absolute,
                    )
                else
                    mqtt.tls_runtime.Client.connectHostAttemptBound(
                        allocator,
                        io,
                        endpoint.host,
                        endpoint.port,
                        local_address,
                        options,
                    );
            }
            return if (deadline) |absolute|
                mqtt.tls_runtime.Client.connectHostAttemptWithDeadline(
                    allocator,
                    io,
                    endpoint.host,
                    endpoint.port,
                    options,
                    absolute,
                )
            else
                mqtt.tls_runtime.Client.connectHostAttempt(
                    allocator,
                    io,
                    endpoint.host,
                    endpoint.port,
                    options,
                );
        }
        if (self.source.bind_address) |local_address| {
            return if (deadline) |absolute|
                mqtt.runtime.Client.connectHostAttemptBoundWithDeadline(
                    allocator,
                    io,
                    endpoint.host,
                    endpoint.port,
                    local_address,
                    mqtt_options,
                    absolute,
                )
            else
                mqtt.runtime.Client.connectHostAttemptBound(
                    allocator,
                    io,
                    endpoint.host,
                    endpoint.port,
                    local_address,
                    mqtt_options,
                );
        }
        return if (deadline) |absolute|
            mqtt.runtime.Client.connectHostAttemptWithDeadline(
                allocator,
                io,
                endpoint.host,
                endpoint.port,
                mqtt_options,
                absolute,
            )
        else
            mqtt.runtime.Client.connectHostAttempt(
                allocator,
                io,
                endpoint.host,
                endpoint.port,
                mqtt_options,
            );
    }

    fn takeEndpoint(
        self: *ConfiguredConnector,
    ) struct { usize, mqtt.broker_config.BridgeEndpoint } {
        const index = self.next_address.load(.acquire);
        return .{ index, self.source.addressAt(index) };
    }

    fn noteAttempt(
        self: *ConfiguredConnector,
        index: usize,
        accepted: bool,
        io: std.Io,
    ) void {
        if (accepted) {
            self.next_address.store(
                if (self.source.round_robin)
                    (index + 1) % self.source.addressCount()
                else
                    0,
                .release,
            );
            self.connected_at_ns.store(
                @intCast(std.Io.Clock.awake.now(io).nanoseconds),
                .release,
            );
            self.current_address.store(index, .release);
            return;
        }
        self.current_address.store(std.math.maxInt(usize), .release);
        self.next_address.store(
            (index + 1) % self.source.addressCount(),
            .release,
        );
    }

    fn shouldFailBack(self: *ConfiguredConnector, now_ns: i64) bool {
        if (self.source.round_robin or self.source.addressCount() == 1) {
            return false;
        }
        const current = self.current_address.load(.acquire);
        if (current == 0 or current == std.math.maxInt(usize)) return false;
        const connected_at = self.connected_at_ns.load(.acquire);
        const interval_ns = @as(i64, self.source.restart.cap_seconds) *
            std.time.ns_per_s;
        if (now_ns < connected_at or now_ns - connected_at < interval_ns) {
            return false;
        }
        if (self.current_address.cmpxchgStrong(
            current,
            std.math.maxInt(usize),
            .acq_rel,
            .acquire,
        ) != null) return false;
        self.next_address.store(0, .release);
        return true;
    }
};

fn tls12TicketForEndpoint(
    io: std.Io,
    endpoint: mqtt.broker_config.BridgeEndpoint,
    ticket: ?*const netz.tls.stream.Tls12SessionTicket,
) ?*const netz.tls.stream.Tls12SessionTicket {
    const cached = ticket orelse return null;
    const now_seconds: u64 = @intCast(@max(
        0,
        std.Io.Timestamp.now(io, .real).toSeconds(),
    ));
    cached.validate(now_seconds, endpoint.host) catch return null;
    return cached;
}

fn tls13TicketForEndpoint(
    io: std.Io,
    endpoint: mqtt.broker_config.BridgeEndpoint,
    ticket: ?*const netz.tls.stream.Tls13SessionTicket,
) ?*const netz.tls.stream.Tls13SessionTicket {
    const cached = ticket orelse return null;
    if (!std.mem.eql(u8, cached.server_name, endpoint.host)) return null;
    const now_ms: u64 = @intCast(@max(
        0,
        std.Io.Timestamp.now(io, .real).toMilliseconds(),
    ));
    _ = cached.obfuscatedTicketAge(now_ms) catch return null;
    return cached;
}

fn reconnectTlsOptions(
    configured: mqtt.tls_runtime.ConnectOptions,
    mqtt_options: mqtt.runtime.ConnectOptions,
) mqtt.tls_runtime.ConnectOptions {
    var options = configured;
    const network_connect_timeout = options.mqtt.network_connect_timeout;
    options.mqtt = mqtt_options;
    options.mqtt.network_connect_timeout = network_connect_timeout;
    return options;
}

const ConnectorResources = struct {
    ca_bundle: CertificateBundle = .empty,
    ca_lock: std.Io.RwLock = .init,
    identity: ?netz.tls.server_identity_file.Identity = null,
    alpn_protocols: [1][]const u8 = undefined,
    connector: ConfiguredConnector = undefined,
    connector_configured: bool = false,

    fn deinit(self: *ConnectorResources, allocator: std.mem.Allocator) void {
        if (self.identity) |*identity| identity.deinit();
        self.ca_bundle.deinit(allocator);
        self.* = undefined;
    }
};

pub const ConfiguredBridge = union(enum) {
    inbound: mqtt.bridge.Bridge,
    outbound: mqtt.bridge.outbound.LocalBridge,

    pub fn deinit(self: *ConfiguredBridge) void {
        switch (self.*) {
            inline else => |*value| value.deinit(),
        }
    }
    pub fn requestReconnect(self: *ConfiguredBridge) void {
        switch (self.*) {
            inline else => |*value| value.requestReconnect(),
        }
    }
    pub fn run(self: *ConfiguredBridge, options: mqtt.reconnect.PollOptions) anyerror!void {
        switch (self.*) {
            inline else => |*value| try value.run(options),
        }
    }

    pub fn runUntilReload(
        self: *ConfiguredBridge,
        options: mqtt.reconnect.PollOptions,
        reload_pending: *const std.atomic.Value(bool),
        connected: *std.atomic.Value(bool),
    ) anyerror!void {
        switch (self.*) {
            inline else => |*value| try value.runUntilReload(
                options,
                reload_pending,
                connected,
            ),
        }
    }
    pub fn runOnce(self: *ConfiguredBridge, options: mqtt.reconnect.PollOptions) anyerror!void {
        switch (self.*) {
            inline else => |*value| try value.runOnce(options),
        }
    }

    pub fn runOnceWithConnectionState(
        self: *ConfiguredBridge,
        options: mqtt.reconnect.PollOptions,
        connected: *std.atomic.Value(bool),
    ) anyerror!void {
        switch (self.*) {
            inline else => |*value| try value.runOnceWithConnectionState(
                options,
                connected,
            ),
        }
    }

    pub fn runLazy(
        self: *ConfiguredBridge,
        options: mqtt.reconnect.PollOptions,
        threshold: usize,
        idle_timeout: std.Io.Duration,
    ) anyerror!void {
        switch (self.*) {
            .outbound => |*value| try value.runLazy(
                options,
                threshold,
                idle_timeout,
            ),
            .inbound => return error.UnsupportedBridgeStartType,
        }
    }

    pub fn runLazyUntilReload(
        self: *ConfiguredBridge,
        options: mqtt.reconnect.PollOptions,
        threshold: usize,
        idle_timeout: std.Io.Duration,
        reload_pending: *const std.atomic.Value(bool),
        connected: *std.atomic.Value(bool),
    ) anyerror!void {
        switch (self.*) {
            .outbound => |*value| try value.runLazyUntilReload(
                options,
                threshold,
                idle_timeout,
                reload_pending,
                connected,
            ),
            .inbound => return error.UnsupportedBridgeStartType,
        }
    }
};

/// One move-stable configured bridge generation. Connector callbacks borrow
/// `configured` and `connector_resources`, while the runtime clients retain
/// the address of `shutdown`, so the complete entry remains heap allocated
/// until its task has stopped and `deinit` returns.
pub const Entry = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    configured: mqtt.broker_config.Bridge,
    value: ConfiguredBridge,
    connector_resources: ConnectorResources = .{},
    shutdown: std.Io.Event = .unset,
    connected: std.atomic.Value(bool) = .init(false),

    fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *mqtt.broker.Broker,
        configured: mqtt.broker_config.Bridge,
        persistence_path: ?[]const u8,
        activate_local_source: bool,
    ) !*Entry {
        const entry = try allocator.create(Entry);
        errdefer allocator.destroy(entry);
        entry.* = .{
            .allocator = allocator,
            .io = io,
            .configured = try configured.clone(allocator),
            .value = undefined,
        };
        errdefer entry.configured.deinit(allocator);
        errdefer entry.connector_resources.deinit(allocator);
        entry.value = try initConfiguredBridge(
            allocator,
            io,
            local,
            &entry.configured,
            &entry.connector_resources,
            &entry.shutdown,
            persistence_path,
            activate_local_source,
        );
        return entry;
    }

    pub fn deinit(self: *Entry) void {
        const allocator = self.allocator;
        self.requestStop();
        self.value.deinit();
        self.connector_resources.deinit(allocator);
        self.configured.deinit(allocator);
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn requestStop(self: *Entry) void {
        self.shutdown.set(self.io);
    }

    pub fn stopRequested(self: *const Entry) bool {
        return self.shutdown.isSet();
    }

    fn activate(self: *Entry) anyerror!void {
        switch (self.value) {
            .inbound => {},
            .outbound => |*bridge| try bridge.activateLocalSource(),
        }
    }

    fn runUntilReload(
        self: *Entry,
        reload_pending: *const std.atomic.Value(bool),
    ) ?anyerror {
        const configured = self.configured;
        switch (configured.start_type) {
            .automatic => self.value.runUntilReload(
                .{ .timeout = .fromSeconds(30) },
                reload_pending,
                &self.connected,
            ) catch |err| return err,
            .lazy => self.value.runLazyUntilReload(
                .{ .timeout = .fromSeconds(30) },
                configured.threshold,
                .fromSeconds(configured.idle_timeout_seconds),
                reload_pending,
                &self.connected,
            ) catch |err| return err,
            .once => self.value.runOnceWithConnectionState(
                .{ .timeout = .fromSeconds(30) },
                &self.connected,
            ) catch |err| return err,
        }
        return null;
    }
};

const Slot = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    name: []u8,
    mutex: std.Io.Mutex = .init,
    active: ?*Entry,
    pending: ?*Entry = null,
    has_pending: bool = false,
    reload_pending: std.atomic.Value(bool) = .init(false),
    running: bool = false,

    fn create(
        allocator: std.mem.Allocator,
        io: std.Io,
        entry: *Entry,
    ) !*Slot {
        const slot = try allocator.create(Slot);
        errdefer allocator.destroy(slot);
        slot.* = .{
            .allocator = allocator,
            .io = io,
            .name = try allocator.dupe(u8, entry.configured.name),
            .active = entry,
        };
        return slot;
    }

    fn deinit(self: *Slot) void {
        const allocator = self.allocator;
        std.debug.assert(!self.running);
        if (self.active) |entry| entry.deinit();
        if (self.pending) |entry| entry.deinit();
        allocator.free(self.name);
        self.* = undefined;
        allocator.destroy(self);
    }

    fn detachActive(self: *Slot) *Entry {
        std.debug.assert(!self.running);
        std.debug.assert(!self.has_pending);
        const entry = self.active.?;
        self.active = null;
        return entry;
    }

    fn install(self: *Slot, replacement: ?*Entry) bool {
        self.mutex.lockUncancelable(self.io);
        const retired_pending = self.pending;
        self.pending = replacement;
        self.has_pending = true;
        self.reload_pending.store(true, .release);
        const should_start = !self.running;
        if (self.running and
            (replacement == null or
                replacement.?.configured.reload_type == .immediate or
                !self.connected()))
        {
            self.active.?.requestStop();
        }
        self.mutex.unlock(self.io);
        if (retired_pending) |entry| entry.deinit();
        return should_start;
    }

    fn connected(self: *const Slot) bool {
        const entry = self.active orelse return false;
        return entry.connected.load(.acquire);
    }

    fn requestActiveStop(self: *Slot) void {
        self.mutex.lockUncancelable(self.io);
        if (self.active) |entry| entry.requestStop();
        self.mutex.unlock(self.io);
    }

    fn activeStopRequested(self: *Slot) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.active orelse return true;
        return entry.stopRequested();
    }

    fn requestPrimaryFailback(self: *Slot, now_ns: i64) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.active orelse return;
        if (entry.stopRequested()) return;
        const resources = &entry.connector_resources;
        if (resources.connector_configured and
            resources.connector.source.addressCount() > 1 and
            !resources.connector.source.round_robin and
            resources.connector.source.start_type == .automatic and
            resources.connector.shouldFailBack(now_ns))
        {
            entry.value.requestReconnect();
        }
    }

    fn disconnectLocalSource(self: *Slot) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const entry = self.active orelse return;
        switch (entry.value) {
            .inbound => {},
            .outbound => |*value| value.source.disconnectTransport(),
        }
    }

    fn start(self: *Slot, owner: *Set, workers: *std.Io.Group) void {
        self.mutex.lockUncancelable(self.io);
        std.debug.assert(!self.running);
        self.running = true;
        self.mutex.unlock(self.io);
        workers.async(self.io, run, .{ self, owner });
    }

    fn run(self: *Slot, owner: *Set) std.Io.Cancelable!void {
        while (true) {
            self.mutex.lockUncancelable(self.io);
            if (owner.stopRequested()) {
                self.running = false;
                self.mutex.unlock(self.io);
                return;
            }
            var retired: ?*Entry = null;
            if (self.has_pending) {
                retired = self.active;
                self.active = self.pending;
                self.pending = null;
                self.has_pending = false;
                self.reload_pending.store(false, .release);
            }
            const active = self.active;
            if (active == null) self.running = false;
            self.mutex.unlock(self.io);
            if (retired) |entry| entry.deinit();
            const entry = active orelse return;

            const maybe_error: ?anyerror = result: {
                entry.activate() catch |err| break :result err;
                break :result entry.runUntilReload(&self.reload_pending);
            };

            self.mutex.lockUncancelable(self.io);
            if (owner.stopRequested()) {
                self.running = false;
                self.mutex.unlock(self.io);
                return;
            }
            const replacement_waiting = self.has_pending;
            if (replacement_waiting) {
                self.mutex.unlock(self.io);
                continue;
            }
            if (entry.configured.start_type == .once) {
                if (maybe_error) |err| {
                    std.debug.print(
                        "netz MQTT bridge {s} completed " ++
                            "start_type=once error={s}\n",
                        .{ self.name, @errorName(err) },
                    );
                } else {
                    std.debug.print(
                        "netz MQTT bridge {s} completed start_type=once\n",
                        .{self.name},
                    );
                }
                self.running = false;
                self.mutex.unlock(self.io);
                return;
            }
            owner.recordFailure(maybe_error orelse error.UnexpectedBridgeExit);
            self.running = false;
            self.mutex.unlock(self.io);
            return;
        }
    }
};

pub const PreparedReload = struct {
    allocator: std.mem.Allocator,
    slots: []?*Slot,
    commit: *std.Io.Event,
    owned: bool = true,

    fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *mqtt.broker.Broker,
        configured: []const mqtt.broker_config.Bridge,
        persistence_path: ?[]const u8,
        activate_local_sources: bool,
    ) !PreparedReload {
        const commit = try allocator.create(std.Io.Event);
        errdefer allocator.destroy(commit);
        commit.* = .unset;
        const slots = try allocator.alloc(?*Slot, configured.len);
        @memset(slots, null);
        errdefer allocator.free(slots);
        var initialized: usize = 0;
        errdefer while (initialized != 0) {
            initialized -= 1;
            slots[initialized].?.deinit();
        };
        for (configured, slots) |source, *slot| {
            const entry = try Entry.create(
                allocator,
                io,
                local,
                source,
                persistence_path,
                activate_local_sources,
            );
            errdefer entry.deinit();
            slot.* = try Slot.create(allocator, io, entry);
            initialized += 1;
        }
        return .{
            .allocator = allocator,
            .slots = slots,
            .commit = commit,
        };
    }

    pub fn deinit(self: *PreparedReload) void {
        if (!self.owned) return;
        for (self.slots) |maybe_slot| {
            if (maybe_slot) |slot| slot.deinit();
        }
        self.allocator.free(self.slots);
        self.allocator.destroy(self.commit);
        self.owned = false;
    }

    fn find(self: *const PreparedReload, name: []const u8) ?usize {
        for (self.slots, 0..) |maybe_slot, index| {
            const slot = maybe_slot orelse continue;
            if (std.mem.eql(u8, slot.name, name)) return index;
        }
        return null;
    }

    fn takeSlot(self: *PreparedReload, index: usize) *Slot {
        const slot = self.slots[index].?;
        self.slots[index] = null;
        return slot;
    }
};

pub const ReloadCommit = struct {
    io: std.Io,
    event: *std.Io.Event,

    pub fn commit(self: ReloadCommit) void {
        self.event.set(self.io);
    }
};

pub const Set = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    local: *mqtt.broker.Broker,
    persistence_path: ?[]const u8,
    /// Stable, Set-local cancellation boundary. Bridge tasks can be stopped
    /// and replaced without signaling the listener/broker shutdown event.
    shutdown: *std.Io.Event,
    slots: std.ArrayList(*Slot),
    slots_mutex: std.Io.Mutex = .init,
    reload_storage: []PreparedReload,
    reload_queue: std.Io.Queue(PreparedReload),
    failure_mutex: std.Io.Mutex = .init,
    failure: ?anyerror = null,
    failed: std.Io.Event = .unset,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        local: *mqtt.broker.Broker,
        configured: []const mqtt.broker_config.Bridge,
        persistence_path: ?[]const u8,
    ) !Set {
        const shutdown = try allocator.create(std.Io.Event);
        errdefer allocator.destroy(shutdown);
        shutdown.* = .unset;
        const reload_storage = try allocator.alloc(PreparedReload, 1);
        errdefer allocator.free(reload_storage);
        var prepared = try PreparedReload.init(
            allocator,
            io,
            local,
            configured,
            persistence_path,
            true,
        );
        defer prepared.deinit();
        var slots: std.ArrayList(*Slot) = .empty;
        errdefer {
            for (slots.items) |slot| slot.deinit();
            slots.deinit(allocator);
        }
        try slots.ensureTotalCapacity(allocator, prepared.slots.len);
        for (0..prepared.slots.len) |index| {
            slots.appendAssumeCapacity(prepared.takeSlot(index));
        }
        return .{
            .allocator = allocator,
            .io = io,
            .local = local,
            .persistence_path = persistence_path,
            .shutdown = shutdown,
            .slots = slots,
            .reload_storage = reload_storage,
            .reload_queue = .init(reload_storage),
        };
    }

    pub fn deinit(self: *Set) void {
        self.requestStop();
        self.reload_queue.close(self.io);
        while (true) {
            var pending: [1]PreparedReload = undefined;
            const count = self.reload_queue.getUncancelable(
                self.io,
                &pending,
                0,
            ) catch break;
            if (count == 0) break;
            pending[0].deinit();
        }
        for (self.slots.items) |slot| slot.deinit();
        self.slots.deinit(self.allocator);
        self.allocator.free(self.reload_storage);
        self.allocator.destroy(self.shutdown);
        self.* = undefined;
    }

    /// Stop the bridge supervisor without affecting listeners or other broker
    /// work. `runAll` forwards this to every active bridge before returning;
    /// the owner must await/cancel it before calling `deinit`.
    pub fn requestStop(self: *Set) void {
        self.shutdown.set(self.io);
    }

    fn requestActiveStops(self: *Set) void {
        self.slots_mutex.lockUncancelable(self.io);
        defer self.slots_mutex.unlock(self.io);
        for (self.slots.items) |slot| slot.requestActiveStop();
    }

    pub fn stopRequested(self: *const Set) bool {
        return self.shutdown.isSet();
    }

    pub fn len(self: *const Set) usize {
        return self.slots.items.len;
    }

    /// Intended for setup-time inspection before `runAll` starts.
    pub fn entryAt(self: *Set, index: usize) *Entry {
        return self.slots.items[index].active.?;
    }

    pub fn requestBridgeStop(self: *Set, index: usize) void {
        self.slots.items[index].requestActiveStop();
    }

    pub fn bridgeStopRequested(self: *Set, index: usize) bool {
        return self.slots.items[index].activeStopRequested();
    }

    /// Supervise every configured bridge behind one task boundary. Callers can
    /// therefore stop and replace this Set without canceling unrelated tasks
    /// in their own Select.
    pub fn runAll(self: *Set) anyerror!void {
        const Result = union(enum) {
            shutdown: std.Io.Cancelable!void,
            failure: std.Io.Cancelable!void,
            reload: anyerror!PreparedReload,
            failback_tick: std.Io.Cancelable!void,
        };
        var workers: std.Io.Group = .init;
        var workers_finished = false;
        defer if (!workers_finished) {
            self.requestStop();
            self.requestActiveStops();
            workers.cancel(self.io);
        };
        for (self.slots.items) |slot| slot.start(self, &workers);

        var result_buffer: [4]Result = undefined;
        var select: std.Io.Select(Result) = .init(self.io, &result_buffer);
        defer select.cancelDiscard();
        try select.concurrent(.shutdown, waitForStop, .{self});
        try select.concurrent(.failure, waitForFailure, .{self});
        try select.concurrent(.reload, receiveReload, .{self});
        try select.concurrent(.failback_tick, waitForFailbackTick, .{self.io});
        while (true) {
            switch (try select.await()) {
                .shutdown => |result| {
                    try result;
                    self.requestStop();
                    self.requestActiveStops();
                    workers.cancel(self.io);
                    workers_finished = true;
                    return;
                },
                .failure => |result| {
                    try result;
                    return self.firstFailure() orelse
                        error.UnexpectedBridgeExit;
                },
                .reload => |result| {
                    var prepared = result catch |err| switch (err) {
                        error.Closed => {
                            if (self.stopRequested()) return;
                            return error.BridgeReloadQueueClosed;
                        },
                        else => return err,
                    };
                    defer prepared.deinit();
                    try prepared.commit.wait(self.io);
                    self.applyReload(&prepared, &workers);
                    std.debug.print(
                        "netz MQTT bridge reload committed\n",
                        .{},
                    );
                    try select.concurrent(.reload, receiveReload, .{self});
                },
                .failback_tick => |result| {
                    try result;
                    self.requestPrimaryFailback();
                    try select.concurrent(
                        .failback_tick,
                        waitForFailbackTick,
                        .{self.io},
                    );
                },
            }
        }
    }

    fn waitForStop(self: *Set) std.Io.Cancelable!void {
        try self.shutdown.wait(self.io);
    }

    fn waitForFailure(self: *Set) std.Io.Cancelable!void {
        try self.failed.wait(self.io);
    }

    fn receiveReload(self: *Set) anyerror!PreparedReload {
        return self.reload_queue.getOne(self.io);
    }

    fn waitForFailbackTick(io: std.Io) std.Io.Cancelable!void {
        try std.Io.sleep(io, .fromMilliseconds(100), .awake);
    }

    /// Validate and fully construct a replacement generation before handing it
    /// to the running supervisor. A failed preparation leaves every active
    /// bridge untouched.
    pub fn reload(
        self: *Set,
        configured: []const mqtt.broker_config.Bridge,
    ) anyerror!void {
        var prepared = try self.prepareReload(configured);
        defer prepared.deinit();
        const commit_token = try self.submitPreparedReload(&prepared);
        commit_token.commit();
    }

    pub fn prepareReload(
        self: *Set,
        configured: []const mqtt.broker_config.Bridge,
    ) anyerror!PreparedReload {
        return PreparedReload.init(
            self.allocator,
            self.io,
            self.local,
            configured,
            self.persistence_path,
            false,
        );
    }

    pub fn submitPreparedReload(
        self: *Set,
        prepared: *PreparedReload,
    ) anyerror!ReloadCommit {
        std.debug.assert(prepared.owned);
        self.slots_mutex.lockUncancelable(self.io);
        self.slots.ensureUnusedCapacity(
            self.allocator,
            prepared.slots.len,
        ) catch |err| {
            self.slots_mutex.unlock(self.io);
            return err;
        };
        self.slots_mutex.unlock(self.io);
        try self.reload_queue.putOne(self.io, prepared.*);
        prepared.owned = false;
        return .{ .io = self.io, .event = prepared.commit };
    }

    fn applyReload(
        self: *Set,
        prepared: *PreparedReload,
        workers: *std.Io.Group,
    ) void {
        self.slots_mutex.lockUncancelable(self.io);
        defer self.slots_mutex.unlock(self.io);
        const existing_count = self.slots.items.len;
        for (self.slots.items[0..existing_count]) |slot| {
            if (prepared.find(slot.name)) |index| {
                const staged_slot = prepared.takeSlot(index);
                const replacement = staged_slot.detachActive();
                staged_slot.deinit();
                if (slot.install(replacement)) slot.start(self, workers);
            } else {
                if (slot.install(null)) slot.start(self, workers);
            }
        }
        for (0..prepared.slots.len) |index| {
            const maybe_slot = prepared.slots[index];
            const slot = maybe_slot orelse continue;
            prepared.slots[index] = null;
            self.slots.appendAssumeCapacity(slot);
            slot.start(self, workers);
        }
    }

    fn recordFailure(self: *Set, err: anyerror) void {
        self.failure_mutex.lockUncancelable(self.io);
        if (self.failure == null) self.failure = err;
        self.failure_mutex.unlock(self.io);
        self.failed.set(self.io);
    }

    fn firstFailure(self: *Set) ?anyerror {
        self.failure_mutex.lockUncancelable(self.io);
        defer self.failure_mutex.unlock(self.io);
        return self.failure;
    }

    /// Normalize every broker-local source before a final persistence
    /// snapshot. Persistent Sessions retain retransmittable work; clean
    /// Sessions remove their routes and queued deliveries.
    pub fn disconnectLocalSources(self: *Set) void {
        self.slots_mutex.lockUncancelable(self.io);
        defer self.slots_mutex.unlock(self.io);
        for (self.slots.items) |slot| slot.disconnectLocalSource();
    }

    fn requestPrimaryFailback(self: *Set) void {
        self.slots_mutex.lockUncancelable(self.io);
        defer self.slots_mutex.unlock(self.io);
        const now_ns: i64 = @intCast(
            std.Io.Clock.awake.now(self.io).nanoseconds,
        );
        for (self.slots.items) |slot| slot.requestPrimaryFailback(now_ns);
    }
};

fn initConfiguredBridge(
    allocator: std.mem.Allocator,
    io: std.Io,
    local: *mqtt.broker.Broker,
    source: *const mqtt.broker_config.Bridge,
    resources: *ConnectorResources,
    shutdown: *std.Io.Event,
    persistence_path: ?[]const u8,
    activate_local_source: bool,
) !ConfiguredBridge {
    if (source.hasOutbound()) {
        return .{ .outbound = try initOutbound(
            allocator,
            io,
            local,
            source,
            resources,
            shutdown,
            persistence_path,
            activate_local_source,
        ) };
    }
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
    const notification_topic = if (source.notifications)
        try source.notificationTopicAlloc(allocator)
    else
        null;
    defer if (notification_topic) |topic| allocator.free(topic);
    const options = mqtt.bridge.MultiOptions{
        .connect = remoteConnectOptions(source, property_slice),
        .reconnect_policy = .{
            .initial_delay = .fromSeconds(source.restart.base_seconds),
            .max_delay = .fromSeconds(source.restart.cap_seconds),
            .backoff = .fixed,
            .jitter = if (source.restart.jitter) .decorrelated else .none,
            .stable_connection_period = .fromSeconds(
                source.restart.stable_connection_seconds,
            ),
            .delay_after_disconnect = true,
            .max_attempts = if (source.start_type == .once)
                source.addressCount()
            else
                0,
        },
        .rules = rules,
        .bridge_id = if (source.usesQoS2())
            stableBridgeId(source.*)
        else
            null,
        .notifications = if (notification_topic) |topic| .{
            .topic = topic,
            .publish_local = true,
            .publish_remote = !source.notifications_local_only,
        } else null,
    };
    return .{ .inbound = if (source.usesTls() or
        source.addressCount() > 1 or
        source.usesPrivateBridgeMode())
    blk: {
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
            resources.connector_configured = true;
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
    ) };
}

fn initOutbound(
    allocator: std.mem.Allocator,
    io: std.Io,
    local: *mqtt.broker.Broker,
    source: *const mqtt.broker_config.Bridge,
    resources: *ConnectorResources,
    shutdown: *std.Io.Event,
    persistence_path: ?[]const u8,
    activate_local_source: bool,
) !mqtt.bridge.outbound.LocalBridge {
    var outbound_count: usize = 0;
    var inbound_count: usize = 0;
    for (source.rules) |rule| switch (rule.direction) {
        .in => inbound_count += 1,
        .out => outbound_count += 1,
        .both => {
            inbound_count += 1;
            outbound_count += 1;
        },
    };
    const rules = try allocator.alloc(mqtt.bridge.OutboundRule, outbound_count);
    defer allocator.free(rules);
    const inbound_rules = try allocator.alloc(
        mqtt.bridge.outbound.InboundRule,
        inbound_count,
    );
    defer allocator.free(inbound_rules);
    var initialized: usize = 0;
    defer for (rules[0..initialized]) |rule| allocator.free(rule.filter);
    var inbound_index: usize = 0;
    for (source.rules) |rule| {
        if (rule.direction != .in) {
            // Config owns a remote-prefixed effective filter. OutboundRule
            // owns the base filter and adds local_prefix to the source.
            const filter = try rule.outboundFilterAlloc(allocator);
            rules[initialized] = .{
                .filter = filter,
                .qos = rule.qos,
                .local_prefix = rule.local_prefix,
                .remote_prefix = rule.remote_prefix,
                .no_local = source.hasInbound(),
            };
            initialized += 1;
        }
        if (rule.direction != .out) {
            inbound_rules[inbound_index] = .{
                .filter = rule.filter,
                .qos = rule.qos,
                .local_prefix = rule.local_prefix,
                .remote_prefix = rule.remote_prefix,
                .no_local = source.hasOutbound() and source.protocol == .v5,
            };
            inbound_index += 1;
        }
    }
    var properties: [1]mqtt.Property = .{.{ .four_byte = .{ .id = .session_expiry_interval, .value = source.session_expiry_interval } }};
    const local_properties: []const mqtt.Property = if (source.local_clean_session)
        &.{}
    else
        &.{.{ .four_byte = .{
            .id = .session_expiry_interval,
            .value = std.math.maxInt(u32),
        } }};
    const id = stableOutboundId(source.*);
    const journal_path = if (source.usesOutboundQoS2()) try std.fmt.allocPrint(allocator, "{s}.outbound-{s}.journal", .{
        persistence_path orelse return error.BridgePersistenceRequired,
        std.fmt.bytesToHex(id, .lower),
    }) else null;
    defer if (journal_path) |path| allocator.free(path);
    const mode: mqtt.bridge.outbound.CoordinatorMode = if (journal_path) |path| blk: {
        var file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| switch (err) {
            error.FileNotFound => break :blk .create,
            else => return err,
        };
        file.close(io);
        break :blk .restore;
    } else .create;
    const notification_topic = if (source.notifications) try source.notificationTopicAlloc(allocator) else null;
    defer if (notification_topic) |topic| allocator.free(topic);
    const options = mqtt.bridge.outbound.MultiOptions{
        .source_connect = .{
            .protocol = .v5,
            .client_id = source.localClientId(),
            .clean_start = source.local_clean_session,
            .properties = local_properties,
        },
        .target_connect = remoteConnectOptions(
            source,
            if (source.protocol == .v5 and
                source.session_expiry_interval != 0)
                &properties
            else
                &.{},
        ),
        .target_reconnect_policy = .{
            .initial_delay = .fromSeconds(source.restart.base_seconds),
            .max_delay = .fromSeconds(source.restart.cap_seconds),
            .backoff = .fixed,
            .jitter = if (source.restart.jitter) .decorrelated else .none,
            .stable_connection_period = .fromSeconds(
                source.restart.stable_connection_seconds,
            ),
            .delay_after_disconnect = true,
            .max_attempts = if (source.start_type == .once) source.addressCount() else 0,
        },
        .rules = rules,
        .inbound_rules = inbound_rules,
        .inbound_bridge_id = if (inbound_count != 0)
            stableBridgeId(source.*)
        else
            null,
        .preserve_retain = source.outgoing_retain,
        .attempt_target_unsubscribe = source.attempt_unsubscribe,
        .coordinator = if (journal_path) |path| .{ .bridge_id = id, .dir = std.Io.Dir.cwd(), .sub_path = path, .mode = mode } else null,
        .notifications = if (notification_topic) |topic| .{ .topic = topic, .publish_remote = !source.notifications_local_only } else null,
        .defer_local_source_connect = !activate_local_source,
        .replace_local_source_subscriptions = !activate_local_source,
    };
    if (source.usesTls()) try loadTlsResources(resources, allocator, io, std.Io.Dir.cwd(), source) else {
        resources.connector = .{
            .source = source,
            .require_private_bridge = source.hasInbound() and
                source.hasOutbound() and source.protocol == .v3_1_1,
        };
        resources.connector_configured = true;
    }
    return mqtt.bridge.outbound.LocalBridge.initEndpoints(allocator, io, .{ .broker = local, .id = id }, .{ .connector = resources.connector.connector() }, options, shutdown);
}

fn remoteConnectOptions(
    source: *const mqtt.broker_config.Bridge,
    properties: []const mqtt.Property,
) mqtt.runtime.ConnectOptions {
    return .{
        .protocol = source.protocol,
        .client_id = source.clientId(),
        .bridge_mode = source.usesPrivateBridgeMode(),
        .clean_start = source.clean_session,
        .keep_alive_seconds = source.keep_alive_seconds,
        .properties = properties,
        .username = if (source.remote_username.len != 0)
            source.remote_username
        else
            null,
        .password = if (source.remote_password.len != 0)
            source.remote_password
        else
            null,
        .limits = .{
            .tcp_keepalive = source.tcp_keepalive,
            .tcp_user_timeout_ms = source.tcp_user_timeout_ms,
        },
        .max_outgoing_packet_size = if (source.max_packet_size == 0)
            std.math.maxInt(usize)
        else
            source.max_packet_size,
        .receive_maximum = source.receive_maximum,
        .topic_alias_maximum = source.max_topic_alias,
        .max_outgoing_topic_aliases = source.max_topic_alias,
        .outgoing_retain = source.outgoing_retain,
    };
}

fn stableOutboundId(source: mqtt.broker_config.Bridge) [16]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update("netz mqtt outbound consumer v1\x00");
    hashField(&hasher, source.localClientId());
    return hasher.finalResult()[0..16].*;
}

fn loadTlsResources(
    resources: *ConnectorResources,
    allocator: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    source: *const mqtt.broker_config.Bridge,
) !void {
    const now = std.Io.Clock.real.now(io);
    if (source.use_os_ca_certificates) {
        try resources.ca_bundle.rescan(allocator, io, now);
    }
    if (source.ca_path.len != 0) {
        var explicit = try netz.tls.client_ca_dir.loadCombined(
            allocator,
            io,
            dir,
            if (source.ca_file.len != 0) source.ca_file else null,
            source.ca_path,
        );
        defer explicit.deinit();
        try explicit.appendToBundle(
            allocator,
            &resources.ca_bundle,
            now.toSeconds(),
        );
    } else if (source.ca_file.len != 0) {
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
            now,
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
    var connect_options = mqtt.tls_runtime.ConnectOptions{
        .mqtt = .{ .client_id = source.clientId() },
        .tls = .{
            .ca_bundle = if (source.ca_file.len != 0 or
                source.ca_path.len != 0 or
                source.use_os_ca_certificates) .{
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
        .stapled_ocsp = if (source.require_ocsp) .require else .ignore,
        .protocol_policy = source.tls_protocol_policy,
    };
    if (source.cipher_suites.len != 0) {
        connect_options.cipher_suites = source.cipher_suites;
    }
    if (source.tls12_cipher_suites.len != 0) {
        connect_options.tls12_cipher_suites = source.tls12_cipher_suites;
    }
    resources.connector = .{
        .source = source,
        .tls_options = connect_options,
        .require_private_bridge = source.hasInbound() and
            source.hasOutbound() and source.protocol == .v3_1_1,
    };
    resources.connector_configured = true;
}

fn stableBridgeId(source: mqtt.broker_config.Bridge) [16]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const mixed_directions = source.hasOutbound();
    hasher.update(if (mixed_directions)
        "netz mqtt mixed bridge inbound v1\x00"
    else
        "netz mqtt inbound bridge v1\x00");
    hashField(&hasher, source.name);
    hashField(&hasher, source.clientId());
    hasher.update(&.{@intFromEnum(source.protocol)});
    var inbound_count: usize = 0;
    for (source.rules) |rule| {
        if (rule.direction != .out) inbound_count += 1;
    }
    hashInteger(&hasher, inbound_count);
    for (source.rules) |rule| {
        if (rule.direction == .out) continue;
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

fn initializeAndQueueBridgeReload(
    allocator: std.mem.Allocator,
    io: std.Io,
    direction: mqtt.broker_config.BridgeDirection,
) !void {
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    var initial_name = "allocation-reload".*;
    var initial_host = "initial.example".*;
    var initial_filter = "initial/#".*;
    var initial_rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &initial_filter,
        .qos = .at_most_once,
        .direction = direction,
    }};
    const initial = [_]mqtt.broker_config.Bridge{.{
        .name = &initial_name,
        .host = &initial_host,
        .rules = &initial_rules,
    }};
    var bridges = try Set.init(allocator, io, &broker, &initial, null);
    defer bridges.deinit();

    var replacement_name = "allocation-reload".*;
    var replacement_host = "replacement.example".*;
    var replacement_filter = "replacement/#".*;
    var replacement_rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &replacement_filter,
        .qos = .at_least_once,
        .direction = direction,
    }};
    const replacement = [_]mqtt.broker_config.Bridge{.{
        .name = &replacement_name,
        .host = &replacement_host,
        .rules = &replacement_rules,
        .reload_type = .immediate,
    }};
    try bridges.reload(&replacement);
}

test "configured bridge reload preparation rolls back allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initializeAndQueueBridgeReload,
        .{ std.testing.io, mqtt.broker_config.BridgeDirection.in },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        initializeAndQueueBridgeReload,
        .{ std.testing.io, mqtt.broker_config.BridgeDirection.out },
    );
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

    var outbound_name = "outbound-a".*;
    var local_client_id = "stable-local".*;
    const outbound = mqtt.broker_config.Bridge{
        .name = &outbound_name,
        .host = &host,
        .rules = &rules,
        .local_client_id = &local_client_id,
    };
    const outbound_id = stableOutboundId(outbound);
    outbound_name[outbound_name.len - 1] = 'b';
    try std.testing.expectEqual(outbound_id, stableOutboundId(outbound));
    local_client_id[local_client_id.len - 1] = 'x';
    try std.testing.expect(!std.mem.eql(
        u8,
        &outbound_id,
        &stableOutboundId(outbound),
    ));

    var inbound_rule = rules[0];
    inbound_rule.direction = .in;
    var outbound_rule = rules[0];
    outbound_rule.direction = .out;
    var mixed_rules = [_]mqtt.broker_config.BridgeRule{
        inbound_rule,
        outbound_rule,
    };
    const mixed = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .rules = &mixed_rules,
        .remote_client_id = &client_id,
    };
    try std.testing.expect(!std.mem.eql(
        u8,
        &stableBridgeId(source),
        &stableBridgeId(mixed),
    ));
}

test "configured bridge set owns parser configuration lifetime" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    var config = try mqtt.broker_config.parse(allocator,
        \\listener 1883
        \\allow_anonymous true
        \\connection owned-runtime
        \\address broker.example:2883 backup.example:3883
        \\topic sensors/# out 0 local/ remote/
        \\remote_username bridge-user
        \\remote_password bridge-secret
    );
    var config_owned = true;
    defer if (config_owned) config.deinit(allocator);
    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        config.bridges,
        null,
    );
    defer bridges.deinit();

    config.deinit(allocator);
    config_owned = false;
    const owned = &bridges.entryAt(0).configured;
    try std.testing.expectEqualStrings("owned-runtime", owned.name);
    try std.testing.expectEqualStrings("broker.example", owned.host);
    try std.testing.expectEqualStrings(
        "backup.example",
        owned.secondary_addresses[0].host,
    );
    try std.testing.expectEqualStrings("remote/sensors/#", owned.rules[0].filter);
    try std.testing.expectEqualStrings("bridge-user", owned.remote_username);
    try std.testing.expectEqualStrings("bridge-secret", owned.remote_password);
    try std.testing.expectEqual(
        owned,
        bridges.entryAt(0).connector_resources.connector.source,
    );
    bridges.disconnectLocalSources();
}

test "configured bridge set owns an independent cancellation domain" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    const configured: [0]mqtt.broker_config.Bridge = .{};

    var listener_shutdown: std.Io.Event = .unset;
    var listener_probe = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    listener_shutdown.set(io);
    try std.testing.expect(listener_shutdown.isSet());
    try std.testing.expect(!listener_probe.stopRequested());
    listener_probe.deinit();

    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    defer bridges.deinit();
    const untouched_listener_shutdown: std.Io.Event = .unset;
    bridges.requestStop();
    try std.testing.expect(bridges.stopRequested());
    try std.testing.expect(!untouched_listener_shutdown.isSet());
}

test "configured bridge supervisor stops without listener cancellation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    const configured: [0]mqtt.broker_config.Bridge = .{};
    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    defer bridges.deinit();

    const Task = struct {
        bridges: *Set,
        started: std.Io.Event = .unset,
        finished: std.Io.Event = .unset,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.started.set(self.bridges.io);
            self.bridges.runAll() catch |err| {
                self.err = err;
            };
            self.finished.set(self.bridges.io);
        }
    };
    var task = Task{ .bridges = &bridges };
    var future = try std.Io.concurrent(io, Task.run, .{&task});
    var joined = false;
    defer if (!joined) future.cancel(io);
    try task.started.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    try std.testing.expect(!task.finished.isSet());

    const listener_shutdown: std.Io.Event = .unset;
    bridges.requestStop();
    try task.finished.waitTimeout(io, .{ .duration = .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    } });
    future.await(io);
    joined = true;
    if (task.err) |err| return err;
    try std.testing.expect(!listener_shutdown.isSet());
}

test "configured bridge entries have independent cancellation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    var first_name = "first".*;
    var second_name = "second".*;
    var first_host = "first.example".*;
    var second_host = "second.example".*;
    var first_filter = "first/#".*;
    var second_filter = "second/#".*;
    var first_rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &first_filter,
        .qos = .at_most_once,
    }};
    var second_rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &second_filter,
        .qos = .at_most_once,
    }};
    const configured = [_]mqtt.broker_config.Bridge{
        .{
            .name = &first_name,
            .host = &first_host,
            .rules = &first_rules,
        },
        .{
            .name = &second_name,
            .host = &second_host,
            .rules = &second_rules,
        },
    };
    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    defer bridges.deinit();

    try std.testing.expect(!bridges.stopRequested());
    try std.testing.expect(!bridges.bridgeStopRequested(0));
    try std.testing.expect(!bridges.bridgeStopRequested(1));
    bridges.requestBridgeStop(0);
    try std.testing.expect(!bridges.stopRequested());
    try std.testing.expect(bridges.bridgeStopRequested(0));
    try std.testing.expect(!bridges.bridgeStopRequested(1));
}

test "configured bidirectional bridge never falls back from private mode" {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();
    var server = try mqtt.runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{},
    );
    defer server.deinit();

    const Peer = struct {
        server: *mqtt.runtime.Server,
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            var rejected = try self.server.accept(.{
                .protocol = .v3_1_1,
                .reason_code = 0x01,
            });
            defer rejected.deinit(self.server.allocator);
            try std.testing.expect(rejected.connect.connect.bridge_mode);
            var fallback = self.server.acceptWithTimeout(
                .{ .protocol = .v3_1_1 },
                .fromMilliseconds(50),
            ) catch |err| switch (err) {
                error.Timeout => return,
                else => return err,
            };
            defer fallback.deinit(self.server.allocator);
            return error.TestUnexpectedResult;
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();

    var name = "required-private".*;
    var host = "127.0.0.1".*;
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .port = server.address().ip4.port,
        .rules = &.{},
    };
    var connector = ConfiguredConnector{
        .source = &source,
        .require_private_bridge = true,
    };
    var attempt = try connector.connectAttemptMaybeBefore(
        allocator,
        io,
        .{
            .protocol = .v3_1_1,
            .client_id = "required-private",
            .bridge_mode = true,
        },
        .{},
        null,
    );
    defer attempt.deinit(allocator);
    try std.testing.expect(!attempt.accepted());
    try std.testing.expectEqual(@as(u8, 0x01), attempt.connack.connack.reason_code);
    try std.testing.expect(connector.private_bridge_supported.load(.acquire));

    thread.join();
    joined = true;
    if (peer.err) |err| return err;
}

fn testConfiguredBridgeResumesTicketOnlyForMatchingEndpoint(
    comptime protocol_policy: netz.tls.stream.VersionPolicy,
) !void {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{
        .async_limit = .unlimited,
    });
    defer threaded.deinit();
    const io = threaded.io();

    var certificate_der: [netz.tls.testing.certificate_der_len]u8 = undefined;
    try std.base64.standard.Decoder.decode(
        &certificate_der,
        netz.tls.testing.certificate_base64,
    );
    const key_pair = try netz.tls.testing.serverKeyPair();
    const public_key = key_pair.public_key.toUncompressedSec1();
    var keyring = try netz.tls.stream.Tls13TicketKeyring.init(.{
        .id = 37,
        .secret = [_]u8{0x37} ** netz.tls.stream.tls13_ticket_key_len,
    });
    defer keyring.deinit();
    var server = try mqtt.tls_runtime.Server.listen(
        allocator,
        io,
        .{ .ip4 = .loopback(0) },
        .{
            .identity = .{
                .certificate_chain = &.{&certificate_der},
                .signer = .{ .ecdsa_p256_sha256 = .{ .key_pair = key_pair } },
            },
            .protocol_policy = protocol_policy,
            .alpn_protocols = &.{"mqtt"},
            .tls12_session_tickets = if (protocol_policy == .tls12_only) .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            } else null,
            .tls13_session_tickets = if (protocol_policy == .tls13_only) .{
                .keyring = &keyring,
                .server_id = "localhost",
                .lifetime_seconds = 3600,
            } else null,
        },
    );
    defer server.deinit();

    const Peer = struct {
        server: *mqtt.tls_runtime.Server,
        resumed: [2]bool = .{ false, false },
        err: ?anyerror = null,

        fn run(self: *@This()) void {
            self.runFallible() catch |err| {
                self.err = err;
            };
        }

        fn runFallible(self: *@This()) !void {
            for (0..2) |index| {
                var accepted = try self.server.accept(.{ .protocol = .v5 });
                defer accepted.deinit(self.server.allocator);
                self.resumed[index] =
                    accepted.connection.wasTlsSessionResumed() orelse
                    return error.MissingTlsMetadata;
                var disconnect = try accepted.connection.readDisconnect();
                disconnect.deinit(self.server.allocator);
            }
        }
    };
    var peer = Peer{ .server = &server };
    const thread = try std.Thread.spawn(.{}, Peer.run, .{&peer});
    var joined = false;
    defer if (!joined) thread.join();

    var name = "tls-ticket".*;
    var host = "localhost".*;
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .port = server.address().ip4.port,
        .rules = &.{},
        .protocol = .v5,
        .try_private = false,
    };
    var connector = ConfiguredConnector{
        .source = &source,
        .tls_options = .{
            .mqtt = .{ .client_id = "placeholder" },
            .use_vail = true,
            .server_verifier = .{
                .pinned_ecdsa_p256_public_key = public_key,
            },
            .alpn_protocols = &.{"mqtt"},
            .protocol_policy = protocol_policy,
        },
    };
    var shutdown: std.Io.Event = .unset;
    var client = try mqtt.reconnect.Client.initConnector(
        allocator,
        io,
        connector.connector(),
        .{ .protocol = .v5, .client_id = "configured-ticket" },
        .{
            .initial_delay = .fromMilliseconds(1),
            .max_delay = .fromMilliseconds(1),
        },
        &shutdown,
    );
    defer client.deinit();
    _ = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(!client.connection().?.wasTlsSessionResumed().?);
    if (protocol_policy == .tls12_only) {
        const ticket = &client.tls12_session_ticket.?;
        try std.testing.expect(tls12TicketForEndpoint(
            io,
            .{ .host = "localhost", .port = source.port },
            ticket,
        ) != null);
        try std.testing.expect(tls12TicketForEndpoint(
            io,
            .{ .host = "other.example", .port = source.port },
            ticket,
        ) == null);
    } else {
        const ticket = &client.tls13_session_ticket.?;
        try std.testing.expect(tls13TicketForEndpoint(
            io,
            .{ .host = "localhost", .port = source.port },
            ticket,
        ) != null);
        try std.testing.expect(tls13TicketForEndpoint(
            io,
            .{ .host = "other.example", .port = source.port },
            ticket,
        ) == null);
    }
    try client.disconnect(0);
    _ = try client.connectWithTimeout(.fromSeconds(2));
    try std.testing.expect(client.connection().?.wasTlsSessionResumed().?);
    try client.disconnect(0);

    thread.join();
    joined = true;
    if (peer.err) |err| return err;
    try std.testing.expectEqualSlices(bool, &.{ false, true }, &peer.resumed);
}

test "configured bridge resumes TLS 1.2 ticket only for matching endpoint" {
    try testConfiguredBridgeResumesTicketOnlyForMatchingEndpoint(.tls12_only);
}

test "configured bridge resumes TLS 1.3 ticket only for matching endpoint" {
    try testConfiguredBridgeResumesTicketOnlyForMatchingEndpoint(.tls13_only);
}

test "configured bridge maps Mosquitto remote protocol limits" {
    var name = "limited".*;
    var host = "localhost".*;
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .rules = &.{},
        .protocol = .v3_1_1,
        .receive_maximum = 7,
        .max_topic_alias = 3,
        .max_packet_size = 2048,
        .outgoing_retain = false,
        .tcp_keepalive = .{
            .idle_seconds = 31,
            .interval_seconds = 11,
            .probe_count = 7,
        },
        .tcp_user_timeout_ms = 12_345,
    };
    const options = remoteConnectOptions(&source, &.{});
    try std.testing.expectEqual(mqtt.ProtocolVersion.v3_1_1, options.protocol);
    try std.testing.expect(options.bridge_mode);
    try std.testing.expectEqual(@as(?u16, 7), options.receive_maximum);
    try std.testing.expectEqual(@as(u16, 3), options.topic_alias_maximum);
    try std.testing.expectEqual(@as(u16, 3), options.max_outgoing_topic_aliases);
    try std.testing.expectEqual(@as(usize, 2048), options.max_outgoing_packet_size);
    try std.testing.expect(!options.outgoing_retain);
    try std.testing.expectEqual(
        mqtt.runtime.TcpKeepAlive{
            .idle_seconds = 31,
            .interval_seconds = 11,
            .probe_count = 7,
        },
        options.limits.tcp_keepalive.?,
    );
    try std.testing.expectEqual(
        @as(?u32, 12_345),
        options.limits.tcp_user_timeout_ms,
    );

    var unlimited = source;
    unlimited.max_packet_size = 0;
    try std.testing.expectEqual(
        std.math.maxInt(usize),
        remoteConnectOptions(&unlimited, &.{}).max_outgoing_packet_size,
    );

    var public_v311 = source;
    public_v311.try_private = false;
    try std.testing.expect(!remoteConnectOptions(&public_v311, &.{}).bridge_mode);
    var v5 = source;
    v5.protocol = .v5;
    try std.testing.expect(!remoteConnectOptions(&v5, &.{}).bridge_mode);
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

test "configured bridge rejects an empty CA directory" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "empty-cas", .default_dir);
    var name = "tls-capath-upstream".*;
    var host = "localhost".*;
    var ca_path = "empty-cas".*;
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .rules = &.{},
        .ca_path = &ca_path,
    };
    var resources: ConnectorResources = .{};
    defer resources.deinit(allocator);
    try std.testing.expectError(
        error.EmptyCertificateDirectory,
        loadTlsResources(&resources, allocator, io, tmp.dir, &source),
    );
}

test "configured bridge passes operating-system roots without a CA file" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var name = "tls-system-roots".*;
    var host = "localhost".*;
    var suites = [_]mqtt.tls_runtime.CipherSuite{
        .chacha20_poly1305_sha256,
        .aes_256_gcm_sha384,
    };
    const source = mqtt.broker_config.Bridge{
        .name = &name,
        .host = &host,
        .rules = &.{},
        .use_os_ca_certificates = true,
        .cipher_suites = &suites,
        .require_ocsp = true,
    };
    var resources: ConnectorResources = .{};
    defer resources.deinit(allocator);
    try loadTlsResources(
        &resources,
        allocator,
        io,
        std.Io.Dir.cwd(),
        &source,
    );
    try std.testing.expect(
        resources.connector.tls_options.?.tls.ca_bundle != null,
    );
    try std.testing.expectEqualSlices(
        mqtt.tls_runtime.CipherSuite,
        &suites,
        resources.connector.tls_options.?.cipher_suites,
    );
    try std.testing.expectEqual(
        mqtt.tls_runtime.StapledOcspPolicy.require,
        resources.connector.tls_options.?.stapled_ocsp,
    );
}

test "configured bridges use Mosquitto decorrelated restart state" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    var name = "jittered".*;
    var host = "localhost".*;
    var filter = "out/#".*;
    var rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &filter,
        .qos = .at_least_once,
        .direction = .out,
    }};
    const configured = [_]mqtt.broker_config.Bridge{.{
        .name = &name,
        .host = &host,
        .rules = &rules,
        .restart = .{
            .base_seconds = 2,
            .cap_seconds = 9,
            .jitter = true,
            .stable_connection_seconds = 11,
        },
    }};
    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    defer bridges.deinit();
    const policy = bridges.entryAt(0).value.outbound.target.policy;
    try std.testing.expectEqual(mqtt.reconnect.Jitter.decorrelated, policy.jitter);
    try std.testing.expect(policy.delay_after_disconnect);
    try std.testing.expectEqual(
        @as(i96, 11 * std.time.ns_per_s),
        policy.stable_connection_period.nanoseconds,
    );
}

test "configured outbound bridge maps local clean Session policy" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    var name = "local-clean".*;
    var local_client_id = "configured-local-clean".*;
    var host = "localhost".*;
    var filter = "out/#".*;
    var rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &filter,
        .qos = .at_most_once,
        .direction = .out,
    }};
    const configured = [_]mqtt.broker_config.Bridge{.{
        .name = &name,
        .host = &host,
        .rules = &rules,
        .local_clean_session = true,
        .local_client_id = &local_client_id,
    }};
    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    defer bridges.deinit();
    const bridge = &bridges.entryAt(0).value.outbound;
    try std.testing.expect(bridge.source.clean_session);
    try std.testing.expectEqualStrings(
        "configured-local-clean",
        bridge.source.client_id,
    );
    try std.testing.expect(bridge.source.isConnected());
    bridges.disconnectLocalSources();
    try std.testing.expect(!bridge.source.isConnected());
}

test "configured bidirectional bridge shares one private remote client" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var broker = try mqtt.broker.Broker.init(allocator, io, .{});
    defer broker.deinit();
    var name = "duplex".*;
    var host = "localhost".*;
    var filter = "remote/#".*;
    var local_prefix = "local/".*;
    var remote_prefix = "remote/".*;
    var rules = [_]mqtt.broker_config.BridgeRule{.{
        .filter = &filter,
        .qos = .at_most_once,
        .local_prefix = &local_prefix,
        .remote_prefix = &remote_prefix,
        .direction = .both,
    }};
    const configured = [_]mqtt.broker_config.Bridge{.{
        .name = &name,
        .host = &host,
        .rules = &rules,
        .clean_session = false,
        .local_clean_session = false,
        .try_private = true,
    }};
    var bridges = try Set.init(
        allocator,
        io,
        &broker,
        &configured,
        null,
    );
    defer bridges.deinit();

    const bridge = &bridges.entryAt(0).value.outbound;
    try std.testing.expectEqual(@as(usize, 1), bridge.rules.values.len);
    try std.testing.expect(bridge.rules.values[0].value.no_local);
    try std.testing.expectEqual(
        @as(usize, 1),
        bridge.inbound_rules.values.len,
    );
    try std.testing.expect(!bridge.inbound_rules.values[0].no_local);
    try std.testing.expect(bridge.target.options.value.bridge_mode);
    try std.testing.expect(
        bridges.entryAt(0).connector_resources.connector.require_private_bridge,
    );
}

//! Shared managed ADS fixture and real LRS peer for automatic binding tests.
const std = @import("std");
const grpc = @import("../../../mod.zig");
const runtime = @import("../../runtime.zig");
const ads = @import("../../ads.zig");
const delta = @import("../../ads/delta.zig");
const bootstrap = @import("../../bootstrap.zig");
const control_plane = @import("../../control_plane.zig");
const lds = @import("../../lds.zig");
const cds = @import("../../cds.zig");
const lrs = @import("../../lrs.zig");
const stats = @import("../../../channel/shared/lrs_stats.zig");
const fixture = @import("../../cds/testing.zig");
const gpa = std.testing.allocator;
pub const Mode = enum { sotw, delta };
const node: ads.codec.Node = .{ .id = "automatic-node" };
pub const self_lrs = "\xd2\x02\x02\x2a\x00";

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
}
pub fn wait(io: std.Io, event: *std.Io.Event) !void {
    try event.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromSeconds(5) } });
}
pub fn noConnection(io: std.Io, event: *std.Io.Event) !void {
    try std.testing.expectError(error.Timeout, event.waitTimeout(io, .{ .duration = .{ .clock = .awake, .raw = .fromMilliseconds(150) } }));
}
pub fn configuration(server: *grpc.runtime.Server) !*bootstrap.Bootstrap {
    const json = try std.fmt.allocPrint(gpa, "{{\"xds_servers\":[{{\"server_uri\":\"http://127.0.0.1:{d}\",\"channel_creds\":[{{\"type\":\"insecure\"}}]}}],\"node\":{{\"id\":\"bootstrap-node\"}}}}", .{server.address().getPort()});
    defer gpa.free(json);
    return bootstrap.parse(gpa, json, .{});
}

pub const Counts = struct { issued: u64 = 0, successful: u64 = 0, failed: u64 = 0, dropped: u64 = 0 };
pub const Observed = struct {
    const Phase = enum { accepting, opening, initial_request, response, reports, shutdown };
    pub const Metrics = struct { in_progress: u64 = 0, cpu_count: u64 = 0, cpu_sum: f64 = 0 };
    io: std.Io,
    category: []const u8,
    endpoint_port: u16 = 1001,
    scenario: []const u8 = "unknown",
    mode: []const u8 = "unknown",
    mutex: std.Io.Mutex = .init,
    counts: Counts = .{},
    metrics: Metrics = .{},
    failure: ?anyerror = null,
    phase: Phase = .accepting,
    initial_requests: usize = 0,
    report_requests: usize = 0,
    events: usize = 0,
    last_event: []const u8 = "none",
    expected_close: ?Counts = null,
    connected: std.Io.Event = .unset,
    completed: [5]std.Io.Event = .{ .unset, .unset, .unset, .unset, .unset },
    dropped: [3]std.Io.Event = .{ .unset, .unset, .unset },

    fn fail(self: *@This(), err: anyerror) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.failure = err;
        self.traceLocked("failed", err);
        self.connected.set(self.io);
        for (&self.completed) |*event| event.set(self.io);
        for (&self.dropped) |*event| event.set(self.io);
    }
    fn traceLocked(self: *@This(), action: []const u8, err: anyerror) void {
        std.debug.print("automatic LRS peer {s}/{s}/{s}: {s} error={s} phase={s} initial={d} reports={d} events={d} last={s} closing={} counts={any}\n", .{ self.scenario, self.mode, self.category, action, @errorName(err), @tagName(self.phase), self.initial_requests, self.report_requests, self.events, self.last_event, self.expected_close != null, self.counts });
    }
    pub fn diagnose(self: *@This(), action: []const u8, err: anyerror) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.traceLocked(action, err);
        std.debug.print("  observed failure={s} metrics={any}\n", .{ if (self.failure) |failure| @errorName(failure) else "none", self.metrics });
    }
    fn enter(self: *@This(), phase: Phase) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.expected_close == null) self.phase = phase;
    }
    fn traceEvent(self: *@This(), value: anytype) void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.events += 1;
        self.last_event = @tagName(value);
    }
    pub fn expectClose(self: *@This(), expected: Counts) !void {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failure) |err| return err;
        try std.testing.expectEqual(expected, self.counts);
        self.expected_close = expected;
        self.phase = .shutdown;
    }
    fn transportClosed(self: *@This(), err: anyerror) bool {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        const expected = self.expected_close orelse return false;
        if (!std.meta.eql(expected, self.counts)) return false;
        self.traceLocked("expected transport close", err);
        return true;
    }
    pub fn awaitPeer(self: *@This(), task: anytype) !void {
        task.await(self.io) catch |err| {
            self.mutex.lockUncancelable(self.io);
            self.traceLocked("await", err);
            self.mutex.unlock(self.io);
            return @as(@TypeOf(err)!void, err);
        };
        const actual = try self.check();
        if (self.expected_close) |expected| try std.testing.expectEqual(expected, actual);
    }
    pub fn check(self: *@This()) !Counts {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failure) |err| return err;
        return self.counts;
    }
    pub fn metricSnapshot(self: *@This()) !Metrics {
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.failure) |err| return err;
        return self.metrics;
    }
    pub fn awaitCounts(self: *@This(), completed: usize, dropped: usize) !Counts {
        if (completed != 0) try wait(self.io, &self.completed[completed - 1]);
        if (dropped != 0) try wait(self.io, &self.dropped[dropped - 1]);
        return self.check();
    }
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        var request = try lrs.codec.decodeRequest(gpa, message.payload, .{});
        defer request.deinit();
        try std.testing.expect(request.value.node == null);
        var delta_counts: Counts = .{};
        var delta_metrics: Metrics = .{};
        for (request.value.clusters) |cluster| {
            try std.testing.expectEqualStrings("a", cluster.name);
            try std.testing.expectEqualStrings("eds-a", cluster.service_name);
            try std.testing.expect(cluster.interval_ns != 0);
            try std.testing.expectEqual(@as(usize, 1), cluster.localities.len);
            const locality = cluster.localities[0];
            delta_metrics.in_progress += locality.in_progress;
            if (locality.cpu_utilization) |cpu| {
                delta_metrics.cpu_count += cpu.count;
                delta_metrics.cpu_sum += cpu.value;
            }
            delta_counts.issued += locality.issued;
            delta_counts.successful += locality.successful;
            delta_counts.failed += locality.error_requests;
            delta_counts.dropped += cluster.total_dropped;
            if (locality.issued != 0 or locality.successful != 0 or locality.error_requests != 0) {
                try std.testing.expectEqual(@as(usize, 1), locality.endpoints.len);
                const endpoint = locality.endpoints[0];
                try std.testing.expectEqual(self.endpoint_port, endpoint.port);
                try std.testing.expectEqual(locality.issued, endpoint.issued);
                try std.testing.expectEqual(locality.successful, endpoint.successful);
                try std.testing.expectEqual(locality.error_requests, endpoint.error_requests);
            }
            var dropped: u64 = 0;
            for (cluster.dropped) |category| {
                try std.testing.expectEqualStrings(self.category, category.category);
                dropped += category.count;
            }
            try std.testing.expectEqual(cluster.total_dropped, dropped);
        }
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        self.report_requests += 1;
        self.metrics.in_progress = delta_metrics.in_progress;
        self.metrics.cpu_count += delta_metrics.cpu_count;
        self.metrics.cpu_sum += delta_metrics.cpu_sum;
        self.counts.issued += delta_counts.issued;
        self.counts.successful += delta_counts.successful;
        self.counts.failed += delta_counts.failed;
        self.counts.dropped += delta_counts.dropped;
        for (&self.completed, 1..) |*event, threshold| if (self.counts.successful + self.counts.failed >= threshold) event.set(self.io);
        for (&self.dropped, 1..) |*event, threshold| if (self.counts.dropped >= threshold) event.set(self.io);
    }
};

const Initial = struct {
    request: ?lrs.codec.OwnedRequest = null,
    fn consume(self: *@This(), message: grpc.StreamingMessage) !void {
        if (self.request != null) return error.UnexpectedRequest;
        self.request = try lrs.codec.decodeRequest(gpa, message.payload, .{});
    }
};
pub const Peer = struct {
    pub fn run(listener: *grpc.runtime.Server, observed: *Observed) !void {
        errdefer |err| observed.fail(err);
        const until = std.Io.Clock.Timestamp.fromNow(observed.io, .{ .clock = .awake, .raw = .fromSeconds(10) });
        while (true) {
            observed.enter(.accepting);
            var connection = listener.acceptWithDeadline(until) catch |err| switch (err) {
                error.ConnectionClosed, error.UnexpectedEof, error.ConnectionResetByPeer, error.SocketUnconnected => continue,
                else => return @as(@TypeOf(err)!void, err),
            };
            defer connection.deinit();
            if (try runConnection(&connection, observed)) return;
        }
    }

    fn runConnection(connection: *grpc.runtime.ServerConnection, observed: *Observed) !bool {
        observed.enter(.opening);
        var duplex = connection.acceptDuplexWithTimeout(.fromSeconds(5)) catch |err| switch (err) {
            error.ConnectionClosed, error.UnexpectedEof, error.ConnectionResetByPeer, error.SocketUnconnected => return false,
            else => return err,
        };
        defer duplex.deinit();
        observed.enter(.initial_request);
        try std.testing.expectEqualStrings(lrs.path, duplex.transport.path);
        var initial: Initial = .{};
        defer if (initial.request) |*value| value.deinit();
        while (initial.request == null) {
            var event = duplex.readRequestEventWithTimeout(.fromSeconds(5), &initial, Initial.consume) catch |err| switch (err) {
                error.ConnectionClosed, error.UnexpectedEof, error.ConnectionResetByPeer, error.SocketUnconnected => return false,
                else => return err,
            };
            defer event.deinit();
            observed.traceEvent(event);
            if (event == .finished or event == .reset) return false;
        }
        try std.testing.expectEqual(@as(usize, 0), initial.request.?.value.clusters.len);
        try std.testing.expect(initial.request.?.value.node != null);
        const encoded_node = try ads.codec.encodeNode(gpa, .{ .id = node.id, .client_features = &.{"envoy.lrs.supports_send_all_clusters"} });
        defer gpa.free(encoded_node);
        try std.testing.expectEqualSlices(u8, encoded_node, initial.request.?.value.node.?);
        observed.mutex.lockUncancelable(observed.io);
        observed.initial_requests += 1;
        observed.mutex.unlock(observed.io);
        observed.enter(.response);
        try duplex.startResponse(.{});
        const response = try lrs.codec.encodeResponse(gpa, .{ .send_all_clusters = true, .report_endpoint_granularity = true, .interval_ns = 30 * std.time.ns_per_ms }, .{});
        defer gpa.free(response);
        try std.testing.expectEqual(grpc.DuplexWriteResult.complete, try duplex.writeMessage(response));
        observed.connected.set(observed.io);
        while (true) {
            observed.enter(.reports);
            var event = duplex.readRequestEventWithTimeout(.fromSeconds(5), observed, Observed.consume) catch |err| switch (err) {
                error.ConnectionClosed, error.UnexpectedEof, error.ConnectionResetByPeer, error.SocketUnconnected => {
                    if (observed.transportClosed(err)) return true;
                    return err;
                },
                else => return err,
            };
            defer event.deinit();
            observed.traceEvent(event);
            if (event == .finished or event == .reset) return true;
        }
    }
};

pub fn Harness(comptime mode: Mode) type {
    return struct {
        const Self = @This();
        const Client = if (mode == .sotw) ads.Client else delta.Client;
        const Update = if (mode == .sotw) ads.Update else delta.Update;
        io: std.Io,
        channel: grpc.SharedChannel,
        client: Client,
        controller: *runtime.Controller,

        pub fn init(io: std.Io, plane: *control_plane.ControlPlane, channel_allocator: std.mem.Allocator, disabled: bool, manual: bool) !Self {
            return initLimited(io, plane, channel_allocator, disabled, manual, 64);
        }
        pub fn initLimited(io: std.Io, plane: *control_plane.ControlPlane, channel_allocator: std.mem.Allocator, disabled: bool, manual: bool, max_sources: usize) !Self {
            var channel = try grpc.SharedChannel.init(channel_allocator, io, .{ .cleartext_ip = .{ .address = .{ .ip4 = .loopback(1) } } }, .{});
            errdefer channel.deinit();
            var sender = plane.sender();
            defer sender.deinit();
            var client = if (manual) try Client.init(gpa, sender, .{ .node = node }) else if (mode == .sotw) try plane.newSotwClient(.{ .node = node }) else try plane.newDeltaClient(.{ .node = node });
            errdefer client.deinit();
            const controller = try runtime.Controller.create(gpa, .{
                .listener_name = "frontend",
                .target = .{ .authority = "backend.test" },
                .disable_automatic_lrs = disabled,
                .automatic_lrs = .{ .reporter = .{ .interval_ns = 30 * std.time.ns_per_ms }, .poll_interval = .fromMilliseconds(50), .connect_timeout = .fromSeconds(1) },
                .limits = .{ .max_lrs_sources = max_sources },
            });
            errdefer controller.deinit();
            if (mode == .sotw) _ = try controller.startWithDeadline(&client, channel, deadline(io)) else _ = try controller.startDeltaWithDeadline(&client, channel, deadline(io));
            try std.testing.expect(channel.state.lrs_stats.allocator == null);
            return .{ .io = io, .channel = channel, .client = client, .controller = controller };
        }
        pub fn deinit(self: *Self) void {
            self.controller.deinit();
            self.client.deinit();
            self.channel.deinit();
        }
        pub fn update(self: *Self, url: []const u8, name: []const u8, version: []const u8, bytes: ?[]const u8) !Update {
            const encoded = if (mode == .sotw)
                try ads.codec.encodeResponse(gpa, .{ .type_url = url, .version = version, .nonce = version, .resources = if (bytes) |value| &.{.{ .type_url = url, .value = value }} else &.{} }, 65536)
            else
                try delta.codec.encodeResponse(gpa, .{ .type_url = url, .nonce = version, .resources = if (bytes) |value| &.{.{ .name = name, .version = version, .resource = .{ .type_url = url, .value = value } }} else &.{}, .removed = if (bytes == null) &.{name} else &.{} }, .{});
            defer gpa.free(encoded);
            var response = if (mode == .sotw) try ads.codec.decodeResponse(gpa, encoded, .{}) else try delta.codec.decodeResponse(gpa, encoded, .{});
            errdefer response.deinit();
            return .{ .response = response, .token = try self.client.subscriptions.received(response.value), .source = if (self.client.source) |source| source.retain() else null };
        }
        pub fn apply(self: *Self, value: Update) !u64 {
            return self.applyUntil(value, deadline(self.io));
        }
        pub fn applyUntil(self: *Self, value: Update, until: std.Io.Clock.Timestamp) !u64 {
            return if (mode == .sotw) self.controller.applyWithDeadline(&self.client, value, self.channel, until) else self.controller.applyDeltaWithDeadline(&self.client, value, self.channel, until);
        }
        pub fn cdsVersion(self: *Self) ?[]const u8 {
            return if (mode == .sotw) self.client.acceptedVersion(cds.type_url) else self.client.acceptedVersion(cds.type_url, "a");
        }
        pub fn cdsAcceptedNs(self: *Self) i128 {
            const entry = self.client.subscriptions.find(cds.type_url) orelse return 0;
            if (mode == .sotw) {
                return entry.accepted_ns;
            } else {
                for (entry.versions) |version| if (std.mem.eql(u8, version.name, "a")) return version.accepted_ns;
                return 0;
            }
        }
        pub fn accept(self: *Self, url: []const u8, name: []const u8, version: []const u8, bytes: ?[]const u8) !void {
            var value = try self.update(url, name, version, bytes);
            defer value.deinit();
            try std.testing.expectError(error.AdsNotConnected, self.apply(value));
        }
        pub fn discover(self: *Self) !void {
            const routes = try @import("../../rds/testing.zig").encode(gpa, "inline", &.{"backend.test"}, &.{.{ .prefix = "/", .cluster = "a" }}, null);
            defer gpa.free(routes);
            const listener = try @import("../../lds/testing.zig").encode(gpa, .{ .inline_rds = routes });
            defer gpa.free(listener);
            try self.accept(lds.type_url, "frontend", "l1", listener);
        }
        pub fn setCds(self: *Self, version: []const u8, enabled: bool) !void {
            const bytes = try fixture.cluster(gpa, "a", "eds-a", if (enabled) self_lrs else "");
            defer gpa.free(bytes);
            try self.accept(cds.type_url, "a", version, bytes);
        }
        pub fn begin(self: *Self) !stats.Registration {
            return self.channel.state.lrs_stats.begin(self.io, "a", "eds-a", .{ .ip4 = .loopback(1001) }) orelse error.CollectionDisabled;
        }
        pub fn complete(self: *Self, registration: stats.Registration, success: bool) void {
            self.channel.state.lrs_stats.complete(self.io, registration, .{ .ip4 = .loopback(1001) }, success);
        }
        pub fn call(self: *Self, success: bool, category: []const u8) !void {
            const registration = try self.begin();
            defer registration.release();
            self.complete(registration, success);
            self.channel.state.lrs_stats.recordDropped(self.io, "a", "eds-a", category);
        }
        pub fn expectDisabled(self: *Self) !void {
            const registration = self.channel.state.lrs_stats.begin(self.io, "a", "eds-a", null);
            defer if (registration) |value| value.release();
            try std.testing.expect(registration == null);
            self.channel.state.lrs_stats.recordDropped(self.io, "a", "eds-a", "disabled");
        }
        pub fn rebind(self: *Self, plane: *control_plane.ControlPlane) !void {
            var next = if (mode == .sotw) try plane.newSotwClient(.{ .node = node }) else try plane.newDeltaClient(.{ .node = node });
            defer next.deinit();
            var sender = next.sender.clone();
            errdefer sender.deinit();
            try self.client.rebindWithSource(sender, next.request, next.source);
        }
    };
}

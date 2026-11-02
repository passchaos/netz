//! Single-caller ADS session over a background-owned gRPC SharedChannel.
const std = @import("std");
const shared = @import("../../channel/shared.zig");
const streaming = @import("../../stream/runtime.zig");
const duplex_response = @import("../../stream/duplex.zig").Response;
const deadline_policy = @import("../../../internal/deadline.zig");
const codec = @import("codec.zig");
const subscriptions = @import("subscriptions.zig");
pub const path = "/envoy.service.discovery.v3.AggregatedDiscoveryService/StreamAggregatedResources";
pub const Error = shared.Error || subscriptions.Error || error{ AdsNotConnected, InvalidAdsOptions };
pub const Options = struct {
    node: codec.Node,
    subscriptions: subscriptions.Options = .{},
    limits: codec.Limits = .{},
    request: streaming.RequestOptions = .{ .path = path, .wait_for_ready = true },
};
pub const Update = struct {
    response: codec.OwnedResponse,
    token: subscriptions.Token,
    pub fn deinit(self: *Update) void {
        self.response.deinit();
        self.* = undefined;
    }
    pub fn resourcesMatchType(self: Update) bool {
        for (self.response.value.resources) |resource| if (!std.mem.eql(u8, resource.type_url, self.response.value.type_url)) return false;
        return true;
    }
};
pub const Event = union(enum) {
    update: Update,
    terminal: duplex_response,
    pub fn deinit(self: *Event) void {
        switch (self.*) {
            .update => |*value| value.deinit(),
            .terminal => |*value| value.deinit(),
        }
        self.* = undefined;
    }
};
pub const Client = struct {
    allocator: std.mem.Allocator,
    sender: shared.Sender,
    inputs: @import("../../channel/shared/request_inputs.zig").Inputs,
    request: streaming.RequestOptions,
    node: []u8,
    limits: codec.Limits,
    subscriptions: subscriptions.State,
    stream: ?shared.Duplex = null,
    node_sent: bool = false,
    pub fn init(gpa: std.mem.Allocator, sender: shared.Sender, options: Options) Error!Client {
        if (options.subscriptions.max_types == 0 or options.subscriptions.max_names_per_type == 0 or options.subscriptions.max_name_bytes == 0 or options.limits.max_message_bytes == 0 or options.limits.max_resources == 0 or options.limits.max_resource_bytes > options.limits.max_message_bytes) return error.InvalidAdsOptions;
        const node = try codec.encodeNode(gpa, options.node);
        errdefer gpa.free(node);
        if (node.len > options.limits.max_message_bytes) return error.DiscoveryLimitExceeded;
        var request = options.request;
        request.path = path;
        request.max_message_size = @min(request.max_message_size, options.limits.max_message_bytes);
        var owned = try @import("../../channel/shared/request_inputs.zig").clone(gpa, request);
        errdefer owned.inputs.deinit();
        return .{ .allocator = gpa, .sender = sender.clone(), .inputs = owned.inputs, .request = owned.options, .node = node, .limits = options.limits, .subscriptions = .{ .allocator = gpa, .options = options.subscriptions } };
    }
    pub fn deinit(self: *Client) void {
        self.disconnect();
        self.subscriptions.deinit();
        self.allocator.free(self.node);
        self.inputs.deinit();
        self.sender.deinit();
        self.* = undefined;
    }
    pub fn disconnect(self: *Client) void {
        if (self.stream) |*value| value.deinit();
        self.stream = null;
        self.node_sent = false;
        self.subscriptions.resetStream();
    }
    pub fn setSubscription(self: *Client, type_url: []const u8, names: []const []const u8) Error!void {
        try self.subscriptions.set(type_url, names);
    }
    pub fn acceptedVersion(self: *Client, type_url: []const u8) ?[]const u8 {
        return if (self.subscriptions.find(type_url)) |entry| entry.version else null;
    }
    pub fn connectWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        if (self.stream == null) {
            self.stream = try self.sender.startDuplexWithDeadline(self.request, deadline);
            self.node_sent = false;
        }
        _ = try self.flushWithDeadline(deadline);
    }
    pub fn connectWithTimeout(self: *Client, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(.fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    fn send(self: *Client, entry: *subscriptions.Entry, deadline: std.Io.Clock.Timestamp) Error!void {
        const stream = self.stream orelse return error.AdsNotConnected;
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        try self.sender.state.io.checkCancel();
        const bytes = try codec.encodeRequest(self.allocator, .{ .version = entry.version, .node = if (self.node_sent) null else self.node, .type_url = entry.type_url, .names = entry.names, .nonce = entry.nonce, .nack = entry.nack }, self.limits.max_message_bytes);
        defer self.allocator.free(bytes);
        var writer = stream.writer();
        defer writer.deinit();
        writer.writeMessageWithDeadline(bytes, deadline) catch |err| {
            // A write may have submitted a prefix. A new stream replays desired
            // names and accepted versions, rather than duplicating that write.
            self.disconnect();
            return err;
        };
        self.node_sent = true;
        entry.dirty = false;
    }
    /// Coalesce desired updates. Responses awaiting an application decision
    /// defer only their own type; other types retain independent progress.
    pub fn flushWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!usize {
        if (self.stream == null) return error.AdsNotConnected;
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        var count: usize = 0;
        for (self.subscriptions.entries.items) |*entry| {
            if (!entry.dirty or entry.pending_sequence != null) continue;
            try self.send(entry, deadline);
            count += 1;
        }
        return count;
    }
    pub fn flushWithTimeout(self: *Client, timeout: std.Io.Duration) Error!usize {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.flushWithDeadline(.fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn acknowledgeWithTimeout(self: *Client, update: Update, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.acknowledgeWithDeadline(update, .fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn rejectWithTimeout(self: *Client, update: Update, nack: codec.Nack, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectWithDeadline(update, nack, .fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Validate before applying a candidate resource snapshot. A serialized
    /// caller can then mark acceptance immediately after actual publication.
    pub fn validateUpdate(self: *Client, update: Update) Error!void {
        if (!update.resourcesMatchType()) return error.InvalidDiscoveryMessage;
        try self.subscriptions.validateToken(update.response.value.type_url, update.token);
    }
    pub fn acceptAppliedUpdate(self: *Client, update: Update) Error!void {
        try self.validateUpdate(update);
        _ = try self.subscriptions.decide(update.response.value.type_url, update.token, null);
    }
    pub fn acknowledgeWithDeadline(self: *Client, update: Update, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        try self.sender.state.io.checkCancel();
        if (!update.resourcesMatchType()) return error.InvalidDiscoveryMessage;
        const entry = try self.subscriptions.decide(update.response.value.type_url, update.token, null);
        try self.send(entry, deadline);
    }
    pub fn rejectWithDeadline(self: *Client, update: Update, nack: codec.Nack, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        try self.sender.state.io.checkCancel();
        if (nack.message.len > self.limits.max_message_bytes) return error.DiscoveryLimitExceeded;
        const entry = try self.subscriptions.decide(update.response.value.type_url, update.token, nack);
        try self.send(entry, deadline);
    }
    pub fn nextWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!Event {
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        const stream = self.stream orelse return error.AdsNotConnected;
        var reader = stream.reader();
        defer reader.deinit();
        while (true) {
            var event = reader.nextWithDeadline(deadline) catch |err| {
                const rpc_expired = if (stream.call.deadline) |until| until.durationFromNow(self.sender.state.io).raw.nanoseconds <= 0 else false;
                if (rpc_expired or (err != error.Timeout and err != error.Canceled and err != error.ConcurrencyUnavailable)) self.disconnect();
                return err;
            };
            var event_owned = true;
            defer if (event_owned) event.deinit(self.sender.state.allocator);
            switch (event) {
                .message => |message| {
                    var response = codec.decodeResponse(self.allocator, message.payload, self.limits) catch |err| {
                        self.disconnect();
                        return err;
                    };
                    const token = self.subscriptions.received(response.value) catch |err| {
                        response.deinit();
                        self.disconnect();
                        return err;
                    };
                    return .{ .update = .{ .response = response, .token = token } };
                },
                .terminal => |terminal| {
                    const owned = terminal;
                    event_owned = false;
                    self.disconnect();
                    return .{ .terminal = owned };
                },
                else => {},
            }
        }
    }
    pub fn nextWithTimeout(self: *Client, timeout: std.Io.Duration) Error!Event {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.nextWithDeadline(.fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
};

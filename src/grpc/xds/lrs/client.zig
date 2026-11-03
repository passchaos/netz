//! Single-caller Load Reporting Service session over a background-owned channel.
const std = @import("std");
const shared = @import("../../channel/shared.zig");
const streaming = @import("../../stream/runtime.zig");
const duplex_response = @import("../../stream/duplex.zig").Response;
const deadline_policy = @import("../../../internal/deadline.zig");
const ads = @import("../ads.zig");
const codec = @import("codec.zig");
pub const path = "/envoy.service.load_stats.v3.LoadReportingService/StreamLoadStats";
pub const Error = shared.Error || codec.Error || ads.codec.Error || error{ LrsNotConnected, InvalidLrsOptions };
pub const Options = struct {
    node: ads.codec.Node,
    limits: codec.Limits = .{},
    request: streaming.RequestOptions = .{ .path = path, .wait_for_ready = true },
};
pub const Event = union(enum) {
    response: codec.OwnedResponse,
    terminal: duplex_response,
    pub fn deinit(self: *Event) void {
        switch (self.*) {
            .response => |*value| value.deinit(),
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
    stream: ?shared.Duplex = null,
    node_sent: bool = false,
    send_all_clusters_supported: bool = false,

    pub fn init(gpa: std.mem.Allocator, sender: shared.Sender, options: Options) Error!Client {
        if (options.limits.max_message_bytes == 0 or options.limits.max_clusters == 0 or options.limits.max_localities == 0 or options.limits.max_dropped == 0 or options.limits.max_text_bytes == 0) return error.InvalidLrsOptions;
        const node = try ads.codec.encodeNode(gpa, options.node);
        errdefer gpa.free(node);
        if (node.len > options.limits.max_message_bytes) return error.LoadReportLimitExceeded;
        var request = options.request;
        request.path = path;
        request.max_message_size = @min(request.max_message_size, options.limits.max_message_bytes);
        var owned = try @import("../../channel/shared/request_inputs.zig").clone(gpa, request);
        errdefer owned.inputs.deinit();
        var send_all_clusters_supported = false;
        for (options.node.client_features) |feature| {
            if (std.mem.eql(u8, feature, "envoy.lrs.supports_send_all_clusters")) send_all_clusters_supported = true;
        }
        return .{ .allocator = gpa, .sender = sender.clone(), .inputs = owned.inputs, .request = owned.options, .node = node, .limits = options.limits, .send_all_clusters_supported = send_all_clusters_supported };
    }
    pub fn deinit(self: *Client) void {
        self.disconnect();
        self.allocator.free(self.node);
        self.inputs.deinit();
        self.sender.deinit();
        self.* = undefined;
    }
    pub fn supportsSendAllClusters(self: Client) bool {
        return self.send_all_clusters_supported;
    }
    pub fn disconnect(self: *Client) void {
        if (self.stream) |*value| value.deinit();
        self.stream = null;
        self.node_sent = false;
    }
    /// Move the client to another channel while retaining the encoded node.
    /// Ownership of `sender` transfers to the client.
    pub fn rebind(self: *Client, sender: shared.Sender, request: streaming.RequestOptions) Error!void {
        var owned_request = request;
        owned_request.path = path;
        owned_request.max_message_size = @min(owned_request.max_message_size, self.limits.max_message_bytes);
        var owned = try @import("../../channel/shared/request_inputs.zig").clone(self.allocator, owned_request);
        errdefer owned.inputs.deinit();
        self.disconnect();
        self.inputs.deinit();
        self.sender.deinit();
        self.inputs = owned.inputs;
        self.request = owned.options;
        self.sender = sender;
    }
    fn send(self: *Client, request: codec.Request, deadline: std.Io.Clock.Timestamp) Error!void {
        const stream = self.stream orelse return error.LrsNotConnected;
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        try self.sender.state.io.checkCancel();
        const bytes = try codec.encodeRequest(self.allocator, request, self.limits);
        defer self.allocator.free(bytes);
        var writer = stream.writer();
        defer writer.deinit();
        writer.writeMessageWithDeadline(bytes, deadline) catch |err| {
            self.disconnect();
            return err;
        };
        self.node_sent = true;
    }
    pub fn connectWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!void {
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        if (self.stream == null) {
            self.stream = try self.sender.startDuplexWithDeadline(self.request, deadline);
            self.node_sent = false;
        }
        try self.send(.{ .node = if (self.node_sent) null else self.node }, deadline);
    }
    pub fn connectWithTimeout(self: *Client, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.connectWithDeadline(.fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    /// Report accumulated stats. The node is sent only on the first request of
    /// each stream.
    pub fn reportWithDeadline(self: *Client, clusters: []const codec.ClusterStats, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.send(.{ .node = if (self.node_sent) null else self.node, .clusters = clusters }, deadline);
    }
    pub fn reportWithTimeout(self: *Client, clusters: []const codec.ClusterStats, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.reportWithDeadline(clusters, .fromNow(self.sender.state.io, .{ .clock = .awake, .raw = timeout }));
    }
    pub fn nextWithDeadline(self: *Client, deadline: std.Io.Clock.Timestamp) Error!Event {
        _ = try deadline_policy.usableAwake(self.sender.state.io, deadline);
        const stream = self.stream orelse return error.LrsNotConnected;
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
                    const response = codec.decodeResponse(self.allocator, message.payload, self.limits) catch |err| {
                        self.disconnect();
                        return err;
                    };
                    return .{ .response = response };
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

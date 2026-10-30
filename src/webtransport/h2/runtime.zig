//! TLS HTTP/2 Extended CONNECT admission for capsule-based WebTransport.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");
const model = @import("state.zig");
const session_mod = @import("session.zig");
const init_header = @import("init_header.zig");
const protocol = @import("../application_protocol.zig");
const origin_policy = @import("../runtime/connect/headers.zig");
pub const Error = session_mod.Error || init_header.Error || protocol.Error || error{ WebTransportDisabled, InvalidOrigin, InvalidConnect, SessionRejected };
pub const Session = session_mod.Session;
pub const ClientOptions = struct {
    path: []const u8,
    authority: []const u8,
    origin: ?[]const u8 = null,
    headers: []const http2.Hpack.HeaderField = &.{},
    initial_receive_stream_data: ?init_header.InitialStreamDataLimits = null,
    protocols: protocol.Policy = .{},
    session: session_mod.Options = .{},
};
pub const ServerOptions = struct {
    origin: origin_policy.OriginPolicy = .same_origin_or_absent,
    protocols: protocol.Policy = .{},
    headers: []const http2.Hpack.HeaderField = &.{},
    initial_receive_stream_data: ?init_header.InitialStreamDataLimits = null,
    session: session_mod.Options = .{},
};
pub const RejectOptions = struct {
    status: u16,
    headers: []const http2.Hpack.HeaderField = &.{},
    body: []const u8 = &.{},
    trailers: []const http2.Hpack.HeaderField = &.{},
};

pub const Rejection = struct {
    response: ?http2.runtime.ExtendedConnectAttempt = null,
    duplex: ?DuplexRejectedResponse = null,
    allocator: std.mem.Allocator,

    pub fn status(self: Rejection) u16 {
        if (self.response) |response| return response.status;
        return self.duplex.?.head.status;
    }
    pub fn responseHeader(self: Rejection, name: []const u8) ?[]const u8 {
        if (self.response) |response| return response.responseHeader(name);
        for (self.duplex.?.head.headers) |header| if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        return null;
    }
    pub fn body(self: Rejection) []const u8 {
        if (self.response) |response| return response.body;
        return self.duplex.?.body;
    }
    pub fn trailers(self: Rejection) []const http2.Hpack.HeaderField {
        if (self.response) |response| return response.trailers;
        return self.duplex.?.trailers;
    }
    pub fn deinit(self: *Rejection) void {
        if (self.response) |*response| response.deinit(self.allocator);
        if (self.duplex) |*duplex| duplex.deinit(self.allocator);
        self.* = undefined;
    }
};

const DuplexRejectedResponse = struct {
    head: http2.runtime.DuplexResponseHead,
    body: []u8,
    trailers: []http2.Hpack.HeaderField,

    fn deinit(self: *DuplexRejectedResponse, allocator: std.mem.Allocator) void {
        self.head.deinit(allocator);
        allocator.free(self.body);
        http2.Hpack.freeOwnedFields(allocator, self.trailers);
        self.* = undefined;
    }
};

pub const ConnectAttempt = struct {
    session: ?Session = null,
    rejection: ?Rejection = null,

    pub fn accepted(self: ConnectAttempt) bool {
        return self.session != null;
    }
    pub fn status(self: ConnectAttempt) u16 {
        if (self.session) |session| return session.responseStatus().?;
        return self.rejection.?.status();
    }
    pub fn responseHeader(self: ConnectAttempt, name: []const u8) ?[]const u8 {
        if (self.session) |session| return session.responseHeader(name);
        return self.rejection.?.responseHeader(name);
    }
    pub fn body(self: ConnectAttempt) []const u8 {
        return if (self.rejection) |rejection| rejection.body() else &.{};
    }
    pub fn trailers(self: ConnectAttempt) []const http2.Hpack.HeaderField {
        return if (self.rejection) |rejection| rejection.trailers() else &.{};
    }
    pub fn deinit(self: *ConnectAttempt) void {
        if (self.session) |*session| session.deinit();
        if (self.rejection) |*rejection| rejection.deinit();
        self.* = undefined;
    }
    pub fn requireAccepted(self: *ConnectAttempt) Error!Session {
        const session = self.session orelse return error.SessionRejected;
        self.* = undefined;
        return session;
    }
};

fn qpack(allocator: std.mem.Allocator, headers: []const http2.Hpack.HeaderField) std.mem.Allocator.Error![]http3.Qpack.HeaderField {
    const fields = try allocator.alloc(http3.Qpack.HeaderField, headers.len);
    for (fields, headers) |*field, header| field.* = .{ .name = header.name, .value = header.value };
    return fields;
}
fn encryption(connection: *http2.runtime.Connection) Error!void {
    if (connection.negotiatedAlpn()) |value| {
        if (std.mem.eql(u8, value, "h2")) return;
    }
    return error.EncryptionRequired;
}

const PreparedClientHeaders = struct {
    offer: protocol.Request,
    fields: []const http2.Hpack.HeaderField,
};

fn prepareClientHeaders(allocator: std.mem.Allocator, options: ClientOptions, init_storage: *[64]u8) Error!PreparedClientHeaders {
    const additional = try qpack(allocator, options.headers);
    const offer = try protocol.Request.init(allocator, options.protocols, additional);
    var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    try fields.appendSlice(allocator, options.headers);
    if (options.origin) |origin| try fields.append(allocator, .{ .name = "origin", .value = origin });
    if (options.protocols.values.len != 0) try fields.append(allocator, .{ .name = protocol.available_header, .value = offer.fields()[0].value });
    if (options.initial_receive_stream_data) |limits| {
        const value = init_header.writeInto(init_storage, limits) catch |err| switch (err) {
            error.InvalidWebTransportInit => return err,
            error.BufferTooShort => unreachable,
        };
        try fields.append(allocator, .{ .name = "webtransport-init", .value = value });
    }
    _ = try init_header.parse(fields.items, .{});
    return .{ .offer = offer, .fields = fields.items };
}

pub fn connectWithDeadline(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, deadline: std.Io.Clock.Timestamp) Error!Session {
    var attempt = try connectAttemptWithDeadline(allocator, connection, options, deadline);
    errdefer attempt.deinit();
    return attempt.requireAccepted();
}
pub fn connectAttemptWithDeadline(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, deadline: std.Io.Clock.Timestamp) Error!ConnectAttempt {
    try encryption(connection);
    if (!connection.peerExtendedConnectEnabled() or !connection.peerWebTransportSettings().enabled) return error.WebTransportDisabled;
    const peer_snapshot = connection.peerWebTransportSettings();
    if (options.session.max_payload < 4 or options.session.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    var init_storage: [64]u8 = undefined;
    const prepared = try prepareClientHeaders(temporary, options, &init_storage);
    // Reject local configuration before creating a CONNECT stream. The final
    // receive snapshot is recomputed after the response because intervening
    // SETTINGS acknowledgements can legitimately raise its baseline.
    var response = try connection.openExtendedConnectAttemptWithDeadline(.{ .method = "CONNECT", .protocol = "webtransport", .scheme = "https", .authority = options.authority, .path = options.path, .headers = prepared.fields }, deadline);
    var response_owned = true;
    errdefer if (response_owned) response.deinit(connection.allocator);
    if (!response.accepted()) {
        response_owned = false;
        return .{ .rejection = .{ .response = response, .allocator = connection.allocator } };
    }
    const received = try qpack(temporary, response.headers);
    const selected = try prepared.offer.validateResponse(received);
    const send_limits = try init_header.parse(response.headers, init_header.fromSettings(peer_snapshot));
    const receive_limits = try init_header.parse(prepared.fields, init_header.fromSettings(connection.localWebTransportSettings()));
    var session = try Session.init(allocator, response.tunnel.?, receive_limits, send_limits, options.session);
    response.tunnel = null;
    session.response = response;
    session.response_allocator = connection.allocator;
    response_owned = false;
    errdefer session.deinit();
    if (selected) |value| {
        const bytes = try allocator.alloc(u8, value.decodedLen());
        _ = value.decodeInto(bytes) catch unreachable;
        session.selected_protocol = bytes;
    }
    return .{ .session = session };
}
pub fn connectWithTimeout(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, timeout: std.Io.Duration) Error!Session {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return connectWithDeadline(allocator, connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}
pub fn connectAttemptWithTimeout(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, timeout: std.Io.Duration) Error!ConnectAttempt {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return connectAttemptWithDeadline(allocator, connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn connectDuplexWithDeadline(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, deadline: std.Io.Clock.Timestamp) Error!Session {
    var attempt = try connectDuplexAttemptWithDeadline(allocator, connection, options, deadline);
    errdefer attempt.deinit();
    return attempt.requireAccepted();
}

pub fn connectDuplexWithTimeout(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, timeout: std.Io.Duration) Error!Session {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return connectDuplexWithDeadline(allocator, connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn connectDuplexAttemptWithTimeout(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, timeout: std.Io.Duration) Error!ConnectAttempt {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return connectDuplexAttemptWithDeadline(allocator, connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn connectDuplexAttemptWithDeadline(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, deadline: std.Io.Clock.Timestamp) Error!ConnectAttempt {
    try encryption(connection);
    if (!connection.peerExtendedConnectEnabled() or !connection.peerWebTransportSettings().enabled) return error.WebTransportDisabled;
    const peer_snapshot = connection.peerWebTransportSettings();
    if (options.session.max_payload < 4 or options.session.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    var init_storage: [64]u8 = undefined;
    const prepared = try prepareClientHeaders(temporary, options, &init_storage);
    var duplex = try connection.startExtendedConnectDuplexWithDeadline(.{
        .method = "CONNECT",
        .protocol = "webtransport",
        .scheme = "https",
        .authority = options.authority,
        .path = options.path,
        .headers = prepared.fields,
    }, deadline);
    var duplex_owned = true;
    errdefer if (duplex_owned) duplex.deinit();
    var head: ?http2.runtime.DuplexResponseHead = null;
    errdefer if (head) |*value| value.deinit(connection.allocator);
    while (head == null) {
        var event = try duplex.readResponseEventWithDeadline(deadline);
        var event_owned = true;
        defer if (event_owned) event.deinit(connection.allocator);
        switch (event) {
            .informational => {},
            .head => |value| {
                head = value;
                event_owned = false;
            },
            .reset => return error.StreamReset,
            .data, .trailers, .finished => return error.UnexpectedFrame,
        }
    }
    if (head.?.status < 200 or head.?.status >= 300) {
        const response_head = head.?;
        head = null;
        const rejection = try receiveDuplexRejection(connection.allocator, &duplex, response_head, deadline);
        duplex.deinit();
        duplex_owned = false;
        return .{ .rejection = .{ .duplex = rejection, .allocator = connection.allocator } };
    }
    if (duplex.responseFinished()) {
        duplex.closeRequestAfterResponse() catch {};
        return error.InvalidConnect;
    }
    const received = try qpack(temporary, head.?.headers);
    const selected = try prepared.offer.validateResponse(received);
    const send_limits = try init_header.parse(head.?.headers, init_header.fromSettings(peer_snapshot));
    const receive_limits = try init_header.parse(prepared.fields, init_header.fromSettings(connection.localWebTransportSettings()));
    var session = try Session.initDuplex(allocator, duplex, receive_limits, send_limits, options.session);
    duplex_owned = false;
    errdefer session.deinit();
    session.duplex_response = head.?;
    session.response_allocator = connection.allocator;
    head = null;
    if (selected) |value| {
        const bytes = try allocator.alloc(u8, value.decodedLen());
        _ = value.decodeInto(bytes) catch unreachable;
        session.selected_protocol = bytes;
    }
    return .{ .session = session };
}

fn receiveDuplexRejection(allocator: std.mem.Allocator, duplex: *http2.runtime.ClientDuplexStream, response_head: http2.runtime.DuplexResponseHead, deadline: std.Io.Clock.Timestamp) Error!DuplexRejectedResponse {
    var head = response_head;
    var head_owned = true;
    errdefer if (head_owned) head.deinit(allocator);
    var body: std.ArrayList(u8) = .empty;
    errdefer body.deinit(allocator);
    var trailers: ?[]http2.Hpack.HeaderField = null;
    errdefer if (trailers) |fields| http2.Hpack.freeOwnedFields(allocator, fields);
    while (true) {
        var event = try duplex.readResponseEventWithDeadline(deadline);
        var event_owned = true;
        defer if (event_owned) event.deinit(allocator);
        switch (event) {
            .data => |data| try body.appendSlice(allocator, data.data),
            .trailers => |fields| {
                trailers = fields;
                event_owned = false;
            },
            .finished => break,
            .reset => return error.StreamReset,
            .informational, .head => return error.UnexpectedFrame,
        }
    }
    duplex.closeRequestAfterResponse() catch {};
    const owned_body = try body.toOwnedSlice(allocator);
    errdefer allocator.free(owned_body);
    const owned_trailers = trailers orelse try allocator.alloc(http2.Hpack.HeaderField, 0);
    trailers = null;
    head_owned = false;
    return .{ .head = head, .body = owned_body, .trailers = owned_trailers };
}

pub const PendingSession = struct {
    request: http2.runtime.ExtendedConnectRequest,
    receive_settings: http2.WebTransportSettings,
    pub fn deinit(self: *PendingSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
    }
    pub fn rejectWithDeadline(self: *const PendingSession, connection: *http2.runtime.Connection, options: RejectOptions, deadline: std.Io.Clock.Timestamp) Error!void {
        return connection.rejectExtendedConnectWithBodyWithDeadline(self.request.stream_id, options.status, options.headers, options.body, options.trailers, deadline);
    }
    pub fn rejectWithTimeout(self: *const PendingSession, connection: *http2.runtime.Connection, options: RejectOptions, timeout: std.Io.Duration) Error!void {
        if (timeout.nanoseconds <= 0) return error.Timeout;
        return self.rejectWithDeadline(connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
    }
};
pub fn readRequestWithDeadline(connection: *http2.runtime.Connection, deadline: std.Io.Clock.Timestamp) Error!PendingSession {
    try encryption(connection);
    var request = try connection.readExtendedConnectRequestWithDeadline("webtransport", deadline);
    errdefer request.deinit(connection.allocator);
    if (!connection.localWebTransportSettings().enabled) {
        try connection.rejectExtendedConnectWithDeadline(request.stream_id, 405, &.{}, deadline);
        return error.WebTransportDisabled;
    }
    if (!std.mem.eql(u8, request.scheme, "https") or request.authority == null or request.authority.?.len == 0 or request.path.len == 0) {
        try connection.rejectExtendedConnectWithDeadline(request.stream_id, 400, &.{}, deadline);
        return error.InvalidConnect;
    }
    return .{ .request = request, .receive_settings = connection.localWebTransportSettings() };
}
pub fn readRequestWithTimeout(connection: *http2.runtime.Connection, timeout: std.Io.Duration) Error!PendingSession {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return readRequestWithDeadline(connection, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

pub fn acceptWithDeadline(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, pending: PendingSession, options: ServerOptions, deadline: std.Io.Clock.Timestamp) Error!Session {
    try encryption(connection);
    origin_policy.validateOrigin(pending.request, options.origin) catch {
        try connection.rejectExtendedConnectWithDeadline(pending.request.stream_id, 403, &.{}, deadline);
        return error.InvalidOrigin;
    };
    const send_limits = init_header.parse(pending.request.headers, init_header.fromSettings(connection.peerWebTransportSettings())) catch |err| {
        try connection.rejectExtendedConnectWithDeadline(pending.request.stream_id, 400, &.{}, deadline);
        return err;
    };
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    const selection = protocol.serverSelection(try qpack(temporary, pending.request.headers), try qpack(temporary, options.headers), options.protocols) catch |err| {
        if (err == error.NoCommonApplicationProtocol) try connection.rejectExtendedConnectWithDeadline(pending.request.stream_id, 400, &.{}, deadline);
        return err;
    };
    var headers: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    try headers.appendSlice(temporary, options.headers);
    if (selection) |value| {
        var supplied = false;
        for (options.headers) |field| supplied = supplied or std.ascii.eqlIgnoreCase(field.name, protocol.selected_header);
        if (!supplied) try headers.append(temporary, .{ .name = protocol.selected_header, .value = try protocol.writeItem(temporary, value) });
    }
    var init_storage: [64]u8 = undefined;
    if (options.initial_receive_stream_data) |limits| {
        const value = init_header.writeInto(&init_storage, limits) catch |err| switch (err) {
            error.InvalidWebTransportInit => return err,
            error.BufferTooShort => unreachable,
        };
        try headers.append(temporary, .{ .name = "webtransport-init", .value = value });
    }
    const receive_limits = try init_header.parse(headers.items, init_header.fromSettings(pending.receive_settings));
    if (options.session.max_payload < 4 or options.session.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
    const selected_copy = if (selection) |value| try allocator.dupe(u8, value) else null;
    var selected_transferred = false;
    errdefer if (!selected_transferred) if (selected_copy) |value| allocator.free(value);
    // Validate local limits and own selected metadata before success admission.
    var state = try model.State.init(allocator, .server, receive_limits, send_limits, options.session.max_live_streams);
    state.deinit();
    const tunnel = try connection.acceptExtendedConnectWithDeadline(pending.request, headers.items, deadline);
    errdefer connection.abortExtendedConnect(pending.request.stream_id, deadline);
    var session = try Session.init(allocator, tunnel, receive_limits, send_limits, options.session);
    errdefer session.deinit();
    session.selected_protocol = selected_copy;
    selected_transferred = true;
    return session;
}
pub fn acceptWithTimeout(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, pending: PendingSession, options: ServerOptions, timeout: std.Io.Duration) Error!Session {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return acceptWithDeadline(allocator, connection, pending, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

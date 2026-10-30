//! TLS HTTP/2 Extended CONNECT admission for capsule-based WebTransport.
const std = @import("std");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");
const model = @import("state.zig");
const session_mod = @import("session.zig");
const init_header = @import("init_header.zig");
const protocol = @import("../application_protocol.zig");
const origin_policy = @import("../runtime/connect/headers.zig");
pub const Error = session_mod.Error || init_header.Error || protocol.Error || error{ WebTransportDisabled, InvalidOrigin, InvalidConnect };
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

pub fn connectWithDeadline(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, deadline: std.Io.Clock.Timestamp) Error!Session {
    try encryption(connection);
    if (!connection.peerExtendedConnectEnabled() or !connection.peerWebTransportSettings().enabled) return error.WebTransportDisabled;
    const peer_snapshot = connection.peerWebTransportSettings();
    if (options.session.max_payload < 4 or options.session.max_payload > std.math.maxInt(usize) - 16) return error.CapsuleTooLarge;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    const additional = try qpack(temporary, options.headers);
    var offer = try protocol.Request.init(temporary, options.protocols, additional);
    var fields: std.ArrayList(http2.Hpack.HeaderField) = .empty;
    try fields.appendSlice(temporary, options.headers);
    if (options.origin) |origin| try fields.append(temporary, .{ .name = "origin", .value = origin });
    if (options.protocols.values.len != 0) try fields.append(temporary, .{ .name = protocol.available_header, .value = offer.fields()[0].value });
    var init_storage: [64]u8 = undefined;
    if (options.initial_receive_stream_data) |limits| {
        const value = init_header.writeInto(&init_storage, limits) catch |err| switch (err) {
            error.InvalidWebTransportInit => return err,
            error.BufferTooShort => unreachable,
        };
        try fields.append(temporary, .{ .name = "webtransport-init", .value = value });
    }
    // Reject local configuration before creating a CONNECT stream. The final
    // receive snapshot is recomputed after the response because intervening
    // SETTINGS acknowledgements can legitimately raise its baseline.
    _ = try init_header.parse(fields.items, .{});
    var response = try connection.openExtendedConnectWithDeadline(.{ .method = "CONNECT", .protocol = "webtransport", .scheme = "https", .authority = options.authority, .path = options.path, .headers = fields.items }, deadline);
    defer response.deinit(connection.allocator);
    var transferred = false;
    errdefer if (!transferred) response.tunnel.abort(deadline);
    const received = try qpack(temporary, response.headers);
    const selected = try offer.validateResponse(received);
    const send_limits = try init_header.parse(response.headers, init_header.fromSettings(peer_snapshot));
    const receive_limits = try init_header.parse(fields.items, init_header.fromSettings(connection.localWebTransportSettings()));
    var session = try Session.init(allocator, response.tunnel, receive_limits, send_limits, options.session);
    transferred = true;
    errdefer session.deinit();
    if (selected) |value| {
        const bytes = try allocator.alloc(u8, value.decodedLen());
        _ = value.decodeInto(bytes) catch unreachable;
        session.selected_protocol = bytes;
    }
    return session;
}
pub fn connectWithTimeout(allocator: std.mem.Allocator, connection: *http2.runtime.Connection, options: ClientOptions, timeout: std.Io.Duration) Error!Session {
    if (timeout.nanoseconds <= 0) return error.Timeout;
    return connectWithDeadline(allocator, connection, options, .fromNow(connection.io, .{ .raw = timeout, .clock = .awake }));
}

pub const PendingSession = struct {
    request: http2.runtime.ExtendedConnectRequest,
    receive_settings: http2.WebTransportSettings,
    pub fn deinit(self: *PendingSession, allocator: std.mem.Allocator) void {
        self.request.deinit(allocator);
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

const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const quic = netz.quic;
const runtime = netz.webtransport.runtime;

pub fn run(
    endpoint: *runtime.EndpointServer,
    expected: model.Summary,
    clients: *[model.client_count]@import("client.zig").Task,
) !model.Summary {
    const allocator = std.testing.allocator;
    const versions = [_]u32{
        quic.Version.version_1.wireValue(),
        quic.Version.version_2.wireValue(),
    };
    var summary = model.Summary{};
    var handles: [model.client_count]?quic.endpoint_dispatcher.ConnectionHandle =
        .{null} ** model.client_count;
    var stream_ids: [model.client_count]?u62 = .{null} ** model.client_count;
    var stream_payloads: [model.client_count][3]u8 = undefined;
    var stream_lengths: [model.client_count]usize = .{0} ** model.client_count;
    var drained: [model.client_count]bool = .{false} ** model.client_count;
    var released = false;
    defer if (!released) for (clients) |*client| client.release.set(client.io);

    var stream_buffer: [64]u8 = undefined;
    const deadline = std.Io.Clock.Timestamp.fromNow(
        clients[0].io,
        .{ .clock = .awake, .raw = model.endpoint_timeout },
    );
    while (!complete(summary, expected)) {
        var event = try endpoint.receiveWithDeadline(
            &versions,
            deadline,
            &stream_buffer,
        );
        defer event.deinit(allocator);
        switch (event) {
            .connected => {},
            .closed => return error.UnexpectedConnectionClose,
            .handshake_failed => |failure| return failure.err,
            .session_request => |handle| {
                const pending = endpoint.pendingSession(handle) orelse
                    return error.MissingPendingSession;
                const client_index = try indexFromPath(pending.path());
                if (handles[client_index] != null) {
                    return error.DuplicateClientSession;
                }
                _ = try endpoint.accept(handle);
                handles[client_index] = handle;
                summary.sessions += 1;
                if (summary.sessions == model.client_count) {
                    for (clients) |*client| try client.ready.wait(client.io);
                    for (clients) |*client| if (client.err) |err| return err;
                    for (clients) |*client| client.release.set(client.io);
                    released = true;
                }
            },
            .session_event => |*value| {
                const client_index = try indexFromHandle(
                    &handles,
                    value.handle,
                );
                summary.routed_to[client_index] += 1;
                const accepted = endpoint.session(value.handle) orelse
                    return error.MissingAcceptedSession;
                switch (value.event) {
                    .datagram => |datagram| {
                        const payload = try parsePayload(
                            client_index,
                            datagram.datagram.payload,
                        );
                        try accepted.trySendDatagramWithTimeout(
                            &payload.response().bytes,
                            model.timeout,
                        );
                        summary.datagrams += 1;
                    },
                    .stream => |stream| switch (stream) {
                        .data => |data| {
                            try std.testing.expect(
                                data.direction == .bidirectional,
                            );
                            try std.testing.expect(!data.locally_initiated);
                            if (stream_ids[client_index]) |stream_id| {
                                try std.testing.expectEqual(
                                    stream_id,
                                    data.stream_id,
                                );
                            } else {
                                stream_ids[client_index] = data.stream_id;
                            }
                            const old_len = stream_lengths[client_index];
                            const new_len = old_len + data.bytes;
                            if (new_len > 3) return error.InvalidPayload;
                            @memcpy(
                                stream_payloads[client_index][old_len..new_len],
                                stream_buffer[0..data.bytes],
                            );
                            stream_lengths[client_index] = new_len;
                            if (data.fin) {
                                const payload = try parsePayload(
                                    client_index,
                                    stream_payloads[client_index][0..new_len],
                                );
                                try accepted.sendStream(
                                    data.stream_id,
                                    &payload.response().bytes,
                                    true,
                                );
                                stream_ids[client_index] = null;
                                stream_lengths[client_index] = 0;
                                summary.streams += 1;
                            }
                        },
                        .reset, .stopped => return error.UnexpectedStreamEnd,
                    },
                    .session => |session| switch (session) {
                        .draining => {
                            if (drained[client_index]) {
                                return error.DuplicateDrain;
                            }
                            drained[client_index] = true;
                            summary.drains += 1;
                        },
                        .closed => |closed| {
                            try std.testing.expectEqual(
                                @as(u32, @intCast(70 + client_index)),
                                closed.code,
                            );
                            try std.testing.expectEqualStrings(
                                if (client_index == 0) "client-a" else "client-b",
                                closed.reason,
                            );
                            summary.closes += 1;
                        },
                        .reset => return error.UnexpectedSessionReset,
                    },
                }
            },
            .unrouted => return error.UnroutedWebTransportPacket,
        }
        if (summary.sessions > expected.sessions or
            summary.datagrams > expected.datagrams or
            summary.streams > expected.streams or
            summary.drains > expected.drains or
            summary.closes > expected.closes)
        {
            return error.UnexpectedEventCount;
        }
    }

    for (handles) |maybe_handle| {
        try std.testing.expect(endpoint.removeConnection(maybe_handle.?));
    }
    try std.testing.expectEqual(@as(usize, 0), endpoint.connectionCount());
    return summary;
}

fn complete(actual: model.Summary, expected: model.Summary) bool {
    return actual.sessions == expected.sessions and
        actual.datagrams == expected.datagrams and
        actual.streams == expected.streams and
        actual.drains == expected.drains and
        actual.closes == expected.closes;
}

fn indexFromPath(path: []const u8) !usize {
    if (std.mem.eql(u8, path, "/fuzz/a")) return 0;
    if (std.mem.eql(u8, path, "/fuzz/b")) return 1;
    return error.UnexpectedSessionPath;
}

fn indexFromHandle(
    handles: *const [model.client_count]?quic.endpoint_dispatcher.ConnectionHandle,
    handle: quic.endpoint_dispatcher.ConnectionHandle,
) !usize {
    for (handles, 0..) |candidate, index| {
        if (candidate == handle) return index;
    }
    return error.UnexpectedConnectionHandle;
}

fn parsePayload(client_index: usize, bytes: []const u8) !model.Payload {
    if (bytes.len != 3 or bytes[0] != client_index) {
        return error.InvalidPayload;
    }
    return .{ .bytes = bytes[0..3].* };
}

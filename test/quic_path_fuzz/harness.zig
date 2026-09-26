const std = @import("std");
const netz = @import("netz");
const model = @import("model.zig");

const quic = netz.quic;
const one_rtt = quic.one_rtt;
const Endpoint = quic.runtime.Endpoint;

const PathState = struct {
    primary: *Endpoint,
    rebound: *Endpoint,
    current: *Endpoint,
    challenge: ?[8]u8 = null,
};

const Harness = struct {
    allocator: std.mem.Allocator,
    server_endpoint: *Endpoint,
    original: PathState,
    path_b: PathState,
    path_c: PathState,
    server: *one_rtt.Connection,
    client_keys: quic.protection.PacketProtectionKeys,
    server_keys: quic.protection.PacketProtectionKeys,
    peer_packet_number: u64 = 0,
    expected_server_packet_number: u64 = 0,
    peer_stream_offset: u64 = 0,
    server_stream_offset: u64 = 0,
    now_ns: u64 = 100,
    challenge_serial: u8 = 0,
    summary: model.Summary = .{},

    fn init(allocator: std.mem.Allocator, io: std.Io) !Harness {
        const endpoint_limits: quic.runtime.Limits = .{
            .max_datagram_size = 4096,
        };
        const server_endpoint = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, server_endpoint);
        const original_primary = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, original_primary);
        const original_rebound = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .loopback(0) },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, original_rebound);
        const b_primary = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0 } },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, b_primary);
        const b_rebound = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 2 }, .port = 0 } },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, b_rebound);
        const c_primary = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 0 } },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, c_primary);
        const c_rebound = try createEndpoint(
            allocator,
            io,
            .{ .ip4 = .{ .bytes = .{ 127, 0, 0, 3 }, .port = 0 } },
            endpoint_limits,
        );
        errdefer destroyEndpoint(allocator, c_rebound);

        const client_keys = quic.protection.deriveAes128Keys(
            [_]u8{0x51} ** quic.protection.secret_len,
        );
        const server_keys = quic.protection.deriveAes128Keys(
            [_]u8{0xa7} ** quic.protection.secret_len,
        );
        const server_cid = [_]u8{ 0x21, 0x22, 0x23, 0x24 };
        const client_cid = [_]u8{ 0x11, 0x12, 0x13, 0x14 };
        const server = try allocator.create(one_rtt.Connection);
        errdefer allocator.destroy(server);
        server.* = try one_rtt.Connection.init(server_endpoint, .{
            .peer = original_primary.address(),
            .receive_keys = client_keys,
            .send_keys = server_keys,
            .local_connection_id = &server_cid,
            .peer_connection_id = &client_cid,
            .local_endpoint = .server,
            .initial_send_max_data = model.max_operations,
            .initial_receive_max_data = model.max_operations,
            .initial_send_max_stream_data = model.max_operations,
            .initial_receive_max_stream_data = model.max_operations,
            .initial_send_max_streams_bidi = 1,
            .initial_receive_max_streams_bidi = 1,
            .enable_pacing = false,
            .automatic_ecn_policy = .disabled,
        });
        errdefer server.deinit();

        return .{
            .allocator = allocator,
            .server_endpoint = server_endpoint,
            .original = .{
                .primary = original_primary,
                .rebound = original_rebound,
                .current = original_primary,
            },
            .path_b = .{
                .primary = b_primary,
                .rebound = b_rebound,
                .current = b_primary,
            },
            .path_c = .{
                .primary = c_primary,
                .rebound = c_rebound,
                .current = c_primary,
            },
            .server = server,
            .client_keys = client_keys,
            .server_keys = server_keys,
        };
    }

    fn deinit(self: *Harness) void {
        self.server.deinit();
        self.allocator.destroy(self.server);
        destroyEndpoint(self.allocator, self.original.primary);
        destroyEndpoint(self.allocator, self.original.rebound);
        destroyEndpoint(self.allocator, self.path_b.primary);
        destroyEndpoint(self.allocator, self.path_b.rebound);
        destroyEndpoint(self.allocator, self.path_c.primary);
        destroyEndpoint(self.allocator, self.path_c.rebound);
        destroyEndpoint(self.allocator, self.server_endpoint);
        self.* = undefined;
    }

    fn startMigration(self: *Harness, path_value: model.Path) !void {
        const target = self.pathState(path_value);
        if (target.challenge != null) return;
        const target_address = target.current.address();
        if (self.server.peerAddress().eql(&target_address)) return;
        self.challenge_serial +%= 1;
        const challenge = model.challenge(path_value, self.challenge_serial);
        try self.server.beginPeerMigration(
            target.current.address(),
            challenge,
        );
        self.server.recordPeerAddressBytesReceived(400);
        try self.server.sendPendingPathChallengeAt(
            self.now_ns,
            model.retry_timeout_ns,
        );
        try self.captureChallenge(target.current, challenge);
        target.challenge = challenge;
        self.summary.migrations_started += 1;
    }

    fn answerMigration(self: *Harness, path_value: model.Path) !void {
        const target = self.pathState(path_value);
        const challenge = target.challenge orelse return;
        const target_address = target.current.address();
        const was_current = self.server.peerAddress().eql(&target_address);
        const was_validated = self.server.peerAddressValidated();
        try self.sendPeerFrames(target.current, &.{.{
            .path_response = .{ .data = challenge },
        }});
        var packet = try self.server.receivePacketAt(self.now_ns);
        packet.deinit(self.allocator);
        target.challenge = null;
        if (was_current) {
            try std.testing.expect(self.server.peerAddressValidated());
            self.summary.paths_validated += 1;
        } else {
            try std.testing.expectEqual(
                was_validated,
                self.server.peerAddressValidated(),
            );
            self.summary.late_responses += 1;
        }
    }

    fn wrongResponse(self: *Harness) !void {
        if (self.server.peerAddressValidated()) return;
        const target = self.currentEndpoint() orelse return;
        const wrong = model.challenge(.b, self.challenge_serial +% 91);
        try self.sendPeerFrames(target, &.{.{
            .path_response = .{ .data = wrong },
        }});
        var packet = try self.server.receivePacketAt(self.now_ns);
        packet.deinit(self.allocator);
        try std.testing.expect(!self.server.peerAddressValidated());
        self.summary.invalid_responses += 1;
    }

    fn timeoutMigration(self: *Harness) !void {
        const deadline = self.server.pathValidationDeadline() orelse return;
        const failures_before = self.server.failedPathValidationCount();
        const expired = try self.server.checkPathValidationTimeouts(deadline);
        try std.testing.expect(expired != 0);
        self.now_ns = deadline + 1;
        if (self.server.failedPathValidationCount() != failures_before) {
            self.path_b.challenge = null;
            self.path_c.challenge = null;
            self.summary.failed_validations += 1;
            try std.testing.expect(self.server.peerAddressValidated());
            return;
        }
        // A server may retransmit only after receiving more bytes on the
        // unvalidated path. Feed one authenticated probing-only packet so the
        // retry exercises the real anti-amplification accounting without
        // committing the candidate as the active application path.
        const target = self.currentEndpoint() orelse
            return error.UnknownPath;
        const wrong = model.challenge(.c, self.challenge_serial +% 53);
        try self.sendPeerFrames(target, &.{
            .{ .path_response = .{ .data = wrong } },
            .{ .padding = .{ .len = 400 } },
        });
        var credit_packet = try self.server.receivePacketAt(self.now_ns);
        credit_packet.deinit(self.allocator);
        self.server.sendPendingPathChallengeAt(
            self.now_ns,
            model.retry_timeout_ns,
        ) catch |err| switch (err) {
            // The expired item may belong to a superseded path while the
            // current path's outstanding probe has a later deadline.
            error.NoPendingPathChallenge => return,
            else => return err,
        };
        const expected = if (self.server.peerAddress().ip4.bytes[3] == 2)
            self.path_b.challenge.?
        else
            self.path_c.challenge.?;
        try self.captureChallenge(target, expected);
        self.summary.timeout_retries += 1;
    }

    fn rebind(self: *Harness) !void {
        if (!self.server.peerAddressValidated()) return;
        const path_state = self.currentPathState() orelse return;
        const next = if (path_state.current == path_state.primary)
            path_state.rebound
        else
            path_state.primary;
        try self.sendApplicationFrom(next);
        const next_address = next.address();
        try std.testing.expect(self.server.peerAddress().eql(&next_address));
        try std.testing.expect(self.server.peerAddressValidated());
        path_state.current = next;
        self.summary.rebindings += 1;
    }

    fn applicationRoundTrip(self: *Harness) !void {
        const target = self.currentEndpoint() orelse return;
        try self.sendApplicationFrom(target);
    }

    fn sendApplicationFrom(self: *Harness, peer: *Endpoint) !void {
        const value: u8 = @truncate(self.peer_stream_offset + 0x30);
        try self.sendPeerFrames(peer, &.{.{ .stream = .{
            .stream_id = 0,
            .offset = self.peer_stream_offset,
            .data = &.{value},
        } }});
        var received = try self.server.receivePacketAt(self.now_ns);
        received.deinit(self.allocator);
        var storage: [1]u8 = undefined;
        const event = (try self.server.pollStreamId(0, &storage)) orelse
            return error.MissingStreamData;
        try std.testing.expect(event == .data);
        try std.testing.expectEqual(@as(usize, 1), event.data.bytes);
        try std.testing.expectEqual(value, storage[0]);
        self.peer_stream_offset += 1;

        const response: u8 = value ^ 0xff;
        try self.server.send(&.{.{ .stream = .{
            .stream_id = 1,
            .offset = self.server_stream_offset,
            .data = &.{response},
        } }});
        self.server_stream_offset += 1;
        var saw_response = false;
        for (0..4) |_| {
            var datagram = try peer.receiveBytesWithTimeout(
                model.receive_timeout,
            );
            defer datagram.deinit(self.allocator);
            var packet = try one_rtt.openReceivedBytes(
                peer,
                datagram.from,
                datagram.bytes,
                self.server_keys,
                4,
                self.expected_server_packet_number,
                16,
            );
            defer packet.deinit(self.allocator);
            self.expected_server_packet_number =
                packet.packet.packet_number + 1;
            for (packet.frames) |frame| switch (frame) {
                .stream => |stream| if (stream.stream_id == 1) {
                    try std.testing.expectEqualSlices(
                        u8,
                        &.{response},
                        stream.data,
                    );
                    saw_response = true;
                },
                else => {},
            };
            if (saw_response) break;
        }
        try std.testing.expect(saw_response);
        self.summary.application_round_trips += 1;
    }

    fn sendPeerFrames(
        self: *Harness,
        peer: *Endpoint,
        frames: []const quic.Frame,
    ) !void {
        try one_rtt.sendFrames(
            peer,
            self.server_endpoint.address(),
            self.client_keys,
            .{
                .destination_connection_id = &.{ 0x21, 0x22, 0x23, 0x24 },
                .packet_number = self.peer_packet_number,
                .frames = frames,
            },
        );
        self.peer_packet_number += 1;
    }

    fn captureChallenge(
        self: *Harness,
        peer: *Endpoint,
        expected: [8]u8,
    ) !void {
        var saw_challenge = false;
        for (0..4) |_| {
            var datagram = try peer.receiveBytesWithTimeout(
                model.receive_timeout,
            );
            defer datagram.deinit(self.allocator);
            var packet = try one_rtt.openReceivedBytes(
                peer,
                datagram.from,
                datagram.bytes,
                self.server_keys,
                4,
                self.expected_server_packet_number,
                16,
            );
            defer packet.deinit(self.allocator);
            self.expected_server_packet_number =
                packet.packet.packet_number + 1;
            for (packet.frames) |frame| switch (frame) {
                .path_challenge => |value| {
                    try std.testing.expectEqual(expected, value.data);
                    saw_challenge = true;
                },
                else => {},
            };
            if (saw_challenge) break;
        }
        try std.testing.expect(saw_challenge);
    }

    fn pathState(self: *Harness, path_value: model.Path) *PathState {
        return switch (path_value) {
            .b => &self.path_b,
            .c => &self.path_c,
        };
    }

    fn currentPathState(self: *Harness) ?*PathState {
        const address = self.server.peerAddress();
        inline for (&.{ &self.original, &self.path_b, &self.path_c }) |path| {
            if (std.mem.eql(
                u8,
                &path.primary.address().ip4.bytes,
                &address.ip4.bytes,
            )) {
                return path;
            }
        }
        return null;
    }

    fn currentEndpoint(self: *Harness) ?*Endpoint {
        const address = self.server.peerAddress();
        inline for (&.{ &self.original, &self.path_b, &self.path_c }) |path| {
            if (path.primary.address().eql(&address)) return path.primary;
            if (path.rebound.address().eql(&address)) return path.rebound;
        }
        return null;
    }
};

fn createEndpoint(
    allocator: std.mem.Allocator,
    io: std.Io,
    address: std.Io.net.IpAddress,
    limits: quic.runtime.Limits,
) !*Endpoint {
    const endpoint = try allocator.create(Endpoint);
    errdefer allocator.destroy(endpoint);
    endpoint.* = try Endpoint.bind(allocator, io, address, limits);
    return endpoint;
}

fn destroyEndpoint(allocator: std.mem.Allocator, endpoint: *Endpoint) void {
    endpoint.deinit();
    allocator.destroy(endpoint);
}

pub fn runSequence(input: []const u8) !model.Summary {
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var harness = try Harness.init(allocator, threaded.io());
    defer harness.deinit();

    for (input[0..@min(input.len, model.max_operations)]) |operation| {
        harness.now_ns += 100;
        switch (operation & 7) {
            0 => try harness.startMigration(.b),
            1 => try harness.startMigration(.c),
            2 => try harness.answerMigration(.b),
            3 => try harness.answerMigration(.c),
            4 => try harness.applicationRoundTrip(),
            5 => try harness.rebind(),
            6 => try harness.timeoutMigration(),
            7 => try harness.wrongResponse(),
            else => unreachable,
        }
        try validate(&harness);
    }
    return harness.summary;
}

fn validate(harness: *const Harness) !void {
    try std.testing.expect(
        harness.server.pendingPathValidationCount() <= 2,
    );
    if (harness.server.peerAddressValidated()) {
        try std.testing.expect(
            harness.server.antiAmplificationLimitRemaining() == null,
        );
    }
}

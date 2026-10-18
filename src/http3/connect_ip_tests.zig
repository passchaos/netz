const std = @import("std");
const http3 = @import("mod.zig");

const connect_ip = http3.connect_ip;
const capsules = connect_ip.capsules;

test "CONNECT-IP default scope path follows RFC 9484" {
    var path_storage: [256]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/.well-known/masque/ip/*/*/",
        try connect_ip.writeDefaultPath(&path_storage, .{}),
    );

    const ipv6_scope = connect_ip.Scope{
        .target = "2001:db8::/64",
        .ip_protocol = 17,
    };
    const ipv6_path = try connect_ip.writeDefaultPath(
        &path_storage,
        ipv6_scope,
    );
    try std.testing.expectEqualStrings(
        "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F64/17/",
        ipv6_path,
    );
    var target_storage: [128]u8 = undefined;
    const parsed = try connect_ip.parseDefaultPath(
        ipv6_path,
        &target_storage,
    );
    try std.testing.expectEqualStrings(ipv6_scope.target, parsed.target);
    try std.testing.expectEqual(@as(?u8, 17), parsed.ip_protocol);

    const hostname = try connect_ip.writeDefaultPath(&path_storage, .{
        .target = "vpn!edge.example",
        .ip_protocol = 6,
    });
    try std.testing.expectEqualStrings(
        "/.well-known/masque/ip/vpn%21edge.example/6/",
        hostname,
    );
}

test "CONNECT-IP scope rejects malformed and non-network prefixes" {
    inline for (.{
        "192.0.2.1/24",
        "192.0.2.0/33",
        "2001:db8::1/64",
        "2001:db8::/129",
        "fe80::1%eth0",
        "name/24",
        "",
    }) |target| {
        try std.testing.expectError(
            error.InvalidScope,
            (connect_ip.Scope{ .target = target }).validate(),
        );
    }

    var target_storage: [64]u8 = undefined;
    inline for (.{
        "/.well-known/masque/ip/192.0.2.1%2F24/*/",
        "/.well-known/masque/ip/2001%3Adb8%3A%3A/256/",
        "/.well-known/masque/ip/*//",
    }) |path| {
        try std.testing.expectError(
            error.InvalidScope,
            connect_ip.parseDefaultPath(path, &target_storage),
        );
    }
    const encoded_wildcard = try connect_ip.parseDefaultPath(
        "/.well-known/masque/ip/%2A/*/",
        &target_storage,
    );
    try std.testing.expectEqualStrings("*", encoded_wildcard.target);
    const fully_encoded_wildcard = try connect_ip.parseDefaultPath(
        "/.well-known/masque/ip/%2A/%2A/",
        &target_storage,
    );
    try std.testing.expectEqualStrings("*", fully_encoded_wildcard.target);
    try std.testing.expect(fully_encoded_wildcard.ip_protocol == null);
    var short: [3]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooShort,
        connect_ip.parseDefaultPath(
            "/.well-known/masque/ip/example.com/*/",
            &short,
        ),
    );
    try (connect_ip.Scope{ .target = "0.0.0.0/0" }).validate();
    try (connect_ip.Scope{ .target = "255.255.255.255/32" }).validate();
    try (connect_ip.Scope{ .target = "::/0" }).validate();
    try (connect_ip.Scope{
        .target = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128",
    }).validate();
}

test "CONNECT-IP custom URI Templates expand optional scope variables" {
    var storage: [256]u8 = undefined;
    const path_template = try connect_ip.UriTemplate.compile(
        "https://example.org/.well-known/masque/ip/{target}/{ipproto}/",
    );
    try std.testing.expectEqualStrings(
        "/.well-known/masque/ip/2001%3Adb8%3A%3A%2F64/17/",
        try path_template.expandRequestTargetInto(&storage, .{
            .target = "2001:db8::/64",
            .ip_protocol = 17,
        }, &.{}),
    );
    try std.testing.expectEqualStrings(
        "/.well-known/masque/ip/%2A/%2A/",
        try path_template.expandRequestTargetInto(&storage, .{}, &.{}),
    );
    var short = [_]u8{0xaa} ** 8;
    try std.testing.expectError(
        error.BufferTooShort,
        path_template.expandRequestTargetInto(&short, .{}, &.{}),
    );
    try std.testing.expectEqual([_]u8{0xaa} ** short.len, short);

    const query = try connect_ip.UriTemplate.compile(
        "https://proxy.example:4443/masque{?target,ipproto,token}",
    );
    try std.testing.expectEqualStrings(
        "/masque?target=192.0.2.0%2F24&ipproto=6&token=a%2Fb",
        try query.expandRequestTargetInto(&storage, .{
            .target = "192.0.2.0/24",
            .ip_protocol = 6,
        }, &.{.{ .name = "token", .value = "a/b" }}),
    );

    const out_of_band = try connect_ip.UriTemplate.compile(
        "https://proxy.example/vpn?user=bob",
    );
    try std.testing.expectEqualStrings(
        "/vpn?user=bob",
        try out_of_band.expandRequestTargetInto(&storage, .{}, &.{}),
    );
    try std.testing.expectError(
        error.DuplicateTemplateVariable,
        query.expandRequestTargetInto(&storage, .{}, &.{.{
            .name = "target",
            .value = "other.example",
        }}),
    );
}

test "CONNECT-IP validates HTTP negotiation and Context ID zero" {
    var path_storage: [128]u8 = undefined;
    const request = try connect_ip.requestInto(
        &path_storage,
        .{ .target = "192.0.2.0/24", .ip_protocol = 6 },
        "proxy.example",
    );
    var target_storage: [64]u8 = undefined;
    const scope = try connect_ip.validateDefaultRequest(
        request,
        &target_storage,
    );
    try std.testing.expectEqualStrings("192.0.2.0/24", scope.target);
    try std.testing.expectEqual(@as(?u8, 6), scope.ip_protocol);
    try connect_ip.validateResponse(connect_ip.successResponse());
    try std.testing.expectError(
        error.InvalidStatus,
        connect_ip.validateResponseHead(302, &connect_ip.response_headers),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        connect_ip.validateRequestFields(
            "CONNECT",
            "/vpn",
            "https",
            "proxy.example",
            &[_]http3.Qpack.HeaderField{
                .{ .name = ":protocol", .value = "connect-udp" },
                http3.capsule.protocol_header,
            },
        ),
    );

    var packet = [_]u8{ 0x45, 0, 0, 20 } ++ [_]u8{0} ** 16;
    var encoded: [64]u8 = undefined;
    const written = try connect_ip.writeIpPacketInto(&encoded, &packet);
    const parsed = try connect_ip.ContextDatagram.parse(written);
    try std.testing.expectEqualStrings(&packet, try parsed.ipPacket());

    const extension = connect_ip.ContextDatagram{
        .context_id = 2,
        .payload = "extension",
    };
    const extension_bytes = try extension.writeInto(&encoded);
    try std.testing.expectError(
        error.UnexpectedContextId,
        (try connect_ip.ContextDatagram.parse(extension_bytes)).ipPacket(),
    );
    try std.testing.expectEqual(
        @as(?usize, 1199),
        connect_ip.maxIpPacketForHttpDatagram(1200),
    );
}

test "CONNECT-IP address request and assignment Capsules round trip" {
    const request = [_]capsules.AddressPrefix{
        .{
            .request_id = 1,
            .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .prefix_length = 32,
        },
        .{
            .request_id = 2,
            .address = .{ .ipv6 = [_]u8{0} ** 16 },
            .prefix_length = 64,
        },
    };
    var storage: [128]u8 = undefined;
    const encoded = try capsules.writeAddressRequestInto(&storage, &request);
    const expected_wire = [_]u8{
        capsules.address_request_type,
        26,
        1,
        4,
        0,
        0,
        0,
        0,
        32,
        2,
        6,
    } ++ ([_]u8{0} ** 16) ++ .{64};
    try std.testing.expectEqualSlices(u8, &expected_wire, encoded);
    const capsule_value = (try http3.capsule.parse(encoded)).capsule;
    try std.testing.expectEqual(
        capsules.address_request_type,
        capsule_value.capsule_type,
    );
    var iterator = try capsules.parseAddressRequest(capsule_value.value);
    for (request) |expected| {
        const actual = (try iterator.next()).?;
        try std.testing.expectEqual(expected.request_id, actual.request_id);
        try std.testing.expectEqual(expected.prefix_length, actual.prefix_length);
        try std.testing.expectEqualSlices(
            u8,
            expected.address.bytes(),
            actual.address.bytes(),
        );
    }
    try std.testing.expect((try iterator.next()) == null);

    const empty_assign = try capsules.writeAddressAssignInto(&storage, &.{});
    const empty_value = (try http3.capsule.parse(empty_assign)).capsule;
    var empty = try capsules.parseAddressAssign(empty_value.value);
    try std.testing.expect((try empty.next()) == null);
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeAddressRequestInto(&storage, &.{}),
    );
}

test "CONNECT-IP address Capsules reject invalid IDs versions and prefixes" {
    var storage = [_]u8{0xaa} ** 64;
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeAddressRequestInto(&storage, &.{.{
            .request_id = 0,
            .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .prefix_length = 32,
        }}),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeAddressRequestInto(&storage, &.{
            .{
                .request_id = 7,
                .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
                .prefix_length = 32,
            },
            .{
                .request_id = 7,
                .address = .{ .ipv6 = [_]u8{0} ** 16 },
                .prefix_length = 128,
            },
        }),
    );
    try std.testing.expectEqual(@as(u8, 0xaa), storage[0]);
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeAddressAssignInto(&storage, &.{.{
            .request_id = 0,
            .address = .{ .ipv4 = .{ 192, 0, 2, 1 } },
            .prefix_length = 24,
        }}),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.parseAddressRequest(&.{ 1, 5, 0, 0, 0, 0, 32 }),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.parseAddressRequest(&.{ 0, 4, 0, 0, 0, 0, 32 }),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.parseAddressAssign(&.{ 0, 4, 192, 0, 2, 1, 24 }),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.parseAddressAssign(&.{ 0, 6, 0, 0, 0 }),
    );
    var too_small = [_]u8{0xaa} ** 8;
    try std.testing.expectError(
        error.BufferTooShort,
        capsules.writeAddressAssignInto(&too_small, &.{.{
            .request_id = 0,
            .address = .{ .ipv4 = .{ 192, 0, 2, 1 } },
            .prefix_length = 32,
        }}),
    );
    try std.testing.expectEqual([_]u8{0xaa} ** too_small.len, too_small);
}

test "CONNECT-IP route advertisements enforce canonical ordering" {
    const routes = [_]capsules.Route{
        .{ .ipv4 = .{
            .start = .{ 192, 0, 2, 0 },
            .end = .{ 192, 0, 2, 41 },
        } },
        .{ .ipv4 = .{
            .start = .{ 192, 0, 2, 43 },
            .end = .{ 192, 0, 2, 255 },
        } },
        .{ .ipv6 = .{
            .start = [_]u8{0} ** 15 ++ .{1},
            .end = [_]u8{0} ** 15 ++ .{2},
            .ip_protocol = 17,
        } },
    };
    var storage: [128]u8 = undefined;
    const encoded = try capsules.writeRouteAdvertisementInto(&storage, &routes);
    const generic = (try http3.capsule.parse(encoded)).capsule;
    try std.testing.expectEqual(
        capsules.route_advertisement_type,
        generic.capsule_type,
    );
    var iterator = try capsules.parseRouteAdvertisement(generic.value);
    for (routes) |expected| {
        const actual = (try iterator.next()).?;
        try std.testing.expectEqual(expected.version(), actual.version());
        try std.testing.expectEqual(expected.protocol(), actual.protocol());
        try std.testing.expectEqualSlices(
            u8,
            expected.startBytes(),
            actual.startBytes(),
        );
        try std.testing.expectEqualSlices(
            u8,
            expected.endBytes(),
            actual.endBytes(),
        );
    }
    try std.testing.expect((try iterator.next()) == null);

    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeRouteAdvertisementInto(&storage, &.{
            routes[1],
            routes[0],
        }),
    );
    var route_short = [_]u8{0xaa} ** 4;
    try std.testing.expectError(
        error.BufferTooShort,
        capsules.writeRouteAdvertisementInto(&route_short, routes[0..1]),
    );
    try std.testing.expectEqual([_]u8{0xaa} ** route_short.len, route_short);
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeRouteAdvertisementInto(&storage, &.{
            routes[0],
            .{ .ipv4 = .{
                .start = .{ 192, 0, 2, 41 },
                .end = .{ 192, 0, 2, 80 },
            } },
        }),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.writeRouteAdvertisementInto(&storage, &.{
            .{ .ipv4 = .{
                .start = .{ 192, 0, 2, 0 },
                .end = .{ 192, 0, 2, 100 },
                .ip_protocol = 0,
            } },
            .{ .ipv4 = .{
                .start = .{ 192, 0, 2, 50 },
                .end = .{ 192, 0, 2, 60 },
                .ip_protocol = 6,
            } },
        }),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.parseRouteAdvertisement(&.{
            4, 192, 0, 2, 2, 192, 0, 2, 1, 0,
        }),
    );
    try std.testing.expectError(
        error.InvalidCapsule,
        capsules.parseRouteAdvertisement(&.{ 5, 0, 0 }),
    );

    const withdrawn = try capsules.writeRouteAdvertisementInto(&storage, &.{});
    const withdrawn_value = (try http3.capsule.parse(withdrawn)).capsule;
    try std.testing.expect(withdrawn_value.isConnectIpConfiguration());
    var no_routes = try capsules.parseRouteAdvertisement(
        withdrawn_value.value,
    );
    try std.testing.expect((try no_routes.next()) == null);
}

test "CONNECT-IP payload receive validates skipped configuration" {
    const ResetCode = enum { protocol_error, enhance_your_calm };
    const Progress = struct { committed_bytes: usize = 0 };
    const Tunnel = struct {
        const Owned = struct {
            data: []const u8,
            end_stream: bool,

            pub fn deinit(self: *@This(), _: std.mem.Allocator) void {
                self.* = undefined;
            }
        };

        stream_id: u31 = 0,
        input: []const u8,
        delivered: bool = false,
        reset_code: ?ResetCode = null,

        pub fn read(self: *@This()) !Owned {
            if (self.delivered) return .{ .data = &.{}, .end_stream = true };
            self.delivered = true;
            return .{ .data = self.input, .end_stream = false };
        }

        pub fn readWithDeadline(
            self: *@This(),
            _: std.Io.Clock.Timestamp,
        ) !Owned {
            return self.read();
        }

        pub fn reset(self: *@This(), code: ResetCode) !void {
            self.reset_code = code;
        }
    };
    const Session = connect_ip.CapsuleSession(ResetCode, Tunnel, Progress);
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{});
    defer threaded.deinit();
    const malformed = [_]u8{
        http3.capsule.CapsuleType.address_request,
        0,
    };
    var session = Session.init(
        std.testing.allocator,
        threaded.io(),
        .{ .input = &malformed },
        .{},
    );
    defer session.deinit();
    try std.testing.expectError(error.InvalidCapsule, session.receive());
    try std.testing.expectEqual(
        ResetCode.protocol_error,
        session.tunnel.reset_code.?,
    );
}

test "CONNECT-IP Capsule Session commits Request ID after timed retry" {
    const ResetCode = enum { protocol_error, enhance_your_calm };
    const Progress = struct { committed_bytes: usize = 0 };
    const Tunnel = struct {
        stream_id: u31 = 0,
        fail_once: bool = true,

        pub fn writeSlices(
            _: *@This(),
            _: []const []const u8,
            _: bool,
        ) !void {}

        pub fn writeSlicesWithDeadline(
            self: *@This(),
            slices: []const []const u8,
            _: bool,
            progress: *Progress,
            _: std.Io.Clock.Timestamp,
        ) !void {
            var total: usize = 0;
            for (slices) |slice| total += slice.len;
            if (self.fail_once) {
                self.fail_once = false;
                progress.committed_bytes = @min(total, 2);
                return error.Timeout;
            }
            progress.committed_bytes = total;
        }

        pub fn reset(_: *@This(), _: ResetCode) !void {}
    };
    const Session = connect_ip.CapsuleSession(ResetCode, Tunnel, Progress);
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var configuration = connect_ip.ConfigurationState.init(allocator, .{});
    defer configuration.deinit();
    var session = Session.init(allocator, io, .{}, .{});
    try session.bindConfigurationState(&configuration);
    defer session.deinit();
    const requests = [_]capsules.AddressPrefix{.{
        .request_id = 51,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .prefix_length = 32,
    }};
    var storage: [64]u8 = undefined;
    const encoded = try capsules.writeAddressRequestInto(&storage, &requests);
    var deadline = std.Io.Clock.Timestamp.fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.Timeout,
        session.sendCapsuleWithDeadline(encoded, deadline),
    );
    try std.testing.expect(session.writeInProgress());
    try std.testing.expectEqual(@as(usize, 0), configuration.localRequestCount());
    const peer_requests = [_]capsules.AddressPrefix{.{
        .request_id = 61,
        .address = .{ .ipv6 = [_]u8{0} ** 16 },
        .prefix_length = 128,
    }};
    var peer_storage: [64]u8 = undefined;
    const peer_encoded = try capsules.writeAddressRequestInto(
        &peer_storage,
        &peer_requests,
    );
    _ = try configuration.applyPeerCapsule(
        capsules.address_request_type,
        (try http3.capsule.parse(peer_encoded)).capsule.value,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        configuration.peerRequestCount(),
    );
    deadline = .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    try session.sendCapsuleWithDeadline(encoded, deadline);
    try std.testing.expect(!session.writeInProgress());
    try std.testing.expectEqual(@as(usize, 1), configuration.localRequestCount());
    try std.testing.expectError(
        error.DuplicateRequestId,
        session.sendCapsule(encoded),
    );

    const routes = [_]capsules.Route{.{ .ipv4 = .{
        .start = .{ 198, 51, 100, 0 },
        .end = .{ 198, 51, 100, 255 },
        .ip_protocol = 17,
    } }};
    const route = try capsules.writeRouteAdvertisementInto(
        &storage,
        &routes,
    );
    session.tunnel.fail_once = true;
    deadline = .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    try std.testing.expectError(
        error.Timeout,
        session.sendCapsuleWithDeadline(route, deadline),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        configuration.sentAdvertisedRoutes().len,
    );
    deadline = .fromNow(io, .{
        .raw = .fromSeconds(1),
        .clock = .awake,
    });
    try session.sendCapsuleWithDeadline(route, deadline);
    try std.testing.expect(configuration.peerRouteAllows(
        .{ .ipv4 = .{ 198, 51, 100, 42 } },
        17,
    ));
}

test "CONNECT-IP payload receive applies skipped configuration" {
    const ResetCode = enum { protocol_error, enhance_your_calm };
    const Progress = struct { committed_bytes: usize = 0 };
    const Tunnel = struct {
        const Owned = struct {
            data: []const u8,
            end_stream: bool,

            pub fn deinit(self: *@This(), _: std.mem.Allocator) void {
                self.* = undefined;
            }
        };

        stream_id: u31 = 0,
        input: []const u8,
        delivered: bool = false,
        reset_code: ?ResetCode = null,

        pub fn read(self: *@This()) !Owned {
            if (self.delivered) return .{ .data = &.{}, .end_stream = true };
            self.delivered = true;
            return .{ .data = self.input, .end_stream = false };
        }

        pub fn readWithDeadline(
            self: *@This(),
            _: std.Io.Clock.Timestamp,
        ) !Owned {
            return self.read();
        }

        pub fn reset(self: *@This(), code: ResetCode) !void {
            self.reset_code = code;
        }
    };
    const Session = connect_ip.CapsuleSession(ResetCode, Tunnel, Progress);
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var configuration = connect_ip.ConfigurationState.init(allocator, .{});
    defer configuration.deinit();

    const requested = [_]capsules.AddressPrefix{.{
        .request_id = 71,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .prefix_length = 32,
    }};
    var capsule_storage: [64]u8 = undefined;
    const request = try capsules.writeAddressRequestInto(
        &capsule_storage,
        &requested,
    );
    try configuration.recordLocalAddressRequest(
        (try http3.capsule.parse(request)).capsule.value,
    );

    const assigned = [_]capsules.AddressPrefix{.{
        .request_id = 71,
        .address = .{ .ipv4 = .{ 192, 0, 2, 71 } },
        .prefix_length = 32,
    }};
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    var assignment_storage: [64]u8 = undefined;
    try stream.appendSlice(
        allocator,
        try capsules.writeAddressAssignInto(&assignment_storage, &assigned),
    );
    try http3.capsule.writeDatagram(&stream, allocator, "\x00ip-packet");

    var session = Session.init(
        allocator,
        threaded.io(),
        .{ .input = stream.items },
        .{},
    );
    try session.bindConfigurationState(&configuration);
    defer session.deinit();
    var payload = try session.receive();
    defer payload.deinit(allocator);
    try std.testing.expectEqualStrings("ip-packet", payload.payload);
    try std.testing.expect(configuration.sourceIsAssigned(.{
        .ipv4 = .{ 192, 0, 2, 71 },
    }));
    try std.testing.expect(session.tunnel.reset_code == null);
}

test "CONNECT-IP configuration OOM is retryable without stream reset" {
    const ResetCode = enum { protocol_error, enhance_your_calm };
    const Progress = struct { committed_bytes: usize = 0 };
    const Tunnel = struct {
        const Owned = struct {
            data: []const u8,
            end_stream: bool,

            pub fn deinit(self: *@This(), _: std.mem.Allocator) void {
                self.* = undefined;
            }
        };

        stream_id: u31 = 0,
        input: []const u8,
        delivered: bool = false,
        reset_code: ?ResetCode = null,

        pub fn read(self: *@This()) !Owned {
            if (self.delivered) return .{ .data = &.{}, .end_stream = true };
            self.delivered = true;
            return .{ .data = self.input, .end_stream = false };
        }

        pub fn readWithDeadline(
            self: *@This(),
            _: std.Io.Clock.Timestamp,
        ) !Owned {
            return self.read();
        }

        pub fn reset(self: *@This(), code: ResetCode) !void {
            self.reset_code = code;
        }
    };
    const Session = connect_ip.CapsuleSession(ResetCode, Tunnel, Progress);
    const allocator = std.testing.allocator;
    var threaded = std.Io.Threaded.init(allocator, .{});
    defer threaded.deinit();
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    var configuration = connect_ip.ConfigurationState.init(
        failing.allocator(),
        .{},
    );
    defer {
        configuration.allocator = allocator;
        configuration.deinit();
    }

    const routes = [_]capsules.Route{.{ .ipv4 = .{
        .start = .{ 203, 0, 113, 0 },
        .end = .{ 203, 0, 113, 255 },
        .ip_protocol = 6,
    } }};
    var encoded: [64]u8 = undefined;
    const route = try capsules.writeRouteAdvertisementInto(&encoded, &routes);
    var session = Session.init(
        allocator,
        threaded.io(),
        .{ .input = route },
        .{},
    );
    try session.bindConfigurationState(&configuration);
    defer session.deinit();

    try std.testing.expectError(error.OutOfMemory, session.receiveCapsule());
    try std.testing.expect(session.tunnel.reset_code == null);
    try std.testing.expectEqual(
        @as(usize, 0),
        configuration.advertisedRoutes().len,
    );
    configuration.allocator = allocator;
    var received = try session.receiveCapsule();
    defer received.deinit(allocator);
    try std.testing.expectEqual(
        @as(usize, 1),
        configuration.advertisedRoutes().len,
    );
}

test "CONNECT-IP configuration state applies snapshots transactionally" {
    const allocator = std.testing.allocator;
    var state = connect_ip.ConfigurationState.init(allocator, .{
        .max_request_ids_per_direction = 4,
        .max_assigned_prefixes = 2,
        .max_routes = 2,
    });
    defer state.deinit();

    const requests = [_]capsules.AddressPrefix{
        .{
            .request_id = 1,
            .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .prefix_length = 24,
        },
        .{
            .request_id = 2,
            .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .prefix_length = 32,
        },
    };
    var encoded: [256]u8 = undefined;
    const request_capsule = try capsules.writeAddressRequestInto(
        &encoded,
        &requests,
    );
    const request_value = (try http3.capsule.parse(request_capsule))
        .capsule.value;
    try state.recordLocalAddressRequest(request_value);
    try std.testing.expectEqual(@as(usize, 2), state.localRequestCount());
    try std.testing.expectError(
        error.DuplicateRequestId,
        state.recordLocalAddressRequest(request_value),
    );
    const prepared_request = [_]capsules.AddressPrefix{.{
        .request_id = 3,
        .address = .{ .ipv6 = [_]u8{0} ** 16 },
        .prefix_length = 128,
    }};
    const prepared_capsule = try capsules.writeAddressRequestInto(
        &encoded,
        &prepared_request,
    );
    const prepared_value = (try http3.capsule.parse(prepared_capsule))
        .capsule.value;
    try state.prepareLocalCapsule(
        capsules.address_request_type,
        prepared_value,
    );
    state.discardPreparedLocalCapsule();
    try std.testing.expectEqual(@as(usize, 2), state.localRequestCount());
    try state.prepareLocalCapsule(
        capsules.address_request_type,
        prepared_value,
    );
    state.commitPreparedLocalCapsule();
    try std.testing.expectEqual(@as(usize, 3), state.localRequestCount());

    const assignments = [_]capsules.AddressPrefix{
        .{
            .request_id = 1,
            .address = .{ .ipv4 = .{ 192, 0, 2, 0 } },
            .prefix_length = 24,
        },
        // All-zero host prefix at maximum length rejects request 2 and must
        // not become an active source assignment.
        .{
            .request_id = 2,
            .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
            .prefix_length = 32,
        },
    };
    const assignment_capsule = try capsules.writeAddressAssignInto(
        &encoded,
        &assignments,
    );
    const assignment_value = (try http3.capsule.parse(assignment_capsule))
        .capsule.value;
    try std.testing.expectEqual(
        connect_ip.ConfigurationApplyResult.address_assign,
        try state.applyPeerCapsule(
            capsules.address_assign_type,
            assignment_value,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), state.assignedPrefixes().len);
    try std.testing.expect(state.sourceIsAssigned(.{
        .ipv4 = .{ 192, 0, 2, 99 },
    }));
    try std.testing.expect(!state.sourceIsAssigned(.{
        .ipv4 = .{ 192, 0, 3, 1 },
    }));

    const routes = [_]capsules.Route{
        .{ .ipv4 = .{
            .start = .{ 10, 0, 0, 0 },
            .end = .{ 10, 0, 0, 255 },
            .ip_protocol = 0,
        } },
        .{ .ipv4 = .{
            .start = .{ 192, 0, 2, 0 },
            .end = .{ 192, 0, 2, 255 },
            .ip_protocol = 6,
        } },
    };
    const route_capsule = try capsules.writeRouteAdvertisementInto(
        &encoded,
        &routes,
    );
    const route_value = (try http3.capsule.parse(route_capsule)).capsule.value;
    _ = try state.applyPeerCapsule(
        capsules.route_advertisement_type,
        route_value,
    );
    try std.testing.expect(state.routeAllows(
        .{ .ipv4 = .{ 10, 0, 0, 7 } },
        17,
    ));
    try std.testing.expect(state.routeAllows(
        .{ .ipv4 = .{ 192, 0, 2, 7 } },
        6,
    ));
    try std.testing.expect(!state.routeAllows(
        .{ .ipv4 = .{ 192, 0, 2, 7 } },
        17,
    ));
    // ICMP remains allowed for an otherwise protocol-scoped route.
    try std.testing.expect(state.routeAllows(
        .{ .ipv4 = .{ 192, 0, 2, 7 } },
        1,
    ));

    const unknown_assignment = [_]capsules.AddressPrefix{.{
        .request_id = 4,
        .address = .{ .ipv4 = .{ 203, 0, 113, 4 } },
        .prefix_length = 32,
    }};
    const unknown_capsule = try capsules.writeAddressAssignInto(
        &encoded,
        &unknown_assignment,
    );
    const unknown_value = (try http3.capsule.parse(unknown_capsule))
        .capsule.value;
    try std.testing.expectError(
        error.UnknownRequestId,
        state.applyPeerCapsule(capsules.address_assign_type, unknown_value),
    );
    try std.testing.expectEqual(@as(usize, 1), state.assignedPrefixes().len);

    const empty_assign = try capsules.writeAddressAssignInto(&encoded, &.{});
    _ = try state.applyPeerCapsule(
        capsules.address_assign_type,
        (try http3.capsule.parse(empty_assign)).capsule.value,
    );
    try std.testing.expectEqual(@as(usize, 0), state.assignedPrefixes().len);
    try std.testing.expectEqual(@as(u64, 2), state.assignment_revision);
}

test "CONNECT-IP configuration state commits sent snapshots transactionally" {
    const allocator = std.testing.allocator;
    var state = connect_ip.ConfigurationState.init(allocator, .{
        .max_request_ids_per_direction = 2,
        .max_assigned_prefixes = 2,
        .max_routes = 2,
    });
    defer state.deinit();
    var encoded: [256]u8 = undefined;

    const peer_request = [_]capsules.AddressPrefix{.{
        .request_id = 81,
        .address = .{ .ipv4 = .{ 0, 0, 0, 0 } },
        .prefix_length = 32,
    }};
    const request = try capsules.writeAddressRequestInto(
        &encoded,
        &peer_request,
    );
    _ = try state.applyPeerCapsule(
        capsules.address_request_type,
        (try http3.capsule.parse(request)).capsule.value,
    );

    const unknown_assignment = [_]capsules.AddressPrefix{.{
        .request_id = 82,
        .address = .{ .ipv4 = .{ 192, 0, 2, 82 } },
        .prefix_length = 32,
    }};
    const unknown = try capsules.writeAddressAssignInto(
        &encoded,
        &unknown_assignment,
    );
    try std.testing.expectError(
        error.UnknownRequestId,
        state.prepareLocalCapsule(
            capsules.address_assign_type,
            (try http3.capsule.parse(unknown)).capsule.value,
        ),
    );

    const assignment = [_]capsules.AddressPrefix{.{
        .request_id = 81,
        .address = .{ .ipv4 = .{ 192, 0, 2, 81 } },
        .prefix_length = 32,
    }};
    const assigned = try capsules.writeAddressAssignInto(
        &encoded,
        &assignment,
    );
    const assigned_value = (try http3.capsule.parse(assigned)).capsule.value;
    try state.prepareLocalCapsule(
        capsules.address_assign_type,
        assigned_value,
    );
    try std.testing.expectEqual(@as(usize, 0), state.sentAssignedPrefixes().len);
    state.discardPreparedLocalCapsule();
    try std.testing.expectEqual(@as(usize, 0), state.sentAssignedPrefixes().len);
    try state.prepareLocalCapsule(
        capsules.address_assign_type,
        assigned_value,
    );
    state.commitPreparedLocalCapsule();
    try std.testing.expect(state.peerSourceIsAssigned(.{
        .ipv4 = .{ 192, 0, 2, 81 },
    }));
    try std.testing.expectEqual(@as(u64, 1), state.sent_assignment_revision);

    const routes = [_]capsules.Route{.{ .ipv4 = .{
        .start = .{ 203, 0, 113, 0 },
        .end = .{ 203, 0, 113, 255 },
        .ip_protocol = 6,
    } }};
    const route = try capsules.writeRouteAdvertisementInto(&encoded, &routes);
    try state.prepareLocalCapsule(
        capsules.route_advertisement_type,
        (try http3.capsule.parse(route)).capsule.value,
    );
    state.commitPreparedLocalCapsule();
    try std.testing.expect(state.peerRouteAllows(
        .{ .ipv4 = .{ 203, 0, 113, 42 } },
        6,
    ));
    try std.testing.expect(state.peerRouteAllows(
        .{ .ipv4 = .{ 203, 0, 113, 42 } },
        1,
    ));
    try std.testing.expect(!state.peerRouteAllows(
        .{ .ipv4 = .{ 203, 0, 113, 42 } },
        17,
    ));

    const empty_assign = try capsules.writeAddressAssignInto(&encoded, &.{});
    try state.prepareLocalCapsule(
        capsules.address_assign_type,
        (try http3.capsule.parse(empty_assign)).capsule.value,
    );
    state.commitPreparedLocalCapsule();
    try std.testing.expectEqual(@as(usize, 0), state.sentAssignedPrefixes().len);
    const empty_routes = try capsules.writeRouteAdvertisementInto(
        &encoded,
        &.{},
    );
    try state.prepareLocalCapsule(
        capsules.route_advertisement_type,
        (try http3.capsule.parse(empty_routes)).capsule.value,
    );
    state.commitPreparedLocalCapsule();
    try std.testing.expectEqual(@as(usize, 0), state.sentAdvertisedRoutes().len);
    try std.testing.expectEqual(@as(u64, 2), state.sent_assignment_revision);
    try std.testing.expectEqual(@as(u64, 2), state.sent_route_revision);
}

test "CONNECT-IP configuration state bounds peer IDs and route rollback" {
    const allocator = std.testing.allocator;
    var state = connect_ip.ConfigurationState.init(allocator, .{
        .max_request_ids_per_direction = 1,
        .max_assigned_prefixes = 1,
        .max_routes = 1,
    });
    defer state.deinit();
    var encoded: [128]u8 = undefined;
    const first_request = [_]capsules.AddressPrefix{.{
        .request_id = 41,
        .address = .{ .ipv6 = [_]u8{0} ** 16 },
        .prefix_length = 128,
    }};
    const first = try capsules.writeAddressRequestInto(
        &encoded,
        &first_request,
    );
    const first_value = (try http3.capsule.parse(first)).capsule.value;
    _ = try state.applyPeerCapsule(capsules.address_request_type, first_value);
    try std.testing.expectError(
        error.DuplicateRequestId,
        state.applyPeerCapsule(capsules.address_request_type, first_value),
    );

    const second_request = [_]capsules.AddressPrefix{.{
        .request_id = 42,
        .address = .{ .ipv6 = [_]u8{0} ** 16 },
        .prefix_length = 128,
    }};
    const second = try capsules.writeAddressRequestInto(
        &encoded,
        &second_request,
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        state.applyPeerCapsule(
            capsules.address_request_type,
            (try http3.capsule.parse(second)).capsule.value,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), state.peerRequestCount());

    const one_route = [_]capsules.Route{.{ .ipv4 = .{
        .start = .{ 10, 0, 0, 0 },
        .end = .{ 10, 0, 0, 10 },
    } }};
    const one = try capsules.writeRouteAdvertisementInto(&encoded, &one_route);
    _ = try state.applyPeerCapsule(
        capsules.route_advertisement_type,
        (try http3.capsule.parse(one)).capsule.value,
    );
    const too_many = [_]capsules.Route{
        one_route[0],
        .{ .ipv4 = .{
            .start = .{ 10, 0, 0, 11 },
            .end = .{ 10, 0, 0, 20 },
        } },
    };
    const overflow = try capsules.writeRouteAdvertisementInto(
        &encoded,
        &too_many,
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        state.applyPeerCapsule(
            capsules.route_advertisement_type,
            (try http3.capsule.parse(overflow)).capsule.value,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), state.advertisedRoutes().len);
    try std.testing.expectEqual(@as(u64, 1), state.route_revision);
}

test "CONNECT-IP configuration OOM preserves live route snapshot" {
    const allocator = std.testing.allocator;
    var state = connect_ip.ConfigurationState.init(allocator, .{
        .max_routes = 2,
    });
    defer {
        state.allocator = allocator;
        state.deinit();
    }
    var encoded: [128]u8 = undefined;
    const installed = [_]capsules.Route{.{ .ipv4 = .{
        .start = .{ 10, 0, 0, 0 },
        .end = .{ 10, 0, 0, 10 },
    } }};
    const first = try capsules.writeRouteAdvertisementInto(&encoded, &installed);
    _ = try state.applyPeerCapsule(
        capsules.route_advertisement_type,
        (try http3.capsule.parse(first)).capsule.value,
    );
    try std.testing.expectEqual(@as(u64, 1), state.route_revision);

    const replacement = [_]capsules.Route{
        .{ .ipv4 = .{
            .start = .{ 192, 0, 2, 0 },
            .end = .{ 192, 0, 2, 10 },
        } },
        .{ .ipv4 = .{
            .start = .{ 192, 0, 2, 11 },
            .end = .{ 192, 0, 2, 20 },
        } },
    };
    const second = try capsules.writeRouteAdvertisementInto(
        &encoded,
        &replacement,
    );
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    state.allocator = failing.allocator();
    try std.testing.expectError(
        error.OutOfMemory,
        state.applyPeerCapsule(
            capsules.route_advertisement_type,
            (try http3.capsule.parse(second)).capsule.value,
        ),
    );
    try std.testing.expectEqual(@as(u64, 1), state.route_revision);
    try std.testing.expectEqual(@as(usize, 1), state.advertisedRoutes().len);
    try std.testing.expect(state.routeAllows(
        .{ .ipv4 = .{ 10, 0, 0, 5 } },
        17,
    ));
    try std.testing.expect(!state.routeAllows(
        .{ .ipv4 = .{ 192, 0, 2, 5 } },
        17,
    ));
}

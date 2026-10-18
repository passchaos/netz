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

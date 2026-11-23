const std = @import("std");
const http3_root = @import("mod.zig");
const Qpack = @import("qpack/mod.zig");
const capsule = @import("capsule.zig");
const early_data = @import("../http/early_data.zig");
const quic = @import("../quic/mod.zig");
const wire = @import("../internal/wire.zig");

const ControlState = http3_root.ControlState;
const Datagram = http3_root.Datagram;
const Frame = http3_root.Frame;
const FrameType = http3_root.FrameType;
const InformationalResponse = http3_root.InformationalResponse;
const Origin = http3_root.Origin;
const OriginPayload = http3_root.OriginPayload;
const Priority = http3_root.Priority;
const Request = http3_root.Request;
const Response = http3_root.Response;
const ReuseDecision = http3_root.ReuseDecision;
const Setting = http3_root.Setting;
const SettingId = http3_root.SettingId;
const Settings = http3_root.Settings;
const StreamType = http3_root.StreamType;
const altSvcTarget = http3_root.altSvcTarget;
const checkDynamicQpackHeadAllocationFailure = http3_root.checkDynamicQpackHeadAllocationFailure;
const checkDynamicQpackMessageAllocationFailure = http3_root.checkDynamicQpackMessageAllocationFailure;
const checkPriorityUpdateStateAllocationFailure = http3_root.checkPriorityUpdateStateAllocationFailure;
const checkPushCancellationStateAllocationFailure = http3_root.checkPushCancellationStateAllocationFailure;
const connectionReuseDecision = http3_root.connectionReuseDecision;
const decodePushPromiseWithDynamicTable = http3_root.decodePushPromiseWithDynamicTable;
const decodeRequest = http3_root.decodeRequest;
const decodeRequestHeadWithDynamicTable = http3_root.decodeRequestHeadWithDynamicTable;
const decodeRequestWithDynamicTable = http3_root.decodeRequestWithDynamicTable;
const decodeRequestWithSettings = http3_root.decodeRequestWithSettings;
const decodeResponse = http3_root.decodeResponse;
const decodeResponseHeadWithDynamicTable = http3_root.decodeResponseHeadWithDynamicTable;
const decodeResponseWithDynamicTable = http3_root.decodeResponseWithDynamicTable;
const decodeResponseWithOptions = http3_root.decodeResponseWithOptions;
const decodeResponseWithSettings = http3_root.decodeResponseWithSettings;
const findHeader = http3_root.findHeader;
const firstHttp3AltSvc = http3_root.firstHttp3AltSvc;
const firstHttp3AltSvcHeader = http3_root.firstHttp3AltSvcHeader;
const firstHttp3AltSvcTarget = http3_root.firstHttp3AltSvcTarget;
const max_peer_origins = http3_root.max_peer_origins;
const max_priority_update_frame_len = http3_root.max_priority_update_frame_len;
const max_settings_payload_size = http3_root.max_settings_payload_size;
const max_single_varint_frame_len = http3_root.max_single_varint_frame_len;
const originFromSerialized = http3_root.originFromSerialized;
const originKeyFromOrigin = http3_root.originKeyFromOrigin;
const ownHeaderFields = http3_root.ownHeaderFields;
const ownedFieldValue = http3_root.ownedFieldValue;
const parseCancelPushPayload = http3_root.parseCancelPushPayload;
const parseGoAwayPayload = http3_root.parseGoAwayPayload;
const parseMaxPushIdPayload = http3_root.parseMaxPushIdPayload;
const parsePriorityUpdatePayload = http3_root.parsePriorityUpdatePayload;
const parsePushPromisePayload = http3_root.parsePushPromisePayload;
const parseSettings = http3_root.parseSettings;
const requestOrigin = http3_root.requestOrigin;
const requestOriginKey = http3_root.requestOriginKey;
const sameOrigin = http3_root.sameOrigin;
const validatePushPromise = http3_root.validatePushPromise;
const validateResponseBodyForStatusWithLength = http3_root.validateResponseBodyForStatusWithLength;
const validateResponsePushPromises = http3_root.validateResponsePushPromises;
const writeCancelPushFrame = http3_root.writeCancelPushFrame;
const writeCancelPushFrameInto = http3_root.writeCancelPushFrameInto;
const writeControlStreamPrefix = http3_root.writeControlStreamPrefix;
const writeMaxPushIdFrame = http3_root.writeMaxPushIdFrame;
const writePriorityUpdateFrame = http3_root.writePriorityUpdateFrame;
const writePriorityUpdateFrameInto = http3_root.writePriorityUpdateFrameInto;
const writePriorityUpdateFrameRaw = http3_root.writePriorityUpdateFrameRaw;
const writePushPriorityUpdateFrame = http3_root.writePushPriorityUpdateFrame;
const writePushPriorityUpdateFrameInto = http3_root.writePushPriorityUpdateFrameInto;
const writePushPromiseFrame = http3_root.writePushPromiseFrame;
const writeQpackDecoderStreamPrefix = http3_root.writeQpackDecoderStreamPrefix;
const writeQpackEncoderStreamPrefix = http3_root.writeQpackEncoderStreamPrefix;
const writeResponseSequence = http3_root.writeResponseSequence;
const writeResponseSequenceWithSettings = http3_root.writeResponseSequenceWithSettings;
const writeSettings = http3_root.writeSettings;
const writeSettingsFrame = http3_root.writeSettingsFrame;

test "HTTP/3 parses Alt-Svc HTTP/3 advertisements" {
    const robotics = try firstHttp3AltSvc("h3=\":443\"; ma=2592000,h3-29=\":443\"; ma=2592000") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("h3", robotics.alpn);
    try std.testing.expectEqualStrings(":443", robotics.authority);
    try std.testing.expectEqual(@as(?u16, 443), robotics.port);
    try std.testing.expectEqual(@as(?u64, 2_592_000), robotics.max_age);

    const draft = try firstHttp3AltSvc(" h2=\":443\"; ma=60, h3-29=\"alt.example:8443\"; ma=120 ") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("h3-29", draft.alpn);
    try std.testing.expectEqualStrings("alt.example:8443", draft.authority);
    try std.testing.expectEqual(@as(?u16, 8443), draft.port);
    try std.testing.expectEqual(@as(?u64, 120), draft.max_age);

    const ipv6 = try firstHttp3AltSvc("h3=\"[2001:db8::1]:443\"") orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("[2001:db8::1]:443", ipv6.authority);
    try std.testing.expectEqual(@as(?u16, 443), ipv6.port);

    try std.testing.expect((try firstHttp3AltSvc("clear")) == null);
    try std.testing.expect((try firstHttp3AltSvc("h2=\":443\"")) == null);

    const headers = [_]Qpack.HeaderField{
        .{ .name = "server", .value = "example" },
        .{ .name = "Alt-Svc", .value = "h2=\":443\", h3=\":8443\"; ma=30" },
    };
    const from_headers = try firstHttp3AltSvcHeader(&headers) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("h3", from_headers.alpn);
    try std.testing.expectEqual(@as(?u16, 8443), from_headers.port);

    const robotics_target = try altSvcTarget("robotics.bytedance.com", robotics, 443);
    try std.testing.expectEqualStrings("robotics.bytedance.com", robotics_target.connect_host);
    try std.testing.expectEqualStrings("robotics.bytedance.com", robotics_target.origin_host);
    try std.testing.expectEqual(@as(u16, 443), robotics_target.port);

    const header_target = try firstHttp3AltSvcTarget("example.com", &headers, 443) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("example.com", header_target.origin_host);
    try std.testing.expectEqualStrings("example.com", header_target.connect_host);
    try std.testing.expectEqual(@as(u16, 8443), header_target.port);

    const ipv6_target = try altSvcTarget("[2001:db8::2]", ipv6, 443);
    try std.testing.expectEqualStrings("2001:db8::2", ipv6_target.origin_host);
    try std.testing.expectEqualStrings("2001:db8::1", ipv6_target.connect_host);
    try std.testing.expectEqual(@as(u16, 443), ipv6_target.port);

    try std.testing.expectError(error.InvalidHeader, altSvcTarget("bad/host", robotics, 443));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\"\""));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\":bad\""));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\"example.com/evil\""));
    try std.testing.expectError(error.InvalidHeader, firstHttp3AltSvc("h3=\":443\"; ma=bad"));
}

test "HTTP/3 normalizes request origins for reuse policy" {
    const https_default = try requestOrigin("https", "Example.COM");
    try std.testing.expectEqualStrings("https", https_default.scheme);
    try std.testing.expectEqualStrings("Example.COM", https_default.host);
    try std.testing.expectEqual(@as(u16, 443), https_default.port);

    const explicit_https = try requestOrigin("https", "example.com:443");
    try std.testing.expect(sameOrigin(https_default, explicit_https));
    try std.testing.expectEqual(
        ReuseDecision.same_origin,
        connectionReuseDecision(https_default, explicit_https),
    );

    const different_port = try requestOrigin("https", "example.com:8443");
    try std.testing.expect(!sameOrigin(https_default, different_port));
    try std.testing.expectEqual(
        ReuseDecision.different_scheme_or_port,
        connectionReuseDecision(https_default, different_port),
    );

    const sibling_origin = try requestOrigin("https", "api.example.com");
    try std.testing.expectEqual(
        ReuseDecision.requires_authority_validation,
        connectionReuseDecision(https_default, sibling_origin),
    );

    const ipv6 = try requestOrigin("https", "[2001:db8::1]:443");
    try std.testing.expectEqualStrings("2001:db8::1", ipv6.host);
    try std.testing.expectEqual(@as(u16, 443), ipv6.port);

    const http_default = try requestOrigin("http", "example.com");
    try std.testing.expectEqual(@as(u16, 80), http_default.port);
    try std.testing.expect(!sameOrigin(https_default, http_default));
    try std.testing.expect(sameOrigin(
        try requestOrigin("https", "[2001:db8::1]:8443"),
        try originFromSerialized("https://[2001:db8::1]:8443"),
    ));

    try std.testing.expectError(error.InvalidHeader, requestOrigin("ftp", "example.com"));
    try std.testing.expectError(error.InvalidHeader, requestOrigin("https", "user@example.com"));
    try std.testing.expectError(error.InvalidHeader, requestOrigin("https", "example.com:bad"));
}

test "HTTP/3 RFC 9412 ORIGIN frames accumulate canonical origins" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    const advertised = [_][]const u8{
        "https://Example.COM",
        "https://cdn.example.com:8443",
        "https://example.com:443",
    };
    try OriginPayload.write(&encoded, allocator, &advertised);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.origin, frame.frame_type);
    var parsed = try OriginPayload.parse(allocator, frame.payload);
    defer parsed.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), parsed.origins.len);
    const expected_single = "\x0c\x15\x00\x13https://example.com";
    var single: std.ArrayList(u8) = .empty;
    defer single.deinit(allocator);
    try OriginPayload.write(
        &single,
        allocator,
        &.{"https://example.com"},
    );
    try std.testing.expectEqualSlices(u8, expected_single, single.items);
    const fixed = try Frame.parse(expected_single);
    var fixed_payload = try OriginPayload.parse(allocator, fixed.payload);
    defer fixed_payload.deinit(allocator);
    try std.testing.expectEqualStrings(
        "https://example.com",
        fixed_payload.origins[0],
    );

    var control = ControlState{};
    defer control.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 0), control.peerOriginGeneration());
    control.settings.received = true;
    try control.applyFrame(allocator, frame);
    try std.testing.expectEqual(@as(u64, 1), control.peerOriginGeneration());
    try std.testing.expect(control.peerOriginSetInitialized());
    // The explicit default port canonicalizes to the first origin rather than
    // consuming another bounded Origin Set entry.
    try std.testing.expectEqual(@as(usize, 2), control.peerOrigins().len);
    try std.testing.expect(control.peerOriginKnown(
        try requestOrigin("https", "example.com"),
    ));
    try std.testing.expect(control.peerOriginKnown(
        try requestOrigin("https", "CDN.EXAMPLE.COM:8443"),
    ));
    try std.testing.expectEqual(
        true,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "cdn.example.com:8443"),
        ).?,
    );
    try std.testing.expectEqual(
        false,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "missing.example"),
        ).?,
    );
    try control.removePeerOrigin(
        allocator,
        try requestOrigin("https", "cdn.example.com:8443"),
    );
    try std.testing.expectEqual(@as(u64, 2), control.peerOriginGeneration());
    try std.testing.expect(control.peerOriginExcluded(
        try requestOrigin("https", "cdn.example.com:8443"),
    ));
    try control.removePeerOrigin(
        allocator,
        try requestOrigin("https", "cdn.example.com:8443"),
    );
    try std.testing.expectEqual(@as(u64, 2), control.peerOriginGeneration());
    try std.testing.expect(!control.peerOriginKnown(
        try requestOrigin("https", "cdn.example.com:8443"),
    ));
    try std.testing.expectEqual(@as(usize, 1), control.peerOrigins().len);
    try control.removePeerOrigin(
        allocator,
        try requestOrigin("https", "initial.example"),
    );
    try std.testing.expectEqual(@as(u64, 3), control.peerOriginGeneration());
    try std.testing.expectEqual(
        false,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "initial.example"),
        ).?,
    );
    var readded: std.ArrayList(u8) = .empty;
    defer readded.deinit(allocator);
    try OriginPayload.write(
        &readded,
        allocator,
        &.{"https://initial.example"},
    );
    try control.applyFrame(allocator, try Frame.parse(readded.items));
    try std.testing.expectEqual(@as(u64, 4), control.peerOriginGeneration());
    try std.testing.expectEqual(
        true,
        control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "initial.example"),
        ).?,
    );
    var uninitialized = ControlState{};
    defer uninitialized.deinit(allocator);
    try std.testing.expect(uninitialized.peerOriginSetAllows(
        try requestOrigin("https", "initial.example"),
        try requestOrigin("https", "missing.example"),
    ) == null);
    try uninitialized.removePeerOrigin(
        allocator,
        try requestOrigin("https", "initial.example"),
    );
    try std.testing.expect(uninitialized.peerOriginExcluded(
        try requestOrigin("https", "initial.example"),
    ));
    try std.testing.expectEqual(
        @as(u64, 1),
        uninitialized.peerOriginGeneration(),
    );
    // Policy remains uninitialized, but pool reuse consults the independent
    // exclusion before applying the normal unknown-origin fallback.
    try std.testing.expect(uninitialized.peerOriginSetAllows(
        try requestOrigin("https", "initial.example"),
        try requestOrigin("https", "initial.example"),
    ) == null);

    var empty: std.ArrayList(u8) = .empty;
    defer empty.deinit(allocator);
    try OriginPayload.write(&empty, allocator, &.{});
    var empty_control = ControlState{};
    defer empty_control.deinit(allocator);
    empty_control.settings.received = true;
    try empty_control.applyFrame(allocator, try Frame.parse(empty.items));
    try std.testing.expect(empty_control.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 0), empty_control.peerOrigins().len);
    try std.testing.expectEqual(
        true,
        empty_control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "initial.example:443"),
        ).?,
    );
    try std.testing.expectEqual(
        false,
        empty_control.peerOriginSetAllows(
            try requestOrigin("https", "initial.example"),
            try requestOrigin("https", "other.example"),
        ).?,
    );
}

test "HTTP/3 ORIGIN ignores invalid origins and rejects malformed framing" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try wire.appendInt(&payload, allocator, u16, 0, .big);
    try wire.appendInt(&payload, allocator, u16, 13, .big);
    try payload.appendSlice(allocator, "not-an-origin");
    try wire.appendInt(&payload, allocator, u16, 21, .big);
    try payload.appendSlice(allocator, "https://valid.example");

    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;
    try control.applyFrame(allocator, .{
        .frame_type = FrameType.origin,
        .payload = payload.items,
        .consumed = 0,
    });
    try std.testing.expect(control.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 1), control.peerOrigins().len);
    try std.testing.expect(control.peerOriginKnown(
        try requestOrigin("https", "valid.example"),
    ));

    var malformed = [_]u8{ 0, 5, 'h', 't' };
    try std.testing.expectError(
        error.BufferTooShort,
        OriginPayload.parse(allocator, &malformed),
    );
    try std.testing.expectError(
        error.InvalidOrigin,
        OriginPayload.write(&payload, allocator, &.{"https://example.com/path"}),
    );
}

test "HTTP/3 ORIGIN state update is transactional on allocation failure" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(
        &encoded,
        allocator,
        &.{"https://new.example"},
    );
    const frame = try Frame.parse(encoded.items);

    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0, .resize_fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        control.applyFrame(fail_first.allocator(), frame),
    );
    try std.testing.expect(!control.peerOriginSetInitialized());
    try std.testing.expectEqual(@as(usize, 0), control.peerOrigins().len);
}

test "HTTP/3 control stream buffers a split ORIGIN frame" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(
        &encoded,
        allocator,
        &.{"https://split.example"},
    );

    for (1..encoded.items.len) |split| {
        var control = ControlState{};
        defer control.deinit(allocator);
        control.settings.received = true;
        try control.appendControlPayload(
            allocator,
            encoded.items[0..split],
        );
        try std.testing.expect(!control.peerOriginSetInitialized());
        try control.appendControlPayload(
            allocator,
            encoded.items[split..],
        );
        try std.testing.expect(control.peerOriginSetInitialized());
        try std.testing.expect(control.peerOriginKnown(
            try requestOrigin("https", "split.example"),
        ));
        try std.testing.expectEqual(
            @as(usize, 0),
            control.peer_control_stream_buffer.items.len,
        );
    }
}

test "HTTP/3 incomplete control frame avoids state snapshot allocation" {
    const allocator = std.testing.allocator;
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);

    var priority: std.ArrayList(u8) = .empty;
    defer priority.deinit(allocator);
    try writePriorityUpdateFrame(
        &priority,
        allocator,
        0,
        .{ .urgency = 2 },
    );
    try control.applyFrame(allocator, try Frame.parse(priority.items));
    try control.peer_control_stream_buffer.ensureTotalCapacity(allocator, 8);

    // Unknown extension frame type 0x21, two-byte payload, one payload byte
    // still missing. Existing priority state ensures the old eager snapshot
    // path would have needed an allocation before noticing incompleteness.
    const partial = [_]u8{ 0x21, 0x02, 0xaa };
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try control.appendControlPayload(no_alloc.allocator(), &partial);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        control.peer_control_stream_skip_remaining,
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );

    try control.appendControlPayload(allocator, &.{0xbb});
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_skip_remaining,
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );

    const complete_extension = [_]u8{ 0x21, 0x01, 0xcc };
    try control.appendControlPayload(
        no_alloc.allocator(),
        &complete_extension,
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        @as(usize, 0),
        control.peer_control_stream_buffer.items.len,
    );
}

test "HTTP/3 ORIGIN state enforces its connection memory bound" {
    const allocator = std.testing.allocator;
    var control = ControlState{};
    defer control.deinit(allocator);
    control.settings.received = true;

    var serialized: [max_peer_origins][32]u8 = undefined;
    var origins: [max_peer_origins][]const u8 = undefined;
    for (&serialized, &origins, 0..) |*storage, *origin, index| {
        origin.* = try std.fmt.bufPrint(
            storage,
            "https://o{d}.example",
            .{index},
        );
    }
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try OriginPayload.write(&encoded, allocator, &origins);
    try control.applyFrame(allocator, try Frame.parse(encoded.items));
    try std.testing.expectEqual(
        max_peer_origins,
        control.peerOrigins().len,
    );

    encoded.clearRetainingCapacity();
    try OriginPayload.write(
        &encoded,
        allocator,
        &.{"https://overflow.example"},
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        control.applyFrame(allocator, try Frame.parse(encoded.items)),
    );
    try std.testing.expectEqual(
        max_peer_origins,
        control.peerOrigins().len,
    );
}

test "HTTP/3 owns canonical origin keys for connection pools" {
    const allocator = std.testing.allocator;

    var key = try requestOriginKey(allocator, "HTTPS", "Example.COM:443");
    defer key.deinit();
    try std.testing.expectEqualStrings("https", key.scheme);
    try std.testing.expectEqualStrings("example.com", key.host);
    try std.testing.expectEqual(@as(u16, 443), key.port);

    var from_origin = try originKeyFromOrigin(allocator, try requestOrigin("HTTPS", "Example.COM"));
    defer from_origin.deinit();
    try std.testing.expect(sameOrigin(key.origin(), from_origin.origin()));

    var sibling = try requestOriginKey(allocator, "https", "api.example.com");
    defer sibling.deinit();
    try std.testing.expectEqual(
        ReuseDecision.requires_authority_validation,
        connectionReuseDecision(key.origin(), sibling.origin()),
    );

    var ipv6 = try requestOriginKey(allocator, "HTTPS", "[2001:DB8::1]:443");
    defer ipv6.deinit();
    try std.testing.expectEqualStrings("2001:db8::1", ipv6.host);
    try std.testing.expect(sameOrigin(
        ipv6.origin(),
        try requestOrigin("https", "[2001:db8::1]"),
    ));
}

test "HTTP/3 frame settings and qpack literal block" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    const settings = [_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.webtransport_max_sessions), .value = 16 },
    };
    try writeSettings(&payload, allocator, &settings);

    var encoded_frame: std.ArrayList(u8) = .empty;
    defer encoded_frame.deinit(allocator);
    try (Frame{ .frame_type = FrameType.settings, .payload = payload.items, .consumed = 0 }).write(&encoded_frame, allocator);
    try std.testing.expectEqual(@as(u8, FrameType.settings), encoded_frame.items[0]);
    try std.testing.expectEqual(@as(u8, @intCast(payload.items.len)), encoded_frame.items[1]);
    const frame = try Frame.parse(encoded_frame.items);
    const parsed_settings = try parseSettings(allocator, frame.payload);
    defer allocator.free(parsed_settings);
    try std.testing.expectEqual(@as(u64, 1), parsed_settings[0].value);
    try std.testing.expectError(error.UnexpectedFrame, (Frame{
        .frame_type = 0x02, // HTTP/2 PRIORITY is reserved in HTTP/3.
        .payload = &.{},
        .consumed = 0,
    }).write(&encoded_frame, allocator));

    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    const fields = [_]Qpack.HeaderField{ .{ .name = ":method", .value = "GET" }, .{ .name = ":path", .value = "/" } };
    try Qpack.encodeLiteralBlock(&block, allocator, &fields);
    try std.testing.expectEqual(@as(u8, 0xd1), block.items[2]); // static index 17, :method GET
    try std.testing.expectEqual(@as(u8, 0xc1), block.items[3]); // static index 1, :path /
    const decoded = try Qpack.decodeLiteralBlock(allocator, block.items);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings(":method", decoded[0].name);
    try std.testing.expectEqualStrings("GET", decoded[0].value);
}

test "HTTP/3 settings identifier zero is an ignorable extension" {
    const allocator = std.testing.allocator;

    const parsed = try parseSettings(allocator, &.{ 0x00, 0x2a });
    defer allocator.free(parsed);
    try std.testing.expectEqualSlices(Setting, &.{.{ .id = 0x00, .value = 0x2a }}, parsed);

    // Identifier zero has no defined HTTP/3 meaning, so the typed settings
    // view must ignore it just like any other unknown extension identifier.
    try std.testing.expectEqual(Settings{}, Settings.fromList(parsed));

    for ([_]u8{ 0x02, 0x03, 0x04, 0x05 }) |reserved_id| {
        try std.testing.expectError(
            error.InvalidSetting,
            parseSettings(allocator, &.{ reserved_id, 0x00 }),
        );
    }
}

test "HTTP/3 frame header parses before payload arrives" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try quic.varint.encode(&encoded, allocator, FrameType.data);
    try quic.varint.encode(&encoded, allocator, 1_000_000);

    const header = try Frame.parseHeader(encoded.items);
    try std.testing.expectEqual(FrameType.data, header.frame_type);
    try std.testing.expectEqual(@as(usize, 1_000_000), header.payload_length);
    try std.testing.expectEqual(encoded.items.len, header.header_length);
    try std.testing.expectEqual(
        encoded.items.len + 1_000_000,
        try header.totalLength(),
    );
    try std.testing.expectError(
        error.BufferTooShort,
        Frame.parse(encoded.items),
    );

    for (0..encoded.items.len) |len| {
        try std.testing.expectError(
            error.BufferTooShort,
            Frame.parseHeader(encoded.items[0..len]),
        );
    }
}

test "HTTP/3 unidirectional stream prefixes write fixed bytes" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try writeControlStreamPrefix(&encoded, allocator);
    try writeQpackEncoderStreamPrefix(&encoded, allocator);
    try writeQpackDecoderStreamPrefix(&encoded, allocator);

    try std.testing.expectEqualSlices(u8, &.{
        @intFromEnum(StreamType.control),
        @intFromEnum(StreamType.qpack_encoder),
        @intFromEnum(StreamType.qpack_decoder),
    }, encoded.items);
}

test "HTTP/3 rejects reserved HTTP/2 frame types" {
    const allocator = std.testing.allocator;
    const reserved_frame_types = [_]u64{ 0x02, 0x06, 0x08, 0x09 };
    for (reserved_frame_types) |frame_type| {
        var encoded: std.ArrayList(u8) = .empty;
        defer encoded.deinit(allocator);
        try std.testing.expectError(error.UnexpectedFrame, (Frame{ .frame_type = frame_type, .payload = "", .consumed = 0 }).write(&encoded, allocator));
        try quic.varint.encode(&encoded, allocator, frame_type);
        try quic.varint.encode(&encoded, allocator, 0);
        try std.testing.expectError(error.UnexpectedFrame, Frame.parse(encoded.items));
    }
}

test "HTTP/3 generic frame codec rejects WebTransport stream prefix" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try quic.varint.encode(
        &encoded,
        allocator,
        FrameType.webtransport_stream,
    );
    try quic.varint.encode(&encoded, allocator, 17);
    try std.testing.expectError(
        error.UnexpectedFrame,
        Frame.parseHeader(encoded.items),
    );
    try std.testing.expectError(
        error.UnexpectedFrame,
        (Frame{
            .frame_type = FrameType.webtransport_stream,
            .payload = &.{},
            .consumed = 0,
        }).write(&encoded, allocator),
    );
}

test "HTTP/3 priority field and PRIORITY_UPDATE frame" {
    const allocator = std.testing.allocator;
    const parsed = Priority.parse("u=1, foo=bar, i=?1");
    try std.testing.expectEqual(@as(u3, 1), parsed.urgency);
    try std.testing.expect(parsed.incremental);
    var field_buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("u=1, i", parsed.serialize(&field_buf));
    try std.testing.expectEqual(@as(u3, 3), Priority.parse("u=9, i=?0").urgency);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(&encoded, allocator, 8, parsed);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.priority_update_request, frame.frame_type);
    const payload = try parsePriorityUpdatePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 8), payload.prioritized_element_id);
    try std.testing.expectEqual(@as(u3, 1), payload.priority().urgency);
    try std.testing.expect(payload.priority().incremental);

    var control = ControlState{};
    defer control.deinit(allocator);
    try std.testing.expect(control.requestPriorityUpdate(8) == null);
    try std.testing.expect(control.pushPriorityUpdate(3) == null);
    var settings_payload: std.ArrayList(u8) = .empty;
    defer settings_payload.deinit(allocator);
    try writeControlStreamPrefix(&settings_payload, allocator);
    try writeSettingsFrame(&settings_payload, allocator, .{});
    try control.applyControlStreamBytes(allocator, settings_payload.items);
    try control.applyFrame(allocator, frame);
    try std.testing.expectEqual(@as(u64, 8), control.latest_priority_update.?.prioritized_element_id);
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );

    var second_request: std.ArrayList(u8) = .empty;
    defer second_request.deinit(allocator);
    try writePriorityUpdateFrame(
        &second_request,
        allocator,
        12,
        .{ .urgency = 5 },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(second_request.items),
    );
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(12).?.priority().urgency,
    );
    var replacement_request: std.ArrayList(u8) = .empty;
    defer replacement_request.deinit(allocator);
    try writePriorityUpdateFrame(
        &replacement_request,
        allocator,
        8,
        .{ .urgency = 0 },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(replacement_request.items),
    );
    try std.testing.expectEqual(
        @as(u3, 0),
        control.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(12).?.priority().urgency,
    );
    try std.testing.expectEqual(@as(usize, 2), control.priority_updates.items.len);
    try std.testing.expectEqual(
        @as(?usize, 0),
        control.priority_update_index.get(.{
            .frame_type = FrameType.priority_update_request,
            .prioritized_element_id = 8,
        }),
    );
    try std.testing.expectEqual(
        @as(?usize, 1),
        control.priority_update_index.get(.{
            .frame_type = FrameType.priority_update_request,
            .prioritized_element_id = 12,
        }),
    );

    var push_priority: std.ArrayList(u8) = .empty;
    defer push_priority.deinit(allocator);
    try writePushPriorityUpdateFrame(
        &push_priority,
        allocator,
        3,
        .{ .urgency = 2, .incremental = true },
    );
    try control.applyFrame(
        allocator,
        try Frame.parse(push_priority.items),
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        control.pushPriorityUpdate(3).?.priority().urgency,
    );
    try std.testing.expect(
        control.pushPriorityUpdate(3).?.priority().incremental,
    );
    var cloned = try control.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(
        @as(u3, 0),
        cloned.requestPriorityUpdate(8).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        cloned.requestPriorityUpdate(12).?.priority().urgency,
    );
    try std.testing.expectEqual(
        @as(u3, 2),
        cloned.pushPriorityUpdate(3).?.priority().urgency,
    );

    try std.testing.expectError(error.UnexpectedFrame, writePriorityUpdateFrame(&encoded, allocator, 1, parsed));
    var invalid_priority: std.ArrayList(u8) = .empty;
    defer invalid_priority.deinit(allocator);
    try writePriorityUpdateFrameRaw(&invalid_priority, allocator, FrameType.priority_update_request, 1, "u=1");
    const invalid_frame = try Frame.parse(invalid_priority.items);
    try std.testing.expectError(error.IdError, control.applyFrame(allocator, invalid_frame));

    var no_alloc_priority: std.ArrayList(u8) = .empty;
    defer no_alloc_priority.deinit(allocator);
    try no_alloc_priority.ensureTotalCapacity(allocator, 32);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writePriorityUpdateFrameRaw(
        &no_alloc_priority,
        no_alloc.allocator(),
        FrameType.priority_update_request,
        16,
        "u=2",
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    const no_alloc_frame = try Frame.parse(no_alloc_priority.items);
    const no_alloc_payload = try parsePriorityUpdatePayload(no_alloc_frame.payload);
    try std.testing.expectEqual(@as(u64, 16), no_alloc_payload.prioritized_element_id);
    try std.testing.expectEqualStrings("u=2", no_alloc_payload.field_value);

    var direct_storage: [max_priority_update_frame_len]u8 = undefined;
    try std.testing.expectEqualSlices(
        u8,
        no_alloc_priority.items,
        try writePriorityUpdateFrameInto(
            &direct_storage,
            16,
            .{ .urgency = 2 },
        ),
    );
    var push_list: std.ArrayList(u8) = .empty;
    defer push_list.deinit(allocator);
    try writePushPriorityUpdateFrame(
        &push_list,
        allocator,
        quic.varint.max_value,
        .{ .urgency = 7, .incremental = true },
    );
    try std.testing.expectEqual(
        max_priority_update_frame_len,
        push_list.items.len,
    );
    try std.testing.expectEqualSlices(
        u8,
        push_list.items,
        try writePushPriorityUpdateFrameInto(
            &direct_storage,
            quic.varint.max_value,
            .{ .urgency = 7, .incremental = true },
        ),
    );
    try std.testing.expectError(
        error.UnexpectedFrame,
        writePriorityUpdateFrameInto(&direct_storage, 1, .{}),
    );
}

test "HTTP/3 per-element priority state is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPriorityUpdateStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 identical priority update replacement does not allocate" {
    const allocator = std.testing.allocator;
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePriorityUpdateFrame(
        &encoded,
        allocator,
        0,
        .{ .urgency = 1, .incremental = true },
    );
    const frame = try Frame.parse(encoded.items);
    try control.applyFrame(allocator, frame);
    const generation = control.priority_update_generation;

    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try control.applyFrame(no_alloc.allocator(), frame);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(
        generation + 1,
        control.priority_update_generation,
    );
    try std.testing.expectEqual(
        @as(u3, 1),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    try std.testing.expect(
        control.requestPriorityUpdate(0).?.priority().incremental,
    );
}

test "HTTP/3 priority state is bounded and request removal repairs indexes" {
    const allocator = std.testing.allocator;
    var control = try ControlState.init(.{ .max_priority_updates = 2 });
    defer control.deinit(allocator);
    control.settings.received = true;

    var first: std.ArrayList(u8) = .empty;
    defer first.deinit(allocator);
    try writePriorityUpdateFrame(&first, allocator, 0, .{ .urgency = 1 });
    try control.applyFrame(allocator, try Frame.parse(first.items));
    var second: std.ArrayList(u8) = .empty;
    defer second.deinit(allocator);
    try writePriorityUpdateFrame(&second, allocator, 4, .{ .urgency = 2 });
    try control.applyFrame(allocator, try Frame.parse(second.items));

    first.clearRetainingCapacity();
    try writePriorityUpdateFrame(&first, allocator, 0, .{ .urgency = 5 });
    try control.applyFrame(allocator, try Frame.parse(first.items));
    try std.testing.expectEqual(
        @as(u3, 5),
        control.requestPriorityUpdate(0).?.priority().urgency,
    );
    var cloned = try control.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(
        @as(u64, 0),
        cloned.latest_priority_update.?.prioritized_element_id,
    );
    try std.testing.expectEqual(
        @as(u3, 5),
        cloned.latest_priority_update.?.priority().urgency,
    );

    var overflow: std.ArrayList(u8) = .empty;
    defer overflow.deinit(allocator);
    try writePriorityUpdateFrame(&overflow, allocator, 8, .{});
    try std.testing.expectError(
        error.ExcessiveLoad,
        control.applyFrame(allocator, try Frame.parse(overflow.items)),
    );
    try std.testing.expect(control.requestPriorityUpdate(8) == null);

    control.removeRequestPriority(allocator, 0);
    try std.testing.expect(control.requestPriorityUpdate(0) == null);
    try std.testing.expectEqual(
        @as(u3, 2),
        control.requestPriorityUpdate(4).?.priority().urgency,
    );
    try control.applyFrame(allocator, try Frame.parse(overflow.items));
    try std.testing.expect(control.requestPriorityUpdate(8) != null);
    control.removeRequestPriority(allocator, 99);

    control.removeRequestPriority(allocator, 4);
    var push: std.ArrayList(u8) = .empty;
    defer push.deinit(allocator);
    try writePushPriorityUpdateFrame(&push, allocator, 3, .{ .urgency = 6 });
    try control.applyFrame(allocator, try Frame.parse(push.items));
    try std.testing.expect(control.pushPriorityUpdate(3) != null);
    control.removePushPriority(allocator, 3);
    try std.testing.expect(control.pushPriorityUpdate(3) == null);

    control.retireRequestPriority(allocator, 8);
    try control.applyFrame(allocator, try Frame.parse(overflow.items));
    control.discardRetiredPriorityUpdates(allocator);
    try std.testing.expect(control.requestPriorityUpdate(8) == null);
    try std.testing.expectEqual(@as(usize, 0), control.priorityUpdates().len);

    try control.applyFrame(allocator, try Frame.parse(push.items));
    control.retirePushPriority(allocator, 3);
    try control.applyFrame(allocator, try Frame.parse(push.items));
    control.discardRetiredPriorityUpdates(allocator);
    try std.testing.expect(control.pushPriorityUpdate(3) == null);
    try std.testing.expectEqual(@as(usize, 0), control.priorityUpdates().len);
}

test "HTTP/3 priority state rejects a zero bound" {
    try std.testing.expectError(
        error.InvalidSetting,
        ControlState.init(.{ .max_priority_updates = 0 }),
    );
}

test "HTTP/3 control stream rejects request frames" {
    const allocator = std.testing.allocator;
    var control = ControlState{};
    defer control.deinit(allocator);
    var stream: std.ArrayList(u8) = .empty;
    defer stream.deinit(allocator);
    try writeControlStreamPrefix(&stream, allocator);
    try writeSettingsFrame(&stream, allocator, .{});
    try (Frame{ .frame_type = FrameType.data, .payload = "forbidden", .consumed = 0 }).write(&stream, allocator);
    try std.testing.expectError(error.UnexpectedFrame, control.applyControlStreamBytes(allocator, stream.items));

    var initialized = ControlState{ .settings = .{ .received = true } };
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.headers,
        .payload = &.{},
        .consumed = 0,
    }));
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.push_promise,
        .payload = &.{},
        .consumed = 0,
    }));
    try std.testing.expectError(error.UnexpectedFrame, initialized.applyFrame(allocator, .{
        .frame_type = FrameType.webtransport_stream,
        .payload = &.{},
        .consumed = 0,
    }));
}

test "HTTP/3 control stream enforces SETTINGS first and GOAWAY monotonicity" {
    const allocator = std.testing.allocator;

    var local_control = ControlState{};
    var stream_bytes: std.ArrayList(u8) = .empty;
    defer stream_bytes.deinit(allocator);
    try local_control.writeSettingsStream(&stream_bytes, allocator, .{
        .h3_datagram = true,
        .webtransport_max_sessions = 2,
    });
    try local_control.writeGoAway(&stream_bytes, allocator, 12);
    try std.testing.expectError(error.GoAwayIdIncreased, local_control.writeGoAway(&stream_bytes, allocator, 16));

    var peer_control = ControlState{};
    try peer_control.applyControlStreamBytes(allocator, stream_bytes.items);
    try std.testing.expectEqual(@as(?u64, 0), peer_control.peer_control_stream_id);
    try peer_control.registerControlStream(0);
    try std.testing.expectError(error.StreamCreationError, peer_control.registerControlStream(4));
    try std.testing.expect(peer_control.settings.received);
    try std.testing.expect(peer_control.settings.peer.h3_datagram);
    try std.testing.expectEqual(@as(u64, 2), peer_control.settings.peer.webtransport_max_sessions);
    try std.testing.expectEqual(@as(?u64, 12), peer_control.peer_goaway_id);
    try std.testing.expect(peer_control.acceptsRequestStream(8));
    try std.testing.expect(!peer_control.acceptsRequestStream(12));

    var invalid: std.ArrayList(u8) = .empty;
    defer invalid.deinit(allocator);
    try writeControlStreamPrefix(&invalid, allocator);
    var goaway_payload: std.ArrayList(u8) = .empty;
    defer goaway_payload.deinit(allocator);
    try quic.varint.encode(&goaway_payload, allocator, 0);
    try (Frame{ .frame_type = FrameType.goaway, .payload = goaway_payload.items, .consumed = 0 }).write(&invalid, allocator);
    var missing_settings = ControlState{};
    try std.testing.expectError(error.MissingSettings, missing_settings.applyControlStreamBytes(allocator, invalid.items));

    var bad_settings: std.ArrayList(u8) = .empty;
    defer bad_settings.deinit(allocator);
    try quic.varint.encode(&bad_settings, allocator, 0x04);
    try quic.varint.encode(&bad_settings, allocator, 1);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    bad_settings.clearRetainingCapacity();
    try quic.varint.encode(&bad_settings, allocator, @intFromEnum(SettingId.h3_datagram));
    try quic.varint.encode(&bad_settings, allocator, 2);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, bad_settings.items));

    try std.testing.expectError(error.InvalidSetting, writeSettings(&bad_settings, allocator, &[_]Setting{
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
        .{ .id = @intFromEnum(SettingId.h3_datagram), .value = 1 },
    }));
    try std.testing.expectError(error.InvalidSetting, writeSettings(&bad_settings, allocator, &[_]Setting{.{ .id = 0x04, .value = 0 }}));

    var excessive_settings: std.ArrayList(u8) = .empty;
    defer excessive_settings.deinit(allocator);
    try excessive_settings.appendNTimes(allocator, 0, max_settings_payload_size + 1);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, excessive_settings.items));

    var duplicate_settings = ControlState{};
    var duplicate: std.ArrayList(u8) = .empty;
    defer duplicate.deinit(allocator);
    try duplicate_settings.writeSettingsStream(&duplicate, allocator, .{});
    try writeSettingsFrame(&duplicate, allocator, .{});
    try std.testing.expectError(error.DuplicateSettings, duplicate_settings.applyControlStreamBytes(allocator, duplicate.items));
}

test "HTTP/3 push control frames and state" {
    const allocator = std.testing.allocator;

    var cancel: std.ArrayList(u8) = .empty;
    defer cancel.deinit(allocator);
    try writeCancelPushFrame(&cancel, allocator, 7);
    const cancel_frame = try Frame.parse(cancel.items);
    try std.testing.expectEqual(FrameType.cancel_push, cancel_frame.frame_type);
    try std.testing.expectEqual(@as(u64, 7), try parseCancelPushPayload(cancel_frame.payload));

    var max_push: std.ArrayList(u8) = .empty;
    defer max_push.deinit(allocator);
    var control = ControlState{};
    defer control.deinit(allocator);
    try control.writeMaxPushId(&max_push, allocator, 4);
    try std.testing.expectEqual(@as(?u64, 4), control.local_max_push_id);
    try control.writeMaxPushId(&max_push, allocator, 8);
    try std.testing.expectEqual(@as(?u64, 8), control.local_max_push_id);
    try std.testing.expectError(error.MaxPushIdReduced, control.writeMaxPushId(&max_push, allocator, 2));

    var peer_control = ControlState{ .settings = .{ .received = true } };
    defer peer_control.deinit(allocator);
    const first = try Frame.parse(max_push.items);
    try peer_control.applyFrame(allocator, first);
    try std.testing.expectEqual(@as(?u64, 4), peer_control.peer_max_push_id);
    const second = try Frame.parse(max_push.items[first.consumed..]);
    try peer_control.applyFrame(allocator, second);
    try std.testing.expectEqual(@as(?u64, 8), peer_control.peer_max_push_id);

    var reduced: std.ArrayList(u8) = .empty;
    defer reduced.deinit(allocator);
    try writeMaxPushIdFrame(&reduced, allocator, 1);
    const reduced_frame = try Frame.parse(reduced.items);
    try std.testing.expectError(error.MaxPushIdReduced, peer_control.applyFrame(allocator, reduced_frame));

    try peer_control.applyFrame(allocator, cancel_frame);
    var second_cancel: std.ArrayList(u8) = .empty;
    defer second_cancel.deinit(allocator);
    try writeCancelPushFrame(&second_cancel, allocator, 3);
    try peer_control.applyFrame(
        allocator,
        try Frame.parse(second_cancel.items),
    );
    // Duplicate cancellation is idempotent; distinct IDs remain queryable.
    try peer_control.applyFrame(allocator, cancel_frame);
    try std.testing.expect(peer_control.pushCancelled(7));
    try std.testing.expect(peer_control.pushCancelled(3));
    try std.testing.expectEqual(
        @as(usize, 2),
        peer_control.cancelledPushRangeCount(),
    );
}

test "HTTP/3 single-varint control frames avoid temporary payload allocation" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.ensureTotalCapacity(allocator, 16);

    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writeCancelPushFrame(&encoded, no_alloc.allocator(), 7);
    try writeMaxPushIdFrame(&encoded, no_alloc.allocator(), 4);

    var control = ControlState{};
    try control.writeGoAway(&encoded, no_alloc.allocator(), 12);

    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(u8, &.{
        FrameType.cancel_push, 1, 7,
        FrameType.max_push_id, 1, 4,
        FrameType.goaway,      1, 12,
    }, encoded.items);

    var storage: [max_single_varint_frame_len]u8 = undefined;
    var direct_control = ControlState{};
    try std.testing.expectEqualSlices(
        u8,
        encoded.items[0..3],
        try writeCancelPushFrameInto(&storage, 7),
    );
    try std.testing.expectEqualSlices(
        u8,
        encoded.items[3..6],
        try direct_control.writeMaxPushIdInto(&storage, 4),
    );
    try std.testing.expectEqualSlices(
        u8,
        encoded.items[6..9],
        try direct_control.writeGoAwayInto(&storage, 12),
    );
    try std.testing.expectError(
        error.GoAwayIdIncreased,
        direct_control.writeGoAwayInto(&storage, 16),
    );
    try std.testing.expectError(
        error.MaxPushIdReduced,
        direct_control.writeMaxPushIdInto(&storage, 2),
    );
    const max_value_frame = try writeCancelPushFrameInto(
        &storage,
        quic.varint.max_value,
    );
    try std.testing.expectEqual(max_single_varint_frame_len, max_value_frame.len);
    try std.testing.expectEqual(
        quic.varint.max_value,
        try parseCancelPushPayload((try Frame.parse(max_value_frame)).payload),
    );
    try std.testing.expectError(
        error.VarIntTooLarge,
        writeCancelPushFrameInto(
            &storage,
            @as(u64, quic.varint.max_value) + 1,
        ),
    );

    var failed_control = ControlState{};
    var failed: std.ArrayList(u8) = .empty;
    defer failed.deinit(allocator);
    var fail_first = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        failed_control.writeGoAway(
            &failed,
            fail_first.allocator(),
            4,
        ),
    );
    try std.testing.expectEqual(@as(?u64, null), failed_control.local_goaway_id);
}

test "HTTP/3 PUSH_PROMISE frame payload and limit validation" {
    const allocator = std.testing.allocator;
    var field_section: std.ArrayList(u8) = .empty;
    defer field_section.deinit(allocator);
    try Qpack.encodeLiteralBlock(&field_section, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/pushed.css" },
        .{ .name = ":authority", .value = "example.test" },
    });

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePushPromiseFrame(&encoded, allocator, 3, field_section.items);
    const frame = try Frame.parse(encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, frame.frame_type);
    const promise = try parsePushPromisePayload(frame.payload);
    try std.testing.expectEqual(@as(u64, 3), promise.push_id);
    const decoded = try Qpack.decodeLiteralBlock(allocator, promise.field_section);
    defer Qpack.freeDecodedFields(allocator, decoded);
    try std.testing.expectEqualStrings("/pushed.css", decoded[2].value);

    try validatePushPromise(.{ .local_max_push_id = 3 }, promise.push_id);
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{}, promise.push_id));
    try std.testing.expectError(error.PushIdExceeded, validatePushPromise(.{ .local_max_push_id = 2 }, promise.push_id));

    var dynamic_table = Qpack.DynamicTable.init(allocator, 0);
    defer dynamic_table.deinit();
    var decoded_promise = try decodePushPromiseWithDynamicTable(
        allocator,
        frame.payload,
        .{},
        dynamic_table,
    );
    defer decoded_promise.deinit(allocator);
    try std.testing.expectEqual(@as(u64, 3), decoded_promise.push_id);
    try std.testing.expectEqualStrings(
        "/pushed.css",
        decoded_promise.request.path,
    );

    var response_with_push: std.ArrayList(u8) = .empty;
    defer response_with_push.deinit(allocator);
    try writePushPromiseFrame(&response_with_push, allocator, 3, field_section.items);
    var response_headers: std.ArrayList(u8) = .empty;
    defer response_headers.deinit(allocator);
    try Qpack.encodeLiteralBlock(&response_headers, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = response_headers.items, .consumed = 0 }).write(&response_with_push, allocator);
    try validateResponsePushPromises(.{ .local_max_push_id = 3 }, response_with_push.items);
    try std.testing.expectError(error.PushIdExceeded, validateResponsePushPromises(.{}, response_with_push.items));
    try std.testing.expectError(error.PushIdExceeded, validateResponsePushPromises(.{ .local_max_push_id = 2 }, response_with_push.items));

    var no_alloc_encoded: std.ArrayList(u8) = .empty;
    defer no_alloc_encoded.deinit(allocator);
    try no_alloc_encoded.ensureTotalCapacity(allocator, 64);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writePushPromiseFrame(&no_alloc_encoded, no_alloc.allocator(), 3, field_section.items);
    try std.testing.expect(!no_alloc.has_induced_failure);
    const no_alloc_frame = try Frame.parse(no_alloc_encoded.items);
    try std.testing.expectEqual(FrameType.push_promise, no_alloc_frame.frame_type);
    try std.testing.expectEqual(@as(u64, 3), (try parsePushPromisePayload(no_alloc_frame.payload)).push_id);
}

test "HTTP/3 enforces SETTINGS_MAX_FIELD_SECTION_SIZE" {
    const allocator = std.testing.allocator;

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    try (Request{
        .method = "GET",
        .path = "/limited",
        .authority = "example.com",
    }).write(&request_bytes, allocator);
    var decoded_request = try decodeRequest(allocator, request_bytes.items);
    decoded_request.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, decodeRequestWithSettings(allocator, request_bytes.items, .{
        .max_field_section_size = 1,
    }));
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.ExcessiveLoad,
        decodeRequestWithSettings(
            no_alloc.allocator(),
            request_bytes.items,
            .{ .max_field_section_size = 1 },
        ),
    );
    try std.testing.expect(!no_alloc.has_induced_failure);
    var rejected_request_write: std.ArrayList(u8) = .empty;
    defer rejected_request_write.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, (Request{
        .method = "GET",
        .path = "/limited",
        .authority = "example.com",
    }).writeWithSettings(&rejected_request_write, allocator, .{
        .max_field_section_size = 1,
    }));

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    try (Response{
        .status = 200,
        .trailers = &.{.{ .name = "grpc-status", .value = "0" }},
    }).write(&response_bytes, allocator);
    var decoded_response = try decodeResponseWithSettings(allocator, response_bytes.items, .{
        .max_field_section_size = 44,
    });
    decoded_response.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, decodeResponseWithSettings(allocator, response_bytes.items, .{
        .max_field_section_size = 43,
    }));

    var rejected_response_write: std.ArrayList(u8) = .empty;
    defer rejected_response_write.deinit(allocator);
    try std.testing.expectError(error.ExcessiveLoad, writeResponseSequenceWithSettings(&rejected_response_write, allocator, &.{.{
        .status = 103,
    }}, .{
        .status = 200,
    }, .{
        .max_field_section_size = 41,
    }));
}

test "HTTP/3 per-ID push cancellation is allocation-failure safe" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkPushCancellationStateAllocationFailure,
        .{},
    );
}

test "HTTP/3 sequential push cancellation history remains allocation-free" {
    const allocator = std.testing.allocator;
    var control = ControlState{ .settings = .{ .received = true } };
    defer control.deinit(allocator);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    for (0..64) |push_id| {
        const payload = [_]u8{@intCast(push_id)};
        try control.applyFrame(no_alloc.allocator(), .{
            .frame_type = FrameType.cancel_push,
            .payload = &payload,
            .consumed = 0,
        });
    }
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), control.cancelledPushRangeCount());
    try std.testing.expectEqual(@as(u64, 64), control.push_cancellation_generation);
    for (0..64) |push_id| try std.testing.expect(
        control.pushCancelled(push_id),
    );

    const generation = control.push_cancellation_generation;
    try control.applyFrame(no_alloc.allocator(), .{
        .frame_type = FrameType.cancel_push,
        .payload = &.{31},
        .consumed = 0,
    });
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(generation, control.push_cancellation_generation);

    var cloned = try control.clone(no_alloc.allocator());
    defer cloned.deinit(allocator);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), cloned.cancelledPushRangeCount());
    try std.testing.expect(cloned.pushCancelled(0));
    try std.testing.expect(cloned.pushCancelled(63));
    try std.testing.expect(!cloned.pushCancelled(64));
}

test "HTTP/3 rejects malformed structured frame payloads" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidFrame, parseGoAwayPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parseCancelPushPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parseMaxPushIdPayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parsePushPromisePayload(&.{}));
    try std.testing.expectError(error.InvalidFrame, parsePriorityUpdatePayload(&.{}));

    const truncated_two_byte_varint = [_]u8{0x40};
    try std.testing.expectError(error.InvalidFrame, parseGoAwayPayload(&truncated_two_byte_varint));
    try std.testing.expectError(error.InvalidFrame, parsePushPromisePayload(&truncated_two_byte_varint));
    try std.testing.expectError(error.InvalidFrame, parsePriorityUpdatePayload(&truncated_two_byte_varint));

    var malformed_frame_write: std.ArrayList(u8) = .empty;
    defer malformed_frame_write.deinit(allocator);
    try std.testing.expectError(error.InvalidFrame, (Frame{ .frame_type = FrameType.goaway, .payload = &.{}, .consumed = 0 }).write(&malformed_frame_write, allocator));

    var malformed_response: std.ArrayList(u8) = .empty;
    defer malformed_response.deinit(allocator);
    try quic.varint.encode(&malformed_response, allocator, FrameType.push_promise);
    try quic.varint.encode(&malformed_response, allocator, 0);
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_response, allocator);
    try std.testing.expectError(error.InvalidFrame, decodeResponse(allocator, malformed_response.items));

    var malformed_settings: std.ArrayList(u8) = .empty;
    defer malformed_settings.deinit(allocator);
    try quic.varint.encode(&malformed_settings, allocator, @intFromEnum(SettingId.h3_datagram));
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, malformed_settings.items));
}

test "HTTP/3 datagram" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{ .quarter_stream_id = 4, .payload = "capsule" }).write(&encoded, allocator);
    try std.testing.expectEqual(@as(u8, 4), encoded.items[0]);
    const parsed = try Datagram.parse(encoded.items);
    try std.testing.expectEqual(@as(u64, 4), parsed.quarter_stream_id);
    try std.testing.expectEqualStrings("capsule", parsed.payload);
}

test "HTTP/3 datagram bounds the Quarter Stream ID" {
    const allocator = std.testing.allocator;
    const maximum = Datagram.max_quarter_stream_id;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try (Datagram{
        .quarter_stream_id = maximum,
        .payload = &.{},
    }).write(&encoded, allocator);
    try std.testing.expectEqual(
        maximum,
        (try Datagram.parse(encoded.items)).quarter_stream_id,
    );

    encoded.clearRetainingCapacity();
    try quic.varint.encode(&encoded, allocator, maximum + 1);
    try std.testing.expectError(error.InvalidFrame, Datagram.parse(encoded.items));
    try std.testing.expectError(error.InvalidFrame, (Datagram{
        .quarter_stream_id = maximum + 1,
        .payload = &.{},
    }).write(&encoded, allocator));
}

test "HTTP/3 request encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Request{
        .method = "POST",
        .path = "/submit",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-type", .value = "text/plain" }},
        .body = "hello",
    }).write(&encoded, allocator);

    var decoded = try decodeRequest(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("/submit", decoded.path);
    try std.testing.expectEqualStrings("example.com", decoded.authority.?);
    try std.testing.expectEqualStrings("hello", decoded.body);
    try std.testing.expectEqualStrings("5", findHeader(decoded.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    try (Request{
        .method = "POST",
        .path = "/empty",
        .authority = "example.com",
    }).write(&encoded, allocator);
    var empty_post = try decodeRequest(allocator, encoded.items);
    defer empty_post.deinit(allocator);
    try std.testing.expectEqualStrings("0", findHeader(empty_post.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    try (Request{
        .method = "GET",
        .path = "/no-length",
        .authority = "example.com",
    }).write(&encoded, allocator);
    var get = try decodeRequest(allocator, encoded.items);
    defer get.deinit(allocator);
    try std.testing.expect(findHeader(get.headers, "content-length") == null);
}

test "HTTP/3 request context accepts OPTIONS asterisk only" {
    const options_asterisk = Request{
        .method = "OPTIONS",
        .path = "*",
        .authority = "example.com",
    };
    try options_asterisk.validateForContext(.direct);
    try options_asterisk.validateForContext(.proxy);

    try std.testing.expectError(
        error.InvalidHeader,
        (Request{
            .method = "GET",
            .path = "*",
            .authority = "example.com",
        }).validateForContext(.direct),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        (Request{
            .method = "options",
            .path = "*",
            .authority = "example.com",
        }).validateForContext(.proxy),
    );
}

test "HTTP/3 dynamic QPACK request decode preserves message semantics and acknowledgment count" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-request-id", "request-20260809");
    _ = try table.insert("x-trailer", "complete");

    const headers = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/dynamic" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "4" },
        .{ .name = "x-request-id", .value = "request-20260809" },
    };
    const trailers = [_]Qpack.HeaderField{
        .{ .name = "x-trailer", .value = "complete" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &headers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &trailers, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeRequestWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("/dynamic", decoded.path);
    try std.testing.expectEqualStrings("https", decoded.scheme);
    try std.testing.expectEqualStrings("example.com", decoded.authority.?);
    try std.testing.expectEqualStrings("body", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("complete", decoded.trailers[0].value);
    try std.testing.expectEqual(@as(usize, 2), decoded.qpack_section_acknowledgments);
}

test "HTTP/3 dynamic QPACK response counts informational and final acknowledgments" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-release", "netz-2026");

    const informational = [_]Qpack.HeaderField{
        .{ .name = ":status", .value = "103" },
        .{ .name = "x-release", .value = "netz-2026" },
    };
    const final = [_]Qpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "2" },
        .{ .name = "x-release", .value = "netz-2026" },
    };
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &informational, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &final, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "ok",
        .consumed = 0,
    }).write(&encoded, allocator);

    var decoded = try decodeResponseWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), decoded.status);
    try std.testing.expectEqualStrings("ok", decoded.body);
    try std.testing.expectEqual(@as(usize, 2), decoded.qpack_section_acknowledgments);
}

test "HTTP/3 aggregate response decodes push promises and counts their acknowledgments" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-push-kind", "dynamic-asset");

    var promise_block: std.ArrayList(u8) = .empty;
    defer promise_block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&promise_block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/asset.css" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "x-push-kind", .value = "dynamic-asset" },
    }, table);
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try writePushPromiseFrame(
        &encoded,
        allocator,
        3,
        promise_block.items,
    );
    try (Response{ .status = 204 }).write(&encoded, allocator);

    var decoded = try decodeResponseWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), decoded.status);
    try std.testing.expectEqual(
        @as(usize, 1),
        decoded.qpack_section_acknowledgments,
    );
    var decoded_head = try decodeResponseHeadWithDynamicTable(
        allocator,
        encoded.items,
        .{},
        table,
    );
    defer decoded_head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 204), decoded_head.status);
    try std.testing.expectEqual(encoded.items.len, decoded_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 1),
        decoded_head.qpack_section_acknowledgments,
    );

    var malformed: std.ArrayList(u8) = .empty;
    defer malformed.deinit(allocator);
    // The prefix is complete and declares no dynamic dependency; the literal
    // field line itself is truncated. This ensures aggregate decoding, not
    // the dependency prepass, detects the malformed promise.
    try writePushPromiseFrame(
        &malformed,
        allocator,
        3,
        &.{ 0x00, 0x00, 0x20 },
    );
    try (Response{ .status = 204 }).write(&malformed, allocator);
    try std.testing.expectError(
        error.QpackDecompressionFailed,
        decodeResponseWithDynamicTable(
            allocator,
            malformed.items,
            .{},
            table,
        ),
    );
}

test "HTTP/3 dynamic heads decode before DATA and own fields" {
    const allocator = std.testing.allocator;
    var table = Qpack.DynamicTable.init(allocator, 512);
    defer table.deinit();
    try table.setCapacity(512);
    _ = try table.insert("x-owned", "dynamic-value");

    var request_bytes: std.ArrayList(u8) = .empty;
    defer request_bytes.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/stream-head" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "1000000" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&request_bytes, allocator);
    const request_head_bytes = request_bytes.items.len;
    try quic.varint.encode(&request_bytes, allocator, FrameType.data);
    try quic.varint.encode(&request_bytes, allocator, 1_000_000);

    var request_head = try decodeRequestHeadWithDynamicTable(
        allocator,
        request_bytes.items,
        .{},
        table,
    );
    defer request_head.deinit(allocator);
    try std.testing.expectEqualStrings("POST", request_head.method);
    try std.testing.expectEqualStrings("/stream-head", request_head.path);
    try std.testing.expectEqual(
        @as(?usize, 1_000_000),
        request_head.content_length,
    );
    try std.testing.expectEqual(request_head_bytes, request_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 1),
        request_head.qpack_section_acknowledgments,
    );
    @memset(block.items, 0);
    try std.testing.expectEqualStrings(
        "dynamic-value",
        ownedFieldValue(request_head.headers, "x-owned").?,
    );
    const request_storage = request_head.headers[0].block_storage orelse
        return error.TestUnexpectedResult;
    for (request_head.headers) |field| {
        try std.testing.expect(field.name_storage == null);
        try std.testing.expect(field.value_storage == null);
        try std.testing.expectEqual(
            field.name.ptr + field.name.len,
            field.value.ptr,
        );
        try std.testing.expect(
            @intFromPtr(field.value.ptr) + field.value.len <=
                @intFromPtr(request_storage.ptr) + request_storage.len,
        );
    }

    var response_bytes: std.ArrayList(u8) = .empty;
    defer response_bytes.deinit(allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "103" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    block.clearRetainingCapacity();
    try Qpack.encodeDynamicBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "8" },
        .{ .name = "x-owned", .value = "dynamic-value" },
    }, table);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&response_bytes, allocator);
    const response_head_bytes = response_bytes.items.len;

    var response_head = try decodeResponseHeadWithDynamicTable(
        allocator,
        response_bytes.items,
        .{},
        table,
    );
    defer response_head.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response_head.status);
    try std.testing.expectEqual(@as(?usize, 8), response_head.content_length);
    try std.testing.expectEqual(response_head_bytes, response_head.consumed);
    try std.testing.expectEqual(
        @as(usize, 2),
        response_head.qpack_section_acknowledgments,
    );
}

test "HTTP/3 owned header fields use one allocation per materialized field" {
    const allocator = std.testing.allocator;
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = tracking.allocator();
    const fields = try tracked.alloc(Qpack.HeaderField, 3);
    var transferred = false;
    defer if (!transferred) tracked.free(fields);

    fields[0] = .{ .name = ":status", .value = "200" };
    const dynamic_storage = try tracked.dupe(u8, "x-dynamicvalue");
    fields[1] = .{
        .name = dynamic_storage[0..9],
        .value = dynamic_storage[9..],
        .name_storage = dynamic_storage,
    };
    const decoded_value = try tracked.dupe(u8, "decoded-value");
    fields[2] = .{
        .name = "content-type",
        .value = decoded_value,
        .value_storage = decoded_value,
    };

    const before = tracking.allocations;
    const owned = try ownHeaderFields(tracked, fields);
    transferred = true;
    defer Qpack.freeDecodedFields(tracked, owned);

    try std.testing.expectEqual(fields.ptr, owned.ptr);
    // The already-contiguous dynamic field transfers without allocation. The
    // fully borrowed and partially owned fields each need exactly one new
    // backing block, rather than one allocation per string.
    try std.testing.expectEqual(before + 2, tracking.allocations);
    for (owned) |field| {
        const storage = field.name_storage orelse
            return error.TestUnexpectedResult;
        try std.testing.expect(field.value_storage == null);
        try std.testing.expectEqual(storage.ptr, field.name.ptr);
        try std.testing.expectEqual(
            storage.ptr + field.name.len,
            field.value.ptr,
        );
        try std.testing.expectEqual(
            storage.len,
            field.name.len + field.value.len,
        );
    }
}

test "HTTP/3 dynamic head decoding is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackHeadAllocationFailure,
        .{},
    );
}

test "HTTP/3 dynamic QPACK message decode is transactional under allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        checkDynamicQpackMessageAllocationFailure,
        .{},
    );
}

test "HTTP/3 message aggregates DATA frames and trailing HEADERS" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/multi" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "11" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&encoded, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "hello ", .consumed = 0 }).write(&encoded, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "world", .consumed = 0 }).write(&encoded, allocator);

    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = "grpc-status", .value = "0" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&encoded, allocator);

    var decoded = try decodeRequest(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("POST", decoded.method);
    try std.testing.expectEqualStrings("hello world", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("grpc-status", decoded.trailers[0].name);
    try std.testing.expectEqual(@as(usize, encoded.items.len), decoded.consumed);
}

test "HTTP/3 response permits PUSH_PROMISE after trailing HEADERS" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    var block: std.ArrayList(u8) = .empty;
    defer block.deinit(allocator);

    try Qpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "4" },
    });
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&encoded, allocator);

    block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&block, allocator, &.{.{
        .name = "x-finished",
        .value = "yes",
    }});
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = block.items,
        .consumed = 0,
    }).write(&encoded, allocator);

    block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&block, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/after-trailers" },
        .{ .name = ":authority", .value = "example.test" },
    });
    try writePushPromiseFrame(&encoded, allocator, 3, block.items);

    var decoded = try decodeResponse(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), decoded.status);
    try std.testing.expectEqualStrings("body", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("yes", decoded.trailers[0].value);
    try std.testing.expectEqual(encoded.items.len, decoded.consumed);
}

test "HTTP/3 message rejects bad frame order and content length" {
    const allocator = std.testing.allocator;

    var data_first: std.ArrayList(u8) = .empty;
    defer data_first.deinit(allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "oops", .consumed = 0 }).write(&data_first, allocator);
    try std.testing.expectError(error.ExpectedHeadersFrame, decodeRequest(allocator, data_first.items));

    var signed_length_request: std.ArrayList(u8) = .empty;
    defer signed_length_request.deinit(allocator);
    var signed_block: std.ArrayList(u8) = .empty;
    defer signed_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/signed-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "+4" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = signed_block.items, .consumed = 0 }).write(&signed_length_request, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&signed_length_request, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, signed_length_request.items));

    var invalid_order_and_length: std.ArrayList(u8) = .empty;
    defer invalid_order_and_length.deinit(allocator);
    signed_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "content-length", .value = "+4" },
        .{ .name = ":path", .value = "/late-pseudo" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = signed_block.items,
        .consumed = 0,
    }).write(&invalid_order_and_length, allocator);
    try std.testing.expectError(
        error.InvalidHeader,
        decodeRequest(allocator, invalid_order_and_length.items),
    );

    var connect_with_length = std.ArrayList(u8).empty;
    defer connect_with_length.deinit(allocator);
    signed_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&signed_block, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "proxy.example.com:443" },
        .{ .name = "content-length", .value = "0" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = signed_block.items, .consumed = 0 }).write(&connect_with_length, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, connect_with_length.items));

    var invalid_length: std.ArrayList(u8) = .empty;
    defer invalid_length.deinit(allocator);
    var header_block: std.ArrayList(u8) = .empty;
    defer header_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/bad-length" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-length", .value = "5" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&invalid_length, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&invalid_length, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeRequest(allocator, invalid_length.items));

    var low_status: std.ArrayList(u8) = .empty;
    defer low_status.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "099" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&low_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, low_status.items));

    var malformed_status: std.ArrayList(u8) = .empty;
    defer malformed_status.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "0200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    malformed_status.clearRetainingCapacity();
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "20x" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    malformed_status.clearRetainingCapacity();
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "101" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&malformed_status, allocator);
    // HTTP/3 has no HTTP/1.1 Upgrade/Switching Protocols path.  Reject 101 at
    // the header-validation boundary instead of silently treating it as a
    // skippable informational response.
    try std.testing.expectError(error.InvalidStatus, decodeResponse(allocator, malformed_status.items));

    var informational_response: std.ArrayList(u8) = .empty;
    defer informational_response.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_response, allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "final", .consumed = 0 }).write(&informational_response, allocator);
    var informational_decoded = try decodeResponse(allocator, informational_response.items);
    defer informational_decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), informational_decoded.status);
    try std.testing.expectEqualStrings("final", informational_decoded.body);

    var extension_prefaced_response: std.ArrayList(u8) = .empty;
    defer extension_prefaced_response.deinit(allocator);
    try (Frame{ .frame_type = 0x21, .payload = "extension", .consumed = 0 }).write(&extension_prefaced_response, allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&extension_prefaced_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "response-ext", .consumed = 0 }).write(&extension_prefaced_response, allocator);
    var extension_decoded = try decodeResponse(allocator, extension_prefaced_response.items);
    defer extension_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("response-ext", extension_decoded.body);

    var pushed_response: std.ArrayList(u8) = .empty;
    defer pushed_response.deinit(allocator);
    var promised_headers: std.ArrayList(u8) = .empty;
    defer promised_headers.deinit(allocator);
    try Qpack.encodeLiteralBlock(&promised_headers, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/promised" },
        .{ .name = ":authority", .value = "example.test" },
    });
    try writePushPromiseFrame(
        &pushed_response,
        allocator,
        0,
        promised_headers.items,
    );
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "200" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&pushed_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "pushed-ok", .consumed = 0 }).write(&pushed_response, allocator);
    var pushed_decoded = try decodeResponse(allocator, pushed_response.items);
    defer pushed_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("pushed-ok", pushed_decoded.body);

    var client_push_promise: std.ArrayList(u8) = .empty;
    defer client_push_promise.deinit(allocator);
    try writePushPromiseFrame(&client_push_promise, allocator, 0, "illegal-client-push");
    try std.testing.expectError(error.ExpectedHeadersFrame, decodeRequest(allocator, client_push_promise.items));

    var informational_only = std.ArrayList(u8).empty;
    defer informational_only.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "103" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&informational_only, allocator);
    try std.testing.expectError(error.MissingStatus, decodeResponse(allocator, informational_only.items));

    var written_sequence: std.ArrayList(u8) = .empty;
    defer written_sequence.deinit(allocator);
    try writeResponseSequence(&written_sequence, allocator, &.{.{
        .status = 103,
        .headers = &.{.{ .name = "link", .value = "</style.css>; rel=preload" }},
    }}, .{ .status = 200, .body = "sequence-final" });
    var sequence_decoded = try decodeResponse(allocator, written_sequence.items);
    defer sequence_decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), sequence_decoded.status);
    try std.testing.expectEqualStrings("sequence-final", sequence_decoded.body);
    try std.testing.expectError(error.InvalidStatus, (InformationalResponse{ .status = 200 }).write(&written_sequence, allocator));
    try std.testing.expectError(error.InvalidContentLength, (InformationalResponse{
        .status = 103,
        .headers = &.{.{ .name = "content-length", .value = "1" }},
    }).write(&written_sequence, allocator));

    var signed_length_response: std.ArrayList(u8) = .empty;
    defer signed_length_response.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-length", .value = "+4" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&signed_length_response, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "1234", .consumed = 0 }).write(&signed_length_response, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeResponse(allocator, signed_length_response.items));

    var no_content_body: std.ArrayList(u8) = .empty;
    defer no_content_body.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{.{ .name = ":status", .value = "204" }});
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&no_content_body, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "body", .consumed = 0 }).write(&no_content_body, allocator);
    try std.testing.expectError(error.InvalidContentLength, decodeResponse(allocator, no_content_body.items));

    var not_modified_length: std.ArrayList(u8) = .empty;
    defer not_modified_length.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "304" },
        .{ .name = "content-length", .value = "123" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&not_modified_length, allocator);
    var not_modified = try decodeResponse(allocator, not_modified_length.items);
    defer not_modified.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 304), not_modified.status);

    var bad_order: std.ArrayList(u8) = .empty;
    defer bad_order.deinit(allocator);
    header_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&header_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
    });
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&bad_order, allocator);
    try (Frame{ .frame_type = FrameType.headers, .payload = header_block.items, .consumed = 0 }).write(&bad_order, allocator);
    try (Frame{ .frame_type = FrameType.data, .payload = "late", .consumed = 0 }).write(&bad_order, allocator);
    try std.testing.expectError(error.UnexpectedFrame, decodeResponse(allocator, bad_order.items));

    inline for ([_]u64{
        FrameType.settings,
        FrameType.origin,
        FrameType.webtransport_stream,
    }) |frame_type| {
        var forbidden: std.ArrayList(u8) = .empty;
        defer forbidden.deinit(allocator);
        try (Frame{
            .frame_type = FrameType.headers,
            .payload = header_block.items,
            .consumed = 0,
        }).write(&forbidden, allocator);
        if (frame_type == FrameType.webtransport_stream) {
            try quic.varint.encode(&forbidden, allocator, frame_type);
            try quic.varint.encode(&forbidden, allocator, 0);
        } else {
            try (Frame{
                .frame_type = frame_type,
                .payload = &.{},
                .consumed = 0,
            }).write(&forbidden, allocator);
        }
        try std.testing.expectError(
            error.UnexpectedFrame,
            decodeResponse(allocator, forbidden.items),
        );
    }
}

test "HTTP/3 validates pseudo headers and connection-specific fields" {
    const allocator = std.testing.allocator;

    const Helper = struct {
        fn writeRequestBlock(list: *std.ArrayList(u8), gpa: std.mem.Allocator, fields: []const Qpack.HeaderField) !void {
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try Qpack.encodeLiteralBlock(&block, gpa, fields);
            try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, gpa);
        }

        fn writeRequestWithTrailers(
            list: *std.ArrayList(u8),
            gpa: std.mem.Allocator,
            fields: []const Qpack.HeaderField,
            trailers: []const Qpack.HeaderField,
        ) !void {
            try writeRequestBlock(list, gpa, fields);
            var block: std.ArrayList(u8) = .empty;
            defer block.deinit(gpa);
            try Qpack.encodeLiteralBlock(&block, gpa, trailers);
            try (Frame{ .frame_type = FrameType.headers, .payload = block.items, .consumed = 0 }).write(list, gpa);
        }
    };

    const valid_request = [_]Qpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    };

    var uppercase: std.ArrayList(u8) = .empty;
    defer uppercase.deinit(allocator);
    try Helper.writeRequestBlock(&uppercase, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "Content-Type", .value = "text/plain" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, uppercase.items));

    var duplicate_pseudo: std.ArrayList(u8) = .empty;
    defer duplicate_pseudo.deinit(allocator);
    try Helper.writeRequestBlock(&duplicate_pseudo, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, duplicate_pseudo.items));

    var connection_specific: std.ArrayList(u8) = .empty;
    defer connection_specific.deinit(allocator);
    try Helper.writeRequestBlock(&connection_specific, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "transfer-encoding", .value = "chunked" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, connection_specific.items));

    var bad_te: std.ArrayList(u8) = .empty;
    defer bad_te.deinit(allocator);
    try Helper.writeRequestBlock(&bad_te, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "te", .value = "gzip" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_te.items));

    var good_te: std.ArrayList(u8) = .empty;
    defer good_te.deinit(allocator);
    try Helper.writeRequestBlock(&good_te, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "te", .value = "trailers" },
    });
    var decoded = try decodeRequest(allocator, good_te.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", decoded.method);

    var bad_priority: std.ArrayList(u8) = .empty;
    defer bad_priority.deinit(allocator);
    try Helper.writeRequestBlock(&bad_priority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=1," },
    });
    var ignored_priority = try decodeRequest(allocator, bad_priority.items);
    defer ignored_priority.deinit(allocator);
    try std.testing.expectEqual(Priority{}, Priority.parseFields(ignored_priority.headers));

    var good_priority: std.ArrayList(u8) = .empty;
    defer good_priority.deinit(allocator);
    try Helper.writeRequestBlock(&good_priority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "priority", .value = "u=1, i" },
    });
    var priority_decoded = try decodeRequest(
        allocator,
        good_priority.items,
    );
    priority_decoded.deinit(allocator);

    var missing_authority = std.ArrayList(u8).empty;
    defer missing_authority.deinit(allocator);
    try Helper.writeRequestBlock(&missing_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, missing_authority.items));

    var host_authority = std.ArrayList(u8).empty;
    defer host_authority.deinit(allocator);
    try Helper.writeRequestBlock(&host_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = "host", .value = "example.com" },
    });
    var host_decoded = try decodeRequest(allocator, host_authority.items);
    defer host_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", host_decoded.method);
    try std.testing.expectEqualStrings("example.com", host_decoded.authority.?);

    var mismatched_authority = std.ArrayList(u8).empty;
    defer mismatched_authority.deinit(allocator);
    try Helper.writeRequestBlock(&mismatched_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "origin.example" },
        .{ .name = "host", .value = "proxy.example" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, mismatched_authority.items));

    var invalid_path = std.ArrayList(u8).empty;
    defer invalid_path.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "relative" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_path.items));

    var query_only_path = std.ArrayList(u8).empty;
    defer query_only_path.deinit(allocator);
    try Helper.writeRequestBlock(&query_only_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "?only=query" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, query_only_path.items));

    var options_asterisk = std.ArrayList(u8).empty;
    defer options_asterisk.deinit(allocator);
    try Helper.writeRequestBlock(&options_asterisk, allocator, &.{
        .{ .name = ":method", .value = "OPTIONS" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    var options_decoded = try decodeRequest(allocator, options_asterisk.items);
    defer options_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("OPTIONS", options_decoded.method);
    try std.testing.expectEqualStrings("*", options_decoded.path);

    var lowercase_options_asterisk = std.ArrayList(u8).empty;
    defer lowercase_options_asterisk.deinit(allocator);
    try Helper.writeRequestBlock(&lowercase_options_asterisk, allocator, &.{
        .{ .name = ":method", .value = "options" },
        .{ .name = ":path", .value = "*" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, lowercase_options_asterisk.items));

    var invalid_authority = std.ArrayList(u8).empty;
    defer invalid_authority.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_authority, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "user@example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_authority.items));

    var invalid_method_token = std.ArrayList(u8).empty;
    defer invalid_method_token.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_method_token, allocator, &.{
        .{ .name = ":method", .value = "GET /" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_method_token.items));

    var empty_path = std.ArrayList(u8).empty;
    defer empty_path.deinit(allocator);
    try Helper.writeRequestBlock(&empty_path, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, empty_path.items));

    var plain_connect = std.ArrayList(u8).empty;
    defer plain_connect.deinit(allocator);
    try (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
    }).write(&plain_connect, allocator);
    var connect_decoded = try decodeRequest(allocator, plain_connect.items);
    defer connect_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("CONNECT", connect_decoded.method);
    try std.testing.expectEqualStrings("", connect_decoded.path);
    try std.testing.expectEqualStrings("", connect_decoded.scheme);

    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
        .headers = &.{.{ .name = "content-length", .value = "0" }},
    }).write(&plain_connect, allocator));

    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "CONNECT",
        .path = "/must-be-omitted",
        .authority = "proxy.example.com:443",
        .body = "tunnel bytes",
    }).write(&plain_connect, allocator));

    var lowercase_connect = std.ArrayList(u8).empty;
    defer lowercase_connect.deinit(allocator);
    try (Request{
        .method = "connect",
        .path = "/ordinary-extension-method",
        .scheme = "https",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-length", .value = "4" }},
        .body = "body",
    }).write(&lowercase_connect, allocator);
    var lowercase_decoded = try decodeRequest(allocator, lowercase_connect.items);
    defer lowercase_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("connect", lowercase_decoded.method);
    try std.testing.expectEqualStrings("body", lowercase_decoded.body);

    var extended_connect_missing_target = std.ArrayList(u8).empty;
    defer extended_connect_missing_target.deinit(allocator);
    try Helper.writeRequestBlock(&extended_connect_missing_target, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, extended_connect_missing_target.items));

    var extended_connect = std.ArrayList(u8).empty;
    defer extended_connect.deinit(allocator);
    try (Request{
        .method = "CONNECT",
        .path = "/wt",
        .scheme = "https",
        .authority = "example.com",
        .headers = &.{.{ .name = ":protocol", .value = "webtransport" }},
    }).write(&extended_connect, allocator);
    try std.testing.expectError(error.ExtendedConnectDisabled, decodeRequestWithSettings(allocator, extended_connect.items, .{}));
    var extended_decoded = try decodeRequestWithSettings(allocator, extended_connect.items, .{ .enable_connect_protocol = true });
    defer extended_decoded.deinit(allocator);
    try std.testing.expectEqualStrings("CONNECT", extended_decoded.method);
    try std.testing.expectEqualStrings("webtransport", findHeader(extended_decoded.headers, ":protocol").?);

    var invalid_protocol_token = std.ArrayList(u8).empty;
    defer invalid_protocol_token.deinit(allocator);
    try Helper.writeRequestBlock(&invalid_protocol_token, allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "web transport" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, invalid_protocol_token.items));

    var bad_protocol_method = std.ArrayList(u8).empty;
    defer bad_protocol_method.deinit(allocator);
    try Helper.writeRequestBlock(&bad_protocol_method, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":protocol", .value = "webtransport" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_protocol_method.items));

    var bad_value = std.ArrayList(u8).empty;
    defer bad_value.deinit(allocator);
    try Helper.writeRequestBlock(&bad_value, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "x-bad", .value = "ok\r\ninjected: yes" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, bad_value.items));

    var pseudo_trailer: std.ArrayList(u8) = .empty;
    try std.testing.expectError(error.InvalidContentLength, (Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "body",
    }).write(&pseudo_trailer, allocator));

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "POST",
        .path = "/upload",
        .authority = "example.com",
        .body = "body",
        .trailers = &.{.{ .name = "content-length", .value = "4" }},
    }).write(&pseudo_trailer, allocator));

    try std.testing.expectError(error.InvalidHeader, (Response{
        .status = 200,
        .body = "ok",
        .trailers = &.{.{ .name = "set-cookie", .value = "a=b" }},
    }).write(&pseudo_trailer, allocator));

    defer pseudo_trailer.deinit(allocator);
    try Helper.writeRequestWithTrailers(&pseudo_trailer, allocator, &valid_request, &.{
        .{ .name = ":status", .value = "200" },
    });
    try std.testing.expectError(error.InvalidHeader, decodeRequest(allocator, pseudo_trailer.items));

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "GET",
        .path = "/",
        .headers = &.{.{ .name = "Connection", .value = "close" }},
    }).write(&pseudo_trailer, allocator));

    var early_request: std.ArrayList(u8) = .empty;
    defer early_request.deinit(allocator);
    try (Request{
        .method = "GET",
        .path = "/early",
        .authority = "example.com",
        .headers = &.{.{ .name = "early-data", .value = "1" }},
    }).write(&early_request, allocator);
    var early_decoded = try decodeRequest(allocator, early_request.items);
    defer early_decoded.deinit(allocator);
    try std.testing.expect(early_decoded.mightHaveBeenEarly());
    try std.testing.expectEqual(
        early_data.ForwardingAction.preserve,
        (Request{
            .method = "GET",
            .path = "/early",
            .authority = "example.com",
            .headers = &.{.{ .name = "early-data", .value = "1" }},
        }).earlyDataForwardingAction(false),
    );

    inline for (.{
        &.{Qpack.HeaderField{ .name = "early-data", .value = "0" }},
        &.{
            Qpack.HeaderField{ .name = "early-data", .value = "1" },
            Qpack.HeaderField{ .name = "early-data", .value = "1" },
        },
    }) |invalid_early| {
        try std.testing.expectError(error.InvalidHeader, (Request{
            .method = "GET",
            .path = "/early",
            .authority = "example.com",
            .headers = invalid_early,
        }).write(&early_request, allocator));
    }

    var forwarded_early: std.ArrayList(u8) = .empty;
    defer forwarded_early.deinit(allocator);
    try Helper.writeRequestBlock(&forwarded_early, allocator, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/forwarded" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "early-data", .value = "invalid" },
        .{ .name = "early-data", .value = "1" },
    });
    var forwarded_decoded = try decodeRequest(
        allocator,
        forwarded_early.items,
    );
    defer forwarded_decoded.deinit(allocator);
    try std.testing.expect(forwarded_decoded.mightHaveBeenEarly());

    try std.testing.expectError(error.InvalidHeader, (Request{
        .method = "GET",
        .path = "/early-trailer",
        .authority = "example.com",
        .trailers = &.{.{ .name = "early-data", .value = "1" }},
    }).write(&early_request, allocator));

    var forwarded_early_trailer: std.ArrayList(u8) = .empty;
    defer forwarded_early_trailer.deinit(allocator);
    try Helper.writeRequestWithTrailers(
        &forwarded_early_trailer,
        allocator,
        &valid_request,
        &.{.{ .name = "early-data", .value = "1" }},
    );
    try std.testing.expectError(
        error.InvalidHeader,
        decodeRequest(allocator, forwarded_early_trailer.items),
    );
    try std.testing.expectError(error.InvalidHeader, (Response{
        .status = 200,
        .headers = &.{.{ .name = "early-data", .value = "1" }},
    }).write(&early_request, allocator));

    var early_response_block: std.ArrayList(u8) = .empty;
    defer early_response_block.deinit(allocator);
    try Qpack.encodeLiteralBlock(&early_response_block, allocator, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "early-data", .value = "1" },
    });
    var early_response: std.ArrayList(u8) = .empty;
    defer early_response.deinit(allocator);
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = early_response_block.items,
        .consumed = 0,
    }).write(&early_response, allocator);
    try std.testing.expectError(
        error.InvalidHeader,
        decodeResponse(allocator, early_response.items),
    );

    early_response.clearRetainingCapacity();
    early_response_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&early_response_block, allocator, &.{.{
        .name = ":status",
        .value = "200",
    }});
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = early_response_block.items,
        .consumed = 0,
    }).write(&early_response, allocator);
    early_response_block.clearRetainingCapacity();
    try Qpack.encodeLiteralBlock(&early_response_block, allocator, &.{.{
        .name = "early-data",
        .value = "1",
    }});
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = early_response_block.items,
        .consumed = 0,
    }).write(&early_response, allocator);
    try std.testing.expectError(
        error.InvalidHeader,
        decodeResponse(allocator, early_response.items),
    );
}

test "HTTP/3 response encode decode" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Response{
        .status = 201,
        .headers = &.{.{ .name = "server", .value = "netz" }},
        .body = "created",
    }).write(&encoded, allocator);
    var default_length = try decodeResponse(allocator, encoded.items);
    defer default_length.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), default_length.status);
    try std.testing.expectEqualStrings("created", default_length.body);
    try std.testing.expectEqualStrings("7", findHeader(default_length.headers, "content-length") orelse return error.MissingHeader);

    encoded.clearRetainingCapacity();
    const response = Response{
        .status = 201,
        .headers = &.{
            .{ .name = "server", .value = "netz" },
            .{ .name = "content-length", .value = "7" },
        },
        .body = "created",
        .trailers = &.{.{ .name = "checksum", .value = "ok" }},
    };
    try std.testing.expect(response.successful());
    try response.write(&encoded, allocator);

    var decoded = try decodeResponse(allocator, encoded.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 201), decoded.status);
    try std.testing.expect(decoded.successful());
    try std.testing.expectEqualStrings("created", decoded.body);
    try std.testing.expectEqual(@as(usize, 1), decoded.trailers.len);
    try std.testing.expectEqualStrings("checksum", decoded.trailers[0].name);
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "5" }},
        .body = "ok",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 204,
        .body = "body",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 205,
        .body = "body",
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 205,
        .headers = &.{.{ .name = "content-length", .value = "1" }},
    }).write(&encoded, allocator));
    try validateResponseBodyForStatusWithLength(
        205,
        4,
        "body",
        &.{},
    );
    var peer_reset_bytes: std.ArrayList(u8) = .empty;
    defer peer_reset_bytes.deinit(allocator);
    var peer_reset_fields: std.ArrayList(u8) = .empty;
    defer peer_reset_fields.deinit(allocator);
    try Qpack.encodeLiteralBlock(&peer_reset_fields, allocator, &.{
        .{ .name = ":status", .value = "205" },
        .{ .name = "content-length", .value = "4" },
    });
    try (Frame{
        .frame_type = FrameType.headers,
        .payload = peer_reset_fields.items,
        .consumed = 0,
    }).write(&peer_reset_bytes, allocator);
    try (Frame{
        .frame_type = FrameType.data,
        .payload = "body",
        .consumed = 0,
    }).write(&peer_reset_bytes, allocator);
    var peer_reset = try decodeResponse(allocator, peer_reset_bytes.items);
    defer peer_reset.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), peer_reset.status);
    try std.testing.expectEqualStrings("body", peer_reset.body);
    encoded.clearRetainingCapacity();
    try (Response{
        .status = 205,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
        .trailers = &.{.{ .name = "x-reset-complete", .value = "yes" }},
    }).write(&encoded, allocator);
    var reset = try decodeResponse(allocator, encoded.items);
    defer reset.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 205), reset.status);
    try std.testing.expectEqualStrings("", reset.body);
    try std.testing.expectEqual(@as(usize, 1), reset.trailers.len);
    try std.testing.expectError(error.InvalidStatus, (Response{
        .status = 103,
    }).write(&encoded, allocator));
    try std.testing.expectError(error.InvalidStatus, (Response{
        .status = 103,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
    }).write(&encoded, allocator));
    try (Response{
        .status = 304,
        .headers = &.{.{ .name = "content-length", .value = "123" }},
    }).write(&encoded, allocator);
}

test "HTTP/3 response honors HEAD and CONNECT request semantics" {
    const allocator = std.testing.allocator;
    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);

    try (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "14" }},
        .body = "representation",
        .request_method = "HEAD",
    }).write(&encoded, allocator);
    var head = try decodeResponseWithOptions(
        allocator,
        encoded.items,
        .{ .request_method = "HEAD" },
    );
    defer head.deinit(allocator);
    try std.testing.expectEqualStrings("", head.body);
    try std.testing.expectEqualStrings(
        "14",
        findHeader(head.headers, "content-length") orelse
            return error.MissingHeader,
    );

    var illegal_head: std.ArrayList(u8) = .empty;
    defer illegal_head.deinit(allocator);
    try (Response{
        .status = 200,
        .body = "illegal",
    }).write(&illegal_head, allocator);
    try std.testing.expectError(
        error.InvalidContentLength,
        decodeResponseWithOptions(allocator, illegal_head.items, .{
            .request_method = "HEAD",
        }),
    );

    encoded.clearRetainingCapacity();
    try (Response{
        .status = 200,
        .headers = &.{.{ .name = "content-length", .value = "0" }},
        .request_method = "CONNECT",
    }).write(&encoded, allocator);
    var connect = try decodeResponseWithOptions(
        allocator,
        encoded.items,
        .{ .request_method = "CONNECT" },
    );
    defer connect.deinit(allocator);
    try std.testing.expect(findHeader(connect.headers, "content-length") == null);

    try std.testing.expectError(error.InvalidContentLength, (Response{
        .status = 200,
        .body = "not-http-body",
        .request_method = "CONNECT",
    }).write(&encoded, allocator));

    encoded.clearRetainingCapacity();
    try (Response{
        .status = 200,
        .body = "extended-data",
        .request_method = "CONNECT",
        .extended_connect = true,
    }).write(&encoded, allocator);
    var extended = try decodeResponseWithOptions(
        allocator,
        encoded.items,
        .{
            .request_method = "CONNECT",
            .extended_connect = true,
        },
    );
    defer extended.deinit(allocator);
    try std.testing.expectEqualStrings("extended-data", extended.body);
}

test "H3 handshake options expose flat native and session accessors" {
    var client: http3_root.runtime.HandshakeClientOptions = .{
        .handshake = .{
            .original_destination_connection_id = &.{},
            .local_connection_id = &.{},
        },
    };
    client.nativeHandshake().max_crypto_buffer = 4096;
    client.sessionOptions().max_body_bytes = 4096;
    try std.testing.expectEqual(
        @as(usize, 4096),
        client.handshake.max_crypto_buffer,
    );
    try std.testing.expectEqual(
        @as(usize, 4096),
        client.session.max_body_bytes,
    );
}

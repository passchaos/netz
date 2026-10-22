const std = @import("std");
const http3 = @import("../mod.zig");
const quic = @import("../../quic/mod.zig");
const Settings = http3.Settings;
const SettingsState = http3.SettingsState;
const ControlState = http3.ControlState;
const Frame = http3.Frame;
const FrameType = http3.FrameType;
const parseSettings = http3.parseSettings;
const writeSettingsFrame = http3.writeSettingsFrame;

test "HTTP/3 typed settings state tracks negotiation" {
    const allocator = std.testing.allocator;
    const defaults = Settings{};
    try std.testing.expectEqual(std.math.maxInt(u64), defaults.max_field_section_size);
    var default_payload: std.ArrayList(u8) = .empty;
    defer default_payload.deinit(allocator);
    try defaults.writePayload(&default_payload, allocator);
    try std.testing.expectEqual(@as(usize, 0), default_payload.items.len);
    try (Settings{
        .qpack_max_table_capacity = 1,
    }).writePayload(&default_payload, allocator);
    default_payload.clearRetainingCapacity();
    try (Settings{
        .qpack_blocked_streams = 128,
    }).writePayload(&default_payload, allocator);
    try std.testing.expect(default_payload.items.len != 0);
    default_payload.clearRetainingCapacity();
    try std.testing.expectError(error.QpackDynamicTableUnsupported, (Settings{
        .qpack_blocked_streams = 129,
    }).writePayload(&default_payload, allocator));
    const beyond_varint = @as(u64, quic.varint.max_value) + 1;
    inline for (.{
        Settings{ .qpack_max_table_capacity = beyond_varint },
        Settings{ .max_field_section_size = beyond_varint },
        Settings{ .webtransport_max_sessions = beyond_varint },
        Settings{ .webtransport_initial_max_data = beyond_varint },
        Settings{ .webtransport_initial_max_streams_uni = beyond_varint },
        Settings{ .webtransport_initial_max_streams_bidi = beyond_varint },
    }) |invalid| {
        try std.testing.expectError(
            error.InvalidSetting,
            invalid.writePayload(&default_payload, allocator),
        );
        try std.testing.expectEqual(@as(usize, 0), default_payload.items.len);
    }
    const maximum_qpack_capacity = @min(
        @as(u64, quic.varint.max_value),
        std.math.maxInt(usize),
    );
    const maximum = Settings{
        .qpack_max_table_capacity = maximum_qpack_capacity,
        .max_field_section_size = quic.varint.max_value,
        .webtransport_max_sessions = quic.varint.max_value,
        .webtransport_initial_max_data = quic.varint.max_value,
        .webtransport_initial_max_streams_uni = quic.varint.max_value,
        .webtransport_initial_max_streams_bidi = quic.varint.max_value,
    };
    default_payload.clearRetainingCapacity();
    try maximum.writePayload(&default_payload, allocator);
    const maximum_raw = try parseSettings(allocator, default_payload.items);
    defer allocator.free(maximum_raw);
    const maximum_decoded = Settings.fromList(maximum_raw);
    try std.testing.expectEqual(
        maximum.qpack_max_table_capacity,
        maximum_decoded.qpack_max_table_capacity,
    );
    try std.testing.expectEqual(
        maximum.max_field_section_size,
        maximum_decoded.max_field_section_size,
    );
    try std.testing.expectEqual(
        maximum.webtransport_max_sessions,
        maximum_decoded.webtransport_max_sessions,
    );
    try std.testing.expectEqual(
        maximum.webtransport_initial_max_data,
        maximum_decoded.webtransport_initial_max_data,
    );
    try std.testing.expectEqual(
        maximum.webtransport_initial_max_streams_uni,
        maximum_decoded.webtransport_initial_max_streams_uni,
    );
    try std.testing.expectEqual(
        maximum.webtransport_initial_max_streams_bidi,
        maximum_decoded.webtransport_initial_max_streams_bidi,
    );

    const local = Settings{
        .max_field_section_size = 32 * 1024,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .webtransport_max_sessions = 16,
    };

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try local.writePayload(&payload, allocator);
    try std.testing.expectEqual(payload.items.len, try local.payloadLen());
    const raw = try parseSettings(allocator, payload.items);
    defer allocator.free(raw);
    const decoded = Settings.fromList(raw);

    try std.testing.expectEqual(@as(u64, 32 * 1024), decoded.max_field_section_size);
    try std.testing.expect(decoded.enable_connect_protocol);
    try std.testing.expect(decoded.h3_datagram);
    try std.testing.expectEqual(@as(u64, 16), decoded.webtransport_max_sessions);

    var state = SettingsState{};
    try std.testing.expect(!state.ready());
    state.markSent(local);
    try std.testing.expect(!state.ready());
    state.markReceived(decoded);
    try std.testing.expect(state.ready());
    try std.testing.expect(state.peer.h3_datagram);

    var direct_frame: std.ArrayList(u8) = .empty;
    defer direct_frame.deinit(allocator);
    try direct_frame.ensureTotalCapacity(allocator, payload.items.len + 2);
    var no_alloc = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    try writeSettingsFrame(&direct_frame, no_alloc.allocator(), local);
    try std.testing.expect(!no_alloc.has_induced_failure);
    const parsed_frame = try Frame.parse(direct_frame.items);
    try std.testing.expectEqual(FrameType.settings, parsed_frame.frame_type);
    try std.testing.expectEqualSlices(u8, payload.items, parsed_frame.payload);
}

test "HTTP/3 SETTINGS frame write is transactional and exactly reserved" {
    const allocator = std.testing.allocator;
    const settings = Settings{ .qpack_max_table_capacity = 64 };

    var encoded: std.ArrayList(u8) = .empty;
    defer encoded.deinit(allocator);
    try encoded.ensureTotalCapacityPrecise(allocator, 2);
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        writeSettingsFrame(&encoded, failing.allocator(), settings),
    );
    try std.testing.expectEqual(@as(usize, 0), encoded.items.len);

    var exact_storage: [5]u8 = undefined;
    var exact = std.ArrayList(u8).initBuffer(&exact_storage);
    var no_alloc = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try writeSettingsFrame(&exact, no_alloc.allocator(), settings);
    try std.testing.expect(!no_alloc.has_induced_failure);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0x04, 0x03, 0x01, 0x40, 0x40 },
        exact.items,
    );
}

test "HTTP/3 accepted early data rejects reduced remembered settings" {
    const remembered = Settings{
        .qpack_max_table_capacity = 256,
        .max_field_section_size = 4096,
        .qpack_blocked_streams = 2,
        .enable_connect_protocol = true,
        .h3_datagram = true,
        .enable_webtransport = true,
        .webtransport_max_sessions = 4,
        .webtransport_initial_max_data = 1024,
        .webtransport_initial_max_streams_uni = 2,
        .webtransport_initial_max_streams_bidi = 3,
    };
    try remembered.validateAfterEarlyDataAccepted(remembered);
    var increased = remembered;
    increased.qpack_max_table_capacity += 1;
    increased.max_field_section_size += 1;
    increased.qpack_blocked_streams += 1;
    increased.webtransport_max_sessions += 1;
    increased.webtransport_initial_max_data += 1;
    increased.webtransport_initial_max_streams_uni += 1;
    increased.webtransport_initial_max_streams_bidi += 1;
    try remembered.validateAfterEarlyDataAccepted(increased);

    inline for (.{
        "qpack capacity",
        "field section size",
        "blocked streams",
        "extended connect",
        "datagrams",
        "webtransport",
        "webtransport sessions",
        "webtransport data",
        "webtransport uni streams",
        "webtransport bidi streams",
    }, 0..) |_, index| {
        var reduced = remembered;
        switch (index) {
            0 => reduced.qpack_max_table_capacity -= 1,
            1 => reduced.max_field_section_size -= 1,
            2 => reduced.qpack_blocked_streams -= 1,
            3 => reduced.enable_connect_protocol = false,
            4 => reduced.h3_datagram = false,
            5 => reduced.enable_webtransport = false,
            6 => reduced.webtransport_max_sessions -= 1,
            7 => reduced.webtransport_initial_max_data -= 1,
            8 => reduced.webtransport_initial_max_streams_uni -= 1,
            9 => reduced.webtransport_initial_max_streams_bidi -= 1,
            else => unreachable,
        }
        try std.testing.expectError(
            error.InvalidSetting,
            remembered.validateAfterEarlyDataAccepted(reduced),
        );
    }

    const allocator = std.testing.allocator;
    var control = ControlState{
        .early_data_peer_settings = remembered,
    };
    defer control.deinit(allocator);
    var reduced_frame: std.ArrayList(u8) = .empty;
    defer reduced_frame.deinit(allocator);
    var reduced = remembered;
    reduced.max_field_section_size -= 1;
    try writeSettingsFrame(&reduced_frame, allocator, reduced);
    try std.testing.expectError(
        error.InvalidSetting,
        control.applyFrame(allocator, try Frame.parse(reduced_frame.items)),
    );
    try std.testing.expect(!control.settings.received);
    try std.testing.expect(control.early_data_peer_settings != null);

    var accepted_frame: std.ArrayList(u8) = .empty;
    defer accepted_frame.deinit(allocator);
    try writeSettingsFrame(&accepted_frame, allocator, increased);
    try control.applyFrame(
        allocator,
        try Frame.parse(accepted_frame.items),
    );
    try std.testing.expect(control.settings.received);
    try std.testing.expect(control.early_data_peer_settings == null);
}

test "HTTP/3 WebTransport enable families are independent of SETTINGS order" {
    const Setting = http3.Setting;
    const legacy = @intFromEnum(http3.SettingId.webtransport_max_sessions);
    const modern = @intFromEnum(http3.SettingId.enable_webtransport);
    inline for (.{ true, false }) |legacy_first| {
        inline for (.{ true, false }) |legacy_enabled| {
            const flags = [_]Setting{
                .{ .id = legacy, .value = @intFromBool(legacy_enabled) },
                .{ .id = modern, .value = @intFromBool(!legacy_enabled) },
            };
            const settings = Settings.fromList(if (legacy_first) &flags else &.{ flags[1], flags[0] });
            const versions = settings.webTransportVersions();
            try std.testing.expect(settings.enable_webtransport);
            try std.testing.expectEqual(legacy_enabled, versions.legacy);
            try std.testing.expectEqual(!legacy_enabled, versions.draft16);
        }
    }
    const counts_only = Settings.fromList(&.{.{
        .id = @intFromEnum(http3.SettingId.webtransport_max_sessions_draft),
        .value = 4,
    }});
    try std.testing.expect(counts_only.webTransportVersions().legacy);
    try std.testing.expect(!counts_only.webTransportVersions().draft16);
    const explicitly_disabled = Settings.fromList(&.{
        .{ .id = legacy, .value = 0 },
        .{ .id = modern, .value = 0 },
        .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions_draft), .value = 4 },
    });
    try std.testing.expect(!explicitly_disabled.enable_webtransport);
    try std.testing.expect(!explicitly_disabled.webTransportVersions().any());
}

test "HTTP/3 WebTransport newer session limits win in every wire permutation" {
    const values = [_]http3.Setting{
        .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions), .value = 16 },
        .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions_draft), .value = 8 },
        .{ .id = @intFromEnum(http3.SettingId.webtransport_max_sessions_v13), .value = 4 },
    };
    for (0..values.len) |first| {
        for (0..values.len) |second| {
            if (second == first) continue;
            const third = 3 - first - second;
            const raw = [_]http3.Setting{ values[first], values[second], values[third] };
            const settings = Settings.fromList(&raw);
            try std.testing.expectEqual(@as(u64, 4), settings.webtransport_max_sessions);
            var zero_limit = raw;
            for (&zero_limit) |*setting| {
                if (setting.id == values[2].id) setting.value = 0;
            }
            try std.testing.expectEqual(@as(u64, 0), Settings.fromList(&zero_limit).webtransport_max_sessions);
        }
    }
}

test "HTTP/3 WebTransport selected advertisement round trips without invented support" {
    const allocator = std.testing.allocator;
    inline for (.{
        http3.WebTransportVersions{ .legacy = true },
        http3.WebTransportVersions{ .draft16 = true },
        http3.WebTransportVersions.compatible,
        http3.WebTransportVersions{},
    }) |versions| {
        const settings = Settings{
            .enable_webtransport = true,
            .webtransport_versions = versions,
            .webtransport_max_sessions = 8,
        };
        var payload: std.ArrayList(u8) = .empty;
        defer payload.deinit(allocator);
        try settings.writePayload(&payload, allocator);
        try std.testing.expectEqual(payload.items.len, try settings.payloadLen());
        const raw = try parseSettings(allocator, payload.items);
        defer allocator.free(raw);
        const decoded = Settings.fromList(raw);
        try std.testing.expectEqual(versions, decoded.webTransportVersions());
        var has_count = false;
        for (raw) |setting| {
            if (setting.id == @intFromEnum(http3.SettingId.webtransport_max_sessions_draft) or
                setting.id == @intFromEnum(http3.SettingId.webtransport_max_sessions_v13)) has_count = true;
        }
        try std.testing.expectEqual(versions.legacy, has_count);
    }
    try std.testing.expectEqual(Settings{}, Settings.fromList(&.{}));
    try std.testing.expectEqual(http3.WebTransportVersions.compatible, (Settings{
        .enable_webtransport = true,
    }).webTransportVersions());
}

test "HTTP/3 accepted early data cannot silently lose a WebTransport wire family" {
    const allocator = std.testing.allocator;
    const remembered = Settings{
        .enable_webtransport = true,
        .webtransport_versions = .compatible,
        .webtransport_max_sessions = 2,
    };
    inline for (.{
        http3.WebTransportVersions{ .legacy = true },
        http3.WebTransportVersions{ .draft16 = true },
    }) |reduced_versions| {
        var reduced = remembered;
        reduced.webtransport_versions = reduced_versions;
        try std.testing.expectError(error.InvalidSetting, remembered.validateAfterEarlyDataAccepted(reduced));
        var control = ControlState{ .early_data_peer_settings = remembered };
        defer control.deinit(allocator);
        var frame: std.ArrayList(u8) = .empty;
        defer frame.deinit(allocator);
        try writeSettingsFrame(&frame, allocator, reduced);
        try std.testing.expectError(error.InvalidSetting, control.applyFrame(allocator, try Frame.parse(frame.items)));
        try std.testing.expect(!control.settings.received);
        try std.testing.expect(control.early_data_peer_settings != null);
    }
    var legacy = remembered;
    legacy.webtransport_versions = .{ .legacy = true };
    try legacy.validateAfterEarlyDataAccepted(remembered);
}

test "HTTP/3 WebTransport modern enable value above one is a settings error" {
    const allocator = std.testing.allocator;
    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(allocator);
    try quic.varint.encode(&payload, allocator, @intFromEnum(http3.SettingId.enable_webtransport));
    try quic.varint.encode(&payload, allocator, 2);
    try std.testing.expectError(error.InvalidSetting, parseSettings(allocator, payload.items));
}

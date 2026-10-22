//! Typed HTTP/3 SETTINGS, encoding and remembered-capability validation.

const std = @import("std");
const http3 = @import("mod.zig");
const quic = @import("../quic/mod.zig");
const Error = http3.Error;

pub const WebTransportVersion = @import("settings/webtransport.zig").Version;
pub const WebTransportVersions = @import("settings/webtransport.zig").Versions;

pub const SettingId = enum(u64) {
    qpack_max_table_capacity = 0x01,
    max_field_section_size = 0x06,
    qpack_blocked_streams = 0x07,
    enable_connect_protocol = 0x08,
    h3_datagram = 0x33,
    /// Legacy WebTransport enable/max-session identifier seen in older
    /// WebTransport drafts and retained by earlier netz releases.  Peers in
    /// the wild disagree on whether this identifier is a boolean enable bit or
    /// a session count, so Settings.fromList accepts either non-zero form.
    webtransport_max_sessions = 0x2b603742,
    enable_webtransport = 0x2c7cf000,
    webtransport_max_sessions_draft = 0xc671706a,
    webtransport_max_sessions_v13 = 0x14e9cd29,
    webtransport_initial_max_data = 0x2b61,
    webtransport_initial_max_streams_uni = 0x2b64,
    webtransport_initial_max_streams_bidi = 0x2b65,
    _,
};

pub const Setting = struct {
    id: u64,
    value: u64,
};

pub const Settings = struct {
    /// Hard implementation cap; each runtime additionally bounds this by its
    /// configured concurrent request-stream retention limit.
    pub const max_supported_qpack_blocked_streams: u64 = 128;

    qpack_max_table_capacity: u64 = 0,
    /// RFC 9114 inherits the HTTP semantics that an omitted
    /// SETTINGS_MAX_FIELD_SECTION_SIZE means "no advertised limit".  Mature
    /// stacks such as tquic represent this as None/unbounded; use maxInt here
    /// so callers can still compare against a concrete value.
    max_field_section_size: u64 = std.math.maxInt(u64),
    qpack_blocked_streams: u64 = 0,
    enable_connect_protocol: bool = false,
    h3_datagram: bool = false,
    enable_webtransport: bool = false,
    /// An explicit local wire-family set; null preserves the historical dual
    /// advertisement. Decoding retains exactly the peer's enable codepoints.
    webtransport_versions: ?WebTransportVersions = null,
    webtransport_max_sessions: u64 = 0,
    webtransport_initial_max_data: u64 = 0,
    webtransport_initial_max_streams_uni: u64 = 0,
    webtransport_initial_max_streams_bidi: u64 = 0,

    pub fn fromList(settings: []const Setting) Settings {
        var out: Settings = .{};
        var legacy_enable: ?bool = null;
        var modern_enable: ?bool = null;
        var legacy_count: ?u64 = null;
        var draft_count: ?u64 = null;
        var v13_count: ?u64 = null;
        for (settings) |setting| {
            switch (setting.id) {
                @intFromEnum(SettingId.qpack_max_table_capacity) => out.qpack_max_table_capacity = setting.value,
                @intFromEnum(SettingId.max_field_section_size) => out.max_field_section_size = setting.value,
                @intFromEnum(SettingId.qpack_blocked_streams) => out.qpack_blocked_streams = setting.value,
                @intFromEnum(SettingId.enable_connect_protocol) => out.enable_connect_protocol = setting.value != 0,
                @intFromEnum(SettingId.h3_datagram) => out.h3_datagram = setting.value != 0,
                @intFromEnum(SettingId.enable_webtransport) => modern_enable = setting.value != 0,
                @intFromEnum(SettingId.webtransport_max_sessions) => {
                    legacy_enable = setting.value != 0;
                    legacy_count = setting.value;
                },
                @intFromEnum(SettingId.webtransport_max_sessions_draft) => draft_count = setting.value,
                @intFromEnum(SettingId.webtransport_max_sessions_v13) => v13_count = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_data) => out.webtransport_initial_max_data = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_streams_uni) => out.webtransport_initial_max_streams_uni = setting.value,
                @intFromEnum(SettingId.webtransport_initial_max_streams_bidi) => out.webtransport_initial_max_streams_bidi = setting.value,
                else => {}, // RFC 9114 requires unknown settings to be ignored.
            }
        }
        // A newer explicit limit, including zero, takes precedence over an
        // older count/enable identifier independently of SETTINGS order.
        out.webtransport_max_sessions = v13_count orelse draft_count orelse legacy_count orelse 0;
        if (legacy_enable != null or modern_enable != null or draft_count != null or v13_count != null) {
            const versions = WebTransportVersions{
                .legacy = legacy_enable orelse (out.webtransport_max_sessions != 0),
                .draft16 = modern_enable orelse false,
            };
            out.webtransport_versions = versions;
            out.enable_webtransport = versions.any();
        }
        return out;
    }

    pub fn webTransportVersions(self: Settings) WebTransportVersions {
        if (!self.enable_webtransport and self.webtransport_max_sessions == 0) return .{};
        return self.webtransport_versions orelse .compatible;
    }

    pub fn writePayload(self: Settings, list: *std.ArrayList(u8), allocator: std.mem.Allocator) Error!void {
        const len = try self.payloadLen();
        try list.ensureUnusedCapacity(allocator, len);
        try self.writePayloadAssumeCapacity(list);
    }

    /// Internal frame writers validate via payloadLen and reserve that many
    /// bytes before calling this allocation-free append operation.
    pub fn writePayloadAssumeCapacity(self: Settings, list: *std.ArrayList(u8)) Error!void {
        if (self.qpack_max_table_capacity != 0) try writeSetting(list, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != std.math.maxInt(u64)) try writeSetting(list, .max_field_section_size, self.max_field_section_size);
        if (self.qpack_blocked_streams != 0) try writeSetting(list, .qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.enable_connect_protocol) try writeSetting(list, .enable_connect_protocol, 1);
        if (self.h3_datagram) try writeSetting(list, .h3_datagram, 1);
        const versions = self.webTransportVersions();
        if (versions.legacy) {
            // The historical netz name for 0x2b603742 is kept for source
            // compatibility. A boolean value avoids peers that validate it as an enable bit
            // rejecting counts greater than one.  The concrete max-session
            // count is emitted below under the newer identifiers.
            try writeSetting(list, .webtransport_max_sessions, 1);
        }
        if (versions.draft16) try writeSetting(list, .enable_webtransport, 1);
        if (versions.legacy and self.webtransport_max_sessions != 0) {
            try writeSetting(list, .webtransport_max_sessions_draft, self.webtransport_max_sessions);
            try writeSetting(list, .webtransport_max_sessions_v13, self.webtransport_max_sessions);
        }
        if (self.webtransport_initial_max_data != 0) try writeSetting(list, .webtransport_initial_max_data, self.webtransport_initial_max_data);
        if (self.webtransport_initial_max_streams_uni != 0) try writeSetting(list, .webtransport_initial_max_streams_uni, self.webtransport_initial_max_streams_uni);
        if (self.webtransport_initial_max_streams_bidi != 0) try writeSetting(list, .webtransport_initial_max_streams_bidi, self.webtransport_initial_max_streams_bidi);
    }

    pub fn payloadLen(self: Settings) Error!usize {
        try self.validateLocal();
        var len: usize = 0;
        if (self.qpack_max_table_capacity != 0) len = try addSettingLen(len, .qpack_max_table_capacity, self.qpack_max_table_capacity);
        if (self.max_field_section_size != std.math.maxInt(u64)) len = try addSettingLen(len, .max_field_section_size, self.max_field_section_size);
        if (self.qpack_blocked_streams != 0) len = try addSettingLen(len, .qpack_blocked_streams, self.qpack_blocked_streams);
        if (self.enable_connect_protocol) len = try addSettingLen(len, .enable_connect_protocol, 1);
        if (self.h3_datagram) len = try addSettingLen(len, .h3_datagram, 1);
        const versions = self.webTransportVersions();
        if (versions.legacy) {
            len = try addSettingLen(len, .webtransport_max_sessions, 1);
        }
        if (versions.draft16) len = try addSettingLen(len, .enable_webtransport, 1);
        if (versions.legacy and self.webtransport_max_sessions != 0) {
            len = try addSettingLen(len, .webtransport_max_sessions_draft, self.webtransport_max_sessions);
            len = try addSettingLen(len, .webtransport_max_sessions_v13, self.webtransport_max_sessions);
        }
        if (self.webtransport_initial_max_data != 0) len = try addSettingLen(len, .webtransport_initial_max_data, self.webtransport_initial_max_data);
        if (self.webtransport_initial_max_streams_uni != 0) len = try addSettingLen(len, .webtransport_initial_max_streams_uni, self.webtransport_initial_max_streams_uni);
        if (self.webtransport_initial_max_streams_bidi != 0) len = try addSettingLen(len, .webtransport_initial_max_streams_bidi, self.webtransport_initial_max_streams_bidi);
        return len;
    }

    pub fn validateLocal(self: Settings) Error!void {
        if (self.qpack_blocked_streams > max_supported_qpack_blocked_streams) {
            return error.QpackDynamicTableUnsupported;
        }
        if (self.qpack_max_table_capacity > quic.varint.max_value or
            (self.max_field_section_size != std.math.maxInt(u64) and
                self.max_field_section_size > quic.varint.max_value) or
            self.webtransport_max_sessions > quic.varint.max_value or
            self.webtransport_initial_max_data > quic.varint.max_value or
            self.webtransport_initial_max_streams_uni > quic.varint.max_value or
            self.webtransport_initial_max_streams_bidi > quic.varint.max_value)
        {
            return error.InvalidSetting;
        }
        if (std.math.cast(usize, self.qpack_max_table_capacity) == null) {
            return error.InvalidSetting;
        }
    }

    /// Validate the server SETTINGS that govern an accepted 0-RTT request.
    /// A server may increase remembered limits, but accepting early data and
    /// then reducing a capability the client was permitted to use would make
    /// already-sent HTTP/3 bytes invalid.
    pub fn validateAfterEarlyDataAccepted(
        remembered: Settings,
        current: Settings,
    ) Error!void {
        if (current.qpack_max_table_capacity <
            remembered.qpack_max_table_capacity or
            current.max_field_section_size <
                remembered.max_field_section_size or
            current.qpack_blocked_streams < remembered.qpack_blocked_streams or
            (remembered.enable_connect_protocol and
                !current.enable_connect_protocol) or
            (remembered.h3_datagram and !current.h3_datagram) or
            (remembered.enable_webtransport and
                !current.enable_webtransport) or
            current.webtransport_max_sessions <
                remembered.webtransport_max_sessions or
            current.webtransport_initial_max_data <
                remembered.webtransport_initial_max_data or
            current.webtransport_initial_max_streams_uni <
                remembered.webtransport_initial_max_streams_uni or
            current.webtransport_initial_max_streams_bidi <
                remembered.webtransport_initial_max_streams_bidi or
            !current.webTransportVersions().containsAll(remembered.webTransportVersions()))
        {
            return error.InvalidSetting;
        }
    }
};

fn settingLen(id: SettingId, value: u64) Error!usize {
    const id_len = try quic.varint.length(@intFromEnum(id));
    return std.math.add(usize, id_len, try quic.varint.length(value)) catch error.IntegerOverflow;
}

fn addSettingLen(current: usize, id: SettingId, value: u64) Error!usize {
    return std.math.add(usize, current, try settingLen(id, value)) catch error.IntegerOverflow;
}

fn writeSetting(list: *std.ArrayList(u8), id: SettingId, value: u64) Error!void {
    try quic.varint.encodeAssumeCapacity(list, @intFromEnum(id));
    try quic.varint.encodeAssumeCapacity(list, value);
}

pub const SettingsState = struct {
    local: Settings = .{},
    peer: Settings = .{},
    sent: bool = false,
    received: bool = false,

    pub fn markSent(self: *SettingsState, settings: Settings) void {
        self.local = settings;
        self.sent = true;
    }

    pub fn markReceived(self: *SettingsState, settings: Settings) void {
        self.peer = settings;
        self.received = true;
    }

    pub fn ready(self: SettingsState) bool {
        return self.sent and self.received;
    }
};

test {
    _ = @import("settings/tests.zig");
}

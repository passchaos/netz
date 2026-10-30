//! Peer SETTINGS policy shared by owned metadata and validated borrowed wire.
const http2 = @import("../../mod.zig");

pub fn Controller(comptime Context: type) type {
    return struct {
        const Connection = Context.ConnectionType;
        const Error = Context.ErrorType;

        pub fn apply(self: *Connection, settings: []const http2.Setting) Error!void {
            for (settings) |setting| try applyOne(self, setting);
            self.peer_initial_settings_applied = true;
        }

        pub fn applyBorrowed(self: *Connection, validated: http2.SettingsIterator) Error!void {
            var iterator = validated;
            while (iterator.next()) |setting| try applyOne(self, setting);
            self.peer_initial_settings_applied = true;
        }

        fn applyOne(self: *Connection, setting: http2.Setting) Error!void {
            try self.peer_webtransport_settings.apply(setting);
            switch (setting.id) {
                .initial_window_size => try Context.applyInitialWindowSize(self, setting.value),
                .max_frame_size => {
                    try http2.validateSetting(.max_frame_size, setting.value);
                    self.peer_max_frame_size = setting.value;
                },
                .max_header_list_size => self.peer_max_header_list_size = setting.value,
                .max_concurrent_streams => self.peer_max_concurrent_streams = setting.value,
                .header_table_size => self.hpack_encoder.setMaxDynamicTableSize(
                    self.allocator,
                    @min(
                        setting.value,
                        self.limits.max_encoder_table_size,
                    ),
                ),
                .no_rfc7540_priorities => {
                    if (setting.value > 1) return error.InvalidSetting;
                    const enabled = setting.value == 1;
                    if (self.peer_initial_settings_applied and
                        !self.peer_priority_setting_seen)
                    {
                        // SETTINGS_NO_RFC7540_PRIORITIES is only valid in the
                        // first peer SETTINGS frame.
                        return error.InvalidSetting;
                    }
                    if (self.peer_priority_setting_seen and
                        self.peer_no_rfc7540_priorities != enabled)
                    {
                        // RFC 9218 requires this value in the initial SETTINGS
                        // and forbids changing it later. Rejecting a change
                        // avoids switching scheduling semantics mid-connection.
                        return error.InvalidSetting;
                    }
                    self.peer_priority_setting_seen = true;
                    self.peer_no_rfc7540_priorities = enabled;
                },
                .enable_push => {
                    if (setting.value > 1) return error.InvalidSetting;
                    // RFC 9113 allows a server to send the setting explicitly
                    // with value 0; only server-to-client value 1 is a
                    // connection-level protocol error.
                    if (self.role == .client and setting.value == 1) {
                        return error.InvalidSetting;
                    }
                    self.peer_enable_push = setting.value == 1;
                },
                .enable_connect_protocol => {
                    if (setting.value > 1) return error.InvalidSetting;
                    // RFC 8441 uses SETTINGS_ENABLE_CONNECT_PROTOCOL as an
                    // irreversible opt-in because :protocol changes request
                    // validation semantics.  A peer may omit the setting or
                    // send 0 before opting in, but once 1 has been observed it
                    // must not downgrade the connection back to 0.
                    if (self.peer_enable_connect_protocol and setting.value == 0) return error.InvalidSetting;
                    self.peer_enable_connect_protocol = setting.value == 1;
                },
                else => {},
            }
        }
    };
}

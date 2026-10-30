//! HTTP/2 WebTransport draft-15 capability and initial credit SETTINGS.
const http2 = @import("mod.zig");
pub const Settings = struct {
    enabled: bool = false,
    max_data: u32 = 0,
    max_stream_data_uni: u32 = 0,
    max_stream_data_bidi_local: u32 = 0,
    max_stream_data_bidi_remote: u32 = 0,
    max_streams_uni: u32 = 0,
    max_streams_bidi: u32 = 0,

    pub fn apply(self: *Settings, setting: http2.Setting) http2.Error!void {
        switch (setting.id) {
            .webtransport_enabled => {
                if (setting.value > 1) return error.InvalidSetting;
                self.enabled = setting.value == 1;
            },
            .webtransport_initial_max_data => self.max_data = setting.value,
            .webtransport_initial_max_stream_data_uni => self.max_stream_data_uni = setting.value,
            .webtransport_initial_max_stream_data_bidi_local => self.max_stream_data_bidi_local = setting.value,
            .webtransport_initial_max_stream_data_bidi_remote => self.max_stream_data_bidi_remote = setting.value,
            .webtransport_initial_max_streams_uni => self.max_streams_uni = setting.value,
            .webtransport_initial_max_streams_bidi => self.max_streams_bidi = setting.value,
            else => {},
        }
    }
    pub fn write(self: Settings, out: *[7]http2.Setting) []const http2.Setting {
        out.* = .{
            .{ .id = .webtransport_enabled, .value = @intFromBool(self.enabled) },
            .{ .id = .webtransport_initial_max_data, .value = self.max_data },
            .{ .id = .webtransport_initial_max_stream_data_uni, .value = self.max_stream_data_uni },
            .{ .id = .webtransport_initial_max_stream_data_bidi_local, .value = self.max_stream_data_bidi_local },
            .{ .id = .webtransport_initial_max_stream_data_bidi_remote, .value = self.max_stream_data_bidi_remote },
            .{ .id = .webtransport_initial_max_streams_uni, .value = self.max_streams_uni },
            .{ .id = .webtransport_initial_max_streams_bidi, .value = self.max_streams_bidi },
        };
        return out;
    }
};

const std = @import("std");

pub const ApplicationErrorCode = struct {
    pub const session_gone: u64 = 0x170d7b68;
    pub const buffered_stream_rejected: u64 = 0x3994bd84;
    pub const flow_control_error: u64 = 0x045d4487;
    pub const mapped_base: u64 = 0x52e4a40fa8db;
};

pub fn applicationToHttp3(application_code: u32) u64 {
    const code: u64 = application_code;
    return ApplicationErrorCode.mapped_base + code + code / 0x1e;
}

pub fn http3ToApplication(http3_code: u64) ?u32 {
    if (http3_code < ApplicationErrorCode.mapped_base) return null;
    const difference = http3_code - ApplicationErrorCode.mapped_base;
    const max_code: u64 = std.math.maxInt(u32);
    const mapped_end = ApplicationErrorCode.mapped_base +
        max_code + max_code / 0x1e;
    if (http3_code > mapped_end) return null;
    if ((http3_code - 0x21) % 0x1f == 0) return null;
    const application_code = std.math.cast(
        u32,
        difference - difference / 0x1f,
    ) orelse return null;
    if (applicationToHttp3(application_code) != http3_code) return null;
    return application_code;
}

pub fn isStreamError(http3_code: u64) bool {
    return http3_code == ApplicationErrorCode.session_gone or
        http3_code == ApplicationErrorCode.buffered_stream_rejected or
        http3_code == ApplicationErrorCode.flow_control_error or
        http3ToApplication(http3_code) != null;
}

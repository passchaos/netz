const std = @import("std");
const netz = @import("netz");

pub const payload = "HTTP3 digest content " ** 512;
pub const generated = "{\"hello\": \"world\"}" ** 512;
pub const paths = [_][]const u8{ "/encoded", "/trailer", "/corrupt", "/head", "/range", "/stream", "/generated", "/sliced", "/finish" };

pub fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .raw = .fromSeconds(15), .clock = .awake });
}

pub fn parameters() netz.quic.TransportParameters {
    var out = netz.quic.practical_transport_parameters;
    out.initial_max_data = 8192;
    out.initial_max_stream_data_bidi_local = 2048;
    out.initial_max_stream_data_bidi_remote = 2048;
    return out;
}

pub fn field(data: []const u8, both: bool, sha512: bool, output: []u8) ![]u8 {
    return (try netz.http.digest.compute(data, .{ .sha256 = both or !sha512, .sha512 = both or sha512 })).writeInto(output);
}

/// Independent stored-gzip test image, also checked by Go's gzip decoder.
pub fn gzip(output: *[payload.len + 23]u8) []const u8 {
    @memcpy(output[0..10], &[_]u8{ 0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255 });
    output[10] = 1;
    std.mem.writeInt(u16, output[11..13], payload.len, .little);
    std.mem.writeInt(u16, output[13..15], ~@as(u16, payload.len), .little);
    @memcpy(output[15..][0..payload.len], payload);
    std.mem.writeInt(u32, output[15 + payload.len ..][0..4], std.hash.Crc32.hash(payload), .little);
    std.mem.writeInt(u32, output[19 + payload.len ..][0..4], payload.len, .little);
    return output;
}

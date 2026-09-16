//! Bounded HTTP/3 UDP receive policy.
//!
//! Keep memory and batching decisions out of the large runtime facade and the
//! packet cursor. The cursor remains responsible only for ordered packet
//! delivery and retained-suffix lifecycle.

const std = @import("std");

pub const default_endpoint_max_datagram_size: usize = 4096;
pub const max_raw_datagram_batch: usize = 16;
pub const raw_datagram_storage_limit: usize = 64 * 1024;

pub fn rawDatagramSlotCount(
    max_datagram_size: usize,
    max_datagrams: usize,
) usize {
    if (max_datagram_size == 0 or max_datagrams == 0) return 0;
    return @min(
        @min(max_raw_datagram_batch, max_datagrams),
        raw_datagram_storage_limit / max_datagram_size,
    );
}

pub fn validateMaxDatagrams(value: usize) error{InvalidSetting}!void {
    if (value == 0 or value > max_raw_datagram_batch) {
        return error.InvalidSetting;
    }
}

test "HTTP/3 receive policy bounds zio datagram batches" {
    try std.testing.expectEqual(
        @as(usize, 4096),
        default_endpoint_max_datagram_size,
    );
    try std.testing.expectEqual(
        @as(usize, max_raw_datagram_batch),
        rawDatagramSlotCount(1400, max_raw_datagram_batch),
    );
    try std.testing.expectEqual(
        @as(usize, 8),
        rawDatagramSlotCount(8192, max_raw_datagram_batch),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        rawDatagramSlotCount(65_535, max_raw_datagram_batch),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        rawDatagramSlotCount(1400, 1),
    );

    try validateMaxDatagrams(1);
    try validateMaxDatagrams(max_raw_datagram_batch);
    try std.testing.expectError(error.InvalidSetting, validateMaxDatagrams(0));
    try std.testing.expectError(
        error.InvalidSetting,
        validateMaxDatagrams(max_raw_datagram_batch + 1),
    );
}

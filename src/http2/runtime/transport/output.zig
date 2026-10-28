//! Keep TCP deadline output borrowed and TLS pending records contiguous.
const std = @import("std");
const stream_io = @import("../../../internal/stream_io.zig");

test {
    _ = @import("output_tests.zig");
}

pub fn writeAllSlicesWithDeadline(
    allocator: std.mem.Allocator,
    transport: anytype,
    parts: []const []const u8,
    batch: *std.ArrayList(u8),
    deadline: std.Io.Clock.Timestamp,
    submitted: *bool,
) !void {
    submitted.* = false;
    var committed: usize = 0;
    switch (transport) {
        .tcp => |tcp| {
            submitted.* = true;
            try stream_io.writeAllSlicesTrackedWithDeadline(tcp.io, tcp.stream, parts, &committed, deadline);
        },
        // Preserve TLS record batching and the contiguous plaintext prefix
        // used to validate a retry of connection-owned pending ciphertext.
        .tls_client, .tls_server => {
            batch.clearRetainingCapacity();
            for (parts) |part| try batch.appendSlice(allocator, part);
            submitted.* = true;
            try transport.writeAllWithDeadline(batch.items, &committed, deadline);
        },
    }
}

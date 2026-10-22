//! Application-body credit, preflighted before submission and committed only
//! for the accepted socket prefix. QUIC owns retransmission accounting.

const std = @import("std");
const webtransport = @import("../../mod.zig");
const flow_progress = @import("progress.zig");

pub fn available(registry: *const webtransport.StreamRegistry) usize {
    const flow = registry.flow orelse return std.math.maxInt(usize);
    return std.math.cast(usize, flow.sendDataAvailable()) orelse std.math.maxInt(usize);
}

pub fn check(registry: *const webtransport.StreamRegistry, bytes: usize) webtransport.Error!void {
    if (bytes > available(registry)) return error.FlowControlBlocked;
}

pub fn commit(registry: *webtransport.StreamRegistry, bytes: usize) void {
    const flow = registry.flow orelse return;
    if (!flow.enabled) return;
    std.debug.assert(bytes <= flow.sendDataAvailable());
    flow.sent.data += bytes;
}

pub fn wait(registry: *const webtransport.StreamRegistry, progress: ?flow_progress.Progress, deadline: ?std.Io.Clock.Timestamp) flow_progress.Error!void {
    if (progress) |owner| try owner.maintain(deadline);
    while (available(registry) == 0) {
        const owning = progress orelse return error.FlowControlBlocked;
        try owning.run(deadline);
    }
}

test {
    _ = @import("send/tests.zig");
}

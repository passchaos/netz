//! One bounded submission for all pending receiver flow-control updates.

const webtransport = @import("../../mod.zig");
const control_mod = @import("../session_control.zig");
const grant = @import("grant.zig");

pub fn replenish(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry) void {
    sendPending(control, h3, registry) catch {};
}

pub fn sendPending(control: *control_mod.Control, h3: anytype, registry: *webtransport.StreamRegistry) control_mod.Error!void {
    if (registry.flow_violation) return;
    const flow = registry.flow orelse return;
    var capsules: [3]webtransport.Capsule = undefined;
    var count: usize = 0;
    if (flow.automaticDataGrant()) |maximum| {
        capsules[count] = .{ .max_data = maximum };
        count += 1;
    }
    if (flow.automaticStreamGrant(.bidirectional)) |maximum| {
        capsules[count] = .{ .max_streams_bidi = maximum };
        count += 1;
    }
    if (flow.automaticStreamGrant(.unidirectional)) |maximum| {
        capsules[count] = .{ .max_streams_uni = maximum };
        count += 1;
    }
    if (count == 0) return;
    // Targets remain derivable from consumption/retirement until submission
    // succeeds, including when no further peer packet arrives.
    try grant.sendMany(control, h3, registry, capsules[0..count]);
}

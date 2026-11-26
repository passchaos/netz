//! All phases and retries of one owner command retain the caller's deadline.
const deadline_policy = @import("../../../internal/deadline.zig");

pub fn execute(owner: anytype, command: anytype) !void {
    if (command.deadline) |until| _ = try deadline_policy.usableAwake(owner.io, until);
    const slot = command.slot;
    switch (command.kind) {
        .informational => |value| {
            if (command.deadline) |until| {
                try slot.stream.writeInformationalResponseWithDeadline(value.status, value.headers, until);
            } else {
                try slot.stream.writeInformationalResponse(value.status, value.headers);
            }
        },
        .start_response => |options| try start(slot, options, command.deadline),
        .start_response_with_body => |value| {
            if (value.fin and comptime @hasDecl(@TypeOf(slot.stream), "startResponseWithBody")) {
                if (command.deadline) |until| {
                    try slot.stream.startResponseWithBodyWithDeadline(value.options, value.data, until);
                } else {
                    try slot.stream.startResponseWithBody(value.options, value.data);
                }
                slot.response_finished = true;
                return;
            }
            if (!command.head_started) {
                try start(slot, value.options, command.deadline);
                command.head_started = true;
            }
            if (slot.stream.responseFinished()) {
                if (value.data.len != 0) return error.InvalidContentLength;
                slot.response_finished = true;
                return;
            }
            try body(slot, command, value.data, value.fin);
        },
        .write_body => |value| try body(slot, command, value.data, value.fin),
        .finish_trailers => |fields| {
            if (command.deadline) |until| {
                try slot.stream.finishResponseTrailersWithDeadline(fields, until);
            } else {
                try slot.stream.finishResponseTrailers(fields);
            }
            slot.response_finished = true;
        },
        .cancel => |code| {
            if (command.deadline) |until| {
                try slot.stream.resetWithDeadline(code, until);
            } else {
                try slot.stream.reset(code);
            }
            slot.response_finished = true;
        },
    }
}

fn start(slot: anytype, options: anytype, deadline: anytype) !void {
    if (deadline) |until| {
        try slot.stream.startResponseWithDeadline(options, until);
    } else {
        try slot.stream.startResponse(options);
    }
}

fn body(slot: anytype, command: anytype, data: []const u8, fin: bool) !void {
    const before = slot.stream.responseCommittedBytes();
    // DATA can commit a prefix before yielding to inbound control traffic or
    // returning backpressure. A retry must neither replay it nor repeat HEADERS.
    defer command.body_offset += slot.stream.responseCommittedBytes() - before;
    const remaining = data[command.body_offset..];
    const slices: []const []const u8 = if (remaining.len == 0) &.{} else &.{remaining};
    const result = if (command.deadline) |until|
        try slot.stream.writeResponseSlicesWithDeadline(slices, fin, until)
    else
        try slot.stream.writeResponseSlices(slices, fin);
    if (result.response_available) return error.FlowControlBlocked;
    if (fin) slot.response_finished = slot.stream.responseFinished();
}

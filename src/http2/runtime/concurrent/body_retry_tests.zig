//! A controlled refusal follows confirmed TCP DATA, exercising the public retry.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const concurrent = @import("../concurrent.zig");
const Fixture = @import("../duplex/testing.zig").Fixture;
const FrameReader = @import("../frame/io.zig").Reader;
const native_io = @import("../../../internal/testing/native_protocol_io.zig");
const allocator = std.testing.allocator;

const Sender = struct {
    io: std.Io,
    socket: std.Io.net.Stream,
    blocked: bool = true,
    return_progress: bool = false,
    committed: usize = 0,
    finished: bool = false,
    deadlines: [4]std.Io.Clock.Timestamp = undefined,
    deadline_count: usize = 0,

    fn observe(self: *Sender, deadline: ?std.Io.Clock.Timestamp) !void {
        self.deadlines[self.deadline_count] = deadline orelse return error.MissingDeadline;
        self.deadline_count += 1;
    }
};
const Stream = struct {
    sender: *Sender,
    pub fn deinit(_: *Stream) void {}
    pub fn startResponse(self: *Stream, options: runtime.StreamingResponseOptions) !void {
        return self.start(options, null);
    }
    pub fn startResponseWithDeadline(self: *Stream, options: runtime.StreamingResponseOptions, deadline: std.Io.Clock.Timestamp) !void {
        return self.start(options, deadline);
    }
    fn start(self: *Stream, _: runtime.StreamingResponseOptions, deadline: ?std.Io.Clock.Timestamp) !void {
        try self.sender.observe(deadline);
        try runtime.writeFrame(allocator, self.sender.io, self.sender.socket, .headers, 4, 1, &.{0x88});
    }
    pub fn responseFinished(self: Stream) bool {
        return self.sender.finished;
    }
    pub fn responseCommittedBytes(self: Stream) usize {
        return self.sender.committed;
    }
    pub fn writeResponseSlices(self: *Stream, slices: []const []const u8, fin: bool) !runtime.DuplexWriteResult {
        return self.write(slices, fin, null);
    }
    pub fn writeResponseSlicesWithDeadline(self: *Stream, slices: []const []const u8, fin: bool, deadline: std.Io.Clock.Timestamp) !runtime.DuplexWriteResult {
        return self.write(slices, fin, deadline);
    }
    fn write(self: *Stream, slices: []const []const u8, fin: bool, deadline: ?std.Io.Clock.Timestamp) !runtime.DuplexWriteResult {
        try self.sender.observe(deadline);
        const bytes: []const u8 = if (slices.len == 0) "" else slices[0];
        const count = if (self.sender.blocked) @min(2, bytes.len) else bytes.len;
        const ended = fin and count == bytes.len;
        try runtime.writeFrame(allocator, self.sender.io, self.sender.socket, .data, @intFromBool(ended), 1, bytes[0..count]);
        self.sender.committed += count;
        self.sender.finished = ended;
        if (self.sender.blocked) {
            if (self.sender.return_progress) return .{ .written = count, .response_available = true };
            return error.FlowControlBlocked;
        }
        return .{ .written = count, .response_available = false };
    }
    pub fn writeInformationalResponse(_: *Stream, _: u16, _: []const http2.Hpack.HeaderField) !void {
        return error.UnexpectedCall;
    }
    pub fn writeInformationalResponseWithDeadline(_: *Stream, _: u16, _: []const http2.Hpack.HeaderField, _: std.Io.Clock.Timestamp) !void {
        return error.UnexpectedCall;
    }
    pub fn finishResponseTrailers(_: *Stream, _: []const http2.Hpack.HeaderField) !void {
        return error.UnexpectedCall;
    }
    pub fn finishResponseTrailersWithDeadline(_: *Stream, _: []const http2.Hpack.HeaderField, _: std.Io.Clock.Timestamp) !void {
        return error.UnexpectedCall;
    }
    pub fn reset(_: *Stream, _: http2.ErrorCode) !void {
        return error.UnexpectedCall;
    }
    pub fn resetWithDeadline(_: *Stream, _: http2.ErrorCode, _: std.Io.Clock.Timestamp) !void {
        return error.UnexpectedCall;
    }
};
const Connection = struct {};
const Engine = concurrent.Engine(Connection, Stream, runtime.StreamingResponseOptions);

fn retry(io: std.Io, combined: bool, return_progress: bool) !void {
    var fixture = try Fixture.init(io);
    defer fixture.deinit();
    var sender: Sender = .{ .io = io, .socket = fixture.connection.stream, .return_progress = return_progress };
    var connection: Connection = .{};
    var engine = Engine.init(&connection, allocator, io, .{});
    defer engine.deinit();
    const Slot = @typeInfo(@FieldType(Engine.Stream, "slot")).pointer.child;
    var slot: Slot = .{ .engine = &engine, .stream = .{ .sender = &sender }, .public_stream = undefined, .handler_inline = true };
    slot.public_stream = .{ .engine = &engine, .slot = &slot };
    engine.inline_active = true;
    engine.inline_slot = &slot;
    const Pump = struct {
        fn run(_: *Engine, raw: *anyopaque) !void {
            const state: *Sender = @ptrCast(@alignCast(raw));
            state.blocked = false;
        }
    };
    engine.inline_pump = Pump.run;
    engine.inline_pump_state = &sender;
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    if (combined) {
        try slot.public_stream.startResponseWithBodyWithDeadline(.{ .status = 200 }, "abcdef", false, deadline);
        try slot.public_stream.writeDataWithDeadline("", true, deadline);
    } else {
        try slot.public_stream.startResponseWithDeadline(.{ .status = 200 }, deadline);
        try slot.public_stream.writeDataWithDeadline("abcdef", true, deadline);
    }
    try std.testing.expect(slot.response_finished);
    for (sender.deadlines[0..sender.deadline_count]) |observed| {
        try std.testing.expectEqual(deadline.clock, observed.clock);
        try std.testing.expectEqual(deadline.raw.nanoseconds, observed.raw.nanoseconds);
    }
    try fixture.connection.stream.shutdown(io, .send);
    var reader: FrameReader = .{};
    defer reader.deinit(allocator);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var heads: usize = 0;
    var fins: usize = 0;
    while (true) {
        const frame = reader.read(allocator, io, fixture.peer, 16_384) catch |err| switch (err) {
            error.ConnectionClosed => break,
            else => return err,
        };
        switch (frame.frame.header.frame_type) {
            .headers => heads += 1,
            .data => {
                try bytes.appendSlice(allocator, frame.frame.payload);
                fins += @intFromBool(frame.frame.header.flags & 1 != 0);
            },
            else => return error.UnexpectedFrame,
        }
    }
    try std.testing.expectEqualStrings("abcdef", bytes.items);
    try std.testing.expectEqual(@as(usize, 1), heads);
    try std.testing.expectEqual(@as(usize, 1), fins);
}

test "HTTP/2 concurrent DATA retry retains confirmed TCP prefix and original deadline" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try retry(io, false, false);
        }
    }.run);
}
test "HTTP/2 concurrent compound response retry retains one HEADERS and exact DATA" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try retry(io, true, false);
        }
    }.run);
}

test "HTTP/2 concurrent DATA retry resumes after inbound progress without replay" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try retry(io, false, true);
        }
    }.run);
}
test "HTTP/2 concurrent compound response retry resumes after inbound progress" {
    try native_io.runStream(struct {
        fn run(io: std.Io) !void {
            try retry(io, true, true);
        }
    }.run);
}

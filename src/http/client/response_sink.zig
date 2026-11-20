//! Common callback sinks and streaming body Writer composition.
const std = @import("std");
const types = @import("types.zig");

pub const ResponseHead = struct {
    protocol: types.Protocol,
    status: u16,
    headers: []const types.Header,
};

/// Writable storage for the stateless discard sink. Callbacks never access it,
/// but a non-const pointer avoids casting away constness in the public API.
var discard_context: u8 = 0;

pub const ResponseSink = struct {
    context: *anyopaque,
    begin: *const fn (*anyopaque, ResponseHead) anyerror!void = ignoreHead,
    data: *const fn (*anyopaque, []const u8) anyerror!void = ignoreData,
    end: *const fn (*anyopaque, []const types.Header) anyerror!void = ignoreTrailers,
    /// Optional 1xx observer. Head slices are valid only during the callback.
    informational: ?*const fn (*anyopaque, ResponseHead) void = null,

    /// Drain the response without retaining its body or trailer fields.
    pub fn discard() ResponseSink {
        return .{ .context = &discard_context };
    }

    /// Forward body chunks into a borrowed Writer. The caller owns flushing
    /// and may attach head/trailer/informational callbacks to the returned sink.
    pub fn toWriter(writer: *std.Io.Writer) ResponseSink {
        return .{ .context = writer, .data = writeData };
    }

    fn ignoreHead(_: *anyopaque, _: ResponseHead) !void {}
    fn ignoreData(_: *anyopaque, _: []const u8) !void {}
    fn ignoreTrailers(_: *anyopaque, _: []const types.Header) !void {}
    fn writeData(context: *anyopaque, bytes: []const u8) !void {
        const writer: *std.Io.Writer = @ptrCast(@alignCast(context));
        try writer.writeAll(bytes);
    }
};

//! Own a single unary response while the worker multiplexes its stream.
const std = @import("std");
const call = @import("../../call.zig");
const duplex = @import("../../stream/duplex.zig");
const codec = @import("../../stream/codec.zig");
const Job = @import("job.zig").Job;

pub const Active = struct {
    job: *Job,
    stream: duplex.ClientDuplex,
    body: ?[]u8 = null,
    count: usize = 0,
    observed_head: bool = false,
    was_compressed: bool = false,

    pub fn deinit(self: *Active) void {
        if (self.body) |body| self.stream.allocator.free(body);
        self.stream.deinit();
    }

    pub fn consume(self: *Active, message: codec.DecodedMessage) !void {
        if (self.count != 0) return error.InvalidMessageCount;
        const body = try self.stream.allocator.alloc(u8, try std.math.add(usize, message.payload.len, 5));
        body[0] = 0;
        std.mem.writeInt(u32, body[1..5], @intCast(message.payload.len), .big);
        @memcpy(body[5..], message.payload);
        self.body = body;
        self.count = 1;
        self.was_compressed = message.was_compressed;
    }

    /// The advanced HTTP/2 body view is a normalized, uncompressed gRPC frame;
    /// decoded payload aliases it, retaining one response-message allocation.
    pub fn finish(self: *Active, terminal: duplex.Response) !call.UnaryResponse {
        if (terminal.status == .ok and self.count != 1) return error.InvalidMessageCount;
        const body: []u8 = self.body orelse &.{};
        const head = terminal.head;
        const trailers_only = if (head) |value| call.headerValue(value.headers, "grpc-status") != null else false;
        const response: call.UnaryResponse = .{
            .allocator = self.stream.allocator,
            .transport = if (head) |value| .{
                .headers = value.headers,
                .status = value.status,
                .body = body,
                .trailers = terminal.trailers orelse &.{},
                .trailers_only = trailers_only,
            } else null,
            .reset = terminal.reset,
            .response_committed = self.observed_head or !trailers_only and head != null,
            .status = terminal.status,
            .status_message = terminal.status_message,
            .status_details = terminal.status_details,
            .message = if (self.body != null) .{ .compressed = false, .payload = body[5..] } else null,
            .was_compressed = self.was_compressed,
            .encoding = terminal.encoding,
            .owned_message = if (head == null) self.body else null,
        };
        self.body = null;
        return response;
    }
};

//! Byte-stream adapter over one gRPC bidirectional RPC.
//!
//! Each gRPC message carries one chunk of the proxy byte stream. The adapter
//! concatenates inbound messages into a bounded buffer and splits outbound
//! writes into bounded gRPC messages.

const std = @import("std");
const netz = @import("../netz.zig");

const max_chunk_bytes: usize = 16 * 1024;

pub const Stream = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    duplex: *netz.grpc.ServerDuplex,
    idle_timeout: std.Io.Duration,
    read_buffer: [max_chunk_bytes]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,
    finished: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        duplex: *netz.grpc.ServerDuplex,
        idle_timeout: std.Io.Duration,
    ) Stream {
        return .{
            .allocator = allocator,
            .io = io,
            .duplex = duplex,
            .idle_timeout = idle_timeout,
        };
    }

    pub fn deinit(self: *Stream) void {
        self.finish();
    }

    pub fn read(self: *Stream, output: []u8) !usize {
        return self.readTimeout(output, self.idle_timeout);
    }

    pub fn readTimeout(
        self: *Stream,
        output: []u8,
        timeout: std.Io.Duration,
    ) !usize {
        if (output.len == 0) return 0;
        if (self.read_start == self.read_end) {
            self.read_start = 0;
            self.read_end = 0;
            while (true) {
                var used: usize = 0;
                var context = ConsumeContext{
                    .buffer = &self.read_buffer,
                    .used = &used,
                };
                var event = self.duplex.readRequestEventWithTimeout(
                    timeout,
                    &context,
                    consumeMessage,
                ) catch |err| switch (err) {
                    error.ConnectionClosed => return 0,
                    else => return err,
                };
                defer event.deinit();
                switch (event) {
                    .messages => |progress| {
                        if (used > 0) {
                            self.read_end = used;
                            break;
                        }
                        if (progress.end_stream) return 0;
                    },
                    .finished => return 0,
                    .reset => return error.ConnectionClosed,
                }
            }
        }
        const take = @min(output.len, self.read_end - self.read_start);
        @memcpy(output[0..take], self.read_buffer[self.read_start..][0..take]);
        self.read_start += take;
        return take;
    }

    pub fn writeAll(self: *Stream, bytes: []const u8) !void {
        if (self.finished) return error.ConnectionClosed;
        var offset: usize = 0;
        while (offset < bytes.len) {
            const chunk = @min(bytes.len - offset, max_chunk_bytes);
            var attempts: usize = 0;
            var result = self.duplex.writeMessage(
                bytes[offset..][0..chunk],
            ) catch |err| return err;
            while (result == .peer_event and attempts < 100) : (attempts += 1) {
                result = self.duplex.resumeMessage() catch |err| return err;
            }
            if (result != .complete) return error.ConnectionClosed;
            offset += chunk;
        }
    }

    pub fn finish(self: *Stream) void {
        if (self.finished) return;
        self.finished = true;
        self.duplex.finishOk() catch {};
    }
};

const ConsumeContext = struct {
    buffer: *[max_chunk_bytes]u8,
    used: *usize,
};

pub fn consumeMessage(
    context: *ConsumeContext,
    message: netz.grpc.stream.DecodedMessage,
) !void {
    if (context.used.* + message.payload.len > context.buffer.len) {
        return error.MessageTooLarge;
    }
    @memcpy(
        context.buffer[context.used.*..][0..message.payload.len],
        message.payload,
    );
    context.used.* += message.payload.len;
}

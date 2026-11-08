//! Byte-stream adapter over one HTTP/2 CONNECT tunnel.
//!
//! VLESS and VMess run their normal byte-oriented parser on the tunnel. The
//! adapter keeps unread DATA in a bounded buffer and exposes the same
//! `readTimeout`/`writeAll`/`finish` surface as the QUIC stream adapter.

const std = @import("std");
const netz = @import("../netz.zig");

pub const Stream = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    tunnel: *netz.http2.runtime.Tunnel,
    idle_timeout: std.Io.Duration,
    read_buffer: [16 * 1024]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,
    finished: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        io: std.Io,
        tunnel: *netz.http2.runtime.Tunnel,
        idle_timeout: std.Io.Duration,
    ) Stream {
        return .{
            .allocator = allocator,
            .io = io,
            .tunnel = tunnel,
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
            var data = self.tunnel.readWithTimeout(timeout) catch |err| switch (err) {
                error.ConnectionClosed => return 0,
                else => return err,
            };
            defer data.deinit(self.allocator);
            if (data.data.len > self.read_buffer.len) {
                return error.BufferTooSmall;
            }
            @memcpy(self.read_buffer[0..data.data.len], data.data);
            self.read_end = data.data.len;
            if (self.read_end == 0 and data.end_stream) return 0;
        }
        const take = @min(output.len, self.read_end - self.read_start);
        @memcpy(output[0..take], self.read_buffer[self.read_start..][0..take]);
        self.read_start += take;
        return take;
    }

    pub fn writeAll(self: *Stream, bytes: []const u8) !void {
        if (self.finished) return error.ConnectionClosed;
        var sent: usize = 0;
        var attempts: usize = 0;
        while (sent < bytes.len and attempts < 200) : (attempts += 1) {
            var progress: netz.http2.runtime.TunnelWriteProgress = .{};
            self.tunnel.writeWithTimeout(
                bytes[sent..],
                false,
                &progress,
                .fromMilliseconds(20),
            ) catch |err| switch (err) {
                error.Timeout => {
                    sent += progress.committed_bytes;
                    std.Io.sleep(
                        self.io,
                        .fromMilliseconds(1),
                        .awake,
                    ) catch {};
                    continue;
                },
                else => return err,
            };
            sent += progress.committed_bytes;
        }
        if (sent < bytes.len) return error.ConnectionClosed;
    }

    pub fn finish(self: *Stream) void {
        if (self.finished) return;
        self.finished = true;
        self.tunnel.closeWriteWithTimeout(.fromMilliseconds(20)) catch {};
    }
};

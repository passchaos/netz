//! Byte-stream adapter over one QUIC bidirectional stream.
//!
//! VLESS and VMess servers operate on a `read`/`writeAll` interface. QUIC
//! already provides TLS, so a stream adapter lets those servers run over QUIC
//! without a second TLS layer.

const std = @import("std");
const netz = @import("../netz.zig");

const quic = netz.quic;

pub const Stream = struct {
    io: std.Io,
    established: *quic.handshake.EstablishedConnection,
    stream_id: u64,
    mutex: std.Io.Mutex = .init,
    send_offset: u64 = 0,
    sent_fin: bool = false,
    idle_timeout: std.Io.Duration,
    read_buffer: [4096]u8 = undefined,
    read_start: usize = 0,
    read_end: usize = 0,

    pub fn init(
        io: std.Io,
        established: *quic.handshake.EstablishedConnection,
        stream_id: u64,
        idle_timeout: std.Io.Duration,
    ) Stream {
        return .{
            .io = io,
            .established = established,
            .stream_id = stream_id,
            .idle_timeout = idle_timeout,
        };
    }

    /// Seed the adapter with bytes already returned by the first stream event.
    pub fn setInitial(self: *Stream, bytes: []const u8) void {
        const take = @min(bytes.len, self.read_buffer.len);
        @memcpy(self.read_buffer[0..take], bytes[0..take]);
        self.read_start = 0;
        self.read_end = take;
    }

    pub fn deinit(self: *Stream) void {
        self.finish();
    }

    pub fn read(self: *Stream, output: []u8) !usize {
        return self.readTimeout(output, self.idle_timeout);
    }

    /// Read with an explicit relative timeout. `error.Timeout` means no bytes
    /// arrived in the window; a zero-length success means the peer finished.
    pub fn readTimeout(
        self: *Stream,
        output: []u8,
        timeout: std.Io.Duration,
    ) !usize {
        if (output.len == 0) return 0;
        if (self.read_start == self.read_end) {
            self.read_start = 0;
            self.read_end = 0;
            self.mutex.lockUncancelable(self.io);
            const event = self.established.connection.receiveStreamIdWithTimeout(
                @intCast(self.stream_id),
                &self.read_buffer,
                timeout,
            ) catch |err| {
                self.mutex.unlock(self.io);
                return err;
            };
            self.mutex.unlock(self.io);
            switch (event) {
                .data => |data| {
                    if (data.bytes == 0) return 0;
                    self.read_end = data.bytes;
                },
                .reset => return error.ConnectionClosed,
            }
        }
        const take = @min(output.len, self.read_end - self.read_start);
        @memcpy(output[0..take], self.read_buffer[self.read_start..][0..take]);
        self.read_start += take;
        return take;
    }

    pub fn writeAll(self: *Stream, bytes: []const u8) !void {
        if (self.sent_fin) return error.ConnectionClosed;
        var sent: usize = 0;
        var attempts: usize = 0;
        while (sent < bytes.len and attempts < 200) : (attempts += 1) {
            var committed: usize = 0;
            self.mutex.lockUncancelable(self.io);
            const result = self.established.connection.sendStreamWithTimeout(
                self.stream_id,
                self.send_offset + sent,
                bytes[sent..],
                false,
                &committed,
                .fromMilliseconds(20),
            );
            self.mutex.unlock(self.io);
            sent += committed;
            result catch |err| switch (err) {
                error.Timeout => {
                    std.Io.sleep(
                        self.io,
                        .fromMilliseconds(1),
                        .awake,
                    ) catch {};
                },
                else => return err,
            };
        }
        if (sent < bytes.len) return error.ConnectionClosed;
        self.send_offset += sent;
    }

    pub fn finish(self: *Stream) void {
        if (self.sent_fin) return;
        self.sent_fin = true;
        var committed: usize = 0;
        self.mutex.lockUncancelable(self.io);
        self.established.connection.sendStreamWithTimeout(
            self.stream_id,
            self.send_offset,
            "",
            true,
            &committed,
            .fromMilliseconds(20),
        ) catch {};
        self.mutex.unlock(self.io);
    }
};

//! Socket-backed duplex test fixture, with caller-owned I/O lifetime.
const std = @import("std");
const http2 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const wire = @import("../frame/wire.zig");
const allocator = std.testing.allocator;

pub const Fixture = struct {
    io: std.Io,
    listener: std.Io.net.Server,
    peer: std.Io.net.Stream,
    connection: runtime.Connection,

    pub fn init(io: std.Io) !Fixture {
        var listener = try (std.Io.net.IpAddress{ .ip4 = .loopback(0) }).listen(io, .{ .reuse_address = true });
        errdefer listener.deinit(io);
        const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
        errdefer stream.close(io);
        const peer = try listener.accept(io);
        return .{ .io = io, .listener = listener, .peer = peer, .connection = .{
            .io = io,
            .allocator = allocator,
            .stream = stream,
            .role = .client,
        } };
    }

    pub fn deinit(self: *Fixture) void {
        self.connection.close();
        self.peer.close(self.io);
        self.listener.deinit(self.io);
    }

    pub fn frame(self: *Fixture, kind: http2.FrameType, flags: u8, id: u31, bytes: []const u8) !void {
        try wire.appendFrame(&self.connection.frame_reader.buffer, allocator, kind, flags, id, bytes);
    }

    pub fn headers(self: *Fixture, encoder: *http2.Hpack.Encoder, id: u31, end_stream: bool, fields: []const http2.Hpack.HeaderField) !void {
        const block = try encoder.encodeBlockRetained(allocator, fields);
        try self.frame(.headers, 4 | @as(u8, if (end_stream) 1 else 0), id, block);
    }

    pub fn open(self: *Fixture) !runtime.ClientDuplexStream {
        var writer = try self.connection.startRequest(.{ .authority = "localhost", .body_length = 0 });
        errdefer writer.deinit();
        try writer.finish();
        return writer.beginDuplex();
    }
};

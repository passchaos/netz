const std = @import("std");
const webtransport = @import("../../mod.zig");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");

pub const Datagram = struct {
    quic_datagram: quic.runtime.OwnedDatagram,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *Datagram, allocator: std.mem.Allocator) void {
        self.quic_datagram.deinit(allocator);
        self.* = undefined;
    }
};

pub const Protected = struct {
    packet: quic.one_rtt.ReceivedPacket,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *Protected, allocator: std.mem.Allocator) void {
        self.packet.deinit(allocator);
        self.* = undefined;
    }
};

pub const Handshake = struct {
    bytes: []u8,
    datagram: webtransport.Datagram,

    pub fn deinit(self: *Handshake, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const HandshakeBatch = struct {
    allocator: std.mem.Allocator,
    datagrams: []?Handshake,
    errors: []?anyerror,

    pub fn deinit(self: *HandshakeBatch) void {
        for (self.datagrams) |*datagram| {
            if (datagram.*) |*owned| owned.deinit(self.allocator);
        }
        self.allocator.free(self.datagrams);
        self.allocator.free(self.errors);
        self.* = undefined;
    }

    pub fn firstError(self: HandshakeBatch) ?anyerror {
        for (self.errors) |err| {
            if (err) |value| return value;
        }
        return null;
    }

    pub fn receivedCount(self: HandshakeBatch) usize {
        var count: usize = 0;
        for (self.datagrams) |datagram| {
            count += @intFromBool(datagram != null);
        }
        return count;
    }
};

pub fn parseQuic(datagram: quic.runtime.OwnedDatagram) !webtransport.Datagram {
    for (datagram.frames) |frame| {
        if (frame != .datagram) continue;
        return webtransport.Datagram.parse(frame.datagram.data);
    }
    return error.MissingDatagram;
}

pub fn fromConnect(
    value: http3.runtime.OwnedConnectDatagram,
    session_id: webtransport.SessionId,
) Handshake {
    std.debug.assert(value.stream_id == session_id.value);
    return .{
        .bytes = value.payload,
        .datagram = .{
            .session_id = session_id,
            .payload = value.payload,
        },
    };
}

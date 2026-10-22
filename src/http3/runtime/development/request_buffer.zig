const std = @import("std");
const quic = @import("../../../quic/mod.zig");
const Error = @import("../error.zig").Error;
const frame_limits = @import("../stream/frame_limits.zig");

const net = std.Io.net;

pub const AssembledStream = struct {
    pub const OwnedParts = struct {
        datagram: quic.runtime.OwnedDatagram,
        extra_datagrams: []quic.runtime.OwnedDatagram,
        bytes: []u8,
    };

    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
    datagrams: []quic.runtime.OwnedDatagram,

    pub fn deinit(self: *AssembledStream, allocator: std.mem.Allocator) void {
        for (self.datagrams) |*datagram| datagram.deinit(allocator);
        allocator.free(self.datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }

    pub fn intoOwnedParts(
        self: *AssembledStream,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!OwnedParts {
        std.debug.assert(self.datagrams.len != 0);
        const extra_datagrams = try allocator.alloc(
            quic.runtime.OwnedDatagram,
            self.datagrams.len - 1,
        );
        return self.intoOwnedPartsPreallocated(allocator, extra_datagrams);
    }

    pub fn intoOwnedPartsPreallocated(
        self: *AssembledStream,
        allocator: std.mem.Allocator,
        extra_datagrams: []quic.runtime.OwnedDatagram,
    ) OwnedParts {
        std.debug.assert(extra_datagrams.len == self.datagrams.len - 1);
        @memcpy(extra_datagrams, self.datagrams[1..]);
        const datagram = self.datagrams[0];
        allocator.free(self.datagrams);
        self.datagrams = &.{};
        const bytes = self.bytes;
        self.bytes = &.{};
        return .{
            .datagram = datagram,
            .extra_datagrams = extra_datagrams,
            .bytes = bytes,
        };
    }
};

pub const PreparedReady = struct {
    from: net.IpAddress,
    stream_id: u62,
    bytes: []u8,
    extra_datagrams: []quic.runtime.OwnedDatagram,

    pub fn deinit(self: *PreparedReady, allocator: std.mem.Allocator) void {
        allocator.free(self.extra_datagrams);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Cleartext development-runtime request assembly keyed by peer address and
/// stream ID. UDP clients all start at stream zero, so stream ID alone cannot
/// identify a request when one server endpoint serves several peers.
pub const Set = struct {
    pub const EntryView = struct {
        from: net.IpAddress,
        stream_id: u62,
    };

    pub const Transfer = struct {
        from: net.IpAddress,
        receive: quic.stream_state.RecvState,
    };

    const Entry = struct {
        from: net.IpAddress,
        receive: quic.stream_state.RecvState,
        datagrams: std.ArrayList(quic.runtime.OwnedDatagram) = .empty,

        fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
            self.receive.deinit();
            for (self.datagrams.items) |*datagram| datagram.deinit(allocator);
            self.datagrams.deinit(allocator);
            self.* = undefined;
        }
    };

    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    max_stream_buffer: usize,
    max_streams: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        max_stream_buffer: usize,
        max_streams: usize,
    ) Set {
        return .{
            .allocator = allocator,
            .max_stream_buffer = max_stream_buffer,
            .max_streams = max_streams,
        };
    }

    pub fn deinit(self: *Set) void {
        for (self.entries.items) |*entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn count(self: Set) usize {
        return self.entries.items.len;
    }

    pub fn isEmpty(self: Set) bool {
        return self.entries.items.len == 0;
    }

    pub fn entryView(self: Set, index: usize) ?EntryView {
        if (index >= self.entries.items.len) return null;
        const entry = self.entries.items[index];
        return .{
            .from = entry.from,
            .stream_id = @intCast(entry.receive.stream_id),
        };
    }

    pub fn countForPeer(self: Set, from: net.IpAddress) usize {
        var result: usize = 0;
        for (self.entries.items) |entry| {
            result += @intFromBool(entry.from.eql(&from));
        }
        return result;
    }

    /// Move every reassembler to `context` after all callers have completed
    /// their capacity preflight. Datagrams retained only for aggregate owned
    /// responses are released here because streaming readers own byte state.
    pub fn transferAllAssumeCapacity(
        self: *Set,
        context: anytype,
        comptime adopt: anytype,
    ) void {
        for (self.entries.items) |*entry| {
            adopt(context, .{
                .from = entry.from,
                .receive = entry.receive,
            });
            for (entry.datagrams.items) |*datagram| {
                datagram.deinit(self.allocator);
            }
            entry.datagrams.deinit(self.allocator);
            entry.* = undefined;
        }
        self.entries.clearRetainingCapacity();
    }

    /// Insert every request/response STREAM frame from one datagram. Returns
    /// whether ownership of the datagram moved into a request entry.
    pub fn insertDatagram(
        self: *Set,
        datagram: *quic.runtime.OwnedDatagram,
    ) Error!bool {
        // Validate the whole datagram before changing reassembly state. This
        // keeps an invalid packet containing multiple request streams from
        // partially mutating one stream before it is rejected.
        var selected_stream_id: ?u62 = null;
        for (datagram.frames) |frame| {
            if (frame != .stream) continue;
            if (try messageStreamDisposition(frame.stream.stream_id) == .ignore) {
                continue;
            }
            const stream_id: u62 = @intCast(frame.stream.stream_id);
            if (selected_stream_id) |selected| {
                if (selected != stream_id) return error.UnexpectedStream;
            } else {
                selected_stream_id = stream_id;
            }
        }
        const stream_id = selected_stream_id orelse return false;

        for (datagram.frames) |frame| {
            if (frame != .stream or frame.stream.stream_id != stream_id) {
                continue;
            }
            const entry = try self.getOrCreate(datagram.from, stream_id);
            entry.receive.insert(frame.stream) catch |err| {
                self.discard(datagram.from, stream_id);
                return err;
            };
            frame_limits.validateAvailableFieldSection(
                entry.receive.available(),
                self.max_stream_buffer,
                .request,
            ) catch |err| {
                self.discard(datagram.from, stream_id);
                return err;
            };
        }
        const entry = self.find(datagram.from, stream_id).?;
        entry.datagrams.append(self.allocator, datagram.*) catch |err| {
            self.discard(datagram.from, stream_id);
            return err;
        };
        return true;
    }

    pub fn takeReady(self: *Set) Error!?AssembledStream {
        for (self.entries.items, 0..) |*entry, index| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;

            const bytes = try self.allocator.dupe(
                u8,
                entry.receive.buffer.items[0..final_size],
            );
            errdefer self.allocator.free(bytes);
            const datagrams = try entry.datagrams.toOwnedSlice(self.allocator);
            const from = entry.from;
            const stream_id: u62 = @intCast(entry.receive.stream_id);
            entry.receive.deinit();
            _ = self.entries.swapRemove(index);
            return .{
                .from = from,
                .stream_id = stream_id,
                .bytes = bytes,
                .datagrams = datagrams,
            };
        }
        return null;
    }

    pub fn prepareReady(
        self: *Set,
        result_allocator: std.mem.Allocator,
    ) Error!?PreparedReady {
        for (self.entries.items) |*entry| {
            const final_size = entry.receive.final_size orelse continue;
            if (entry.receive.contiguous_end < final_size) continue;
            const bytes = try result_allocator.dupe(
                u8,
                entry.receive.buffer.items[0..final_size],
            );
            errdefer result_allocator.free(bytes);
            return .{
                .from = entry.from,
                .stream_id = @intCast(entry.receive.stream_id),
                .bytes = bytes,
                .extra_datagrams = try result_allocator.alloc(
                    quic.runtime.OwnedDatagram,
                    entry.datagrams.items.len - 1,
                ),
            };
        }
        return null;
    }

    pub fn commitPreparedReady(
        self: *Set,
        prepared: *PreparedReady,
    ) AssembledStream.OwnedParts {
        for (self.entries.items, 0..) |*entry, index| {
            if (entry.receive.stream_id != prepared.stream_id or
                !entry.from.eql(&prepared.from)) continue;
            std.debug.assert(entry.datagrams.items.len != 0);
            std.debug.assert(
                prepared.extra_datagrams.len ==
                    entry.datagrams.items.len - 1,
            );
            @memcpy(
                prepared.extra_datagrams,
                entry.datagrams.items[1..],
            );
            const datagram = entry.datagrams.items[0];
            entry.datagrams.deinit(self.allocator);
            entry.receive.deinit();
            _ = self.entries.swapRemove(index);
            const result: AssembledStream.OwnedParts = .{
                .datagram = datagram,
                .extra_datagrams = prepared.extra_datagrams,
                .bytes = prepared.bytes,
            };
            prepared.* = undefined;
            return result;
        }
        unreachable;
    }

    pub fn discardReady(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) void {
        self.discard(from, stream_id);
    }

    pub fn ensureStream(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!*quic.stream_state.RecvState {
        const entry = try self.getOrCreate(from, stream_id);
        return &entry.receive;
    }

    fn getOrCreate(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) Error!*Entry {
        if (self.find(from, stream_id)) |entry| return entry;
        if (self.entries.items.len >= self.max_streams) {
            return error.ExcessiveLoad;
        }
        try self.entries.append(self.allocator, .{
            .from = from,
            .receive = .init(
                self.allocator,
                stream_id,
                self.max_stream_buffer,
            ),
        });
        return &self.entries.items[self.entries.items.len - 1];
    }

    fn find(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) ?*Entry {
        for (self.entries.items) |*entry| {
            if (entry.receive.stream_id == stream_id and
                entry.from.eql(&from)) return entry;
        }
        return null;
    }

    fn discard(
        self: *Set,
        from: net.IpAddress,
        stream_id: u62,
    ) void {
        for (self.entries.items, 0..) |*entry, index| {
            if (entry.receive.stream_id != stream_id or
                !entry.from.eql(&from)) continue;
            entry.deinit(self.allocator);
            _ = self.entries.swapRemove(index);
            return;
        }
    }
};

const MessageStreamDisposition = enum { request_response, ignore };

fn messageStreamDisposition(stream_id: u64) Error!MessageStreamDisposition {
    if ((stream_id & 0x02) != 0) return .ignore;
    if ((stream_id & 0x01) != 0) return error.StreamCreationError;
    return .request_response;
}

test "HTTP/3 development request buffer rejects mixed streams transactionally" {
    const allocator = std.testing.allocator;
    var set = Set.init(allocator, 512, 4);
    defer set.deinit();

    const bytes = try allocator.dupe(u8, "ab");
    const frames = try allocator.alloc(quic.Frame, 2);
    frames[0] = .{ .stream = .{ .stream_id = 0, .data = bytes[0..1] } };
    frames[1] = .{ .stream = .{ .stream_id = 4, .data = bytes[1..2] } };
    var datagram: quic.runtime.OwnedDatagram = .{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = bytes,
        .frames = frames,
    };
    defer datagram.deinit(allocator);

    try std.testing.expectError(
        error.UnexpectedStream,
        set.insertDatagram(&datagram),
    );
    try std.testing.expect(set.isEmpty());
}

test "HTTP/3 development request buffer drops unbufferable field section header" {
    const allocator = std.testing.allocator;
    var set = Set.init(allocator, 64, 1);
    defer set.deinit();

    const bytes = try allocator.dupe(u8, &.{ 0x01, 63 });
    const frames = try allocator.alloc(quic.Frame, 1);
    frames[0] = .{ .stream = .{
        .stream_id = 0,
        .data = bytes,
    } };
    var datagram: quic.runtime.OwnedDatagram = .{
        .from = .{ .ip4 = .loopback(443) },
        .bytes = bytes,
        .frames = frames,
    };
    defer datagram.deinit(allocator);

    try std.testing.expectError(
        error.ExcessiveLoad,
        set.insertDatagram(&datagram),
    );
    try std.testing.expect(set.isEmpty());
}

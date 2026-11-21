//! HTTP/1.1 byte-stream adapter for RFC 9298 CONNECT-UDP capsules.
//!
//! HTTP/1.1 switches the entire connection with `Upgrade: connect-udp`.
//! The shared capsule session expects the framed HTTP/2 tunnel surface, so
//! this module supplies the small ownership-preserving adapter: stream ID 0,
//! bounded allocated reads, exact timed-write progress, and connection abort
//! in place of a per-stream reset.

const std = @import("std");
const deadline_policy = @import("../../internal/deadline.zig");

pub const ResetCode = enum {
    protocol_error,
    enhance_your_calm,
};

pub const WriteProgress = struct {
    committed_bytes: usize = 0,
};

pub fn validateRequest(
    comptime Capsule: type,
    protocol: []const u8,
    expected_scheme: []const u8,
    request: anytype,
) error{InvalidResponse}!void {
    if (request.method != .GET or
        request.version != .http_1_1 or
        request.body_framing != .none or
        request.body.len != 0 or
        request.trailers.len != 0)
    {
        return error.InvalidResponse;
    }
    _ = try requestPath(request.target);
    if (try requestScheme(request.target)) |scheme| {
        if (!std.ascii.eqlIgnoreCase(scheme, expected_scheme)) {
            return error.InvalidResponse;
        }
    }
    var upgrade_count: usize = 0;
    for (request.headers) |header| {
        if (!header.eqlName("upgrade")) continue;
        upgrade_count += 1;
        if (!std.ascii.eqlIgnoreCase(
            std.mem.trim(u8, header.value, " \t"),
            protocol,
        )) {
            return error.InvalidResponse;
        }
    }
    if (upgrade_count != 1 or request.upgradeProtocol() == null) {
        return error.InvalidResponse;
    }
    if (!(Capsule.protocolEnabled(request.headers) catch
        return error.InvalidResponse))
    {
        return error.InvalidResponse;
    }
}

/// RFC 9298 examples use absolute-form request targets while direct HTTP/1.1
/// peers commonly send origin-form. The HTTP parser has already validated the
/// absolute URI and matched its authority to Host; retain only path/query for
/// URI-template routing.
pub fn requestPath(target: []const u8) error{InvalidResponse}![]const u8 {
    if (target.len == 0) return error.InvalidResponse;
    if (target[0] == '/') return target;
    const scheme = (try requestScheme(target)) orelse
        return error.InvalidResponse;
    const scheme_end = scheme.len;
    const authority_start = scheme_end + 3;
    const path_start = std.mem.indexOfScalarPos(
        u8,
        target,
        authority_start,
        '/',
    ) orelse return error.InvalidResponse;
    if (path_start == authority_start) return error.InvalidResponse;
    return target[path_start..];
}

pub fn requestScheme(
    target: []const u8,
) error{InvalidResponse}!?[]const u8 {
    if (target.len == 0) return error.InvalidResponse;
    if (target[0] == '/') return null;
    const scheme_end = std.mem.indexOf(u8, target, "://") orelse
        return error.InvalidResponse;
    if (scheme_end == 0) return error.InvalidResponse;
    return target[0..scheme_end];
}

pub fn TunnelAdapter(comptime Tunnel: type) type {
    return struct {
        pub const read_chunk_bytes: usize = 16 * 1024;

        allocator: std.mem.Allocator,
        inner: Tunnel,
        stream_id: u31 = 0,
        read_buffer: std.ArrayList(u8) = .empty,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            tunnel: Tunnel,
        ) Self {
            return .{ .allocator = allocator, .inner = tunnel };
        }

        pub fn deinit(self: *Self) void {
            self.read_buffer.deinit(self.allocator);
        }

        pub fn writeSlices(
            self: *Self,
            slices: []const []const u8,
            end_stream: bool,
        ) !void {
            std.debug.assert(!end_stream);
            try self.inner.writeSlices(slices);
        }

        pub fn writeSlicesWithDeadline(
            self: *Self,
            slices: []const []const u8,
            end_stream: bool,
            progress: *WriteProgress,
            deadline: std.Io.Clock.Timestamp,
        ) !void {
            std.debug.assert(!end_stream);
            try self.inner.writeSlicesWithDeadline(
                slices,
                progress,
                deadline,
            );
        }

        /// Relative-timeout counterpart to `writeSlicesWithDeadline`. A
        /// non-positive duration clears `progress` and returns `Timeout`
        /// before any slice is submitted.
        pub fn writeSlicesWithTimeout(
            self: *Self,
            slices: []const []const u8,
            end_stream: bool,
            progress: *WriteProgress,
            timeout: std.Io.Duration,
        ) !void {
            std.debug.assert(!end_stream);
            try self.inner.writeSlicesWithTimeout(
                slices,
                progress,
                timeout,
            );
        }

        pub fn closeWrite(self: *Self) !void {
            try self.inner.closeWrite();
        }

        pub fn read(self: *Self) !OwnedData {
            return self.readUntil(null);
        }

        pub fn readWithDeadline(
            self: *Self,
            deadline: std.Io.Clock.Timestamp,
        ) !OwnedData {
            return self.readUntil(deadline);
        }

        /// Relative-timeout counterpart to `readWithDeadline`. A non-positive
        /// duration returns `Timeout` before any transport read.
        pub fn readWithTimeout(
            self: *Self,
            timeout: std.Io.Duration,
        ) !OwnedData {
            return self.readUntil(
                (try deadline_policy.fromTimeout(self.inner.io, timeout)).?,
            );
        }

        pub fn reset(self: *Self, _: ResetCode) !void {
            // HTTP/1.1 has no stream reset after Upgrade: the whole
            // connection is the CONNECT-UDP stream.
            self.inner.abort();
        }

        fn readUntil(
            self: *Self,
            deadline: ?std.Io.Clock.Timestamp,
        ) !OwnedData {
            try self.read_buffer.ensureTotalCapacity(
                self.allocator,
                read_chunk_bytes,
            );
            self.read_buffer.items.len = read_chunk_bytes;
            errdefer {
                self.read_buffer.items.len = 0;
            }
            const count = if (deadline) |absolute|
                self.inner.readWithDeadline(
                    self.read_buffer.items,
                    absolute,
                ) catch |err|
                    switch (err) {
                        error.ConnectionClosed => 0,
                        else => |other| return other,
                    }
            else
                self.inner.read(self.read_buffer.items) catch |err| switch (err) {
                    error.ConnectionClosed => 0,
                    else => |other| return other,
                };
            self.read_buffer.items.len = count;
            return .{
                .data = self.read_buffer.items,
                .end_stream = count == 0,
            };
        }
    };
}

pub const OwnedData = struct {
    data: []const u8,
    end_stream: bool,

    pub fn deinit(self: *OwnedData, _: std.mem.Allocator) void {
        self.* = undefined;
    }
};

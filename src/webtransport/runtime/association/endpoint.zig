//! Shared-endpoint ownership and timer integration for early streams.

const std = @import("std");
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const early_streams = @import("early_streams.zig");

pub fn For(comptime Server: type) type {
    return struct {
        const Error = early_streams.Error || http3.runtime.Error || http3.runtime.HandshakeAdmissionError;

        fn state(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle) Error!*early_streams.State {
            const slot = try server.early.getOrPut(server.allocator, handle);
            if (!slot.found_existing) slot.value_ptr.* = .{ .limits = server.limits.early_connect_streams };
            return slot.value_ptr;
        }

        fn active(context: *const anyopaque, scope: u64, session_id: u62) bool {
            const server: *const Server = @ptrCast(@alignCast(context));
            const accepted = server.sessions.get(.{ .handle = @intCast(scope), .session_id = .init(session_id) }) orelse return false;
            return !accepted.control.state.closed and !accepted.control.terminal_reported;
        }

        fn owns(context: *const anyopaque, scope: u64, stream_id: u62) bool {
            const server: *const Server = @ptrCast(@alignCast(context));
            var iterator = server.sessions.iterator();
            while (iterator.next()) |entry| {
                if (entry.key_ptr.handle == scope and entry.value_ptr.*.streams.get(stream_id) != null) return true;
            }
            return false;
        }

        pub fn maintain(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle, h3: *http3.runtime.HandshakeServerSession) Error!bool {
            const owner = server.early.getPtr(handle) orelse try state(server, handle);
            const progressed = owner.poll(server.allocator, &h3.established.connection, .{ .sessions = .{ .context = server, .scope = @intCast(handle), .containsFn = active }, .ownsStreamFn = owns }) catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => false,
                else => return err,
            };
            try server.h3.dispatcher.refreshConnectionTimer(handle);
            return progressed;
        }

        pub fn maintainAll(server: *Server) Error!void {
            var iterator = server.early.iterator();
            while (iterator.next()) |entry| {
                const h3 = server.h3.session(entry.key_ptr.*) orelse continue;
                _ = try maintain(server, entry.key_ptr.*, h3);
            }
        }

        pub fn reject(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle, h3: *http3.runtime.HandshakeServerSession, session_id: u62) Error!void {
            const owner = try state(server, handle);
            try owner.rejectSession(server.allocator, &h3.established.connection, session_id);
        }

        pub fn boundedDeadline(server: *const Server, deadline: std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
            var result = deadline;
            var iterator = server.early.valueIterator();
            while (iterator.next()) |owner| {
                if (owner.nextExpiry()) |expiry| {
                    if (expiry < result.raw.nanoseconds) result = .{ .clock = .awake, .raw = .fromNanoseconds(expiry) };
                }
            }
            return result;
        }
    };
}

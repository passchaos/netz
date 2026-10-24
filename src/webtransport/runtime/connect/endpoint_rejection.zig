//! Retained CONNECT cancellation belongs to connection work, including peers
//! that have no accepted Session. Retry it before waiting for more UDP traffic.
const http3 = @import("../../../http3/mod.zig");
const quic = @import("../../../quic/mod.zig");
const webtransport = @import("../../mod.zig");
const rejection = @import("rejection.zig");
const connection_lifecycle = @import("../connection_lifecycle.zig");

pub fn For(comptime Server: type, comptime rejectEarly: anytype) type {
    return struct {
        const Error = webtransport.runtime.EndpointServerError;

        /// Reserve before consuming a request head. Every subsequent refusal
        /// can retain its owner and keep this connection eligible for polling.
        pub fn reserve(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle) Error!void {
            try server.request_rejection_pending.ensureUnusedCapacity(server.allocator, 1);
            if (!server.idle_connections.contains(handle)) {
                try server.idle_connections.ensureUnusedCapacity(server.allocator, 1);
            }
        }

        pub fn retain(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle, pending: rejection.Pending) void {
            server.request_rejection_pending.putAssumeCapacity(handle, pending);
            if (!server.idle_connections.contains(handle) and server.sessionCountForConnection(handle) == 0) server.idle_connections.putAssumeCapacity(handle, {});
        }

        fn submit(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle, h3: *http3.runtime.HandshakeServerSession, pending: rejection.Pending) Error!void {
            try rejectEarly(server, handle, h3, pending.stream_id);
            try pending.submit(h3);
        }

        /// One cancellation attempt per connection. Backpressure leaves the
        /// owner in place; completed cancellation reports its original cause.
        pub fn retryOne(server: *Server, handle: quic.endpoint_dispatcher.ConnectionHandle, h3: *http3.runtime.HandshakeServerSession) Error!bool {
            const pending = server.request_rejection_pending.get(handle) orelse return true;
            if (connection_lifecycle.terminating(&h3.established.connection)) {
                _ = server.request_rejection_pending.remove(handle);
                return true;
            }
            const result = submit(server, handle, h3, pending);
            // Early-stream resets and CONNECT cancellation can both change
            // recovery/pacing even when a later socket submission fails.
            try server.h3.dispatcher.refreshConnectionTimer(handle);
            result catch |err| switch (err) {
                error.PacingLimited, error.CongestionLimited, error.FlowControlBlocked => return false,
                else => return err,
            };
            _ = server.request_rejection_pending.remove(handle);
            if (pending.failure) |failure| return failure.cause();
            return true;
        }

        pub fn retryBuffered(server: *Server) Error!void {
            if (server.request_rejection_pending.count() == 0) return;
            // retryOne only removes entries from this map; early-stream state
            // lives elsewhere, so this iterator cannot be invalidated by growth.
            var pending = server.request_rejection_pending.keyIterator();
            while (pending.next()) |entry| {
                const handle = entry.*;
                const h3 = server.h3.session(handle) orelse return error.InvalidSessionState;
                _ = try retryOne(server, handle, h3);
            }
        }
    };
}

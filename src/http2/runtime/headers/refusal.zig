//! Refused streams still decode HPACK but never gain message ownership.
const std = @import("std");
const http2 = @import("../../mod.zig");

pub fn Reader(comptime hooks: anytype) type {
    return struct {
        /// A complete output-limit rejection has already applied all HPACK
        /// changes. Field validation failures are stream-local; incomplete
        /// assembly, compression, and allocation failures remain fatal.
        pub fn read(self: anytype, first: http2.Frame, deadline: ?std.Io.Clock.Timestamp) hooks.Error!http2.ErrorCode {
            const previous_stream_error = self.serve_read_stream_error;
            const headers = hooks.readHeaders(self, first, deadline) catch |err| {
                if (err == error.MessageTooLarge and
                    !self.aggregate_timeout_unusable and
                    self.serve_read_connection_error == null and
                    !self.hpack_decoder.lastDecodeWasCompressionError())
                {
                    self.serve_read_stream_error = previous_stream_error;
                    return .refused_stream;
                }
                self.aggregate_timeout_unusable = true;
                return err;
            };
            defer hooks.freeHeaders(self.allocator, headers);
            hooks.validate(headers, .request) catch return .protocol_error;
            _ = hooks.lookup(headers) catch return .protocol_error;
            return .refused_stream;
        }
    };
}

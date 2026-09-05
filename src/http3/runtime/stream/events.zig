const std = @import("std");
const reader = @import("reader.zig");

const net = std.Io.net;

/// One event from the server-side request-stream poller.
///
/// Request streams are multiplexed, so every event carries its peer and stream
/// identity. A reset is data rather than an unqualified error: otherwise an
/// application polling several streams could not determine which request was
/// cancelled.
pub const Request = union(enum) {
    message: Message,
    reset: Reset,

    pub const Message = struct {
        from: net.IpAddress,
        stream_id: u62,
        value: reader.Event,
    };

    pub const Reset = struct {
        from: net.IpAddress,
        stream_id: u62,
        application_error_code: u64,
    };

    pub fn deinit(self: *Request, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .message => |*message| message.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

/// One event from the client-side response-stream poller.
///
/// Applications can drive all outstanding requests from one loop, then pass
/// the reported stream ID to a body-reader API when DATA is available.
pub const Response = union(enum) {
    message: Message,
    reset: Reset,

    pub const Message = struct {
        stream_id: u62,
        value: reader.Event,
    };

    pub const Reset = struct {
        stream_id: u62,
        application_error_code: u64,
    };

    pub fn deinit(self: *Response, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .message => |*message| message.value.deinit(allocator),
            .reset => {},
        }
        self.* = undefined;
    }
};

/// A peer request-stream receiver abandoned the response direction.
pub const PeerResponseCancellation = struct {
    stream_id: u62,
    application_error_code: u64,
};

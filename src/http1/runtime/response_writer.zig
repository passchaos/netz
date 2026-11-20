//! Incremental HTTP/1 response output.
const std = @import("std");
const runtime = @import("../runtime.zig");
const http1 = @import("../mod.zig");
const Error = runtime.Error;
const StreamingBodyWriter = runtime.StreamingBodyWriter;

pub const ResponseWriter = struct {
    body: StreamingBodyWriter,

    pub fn deinit(self: *ResponseWriter) void {
        self.body.deinit();
    }

    pub fn write(
        self: *ResponseWriter,
        data: []const u8,
    ) Error!void {
        try self.body.write(data);
    }

    pub fn writeChunks(
        self: *ResponseWriter,
        chunks: []const []const u8,
    ) Error!void {
        try self.body.writeChunks(chunks);
    }

    pub fn writeWithDeadline(self: *ResponseWriter, data: []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.writeWithDeadline(data, deadline);
    }

    pub fn writeWithTimeout(self: *ResponseWriter, data: []const u8, timeout: std.Io.Duration) Error!void {
        return self.body.writeWithTimeout(data, timeout);
    }

    pub fn writeChunksWithDeadline(self: *ResponseWriter, chunks: []const []const u8, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.writeChunksWithDeadline(chunks, deadline);
    }

    pub fn writeChunksWithTimeout(self: *ResponseWriter, chunks: []const []const u8, timeout: std.Io.Duration) Error!void {
        return self.body.writeChunksWithTimeout(chunks, timeout);
    }

    pub fn finishTrailersWithDeadline(self: *ResponseWriter, trailers: []const http1.Header, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.finishTrailersWithDeadline(trailers, deadline);
    }

    pub fn finishTrailersWithTimeout(self: *ResponseWriter, trailers: []const http1.Header, timeout: std.Io.Duration) Error!void {
        return self.body.finishTrailersWithTimeout(trailers, timeout);
    }

    pub fn finishWithDeadline(self: *ResponseWriter, deadline: std.Io.Clock.Timestamp) Error!void {
        return self.body.finishWithDeadline(deadline);
    }

    pub fn finishWithTimeout(self: *ResponseWriter, timeout: std.Io.Duration) Error!void {
        return self.body.finishWithTimeout(timeout);
    }

    pub fn committedBytes(self: ResponseWriter) usize {
        return self.body.committedBytes();
    }

    pub fn finish(self: *ResponseWriter) Error!void {
        try self.body.finish();
    }

    pub fn finishTrailers(
        self: *ResponseWriter,
        trailers: []const http1.Header,
    ) Error!void {
        try self.body.finishTrailers(trailers);
    }
};

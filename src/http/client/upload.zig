//! Unified incremental upload operations and per-call acceptance progress.
const std = @import("std");
const duplex = @import("duplex.zig");
const Handle = duplex.Handle;
const Http3 = Handle.Http3;
const Header = duplex.Header;
const http1 = @import("../../http1/mod.zig");
const http2 = @import("../../http2/mod.zig");
const http3 = @import("../../http3/mod.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub const Progress = struct {
    /// Application bytes accepted by this call's protocol writer. Pooled H3
    /// reports acceptance into its bounded owner queue, rather than delivery.
    accepted_bytes: usize = 0,
    /// True when this call accepted the request's message end.
    end_accepted: bool = false,
};

pub fn io(self: *const Handle) std.Io {
    return switch (self.state) {
        .http1 => |writer| writer.client.io,
        .http2 => |writer| writer.connection.io,
        .http3 => |h3| h3.client.connectionIo(),
    };
}

pub fn writeBody(self: *Handle, bytes: []const u8) !void {
    try self.reader_upload.ensureDrained();
    return writeBodyBefore(self, bytes, null, null);
}

pub fn writeBodyWithDeadline(self: *Handle, bytes: []const u8, progress: *Progress, deadline: std.Io.Clock.Timestamp) !void {
    progress.* = .{};
    _ = try deadline_policy.usableAwake(io(self), deadline);
    try self.reader_upload.ensureDrained();
    return writeBodyBefore(self, bytes, progress, deadline);
}

pub fn writeBodyWithTimeout(self: *Handle, bytes: []const u8, progress: *Progress, timeout: std.Io.Duration) !void {
    progress.* = .{};
    return writeBodyWithDeadline(self, bytes, progress, (try deadline_policy.fromTimeout(io(self), timeout)).?);
}

fn ensureOpen(self: *const Handle) !void {
    if (self.response_available) return error.ResponseAvailable;
    if (self.body_finished or self.response_complete) return error.RequestBodyFinished;
}

fn writeBodyBefore(self: *Handle, bytes: []const u8, progress: ?*Progress, deadline: ?std.Io.Clock.Timestamp) !void {
    try ensureOpen(self);
    switch (self.state) {
        .http1 => |*writer| {
            if (self.h1_continue_pending) {
                const continued = if (deadline) |absolute| try writer.waitForContinueWithDeadline(absolute) else try writer.waitForContinue();
                self.h1_continue_pending = false;
                switch (continued) {
                    .proceed => {},
                    .final_response => |response| {
                        self.h1_buffered_response = response;
                        self.response_available = true;
                        return error.ResponseAvailable;
                    },
                }
            }
            const before = writer.committedBytes();
            defer if (progress) |value| {
                value.accepted_bytes = writer.committedBytes() - before;
            };
            if (deadline) |absolute| try writer.writeWithDeadline(bytes, absolute) else try writer.write(bytes);
        },
        .http2 => |*writer| {
            const before = writer.committedBytes();
            defer if (progress) |value| {
                value.accepted_bytes = writer.committedBytes() - before;
            };
            const result = if (deadline) |absolute| writer.writeWithDeadline(bytes, absolute) else writer.write(bytes);
            result catch |err| switch (err) {
                error.ResponseAvailable => {
                    self.response_available = true;
                    self.body_finished = true;
                    return error.ResponseAvailable;
                },
                else => return err,
            };
        },
        .http3 => |*h3| {
            var accepted: @import("../../http3/runtime.zig").BodyWriteProgress = .{};
            defer if (progress) |value| {
                value.accepted_bytes = accepted.committed_bytes;
            };
            const result = if (deadline) |absolute|
                h3.client.sendRequestBodyPacedWithDeadline(h3.stream_id, bytes, false, &accepted, absolute)
            else
                h3.client.sendRequestBodyPacedTracked(h3.stream_id, bytes, false, &accepted);
            result catch |err| switch (err) {
                error.RequestCancelled, error.RequestRejected => {
                    if (try stashHttp3Head(self, h3)) {
                        self.response_available = true;
                        return error.ResponseAvailable;
                    }
                    return err;
                },
                else => return err,
            };
        },
    }
}

/// Pump a single-pass Reader; the source must cooperate with cancellation.
pub fn writeBodyFromReader(self: *Handle, reader: *std.Io.Reader) !void {
    var progress: Progress = .{};
    return writeBodyFromReaderBefore(self, reader, &progress, null);
}

pub fn writeBodyFromReaderWithDeadline(self: *Handle, reader: *std.Io.Reader, progress: *Progress, deadline: std.Io.Clock.Timestamp) !void {
    progress.* = .{};
    _ = try deadline_policy.usableAwake(io(self), deadline);
    return writeBodyFromReaderBefore(self, reader, progress, deadline);
}

pub fn writeBodyFromReaderWithTimeout(self: *Handle, reader: *std.Io.Reader, progress: *Progress, timeout: std.Io.Duration) !void {
    progress.* = .{};
    return writeBodyFromReaderWithDeadline(self, reader, progress, (try deadline_policy.fromTimeout(io(self), timeout)).?);
}

fn writeBodyFromReaderBefore(self: *Handle, reader: *std.Io.Reader, progress: *Progress, deadline: ?std.Io.Clock.Timestamp) !void {
    try ensureOpen(self);
    return self.reader_upload.run(self.allocator, io(self), reader, self, writeBodyBefore, progress, deadline);
}

pub fn finishBody(self: *Handle) !void {
    return finishBodyBefore(self, null, null);
}

pub fn finishBodyWithDeadline(self: *Handle, progress: *Progress, deadline: std.Io.Clock.Timestamp) !void {
    progress.* = .{};
    _ = try deadline_policy.usableAwake(io(self), deadline);
    return finishBodyBefore(self, progress, deadline);
}

pub fn finishBodyWithTimeout(self: *Handle, progress: *Progress, timeout: std.Io.Duration) !void {
    progress.* = .{};
    return finishBodyWithDeadline(self, progress, (try deadline_policy.fromTimeout(io(self), timeout)).?);
}

fn finishBodyBefore(self: *Handle, progress: ?*Progress, deadline: ?std.Io.Clock.Timestamp) !void {
    try ensureOpen(self);
    try self.reader_upload.ensureDrained();
    switch (self.state) {
        .http1 => |*writer| if (deadline) |absolute| try writer.finishWithDeadline(absolute) else try writer.finish(),
        .http2 => |*writer| {
            const result = if (deadline) |absolute| writer.finishWithDeadline(absolute) else writer.finish();
            result catch |err| switch (err) {
                error.ResponseAvailable => {
                    self.response_available = true;
                    self.body_finished = true;
                    return;
                },
                else => return err,
            };
        },
        .http3 => |*h3| {
            var accepted: @import("../../http3/runtime.zig").BodyWriteProgress = .{};
            defer if (progress) |value| {
                value.accepted_bytes = accepted.committed_bytes;
                value.end_accepted = accepted.fin_committed;
                if (accepted.fin_committed) self.body_finished = true;
            };
            const result = if (deadline) |absolute|
                h3.client.sendRequestBodyPacedWithDeadline(h3.stream_id, &.{}, true, &accepted, absolute)
            else
                h3.client.sendRequestBodyPaced(h3.stream_id, &.{}, true);
            result catch |err| switch (err) {
                error.RequestCancelled, error.RequestRejected => {
                    if (try stashHttp3Head(self, h3)) {
                        self.response_available = true;
                        self.body_finished = true;
                        return;
                    }
                    return err;
                },
                else => return err,
            };
        },
    }
    self.body_finished = true;
    if (progress) |value| value.end_accepted = true;
}

pub fn finishTrailers(self: *Handle, trailers: []const Header) !void {
    return finishTrailersBefore(self, trailers, null, null);
}

pub fn finishTrailersWithDeadline(self: *Handle, trailers: []const Header, progress: *Progress, deadline: std.Io.Clock.Timestamp) !void {
    progress.* = .{};
    _ = try deadline_policy.usableAwake(io(self), deadline);
    return finishTrailersBefore(self, trailers, progress, deadline);
}

pub fn finishTrailersWithTimeout(self: *Handle, trailers: []const Header, progress: *Progress, timeout: std.Io.Duration) !void {
    progress.* = .{};
    return finishTrailersWithDeadline(self, trailers, progress, (try deadline_policy.fromTimeout(io(self), timeout)).?);
}

fn finishTrailersBefore(self: *Handle, trailers: []const Header, progress: ?*Progress, deadline: ?std.Io.Clock.Timestamp) !void {
    try ensureOpen(self);
    try self.reader_upload.ensureDrained();
    switch (self.state) {
        .http1 => |*writer| {
            const mapped = try mapToHttp1(self.allocator, trailers);
            defer self.allocator.free(mapped);
            if (deadline) |absolute| try writer.finishTrailersWithDeadline(mapped, absolute) else try writer.finishTrailers(mapped);
        },
        .http2 => |*writer| {
            const mapped = try mapToHttp2(self.allocator, trailers);
            defer self.allocator.free(mapped);
            const result = if (deadline) |absolute| writer.finishTrailersWithDeadline(mapped, absolute) else writer.finishTrailers(mapped);
            result catch |err| switch (err) {
                error.ResponseAvailable => {
                    self.response_available = true;
                    self.body_finished = true;
                    return;
                },
                else => return err,
            };
        },
        .http3 => |*h3| {
            const mapped = try mapToHttp3(self.allocator, trailers);
            defer self.allocator.free(mapped);
            const result = if (deadline) |absolute| h3.client.finishRequestTrailersPacedWithDeadline(h3.stream_id, mapped, absolute) else h3.client.finishRequestTrailersPaced(h3.stream_id, mapped);
            result catch |err| switch (err) {
                error.RequestCancelled, error.RequestRejected => {
                    if (try stashHttp3Head(self, h3)) {
                        self.response_available = true;
                        self.body_finished = true;
                        return;
                    }
                    return err;
                },
                else => return err,
            };
        },
    }
    self.body_finished = true;
    if (progress) |value| value.end_accepted = true;
}

/// Move an already buffered final response head out of the H3 event
/// queue. Used when a request-body write observes an early rejection and
/// the caller should read the response instead of sending more body.
fn stashHttp3Head(self: *Handle, h3: *const Http3) !bool {
    return retainResponseHeads(self, h3.client, h3.stream_id);
}

fn retainResponseHeads(self: *Handle, client: anytype, stream_id: u62) !bool {
    if (self.h3_pending_event != null) return true;
    while (try client.pollResponseEvent(stream_id)) |event| {
        switch (event) {
            .head => |head| switch (head) {
                .request => {
                    var invalid = event;
                    invalid.deinit(self.allocator);
                    return error.InvalidResponse;
                },
                .response => |response| {
                    if (response.status >= 200) {
                        self.h3_pending_event = event;
                        return true;
                    }
                    self.h3_pending_interims.append(self.allocator, event) catch |err| {
                        self.h3_pending_event = event;
                        return err;
                    };
                },
            },
            .data_available, .trailers, .finished, .push_promise => {
                var ignored = event;
                ignored.deinit(self.allocator);
            },
        }
    }
    return false;
}

fn mapToHttp1(
    allocator: std.mem.Allocator,
    headers: []const Header,
) ![]http1.Header {
    const result = try allocator.alloc(http1.Header, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value };
    }
    return result;
}

fn mapToHttp2(
    allocator: std.mem.Allocator,
    headers: []const Header,
) ![]http2.Hpack.HeaderField {
    const result = try allocator.alloc(http2.Hpack.HeaderField, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value, .never_index = source.never_indexed };
    }
    return result;
}

fn mapToHttp3(
    allocator: std.mem.Allocator,
    headers: []const Header,
) ![]http3.Qpack.HeaderField {
    const result = try allocator.alloc(http3.Qpack.HeaderField, headers.len);
    for (headers, result) |source, *target| {
        target.* = .{ .name = source.name, .value = source.value, .never_indexed = source.never_indexed };
    }
    return result;
}

test "unified HTTP streaming deadlines retain H3 interim heads before an early final response" {
    const Event = @import("../../http3/runtime.zig").StreamingEvent;
    const Mock = struct {
        events: [3]Event,
        next: usize = 0,
        fn pollResponseEvent(self: *@This(), _: u62) !?Event {
            if (self.next == self.events.len) return null;
            defer self.next += 1;
            return self.events[self.next];
        }
        fn head(status: u16) Event {
            return .{ .head = .{ .response = .{ .status = status, .headers = &.{}, .content_length = null, .body_allowed = status >= 200, .consumed = 0, .qpack_section_acknowledgments = 0 } } };
        }
    };
    var mock = Mock{ .events = .{ Mock.head(100), Mock.head(103), Mock.head(413) } };
    var handle = Handle{ .allocator = std.testing.allocator, .protocol = .http3, .state = .{ .http3 = .{ .client = undefined, .stream_id = 0 } } };
    defer handle.h3_pending_interims.deinit(handle.allocator);
    defer if (handle.h3_pending_event) |*event| event.deinit(handle.allocator);
    try std.testing.expect(try retainResponseHeads(&handle, &mock, 0));
    var first = handle.h3_pending_interims.popFront().?;
    defer first.deinit(handle.allocator);
    var second = handle.h3_pending_interims.popFront().?;
    defer second.deinit(handle.allocator);
    try std.testing.expectEqual(@as(u16, 100), first.head.response.status);
    try std.testing.expectEqual(@as(u16, 103), second.head.response.status);
    try std.testing.expectEqual(@as(u16, 413), handle.h3_pending_event.?.head.response.status);
}

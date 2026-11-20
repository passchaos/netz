//! A pooled streaming request owns a TCP lease or one H3 dispatcher command.
const std = @import("std");
const client = @import("../client.zig");
const Lease = @import("../client_pool.zig").Lease;
const h3_support = @import("http3.zig");
const http3 = @import("../../http3/mod.zig");
const http3_runtime = @import("../../http3/runtime.zig");
const header_mapping = @import("../client/header_mapping.zig");
const deadline_policy = @import("../../internal/deadline.zig");

pub const StreamHandle = struct {
    kind: Kind,

    const Kind = union(enum) {
        tcp: Tcp,
        http3: Http3,
    };

    const Tcp = struct {
        allocator: std.mem.Allocator,
        lease: *Lease,
        handle: client.RequestHandle,
    };

    const Http3 = struct {
        allocator: std.mem.Allocator,
        handle: h3_support.StreamHandle,
        body_finished: bool = false,
        head: ?OwnedHead = null,
    };

    const OwnedHead = struct {
        headers: []client.DuplexHeader,
        storage: []u8,

        fn deinit(self: *OwnedHead, allocator: std.mem.Allocator) void {
            allocator.free(self.headers);
            allocator.free(self.storage);
            self.* = undefined;
        }
    };

    fn uploadIo(self: *const StreamHandle) std.Io {
        return switch (self.kind) {
            .tcp => |tcp| tcp.lease.pool.io,
            .http3 => |h3| h3.handle.io(),
        };
    }

    pub fn writeBody(self: *StreamHandle, bytes: []const u8) !void {
        switch (self.kind) {
            .tcp => |*tcp| try tcp.handle.writeBody(bytes),
            .http3 => |*h3| {
                if (h3.body_finished) return error.RequestBodyFinished;
                try h3.handle.writeBodyBlocking(bytes, false, null);
            },
        }
    }

    pub fn writeBodyWithDeadline(self: *StreamHandle, bytes: []const u8, progress: *client.UploadProgress, deadline: std.Io.Clock.Timestamp) !void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.uploadIo(), deadline);
        switch (self.kind) {
            .tcp => |*tcp| try tcp.handle.writeBodyWithDeadline(bytes, progress, deadline),
            .http3 => |*h3| {
                if (h3.body_finished) return error.RequestBodyFinished;
                try h3.handle.writeBodyBlockingTracked(bytes, false, &progress.accepted_bytes, deadline);
            },
        }
    }

    pub fn writeBodyWithTimeout(self: *StreamHandle, bytes: []const u8, progress: *client.UploadProgress, timeout: std.Io.Duration) !void {
        progress.* = .{};
        return self.writeBodyWithDeadline(bytes, progress, (try deadline_policy.fromTimeout(self.uploadIo(), timeout)).?);
    }

    pub fn writeBodyFromReader(self: *StreamHandle, reader: *std.Io.Reader) !void {
        var buffer: [16 * 1024]u8 = undefined;
        while (true) {
            const count = try reader.readSliceShort(&buffer);
            if (count == 0) break;
            try self.writeBody(buffer[0..count]);
        }
    }

    pub fn finishBody(self: *StreamHandle) !void {
        switch (self.kind) {
            .tcp => |*tcp| try tcp.handle.finishBody(),
            .http3 => |*h3| {
                if (h3.body_finished) return error.RequestBodyFinished;
                try h3.handle.writeBodyBlocking(&.{}, true, null);
                h3.body_finished = true;
            },
        }
    }

    pub fn finishBodyWithDeadline(self: *StreamHandle, progress: *client.UploadProgress, deadline: std.Io.Clock.Timestamp) !void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.uploadIo(), deadline);
        switch (self.kind) {
            .tcp => |*tcp| try tcp.handle.finishBodyWithDeadline(progress, deadline),
            .http3 => |*h3| {
                if (h3.body_finished) return error.RequestBodyFinished;
                try h3.handle.writeBodyBlockingTracked(&.{}, true, &progress.accepted_bytes, deadline);
                h3.body_finished = true;
                progress.end_accepted = true;
            },
        }
    }

    pub fn finishBodyWithTimeout(self: *StreamHandle, progress: *client.UploadProgress, timeout: std.Io.Duration) !void {
        progress.* = .{};
        return self.finishBodyWithDeadline(progress, (try deadline_policy.fromTimeout(self.uploadIo(), timeout)).?);
    }

    pub fn finishTrailers(self: *StreamHandle, trailers: []const client.DuplexHeader) !void {
        var progress: client.UploadProgress = .{};
        return self.finishTrailersBefore(trailers, &progress, null);
    }

    pub fn finishTrailersWithDeadline(self: *StreamHandle, trailers: []const client.DuplexHeader, progress: *client.UploadProgress, deadline: std.Io.Clock.Timestamp) !void {
        progress.* = .{};
        _ = try deadline_policy.usableAwake(self.uploadIo(), deadline);
        return self.finishTrailersBefore(trailers, progress, deadline);
    }

    pub fn finishTrailersWithTimeout(self: *StreamHandle, trailers: []const client.DuplexHeader, progress: *client.UploadProgress, timeout: std.Io.Duration) !void {
        progress.* = .{};
        return self.finishTrailersWithDeadline(trailers, progress, (try deadline_policy.fromTimeout(self.uploadIo(), timeout)).?);
    }

    fn finishTrailersBefore(self: *StreamHandle, trailers: []const client.DuplexHeader, progress: *client.UploadProgress, deadline: ?std.Io.Clock.Timestamp) !void {
        switch (self.kind) {
            .tcp => |*tcp| {
                if (deadline) |absolute| try tcp.handle.finishTrailersWithDeadline(trailers, progress, absolute) else {
                    try tcp.handle.finishTrailers(trailers);
                    progress.end_accepted = true;
                }
            },
            .http3 => |*h3| {
                if (h3.body_finished) return error.RequestBodyFinished;
                var stack: [header_mapping.max_stack_trailers]http3.Qpack.HeaderField = undefined;
                var mapped = try header_mapping.mapHttp3(h3.allocator, trailers, &stack);
                defer mapped.deinit(h3.allocator);
                if (deadline) |absolute| try h3.handle.writeTrailersWithDeadline(mapped.items, absolute) else try h3.handle.writeTrailers(mapped.items);
                h3.body_finished = true;
                progress.end_accepted = true;
            },
        }
    }

    pub fn readResponse(
        self: *StreamHandle,
        sink: client.ResponseSink,
    ) !client.ResponseHead {
        switch (self.kind) {
            .tcp => |*tcp| return tcp.handle.readResponse(sink),
            .http3 => |*h3| return readHttp3Response(h3, sink, null),
        }
    }

    pub fn readResponseWithDeadline(
        self: *StreamHandle,
        sink: client.ResponseSink,
        deadline: std.Io.Clock.Timestamp,
    ) !client.ResponseHead {
        switch (self.kind) {
            .tcp => |*tcp| return tcp.handle.readResponseWithDeadline(
                sink,
                deadline,
            ),
            .http3 => |*h3| return readHttp3Response(h3, sink, deadline),
        }
    }

    pub fn protocol(self: *const StreamHandle) client.Protocol {
        return switch (self.kind) {
            .tcp => |tcp| tcp.lease.protocol(),
            .http3 => .http3,
        };
    }

    /// Close the connection instead of returning it to the idle pool.
    pub fn discard(self: *StreamHandle) void {
        self.deinit();
    }

    pub fn deinit(self: *StreamHandle) void {
        switch (self.kind) {
            .tcp => |*tcp| {
                tcp.handle.deinit();
                tcp.lease.release();
                tcp.allocator.destroy(tcp.lease);
            },
            .http3 => |*h3| {
                h3.handle.deinit();
                if (h3.head) |*head| head.deinit(h3.allocator);
            },
        }
        self.* = undefined;
    }

    fn readHttp3Response(
        h3: *Http3,
        sink: client.ResponseSink,
        deadline: ?std.Io.Clock.Timestamp,
    ) !client.ResponseHead {
        var adapter = H3Adapter{ .http3 = h3, .response_sink = sink };
        const head = try h3.handle.readResponse(
            adapter.callbackSink(),
            deadline,
        );
        return .{
            .protocol = .http3,
            .status = head.status,
            .headers = if (h3.head) |owned| owned.headers else &.{},
        };
    }

    const H3Adapter = struct {
        http3: *Http3,
        response_sink: client.ResponseSink,

        fn callbackSink(self: *H3Adapter) http3_runtime.StreamCallbackSink {
            return .{
                .context = self,
                .begin = begin,
                .data = data,
                .end = end,
                .informational = if (self.response_sink.informational != null) informational else null,
            };
        }

        fn begin(
            context: *anyopaque,
            head: http3.DecodedResponseHead,
        ) !void {
            const self: *H3Adapter = @ptrCast(@alignCast(context));
            if (self.http3.head) |*old| old.deinit(self.http3.allocator);
            self.http3.head = null;
            var total: usize = 0;
            for (head.headers) |field| {
                total = try std.math.add(usize, total, field.name.len);
                total = try std.math.add(usize, total, field.value.len);
            }
            const storage = try self.http3.allocator.alloc(u8, total);
            errdefer self.http3.allocator.free(storage);
            const headers = try self.http3.allocator.alloc(
                client.DuplexHeader,
                head.headers.len,
            );
            errdefer self.http3.allocator.free(headers);
            var offset: usize = 0;
            for (head.headers, headers) |source, *target| {
                const name = storage[offset..][0..source.name.len];
                @memcpy(name, source.name);
                offset += source.name.len;
                const value = storage[offset..][0..source.value.len];
                @memcpy(value, source.value);
                offset += source.value.len;
                target.* = .{ .name = name, .value = value, .never_indexed = source.never_indexed };
            }
            self.http3.head = .{
                .headers = headers,
                .storage = storage,
            };
            try self.response_sink.begin(self.response_sink.context, .{
                .protocol = .http3,
                .status = head.status,
                .headers = headers,
            });
        }

        fn data(context: *anyopaque, bytes: []const u8) !void {
            const self: *H3Adapter = @ptrCast(@alignCast(context));
            try self.response_sink.data(self.response_sink.context, bytes);
        }

        fn informational(context: *anyopaque, head: http3.DecodedResponseHead) void {
            const self: *H3Adapter = @ptrCast(@alignCast(context));
            const observe = self.response_sink.informational orelse return;
            var stack: [header_mapping.max_stack_headers]client.Header = undefined;
            var mapped = header_mapping.fromHttp3(self.http3.allocator, head.headers, &stack) catch return;
            defer mapped.deinit(self.http3.allocator);
            observe(self.response_sink.context, .{ .protocol = .http3, .status = head.status, .headers = mapped.items });
        }

        fn end(
            context: *anyopaque,
            trailers: []const http3.Qpack.HeaderField,
        ) !void {
            const self: *H3Adapter = @ptrCast(@alignCast(context));
            var stack: [header_mapping.max_stack_trailers]client.Header = undefined;
            var mapped = try header_mapping.fromHttp3(self.http3.allocator, trailers, &stack);
            defer mapped.deinit(self.http3.allocator);
            try self.response_sink.end(
                self.response_sink.context,
                mapped.items,
            );
        }
    };
};

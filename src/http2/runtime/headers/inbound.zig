//! Inbound field-section assembly, deferred ownership and HPACK result mapping.
//! The connection retains its scratch, decoder and sole transport reader;
//! callbacks keep connection-private operations behind the existing owner.
const std = @import("std");
const http2 = @import("../../mod.zig");
const header_block_limits = @import("block_limits.zig");
const RetainedFrame = @import("../frame/io.zig").RetainedFrame;
const flag_end_headers: u8 = 0x4;

pub fn Reader(comptime hooks: anytype) type {
    return struct {
        pub fn read(
            self: anytype,
            first: http2.Frame,
            deadline: ?std.Io.Clock.Timestamp,
            raw_continuations: bool,
        ) hooks.Error![]http2.Hpack.HeaderField {
            if (try resumeDeferred(self, first, deadline, raw_continuations, false)) |headers| return headers;
            const block = try collect(
                self,
                first,
                deadline,
                raw_continuations,
            );
            if (block.limit_exceeded) {
                self.hpack_decoder.discardBlock(self.allocator, block.bytes) catch |err| {
                    if (self.hpack_decoder.lastDecodeWasCompressionError()) {
                        self.serve_read_connection_error = .compression;
                        self.aggregate_timeout_unusable = true;
                    }
                    return @errorCast(err);
                };
                hooks.recordStreamError(self, first.header.stream_id, .enhance_your_calm);
                return error.MessageTooLarge;
            }
            return self.hpack_decoder.decodeBlockOwnedWithLimit(
                self.allocator,
                block.bytes,
                self.limits.max_header_fields,
                self.limits.max_header_list_size,
            ) catch |err| {
                const compression_error =
                    self.hpack_decoder.lastDecodeWasCompressionError();
                self.serve_read_connection_error = if (compression_error)
                    .compression
                else
                    null;
                if (compression_error) self.aggregate_timeout_unusable = true;
                return switch (err) {
                    error.BufferTooShort,
                    error.HeaderListTooLarge,
                    => error.MessageTooLarge,
                    else => |other| other,
                };
            };
        }

        pub fn resumeDeferred(
            self: anytype,
            first: http2.Frame,
            deadline: ?std.Io.Clock.Timestamp,
            raw_continuations: bool,
            discard: bool,
        ) hooks.Error!?[]http2.Hpack.HeaderField {
            if (try hooks.takeDeferred(self, first, raw_continuations, discard)) |headers| return headers;
            if (!raw_continuations) {
                if (self.pending_duplex_sibling_header.getPtr()) |pending| {
                    if (pending.payload_key == @intFromPtr(first.payload.ptr)) {
                        for (0..pending.queued_continuation_count) |_| {
                            var continuation = (try hooks.popQueued(self)) orelse return error.UnexpectedFrame;
                            defer continuation.deinit(self.allocator);
                            if (continuation.frame.header.frame_type != .continuation or continuation.frame.header.stream_id != first.header.stream_id) return error.UnexpectedFrame;
                        }
                        pending.queued_continuation_count = 0;
                        self.push_ingress_headers_active = true;
                        defer self.push_ingress_headers_active = false;
                        const fields = if (discard)
                            try pending.header.discardUntil(self, deadline)
                        else
                            (try pending.header.resumeUntil(self, deadline)) orelse return error.UnexpectedFrame;
                        self.pending_duplex_sibling_header.deinit(self.allocator);
                        return fields;
                    }
                }
            }
            return null;
        }

        pub fn collect(
            self: anytype,
            first: http2.Frame,
            deadline: ?std.Io.Clock.Timestamp,
            raw_continuations: bool,
        ) hooks.Error!header_block_limits.Collected {
            const header_mode = self.push_ingress_headers_active;
            self.push_ingress_headers_active = true;
            defer self.push_ingress_headers_active = header_mode;
            if (first.header.frame_type != .headers) return error.UnexpectedFrame;
            const first_headers = try hooks.parseFirstHeaders(self, first);
            var flags = first.header.flags;
            var limit_exceeded = false;
            const header_block_limit = header_block_limits.byteLimit(self.limits.max_frame_payload, self.limits.max_header_fields);
            const block = if ((flags & flag_end_headers) != 0)
                first_headers.header_block
            else blk: {
                self.header_block_scratch.clearRetainingCapacity();
                try self.header_block_scratch.appendSlice(
                    self.allocator,
                    first_headers.header_block,
                );
                if (self.header_block_scratch.items.len > header_block_limit) {
                    self.serve_read_connection_error =
                        .excessive_header_block;
                    self.aggregate_timeout_unusable = true;
                    return error.MessageTooLarge;
                }
                var continuation_count: usize = 0;
                const max_continuations = hooks.maxContinuations(self.*);
                while ((flags & flag_end_headers) == 0) {
                    // Duplex/push owners already selected this block from the
                    // transport. Older queued sibling frames cannot precede its
                    // CONTINUATION, and the ordinary reader rejects duplex use.
                    var frame: RetainedFrame = if (self.duplex_reader_active or header_mode)
                        try hooks.readDuplex(self, deadline)
                    else if (raw_continuations)
                        RetainedFrame.fromOwned(try hooks.readRaw(self, deadline))
                    else
                        RetainedFrame.fromOwned(try hooks.readQueued(self, deadline));
                    defer frame.deinit(self.allocator);
                    if (frame.frame.header.frame_type != .continuation or
                        frame.frame.header.stream_id != first.header.stream_id)
                    {
                        self.serve_read_connection_error = .frame_sequence;
                        return error.UnexpectedFrame;
                    }
                    continuation_count += 1;
                    const next_len = std.math.add(usize, self.header_block_scratch.items.len, frame.frame.payload.len) catch return error.MessageTooLarge;
                    limit_exceeded = header_block_limits.completeOverflow(continuation_count, max_continuations, next_len, header_block_limit, (frame.frame.header.flags & flag_end_headers) != 0) catch |err| {
                        self.serve_read_connection_error = .excessive_header_block;
                        self.aggregate_timeout_unusable = true;
                        return @errorCast(err);
                    };
                    try self.header_block_scratch.appendSlice(
                        self.allocator,
                        frame.frame.payload,
                    );
                    flags = frame.frame.header.flags;
                }
                break :blk self.header_block_scratch.items;
            };
            return .{ .bytes = block, .limit_exceeded = limit_exceeded };
        }
    };
}

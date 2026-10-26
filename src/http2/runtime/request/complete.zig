//! Complete request preparation, output deadline, and failed-upload ownership.
const std = @import("std");
const http2 = @import("../../mod.zig");
const headers = @import("../headers/message.zig");
const outbound_headers = @import("../headers/connection.zig");
const cleanup = @import("../response/cleanup.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const upload = @import("upload.zig");

pub fn send(self: anytype, options: anytype, deadline: ?std.Io.Clock.Timestamp, comptime Context: anytype) Context.ErrorType!Context.PendingType {
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
    if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
    if (self.role != .client) return error.UnexpectedFrame;
    try Context.synchronize(self, deadline);
    // A previous reset reason is useful only to the operation that
    // returned StreamReset. Starting a new request invalidates any value
    // that its caller chose not to consume.
    self.last_peer_reset = null;
    var request_options = options;
    request_options.authority = Context.resolveAuthority(self, request_options.authority, request_options.headers);
    const scheme = request_options.scheme orelse self.default_scheme orelse "https";

    var fields_stack: [16]http2.Hpack.HeaderField = undefined;
    const fields_capacity = std.math.add(
        usize,
        request_options.headers.len,
        7,
    ) catch return error.MessageTooLarge;
    const fields_buffer = if (fields_capacity <= fields_stack.len)
        fields_stack[0..fields_capacity]
    else
        try self.allocator.alloc(http2.Hpack.HeaderField, fields_capacity);
    defer if (fields_buffer.ptr != fields_stack[0..].ptr) self.allocator.free(fields_buffer);
    var fields: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(fields_buffer);
    const method_is_connect = headers.methodIsConnect(request_options.method);
    const extended_connect = request_options.protocol != null;
    if (method_is_connect and !extended_connect and (request_options.body.len != 0 or request_options.trailers.len != 0)) {
        return error.InvalidContentLength;
    }
    fields.appendAssumeCapacity(.{
        .name = ":method",
        .value = request_options.method,
    });
    if (!method_is_connect or extended_connect) {
        fields.appendAssumeCapacity(.{
            .name = ":path",
            .value = request_options.path,
        });
        fields.appendAssumeCapacity(.{
            .name = ":scheme",
            .value = scheme,
        });
    }
    if (request_options.protocol) |protocol| {
        if (!self.peer_enable_connect_protocol) return error.ExtendedConnectDisabled;
        fields.appendAssumeCapacity(.{
            .name = ":protocol",
            .value = protocol,
        });
    }
    if (request_options.authority) |authority| {
        fields.appendAssumeCapacity(.{
            .name = ":authority",
            .value = authority,
        });
    }
    var priority_buf: [16]u8 = undefined;
    if (request_options.priority) |value| {
        fields.appendAssumeCapacity(.{
            .name = "priority",
            .value = value.serialize(&priority_buf),
        });
    }
    fields.appendSliceAssumeCapacity(request_options.headers);
    try outbound_headers.stripConnectionHeaders(
        self.allocator,
        &fields,
        .request,
    );
    var content_length_buf: [32]u8 = undefined;
    if (headers.requestShouldDefaultContentLength(request_options.method, fields.items, request_options.body.len)) {
        const content_length = std.fmt.bufPrint(&content_length_buf, "{}", .{request_options.body.len}) catch unreachable;
        fields.appendAssumeCapacity(.{
            .name = "content-length",
            .value = content_length,
        });
    }
    try headers.validateHeaderBlock(fields.items, .request);
    try headers.validateHeaderBlock(request_options.trailers, .request_trailers);
    try headers.validateDeclaredRequestLength(fields.items, request_options.body.len);

    if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
    const stream_id = try Context.reserve(self);
    var head_committed = false;
    var body_written: usize = 0;
    var response_available = false;
    errdefer |err| {
        // A partial wire write forbids any appended CANCEL frame. If a
        // complete head was sent before a flow-control timeout or OOM, retire
        // the non-resumable request under the bounded terminal cleanup budget.
        if (self.aggregate_timeout_unusable) {
            self.terminal_write_failed = true;
        } else if (head_committed and (err == error.Timeout or err == error.OutOfMemory)) {
            // Timeout is authoritative even when a transport's timer rounds
            // before the clock's exact timestamp. Do not spend the last few
            // sub-millisecond operation ticks on terminal cancellation.
            Context.discard(self, stream_id, cleanup.cleanupDeadline(self, if (err == error.Timeout) null else deadline));
        }
        Context.release(self, stream_id);
        Context.forgetWindows(self, stream_id);
    }
    if (request_options.body.len != 0 and
        request_options.trailers.len == 0)
    {
        Context.burst(
            self,
            stream_id,
            fields.items,
            request_options.body,
            true,
            deadline,
            &head_committed,
            &body_written,
        ) catch |err| {
            if (err != error.ResponseAvailable) return @as(Context.ErrorType!Context.PendingType, err);
            response_available = true;
        };
    } else {
        try Context.headers(
            self,
            stream_id,
            fields.items,
            request_options.body.len == 0 and
                request_options.trailers.len == 0,
            deadline,
        );
        head_committed = true;
        if (request_options.body.len != 0) {
            Context.data(
                self,
                stream_id,
                request_options.body,
                false,
                &body_written,
                deadline,
            ) catch |err| {
                if (err != error.ResponseAvailable) return @as(Context.ErrorType!Context.PendingType, err);
                response_available = true;
            };
        }
    }
    if (!response_available and request_options.trailers.len != 0) try Context.headers(self, stream_id, request_options.trailers, true, deadline);
    return .{
        .stream_id = stream_id,
        .request_method = request_options.method,
        .extended_connect = extended_connect,
        .upload = if (response_available) upload.Upload{
            .body = request_options.body[body_written..],
            .trailers = request_options.trailers,
        } else null,
    };
}

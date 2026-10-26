//! Prepare and submit a streaming response head under the caller's budget.
const std = @import("std");
const http2 = @import("../../mod.zig");
const headers = @import("../headers/message.zig");
const outbound_headers = @import("../headers/connection.zig");
const deadline_policy = @import("../../../internal/deadline.zig");
const statusIsInformational = headers.statusIsInformational;
const responseWriteSuppressesBodySemantics = headers.responseWriteSuppressesBodySemantics;
const stripSuccessfulConnectContentLength = headers.stripSuccessfulConnectContentLength;
const contentLength = headers.contentLength;
const validateOutgoingResponseBodyForStatusWithLength = headers.validateOutgoingResponseBodyForStatusWithLength;
const validateHeaderBlock = headers.validateHeaderBlock;

pub fn start(self: anytype, stream_id: u31, options: anytype, release_at_headers: bool, deadline: ?std.Io.Clock.Timestamp, comptime Context: anytype) Context.ErrorType!Context.WriterType {
    if (deadline) |absolute| _ = try deadline_policy.usableAwake(self.io, absolute);
    if (self.aggregate_timeout_unusable) return error.ConnectionClosed;
    if (self.role != .server) return error.UnexpectedFrame;
    if (!Context.active(self.*, stream_id)) {
        return error.InvalidStreamId;
    }
    if (options.status < 100 or options.status > 999 or
        statusIsInformational(options.status))
    {
        return error.InvalidStatus;
    }
    const semantics = Context.semantics(self.*, stream_id, .{
        .status = options.status,
        .request_method = options.request_method,
        .extended_connect = options.extended_connect,
    });
    const suppress_body =
        responseWriteSuppressesBodySemantics(options.status, semantics);
    var status_buffer: [3]u8 = undefined;
    const status = std.fmt.bufPrint(
        &status_buffer,
        "{}",
        .{options.status},
    ) catch return error.InvalidStatus;

    var fields_stack: [16]http2.Hpack.HeaderField = undefined;
    const fields_capacity = std.math.add(
        usize,
        options.headers.len,
        3,
    ) catch return error.MessageTooLarge;
    const fields_buffer = if (fields_capacity <= fields_stack.len)
        fields_stack[0..fields_capacity]
    else
        try self.allocator.alloc(
            http2.Hpack.HeaderField,
            fields_capacity,
        );
    defer if (fields_buffer.ptr != fields_stack[0..].ptr) {
        self.allocator.free(fields_buffer);
    };
    var fields: std.ArrayList(http2.Hpack.HeaderField) =
        .initBuffer(fields_buffer);
    fields.appendAssumeCapacity(.{
        .name = ":status",
        .value = status,
    });
    fields.appendSliceAssumeCapacity(options.headers);
    try outbound_headers.stripConnectionHeaders(
        self.allocator,
        &fields,
        .response,
    );
    if (semantics.traditional_connect and
        options.status >= 200 and options.status < 300)
    {
        try stripSuccessfulConnectContentLength(&fields);
    }
    const declared_length = try contentLength(fields.items);
    try validateOutgoingResponseBodyForStatusWithLength(
        options.status,
        declared_length,
        &.{},
        &.{},
    );
    if (semantics.traditional_connect and
        options.status >= 200 and options.status < 300 and
        (declared_length orelse 0) != 0)
    {
        return error.InvalidContentLength;
    }
    try validateHeaderBlock(fields.items, .response);
    Context.date(self, &fields);

    // HEAD/204/304 and successful traditional CONNECT end at HEADERS.
    // An ordinary zero-length response stays open so the writer may choose
    // either an empty END_STREAM DATA frame or response trailers.
    const ends_at_headers = suppress_body;
    Context.write(
        self,
        stream_id,
        fields.items,
        ends_at_headers,
        deadline,
    ) catch |err| {
        // Pre-wire preparation remains retryable. A failed submission
        // retires this stream while the parent forbids further wire I/O.
        if (self.aggregate_timeout_unusable) Context.release(self, stream_id);
        return err;
    };
    if (ends_at_headers and release_at_headers) {
        Context.release(self, stream_id);
    }
    return .{
        .connection = self,
        .stream_id = stream_id,
        .expected_length = if (options.status == 205)
            0
        else
            declared_length,
        .finished = ends_at_headers,
    };
}

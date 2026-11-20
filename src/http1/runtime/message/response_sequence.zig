//! Method-aware response decoding and bounded informational response sequences.
const std = @import("std");
const http1 = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");
const buffered_input = @import("buffered_input.zig");
const Error = runtime.Error;
const Limits = runtime.Limits;
const RuntimeTransport = runtime.RuntimeTransport;
const OwnedResponse = runtime.OwnedResponse;
const InformationalObserver = runtime.InformationalObserver;
const InformationalResponseHead = runtime.InformationalResponseHead;
const readMessageBytesBufferedWithContext = runtime.readMessageBytesBufferedWithContext;

pub fn parseResponseForRuntime(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    options: http1.ParseOptions,
    request_method: ?http1.Method,
) Error!http1.Response {
    return if (request_method) |method|
        try http1.parseResponseForRequest(allocator, bytes, options, method)
    else
        try http1.parseResponse(allocator, bytes, options);
}

pub fn informationalResponseHead(response: http1.Response) InformationalResponseHead {
    return .{
        .version = response.version,
        .status = response.status,
        .reason = response.reason,
        .headers = response.headers,
    };
}

pub fn validateAndCountInformationalResponse(
    response: http1.Response,
    limits: Limits,
    count: *usize,
) Error!void {
    try http1.validateResponseBodyForStatus(
        response.status,
        response.headers,
        response.body,
        response.trailers,
    );
    count.* += 1;
    if (count.* > limits.max_informational_responses) {
        return error.TooManyInformationalResponses;
    }
}

pub fn notifyInformationalResponse(
    informational: ?InformationalObserver,
    response: http1.Response,
) void {
    if (informational) |observer| {
        observer.on_response(
            observer.context,
            informationalResponseHead(response),
        );
    }
}

pub fn readOneResponseFromTransportBufferedForRequest(
    allocator: std.mem.Allocator,
    transport: RuntimeTransport,
    limits: Limits,
    options: http1.ParseOptions,
    inbuf: *std.ArrayList(u8),
    request_method: http1.Method,
    head_deadline: ?std.Io.Clock.Timestamp,
    body_deadline: ?std.Io.Clock.Timestamp,
) Error!OwnedResponse {
    const bytes = try readMessageBytesBufferedWithContext(
        allocator,
        transport,
        limits,
        options,
        inbuf,
        request_method,
        false,
        true,
        head_deadline,
        body_deadline,
        null,
        null,
    );
    errdefer |err| if (err == error.OutOfMemory) buffered_input.restore(allocator, inbuf, bytes) else allocator.free(bytes);
    var response = try parseResponseForRuntime(
        allocator,
        bytes,
        options,
        request_method,
    );
    errdefer response.deinit(allocator);
    return .{ .bytes = bytes, .response = response };
}

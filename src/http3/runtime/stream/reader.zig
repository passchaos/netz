const std = @import("std");
const http3 = @import("../../mod.zig");
const quic = @import("../../../quic/mod.zig");
const Error = @import("../error.zig").Error;

pub const Head = union(enum) {
    request: http3.DecodedRequestHead,
    response: http3.DecodedResponseHead,

    pub fn deinit(self: *Head, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .request => |*head| head.deinit(allocator),
            .response => |*head| head.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const Event = union(enum) {
    head: Head,
    push_promise: PushPromise,
    data_available,
    trailers: http3.DecodedTrailers,
    finished,

    pub const PushPromise = struct {
        push_id: u64,
        request: http3.DecodedRequestHead,

        pub fn deinit(self: *PushPromise, allocator: std.mem.Allocator) void {
            self.request.deinit(allocator);
            self.* = undefined;
        }
    };

    pub fn deinit(self: *Event, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .head => |*head| head.deinit(allocator),
            .push_promise => |*promise| promise.deinit(allocator),
            .trailers => |*trailers| trailers.deinit(allocator),
            .data_available, .finished => {},
        }
        self.* = undefined;
    }
};

pub const Reader = struct {
    pub const Kind = enum { request, response };
    pub const Phase = enum { initial_headers, body, trailers, done };
    pub const CreditUpdate = struct {
        stream_id: u62,
        amount: usize,
        maximum_stream_data: u64,
    };

    allocator: std.mem.Allocator,
    receive: quic.stream_state.RecvState,
    settings: http3.Settings,
    kind: Kind,
    push_promises_allowed: bool = false,
    phase: Phase = .initial_headers,
    current_frame: ?http3.Frame.Header = null,
    current_header_consumed: bool = false,
    current_payload_read: usize = 0,
    body_read: usize = 0,
    content_length: ?usize = null,
    body_allowed: bool = true,
    final_observed: bool = false,
    informational_count: usize = 0,
    max_informational_responses: usize =
        http3.default_max_informational_responses,
    response_request_method: ?[]const u8 = null,
    response_extended_connect: bool = false,
    request_extended_connect: bool = false,
    response_connect_established: bool = false,
    /// Absolute HTTP/3 stream offset already returned to QUIC flow control.
    credited_offset: usize = 0,

    pub fn initRequest(
        allocator: std.mem.Allocator,
        stream_id: u64,
        max_buffered: usize,
        settings: http3.Settings,
    ) Reader {
        return .{
            .allocator = allocator,
            .receive = .init(allocator, stream_id, max_buffered),
            .settings = settings,
            .kind = .request,
        };
    }

    pub fn initRequestFromReceive(
        allocator: std.mem.Allocator,
        receive: quic.stream_state.RecvState,
        settings: http3.Settings,
    ) Reader {
        return .{
            .allocator = allocator,
            .receive = receive,
            .settings = settings,
            .kind = .request,
            .credited_offset = receive.read_offset,
        };
    }

    pub fn initResponse(
        allocator: std.mem.Allocator,
        stream_id: u64,
        max_buffered: usize,
        settings: http3.Settings,
    ) Reader {
        return initResponseWithInformationalLimit(
            allocator,
            stream_id,
            max_buffered,
            settings,
            http3.default_max_informational_responses,
        );
    }

    pub fn initResponseWithInformationalLimit(
        allocator: std.mem.Allocator,
        stream_id: u64,
        max_buffered: usize,
        settings: http3.Settings,
        max_informational_responses: usize,
    ) Reader {
        return .{
            .allocator = allocator,
            .receive = .init(allocator, stream_id, max_buffered),
            .settings = settings,
            .kind = .response,
            .push_promises_allowed = true,
            .max_informational_responses = max_informational_responses,
        };
    }

    pub fn initResponseFromReceive(
        allocator: std.mem.Allocator,
        receive: quic.stream_state.RecvState,
        settings: http3.Settings,
        max_informational_responses: usize,
    ) Reader {
        return .{
            .allocator = allocator,
            .receive = receive,
            .settings = settings,
            .kind = .response,
            .push_promises_allowed = true,
            .max_informational_responses = max_informational_responses,
            .credited_offset = receive.read_offset,
        };
    }

    pub fn initPushFromReceive(
        allocator: std.mem.Allocator,
        receive: quic.stream_state.RecvState,
        settings: http3.Settings,
        max_informational_responses: usize,
    ) Reader {
        return .{
            .allocator = allocator,
            .receive = receive,
            .settings = settings,
            .kind = .response,
            .max_informational_responses = max_informational_responses,
        };
    }

    pub fn deinit(self: *Reader) void {
        self.receive.deinit();
        self.* = undefined;
    }

    pub fn insert(self: *Reader, frame: quic.StreamFrame) Error!void {
        try self.receive.insert(frame);
        if (frame.fin) self.final_observed = true;
    }

    pub fn next(
        self: *Reader,
        table: http3.Qpack.DynamicTable,
    ) Error!?Event {
        if (self.phase == .done) return null;
        while (true) {
            if (self.current_frame == null) {
                const available = self.receive.available();
                if (available.len == 0) {
                    if (self.receive.complete()) return self.finishAtStreamEnd();
                    return null;
                }
                const header = http3.Frame.parseHeader(available) catch |err| switch (err) {
                    error.BufferTooShort => {
                        if (self.receive.final_size) |final_size| {
                            if (self.receive.contiguous_end >= final_size) {
                                return err;
                            }
                        }
                        return null;
                    },
                    else => return err,
                };
                self.current_frame = header;
                self.current_header_consumed = false;
                self.current_payload_read = 0;
                // QPACK field sections remain wholly unconsumed until semantic
                // decoding succeeds, making QpackBlocked/OOM retryable without
                // cloning the receive window. DATA and ignorable frames can
                // commit their header immediately.
                if (header.frame_type != http3.FrameType.headers and
                    header.frame_type != http3.FrameType.push_promise)
                {
                    try self.receive.consume(header.header_length);
                    self.current_header_consumed = true;
                }
            }
            const header = self.current_frame.?;
            switch (header.frame_type) {
                http3.FrameType.headers => {
                    const total_length = try header.totalLength();
                    if (self.receive.available().len < total_length) {
                        if (self.framePayloadTruncated()) {
                            return error.BufferTooShort;
                        }
                        return null;
                    }
                    const payload = self.receive.available()[header.header_length..total_length];
                    if (self.phase == .initial_headers) {
                        var final_head = true;
                        const event = switch (self.kind) {
                            .request => blk: {
                                var head = try http3.decodeRequestHeadFieldSectionWithDynamicTable(
                                    self.allocator,
                                    payload,
                                    self.settings,
                                    table,
                                );
                                head.consumed =
                                    header.header_length + header.payload_length;
                                self.content_length = head.content_length;
                                self.body_allowed = head.body_allowed;
                                self.request_extended_connect =
                                    std.mem.eql(u8, head.method, "CONNECT") and
                                    requestHasProtocol(head.headers);
                                break :blk Event{
                                    .head = .{ .request = head },
                                };
                            },
                            .response => blk: {
                                var head = try http3.decodeResponseHeadFieldSectionWithDynamicTable(
                                    self.allocator,
                                    payload,
                                    self.settings,
                                    table,
                                );
                                try http3.applyResponseHeadRequestSemantics(
                                    &head,
                                    self.response_request_method,
                                    self.response_extended_connect,
                                );
                                head.consumed =
                                    header.header_length + header.payload_length;
                                final_head = head.status >= 200;
                                if (!final_head) {
                                    self.informational_count = std.math.add(
                                        usize,
                                        self.informational_count,
                                        1,
                                    ) catch {
                                        head.deinit(self.allocator);
                                        return error.TooManyInformationalResponses;
                                    };
                                    if (self.informational_count >
                                        self.max_informational_responses)
                                    {
                                        head.deinit(self.allocator);
                                        return error.TooManyInformationalResponses;
                                    }
                                }
                                if (final_head) self.updateResponseBodyState(head);
                                break :blk Event{
                                    .head = .{ .response = head },
                                };
                            },
                        };
                        try self.receive.consume(total_length);
                        self.current_frame = null;
                        self.current_header_consumed = false;
                        if (final_head) self.phase = .body;
                        return event;
                    }
                    if (self.phase != .body) return error.UnexpectedFrame;
                    if (!self.body_allowed) return error.InvalidContentLength;
                    const trailers = try http3.decodeTrailersWithDynamicTable(
                        self.allocator,
                        payload,
                        self.settings,
                        table,
                    );
                    try self.receive.consume(total_length);
                    self.current_frame = null;
                    self.current_header_consumed = false;
                    self.phase = .trailers;
                    return .{ .trailers = trailers };
                },
                http3.FrameType.push_promise => {
                    if (self.kind != .response or
                        !self.push_promises_allowed or
                        self.phase == .trailers)
                    {
                        return error.UnexpectedFrame;
                    }
                    const total_length = try header.totalLength();
                    if (self.receive.available().len < total_length) {
                        if (self.framePayloadTruncated()) {
                            return error.BufferTooShort;
                        }
                        return null;
                    }
                    const payload = self.receive.available()[header.header_length..total_length];
                    var promise = try http3.decodePushPromiseWithDynamicTable(
                        self.allocator,
                        payload,
                        self.settings,
                        table,
                    );
                    errdefer promise.deinit(self.allocator);
                    try self.receive.consume(total_length);
                    self.current_frame = null;
                    self.current_header_consumed = false;
                    return .{ .push_promise = .{
                        .push_id = promise.push_id,
                        .request = promise.request,
                    } };
                },
                http3.FrameType.data => {
                    if (self.phase != .body) return error.UnexpectedFrame;
                    if (!self.body_allowed and header.payload_length != 0) {
                        return error.InvalidContentLength;
                    }
                    const next_body = std.math.add(
                        usize,
                        self.body_read,
                        header.payload_length - self.current_payload_read,
                    ) catch return error.InvalidContentLength;
                    if (self.content_length) |expected| {
                        if (next_body > expected) return error.InvalidContentLength;
                    }
                    if (header.payload_length == 0) {
                        self.current_frame = null;
                        self.current_header_consumed = false;
                        continue;
                    }
                    if (self.receive.available().len == 0) {
                        if (self.framePayloadTruncated()) {
                            return error.BufferTooShort;
                        }
                        return null;
                    }
                    return .data_available;
                },
                else => {
                    if (streamingForbiddenFrame(header.frame_type)) {
                        return error.UnexpectedFrame;
                    }
                    const remaining =
                        header.payload_length - self.current_payload_read;
                    const skip = @min(remaining, self.receive.available().len);
                    try self.receive.consume(skip);
                    self.current_payload_read += skip;
                    if (self.current_payload_read == header.payload_length) {
                        self.current_frame = null;
                        self.current_header_consumed = false;
                        continue;
                    }
                    if (self.framePayloadTruncated()) return error.BufferTooShort;
                    return null;
                },
            }
        }
    }

    pub fn readData(self: *Reader, out: []u8) Error!usize {
        const header = self.current_frame orelse return error.UnexpectedFrame;
        if (header.frame_type != http3.FrameType.data or self.phase != .body) {
            return error.UnexpectedFrame;
        }
        const remaining = header.payload_length - self.current_payload_read;
        const count = @min(remaining, @min(out.len, self.receive.available().len));
        if (count == 0) return 0;
        @memcpy(out[0..count], self.receive.available()[0..count]);
        try self.receive.consume(count);
        self.current_payload_read += count;
        self.body_read += count;
        if (self.current_payload_read == header.payload_length) {
            self.current_frame = null;
            self.current_header_consumed = false;
            self.current_payload_read = 0;
        }
        return count;
    }

    pub fn skipData(self: *Reader) Error!usize {
        const header = self.current_frame orelse return error.UnexpectedFrame;
        if (header.frame_type != http3.FrameType.data or self.phase != .body) {
            return error.UnexpectedFrame;
        }
        const remaining = header.payload_length - self.current_payload_read;
        const count = @min(remaining, self.receive.available().len);
        if (count == 0) return 0;
        try self.receive.consume(count);
        self.current_payload_read += count;
        self.body_read += count;
        if (self.current_payload_read == header.payload_length) {
            self.current_frame = null;
            self.current_header_consumed = false;
            self.current_payload_read = 0;
        }
        return count;
    }

    pub fn streamId(self: Reader) u62 {
        return @intCast(self.receive.stream_id);
    }

    pub fn receiveState(self: *Reader) *quic.stream_state.RecvState {
        return &self.receive;
    }

    pub fn maxBuffered(self: Reader) usize {
        return self.receive.max_buffered;
    }

    pub fn pendingCredit(self: Reader) Error!?CreditUpdate {
        const amount = self.uncreditedConsumed();
        if (amount == 0) return null;
        const credited = std.math.add(
            u64,
            self.credited_offset,
            amount,
        ) catch return error.InvalidFrameLength;
        const window = std.math.cast(u64, self.receive.max_buffered) orelse
            return error.InvalidFrameLength;
        const maximum_stream_data = std.math.add(
            u64,
            credited,
            window,
        ) catch quic.varint.max_value;
        return .{
            .stream_id = self.streamId(),
            .amount = amount,
            .maximum_stream_data = @min(
                maximum_stream_data,
                quic.varint.max_value,
            ),
        };
    }

    pub fn bufferedBytes(self: Reader) usize {
        return self.receive.buffer.items.len;
    }

    pub fn readOffset(self: Reader) usize {
        return self.receive.read_offset;
    }

    pub fn hasPendingFrame(self: Reader) bool {
        return self.current_frame != null;
    }

    pub fn awaitingInitialHead(self: Reader) bool {
        return self.phase == .initial_headers;
    }

    pub fn canDetachRequest(self: Reader) bool {
        return self.phase == .body and self.current_frame == null and
            self.request_extended_connect;
    }

    pub fn canDetachResponse(self: Reader) bool {
        return self.phase == .body and self.current_frame == null and
            self.response_connect_established;
    }

    pub fn responseRequestMethod(self: Reader) ?[]const u8 {
        return self.response_request_method;
    }

    pub fn responseExtendedConnect(self: Reader) bool {
        return self.response_extended_connect;
    }

    pub fn applyResponseSemantics(
        self: *Reader,
        options: http3.ResponseDecodeOptions,
    ) void {
        self.response_request_method = options.request_method;
        self.response_extended_connect = options.extended_connect;
    }

    pub fn applyDecodedResponseHead(
        self: *Reader,
        head: *http3.DecodedResponseHead,
    ) Error!void {
        try http3.applyResponseHeadRequestSemantics(
            head,
            self.response_request_method,
            self.response_extended_connect,
        );
        self.updateResponseBodyState(head.*);
    }

    pub fn adoptDecodedResponseHead(
        self: *Reader,
        head: http3.DecodedResponseHead,
        extended_connect: bool,
    ) void {
        self.phase = .body;
        self.response_extended_connect = extended_connect;
        self.updateResponseBodyState(head);
        self.credited_offset = self.receive.read_offset;
    }

    pub fn adoptDecodedResponseHeadFromReceive(
        self: *Reader,
        head: http3.DecodedResponseHead,
        extended_connect: bool,
        receive: quic.stream_state.RecvState,
    ) void {
        self.receive.deinit();
        self.receive = receive;
        self.final_observed = receive.final_size != null;
        self.adoptDecodedResponseHead(head, extended_connect);
    }

    pub fn uncreditedConsumed(self: Reader) usize {
        std.debug.assert(self.receive.read_offset >= self.credited_offset);
        return self.receive.read_offset - self.credited_offset;
    }

    pub fn markCredited(self: *Reader, amount: usize) void {
        std.debug.assert(amount <= self.uncreditedConsumed());
        self.credited_offset += amount;
    }

    pub fn hasUnacknowledgedDynamicSection(
        self: Reader,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const available = self.receive.available();
        var offset: usize = 0;
        if (self.current_frame) |current| {
            if (frameCarriesFieldSection(current.frame_type)) {
                return frameFieldSectionUsesDynamicTable(
                    available,
                    current,
                    table,
                );
            }
            // Frames without field sections commit their headers eagerly. Skip
            // the unconsumed payload before scanning complete frames queued
            // behind it (notably dynamic trailers or promises).
            const remaining =
                current.payload_length - self.current_payload_read;
            if (available.len < remaining) return false;
            offset = remaining;
        }
        while (offset < available.len) {
            const header = http3.Frame.parseHeader(
                available[offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => return false,
                else => return err,
            };
            if (frameCarriesFieldSection(header.frame_type) and
                try frameFieldSectionUsesDynamicTable(
                    available[offset..],
                    header,
                    table,
                ))
            {
                return true;
            }
            const frame_length = try header.totalLength();
            if (available.len - offset < frame_length) return false;
            offset += frame_length;
        }
        return false;
    }

    pub fn blockedByQpack(
        self: Reader,
        table: http3.Qpack.DynamicTable,
    ) Error!bool {
        const available = self.receive.available();
        if (self.current_frame) |current| {
            if (frameCarriesFieldSection(current.frame_type)) {
                return frameFieldSectionBlocked(available, current, table);
            }
            // A parser parked on DATA cannot reach a later field section until
            // the application explicitly reads or skips the remaining DATA.
            return false;
        }
        var offset: usize = 0;
        while (offset < available.len) {
            const header = http3.Frame.parseHeader(
                available[offset..],
            ) catch |err| switch (err) {
                error.BufferTooShort => return false,
                else => return err,
            };
            if (frameCarriesFieldSection(header.frame_type)) {
                return try frameFieldSectionBlocked(
                    available[offset..],
                    header,
                    table,
                );
            }
            if (header.frame_type == http3.FrameType.data) return false;
            const frame_length = try header.totalLength();
            if (available.len - offset < frame_length) return false;
            offset += frame_length;
        }
        return false;
    }

    fn updateResponseBodyState(
        self: *Reader,
        head: http3.DecodedResponseHead,
    ) void {
        self.content_length = if (head.body_allowed) head.content_length else null;
        self.body_allowed = head.body_allowed;
        self.response_connect_established =
            self.response_extended_connect and
            head.status >= 200 and head.status < 300;
    }

    fn finishAtStreamEnd(self: *Reader) Error!?Event {
        if (self.current_frame != null) return error.BufferTooShort;
        if (self.phase == .initial_headers) {
            return if (self.kind == .request)
                error.RequestIncomplete
            else
                error.MissingStatus;
        }
        if (self.content_length) |expected| {
            if (self.body_read != expected) return error.InvalidContentLength;
        }
        self.phase = .done;
        return .finished;
    }

    fn framePayloadTruncated(self: Reader) bool {
        const header = self.current_frame orelse return false;
        const final_size = self.receive.final_size orelse return false;
        const remaining = header.payload_length - self.current_payload_read;
        const unconsumed_header =
            if (self.current_header_consumed) 0 else header.header_length;
        const required_end = std.math.add(
            usize,
            self.receive.read_offset,
            std.math.add(
                usize,
                unconsumed_header,
                remaining,
            ) catch return true,
        ) catch return true;
        return required_end > final_size;
    }
};

fn requestHasProtocol(headers: []const http3.Qpack.HeaderField) bool {
    for (headers) |header| {
        if (std.mem.eql(u8, header.name, ":protocol")) return true;
    }
    return false;
}

fn frameCarriesFieldSection(frame_type: u64) bool {
    return frame_type == http3.FrameType.headers or
        frame_type == http3.FrameType.push_promise;
}

fn frameFieldSectionUsesDynamicTable(
    bytes: []const u8,
    header: http3.Frame.Header,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    if (bytes.len <= header.header_length) return false;
    const payload_available = @min(
        header.payload_length,
        bytes.len - header.header_length,
    );
    const payload = bytes[header.header_length..][0..payload_available];
    const field_section = if (header.frame_type == http3.FrameType.push_promise)
        (http3.parsePushPromisePayload(payload) catch |err| switch (err) {
            error.BufferTooShort => return false,
            else => return err,
        }).field_section
    else
        payload;
    const prefix = http3.Qpack.decodeFieldSectionPrefix(
        field_section,
        table,
    ) catch |err| switch (err) {
        error.BufferTooShort => return false,
        else => return err,
    };
    return prefix.required_insert_count != 0;
}

fn frameFieldSectionBlocked(
    bytes: []const u8,
    header: http3.Frame.Header,
    table: http3.Qpack.DynamicTable,
) Error!bool {
    if (bytes.len <= header.header_length) return false;
    const payload_available = @min(
        header.payload_length,
        bytes.len - header.header_length,
    );
    if (payload_available < header.payload_length) return false;
    const payload = bytes[header.header_length..][0..payload_available];
    const field_section = if (header.frame_type == http3.FrameType.push_promise)
        (try http3.parsePushPromisePayload(payload)).field_section
    else
        payload;
    const prefix = http3.Qpack.decodeFieldSectionPrefix(
        field_section,
        table,
    ) catch |err| switch (err) {
        error.OutOfMemory,
        error.ExcessiveLoad,
        error.QpackBlocked,
        error.QpackDecompressionFailed,
        => return err,
        else => return error.QpackDecompressionFailed,
    };
    return prefix.required_insert_count > table.insert_count;
}

fn streamingForbiddenFrame(frame_type: u64) bool {
    return switch (frame_type) {
        http3.FrameType.cancel_push,
        http3.FrameType.settings,
        http3.FrameType.goaway,
        http3.FrameType.max_push_id,
        http3.FrameType.priority_update_request,
        http3.FrameType.priority_update_push,
        => true,
        else => false,
    };
}

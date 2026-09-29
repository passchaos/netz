const std = @import("std");
const netz = @import("netz");

/// Validates a browser send-stream abort while allowing QUIC delivery of the
/// immediately preceding write to race with RESET_STREAM.
pub const Validator = struct {
    expected: []const u8,
    application_code: u32,
    association_prefix_len: usize,
    stream_id: ?u62 = null,
    received: usize = 0,

    pub fn observeData(
        self: *Validator,
        stream_id: u62,
        direction: netz.webtransport.StreamDirection,
        locally_initiated: bool,
        fin: bool,
        payload: []const u8,
    ) !void {
        if (self.stream_id) |id| {
            if (stream_id != id) return error.UnexpectedResetStream;
        } else {
            self.stream_id = stream_id;
        }
        if (direction != .unidirectional or locally_initiated or fin or
            self.received > self.expected.len or
            payload.len > self.expected.len - self.received or
            !std.mem.eql(
                u8,
                payload,
                self.expected[self.received..][0..payload.len],
            ))
        {
            return error.UnexpectedResetStream;
        }
        self.received += payload.len;
    }

    pub fn observeReset(
        self: *Validator,
        stream_id: u62,
        direction: netz.webtransport.StreamDirection,
        locally_initiated: bool,
        application_code: ?u32,
        final_size: u64,
    ) !u62 {
        if (self.stream_id) |id| {
            if (stream_id != id) return error.UnexpectedResetStream;
        }
        const expected_final_size = std.math.add(
            usize,
            self.association_prefix_len,
            self.expected.len,
        ) catch return error.UnexpectedResetStream;
        if (direction != .unidirectional or locally_initiated or
            application_code != self.application_code or
            final_size != expected_final_size or
            self.received > self.expected.len)
        {
            return error.UnexpectedResetStream;
        }
        self.stream_id = stream_id;
        return stream_id;
    }
};

test "browser reset accepts zero, partial, and complete visible prefixes" {
    const expected = "wtransport reset";
    for ([_]usize{ 0, 5, expected.len }) |prefix_len| {
        var validator = Validator{
            .expected = expected,
            .application_code = 71,
            .association_prefix_len = 3,
        };
        if (prefix_len != 0) {
            try validator.observeData(14, .unidirectional, false, false, expected[0..prefix_len]);
        }
        try std.testing.expectEqual(
            @as(u62, 14),
            try validator.observeReset(14, .unidirectional, false, 71, expected.len + 3),
        );
    }
}

test "browser reset rejects invalid data events" {
    const expected = "wtransport reset";
    var wrong_payload = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        wrong_payload.observeData(14, .unidirectional, false, false, "wrong"),
    );
    var fin = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        fin.observeData(14, .unidirectional, false, true, expected),
    );
    var direction = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        direction.observeData(14, .bidirectional, false, false, expected),
    );
    var local = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        local.observeData(14, .unidirectional, true, false, expected),
    );
}

test "browser reset rejects mismatched identity code and final size" {
    const expected = "wtransport reset";
    var stream = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try stream.observeData(14, .unidirectional, false, false, expected[0..4]);
    try std.testing.expectError(
        error.UnexpectedResetStream,
        stream.observeData(18, .unidirectional, false, false, expected[4..]),
    );
    try std.testing.expectError(
        error.UnexpectedResetStream,
        stream.observeReset(18, .unidirectional, false, 71, expected.len + 3),
    );

    var code = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        code.observeReset(14, .unidirectional, false, 72, expected.len + 3),
    );
    try std.testing.expectError(
        error.UnexpectedResetStream,
        code.observeReset(14, .unidirectional, false, null, expected.len + 3),
    );
    try std.testing.expectError(
        error.UnexpectedResetStream,
        code.observeReset(14, .bidirectional, false, 71, expected.len + 3),
    );
    try std.testing.expectError(
        error.UnexpectedResetStream,
        code.observeReset(14, .unidirectional, true, 71, expected.len + 3),
    );
    var final_size = Validator{ .expected = expected, .application_code = 71, .association_prefix_len = 3 };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        final_size.observeReset(14, .unidirectional, false, 71, expected.len + 2),
    );

    var corrupted = Validator{
        .expected = expected,
        .application_code = 71,
        .association_prefix_len = 3,
        .received = expected.len + 1,
    };
    try std.testing.expectError(
        error.UnexpectedResetStream,
        corrupted.observeData(14, .unidirectional, false, false, ""),
    );
}

//! RFC 8470 signaling shared by HTTP/1, HTTP/2, and HTTP/3.
//!
//! Transport provenance and the `Early-Data: 1` field are deliberately
//! separate. A gateway can receive an ordinary 1-RTT request that still
//! carries replay risk from an earlier hop, while an origin-facing client
//! must emit at most one canonical field instance.

const std = @import("std");

pub const header_name = "early-data";
pub const header_value = "1";
pub const too_early_status: u16 = 425;

pub const Error = error{InvalidHeader};

/// Mutation required before a gateway forwards a request.
///
/// `set` means the outbound field set must contain exactly one canonical
/// `Early-Data: 1` instance. This retains rather than drops the replay-risk
/// signal while coalescing invalid or repeated inbound instances.
pub const ForwardingAction = enum {
    none,
    preserve,
    set,
};

const Scan = struct {
    count: usize = 0,
    canonical: bool = false,
};

pub fn isHeaderName(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, header_name);
}

fn scan(headers: anytype) Scan {
    var result: Scan = .{};
    for (headers) |header| {
        if (!isHeaderName(header.name)) continue;
        result.count += 1;
        if (result.count == 1) {
            result.canonical = std.mem.eql(
                u8,
                std.mem.trim(u8, header.value, " \t"),
                header_value,
            );
        } else {
            result.canonical = false;
        }
    }
    return result;
}

/// Treat any Early-Data field as replay-risk signaling.
///
/// RFC 8470 requires recipients to interpret repeated or invalid field values
/// as though one valid `Early-Data: 1` instance had been received.
pub fn requestMightHaveBeenEarly(headers: anytype) bool {
    return scan(headers).count != 0;
}

/// Enforce the sender-side single canonical field requirement.
pub fn validateOutboundRequestHeaders(headers: anytype) Error!void {
    const result = scan(headers);
    if (result.count == 0) return;
    if (result.count != 1 or !result.canonical) return error.InvalidHeader;
}

/// Reject Early-Data in responses or request/response trailers.
pub fn validateForbiddenFields(headers: anytype) Error!void {
    if (requestMightHaveBeenEarly(headers)) return error.InvalidHeader;
}

/// Decide how a gateway should propagate replay risk to its next hop.
pub fn forwardingAction(
    headers: anytype,
    current_hop_was_early_data: bool,
) ForwardingAction {
    const result = scan(headers);
    if (result.count == 1 and result.canonical) return .preserve;
    if (result.count != 0 or current_hop_was_early_data) return .set;
    return .none;
}

test "RFC 8470 Early-Data request and forwarding classification" {
    const Field = struct { name: []const u8, value: []const u8 };

    const absent = [_]Field{.{ .name = "x-test", .value = "ok" }};
    try std.testing.expect(!requestMightHaveBeenEarly(&absent));
    try validateOutboundRequestHeaders(&absent);
    try std.testing.expectEqual(
        ForwardingAction.none,
        forwardingAction(&absent, false),
    );
    try std.testing.expectEqual(
        ForwardingAction.set,
        forwardingAction(&absent, true),
    );

    const canonical = [_]Field{.{
        .name = "Early-Data",
        .value = "\t1 ",
    }};
    try std.testing.expect(requestMightHaveBeenEarly(&canonical));
    try validateOutboundRequestHeaders(&canonical);
    try std.testing.expectEqual(
        ForwardingAction.preserve,
        forwardingAction(&canonical, false),
    );

    const invalid = [_]Field{.{ .name = "early-data", .value = "0" }};
    try std.testing.expect(requestMightHaveBeenEarly(&invalid));
    try std.testing.expectError(
        error.InvalidHeader,
        validateOutboundRequestHeaders(&invalid),
    );
    try std.testing.expectEqual(
        ForwardingAction.set,
        forwardingAction(&invalid, false),
    );

    const repeated = [_]Field{
        .{ .name = "early-data", .value = "1" },
        .{ .name = "EARLY-DATA", .value = "invalid" },
    };
    try std.testing.expect(requestMightHaveBeenEarly(&repeated));
    try std.testing.expectError(
        error.InvalidHeader,
        validateOutboundRequestHeaders(&repeated),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        validateForbiddenFields(&repeated),
    );
    try std.testing.expectEqual(
        ForwardingAction.set,
        forwardingAction(&repeated, false),
    );
}

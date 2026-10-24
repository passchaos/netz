//! RFC 9112 section 6.3 response framing precedence and optional metadata.
const http1 = @import("mod.zig");
const wire = @import("../internal/wire.zig");

pub const Metadata = struct {
    body_allowed: bool,
    has_transfer_encoding: bool,
    must_close: bool,

    pub fn contentLength(self: Metadata, headers: []const http1.Header) http1.Error!?usize {
        if (self.has_transfer_encoding) return null;
        if (self.body_allowed) return http1.contentLength(headers);
        return http1.contentLength(headers) catch |err| switch (err) {
            error.InvalidContentLength, error.ConflictingContentLength, error.ContentLengthOverflow => null,
            else => return err,
        };
    }
};

pub fn forbidsBody(status: u16, request_method: ?http1.Method) bool {
    if (http1.statusCodeForbidsBody(status)) return true;
    return switch (request_method orelse return false) {
        .HEAD => true,
        .CONNECT => status >= 200 and status < 300,
        else => false,
    };
}

/// A bodyless response always ends at the head, regardless of framing fields.
/// Preserve a valid representation length for HEAD/304-style consumers; an
/// unusable numeric value cannot override the known wire boundary. Responses
/// that carry content retain normal Transfer-Encoding/Content-Length checks.
pub fn inspect(version: http1.Version, status: u16, request_method: ?http1.Method, headers: []const http1.Header) http1.Error!Metadata {
    const body_allowed = !forbidsBody(status, request_method);
    const transfer = wire.findHeader(headers, "transfer-encoding") != null;
    const length_present = wire.findHeader(headers, "content-length") != null;
    if (body_allowed and version == .http_1_0 and transfer) return error.InvalidTransferEncoding;
    return .{
        .body_allowed = body_allowed,
        .has_transfer_encoding = transfer,
        .must_close = transfer and length_present,
    };
}

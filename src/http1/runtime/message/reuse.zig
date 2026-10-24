//! HTTP persistence ends at EOF-delimited entities and protocol switches.
//! Both owned and streaming responses use the originating request method.
const http1 = @import("../../mod.zig");

pub fn switchesProtocol(method: http1.Method, status: u16) bool {
    return status == 101 or (method == .CONNECT and status >= 200 and status < 300);
}

pub fn reusable(response: anytype, method: http1.Method) bool {
    return response.version != .http_0_9 and
        response.keepAlive() and
        response.body_framing != .close_delimited and
        !switchesProtocol(method, response.status);
}

//! Transfer one CONNECT head or one owned HTTP/3 message rejection.
const http3 = @import("../../../http3/mod.zig");
const webtransport = @import("../../mod.zig");
const runtime = @import("../../runtime.zig");

pub const Head = struct {
    request: runtime.OwnedHandshakeConnectRequest,
    session_id: webtransport.SessionId,
};

pub const Result = union(enum) {
    head: Head,
    failure: http3.runtime.RequestFailure,
};

pub fn poll(h3: *http3.runtime.HandshakeServerSession) runtime.Error!?Result {
    if (!h3.control.settings.received) return null;
    while (try h3.pollRequestEventOnceWithFailure()) |result_value| {
        var result = result_value;
        defer result.deinit(h3.established.connection.endpoint.allocator);
        switch (result) {
            .failure => |failure| return .{ .failure = failure },
            .event => |*event| switch (event.*) {
                .reset => return error.InvalidConnect,
                .message => |*message| switch (message.value) {
                    .head => |*head| {
                        if (head.* != .request) return error.InvalidConnect;
                        const id = webtransport.SessionId.init(message.stream_id);
                        if (!id.isClientInitiatedBidirectional()) return error.InvalidConnect;
                        const request = head.request;
                        message.value = .finished;
                        return .{ .head = .{ .request = .{ .stream_id = message.stream_id, .request = request }, .session_id = id } };
                    },
                    else => return error.InvalidConnect,
                },
            },
        }
    }
    return null;
}

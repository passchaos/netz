//! One replay budget shared by the safe pre-response transport outcomes.
const call = @import("../call.zig");

pub const Budget = struct {
    enabled: bool,
    used: bool = false,

    pub fn replayError(self: *Budget, err: anyerror) bool {
        // Production attempt owners normalize local GOAWAY failures and
        // require peer unprocessed-stream evidence before exposing this error.
        if (err != error.ConnectionGoAway) return false;
        return self.consume();
    }

    pub fn replayResponse(self: *Budget, response: call.UnaryResponse) bool {
        if (response.response_committed or response.reset == null or
            response.reset.?.error_code != .refused_stream) return false;
        return self.consume();
    }

    fn consume(self: *Budget) bool {
        if (!self.enabled or self.used) return false;
        self.used = true;
        return true;
    }
};

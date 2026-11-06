//! One replay budget shared by the safe pre-response transport outcomes.
const call = @import("../call.zig");

pub fn replayableError(err: anyerror) bool {
    return err == error.ConnectionGoAway;
}

pub fn replayableResponse(response: call.UnaryResponse) bool {
    return !response.response_committed and response.reset != null and
        response.reset.?.error_code == .refused_stream;
}

pub const Budget = struct {
    enabled: bool,
    used: bool = false,

    pub fn replayError(self: *Budget, err: anyerror) bool {
        // Production attempt owners normalize local GOAWAY failures and
        // require peer unprocessed-stream evidence before exposing this error.
        if (!replayableError(err)) return false;
        return self.consume();
    }

    pub fn replayResponse(self: *Budget, response: call.UnaryResponse) bool {
        if (!replayableResponse(response)) return false;
        return self.consume();
    }

    fn consume(self: *Budget) bool {
        if (!self.enabled or self.used) return false;
        self.used = true;
        return true;
    }
};

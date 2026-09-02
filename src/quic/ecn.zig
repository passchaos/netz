const std = @import("std");

/// Connection-level automatic ECN marking policy.
///
/// Explicit `sendWithEcn*` calls continue to select their requested codepoint.
/// This policy only controls the convenience send paths that otherwise choose
/// `Not-ECT` automatically.
pub const Policy = enum {
    /// Never apply automatic ECN marking on ordinary 1-RTT sends.
    disabled,
    /// Start each validated path in ECN testing mode and fall back per path.
    enabled,
};

/// Current path-scoped automatic ECN validation state.
pub const ValidationState = enum {
    disabled,
    testing,
    capable,
    failed,
};

/// Path-local automatic ECN state machine.
///
/// QUIC validates ACK_ECN counters per packet number space, but whether new
/// application traffic should carry ECT marking is a path property. When a
/// peer migrates or NAT rebinding selects a different 4-tuple, the new path
/// must start from fresh ECN testing instead of inheriting the old path's
/// success or failure.
pub const PathState = struct {
    policy: Policy = .disabled,
    validation: ValidationState = .disabled,

    pub fn init(policy: Policy) PathState {
        return .{
            .policy = policy,
            .validation = switch (policy) {
                .disabled => .disabled,
                .enabled => .testing,
            },
        };
    }

    pub fn resetForPath(self: *PathState) void {
        self.validation = switch (self.policy) {
            .disabled => .disabled,
            .enabled => .testing,
        };
    }

    pub fn mayMarkEct0(self: PathState) bool {
        return switch (self.validation) {
            .testing, .capable => true,
            .disabled, .failed => false,
        };
    }

    pub fn state(self: PathState) ValidationState {
        return self.validation;
    }

    pub fn onValidatedAck(self: *PathState) void {
        if (self.validation == .testing or self.validation == .capable) {
            self.validation = .capable;
        }
    }

    pub fn onValidationFailure(self: *PathState) void {
        if (self.policy == .enabled) self.validation = .failed;
    }
};

test "QUIC ECN path state resets per path" {
    var state = PathState.init(.enabled);
    try std.testing.expectEqual(ValidationState.testing, state.state());
    try std.testing.expect(state.mayMarkEct0());

    state.onValidatedAck();
    try std.testing.expectEqual(ValidationState.capable, state.state());

    state.onValidationFailure();
    try std.testing.expectEqual(ValidationState.failed, state.state());
    try std.testing.expect(!state.mayMarkEct0());

    state.resetForPath();
    try std.testing.expectEqual(ValidationState.testing, state.state());
    try std.testing.expect(state.mayMarkEct0());
}

test "QUIC ECN disabled policy never marks" {
    var state = PathState.init(.disabled);
    try std.testing.expectEqual(ValidationState.disabled, state.state());
    try std.testing.expect(!state.mayMarkEct0());
    state.onValidatedAck();
    try std.testing.expectEqual(ValidationState.disabled, state.state());
}

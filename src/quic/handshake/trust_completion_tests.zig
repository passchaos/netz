const std = @import("std");
const quic = @import("../mod.zig");
const authentication = @import("client_authentication.zig");
const support = @import("../../internal/testing/trust_completion.zig");

fn bundled(mode: support.Mode) !void {
    var probe: support.Probe = .{ .mode = mode };
    var owner: authentication.Owner = .{};
    defer owner.deinit();
    const options: quic.handshake.ClientOptions = .{
        .original_destination_connection_id = "completion-origin",
        .local_connection_id = "completion-client",
        .root_source = .bundled,
        .handshake_recovery = .{ .deadline = probe.deadline() },
    };
    try std.testing.expectError(switch (mode) {
        .ordinary => error.OutOfMemory,
        .expired => error.HandshakeTimeout,
        .canceled => error.Canceled,
    }, owner.init(probe.allocator(), probe.io(), options));
    try std.testing.expectEqual(@as(usize, 1), probe.allocations);
    try std.testing.expect(owner.system_store == null);
    try std.testing.expect(owner.verifier == null);
}

test "QUIC trust completion preserves allocation failure within budget" {
    try bundled(.ordinary);
}
test "QUIC trust completion expired bundled-source failure returns HandshakeTimeout" {
    try bundled(.expired);
}
test "QUIC trust completion canceled bundled-source failure returns Canceled" {
    try bundled(.canceled);
}

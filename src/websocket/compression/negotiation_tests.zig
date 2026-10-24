const std = @import("std");
const websocket = @import("../mod.zig");

test "WebSocket directional takeover binds mandatory server no-context offer" {
    const policy = websocket.ExtensionNegotiation.Policy{
        .enable_permessage_deflate = true,
        .allow_context_takeover = true,
    };
    try std.testing.expectError(error.InvalidExtension, websocket.ExtensionNegotiation.validateResponseForOfferWithPolicy(
        "permessage-deflate",
        "permessage-deflate; server_no_context_takeover",
        policy,
    ));
    const hint = try websocket.ExtensionNegotiation.validateResponseForOfferWithPolicy(
        "permessage-deflate",
        "permessage-deflate; client_no_context_takeover",
        policy,
    );
    try std.testing.expect(hint.permessage_deflate);
    try std.testing.expect(!hint.client_no_context_takeover);
    const alternative = try websocket.ExtensionNegotiation.validateResponseForOfferWithPolicy(
        "permessage-deflate",
        "permessage-deflate; server_no_context_takeover, permessage-deflate",
        policy,
    );
    try std.testing.expect(alternative.permessage_deflate);
    try std.testing.expectError(error.InvalidExtension, websocket.ExtensionNegotiation.validateResponseForOfferWithPolicy(
        "permessage-deflate; client_max_window_bits=12",
        "permessage-deflate; server_no_context_takeover; client_max_window_bits=12, permessage-deflate",
        policy,
    ));
}

test "WebSocket directional takeover offers and server selections cover all policies" {
    const modes = [_]websocket.ContextTakeover{ .none, .client, .server, .both };
    const values = [_][]const u8{
        "permessage-deflate; server_no_context_takeover; client_no_context_takeover",
        "permessage-deflate; server_no_context_takeover",
        "permessage-deflate; client_no_context_takeover",
        "permessage-deflate",
    };
    for (modes, values) |mode, expected| {
        const policy = websocket.ExtensionNegotiation.Policy{
            .enable_permessage_deflate = true,
            .allow_context_takeover = mode == .none,
            .context_takeover = mode,
        };
        try std.testing.expectEqualStrings(expected, websocket.ExtensionNegotiation.offerValue(policy).?);
        var storage: [websocket.ExtensionNegotiation.max_offer_value_len]u8 = undefined;
        const bounded = (try websocket.ExtensionNegotiation.offerValueInto(&storage, policy, 9, 10)).?;
        const parsed = try websocket.ExtensionNegotiation.parseOffer(bounded);
        try std.testing.expectEqual(mode != .client and mode != .both, parsed.client_no_context_takeover);
        try std.testing.expectEqual(mode != .server and mode != .both, parsed.server_no_context_takeover);
        try std.testing.expectEqual(@as(?u8, 9), parsed.client_max_window_bits);
        try std.testing.expectEqual(@as(?u8, 10), parsed.server_max_window_bits);
        const selected = (try websocket.ExtensionNegotiation.acceptWithPolicy(std.testing.allocator, "permessage-deflate", policy)).?;
        defer std.testing.allocator.free(selected);
        try std.testing.expectEqualStrings(expected, selected);
        _ = try websocket.ExtensionNegotiation.validateResponseWithPolicy(selected, policy);
        if (mode != .both) try std.testing.expectError(error.InvalidExtension, websocket.ExtensionNegotiation.validateResponseWithPolicy("permessage-deflate", policy));
    }
}

test "WebSocket directional takeover client policy remains effective without hint echo" {
    for ([_]?websocket.ContextTakeover{ null, .none, .server }) |mode| {
        const policy = websocket.ExtensionNegotiation.Policy{ .enable_permessage_deflate = true, .context_takeover = mode };
        const response = if (mode == .server) "permessage-deflate" else "permessage-deflate; server_no_context_takeover";
        const offer = websocket.ExtensionNegotiation.offerValue(policy).?;
        const negotiated = try websocket.ExtensionNegotiation.validateResponseForOfferWithPolicy(response, offer, policy);
        try std.testing.expect(negotiated.client_no_context_takeover);
        try std.testing.expectEqual(mode != .server, negotiated.server_no_context_takeover);
    }
}

//! Protocol-specific test root; dependencies cannot satisfy the match guard.

const std = @import("std");
const options = @import("test_scope_options");

test {
    switch (options.scope) {
        .proxy => _ = @import("proxy/mod.zig"),
        .proxy_queues => {
            _ = @import("proxy/internal/byte_bucket.zig");
            _ = @import("proxy/internal/relay_queue.zig");
            _ = @import("proxy/internal/relay_queue/pending_input.zig");
            _ = @import("proxy/internal/relay_queue/stream_send_tests.zig");
            _ = @import("proxy/internal/udp_session.zig");
        },
        .http => _ = @import("http/mod.zig"),
        .http1 => _ = @import("http1/mod.zig"),
        .http2 => _ = @import("http2/mod.zig"),
        .http3 => _ = @import("http3/mod.zig"),
        .quic => _ = @import("quic/mod.zig"),
        .grpc => _ = @import("grpc/mod.zig"),
        .mqtt => _ = @import("mqtt/mod.zig"),
        .websocket => _ = @import("websocket/mod.zig"),
        .webtransport => _ = @import("webtransport/mod.zig"),
        .tls => _ = @import("tls/mod.zig"),
        .vpn => _ = @import("vpn/mod.zig"),
        .mesh => _ = @import("mesh/mod.zig"),
    }
    const prefix = if (options.scope == .proxy_queues) "proxy." else @tagName(options.scope) ++ ".";
    var matched: usize = 0;
    for (@import("builtin").test_functions) |function| {
        if (!std.mem.startsWith(u8, function.name, prefix)) continue;
        if (std.mem.indexOf(u8, function.name, ".test.") == null) continue;
        const selected = for (options.filters) |filter| {
            if (std.mem.indexOf(u8, function.name, filter) != null) break true;
        } else options.filters.len == 0;
        if (selected) matched += 1;
    }
    if (matched == 0) {
        std.debug.print("focused suite {s}: no named protocol test matches the requested filters\n", .{@tagName(options.scope)});
        return error.NoMatchingProtocolTests;
    }
}
